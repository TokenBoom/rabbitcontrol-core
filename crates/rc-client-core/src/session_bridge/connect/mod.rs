use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use rc_net::quic::{Identity, QuicEndpoint};
use rc_net::{NetConfig, Role, Transport};
use rc_pipeline::{ControllerPipeline, DiffMode, PipelineConfig};
use rc_session::dev_cert::{dev_server_cert_pem, DEV_CERT_PEM, DEV_KEY_PEM, DEV_SERVER_NAME};
use rc_session::proto::{
    ByeReason, ControllerMeta, SessionParams, CONTROLLER_MODE_REMOTE_CONTROL,
    CONTROLLER_MODE_TOOLS, CONTROLLER_MODE_WATCH_ONLY, MAX_CONTROLLER_META_FIELD_BYTES,
};
use rc_session::{ClientAuthConfig, ClientSession, ClientSessionConfig, SessionClock};
use rc_types::Resolution;

use crate::app_prefs::ConnectionMode;
use crate::platform::PreallocatedRenderSurface;
use crate::relay_transport::{
    E2eeRelayTransport, RelayE2eeMode, RelayRole, RelayShutdownHandle, SessionMtlsBundle,
    TcpRelayTransport,
};
use crate::switchable_transport::{SwitchHandle, SwitchableTransport};

use super::adapters::{
    build_controller_pipeline, create_clipboard_backend, fake_controller_stack,
    ActiveRelayInterrupt, BridgeInputCapture, BridgeTransport, LanQuicTransport, LayerLease,
    RendererHandle, ToggleableClipboardBackend,
};
use super::classify::{
    classify_relay_connect_error, is_busy_controlled_reason, is_preempted_reason,
    should_fallback_after_handshake_error,
};
use super::queues::{BoundedInputQueue, BoundedUpdateQueue};
use super::routing::{effective_connection_mode, path_kind_from_transport_label};
use super::types::{ConnectPhase, SessionEnd, SessionUpdate, UiSessionConfig};

mod relay_first;
mod signaling;

pub(in crate::session_bridge) type BgP2pUpgradeRx =
    mpsc::Receiver<Result<(Box<dyn Transport>, Option<String>), String>>;

type PipelineFactory =
    Box<dyn FnMut(&PipelineConfig) -> rc_types::Result<ControllerPipeline> + Send>;

/// 可重锚的会话钟（同 `rc-cli/src/cmd/client.rs` 修复卡 C-1）。
pub(in crate::session_bridge) fn reanchorable_clock(
    origin: Instant,
) -> (SessionClock, Arc<Mutex<Instant>>) {
    let anchor = Arc::new(Mutex::new(origin));
    let clock: SessionClock = {
        let anchor = Arc::clone(&anchor);
        Arc::new(move || {
            let a = *anchor.lock().unwrap_or_else(|e| e.into_inner());
            u32::try_from(a.elapsed().as_micros()).unwrap_or(u32::MAX)
        })
    };
    (clock, anchor)
}

/// 生成进程内唯一会话号（同 `rc-cli/src/cmd/client.rs`）。
pub(in crate::session_bridge) fn derive_session_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    (u64::from(std::process::id()) << 20) | (n & 0xF_FFFF) | 0x200_000
}

pub(in crate::session_bridge) fn clamp_meta_field(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() <= MAX_CONTROLLER_META_FIELD_BYTES {
        return trimmed.to_string();
    }
    let mut end = MAX_CONTROLLER_META_FIELD_BYTES;
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    trimmed[..end].to_string()
}

pub(in crate::session_bridge) fn compute_controller_meta_mode(wo: bool, tools: bool) -> u8 {
    if tools {
        CONTROLLER_MODE_TOOLS
    } else if wo {
        CONTROLLER_MODE_WATCH_ONLY
    } else {
        CONTROLLER_MODE_REMOTE_CONTROL
    }
}

pub(super) struct SelectedRelayPath {
    pub(super) transport: Box<dyn Transport>,
    pub(super) relay_shutdown: Option<RelayShutdownHandle>,
    pub(super) transport_label: &'static str,
    pub(super) backend_suffix: Option<&'static str>,
    pub(super) mtls_active: bool,
    pub(super) peer_cert_fingerprint: Option<String>,
}

pub(super) struct ReadySignalingSession {
    pub(super) client: ClientSession,
    pub(super) negotiated: SessionParams,
    pub(super) transport_label: &'static str,
    pub(super) backend_suffix: Option<&'static str>,
    pub(super) mtls_active: bool,
    pub(super) peer_cert_fingerprint: Option<String>,
    pub(super) switch_handle: SwitchHandle,
}

pub(super) enum TierHandshakeResult {
    Ready(Box<ReadySignalingSession>),
    Fallback(String),
    Abort(Result<SessionEnd, SessionEnd>),
}

/// 建连阶段所需的共享只读/原子上下文。
pub(in crate::session_bridge) struct ConnectEnv<'a> {
    pub(in crate::session_bridge) cfg: &'a UiSessionConfig,
    pub(in crate::session_bridge) t0: Instant,
    pub(in crate::session_bridge) clock: SessionClock,
    pub(in crate::session_bridge) pipeline_cfg: PipelineConfig,
    pub(in crate::session_bridge) initial_controller_meta: ControllerMeta,
    pub(in crate::session_bridge) effective_mode: ConnectionMode,
    pub(in crate::session_bridge) render_surface: Arc<Mutex<Option<PreallocatedRenderSurface>>>,
    pub(in crate::session_bridge) input_rx: Arc<BoundedInputQueue>,
    pub(in crate::session_bridge) update_tx: Arc<BoundedUpdateQueue>,
    pub(in crate::session_bridge) layer_lease: Arc<Mutex<Option<LayerLease>>>,
    pub(in crate::session_bridge) disconnect_flag: Arc<AtomicBool>,
    pub(in crate::session_bridge) relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    pub(in crate::session_bridge) live_watch_only: Arc<AtomicBool>,
    pub(in crate::session_bridge) pending_control: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub(in crate::session_bridge) backend_label: Arc<Mutex<String>>,
    pub(in crate::session_bridge) renderer_handle: Arc<Mutex<Option<RendererHandle>>>,
    pub(in crate::session_bridge) renderer_pending_resize: Arc<Mutex<Arc<AtomicU64>>>,
    pub(in crate::session_bridge) streaming_started: Arc<AtomicBool>,
    pub(in crate::session_bridge) clipboard_enabled_flag: Arc<AtomicBool>,
    pub(in crate::session_bridge) want_real_pipeline: Arc<AtomicBool>,
    pub(in crate::session_bridge) real_pipeline_built: Arc<AtomicBool>,
    pub(in crate::session_bridge) is_hw_decoder_slot: Arc<AtomicBool>,
}

/// 建连与握手成功后的会话运行要素。
pub(in crate::session_bridge) struct EstablishedSession {
    pub(in crate::session_bridge) client: ClientSession,
    pub(in crate::session_bridge) negotiated: SessionParams,
    pub(in crate::session_bridge) transport_label: &'static str,
    pub(in crate::session_bridge) active_backend_suffix: Option<&'static str>,
    pub(in crate::session_bridge) mtls_active: bool,
    pub(in crate::session_bridge) peer_cert_fingerprint: Option<String>,
    pub(in crate::session_bridge) switch_handle: Option<SwitchHandle>,
    pub(in crate::session_bridge) bg_p2p_upgrade_rx: Option<BgP2pUpgradeRx>,
    pub(in crate::session_bridge) bg_p2p_cancel_slot: Option<Arc<AtomicBool>>,
    pub(in crate::session_bridge) grant_obtained_at: Instant,
    pub(in crate::session_bridge) initial_relay_token_consumed: bool,
    pub(in crate::session_bridge) proxy_active_runtime: bool,
    pub(in crate::session_bridge) runtime_mode: ConnectionMode,
}

impl ConnectEnv<'_> {
    pub(super) fn make_client_cfg(
        &self,
        peer_addr: SocketAddr,
        handshake_timeout: Duration,
    ) -> ClientSessionConfig {
        ClientSessionConfig {
            peer_addr,
            mtu: rc_session::DEFAULT_SESSION_MTU,
            requested: SessionParams {
                width: self.cfg.width,
                height: self.cfg.height,
                fps: self.cfg.fps.max(1),
                bitrate_bps: self.cfg.bitrate_bps.max(1),
            },
            session_id: derive_session_id(),
            pipeline: self.pipeline_cfg.clone(),
            connect_timeout: Duration::from_secs(10),
            handshake_timeout,
            capture: Box::new(BridgeInputCapture {
                queue: Arc::clone(&self.input_rx),
                watch_only: Arc::clone(&self.live_watch_only),
            }),
            input_window: rc_input::DEFAULT_WINDOW,
            auth: ClientAuthConfig {
                password: self.cfg.password.clone(),
                owner_signer: self.cfg.owner_signer.clone(),
                ..ClientAuthConfig::default()
            },
        }
    }

    pub(super) fn make_pipeline_factory(
        &self,
        backend_suffix: Option<&'static str>,
    ) -> PipelineFactory {
        let label = Arc::clone(&self.backend_label);
        let rend_slot = Arc::clone(&self.renderer_handle);
        let pending_slot = Arc::clone(&self.renderer_pending_resize);
        let layer_slot = Arc::clone(&self.layer_lease);
        let want_real = Arc::clone(&self.want_real_pipeline);
        let built_real = Arc::clone(&self.real_pipeline_built);
        let hw_slot = Arc::clone(&self.is_hw_decoder_slot);
        let prefer_hw = self.cfg.prefer_hardware;
        let surface_slot = Arc::clone(&self.render_surface);
        let t0 = self.t0;
        Box::new(move |pcfg: &PipelineConfig| {
            if !want_real.load(Ordering::Acquire) {
                let placeholder_cfg = PipelineConfig {
                    resolution: Resolution::new(64, 64),
                    fps: pcfg.fps.max(1),
                    bitrate_bps: pcfg.bitrate_bps.max(1),
                    prefer_hardware: false,
                    async_decode: false,
                    ..pcfg.clone()
                };
                let (pipeline, _renderer, _pending_resize) =
                    fake_controller_stack(&placeholder_cfg)?;
                let final_label = match backend_suffix {
                    Some(suffix) => format!("tools-only {suffix}"),
                    None => "tools-only".to_string(),
                };
                *label.lock().unwrap_or_else(|e| e.into_inner()) = final_label;
                *rend_slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
                *pending_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                    Arc::new(AtomicU64::new(0));
                // tools_only 模式严禁创建硬件 VT/Metal，也不写入 layer_lease。
                built_real.store(false, Ordering::Release);
                hw_slot.store(false, Ordering::Release);
                return Ok(pipeline);
            }
            let pre_surface = surface_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let built = build_controller_pipeline(pcfg, prefer_hw, t0, pre_surface.as_ref())?;
            let final_label = match backend_suffix {
                Some(suffix) => format!("{} {suffix}", built.backend_label),
                None => built.backend_label,
            };
            *label.lock().unwrap_or_else(|e| e.into_inner()) = final_label;
            *pending_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                Arc::clone(&built.pending_resize);
            *rend_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(Arc::clone(&built.renderer));
            *layer_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                LayerLease::from_renderer(built.renderer, built.layer_addr);
            built_real.store(true, Ordering::Release);
            hw_slot.store(built.is_hardware, Ordering::Release);
            Ok(built.pipeline)
        })
    }

    pub(super) fn attempt_tier_handshake(
        &self,
        path: SelectedRelayPath,
        peer_addr: SocketAddr,
        handshake_timeout: Duration,
        allow_fallback: bool,
    ) -> TierHandshakeResult {
        let SelectedRelayPath {
            transport: raw_transport,
            relay_shutdown,
            transport_label: chosen_transport_label,
            backend_suffix,
            mtls_active,
            peer_cert_fingerprint: peer_fp,
        } = path;

        self.update_tx.push(SessionUpdate::Connecting {
            phase: ConnectPhase::AwaitingWelcome,
            watch_only: self.live_watch_only.load(Ordering::Acquire),
        });

        let sw_kind = path_kind_from_transport_label(chosen_transport_label);
        let (sw_transport, switch_handle) = SwitchableTransport::new(
            raw_transport,
            Role::Controller,
            sw_kind,
            self.cfg.encrypt_connection,
        );
        let bridge_transport = BridgeTransport {
            inner: Box::new(sw_transport),
            pending_control: Arc::clone(&self.pending_control),
            disconnect_flag: Arc::clone(&self.disconnect_flag),
            relay_shutdown,
            streaming_started: Arc::clone(&self.streaming_started),
        };
        // 占位解码/渲染器仅用于满足 `ClientSession::with_parts` 签名；握手成功后
        // `set_pipeline_factory_for` 会按裁定参数构造实际硬件/假栈并挂载 `LayerLease`。
        let placeholder_res = Resolution::new(64, 64);
        let dummy_decoder = match rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
            resolution: placeholder_res,
            ..rc_decode::FakeDecoderConfig::default()
        }) {
            Ok(d) => d,
            Err(e) => {
                return TierHandshakeResult::Abort(Err(SessionEnd::fatal(format!(
                    "会话占位解码器构造失败: {e}"
                ))));
            }
        };
        let dummy_renderer = match rc_render::FakeRenderer::new(rc_render::FakeRendererConfig {
            size: (placeholder_res.width, placeholder_res.height),
            ..rc_render::FakeRendererConfig::default()
        }) {
            Ok(r) => r,
            Err(e) => {
                return TierHandshakeResult::Abort(Err(SessionEnd::fatal(format!(
                    "会话占位渲染器构造失败: {e}"
                ))));
            }
        };

        let mut client = match ClientSession::with_parts(
            self.make_client_cfg(peer_addr, handshake_timeout),
            Box::new(bridge_transport),
            Box::new(dummy_decoder),
            Box::new(dummy_renderer),
            Arc::clone(&self.clock),
        ) {
            Ok(c) => c,
            Err(e) => {
                return TierHandshakeResult::Abort(Err(SessionEnd::fatal(format!(
                    "信令会话构造失败: {e}"
                ))));
            }
        };
        client.set_pipeline_factory_for(self.make_pipeline_factory(backend_suffix));
        client.set_controller_meta(Some(self.initial_controller_meta.clone()));
        if let Some(cb) = create_clipboard_backend(self.cfg.prefer_hardware) {
            client.enable_clipboard(Box::new(ToggleableClipboardBackend::new(
                cb,
                Arc::clone(&self.clipboard_enabled_flag),
            )));
        }

        match client.handshake() {
            Ok(negotiated) => TierHandshakeResult::Ready(Box::new(ReadySignalingSession {
                client,
                negotiated,
                transport_label: chosen_transport_label,
                backend_suffix,
                mtls_active,
                peer_cert_fingerprint: peer_fp,
                switch_handle,
            })),
            Err(e) => {
                let user_disc = self.disconnect_flag.load(Ordering::Acquire);
                if user_disc {
                    return TierHandshakeResult::Abort(Ok(SessionEnd::fatal("用户主动断开")));
                }
                if client.handshake_busy_controlled() || is_busy_controlled_reason(&e.to_string()) {
                    return TierHandshakeResult::Abort(Err(SessionEnd::busy_controlled(
                        "目标设备正在被控中，需要确认接管",
                    )));
                }
                if matches!(
                    client.closed_reason(),
                    Some(rc_session::StopReason::ByeReceived(ByeReason::Preempted))
                ) || is_preempted_reason(&e.to_string())
                {
                    return TierHandshakeResult::Abort(Err(SessionEnd::preempted(
                        "当前连接已被其他设备接管",
                    )));
                }
                if allow_fallback
                    && should_fallback_after_handshake_error(
                        &e,
                        client.handshake_entered_auth(),
                        false,
                    )
                {
                    return TierHandshakeResult::Fallback(format!(
                        "{chosen_transport_label} 握手前连接断开: {e}"
                    ));
                }
                TierHandshakeResult::Abort(Err(SessionEnd::fatal(format!("连接/握手失败: {e}"))))
            }
        }
    }
}

pub(super) fn dial_relay_transport(
    relay_addr: &str,
    relay_token: &str,
    peer_b: Option<&SessionMtlsBundle>,
    encrypt_conn: bool,
    cancel: Arc<AtomicBool>,
    disc_flag: &AtomicBool,
) -> Result<SelectedRelayPath, Result<SessionEnd, SessionEnd>> {
    const RELAY_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
    let (raw_transport, shutdown_handle, active, fp): (
        Box<dyn Transport>,
        RelayShutdownHandle,
        bool,
        Option<String>,
    ) = if encrypt_conn {
        let Some(bundle) = peer_b else {
            return Err(Err(SessionEnd::fatal(
                "已开启「加密连接 (mTLS)」，但缺少设备证书配置",
            )));
        };
        let relay_mtls = bundle.to_relay_mtls_config(None);
        let t = E2eeRelayTransport::connect_cancellable(
            relay_addr,
            RelayRole::Client,
            relay_token,
            RELAY_CLIENT_CONNECT_TIMEOUT,
            cancel,
            Some(&relay_mtls),
            RelayE2eeMode::ClientRequired(bundle.clone()),
        )
        .map_err(|e| {
            if disc_flag.load(Ordering::Acquire) {
                Ok(SessionEnd::fatal("用户主动断开"))
            } else {
                Err(SessionEnd::fatal(classify_relay_connect_error(
                    &e, true, true,
                )))
            }
        })?;
        let h = t.shutdown_handle();
        let fp = t
            .peer_mtls_identity()
            .map(|id| id.cert_fingerprint_sha256.clone());
        (Box::new(t), h, true, fp)
    } else if let Some(bundle) = peer_b {
        let relay_mtls = bundle.to_relay_mtls_config(None);
        let t = TcpRelayTransport::connect_mtls_cancellable(
            relay_addr,
            RelayRole::Client,
            relay_token,
            RELAY_CLIENT_CONNECT_TIMEOUT,
            cancel,
            &relay_mtls,
        )
        .map_err(|e| {
            if disc_flag.load(Ordering::Acquire) {
                Ok(SessionEnd::fatal("用户主动断开"))
            } else {
                Err(SessionEnd::fatal(classify_relay_connect_error(
                    &e, false, true,
                )))
            }
        })?;
        let h = t.shutdown_handle();
        (Box::new(t), h, false, None)
    } else {
        let t = TcpRelayTransport::connect_cancellable(
            relay_addr,
            RelayRole::Client,
            relay_token,
            RELAY_CLIENT_CONNECT_TIMEOUT,
            cancel,
        )
        .map_err(|e| {
            if disc_flag.load(Ordering::Acquire) {
                Ok(SessionEnd::fatal("用户主动断开"))
            } else {
                Err(SessionEnd::fatal(classify_relay_connect_error(
                    &e, false, false,
                )))
            }
        })?;
        let h = t.shutdown_handle();
        (Box::new(t), h, false, None)
    };
    Ok(SelectedRelayPath {
        transport: raw_transport,
        relay_shutdown: Some(shutdown_handle),
        transport_label: "TCP Relay",
        backend_suffix: Some("(中继)"),
        mtls_active: active,
        peer_cert_fingerprint: fp,
    })
}

/// 构造控制端建连所需的管线默认配置。
pub(in crate::session_bridge) fn build_initial_pipeline_config(
    cfg: &UiSessionConfig,
) -> PipelineConfig {
    let resolution = Resolution::new(
        if cfg.width == 0 { 1920 } else { cfg.width },
        if cfg.height == 0 { 1080 } else { cfg.height },
    );
    PipelineConfig {
        resolution,
        fps: cfg.fps.max(1),
        bitrate_bps: cfg.bitrate_bps.max(1),
        prefer_hardware: cfg.prefer_hardware,
        target_latency_us: 22_000,
        trace_capacity: 4096,
        diff: DiffMode::TrustPlatform,
        clock_origin_us: None,
        async_decode: cfg.prefer_hardware,
        max_packet_payload: rc_pipeline::MAX_PAYLOAD,
        ..PipelineConfig::default()
    }
}

/// 统一入口：根据是否携带 `relay_grant` 选择信令三阶路由建连或纯 IP 直连。
pub(in crate::session_bridge) fn establish_session(
    env: &ConnectEnv<'_>,
) -> Result<EstablishedSession, Result<SessionEnd, SessionEnd>> {
    let _ = effective_connection_mode(env.cfg);
    if let Some(grant) = env.cfg.relay_grant.as_ref() {
        signaling::connect_signaling_session(env, grant)
    } else {
        connect_direct_ip_session(env)
    }
}

fn connect_direct_ip_session(
    env: &ConnectEnv<'_>,
) -> Result<EstablishedSession, Result<SessionEnd, SessionEnd>> {
    let cfg = env.cfg;
    let direct_mtls = if cfg.encrypt_connection {
        let bundle = cfg.mtls_config.as_ref().ok_or_else(|| {
            Err(SessionEnd::fatal(
                "已开启「加密连接 (mTLS)」，但缺少设备证书配置",
            ))
        })?;
        Some(
            bundle
                .to_quic_mtls_config()
                .map_err(|e| Err(SessionEnd::fatal(e)))?,
        )
    } else {
        None
    };
    let direct_peer_fp: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let server_cert = dev_server_cert_pem();
    let mut client = ClientSession::new(
        env.make_client_cfg(cfg.connect_addr, Duration::from_secs(10)),
        DEV_CERT_PEM,
        DEV_KEY_PEM,
        server_cert,
        DEV_SERVER_NAME,
        Arc::clone(&env.clock),
    )
    .map_err(|e| Err(SessionEnd::fatal(format!("会话构造失败: {e}"))))?;
    if let Some(cb) = create_clipboard_backend(cfg.prefer_hardware) {
        client.enable_clipboard(Box::new(ToggleableClipboardBackend::new(
            cb,
            Arc::clone(&env.clipboard_enabled_flag),
        )));
    }

    // ── 自定义 connect 工厂：每次建连/重连均丢弃旧端点并重新绑定 `0.0.0.0:0`（避免切网后旧 UDP 套接字失效） ──
    {
        let peer_addr = cfg.connect_addr;
        let pending = Arc::clone(&env.pending_control);
        let upd = Arc::clone(&env.update_tx);
        let disc = Arc::clone(&env.disconnect_flag);
        let started = Arc::clone(&env.streaming_started);
        let fp_slot = Arc::clone(&direct_peer_fp);
        let watch_only_flag = Arc::clone(&env.live_watch_only);
        let mut first_connect = true;
        client.set_connect_factory(Box::new(move || {
            if disc.load(Ordering::Acquire) {
                return Err(rc_types::Error::Network("用户主动断开".to_string()));
            }
            if first_connect {
                upd.push(SessionUpdate::Connecting {
                    phase: ConnectPhase::EndpointCreating,
                    watch_only: watch_only_flag.load(Ordering::Acquire),
                });
            }
            let identity = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM)?;
            let net = NetConfig {
                role: Role::Controller,
                local_addr: "0.0.0.0:0"
                    .parse()
                    .expect("0.0.0.0:0 is a valid socket addr"),
                peer_addr: Some(peer_addr),
                mtu: rc_session::DEFAULT_SESSION_MTU,
            };
            let endpoint = QuicEndpoint::new(&net, &identity)?;
            if first_connect {
                upd.push(SessionUpdate::Connecting {
                    phase: ConnectPhase::Connecting,
                    watch_only: watch_only_flag.load(Ordering::Acquire),
                });
            }
            let transport = if let Some(ref mtls_cfg) = direct_mtls {
                let t = endpoint.connect_mtls_cancelable(
                    peer_addr,
                    mtls_cfg,
                    "",
                    Duration::from_secs(10),
                    &disc,
                )?;
                *fp_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                    t.peer_mtls_identity().map(|id| id.cert_fingerprint_sha256);
                t
            } else {
                let certs = Identity::certs_from_pem(dev_server_cert_pem())?;
                endpoint.connect_cancelable(
                    peer_addr,
                    &certs,
                    DEV_SERVER_NAME,
                    Duration::from_secs(10),
                    &disc,
                )?
            };
            if first_connect {
                first_connect = false;
                upd.push(SessionUpdate::Connecting {
                    phase: ConnectPhase::AwaitingWelcome,
                    watch_only: watch_only_flag.load(Ordering::Acquire),
                });
            }
            Ok(Box::new(BridgeTransport {
                inner: Box::new(LanQuicTransport {
                    transport,
                    _endpoint: endpoint,
                }),
                pending_control: Arc::clone(&pending),
                disconnect_flag: Arc::clone(&disc),
                relay_shutdown: None,
                streaming_started: Arc::clone(&started),
            }))
        }));
    }

    // ── 管线工厂：prefer_hardware 时优先 VT + 离屏 MetalRenderer，失败降级假后端；tools_only 走轻量占位管线 ──
    client.set_pipeline_factory_for(env.make_pipeline_factory(None));
    client.set_controller_meta(Some(env.initial_controller_meta.clone()));

    // ── 连接 + 握手 ──
    let negotiated = match client.connect_and_handshake() {
        Ok(n) => n,
        Err(e) => {
            if env.disconnect_flag.load(Ordering::Acquire) {
                return Err(Ok(SessionEnd::fatal("用户主动断开")));
            }
            if client.handshake_busy_controlled() || is_busy_controlled_reason(&e.to_string()) {
                return Err(Err(SessionEnd::busy_controlled(
                    "目标设备正在被控中，需要确认接管",
                )));
            }
            if matches!(
                client.closed_reason(),
                Some(rc_session::StopReason::ByeReceived(ByeReason::Preempted))
            ) || is_preempted_reason(&e.to_string())
            {
                return Err(Err(SessionEnd::preempted("当前连接已被其他设备接管")));
            }
            return Err(Err(SessionEnd::fatal(format!("连接/握手失败: {e}"))));
        }
    };
    let fp = direct_peer_fp
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    Ok(EstablishedSession {
        client,
        negotiated,
        transport_label: "UDP LAN",
        active_backend_suffix: None,
        mtls_active: cfg.encrypt_connection,
        peer_cert_fingerprint: fp,
        switch_handle: None,
        bg_p2p_upgrade_rx: None,
        bg_p2p_cancel_slot: None,
        grant_obtained_at: Instant::now(),
        initial_relay_token_consumed: false,
        proxy_active_runtime: false,
        runtime_mode: ConnectionMode::P2pOnly,
    })
}
