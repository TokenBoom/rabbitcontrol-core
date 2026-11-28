use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rc_net::quic::QuicEndpoint;
use rc_net::{NetConfig, NetEvent, NetStats, Role, Transport};
use rc_pipeline::{DiffMode, PipelineConfig};
use rc_session::auth::{ConnectionApprover, OwnerTicketVerifier, DEFAULT_AUTH_ITERATIONS};
use rc_session::dev_cert::{DEV_CERT_PEM, DEV_KEY_PEM};
use rc_session::proto::SessionParams;
use rc_session::testkit::RecordingInjector;
use rc_session::{ClipboardBackend, HostAuthConfig, HostSession, HostSessionConfig, SessionClock};
use rc_types::Resolution;

use crate::display_ctrl;
use crate::lan_discovery;
use crate::relay_transport::SessionMtlsBundle;

use super::media_aux::replace_wake_guard;
use super::queues::BoundedHostUpdateQueue;
use super::types::{
    host_resume_ttl, HostTransportKind, HostUpdate, SharedWakeGuard, FAKE_ENCODE_COST_US,
};

#[derive(Debug, Clone)]
pub(super) enum ClockOrigin {
    /// 握手/审批阶段：以每次 accept 分片前的墙钟推进，保证审批超时准确触发。
    Pending(Instant),
    /// 假后端：与 `WallCapture` 共用单次采样锚点。
    Fake(Instant),
    /// 真后端：锚定主机钟 µs（与 SCK PTS 同域同零点）。
    HostClock(u64),
}

pub(super) fn make_session_clock(origin: Arc<Mutex<ClockOrigin>>) -> SessionClock {
    Arc::new(move || {
        let guard = origin.lock().unwrap_or_else(|e| e.into_inner());
        match *guard {
            ClockOrigin::Pending(i) | ClockOrigin::Fake(i) => {
                u32::try_from(i.elapsed().as_micros()).unwrap_or(u32::MAX)
            }
            ClockOrigin::HostClock(o) => {
                u32::try_from(rc_pipeline::host_clock_us().unwrap_or(o).saturating_sub(o))
                    .unwrap_or(u32::MAX)
            }
        }
    })
}

#[derive(Clone)]
pub(super) struct HostClockAnchor {
    pub(super) origin: Arc<Mutex<ClockOrigin>>,
    /// 指示下一次管线工厂构造必须放弃旧纪元零点并重新锚定（供 `Bye(Refresh)` 与 `DetachOutcome::Replaced` 跨纪元复位）。
    pub(super) reanchor_next_build: Arc<AtomicBool>,
}

impl HostClockAnchor {
    pub(super) fn new_pending() -> Self {
        Self {
            origin: Arc::new(Mutex::new(ClockOrigin::Pending(Instant::now()))),
            reanchor_next_build: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(super) fn reset_pending(&self) {
        *self.origin.lock().unwrap_or_else(|e| e.into_inner()) =
            ClockOrigin::Pending(Instant::now());
    }
}

pub(super) struct BuiltUiHost {
    pub(super) host: HostSession,
    pub(super) clock: SessionClock,
    pub(super) clock_anchor: HostClockAnchor,
    pub(super) backend_label: Arc<Mutex<String>>,
    pub(super) hardware_video_active: Arc<AtomicBool>,
    pub(super) wake_guard: SharedWakeGuard,
}

pub(super) enum HostListener {
    Plain(Box<BuiltUiHost>),
    MtlsLan { endpoint: QuicEndpoint },
    AwaitingMtlsCert,
}

pub(super) fn bind_mtls_lan_endpoint(
    listen_addr: SocketAddr,
    bundle: &SessionMtlsBundle,
) -> Result<QuicEndpoint, String> {
    // LAN 直连监听端接受任意同 CA 设备（客户端证书 SAN 验证其身份）；expected_peer_device_id 置 None。
    let mut server_bundle = bundle.clone();
    server_bundle.expected_peer_device_id = None;
    server_bundle.expected_peer_user_id = None;
    let mtls_cfg = server_bundle.to_quic_mtls_config()?;
    QuicEndpoint::new_mtls(&NetConfig::new(Role::Host, listen_addr), &mtls_cfg)
        .map_err(|e| format!("mTLS LAN 监听器绑定失败: {e}"))
}

/// 查询硬件主显示器逻辑分辨率（`prefer_hardware == true` 且平台钩子已注册时生效）。
pub(super) fn host_hardware_display_caps(prefer_hardware: bool) -> Option<Resolution> {
    if !prefer_hardware {
        return None;
    }
    crate::platform::main_display_logical_resolution()
}

/// 查询硬件主显示器物理像素分辨率（backing pixels；`prefer_hardware == true` 且平台钩子已注册时生效）。
pub(super) fn host_hardware_display_backing(prefer_hardware: bool) -> Option<Resolution> {
    if !prefer_hardware {
        return None;
    }
    crate::platform::main_display_backing_resolution()
}

/// HiDPI/Retina 物理像素采集默认最大宽度上限（覆盖 14" MBP `3024×1964`、16" MBP `3456×2234` 与 4K `3840×2160`）。
pub(super) const DEFAULT_HIDPI_STREAM_MAX_WIDTH: u32 = 3840;
/// HiDPI/Retina 物理像素采集默认最大高度上限（覆盖 16:10 16" MBP `3456×2234` 1:1 直出）。
pub(super) const DEFAULT_HIDPI_STREAM_MAX_HEIGHT: u32 = 2400;

/// 计算 HiDPI 显示器在不改动系统逻辑分辨率的前提下，满足编码像素率预算与上限封顶的流采集目标分辨率。
///
/// - 优先 1:1 物理 `backing` 像素直出（当宽高不超过 `3840×2400` 且像素率在当前编码器甜点预算内时零缩放）；
/// - 超出封顶或高刷像素率预算时，在 `logical` 宽高比下向下偶数缩放；
/// - 非 HiDPI 或退化输入保持 `logical.to_even()`。
pub(super) fn compute_hidpi_stream_target(
    logical: Resolution,
    backing: Option<Resolution>,
    fps: u32,
    codec: rc_encode::Codec,
) -> Resolution {
    let logical_even = logical.to_even();
    let Some(backing_even) = backing.map(|b| b.to_even()) else {
        return logical_even;
    };
    if logical_even.width < 2
        || logical_even.height < 2
        || backing_even.width <= logical_even.width
        || backing_even.height <= logical_even.height
    {
        return logical_even;
    }
    let budget_rate = display_ctrl::StreamCodec::from(codec).high_refresh_max_pixel_rate();
    let max_pixels = budget_rate / u64::from(fps.max(1));
    let backing_pixels =
        u64::from(backing_even.width).saturating_mul(u64::from(backing_even.height));
    if backing_even.width <= DEFAULT_HIDPI_STREAM_MAX_WIDTH
        && backing_even.height <= DEFAULT_HIDPI_STREAM_MAX_HEIGHT
        && backing_pixels <= max_pixels
    {
        return backing_even;
    }
    let logical_pixels =
        u64::from(logical_even.width).saturating_mul(u64::from(logical_even.height));
    if max_pixels <= logical_pixels {
        return logical_even;
    }
    let cap_w = backing_even
        .width
        .min(DEFAULT_HIDPI_STREAM_MAX_WIDTH)
        .max(logical_even.width);
    let cap_h = backing_even
        .height
        .min(DEFAULT_HIDPI_STREAM_MAX_HEIGHT)
        .max(logical_even.height);
    let scale = (max_pixels as f64 / logical_pixels as f64).sqrt();
    let budget_w = ((logical_even.width as f64 * scale).floor() as u32).max(logical_even.width);
    let budget_h = ((logical_even.height as f64 * scale).floor() as u32).max(logical_even.height);
    let (w, h) = display_ctrl::fit_within_cap(
        cap_w.min(budget_w),
        cap_h.min(budget_h),
        logical_even.width,
        logical_even.height,
    );
    Resolution::new(w.max(logical_even.width), h.max(logical_even.height)).to_even()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn default_host_session_config(
    listen_addr: SocketAddr,
    password: Option<String>,
    approval_timeout_us: u64,
    prefer_hardware: bool,
    allow_owner_control: bool,
    allow_remote_assist: bool,
    owner_verifier: Option<Arc<dyn OwnerTicketVerifier>>,
    owner_replay_cache: Arc<Mutex<rc_session::OwnerReplayCache>>,
    approver: Box<dyn ConnectionApprover>,
) -> (HostSessionConfig, bool) {
    let injector: Box<dyn rc_input::InputInjector> = build_injector(prefer_hardware);

    // 初始握手仍保持 1× 逻辑分辨率，保证不支持 HEVC 的对端与 H.264 路径严格留在 H.264 高刷甜点内；
    // 双端确认切入 HEVC（SetCodec("hevc")）时再在同一次热重建中一步升至 HiDPI 2K 锐利甜点。
    let hw_display_res = host_hardware_display_caps(prefer_hardware);
    let (cap_w, cap_h, preserve_aspect) = match hw_display_res {
        Some(res) => (res.width, res.height, true),
        None => (3840, 2160, false),
    };
    let caps = SessionParams {
        width: cap_w,
        height: cap_h,
        fps: 380,
        bitrate_bps: 150_000_000,
    };
    let pipeline = PipelineConfig {
        resolution: hw_display_res.unwrap_or_else(|| Resolution::new(1920, 1080)),
        fps: 144,
        bitrate_bps: 40_000_000,
        prefer_hardware,
        target_latency_us: 22_000,
        trace_capacity: 4096,
        diff: DiffMode::TrustPlatform,
        clock_origin_us: None,
        max_packet_payload: rc_pipeline::MAX_PAYLOAD,
        ..PipelineConfig::default()
    };
    let cfg = HostSessionConfig {
        listen_addr,
        mtu: rc_session::DEFAULT_SESSION_MTU,
        caps,
        pipeline,
        handshake_timeout: Duration::from_secs(10),
        injector,
        pace_capture: true,
        auth: HostAuthConfig {
            password,
            iterations: DEFAULT_AUTH_ITERATIONS,
            approval_timeout_us,
            allow_owner_control,
            allow_remote_assist,
            owner_verifier,
            replay_cache: Some(owner_replay_cache),
            ..HostAuthConfig::default()
        },
        approver,
        tool_permissions: rc_session::ToolPermissions::all_allowed(),
    };
    (cfg, preserve_aspect)
}

pub(super) type HostPipelineFactory =
    Box<dyn FnMut(&PipelineConfig) -> rc_types::Result<rc_pipeline::HostPipeline> + Send>;

pub(super) fn make_host_pipeline_factory(
    prefer_hardware: bool,
    clock_anchor: HostClockAnchor,
    backend_label: Arc<Mutex<String>>,
    hardware_video_active: Arc<AtomicBool>,
    wake_guard: SharedWakeGuard,
    updates: Arc<BoundedHostUpdateQueue>,
) -> HostPipelineFactory {
    Box::new(
        move |pcfg: &PipelineConfig| -> rc_types::Result<rc_pipeline::HostPipeline> {
            // 同会话热切换分辨率/帧率/编解码器时复用既有零点，保证会话钟与采集 PTS 严格单调连续；
            // 发生 `Bye(Refresh)` / `DetachOutcome::Replaced` 纪元重置时放弃旧零点并重新锚定，
            // 防止 71.58 分钟 `u32::MAX` 饱和导致 8s 看门狗与采集时间戳永久卡死。
            let force_reanchor = clock_anchor
                .reanchor_next_build
                .swap(false, Ordering::AcqRel);
            let existing_origin = if force_reanchor {
                ClockOrigin::Pending(Instant::now())
            } else {
                clock_anchor
                    .origin
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
            };
            if prefer_hardware {
                match crate::platform::wake_display_if_asleep() {
                    Ok(Some(guard)) => {
                        replace_wake_guard(&wake_guard, Some(guard));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("[rc-ui-host] 唤醒熄屏显示器失败（将继续尝试硬件采集）: {e}");
                    }
                }
                let mut hw_cfg = pcfg.clone();
                hw_cfg.prefer_hardware = true;
                let existing_host_us = match existing_origin {
                    ClockOrigin::HostClock(o) => Some(o),
                    _ => None,
                };
                let mut final_try = real_host_stack(&hw_cfg, existing_host_us);
                if final_try.is_err() {
                    for fb_fps in [240u32, 144, 120, 60] {
                        if fb_fps < hw_cfg.fps {
                            let mut fb_cfg = hw_cfg.clone();
                            fb_cfg.fps = fb_fps;
                            final_try = real_host_stack(&fb_cfg, existing_host_us);
                            if final_try.is_ok() {
                                break;
                            }
                        }
                    }
                }
                match final_try {
                    Ok((p, l, origin_us)) => {
                        *backend_label.lock().unwrap_or_else(|e| e.into_inner()) = l;
                        *clock_anchor
                            .origin
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = ClockOrigin::HostClock(origin_us);
                        hardware_video_active.store(true, Ordering::Release);
                        return Ok(p);
                    }
                    Err(err) => {
                        if hardware_video_active.load(Ordering::Acquire) {
                            // 活跃硬件会话热切换失败时绝不降级到 FakeEncoder（否则对端 VtDecoder
                            // 持续收到非 H.264 伪帧导致黑屏），直接返回错误；
                            // 若本次是 HEVC 尝试，HostSession 会透明回退 H.264，因此仅记录 stderr 不弹错误横幅。
                            let message = format!("硬件分辨率/帧率热切换失败：{err}");
                            eprintln!("[rc-ui-host] {message}");
                            if hw_cfg.codec != rc_encode::Codec::Hevc {
                                updates.push(HostUpdate::error(message));
                            }
                            return Err(err);
                        }
                        // 注意：在 macOS 上若 SCK / VideoToolbox 初始化失败（常见原因：缺少「屏幕录制」
                        // 权限或授权后尚未重启进程），降级为 FakeEncoder 会发送非 H.264/HEVC 伪帧，
                        // 对端若启用硬件 VtDecoder 将无法解出真实画面（表现为黑屏）。
                        // 因此绝不静默吞错：同时输出 stderr 诊断并向 UI 推送 `HostUpdate::Error`。
                        let message = format!(
                            "硬件屏幕采集/编码初始化失败（请确认已授予屏幕/录制权限），已降级为测试后端：{err}"
                        );
                        eprintln!("[rc-ui-host] {message}");
                        updates.push(HostUpdate::error(message));

                        hardware_video_active.store(false, Ordering::Release);
                        *backend_label.lock().unwrap_or_else(|e| e.into_inner()) =
                            "fake(降级)".to_string();
                        let existing_fake = match existing_origin {
                            ClockOrigin::Fake(a) => Some(a),
                            _ => None,
                        };
                        let (p, anchor) = fake_stack_anchored(pcfg, existing_fake)?;
                        *clock_anchor
                            .origin
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = ClockOrigin::Fake(anchor);
                        return Ok(p);
                    }
                }
            }
            hardware_video_active.store(false, Ordering::Release);
            *backend_label.lock().unwrap_or_else(|e| e.into_inner()) = "fake".to_string();
            let existing_fake = match existing_origin {
                ClockOrigin::Fake(a) => Some(a),
                _ => None,
            };
            let (p, anchor) = fake_stack_anchored(pcfg, existing_fake)?;
            *clock_anchor
                .origin
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = ClockOrigin::Fake(anchor);
            Ok(p)
        },
    )
}

/// 按平台与硬件偏好构造剪贴板后端：仅 `prefer_hardware == true` 时挂接本机真实剪贴板，
/// 离线假后端测试绝不触碰开发者真实系统剪贴板。
fn create_clipboard_backend(prefer_hardware: bool) -> Option<Box<dyn ClipboardBackend>> {
    if !prefer_hardware {
        return None;
    }
    rc_session::create_system_clipboard().ok()
}

/// 握手期可中断的传输层包装：在 `streaming_started == false` 期间响应 `stop_flag` / `disconnect_flag`，
/// 使 P2P QUIC 与 TCP 中继会话在握手/审批阶段均可在数毫秒内中止。
pub(super) struct CancellableHostTransport {
    pub(super) inner: Box<dyn Transport>,
    pub(super) stop_flag: Arc<AtomicBool>,
    pub(super) disconnect_flag: Arc<AtomicBool>,
    pub(super) streaming_started: Arc<AtomicBool>,
}

impl Transport for CancellableHostTransport {
    fn send_datagram(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.inner.send_datagram(data)
    }

    fn send_datagrams_batch(&mut self, datagrams: &[Vec<u8>]) -> rc_types::Result<usize> {
        self.inner.send_datagrams_batch(datagrams)
    }

    fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.inner.send_reliable(data)
    }

    fn send_reliable_urgent(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.inner.send_reliable_urgent(data)
    }

    fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
        if !self.streaming_started.load(Ordering::Acquire)
            && (self.stop_flag.load(Ordering::Acquire)
                || self.disconnect_flag.load(Ordering::Acquire))
        {
            return Ok(vec![NetEvent::Disconnected {
                reason: "本机主动断开".to_string(),
            }]);
        }
        self.inner.poll(timeout)
    }

    fn stats(&self) -> NetStats {
        self.inner.stats()
    }

    fn set_pacing_rate(&mut self, bps: u64) {
        self.inner.set_pacing_rate(bps);
    }

    fn tx_queued_bytes(&self) -> usize {
        self.inner.tx_queued_bytes()
    }

    fn tx_dropped_datagrams(&self) -> u64 {
        self.inner.tx_dropped_datagrams()
    }

    fn reliable_tx_queued_len(&self) -> usize {
        self.inner.reliable_tx_queued_len()
    }

    fn has_live_rtt(&self) -> bool {
        self.inner.has_live_rtt()
    }

    fn wake_handle(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        self.inner.wake_handle()
    }
}

/// 构造一轮直连 QUIC `HostSession`（优先硬件注入/采集/编码，无权限或非 macOS 自动降级假栈）。
#[allow(clippy::too_many_arguments)]
pub(super) fn build_host_session(
    listen_addr: SocketAddr,
    password: Option<String>,
    approval_timeout_us: u64,
    prefer_hardware: bool,
    clipboard_enabled: bool,
    allow_owner_control: bool,
    allow_remote_assist: bool,
    owner_verifier: Option<Arc<dyn OwnerTicketVerifier>>,
    owner_replay_cache: Arc<Mutex<rc_session::OwnerReplayCache>>,
    approver: Box<dyn ConnectionApprover>,
    updates: Arc<BoundedHostUpdateQueue>,
) -> Result<BuiltUiHost, String> {
    let (host_cfg, preserve_aspect) = default_host_session_config(
        listen_addr,
        password,
        approval_timeout_us,
        prefer_hardware,
        allow_owner_control,
        allow_remote_assist,
        owner_verifier,
        owner_replay_cache,
        approver,
    );

    let clock_anchor = HostClockAnchor::new_pending();
    let clock = make_session_clock(Arc::clone(&clock_anchor.origin));
    let backend_label: Arc<Mutex<String>> = Arc::new(Mutex::new(if prefer_hardware {
        "auto".to_string()
    } else {
        "fake".to_string()
    }));
    let hardware_video_active = Arc::new(AtomicBool::new(false));
    let wake_guard: SharedWakeGuard = Arc::new(Mutex::new(None));

    let factory = make_host_pipeline_factory(
        prefer_hardware,
        clock_anchor.clone(),
        Arc::clone(&backend_label),
        Arc::clone(&hardware_video_active),
        Arc::clone(&wake_guard),
        updates,
    );

    let mut host = HostSession::new(host_cfg, DEV_CERT_PEM, DEV_KEY_PEM, Arc::clone(&clock))
        .map_err(|e| format!("host 会话构造失败: {e}"))?;
    let _ = host.set_reconnect(rc_session::ReconnectConfig {
        resume_ttl: host_resume_ttl(HostTransportKind::Lan),
        ..rc_session::ReconnectConfig::default()
    });
    host.set_preserve_caps_aspect(preserve_aspect);
    host.set_pipeline_factory_for(factory);
    if clipboard_enabled {
        if let Some(cb) = create_clipboard_backend(prefer_hardware) {
            host.enable_clipboard(cb);
        }
    }

    Ok(BuiltUiHost {
        host,
        clock,
        clock_anchor,
        backend_label,
        hardware_video_active,
        wake_guard,
    })
}

/// 构造一轮基于已建立传输层（LAN mTLS、P2P QUIC 或 TCP `RCR1` 中继）的 `HostSession`。
#[allow(clippy::too_many_arguments)]
pub(super) fn build_transport_host_session(
    listen_addr: SocketAddr,
    transport: Box<dyn Transport>,
    transport_kind: HostTransportKind,
    password: Option<String>,
    approval_timeout_us: u64,
    prefer_hardware: bool,
    clipboard_enabled: bool,
    allow_owner_control: bool,
    allow_remote_assist: bool,
    owner_verifier: Option<Arc<dyn OwnerTicketVerifier>>,
    owner_replay_cache: Arc<Mutex<rc_session::OwnerReplayCache>>,
    approver: Box<dyn ConnectionApprover>,
    updates: Arc<BoundedHostUpdateQueue>,
) -> Result<BuiltUiHost, String> {
    let (host_cfg, preserve_aspect) = default_host_session_config(
        listen_addr,
        password,
        approval_timeout_us,
        prefer_hardware,
        allow_owner_control,
        allow_remote_assist,
        owner_verifier,
        owner_replay_cache,
        approver,
    );

    let clock_anchor = HostClockAnchor::new_pending();
    let clock = make_session_clock(Arc::clone(&clock_anchor.origin));
    let backend_label: Arc<Mutex<String>> = Arc::new(Mutex::new(if prefer_hardware {
        "auto".to_string()
    } else {
        "fake".to_string()
    }));
    let hardware_video_active = Arc::new(AtomicBool::new(false));
    let wake_guard: SharedWakeGuard = Arc::new(Mutex::new(None));

    // 占位后端仅用于满足 `HostSession::with_parts` 签名；握手成功后优先执行
    // `set_pipeline_factory_for`，按裁定参数构建硬件/假栈并锚定会话钟零点。
    let placeholder_res = Resolution::new(64, 64);
    let dummy_capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
        display: rc_capture::DisplayInfo {
            id: rc_types::DisplayId(0),
            resolution: placeholder_res,
            scale: 1.0,
            hdr: false,
        },
        fps: 30,
        content: rc_capture::FakeContent::Static,
        dirty_rect: None,
    })
    .map_err(|e| format!("会话占位采集构造失败: {e}"))?;
    let dummy_encoder = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
        resolution: placeholder_res,
        fps: 30,
        bitrate_bps: 2_000_000,
        ..rc_encode::EncoderConfig::default()
    })
    .map_err(|e| format!("会话占位编码构造失败: {e}"))?;

    let mut host = HostSession::with_parts(
        host_cfg,
        transport,
        Box::new(dummy_capture),
        Box::new(dummy_encoder),
        Arc::clone(&clock),
    )
    .map_err(|e| format!("信令 host 会话构造失败: {e}"))?;
    let _ = host.set_reconnect(rc_session::ReconnectConfig {
        resume_ttl: host_resume_ttl(transport_kind),
        ..rc_session::ReconnectConfig::default()
    });
    host.set_preserve_caps_aspect(preserve_aspect);

    let factory = make_host_pipeline_factory(
        prefer_hardware,
        clock_anchor.clone(),
        Arc::clone(&backend_label),
        Arc::clone(&hardware_video_active),
        Arc::clone(&wake_guard),
        updates,
    );
    host.set_pipeline_factory_for(factory);
    if clipboard_enabled {
        if let Some(cb) = create_clipboard_backend(prefer_hardware) {
            host.enable_clipboard(cb);
        }
    }

    Ok(BuiltUiHost {
        host,
        clock,
        clock_anchor,
        backend_label,
        hardware_video_active,
        wake_guard,
    })
}

fn build_injector(prefer_hardware: bool) -> Box<dyn rc_input::InputInjector> {
    if prefer_hardware {
        if let Some(injector) = crate::platform::create_main_display_injector() {
            return injector;
        }
    }
    Box::new(RecordingInjector::new())
}

fn real_host_stack(
    hw_cfg: &PipelineConfig,
    existing_origin_us: Option<u64>,
) -> rc_types::Result<(rc_pipeline::HostPipeline, String, u64)> {
    let (encoder, el) = rc_pipeline::select_encoder_labeled(hw_cfg)?;
    let origin_us = match existing_origin_us {
        Some(o) => o,
        None => rc_pipeline::host_clock_us()
            .ok_or_else(|| rc_types::Error::InvalidConfig("平台未注册低延迟主机时钟".into()))?,
    };
    // 顺序红线：先锚定原点再建 SCK 流，保证硬件 PTS 与会话钟同域同零点。
    let mut pcfg = hw_cfg.clone();
    pcfg.clock_origin_us = Some(origin_us);
    let (capture, cl) = rc_pipeline::select_capture_labeled(&pcfg)?;
    if el == "fake" || cl == "fake" {
        return Err(rc_types::Error::InvalidConfig(format!(
            "real 后端要求真实硬件采集与编码，实际 {cl}+{el}"
        )));
    }
    let pipeline = rc_pipeline::HostPipeline::with_backends_paced(pcfg, capture, encoder, false)?;
    Ok((pipeline, format!("{cl}+{el}"), origin_us))
}

pub(super) fn fake_stack_anchored(
    pcfg: &PipelineConfig,
    existing_anchor: Option<Instant>,
) -> rc_types::Result<(rc_pipeline::HostPipeline, Instant)> {
    let anchor = existing_anchor.unwrap_or_else(Instant::now);
    let capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
        display: rc_capture::DisplayInfo {
            id: rc_types::DisplayId(0),
            resolution: pcfg.resolution,
            scale: 1.0,
            hdr: false,
        },
        fps: pcfg.fps,
        content: rc_capture::FakeContent::Dynamic,
        dirty_rect: None,
    })?;
    let pixels = pcfg.resolution.width as usize * pcfg.resolution.height as usize;
    const SINGLE_PACKET_PAYLOAD: usize = 1_088;
    let output_bytes = (pixels / 8).clamp(128, SINGLE_PACKET_PAYLOAD);
    let encoder = rc_encode::FakeEncoder::with_tuning(
        rc_encode::EncoderConfig {
            resolution: pcfg.resolution,
            fps: pcfg.fps,
            bitrate_bps: pcfg.bitrate_bps,
            ..rc_encode::EncoderConfig::default()
        },
        FAKE_ENCODE_COST_US,
        output_bytes,
    )?;
    let pipeline = rc_pipeline::HostPipeline::with_backends_paced(
        pcfg.clone(),
        Box::new(WallCapture {
            inner: Box::new(capture),
            anchor,
        }),
        Box::new(encoder),
        true,
    )?;
    Ok((pipeline, anchor))
}

struct WallCapture {
    inner: Box<dyn rc_capture::CaptureBackend>,
    anchor: Instant,
}

impl rc_capture::CaptureBackend for WallCapture {
    fn next_frame(
        &mut self,
        timeout: Duration,
    ) -> rc_types::Result<Option<rc_capture::CapturedFrame>> {
        match self.inner.next_frame(timeout)? {
            Some(mut frame) => {
                frame.timestamp = rc_types::Timestamp(
                    u32::try_from(self.anchor.elapsed().as_micros()).unwrap_or(u32::MAX),
                );
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    fn poll_invalidation(&mut self) -> Option<rc_capture::InvalidationReason> {
        self.inner.poll_invalidation()
    }

    fn rebuild(&mut self) -> rc_types::Result<()> {
        self.inner.rebuild()
    }

    fn display_info(&self) -> rc_capture::DisplayInfo {
        self.inner.display_info()
    }

    fn last_dirty_rects(&self) -> &[rc_types::Rect] {
        self.inner.last_dirty_rects()
    }
}

pub use crate::bridge_shared::collect_host_lan_addrs;
#[cfg(test)]
pub(super) use crate::bridge_shared::format_host_lan_addrs_from_ips;

pub(super) fn format_display_addr(actual: SocketAddr) -> String {
    if actual.ip().is_unspecified() {
        let ip = lan_discovery::detect_local_lan_ipv4().unwrap_or(Ipv4Addr::LOCALHOST);
        format!("{ip}:{}", actual.port())
    } else {
        actual.to_string()
    }
}
