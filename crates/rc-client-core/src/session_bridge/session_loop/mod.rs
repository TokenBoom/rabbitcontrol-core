use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rc_audio::AudioPlayer;
use rc_session::proto::{ByeReason, ControllerMeta, SessionParams};
use rc_session::{
    ClientSession, SessionClock, SessionState, ToolPermissions, TOOL_CHANNEL_DISPLAY_CTRL,
};
use rc_tools::{PortMapRuleSnapshot, TerminalEvent};

use crate::app_prefs::ConnectionMode;
use crate::codec_selector::{self, CodecSelectionPref};
use crate::display_ctrl::{self, DisplayControlMsg, StreamCodec};
use crate::hud::{HudSample, HudSnapshot};
use crate::platform::PreallocatedRenderSurface;
use crate::switchable_transport::{
    CandidateTransport, HysteresisConfig, RuntimePathMonitor, SwitchControlMsg, SwitchHandle,
    TransportPathKind,
};

use super::adapters::{
    encode_audio_ctrl_muted, ActiveRelayInterrupt, LayerLease, RelayInterruptSlotGuard,
    RendererHandle,
};
use super::classify::classify_stop_reason_end;
use super::connect::{
    build_initial_pipeline_config, clamp_meta_field, compute_controller_meta_mode,
    establish_session, reanchorable_clock, BgP2pUpgradeRx, ConnectEnv, EstablishedSession,
};
use super::display_ctrl::{build_client_media_caps_msg, sample_hud};
use super::handle::ScrollDispatchState;
use super::queues::{BoundedInputQueue, BoundedQueue, BoundedUpdateQueue, ZeroizingByteQueue};
use super::routing::{
    effective_connection_mode, path_kind_from_transport_label, sync_relay_rtt_ctrl_for_path,
    RelayRttController,
};
use super::tools::{FileClientWorker, ToolClientHub};
use super::types::{ConnectPhase, SessionCommand, SessionEnd, SessionUpdate, UiSessionConfig};

mod commands;
mod path_switch;
mod reconnect;
mod tick;

/// 会话线程入口入参包。
pub(in crate::session_bridge) struct SessionThreadArgs<'a> {
    pub(in crate::session_bridge) cfg: UiSessionConfig,
    pub(in crate::session_bridge) render_surface: Arc<Mutex<Option<PreallocatedRenderSurface>>>,
    pub(in crate::session_bridge) cmd_rx: Arc<BoundedQueue<SessionCommand>>,
    pub(in crate::session_bridge) display_ctrl_rx: Arc<BoundedQueue<DisplayControlMsg>>,
    pub(in crate::session_bridge) input_rx: Arc<BoundedInputQueue>,
    pub(in crate::session_bridge) update_tx: Arc<BoundedUpdateQueue>,
    pub(in crate::session_bridge) layer_lease: Arc<Mutex<Option<LayerLease>>>,
    pub(in crate::session_bridge) disconnect_flag: Arc<AtomicBool>,
    pub(in crate::session_bridge) lock_on_disconnect: Arc<AtomicBool>,
    pub(in crate::session_bridge) relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    pub(in crate::session_bridge) tools_hub: Arc<Mutex<ToolClientHub>>,
    pub(in crate::session_bridge) file_worker: &'a FileClientWorker,
    pub(in crate::session_bridge) terminal_events: Arc<BoundedQueue<TerminalEvent>>,
    pub(in crate::session_bridge) portmap_latest: Arc<Mutex<Option<Vec<PortMapRuleSnapshot>>>>,
    pub(in crate::session_bridge) watch_only: Arc<AtomicBool>,
    pub(in crate::session_bridge) tool_permissions: Arc<Mutex<ToolPermissions>>,
    pub(in crate::session_bridge) still_refine_metrics:
        Arc<Mutex<crate::still_refine::StillRefineMetrics>>,
    pub(in crate::session_bridge) scroll_state: Arc<ScrollDispatchState>,
}

/// 单拍驱动循环控制流指令（精确对应主 `while` 循环中的继续 / `continue` / `break` / 早退 `return Err`）。
pub(super) enum LoopStep {
    Continue,
    NextIter,
    Break,
    ReturnErr(SessionEnd),
}

pub(super) struct SessionLoopState<'a> {
    pub(super) cfg: UiSessionConfig,
    pub(super) t0: Instant,
    pub(super) clock_anchor: Arc<Mutex<Instant>>,
    pub(super) clock_reader: SessionClock,
    pub(super) initial_controller_meta: ControllerMeta,
    pub(super) last_sent_controller_mode: u8,

    pub(super) render_surface: Arc<Mutex<Option<PreallocatedRenderSurface>>>,
    pub(super) cmd_rx: Arc<BoundedQueue<SessionCommand>>,
    pub(super) display_ctrl_rx: Arc<BoundedQueue<DisplayControlMsg>>,
    pub(super) input_rx: Arc<BoundedInputQueue>,
    pub(super) update_tx: Arc<BoundedUpdateQueue>,
    pub(super) layer_lease: Arc<Mutex<Option<LayerLease>>>,
    pub(super) disconnect_flag: Arc<AtomicBool>,
    pub(super) lock_on_disconnect: Arc<AtomicBool>,
    pub(super) tools_hub: Arc<Mutex<ToolClientHub>>,
    pub(super) file_worker: &'a FileClientWorker,
    pub(super) terminal_events: Arc<BoundedQueue<TerminalEvent>>,
    pub(super) portmap_latest: Arc<Mutex<Option<Vec<PortMapRuleSnapshot>>>>,
    pub(super) live_watch_only: Arc<AtomicBool>,
    pub(super) tool_permissions: Arc<Mutex<ToolPermissions>>,
    pub(super) still_refine_metrics: Arc<Mutex<crate::still_refine::StillRefineMetrics>>,
    pub(super) scroll_state: Arc<ScrollDispatchState>,

    pub(super) pending_control: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub(super) backend_label: Arc<Mutex<String>>,
    pub(super) renderer_handle: Arc<Mutex<Option<RendererHandle>>>,
    pub(super) renderer_pending_resize: Arc<Mutex<Arc<AtomicU64>>>,
    pub(super) is_signaling_session: bool,
    pub(super) clipboard_enabled_flag: Arc<AtomicBool>,
    pub(super) want_real_pipeline: Arc<AtomicBool>,
    pub(super) real_pipeline_built: Arc<AtomicBool>,
    pub(super) is_hw_decoder_slot: Arc<AtomicBool>,

    pub(super) client: ClientSession,
    pub(super) negotiated: SessionParams,
    pub(super) transport_label: &'static str,
    pub(super) active_backend_suffix: Option<&'static str>,
    pub(super) mtls_active: bool,
    pub(super) peer_cert_fingerprint: Option<String>,
    pub(super) switch_handle: Option<SwitchHandle>,
    pub(super) bg_p2p_upgrade_rx: Option<BgP2pUpgradeRx>,
    pub(super) bg_p2p_cancel_slot: Option<Arc<AtomicBool>>,
    pub(super) grant_obtained_at: Instant,
    pub(super) initial_relay_token_consumed: bool,
    pub(super) proxy_active_runtime: bool,
    pub(super) runtime_mode: ConnectionMode,

    pub(super) backend: String,
    pub(super) is_hardware_decoder: bool,
    pub(super) audio_player: Option<Box<dyn AudioPlayer>>,
    pub(super) audio_player_format: Option<(u32, u8)>,
    pub(super) audio_muted: bool,
    pub(super) pending_audio_ctrl: Option<Vec<u8>>,

    pub(super) prev_hud: HudSample,
    pub(super) last_hud_at: Instant,
    pub(super) stream_started_at: Instant,
    pub(super) first_frame_logged: bool,
    pub(super) decode_error_logged: bool,
    pub(super) last_portmap_poll_at: Instant,
    pub(super) last_portmap_snapshot: Vec<PortMapRuleSnapshot>,

    pub(super) pending_file_in: VecDeque<Vec<u8>>,
    pub(super) pending_file_tx: VecDeque<Vec<u8>>,
    pub(super) pending_term_tx: VecDeque<Vec<u8>>,
    pub(super) pending_portmap_tx: VecDeque<Vec<u8>>,
    pub(super) pending_display_tx: ZeroizingByteQueue,
    pub(super) pending_update_tx: VecDeque<(bool, Vec<u8>)>,

    pub(super) client_decode_caps: Vec<rc_pipeline::CodecCapability>,
    pub(super) client_supports_hevc: bool,
    pub(super) client_supports_av1: bool,
    pub(super) active_codec: StreamCodec,
    pub(super) user_pinned_codec: Option<StreamCodec>,
    pub(super) host_supports_hevc: bool,
    pub(super) host_supports_ext_codec_flags: bool,
    pub(super) host_codec_generation: u64,
    pub(super) pending_unrecovered_decode_failure: Option<(rc_encode::Codec, u64, String)>,
    pub(super) legacy_hevc_requested: bool,
    pub(super) still_refinement_enabled: bool,
    pub(super) pending_still_clear: bool,
    pub(super) still_receiver: crate::still_refine::StillRefineReceiver,

    pub(super) hud_width: u32,
    pub(super) hud_height: u32,
    pub(super) current_fps: u32,
    pub(super) active_path_kind: TransportPathKind,
    pub(super) path_monitor: RuntimePathMonitor,
    pub(super) last_path_sample_at: Instant,
    pub(super) runtime_switch_inflight: Option<u8>,
    pub(super) last_seen_committed: u64,
    pub(super) last_seen_aborted: u64,
    pub(super) degrade_rx: Option<mpsc::Receiver<Result<CandidateTransport, String>>>,
    pub(super) reprobe_rx: Option<mpsc::Receiver<Result<CandidateTransport, String>>>,
    pub(super) reprobe_answer_tx: Option<mpsc::Sender<SwitchControlMsg>>,

    pub(super) last_manual_bitrate_bps: Option<u32>,
    pub(super) relay_rtt_ctrl: Option<RelayRttController>,
    pub(super) last_busy: bool,
    pub(super) epoch_sid: u64,
    pub(super) disconnect_requested: bool,
    pub(super) end_state: SessionEnd,
    pub(super) in_reconnecting: bool,
    pub(super) reconnect_base_attempts: u32,
    pub(super) last_emitted_reconnect_attempt: u32,
    pub(super) last_stage_rect: Option<(u32, u32)>,
    pub(super) pending_desktop_upgrade: bool,
    pub(super) update_relay: crate::updater::ControllerUpdateRelay,
    pub(super) awaiting_host_relay_finish: bool,
    pub(super) active_update_request_id: u64,
    pub(super) peer_tool_perms: ToolPermissions,
    pub(super) last_local_tool_denied: [Option<Instant>; 8],
}

pub(in crate::session_bridge) fn run_session_thread(
    args: SessionThreadArgs<'_>,
) -> Result<SessionEnd, SessionEnd> {
    let relay_interrupt = Arc::clone(&args.relay_interrupt);
    let _relay_guard = RelayInterruptSlotGuard {
        slot: &relay_interrupt,
    };

    if args.disconnect_flag.load(Ordering::Acquire) {
        return Ok(SessionEnd::fatal("用户主动断开"));
    }

    // 严禁静默降级：开启加密连接但缺少 mTLS 证书束时立即拒绝建连。
    if args.cfg.encrypt_connection && args.cfg.mtls_config.is_none() {
        return Err(SessionEnd::fatal(
            "已开启「加密连接 (mTLS)」，但缺少设备证书配置，已拒绝降级连接",
        ));
    }

    let effective_mode = effective_connection_mode(&args.cfg);

    // ── 计时起点：Endpoint 创建之前（T21 U8 / 坑 11，对齐 T18 口径）──
    let t0 = Instant::now();
    let (clock, clock_anchor) = reanchorable_clock(t0);
    let clock_reader = Arc::clone(&clock);
    let live_watch_only = Arc::clone(&args.watch_only);

    let last_sent_controller_mode =
        compute_controller_meta_mode(live_watch_only.load(Ordering::Acquire), args.cfg.tools_only);
    let initial_controller_meta = ControllerMeta {
        device_id: clamp_meta_field(args.cfg.self_device_id.as_deref().unwrap_or("")),
        device_name: clamp_meta_field(args.cfg.self_device_name.as_deref().unwrap_or("")),
        os: clamp_meta_field(args.cfg.self_os.as_deref().unwrap_or(std::env::consts::OS)),
        mode: last_sent_controller_mode,
    };

    let pipeline_cfg = build_initial_pipeline_config(&args.cfg);
    let pending_control: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
    let backend_label: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let renderer_handle: Arc<Mutex<Option<RendererHandle>>> = Arc::new(Mutex::new(None));
    let renderer_pending_resize: Arc<Mutex<Arc<AtomicU64>>> =
        Arc::new(Mutex::new(Arc::new(AtomicU64::new(0))));
    let is_signaling_session = args.cfg.relay_grant.is_some();
    let streaming_started = Arc::new(AtomicBool::new(false));
    let clipboard_enabled_flag = Arc::new(AtomicBool::new(args.cfg.clipboard_enabled));
    let want_real_pipeline = Arc::new(AtomicBool::new(!args.cfg.tools_only));
    let real_pipeline_built = Arc::new(AtomicBool::new(false));
    let is_hw_decoder_slot = Arc::new(AtomicBool::new(false));

    let connect_env = ConnectEnv {
        cfg: &args.cfg,
        t0,
        clock,
        pipeline_cfg,
        initial_controller_meta: initial_controller_meta.clone(),
        effective_mode,
        render_surface: Arc::clone(&args.render_surface),
        input_rx: Arc::clone(&args.input_rx),
        update_tx: Arc::clone(&args.update_tx),
        layer_lease: Arc::clone(&args.layer_lease),
        disconnect_flag: Arc::clone(&args.disconnect_flag),
        relay_interrupt: Arc::clone(&args.relay_interrupt),
        live_watch_only: Arc::clone(&live_watch_only),
        pending_control: Arc::clone(&pending_control),
        backend_label: Arc::clone(&backend_label),
        renderer_handle: Arc::clone(&renderer_handle),
        renderer_pending_resize: Arc::clone(&renderer_pending_resize),
        streaming_started: Arc::clone(&streaming_started),
        clipboard_enabled_flag: Arc::clone(&clipboard_enabled_flag),
        want_real_pipeline: Arc::clone(&want_real_pipeline),
        real_pipeline_built: Arc::clone(&real_pipeline_built),
        is_hw_decoder_slot: Arc::clone(&is_hw_decoder_slot),
    };

    let established = match establish_session(&connect_env) {
        Ok(est) => est,
        Err(end_res) => return end_res,
    };
    drop(connect_env);

    let mut state = SessionLoopState::from_established(
        args,
        established,
        t0,
        clock_anchor,
        clock_reader,
        initial_controller_meta,
        last_sent_controller_mode,
        live_watch_only,
        pending_control,
        backend_label,
        renderer_handle,
        renderer_pending_resize,
        is_signaling_session,
        streaming_started,
        clipboard_enabled_flag,
        want_real_pipeline,
        real_pipeline_built,
        is_hw_decoder_slot,
    );

    let _activity =
        crate::platform::begin_latency_critical_activity("RabbitControl 远控会话", true);

    // ── 驱动循环（无 duration 上限，直到 Disconnect 或对端 Bye/错误）──
    while state.client.state() != SessionState::Closed {
        state.sync_controller_meta();
        state.process_ui_commands();
        state.process_display_ctrl_commands();

        if state.disconnect_requested || state.disconnect_flag.load(Ordering::Acquire) {
            state.end_state = SessionEnd::fatal("用户主动断开");
            break;
        }

        // 2) 驱动会话状态机。
        let step = match state.client.state() {
            SessionState::Streaming => state.tick_streaming(),
            SessionState::Reconnecting => state.tick_reconnecting(),
            _ => {
                if let Some(stop) = state.client.closed_reason() {
                    state.end_state = classify_stop_reason_end(stop);
                }
                LoopStep::Break
            }
        };
        match step {
            LoopStep::Continue => {}
            LoopStep::NextIter => continue,
            LoopStep::Break => break,
            LoopStep::ReturnErr(err) => return Err(err),
        }

        // 4) 纪元检测：T17 全新重建时重锚会话钟（同 rc-cli/src/cmd/client.rs）。
        state.check_epoch_reanchor();
    }

    Ok(state.shutdown())
}

impl<'a> SessionLoopState<'a> {
    #[allow(clippy::too_many_arguments)]
    fn from_established(
        args: SessionThreadArgs<'a>,
        mut est: EstablishedSession,
        t0: Instant,
        clock_anchor: Arc<Mutex<Instant>>,
        clock_reader: SessionClock,
        initial_controller_meta: ControllerMeta,
        last_sent_controller_mode: u8,
        live_watch_only: Arc<AtomicBool>,
        pending_control: Arc<Mutex<VecDeque<Vec<u8>>>>,
        backend_label: Arc<Mutex<String>>,
        renderer_handle: Arc<Mutex<Option<RendererHandle>>>,
        renderer_pending_resize: Arc<Mutex<Arc<AtomicU64>>>,
        is_signaling_session: bool,
        streaming_started: Arc<AtomicBool>,
        clipboard_enabled_flag: Arc<AtomicBool>,
        want_real_pipeline: Arc<AtomicBool>,
        real_pipeline_built: Arc<AtomicBool>,
        is_hw_decoder_slot: Arc<AtomicBool>,
    ) -> Self {
        est.client
            .set_peer_idle_timeout_us(ClientSession::PEER_IDLE_TIMEOUT_US);
        args.scroll_state
            .update_peer_capability(est.client.peer_supports_pixel_scroll());
        args.input_rx
            .set_wake_handle(est.client.transport_wake_handle());
        streaming_started.store(true, Ordering::Release);

        let backend = backend_label
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let is_hardware_decoder = is_hw_decoder_slot.load(Ordering::Acquire);

        let live_wo = live_watch_only.load(Ordering::Acquire);
        args.update_tx.push(SessionUpdate::Connecting {
            phase: ConnectPhase::FirstFramePending,
            watch_only: live_wo,
        });
        args.update_tx.push(SessionUpdate::Negotiated {
            width: est.negotiated.width,
            height: est.negotiated.height,
            fps: est.negotiated.fps,
            bitrate_bps: est.negotiated.bitrate_bps,
            backend: backend.clone(),
            watch_only: live_wo,
            transport: est.transport_label.to_string(),
            mtls_active: est.mtls_active,
            peer_cert_fingerprint: est.peer_cert_fingerprint.clone(),
        });

        let audio_muted = !args.cfg.audio_enabled;
        let pending_audio_ctrl = audio_muted.then(|| encode_audio_ctrl_muted(true));

        // 初始 HUD 快照（prev = None → fps/bitrate 均为 0.0）。
        let initial_sample = sample_hud(&est.client, &clock_reader, est.negotiated);
        args.update_tx
            .push(SessionUpdate::Hud(HudSnapshot::derive_with_transport(
                None,
                &initial_sample,
                est.transport_label,
            )));

        let client_decode_caps = codec_selector::cached_or_platform_decode_caps(
            args.cfg.prefer_hardware && is_hardware_decoder,
        );
        let client_supports_hevc = args.cfg.prefer_hardware
            && is_hardware_decoder
            && (rc_pipeline::platform_supports_hevc()
                || client_decode_caps
                    .iter()
                    .any(|c| c.codec == rc_encode::Codec::Hevc && c.hardware));
        let client_supports_av1 = args.cfg.prefer_hardware
            && is_hardware_decoder
            && client_decode_caps
                .iter()
                .any(|c| c.codec == rc_encode::Codec::Av1 && c.hardware);

        let mut pending_display_tx = ZeroizingByteQueue::new();
        if args.cfg.tools_only {
            est.client.set_media_paused(true);
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetMediaPaused {
                    paused: true,
                })
            {
                pending_display_tx.push_back(payload);
            }
        } else if let Some(payload) =
            display_ctrl::encode_display_ctrl(&build_client_media_caps_msg(
                &client_decode_caps,
                args.cfg.prefer_hardware && is_hardware_decoder,
                CodecSelectionPref::Auto,
            ))
        {
            pending_display_tx.push_back(payload);
        }

        let active_path_kind = est.switch_handle.as_ref().map_or_else(
            || path_kind_from_transport_label(est.transport_label),
            |h| h.active_kind(),
        );
        let path_monitor = RuntimePathMonitor::with_initial_path(
            HysteresisConfig::default(),
            active_path_kind,
            Instant::now(),
        );
        let last_seen_committed = est
            .switch_handle
            .as_ref()
            .map_or(0, |h| h.switches_committed());
        let last_seen_aborted = est
            .switch_handle
            .as_ref()
            .map_or(0, |h| h.switches_aborted());
        let relay_rtt_ctrl = sync_relay_rtt_ctrl_for_path(
            active_path_kind,
            est.negotiated.bitrate_bps,
            Instant::now(),
        );
        let epoch_sid = est.client.session_id();
        let still_receiver = crate::still_refine::StillRefineReceiver::new(
            1,
            est.negotiated.width,
            est.negotiated.height,
        );

        Self {
            cfg: args.cfg,
            t0,
            clock_anchor,
            clock_reader,
            initial_controller_meta,
            last_sent_controller_mode,
            render_surface: args.render_surface,
            cmd_rx: args.cmd_rx,
            display_ctrl_rx: args.display_ctrl_rx,
            input_rx: args.input_rx,
            update_tx: args.update_tx,
            layer_lease: args.layer_lease,
            disconnect_flag: args.disconnect_flag,
            lock_on_disconnect: args.lock_on_disconnect,
            tools_hub: args.tools_hub,
            file_worker: args.file_worker,
            terminal_events: args.terminal_events,
            portmap_latest: args.portmap_latest,
            live_watch_only,
            tool_permissions: args.tool_permissions,
            still_refine_metrics: args.still_refine_metrics,
            scroll_state: args.scroll_state,
            pending_control,
            backend_label,
            renderer_handle,
            renderer_pending_resize,
            is_signaling_session,
            clipboard_enabled_flag,
            want_real_pipeline,
            real_pipeline_built,
            is_hw_decoder_slot,
            client: est.client,
            negotiated: est.negotiated,
            transport_label: est.transport_label,
            active_backend_suffix: est.active_backend_suffix,
            mtls_active: est.mtls_active,
            peer_cert_fingerprint: est.peer_cert_fingerprint,
            switch_handle: est.switch_handle,
            bg_p2p_upgrade_rx: est.bg_p2p_upgrade_rx,
            bg_p2p_cancel_slot: est.bg_p2p_cancel_slot,
            grant_obtained_at: est.grant_obtained_at,
            initial_relay_token_consumed: est.initial_relay_token_consumed,
            proxy_active_runtime: est.proxy_active_runtime,
            runtime_mode: est.runtime_mode,
            backend,
            is_hardware_decoder,
            audio_player: None,
            audio_player_format: None,
            audio_muted,
            pending_audio_ctrl,
            prev_hud: initial_sample,
            last_hud_at: Instant::now(),
            stream_started_at: Instant::now(),
            first_frame_logged: false,
            decode_error_logged: false,
            last_portmap_poll_at: Instant::now(),
            last_portmap_snapshot: Vec::new(),
            pending_file_in: VecDeque::new(),
            pending_file_tx: VecDeque::new(),
            pending_term_tx: VecDeque::new(),
            pending_portmap_tx: VecDeque::new(),
            pending_display_tx,
            pending_update_tx: VecDeque::new(),
            client_decode_caps,
            client_supports_hevc,
            client_supports_av1,
            active_codec: StreamCodec::H264,
            user_pinned_codec: None,
            host_supports_hevc: false,
            host_supports_ext_codec_flags: false,
            host_codec_generation: 1,
            pending_unrecovered_decode_failure: None,
            legacy_hevc_requested: false,
            still_refinement_enabled: true,
            pending_still_clear: false,
            still_receiver,
            hud_width: est.negotiated.width,
            hud_height: est.negotiated.height,
            current_fps: est.negotiated.fps,
            active_path_kind,
            path_monitor,
            last_path_sample_at: Instant::now(),
            runtime_switch_inflight: None,
            last_seen_committed,
            last_seen_aborted,
            degrade_rx: None,
            reprobe_rx: None,
            reprobe_answer_tx: None,
            last_manual_bitrate_bps: None,
            relay_rtt_ctrl,
            last_busy: true,
            epoch_sid,
            disconnect_requested: false,
            end_state: SessionEnd::fatal("会话已结束"),
            in_reconnecting: false,
            reconnect_base_attempts: 0,
            last_emitted_reconnect_attempt: 0,
            last_stage_rect: None,
            pending_desktop_upgrade: false,
            update_relay: crate::updater::ControllerUpdateRelay::new(),
            awaiting_host_relay_finish: false,
            active_update_request_id: 0,
            peer_tool_perms: ToolPermissions::all_allowed(),
            last_local_tool_denied: [None; 8],
        }
    }

    fn check_epoch_reanchor(&mut self) {
        if self.client.session_id() != self.epoch_sid {
            self.epoch_sid = self.client.session_id();
            *self.clock_anchor.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            self.client.reset_clipboard_epoch();
            self.client
                .reset_activity_clock(u64::from((self.clock_reader)()));
        }
    }

    fn shutdown(mut self) -> SessionEnd {
        if let Some(ref mut player) = self.audio_player {
            player.stop();
        }
        drop(self.audio_player);
        if let Some(bg_cancel) = self.bg_p2p_cancel_slot {
            bg_cancel.store(true, Ordering::Release);
        }

        if self.lock_on_disconnect.load(Ordering::Acquire)
            && self.client.state() == SessionState::Streaming
        {
            if let Some(payload) = display_ctrl::encode_display_ctrl(&DisplayControlMsg::LockScreen)
            {
                if self
                    .client
                    .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, payload)
                    .is_ok()
                {
                    let flush_until = Instant::now() + Duration::from_millis(150);
                    while Instant::now() < flush_until
                        && self.client.state() == SessionState::Streaming
                    {
                        let _ = self.client.tick(Duration::from_millis(5), Instant::now());
                        thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        }

        // 优雅关闭（若尚未 Closed，发 Bye(Normal) 并执行 S6 停机序列）。
        if self.client.state() != SessionState::Closed {
            let _ = self.client.close(ByeReason::Normal);
        }

        self.end_state
    }
}
