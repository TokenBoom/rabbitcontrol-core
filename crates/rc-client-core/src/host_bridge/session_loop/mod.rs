mod detached;
mod display_ctrl_features;
mod display_ctrl_media;
mod io_pump;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rc_audio::AudioSilenceGate;
use rc_net::quic::QuicEndpoint;
use rc_session::proto::ByeReason;
use rc_session::{
    HostSession, SessionClock, SessionState, StopReason, ToolPermissions, TOOL_CHANNEL_DISPLAY_CTRL,
};
use rc_tools::{PortMapHostEngine, TerminalHostEngine};
use rc_types::Resolution;

use crate::codec_selector::{self, HostCodecNegotiator, NetworkHint};
use crate::display_ctrl::{self, DisplayControlMsg};

use super::audio_bwe::{HostAudioManager, RelayBitrateController};
use super::media_aux::{
    build_hardware_display_presets, build_session_display_caps_params, compute_host_display_bounds,
    encode_host_display_caps, encode_host_displays_state, HostDisplayModeSession,
    HostHardwareCleanupGuard, MidSessionWakeDriver, WakeGuardReleaser,
};
use super::pipeline_factory::{host_hardware_display_backing, HostClockAnchor};
use super::queues::{
    build_active_controller_session, clear_active_controllers, publish_active_controller,
    unix_now_ms, BoundedHostUpdateQueue, BoundedRelayIncomingQueue, BusyLanRejectWorker,
    HostDisplayCtrlOutbox, PersistentOwnerTerminals,
};
#[cfg(test)]
use super::tests::mock::{TestHostMediaOverride, TestHostPlatformMock};
use super::tools_worker::{
    compute_effective_tool_permissions, encode_terminal_lock_state, encode_tool_permissions_state,
    FileHostWorker, TerminalLockGate, TerminalVerifyDriver,
};
use super::types::{
    AuthRuntimeState, DriveSessionOutcome, HostControllerTracking, HostSwitchRuntime,
    HostTransportKind, SharedFileTransferDir, SharedWakeGuard,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LoopControl {
    Continue,
    Break,
}

pub(super) struct SessionLoopCtx<'a> {
    pub(super) host: &'a mut HostSession,
    pub(super) clock: &'a SessionClock,
    pub(super) clock_anchor: Option<&'a HostClockAnchor>,
    pub(super) updates: &'a BoundedHostUpdateQueue,
    pub(super) password_version: &'a AtomicU64,
    pub(super) observed_pw_ver: u64,
    pub(super) config_version: &'a AtomicU64,
    pub(super) observed_cfg_ver: u64,
    pub(super) disconnect_flag: &'a AtomicBool,
    pub(super) stop_flag: &'a AtomicBool,
    pub(super) close_reason: &'a AtomicU8,
    pub(super) transport_kind: HostTransportKind,
    pub(super) prefer_hardware: bool,
    pub(super) hardware_video_active: bool,
    pub(super) hardware_media_active: bool,
    pub(super) hw_display_ops_active: bool,
    pub(super) lock_screen_count: &'a AtomicU64,
    pub(super) auth_state: Option<&'a Mutex<AuthRuntimeState>>,
    pub(super) owner_terminals: &'a mut PersistentOwnerTerminals,
    pub(super) wake_guard: SharedWakeGuard,
    pub(super) file_transfer_dir: SharedFileTransferDir,
    pub(super) allow_assist_file_transfer: &'a AtomicBool,
    pub(super) incoming_relay: Option<&'a Arc<BoundedRelayIncomingQueue>>,
    pub(super) active_peer_id: Option<String>,
    pub(super) session_started_at: Instant,
    pub(super) audio_mgr: HostAudioManager,
    pub(super) switch_rt: Option<HostSwitchRuntime>,
    pub(super) controller_tracking: Option<HostControllerTracking>,

    pub(super) hw_cleanup: HostHardwareCleanupGuard,
    pub(super) active_display_id: Option<u32>,
    pub(super) virtual_display_hidpi: HashMap<u32, bool>,
    pub(super) shows_cursor: bool,

    pub(super) detached_reason: Option<String>,
    pub(super) drive_err: Option<String>,
    pub(super) pending_lock_on_exit: bool,
    pub(super) preempted_by_incoming: bool,
    pub(super) preempted_by_takeover: bool,
    pub(super) force_disconnected: bool,
    pub(super) last_preempt_check: Instant,
    pub(super) epoch_reanchored_in_detached: bool,

    pub(super) file_worker: FileHostWorker,
    pub(super) guest_term_host: TerminalHostEngine,
    pub(super) use_owner_terminals: bool,
    pub(super) portmap_host: PortMapHostEngine,
    pub(super) update_worker: crate::updater::HostUpdateWorker,
    pub(super) pending_file_in: VecDeque<Vec<u8>>,
    pub(super) pending_file_tx: VecDeque<Vec<u8>>,
    pub(super) pending_term_tx: VecDeque<Vec<u8>>,
    pub(super) pending_portmap_tx: VecDeque<Vec<u8>>,
    pub(super) pending_display_tx: HostDisplayCtrlOutbox,
    pub(super) pending_update_tx: crate::updater::PendingUpdateTxQueue,

    pub(super) session_native_res: Resolution,
    pub(super) session_max_res: Resolution,
    pub(super) session_display_hidpi: bool,
    pub(super) display_mode_session: HostDisplayModeSession,
    pub(super) original_native_res: Option<Resolution>,
    pub(super) wallpaper_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub(super) auto_hidpi_active: bool,
    pub(super) host_encode_caps: Vec<rc_pipeline::CodecCapability>,
    pub(super) codec_negotiator: HostCodecNegotiator,
    pub(super) host_refinement_supported: bool,
    pub(super) still_refine: crate::still_refine::HostStillRefineController,
    pub(super) still_loss_window_at: Instant,
    pub(super) still_window_sent_dgrams: u64,
    pub(super) still_window_dropped_dgrams: u64,
    pub(super) still_last_dropped_total: u64,
    pub(super) hevc_runtime_failed: bool,
    pub(super) base_hevc_supported: bool,

    pub(super) last_reported_screen_state: Option<(bool, bool)>,
    pub(super) last_screen_state_check: Instant,
    pub(super) mid_session_wake: MidSessionWakeDriver,
    pub(super) last_controller_meta_gen: u64,
    pub(super) active_controller_connected_at_ms: u64,

    pub(super) terminal_lock_gate: TerminalLockGate,
    pub(super) terminal_verify_driver: TerminalVerifyDriver,
    pub(super) last_terminal_lock_prompt_sent: Option<Instant>,
    pub(super) current_tool_perms: ToolPermissions,
    pub(super) last_tool_denied_sent: [Option<Instant>; 8],

    pub(super) audio_muted: bool,
    pub(super) audio_silence_gate: AudioSilenceGate,
    pub(super) audio_seq: u32,
    pub(super) last_busy: bool,
    pub(super) negotiated_initial_bitrate_bps: u32,
    pub(super) relay_bitrate_ctrl: Option<RelayBitrateController>,
    pub(super) last_relay_bwe_at: Instant,

    #[cfg(test)]
    pub(super) media_override: Option<TestHostMediaOverride>,
    #[cfg(test)]
    pub(super) test_platform: Option<TestHostPlatformMock>,
}

impl<'a> SessionLoopCtx<'a> {
    pub(super) fn host_hevc_available(&self) -> bool {
        !self.hevc_runtime_failed && self.base_hevc_supported
    }

    pub(super) fn current_net_hint(&self) -> NetworkHint {
        NetworkHint {
            is_relay: self.transport_kind == HostTransportKind::Relay,
            is_lan: self.transport_kind == HostTransportKind::Lan,
            estimated_bitrate_bps: self.host.current_bitrate_bps(),
            rtt_us: 0,
        }
    }

    pub(super) fn encode_displays_state(&self, active_id: Option<u32>) -> Option<Vec<u8>> {
        #[cfg(test)]
        if let Some(ref tp) = self.test_platform {
            return super::media_aux::encode_host_displays_state_from_list(
                active_id,
                tp.list_displays(),
            );
        }
        encode_host_displays_state(active_id)
    }

    pub(super) fn list_session_displays(&self) -> Vec<crate::platform::PlatformDisplayInfo> {
        #[cfg(test)]
        if let Some(ref tp) = self.test_platform {
            return tp.list_displays();
        }
        crate::platform::list_displays()
    }

    pub(super) fn current_main_backing(&self) -> Option<Resolution> {
        #[cfg(test)]
        if let Some(ref tp) = self.test_platform {
            return tp.backing_resolution();
        }
        host_hardware_display_backing(true)
    }

    pub(super) fn push_session_display_caps(&mut self) {
        let (caps_native, presets) = build_session_display_caps_params(
            self.active_display_id,
            self.session_native_res,
            self.session_max_res,
            self.original_native_res,
            self.prefer_hardware,
            self.hardware_video_active,
        );
        if let Some(caps_payload) = encode_host_display_caps(
            self.host,
            caps_native,
            self.session_native_res,
            self.session_max_res,
            self.session_display_hidpi,
            presets,
            self.host_hevc_available(),
            &self.codec_negotiator,
            self.hardware_media_active,
            self.still_refine.stream_epoch(),
        ) {
            self.pending_display_tx.set_caps(caps_payload);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        host: &'a mut HostSession,
        clock: &'a SessionClock,
        clock_anchor: Option<&'a HostClockAnchor>,
        updates: &'a BoundedHostUpdateQueue,
        password_version: &'a AtomicU64,
        observed_pw_ver: u64,
        config_version: &'a AtomicU64,
        observed_cfg_ver: u64,
        disconnect_flag: &'a AtomicBool,
        stop_flag: &'a AtomicBool,
        close_reason: &'a AtomicU8,
        transport_kind: HostTransportKind,
        prefer_hardware: bool,
        hardware_video_active: bool,
        lock_screen_count: &'a AtomicU64,
        auth_state: Option<&'a Mutex<AuthRuntimeState>>,
        owner_terminals: &'a mut PersistentOwnerTerminals,
        wake_guard: SharedWakeGuard,
        file_transfer_dir: SharedFileTransferDir,
        allow_assist_file_transfer: &'a AtomicBool,
        incoming_relay: Option<&'a Arc<BoundedRelayIncomingQueue>>,
        active_peer_id: Option<&str>,
        session_started_at: Instant,
        audio_mgr: HostAudioManager,
        switch_rt: Option<HostSwitchRuntime>,
        controller_tracking: Option<HostControllerTracking>,
        #[cfg(test)] media_override: Option<TestHostMediaOverride>,
    ) -> Self {
        #[cfg(test)]
        let test_platform = media_override.as_ref().and_then(|ov| ov.platform.clone());
        #[cfg(test)]
        let hw_display_ops_active = (prefer_hardware && hardware_video_active)
            || test_platform
                .as_ref()
                .is_some_and(|p| p.enable_hardware_display_ops);
        #[cfg(not(test))]
        let hw_display_ops_active = prefer_hardware && hardware_video_active;
        #[cfg(test)]
        let hw_cleanup =
            HostHardwareCleanupGuard::with_test_platform(prefer_hardware, test_platform.clone());
        #[cfg(not(test))]
        let hw_cleanup = HostHardwareCleanupGuard::new(prefer_hardware);

        // 文件 I/O 与端口映射严格绑定单次控制端会话（断线清理 .rcpart 与监听套接字）；
        // W3 终端在机主（OwnerTicket）身份下复用 `owner_terminals` 跨重连保活，访客会话仅使用会话级 `guest_term_host`。
        let file_worker = FileHostWorker::spawn(Arc::clone(&file_transfer_dir));
        let guest_term_host = TerminalHostEngine::new();
        let use_owner_terminals = match host.authenticated_owner() {
            Some(owner) => {
                let _ = owner_terminals.bind_for_owner(&owner.user_id);
                true
            }
            None => false,
        };
        let portmap_host = PortMapHostEngine::new();
        let update_worker = crate::updater::HostUpdateWorker::new();

        #[cfg(test)]
        let (session_native_res, session_max_res) = match media_override {
            Some(ref ov) => (
                ov.native_res,
                super::media_aux::clamp_display_max_res(ov.native_res, ov.max_res),
            ),
            None => compute_host_display_bounds(host, prefer_hardware, hardware_video_active),
        };
        #[cfg(not(test))]
        let (session_native_res, session_max_res) =
            compute_host_display_bounds(host, prefer_hardware, hardware_video_active);

        #[cfg(test)]
        let session_display_hidpi = match media_override {
            Some(ref ov) => {
                ov.max_res.width > ov.native_res.width && ov.max_res.height > ov.native_res.height
            }
            None => {
                prefer_hardware
                    && hardware_video_active
                    && session_max_res.width > session_native_res.width
                    && session_max_res.height > session_native_res.height
            }
        };
        #[cfg(not(test))]
        let session_display_hidpi = prefer_hardware
            && hardware_video_active
            && session_max_res.width > session_native_res.width
            && session_max_res.height > session_native_res.height;

        #[cfg(test)]
        let display_mode_session = HostDisplayModeSession::capture_with_test_platform(
            prefer_hardware,
            hardware_video_active,
            test_platform.clone(),
        );
        #[cfg(not(test))]
        let display_mode_session =
            HostDisplayModeSession::capture(prefer_hardware, hardware_video_active);

        let original_native_res = display_mode_session
            .original_resolution()
            .or(Some(session_native_res));
        let wallpaper_rx = if prefer_hardware && hardware_video_active {
            Some(super::media_aux::spawn_wallpaper_fetcher())
        } else {
            None
        };

        let hardware_media_active = prefer_hardware && hardware_video_active;
        #[cfg(test)]
        let auto_hidpi_active = media_override
            .as_ref()
            .map_or(prefer_hardware && hardware_video_active, |ov| ov.auto_hidpi);
        #[cfg(not(test))]
        let auto_hidpi_active = prefer_hardware && hardware_video_active;

        #[cfg(test)]
        let host_encode_caps = media_override
            .as_ref()
            .map(|ov| ov.encode_caps.clone())
            .unwrap_or_else(|| {
                codec_selector::cached_or_platform_encode_caps(hardware_media_active)
            });
        #[cfg(not(test))]
        let host_encode_caps =
            codec_selector::cached_or_platform_encode_caps(hardware_media_active);

        let codec_negotiator = HostCodecNegotiator::new(host_encode_caps.clone());
        let host_refinement_supported =
            codec_selector::cached_or_platform_refinement_caps(hardware_media_active).supported;
        let init_stream_dims = host
            .negotiated()
            .map(|n| (n.width, n.height))
            .unwrap_or((session_native_res.width, session_native_res.height));
        let still_refine = crate::still_refine::HostStillRefineController::new(
            1,
            init_stream_dims.0,
            init_stream_dims.1,
            host_refinement_supported,
        );
        let still_last_dropped_total = host.transport_tx_dropped_datagrams();

        #[cfg(test)]
        let base_hevc_supported = (hardware_media_active && rc_pipeline::platform_supports_hevc())
            || media_override.as_ref().is_some_and(|ov| ov.hevc_available);
        #[cfg(not(test))]
        let base_hevc_supported = hardware_media_active && rc_pipeline::platform_supports_hevc();

        let last_controller_meta_gen = host.controller_meta_gen();
        let active_controller_connected_at_ms = unix_now_ms();
        if let Some(ref tr) = controller_tracking {
            if host.state() == SessionState::Streaming {
                let initial_ctrl = build_active_controller_session(
                    host,
                    &tr.peer_hints,
                    active_controller_connected_at_ms,
                );
                publish_active_controller(
                    &tr.active_controllers,
                    updates,
                    Some(&tr.signal_client),
                    initial_ctrl,
                );
            }
        }

        let initial_screen_locked = crate::platform::is_screen_locked();
        let terminal_lock_gate = TerminalLockGate::new(initial_screen_locked);
        let current_tool_perms = compute_effective_tool_permissions(
            host.authenticated_owner().is_some(),
            allow_assist_file_transfer.load(Ordering::Acquire),
        );
        host.set_tool_permissions(current_tool_perms);

        let negotiated_initial_bitrate_bps = host
            .negotiated()
            .map(|n| n.bitrate_bps)
            .filter(|&b| b > 0)
            .unwrap_or_else(|| host.current_bitrate_bps().max(1));
        let relay_bitrate_ctrl = (transport_kind == HostTransportKind::Relay).then(|| {
            RelayBitrateController::new(host.current_bitrate_bps().max(1), Instant::now())
        });

        let mut ctx = Self {
            host,
            clock,
            clock_anchor,
            updates,
            password_version,
            observed_pw_ver,
            config_version,
            observed_cfg_ver,
            disconnect_flag,
            stop_flag,
            close_reason,
            transport_kind,
            prefer_hardware,
            hardware_video_active,
            hardware_media_active,
            hw_display_ops_active,
            lock_screen_count,
            auth_state,
            owner_terminals,
            wake_guard,
            file_transfer_dir,
            allow_assist_file_transfer,
            incoming_relay,
            active_peer_id: active_peer_id.map(str::to_string),
            session_started_at,
            audio_mgr,
            switch_rt,
            controller_tracking,
            hw_cleanup,
            active_display_id: None,
            virtual_display_hidpi: HashMap::new(),
            shows_cursor: false,
            detached_reason: None,
            drive_err: None,
            pending_lock_on_exit: false,
            preempted_by_incoming: false,
            preempted_by_takeover: false,
            force_disconnected: false,
            last_preempt_check: Instant::now(),
            epoch_reanchored_in_detached: false,
            file_worker,
            guest_term_host,
            use_owner_terminals,
            portmap_host,
            update_worker,
            pending_file_in: VecDeque::new(),
            pending_file_tx: VecDeque::new(),
            pending_term_tx: VecDeque::new(),
            pending_portmap_tx: VecDeque::new(),
            pending_display_tx: HostDisplayCtrlOutbox::new(),
            pending_update_tx: crate::updater::PendingUpdateTxQueue::new(),
            session_native_res,
            session_max_res,
            session_display_hidpi,
            display_mode_session,
            original_native_res,
            wallpaper_rx,
            auto_hidpi_active,
            host_encode_caps,
            codec_negotiator,
            host_refinement_supported,
            still_refine,
            still_loss_window_at: Instant::now(),
            still_window_sent_dgrams: 0,
            still_window_dropped_dgrams: 0,
            still_last_dropped_total,
            hevc_runtime_failed: false,
            base_hevc_supported,
            last_reported_screen_state: None,
            last_screen_state_check: Instant::now(),
            mid_session_wake: MidSessionWakeDriver::new(),
            last_controller_meta_gen,
            active_controller_connected_at_ms,
            terminal_lock_gate,
            terminal_verify_driver: TerminalVerifyDriver::new(),
            last_terminal_lock_prompt_sent: None,
            current_tool_perms,
            last_tool_denied_sent: [None; 8],
            audio_muted: false,
            audio_silence_gate: AudioSilenceGate::default(),
            audio_seq: 0,
            last_busy: true,
            negotiated_initial_bitrate_bps,
            relay_bitrate_ctrl,
            last_relay_bwe_at: Instant::now(),
            #[cfg(test)]
            media_override,
            #[cfg(test)]
            test_platform,
        };
        ctx.init_streaming_outbox(initial_screen_locked);
        ctx
    }

    fn init_streaming_outbox(&mut self, initial_screen_locked: bool) {
        if self.host.state() != SessionState::Streaming {
            return;
        }
        if let Some(perm_payload) = encode_tool_permissions_state(self.current_tool_perms) {
            self.pending_display_tx.set_tool_perms(perm_payload);
        }
        if let Some(term_lock_payload) =
            encode_terminal_lock_state(self.use_owner_terminals, &self.terminal_lock_gate)
        {
            self.pending_display_tx.set_terminal_lock(term_lock_payload);
        }
        let presets = build_hardware_display_presets(
            self.prefer_hardware,
            self.hardware_video_active,
            self.original_native_res,
        );
        if let Some(payload) = encode_host_display_caps(
            self.host,
            self.original_native_res.unwrap_or(self.session_native_res),
            self.session_native_res,
            self.session_max_res,
            self.session_display_hidpi,
            presets,
            self.host_hevc_available(),
            &self.codec_negotiator,
            self.hardware_media_active,
            self.still_refine.stream_epoch(),
        ) {
            self.pending_display_tx.set_caps(payload);
        }
        if self.hw_display_ops_active {
            if let Some(disp_payload) = self.encode_displays_state(self.active_display_id) {
                self.pending_display_tx.push_transient(disp_payload);
            }
        }
        let init_screen_state = (initial_screen_locked, self.host.is_capture_suspended());
        if init_screen_state.0 || init_screen_state.1 {
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::HostScreenState {
                    locked: init_screen_state.0,
                    capture_suspended: init_screen_state.1,
                })
            {
                self.pending_display_tx.set_screen_state(payload);
            }
        }
        self.last_reported_screen_state = Some(init_screen_state);
        let ver_msg = crate::updater::HostUpdateWorker::build_version_info_msg(
            self.host.authenticated_owner().is_some(),
        );
        self.pending_update_tx
            .enqueue(&ver_msg, self.host.authenticated_owner().is_some());
    }

    fn step_streaming(&mut self, busy_lan_worker: Option<&BusyLanRejectWorker>) -> LoopControl {
        if let Some(worker) = busy_lan_worker {
            worker.set_active();
        }
        self.sync_runtime_tool_permissions();

        let poll_budget = if self.last_busy || self.host.has_pending_pipeline_work() {
            Duration::ZERO
        } else {
            Duration::from_millis(1)
        };
        let r = match self.host.tick(poll_budget) {
            Ok(r) => r,
            Err(e) => {
                self.drive_err = Some(format!("会话运行异常: {e}"));
                return LoopControl::Break;
            }
        };

        if r.closed.is_some() {
            for (channel, mut payload) in self.host.drain_tool_messages() {
                if channel == TOOL_CHANNEL_DISPLAY_CTRL {
                    match display_ctrl::decode_display_ctrl(&payload) {
                        Some(DisplayControlMsg::LockScreen) => {
                            self.pending_lock_on_exit = true;
                        }
                        Some(DisplayControlMsg::TerminalUnlockRequest { .. }) => {
                            use zeroize::Zeroize;
                            payload.zeroize();
                        }
                        _ => {}
                    }
                }
            }
            return LoopControl::Break;
        }
        if self.host.state() != SessionState::Streaming {
            return LoopControl::Continue;
        }

        self.sync_controller_meta();
        self.update_still_refine_on_tick(&r);
        self.check_encode_overload_fallback();
        self.poll_relay_bitrate();
        self.poll_audio_and_wallpaper();

        // 1) 剪贴板本机侧轮询泵。
        let _ = self.host.pump_clipboard(u64::from((self.clock)()));

        // 2) 工具复用通道入站分发与终端核验/更新/文件入站泵。
        let mut tools_busy = self.dispatch_incoming_tools();

        // 2.5) 接收后台唤醒结果并节流巡检被控端锁屏与采集挂起态（250ms）。
        self.poll_screen_state_and_wake();

        // 3) & 4) 工具复用通道出站节流泵、静止补帧与系统音频泵。
        let audio_busy = self.flush_outgoing_tools_and_media(&mut tools_busy);

        if !self.host.is_media_paused() && !self.host.has_pipeline() {
            self.drive_err = Some("硬件视频管线热重建失败且无法恢复，会话已终止".to_string());
            return LoopControl::Break;
        }

        self.poll_path_switch_runtime();

        if self.check_preempt_and_force_disconnect(false) {
            return LoopControl::Break;
        }

        self.last_busy = r.busy || tools_busy || audio_busy;
        if !self.last_busy && self.host.state() == SessionState::Streaming {
            let wait_budget = if self.pending_file_in.is_empty()
                && self.pending_display_tx.is_empty()
                && self.pending_update_tx.is_empty()
            {
                if self.host.is_media_paused() {
                    Duration::from_millis(3)
                } else {
                    Duration::from_micros(500)
                }
            } else {
                Duration::from_micros(500)
            };
            if self.host.has_pipeline() {
                self.host.pipeline().wait_event(wait_budget);
            } else if self.host.is_media_paused() {
                thread::sleep(wait_budget);
            }
        }
        LoopControl::Continue
    }

    fn finish(mut self, busy_lan_worker: Option<BusyLanRejectWorker>) -> DriveSessionOutcome {
        // 停止并释放音频采集器与在途初始化接收端（H13）。
        self.audio_mgr.stop_all();
        drop(self.audio_mgr);
        drop(self.file_worker);
        if self.use_owner_terminals {
            self.owner_terminals.detach_all();
        }
        drop(self.guest_term_host);
        drop(self.portmap_host);
        self.display_mode_session.restore();
        drop(self.display_mode_session);
        if self.pending_lock_on_exit {
            super::media_aux::trigger_host_lock_screen(
                self.lock_screen_count,
                self.prefer_hardware,
            );
        }

        let user_disconnected = self.disconnect_flag.load(Ordering::Acquire);
        let bye_reason = if self.preempted_by_takeover {
            ByeReason::Preempted
        } else if self.stop_flag.load(Ordering::Acquire) {
            match self.close_reason.load(Ordering::Acquire) {
                1 => ByeReason::Refresh,
                2 => ByeReason::SessionSwitching,
                _ => ByeReason::Normal,
            }
        } else {
            ByeReason::Normal
        };
        let close_res = self.host.close(bye_reason);
        if let Some(ref tr) = self.controller_tracking {
            clear_active_controllers(
                &tr.active_controllers,
                self.updates,
                Some(&tr.signal_client),
            );
        }
        drop(busy_lan_worker);
        let reason = if self.preempted_by_takeover {
            "连接已被其他设备接管".to_string()
        } else if self.force_disconnected {
            "已被同账号设备远程断开".to_string()
        } else if self.preempted_by_incoming {
            "收到新的远控连接，已切换会话".to_string()
        } else if user_disconnected {
            "本机主动断开".to_string()
        } else if let Some(err) = self.drive_err {
            err
        } else if let Some(reason) = self.detached_reason {
            reason
        } else {
            match close_res {
                Ok(summary) => match summary.stop_reason {
                    StopReason::Requested => "本机主动断开".to_string(),
                    StopReason::ByeReceived(_) => "控制端已断开".to_string(),
                    StopReason::Disconnected(r) => format!("连接中断 ({r})"),
                },
                Err(e) => format!("会话运行异常: {e}"),
            }
        };
        DriveSessionOutcome {
            reason,
            preempted_by_incoming: self.preempted_by_incoming,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn drive_ui_host_session_with_switch_and_tracking(
    host: &mut HostSession,
    clock: &SessionClock,
    clock_anchor: Option<&HostClockAnchor>,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
    close_reason: &AtomicU8,
    transport_kind: HostTransportKind,
    prefer_hardware: bool,
    audio_enabled: bool,
    hardware_video_active: bool,
    lock_screen_count: &AtomicU64,
    auth_state: Option<&Mutex<AuthRuntimeState>>,
    owner_terminals: &mut PersistentOwnerTerminals,
    wake_guard: SharedWakeGuard,
    file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: &AtomicBool,
    incoming_relay: Option<&Arc<BoundedRelayIncomingQueue>>,
    active_peer_id: Option<&str>,
    session_started_at: Instant,
    switch_rt: Option<HostSwitchRuntime>,
    controller_tracking: Option<HostControllerTracking>,
    busy_lan_endpoint: Option<&QuicEndpoint>,
) -> DriveSessionOutcome {
    let audio_mgr =
        HostAudioManager::new(audio_enabled && prefer_hardware && hardware_video_active);
    drive_ui_host_session_core(
        host,
        clock,
        clock_anchor,
        updates,
        password_version,
        observed_pw_ver,
        config_version,
        observed_cfg_ver,
        disconnect_flag,
        stop_flag,
        close_reason,
        transport_kind,
        prefer_hardware,
        hardware_video_active,
        lock_screen_count,
        auth_state,
        owner_terminals,
        wake_guard,
        file_transfer_dir,
        allow_assist_file_transfer,
        incoming_relay,
        active_peer_id,
        session_started_at,
        audio_mgr,
        switch_rt,
        controller_tracking,
        busy_lan_endpoint,
        #[cfg(test)]
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn drive_ui_host_session_core(
    host: &mut HostSession,
    clock: &SessionClock,
    clock_anchor: Option<&HostClockAnchor>,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
    close_reason: &AtomicU8,
    transport_kind: HostTransportKind,
    prefer_hardware: bool,
    hardware_video_active: bool,
    lock_screen_count: &AtomicU64,
    auth_state: Option<&Mutex<AuthRuntimeState>>,
    owner_terminals: &mut PersistentOwnerTerminals,
    wake_guard: SharedWakeGuard,
    file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: &AtomicBool,
    incoming_relay: Option<&Arc<BoundedRelayIncomingQueue>>,
    active_peer_id: Option<&str>,
    session_started_at: Instant,
    audio_mgr: HostAudioManager,
    switch_rt: Option<HostSwitchRuntime>,
    controller_tracking: Option<HostControllerTracking>,
    busy_lan_endpoint: Option<&QuicEndpoint>,
    #[cfg(test)] media_override: Option<TestHostMediaOverride>,
) -> DriveSessionOutcome {
    // 启用 8s 应用层客户端失活看门狗（控制端在静屏与纯工具模式下每 1s 发送 ProbePing 心跳）。
    host.set_client_idle_timeout_us(HostSession::CLIENT_IDLE_TIMEOUT_US);

    let _wake_guard_releaser = WakeGuardReleaser {
        slot: Arc::clone(&wake_guard),
    };
    let _activity =
        crate::platform::begin_latency_critical_activity("RabbitControl 被控会话", true);

    let mut ctx = SessionLoopCtx::new(
        host,
        clock,
        clock_anchor,
        updates,
        password_version,
        observed_pw_ver,
        config_version,
        observed_cfg_ver,
        disconnect_flag,
        stop_flag,
        close_reason,
        transport_kind,
        prefer_hardware,
        hardware_video_active,
        lock_screen_count,
        auth_state,
        owner_terminals,
        wake_guard,
        file_transfer_dir,
        allow_assist_file_transfer,
        incoming_relay,
        active_peer_id,
        session_started_at,
        audio_mgr,
        switch_rt,
        controller_tracking,
        #[cfg(test)]
        media_override,
    );

    let busy_lan_worker = busy_lan_endpoint.or_else(|| ctx.host.endpoint()).map(|ep| {
        BusyLanRejectWorker::spawn(
            ep.clone(),
            ctx.host.negotiated().unwrap_or_else(|| ctx.host.caps()),
            ctx.controller_tracking
                .as_ref()
                .map(|tr| Arc::clone(&tr.active_controllers)),
            incoming_relay.cloned(),
        )
    });

    while !ctx.stop_flag.load(Ordering::Acquire)
        && !ctx.disconnect_flag.load(Ordering::Acquire)
        && ctx.host.state() != SessionState::Closed
    {
        match ctx.host.state() {
            SessionState::Streaming => {
                if ctx.step_streaming(busy_lan_worker.as_ref()) == LoopControl::Break {
                    break;
                }
            }
            SessionState::Detached => {
                if ctx.step_detached(busy_lan_worker.as_ref()) == LoopControl::Break {
                    break;
                }
            }
            SessionState::Init
            | SessionState::Connected
            | SessionState::Reconnecting
            | SessionState::Closed => break,
        }
    }

    ctx.finish(busy_lan_worker)
}
