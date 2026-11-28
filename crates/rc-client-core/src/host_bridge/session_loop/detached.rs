use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use rc_session::DetachOutcome;
use rc_tools::{PortMapHostEngine, TerminalHostEngine};

use crate::codec_selector::HostCodecNegotiator;
use crate::display_ctrl::{self, DisplayControlMsg};

use super::super::media_aux::{
    build_hardware_display_presets, compute_host_display_bounds, encode_host_display_caps,
    spawn_wallpaper_fetcher,
};
use super::super::queues::{
    build_active_controller_session, emit_peer_connected, publish_active_controller, unix_now_ms,
    BusyLanRejectWorker,
};
use super::super::tools_worker::{
    compute_effective_tool_permissions, encode_terminal_lock_state, encode_tool_permissions_state,
    FileHostWorker, TerminalLockGate, TerminalVerifyDriver,
};
use super::super::types::{ActiveControllerPeerHints, HostTransportKind};
use super::{LoopControl, SessionLoopCtx};

impl SessionLoopCtx<'_> {
    pub(super) fn step_detached(
        &mut self,
        busy_lan_worker: Option<&BusyLanRejectWorker>,
    ) -> LoopControl {
        if let Some(worker) = busy_lan_worker {
            worker.pause_and_sync();
        }
        match self.transport_kind {
            HostTransportKind::P2p => {
                self.detached_reason = Some("P2P 连接已断开".to_string());
                return LoopControl::Break;
            }
            HostTransportKind::Relay => {
                // 一次性 RCR1 中继令牌不可在原连接上续传，断链后直接收尾回到监听态。
                self.detached_reason = Some("中继连接已断开".to_string());
                return LoopControl::Break;
            }
            HostTransportKind::MtlsLan => {
                self.detached_reason = Some("mTLS LAN 连接已断开".to_string());
                return LoopControl::Break;
            }
            HostTransportKind::Lan => {}
        }
        if self.host.is_media_paused() && !self.host.is_pending_epoch_reset() {
            self.detached_reason = Some("纯工具连接已断开".to_string());
            return LoopControl::Break;
        }
        if self.password_version.load(Ordering::Acquire) != self.observed_pw_ver {
            self.detached_reason = Some("密码已变更，重置监听".to_string());
            return LoopControl::Break;
        }
        if self.config_version.load(Ordering::Acquire) != self.observed_cfg_ver {
            self.detached_reason = Some("鉴权配置已变更，重置监听".to_string());
            return LoopControl::Break;
        }
        if self.check_preempt_and_force_disconnect(true) {
            return LoopControl::Break;
        }
        // 70 分钟 `Bye(Refresh)` 触发后立即重锚会话钟原点并复位活动钟，
        // 避免 71.58 分钟 `u32::MAX` 饱和导致 Detached 候选超时与新纪元 8s 看门狗失明。
        if self.host.is_pending_epoch_reset() && !self.epoch_reanchored_in_detached {
            if let Some(anchor) = self.clock_anchor {
                anchor.reset_pending();
            }
            self.host.reset_activity_clock(u64::from((self.clock)()));
            self.epoch_reanchored_in_detached = true;
        }
        if let Some(anchor) = self.clock_anchor {
            anchor.reanchor_next_build.store(true, Ordering::Release);
        }
        let now_us = u64::from((self.clock)());
        let detach_res = self.host.tick_detached(now_us);
        let factory_consumed_reanchor = self
            .clock_anchor
            .map(|anchor| !anchor.reanchor_next_build.swap(false, Ordering::AcqRel))
            .unwrap_or(false);
        match detach_res {
            Ok(DetachOutcome::TornDown) => {
                self.detached_reason = Some("控制端重连超时已断开".to_string());
                LoopControl::Break
            }
            Ok(DetachOutcome::Resumed) => {
                self.on_detached_resumed();
                LoopControl::Continue
            }
            Ok(DetachOutcome::Replaced) => {
                self.on_detached_replaced(factory_consumed_reanchor);
                LoopControl::Continue
            }
            Ok(DetachOutcome::Waiting) => {
                self.owner_terminals.sync_auth_and_poll(self.auth_state);
                if !self.use_owner_terminals {
                    self.guest_term_host.poll_background();
                }
                LoopControl::Continue
            }
            Err(e) => {
                self.drive_err = Some(format!("会话运行异常: {e}"));
                LoopControl::Break
            }
        }
    }

    fn on_detached_resumed(&mut self) {
        self.epoch_reanchored_in_detached = false;
        self.host.reset_clipboard_epoch();
        self.last_busy = true;
        self.pending_display_tx.clear();
        self.still_refine.on_input_event();
        self.push_session_display_caps();
        if self.hw_display_ops_active {
            if let Some(dp) = self.encode_displays_state(self.active_display_id) {
                self.pending_display_tx.push_transient(dp);
            }
        }
        if self.update_worker.has_active_or_pending_relay() {
            self.pending_update_tx.clear();
            self.update_worker
                .abort_relay_on_transport_resume("连接短暂中断导致安装包中转中断，请重试");
        }
        let ver_msg = crate::updater::HostUpdateWorker::build_version_info_msg(
            self.host.authenticated_owner().is_some(),
        );
        self.pending_update_tx
            .enqueue(&ver_msg, self.host.authenticated_owner().is_some());
        let resumed_screen_state = (
            crate::platform::is_screen_locked(),
            self.host.is_capture_suspended(),
        );
        self.terminal_lock_gate
            .on_screen_lock_observed(resumed_screen_state.0);
        // 断线恢复后无条件重发一次最新状态（含 `(false, false)`），避免对端卡死在断线前收到的锁屏/挂起提示。
        if let Some(payload) =
            display_ctrl::encode_display_ctrl(&DisplayControlMsg::HostScreenState {
                locked: resumed_screen_state.0,
                capture_suspended: resumed_screen_state.1,
            })
        {
            self.pending_display_tx.set_screen_state(payload);
        }
        self.last_reported_screen_state = Some(resumed_screen_state);
        self.last_screen_state_check = Instant::now();
        self.current_tool_perms = compute_effective_tool_permissions(
            self.host.authenticated_owner().is_some(),
            self.allow_assist_file_transfer.load(Ordering::Acquire),
        );
        self.host.set_tool_permissions(self.current_tool_perms);
        if !self.current_tool_perms.allow_file_transfer {
            self.pending_file_in.clear();
            self.pending_file_tx.clear();
            self.file_worker = FileHostWorker::spawn(Arc::clone(&self.file_transfer_dir));
        }
        if let Some(perm_payload) = encode_tool_permissions_state(self.current_tool_perms) {
            self.pending_display_tx.set_tool_perms(perm_payload);
        }
        if let Some(term_lock_payload) =
            encode_terminal_lock_state(self.use_owner_terminals, &self.terminal_lock_gate)
        {
            self.pending_display_tx.set_terminal_lock(term_lock_payload);
        }
        emit_peer_connected(self.host, &self.host.peer_addr().to_string(), self.updates);
    }

    fn on_detached_replaced(&mut self, factory_consumed_reanchor: bool) {
        // 新会话落成（含 70 分钟 Bye(Refresh) 跨纪元重建）：确保时钟原点已重锚
        // 且被控端 8s 失活看门狗与刷新基准以新纪元零点起算。
        self.epoch_reanchored_in_detached = false;
        self.session_started_at = Instant::now();
        if !factory_consumed_reanchor {
            if let Some(anchor) = self.clock_anchor {
                anchor.reset_pending();
            }
        }
        self.host.reset_activity_clock(u64::from((self.clock)()));
        // M9：新控制端顶替旧会话时复位隐私幕布/被控端静音/虚拟屏、音频静音与全部会话级工具引擎，
        // 避免新客户端继承旧客户端的隐私/音频/虚拟屏状态、终端 PTY 或陈旧线帧。
        // `finalize_session` 已基于 `cfg.pipeline` 基线模板在主屏上启动新管线，
        // 仅当旧会话曾启用隐私幕布时需在清理幕布后重建一次 SCK 过滤器。
        let had_privacy_curtain = self.hw_cleanup.privacy_active;
        self.hw_cleanup.cleanup_now();
        self.active_display_id = None;
        self.virtual_display_hidpi.clear();
        self.shows_cursor = false;
        self.host.set_capture_options(None, false);
        self.display_mode_session.restore();
        let main_origin = if self.hw_display_ops_active {
            self.list_session_displays()
                .into_iter()
                .find(|d| d.is_main)
                .map(|d| (d.origin_x, d.origin_y))
                .unwrap_or((0.0, 0.0))
        } else {
            (0.0, 0.0)
        };
        if let Some(orig) = self.original_native_res {
            self.host.set_injector_screen_bounds(
                main_origin.0,
                main_origin.1,
                orig.width,
                orig.height,
            );
        }
        self.hevc_runtime_failed = false;
        self.codec_negotiator = HostCodecNegotiator::new(self.host_encode_caps.clone());
        let replaced_dims = self
            .host
            .negotiated()
            .map(|n| (n.width, n.height))
            .unwrap_or((
                self.session_native_res.width,
                self.session_native_res.height,
            ));
        self.still_refine = crate::still_refine::HostStillRefineController::new(
            1,
            replaced_dims.0,
            replaced_dims.1,
            self.host_refinement_supported,
        );
        self.still_window_sent_dgrams = 0;
        self.still_window_dropped_dgrams = 0;
        self.still_last_dropped_total = self.host.transport_tx_dropped_datagrams();
        self.still_loss_window_at = Instant::now();
        self.last_busy = true;
        self.host.reset_clipboard_epoch();
        self.audio_muted = false;
        self.audio_silence_gate.reset();
        self.audio_seq = 0;
        self.audio_mgr.resume(&mut self.audio_silence_gate);
        self.active_peer_id = self
            .host
            .authenticated_owner()
            .map(|o| o.caller_device_id.clone());
        self.pending_file_in.clear();
        self.pending_file_tx.clear();
        self.pending_term_tx.clear();
        self.pending_portmap_tx.clear();
        self.pending_display_tx.clear();
        self.pending_update_tx.clear();

        #[cfg(test)]
        match self.media_override {
            Some(ref ov) => {
                self.session_native_res = ov.native_res;
                self.session_max_res =
                    super::super::media_aux::clamp_display_max_res(ov.native_res, ov.max_res);
                self.auto_hidpi_active = ov.auto_hidpi;
                self.session_display_hidpi = self.session_max_res.width
                    > self.session_native_res.width
                    && self.session_max_res.height > self.session_native_res.height;
            }
            None => {
                (self.session_native_res, self.session_max_res) = compute_host_display_bounds(
                    self.host,
                    self.prefer_hardware,
                    self.hardware_video_active,
                );
                self.auto_hidpi_active = self.prefer_hardware && self.hardware_video_active;
                self.session_display_hidpi = self.auto_hidpi_active
                    && self.session_max_res.width > self.session_native_res.width
                    && self.session_max_res.height > self.session_native_res.height;
            }
        }
        #[cfg(not(test))]
        {
            (self.session_native_res, self.session_max_res) = compute_host_display_bounds(
                self.host,
                self.prefer_hardware,
                self.hardware_video_active,
            );
            self.auto_hidpi_active = self.prefer_hardware && self.hardware_video_active;
            self.session_display_hidpi = self.auto_hidpi_active
                && self.session_max_res.width > self.session_native_res.width
                && self.session_max_res.height > self.session_native_res.height;
        }
        if had_privacy_curtain {
            if let Some(cur) = self.host.negotiated() {
                let _ = self.host.force_reconfigure_stream(
                    cur.width,
                    cur.height,
                    Some(cur.fps),
                    Some(self.session_max_res),
                    None,
                );
            }
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
            if let Some(dp) = self.encode_displays_state(self.active_display_id) {
                self.pending_display_tx.push_transient(dp);
            }
        }
        self.update_worker.reset();
        let ver_msg = crate::updater::HostUpdateWorker::build_version_info_msg(
            self.host.authenticated_owner().is_some(),
        );
        self.pending_update_tx
            .enqueue(&ver_msg, self.host.authenticated_owner().is_some());
        self.wallpaper_rx = if self.prefer_hardware && self.hardware_video_active {
            Some(spawn_wallpaper_fetcher())
        } else {
            None
        };
        let replaced_screen_state = (
            crate::platform::is_screen_locked(),
            self.host.is_capture_suspended(),
        );
        if replaced_screen_state.0 || replaced_screen_state.1 {
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::HostScreenState {
                    locked: replaced_screen_state.0,
                    capture_suspended: replaced_screen_state.1,
                })
            {
                self.pending_display_tx.set_screen_state(payload);
            }
        }
        self.last_reported_screen_state = Some(replaced_screen_state);
        self.last_screen_state_check = Instant::now();
        self.terminal_lock_gate = TerminalLockGate::new(replaced_screen_state.0);
        self.terminal_verify_driver = TerminalVerifyDriver::new();
        self.last_terminal_lock_prompt_sent = None;
        self.current_tool_perms = compute_effective_tool_permissions(
            self.host.authenticated_owner().is_some(),
            self.allow_assist_file_transfer.load(Ordering::Acquire),
        );
        self.host.set_tool_permissions(self.current_tool_perms);
        self.last_tool_denied_sent = [None; 8];
        if let Some(perm_payload) = encode_tool_permissions_state(self.current_tool_perms) {
            self.pending_display_tx.set_tool_perms(perm_payload);
        }
        self.file_worker = FileHostWorker::spawn(Arc::clone(&self.file_transfer_dir));
        if self.use_owner_terminals {
            self.owner_terminals.detach_all();
        } else {
            self.guest_term_host = TerminalHostEngine::new();
        }
        self.use_owner_terminals = match self.host.authenticated_owner() {
            Some(owner) => {
                let _ = self.owner_terminals.bind_for_owner(&owner.user_id);
                true
            }
            None => false,
        };
        if let Some(term_lock_payload) =
            encode_terminal_lock_state(self.use_owner_terminals, &self.terminal_lock_gate)
        {
            self.pending_display_tx.set_terminal_lock(term_lock_payload);
        }
        self.portmap_host = PortMapHostEngine::new();
        emit_peer_connected(self.host, &self.host.peer_addr().to_string(), self.updates);
        self.active_controller_connected_at_ms = unix_now_ms();
        self.last_controller_meta_gen = self.host.controller_meta_gen();
        if let Some(ref mut tr) = self.controller_tracking {
            tr.peer_hints = ActiveControllerPeerHints {
                session_id_hint: None,
                relay_peer_id: self
                    .host
                    .authenticated_owner()
                    .map(|o| o.caller_device_id.clone()),
                relay_peer_name: None,
                relay_peer_hostname: None,
                relay_peer_os: None,
                mtls_peer_did: None,
                remote_addr: self.host.peer_addr().to_string(),
            };
            let replaced_ctrl = build_active_controller_session(
                self.host,
                &tr.peer_hints,
                self.active_controller_connected_at_ms,
            );
            publish_active_controller(
                &tr.active_controllers,
                self.updates,
                Some(&tr.signal_client),
                replaced_ctrl,
            );
        }
    }
}
