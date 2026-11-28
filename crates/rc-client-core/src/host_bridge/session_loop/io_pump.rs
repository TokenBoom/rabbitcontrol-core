use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use rc_session::{
    TOOL_CHANNEL_AUDIO_CTRL, TOOL_CHANNEL_DISPLAY_CTRL, TOOL_CHANNEL_FILE, TOOL_CHANNEL_PORTMAP,
    TOOL_CHANNEL_TERMINAL,
};

use crate::display_ctrl::{self, DisplayControlMsg};
use crate::switchable_transport::{SwitchControlMsg, TransportPathKind};

use super::super::audio_bwe::{
    parse_audio_ctrl_muted, pump_host_audio, sync_host_bitrate_on_path_switch,
};
use super::super::queues::{
    build_active_controller_session, drain_matching_force_disconnect, emit_peer_connected,
    publish_active_controller,
};
use super::super::tools_worker::{
    compute_effective_tool_permissions, encode_terminal_lock_state, encode_tool_permissions_state,
    flush_tool_channel_with_retry, handle_terminal_verify_completion, FileHostWorker,
};
use super::super::transport_dial::{
    rebuild_host_p2p_mtls, spawn_host_reprobe_p2p_candidate, spawn_host_switch_relay_candidate,
};
use super::super::types::{
    HostTransportKind, PreemptDecision, LAN_STALE_SIGNAL_GRACE, MAX_TOOL_FRAMES_PER_TICK,
    PREEMPT_CHECK_INTERVAL, RELAY_INCOMING_TTL, TOOL_PERMISSION_DENIED_THROTTLE,
};
use super::SessionLoopCtx;

impl SessionLoopCtx<'_> {
    pub(super) fn sync_runtime_tool_permissions(&mut self) {
        // 运行期工具通道权限热更新（不中断会话；撤销文件传输权限时立即中止在途传输并丢弃待投递帧）。
        let desired_tool_perms = compute_effective_tool_permissions(
            self.host.authenticated_owner().is_some(),
            self.allow_assist_file_transfer.load(Ordering::Acquire),
        );
        if desired_tool_perms != self.current_tool_perms {
            let file_revoked = self.current_tool_perms.allow_file_transfer
                && !desired_tool_perms.allow_file_transfer;
            self.current_tool_perms = desired_tool_perms;
            self.host.set_tool_permissions(self.current_tool_perms);
            if file_revoked {
                self.pending_file_in.clear();
                self.pending_file_tx.clear();
                self.file_worker = FileHostWorker::spawn(Arc::clone(&self.file_transfer_dir));
            }
            if let Some(perm_payload) = encode_tool_permissions_state(self.current_tool_perms) {
                self.pending_display_tx.set_tool_perms(perm_payload);
            }
        }
    }

    pub(super) fn sync_controller_meta(&mut self) {
        // 若对端上报或更新了 ControllerMeta，立即刷新 ActiveControllerSession 并推送更新。
        let cur_meta_gen = self.host.controller_meta_gen();
        if cur_meta_gen == self.last_controller_meta_gen {
            return;
        }
        self.last_controller_meta_gen = cur_meta_gen;
        if let Some(ref tr) = self.controller_tracking {
            let updated_ctrl = build_active_controller_session(
                self.host,
                &tr.peer_hints,
                self.active_controller_connected_at_ms,
            );
            let prev_ctrl = tr
                .active_controllers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .first()
                .cloned();
            if prev_ctrl.as_ref() != Some(&updated_ctrl) {
                publish_active_controller(
                    &tr.active_controllers,
                    self.updates,
                    Some(&tr.signal_client),
                    updated_ctrl,
                );
            }
        }
    }

    pub(super) fn update_still_refine_on_tick(&mut self, r: &rc_session::HostTickReport) {
        // 修正 #5：收到任意输入事件或产出新动态帧时，毫秒级立即抢占清空待发静止补帧并推进状态机。
        if r.events_injected > 0 {
            self.still_refine.on_input_event();
        }
        if r.datagrams_sent > 0 {
            let now_ms =
                u64::try_from(self.session_started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
            let seq = self.host.last_sent_frame_seq().unwrap_or(0);
            self.still_refine
                .on_dynamic_frame(now_ms, seq, self.host.last_dirty_rects());
            self.still_window_sent_dgrams = self
                .still_window_sent_dgrams
                .saturating_add(r.datagrams_sent as u64);
        }
        let cur_dropped_total = self.host.transport_tx_dropped_datagrams();
        let dropped_delta = cur_dropped_total.saturating_sub(self.still_last_dropped_total);
        self.still_last_dropped_total = cur_dropped_total;
        self.still_window_dropped_dgrams = self
            .still_window_dropped_dgrams
            .saturating_add(dropped_delta);
        if self.still_loss_window_at.elapsed() >= Duration::from_secs(1) {
            let total = self
                .still_window_sent_dgrams
                .saturating_add(self.still_window_dropped_dgrams);
            let loss_rate = if total > 0 {
                self.still_window_dropped_dgrams as f32 / total as f32
            } else {
                0.0
            };
            self.still_refine
                .update_network(self.host.current_bitrate_bps(), loss_rate);
            self.still_window_sent_dgrams = 0;
            self.still_window_dropped_dgrams = 0;
            self.still_loss_window_at = Instant::now();
        } else if dropped_delta > 0 {
            let total = self
                .still_window_sent_dgrams
                .saturating_add(self.still_window_dropped_dgrams)
                .max(1);
            let loss_rate = self.still_window_dropped_dgrams as f32 / total as f32;
            self.still_refine
                .update_network(self.host.current_bitrate_bps(), loss_rate);
        }
    }

    pub(super) fn poll_relay_bitrate(&mut self) {
        let Some(ref mut ctrl) = self.relay_bitrate_ctrl else {
            return;
        };
        let now_bwe = Instant::now();
        let manual_cap = self
            .host
            .last_manual_bitrate_bps()
            .map(|bps| (self.host.last_manual_bitrate_gen(), bps));
        if let Some(clamped_bps) = ctrl.sync_external_caps(
            manual_cap,
            self.host.last_remote_probe_bitrate_bps(),
            self.host.current_bitrate_bps().max(1),
            now_bwe,
        ) {
            let _ = self
                .host
                .on_set_bitrate(clamped_bps, rc_session::proto::BitrateReason::Probe as u8);
        }
        if now_bwe.saturating_duration_since(self.last_relay_bwe_at) >= Duration::from_millis(100) {
            self.last_relay_bwe_at = now_bwe;
            if let Some(next_bps) = ctrl.poll(
                now_bwe,
                self.host.transport_tx_queued_bytes(),
                self.host.transport_tx_dropped_datagrams(),
            ) {
                let _ = self
                    .host
                    .on_set_bitrate(next_bps, rc_session::proto::BitrateReason::Probe as u8);
            }
        }
    }

    pub(super) fn poll_audio_and_wallpaper(&mut self) {
        // 0) 非阻塞检查后台音频采集初始化/自愈重建（H13）与桌面壁纸初始化是否就绪。
        self.audio_mgr.poll_and_recover(
            Instant::now(),
            self.host.is_media_paused(),
            &mut self.audio_silence_gate,
        );
        if let Some(ref rx) = self.wallpaper_rx {
            match rx.try_recv() {
                Ok(jpeg) => {
                    self.wallpaper_rx = None;
                    let data_base64 = display_ctrl::base64_encode(&jpeg);
                    if let Some(wp_payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::Wallpaper {
                            mime: "image/jpeg".to_string(),
                            data_base64,
                        })
                    {
                        self.pending_display_tx.push_transient(wp_payload);
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.wallpaper_rx = None;
                }
            }
        }
    }

    pub(super) fn dispatch_incoming_tools(&mut self) -> bool {
        // 2) 工具复用通道入站分发（W2 文件异步交由专用工作线程 / W3 终端 / W4 端口映射 / 音频控制）。
        let incoming_tools = self.host.drain_tool_messages();
        let rejected_channels = self.host.drain_rejected_tool_channels();
        let mut tools_busy = !incoming_tools.is_empty() || !rejected_channels.is_empty();
        if !rejected_channels.is_empty() {
            let now_denied = Instant::now();
            for ch in rejected_channels {
                let idx = usize::from(ch);
                let should_send = if idx < self.last_tool_denied_sent.len() {
                    match self.last_tool_denied_sent[idx] {
                        None => true,
                        Some(prev) => {
                            now_denied.saturating_duration_since(prev)
                                >= TOOL_PERMISSION_DENIED_THROTTLE
                        }
                    }
                } else {
                    true
                };
                if should_send {
                    if idx < self.last_tool_denied_sent.len() {
                        self.last_tool_denied_sent[idx] = Some(now_denied);
                    }
                    if let Some(denied_payload) = display_ctrl::encode_display_ctrl(
                        &DisplayControlMsg::ToolPermissionDenied {
                            channel: ch,
                            reason: Some(format!(
                                "被控端已禁止本次远程协助使用{}",
                                crate::ui_error::tool_channel_name_zh(ch)
                            )),
                        },
                    ) {
                        self.pending_display_tx.push_transient(denied_payload);
                    }
                }
            }
        }
        for (channel, payload) in incoming_tools {
            match channel {
                TOOL_CHANNEL_FILE => {
                    if self.current_tool_perms.allow_file_transfer {
                        self.pending_file_in.push_back(payload);
                    }
                }
                TOOL_CHANNEL_TERMINAL => {
                    if self.current_tool_perms.allow_terminal && self.use_owner_terminals {
                        if self.terminal_lock_gate.is_locked() {
                            let now_prompt = Instant::now();
                            let should_emit =
                                self.last_terminal_lock_prompt_sent.map_or(true, |prev| {
                                    now_prompt.saturating_duration_since(prev)
                                        >= TOOL_PERMISSION_DENIED_THROTTLE
                                });
                            if should_emit {
                                self.last_terminal_lock_prompt_sent = Some(now_prompt);
                                if let Some(lock_payload) =
                                    encode_terminal_lock_state(true, &self.terminal_lock_gate)
                                {
                                    self.pending_display_tx.set_terminal_lock(lock_payload);
                                }
                            }
                        } else {
                            self.owner_terminals.engine.handle_incoming(&payload);
                        }
                    }
                }
                TOOL_CHANNEL_PORTMAP => {
                    if self.current_tool_perms.allow_port_map {
                        self.portmap_host.handle_incoming(&payload);
                    }
                }
                TOOL_CHANNEL_AUDIO_CTRL => {
                    if let Some(muted) = parse_audio_ctrl_muted(&payload) {
                        if self.audio_muted && !muted {
                            self.audio_silence_gate.reset();
                        }
                        self.audio_muted = muted;
                    }
                }
                TOOL_CHANNEL_DISPLAY_CTRL => {
                    self.dispatch_display_ctrl_msg(payload);
                }
                _ => {}
            }
        }

        if let Some(verify_res) = self.terminal_verify_driver.poll_completed() {
            tools_busy = true;
            let is_owner =
                self.host.authenticated_owner().is_some() && self.current_tool_perms.allow_terminal;
            handle_terminal_verify_completion(
                verify_res,
                is_owner,
                &mut self.terminal_lock_gate,
                &mut self.pending_display_tx,
            );
        }

        let is_owner_for_update = self.host.authenticated_owner().is_some();
        for umsg in self.update_worker.poll_outgoing() {
            if self.pending_update_tx.enqueue(&umsg, is_owner_for_update) {
                tools_busy = true;
            }
        }

        // H12：非阻塞冲刷入站文件帧至 `rc-file-host-worker` 有界通道（满载时留待下拍重试，零丢帧）。
        if self.current_tool_perms.allow_file_transfer {
            while let Some(front) = self.pending_file_in.front() {
                match self.file_worker.try_send_incoming(front.clone()) {
                    Ok(()) => {
                        self.pending_file_in.pop_front();
                        tools_busy = true;
                    }
                    Err(mpsc::TrySendError::Full(_)) => break,
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        self.pending_file_in.clear();
                        break;
                    }
                }
            }
        } else {
            self.pending_file_in.clear();
        }
        tools_busy
    }

    pub(super) fn poll_screen_state_and_wake(&mut self) {
        // 2.5) 接收后台唤醒结果并节流巡检被控端锁屏与采集挂起态（250ms）：
        // 变化时通知控制端；活跃桌面远控遇到采集挂起且显示器休眠时异步派发单在途后台唤醒（锁屏期间亦允许唤醒，以便显示锁屏画面并直接键鼠解锁）。
        self.mid_session_wake
            .poll_completed(&self.wake_guard, Instant::now());
        if self.last_screen_state_check.elapsed() < Duration::from_millis(250) {
            return;
        }
        let now_screen = Instant::now();
        self.last_screen_state_check = now_screen;
        let screen_locked = crate::platform::is_screen_locked();
        let capture_suspended = self.host.is_capture_suspended();
        let cur_state = (screen_locked, capture_suspended);
        let should_emit = match self.last_reported_screen_state {
            None => screen_locked || capture_suspended,
            Some(prev) => prev != cur_state,
        };
        if should_emit {
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::HostScreenState {
                    locked: screen_locked,
                    capture_suspended,
                })
            {
                self.pending_display_tx.set_screen_state(payload);
            }
        }
        self.last_reported_screen_state = Some(cur_state);

        if self
            .terminal_lock_gate
            .on_screen_lock_observed(screen_locked)
            && self.use_owner_terminals
            && self.current_tool_perms.allow_terminal
        {
            if let Some(state_payload) = encode_terminal_lock_state(true, &self.terminal_lock_gate)
            {
                self.pending_display_tx.set_terminal_lock(state_payload);
            }
        }

        if !self.host.is_media_paused()
            && self.prefer_hardware
            && capture_suspended
            && crate::platform::is_display_asleep()
        {
            self.mid_session_wake.maybe_spawn(now_screen, || {
                let res = crate::platform::wake_display_if_asleep();
                let still_asleep = crate::platform::is_display_asleep();
                (res, still_asleep)
            });
        }
    }

    pub(super) fn flush_outgoing_tools_and_media(&mut self, tools_busy: &mut bool) -> bool {
        // 3) 工具复用通道出站节流泵（每引擎单拍最多 8 帧 + 背压重试队列，零丢块且不饿死视频/输入）。
        if self.current_tool_perms.allow_file_transfer {
            if flush_tool_channel_with_retry(
                &mut self.pending_file_tx,
                MAX_TOOL_FRAMES_PER_TICK,
                |n| self.file_worker.try_recv_outgoing(n),
                |frame| self.host.send_tool_message(TOOL_CHANNEL_FILE, frame),
            ) {
                *tools_busy = true;
            }
        } else {
            self.pending_file_tx.clear();
        }
        if self.current_tool_perms.allow_terminal && self.use_owner_terminals {
            if self.terminal_lock_gate.is_locked() {
                self.pending_term_tx.clear();
                self.owner_terminals.sync_auth_and_poll(self.auth_state);
            } else if flush_tool_channel_with_retry(
                &mut self.pending_term_tx,
                MAX_TOOL_FRAMES_PER_TICK,
                |n| self.owner_terminals.engine.poll_outgoing(n),
                |frame| self.host.send_tool_message(TOOL_CHANNEL_TERMINAL, frame),
            ) {
                *tools_busy = true;
            }
        } else {
            self.pending_term_tx.clear();
            self.owner_terminals.sync_auth_and_poll(self.auth_state);
        }
        if self.current_tool_perms.allow_port_map {
            if flush_tool_channel_with_retry(
                &mut self.pending_portmap_tx,
                MAX_TOOL_FRAMES_PER_TICK,
                |n| self.portmap_host.poll_outgoing(n),
                |frame| self.host.send_tool_message(TOOL_CHANNEL_PORTMAP, frame),
            ) {
                *tools_busy = true;
            }
        } else {
            self.pending_portmap_tx.clear();
        }
        if self.pending_display_tx.flush(
            MAX_TOOL_FRAMES_PER_TICK,
            |frame| {
                self.host
                    .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, frame)
            },
            |e| matches!(e, rc_types::Error::InvalidConfig(_)),
        ) {
            *tools_busy = true;
        }
        if self.pending_update_tx.flush(
            MAX_TOOL_FRAMES_PER_TICK,
            |frame| {
                self.host
                    .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, frame)
            },
            |e| matches!(e, rc_types::Error::InvalidConfig(_)),
        ) {
            *tools_busy = true;
        }

        // 4) 系统音频采集 → IMA-ADPCM 编码 → AudioFramePacket 发送。
        //    M9：当文件/端口映射/更新中转通道存在背压待重试帧或 Stream A 发送队列深度达高水位时，提前让渡跳过音频与静态补帧避免加剧 Stream A 拥塞。
        let stream_a_congested = !self.pending_file_tx.is_empty()
            || !self.pending_portmap_tx.is_empty()
            || !self.pending_update_tx.is_empty()
            || self.host.transport_reliable_tx_queued_len() >= 16;
        // 3.5) 静止无损 Tile 补帧低优先级限速发送（仅当控制面空闲、无 Stream A 拥塞且媒体发送队列无积压时最多发送 1 片，
        //      保证控制消息、输入与动态视频流零阻塞，且输入/新帧抢占可瞬间清空未发队列）。
        if !self.host.is_media_paused()
            && self.pending_display_tx.is_empty()
            && !stream_a_congested
            && self.host.transport_tx_queued_bytes() < 64 * 1024
            && self.still_refine.is_active()
        {
            let now_ms =
                u64::try_from(self.session_started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
            if let Some(tile_msg) = self.still_refine.poll_next_display_ctrl_msg(now_ms) {
                if let Some(tile_payload) = display_ctrl::encode_display_ctrl(&tile_msg) {
                    if self
                        .host
                        .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, tile_payload)
                        .is_ok()
                    {
                        *tools_busy = true;
                    }
                }
            }
        }
        if self.host.is_media_paused() {
            false
        } else {
            match self.audio_mgr.capture_mut() {
                Some(cap) => pump_host_audio(
                    self.host,
                    cap.as_mut(),
                    self.audio_muted || stream_a_congested,
                    &mut self.audio_silence_gate,
                    &mut self.audio_seq,
                ),
                None => false,
            }
        }
    }

    pub(super) fn poll_path_switch_runtime(&mut self) {
        let Some(ref sw_rt) = self.switch_rt else {
            return;
        };
        for ev in sw_rt.handle.drain_path_events() {
            let was_relay = self.transport_kind == HostTransportKind::Relay;
            self.transport_kind = match ev.kind {
                TransportPathKind::Relay => HostTransportKind::Relay,
                TransportPathKind::P2p => HostTransportKind::P2p,
                TransportPathKind::Lan => HostTransportKind::Lan,
                TransportPathKind::MtlsLan => HostTransportKind::MtlsLan,
            };
            self.relay_bitrate_ctrl = sync_host_bitrate_on_path_switch(
                self.host,
                was_relay,
                self.transport_kind,
                self.negotiated_initial_bitrate_bps,
                Instant::now(),
            );
            let new_label = ev.kind.host_label(&sw_rt.incoming.peer_id);
            emit_peer_connected(self.host, &new_label, self.updates);
        }

        for ctrl_msg in sw_rt.handle.drain_control_msgs() {
            match ctrl_msg {
                SwitchControlMsg::UseInitialRelay => {
                    if !sw_rt.incoming.relay_addr.is_empty()
                        && !sw_rt.incoming.relay_token.is_empty()
                    {
                        spawn_host_switch_relay_candidate(
                            sw_rt.incoming.clone(),
                            sw_rt.mtls_bundle.clone(),
                            sw_rt.require_mtls,
                            Arc::clone(&sw_rt.updates),
                            Arc::clone(&sw_rt.active_relay_interrupt),
                            Arc::clone(&sw_rt.bg_cancel),
                            Arc::clone(&sw_rt.disconnect_flag),
                            Arc::clone(&sw_rt.stop_flag),
                            sw_rt.handle.clone(),
                        );
                    }
                }
                SwitchControlMsg::RelayAllocReady { session_id } => {
                    if let Some(relay_q) = self.incoming_relay {
                        if let Some(fresh_inc) =
                            relay_q.pop_by_session_id(&session_id, RELAY_INCOMING_TTL)
                        {
                            spawn_host_switch_relay_candidate(
                                fresh_inc,
                                sw_rt.mtls_bundle.clone(),
                                sw_rt.require_mtls,
                                Arc::clone(&sw_rt.updates),
                                Arc::clone(&sw_rt.active_relay_interrupt),
                                Arc::clone(&sw_rt.bg_cancel),
                                Arc::clone(&sw_rt.disconnect_flag),
                                Arc::clone(&sw_rt.stop_flag),
                                sw_rt.handle.clone(),
                            );
                        }
                    }
                }
                SwitchControlMsg::P2pReprobeOffer {
                    probe_id,
                    local_udp_port: peer_port,
                    addrs,
                    nat_type,
                    nat_port_delta,
                    nat_port_range,
                    punch_secret,
                } => {
                    if !sw_rt.skip_p2p_for_proxy {
                        let reprobe_mtls = rebuild_host_p2p_mtls(
                            sw_rt.mtls_bundle.as_ref(),
                            sw_rt.require_mtls,
                            &sw_rt.incoming.peer_id,
                            sw_rt.incoming.is_owner_connection,
                        );
                        spawn_host_reprobe_p2p_candidate(
                            probe_id,
                            peer_port,
                            addrs,
                            nat_type,
                            nat_port_delta,
                            nat_port_range,
                            punch_secret,
                            sw_rt.incoming.self_nat_type,
                            sw_rt.incoming.self_nat_port_delta,
                            sw_rt.incoming.self_nat_port_range,
                            sw_rt.incoming.local_udp_port,
                            sw_rt.incoming.self_public_addr.clone(),
                            sw_rt.incoming.peer_public_addrs.clone(),
                            Arc::clone(&sw_rt.signal_client),
                            reprobe_mtls,
                            sw_rt.require_mtls,
                            Arc::clone(&sw_rt.bg_cancel),
                            sw_rt.handle.clone(),
                        );
                    }
                }
                SwitchControlMsg::P2pReprobeAnswer { .. } => {}
            }
        }
    }

    /// 定期巡检远程强制断开与入站抢占候选；返回 `true` 表示主循环应立即 `break`。
    pub(super) fn check_preempt_and_force_disconnect(&mut self, is_detached: bool) -> bool {
        if self.last_preempt_check.elapsed() < PREEMPT_CHECK_INTERVAL {
            return false;
        }
        self.last_preempt_check = Instant::now();
        let active_sid_str = self.host.session_id().map(|id| id.to_string());
        if drain_matching_force_disconnect(
            self.controller_tracking
                .as_ref()
                .map(|tr| &tr.signal_client),
            self.controller_tracking
                .as_ref()
                .map(|tr| &tr.active_controllers),
            self.active_peer_id.as_deref(),
            active_sid_str.as_deref(),
        ) {
            self.force_disconnected = true;
            self.disconnect_flag.store(true, Ordering::Release);
            return true;
        }
        if let Some(relay_q) = self.incoming_relay {
            let idle_us = self
                .host
                .idle_since_last_client_rx_us(u64::from((self.clock)()));
            let ignore_lan_before = matches!(
                self.transport_kind,
                HostTransportKind::Lan | HostTransportKind::MtlsLan
            )
            .then_some(self.session_started_at + LAN_STALE_SIGNAL_GRACE);
            if let Some(cutoff) = ignore_lan_before {
                // 主动清掉本次 LAN 建连同源迟到的旧 PunchCoord（!is_relay_alloc），
                // 防止其滞留满 20s 后在 Detached 期复活误抢占、打断 6s 续传。
                relay_q.purge_stale_lan_punch_for_peer(
                    self.active_peer_id.as_deref(),
                    cutoff,
                    RELAY_INCOMING_TTL,
                );
            }
            let decision = if is_detached {
                relay_q.check_preempt_candidate_filtered(
                    RELAY_INCOMING_TTL,
                    self.active_peer_id.as_deref(),
                    idle_us,
                    true,
                    ignore_lan_before,
                )
            } else {
                let sw_capable = self
                    .switch_rt
                    .as_ref()
                    .is_some_and(|s| s.handle.is_switch_capable());
                relay_q.check_preempt_candidate_with_switch(
                    RELAY_INCOMING_TTL,
                    self.active_peer_id.as_deref(),
                    idle_us,
                    false,
                    ignore_lan_before,
                    sw_capable,
                )
            };
            match decision {
                PreemptDecision::TakeoverOwner => {
                    self.preempted_by_incoming = true;
                    self.preempted_by_takeover = true;
                    return true;
                }
                PreemptDecision::SamePeerOrIdle => {
                    self.preempted_by_incoming = true;
                    return true;
                }
                PreemptDecision::None => {}
            }
        }
        false
    }
}
