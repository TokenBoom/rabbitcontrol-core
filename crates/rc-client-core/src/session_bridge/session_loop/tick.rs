use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Instant;

use rc_audio::{NullAudioPlayer, PcmFrame};
use rc_session::proto::{BitrateReason, ByeReason, ControlMessage};
use rc_session::{
    SessionState, ToolPermissions, TOOL_CHANNEL_AUDIO_CTRL, TOOL_CHANNEL_DISPLAY_CTRL,
    TOOL_CHANNEL_FILE, TOOL_CHANNEL_PORTMAP, TOOL_CHANNEL_TERMINAL,
};
use rc_tools::{PortMapClientEngine, TerminalEvent};

use crate::display_ctrl::{self, DisplayControlMsg, StreamCodec};
use crate::hud::HudSnapshot;
use crate::ui_error::IntoUiError;

use super::super::adapters::{decode_audio_packet_samples, ensure_audio_player_for_format};
use super::super::classify::{classify_runtime_err_end, classify_stop_reason_end};
use super::super::display_ctrl::{
    count_decode_errors, handle_display_ctrl_msg, is_persistent_decode_failure,
    reconcile_decode_failure_on_capabilities, sample_hud, try_clear_still_overlay,
};
use super::super::queues::{flush_pending_display_tx_checked, flush_pending_tool_queue};
use super::super::routing::should_run_initial_bw_probe;
use super::super::types::{
    SessionEnd, SessionUpdate, HUD_INTERVAL, LOCAL_TOOL_DENIED_THROTTLE, MAX_TOOL_FRAMES_PER_TICK,
    PORTMAP_SNAPSHOT_INTERVAL, RUN_IDLE_POLL_BUDGET, RUN_POLL_BUDGET,
};
use super::{LoopStep, SessionLoopState};

impl SessionLoopState<'_> {
    /// 驱动 `SessionState::Streaming` 单拍全流程（探针、切径、媒体 tick、音频、工具通道、HUD 与解码健康）。
    pub(super) fn tick_streaming(&mut self) -> LoopStep {
        let now_us = u64::from((self.clock_reader)());
        if let Err(e) = self.client.pump_probes(now_us) {
            return LoopStep::ReturnErr(classify_runtime_err_end(
                "探测泵失败",
                &e,
                self.disconnect_flag.load(Ordering::Acquire),
            ));
        }
        if self.client.state() != SessionState::Streaming {
            return LoopStep::NextIter;
        }
        if should_run_initial_bw_probe(self.active_path_kind) {
            if let Err(e) = self.client.start_bw_probe(now_us) {
                return LoopStep::ReturnErr(classify_runtime_err_end(
                    "带宽粗测失败",
                    &e,
                    self.disconnect_flag.load(Ordering::Acquire),
                ));
            }
        }

        self.pump_runtime_path_switching();

        if self.clipboard_enabled_flag.load(Ordering::Acquire) {
            let _ = self.client.pump_clipboard(now_us);
        }
        let budget = if self.last_busy {
            RUN_POLL_BUDGET
        } else {
            RUN_IDLE_POLL_BUDGET
        };
        let tick_report = match self.client.tick(budget, Instant::now()) {
            Ok(rep) => rep,
            Err(e) => {
                if let Some(stop @ rc_session::StopReason::ByeReceived(ByeReason::Preempted)) =
                    self.client.closed_reason()
                {
                    return LoopStep::ReturnErr(classify_stop_reason_end(stop));
                }
                return LoopStep::ReturnErr(classify_runtime_err_end(
                    "会话运行失败",
                    &e,
                    self.disconnect_flag.load(Ordering::Acquire),
                ));
            }
        };
        if let Some(stop) = tick_report.closed {
            self.end_state = classify_stop_reason_end(&stop);
            return LoopStep::Break;
        }
        if tick_report.frames_displayed_delta > 0 {
            let latest_seq = self
                .client
                .pipeline()
                .highest_delivered_seq()
                .map(|s| s.0)
                .unwrap_or(0);
            self.still_receiver.on_dynamic_frame(latest_seq, &[]);
            if self.still_receiver.has_active_overlay() || self.pending_still_clear {
                // 全屏动态帧覆盖时直接清空所有静止叠加层（防分辨率缩小时边缘残影），
                // 若异步解码线程当前持锁，保留 pending_still_clear 在后续每拍重试直至真正清空。
                try_clear_still_overlay(
                    &self.renderer_handle,
                    &mut self.still_receiver,
                    &mut self.pending_still_clear,
                );
            }
        }

        self.pump_relay_rtt_controller();
        let audio_busy = self.pump_audio_packets();
        let (tools_busy, decode_failure_busy) = self.pump_tools_and_display_ctrl();
        self.last_busy = tick_report.busy || tools_busy || audio_busy || decode_failure_busy;

        self.pump_hud_and_decode_health()
    }

    fn pump_relay_rtt_controller(&mut self) {
        if let Some(ref mut ctrl) = self.relay_rtt_ctrl {
            if self.client.state() == SessionState::Streaming {
                let snap = self.client.probe_snapshot();
                if let Some(next_bps) = ctrl.on_probe(
                    Instant::now(),
                    snap.pongs_received,
                    self.client.latest_probe_rtt_us(),
                ) {
                    let mut buf = Vec::new();
                    ControlMessage::SetBitrate {
                        bps: next_bps,
                        reason: BitrateReason::Probe,
                    }
                    .encode(&mut buf);
                    self.pending_control
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push_back(buf);
                }
            }
        }
    }

    /// 2a) 音频帧解码与播放（M9：采样率/声道数变更时先 stop 旧播放器再按新格式重建）。
    fn pump_audio_packets(&mut self) -> bool {
        let audio_packets = self.client.drain_audio_frames();
        let audio_busy = !audio_packets.is_empty();
        for pkt in audio_packets {
            if self.audio_muted {
                continue;
            }
            let Some(samples) = decode_audio_packet_samples(&pkt) else {
                continue;
            };
            if samples.is_empty() {
                continue;
            }
            let prefer_hardware = self.cfg.prefer_hardware;
            ensure_audio_player_for_format(
                &mut self.audio_player,
                &mut self.audio_player_format,
                pkt.sample_rate,
                pkt.channels,
                self.audio_muted,
                |sr, ch| {
                    if prefer_hardware {
                        rc_audio::create_audio_player(sr, ch)
                            .unwrap_or_else(|_| Box::new(NullAudioPlayer::new()))
                    } else {
                        Box::new(NullAudioPlayer::new())
                    }
                },
            );
            if let Some(player) = self.audio_player.as_mut() {
                let frame = PcmFrame {
                    sample_rate: pkt.sample_rate,
                    channels: pkt.channels,
                    timestamp_us: pkt.timestamp_us,
                    samples,
                };
                let _ = player.push_frame(&frame);
            }
        }
        audio_busy
    }

    /// 2b) W2/W3/W4 工具复用通道与显示控制通道收发。
    fn pump_tools_and_display_ctrl(&mut self) -> (bool, bool) {
        let incoming_tools = self.client.drain_tool_messages();
        let mut tools_busy = !incoming_tools.is_empty();
        let mut non_file_incoming: Vec<(u8, Vec<u8>)> = Vec::new();

        for (channel, payload) in incoming_tools {
            if channel == TOOL_CHANNEL_FILE {
                self.pending_file_in.push_back(payload);
            } else if channel == TOOL_CHANNEL_DISPLAY_CTRL {
                self.handle_incoming_display_ctrl(&payload, &mut tools_busy);
            } else {
                non_file_incoming.push((channel, payload));
            }
        }

        let decode_failure_busy = self.consume_pipeline_decode_failures();
        self.exchange_tool_channel_frames(non_file_incoming, &mut tools_busy);

        (tools_busy, decode_failure_busy)
    }

    fn handle_incoming_display_ctrl(&mut self, payload: &[u8], tools_busy: &mut bool) {
        let Some(msg) = display_ctrl::decode_display_ctrl(payload) else {
            return;
        };
        let mut suppress_update_emit = false;
        let mut caps_ext_meta: Option<(bool, u64)> = None;
        match &msg {
            DisplayControlMsg::Capabilities {
                current_width,
                current_height,
                supports_ext_codec_flags,
                codec_generation,
                still_stream_epoch,
                supports_pixel_scroll,
                supports_controller_meta,
                ..
            } => {
                if *supports_pixel_scroll {
                    self.client.set_peer_supports_pixel_scroll(true);
                    self.scroll_state.update_peer_capability(true);
                }
                if *supports_controller_meta && !self.client.peer_supports_controller_meta() {
                    if let Err(e) = self.client.enable_peer_supports_controller_meta() {
                        eprintln!("[rc-client] send ControllerMeta after Capabilities failed: {e}");
                    }
                }
                caps_ext_meta = Some((*supports_ext_codec_flags, *codec_generation));
                let target_w = if *current_width > 0 {
                    *current_width
                } else {
                    self.hud_width
                };
                let target_h = if *current_height > 0 {
                    *current_height
                } else {
                    self.hud_height
                };
                let dims_changed = (target_w, target_h) != self.still_receiver.dimensions();
                let epoch_changed = *still_stream_epoch > 0
                    && *still_stream_epoch != self.still_receiver.current_epoch();
                if epoch_changed || dims_changed {
                    let next_epoch = if *still_stream_epoch > 0 {
                        *still_stream_epoch
                    } else {
                        self.still_receiver.current_epoch().saturating_add(1)
                    };
                    self.still_receiver
                        .on_stream_reset(next_epoch, target_w, target_h);
                    try_clear_still_overlay(
                        &self.renderer_handle,
                        &mut self.still_receiver,
                        &mut self.pending_still_clear,
                    );
                }
            }
            DisplayControlMsg::StillTileRefine { .. } => {
                suppress_update_emit = true;
                if self.pending_still_clear {
                    try_clear_still_overlay(
                        &self.renderer_handle,
                        &mut self.still_receiver,
                        &mut self.pending_still_clear,
                    );
                }
                if self.pending_still_clear
                    || !self.still_refinement_enabled
                    || self.client.is_media_paused()
                {
                    self.still_receiver.record_dropped();
                } else if let Ok((patch, raw_len)) =
                    self.still_receiver.decode_msg_without_commit(&msg)
                {
                    // 绝不在持有渲染器锁期间做 QOI 解码，且以 `try_lock` 非阻塞叠加，
                    // 若异步解码线程正在呈现新动态帧则直接让路记丢弃，零阻塞视频主循环。
                    let applied = self
                        .renderer_handle
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .as_ref()
                        .is_some_and(|rend| {
                            rend.try_lock()
                                .is_ok_and(|mut r| r.apply_still_tile(&patch).is_ok())
                        });
                    if applied {
                        self.still_receiver.commit_applied(raw_len);
                    } else {
                        self.still_receiver.record_dropped();
                    }
                }
                *self
                    .still_refine_metrics
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = self.still_receiver.metrics();
            }
            DisplayControlMsg::UpdateChunkAck { next_offset } => {
                self.update_relay.on_chunk_ack(*next_offset);
            }
            DisplayControlMsg::UpdateStatus {
                stage,
                need_controller_relay,
                request_id,
                ..
            } => {
                let has_unsent_trigger = self.pending_update_tx.iter().any(|(is_trig, _)| *is_trig);
                let stale_request =
                    *request_id != 0 && *request_id != self.active_update_request_id;
                let stale_for_unsent_trigger = has_unsent_trigger
                    && (matches!(
                        stage,
                        crate::updater::UpdateStage::Failed
                            | crate::updater::UpdateStage::Succeeded
                            | crate::updater::UpdateStage::Restarting
                    ) || (matches!(stage, crate::updater::UpdateStage::Relaying)
                        && *need_controller_relay));

                if stale_request || stale_for_unsent_trigger {
                    // 跨重试/跨 RTT/背压未发出新 Trigger 前到达的旧任务状态一律静默忽略。
                    suppress_update_emit = true;
                } else if matches!(stage, crate::updater::UpdateStage::Relaying)
                    && !*need_controller_relay
                {
                    // 中转推送进度与本地失败均由控制端统一上报，无条件抑制主机侧
                    // `Relaying(need_controller_relay=false)` 帧，杜绝进度回跳及覆盖本地 Failed。
                    suppress_update_emit = true;
                } else if matches!(stage, crate::updater::UpdateStage::Relaying)
                    && *need_controller_relay
                {
                    self.update_relay.maybe_start_relay_for_host_request();
                    if self.update_relay.is_active() {
                        self.awaiting_host_relay_finish = true;
                    }
                } else if matches!(
                    stage,
                    crate::updater::UpdateStage::Failed
                        | crate::updater::UpdateStage::Succeeded
                        | crate::updater::UpdateStage::Restarting
                ) {
                    self.awaiting_host_relay_finish = false;
                    self.update_relay.cancel_active_relay();
                    self.pending_update_tx.clear();
                } else {
                    self.awaiting_host_relay_finish = false;
                }
            }
            DisplayControlMsg::ToolPermissionsState {
                allow_file_transfer,
                allow_terminal,
                allow_port_map,
            } => {
                self.peer_tool_perms = ToolPermissions {
                    allow_file_transfer: *allow_file_transfer,
                    allow_terminal: *allow_terminal,
                    allow_port_map: *allow_port_map,
                };
                if !self.peer_tool_perms.allow_file_transfer {
                    self.pending_file_in.clear();
                    self.pending_file_tx.clear();
                    self.file_worker
                        .abort_all_active("目标设备已禁用文件传输权限，当前传输已中止");
                }
                if !self.peer_tool_perms.allow_terminal {
                    self.pending_term_tx.clear();
                }
                if !self.peer_tool_perms.allow_port_map {
                    self.pending_portmap_tx.clear();
                    self.last_portmap_snapshot.clear();
                }
                // 严格遵循 `tools_hub -> tool_permissions -> portmap_latest` 全局锁序，
                // 原子更新权限标志并同步清理已撤销工具引擎状态，彻底消除 TOCTOU。
                let mut hub = self.tools_hub.lock().unwrap_or_else(|e| e.into_inner());
                *self
                    .tool_permissions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = self.peer_tool_perms;
                if !self.peer_tool_perms.allow_terminal {
                    hub.reset_terminal();
                }
                if !self.peer_tool_perms.allow_port_map {
                    hub.portmap = PortMapClientEngine::new();
                    *self
                        .portmap_latest
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Some(Vec::new());
                }
            }
            _ => {}
        }

        if suppress_update_emit {
            return;
        }
        let Some(upd) = handle_display_ctrl_msg(
            msg,
            &mut self.hud_width,
            &mut self.hud_height,
            self.client_supports_hevc,
        ) else {
            return;
        };
        if let SessionUpdate::DisplayConfig {
            fps,
            ref codec,
            ref supported_codecs,
            ..
        } = upd
        {
            if fps > 0 {
                self.current_fps = fps;
            }
            let reported_codec = codec.as_deref().and_then(StreamCodec::parse_lossy);
            self.active_codec = reported_codec.unwrap_or(StreamCodec::H264);
            self.host_supports_hevc = supported_codecs
                .iter()
                .any(|c| StreamCodec::parse_lossy(c) == Some(StreamCodec::Hevc))
                || reported_codec == Some(StreamCodec::Hevc);
            if let Some((ext_flags, codec_gen)) = caps_ext_meta {
                self.host_supports_ext_codec_flags = ext_flags;
                if codec_gen > 0 {
                    self.host_codec_generation = codec_gen;
                }
                if let Some(reemit) = reconcile_decode_failure_on_capabilities(
                    &mut self.pending_unrecovered_decode_failure,
                    self.active_codec.into(),
                    self.host_codec_generation,
                ) {
                    if let Some(payload) = display_ctrl::encode_display_ctrl(&reemit) {
                        self.pending_display_tx.push_front(payload);
                        *tools_busy = true;
                    }
                }
                // 兼容老版被控端（不支持 ClientMediaCaps / supports_ext_codec_flags == false）：
                // 若双端支持 HEVC 且当前仍为 H.264，则按旧协议发送 SetCodec("hevc")。
                if !ext_flags
                    && !self.client.is_media_paused()
                    && self.client_supports_hevc
                    && self.host_supports_hevc
                    && self.active_codec == StreamCodec::H264
                    && self.user_pinned_codec != Some(StreamCodec::H264)
                    && !self.legacy_hevc_requested
                {
                    self.legacy_hevc_requested = true;
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetCodec {
                            codec: StreamCodec::Hevc.as_str().to_string(),
                        })
                    {
                        self.pending_display_tx.push_back(payload);
                        self.active_codec = StreamCodec::Hevc;
                    }
                }
            }
        }
        self.update_tx.push(upd);
    }

    /// 在 `drain_tool_messages()` 更新 `host_codec_generation` 之后再消费控制端管线热切/解码失败事件，
    /// 避免同拍抵达的 UDP 新 codec 帧与 Stream A `Capabilities` 出现代次倒置，并记录未恢复失败态以便晚到 Capabilities 补发。
    fn consume_pipeline_decode_failures(&mut self) -> bool {
        let mut decode_failure_busy = false;
        while let Some(failure) = self.client.take_decode_failure() {
            let ui_err = rc_types::Error::Decoder(format!(
                "codec {} decode failed (gen={}): {}",
                failure.codec.as_str(),
                self.host_codec_generation,
                failure.reason
            ))
            .to_ui_error(crate::ui_error::current_platform());
            eprintln!(
                "rc-ui: [{}] {} (codec={}, gen={}, detail={})",
                ui_err.code,
                ui_err.title,
                failure.codec.as_str(),
                self.host_codec_generation,
                failure.reason
            );
            self.pending_unrecovered_decode_failure = Some((
                failure.codec,
                self.host_codec_generation,
                failure.reason.clone(),
            ));
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::CodecDecodeFailed {
                    codec: failure.codec.as_str().to_string(),
                    generation: self.host_codec_generation,
                    reason: failure.reason,
                })
            {
                self.pending_display_tx.push_front(payload);
                decode_failure_busy = true;
            }
        }
        decode_failure_busy
    }

    /// 与文件工作线程、`tools_hub` 和网络通道交换 W2/W3/W4 工具帧与显示控制帧。
    fn exchange_tool_channel_frames(
        &mut self,
        non_file_incoming: Vec<(u8, Vec<u8>)>,
        tools_busy: &mut bool,
    ) {
        let poll_file = self.pending_file_tx.is_empty();
        let poll_term = self.pending_term_tx.is_empty();
        let poll_portmap = self.pending_portmap_tx.is_empty();
        let mut new_term_events: Vec<TerminalEvent> = Vec::new();

        // H12：非阻塞冲刷入站文件帧至专用文件工作线程（满载时留待下拍重试，零丢帧；权限被禁时立即清空）。
        if self.peer_tool_perms.allow_file_transfer {
            while let Some(front) = self.pending_file_in.front() {
                match self.file_worker.try_send_incoming(front.clone()) {
                    Ok(()) => {
                        self.pending_file_in.pop_front();
                        *tools_busy = true;
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

        // H12：在 `tools_hub.lock()` 之外非阻塞拉取文件工作线程产出的出站线帧（权限被禁时跳过拉取并清空队列，防止空读刷屏）。
        let file_out = if poll_file && self.peer_tool_perms.allow_file_transfer {
            self.file_worker.try_recv_outgoing(MAX_TOOL_FRAMES_PER_TICK)
        } else {
            if !self.peer_tool_perms.allow_file_transfer {
                self.pending_file_tx.clear();
            }
            Vec::new()
        };

        let (term_out, pm_out) = {
            let mut hub = self.tools_hub.lock().unwrap_or_else(|e| e.into_inner());
            let mut pm_dirty = false;
            for (channel, payload) in non_file_incoming {
                match channel {
                    TOOL_CHANNEL_TERMINAL if self.peer_tool_perms.allow_terminal => {
                        let evs = hub.terminal.handle_incoming(&payload);
                        for ev in &evs {
                            hub.apply_terminal_event(ev);
                        }
                        new_term_events.extend(evs);
                    }
                    TOOL_CHANNEL_PORTMAP
                        if self.peer_tool_perms.allow_port_map
                            && hub.portmap.handle_incoming(&payload) =>
                    {
                        pm_dirty = true;
                    }
                    _ => {}
                }
            }

            let t_out = if poll_term && self.peer_tool_perms.allow_terminal {
                hub.terminal.poll_outgoing(MAX_TOOL_FRAMES_PER_TICK)
            } else {
                Vec::new()
            };
            let p_out = if poll_portmap && self.peer_tool_perms.allow_port_map {
                hub.portmap.poll_outgoing(MAX_TOOL_FRAMES_PER_TICK)
            } else {
                Vec::new()
            };

            if (pm_dirty
                || !p_out.is_empty()
                || self.last_portmap_poll_at.elapsed() >= PORTMAP_SNAPSHOT_INTERVAL)
                && self.peer_tool_perms.allow_port_map
            {
                self.last_portmap_poll_at = Instant::now();
                let cur_rules = hub.portmap.list_rules();
                if cur_rules != self.last_portmap_snapshot {
                    self.last_portmap_snapshot = cur_rules.clone();
                    // 与 ToolClientHandle 共享严格 `hub -> portmap_latest` 锁序，防并发乱序覆盖。
                    *self
                        .portmap_latest
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Some(cur_rules);
                }
            }

            (t_out, p_out)
        };

        self.pending_file_tx.extend(file_out);
        self.pending_term_tx.extend(term_out);
        self.pending_portmap_tx.extend(pm_out);

        if self.client.state() == SessionState::Streaming {
            if let Some(ctrl) = self.pending_audio_ctrl.as_ref() {
                if self
                    .client
                    .send_tool_message(TOOL_CHANNEL_AUDIO_CTRL, ctrl.clone())
                    .is_ok()
                {
                    self.pending_audio_ctrl = None;
                    *tools_busy = true;
                }
            }
            let peer_perms = self.peer_tool_perms;
            let last_denied = &mut self.last_local_tool_denied;
            let update_tx = &self.update_tx;
            let client = &mut self.client;
            let mut gate_or_flush = |channel: u8, queue: &mut VecDeque<Vec<u8>>| -> bool {
                if !peer_perms.allows_channel(channel) {
                    if !queue.is_empty() {
                        queue.clear();
                        let now_denied = Instant::now();
                        let idx = usize::from(channel);
                        let should_emit = if idx < last_denied.len() {
                            match last_denied[idx] {
                                None => true,
                                Some(prev) => {
                                    now_denied.saturating_duration_since(prev)
                                        >= LOCAL_TOOL_DENIED_THROTTLE
                                }
                            }
                        } else {
                            true
                        };
                        if should_emit {
                            if idx < last_denied.len() {
                                last_denied[idx] = Some(now_denied);
                            }
                            update_tx.push(SessionUpdate::ToolPermissionDenied {
                                channel,
                                ui_error: crate::ui_error::tool_forbidden_ui_error(
                                    channel,
                                    crate::ui_error::current_platform(),
                                    None,
                                ),
                            });
                        }
                    }
                    false
                } else {
                    flush_pending_tool_queue(queue, |frame| {
                        client.send_tool_message(channel, frame)
                    })
                }
            };
            if gate_or_flush(TOOL_CHANNEL_FILE, &mut self.pending_file_tx) {
                *tools_busy = true;
            }
            if gate_or_flush(TOOL_CHANNEL_TERMINAL, &mut self.pending_term_tx) {
                *tools_busy = true;
            }
            if gate_or_flush(TOOL_CHANNEL_PORTMAP, &mut self.pending_portmap_tx) {
                *tools_busy = true;
            }
            let update_tx_budget = crate::updater::UPDATE_RELAY_WINDOW_CHUNKS
                .saturating_sub(self.pending_update_tx.len());
            if update_tx_budget > 0 {
                let (relay_msgs, relay_progs) = self.update_relay.poll_bounded(update_tx_budget);
                for rmsg in relay_msgs {
                    if let Some(payload) = display_ctrl::encode_display_ctrl(&rmsg) {
                        self.pending_update_tx.push_back((false, payload));
                        *tools_busy = true;
                    }
                }
                for rprog in relay_progs {
                    if matches!(
                        rprog.stage,
                        crate::updater::UpdateStage::Failed
                            | crate::updater::UpdateStage::Succeeded
                            | crate::updater::UpdateStage::Restarting
                    ) {
                        self.awaiting_host_relay_finish = false;
                    }
                    self.update_tx
                        .push(SessionUpdate::RemoteUpdateStatus(rprog));
                }
            }
            if flush_pending_display_tx_checked(
                &mut self.pending_display_tx,
                |frame| {
                    self.client
                        .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, frame)
                },
                |e| matches!(e, rc_types::Error::InvalidConfig(_)),
            ) {
                *tools_busy = true;
            }
            for _ in 0..MAX_TOOL_FRAMES_PER_TICK {
                let Some((_, frame)) = self.pending_update_tx.front() else {
                    break;
                };
                match self
                    .client
                    .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, frame.clone())
                {
                    Ok(()) => {
                        self.pending_update_tx.pop_front();
                        *tools_busy = true;
                    }
                    Err(rc_types::Error::InvalidConfig(_)) => {
                        self.pending_update_tx.pop_front();
                    }
                    Err(_) => break,
                }
            }
        }
        for ev in new_term_events {
            self.terminal_events.push_drop_oldest(ev);
        }
    }

    /// 3) 首帧诊断、1s 节流推送 HUD 快照与持久硬件解码失败检测。
    fn pump_hud_and_decode_health(&mut self) -> LoopStep {
        let displayed_now = self.client.pipeline().displayed();
        if !self.first_frame_logged && displayed_now > 0 {
            self.first_frame_logged = true;
            eprintln!(
                "rc-ui: first video frame presented (backend={}, displayed={displayed_now})",
                self.backend
            );
        }

        if self.last_hud_at.elapsed() >= HUD_INTERVAL {
            let mut cur_negotiated = self.client.negotiated().unwrap_or(self.negotiated);
            cur_negotiated.width = self.hud_width;
            cur_negotiated.height = self.hud_height;
            let cur = sample_hud(&self.client, &self.clock_reader, cur_negotiated);
            let snap = HudSnapshot::derive_with_transport(
                Some(&self.prev_hud),
                &cur,
                self.transport_label,
            );
            self.update_tx.push(SessionUpdate::Hud(snap));
            self.prev_hud = cur;
            self.last_hud_at = Instant::now();

            // 当本地启用 VideoToolbox 硬件解码但远端持续产出非 H.264 码流（例如被控端
            // 未授屏幕录制权限而降级到 FakeEncoder）时，`displayed` 恒为 0 且持续出现
            // `Outcome::DecodeError`。达到阈值时显式报错并结束会话，避免无限静默黑屏。
            // 媒体处于暂停态（纯工具模式）时跳过检查。
            if !self.client.is_media_paused() && self.is_hardware_decoder && displayed_now == 0 {
                let decode_errors = count_decode_errors(&self.client);
                if decode_errors > 0 && !self.decode_error_logged {
                    self.decode_error_logged = true;
                    eprintln!(
                        "rc-ui: hardware decoder reporting decode errors before first frame \
                         (backend={}, decode_errors={decode_errors})",
                        self.backend
                    );
                }
                if is_persistent_decode_failure(
                    self.is_hardware_decoder,
                    displayed_now,
                    decode_errors,
                    self.stream_started_at.elapsed(),
                ) {
                    eprintln!(
                        "rc-ui: persistent hardware decode failure \
                         (backend={}, displayed=0, decode_errors={decode_errors}); \
                         ending session",
                        self.backend
                    );
                    self.end_state =
                        SessionEnd::fatal("远端画面解码失败（请确认被控端已授予屏幕录制权限）");
                    return LoopStep::Break;
                }
            }
        }
        LoopStep::Continue
    }
}
