use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use rc_session::{ReconnectOutcome, ToolPermissions};

use crate::codec_selector::{self, CodecSelectionPref};
use crate::display_ctrl::{self, DisplayControlMsg, StreamCodec};

use super::super::adapters::{apply_stage_rect_to_slot, encode_audio_ctrl_muted};
use super::super::classify::{
    classify_gave_up_end, classify_runtime_err_end, signaling_disconnect_end,
};
use super::super::display_ctrl::{
    build_client_media_caps_msg, refresh_after_reconnect_outcome, try_clear_still_overlay,
};
use super::super::types::{SessionUpdate, RUN_RECONNECT_SLEEP};
use super::{LoopStep, SessionLoopState};

impl SessionLoopState<'_> {
    /// 驱动 `SessionState::Reconnecting` 单拍状态（纯 IP 自动重连或信令会话可恢复退出）。
    pub(super) fn tick_reconnecting(&mut self) -> LoopStep {
        if self.is_signaling_session {
            self.end_state = signaling_disconnect_end(self.transport_label);
            return LoopStep::Break;
        }
        let max_attempts = self.client.reconnect_config().backoff_max_attempts.max(1);
        if !self.in_reconnecting {
            self.in_reconnecting = true;
            self.reconnect_base_attempts = self.client.reconnect_stats().reconnect_attempts;
            self.last_emitted_reconnect_attempt = 1;
            self.update_tx.push(SessionUpdate::Reconnecting {
                attempt: 1,
                max_attempts,
                reason: "连接已中断，正在尝试重连…".to_string(),
            });
        }
        let outcome = match self.client.tick_reconnect(u64::from((self.clock_reader)())) {
            Ok(outcome) => outcome,
            Err(e) => {
                return LoopStep::ReturnErr(classify_runtime_err_end(
                    "重连驱动失败",
                    &e,
                    self.disconnect_flag.load(Ordering::Acquire),
                ));
            }
        };
        let cur_attempt = self
            .client
            .reconnect_stats()
            .reconnect_attempts
            .saturating_sub(self.reconnect_base_attempts);
        if cur_attempt > self.last_emitted_reconnect_attempt
            && matches!(
                outcome,
                ReconnectOutcome::Connecting | ReconnectOutcome::Waiting { .. }
            )
        {
            let display_attempt = cur_attempt.min(max_attempts);
            self.last_emitted_reconnect_attempt = cur_attempt;
            self.update_tx.push(SessionUpdate::Reconnecting {
                attempt: display_attempt,
                max_attempts,
                reason: format!("第 {display_attempt}/{max_attempts} 次重连尝试中…"),
            });
        }
        match outcome {
            ReconnectOutcome::Waiting { next_attempt_in_ms } => {
                let nap = Duration::from_millis(next_attempt_in_ms).min(RUN_RECONNECT_SLEEP);
                thread::sleep(nap);
            }
            ReconnectOutcome::GaveUp => {
                self.end_state = classify_gave_up_end(self.client.closed_reason());
                return LoopStep::Break;
            }
            outcome @ (ReconnectOutcome::Resumed | ReconnectOutcome::Rebuilt) => {
                self.handle_reconnect_restored(outcome);
            }
            ReconnectOutcome::Connecting => {}
        }
        LoopStep::Continue
    }

    fn handle_reconnect_restored(&mut self, outcome: ReconnectOutcome) {
        self.in_reconnecting = false;
        self.last_emitted_reconnect_attempt = 0;
        refresh_after_reconnect_outcome(&mut self.client, &self.input_rx, &self.scroll_state);
        if matches!(outcome, ReconnectOutcome::Rebuilt) {
            self.backend = self
                .backend_label
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            self.is_hardware_decoder = self.is_hw_decoder_slot.load(Ordering::Acquire);
            self.client_decode_caps = codec_selector::cached_or_platform_decode_caps(
                self.cfg.prefer_hardware && self.is_hardware_decoder,
            );
            self.client_supports_hevc = self.cfg.prefer_hardware
                && self.is_hardware_decoder
                && (rc_pipeline::platform_supports_hevc()
                    || self
                        .client_decode_caps
                        .iter()
                        .any(|c| c.codec == rc_encode::Codec::Hevc && c.hardware));
            self.client_supports_av1 = self.cfg.prefer_hardware
                && self.is_hardware_decoder
                && self
                    .client_decode_caps
                    .iter()
                    .any(|c| c.codec == rc_encode::Codec::Av1 && c.hardware);
            self.active_codec = StreamCodec::H264;
            self.host_supports_ext_codec_flags = false;
            self.host_codec_generation = 1;
            self.pending_unrecovered_decode_failure = None;
            self.legacy_hevc_requested = false;
            if let Some((w, h)) = self.last_stage_rect {
                apply_stage_rect_to_slot(
                    &self.renderer_handle,
                    &self.renderer_pending_resize,
                    w,
                    h,
                );
            }
        }
        if let Some(n) = self.client.negotiated() {
            self.hud_width = n.width;
            self.hud_height = n.height;
            if n.fps > 0 {
                self.current_fps = n.fps;
            }
        }
        if matches!(outcome, ReconnectOutcome::Rebuilt) {
            self.still_receiver.on_stream_reset(
                self.still_receiver.current_epoch().saturating_add(1),
                self.hud_width,
                self.hud_height,
            );
            try_clear_still_overlay(
                &self.renderer_handle,
                &mut self.still_receiver,
                &mut self.pending_still_clear,
            );
        }
        // M9：重连恢复或重建后若本地处于静音态，重新向主机同步静音控制消息。
        if self.audio_muted {
            self.pending_audio_ctrl = Some(encode_audio_ctrl_muted(true));
        }
        let mut upgraded_after_reconnect = false;
        if self.pending_desktop_upgrade {
            self.pending_desktop_upgrade = false;
            upgraded_after_reconnect = self.run_desktop_upgrade();
        }
        if !upgraded_after_reconnect && self.client.is_media_paused() {
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetMediaPaused {
                    paused: true,
                })
            {
                self.pending_display_tx.push_back(payload);
            }
        }
        // 重连恢复（`Resumed` 丢失在途 QUIC Stream A 分块）或重建（`Rebuilt`）后均需中止进行中的安装包中转，
        // 避免主机接收线程死等丢失分块或控制器卡在 92%；重建时另外重新协商 HEVC。
        let was_relaying = self.update_relay.is_active() || self.awaiting_host_relay_finish;
        if matches!(outcome, ReconnectOutcome::Rebuilt) {
            self.peer_tool_perms = ToolPermissions::all_allowed();
            *self
                .tool_permissions
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = self.peer_tool_perms;
            self.last_local_tool_denied = [None; 8];
        }
        if matches!(outcome, ReconnectOutcome::Rebuilt) || was_relaying {
            self.awaiting_host_relay_finish = false;
            self.update_relay.cancel_active_relay();
            self.pending_update_tx.clear();
            if was_relaying {
                let msg_text = if matches!(outcome, ReconnectOutcome::Rebuilt) {
                    "会话已重建，安装包中转已中断，请重试"
                } else {
                    "连接短暂中断，安装包中转已中断，请重试"
                };
                self.update_tx.push(SessionUpdate::RemoteUpdateStatus(
                    crate::updater::UpdateProgress {
                        stage: crate::updater::UpdateStage::Failed,
                        progress_pct: 0,
                        downloaded_bytes: 0,
                        total_bytes: 0,
                        target_version: String::new(),
                        message: msg_text.to_string(),
                        need_controller_relay: false,
                        error: Some(msg_text.to_string()),
                    },
                ));
            }
        }
        if matches!(outcome, ReconnectOutcome::Rebuilt)
            && !upgraded_after_reconnect
            && !self.client.is_media_paused()
        {
            let pref = self
                .user_pinned_codec
                .map(|c| CodecSelectionPref::Manual(c.into()))
                .unwrap_or(CodecSelectionPref::Auto);
            if let Some(payload) = display_ctrl::encode_display_ctrl(&build_client_media_caps_msg(
                &self.client_decode_caps,
                self.cfg.prefer_hardware && self.is_hardware_decoder,
                pref,
            )) {
                self.pending_display_tx.push_back(payload);
            }
            if !self.still_refinement_enabled {
                if let Some(payload) =
                    display_ctrl::encode_display_ctrl(&DisplayControlMsg::StillRefineConfig {
                        enabled: false,
                    })
                {
                    self.pending_display_tx.push_back(payload);
                }
            }
        }
    }
}
