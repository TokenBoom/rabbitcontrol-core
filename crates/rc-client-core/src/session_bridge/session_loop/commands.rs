use std::sync::atomic::Ordering;
use std::time::Instant;

use rc_session::proto::{BitrateReason, ControlMessage, ControllerMeta};
use rc_session::SessionState;

use crate::display_ctrl::{self, DisplayControlMsg, StreamCodec};

use super::super::adapters::{
    apply_stage_rect_to_slot, build_controller_pipeline, encode_audio_ctrl_muted,
};
use super::super::connect::compute_controller_meta_mode;
use super::super::display_ctrl::{
    try_clear_still_overlay, try_resume_or_upgrade_desktop, DesktopUpgradeCtx,
};
use super::super::types::{SessionCommand, SessionUpdate, COMMAND_CHANNEL_CAP};
use super::SessionLoopState;

impl SessionLoopState<'_> {
    pub(super) fn sync_controller_meta(&mut self) {
        if self.client.state() == SessionState::Streaming {
            let desired_mode = compute_controller_meta_mode(
                self.live_watch_only.load(Ordering::Acquire),
                self.client.is_media_paused(),
            );
            if desired_mode != self.last_sent_controller_mode {
                self.last_sent_controller_mode = desired_mode;
                let _ = self.client.send_controller_meta(ControllerMeta {
                    mode: desired_mode,
                    ..self.initial_controller_meta.clone()
                });
            }
        }
    }

    pub(super) fn run_desktop_upgrade(&mut self) -> bool {
        let surface = self
            .render_surface
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let prefer_hw = self.cfg.prefer_hardware;
        let t0 = self.t0;
        try_resume_or_upgrade_desktop(
            DesktopUpgradeCtx {
                client: &mut self.client,
                real_pipeline_built: &self.real_pipeline_built,
                want_real_pipeline: &self.want_real_pipeline,
                is_hw_decoder_slot: &self.is_hw_decoder_slot,
                backend: &mut self.backend,
                backend_label: &self.backend_label,
                renderer_handle: &self.renderer_handle,
                renderer_pending_resize: &self.renderer_pending_resize,
                layer_lease: &self.layer_lease,
                active_backend_suffix: self.active_backend_suffix,
                is_hardware_decoder: &mut self.is_hardware_decoder,
                client_supports_hevc: &mut self.client_supports_hevc,
                client_supports_av1: &mut self.client_supports_av1,
                client_decode_caps: &mut self.client_decode_caps,
                user_pinned_codec: self.user_pinned_codec,
                still_refinement_enabled: self.still_refinement_enabled,
                prefer_hardware: prefer_hw,
                hud_width: self.hud_width,
                hud_height: self.hud_height,
                current_fps: self.current_fps,
                negotiated: self.negotiated,
                last_stage_rect: self.last_stage_rect,
                stream_started_at: &mut self.stream_started_at,
                first_frame_logged: &mut self.first_frame_logged,
                decode_error_logged: &mut self.decode_error_logged,
                pending_display_tx: &mut self.pending_display_tx,
                update_tx: &self.update_tx,
            },
            |upgrade_pcfg| build_controller_pipeline(upgrade_pcfg, prefer_hw, t0, surface.as_ref()),
        )
    }

    /// 排空并执行来自 UI 的控制命令。
    pub(super) fn process_ui_commands(&mut self) {
        // 若上一拍因异步解码线程持锁争用未能清空静止无损叠加层，每拍开头非阻塞重试直至实际清除完成。
        if self.pending_still_clear {
            try_clear_still_overlay(
                &self.renderer_handle,
                &mut self.still_receiver,
                &mut self.pending_still_clear,
            );
        }

        // 1) 处理来自 UI 的控制命令。
        for cmd in self.cmd_rx.drain_all() {
            match cmd {
                SessionCommand::Disconnect => {
                    self.disconnect_requested = true;
                }
                SessionCommand::SetBitrate { bps } => {
                    if bps > 0 && self.client.state() == SessionState::Streaming {
                        self.last_manual_bitrate_bps = Some(bps);
                        if let Some(ref mut ctrl) = self.relay_rtt_ctrl {
                            ctrl.on_manual_bitrate(bps, Instant::now());
                        }
                        let mut buf = Vec::new();
                        ControlMessage::SetBitrate {
                            bps,
                            reason: BitrateReason::Manual,
                        }
                        .encode(&mut buf);
                        self.pending_control
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push_back(buf);
                    }
                }
                SessionCommand::StageRect { width, height } => {
                    if width > 0 && height > 0 {
                        self.last_stage_rect = Some((width, height));
                        apply_stage_rect_to_slot(
                            &self.renderer_handle,
                            &self.renderer_pending_resize,
                            width,
                            height,
                        );
                    }
                }
                SessionCommand::SetClipboardEnabled { enabled } => {
                    let prev = self.clipboard_enabled_flag.swap(enabled, Ordering::AcqRel);
                    if enabled && !prev {
                        // 重新开启时重置基线，避免把暂停期间复制的内容突发外发。
                        self.client.reset_clipboard_epoch();
                    }
                }
                SessionCommand::SetAudioMuted { muted } => {
                    self.audio_muted = muted;
                    if let Some(ref mut player) = self.audio_player {
                        player.set_muted(muted);
                    }
                    self.pending_audio_ctrl = Some(encode_audio_ctrl_muted(muted));
                }
                SessionCommand::SetStreamParams { width, height, fps } => {
                    let (eff_w, eff_h) = if width > 0 && height > 0 {
                        (width, height)
                    } else {
                        (self.hud_width, self.hud_height)
                    };
                    let eff_fps = if fps > 0 { fps } else { self.current_fps };
                    // 当用户未手动锁定 H.264、切入超出 H.264 高刷甜点的分辨率/帧率组合且双端均支持 HEVC 时，
                    // 通过 SetStream 附带 codec="hevc" 原子升级，避免两次硬件管线重建与中间态 Capabilities 抖动。
                    let auto_hevc = self.active_codec == StreamCodec::H264
                        && self.user_pinned_codec != Some(StreamCodec::H264)
                        && self.host_supports_hevc
                        && self.client_supports_hevc
                        && !display_ctrl::is_within_high_refresh_sweet_spot(
                            eff_w,
                            eff_h,
                            eff_fps,
                            StreamCodec::H264,
                        );
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetStream {
                            width,
                            height,
                            fps,
                            codec: auto_hevc.then(|| StreamCodec::Hevc.as_str().to_string()),
                        })
                    {
                        self.pending_display_tx.push_back(payload);
                        if auto_hevc {
                            self.active_codec = StreamCodec::Hevc;
                        }
                    }
                }
                SessionCommand::SetCodec { codec } => {
                    if codec == StreamCodec::Hevc && !self.client_supports_hevc {
                        continue;
                    }
                    if codec == StreamCodec::Av1
                        && (!self.client_supports_av1 || !self.host_supports_ext_codec_flags)
                    {
                        continue;
                    }
                    self.user_pinned_codec = Some(codec);
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetCodec {
                            codec: codec.as_str().to_string(),
                        })
                    {
                        self.pending_display_tx.push_back(payload);
                        self.active_codec = codec;
                    }
                }
                SessionCommand::LockRemoteScreen => {
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::LockScreen)
                    {
                        self.pending_display_tx.push_back(payload);
                    }
                }
                SessionCommand::SetMediaPaused { paused } => {
                    if self.client.state() != SessionState::Streaming {
                        if paused {
                            self.pending_desktop_upgrade = false;
                            self.client.set_media_paused(true);
                            try_clear_still_overlay(
                                &self.renderer_handle,
                                &mut self.still_receiver,
                                &mut self.pending_still_clear,
                            );
                            self.update_tx
                                .push(SessionUpdate::MediaState { paused: true });
                        } else {
                            // 重连期间缓存桌面升级/恢复意图，待重连回到 Streaming 后立即执行。
                            self.pending_desktop_upgrade = true;
                        }
                        continue;
                    }
                    if paused {
                        self.pending_desktop_upgrade = false;
                        self.client.set_media_paused(true);
                        try_clear_still_overlay(
                            &self.renderer_handle,
                            &mut self.still_receiver,
                            &mut self.pending_still_clear,
                        );
                        if let Some(payload) =
                            display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetMediaPaused {
                                paused: true,
                            })
                        {
                            self.pending_display_tx.push_back(payload);
                        }
                        self.update_tx
                            .push(SessionUpdate::MediaState { paused: true });
                    } else {
                        self.pending_desktop_upgrade = false;
                        let _ = self.run_desktop_upgrade();
                    }
                }
                SessionCommand::ProbeNow => {
                    if self.client.state() == SessionState::Streaming {
                        let now_us = u64::from((self.clock_reader)());
                        let _ = self.client.trigger_fast_probe(now_us);
                    }
                }
                SessionCommand::SetStillRefinementEnabled { enabled } => {
                    self.still_refinement_enabled = enabled;
                    if !enabled {
                        try_clear_still_overlay(
                            &self.renderer_handle,
                            &mut self.still_receiver,
                            &mut self.pending_still_clear,
                        );
                    }
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::StillRefineConfig {
                            enabled,
                        })
                    {
                        self.pending_display_tx.push_back(payload);
                    }
                }
            }
        }
    }

    /// 排空来自 UI 的显示/防窥/多屏/远端更新控制消息并分流至对应发送队列。
    pub(super) fn process_display_ctrl_commands(&mut self) {
        if self.client.state() != SessionState::Streaming {
            return;
        }
        for mut dmsg in self.display_ctrl_rx.drain_all() {
            let mut is_update_trigger = false;
            match &mut dmsg {
                DisplayControlMsg::UpdateTrigger {
                    target_version,
                    download_url,
                    expected_sha256,
                    asset_name,
                    mirror_url,
                    relay_fallback_allowed,
                    request_id,
                } => {
                    self.active_update_request_id = self.active_update_request_id.wrapping_add(1);
                    if self.active_update_request_id == 0 {
                        self.active_update_request_id = 1;
                    }
                    *request_id = self.active_update_request_id;
                    is_update_trigger = true;
                    self.awaiting_host_relay_finish = false;
                    self.update_relay
                        .arm_confirmed_request(crate::updater::RemoteUpdateRequest {
                            target_version: target_version.clone(),
                            download_url: download_url.clone(),
                            expected_sha256: expected_sha256.clone(),
                            asset_name: asset_name.clone(),
                            mirror_url: mirror_url.clone(),
                            relay_fallback_allowed: *relay_fallback_allowed,
                        });
                }
                DisplayControlMsg::UpdateCancel => {
                    self.awaiting_host_relay_finish = false;
                    self.update_relay.cancel_active_relay();
                    self.pending_update_tx.clear();
                }
                _ => {}
            }
            let is_update_msg = matches!(
                &dmsg,
                DisplayControlMsg::UpdateTrigger { .. }
                    | DisplayControlMsg::UpdateCancel
                    | DisplayControlMsg::UpdateChunkBegin { .. }
                    | DisplayControlMsg::UpdateChunkData { .. }
                    | DisplayControlMsg::UpdateChunkEnd
                    | DisplayControlMsg::UpdateChunkAbort { .. }
            );
            if let Some(payload) = display_ctrl::encode_display_ctrl(&dmsg) {
                if is_update_msg {
                    self.pending_update_tx
                        .push_back((is_update_trigger, payload));
                } else {
                    while self.pending_display_tx.len() >= COMMAND_CHANNEL_CAP {
                        if let Some(mut evicted) = self.pending_display_tx.pop_front() {
                            use zeroize::Zeroize;
                            evicted.zeroize();
                        }
                    }
                    self.pending_display_tx.push_back(payload);
                }
            }
        }
    }
}
