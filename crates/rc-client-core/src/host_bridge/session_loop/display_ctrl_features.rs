use std::thread;
use std::time::{Duration, Instant};

use rc_types::Resolution;

use crate::display_ctrl::{self, DisplayControlMsg};

use super::super::media_aux::{
    build_hardware_display_presets, compute_host_display_bounds, encode_host_display_caps,
    handle_codec_fallback_hidpi, is_valid_privacy_image_bytes, trigger_host_lock_screen,
};
use super::super::pipeline_factory::compute_hidpi_stream_target;
use super::super::tools_worker::handle_terminal_unlock_request;
use super::super::types::MAX_VIRTUAL_DISPLAYS_PER_SESSION;
use super::SessionLoopCtx;

impl SessionLoopCtx<'_> {
    pub(super) fn dispatch_display_ctrl_msg(&mut self, mut payload: Vec<u8>) {
        let decoded = display_ctrl::decode_display_ctrl(&payload);
        if matches!(
            &decoded,
            Some(DisplayControlMsg::TerminalUnlockRequest { .. })
        ) {
            use zeroize::Zeroize;
            payload.zeroize();
        }
        match decoded {
            Some(DisplayControlMsg::SetStream {
                width,
                height,
                fps,
                codec,
            }) => self.handle_set_stream(width, height, fps, codec),
            Some(DisplayControlMsg::ClientMediaCaps {
                decode_caps,
                refinement_caps,
                pref,
                supports_ext_codec_flags,
            }) => self.handle_client_media_caps(
                decode_caps,
                refinement_caps,
                pref,
                supports_ext_codec_flags,
            ),
            Some(DisplayControlMsg::StillRefineConfig { enabled }) => {
                self.still_refine.on_still_refine_config(enabled);
            }
            Some(DisplayControlMsg::CodecDecodeFailed {
                codec,
                generation,
                reason,
            }) => self.handle_codec_decode_failed(codec, generation, reason),
            Some(DisplayControlMsg::LockScreen) => {
                trigger_host_lock_screen(self.lock_screen_count, self.prefer_hardware);
            }
            Some(DisplayControlMsg::SetCodec { codec }) => self.handle_set_codec(codec),
            Some(DisplayControlMsg::SetPrivacyMode {
                mode,
                preset,
                custom_image_base64,
            }) => self.handle_set_privacy_mode(mode, preset, custom_image_base64),
            Some(DisplayControlMsg::SetHostMute {
                muted,
                restore_on_exit,
            }) => self.handle_set_host_mute(muted, restore_on_exit),
            Some(DisplayControlMsg::SetMouseMode { mode }) => self.handle_set_mouse_mode(mode),
            Some(DisplayControlMsg::ListDisplays) => {
                if self.hw_display_ops_active {
                    if let Some(p) = self.encode_displays_state(self.active_display_id) {
                        self.pending_display_tx.push_transient(p);
                    }
                }
            }
            Some(DisplayControlMsg::SwitchDisplay { display_id }) => {
                self.handle_switch_display(display_id);
            }
            Some(DisplayControlMsg::CreateVirtualDisplay {
                width,
                height,
                hidpi,
            }) => self.handle_create_virtual_display(width, height, hidpi),
            Some(DisplayControlMsg::RemoveVirtualDisplay { display_id })
                if self.hw_display_ops_active =>
            {
                self.handle_remove_virtual_display(display_id);
            }
            Some(DisplayControlMsg::SetMediaPaused { paused }) => {
                self.handle_set_media_paused(paused);
            }
            Some(
                upd_msg @ (DisplayControlMsg::UpdateTrigger { .. }
                | DisplayControlMsg::UpdateCancel
                | DisplayControlMsg::UpdateChunkBegin { .. }
                | DisplayControlMsg::UpdateChunkData { .. }
                | DisplayControlMsg::UpdateChunkEnd
                | DisplayControlMsg::UpdateChunkAbort { .. }),
            ) => {
                self.update_worker
                    .handle_message(upd_msg, self.host.authenticated_owner().is_some());
            }
            Some(DisplayControlMsg::TerminalUnlockRequest { password, username }) => {
                handle_terminal_unlock_request(
                    self.host.authenticated_owner().is_some()
                        && self.current_tool_perms.allow_terminal,
                    password,
                    username,
                    &self.terminal_lock_gate,
                    &mut self.terminal_verify_driver,
                    &mut self.pending_display_tx,
                );
            }
            _ => {}
        }
    }

    fn handle_set_privacy_mode(
        &mut self,
        mode: String,
        preset: String,
        custom_image_base64: Option<String>,
    ) {
        let norm_mode = match mode.as_str() {
            "privacy" | "black" => mode.as_str(),
            _ => "off",
        };
        let norm_preset = match preset.as_str() {
            "preset-1" | "preset-2" | "preset-3" | "preset-4" | "preset-5" | "preset-6"
            | "custom" => preset.as_str(),
            _ => "preset-1",
        };
        let mut hevc_fell_back = false;
        let (applied_mode, applied_preset, supported) = if !self.hw_display_ops_active {
            ("off", norm_preset, false)
        } else if norm_mode == "off" {
            let was_active = self.hw_cleanup.privacy_active;
            if was_active {
                #[cfg(test)]
                let cleared_by_test = self.test_platform.is_some();
                #[cfg(not(test))]
                let cleared_by_test = false;
                if !cleared_by_test {
                    crate::platform::clear_privacy_curtain();
                }
                self.hw_cleanup.privacy_active = false;
                if let Some(cur) = self.host.negotiated() {
                    let prev_codec = self.host.active_codec();
                    let _ = self.host.force_reconfigure_stream(
                        cur.width,
                        cur.height,
                        Some(cur.fps),
                        Some(self.session_max_res),
                        None,
                    );
                    if handle_codec_fallback_hidpi(
                        self.host,
                        prev_codec,
                        self.auto_hidpi_active,
                        self.session_native_res,
                        self.session_max_res,
                        &mut self.hevc_runtime_failed,
                        &mut self.codec_negotiator,
                    ) {
                        hevc_fell_back = true;
                    }
                }
            }
            ("off", norm_preset, true)
        } else {
            let decoded_custom = custom_image_base64
                .as_deref()
                .and_then(display_ctrl::base64_decode)
                .filter(|b| is_valid_privacy_image_bytes(b));
            let eff_preset = if norm_preset == "custom" && decoded_custom.is_none() {
                "preset-1"
            } else {
                norm_preset
            };
            #[cfg(test)]
            let curtain_res = if let Some(ref tp) = self.test_platform {
                if tp.privacy_curtain_ok {
                    Ok(())
                } else {
                    Err("mock privacy curtain failed".to_string())
                }
            } else {
                crate::platform::set_privacy_curtain(
                    norm_mode,
                    eff_preset,
                    decoded_custom.as_deref(),
                )
            };
            #[cfg(not(test))]
            let curtain_res = crate::platform::set_privacy_curtain(
                norm_mode,
                eff_preset,
                decoded_custom.as_deref(),
            );
            match curtain_res {
                Ok(()) => {
                    self.hw_cleanup.privacy_active = true;
                    // 重建 SCK 流使 SCContentFilter 立即排除新创建的幕布窗口。
                    if let Some(cur) = self.host.negotiated() {
                        let prev_codec = self.host.active_codec();
                        let _ = self.host.force_reconfigure_stream(
                            cur.width,
                            cur.height,
                            Some(cur.fps),
                            Some(self.session_max_res),
                            None,
                        );
                        if handle_codec_fallback_hidpi(
                            self.host,
                            prev_codec,
                            self.auto_hidpi_active,
                            self.session_native_res,
                            self.session_max_res,
                            &mut self.hevc_runtime_failed,
                            &mut self.codec_negotiator,
                        ) {
                            hevc_fell_back = true;
                        }
                    }
                    (norm_mode, eff_preset, true)
                }
                Err(err) => {
                    eprintln!("[rc-ui-host] 设置防窥隐私幕布失败: {err}");
                    if self.hw_cleanup.privacy_active {
                        #[cfg(test)]
                        let cleared_by_test = self.test_platform.is_some();
                        #[cfg(not(test))]
                        let cleared_by_test = false;
                        if !cleared_by_test {
                            crate::platform::clear_privacy_curtain();
                        }
                        self.hw_cleanup.privacy_active = false;
                    }
                    ("off", eff_preset, false)
                }
            }
        };
        if let Some(p) = display_ctrl::encode_display_ctrl(&DisplayControlMsg::PrivacyState {
            mode: applied_mode.to_string(),
            preset: applied_preset.to_string(),
            supported,
        }) {
            self.pending_display_tx.push_transient(p);
        }
        if hevc_fell_back {
            if let Some(n) = self.host.negotiated() {
                self.still_refine.on_stream_reset(n.width, n.height);
            }
            self.push_session_display_caps();
        }
    }

    fn handle_set_host_mute(&mut self, muted: bool, restore_on_exit: bool) {
        self.hw_cleanup.restore_audio_on_exit = restore_on_exit;
        let (eff_muted, supported) = if !self.prefer_hardware {
            (false, false)
        } else {
            match crate::platform::set_host_system_muted(muted) {
                Ok(actual) => {
                    self.hw_cleanup.host_audio_modified = true;
                    (actual, true)
                }
                Err(err) => {
                    eprintln!("[rc-ui-host] 设置被控端系统静音失败: {err}");
                    (false, false)
                }
            }
        };
        if let Some(p) = display_ctrl::encode_display_ctrl(&DisplayControlMsg::HostMuteState {
            muted: eff_muted,
            supported,
        }) {
            self.pending_display_tx.push_transient(p);
        }
    }

    fn handle_set_mouse_mode(&mut self, mode: String) {
        let norm = match mode.as_str() {
            "remote" => "remote",
            "local" => "local",
            _ => "smart",
        };
        let want_cursor = norm == "remote";
        let mut hevc_fell_back = false;
        if want_cursor != self.shows_cursor {
            let prev_cursor = self.shows_cursor;
            self.shows_cursor = want_cursor;
            self.host
                .set_capture_options(self.active_display_id, self.shows_cursor);
            if let Some(cur) = self.host.negotiated() {
                let prev_codec = self.host.active_codec();
                if let Err(err) = self.host.force_reconfigure_stream(
                    cur.width,
                    cur.height,
                    Some(cur.fps),
                    Some(self.session_max_res),
                    None,
                ) {
                    eprintln!("[rc-ui-host] 切换鼠标光标采集失败（回滚）: {err}");
                    self.shows_cursor = prev_cursor;
                    self.host
                        .set_capture_options(self.active_display_id, self.shows_cursor);
                }
                if handle_codec_fallback_hidpi(
                    self.host,
                    prev_codec,
                    self.auto_hidpi_active,
                    self.session_native_res,
                    self.session_max_res,
                    &mut self.hevc_runtime_failed,
                    &mut self.codec_negotiator,
                ) {
                    hevc_fell_back = true;
                }
            }
        }
        let reported_mode = if self.shows_cursor {
            "remote"
        } else if norm == "local" {
            "local"
        } else {
            "smart"
        };
        if let Some(p) = display_ctrl::encode_display_ctrl(&DisplayControlMsg::MouseModeState {
            mode: reported_mode.to_string(),
        }) {
            self.pending_display_tx.push_transient(p);
        }
        if hevc_fell_back {
            if let Some(n) = self.host.negotiated() {
                self.still_refine.on_stream_reset(n.width, n.height);
            }
            self.push_session_display_caps();
        }
    }

    fn handle_switch_display(&mut self, display_id: u32) {
        if !self.hw_display_ops_active {
            return;
        }
        let displays = self.list_session_displays();
        if let Some(target) = displays.iter().find(|d| d.id == display_id) {
            let prev_active = self.active_display_id;
            let prev_native = self.session_native_res;
            let prev_max = self.session_max_res;
            let prev_auto_hidpi = self.auto_hidpi_active;
            let prev_display_hidpi = self.session_display_hidpi;
            let next_active = if target.is_main {
                None
            } else {
                Some(target.id)
            };
            let disp_res = Resolution::new(target.width, target.height).to_even();
            let (next_max, next_auto_hidpi, next_display_hidpi) = if target.is_main {
                #[cfg(test)]
                let (main_max, next_auto) = match self.media_override {
                    Some(ref ov) => (
                        super::super::media_aux::clamp_display_max_res(disp_res, ov.max_res),
                        ov.auto_hidpi,
                    ),
                    None => (
                        compute_host_display_bounds(
                            self.host,
                            self.prefer_hardware,
                            self.hardware_video_active,
                        )
                        .1,
                        self.prefer_hardware && self.hardware_video_active,
                    ),
                };
                #[cfg(not(test))]
                let (main_max, next_auto) = (
                    compute_host_display_bounds(
                        self.host,
                        self.prefer_hardware,
                        self.hardware_video_active,
                    )
                    .1,
                    self.prefer_hardware && self.hardware_video_active,
                );
                let is_hi = next_auto
                    && main_max.width > disp_res.width
                    && main_max.height > disp_res.height;
                (main_max, next_auto, is_hi)
            } else {
                match self.virtual_display_hidpi.get(&target.id).copied() {
                    Some(false) => (
                        Resolution::new(
                            disp_res.width.min(display_ctrl::MAX_STREAM_WIDTH),
                            disp_res.height.min(display_ctrl::MAX_STREAM_HEIGHT),
                        ),
                        false,
                        false,
                    ),
                    Some(true) => {
                        let max_2x = Resolution::new(
                            disp_res
                                .width
                                .saturating_mul(2)
                                .min(display_ctrl::MAX_STREAM_WIDTH),
                            disp_res
                                .height
                                .saturating_mul(2)
                                .min(display_ctrl::MAX_STREAM_HEIGHT),
                        );
                        let is_hi =
                            max_2x.width > disp_res.width && max_2x.height > disp_res.height;
                        (max_2x, false, is_hi)
                    }
                    None => (
                        Resolution::new(
                            disp_res
                                .width
                                .saturating_mul(2)
                                .min(display_ctrl::MAX_STREAM_WIDTH),
                            disp_res
                                .height
                                .saturating_mul(2)
                                .min(display_ctrl::MAX_STREAM_HEIGHT),
                        ),
                        false,
                        false,
                    ),
                }
            };
            self.host
                .set_capture_options(next_active, self.shows_cursor);
            let prev_codec = self.host.active_codec();
            let reconfig_ok = if let Some(cur) = self.host.negotiated() {
                let target_stream_res = if next_auto_hidpi {
                    compute_hidpi_stream_target(disp_res, Some(next_max), cur.fps, prev_codec)
                } else {
                    disp_res
                };
                self.host
                    .force_reconfigure_stream(
                        target_stream_res.width,
                        target_stream_res.height,
                        Some(cur.fps),
                        Some(next_max),
                        None,
                    )
                    .is_ok()
            } else {
                true
            };
            if reconfig_ok {
                self.audio_mgr
                    .reset_backoff_for_display_change(Instant::now());
                self.active_display_id = next_active;
                self.session_native_res = disp_res;
                self.session_max_res = next_max;
                self.auto_hidpi_active = next_auto_hidpi;
                self.session_display_hidpi = next_display_hidpi;
                let _ = handle_codec_fallback_hidpi(
                    self.host,
                    prev_codec,
                    next_auto_hidpi,
                    disp_res,
                    next_max,
                    &mut self.hevc_runtime_failed,
                    &mut self.codec_negotiator,
                );
                self.host.set_injector_screen_bounds(
                    target.origin_x,
                    target.origin_y,
                    target.width,
                    target.height,
                );
                let (caps_native, presets) = if target.is_main {
                    let nat = self.original_native_res.unwrap_or(disp_res);
                    (
                        nat,
                        build_hardware_display_presets(
                            self.prefer_hardware,
                            self.hardware_video_active,
                            Some(nat),
                        ),
                    )
                } else {
                    (
                        disp_res,
                        display_ctrl::build_resolution_presets(
                            disp_res.width,
                            disp_res.height,
                            self.session_max_res.width,
                            self.session_max_res.height,
                        ),
                    )
                };
                if let Some(n) = self.host.negotiated() {
                    self.still_refine.on_stream_reset(n.width, n.height);
                }
                if let Some(cp) = encode_host_display_caps(
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
                    self.pending_display_tx.set_caps(cp);
                }
            } else {
                self.active_display_id = prev_active;
                self.session_native_res = prev_native;
                self.session_max_res = prev_max;
                self.auto_hidpi_active = prev_auto_hidpi;
                self.session_display_hidpi = prev_display_hidpi;
                self.host
                    .set_capture_options(prev_active, self.shows_cursor);
            }
        }
        if let Some(dp) = self.encode_displays_state(self.active_display_id) {
            self.pending_display_tx.push_transient(dp);
        }
    }

    fn handle_create_virtual_display(&mut self, width: u32, height: u32, hidpi: bool) {
        if !self.hw_display_ops_active {
            if let Some(ep) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::VirtualDisplayError {
                    message: "当前会话未启用硬件视频管线，无法创建虚拟屏".to_string(),
                })
            {
                self.pending_display_tx.push_transient(ep);
            }
            return;
        }
        if self.hw_cleanup.virtual_display_count >= MAX_VIRTUAL_DISPLAYS_PER_SESSION {
            if let Some(ep) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::VirtualDisplayError {
                    message: format!(
                        "单次会话最多创建 {MAX_VIRTUAL_DISPLAYS_PER_SESSION} 个虚拟显示器"
                    ),
                })
            {
                self.pending_display_tx.push_transient(ep);
            }
            return;
        }
        let req_w = if width >= 640 { width.min(3840) } else { 1920 };
        let req_h = if height >= 480 {
            height.min(2160)
        } else {
            1080
        };
        #[cfg(test)]
        let create_res = if let Some(ref tp) = self.test_platform {
            tp.create_virtual_display(req_w, req_h, hidpi)
        } else {
            crate::platform::create_virtual_display(req_w, req_h, hidpi)
        };
        #[cfg(not(test))]
        let create_res = crate::platform::create_virtual_display(req_w, req_h, hidpi);

        match create_res {
            Ok(vinfo) => {
                self.hw_cleanup.virtual_display_count =
                    self.hw_cleanup.virtual_display_count.saturating_add(1);
                #[cfg(test)]
                let skip_wait = self.test_platform.is_some();
                #[cfg(not(test))]
                let skip_wait = false;
                if !skip_wait {
                    // 等待 WindowServer 将新虚拟屏注册到 CG/SCK 列表。
                    thread::sleep(Duration::from_millis(260));
                }
                let fresh_list = self.list_session_displays();
                let resolved = fresh_list
                    .iter()
                    .find(|d| d.id == vinfo.id)
                    .cloned()
                    .unwrap_or(vinfo);
                self.virtual_display_hidpi.insert(resolved.id, hidpi);
                let prev_active = self.active_display_id;
                let prev_native = self.session_native_res;
                let prev_max = self.session_max_res;
                let prev_display_hidpi = self.session_display_hidpi;
                let vres = Resolution::new(resolved.width, resolved.height).to_even();
                let next_max = if hidpi {
                    Resolution::new(
                        vres.width
                            .saturating_mul(2)
                            .min(display_ctrl::MAX_STREAM_WIDTH),
                        vres.height
                            .saturating_mul(2)
                            .min(display_ctrl::MAX_STREAM_HEIGHT),
                    )
                } else {
                    Resolution::new(
                        vres.width.min(display_ctrl::MAX_STREAM_WIDTH),
                        vres.height.min(display_ctrl::MAX_STREAM_HEIGHT),
                    )
                };
                let next_display_hidpi =
                    hidpi && next_max.width > vres.width && next_max.height > vres.height;
                self.host
                    .set_capture_options(Some(resolved.id), self.shows_cursor);
                let prev_codec = self.host.active_codec();
                let switch_res = if let Some(cur) = self.host.negotiated() {
                    self.host
                        .force_reconfigure_stream(
                            vres.width,
                            vres.height,
                            Some(cur.fps),
                            Some(next_max),
                            None,
                        )
                        .map(|_| ())
                } else {
                    Ok(())
                };
                match switch_res {
                    Ok(()) => {
                        self.audio_mgr
                            .reset_backoff_for_display_change(Instant::now());
                        self.active_display_id = Some(resolved.id);
                        self.session_native_res = vres;
                        self.session_max_res = next_max;
                        self.session_display_hidpi = next_display_hidpi;
                        self.auto_hidpi_active = false;
                        let _ = handle_codec_fallback_hidpi(
                            self.host,
                            prev_codec,
                            false,
                            vres,
                            next_max,
                            &mut self.hevc_runtime_failed,
                            &mut self.codec_negotiator,
                        );
                        self.host.set_injector_screen_bounds(
                            resolved.origin_x,
                            resolved.origin_y,
                            resolved.width,
                            resolved.height,
                        );
                        let presets = display_ctrl::build_resolution_presets(
                            vres.width,
                            vres.height,
                            self.session_max_res.width,
                            self.session_max_res.height,
                        );
                        if let Some(n) = self.host.negotiated() {
                            self.still_refine.on_stream_reset(n.width, n.height);
                        }
                        if let Some(cp) = encode_host_display_caps(
                            self.host,
                            vres,
                            self.session_native_res,
                            self.session_max_res,
                            self.session_display_hidpi,
                            presets,
                            self.host_hevc_available(),
                            &self.codec_negotiator,
                            self.hardware_media_active,
                            self.still_refine.stream_epoch(),
                        ) {
                            self.pending_display_tx.set_caps(cp);
                        }
                    }
                    Err(err) => {
                        eprintln!("[rc-ui-host] 切换至虚拟屏失败（回滚）: {err}");
                        self.active_display_id = prev_active;
                        self.session_native_res = prev_native;
                        self.session_max_res = prev_max;
                        self.session_display_hidpi = prev_display_hidpi;
                        self.host
                            .set_capture_options(prev_active, self.shows_cursor);
                        if let Some(ep) = display_ctrl::encode_display_ctrl(
                            &DisplayControlMsg::VirtualDisplayError {
                                message: format!("虚拟屏已创建但切换采集失败：{err}"),
                            },
                        ) {
                            self.pending_display_tx.push_transient(ep);
                        }
                    }
                }
                if let Some(dp) = self.encode_displays_state(self.active_display_id) {
                    self.pending_display_tx.push_transient(dp);
                }
            }
            Err(msg) => {
                if let Some(ep) =
                    display_ctrl::encode_display_ctrl(&DisplayControlMsg::VirtualDisplayError {
                        message: msg,
                    })
                {
                    self.pending_display_tx.push_transient(ep);
                }
            }
        }
    }

    fn handle_remove_virtual_display(&mut self, display_id: u32) {
        let was_active = self.active_display_id == Some(display_id);
        #[cfg(test)]
        let removed = if let Some(ref tp) = self.test_platform {
            tp.destroy_virtual_display(display_id)
        } else {
            crate::platform::destroy_virtual_display(display_id)
        };
        #[cfg(not(test))]
        let removed = crate::platform::destroy_virtual_display(display_id);
        if removed {
            self.virtual_display_hidpi.remove(&display_id);
            self.audio_mgr
                .reset_backoff_for_display_change(Instant::now());
            self.hw_cleanup.virtual_display_count =
                self.hw_cleanup.virtual_display_count.saturating_sub(1);
        }
        if removed && was_active {
            self.active_display_id = None;
            self.host.set_capture_options(None, self.shows_cursor);
            #[cfg(test)]
            let ((main_native, main_max), next_auto_hidpi) = match self.media_override {
                Some(ref ov) => (
                    (
                        ov.native_res,
                        super::super::media_aux::clamp_display_max_res(ov.native_res, ov.max_res),
                    ),
                    ov.auto_hidpi,
                ),
                None => (
                    compute_host_display_bounds(
                        self.host,
                        self.prefer_hardware,
                        self.hardware_video_active,
                    ),
                    self.prefer_hardware && self.hardware_video_active,
                ),
            };
            #[cfg(not(test))]
            let ((main_native, main_max), next_auto_hidpi) = (
                compute_host_display_bounds(
                    self.host,
                    self.prefer_hardware,
                    self.hardware_video_active,
                ),
                self.prefer_hardware && self.hardware_video_active,
            );
            let caps_native = self.original_native_res.unwrap_or(main_native);
            self.session_native_res = main_native;
            self.session_max_res = main_max;
            self.auto_hidpi_active = next_auto_hidpi;
            self.session_display_hidpi = next_auto_hidpi
                && main_max.width > main_native.width
                && main_max.height > main_native.height;
            let main_origin = self
                .list_session_displays()
                .into_iter()
                .find(|d| d.is_main)
                .map(|d| (d.origin_x, d.origin_y))
                .unwrap_or((0.0, 0.0));
            self.host.set_injector_screen_bounds(
                main_origin.0,
                main_origin.1,
                main_native.width,
                main_native.height,
            );
            if let Some(cur) = self.host.negotiated() {
                let prev_codec = self.host.active_codec();
                let target_stream_res = if next_auto_hidpi {
                    compute_hidpi_stream_target(
                        main_native,
                        Some(self.session_max_res),
                        cur.fps,
                        prev_codec,
                    )
                } else {
                    main_native
                };
                let _ = self.host.force_reconfigure_stream(
                    target_stream_res.width,
                    target_stream_res.height,
                    Some(cur.fps),
                    Some(self.session_max_res),
                    None,
                );
                let _ = handle_codec_fallback_hidpi(
                    self.host,
                    prev_codec,
                    next_auto_hidpi,
                    main_native,
                    self.session_max_res,
                    &mut self.hevc_runtime_failed,
                    &mut self.codec_negotiator,
                );
            }
            let presets = build_hardware_display_presets(
                self.prefer_hardware,
                self.hardware_video_active,
                Some(caps_native),
            );
            if let Some(n) = self.host.negotiated() {
                self.still_refine.on_stream_reset(n.width, n.height);
            }
            if let Some(cp) = encode_host_display_caps(
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
                self.pending_display_tx.set_caps(cp);
            }
        }
        if let Some(dp) = self.encode_displays_state(self.active_display_id) {
            self.pending_display_tx.push_transient(dp);
        }
    }
}
