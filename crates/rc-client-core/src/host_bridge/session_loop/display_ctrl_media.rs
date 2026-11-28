use std::time::Instant;

use rc_types::Resolution;

use crate::codec_selector::{ResolutionTier, StreamTarget};
use crate::display_ctrl::{self, DisplayControlMsg};

use super::super::media_aux::{clamp_display_max_res, handle_codec_fallback_hidpi};
use super::super::pipeline_factory::compute_hidpi_stream_target;
use super::super::queues::{build_active_controller_session, publish_active_controller};
use super::super::types::HOST_ENCODE_OVERLOAD_TRIP_LIMIT;
use super::SessionLoopCtx;

impl SessionLoopCtx<'_> {
    pub(super) fn check_encode_overload_fallback(&mut self) {
        // 编码侧连续过载熔断：当前非 H.264 且连续编码过载达到阈值时，立即熔断并顺延下一档。
        if self.host.active_codec() == rc_encode::Codec::H264
            || self.host.consecutive_encode_overloads() < HOST_ENCODE_OVERLOAD_TRIP_LIMIT
        {
            return;
        }
        let Some(cur) = self.host.negotiated() else {
            return;
        };
        let failed_codec = self.host.active_codec();
        let target = StreamTarget {
            width: cur.width,
            height: cur.height,
            fps: cur.fps,
        };
        let net_hint = self.current_net_hint();
        let fb_plan = self.codec_negotiator.on_encode_failure(
            failed_codec,
            "consecutive encoder overload",
            failed_codec,
            target,
            net_hint,
        );
        if failed_codec == rc_encode::Codec::Hevc {
            self.hevc_runtime_failed = true;
        }
        let fb_res = if self.auto_hidpi_active {
            compute_hidpi_stream_target(
                self.session_native_res,
                Some(self.session_max_res),
                cur.fps,
                fb_plan.codec,
            )
        } else {
            Resolution::new(cur.width, cur.height)
        };
        let prev_codec = self.host.active_codec();
        let _ = self.host.reconfigure_stream_with_codec(
            fb_res.width,
            fb_res.height,
            Some(cur.fps),
            Some(self.session_max_res),
            Some(fb_plan.codec),
        );
        let actual_codec = self.host.active_codec();
        if actual_codec != fb_plan.codec && self.auto_hidpi_active {
            let actual_res = compute_hidpi_stream_target(
                self.session_native_res,
                Some(self.session_max_res),
                cur.fps,
                actual_codec,
            );
            if let Some(n) = self.host.negotiated() {
                if (actual_res.width, actual_res.height) != (n.width, n.height) {
                    let _ = self.host.reconfigure_stream_with_codec(
                        actual_res.width,
                        actual_res.height,
                        Some(cur.fps),
                        Some(self.session_max_res),
                        Some(actual_codec),
                    );
                }
            }
        }
        if self.host.active_codec() != prev_codec {
            self.codec_negotiator.bump_generation();
        }
        if let Some(n) = self.host.negotiated() {
            self.still_refine.on_stream_reset(n.width, n.height);
        }
        self.push_session_display_caps();
    }

    pub(super) fn handle_set_stream(
        &mut self,
        width: u32,
        height: u32,
        fps: u32,
        codec: Option<String>,
    ) {
        let Some(cur) = self.host.negotiated() else {
            return;
        };
        let target_fps = (fps > 0).then_some(fps);
        let prev_codec = self.host.active_codec();
        if width > 0 && height > 0 {
            self.codec_negotiator
                .reset_breaker_on_manual_or_res_change();
            self.hevc_runtime_failed = false;
        }
        let cur_tier = ResolutionTier::from_dimensions(
            if width > 0 { width } else { cur.width },
            if height > 0 { height } else { cur.height },
        );
        let requested_codec = codec
            .as_deref()
            .and_then(display_ctrl::StreamCodec::parse_lossy)
            .and_then(|c| match c {
                display_ctrl::StreamCodec::Av1 => self
                    .codec_negotiator
                    .is_codec_selectable(rc_encode::Codec::Av1, cur_tier)
                    .then_some(rc_encode::Codec::Av1),
                display_ctrl::StreamCodec::Hevc => {
                    self.host_hevc_available().then_some(rc_encode::Codec::Hevc)
                }
                display_ctrl::StreamCodec::H264 => Some(rc_encode::Codec::H264),
            });
        let attempted_codec = requested_codec.unwrap_or_else(|| self.host.active_codec());
        if width > 0 && height > 0 {
            let switched_main = if self.active_display_id.is_none() {
                self.display_mode_session.switch_to(width, height).ok()
            } else {
                None
            };
            if let Some(switched_res) = switched_main {
                self.audio_mgr
                    .reset_backoff_for_display_change(Instant::now());
                self.host
                    .set_injector_screen_size(switched_res.width, switched_res.height);
                self.session_native_res = switched_res;
                let cur_backing = self.current_main_backing().unwrap_or(switched_res);
                self.session_max_res = clamp_display_max_res(switched_res, cur_backing);
                self.session_display_hidpi = self.session_max_res.width > switched_res.width
                    && self.session_max_res.height > switched_res.height;
                self.auto_hidpi_active = true;
                let eff_fps = target_fps.unwrap_or(cur.fps);
                let stream_res = compute_hidpi_stream_target(
                    switched_res,
                    Some(self.session_max_res),
                    eff_fps,
                    attempted_codec,
                );
                if let Err(err) = self.host.reconfigure_stream_with_codec(
                    stream_res.width,
                    stream_res.height,
                    target_fps,
                    Some(self.session_max_res),
                    requested_codec,
                ) {
                    eprintln!(
                        "[rc-ui-host] 热切换流参数 ({}x{}@{fps}fps, {requested_codec:?}) 失败: {err}",
                        stream_res.width, stream_res.height
                    );
                }
            } else {
                self.auto_hidpi_active = false;
                let (target_w, target_h) = display_ctrl::fit_target_preserving_aspect(
                    width,
                    height,
                    self.session_native_res.width,
                    self.session_native_res.height,
                    self.session_max_res.width,
                    self.session_max_res.height,
                );
                match self.host.reconfigure_stream_with_codec(
                    target_w,
                    target_h,
                    target_fps,
                    Some(self.session_max_res),
                    requested_codec,
                ) {
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!(
                            "[rc-ui-host] 热切换流参数 ({target_w}x{target_h}@{fps}fps, {requested_codec:?}) 失败: {err}"
                        );
                    }
                }
            }
        } else {
            let eff_fps = target_fps.unwrap_or(cur.fps);
            let target_res = if self.auto_hidpi_active {
                compute_hidpi_stream_target(
                    self.session_native_res,
                    Some(self.session_max_res),
                    eff_fps,
                    attempted_codec,
                )
            } else {
                Resolution::new(cur.width, cur.height)
            };
            if let Err(err) = self.host.reconfigure_stream_with_codec(
                target_res.width,
                target_res.height,
                target_fps,
                Some(self.session_max_res),
                requested_codec,
            ) {
                eprintln!(
                    "[rc-ui-host] 热切换流参数 ({}x{}@{fps}fps, {requested_codec:?}) 失败: {err}",
                    target_res.width, target_res.height
                );
            }
        }
        let actual_codec = self.host.active_codec();
        if attempted_codec != rc_encode::Codec::H264 && actual_codec != attempted_codec {
            let fail_target = StreamTarget {
                width: cur.width,
                height: cur.height,
                fps: target_fps.unwrap_or(cur.fps),
            };
            let net_hint = self.current_net_hint();
            let _ = self.codec_negotiator.on_encode_failure(
                attempted_codec,
                "reconfigure stream encoder init failed",
                actual_codec,
                fail_target,
                net_hint,
            );
            if attempted_codec == rc_encode::Codec::Hevc {
                self.hevc_runtime_failed = true;
            }
        }
        if actual_codec != attempted_codec && self.auto_hidpi_active {
            let eff_fps = target_fps.unwrap_or(cur.fps);
            let fb_res = compute_hidpi_stream_target(
                self.session_native_res,
                Some(self.session_max_res),
                eff_fps,
                actual_codec,
            );
            if let Some(n) = self.host.negotiated() {
                if (fb_res.width, fb_res.height) != (n.width, n.height) {
                    let _ = self.host.reconfigure_stream_with_codec(
                        fb_res.width,
                        fb_res.height,
                        target_fps,
                        Some(self.session_max_res),
                        Some(actual_codec),
                    );
                }
            }
        }
        if self.host.active_codec() != prev_codec {
            self.codec_negotiator.bump_generation();
        }
        if let Some(n) = self.host.negotiated() {
            self.still_refine.on_stream_reset(n.width, n.height);
        }
        self.push_session_display_caps();
    }

    pub(super) fn handle_client_media_caps(
        &mut self,
        decode_caps: Vec<rc_pipeline::CodecCapability>,
        refinement_caps: Option<rc_pipeline::RefinementCapability>,
        pref: crate::codec_selector::CodecSelectionPref,
        supports_ext_codec_flags: bool,
    ) {
        self.still_refine
            .on_client_media_caps(refinement_caps.as_ref(), pref);
        if let Some(cur) = self.host.negotiated() {
            let prev_codec = self.host.active_codec();
            let prev_dims = (cur.width, cur.height);
            let target = StreamTarget {
                width: cur.width,
                height: cur.height,
                fps: cur.fps,
            };
            let net_hint = self.current_net_hint();
            let plan = self.codec_negotiator.on_client_media_caps(
                decode_caps,
                refinement_caps,
                pref,
                supports_ext_codec_flags,
                target,
                net_hint,
            );
            let target_res = if self.auto_hidpi_active {
                compute_hidpi_stream_target(
                    self.session_native_res,
                    Some(self.session_max_res),
                    cur.fps,
                    plan.codec,
                )
            } else {
                Resolution::new(cur.width, cur.height)
            };
            if plan.codec != prev_codec || (target_res.width, target_res.height) != prev_dims {
                if let Err(err) = self.host.reconfigure_stream_with_codec(
                    target_res.width,
                    target_res.height,
                    Some(cur.fps),
                    Some(self.session_max_res),
                    Some(plan.codec),
                ) {
                    eprintln!(
                        "[rc-ui-host] ClientMediaCaps 自动选型切换 ({:?}, {}x{}) 失败: {err}",
                        plan.codec, target_res.width, target_res.height
                    );
                }
                let actual_codec = self.host.active_codec();
                if actual_codec != plan.codec {
                    let net_hint = self.current_net_hint();
                    let _ = self.codec_negotiator.on_encode_failure(
                        plan.codec,
                        "selected codec encoder init failed",
                        actual_codec,
                        target,
                        net_hint,
                    );
                    if plan.codec == rc_encode::Codec::Hevc {
                        self.hevc_runtime_failed = true;
                    }
                    if self.auto_hidpi_active {
                        let fb_res = compute_hidpi_stream_target(
                            self.session_native_res,
                            Some(self.session_max_res),
                            cur.fps,
                            actual_codec,
                        );
                        if let Some(n) = self.host.negotiated() {
                            if (fb_res.width, fb_res.height) != (n.width, n.height) {
                                let _ = self.host.reconfigure_stream_with_codec(
                                    fb_res.width,
                                    fb_res.height,
                                    Some(cur.fps),
                                    Some(self.session_max_res),
                                    Some(actual_codec),
                                );
                            }
                        }
                    }
                }
                if self.host.active_codec() != prev_codec {
                    self.codec_negotiator.bump_generation();
                }
                if let Some(n) = self.host.negotiated() {
                    if self.host.active_codec() != prev_codec || (n.width, n.height) != prev_dims {
                        self.still_refine.on_stream_reset(n.width, n.height);
                    }
                }
            }
        }
        self.push_session_display_caps();
    }

    pub(super) fn handle_codec_decode_failed(
        &mut self,
        codec: String,
        generation: u64,
        reason: String,
    ) {
        let (Some(failed_codec), Some(cur)) = (
            rc_encode::Codec::parse_lossy(&codec),
            self.host.negotiated(),
        ) else {
            return;
        };
        let target = StreamTarget {
            width: cur.width,
            height: cur.height,
            fps: cur.fps,
        };
        let prev_codec = self.host.active_codec();
        let net_hint = self.current_net_hint();
        let Some(fallback_plan) = self.codec_negotiator.on_codec_decode_failed(
            failed_codec,
            generation,
            reason,
            prev_codec,
            target,
            net_hint,
        ) else {
            return;
        };
        if failed_codec == rc_encode::Codec::Hevc {
            self.hevc_runtime_failed = true;
        }
        let fb_res = if self.auto_hidpi_active {
            compute_hidpi_stream_target(
                self.session_native_res,
                Some(self.session_max_res),
                cur.fps,
                fallback_plan.codec,
            )
        } else {
            Resolution::new(cur.width, cur.height)
        };
        let _ = self.host.reconfigure_stream_with_codec(
            fb_res.width,
            fb_res.height,
            Some(cur.fps),
            Some(self.session_max_res),
            Some(fallback_plan.codec),
        );
        // 若降级目标（如 HEVC）在编码侧同样构造失败并被 HostSession 内部顺延 H.264，
        // 同步记录熔断与 hevc_runtime_failed，并对齐回退编码器分辨率预算。
        let actual_codec = self.host.active_codec();
        if fallback_plan.codec != rc_encode::Codec::H264 && actual_codec != fallback_plan.codec {
            let net_hint = self.current_net_hint();
            let _ = self.codec_negotiator.on_encode_failure(
                fallback_plan.codec,
                "fallback codec encoder init failed",
                actual_codec,
                target,
                net_hint,
            );
            if fallback_plan.codec == rc_encode::Codec::Hevc {
                self.hevc_runtime_failed = true;
            }
            if self.auto_hidpi_active {
                let actual_res = compute_hidpi_stream_target(
                    self.session_native_res,
                    Some(self.session_max_res),
                    cur.fps,
                    actual_codec,
                );
                if let Some(n) = self.host.negotiated() {
                    if (actual_res.width, actual_res.height) != (n.width, n.height) {
                        let _ = self.host.reconfigure_stream_with_codec(
                            actual_res.width,
                            actual_res.height,
                            Some(cur.fps),
                            Some(self.session_max_res),
                            Some(actual_codec),
                        );
                    }
                }
            }
        }
        if self.host.active_codec() != prev_codec {
            self.codec_negotiator.bump_generation();
        }
        if let Some(n) = self.host.negotiated() {
            self.still_refine.on_stream_reset(n.width, n.height);
        }
        self.push_session_display_caps();
    }

    pub(super) fn handle_set_codec(&mut self, codec: String) {
        self.codec_negotiator
            .reset_breaker_on_manual_or_res_change();
        self.hevc_runtime_failed = false;
        let cur_tier = self.host.negotiated().map_or(ResolutionTier::Fhd1080, |n| {
            ResolutionTier::from_dimensions(n.width, n.height)
        });
        let target_codec = display_ctrl::StreamCodec::parse_lossy(&codec).and_then(|c| match c {
            display_ctrl::StreamCodec::Av1 => self
                .codec_negotiator
                .is_codec_selectable(rc_encode::Codec::Av1, cur_tier)
                .then_some(rc_encode::Codec::Av1),
            display_ctrl::StreamCodec::Hevc => {
                self.host_hevc_available().then_some(rc_encode::Codec::Hevc)
            }
            display_ctrl::StreamCodec::H264 => Some(rc_encode::Codec::H264),
        });
        if let (Some(c), Some(cur)) = (target_codec, self.host.negotiated()) {
            self.codec_negotiator.set_manual_pref(c);
            let prev_codec = self.host.active_codec();
            let prev_dims = (cur.width, cur.height);
            let target_res = if self.auto_hidpi_active {
                compute_hidpi_stream_target(
                    self.session_native_res,
                    Some(self.session_max_res),
                    cur.fps,
                    c,
                )
            } else {
                Resolution::new(cur.width, cur.height)
            };
            if let Err(err) = self.host.reconfigure_stream_with_codec(
                target_res.width,
                target_res.height,
                Some(cur.fps),
                Some(self.session_max_res),
                Some(c),
            ) {
                eprintln!("[rc-ui-host] 热切换编解码器 ({c:?}) 失败（保持当前管线）: {err}");
            }
            let actual_codec = self.host.active_codec();
            if c != rc_encode::Codec::H264 && actual_codec != c {
                let fail_target = StreamTarget {
                    width: target_res.width,
                    height: target_res.height,
                    fps: cur.fps,
                };
                let net_hint = self.current_net_hint();
                let _ = self.codec_negotiator.on_encode_failure(
                    c,
                    "manual SetCodec encoder init failed",
                    actual_codec,
                    fail_target,
                    net_hint,
                );
                if c == rc_encode::Codec::Hevc {
                    self.hevc_runtime_failed = true;
                }
                if self.auto_hidpi_active {
                    let fb_res = compute_hidpi_stream_target(
                        self.session_native_res,
                        Some(self.session_max_res),
                        cur.fps,
                        actual_codec,
                    );
                    if let Some(n) = self.host.negotiated() {
                        if (fb_res.width, fb_res.height) != (n.width, n.height) {
                            let _ = self.host.reconfigure_stream_with_codec(
                                fb_res.width,
                                fb_res.height,
                                Some(cur.fps),
                                Some(self.session_max_res),
                                Some(actual_codec),
                            );
                        }
                    }
                }
            }
            if self.host.active_codec() != prev_codec {
                self.codec_negotiator.bump_generation();
            }
            if let Some(n) = self.host.negotiated() {
                if self.host.active_codec() != prev_codec || (n.width, n.height) != prev_dims {
                    self.still_refine.on_stream_reset(n.width, n.height);
                }
            }
        }
        // 无论切换成功、幂等或拒绝，均回推最新 Capabilities，让控制端获知权威生效 codec。
        self.push_session_display_caps();
    }

    pub(super) fn handle_set_media_paused(&mut self, paused: bool) {
        let was_paused = self.host.is_media_paused();
        if paused {
            self.still_refine.on_input_event();
            self.host.pause_media();
            self.audio_mgr.pause(&mut self.audio_silence_gate);
            if let Some(mp) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::MediaState { paused: true })
            {
                self.pending_display_tx.push_transient(mp);
            }
        } else {
            let prev_codec = self.host.active_codec();
            match self.host.resume_media() {
                Ok(()) => {
                    let _ = handle_codec_fallback_hidpi(
                        self.host,
                        prev_codec,
                        self.auto_hidpi_active,
                        self.session_native_res,
                        self.session_max_res,
                        &mut self.hevc_runtime_failed,
                        &mut self.codec_negotiator,
                    );
                    if let Some(n) = self.host.negotiated() {
                        self.still_refine.on_stream_reset(n.width, n.height);
                    }
                    self.push_session_display_caps();
                    if self.hw_display_ops_active {
                        if let Some(dp) = self.encode_displays_state(self.active_display_id) {
                            self.pending_display_tx.push_transient(dp);
                        }
                    }
                    let screen_state = (
                        crate::platform::is_screen_locked(),
                        self.host.is_capture_suspended(),
                    );
                    if let Some(sp) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::HostScreenState {
                            locked: screen_state.0,
                            capture_suspended: screen_state.1,
                        })
                    {
                        self.pending_display_tx.set_screen_state(sp);
                    }
                    self.last_reported_screen_state = Some(screen_state);
                    self.last_screen_state_check = Instant::now();
                    self.audio_mgr.resume(&mut self.audio_silence_gate);
                    if let Some(mp) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::MediaState {
                            paused: false,
                        })
                    {
                        self.pending_display_tx.push_transient(mp);
                    }
                }
                Err(err) => {
                    eprintln!("[rc-ui-host] 恢复媒体管线失败: {err}");
                    if let Some(mp) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::MediaState {
                            paused: self.host.is_media_paused(),
                        })
                    {
                        self.pending_display_tx.push_transient(mp);
                    }
                }
            }
        }
        if self.host.controller_meta().is_none() && self.host.is_media_paused() != was_paused {
            if let Some(ref tr) = self.controller_tracking {
                let updated_ctrl = build_active_controller_session(
                    self.host,
                    &tr.peer_hints,
                    self.active_controller_connected_at_ms,
                );
                publish_active_controller(
                    &tr.active_controllers,
                    self.updates,
                    Some(&tr.signal_client),
                    updated_ctrl,
                );
            }
        }
    }
}
