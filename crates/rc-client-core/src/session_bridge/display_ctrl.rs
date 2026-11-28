use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rc_pipeline::{DiffMode, PipelineConfig};
use rc_session::proto::SessionParams;
use rc_session::{ClientSession, SessionClock, ToolPermissions};
use rc_types::Resolution;

use crate::codec_selector::{self, CodecSelectionPref};
use crate::display_ctrl::{self, DisplayControlMsg, StreamCodec};
use crate::hud::HudSample;

use super::adapters::{apply_stage_rect_nonblocking, BuiltPipeline, LayerLease, RendererHandle};
use super::handle::ScrollDispatchState;
use super::queues::{BoundedInputQueue, BoundedUpdateQueue};
use super::types::{
    SessionUpdate, CONSECUTIVE_DECODE_ERROR_LIMIT, E2E_WINDOW_FRAMES,
    PERSISTENT_DECODE_ERROR_MIN_ELAPSED,
};

/// 非阻塞尝试清空渲染器的静止无损 Tile 叠加层，并严格仅在实际执行成功后清零
/// `pending_still_clear` 与 `still_receiver.clear_active_overlay()`。
///
/// 当异步解码线程正在 `present()` 中持有 `renderer_handle` 锁导致 `try_lock()` 返回
/// `WouldBlock` 时，保留 `*pending_still_clear = true`（且不提前清掉活跃标记），
/// 供会话循环在后续每拍开头重试直至真正清空，杜绝旧无损层永久残留鬼影。
pub(in crate::session_bridge) fn try_clear_still_overlay(
    renderer_handle: &Mutex<Option<RendererHandle>>,
    still_receiver: &mut crate::still_refine::StillRefineReceiver,
    pending_still_clear: &mut bool,
) -> bool {
    *pending_still_clear = true;
    let rend = renderer_handle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match rend {
        None => {
            *pending_still_clear = false;
            still_receiver.clear_active_overlay();
            true
        }
        Some(handle) => {
            if let Ok(mut r) = handle.try_lock() {
                r.clear_still_tiles();
                *pending_still_clear = false;
                still_receiver.clear_active_overlay();
                true
            } else {
                false
            }
        }
    }
}

/// 重连恢复（`Resumed`）或重建（`Rebuilt`）后刷新公共控制端会话状态。
///
/// `ClientSession::on_disconnected` 会丢弃旧传输且 `tick_reconnect` 必然新建传输连接，
/// 因此无论 `Resumed` 还是 `Rebuilt` 都必须刷新 `BoundedInputQueue` 的传输唤醒句柄，
/// 否则快速恢复后空闲 `poll()` 等待期间的新输入将失去即时唤醒能力。
pub(in crate::session_bridge) fn refresh_after_reconnect_outcome(
    client: &mut ClientSession,
    input_rx: &BoundedInputQueue,
    scroll_state: &ScrollDispatchState,
) {
    scroll_state.update_peer_capability(client.peer_supports_pixel_scroll());
    scroll_state.reset_accumulator();
    client.reset_clipboard_epoch();
    input_rx.set_wake_handle(client.transport_wake_handle());
}

/// 纯工具态原地热升级为桌面控屏的上下文（用于统一 `SetMediaPaused(false)` 与重连回 `Streaming` 补升级）。
pub(in crate::session_bridge) struct DesktopUpgradeCtx<'a> {
    pub(in crate::session_bridge) client: &'a mut ClientSession,
    pub(in crate::session_bridge) real_pipeline_built: &'a AtomicBool,
    pub(in crate::session_bridge) want_real_pipeline: &'a AtomicBool,
    pub(in crate::session_bridge) is_hw_decoder_slot: &'a AtomicBool,
    pub(in crate::session_bridge) backend: &'a mut String,
    pub(in crate::session_bridge) backend_label: &'a Mutex<String>,
    pub(in crate::session_bridge) renderer_handle: &'a Mutex<Option<RendererHandle>>,
    pub(in crate::session_bridge) renderer_pending_resize: &'a Mutex<Arc<AtomicU64>>,
    pub(in crate::session_bridge) layer_lease: &'a Mutex<Option<LayerLease>>,
    pub(in crate::session_bridge) active_backend_suffix: Option<&'static str>,
    pub(in crate::session_bridge) is_hardware_decoder: &'a mut bool,
    pub(in crate::session_bridge) client_supports_hevc: &'a mut bool,
    pub(in crate::session_bridge) client_supports_av1: &'a mut bool,
    pub(in crate::session_bridge) client_decode_caps: &'a mut Vec<rc_pipeline::CodecCapability>,
    pub(in crate::session_bridge) user_pinned_codec: Option<StreamCodec>,
    pub(in crate::session_bridge) still_refinement_enabled: bool,
    pub(in crate::session_bridge) prefer_hardware: bool,
    pub(in crate::session_bridge) hud_width: u32,
    pub(in crate::session_bridge) hud_height: u32,
    pub(in crate::session_bridge) current_fps: u32,
    pub(in crate::session_bridge) negotiated: SessionParams,
    pub(in crate::session_bridge) last_stage_rect: Option<(u32, u32)>,
    pub(in crate::session_bridge) stream_started_at: &'a mut Instant,
    pub(in crate::session_bridge) first_frame_logged: &'a mut bool,
    pub(in crate::session_bridge) decode_error_logged: &'a mut bool,
    pub(in crate::session_bridge) pending_display_tx: &'a mut VecDeque<Vec<u8>>,
    pub(in crate::session_bridge) update_tx: &'a BoundedUpdateQueue,
}

/// 执行纯工具态到桌面控屏的原地热升级（或从暂停恢复媒体推流）。
///
/// 若尚未构建真实管线且 `build_pipeline` 或 `client.replace_pipeline` 任一步失败，
/// 必须保持 `media_paused = true` 并立即返回 `false`——严禁取消暂停、严禁通知被控端恢复推流、
/// 严禁向 UI 发射 `MediaResumed` / `MediaState(false)`，避免真实码流灌入 64×64 占位解码器。
pub(in crate::session_bridge) fn try_resume_or_upgrade_desktop<F>(
    ctx: DesktopUpgradeCtx<'_>,
    build_pipeline: F,
) -> bool
where
    F: FnOnce(&PipelineConfig) -> rc_types::Result<BuiltPipeline>,
{
    if !ctx.real_pipeline_built.load(Ordering::Acquire) {
        let upgrade_w = if ctx.hud_width > 0 {
            ctx.hud_width
        } else if ctx.negotiated.width > 0 {
            ctx.negotiated.width
        } else {
            1920
        };
        let upgrade_h = if ctx.hud_height > 0 {
            ctx.hud_height
        } else if ctx.negotiated.height > 0 {
            ctx.negotiated.height
        } else {
            1080
        };
        let upgrade_fps = ctx.current_fps.max(1);
        let upgrade_pcfg = PipelineConfig {
            resolution: Resolution::new(upgrade_w, upgrade_h),
            fps: upgrade_fps,
            bitrate_bps: ctx.negotiated.bitrate_bps.max(1),
            prefer_hardware: ctx.prefer_hardware,
            target_latency_us: 22_000,
            trace_capacity: 4096,
            diff: DiffMode::TrustPlatform,
            clock_origin_us: None,
            async_decode: ctx.prefer_hardware,
            max_packet_payload: rc_pipeline::MAX_PAYLOAD,
            ..PipelineConfig::default()
        };
        let built = match build_pipeline(&upgrade_pcfg) {
            Ok(built) => built,
            Err(e) => {
                eprintln!("rc-ui: build_controller_pipeline during desktop upgrade failed: {e}");
                ctx.client.set_media_paused(true);
                return false;
            }
        };
        if let Err(e) = ctx.client.replace_pipeline(built.pipeline) {
            eprintln!("rc-ui: replace_pipeline during desktop upgrade failed: {e}");
            ctx.client.set_media_paused(true);
            return false;
        }
        let final_label = match ctx.active_backend_suffix {
            Some(suffix) => format!("{} {suffix}", built.backend_label),
            None => built.backend_label,
        };
        *ctx.backend = final_label.clone();
        *ctx.backend_label.lock().unwrap_or_else(|e| e.into_inner()) = final_label;
        *ctx.renderer_pending_resize
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Arc::clone(&built.pending_resize);
        if let Some((w, h)) = ctx.last_stage_rect {
            apply_stage_rect_nonblocking(&built.renderer, &built.pending_resize, w, h);
        }
        *ctx.renderer_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&built.renderer));
        *ctx.layer_lease.lock().unwrap_or_else(|e| e.into_inner()) =
            LayerLease::from_renderer(built.renderer, built.layer_addr);
        *ctx.is_hardware_decoder = built.is_hardware;
        ctx.is_hw_decoder_slot
            .store(built.is_hardware, Ordering::Release);
        *ctx.first_frame_logged = false;
        *ctx.decode_error_logged = false;
        ctx.real_pipeline_built.store(true, Ordering::Release);
        ctx.want_real_pipeline.store(true, Ordering::Release);
        *ctx.client_decode_caps = codec_selector::cached_or_platform_decode_caps(
            ctx.prefer_hardware && *ctx.is_hardware_decoder,
        );
        *ctx.client_supports_hevc = ctx.prefer_hardware
            && *ctx.is_hardware_decoder
            && (rc_pipeline::platform_supports_hevc()
                || ctx
                    .client_decode_caps
                    .iter()
                    .any(|c| c.codec == rc_encode::Codec::Hevc && c.hardware));
        *ctx.client_supports_av1 = ctx.prefer_hardware
            && *ctx.is_hardware_decoder
            && ctx
                .client_decode_caps
                .iter()
                .any(|c| c.codec == rc_encode::Codec::Av1 && c.hardware);
        let pref = ctx
            .user_pinned_codec
            .map(|c| CodecSelectionPref::Manual(c.into()))
            .unwrap_or(CodecSelectionPref::Auto);
        if let Some(payload) = display_ctrl::encode_display_ctrl(&build_client_media_caps_msg(
            ctx.client_decode_caps,
            ctx.prefer_hardware && *ctx.is_hardware_decoder,
            pref,
        )) {
            ctx.pending_display_tx.push_back(payload);
        }
    }
    if !ctx.still_refinement_enabled {
        if let Some(payload) =
            display_ctrl::encode_display_ctrl(&DisplayControlMsg::StillRefineConfig {
                enabled: false,
            })
        {
            ctx.pending_display_tx.push_back(payload);
        }
    }
    *ctx.stream_started_at = Instant::now();
    ctx.client.set_media_paused(false);
    if let Some(payload) =
        display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetMediaPaused { paused: false })
    {
        ctx.pending_display_tx.push_back(payload);
    }
    let _ = ctx.client.request_idr_now();
    ctx.update_tx.push(SessionUpdate::MediaResumed {
        backend: ctx.backend.clone(),
        width: ctx.hud_width,
        height: ctx.hud_height,
        fps: ctx.current_fps,
    });
    ctx.update_tx
        .push(SessionUpdate::MediaState { paused: false });
    true
}

/// 当晚到的 `Capabilities` 抵达时校准未恢复的解码失败记录：
/// - 若被控端已切至其他编解码器（`reported_codec != failed_codec`），清除未恢复标记；
/// - 若被控端仍处于 `failed_codec` 且携带更新的 `codec_generation > reported_gen`，
///   补发一次带最新代次的 `CodecDecodeFailed` 防止跨通道竞态黑屏。
pub(in crate::session_bridge) fn reconcile_decode_failure_on_capabilities(
    pending: &mut Option<(rc_encode::Codec, u64, String)>,
    reported_codec: rc_encode::Codec,
    reported_generation: u64,
) -> Option<DisplayControlMsg> {
    let (failed_codec, reported_gen, reason) = pending.as_mut()?;
    if reported_codec != *failed_codec {
        *pending = None;
        return None;
    }
    if reported_generation > *reported_gen {
        *reported_gen = reported_generation;
        return Some(DisplayControlMsg::CodecDecodeFailed {
            codec: failed_codec.as_str().to_string(),
            generation: reported_generation,
            reason: reason.clone(),
        });
    }
    None
}

/// 统计控制端 trace 环形缓冲中 `Outcome::DecodeError` 的帧数。
pub(in crate::session_bridge) fn count_decode_errors(client: &ClientSession) -> usize {
    client
        .pipeline()
        .trace()
        .frames()
        .iter()
        .filter(|f| f.outcome() == Some(rc_trace::Outcome::DecodeError))
        .count()
}

/// 判定硬件解码器是否处于持续不可恢复的码流不兼容/解码失败状态（纯逻辑，便于单测）。
///
/// 仅在本地启用 VideoToolbox 硬件解码、从未成功上屏（`displayed == 0`）、累计
/// `Outcome::DecodeError` 达到阈值且串流已持续足够时长时返回 `true`：
/// - 静止桌面（0 帧，0 解码错误）返回 `false`；
/// - 正常已出画（`displayed > 0`）返回 `false`；
/// - 假后端测试（`is_hardware_decoder == false`）返回 `false`。
pub(in crate::session_bridge) fn is_persistent_decode_failure(
    is_hardware_decoder: bool,
    displayed: u64,
    decode_errors: usize,
    stream_elapsed: Duration,
) -> bool {
    is_hardware_decoder
        && displayed == 0
        && decode_errors >= CONSECUTIVE_DECODE_ERROR_LIMIT
        && stream_elapsed >= PERSISTENT_DECODE_ERROR_MIN_ELAPSED
}

/// 从 `ClientSession` 提取当前 [`HudSample`]（全注入数据，铁律 4）。
pub(in crate::session_bridge) fn sample_hud(
    client: &ClientSession,
    clock: &SessionClock,
    negotiated: SessionParams,
) -> HudSample {
    let at_us = u64::from((clock)());
    let displayed = client.pipeline().displayed();
    let net = client.net_stats();
    let probe = client.probe_snapshot();
    let rtt_us = probe.rtt_us_median.and_then(|v| u32::try_from(v).ok());
    let e2e_p50_ms = compute_recent_e2e_p50_ms(client);
    HudSample {
        at_us,
        displayed,
        bytes_recv: net.bytes_recv,
        rtt_us,
        loss_rate: net.loss_rate,
        e2e_p50_ms,
        width: negotiated.width,
        height: negotiated.height,
    }
}

/// 从最近若干已上屏帧计算偏移折算后的端到端帧时间 p50（毫秒）。
fn compute_recent_e2e_p50_ms(client: &ClientSession) -> Option<f64> {
    let mut samples_ms: Vec<f64> = Vec::with_capacity(E2E_WINDOW_FRAMES);
    for frame in client.pipeline().trace().frames().iter().rev() {
        if samples_ms.len() >= E2E_WINDOW_FRAMES {
            break;
        }
        if frame.outcome() != Some(rc_trace::Outcome::Displayed) {
            continue;
        }
        let Some(captured_host) = frame.at(rc_trace::Mark::Captured) else {
            continue;
        };
        let Some(presented_local) = frame.at(rc_trace::Mark::Presented) else {
            continue;
        };
        let Some(captured_local) = client.host_to_local_us(captured_host.0) else {
            continue;
        };
        let presented_u64 = u64::from(presented_local.0);
        if presented_u64 >= captured_local {
            samples_ms.push((presented_u64 - captured_local) as f64 / 1000.0);
        }
    }
    if samples_ms.is_empty() {
        return None;
    }
    samples_ms.sort_by(|a, b| a.total_cmp(b));
    Some(samples_ms[samples_ms.len() / 2])
}

/// 构造控制端入流后上报给被控端的 `ClientMediaCaps` 协商消息（只读非阻塞缓存，不阻塞首帧）。
pub(in crate::session_bridge) fn build_client_media_caps_msg(
    decode_caps: &[rc_pipeline::CodecCapability],
    prefer_hardware: bool,
    pref: CodecSelectionPref,
) -> DisplayControlMsg {
    DisplayControlMsg::ClientMediaCaps {
        decode_caps: decode_caps.to_vec(),
        refinement_caps: Some(codec_selector::cached_or_platform_refinement_caps(
            prefer_hardware,
        )),
        pref,
        supports_ext_codec_flags: true,
    }
}

/// 解析控制端收到的 [`DisplayControlMsg`]，同步更新 HUD 尺寸并产出对应的 [`SessionUpdate`]。
pub(in crate::session_bridge) fn handle_display_ctrl_msg(
    msg: DisplayControlMsg,
    hud_width: &mut u32,
    hud_height: &mut u32,
    client_supports_hevc: bool,
) -> Option<SessionUpdate> {
    match msg {
        DisplayControlMsg::Capabilities {
            current_width,
            current_height,
            current_fps,
            native_width,
            native_height,
            max_width,
            max_height,
            max_fps,
            presets,
            current_codec,
            supported_codecs,
            encode_caps: _,
            decode_caps: _,
            refinement_caps: _,
            supports_ext_codec_flags: _,
            codec_generation: _,
            still_stream_epoch: _,
            supports_pixel_scroll: _,
            supports_controller_meta: _,
            display_width,
            display_height,
            display_hidpi,
        } => {
            if current_width > 0 && current_height > 0 {
                *hud_width = current_width;
                *hud_height = current_height;
            }
            let resolved_presets = if presets.is_empty() {
                display_ctrl::build_resolution_presets(
                    native_width,
                    native_height,
                    max_width,
                    max_height,
                )
            } else {
                presets
            };
            let parsed_codec = current_codec
                .as_deref()
                .and_then(StreamCodec::parse_lossy)
                .unwrap_or(StreamCodec::H264);
            let host_supports_hevc = supported_codecs
                .iter()
                .any(|c| StreamCodec::parse_lossy(c) == Some(StreamCodec::Hevc))
                || parsed_codec == StreamCodec::Hevc;
            let advisory = display_ctrl::evaluate_high_refresh_advisory(
                current_width,
                current_height,
                current_fps,
                parsed_codec,
                host_supports_hevc,
                client_supports_hevc,
                &resolved_presets,
            );
            let (eff_display_width, eff_display_height, eff_display_hidpi) =
                if display_width == 0 || display_height == 0 {
                    (0, 0, false)
                } else {
                    (display_width, display_height, display_hidpi)
                };
            Some(SessionUpdate::DisplayConfig {
                width: current_width,
                height: current_height,
                fps: current_fps,
                native_width,
                native_height,
                max_fps,
                presets: resolved_presets,
                codec: current_codec,
                supported_codecs,
                client_supports_hevc,
                advisory,
                display_width: eff_display_width,
                display_height: eff_display_height,
                display_hidpi: eff_display_hidpi,
            })
        }
        DisplayControlMsg::Wallpaper { mime, data_base64 } => {
            if matches!(mime.as_str(), "image/jpeg" | "image/png")
                && !data_base64.is_empty()
                && data_base64.len() <= 90_000
                && display_ctrl::base64_decode(&data_base64).is_some()
            {
                Some(SessionUpdate::Wallpaper {
                    data_url: format!("data:{mime};base64,{data_base64}"),
                })
            } else {
                None
            }
        }
        DisplayControlMsg::PrivacyState {
            mode,
            preset,
            supported,
        } => Some(SessionUpdate::PrivacyState {
            mode,
            preset,
            supported,
        }),
        DisplayControlMsg::HostMuteState { muted, supported } => {
            Some(SessionUpdate::HostMuteState { muted, supported })
        }
        DisplayControlMsg::MouseModeState { mode } => Some(SessionUpdate::MouseModeState { mode }),
        DisplayControlMsg::DisplaysState {
            displays,
            active_display_id,
        } => Some(SessionUpdate::DisplaysState {
            displays,
            active_display_id,
        }),
        DisplayControlMsg::VirtualDisplayError { message } => {
            Some(SessionUpdate::VirtualDisplayError { message })
        }
        DisplayControlMsg::HostVersionInfo {
            version,
            arch,
            os,
            update_capable,
            is_owner_session,
            service_installed,
        } => Some(SessionUpdate::HostVersion(
            crate::updater::RemoteHostVersion {
                version,
                arch,
                os,
                update_capable,
                is_owner_session,
                service_installed,
            },
        )),
        DisplayControlMsg::UpdateStatus {
            stage,
            progress_pct,
            downloaded_bytes,
            total_bytes,
            target_version,
            message,
            need_controller_relay,
            error,
            request_id: _,
        } => Some(SessionUpdate::RemoteUpdateStatus(
            crate::updater::UpdateProgress {
                stage,
                progress_pct,
                downloaded_bytes,
                total_bytes,
                target_version,
                message,
                need_controller_relay,
                error,
            },
        )),
        DisplayControlMsg::HostScreenState {
            locked,
            capture_suspended,
        } => Some(SessionUpdate::HostScreenState {
            locked,
            capture_suspended,
        }),
        DisplayControlMsg::MediaState { paused } => Some(SessionUpdate::MediaState { paused }),
        DisplayControlMsg::ToolPermissionsState {
            allow_file_transfer,
            allow_terminal,
            allow_port_map,
        } => Some(SessionUpdate::ToolPermissionsUpdated(ToolPermissions {
            allow_file_transfer,
            allow_terminal,
            allow_port_map,
        })),
        DisplayControlMsg::ToolPermissionDenied { channel, reason } => {
            Some(SessionUpdate::ToolPermissionDenied {
                channel,
                ui_error: crate::ui_error::tool_forbidden_ui_error(
                    channel,
                    crate::ui_error::current_platform(),
                    reason,
                ),
            })
        }
        DisplayControlMsg::TerminalLockState {
            required,
            unlocked,
            username,
            retry_after_secs,
        } => Some(SessionUpdate::TerminalLockState {
            required,
            unlocked,
            username,
            retry_after_secs,
        }),
        DisplayControlMsg::TerminalUnlockResult {
            ok,
            error,
            retry_after_secs,
        } => Some(SessionUpdate::TerminalUnlockResult {
            ok,
            error,
            retry_after_secs,
        }),
        DisplayControlMsg::SetStream { .. }
        | DisplayControlMsg::LockScreen
        | DisplayControlMsg::SetCodec { .. }
        | DisplayControlMsg::ClientMediaCaps { .. }
        | DisplayControlMsg::CodecDecodeFailed { .. }
        | DisplayControlMsg::SetPrivacyMode { .. }
        | DisplayControlMsg::SetHostMute { .. }
        | DisplayControlMsg::SetMouseMode { .. }
        | DisplayControlMsg::ListDisplays
        | DisplayControlMsg::UpdateTrigger { .. }
        | DisplayControlMsg::UpdateCancel
        | DisplayControlMsg::UpdateChunkBegin { .. }
        | DisplayControlMsg::UpdateChunkData { .. }
        | DisplayControlMsg::UpdateChunkAck { .. }
        | DisplayControlMsg::UpdateChunkEnd
        | DisplayControlMsg::UpdateChunkAbort { .. }
        | DisplayControlMsg::SwitchDisplay { .. }
        | DisplayControlMsg::CreateVirtualDisplay { .. }
        | DisplayControlMsg::RemoveVirtualDisplay { .. }
        | DisplayControlMsg::SetMediaPaused { .. }
        | DisplayControlMsg::TerminalUnlockRequest { .. }
        | DisplayControlMsg::StillTileRefine { .. }
        | DisplayControlMsg::StillRefineConfig { .. } => None,
    }
}
