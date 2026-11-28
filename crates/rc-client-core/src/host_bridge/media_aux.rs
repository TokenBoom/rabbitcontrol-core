use std::any::Any;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use rc_session::HostSession;
use rc_types::Resolution;

use crate::codec_selector::{self, HostCodecNegotiator, ResolutionTier};
use crate::display_ctrl::{self, DisplayControlMsg, DisplayDescriptor, DisplayPreset};

use super::pipeline_factory::{
    compute_hidpi_stream_target, host_hardware_display_backing, host_hardware_display_caps,
};
#[cfg(test)]
use super::tests::mock::TestHostPlatformMock;
use super::types::{AtomicFlagReset, SharedWakeGuard};

/// 在 `SharedWakeGuard` 中替换新守卫，并在锁外析构旧守卫（避免持有互斥锁时调用平台释放 FFI）。
pub(super) fn replace_wake_guard(slot: &SharedWakeGuard, new_guard: Option<Box<dyn Any + Send>>) {
    let old = {
        let mut g = slot.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::replace(&mut *g, new_guard)
    };
    drop(old);
}

pub(super) struct WakeGuardReleaser {
    pub(super) slot: SharedWakeGuard,
}

impl Drop for WakeGuardReleaser {
    fn drop(&mut self) {
        replace_wake_guard(&self.slot, None);
    }
}

struct MidSessionWakeResult {
    guard: Option<Box<dyn Any + Send>>,
    still_asleep: bool,
    err: Option<String>,
}

/// 会话中单在途非阻塞唤醒驱动器：
/// - 绝不在 `rc-ui-host` 主循环内同步阻塞等待显示器唤醒（最长可达 2.5s）；
/// - 同一时刻最多一个后台唤醒线程在途，完成后经 `try_recv()` 交换守卫并在锁外释放旧守卫；
/// - 若会话在后台唤醒返回前结束，本驱动器析构关闭接收端，后台线程 `send` 失败立即析构新守卫，零泄漏；
/// - 冷却期从唤醒**完成时刻**起算：唤醒超时/仍熄屏退避 15s，成功亮屏冷却 5s。
pub(super) struct MidSessionWakeDriver {
    pub(super) in_flight: Arc<AtomicBool>,
    rx: Option<mpsc::Receiver<MidSessionWakeResult>>,
    next_allowed_at: Option<Instant>,
}

impl MidSessionWakeDriver {
    pub(super) const WAKE_SUCCESS_COOLDOWN: Duration = Duration::from_secs(5);
    pub(super) const WAKE_TIMEOUT_BACKOFF: Duration = Duration::from_secs(15);

    pub(super) fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicBool::new(false)),
            rx: None,
            next_allowed_at: None,
        }
    }

    pub(super) fn poll_completed(&mut self, wake_guard: &SharedWakeGuard, now: Instant) {
        let Some(ref rx) = self.rx else {
            return;
        };
        match rx.try_recv() {
            Ok(res) => {
                self.rx = None;
                if let Some(ref err) = res.err {
                    eprintln!("[rc-ui-host] 会话中重新唤醒显示器失败: {err}");
                }
                if let Some(new_guard) = res.guard {
                    replace_wake_guard(wake_guard, Some(new_guard));
                }
                let cooldown = if res.still_asleep || res.err.is_some() {
                    Self::WAKE_TIMEOUT_BACKOFF
                } else {
                    Self::WAKE_SUCCESS_COOLDOWN
                };
                self.next_allowed_at = Some(now + cooldown);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.rx = None;
                self.next_allowed_at = Some(now + Self::WAKE_TIMEOUT_BACKOFF);
            }
        }
    }

    pub(super) fn maybe_spawn<F>(&mut self, now: Instant, wake_fn: F) -> bool
    where
        F: FnOnce() -> (Result<Option<Box<dyn Any + Send>>, String>, bool) + Send + 'static,
    {
        if self.rx.is_some() || self.in_flight.load(Ordering::Acquire) {
            return false;
        }
        if self.next_allowed_at.is_some_and(|t| now < t) {
            return false;
        }
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let (tx, rx) = mpsc::sync_channel::<MidSessionWakeResult>(1);
        let flag = Arc::clone(&self.in_flight);
        match thread::Builder::new()
            .name("rc-mid-session-wake".to_string())
            .spawn(move || {
                let _reset = AtomicFlagReset(flag);
                let (res, still_asleep) = wake_fn();
                let msg = match res {
                    Ok(guard) => MidSessionWakeResult {
                        guard,
                        still_asleep,
                        err: None,
                    },
                    Err(e) => MidSessionWakeResult {
                        guard: None,
                        still_asleep: true,
                        err: Some(e),
                    },
                };
                // 若会话已结束并丢弃 rx，SendError 携带的 msg（含守卫）会在此立刻析构，零泄漏。
                let _ = tx.send(msg);
            }) {
            Ok(_) => {
                self.rx = Some(rx);
                true
            }
            Err(e) => {
                self.in_flight.store(false, Ordering::Release);
                self.next_allowed_at = Some(now + Self::WAKE_TIMEOUT_BACKOFF);
                eprintln!("[rc-ui-host] 派发后台显示器唤醒线程失败: {e}");
                false
            }
        }
    }
}

/// 将显示器的物理 `backing` 分辨率按 `logical` 宽高比夹紧至协议流上限（`5120×2880`），
/// 并保证不低于逻辑分辨率（同样封顶 `5120×2880`）且偶数对齐。
pub(super) fn clamp_display_max_res(logical: Resolution, backing: Resolution) -> Resolution {
    let logical_even = logical.to_even();
    let backing_even = backing.to_even();
    let cap_w = backing_even
        .width
        .max(logical_even.width)
        .min(display_ctrl::MAX_STREAM_WIDTH);
    let cap_h = backing_even
        .height
        .max(logical_even.height)
        .min(display_ctrl::MAX_STREAM_HEIGHT);
    let (mw, mh) =
        display_ctrl::fit_within_cap(cap_w, cap_h, logical_even.width, logical_even.height);
    Resolution::new(
        mw.max(logical_even.width.min(display_ctrl::MAX_STREAM_WIDTH)),
        mh.max(logical_even.height.min(display_ctrl::MAX_STREAM_HEIGHT)),
    )
    .to_even()
}

/// 计算本会话被控端的原生逻辑分辨率与最高输出分辨率上界（封顶 5120×2880）。
pub(super) fn compute_host_display_bounds(
    host: &HostSession,
    prefer_hardware: bool,
    hardware_video_active: bool,
) -> (Resolution, Resolution) {
    let neg = host.negotiated().unwrap_or_else(|| host.caps());
    let caps = host.caps();
    if prefer_hardware && hardware_video_active {
        let native = host_hardware_display_caps(true)
            .unwrap_or_else(|| Resolution::new(neg.width, neg.height).to_even());
        let backing = host_hardware_display_backing(true).unwrap_or(native);
        let max_res = clamp_display_max_res(native, backing);
        (native, max_res)
    } else {
        let native = Resolution::new(neg.width, neg.height).to_even();
        let max_res = Resolution::new(
            caps.width.min(display_ctrl::MAX_STREAM_WIDTH),
            caps.height.min(display_ctrl::MAX_STREAM_HEIGHT),
        )
        .to_even();
        (native, max_res)
    }
}

/// 组装本机硬件显示器预设列表，并在原生逻辑分辨率处标记 `is_native = true`。
pub(super) fn build_hardware_display_presets(
    prefer_hardware: bool,
    hardware_video_active: bool,
    original_native: Option<Resolution>,
) -> Vec<DisplayPreset> {
    if !(prefer_hardware && hardware_video_active) {
        return Vec::new();
    }
    let modes = crate::platform::list_main_display_modes();
    if modes.is_empty() {
        return Vec::new();
    }
    let native_res = original_native.or_else(crate::platform::main_display_logical_resolution);
    let mut presets: Vec<DisplayPreset> = Vec::with_capacity(modes.len());
    for m in modes {
        let is_native = native_res
            .is_some_and(|n| n.width.abs_diff(m.width) <= 2 && n.height.abs_diff(m.height) <= 2);
        let label = if m.is_hidpi {
            format!("{} × {} (HiDPI)", m.width, m.height)
        } else {
            format!("{} × {}", m.width, m.height)
        };
        presets.push(DisplayPreset {
            width: m.width,
            height: m.height,
            label,
            is_native,
            is_hidpi: m.is_hidpi,
        });
    }
    if let Some(nat) = native_res {
        if nat.width >= 2 && nat.height >= 2 && !presets.iter().any(|p| p.is_native) {
            presets.push(DisplayPreset {
                width: nat.width,
                height: nat.height,
                label: format!("{} × {}", nat.width, nat.height),
                is_native: true,
                is_hidpi: false,
            });
            presets.sort_by(|a, b| b.width.cmp(&a.width).then_with(|| b.height.cmp(&a.height)));
        }
    }
    presets
}

/// 计算当前被控端对外声明支持的视频编解码器列表（按当前分辨率档位排除已熔断项）。
fn host_supported_codecs(
    negotiator: &HostCodecNegotiator,
    tier: ResolutionTier,
    hevc_available: bool,
) -> Vec<String> {
    let mut out = Vec::with_capacity(3);
    if negotiator.is_codec_selectable(rc_encode::Codec::Av1, tier) {
        out.push("av1".to_string());
    }
    if hevc_available && negotiator.is_codec_selectable(rc_encode::Codec::Hevc, tier) {
        out.push("hevc".to_string());
    }
    out.push("h264".to_string());
    out
}

/// 编码当前被控端 `DisplayControlMsg::Capabilities` 载荷（含非对称能力明细、扩展标志位声明、权威编解码代次与静止补帧流纪元）。
#[allow(clippy::too_many_arguments)]
pub(super) fn encode_host_display_caps(
    host: &HostSession,
    native_res: Resolution,
    active_display_logical: Resolution,
    max_res: Resolution,
    display_hidpi: bool,
    presets: Vec<DisplayPreset>,
    hevc_available: bool,
    negotiator: &HostCodecNegotiator,
    hardware_media_active: bool,
    still_stream_epoch: u64,
) -> Option<Vec<u8>> {
    let cur = host.negotiated()?;
    let tier = ResolutionTier::from_dimensions(cur.width, cur.height);
    let max_fps = host.caps().fps.max(1);
    let current_codec = Some(host.active_codec().as_str().to_string());
    let supported_codecs = host_supported_codecs(negotiator, tier, hevc_available);
    let encode_caps = negotiator.host_encode_caps().to_vec();
    let decode_caps = codec_selector::cached_or_platform_decode_caps(hardware_media_active);
    let refinement_caps = Some(codec_selector::cached_or_platform_refinement_caps(
        hardware_media_active,
    ));
    display_ctrl::encode_display_ctrl(&DisplayControlMsg::Capabilities {
        current_width: cur.width,
        current_height: cur.height,
        current_fps: cur.fps,
        native_width: native_res.width,
        native_height: native_res.height,
        max_width: max_res.width,
        max_height: max_res.height,
        max_fps,
        presets,
        current_codec,
        supported_codecs,
        encode_caps,
        decode_caps,
        refinement_caps,
        supports_ext_codec_flags: true,
        codec_generation: negotiator.codec_generation(),
        still_stream_epoch,
        supports_pixel_scroll: true,
        supports_controller_meta: true,
        display_width: active_display_logical.width,
        display_height: active_display_logical.height,
        display_hidpi,
    })
}

/// 根据当前激活显示器状态生成 `Capabilities` 所需的原生分辨率与预设列表。
pub(super) fn build_session_display_caps_params(
    active_display_id: Option<u32>,
    session_native_res: Resolution,
    session_max_res: Resolution,
    original_native_res: Option<Resolution>,
    prefer_hardware: bool,
    hardware_video_active: bool,
) -> (Resolution, Vec<DisplayPreset>) {
    if active_display_id.is_some() {
        (
            session_native_res,
            display_ctrl::build_resolution_presets(
                session_native_res.width,
                session_native_res.height,
                session_max_res.width,
                session_max_res.height,
            ),
        )
    } else {
        (
            original_native_res.unwrap_or(session_native_res),
            build_hardware_display_presets(
                prefer_hardware,
                hardware_video_active,
                original_native_res,
            ),
        )
    }
}

/// 当热重建或恢复后发生编码器回退（如 HEVC → H.264）时：
/// 1. 若原编码器为 HEVC，置位 `hevc_runtime_failed`；
/// 2. 若处于 `auto_hidpi_active`，按实际生效编码器的像素率预算重算目标分辨率并重建流；
/// 3. 递增编解码协商代次 `codec_generation`。
pub(super) fn handle_codec_fallback_hidpi(
    host: &mut HostSession,
    prev_codec: rc_encode::Codec,
    auto_hidpi_active: bool,
    session_native_res: Resolution,
    session_max_res: Resolution,
    hevc_runtime_failed: &mut bool,
    codec_negotiator: &mut HostCodecNegotiator,
) -> bool {
    let actual_codec = host.active_codec();
    if actual_codec == prev_codec {
        return false;
    }
    if prev_codec == rc_encode::Codec::Hevc {
        *hevc_runtime_failed = true;
    }
    if auto_hidpi_active {
        if let Some(cur) = host.negotiated() {
            let fb_res = compute_hidpi_stream_target(
                session_native_res,
                Some(session_max_res),
                cur.fps,
                actual_codec,
            );
            if (fb_res.width, fb_res.height) != (cur.width, cur.height) {
                let _ = host.reconfigure_stream_with_codec(
                    fb_res.width,
                    fb_res.height,
                    Some(cur.fps),
                    Some(session_max_res),
                    Some(actual_codec),
                );
            }
        }
    }
    codec_negotiator.bump_generation();
    true
}

pub(super) struct HostDisplayModeSession {
    guard: Option<Box<dyn crate::platform::DisplayModeSessionGuard>>,
    #[cfg(test)]
    test_platform: Option<TestHostPlatformMock>,
}

impl HostDisplayModeSession {
    pub(super) fn capture(prefer_hardware: bool, hardware_video_active: bool) -> Self {
        let guard = if prefer_hardware && hardware_video_active {
            crate::platform::capture_display_mode_guard()
        } else {
            None
        };
        Self {
            guard,
            #[cfg(test)]
            test_platform: None,
        }
    }

    #[cfg(test)]
    pub(super) fn capture_with_test_platform(
        prefer_hardware: bool,
        hardware_video_active: bool,
        test_platform: Option<TestHostPlatformMock>,
    ) -> Self {
        let mut this = Self::capture(prefer_hardware, hardware_video_active);
        this.test_platform = test_platform;
        this
    }

    pub(super) fn original_resolution(&self) -> Option<Resolution> {
        self.guard.as_ref().map(|g| g.original_resolution())
    }

    pub(super) fn switch_to(&mut self, target_w: u32, target_h: u32) -> Result<Resolution, String> {
        #[cfg(test)]
        if let Some(ref tp) = self.test_platform {
            return tp.switch_mode(target_w, target_h);
        }
        match self.guard.as_mut() {
            Some(g) => g.switch_to(target_w, target_h),
            None => Err("显示器模式守卫未激活".to_string()),
        }
    }

    pub(super) fn restore(&mut self) {
        #[cfg(test)]
        if let Some(ref tp) = self.test_platform {
            tp.restore_mode();
        }
        if let Some(g) = self.guard.as_mut() {
            g.restore();
        }
    }
}

pub(super) fn spawn_wallpaper_fetcher() -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(1);
    let _ = thread::Builder::new()
        .name("rc-host-wallpaper".to_string())
        .spawn(move || {
            if let Some(jpeg) = crate::platform::capture_wallpaper_jpeg(640, 400) {
                if !jpeg.is_empty() {
                    let _ = tx.send(jpeg);
                }
            }
        });
    rx
}

/// 校验隐私屏保自定义图片魔数（仅放行非空 PNG / JPEG / WebP）。
pub(super) fn is_valid_privacy_image_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
        || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        || (bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
}

/// 被控端会话级硬件副作用清理守卫（隐私幕布 / 系统静音恢复 / 虚拟显示器销毁）。
///
/// 无论会话正常结束、断线、报错还是 panic，[`Drop`] 均会确定性清理全部本会话创建的硬件状态。
pub(super) struct HostHardwareCleanupGuard {
    prefer_hardware: bool,
    pub(super) privacy_active: bool,
    pub(super) host_audio_modified: bool,
    pub(super) restore_audio_on_exit: bool,
    pub(super) virtual_display_count: usize,
    #[cfg(test)]
    test_platform: Option<TestHostPlatformMock>,
}

impl HostHardwareCleanupGuard {
    pub(super) fn new(prefer_hardware: bool) -> Self {
        Self {
            prefer_hardware,
            privacy_active: false,
            host_audio_modified: false,
            restore_audio_on_exit: true,
            virtual_display_count: 0,
            #[cfg(test)]
            test_platform: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_test_platform(
        prefer_hardware: bool,
        test_platform: Option<TestHostPlatformMock>,
    ) -> Self {
        let mut this = Self::new(prefer_hardware || test_platform.is_some());
        this.test_platform = test_platform;
        this
    }

    pub(super) fn cleanup_now(&mut self) {
        if !self.prefer_hardware {
            self.privacy_active = false;
            self.host_audio_modified = false;
            self.restore_audio_on_exit = true;
            self.virtual_display_count = 0;
            return;
        }
        #[cfg(test)]
        if let Some(ref tp) = self.test_platform {
            self.privacy_active = false;
            self.host_audio_modified = false;
            self.restore_audio_on_exit = true;
            if self.virtual_display_count > 0 {
                tp.destroy_all_virtual_displays();
                self.virtual_display_count = 0;
            }
            return;
        }
        if self.privacy_active {
            crate::platform::clear_privacy_curtain();
            self.privacy_active = false;
        }
        if self.host_audio_modified {
            if self.restore_audio_on_exit {
                crate::platform::restore_host_system_audio();
            } else {
                crate::platform::clear_host_audio_snapshot();
            }
        }
        self.host_audio_modified = false;
        self.restore_audio_on_exit = true;
        if self.virtual_display_count > 0 {
            crate::platform::destroy_all_virtual_displays();
            self.virtual_display_count = 0;
        }
    }
}

impl Drop for HostHardwareCleanupGuard {
    fn drop(&mut self) {
        self.cleanup_now();
    }
}

pub(super) fn encode_host_displays_state_from_list(
    active_display_id: Option<u32>,
    raw: Vec<crate::platform::PlatformDisplayInfo>,
) -> Option<Vec<u8>> {
    if raw.is_empty() {
        return None;
    }
    let resolved_active = active_display_id
        .filter(|id| raw.iter().any(|d| d.id == *id))
        .or_else(|| raw.iter().find(|d| d.is_main).map(|d| d.id))
        .unwrap_or(raw[0].id);
    let displays = raw
        .into_iter()
        .map(|d| DisplayDescriptor {
            id: d.id,
            name: d.name,
            width: d.width,
            height: d.height,
            is_main: d.is_main,
            is_virtual: d.is_virtual,
        })
        .collect();
    display_ctrl::encode_display_ctrl(&DisplayControlMsg::DisplaysState {
        displays,
        active_display_id: resolved_active,
    })
}

pub(super) fn encode_host_displays_state(active_display_id: Option<u32>) -> Option<Vec<u8>> {
    encode_host_displays_state_from_list(active_display_id, crate::platform::list_displays())
}

pub(super) fn trigger_host_lock_screen(lock_screen_count: &AtomicU64, prefer_hardware: bool) {
    lock_screen_count.fetch_add(1, Ordering::AcqRel);
    if prefer_hardware {
        let ok = crate::platform::lock_screen_now();
        if !ok {
            eprintln!("[rc-ui-host] 锁定本机屏幕失败");
        }
    }
}
