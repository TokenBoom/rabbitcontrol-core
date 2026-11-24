//! 跨平台客户端核心对宿主平台（macOS / Windows / Linux）的硬件钩子抽象。
//!
//! 本模块全量 `#![deny(unsafe_code)]` 且不引入任何 OS 特定依赖；
//! 宿主端（例如 `rc-platform-macos`）在启动时调用 [`register_platform_hooks`]
//! 注入系统显示、硬件渲染表面、线程 QoS、锁屏、壁纸抓取与系统输入注入器。

#![deny(unsafe_code)]

use std::any::Any;
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use rc_render::Renderer;
use rc_types::Resolution;

/// 在平台主线程预分配的渲染表面句柄（例如 macOS `CAMetalLayer*`），
/// 通过不透明指针整型与类型擦除守卫跨线程移交并在析构时安全回收。
#[derive(Clone)]
pub struct PreallocatedRenderSurface {
    raw_ptr: usize,
    _guard: Arc<dyn Any + Send + Sync>,
}

impl fmt::Debug for PreallocatedRenderSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreallocatedRenderSurface")
            .field("raw_ptr", &self.raw_ptr)
            .finish()
    }
}

impl PreallocatedRenderSurface {
    /// 封装预分配渲染表面原始指针地址与生命周期保活守卫。
    pub fn new<G: Any + Send + Sync>(raw_ptr: usize, guard: G) -> Self {
        Self {
            raw_ptr,
            _guard: Arc::new(guard),
        }
    }

    /// 返回底层渲染表面原始指针地址（供平台渲染器领养）。
    pub fn raw_ptr(&self) -> usize {
        self.raw_ptr
    }
}

/// 宿主主显示器的单个分辨率预设项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformDisplayMode {
    /// 逻辑宽度（像素/点）。
    pub width: u32,
    /// 逻辑高度（像素/点）。
    pub height: u32,
    /// 是否为高分屏 HiDPI 模式。
    pub is_hidpi: bool,
}

/// 被控期间临时切换系统显示器分辨率的 RAII 守卫（`Drop` 时自动恢复原生分辨率）。
pub trait DisplayModeSessionGuard: Send {
    /// 返回接管前记录的原生逻辑分辨率。
    fn original_resolution(&self) -> Resolution;

    /// 将主显示器物理切换至最接近目标尺寸的模式，返回实际切换后的逻辑分辨率。
    fn switch_to(&mut self, target_w: u32, target_h: u32) -> Result<Resolution, String>;

    /// 显式恢复到接管前的原生分辨率。
    fn restore(&mut self);
}

/// 平台硬件渲染器构造结果。
pub struct HardwareRendererOutput {
    /// 已就绪的硬件渲染器实现。
    pub renderer: Box<dyn Renderer>,
    /// 可选的底层显示层原始指针地址（供前端窗口挂载，无独立层时为 `0`）。
    pub layer_addr: usize,
    /// 诊断后端标签（例如 `"metal"`）。
    pub label: &'static str,
}

/// 客户端跨平台内核向原生 OS 层委托的硬件能力接口。
pub trait ClientPlatformHooks: Send + Sync {
    /// 提升当前工作线程至平台高实时性交互 QoS。
    fn promote_current_thread_qos(&self) {}

    /// 开始阻止系统休眠/App Nap 的低延迟活动周期，返回 RAII 保活句柄。
    fn begin_latency_critical_activity(
        &self,
        _reason: &str,
        _interactive: bool,
    ) -> Option<Box<dyn Any + Send>> {
        None
    }

    /// 读取当前主显示器逻辑分辨率。
    fn main_display_logical_resolution(&self) -> Option<Resolution> {
        None
    }

    /// 读取当前主显示器物理像素分辨率。
    fn main_display_backing_resolution(&self) -> Option<Resolution> {
        None
    }

    /// 列举当前主显示器支持的分辨率预设列表。
    fn list_main_display_modes(&self) -> Vec<PlatformDisplayMode> {
        Vec::new()
    }

    /// 捕获当前显示器模式，用于在远控期间切换分辨率并在断开后恢复。
    fn capture_display_mode_guard(&self) -> Option<Box<dyn DisplayModeSessionGuard>> {
        None
    }

    /// 抓取当前主显示器壁纸缩略图 JPEG 字节。
    fn capture_wallpaper_jpeg(&self, _max_width: u32, _max_height: u32) -> Option<Vec<u8>> {
        None
    }

    /// 立即锁定当前主屏幕；成功返回 `true`。
    fn lock_screen_now(&self) -> bool {
        false
    }

    /// 创建绑定到主显示器的系统输入注入器。
    fn create_main_display_injector(&self) -> Option<Box<dyn rc_input::InputInjector>> {
        None
    }

    /// 构造控制端硬件渲染器（可选接管主线程预分配表面）。
    fn create_hardware_renderer(
        &self,
        _width: u32,
        _height: u32,
        _session_start: Instant,
        _preallocated: Option<&PreallocatedRenderSurface>,
    ) -> Result<HardwareRendererOutput, String> {
        Err("hardware renderer is not registered on this platform".to_string())
    }
}

static PLATFORM_HOOKS: OnceLock<Arc<dyn ClientPlatformHooks>> = OnceLock::new();

/// 注册当前进程的客户端原生平台钩子实现（仅首次调用生效）。
pub fn register_platform_hooks(hooks: Arc<dyn ClientPlatformHooks>) -> bool {
    PLATFORM_HOOKS.set(hooks).is_ok()
}

/// 提升当前线程 QoS（未注册钩子时无操作）。
pub fn promote_current_thread_qos() {
    if let Some(h) = PLATFORM_HOOKS.get() {
        h.promote_current_thread_qos();
    }
}

/// 开启低延迟关键活动周期并返回 RAII 保活守卫。
pub fn begin_latency_critical_activity(
    reason: &str,
    interactive: bool,
) -> Option<Box<dyn Any + Send>> {
    PLATFORM_HOOKS
        .get()
        .and_then(|h| h.begin_latency_critical_activity(reason, interactive))
}

/// 查询主显示器逻辑分辨率。
pub fn main_display_logical_resolution() -> Option<Resolution> {
    PLATFORM_HOOKS
        .get()
        .and_then(|h| h.main_display_logical_resolution())
}

/// 查询主显示器物理像素分辨率。
pub fn main_display_backing_resolution() -> Option<Resolution> {
    PLATFORM_HOOKS
        .get()
        .and_then(|h| h.main_display_backing_resolution())
}

/// 列举主显示器分辨率预设列表。
pub fn list_main_display_modes() -> Vec<PlatformDisplayMode> {
    PLATFORM_HOOKS
        .get()
        .map(|h| h.list_main_display_modes())
        .unwrap_or_default()
}

/// 捕获当前主显示器分辨率切换守卫。
pub fn capture_display_mode_guard() -> Option<Box<dyn DisplayModeSessionGuard>> {
    PLATFORM_HOOKS
        .get()
        .and_then(|h| h.capture_display_mode_guard())
}

/// 抓取主显示器壁纸 JPEG 缩略图。
pub fn capture_wallpaper_jpeg(max_width: u32, max_height: u32) -> Option<Vec<u8>> {
    PLATFORM_HOOKS
        .get()
        .and_then(|h| h.capture_wallpaper_jpeg(max_width, max_height))
}

/// 立即锁定当前主屏幕。
pub fn lock_screen_now() -> bool {
    PLATFORM_HOOKS.get().is_some_and(|h| h.lock_screen_now())
}

/// 创建绑定主显示器的系统输入注入器。
pub fn create_main_display_injector() -> Option<Box<dyn rc_input::InputInjector>> {
    PLATFORM_HOOKS
        .get()
        .and_then(|h| h.create_main_display_injector())
}

/// 构造控制端硬件渲染器。
pub fn create_hardware_renderer(
    width: u32,
    height: u32,
    session_start: Instant,
    preallocated: Option<&PreallocatedRenderSurface>,
) -> Result<HardwareRendererOutput, String> {
    match PLATFORM_HOOKS.get() {
        Some(h) => h.create_hardware_renderer(width, height, session_start, preallocated),
        None => Err("hardware renderer is not registered on this platform".to_string()),
    }
}
