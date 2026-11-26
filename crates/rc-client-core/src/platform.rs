//! 跨平台客户端核心对宿主平台（macOS / Windows / Linux）的硬件钩子抽象。
//!
//! 本模块全量 `#![deny(unsafe_code)]` 且不引入任何 OS 特定依赖；
//! 宿主端（例如 `rc-platform-macos`）在启动时调用 [`register_platform_hooks`]
//! 注入系统显示、硬件渲染表面、线程 QoS、锁屏、壁纸抓取与系统输入注入器。

#![deny(unsafe_code)]

use std::any::Any;
use std::fmt;
use std::path::Path;
use std::sync::atomic::AtomicBool;
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

/// 宿主系统在线显示器（物理屏或虚拟屏）完整描述。
#[derive(Debug, Clone, PartialEq)]
pub struct PlatformDisplayInfo {
    /// 平台显示器唯一标识（macOS `CGDirectDisplayID`）。
    pub id: u32,
    /// 可读名称。
    pub name: String,
    /// 逻辑宽度（点）。
    pub width: u32,
    /// 逻辑高度（点）。
    pub height: u32,
    /// 全局桌面坐标系原点 X（点）。
    pub origin_x: f64,
    /// 全局桌面坐标系原点 Y（点）。
    pub origin_y: f64,
    /// 是否为主显示器。
    pub is_main: bool,
    /// 是否为本进程创建的虚拟显示器。
    pub is_virtual: bool,
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

    /// 若宿主显示器当前处于熄屏/休眠状态，则声明用户活动以唤醒亮屏并返回可选 RAII 断言守卫。
    fn wake_display_if_asleep(&self) -> Result<Option<Box<dyn Any + Send>>, String> {
        Ok(None)
    }

    /// 判断宿主显示器当前是否处于熄屏/休眠状态。
    fn is_display_asleep(&self) -> bool {
        false
    }

    /// 判断宿主当前桌面会话是否处于锁屏状态。
    fn is_screen_locked(&self) -> bool {
        false
    }

    /// 开启或更新被控端物理防窥隐私幕布（遮挡所有物理屏但对屏幕采集排除）；
    /// `mode` 为 `"privacy"` / `"black"` / `"off"`。
    fn set_privacy_curtain(
        &self,
        _mode: &str,
        _preset: &str,
        _custom_image_bytes: Option<&[u8]>,
    ) -> Result<(), String> {
        Err("当前平台暂不支持物理防窥隐私幕布".to_string())
    }

    /// 关闭并销毁被控端全部物理防窥隐私幕布窗口（幂等）。
    fn clear_privacy_curtain(&self) {}

    /// 设置被控端本机扬声器系统静音状态，返回设置后的静音状态。
    fn set_host_system_muted(&self, _muted: bool) -> Result<bool, String> {
        Err("当前平台暂不支持被控端系统静音".to_string())
    }

    /// 恢复被控端本机扬声器在进入远控前的原始静音状态（幂等）。
    fn restore_host_system_audio(&self) {}

    /// 清除已保存的被控端声音快照而不修改当前硬件静音状态（用于 `restore_on_exit == false` 结束会话，防止污染下一次会话）。
    fn clear_host_audio_snapshot(&self) {}

    /// 枚举当前全部在线显示器（含物理屏与本进程创建的虚拟屏）。
    fn list_displays(&self) -> Vec<PlatformDisplayInfo> {
        Vec::new()
    }

    /// 创建一个虚拟显示器，返回新显示器的完整描述。
    fn create_virtual_display(
        &self,
        _width: u32,
        _height: u32,
        _hidpi: bool,
    ) -> Result<PlatformDisplayInfo, String> {
        Err("当前平台暂不支持创建虚拟显示器".to_string())
    }

    /// 销毁由本进程创建的指定虚拟显示器；成功销毁返回 `true`。
    fn destroy_virtual_display(&self, _display_id: u32) -> bool {
        false
    }

    /// 销毁本进程创建的全部虚拟显示器（幂等，会话退出时调用）。
    fn destroy_all_virtual_displays(&self) {}

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

    /// 返回当前运行应用的语义版本号（如 `"0.1.9"`）。
    fn current_app_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// 返回当前运行应用的规范化 CPU 架构（如 `"arm64"` / `"x86_64"`）。
    fn current_app_arch(&self) -> &'static str {
        if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            std::env::consts::ARCH
        }
    }

    /// 当前宿主平台是否支持自动下载并应用更新包。
    fn can_self_update(&self) -> bool {
        false
    }

    /// 当前宿主是否已安装系统级后台服务（用于判断是否可免密重启更新）。
    fn is_system_service_installed(&self) -> bool {
        false
    }

    /// 拉取最新 Release 元数据与各架构资产的 SHA-256 校验值。
    fn fetch_latest_release(
        &self,
        _mirror_url: &str,
    ) -> Result<crate::updater::ReleaseInfo, String> {
        Err("当前平台未注册更新检查实现".to_string())
    }

    /// 下载更新安装包至 `dest_path` 并校验其 SHA-256 摘要（支持取消与实时进度回调）。
    fn download_update_package(
        &self,
        _url: &str,
        _expected_sha256: &str,
        _dest_path: &Path,
        _cancel: &AtomicBool,
        _on_progress: &mut dyn FnMut(u64, u64),
    ) -> Result<(), String> {
        Err("当前平台未注册更新下载实现".to_string())
    }

    /// 校验并原子安装已验证的更新包（含代码签名校验、目录替换及可选重启）。
    fn install_verified_update(
        &self,
        _package_path: &Path,
        _expected_sha256: &str,
        _restart_after: bool,
        _is_remote_headless: bool,
    ) -> Result<(), String> {
        Err("当前平台未注册更新安装实现".to_string())
    }

    /// 读取当前操作系统的系统级网络代理配置（未配置或未实现时返回 `None`，由核心层回退环境变量）。
    fn resolve_system_proxy(&self) -> Option<crate::proxy::ProxyConfig> {
        None
    }

    /// 读取当前宿主设备主有线/无线网卡的单播 MAC 地址（供 Wake-on-LAN 上报，未实现时返回 `None`）。
    fn primary_mac_address(&self) -> Option<String> {
        None
    }
}

static PLATFORM_HOOKS: OnceLock<Arc<dyn ClientPlatformHooks>> = OnceLock::new();
static UPDATE_HOOKS: OnceLock<Arc<dyn ClientUpdateHooks>> = OnceLock::new();

/// 客户端自动更新与远程更新钩子接口（独立注册口，供宿主 App / 后台服务在不侵入硬件渲染钩子时注入）。
///
/// 未单独注册时，相关模块级包装函数会自动回退至 [`ClientPlatformHooks`] 的默认实现。
pub trait ClientUpdateHooks: Send + Sync {
    /// 返回当前运行应用的语义版本号（如 `"0.1.10"`）。
    fn current_app_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// 返回当前运行应用的规范化 CPU 架构（如 `"arm64"` / `"x86_64"`）。
    fn current_app_arch(&self) -> &'static str {
        if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            std::env::consts::ARCH
        }
    }

    /// 当前宿主平台是否支持自动下载并应用更新包。
    fn can_self_update(&self) -> bool {
        false
    }

    /// 当前宿主是否已安装系统级后台服务（用于判断是否可免密重启更新）。
    fn is_system_service_installed(&self) -> bool {
        false
    }

    /// 拉取最新 Release 元数据与各架构资产的 SHA-256 校验值。
    fn fetch_latest_release(
        &self,
        _mirror_url: &str,
    ) -> Result<crate::updater::ReleaseInfo, String> {
        Err("当前平台未注册更新检查实现".to_string())
    }

    /// 下载更新安装包至 `dest_path` 并校验其 SHA-256 摘要（支持取消与实时进度回调）。
    fn download_update_package(
        &self,
        _url: &str,
        _expected_sha256: &str,
        _dest_path: &Path,
        _cancel: &AtomicBool,
        _on_progress: &mut dyn FnMut(u64, u64),
    ) -> Result<(), String> {
        Err("当前平台未注册更新下载实现".to_string())
    }

    /// 校验并原子安装已验证的更新包（含代码签名校验、目录替换及可选重启）。
    fn install_verified_update(
        &self,
        _package_path: &Path,
        _expected_sha256: &str,
        _restart_after: bool,
        _is_remote_headless: bool,
    ) -> Result<(), String> {
        Err("当前平台未注册更新安装实现".to_string())
    }
}

/// 注册当前进程的客户端原生平台钩子实现（仅首次调用生效）。
pub fn register_platform_hooks(hooks: Arc<dyn ClientPlatformHooks>) -> bool {
    PLATFORM_HOOKS.set(hooks).is_ok()
}

/// 注册当前进程的客户端自动更新钩子实现（仅首次调用生效，优先于 [`ClientPlatformHooks`] 的默认更新方法）。
pub fn register_update_hooks(hooks: Arc<dyn ClientUpdateHooks>) -> bool {
    UPDATE_HOOKS.set(hooks).is_ok()
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

/// 若宿主显示器当前处于熄屏/休眠状态则唤醒亮屏，返回可选 RAII 断言守卫。
pub fn wake_display_if_asleep() -> Result<Option<Box<dyn Any + Send>>, String> {
    match PLATFORM_HOOKS.get() {
        Some(h) => h.wake_display_if_asleep(),
        None => Ok(None),
    }
}

/// 判断宿主显示器当前是否处于熄屏/休眠状态。
pub fn is_display_asleep() -> bool {
    PLATFORM_HOOKS.get().is_some_and(|h| h.is_display_asleep())
}

/// 判断宿主当前桌面会话是否处于锁屏状态。
pub fn is_screen_locked() -> bool {
    PLATFORM_HOOKS.get().is_some_and(|h| h.is_screen_locked())
}

/// 开启或更新被控端物理防窥隐私幕布。
pub fn set_privacy_curtain(
    mode: &str,
    preset: &str,
    custom_image_bytes: Option<&[u8]>,
) -> Result<(), String> {
    match PLATFORM_HOOKS.get() {
        Some(h) => h.set_privacy_curtain(mode, preset, custom_image_bytes),
        None => Err("当前平台未注册防窥隐私幕布钩子".to_string()),
    }
}

/// 关闭并销毁被控端全部物理防窥隐私幕布窗口。
pub fn clear_privacy_curtain() {
    if let Some(h) = PLATFORM_HOOKS.get() {
        h.clear_privacy_curtain();
    }
}

/// 设置被控端本机扬声器静音状态。
pub fn set_host_system_muted(muted: bool) -> Result<bool, String> {
    match PLATFORM_HOOKS.get() {
        Some(h) => h.set_host_system_muted(muted),
        None => Err("当前平台未注册系统静音钩子".to_string()),
    }
}

/// 恢复被控端本机扬声器原始声音设置。
pub fn restore_host_system_audio() {
    if let Some(h) = PLATFORM_HOOKS.get() {
        h.restore_host_system_audio();
    }
}

/// 清除被控端已保存的原始声音快照（不改动当前音量/静音状态）。
pub fn clear_host_audio_snapshot() {
    if let Some(h) = PLATFORM_HOOKS.get() {
        h.clear_host_audio_snapshot();
    }
}

/// 枚举当前全部在线显示器（含物理屏与虚拟屏）。
pub fn list_displays() -> Vec<PlatformDisplayInfo> {
    PLATFORM_HOOKS
        .get()
        .map(|h| h.list_displays())
        .unwrap_or_default()
}

/// 创建一个新的虚拟显示器。
pub fn create_virtual_display(
    width: u32,
    height: u32,
    hidpi: bool,
) -> Result<PlatformDisplayInfo, String> {
    match PLATFORM_HOOKS.get() {
        Some(h) => h.create_virtual_display(width, height, hidpi),
        None => Err("当前平台未注册虚拟显示器钩子".to_string()),
    }
}

/// 销毁指定的虚拟显示器。
pub fn destroy_virtual_display(display_id: u32) -> bool {
    PLATFORM_HOOKS
        .get()
        .is_some_and(|h| h.destroy_virtual_display(display_id))
}

/// 销毁本进程创建的全部虚拟显示器。
pub fn destroy_all_virtual_displays() {
    if let Some(h) = PLATFORM_HOOKS.get() {
        h.destroy_all_virtual_displays();
    }
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

/// 返回当前运行应用的语义版本号。
pub fn current_app_version() -> String {
    if let Some(u) = UPDATE_HOOKS.get() {
        return u.current_app_version();
    }
    PLATFORM_HOOKS
        .get()
        .map(|h| h.current_app_version())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}

/// 返回当前运行应用的规范化 CPU 架构。
pub fn current_app_arch() -> &'static str {
    if let Some(u) = UPDATE_HOOKS.get() {
        return u.current_app_arch();
    }
    PLATFORM_HOOKS
        .get()
        .map(|h| h.current_app_arch())
        .unwrap_or(if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            std::env::consts::ARCH
        })
}

/// 返回当前平台是否支持自动更新。
pub fn can_self_update() -> bool {
    if let Some(u) = UPDATE_HOOKS.get() {
        return u.can_self_update();
    }
    PLATFORM_HOOKS.get().is_some_and(|h| h.can_self_update())
}

/// 返回当前宿主是否已安装系统级后台服务。
pub fn is_system_service_installed() -> bool {
    if let Some(u) = UPDATE_HOOKS.get() {
        return u.is_system_service_installed();
    }
    PLATFORM_HOOKS
        .get()
        .is_some_and(|h| h.is_system_service_installed())
}

/// 拉取最新 Release 信息与 SHA-256 校验值。
pub fn fetch_latest_release(mirror_url: &str) -> Result<crate::updater::ReleaseInfo, String> {
    if let Some(u) = UPDATE_HOOKS.get() {
        return u.fetch_latest_release(mirror_url);
    }
    match PLATFORM_HOOKS.get() {
        Some(h) => h.fetch_latest_release(mirror_url),
        None => Err("当前平台未注册更新检查实现".to_string()),
    }
}

/// 下载并校验更新安装包。
pub fn download_update_package(
    url: &str,
    expected_sha256: &str,
    dest_path: &Path,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(u64, u64),
) -> Result<(), String> {
    if let Some(u) = UPDATE_HOOKS.get() {
        return u.download_update_package(url, expected_sha256, dest_path, cancel, on_progress);
    }
    match PLATFORM_HOOKS.get() {
        Some(h) => h.download_update_package(url, expected_sha256, dest_path, cancel, on_progress),
        None => Err("当前平台未注册更新下载实现".to_string()),
    }
}

/// 校验签名并原子安装已验证的更新包。
pub fn install_verified_update(
    package_path: &Path,
    expected_sha256: &str,
    restart_after: bool,
    is_remote_headless: bool,
) -> Result<(), String> {
    if let Some(u) = UPDATE_HOOKS.get() {
        return u.install_verified_update(
            package_path,
            expected_sha256,
            restart_after,
            is_remote_headless,
        );
    }
    match PLATFORM_HOOKS.get() {
        Some(h) => h.install_verified_update(
            package_path,
            expected_sha256,
            restart_after,
            is_remote_headless,
        ),
        None => Err("当前平台未注册更新安装实现".to_string()),
    }
}

/// 查询宿主操作系统的系统级网络代理配置（未注册平台钩子或系统未配置时返回 `None`）。
pub fn resolve_system_proxy() -> Option<crate::proxy::ProxyConfig> {
    PLATFORM_HOOKS.get().and_then(|h| h.resolve_system_proxy())
}

/// 查询宿主设备主网卡单播 MAC 地址（供 Wake-on-LAN 上报；未注册钩子或不可用时返回 `None`）。
pub fn primary_mac_address() -> Option<String> {
    PLATFORM_HOOKS.get().and_then(|h| h.primary_mac_address())
}
