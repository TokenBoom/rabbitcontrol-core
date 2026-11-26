//! RabbitControl 跨平台客户端核心运行时库。
//!
//! 聚合认证与设备证书管理、服务器信令/P2P/mTLS 中继传输、局域网快速路由、
//! 控制端与被控端会话桥接引擎、配置路径与偏好设置等全部跨平台业务逻辑；
//! 零 GUI/Tauri 依赖、零 OS 原生 FFI，全 crate `#![deny(unsafe_code)]`。

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod app_prefs;
pub mod auth_client;
pub mod cert_manager;
pub mod codec_selector;
pub mod config_paths;
pub mod display_ctrl;
pub mod generated;
pub mod host_bridge;
pub mod hud;
pub mod input_bridge;
pub mod lan_discovery;
pub mod model;
pub mod p2p;
pub mod platform;
pub mod relay_transport;
pub mod server_config;
pub mod session_bridge;
pub mod signal_client;
pub mod still_refine;
pub mod ui_error;
pub mod updater;
pub mod upnp;
pub mod version;

pub use version::{core_build_info, core_version, CoreBuildInfo, CORE_ABI_VERSION};

/// 根据操作系统名称推导缺省的「允许被远程控制」默认值（供老服务端未返回该字段时安全兜底）。
///
/// Android / iOS 等移动设备默认关闭远程控制（返回 `false`），桌面与服务器平台默认开启（返回 `true`）。
pub fn default_allow_remote_control_for_os(os: &str) -> bool {
    let lower = os.to_ascii_lowercase();
    !(lower.contains("android") || lower.contains("ios"))
}

#[cfg(test)]
mod tests {
    use super::default_allow_remote_control_for_os;

    #[test]
    fn default_allow_remote_control_for_os_blocks_mobile_and_allows_desktop() {
        assert!(!default_allow_remote_control_for_os("android"));
        assert!(!default_allow_remote_control_for_os("Android 14"));
        assert!(!default_allow_remote_control_for_os("iOS"));
        assert!(!default_allow_remote_control_for_os("ios-arm64"));
        assert!(default_allow_remote_control_for_os("macos"));
        assert!(default_allow_remote_control_for_os("windows"));
        assert!(default_allow_remote_control_for_os("linux"));
        assert!(default_allow_remote_control_for_os(""));
    }
}
