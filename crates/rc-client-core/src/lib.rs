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
pub mod config_paths;
pub mod display_ctrl;
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
