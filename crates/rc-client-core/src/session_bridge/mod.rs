//! UI ↔ 会话层唯一通道（T21 API 契约 §1）。
//!
//! 本模块**严禁引入 `tauri` 类型**，仅依赖 `std` + `rc-session` + `rc-net` +
//! `rc-pipeline` + `rc-input` + `rc-render` + `rc-decode` + `rc-trace`，
//! 从而使 `cargo test -p rc-ui` 的离线单测与进程内集成测试无需窗口与事件循环。
//!
//! # 硬性纪律
//! - 全模块 `#![deny(unsafe_code)]`（`CAMetalLayer` 借用指针以 `usize` 传递，不解引用）；
//! - 铁律 1（UI 侧延伸 / U6）：命令通道容量 `64`、输入通道容量 `256`、更新通道容量 `64`，
//!   满载一律非阻塞丢最旧；输入通道满载时优先保留关键事件（`Key` / `MouseButton` / `MouseWheel`），
//!   优先淘汰非关键的 `MouseMove` / `Sync`；
//! - U3：会话协议零改动，S3 手动调码率仅发送既有 `SetBitrate { reason: Manual }`；
//! - U5：HUD 数字全部由会话线程调用 [`crate::hud::HudSnapshot::derive`] 差分聚合后推送；
//! - U8：使用 `rc_session::dev_cert` 零配置直连，`ConnectPhase` 起点在 Endpoint 创建之前；
//! - U9：`watch_only == true` 时双层拦截输入（`send_input` + `BridgeInputCapture`）；
//! - U10：`join` 与 `Drop` 均自动发 `Disconnect` 并回收会话线程，不留僵尸线程。

#![deny(unsafe_code)]

mod adapters;
mod classify;
mod connect;
mod display_ctrl;
mod handle;
mod queues;
mod routing;
mod session_loop;
mod tools;
mod types;

#[cfg(test)]
mod tests;

pub use crate::relay_transport::SessionMtlsBundle;
pub use adapters::LayerLease;
pub use classify::classify_relay_connect_error;
#[allow(unused_imports)]
pub(crate) use classify::is_mtls_cert_or_config_error;
pub use handle::{SessionHandle, SessionInputHandle};
pub use tools::ToolClientHandle;
pub use types::{
    ConnectPhase, SessionCommand, SessionUpdate, UiSessionConfig, COMMAND_CHANNEL_CAP,
    INPUT_CHANNEL_CAP, SESSION_SWITCHING_REASON, UPDATE_CHANNEL_CAP,
};
