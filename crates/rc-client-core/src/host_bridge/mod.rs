//! UI ↔ 被控端会话桥接层（一体化 All-in-One 模式）。
//!
//! 本模块**严禁引入 `tauri` 类型**，全模块 `#![deny(unsafe_code)]`，
//! 复用 T19 唯一审批 trait [`rc_session::auth::ConnectionApprover`]，
//! 使 `cargo test -p rc-ui` 离线集成测试无需窗口与事件循环。
//!
//! # 设计要点
//! - 启动时在 `HostHandle::spawn` 内即完成首轮 `HostSession` 绑定（默认 `9901` 端口
//!   若被占用自动回退到同 IP 临时端口 `0`），使 [`HostHandle::listen_addr`] 立即可用；
//! - 工作线程单会话串行循环 accept：每轮 accept 分片前重锚 `ClockOrigin::Pending`，
//!   管线工厂按裁定参数构建硬件/假后端并重锚会话钟；
//! - [`UiApprover`] 实现 [`ConnectionApprover`]：代次单调递增防过期裁决串台，
//!   `submit` / `cancel` 直接推送 [`HostUpdate::ApprovalRequested`] /
//!   [`HostUpdate::ApprovalCancelled`]；
//! - [`HostHandle::stop`] 与 `Drop` 自动拒绝在途审批并触发 `HostSession::run` 优雅停机，
//!   回收工作线程不留僵尸线程。

#![deny(unsafe_code)]

mod approver;
mod audio_bwe;
mod handle;
mod media_aux;
mod pipeline_factory;
mod queues;
mod session_loop;
mod tools_worker;
mod transport_dial;
mod transport_worker;
mod types;
mod worker;

#[cfg(test)]
mod tests;

pub use crate::relay_transport::SessionMtlsBundle;
pub use approver::UiApprover;
pub use handle::HostHandle;
pub use pipeline_factory::collect_host_lan_addrs;
pub use types::{
    generate_temp_code, ActiveControllerSession, HostApprovalPrompt, HostCommand, HostUpdate,
    UiHostConfig, DEFAULT_HOST_PORT, HOST_UPDATE_CHANNEL_CAP, TEMP_CODE_LEN,
};
