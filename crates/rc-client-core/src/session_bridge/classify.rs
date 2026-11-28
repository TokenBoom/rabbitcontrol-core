use rc_session::proto::ByeReason;

pub use crate::bridge_shared::classify_relay_connect_error;
pub(crate) use crate::bridge_shared::is_mtls_cert_or_config_error;

use super::types::{SessionEnd, SESSION_SWITCHING_REASON};

pub(in crate::session_bridge) fn is_busy_controlled_reason(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("hostbusycontrolled")
        || lower.contains("host_busy_controlled")
        || lower.contains("target_in_session")
        || msg.contains("正在被控中")
        || msg.contains("正在被控制")
        || msg.contains("需要确认接管")
}

pub(in crate::session_bridge) fn is_preempted_reason(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("preempted") || msg.contains("已被其他设备接管")
}

/// 判定一段错误/断开文案是否属于不可自动恢复的终态（用户主动断开、密码/鉴权拒绝、mTLS 证书校验失败、仅 P2P 模式拒绝回退、硬件解码持久失败、被接管或目标忙）。
pub(in crate::session_bridge) fn is_non_recoverable_error_reason(msg: &str) -> bool {
    if is_mtls_cert_or_config_error(msg)
        || is_busy_controlled_reason(msg)
        || is_preempted_reason(msg)
    {
        return true;
    }
    let lower = msg.to_ascii_lowercase();
    msg.contains("用户主动断开")
        || msg.contains("已取消")
        || lower.contains("cancelled")
        || lower.contains("hoststopped")
        || lower.contains("host_stopped")
        || lower.contains("proxy_config_conflict")
        || msg.contains("代理配置冲突")
        || msg.contains("代理认证失败")
        || msg.contains("仅 P2P")
        || msg.contains("远端画面解码失败")
        || msg.contains("密码")
        || msg.contains("鉴权")
        || msg.contains("认证")
        || msg.contains("拒绝")
        || lower.contains("auth")
        || lower.contains("password")
        || lower.contains("unauthorized")
        || lower.contains("rejected")
        || lower.contains("denied")
}

/// 判定 Tier 1（`UDP LAN`）/ Tier 2（`UDP P2P`）会话握手失败后，是否允许安全回退至下一级传输链路。
///
/// 严格红线：
/// - 仅当**尚未进入鉴权/审批交互**（`!entered_auth_or_approval`，未收到 `Welcome` / `AuthChallenge`）
///   且发生底层连接断开/重置或首包超时（`Error::Network` / `Error::Io` / `Error::Timeout`）时才允许回退；
/// - 严禁在用户主动断开、密码/鉴权拒绝、机主拒绝、mTLS 证书校验失败（含服务端拒收客户端证书的 QUIC
///   `CRYPTO_ERROR` alert）、协议版本不兼容、或已收到 `Welcome{ChallengeRequired}` / `AuthChallenge`
///   后的任何失败/审批超时中回退（防止被控端连弹多个审批窗）。
pub(in crate::session_bridge) fn should_fallback_after_handshake_error(
    err: &rc_types::Error,
    entered_auth_or_approval: bool,
    user_disconnected: bool,
) -> bool {
    if user_disconnected || entered_auth_or_approval {
        return false;
    }
    if !matches!(
        err,
        rc_types::Error::Network(_) | rc_types::Error::Io(_) | rc_types::Error::Timeout(_)
    ) {
        return false;
    }
    let msg = err.to_string();
    if is_mtls_cert_or_config_error(&msg) || is_non_recoverable_error_reason(&msg) {
        return false;
    }
    let lower = msg.to_ascii_lowercase();
    !(lower.contains("protocol")
        || lower.contains("version")
        || lower.contains("incompatible")
        || lower.contains("unsupported"))
}

/// 信令会话进入 `Reconnecting` 退出时按当前传输通道标签生成精确文案并标记 `recoverable = true`。
pub(in crate::session_bridge) fn signaling_disconnect_end(transport_label: &str) -> SessionEnd {
    let reason = match transport_label {
        "UDP LAN" => "局域网连接已断开",
        "UDP P2P" => "P2P 连接已断开",
        _ => "中继连接已断开",
    };
    SessionEnd::recoverable(reason)
}

/// 将 `ClientSession::tick` 返回的 `StopReason` 映射为 [`SessionEnd`]。
pub(in crate::session_bridge) fn classify_stop_reason_end(
    stop: &rc_session::StopReason,
) -> SessionEnd {
    match stop {
        rc_session::StopReason::ByeReceived(ByeReason::SessionSwitching) => {
            SessionEnd::fatal(SESSION_SWITCHING_REASON)
        }
        rc_session::StopReason::ByeReceived(ByeReason::Preempted) => {
            SessionEnd::preempted("当前连接已被其他设备接管")
        }
        rc_session::StopReason::ByeReceived(ByeReason::Normal)
        | rc_session::StopReason::Requested => SessionEnd::fatal(format!("对端已关闭 ({stop:?})")),
        rc_session::StopReason::ByeReceived(ByeReason::Refresh) => {
            SessionEnd::recoverable(format!("对端已关闭 ({stop:?})"))
        }
        rc_session::StopReason::Disconnected(msg) => {
            if is_busy_controlled_reason(msg) {
                SessionEnd::busy_controlled("目标设备正在被控中，需要确认接管")
            } else if is_preempted_reason(msg) {
                SessionEnd::preempted("当前连接已被其他设备接管")
            } else {
                let reason = format!("对端已关闭 ({stop:?})");
                if is_non_recoverable_error_reason(msg) {
                    SessionEnd::fatal(reason)
                } else {
                    SessionEnd::recoverable(reason)
                }
            }
        }
    }
}

/// 将纯 IP 直连 `ReconnectOutcome::GaveUp` 映射为 [`SessionEnd`]。
pub(in crate::session_bridge) fn classify_gave_up_end(
    closed_reason: Option<&rc_session::StopReason>,
) -> SessionEnd {
    match closed_reason {
        Some(rc_session::StopReason::ByeReceived(ByeReason::SessionSwitching)) => {
            SessionEnd::fatal(SESSION_SWITCHING_REASON)
        }
        Some(rc_session::StopReason::ByeReceived(ByeReason::Preempted)) => {
            SessionEnd::preempted("当前连接已被其他设备接管")
        }
        Some(stop @ rc_session::StopReason::ByeReceived(ByeReason::Normal)) => {
            SessionEnd::fatal(format!("对端已关闭 ({stop:?})"))
        }
        Some(rc_session::StopReason::Disconnected(msg)) if is_busy_controlled_reason(msg) => {
            SessionEnd::busy_controlled("目标设备正在被控中，需要确认接管")
        }
        Some(rc_session::StopReason::Disconnected(msg)) if is_preempted_reason(msg) => {
            SessionEnd::preempted("当前连接已被其他设备接管")
        }
        _ => SessionEnd::recoverable("重连次数已耗尽"),
    }
}

/// 将运行期驱动错误（`pump_probes` / `tick` / `tick_reconnect`）映射为 [`SessionEnd`]。
pub(in crate::session_bridge) fn classify_runtime_err_end(
    prefix: &str,
    err: &rc_types::Error,
    user_disconnected: bool,
) -> SessionEnd {
    if user_disconnected {
        return SessionEnd::fatal("用户主动断开");
    }
    let raw = err.to_string();
    if is_preempted_reason(&raw) {
        return SessionEnd::preempted("当前连接已被其他设备接管");
    }
    if is_busy_controlled_reason(&raw) {
        return SessionEnd::busy_controlled("目标设备正在被控中，需要确认接管");
    }
    let reason = format!("{prefix}: {raw}");
    if is_non_recoverable_error_reason(&raw) {
        SessionEnd::fatal(reason)
    } else {
        SessionEnd::recoverable(reason)
    }
}
