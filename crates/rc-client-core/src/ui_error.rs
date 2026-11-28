//! 跨平台结构化 UI 错误模型与错误归因层（基于 `TokenBoom/rabbitcontrol-spec` v1.0.0）。
//!
//! 统一封装 `generated::error_catalog` 的规范错误码、4 级 UI 展示元数据
//!（`severity` / `presentation` / `action` / `retryable`）及本地化中文文案，
//! 为 [`AuthClientError`]、[`rc_types::Error`]、信令/会话/被控端错误及工具权限拒绝
//! 提供零裸露占位符、平台感知的 [`UiError`] 转换能力。

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::io::ErrorKind;

use rc_session::{TOOL_CHANNEL_FILE, TOOL_CHANNEL_PORTMAP, TOOL_CHANNEL_TERMINAL};
use serde::{Deserialize, Serialize};

use crate::auth_client::AuthClientError;
pub use crate::generated::error_catalog::{
    codes, lookup_error_entry, render_copy_template, resolve_wire_alias, resolve_zh_cn_copy,
    ErrorAction, ErrorCatalogEntry, ErrorCopy, ErrorPlatform, ErrorPresentation, ErrorSeverity,
    ERROR_CATALOG, SPEC_VERSION,
};

/// 面向全端 UI 渲染的结构化错误模型（`camelCase` JSON 序列化）。
///
/// 完整超集覆盖 `{ code, message, status, detail }` 与 4 级 UI 展示规范
///（`severity` / `presentation` / `action` / `retryable`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiError {
    /// 规范点分错误码（如 `"auth.invalid_credentials"`、`"tool.forbidden"`）。
    pub code: String,
    /// 短标题（中文）。
    pub title: String,
    /// 详细错误说明（已完成模板渲染并清理未提供参数占位符）。
    pub message: String,
    /// 可执行恢复建议（已完成平台覆写与模板渲染）。
    pub suggestion: String,
    /// 严重级别（`info` / `warning` / `error` / `critical`）。
    pub severity: ErrorSeverity,
    /// 推荐展示形式（`inline` / `toast` / `banner` / `modal`）。
    pub presentation: ErrorPresentation,
    /// 推荐主恢复动作（`none` / `retry` / `relogin` / `change_password` / `open_settings` / `open_permissions` / `contact_admin`）。
    pub action: ErrorAction,
    /// 是否适合用户或上层重试。
    pub retryable: bool,
    /// 可选关联 HTTP 状态码（仅 REST API 场景填充）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// 可选原始技术诊断细节（供「查看详情」折叠面板或日志排查使用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// 返回当前编译目标对应的 [`ErrorPlatform`]。
pub const fn current_platform() -> ErrorPlatform {
    #[cfg(target_os = "macos")]
    {
        ErrorPlatform::Macos
    }
    #[cfg(target_os = "windows")]
    {
        ErrorPlatform::Windows
    }
    #[cfg(target_os = "linux")]
    {
        ErrorPlatform::Linux
    }
    #[cfg(target_os = "android")]
    {
        ErrorPlatform::Android
    }
    #[cfg(target_os = "ios")]
    {
        ErrorPlatform::Ios
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "linux",
        target_os = "android",
        target_os = "ios"
    )))]
    {
        ErrorPlatform::Generic
    }
}

/// 将工具复用子通道号映射为用户可读的中文工具名称（供 `tool.forbidden` `{tool_name}` 模板填充）。
pub const fn tool_channel_name_zh(channel: u8) -> &'static str {
    match channel {
        TOOL_CHANNEL_FILE => "文件传输",
        TOOL_CHANNEL_TERMINAL => "远程终端",
        TOOL_CHANNEL_PORTMAP => "端口映射",
        _ => "远程工具",
    }
}

/// 构造工具通道权限被拒绝的规范 [`UiError`]（错误码 `tool.forbidden`）。
pub fn tool_forbidden_ui_error(
    channel: u8,
    platform: ErrorPlatform,
    detail: Option<String>,
) -> UiError {
    resolve_ui_error(
        codes::TOOL_FORBIDDEN,
        platform,
        &[("tool_name", tool_channel_name_zh(channel))],
        None,
        detail,
    )
}

fn fallback_for_missing_param(key: &str) -> Option<&'static str> {
    match key {
        "max_count" => Some("若干"),
        _ => None,
    }
}

fn is_cjk_punctuation(ch: char) -> bool {
    matches!(
        ch,
        '。' | '，' | '、' | '：' | '；' | '！' | '？' | '）' | '」' | '】'
    )
}

/// 单遍扫描渲染文案模板，并兜底清理所有未提供参数的 `{...}` 占位符，
/// 同时确保已提供参数值直接写入输出缓冲、绝不进行二次展开。
fn render_template_no_exposed_placeholders(template: &str, params: &[(&str, &str)]) -> String {
    if !template.contains('{') {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open_idx) = rest.find('{') {
        out.push_str(&rest[..open_idx]);
        let after_open = &rest[open_idx + 1..];
        let Some(close_idx) = after_open.find('}') else {
            out.push_str(&rest[open_idx..]);
            return out;
        };
        let key = &after_open[..close_idx];
        if let Some(nested_open) = key.find('{') {
            out.push('{');
            out.push_str(&key[..nested_open]);
            rest = &after_open[nested_open..];
            continue;
        }
        let mut remaining = &after_open[close_idx + 1..];
        if let Some((_, value)) = params
            .iter()
            .find(|(k, v)| *k == key && !v.trim().is_empty())
        {
            out.push_str(value);
        } else if let Some(fallback) = fallback_for_missing_param(key) {
            out.push_str(fallback);
        } else if out.ends_with('「') && remaining.starts_with('」') {
            out.pop();
            remaining = &remaining['」'.len_utf8()..];
        } else {
            if out.ends_with(' ') {
                let prev_non_ascii = out[..out.len() - 1]
                    .chars()
                    .next_back()
                    .is_some_and(|c| !c.is_ascii());
                let next_char = remaining.chars().next();
                if next_char == Some(' ') {
                    remaining = &remaining[1..];
                    if prev_non_ascii {
                        out.pop();
                    }
                } else if next_char.is_none()
                    || next_char.is_some_and(is_cjk_punctuation)
                    || (prev_non_ascii && next_char.is_some_and(|c| !c.is_ascii()))
                {
                    out.pop();
                }
            } else if remaining.starts_with(' ') {
                let prev_non_ascii = out.chars().next_back().is_some_and(|c| !c.is_ascii());
                if prev_non_ascii {
                    remaining = &remaining[1..];
                }
            }
        }
        rest = remaining;
    }
    out.push_str(rest);
    out
}

fn normalize_detail(detail: Option<String>) -> Option<String> {
    detail.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

/// 根据规范错误码或 wire alias、目标平台及模板参数解析结构化 [`UiError`]。
///
/// - 优先按 canonical code 或 ASCII 大小写不敏感 wire alias 查表；未知错误码回退至 `common.unknown`；
/// - 应用 `platform` 对应的中文文案覆写；
/// - 执行单遍模板参数替换并兜底清理所有未提供参数的 `{...}` 占位符，保证绝不裸露 `{...}`。
pub fn resolve_ui_error(
    code_or_wire: &str,
    platform: ErrorPlatform,
    params: &[(&str, &str)],
    status: Option<u16>,
    detail: Option<String>,
) -> UiError {
    let entry = lookup_error_entry(code_or_wire)
        .or_else(|| resolve_wire_alias(code_or_wire).and_then(lookup_error_entry))
        .or_else(|| lookup_error_entry(codes::COMMON_UNKNOWN))
        .expect("common.unknown must exist in generated ERROR_CATALOG");
    let copy = resolve_zh_cn_copy(entry.code, platform).unwrap_or(entry.default_zh_cn);

    UiError {
        code: entry.code.to_string(),
        title: render_template_no_exposed_placeholders(copy.title, params),
        message: render_template_no_exposed_placeholders(copy.message, params),
        suggestion: render_template_no_exposed_placeholders(copy.suggestion, params),
        severity: entry.severity,
        presentation: entry.presentation,
        action: entry.action,
        retryable: entry.retryable,
        status,
        detail: normalize_detail(detail),
    }
}

/// 将领域错误转换为结构化 [`UiError`] 的统一 Trait。
pub trait IntoUiError {
    /// 按目标运行平台生成带对应本地化文案的 [`UiError`]。
    fn to_ui_error(&self, platform: ErrorPlatform) -> UiError;

    /// 使用平台无关（[`ErrorPlatform::Generic`]）文案生成 [`UiError`]。
    fn to_ui_error_generic(&self) -> UiError {
        self.to_ui_error(ErrorPlatform::Generic)
    }
}

fn classify_http_status_code(status: u16) -> &'static str {
    match status {
        400 | 422 => codes::VALIDATION_INVALID_INPUT,
        401 => codes::AUTH_UNAUTHORIZED,
        403 => codes::AUTH_FORBIDDEN,
        404 => codes::SERVER_NOT_FOUND,
        409 => codes::SERVER_CONFLICT,
        413 => codes::VALIDATION_PAYLOAD_TOO_LARGE,
        429 => codes::NETWORK_RATE_LIMITED,
        503 => codes::SERVER_UNAVAILABLE,
        500..=599 => codes::SERVER_INTERNAL_ERROR,
        _ => codes::COMMON_UNKNOWN,
    }
}

fn classify_tls_message(msg: &str) -> &'static str {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("fingerprint")
        || lower.contains("ca_fingerprint_mismatch")
        || lower.contains("pin mismatch")
        || lower.contains("pinned")
        || msg.contains("指纹")
    {
        codes::PKI_CA_FINGERPRINT_MISMATCH
    } else if lower.contains("revoked") || msg.contains("吊销") {
        codes::PKI_CERT_REVOKED
    } else if lower.contains("expired") || msg.contains("过期") {
        codes::PKI_CERT_EXPIRED
    } else if lower.contains("missing")
        || lower.contains("not anchored")
        || msg.contains("尚未锚定")
        || msg.contains("缺少")
        || msg.contains("不包含任何证书")
        || msg.contains("ca pem 为空")
        || msg.contains("CA PEM 为空")
        || msg.contains("未提供对端证书")
    {
        codes::PKI_CERT_MISSING
    } else if lower.contains("mtls")
        || lower.contains("verify")
        || lower.contains("certificate")
        || lower.contains("unknownissuer")
        || lower.contains("badcertificate")
        || lower.contains("untrusted")
        || lower.contains("san")
        || lower.contains("webpki")
        || lower.contains("cert")
        || msg.contains("证书")
        || msg.contains("校验")
    {
        codes::PKI_MTLS_VERIFY_FAILED
    } else {
        codes::PKI_TLS_HANDSHAKE_FAILED
    }
}

fn classify_network_message(msg: &str) -> &'static str {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("proxy_config_conflict")
        || lower.contains("proxy config conflict")
        || msg.contains("代理配置冲突")
        || (msg.contains("代理") && msg.contains("冲突"))
    {
        codes::PROXY_CONFIG_CONFLICT
    } else if lower.contains("407")
        || lower.contains("proxy_auth_failed")
        || lower.contains("proxy auth")
        || lower.contains("proxy authentication")
        || msg.contains("代理认证")
    {
        codes::PROXY_AUTH_FAILED
    } else if lower.contains("proxy") || lower.contains("socks") || msg.contains("代理") {
        codes::PROXY_CONNECT_FAILED
    } else if lower.contains("timed out") || lower.contains("timeout") || msg.contains("超时") {
        codes::NETWORK_TIMEOUT
    } else if lower.contains("dns")
        || lower.contains("lookup")
        || lower.contains("resolve")
        || lower.contains("nodename")
        || lower.contains("name or service not known")
        || lower.contains("no such host")
        || msg.contains("域名")
        || msg.contains("解析")
    {
        codes::NETWORK_DNS_FAILED
    } else if lower.contains("connection refused")
        || lower.contains("refused")
        || msg.contains("拒绝连接")
        || msg.contains("连接被拒绝")
    {
        codes::NETWORK_CONNECTION_REFUSED
    } else if lower.contains("rate limit")
        || lower.contains("too many requests")
        || msg.contains("限流")
    {
        codes::NETWORK_RATE_LIMITED
    } else {
        codes::NETWORK_UNREACHABLE
    }
}

fn classify_relogin_message(msg: &str) -> &'static str {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("token_reuse") || lower.contains("reuse") || msg.contains("重放") {
        codes::AUTH_TOKEN_REUSE_DETECTED
    } else if lower.contains("password_change_required")
        || msg.contains("修改初始密码")
        || msg.contains("必须先修改")
    {
        codes::AUTH_PASSWORD_CHANGE_REQUIRED
    } else if lower.contains("account_locked") || msg.contains("账号已被锁定") {
        codes::ACCOUNT_LOCKED
    } else if lower.contains("token_revoked") || lower.contains("revoked") || msg.contains("吊销")
    {
        codes::AUTH_TOKEN_REVOKED
    } else if lower.contains("password_changed") || msg.contains("密码已修改") {
        codes::AUTH_PASSWORD_CHANGED
    } else if lower.contains("account_disabled") || msg.contains("账号已被禁用") {
        codes::ACCOUNT_DISABLED
    } else if lower.contains("account_deleted")
        || lower.contains("user_deleted")
        || msg.contains("账号已被删除")
    {
        codes::ACCOUNT_DELETED
    } else if lower.contains("invalid_refresh_token") || msg.contains("刷新令牌") {
        codes::AUTH_INVALID_REFRESH_TOKEN
    } else {
        codes::AUTH_RELOGIN_REQUIRED
    }
}

impl IntoUiError for AuthClientError {
    fn to_ui_error(&self, platform: ErrorPlatform) -> UiError {
        match self {
            Self::Api {
                status,
                code,
                message,
            } => {
                let canonical =
                    resolve_wire_alias(code).unwrap_or_else(|| classify_http_status_code(*status));
                let detail = if !message.trim().is_empty() {
                    Some(message.clone())
                } else if !code.trim().is_empty() {
                    Some(code.clone())
                } else {
                    None
                };
                resolve_ui_error(canonical, platform, &[], Some(*status), detail)
            }
            Self::Config(msg) => {
                let lower = msg.to_ascii_lowercase();
                let code = if lower.contains("proxy") || msg.contains("代理") {
                    codes::PROXY_CONFIG_CONFLICT
                } else if lower.contains("cert") || lower.contains("mtls") || msg.contains("证书")
                {
                    codes::PKI_CERT_MISSING
                } else {
                    codes::VALIDATION_INVALID_CONFIG
                };
                resolve_ui_error(code, platform, &[], None, Some(msg.clone()))
            }
            Self::Network(msg) => {
                let code = classify_network_message(msg);
                resolve_ui_error(code, platform, &[], None, Some(msg.clone()))
            }
            Self::Tls(msg) => {
                let code = classify_tls_message(msg);
                resolve_ui_error(code, platform, &[], None, Some(msg.clone()))
            }
            Self::Protocol(msg) => {
                let lower = msg.to_ascii_lowercase();
                let code = if lower.contains("too large")
                    || msg.contains("过大")
                    || msg.contains("过长")
                    || msg.contains("上限")
                {
                    codes::VALIDATION_PAYLOAD_TOO_LARGE
                } else if lower.contains("json") || lower.contains("serde") {
                    codes::VALIDATION_INVALID_JSON
                } else {
                    codes::SIGNAL_INVALID_FRAME
                };
                resolve_ui_error(code, platform, &[], None, Some(msg.clone()))
            }
            Self::ReloginRequired(msg) => {
                let code = classify_relogin_message(msg);
                resolve_ui_error(code, platform, &[], None, Some(msg.clone()))
            }
        }
    }
}

impl IntoUiError for rc_types::Error {
    fn to_ui_error(&self, platform: ErrorPlatform) -> UiError {
        let detail = Some(self.to_string());
        match self {
            rc_types::Error::InvalidFrame(_) | rc_types::Error::Decoder(_) => {
                resolve_ui_error(codes::CODEC_DECODE_FAILED, platform, &[], None, detail)
            }
            rc_types::Error::InvalidConfig(_) => resolve_ui_error(
                codes::VALIDATION_INVALID_CONFIG,
                platform,
                &[],
                None,
                detail,
            ),
            rc_types::Error::Protocol { msg, .. } => {
                let lower = msg.to_ascii_lowercase();
                let code = if lower.contains("approval") || msg.contains("审批") {
                    codes::SESSION_APPROVAL_REJECTED
                } else if lower.contains("auth")
                    || lower.contains("password")
                    || lower.contains("rejected")
                    || msg.contains("密码")
                    || msg.contains("鉴权")
                {
                    codes::SESSION_AUTH_REJECTED
                } else {
                    codes::SESSION_PROTOCOL_MISMATCH
                };
                resolve_ui_error(code, platform, &[], None, detail)
            }
            rc_types::Error::Encoder(_) | rc_types::Error::EncoderDroppedFrame { .. } => {
                resolve_ui_error(codes::CODEC_ENCODE_FAILED, platform, &[], None, detail)
            }
            rc_types::Error::Capture { msg, .. } => {
                let lower = msg.to_ascii_lowercase();
                let code = if lower.contains("dxgi") {
                    codes::PLATFORM_WINDOWS_DXGI_LOST
                } else if lower.contains("screen recording")
                    || lower.contains("tcc")
                    || lower.contains("permission")
                    || msg.contains("屏幕录制")
                    || msg.contains("权限")
                {
                    codes::PLATFORM_MACOS_SCREEN_RECORDING_DENIED
                } else {
                    codes::CODEC_CAPTURE_FAILED
                };
                resolve_ui_error(code, platform, &[], None, detail)
            }
            rc_types::Error::Network(msg) => {
                let lower = msg.to_ascii_lowercase();
                let code = if lower.contains("cancelled") || msg.contains("取消") {
                    codes::SESSION_CANCELLED
                } else if lower.contains("tls")
                    || lower.contains("mtls")
                    || lower.contains("cert")
                    || lower.contains("crypto")
                    || lower.contains("fingerprint")
                    || msg.contains("证书")
                    || msg.contains("指纹")
                {
                    classify_tls_message(msg)
                } else if lower.contains("disconnect")
                    || lower.contains("closed")
                    || msg.contains("断开")
                {
                    codes::SESSION_DISCONNECTED
                } else {
                    classify_network_message(msg)
                };
                resolve_ui_error(code, platform, &[], None, detail)
            }
            rc_types::Error::Timeout(_) => {
                resolve_ui_error(codes::NETWORK_TIMEOUT, platform, &[], None, detail)
            }
            rc_types::Error::Io(io_err) => {
                let code = match io_err.kind() {
                    ErrorKind::TimedOut => codes::NETWORK_TIMEOUT,
                    ErrorKind::ConnectionRefused => codes::NETWORK_CONNECTION_REFUSED,
                    ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::UnexpectedEof => codes::SESSION_DISCONNECTED,
                    ErrorKind::PermissionDenied => codes::AUTH_FORBIDDEN,
                    ErrorKind::NotFound => codes::SERVER_NOT_FOUND,
                    _ => codes::NETWORK_UNREACHABLE,
                };
                resolve_ui_error(code, platform, &[], None, detail)
            }
        }
    }
}

/// 构造「目标设备正在被控中，需要确认接管」的结构化 [`UiError`]（对齐 `signal.target_in_session`）。
pub fn target_in_session_ui_error(detail: Option<String>) -> UiError {
    resolve_ui_error(
        codes::SIGNAL_TARGET_IN_SESSION,
        current_platform(),
        &[],
        None,
        detail,
    )
}

/// 构造「当前连接已被其他设备接管」的结构化 [`UiError`]（`session.preempted`，严禁自动重连）。
pub fn preempted_ui_error(detail: Option<String>) -> UiError {
    resolve_ui_error(
        codes::SESSION_PREEMPTED,
        current_platform(),
        &[],
        None,
        detail,
    )
}

/// 将信令通道错误字符串或 wire error code 归因为结构化 [`UiError`]。
pub fn classify_signal_error(raw: &str, platform: ErrorPlatform) -> UiError {
    let trimmed = raw.trim();
    if let Some(canonical) = resolve_wire_alias(trimmed) {
        return resolve_ui_error(canonical, platform, &[], None, Some(trimmed.to_string()));
    }

    let lower = trimmed.to_ascii_lowercase();
    let code = if lower.contains("target_in_session")
        || lower.contains("hostbusycontrolled")
        || lower.contains("host_busy_controlled")
        || trimmed.contains("正在被控制")
        || trimmed.contains("正在被控中")
        || trimmed.contains("需要确认接管")
    {
        codes::SIGNAL_TARGET_IN_SESSION
    } else if lower.contains("token_reuse") || trimmed.contains("重放") {
        codes::AUTH_TOKEN_REUSE_DETECTED
    } else if lower.contains("token_revoked") || trimmed.contains("令牌已吊销") {
        codes::AUTH_TOKEN_REVOKED
    } else if lower.contains("token_expired") || trimmed.contains("令牌已过期") {
        codes::AUTH_TOKEN_EXPIRED
    } else if lower.contains("user_logout") || trimmed.contains("已退出登录") {
        codes::AUTH_USER_LOGOUT
    } else if lower.contains("account_disabled") || trimmed.contains("账号已被禁用") {
        codes::ACCOUNT_DISABLED
    } else if lower.contains("account_locked") || trimmed.contains("账号已被锁定") {
        codes::ACCOUNT_LOCKED
    } else if lower.contains("account_deleted")
        || lower.contains("user_deleted")
        || trimmed.contains("账号已被删除")
    {
        codes::ACCOUNT_DELETED
    } else if lower.contains("account_updated") || trimmed.contains("安全状态已变更") {
        codes::ACCOUNT_UPDATED
    } else if lower.contains("device_disabled")
        || lower.contains("disabled_by_admin")
        || trimmed.contains("设备已被管理员禁用")
        || trimmed.contains("设备已被禁用")
    {
        codes::DEVICE_DISABLED
    } else if lower.contains("device_unbound")
        || trimmed.contains("设备已被解绑")
        || trimmed.contains("已被解绑")
    {
        codes::DEVICE_UNBOUND
    } else if lower.contains("peer_offline") || trimmed.contains("离线") {
        codes::SIGNAL_PEER_OFFLINE
    } else if lower.contains("peer_busy") || trimmed.contains("忙碌") {
        codes::SIGNAL_PEER_BUSY
    } else if lower.contains("peer_disabled") {
        codes::SIGNAL_PEER_DISABLED
    } else if lower.contains("peer_not_found") || trimmed.contains("未找到目标设备") {
        codes::SIGNAL_PEER_NOT_FOUND
    } else if lower.contains("assist_disabled") || trimmed.contains("远程协助") {
        codes::SIGNAL_ASSIST_DISABLED
    } else if lower.contains("remote_control_disabled") || trimmed.contains("禁止远程控制") {
        codes::SIGNAL_REMOTE_CONTROL_DISABLED
    } else if lower.contains("self_connect") || trimmed.contains("不能连接自己") {
        codes::SIGNAL_SELF_CONNECT
    } else if lower.contains("replaced_by_new_connection")
        || trimmed.contains("信令连接已被替换")
        || trimmed.contains("被新连接顶替")
        || trimmed.contains("已被替换")
    {
        codes::SIGNAL_REPLACED_BY_NEW_CONNECTION
    } else if lower.contains("server_shutdown") || trimmed.contains("服务端正在关闭") {
        codes::SIGNAL_SERVER_SHUTDOWN
    } else if lower.contains("handshake_timeout") || trimmed.contains("握手超时") {
        codes::SIGNAL_HANDSHAKE_TIMEOUT
    } else if lower.contains("capacity_exceeded") || trimmed.contains("中继容量") {
        codes::RELAY_CAPACITY_EXCEEDED
    } else if lower.contains("pair_timeout") || trimmed.contains("配对超时") {
        codes::RELAY_PAIR_TIMEOUT
    } else if lower.contains("pair_rejected") || trimmed.contains("配对被拒") {
        codes::RELAY_PAIR_REJECTED
    } else if lower.contains("tls")
        || lower.contains("mtls")
        || lower.contains("cert")
        || lower.contains("fingerprint")
        || trimmed.contains("证书")
        || trimmed.contains("指纹")
    {
        classify_tls_message(trimmed)
    } else if lower.contains("proxy_config_conflict")
        || lower.contains("proxy_auth_failed")
        || lower.contains("proxy")
        || lower.contains("socks")
        || lower.contains("407")
        || trimmed.contains("代理")
    {
        classify_network_message(trimmed)
    } else if lower.contains("unauthorized")
        || lower.contains("auth")
        || trimmed.contains("重新登录")
        || trimmed.contains("未登录")
    {
        codes::AUTH_UNAUTHORIZED
    } else if lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("dns")
        || lower.contains("refused")
        || trimmed.contains("超时")
        || trimmed.contains("解析")
        || trimmed.contains("拒绝连接")
        || trimmed.contains("连接失败")
    {
        classify_network_message(trimmed)
    } else if lower.contains("register") || trimmed.contains("注册失败") {
        codes::SIGNAL_REGISTER_FAILED
    } else if lower.contains("frame_too_large") || trimmed.contains("帧过大") {
        codes::SIGNAL_FRAME_TOO_LARGE
    } else if lower.contains("invalid_frame") || lower.contains("invalid_payload") {
        codes::SIGNAL_INVALID_FRAME
    } else {
        codes::NETWORK_UNREACHABLE
    };

    resolve_ui_error(code, platform, &[], None, Some(trimmed.to_string()))
}

/// 将控制端会话结束原因（`SessionUpdate::Ended.reason`）归因为结构化 [`UiError`]。
pub fn classify_session_reason(reason: &str, platform: ErrorPlatform) -> UiError {
    let trimmed = reason.trim();
    if let Some(canonical) = resolve_wire_alias(trimmed) {
        return resolve_ui_error(canonical, platform, &[], None, Some(trimmed.to_string()));
    }

    let lower = trimmed.to_ascii_lowercase();
    let code = if lower.contains("preempted") || trimmed.contains("已被其他设备接管") {
        codes::SESSION_PREEMPTED
    } else if lower.contains("target_in_session")
        || lower.contains("hostbusycontrolled")
        || lower.contains("host_busy_controlled")
        || trimmed.contains("正在被控制")
        || trimmed.contains("正在被控中")
        || trimmed.contains("需要确认接管")
    {
        codes::SIGNAL_TARGET_IN_SESSION
    } else if trimmed.contains("切换系统桌面") || lower.contains("sessionswitching") {
        codes::SESSION_SWITCHING
    } else if trimmed.contains("用户主动断开")
        || trimmed.contains("已取消")
        || lower.contains("cancelled")
    {
        codes::SESSION_CANCELLED
    } else if lower.contains("proxy_config_conflict")
        || lower.contains("proxy config conflict")
        || trimmed.contains("代理配置冲突")
        || (trimmed.contains("代理") && trimmed.contains("冲突"))
    {
        codes::PROXY_CONFIG_CONFLICT
    } else if lower.contains("proxy_auth_failed")
        || lower.contains("proxy auth")
        || lower.contains("proxy authentication")
        || lower.contains("407")
        || trimmed.contains("代理认证")
    {
        codes::PROXY_AUTH_FAILED
    } else if lower.contains("proxy_connect_failed")
        || lower.contains("proxy connect")
        || trimmed.contains("通过代理")
        || trimmed.contains("代理服务器")
    {
        codes::PROXY_CONNECT_FAILED
    } else if trimmed.contains("审批超时") || lower.contains("approval timeout") {
        codes::SESSION_APPROVAL_TIMEOUT
    } else if trimmed.contains("机主拒绝")
        || trimmed.contains("审批拒绝")
        || lower.contains("approval rejected")
    {
        codes::SESSION_APPROVAL_REJECTED
    } else if trimmed.contains("密码")
        || trimmed.contains("鉴权")
        || trimmed.contains("认证失败")
        || lower.contains("auth rejected")
        || lower.contains("authentication rejected")
        || lower.contains("unauthorized")
    {
        codes::SESSION_AUTH_REJECTED
    } else if trimmed.contains("仅 P2P") || lower.contains("p2p") && trimmed.contains("失败") {
        codes::NETWORK_P2P_FAILED
    } else if trimmed.contains("端到端加密") || trimmed.contains("e2ee") || lower.contains("e2ee")
    {
        codes::RELAY_E2EE_FAILED
    } else if trimmed.contains("证书")
        || trimmed.contains("指纹")
        || lower.contains("mtls")
        || lower.contains("tls")
        || lower.contains("cert")
    {
        classify_tls_message(trimmed)
    } else if trimmed.contains("无法解析")
        || lower.contains("resolve relay addr")
        || lower.contains("dns")
    {
        codes::NETWORK_DNS_FAILED
    } else if trimmed.contains("未响应中继配对")
        || (trimmed.contains("中继") && trimmed.contains("配对超时"))
    {
        codes::RELAY_PAIR_TIMEOUT
    } else if trimmed.contains("中继") && (trimmed.contains("拒绝") || trimmed.contains("令牌"))
    {
        codes::RELAY_PAIR_REJECTED
    } else if trimmed.contains("无法连接中继服务器")
        || (trimmed.contains("中继") && trimmed.contains("失败"))
    {
        codes::RELAY_CONNECT_FAILED
    } else if trimmed.contains("解码失败") || lower.contains("decode") {
        codes::CODEC_DECODE_FAILED
    } else if lower.contains("protocol") || lower.contains("version") || trimmed.contains("协议")
    {
        codes::SESSION_PROTOCOL_MISMATCH
    } else if trimmed.contains("握手") || lower.contains("handshake") {
        codes::SESSION_HANDSHAKE_FAILED
    } else if trimmed.contains("超时") || lower.contains("timeout") || lower.contains("timed out")
    {
        codes::NETWORK_TIMEOUT
    } else if trimmed.contains("断开")
        || trimmed.contains("已关闭")
        || trimmed.contains("已结束")
        || trimmed.contains("重连次数已耗尽")
        || lower.contains("disconnected")
        || lower.contains("byereceived")
    {
        codes::SESSION_DISCONNECTED
    } else {
        codes::COMMON_UNKNOWN
    };

    resolve_ui_error(code, platform, &[], None, Some(trimmed.to_string()))
}

/// 将被控端运行错误（`HostUpdate::Error.message`）归因为结构化 [`UiError`]。
pub fn classify_host_error(message: &str, platform: ErrorPlatform) -> UiError {
    let trimmed = message.trim();
    if let Some(canonical) = resolve_wire_alias(trimmed) {
        return resolve_ui_error(canonical, platform, &[], None, Some(trimmed.to_string()));
    }

    let lower = trimmed.to_ascii_lowercase();
    let code = if trimmed.contains("屏幕/录制权限")
        || trimmed.contains("屏幕录制")
        || lower.contains("screen recording")
    {
        codes::PLATFORM_MACOS_SCREEN_RECORDING_DENIED
    } else if trimmed.contains("辅助功能") || lower.contains("accessibility") {
        codes::PLATFORM_MACOS_ACCESSIBILITY_DENIED
    } else if trimmed.contains("输入监控") || lower.contains("input monitoring") {
        codes::PLATFORM_MACOS_INPUT_MONITORING_DENIED
    } else if trimmed.contains("硬件屏幕采集") || trimmed.contains("热切换失败") {
        codes::CODEC_CAPTURE_FAILED
    } else if trimmed.contains("硬件视频管线") || trimmed.contains("编码") {
        codes::CODEC_ENCODE_FAILED
    } else if trimmed.contains("中继") && trimmed.contains("连接失败") {
        codes::RELAY_CONNECT_FAILED
    } else if trimmed.contains("证书")
        || trimmed.contains("指纹")
        || lower.contains("mtls")
        || lower.contains("tls")
        || lower.contains("cert")
    {
        classify_tls_message(trimmed)
    } else if trimmed.contains("超时") || lower.contains("timeout") {
        codes::NETWORK_TIMEOUT
    } else {
        codes::SESSION_HOST_NOT_READY
    };

    resolve_ui_error(code, platform, &[], None, Some(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_all_catalog_entries_never_exposes_braces_without_params() {
        let platforms = [
            ErrorPlatform::Macos,
            ErrorPlatform::Windows,
            ErrorPlatform::Linux,
            ErrorPlatform::Android,
            ErrorPlatform::Ios,
            ErrorPlatform::Web,
            ErrorPlatform::Generic,
        ];
        for entry in ERROR_CATALOG {
            for platform in platforms {
                let ui = resolve_ui_error(entry.code, platform, &[], None, None);
                assert_eq!(ui.code, entry.code);
                assert!(
                    !ui.title.contains('{') && !ui.title.contains('}'),
                    "exposed placeholder in title for {} ({platform:?}): {}",
                    entry.code,
                    ui.title
                );
                assert!(
                    !ui.message.contains('{') && !ui.message.contains('}'),
                    "exposed placeholder in message for {} ({platform:?}): {}",
                    entry.code,
                    ui.message
                );
                assert!(
                    !ui.suggestion.contains('{') && !ui.suggestion.contains('}'),
                    "exposed placeholder in suggestion for {} ({platform:?}): {}",
                    entry.code,
                    ui.suggestion
                );
            }
        }
    }

    #[test]
    fn resolve_wire_alias_and_platform_copy_override() {
        let generic = resolve_ui_error(
            "TOKEN_REUSE_DETECTED",
            ErrorPlatform::Generic,
            &[],
            Some(401),
            Some("family revoked".to_string()),
        );
        assert_eq!(generic.code, codes::AUTH_TOKEN_REUSE_DETECTED);
        assert_eq!(generic.severity, ErrorSeverity::Critical);
        assert_eq!(generic.presentation, ErrorPresentation::Modal);
        assert_eq!(generic.action, ErrorAction::Relogin);
        assert!(!generic.retryable);
        assert_eq!(generic.status, Some(401));
        assert_eq!(generic.detail.as_deref(), Some("family revoked"));

        let macos = resolve_ui_error("token_reuse", ErrorPlatform::Macos, &[], None, None);
        assert_eq!(macos.code, codes::AUTH_TOKEN_REUSE_DETECTED);
        assert!(macos.suggestion.contains("系统级后台被控服务"));
        assert_ne!(macos.suggestion, generic.suggestion);

        let web = resolve_ui_error("unauthorized", ErrorPlatform::Web, &[], Some(401), None);
        assert_eq!(web.code, codes::AUTH_UNAUTHORIZED);
        assert!(web.suggestion.contains("管理后台"));
    }

    #[test]
    fn resolve_template_substitution_and_single_pass_safety() {
        let with_param = resolve_ui_error(
            codes::TOOL_FORBIDDEN,
            ErrorPlatform::Generic,
            &[("tool_name", "文件传输")],
            None,
            None,
        );
        assert!(with_param.message.contains("「文件传输」"));
        assert!(!with_param.message.contains("{tool_name}"));

        // Single-pass safety: param value containing `{other}` is emitted once and never re-expanded.
        let single_pass = resolve_ui_error(
            codes::DEVICE_NOT_FOUND,
            ErrorPlatform::Generic,
            &[("device_id", "{other}"), ("other", "INJECTED")],
            None,
            None,
        );
        assert!(single_pass.message.contains("{other}"));
        assert!(!single_pass.message.contains("INJECTED"));

        // Unknown code falls back to common.unknown cleanly.
        let unknown = resolve_ui_error("nonexistent.code", ErrorPlatform::Generic, &[], None, None);
        assert_eq!(unknown.code, codes::COMMON_UNKNOWN);
    }

    #[test]
    fn auth_client_error_maps_all_variants_precisely() {
        // Api (known wire alias)
        let api_creds = AuthClientError::Api {
            status: 401,
            code: "invalid_credentials".to_string(),
            message: "bad password".to_string(),
        }
        .to_ui_error_generic();
        assert_eq!(api_creds.code, codes::AUTH_INVALID_CREDENTIALS);
        assert_eq!(api_creds.status, Some(401));
        assert_eq!(api_creds.detail.as_deref(), Some("bad password"));
        assert_eq!(api_creds.presentation, ErrorPresentation::Inline);

        // Api (unknown code falls back to HTTP status)
        let api_429 = AuthClientError::Api {
            status: 429,
            code: "custom_burst".to_string(),
            message: "slow down".to_string(),
        }
        .to_ui_error_generic();
        assert_eq!(api_429.code, codes::NETWORK_RATE_LIMITED);
        assert_eq!(api_429.status, Some(429));

        // Config
        let cfg_err =
            AuthClientError::Config("服务器地址不能为空".to_string()).to_ui_error_generic();
        assert_eq!(cfg_err.code, codes::VALIDATION_INVALID_CONFIG);
        let cfg_proxy = AuthClientError::Config("代理配置冲突".to_string()).to_ui_error_generic();
        assert_eq!(cfg_proxy.code, codes::PROXY_CONFIG_CONFLICT);

        // Network (timeout / dns / refused / unreachable)
        assert_eq!(
            AuthClientError::Network("connect timed out".to_string())
                .to_ui_error_generic()
                .code,
            codes::NETWORK_TIMEOUT
        );
        assert_eq!(
            AuthClientError::Network("DNS lookup failed".to_string())
                .to_ui_error_generic()
                .code,
            codes::NETWORK_DNS_FAILED
        );
        assert_eq!(
            AuthClientError::Network("connection refused".to_string())
                .to_ui_error_generic()
                .code,
            codes::NETWORK_CONNECTION_REFUSED
        );
        assert_eq!(
            AuthClientError::Network("network down".to_string())
                .to_ui_error_generic()
                .code,
            codes::NETWORK_UNREACHABLE
        );

        // Tls: distinguish pin mismatch, cert verification, cert missing, and plain TLS handshake
        assert_eq!(
            AuthClientError::Tls("Root CA 指纹不匹配（期望 aaa，实际 bbb）".to_string())
                .to_ui_error_generic()
                .code,
            codes::PKI_CA_FINGERPRINT_MISMATCH
        );
        assert_eq!(
            AuthClientError::Tls("服务器 TLS 证书无法通过所返回的 Root CA 校验".to_string())
                .to_ui_error_generic()
                .code,
            codes::PKI_MTLS_VERIFY_FAILED
        );
        assert_eq!(
            AuthClientError::Tls("HTTPS 已开启但尚未锚定 Root CA".to_string())
                .to_ui_error_generic()
                .code,
            codes::PKI_CERT_MISSING
        );
        assert_eq!(
            AuthClientError::Tls("初始化 TLS 会话失败：unexpected EOF".to_string())
                .to_ui_error_generic()
                .code,
            codes::PKI_TLS_HANDSHAKE_FAILED
        );

        // Protocol
        assert_eq!(
            AuthClientError::Protocol("解析服务端 JSON 响应失败".to_string())
                .to_ui_error_generic()
                .code,
            codes::VALIDATION_INVALID_JSON
        );
        assert_eq!(
            AuthClientError::Protocol("响应体超过大小上限".to_string())
                .to_ui_error_generic()
                .code,
            codes::VALIDATION_PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            AuthClientError::Protocol("缺少 HTTP 状态行".to_string())
                .to_ui_error_generic()
                .code,
            codes::SIGNAL_INVALID_FRAME
        );

        // ReloginRequired
        assert_eq!(
            AuthClientError::ReloginRequired("当前未登录".to_string())
                .to_ui_error_generic()
                .code,
            codes::AUTH_RELOGIN_REQUIRED
        );
        assert_eq!(
            AuthClientError::ReloginRequired("token_reuse_detected".to_string())
                .to_ui_error(ErrorPlatform::Macos)
                .code,
            codes::AUTH_TOKEN_REUSE_DETECTED
        );
    }

    #[test]
    fn rc_types_error_maps_to_canonical_ui_errors() {
        assert_eq!(
            rc_types::Error::Timeout(std::time::Duration::from_secs(3))
                .to_ui_error_generic()
                .code,
            codes::NETWORK_TIMEOUT
        );
        assert_eq!(
            rc_types::Error::Protocol {
                offset: 0,
                msg: "authentication rejected".to_string()
            }
            .to_ui_error_generic()
            .code,
            codes::SESSION_AUTH_REJECTED
        );
        assert_eq!(
            rc_types::Error::Capture {
                recoverable: false,
                msg: "Screen Recording permission denied".to_string()
            }
            .to_ui_error(ErrorPlatform::Macos)
            .code,
            codes::PLATFORM_MACOS_SCREEN_RECORDING_DENIED
        );
        assert_eq!(
            rc_types::Error::Io(std::io::Error::new(ErrorKind::ConnectionRefused, "refused"))
                .to_ui_error_generic()
                .code,
            codes::NETWORK_CONNECTION_REFUSED
        );
    }

    #[test]
    fn ui_error_serde_json_roundtrip_camel_case() {
        let err = tool_forbidden_ui_error(
            TOOL_CHANNEL_FILE,
            ErrorPlatform::Macos,
            Some("host disabled assist file transfer".to_string()),
        );
        let json = serde_json::to_value(&err).expect("serialize UiError");
        assert_eq!(json["code"], "tool.forbidden");
        assert_eq!(json["severity"], "warning");
        assert_eq!(json["presentation"], "modal");
        assert_eq!(json["action"], "none");
        assert_eq!(json["retryable"], false);
        assert!(json.get("status").is_none());
        assert_eq!(json["detail"], "host disabled assist file transfer");

        let parsed: UiError = serde_json::from_value(json).expect("deserialize UiError");
        assert_eq!(parsed, err);
    }

    #[test]
    fn real_signal_session_and_relogin_messages_classify_accurately_and_blank_params_cleanly() {
        // 1) signal_client::classify_kicked_reason 全部真实中文文案精准归因
        assert_eq!(
            classify_signal_error(
                "当前设备已在其他位置登录，信令连接已被替换，已停止自动重连",
                ErrorPlatform::Generic
            )
            .code,
            codes::SIGNAL_REPLACED_BY_NEW_CONNECTION
        );
        assert_eq!(
            classify_signal_error(
                "当前设备已被管理员禁用，已停止自动重连",
                ErrorPlatform::Generic
            )
            .code,
            codes::DEVICE_DISABLED
        );
        assert_eq!(
            classify_signal_error("当前设备已被解绑，请重新登录绑定", ErrorPlatform::Generic).code,
            codes::DEVICE_UNBOUND
        );
        assert_eq!(
            classify_signal_error("当前会话已退出登录，已停止自动重连", ErrorPlatform::Generic)
                .code,
            codes::AUTH_USER_LOGOUT
        );
        assert_eq!(
            classify_signal_error(
                "账号凭证或安全状态已变更，请重新登录",
                ErrorPlatform::Generic
            )
            .code,
            codes::ACCOUNT_UPDATED
        );
        assert_eq!(
            classify_signal_error("当前设备证书已被吊销，请重新登录", ErrorPlatform::Generic).code,
            codes::PKI_CERT_REVOKED
        );

        // 2) session_bridge::classify_relay_connect_error 全部真实中文文案精准归因
        assert_eq!(
            classify_session_reason(
                "对端未响应中继配对（对方可能离线、被控服务未就绪或网络受限）",
                ErrorPlatform::Generic
            )
            .code,
            codes::RELAY_PAIR_TIMEOUT
        );
        assert_eq!(
            classify_session_reason(
                "无法连接中继服务器（端口不可达或连接中断）：connection refused",
                ErrorPlatform::Generic
            )
            .code,
            codes::RELAY_CONNECT_FAILED
        );
        assert_eq!(
            classify_session_reason(
                "无法解析中继服务器地址，请检查网络或服务器配置：failed to lookup",
                ErrorPlatform::Generic
            )
            .code,
            codes::NETWORK_DNS_FAILED
        );

        // 3) AuthClientError::ReloginRequired 携带 403 password_change_required / account_locked
        assert_eq!(
            AuthClientError::ReloginRequired(
                "服务端返回 403 (password_change_required)：请先修改初始密码".to_string()
            )
            .to_ui_error_generic()
            .code,
            codes::AUTH_PASSWORD_CHANGE_REQUIRED
        );
        assert_eq!(
            AuthClientError::ReloginRequired(
                "服务端返回 403 (account_locked)：账号已被锁定".to_string()
            )
            .to_ui_error_generic()
            .code,
            codes::ACCOUNT_LOCKED
        );

        // 4) 纯空白模板参数不得产生双空格或裸露 `{...}`
        let blank_device = resolve_ui_error(
            codes::DEVICE_NOT_FOUND,
            ErrorPlatform::Generic,
            &[("device_id", "   ")],
            None,
            None,
        );
        assert!(!blank_device.message.contains('{'));
        assert!(!blank_device.message.contains("  "));
        assert_eq!(blank_device.message, "未找到设备的注册记录。");

        let blank_tool = resolve_ui_error(
            codes::TOOL_FORBIDDEN,
            ErrorPlatform::Generic,
            &[("tool_name", "  \t ")],
            None,
            None,
        );
        assert!(!blank_tool.message.contains('{'));
        assert!(!blank_tool.message.contains("「」"));
        assert!(!blank_tool.message.contains("  "));
    }

    #[test]
    fn classify_signal_error_maps_proxy_407_and_conflict_before_auth_unauthorized() {
        let auth_407 = classify_signal_error(
            "代理认证失败 (407)：HTTP 代理认证失败 (407 Proxy Authentication Required)",
            ErrorPlatform::Macos,
        );
        assert_eq!(auth_407.code, codes::PROXY_AUTH_FAILED);

        let socks_auth = classify_signal_error(
            "代理认证失败 (407)：SOCKS5 代理用户名或密码认证失败",
            ErrorPlatform::Generic,
        );
        assert_eq!(socks_auth.code, codes::PROXY_AUTH_FAILED);

        let conflict = classify_signal_error(
            "proxy_config_conflict: 代理配置无效：暂不支持 https:// 加密代理",
            ErrorPlatform::Macos,
        );
        assert_eq!(conflict.code, codes::PROXY_CONFIG_CONFLICT);

        let connect_err = classify_signal_error(
            "通过代理连接信令服务器 signal.corp.internal:21116 失败：connection refused",
            ErrorPlatform::Macos,
        );
        assert_eq!(connect_err.code, codes::PROXY_CONNECT_FAILED);
    }

    #[test]
    fn classify_target_in_session_and_preempted_errors() {
        assert_eq!(
            resolve_wire_alias("target_in_session"),
            Some(codes::SIGNAL_TARGET_IN_SESSION)
        );
        assert_eq!(
            resolve_wire_alias("session_preempted"),
            Some(codes::SESSION_PREEMPTED)
        );
        assert_eq!(
            resolve_wire_alias("preempted"),
            Some(codes::SESSION_PREEMPTED)
        );

        let direct_busy = target_in_session_ui_error(Some("target_in_session".to_string()));
        assert_eq!(direct_busy.code, codes::SIGNAL_TARGET_IN_SESSION);
        assert_eq!(direct_busy.severity, ErrorSeverity::Warning);
        assert_eq!(direct_busy.presentation, ErrorPresentation::Modal);
        assert_eq!(direct_busy.action, ErrorAction::Retry);
        assert!(direct_busy.retryable);

        let direct_preempted = preempted_ui_error(Some("ByeReceived(Preempted)".to_string()));
        assert_eq!(direct_preempted.code, codes::SESSION_PREEMPTED);
        assert_eq!(direct_preempted.severity, ErrorSeverity::Warning);
        assert_eq!(direct_preempted.presentation, ErrorPresentation::Modal);
        assert_eq!(direct_preempted.action, ErrorAction::None);
        assert!(!direct_preempted.retryable);

        let sig_busy = classify_signal_error("target_in_session", ErrorPlatform::Macos);
        assert_eq!(sig_busy.code, codes::SIGNAL_TARGET_IN_SESSION);
        assert!(sig_busy.retryable);

        let lan_busy = classify_signal_error(
            "HostBusyControlled: host already has an active controller",
            ErrorPlatform::Macos,
        );
        assert_eq!(lan_busy.code, codes::SIGNAL_TARGET_IN_SESSION);
        assert!(lan_busy.retryable);

        let sess_busy = classify_session_reason(
            "HostBusyControlled: host already has an active controller",
            ErrorPlatform::Macos,
        );
        assert_eq!(sess_busy.code, codes::SIGNAL_TARGET_IN_SESSION);
        assert!(sess_busy.retryable);

        let preempted = classify_session_reason("ByeReceived(Preempted)", ErrorPlatform::Macos);
        assert_eq!(preempted.code, codes::SESSION_PREEMPTED);
        assert!(!preempted.retryable);

        let preempted_zh =
            classify_session_reason("当前连接已被其他设备接管", ErrorPlatform::Macos);
        assert_eq!(preempted_zh.code, codes::SESSION_PREEMPTED);
        assert!(!preempted_zh.retryable);
    }
}
