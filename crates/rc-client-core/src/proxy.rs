//! 统一纯同步出站网络代理层（`SOCKS5` RFC 1928/1929 + `HTTP CONNECT` RFC 9110）。
//!
//! 职责边界：
//! - 统一代理配置模型（[`ProxyMode`]、[`ProxyProtocol`]、[`ProxyConfig`]、[`ResolvedProxy`]），
//!   密码字段经自定义 `Debug` 脱敏为 `"<redacted>"`，绝不在任何错误字符串或 `UiError.detail` 泄露；
//! - 系统代理与环境变量回退解析（优先 [`crate::platform::resolve_system_proxy`]，
//!   未注册时依次读取 `ALL_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY`）；
//! - 强制回环 Bypass（`127.0.0.1` / `::1` / `localhost`）与 `NO_PROXY` / `no_proxy` 规则匹配；
//! - 纯同步可中断拨号器 [`dial_tcp_with_proxy`]：透传原始 `target_host`（SOCKS5 `ATYP=0x03` /
//!   HTTP `CONNECT host:port HTTP/1.1`），支持企业无公网 DNS 环境，整段建连 + 代理握手受单一
//!   `deadline` 约束并按 50ms 切片轮询 `cancel`；
//! - 全模块 `#![deny(unsafe_code)]` 与 `#![deny(missing_docs)]`，零外部/C 依赖。

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::ui_error::{codes, resolve_ui_error, ErrorPlatform, IntoUiError, UiError};

/// 代理握手读写轮询取消标志的切片上限（50ms）。
const DIAL_POLL_SLICE: Duration = Duration::from_millis(50);

/// 多候选地址拨号时的单地址最小超时预算。
const MIN_ADDR_TIMEOUT: Duration = Duration::from_millis(250);

/// HTTP `CONNECT` 响应头最大允许字节数（16 KiB，防恶意代理无限输出导致 OOM）。
pub const MAX_HTTP_CONNECT_HEADER_BYTES: usize = 16 * 1024;

/// SOCKS5 协议版本字节（RFC 1928）。
const SOCKS5_VERSION: u8 = 0x05;
/// SOCKS5 无认证方式。
const SOCKS5_AUTH_NONE: u8 = 0x00;
/// SOCKS5 用户名/密码认证方式（RFC 1929）。
const SOCKS5_AUTH_USERPASS: u8 = 0x02;
/// SOCKS5 无可接受认证方式应答。
const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;
/// RFC 1929 用户名/密码认证子协商版本。
const SOCKS5_USERPASS_VERSION: u8 = 0x01;
/// SOCKS5 `CONNECT` 命令码。
const SOCKS5_CMD_CONNECT: u8 = 0x01;
/// SOCKS5 IPv4 地址类型。
const SOCKS5_ATYP_IPV4: u8 = 0x01;
/// SOCKS5 域名地址类型（由代理端解析，支持企业无公网 DNS 环境）。
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
/// SOCKS5 IPv6 地址类型。
const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// 出站代理模式。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// 不使用代理（默认直连）。
    #[default]
    None,
    /// 跟随系统代理（优先平台钩子，未注册时回退环境变量）。
    System,
    /// 手动指定代理协议、主机、端口与可选认证凭据。
    Manual,
}

/// 出站代理协议类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    /// HTTP `CONNECT` 隧道代理。
    Http,
    /// SOCKS5（RFC 1928 / RFC 1929）代理。
    Socks5,
}

impl ProxyProtocol {
    /// 返回协议的小写 URL Scheme 字符串（`"http"` 或 `"socks5"`）。
    pub const fn as_scheme(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
        }
    }
}

/// 持久化与运行期共享的出站代理配置。
///
/// 手动实现 [`fmt::Debug`] 对 `password` 字段脱敏为 `"<redacted>"`，防止凭据进入日志或错误详情。
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyConfig {
    /// 代理模式（默认 [`ProxyMode::None`]）。
    #[serde(default)]
    pub mode: ProxyMode,
    /// 手动模式下的代理协议（`Http` 或 `Socks5`）。
    #[serde(default)]
    pub protocol: Option<ProxyProtocol>,
    /// 代理服务器主机名或 IP 地址。
    #[serde(default)]
    pub host: String,
    /// 代理服务器 TCP 端口（`1..=65535`）。
    #[serde(default)]
    pub port: u16,
    /// 可选代理认证用户名。
    #[serde(default)]
    pub username: Option<String>,
    /// 可选代理认证密码（`Debug` 脱敏，严禁写入错误消息）。
    #[serde(default)]
    pub password: Option<String>,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_password = self.password.as_ref().map(|_| "<redacted>");
        f.debug_struct("ProxyConfig")
            .field("mode", &self.mode)
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redacted_password)
            .finish()
    }
}

impl ProxyConfig {
    /// 校验当前代理配置是否合法（仅在 `Manual` 模式下严格校验协议、主机、端口与凭据）。
    pub fn validate(&self) -> Result<(), ProxyError> {
        let _ = resolve_effective_proxy(self)?;
        Ok(())
    }
}

/// 解析并校验后可直接用于建连的有效代理端点。
///
/// 手动实现 [`fmt::Debug`] 对 `password` 字段脱敏为 `"<redacted>"`。
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedProxy {
    /// 代理协议。
    pub protocol: ProxyProtocol,
    /// 已剥离方括号与首尾空白的代理主机名或 IP。
    pub host: String,
    /// 代理端口（`1..=65535`）。
    pub port: u16,
    /// 可选代理认证用户名。
    pub username: Option<String>,
    /// 可选代理认证密码（`Debug` 脱敏）。
    pub password: Option<String>,
}

impl fmt::Debug for ResolvedProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_password = self.password.as_ref().map(|_| "<redacted>");
        f.debug_struct("ResolvedProxy")
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redacted_password)
            .finish()
    }
}

impl ResolvedProxy {
    /// 返回不含任何凭据的脱敏代理地址标签（例如 `"socks5://proxy.corp:1080"`）。
    pub fn endpoint_label(&self) -> String {
        let authority = format_authority(&self.host, self.port);
        format!("{}://{authority}", self.protocol.as_scheme())
    }
}

/// 代理配置解析与校验错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// 代理配置不完整或包含非法字符/越界长度。
    InvalidConfig(String),
    /// 代理配置存在策略或模式冲突。
    ConfigConflict(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) | Self::ConfigConflict(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ProxyError {}

impl IntoUiError for ProxyError {
    fn to_ui_error(&self, platform: ErrorPlatform) -> UiError {
        resolve_ui_error(
            codes::PROXY_CONFIG_CONFLICT,
            platform,
            &[],
            None,
            Some(self.to_string()),
        )
    }
}

/// 统一 TCP/代理拨号错误类型（严禁包含代理密码明文）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyDialError {
    /// 代理配置无效或参数非法。
    Config(String),
    /// 代理策略与连接模式存在冲突。
    ConfigConflict(String),
    /// 代理认证失败（HTTP `407` 或 SOCKS5 用户名/密码/方法协商拒绝）。
    AuthFailed(String),
    /// 连接代理服务器失败或代理拒绝转发目标连接。
    ConnectFailed(String),
    /// 建连或代理握手整体超时。
    Timeout(String),
    /// 调用方主动取消拨号。
    Cancelled,
    /// 直连场景下目标主机 DNS 解析失败。
    DnsFailed(String),
    /// 直连场景下目标 TCP 建连失败。
    TargetConnectFailed(String),
}

impl fmt::Display for ProxyDialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg)
            | Self::ConfigConflict(msg)
            | Self::AuthFailed(msg)
            | Self::ConnectFailed(msg)
            | Self::Timeout(msg)
            | Self::DnsFailed(msg)
            | Self::TargetConnectFailed(msg) => f.write_str(msg),
            Self::Cancelled => f.write_str("连接已取消"),
        }
    }
}

impl std::error::Error for ProxyDialError {}

impl IntoUiError for ProxyDialError {
    fn to_ui_error(&self, platform: ErrorPlatform) -> UiError {
        let code = match self {
            Self::Config(_) | Self::ConfigConflict(_) => codes::PROXY_CONFIG_CONFLICT,
            Self::AuthFailed(_) => codes::PROXY_AUTH_FAILED,
            Self::ConnectFailed(_) => codes::PROXY_CONNECT_FAILED,
            Self::Timeout(_) => codes::NETWORK_TIMEOUT,
            Self::Cancelled => codes::SESSION_CANCELLED,
            Self::DnsFailed(_) => codes::NETWORK_DNS_FAILED,
            Self::TargetConnectFailed(msg) => {
                let lower = msg.to_ascii_lowercase();
                if lower.contains("connection refused") || msg.contains("拒绝连接") {
                    codes::NETWORK_CONNECTION_REFUSED
                } else {
                    codes::NETWORK_UNREACHABLE
                }
            }
        };
        resolve_ui_error(code, platform, &[], None, Some(self.to_string()))
    }
}

static GLOBAL_PROXY_CONFIG: OnceLock<RwLock<ProxyConfig>> = OnceLock::new();

fn global_proxy_lock() -> &'static RwLock<ProxyConfig> {
    GLOBAL_PROXY_CONFIG.get_or_init(|| RwLock::new(ProxyConfig::default()))
}

/// 更新进程级活跃出站代理配置（线程安全，立即对后续认证、信令、中继与更新器生效）。
pub fn set_global_proxy_config(cfg: ProxyConfig) {
    let mut guard = global_proxy_lock()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    *guard = cfg;
}

/// 读取当前进程级活跃出站代理配置快照。
pub fn active_proxy_config() -> ProxyConfig {
    global_proxy_lock()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// 校验并清理代理/目标主机名（拒绝空白、CRLF、控制字符及 URL 路径注入字符）。
fn sanitize_host(raw: &str, label: &str) -> Result<String, ProxyError> {
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        return Err(ProxyError::InvalidConfig(format!(
            "{label}包含非法控制字符"
        )));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidConfig(format!("{label}不能为空")));
    }
    if trimmed.chars().any(char::is_whitespace)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('@')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err(ProxyError::InvalidConfig(format!(
            "{label}包含非法字符或空白"
        )));
    }
    let unbracketed = if let Some(rest) = trimmed.strip_prefix('[') {
        let Some(inner) = rest.strip_suffix(']') else {
            return Err(ProxyError::InvalidConfig(format!(
                "{label}的 IPv6 方括号格式无效"
            )));
        };
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err(ProxyError::InvalidConfig(format!(
                "{label}包含无效 IPv6 地址"
            )));
        }
        inner
    } else {
        if trimmed.contains('[') || trimmed.contains(']') {
            return Err(ProxyError::InvalidConfig(format!("{label}包含非法方括号")));
        }
        if trimmed.contains(':') && trimmed.parse::<Ipv6Addr>().is_err() {
            return Err(ProxyError::InvalidConfig(format!(
                "{label}不应包含端口号或非法冒号"
            )));
        }
        trimmed
    };
    if unbracketed.is_empty() || unbracketed.len() > 255 {
        return Err(ProxyError::InvalidConfig(format!(
            "{label}长度无效（要求 1..=255 字节）"
        )));
    }
    Ok(unbracketed.to_string())
}

fn validate_credentials(
    protocol: ProxyProtocol,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(Option<String>, Option<String>), ProxyError> {
    let has_user = username.is_some_and(|u| !u.is_empty());
    let has_pass = password.is_some_and(|p| !p.is_empty());
    if !has_user && !has_pass {
        return Ok((None, None));
    }
    let user = username.unwrap_or("");
    let pass = password.unwrap_or("");
    if user.contains('\0')
        || user.contains('\r')
        || user.contains('\n')
        || user.chars().any(char::is_control)
    {
        return Err(ProxyError::InvalidConfig(
            "代理用户名包含非法控制字符或换行符".to_string(),
        ));
    }
    if pass.contains('\0')
        || pass.contains('\r')
        || pass.contains('\n')
        || pass.chars().any(char::is_control)
    {
        return Err(ProxyError::InvalidConfig(
            "代理密码包含非法控制字符或换行符".to_string(),
        ));
    }
    match protocol {
        ProxyProtocol::Socks5 => {
            if user.len() > 255 || pass.len() > 255 {
                return Err(ProxyError::InvalidConfig(
                    "SOCKS5 代理用户名与密码字节长度均不能超过 255 字节".to_string(),
                ));
            }
        }
        ProxyProtocol::Http => {
            if user.contains(':') {
                return Err(ProxyError::InvalidConfig(
                    "HTTP Basic 代理用户名不能包含冒号 ':'".to_string(),
                ));
            }
        }
    }
    Ok((Some(user.to_string()), Some(pass.to_string())))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn percent_decode_component(raw: &str) -> Result<String, ProxyError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(ProxyError::InvalidConfig(
                    "代理 URL 凭据包含不完整的百分号转义".to_string(),
                ));
            }
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            match (hi, lo) {
                (Some(h), Some(l)) => {
                    out.push(((h << 4) | l) as u8);
                    i += 3;
                }
                _ => {
                    return Err(ProxyError::InvalidConfig(
                        "代理 URL 凭据包含无效十六进制转义".to_string(),
                    ));
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|_| ProxyError::InvalidConfig("代理 URL 凭据不是合法 UTF-8".to_string()))
}

fn is_rfc3986_scheme(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.len() > 16 || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
}

/// 解析环境变量或系统配置中的代理 URL（仅支持 `http://`、`socks5://`、`socks5h://`；显式拒绝 `https://` 以防明文降级泄露凭据）。
pub fn parse_proxy_url(raw: &str) -> Result<ResolvedProxy, ProxyError> {
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        return Err(ProxyError::InvalidConfig(
            "代理 URL 包含非法控制字符".to_string(),
        ));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidConfig("代理 URL 不能为空".to_string()));
    }

    let (protocol, default_port, rest) = match trimmed.split_once("://") {
        Some((scheme, after)) if is_rfc3986_scheme(scheme) => {
            let lower = scheme.to_ascii_lowercase();
            match lower.as_str() {
                "socks5" | "socks5h" => (ProxyProtocol::Socks5, 1080u16, after),
                "http" => (ProxyProtocol::Http, 8080u16, after),
                "https" => {
                    return Err(ProxyError::InvalidConfig(
                        "暂不支持 https:// 加密代理（拒绝静默降级为明文 HTTP 代理），请使用 http:// 或 socks5://".to_string(),
                    ));
                }
                _ => {
                    return Err(ProxyError::InvalidConfig(
                        "不支持的代理协议（仅支持 http / socks5 / socks5h）".to_string(),
                    ));
                }
            }
        }
        _ => (ProxyProtocol::Http, 8080u16, trimmed),
    };

    // 剥离尾部路径（如 `http://127.0.0.1:7890/`）。
    let authority_and_auth = match rest.find(['/', '?', '#']) {
        Some(idx) => &rest[..idx],
        None => rest,
    };
    if authority_and_auth.is_empty() {
        return Err(ProxyError::InvalidConfig(
            "代理 URL 缺少主机地址".to_string(),
        ));
    }

    let (raw_user, raw_pass, hostport) = match authority_and_auth.rsplit_once('@') {
        Some((userinfo, hp)) => {
            let (u, p) = match userinfo.split_once(':') {
                Some((u, p)) => (
                    Some(percent_decode_component(u)?),
                    Some(percent_decode_component(p)?),
                ),
                None => (Some(percent_decode_component(userinfo)?), None),
            };
            (u, p, hp)
        }
        None => (None, None, authority_and_auth),
    };

    let (host, port) = parse_host_port_with_default(hostport, default_port)?;
    let (username, password) =
        validate_credentials(protocol, raw_user.as_deref(), raw_pass.as_deref())?;

    Ok(ResolvedProxy {
        protocol,
        host,
        port,
        username,
        password,
    })
}

fn parse_host_port_with_default(raw: &str, default_port: u16) -> Result<(String, u16), ProxyError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidConfig(
            "代理主机地址不能为空".to_string(),
        ));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err(ProxyError::InvalidConfig(
                "代理 IPv6 地址缺少闭合方括号".to_string(),
            ));
        };
        let host = sanitize_host(&trimmed[..=close + 1], "代理主机")?;
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            default_port
        } else if let Some(p_str) = after.strip_prefix(':') {
            parse_nonzero_port(p_str, "代理端口")?
        } else {
            return Err(ProxyError::InvalidConfig(
                "代理 IPv6 地址端口分隔格式无效".to_string(),
            ));
        };
        return Ok((host, port));
    }

    if let Some((h, p_str)) = trimmed.rsplit_once(':') {
        if h.contains(':') {
            // 裸 IPv6 地址无端口
            let host = sanitize_host(trimmed, "代理主机")?;
            return Ok((host, default_port));
        }
        let host = sanitize_host(h, "代理主机")?;
        let port = parse_nonzero_port(p_str, "代理端口")?;
        Ok((host, port))
    } else {
        let host = sanitize_host(trimmed, "代理主机")?;
        Ok((host, default_port))
    }
}

fn parse_nonzero_port(raw: &str, label: &str) -> Result<u16, ProxyError> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProxyError::InvalidConfig(format!("{label}格式无效")));
    }
    let port: u16 = raw
        .parse()
        .map_err(|_| ProxyError::InvalidConfig(format!("{label}超出有效范围")))?;
    if port == 0 {
        return Err(ProxyError::InvalidConfig(format!("{label}不能为 0")));
    }
    Ok(port)
}

fn resolve_manual_proxy(cfg: &ProxyConfig) -> Result<ResolvedProxy, ProxyError> {
    let protocol = cfg.protocol.ok_or_else(|| {
        ProxyError::InvalidConfig("手动代理模式必须指定代理协议（HTTP 或 SOCKS5）".to_string())
    })?;
    let host = sanitize_host(&cfg.host, "代理主机")?;
    if cfg.port == 0 {
        return Err(ProxyError::InvalidConfig(
            "代理端口必须为 1–65535".to_string(),
        ));
    }
    let (username, password) =
        validate_credentials(protocol, cfg.username.as_deref(), cfg.password.as_deref())?;
    Ok(ResolvedProxy {
        protocol,
        host,
        port: cfg.port,
        username,
        password,
    })
}

fn resolve_proxy_from_env() -> Result<Option<ResolvedProxy>, ProxyError> {
    const ENV_KEYS: [&str; 6] = [
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ];
    for key in ENV_KEYS {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return parse_proxy_url(trimmed).map(Some);
            }
        }
    }
    Ok(None)
}

/// 按代理配置解析当前生效的出站代理（不含按目标 Bypass 判定）。
///
/// - [`ProxyMode::None`]：返回 `Ok(None)`；
/// - [`ProxyMode::Manual`]：校验协议、主机、端口与凭据后返回 `Ok(Some(ResolvedProxy))`；
/// - [`ProxyMode::System`]：优先调用 [`crate::platform::resolve_system_proxy`]；
///   若返回 `Some(cfg)` 且非 `ProxyMode::None` 则校验使用，否则回退解析
///   `ALL_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` 环境变量。
pub fn resolve_effective_proxy(cfg: &ProxyConfig) -> Result<Option<ResolvedProxy>, ProxyError> {
    match cfg.mode {
        ProxyMode::None => Ok(None),
        ProxyMode::Manual => resolve_manual_proxy(cfg).map(Some),
        ProxyMode::System => {
            if let Some(sys_cfg) = crate::platform::resolve_system_proxy() {
                match sys_cfg.mode {
                    ProxyMode::None => return Ok(None),
                    ProxyMode::Manual => return resolve_manual_proxy(&sys_cfg).map(Some),
                    ProxyMode::System => {}
                }
            }
            resolve_proxy_from_env()
        }
    }
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// 判断目标主机是否属于强制直连的回环地址（`127.0.0.0/8` / `::1` / `localhost`）。
pub fn is_loopback_target(target_host: &str) -> bool {
    let clean = target_host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if clean == "localhost" || clean.ends_with(".localhost") {
        return true;
    }
    clean
        .parse::<IpAddr>()
        .map(canonicalize_ip)
        .is_ok_and(|ip| ip.is_loopback())
}

fn ip_matches_cidr(target: IpAddr, cidr_net: IpAddr, prefix_len: u8) -> bool {
    match (canonicalize_ip(target), canonicalize_ip(cidr_net)) {
        (IpAddr::V4(t), IpAddr::V4(n)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = !0u32 << (32 - prefix_len);
            (u32::from(t) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(t), IpAddr::V6(n)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = !0u128 << (128 - prefix_len);
            (u128::from(t) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

fn match_no_proxy_entry(target_host_lower: &str, target_port: u16, raw_entry: &str) -> bool {
    let entry = raw_entry.trim();
    if entry.is_empty() {
        return false;
    }
    if entry == "*" {
        return true;
    }

    // 尝试 CIDR 规则（如 `10.0.0.0/8`、`192.168.1.0/24`、`fd00::/8`）。
    if let Some((ip_part, prefix_part)) = entry.split_once('/') {
        let ip_clean = ip_part.trim().trim_start_matches('[').trim_end_matches(']');
        if let (Ok(target_ip), Ok(net_ip), Ok(prefix)) = (
            target_host_lower.parse::<IpAddr>(),
            ip_clean.parse::<IpAddr>(),
            prefix_part.trim().parse::<u8>(),
        ) {
            return ip_matches_cidr(target_ip, net_ip, prefix);
        }
        return false;
    }

    // 拆分可选 `:port` 后缀（兼容 IPv6 `[::1]:8080`）。
    let (pattern_host, pattern_port) = if let Some(rest) = entry.strip_prefix('[') {
        match rest.find(']') {
            Some(close) => {
                let h = &rest[..close];
                let after = &rest[close + 1..];
                let p = after.strip_prefix(':').and_then(|s| s.parse::<u16>().ok());
                (h, p)
            }
            None => return false,
        }
    } else if let Some((h, p_str)) = entry.rsplit_once(':') {
        if h.contains(':') {
            // 裸 IPv6 地址
            (entry, None)
        } else if let Ok(p) = p_str.parse::<u16>() {
            (h, Some(p))
        } else {
            return false;
        }
    } else {
        (entry, None)
    };

    if let Some(req_port) = pattern_port {
        if req_port != target_port {
            return false;
        }
    }

    let pat_lower = pattern_host
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if pat_lower.is_empty() {
        return false;
    }

    // 若双方都是 IP 地址，使用规范化 IP 精确比较（兼容 IPv4-mapped IPv6）。
    if let (Ok(t_ip), Ok(p_ip)) = (
        target_host_lower.parse::<IpAddr>(),
        pat_lower.parse::<IpAddr>(),
    ) {
        return canonicalize_ip(t_ip) == canonicalize_ip(p_ip);
    }

    // 域名精确或子域后缀匹配：`.example.com` 或 `example.com` 均匹配 `example.com` 及 `a.example.com`，
    // 绝不误匹配 `notexample.com`。
    let bare = pat_lower.strip_prefix('.').unwrap_or(&pat_lower);
    if bare.is_empty() {
        return false;
    }
    if target_host_lower == bare {
        return true;
    }
    target_host_lower.len() > bare.len()
        && target_host_lower.ends_with(bare)
        && target_host_lower.as_bytes()[target_host_lower.len() - bare.len() - 1] == b'.'
}

/// 判断目标 `(target_host, target_port)` 在给定 `no_proxy` 规则串下是否应 Bypass 代理直连。
///
/// 始终强制 Bypass 回环地址（`127.0.0.0/8` / `::1` / `localhost`）。
pub fn should_bypass_proxy_with_no_proxy(
    target_host: &str,
    target_port: u16,
    no_proxy: Option<&str>,
) -> bool {
    if is_loopback_target(target_host) {
        return true;
    }
    let Some(rules) = no_proxy else {
        return false;
    };
    let target_lower = target_host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if target_lower.is_empty() {
        return false;
    }
    rules
        .split(',')
        .any(|entry| match_no_proxy_entry(&target_lower, target_port, entry))
}

/// 判断目标 `(target_host, target_port)` 是否应 Bypass 代理直连（强制回环 + 环境变量 `NO_PROXY` / `no_proxy`）。
pub fn should_bypass_proxy(target_host: &str, target_port: u16) -> bool {
    if is_loopback_target(target_host) {
        return true;
    }
    let no_proxy = std::env::var("NO_PROXY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("no_proxy")
                .ok()
                .filter(|s| !s.trim().is_empty())
        });
    should_bypass_proxy_with_no_proxy(target_host, target_port, no_proxy.as_deref())
}

/// 解析目标 `(target_host, target_port)` 实际生效的代理（已综合 `ProxyMode`、回环 Bypass 与 `NO_PROXY`）。
pub fn resolve_proxy_for_target(
    cfg: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<Option<ResolvedProxy>, ProxyError> {
    let resolved = resolve_effective_proxy(cfg)?;
    if resolved.is_some() && should_bypass_proxy(target_host, target_port) {
        return Ok(None);
    }
    Ok(resolved)
}

/// 判断给定代理配置对目标 `(target_host, target_port)` 是否处于有效激活态。
pub fn is_proxy_active_for_target(cfg: &ProxyConfig, target_host: &str, target_port: u16) -> bool {
    matches!(
        resolve_proxy_for_target(cfg, target_host, target_port),
        Ok(Some(_))
    )
}

/// 将 `host:port`（含 IPv6 `[::1]:21116`）解析为 `(host, port)`，不触发任何 DNS 查询。
pub fn split_host_port(addr: &str) -> Result<(String, u16), ProxyError> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidConfig("目标地址不能为空".to_string()));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err(ProxyError::InvalidConfig(
                "IPv6 目标地址缺少闭合方括号".to_string(),
            ));
        };
        let host = sanitize_host(&trimmed[..=close + 1], "目标主机")?;
        let after = &rest[close + 1..];
        let Some(port_str) = after.strip_prefix(':') else {
            return Err(ProxyError::InvalidConfig("目标地址缺少端口号".to_string()));
        };
        let port = parse_nonzero_port(port_str, "目标端口")?;
        return Ok((host, port));
    }
    let Some((h, p_str)) = trimmed.rsplit_once(':') else {
        return Err(ProxyError::InvalidConfig("目标地址缺少端口号".to_string()));
    };
    let host = sanitize_host(h, "目标主机")?;
    let port = parse_nonzero_port(p_str, "目标端口")?;
    Ok((host, port))
}

/// 统一纯同步 TCP 拨号器（支持直连、SOCKS5 RFC 1928/1929 与 HTTP CONNECT 隧道）。
///
/// - 透传原始 `target_host`（SOCKS5 `ATYP=0x03` 域名解析 / HTTP `CONNECT host:port HTTP/1.1`），
///   在启用代理时不在本机解析目标域名，支持企业内网无公网 DNS 环境；
/// - 强制 Bypass 回环地址与 `NO_PROXY` 匹配目标；
/// - 整段 TCP 建连与代理握手共享同一个 `timeout` 截止时间，并以 `<= 50ms` 切片轮询 `cancel`。
pub fn dial_tcp_with_proxy(
    target_host: &str,
    target_port: u16,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    proxy: &ProxyConfig,
) -> Result<TcpStream, ProxyDialError> {
    let (stream, _) =
        dial_tcp_with_proxy_interruptible(target_host, target_port, timeout, proxy, || {
            cancel.is_some_and(|c| c.load(Ordering::Acquire))
        })?;
    Ok(stream)
}

/// 内部可自定义中断断言的统一代理拨号器，返回 `(TcpStream, used_proxy)`。
pub(crate) fn dial_tcp_with_proxy_interruptible<F>(
    target_host: &str,
    target_port: u16,
    timeout: Duration,
    proxy: &ProxyConfig,
    is_cancelled: F,
) -> Result<(TcpStream, bool), ProxyDialError>
where
    F: Fn() -> bool,
{
    if is_cancelled() {
        return Err(ProxyDialError::Cancelled);
    }
    if target_port == 0 {
        return Err(ProxyDialError::Config("目标端口不能为 0".to_string()));
    }
    let clean_target_host = sanitize_host(target_host, "目标主机")
        .map_err(|e| ProxyDialError::Config(e.to_string()))?;

    let effective_proxy = resolve_proxy_for_target(proxy, &clean_target_host, target_port)
        .map_err(|e| match e {
            ProxyError::ConfigConflict(m) => ProxyDialError::ConfigConflict(m),
            ProxyError::InvalidConfig(m) => ProxyDialError::Config(m),
        })?;

    let deadline = Instant::now() + timeout;

    let Some(resolved) = effective_proxy else {
        let stream = dial_direct_interruptible(
            &clean_target_host,
            target_port,
            deadline,
            &is_cancelled,
            false,
        )?;
        return Ok((stream, false));
    };

    let mut stream =
        dial_direct_interruptible(&resolved.host, resolved.port, deadline, &is_cancelled, true)?;
    let _ = stream.set_nodelay(true);

    let handshake_res = match resolved.protocol {
        ProxyProtocol::Socks5 => socks5_handshake(
            &mut stream,
            &resolved,
            &clean_target_host,
            target_port,
            deadline,
            &is_cancelled,
        ),
        ProxyProtocol::Http => http_connect_handshake(
            &mut stream,
            &resolved,
            &clean_target_host,
            target_port,
            deadline,
            &is_cancelled,
        ),
    };

    if let Err(err) = handshake_res {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(err);
    }

    // 握手完成后恢复默认阻塞超时，交由调用方按自身协议配置。
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
    Ok((stream, true))
}

fn remaining_budget(deadline: Instant) -> Result<Duration, ProxyDialError> {
    let now = Instant::now();
    if now >= deadline {
        Err(ProxyDialError::Timeout("连接或代理握手超时".to_string()))
    } else {
        Ok(deadline - now)
    }
}

fn per_addr_timeout(remaining: Duration, remaining_addrs: usize) -> Duration {
    let count = remaining_addrs.max(1) as u32;
    (remaining / count).max(MIN_ADDR_TIMEOUT).min(remaining)
}

fn dial_direct_interruptible<F>(
    host: &str,
    port: u16,
    deadline: Instant,
    is_cancelled: &F,
    is_proxy_hop: bool,
) -> Result<TcpStream, ProxyDialError>
where
    F: Fn() -> bool,
{
    if is_cancelled() {
        return Err(ProxyDialError::Cancelled);
    }
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            if is_proxy_hop {
                ProxyDialError::ConnectFailed(format!("解析代理服务器地址 {host}:{port} 失败：{e}"))
            } else {
                ProxyDialError::DnsFailed(format!("解析目标地址 {host}:{port} 失败：{e}"))
            }
        })?
        .collect();
    if addrs.is_empty() {
        return Err(if is_proxy_hop {
            ProxyDialError::ConnectFailed(format!("代理服务器地址 {host}:{port} 未解析到可用 IP"))
        } else {
            ProxyDialError::DnsFailed(format!("目标地址 {host}:{port} 未解析到可用 IP"))
        });
    }

    let mut last_err: Option<io::Error> = None;
    let mut timed_out_any = false;
    for (idx, &addr) in addrs.iter().enumerate() {
        if is_cancelled() {
            return Err(ProxyDialError::Cancelled);
        }
        let rem = remaining_budget(deadline)?;
        let budget = per_addr_timeout(rem, addrs.len() - idx);
        match connect_single_addr(addr, budget, is_cancelled) {
            Ok(stream) => return Ok(stream),
            Err(SingleDialErr::Cancelled) => return Err(ProxyDialError::Cancelled),
            Err(SingleDialErr::TimedOut) => timed_out_any = true,
            Err(SingleDialErr::Io(err)) => last_err = Some(err),
        }
    }

    if last_err.is_none() && timed_out_any {
        return Err(ProxyDialError::Timeout(if is_proxy_hop {
            format!("连接代理服务器 {host}:{port} 超时")
        } else {
            format!("连接 {host}:{port} 超时")
        }));
    }
    let detail = last_err
        .map(|e| e.to_string())
        .unwrap_or_else(|| "未知网络错误".to_string());
    if is_proxy_hop {
        Err(ProxyDialError::ConnectFailed(format!(
            "连接代理服务器 {host}:{port} 失败：{detail}"
        )))
    } else {
        Err(ProxyDialError::TargetConnectFailed(format!(
            "连接 {host}:{port} 失败：{detail}"
        )))
    }
}

enum SingleDialErr {
    Cancelled,
    TimedOut,
    Io(io::Error),
}

fn connect_single_addr<F>(
    addr: SocketAddr,
    timeout: Duration,
    is_cancelled: &F,
) -> Result<TcpStream, SingleDialErr>
where
    F: Fn() -> bool,
{
    if is_cancelled() {
        return Err(SingleDialErr::Cancelled);
    }
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
        .map_err(SingleDialErr::Io)?;
    socket.set_nonblocking(true).map_err(SingleDialErr::Io)?;

    let sock_addr = SockAddr::from(addr);
    match socket.connect(&sock_addr) {
        Ok(()) => {}
        Err(err) if crate::signal_client::is_connect_in_progress(&err) => {
            let deadline = Instant::now() + timeout;
            let mut sleep_ms = 5u64;
            loop {
                if is_cancelled() {
                    return Err(SingleDialErr::Cancelled);
                }
                if let Some(so_err) = socket.take_error().map_err(SingleDialErr::Io)? {
                    return Err(SingleDialErr::Io(so_err));
                }
                #[cfg(not(windows))]
                match socket.peer_addr() {
                    Ok(_) => {
                        if let Some(so_err) = socket.take_error().map_err(SingleDialErr::Io)? {
                            return Err(SingleDialErr::Io(so_err));
                        }
                        break;
                    }
                    Err(err) => {
                        if let Some(so_err) = socket.take_error().map_err(SingleDialErr::Io)? {
                            return Err(SingleDialErr::Io(so_err));
                        }
                        if !matches!(
                            err.kind(),
                            ErrorKind::NotConnected
                                | ErrorKind::WouldBlock
                                | ErrorKind::Interrupted
                        ) {
                            return Err(SingleDialErr::Io(err));
                        }
                    }
                }
                #[cfg(windows)]
                {
                    let mut probe = [std::mem::MaybeUninit::<u8>::uninit(); 1];
                    match socket.peek(&mut probe) {
                        Ok(_) => {
                            if let Some(so_err) = socket.take_error().map_err(SingleDialErr::Io)? {
                                return Err(SingleDialErr::Io(so_err));
                            }
                            break;
                        }
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            if let Some(so_err) = socket.take_error().map_err(SingleDialErr::Io)? {
                                return Err(SingleDialErr::Io(so_err));
                            }
                            break;
                        }
                        Err(err) => {
                            if let Some(so_err) = socket.take_error().map_err(SingleDialErr::Io)? {
                                return Err(SingleDialErr::Io(so_err));
                            }
                            if !matches!(
                                err.kind(),
                                ErrorKind::NotConnected | ErrorKind::Interrupted
                            ) {
                                return Err(SingleDialErr::Io(err));
                            }
                        }
                    }
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(SingleDialErr::TimedOut);
                }
                let step = Duration::from_millis(sleep_ms).min(deadline - now);
                thread::sleep(step);
                sleep_ms = (sleep_ms * 2).min(50);
            }
        }
        Err(err) => return Err(SingleDialErr::Io(err)),
    }

    socket.set_nonblocking(false).map_err(SingleDialErr::Io)?;
    Ok(socket.into())
}

fn write_all_deadline<F>(
    stream: &mut TcpStream,
    mut buf: &[u8],
    deadline: Instant,
    is_cancelled: &F,
) -> Result<(), ProxyDialError>
where
    F: Fn() -> bool,
{
    while !buf.is_empty() {
        if is_cancelled() {
            return Err(ProxyDialError::Cancelled);
        }
        let rem = remaining_budget(deadline)?;
        let slice = rem.min(DIAL_POLL_SLICE);
        stream
            .set_write_timeout(Some(slice))
            .map_err(|e| ProxyDialError::ConnectFailed(format!("设置代理写超时失败：{e}")))?;
        match stream.write(buf) {
            Ok(0) => {
                return Err(ProxyDialError::ConnectFailed(
                    "代理连接在握手写入阶段被关闭".to_string(),
                ));
            }
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) => {
                return Err(ProxyDialError::ConnectFailed(format!(
                    "代理握手写入失败：{e}"
                )));
            }
        }
    }
    Ok(())
}

fn read_exact_deadline<F>(
    stream: &mut TcpStream,
    mut buf: &mut [u8],
    deadline: Instant,
    is_cancelled: &F,
) -> Result<(), ProxyDialError>
where
    F: Fn() -> bool,
{
    while !buf.is_empty() {
        if is_cancelled() {
            return Err(ProxyDialError::Cancelled);
        }
        let rem = remaining_budget(deadline)?;
        let slice = rem.min(DIAL_POLL_SLICE);
        stream
            .set_read_timeout(Some(slice))
            .map_err(|e| ProxyDialError::ConnectFailed(format!("设置代理读超时失败：{e}")))?;
        match stream.read(buf) {
            Ok(0) => {
                return Err(ProxyDialError::ConnectFailed(
                    "代理服务器在握手完成前关闭了连接".to_string(),
                ));
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) => {
                return Err(ProxyDialError::ConnectFailed(format!(
                    "代理握手读取失败：{e}"
                )));
            }
        }
    }
    Ok(())
}

fn socks5_reply_description(rep: u8) -> &'static str {
    match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown SOCKS5 error",
    }
}

fn socks5_handshake<F>(
    stream: &mut TcpStream,
    proxy: &ResolvedProxy,
    target_host: &str,
    target_port: u16,
    deadline: Instant,
    is_cancelled: &F,
) -> Result<(), ProxyDialError>
where
    F: Fn() -> bool,
{
    let has_auth = proxy.username.is_some() || proxy.password.is_some();
    if has_auth {
        let ulen = proxy.username.as_deref().map_or(0, str::len);
        let plen = proxy.password.as_deref().map_or(0, str::len);
        if ulen > 255 || plen > 255 {
            return Err(ProxyDialError::Config(
                "SOCKS5 代理用户名或密码超过 255 字节上限".to_string(),
            ));
        }
    }

    // 1. 方法协商（RFC 1928 §3）
    if has_auth {
        let greeting = [SOCKS5_VERSION, 2, SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERPASS];
        write_all_deadline(stream, &greeting, deadline, is_cancelled)?;
    } else {
        let greeting = [SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE];
        write_all_deadline(stream, &greeting, deadline, is_cancelled)?;
    }

    let mut method_reply = [0u8; 2];
    read_exact_deadline(stream, &mut method_reply, deadline, is_cancelled)?;
    if method_reply[0] != SOCKS5_VERSION {
        return Err(ProxyDialError::ConnectFailed(format!(
            "SOCKS5 代理返回非预期协议版本 0x{:02x}",
            method_reply[0]
        )));
    }

    match method_reply[1] {
        SOCKS5_AUTH_NONE => {}
        SOCKS5_AUTH_USERPASS => {
            if !has_auth {
                return Err(ProxyDialError::AuthFailed(
                    "SOCKS5 代理要求用户名/密码认证，但当前未配置凭据".to_string(),
                ));
            }
            let user_bytes = proxy.username.as_deref().unwrap_or("").as_bytes();
            let pass_bytes = proxy.password.as_deref().unwrap_or("").as_bytes();
            let mut auth_req = Vec::with_capacity(3 + user_bytes.len() + pass_bytes.len());
            auth_req.push(SOCKS5_USERPASS_VERSION);
            auth_req.push(user_bytes.len() as u8);
            auth_req.extend_from_slice(user_bytes);
            auth_req.push(pass_bytes.len() as u8);
            auth_req.extend_from_slice(pass_bytes);
            write_all_deadline(stream, &auth_req, deadline, is_cancelled)?;

            let mut auth_reply = [0u8; 2];
            read_exact_deadline(stream, &mut auth_reply, deadline, is_cancelled)?;
            if auth_reply[0] != SOCKS5_USERPASS_VERSION {
                return Err(ProxyDialError::AuthFailed(format!(
                    "SOCKS5 认证子协商返回非预期版本 0x{:02x}",
                    auth_reply[0]
                )));
            }
            if auth_reply[1] != 0x00 {
                return Err(ProxyDialError::AuthFailed(
                    "SOCKS5 代理用户名或密码认证失败".to_string(),
                ));
            }
        }
        SOCKS5_AUTH_NO_ACCEPTABLE => {
            return Err(ProxyDialError::AuthFailed(
                "SOCKS5 代理拒绝当前认证方式（可能需要用户名与密码）".to_string(),
            ));
        }
        other => {
            return Err(ProxyDialError::ConnectFailed(format!(
                "SOCKS5 代理选择了不支持的认证方式 0x{other:02x}"
            )));
        }
    }

    // 2. CONNECT 请求（RFC 1928 §4），非 IP 文本一律使用 ATYP=0x03 透传原始域名
    let mut req = Vec::with_capacity(7 + target_host.len());
    req.push(SOCKS5_VERSION);
    req.push(SOCKS5_CMD_CONNECT);
    req.push(0x00); // RSV

    if let Ok(v4) = target_host.parse::<Ipv4Addr>() {
        req.push(SOCKS5_ATYP_IPV4);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = target_host.parse::<Ipv6Addr>() {
        req.push(SOCKS5_ATYP_IPV6);
        req.extend_from_slice(&v6.octets());
    } else {
        let domain_bytes = target_host.as_bytes();
        if domain_bytes.is_empty() || domain_bytes.len() > 255 {
            return Err(ProxyDialError::Config(
                "目标域名长度无效（SOCKS5 ATYP=0x03 要求 1..=255 字节）".to_string(),
            ));
        }
        req.push(SOCKS5_ATYP_DOMAIN);
        req.push(domain_bytes.len() as u8);
        req.extend_from_slice(domain_bytes);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    write_all_deadline(stream, &req, deadline, is_cancelled)?;

    // 3. 读取 CONNECT 响应头及变长 BND.ADDR + BND.PORT
    let mut hdr = [0u8; 4];
    read_exact_deadline(stream, &mut hdr, deadline, is_cancelled)?;
    if hdr[0] != SOCKS5_VERSION {
        return Err(ProxyDialError::ConnectFailed(format!(
            "SOCKS5 代理 CONNECT 响应版本异常 0x{:02x}",
            hdr[0]
        )));
    }
    if hdr[1] != 0x00 {
        return Err(ProxyDialError::ConnectFailed(format!(
            "SOCKS5 代理连接目标失败 (rep=0x{:02x}: {})",
            hdr[1],
            socks5_reply_description(hdr[1])
        )));
    }
    match hdr[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut tail = [0u8; 6];
            read_exact_deadline(stream, &mut tail, deadline, is_cancelled)?;
        }
        SOCKS5_ATYP_IPV6 => {
            let mut tail = [0u8; 18];
            read_exact_deadline(stream, &mut tail, deadline, is_cancelled)?;
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            read_exact_deadline(stream, &mut len_buf, deadline, is_cancelled)?;
            let mut tail = vec![0u8; usize::from(len_buf[0]) + 2];
            read_exact_deadline(stream, &mut tail, deadline, is_cancelled)?;
        }
        other => {
            return Err(ProxyDialError::ConnectFailed(format!(
                "SOCKS5 代理响应包含未知地址类型 0x{other:02x}"
            )));
        }
    }
    Ok(())
}

fn http_connect_handshake<F>(
    stream: &mut TcpStream,
    proxy: &ResolvedProxy,
    target_host: &str,
    target_port: u16,
    deadline: Instant,
    is_cancelled: &F,
) -> Result<(), ProxyDialError>
where
    F: Fn() -> bool,
{
    if target_host.contains('\r')
        || target_host.contains('\n')
        || target_host.contains('\0')
        || target_host.chars().any(char::is_whitespace)
    {
        return Err(ProxyDialError::Config(
            "目标主机名包含非法换行或空白字符".to_string(),
        ));
    }

    let authority = format_authority(target_host, target_port);
    let mut req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );

    if proxy.username.is_some() || proxy.password.is_some() {
        let user = proxy.username.as_deref().unwrap_or("");
        let pass = proxy.password.as_deref().unwrap_or("");
        if user.contains('\r')
            || user.contains('\n')
            || user.contains(':')
            || pass.contains('\r')
            || pass.contains('\n')
        {
            return Err(ProxyDialError::Config(
                "HTTP 代理认证凭据包含非法字符".to_string(),
            ));
        }
        let encoded = BASE64_STANDARD.encode(format!("{user}:{pass}"));
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&encoded);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    write_all_deadline(stream, req.as_bytes(), deadline, is_cancelled)?;

    // 逐字节读取至 `\r\n\r\n`（上限 16 KiB），确保绝不越界预读隧道内层协议首字节。
    let mut header_bytes = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        read_exact_deadline(stream, &mut byte, deadline, is_cancelled)?;
        header_bytes.push(byte[0]);
        if header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_bytes.len() >= MAX_HTTP_CONNECT_HEADER_BYTES {
            return Err(ProxyDialError::ConnectFailed(format!(
                "HTTP 代理响应头超过 {MAX_HTTP_CONNECT_HEADER_BYTES} 字节上限"
            )));
        }
    }

    let status_line_end = header_bytes
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| ProxyDialError::ConnectFailed("HTTP 代理响应缺少状态行".to_string()))?;
    let status_line = std::str::from_utf8(&header_bytes[..status_line_end]).map_err(|_| {
        ProxyDialError::ConnectFailed("HTTP 代理响应状态行不是合法 UTF-8".to_string())
    })?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    let status_str = parts.next().unwrap_or("");
    if !(version.eq_ignore_ascii_case("HTTP/1.1") || version.eq_ignore_ascii_case("HTTP/1.0")) {
        return Err(ProxyDialError::ConnectFailed(format!(
            "HTTP 代理返回非预期协议前缀：{version:?}"
        )));
    }
    if status_str.len() != 3 || !status_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProxyDialError::ConnectFailed(
            "HTTP 代理返回非标准 3 位状态码".to_string(),
        ));
    }
    let status_code: u16 = status_str
        .parse()
        .map_err(|_| ProxyDialError::ConnectFailed("HTTP 代理返回无效状态码".to_string()))?;

    match status_code {
        200 => Ok(()),
        407 => Err(ProxyDialError::AuthFailed(
            "HTTP 代理认证失败 (407 Proxy Authentication Required)".to_string(),
        )),
        other => Err(ProxyDialError::ConnectFailed(format!(
            "HTTP 代理拒绝 CONNECT 隧道 (HTTP {other})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn spawn_mock_socks5_server(
        require_auth: Option<(String, String)>,
        forward_to: Option<SocketAddr>,
    ) -> (SocketAddr, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock socks5");
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let cap_clone = Arc::clone(&captured);

        let handle = thread::spawn(move || {
            let Ok((mut client, _)) = listener.accept() else {
                return;
            };
            let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
            let mut hdr = [0u8; 2];
            if client.read_exact(&mut hdr).is_err() || hdr[0] != 0x05 {
                return;
            }
            let mut methods = vec![0u8; usize::from(hdr[1])];
            if client.read_exact(&mut methods).is_err() {
                return;
            }

            if let Some((exp_u, exp_p)) = require_auth {
                if !methods.contains(&0x02) {
                    let _ = client.write_all(&[0x05, 0xFF]);
                    return;
                }
                let _ = client.write_all(&[0x05, 0x02]);
                let mut v_ul = [0u8; 2];
                if client.read_exact(&mut v_ul).is_err() || v_ul[0] != 0x01 {
                    return;
                }
                let mut ubuf = vec![0u8; usize::from(v_ul[1])];
                if client.read_exact(&mut ubuf).is_err() {
                    return;
                }
                let mut pl = [0u8; 1];
                if client.read_exact(&mut pl).is_err() {
                    return;
                }
                let mut pbuf = vec![0u8; usize::from(pl[0])];
                if client.read_exact(&mut pbuf).is_err() {
                    return;
                }
                if ubuf == exp_u.as_bytes() && pbuf == exp_p.as_bytes() {
                    let _ = client.write_all(&[0x01, 0x00]);
                } else {
                    let _ = client.write_all(&[0x01, 0x01]);
                    return;
                }
            } else {
                let _ = client.write_all(&[0x05, 0x00]);
            }

            let mut req_hdr = [0u8; 4];
            if client.read_exact(&mut req_hdr).is_err() || req_hdr[0] != 0x05 || req_hdr[1] != 0x01
            {
                return;
            }
            let target_desc = match req_hdr[3] {
                0x01 => {
                    let mut ip = [0u8; 4];
                    if client.read_exact(&mut ip).is_err() {
                        return;
                    }
                    format!("ipv4:{}", Ipv4Addr::from(ip))
                }
                0x03 => {
                    let mut l = [0u8; 1];
                    if client.read_exact(&mut l).is_err() {
                        return;
                    }
                    let mut dom = vec![0u8; usize::from(l[0])];
                    if client.read_exact(&mut dom).is_err() {
                        return;
                    }
                    format!("domain:{}", String::from_utf8_lossy(&dom))
                }
                0x04 => {
                    let mut ip = [0u8; 16];
                    if client.read_exact(&mut ip).is_err() {
                        return;
                    }
                    format!("ipv6:{}", Ipv6Addr::from(ip))
                }
                _ => return,
            };
            let mut port_buf = [0u8; 2];
            if client.read_exact(&mut port_buf).is_err() {
                return;
            }
            let port = u16::from_be_bytes(port_buf);
            cap_clone
                .lock()
                .unwrap()
                .push(format!("{target_desc}:{port}"));

            let _ = client.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
            let _ = client.flush();

            if let Some(backend_addr) = forward_to {
                if let Ok(backend) = TcpStream::connect(backend_addr) {
                    bridge_streams(client, backend);
                }
            } else {
                let mut echo = [0u8; 16];
                if let Ok(n) = client.read(&mut echo) {
                    let _ = client.write_all(&echo[..n]);
                }
            }
        });

        (addr, captured, handle)
    }

    fn spawn_mock_http_connect_server(
        expected_auth_header: Option<String>,
        status_response: &'static str,
        forward_to: Option<SocketAddr>,
    ) -> (
        SocketAddr,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        thread::JoinHandle<()>,
    ) {
        use std::sync::{Arc, Mutex};
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock http proxy");
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let cap_clone = Arc::clone(&captured);

        let handle = thread::spawn(move || {
            let Ok((mut client, _)) = listener.accept() else {
                return;
            };
            let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
            let mut req_buf = Vec::new();
            let mut b = [0u8; 1];
            while !req_buf.ends_with(b"\r\n\r\n") && req_buf.len() < 8192 {
                if client.read_exact(&mut b).is_err() {
                    return;
                }
                req_buf.push(b[0]);
            }
            let req_text = String::from_utf8_lossy(&req_buf).to_string();
            cap_clone.lock().unwrap().push(req_text.clone());

            if let Some(ref expected) = expected_auth_header {
                let auth_ok = req_text.lines().any(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower.starts_with("proxy-authorization:")
                        && line.trim().ends_with(expected.as_str())
                });
                if !auth_ok {
                    let _ = client.write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"rc\"\r\n\r\n",
                    );
                    return;
                }
            }

            let _ = client.write_all(status_response.as_bytes());
            let _ = client.flush();

            if !status_response.starts_with("HTTP/1.1 200") {
                return;
            }
            if let Some(backend_addr) = forward_to {
                if let Ok(backend) = TcpStream::connect(backend_addr) {
                    bridge_streams(client, backend);
                }
            } else {
                let mut echo = [0u8; 16];
                if let Ok(n) = client.read(&mut echo) {
                    let _ = client.write_all(&echo[..n]);
                }
            }
        });

        (addr, captured, handle)
    }

    fn bridge_streams(mut a: TcpStream, mut b: TcpStream) {
        let Ok(mut a_r) = a.try_clone() else { return };
        let Ok(mut b_w) = b.try_clone() else { return };
        let t = thread::spawn(move || {
            let _ = io::copy(&mut a_r, &mut b_w);
            let _ = b_w.shutdown(Shutdown::Write);
        });
        let _ = io::copy(&mut b, &mut a);
        let _ = a.shutdown(Shutdown::Write);
        let _ = t.join();
    }

    #[test]
    fn proxy_config_debug_redacts_password() {
        let cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Socks5),
            host: "proxy.corp.local".to_string(),
            port: 1080,
            username: Some("alice".to_string()),
            password: Some("SuperSecretP@ss123".to_string()),
        };
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("SuperSecretP@ss123"));

        let resolved = resolve_effective_proxy(&cfg).unwrap().unwrap();
        let rdbg = format!("{resolved:?}");
        assert!(rdbg.contains("<redacted>"));
        assert!(!rdbg.contains("SuperSecretP@ss123"));
    }

    #[test]
    fn socks5_no_auth_and_domain_atyp_passthrough() {
        let (proxy_addr, captured, srv) = spawn_mock_socks5_server(None, None);
        let cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Socks5),
            host: "127.0.0.1".to_string(),
            port: proxy_addr.port(),
            username: None,
            password: None,
        };
        // 使用不存在的内部域名，验证不走本地 DNS 且通过 ATYP=0x03 透传原始域名
        let mut stream = dial_tcp_with_proxy(
            "signal.corp-no-dns.internal",
            21116,
            Duration::from_secs(3),
            None,
            &cfg,
        )
        .expect("socks5 dial must succeed");
        stream.write_all(b"ping").unwrap();
        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"ping");
        srv.join().unwrap();

        let targets = captured.lock().unwrap();
        assert_eq!(
            targets.as_slice(),
            &["domain:signal.corp-no-dns.internal:21116"]
        );
    }

    #[test]
    fn socks5_userpass_auth_success_and_failure_maps_to_proxy_auth_failed() {
        // 1) 成功路径
        let (ok_addr, _, srv_ok) =
            spawn_mock_socks5_server(Some(("alice".into(), "s3cr3t".into())), None);
        let ok_cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Socks5),
            host: "127.0.0.1".to_string(),
            port: ok_addr.port(),
            username: Some("alice".to_string()),
            password: Some("s3cr3t".to_string()),
        };
        let mut stream = dial_tcp_with_proxy(
            "relay.corp.internal",
            21117,
            Duration::from_secs(3),
            None,
            &ok_cfg,
        )
        .expect("socks5 auth ok");
        stream.write_all(b"ok").unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ok");
        srv_ok.join().unwrap();

        // 2) 密码错误 -> AuthFailed -> codes::PROXY_AUTH_FAILED 且绝不泄露密码
        let (bad_addr, _, srv_bad) =
            spawn_mock_socks5_server(Some(("alice".into(), "s3cr3t".into())), None);
        let bad_cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Socks5),
            host: "127.0.0.1".to_string(),
            port: bad_addr.port(),
            username: Some("alice".to_string()),
            password: Some("WrongSecret999".to_string()),
        };
        let err = dial_tcp_with_proxy(
            "relay.corp.internal",
            21117,
            Duration::from_secs(3),
            None,
            &bad_cfg,
        )
        .expect_err("wrong socks5 password must fail");
        srv_bad.join().unwrap();
        assert!(matches!(err, ProxyDialError::AuthFailed(_)));
        assert!(!err.to_string().contains("WrongSecret999"));
        let ui = err.to_ui_error(ErrorPlatform::Macos);
        assert_eq!(ui.code, codes::PROXY_AUTH_FAILED);
        assert!(!ui.detail.unwrap_or_default().contains("WrongSecret999"));
    }

    #[test]
    fn http_connect_200_407_and_crlf_injection_rejected() {
        // 1) 200 + Basic Auth
        let expected_b64 = BASE64_STANDARD.encode("bob:pass42");
        let (ok_addr, captured, srv_ok) = spawn_mock_http_connect_server(
            Some(expected_b64),
            "HTTP/1.1 200 Connection Established\r\n\r\n",
            None,
        );
        let cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Http),
            host: "127.0.0.1".to_string(),
            port: ok_addr.port(),
            username: Some("bob".to_string()),
            password: Some("pass42".to_string()),
        };
        let mut stream = dial_tcp_with_proxy(
            "api.corp.internal",
            21118,
            Duration::from_secs(3),
            None,
            &cfg,
        )
        .expect("http connect 200");
        stream.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
        srv_ok.join().unwrap();
        let req_text = &captured.lock().unwrap()[0];
        assert!(req_text.starts_with("CONNECT api.corp.internal:21118 HTTP/1.1\r\n"));

        // 2) 407 -> AuthFailed -> codes::PROXY_AUTH_FAILED
        let (auth_addr, _, srv_407) = spawn_mock_http_connect_server(
            Some("expected".to_string()),
            "HTTP/1.1 200 Connection Established\r\n\r\n",
            None,
        );
        let bad_cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Http),
            host: "127.0.0.1".to_string(),
            port: auth_addr.port(),
            username: Some("bob".to_string()),
            password: Some("BadHttpSecret!".to_string()),
        };
        let err = dial_tcp_with_proxy(
            "api.corp.internal",
            21118,
            Duration::from_secs(3),
            None,
            &bad_cfg,
        )
        .expect_err("407 must fail");
        srv_407.join().unwrap();
        assert!(matches!(err, ProxyDialError::AuthFailed(_)));
        assert_eq!(err.to_ui_error_generic().code, codes::PROXY_AUTH_FAILED);
        assert!(!err.to_string().contains("BadHttpSecret!"));

        // 3) CRLF 注入拒收（目标主机与密码均拦截）
        let inj_err = dial_tcp_with_proxy(
            "evil.com\r\nX-Injected: 1",
            21116,
            Duration::from_secs(1),
            None,
            &cfg,
        )
        .expect_err("CRLF in target_host must be rejected");
        assert!(matches!(inj_err, ProxyDialError::Config(_)));
        assert_eq!(
            inj_err.to_ui_error_generic().code,
            codes::PROXY_CONFIG_CONFLICT
        );

        let mut crlf_pass_cfg = cfg.clone();
        crlf_pass_cfg.password = Some("abc\r\ndef".to_string());
        let pass_err = dial_tcp_with_proxy(
            "api.corp.internal",
            21118,
            Duration::from_secs(1),
            None,
            &crlf_pass_cfg,
        )
        .expect_err("CRLF in password must be rejected");
        assert!(matches!(pass_err, ProxyDialError::Config(_)));
        assert!(!pass_err.to_string().contains("abc"));
    }

    #[test]
    fn http_connect_cancel_and_timeout_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stall proxy");
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let _accepted = listener.accept();
            thread::sleep(Duration::from_millis(600));
        });

        let cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Http),
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: None,
            password: None,
        };
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let cancel_trigger = std::sync::Arc::clone(&cancel);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(80));
            cancel_trigger.store(true, Ordering::Release);
        });
        let start = Instant::now();
        let err = dial_tcp_with_proxy(
            "stall.corp.internal",
            21116,
            Duration::from_secs(5),
            Some(&cancel),
            &cfg,
        )
        .expect_err("cancelled dial must fail");
        assert_eq!(err, ProxyDialError::Cancelled);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "cancel should interrupt within ~100ms, took {:?}",
            start.elapsed()
        );
        let _ = srv.join();
    }

    #[test]
    fn bypass_loopback_and_no_proxy_rules() {
        assert!(should_bypass_proxy_with_no_proxy("127.0.0.1", 21116, None));
        assert!(should_bypass_proxy_with_no_proxy("::1", 21116, None));
        assert!(should_bypass_proxy_with_no_proxy("[::1]", 21116, None));
        assert!(should_bypass_proxy_with_no_proxy("localhost", 21116, None));
        assert!(should_bypass_proxy_with_no_proxy(
            "sub.localhost",
            21116,
            None
        ));
        assert!(!should_bypass_proxy_with_no_proxy(
            "example.com",
            21116,
            None
        ));

        let rules = ".corp.internal,10.0.0.0/8,exact.example.com:21116,192.168.50.10";
        assert!(should_bypass_proxy_with_no_proxy(
            "a.corp.internal",
            443,
            Some(rules)
        ));
        assert!(should_bypass_proxy_with_no_proxy(
            "corp.internal",
            443,
            Some(rules)
        ));
        assert!(!should_bypass_proxy_with_no_proxy(
            "evilcorp.internal",
            443,
            Some(rules)
        ));
        assert!(should_bypass_proxy_with_no_proxy(
            "10.20.30.40",
            21117,
            Some(rules)
        ));
        assert!(!should_bypass_proxy_with_no_proxy(
            "11.20.30.40",
            21117,
            Some(rules)
        ));
        assert!(should_bypass_proxy_with_no_proxy(
            "exact.example.com",
            21116,
            Some(rules)
        ));
        assert!(!should_bypass_proxy_with_no_proxy(
            "exact.example.com",
            21117,
            Some(rules)
        ));
        assert!(should_bypass_proxy_with_no_proxy(
            "192.168.50.10",
            80,
            Some(rules)
        ));
        assert!(should_bypass_proxy_with_no_proxy(
            "anything.com",
            443,
            Some("*")
        ));
    }

    #[test]
    fn parse_proxy_url_supports_socks5_http_and_credentials() {
        let p1 = parse_proxy_url("socks5://user:p%40ss@10.0.0.5:1080").unwrap();
        assert_eq!(p1.protocol, ProxyProtocol::Socks5);
        assert_eq!(p1.host, "10.0.0.5");
        assert_eq!(p1.port, 1080);
        assert_eq!(p1.username.as_deref(), Some("user"));
        assert_eq!(p1.password.as_deref(), Some("p@ss"));

        let p2 = parse_proxy_url("http://[::1]:7890/").unwrap();
        assert_eq!(p2.protocol, ProxyProtocol::Http);
        assert_eq!(p2.host, "::1");
        assert_eq!(p2.port, 7890);

        let p3 = parse_proxy_url("socks5h://proxy.internal").unwrap();
        assert_eq!(p3.protocol, ProxyProtocol::Socks5);
        assert_eq!(p3.port, 1080);
    }

    #[test]
    fn socks5_rejects_oversized_credentials() {
        let cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Socks5),
            host: "127.0.0.1".to_string(),
            port: 1080,
            username: Some("a".repeat(256)),
            password: Some("ok".to_string()),
        };
        let err = resolve_effective_proxy(&cfg).expect_err("256-byte username must fail");
        assert_eq!(err.to_ui_error_generic().code, codes::PROXY_CONFIG_CONFLICT);
    }

    #[test]
    fn auth_http_client_connects_end_to_end_via_mock_http_connect_proxy() {
        // 1) 启动本地 HTTP 后端模拟 `/api/v1/health`
        let backend_listener = TcpListener::bind("127.0.0.1:0").expect("bind mock auth backend");
        let backend_addr = backend_listener.local_addr().unwrap();
        let backend_srv = thread::spawn(move || {
            let (mut s, _) = backend_listener.accept().expect("accept backend");
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let body = r#"{"status":"ok","version":"0.2.2","allow_registration":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
            let _ = s.flush();
        });

        // 2) 启动 Mock HTTP CONNECT 代理转发至本地后端
        let (proxy_addr, captured, proxy_srv) = spawn_mock_http_connect_server(
            None,
            "HTTP/1.1 200 Connection Established\r\n\r\n",
            Some(backend_addr),
        );
        let proxy_cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Http),
            host: "127.0.0.1".to_string(),
            port: proxy_addr.port(),
            username: None,
            password: None,
        };

        // 3) 使用无公网 DNS 的虚构主机名，验证 AuthHttpClient 完整穿透代理拿到健康状态
        let client = crate::auth_client::AuthHttpClient::new(
            "auth-backend.corp.internal",
            21118,
            false,
            None,
        )
        .unwrap()
        .with_proxy(proxy_cfg);
        let auth_cfg = client
            .fetch_auth_config()
            .expect("fetch_auth_config via proxy");
        assert!(auth_cfg.allow_registration);

        proxy_srv.join().unwrap();
        backend_srv.join().unwrap();
        assert!(captured.lock().unwrap()[0]
            .starts_with("CONNECT auth-backend.corp.internal:21118 HTTP/1.1\r\n"));
    }

    #[test]
    fn tcp_relay_transport_connects_end_to_end_via_mock_socks5_proxy() {
        use rc_net::{NetEvent, Transport};
        // 1) 启动本地 Mock RCR1 中继后端，完成握手并回送一条 Reliable 帧
        let backend_listener = TcpListener::bind("127.0.0.1:0").expect("bind mock relay backend");
        let backend_addr = backend_listener.local_addr().unwrap();
        let backend_srv = thread::spawn(move || {
            let (mut s, _) = backend_listener.accept().expect("accept relay backend");
            let mut hdr = [0u8; 6];
            s.read_exact(&mut hdr).unwrap();
            assert_eq!(&hdr[0..4], b"RCR1");
            assert_eq!(hdr[4], 2); // Client
            let mut tok = vec![0u8; usize::from(hdr[5])];
            s.read_exact(&mut tok).unwrap();
            assert_eq!(&tok, b"proxy-tok-1");
            // 回复握手成功 0x00
            s.write_all(&[0x00]).unwrap();
            // 发送 1 条 Reliable 帧（ch=2, len=5, payload="hello"）
            let mut frame = vec![2u8];
            frame.extend_from_slice(&(5u32).to_be_bytes());
            frame.extend_from_slice(b"hello");
            s.write_all(&frame).unwrap();
            let _ = s.flush();
            thread::sleep(Duration::from_millis(120));
        });

        // 2) 启动 Mock SOCKS5 代理（带用户名密码认证）转发至本地 RCR1 后端
        let (proxy_addr, captured, proxy_srv) = spawn_mock_socks5_server(
            Some(("relay-user".into(), "relay-pass".into())),
            Some(backend_addr),
        );
        let proxy_cfg = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Socks5),
            host: "127.0.0.1".to_string(),
            port: proxy_addr.port(),
            username: Some("relay-user".to_string()),
            password: Some("relay-pass".to_string()),
        };

        let mut transport =
            crate::relay_transport::TcpRelayTransport::connect_with_proxy_cancellable(
                "relay-backend.corp.internal:21117",
                crate::relay_transport::RelayRole::Client,
                "proxy-tok-1",
                Duration::from_secs(3),
                Arc::new(AtomicBool::new(false)),
                Some(&proxy_cfg),
            )
            .expect("TcpRelayTransport via SOCKS5 must succeed");

        let mut received = None;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            for ev in transport.poll(Duration::from_millis(20)).unwrap() {
                if let NetEvent::Reliable(data) = ev {
                    received = Some(data);
                    break;
                }
            }
            if received.is_some() {
                break;
            }
        }
        assert_eq!(received.as_deref(), Some(b"hello".as_slice()));
        drop(transport);
        proxy_srv.join().unwrap();
        backend_srv.join().unwrap();
        assert_eq!(
            captured.lock().unwrap().as_slice(),
            &["domain:relay-backend.corp.internal:21117"]
        );
    }

    #[test]
    fn app_prefs_and_updater_proxy_integration_redacts_secrets() {
        let mut prefs = crate::app_prefs::AppPrefs::default();
        assert_eq!(prefs.proxy.mode, ProxyMode::None);
        assert!(!prefs.allow_wol);

        prefs.allow_wol = true;
        prefs.proxy = ProxyConfig {
            mode: ProxyMode::Manual,
            protocol: Some(ProxyProtocol::Http),
            host: "proxy.corp.internal".to_string(),
            port: 8080,
            username: Some("ops".to_string()),
            password: Some("TopSecretUpdatePass".to_string()),
        };
        let dbg = format!("{prefs:?}");
        assert!(!dbg.contains("TopSecretUpdatePass"));
        assert!(dbg.contains("<redacted>"));

        let json = serde_json::to_string(&prefs).unwrap();
        let parsed: crate::app_prefs::AppPrefs = serde_json::from_str(&json).unwrap();
        assert!(parsed.allow_wol);
        assert_eq!(parsed.proxy, prefs.proxy);

        // 全局活跃代理 -> updater::resolve_updater_proxy 生效且回环强制 Bypass
        set_global_proxy_config(prefs.proxy.clone());
        let resolved_github = crate::updater::resolve_updater_proxy(
            "https://api.github.com/repos/TokenBoom/rabbitcontrol-macos/releases/latest",
        )
        .expect("resolve updater proxy")
        .expect("must return active proxy for external URL");
        assert_eq!(resolved_github.host, "proxy.corp.internal");
        assert_eq!(resolved_github.port, 8080);

        let bypassed_local =
            crate::updater::resolve_updater_proxy("https://127.0.0.1:8443/releases/latest")
                .expect("resolve local updater proxy");
        assert!(
            bypassed_local.is_none(),
            "loopback updater URL must bypass proxy"
        );
        set_global_proxy_config(ProxyConfig::default());
    }

    #[test]
    fn parse_proxy_url_rejects_https_and_never_leaks_credentials_on_scheme_errors() {
        // High 1: 严禁将 https:// 静默降级为明文 HTTP 代理，且报错不泄露密码
        let https_err = parse_proxy_url("https://alice:HttpsSecret42@proxy.corp.internal:443")
            .expect_err("https proxy must be explicitly rejected");
        let https_msg = https_err.to_string();
        assert!(!https_msg.contains("HttpsSecret42"));
        let https_ui = https_err.to_ui_error(ErrorPlatform::Macos);
        assert_eq!(https_ui.code, codes::PROXY_CONFIG_CONFLICT);
        assert!(!https_ui
            .detail
            .unwrap_or_default()
            .contains("HttpsSecret42"));

        // Medium 4: 非 RFC 3986 scheme（如含密码中的 `://`）或不支持的协议绝不把原始输入回显到错误文本
        let ftp_err = parse_proxy_url("ftp://bob:FtpSecret99@proxy.corp.internal:21")
            .expect_err("unsupported scheme must fail");
        assert!(!ftp_err.to_string().contains("FtpSecret99"));
        assert!(!ftp_err.to_string().contains("ftp"));

        let fake_scheme_res = parse_proxy_url("alice:my://WeirdPass77@10.0.0.2:8080");
        match fake_scheme_res {
            Ok(resolved) => {
                assert_eq!(resolved.protocol, ProxyProtocol::Http);
                assert_eq!(resolved.host, "10.0.0.2");
                assert_eq!(resolved.port, 8080);
                assert!(!format!("{resolved:?}").contains("WeirdPass77"));
            }
            Err(err) => {
                assert!(!err.to_string().contains("WeirdPass77"));
            }
        }
    }

    #[test]
    fn http_connect_rejects_non_three_digit_status_codes() {
        for bad_resp in [
            "HTTP/1.1 +200 OK\r\n\r\n",
            "HTTP/1.1 0200 OK\r\n\r\n",
            "HTTP/1.1 2000 OK\r\n\r\n",
        ] {
            let (proxy_addr, _, srv) = spawn_mock_http_connect_server(None, bad_resp, None);
            let cfg = ProxyConfig {
                mode: ProxyMode::Manual,
                protocol: Some(ProxyProtocol::Http),
                host: "127.0.0.1".to_string(),
                port: proxy_addr.port(),
                username: None,
                password: None,
            };
            let err = dial_tcp_with_proxy(
                "api.corp.internal",
                21118,
                Duration::from_secs(2),
                None,
                &cfg,
            )
            .expect_err("malformed status code must be rejected");
            srv.join().unwrap();
            assert!(matches!(err, ProxyDialError::ConnectFailed(_)));
        }
    }
}
