//! 控制端（`session_bridge`）与被控端（`host_bridge`）共享的纯工具常量与函数。
//!
//! 将双方共用的默认监听端口、本机局域网候选地址收集与中继/mTLS 建连错误分类
//! 抽离至独立共享模块，使 `host_bridge/` 与 `session_bridge/` 生产代码零互相依赖；
//! 原公开及 `pub(crate)` 路径继续由各自 `mod.rs` 原样重导出以保持 100% API 兼容。

#![deny(unsafe_code)]

use std::net::{IpAddr, SocketAddr};

use crate::lan_discovery;

/// 默认被控端监听端口（被占用时回退临时端口 `0`）。
pub const DEFAULT_HOST_PORT: u16 = 9901;

/// 收集被控端全部 UP 非回环网卡上的直连候选地址（多网卡/VPN IPv4 与全球单播 IPv6），
/// 自动去重并按 `<= 16` 条上限截断；当 `listen_port == 0` 时返回空列表。
pub fn collect_host_lan_addrs(listen_port: u16) -> Vec<String> {
    if listen_port == 0 {
        return Vec::new();
    }
    let ips = lan_discovery::detect_local_interface_ips();
    format_host_lan_addrs_from_ips(&ips, listen_port)
}

pub(crate) fn format_host_lan_addrs_from_ips(
    ips: &lan_discovery::LocalInterfaceIps,
    listen_port: u16,
) -> Vec<String> {
    const MAX_HOST_LAN_ADDRS: usize = 16;
    if listen_port == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for v4 in &ips.ipv4s {
        if out.len() >= MAX_HOST_LAN_ADDRS {
            break;
        }
        let formatted = SocketAddr::new(IpAddr::V4(*v4), listen_port).to_string();
        if !out.contains(&formatted) {
            out.push(formatted);
        }
    }
    for v6 in &ips.global_ipv6s {
        if out.len() >= MAX_HOST_LAN_ADDRS {
            break;
        }
        let formatted = SocketAddr::new(IpAddr::V6(*v6), listen_port).to_string();
        if !out.contains(&formatted) {
            out.push(formatted);
        }
    }
    out
}

pub(crate) fn is_mtls_cert_or_config_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("timeout")
        || lower.contains("timed out")
        || msg.contains("超时")
        || lower.contains("connection refused")
        || lower.contains("unexpected eof")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("unreachable")
    {
        return false;
    }
    lower.contains("invalid peer certificate")
        || lower.contains("invalidcertificate")
        || lower.contains("badcertificate")
        || lower.contains("bad certificate")
        || lower.contains("unknownissuer")
        || lower.contains("unknown_issuer")
        || lower.contains("unknown ca")
        || lower.contains("certificate unknown")
        || lower.contains("certificate required")
        || lower.contains("certificate_required")
        || lower.contains("the cryptographic handshake failed")
        || lower.contains("crypto error")
        || lower.contains("handshake failure")
        || lower.contains("notvalidforname")
        || lower.contains("notvalidyet")
        || lower.contains("expired")
        || lower.contains("revoked")
        || lower.contains("badsignature")
        || lower.contains("san uri")
        || lower.contains("urn:rabbitcontrol")
        || lower.contains("no peer certificate")
        || lower.contains("missing client certificate")
        || msg.contains("设备证书")
        || msg.contains("证书校验")
        || msg.contains("身份不匹配")
        || lower.contains("root ca")
}

/// 将底层中继建连错误映射为用户可读的具体中文提示，避免将超时/EOF/拒连一刀切报成 mTLS 错误。
pub fn classify_relay_connect_error(
    err: &rc_types::Error,
    encrypt_connection: bool,
    had_outer_mtls: bool,
) -> String {
    let raw = err.to_string();
    let lower = raw.to_ascii_lowercase();
    if lower.contains("relay connect cancelled") || lower.contains("cancelled") {
        return "连接已取消".to_string();
    }
    if lower.contains("proxy config conflict") || raw.contains("代理配置冲突") {
        return format!("proxy_config_conflict: 代理配置无效或存在冲突：{raw}");
    }
    if lower.contains("proxy authentication failed")
        || lower.contains("proxy auth")
        || lower.contains("407")
        || raw.contains("代理认证")
    {
        return format!("代理认证失败 (407)：{raw}");
    }
    if lower.contains("proxy connect failed") || raw.contains("代理") {
        return format!("无法通过代理连接中继服务器：{raw}");
    }
    if lower.contains("resolve relay addr") || lower.contains("resolved to no socket addresses") {
        return format!("无法解析中继服务器地址，请检查网络或服务器配置：{raw}");
    }
    if lower.contains("connect relay tcp timed out") {
        return "连接中继服务器超时，请检查网络或服务器中继端口".to_string();
    }
    if matches!(err, rc_types::Error::Timeout(_))
        || lower.contains("relay pair timeout")
        || lower.contains("timed out")
        || lower.contains("timeout")
    {
        return "对端未响应中继配对（对方可能离线、被控服务未就绪或网络受限）".to_string();
    }
    if lower.contains("hit eof before completing handshake")
        || lower.contains("hit eof before completing e2ee mtls handshake")
    {
        return "对端已断开或拒绝连接（对方可能未开启远程协助、被控服务未就绪或已离线）"
            .to_string();
    }
    if lower.contains("reply=0x01") || lower.contains("handshake rejected") {
        return "中继服务器拒绝配对（会话凭据已失效、对方已离线或连接已满）".to_string();
    }
    if lower.contains("connection refused")
        || lower.contains("unreachable")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("connect relay failed")
    {
        return format!("无法连接中继服务器（端口不可达或连接中断）：{raw}");
    }
    if is_mtls_cert_or_config_error(&raw) {
        if lower.contains("e2ee") {
            return format!("端到端 mTLS 证书身份校验失败：{raw}");
        }
        if had_outer_mtls || lower.contains("outer mtls") {
            return format!("中继服务器 mTLS 证书校验失败：{raw}");
        }
        return format!("mTLS 证书配置或校验失败：{raw}");
    }
    if lower.contains("e2ee mtls handshake failed") {
        return format!("建立端到端加密通道时连接中断：{raw}");
    }
    if lower.contains("outer mtls handshake failed") {
        return format!("连接中继服务器加密通道时连接中断：{raw}");
    }
    let _ = (encrypt_connection, had_outer_mtls);
    format!("中继连接失败：{raw}")
}
