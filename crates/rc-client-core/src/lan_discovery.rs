//! 局域网设备发现（基于 `std::net::UdpSocket` + `socket2` 端口复用多播信标）。
//!
//! 本模块**严禁引入 `tauri` 类型**，全模块 `#![deny(unsafe_code)]`；
//! 状态管理 [`PeerTable`] 遵循铁律 4（所有时间由调用方注入 `now_ms: u64`），
//! 便于离线确定性单测。
//!
//! # 二进制信标格式
//!
//! ```text
//! [0..4]   magic:       b"RCBC"
//! [4]      version:     u8 = 1
//! [5..13]  instance_id: u64 LE
//! [13..15] listen_port: u16 LE
//! [15]     flags:       u8 (bit0 = requires_password)
//! [16]     name_len:    u8 (<= 64)
//! [17..]   name:        UTF-8 字节（精确 name_len 字节）
//! [可选尾部] did_len:   u8 (= 9，仅当存在合法 9 位数字设备码时附带)
//! [可选尾部] device_id: 9 字节 ASCII 数字
//! ```

#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockRef, Socket, Type};

/// 局域网信标魔数。
pub const BEACON_MAGIC: &[u8; 4] = b"RCBC";

/// 当前信标协议版本。
pub const BEACON_VERSION: u8 = 1;

/// 信标固定头部长度（字节）：4 + 1 + 8 + 2 + 1 + 1 = 17。
pub const BEACON_HEADER_LEN: usize = 17;

/// 设备名称编码字节上限（UTF-8 字符边界安全截断）。
pub const MAX_BEACON_NAME_LEN: usize = 64;

/// 标志位 bit 0：被控端是否启用访问密码。
pub const FLAG_REQUIRES_PASSWORD: u8 = 0x01;

/// 局域网多播组地址（本地管理段 `239.255.77.77`）。
pub const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 77, 77);

/// 局域网多播端口。
pub const MULTICAST_PORT: u16 = 19999;

/// 默认信标广播周期。
const BROADCAST_INTERVAL: Duration = Duration::from_millis(1_500);

/// 接收超时分片（兼顾低功耗、`clear_and_refresh()` 切网快速响应与 `stop()` 快速回收）。
const RECV_POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// 多播网卡复检周期（检测局域网 IP 变化或补做首次加入失败的重试，U-M4）。
const MULTICAST_IFACE_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// 默认局域网节点过期 TTL（毫秒；4 倍广播周期）。
pub const DEFAULT_PEER_TTL_MS: u64 = 6_000;

/// 9 位数字设备码固定长度。
const BEACON_DEVICE_ID_LEN: usize = 9;

/// 校验是否为合法的 9 位纯 ASCII 数字设备码。
fn is_valid_beacon_device_id(id: &str) -> bool {
    id.len() == BEACON_DEVICE_ID_LEN && id.bytes().all(|b| b.is_ascii_digit())
}

/// 解码后的局域网信标载荷。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    /// 发送方随机实例 ID（用于过滤自身回环包与节点去重）。
    pub instance_id: u64,
    /// 被控端监听的 QUIC 端口。
    pub listen_port: u16,
    /// 是否启用了访问密码。
    pub requires_password: bool,
    /// 设备可读名称（编码上限 64 UTF-8 字节）。
    pub name: String,
    /// 可选 9 位纯数字设备码（用于局域网设备无缝回退中继连接）。
    pub device_id: Option<String>,
}

/// 局域网发现的在线被控端节点（经 IPC 推送/拉取至前端列表）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LanPeer {
    /// 对端实例 ID。
    pub instance_id: u64,
    /// 对端设备可读名称。
    pub name: String,
    /// 对端直连地址（`ip:port`）。
    pub addr: String,
    /// 对端是否需要密码。
    pub requires_password: bool,
    /// 对端可选 9 位数字设备码。
    pub device_id: Option<String>,
}

/// 将 `s` 按 UTF-8 字符边界安全截断至不超过 `max_bytes` 字节。
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// 编码局域网信标为纯二进制报文。
///
/// 设备名超过 [`MAX_BEACON_NAME_LEN`] 字节时自动在 UTF-8 字符边界截断；
/// 仅当 `device_id` 为合法 9 位数字时附带向后兼容尾部段。
pub fn encode_beacon(beacon: &Beacon) -> Vec<u8> {
    let name = truncate_utf8(&beacon.name, MAX_BEACON_NAME_LEN);
    let name_bytes = name.as_bytes();
    let flags = if beacon.requires_password {
        FLAG_REQUIRES_PASSWORD
    } else {
        0
    };
    let valid_device_id = beacon
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|s| is_valid_beacon_device_id(s));
    let tail_len = if valid_device_id.is_some() {
        1 + BEACON_DEVICE_ID_LEN
    } else {
        0
    };
    let mut out = Vec::with_capacity(BEACON_HEADER_LEN + name_bytes.len() + tail_len);
    out.extend_from_slice(BEACON_MAGIC);
    out.push(BEACON_VERSION);
    out.extend_from_slice(&beacon.instance_id.to_le_bytes());
    out.extend_from_slice(&beacon.listen_port.to_le_bytes());
    out.push(flags);
    out.push(name_bytes.len() as u8);
    out.extend_from_slice(name_bytes);
    if let Some(did) = valid_device_id {
        out.push(BEACON_DEVICE_ID_LEN as u8);
        out.extend_from_slice(did.as_bytes());
    }
    out
}

/// 解码局域网信标（严格校验魔数、版本、精确长度、名称上限与合法 UTF-8；兼容无尾部设备码的旧版 v1 报文）。
pub fn decode_beacon(buf: &[u8]) -> Option<Beacon> {
    if buf.len() < BEACON_HEADER_LEN {
        return None;
    }
    if &buf[0..4] != BEACON_MAGIC {
        return None;
    }
    if buf[4] != BEACON_VERSION {
        return None;
    }
    let instance_id = u64::from_le_bytes(buf[5..13].try_into().ok()?);
    let listen_port = u16::from_le_bytes(buf[13..15].try_into().ok()?);
    let flags = buf[15];
    let name_len = usize::from(buf[16]);
    if name_len > MAX_BEACON_NAME_LEN {
        return None;
    }
    let name_end = BEACON_HEADER_LEN + name_len;
    if buf.len() < name_end {
        return None;
    }
    let name = std::str::from_utf8(&buf[BEACON_HEADER_LEN..name_end])
        .ok()?
        .to_string();
    let device_id = if buf.len() == name_end {
        None
    } else if buf.len() == name_end + 1 + BEACON_DEVICE_ID_LEN
        && usize::from(buf[name_end]) == BEACON_DEVICE_ID_LEN
    {
        let did = std::str::from_utf8(&buf[name_end + 1..]).ok()?;
        if !is_valid_beacon_device_id(did) {
            return None;
        }
        Some(did.to_string())
    } else {
        return None;
    };
    Some(Beacon {
        instance_id,
        listen_port,
        requires_password: (flags & FLAG_REQUIRES_PASSWORD) != 0,
        name,
        device_id,
    })
}

/// 节点表内部条目。
#[derive(Debug, Clone)]
struct PeerEntry {
    peer: LanPeer,
    last_seen_ms: u64,
}

/// 局域网在线节点表（纯确定性状态机，所有时间戳由调用方注入 `now_ms`，铁律 4）。
#[derive(Debug, Clone)]
pub struct PeerTable {
    self_instance_id: u64,
    entries: BTreeMap<u64, PeerEntry>,
}

impl PeerTable {
    /// 构造空节点表，指定本机 `self_instance_id` 以过滤自身回环广播。
    pub fn new(self_instance_id: u64) -> Self {
        Self {
            self_instance_id,
            entries: BTreeMap::new(),
        }
    }

    /// 插入或刷新一条局域网节点记录；自动忽略自身回环包与端口为 0 的无效包。
    pub fn upsert(&mut self, peer_ip: IpAddr, beacon: Beacon, now_ms: u64) {
        if beacon.instance_id == self.self_instance_id || beacon.listen_port == 0 {
            return;
        }
        let addr = SocketAddr::new(peer_ip, beacon.listen_port).to_string();
        let peer = LanPeer {
            instance_id: beacon.instance_id,
            name: beacon.name,
            addr,
            requires_password: beacon.requires_password,
            device_id: beacon.device_id,
        };
        self.entries.insert(
            beacon.instance_id,
            PeerEntry {
                peer,
                last_seen_ms: now_ms,
            },
        );
    }

    /// 按注入时间 `now_ms` 淘汰超时未刷新（`now_ms - last_seen_ms >= ttl_ms`）的节点。
    pub fn prune(&mut self, now_ms: u64, ttl_ms: u64) {
        self.entries
            .retain(|_, entry| now_ms.saturating_sub(entry.last_seen_ms) < ttl_ms);
    }

    /// 立刻清空所有已缓存的局域网节点（用于切网后清除旧网段缓存）。
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// 导出当前在线节点快照（按名称、地址、实例 ID 稳定排序）。
    pub fn snapshot(&self) -> Vec<LanPeer> {
        let mut peers: Vec<LanPeer> = self.entries.values().map(|e| e.peer.clone()).collect();
        peers.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.addr.cmp(&b.addr))
                .then_with(|| a.instance_id.cmp(&b.instance_id))
        });
        peers
    }

    /// 按 9 位设备码（允许空格/短横线）查询最近活跃的局域网直连地址，供三阶路由优先尝试 `UDP LAN`。
    pub fn lookup_addr(&self, device_id: &str) -> Option<SocketAddr> {
        let normalized = crate::server_config::parse_device_id_input(device_id)?;
        self.entries
            .values()
            .filter(|entry| entry.peer.device_id.as_deref() == Some(normalized.as_str()))
            .max_by_key(|entry| (entry.last_seen_ms, entry.peer.instance_id))
            .and_then(|entry| entry.peer.addr.parse::<SocketAddr>().ok())
    }
}

/// 默认路由探测目标（RFC 5737 TEST-NET-1 与公共路由），用于兜底探测本机出向局域网 IPv4。
const DEFAULT_ROUTE_PROBE_TARGETS: [SocketAddrV4; 2] = [
    SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9),
    SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 80),
];

/// 判断 IPv4 地址是否为可向对端通告的本机局域网候选地址（排除未指定、回环、多播、链路本地与广播）。
pub fn is_usable_lan_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_link_local()
        && !ip.is_broadcast()
}

fn probe_route_local_ipv4(target: SocketAddrV4) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(target).ok()?;
    match sock.local_addr().ok()?.ip().to_canonical() {
        IpAddr::V4(ip) if is_usable_lan_ipv4(ip) => Some(ip),
        _ => None,
    }
}

/// 探测本机出向局域网 IPv4 地址列表（纯标准库 UDP `connect` 路由表查询，发送 0 个报文）。
///
/// 先按顺序探测 `preferred_targets`（将 IPv4-mapped IPv6 规范化为 IPv4，跳过未指定/回环/多播/纯 IPv6 目标），
/// 再探测默认路由目标 `192.0.2.1:9`（RFC 5737 TEST-NET-1）与 `8.8.8.8:80`；
/// 返回经 [`is_usable_lan_ipv4`] 过滤并按探测顺序去重后的本机源 IPv4 列表。
pub fn discover_local_lan_ipv4s(preferred_targets: &[SocketAddr]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut push_unique = |target: SocketAddrV4| {
        if let Some(ip) = probe_route_local_ipv4(target) {
            if is_usable_lan_ipv4(ip) && !out.contains(&ip) {
                out.push(ip);
            }
        }
    };

    for target in preferred_targets {
        let v4_target = match target.ip().to_canonical() {
            IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_loopback() && !v4.is_multicast() => {
                let port = if target.port() == 0 { 9 } else { target.port() };
                SocketAddrV4::new(v4, port)
            }
            _ => continue,
        };
        push_unique(v4_target);
    }

    for default_target in DEFAULT_ROUTE_PROBE_TARGETS {
        push_unique(default_target);
    }

    out
}

/// 按给定目标列表探测首选本机出向局域网 IPv4 地址（纯标准库 UDP `connect` 路由表查询，发送 0 个报文）。
pub fn detect_local_lan_ipv4_for_targets(preferred_targets: &[SocketAddr]) -> Option<Ipv4Addr> {
    discover_local_lan_ipv4s(preferred_targets)
        .into_iter()
        .next()
}

/// 探测本机出向局域网 IPv4 地址（纯标准库 UDP `connect` 路由表查询，发送 0 个报文）。
pub fn detect_local_lan_ipv4() -> Option<Ipv4Addr> {
    detect_local_lan_ipv4_for_targets(&[])
}

/// 本机所有 UP 非回环网卡上的可用直连 IP 集合（多网卡/VPN IPv4 + 全球单播 IPv6）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalInterfaceIps {
    /// 可用于局域网/VPN 直连或候选通告的 IPv4 地址列表（首选出向路由排在最前，已去重）。
    pub ipv4s: Vec<Ipv4Addr>,
    /// 全球单播 IPv6 地址列表（仅保留 `2000::/3`，过滤 `::1` / `fe80::/10` / `fc00::/7` / `::`）。
    pub global_ipv6s: Vec<Ipv6Addr>,
}

const DEFAULT_V6_ROUTE_PROBE_TARGETS: [Ipv6Addr; 2] = [
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
];

fn push_unique_v4(out: &mut Vec<Ipv4Addr>, ip: Ipv4Addr) {
    if is_usable_lan_ipv4(ip) && !out.contains(&ip) {
        out.push(ip);
    }
}

fn push_unique_global_v6(out: &mut Vec<Ipv6Addr>, ip: Ipv6Addr) {
    if crate::nat::is_global_unicast_ipv6(ip) && !out.contains(&ip) {
        out.push(ip);
    }
}

fn probe_route_local_ipv6(target: SocketAddrV6) -> Option<Ipv6Addr> {
    let sock = UdpSocket::bind("[::]:0").ok()?;
    sock.connect(target).ok()?;
    match sock.local_addr().ok()?.ip().to_canonical() {
        IpAddr::V6(v6) if crate::nat::is_global_unicast_ipv6(v6) => Some(v6),
        _ => None,
    }
}

fn parse_ipv4_token(raw: &str) -> Option<Ipv4Addr> {
    let token = raw.trim().split('/').next()?.trim();
    token.parse::<Ipv4Addr>().ok()
}

fn parse_ipv6_token(raw: &str) -> Option<Ipv6Addr> {
    let no_cidr = raw.trim().split('/').next()?.trim();
    let no_zone = no_cidr.split('%').next()?.trim();
    let trimmed = no_zone.trim_start_matches('[').trim_end_matches(']');
    match trimmed.parse::<Ipv6Addr>().ok()? {
        v6 if v6.to_ipv4_mapped().is_some() => None,
        v6 => Some(v6),
    }
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn parse_macos_ifconfig_output(stdout: &str) -> LocalInterfaceIps {
    let mut out = LocalInterfaceIps::default();
    let mut iface_active = false;
    let mut current_v4s: Vec<Ipv4Addr> = Vec::new();
    let mut current_v6s: Vec<Ipv6Addr> = Vec::new();
    let mut flush_iface = |active: bool, v4s: &mut Vec<Ipv4Addr>, v6s: &mut Vec<Ipv6Addr>| {
        if active {
            for ip in v4s.drain(..) {
                push_unique_v4(&mut out.ipv4s, ip);
            }
            for ip in v6s.drain(..) {
                push_unique_global_v6(&mut out.global_ipv6s, ip);
            }
        } else {
            v4s.clear();
            v6s.clear();
        }
    };

    for line in stdout.lines() {
        let is_header = !line.is_empty() && !line.starts_with([' ', '\t']);
        if is_header {
            flush_iface(iface_active, &mut current_v4s, &mut current_v6s);
            let is_up_non_loopback = line
                .split('<')
                .nth(1)
                .and_then(|s| s.split('>').next())
                .map(|flags| {
                    let parts: Vec<&str> = flags.split(',').map(str::trim).collect();
                    parts.contains(&"UP") && !parts.contains(&"LOOPBACK")
                })
                .unwrap_or(false);
            iface_active = is_up_non_loopback;
            continue;
        }
        if !iface_active {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("status:") && trimmed.contains("inactive") {
            iface_active = false;
            current_v4s.clear();
            current_v6s.clear();
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(tok) = rest.split_whitespace().next() {
                if let Some(v4) = parse_ipv4_token(tok) {
                    current_v4s.push(v4);
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            if trimmed.contains("deprecated") {
                continue;
            }
            if let Some(tok) = rest.split_whitespace().next() {
                if let Some(v6) = parse_ipv6_token(tok) {
                    current_v6s.push(v6);
                }
            }
        }
    }
    flush_iface(iface_active, &mut current_v4s, &mut current_v6s);
    out
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn parse_linux_ip_addr_show(stdout: &str) -> LocalInterfaceIps {
    let mut out = LocalInterfaceIps::default();
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let ifname = cols[1].trim_end_matches(':');
        if ifname == "lo" || line.contains(" deprecated ") {
            continue;
        }
        match cols[2] {
            "inet" => {
                if let Some(v4) = parse_ipv4_token(cols[3]) {
                    push_unique_v4(&mut out.ipv4s, v4);
                }
            }
            "inet6" => {
                if let Some(v6) = parse_ipv6_token(cols[3]) {
                    push_unique_global_v6(&mut out.global_ipv6s, v6);
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn parse_proc_if_inet6(content: &str) -> Vec<Ipv6Addr> {
    let mut out = Vec::new();
    for line in content.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let hex = cols[0].trim();
        let ifname = cols[5].trim();
        if hex.len() != 32 || ifname == "lo" {
            continue;
        }
        // scope == "00" 表示 global scope，过滤链路本地/回环；flags bit 0x20 (IFA_F_DEPRECATED) 忽略已废弃地址
        let flags = u8::from_str_radix(cols[4], 16).unwrap_or(0);
        if (flags & 0x20) != 0 {
            continue;
        }
        let mut raw = [0u8; 16];
        let mut ok = true;
        for (i, byte_slot) in raw.iter_mut().enumerate() {
            let start = i * 2;
            match u8::from_str_radix(&hex[start..start + 2], 16) {
                Ok(b) => *byte_slot = b,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            push_unique_global_v6(&mut out, Ipv6Addr::from(raw));
        }
    }
    out
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
fn parse_windows_ipconfig_output(stdout: &str) -> LocalInterfaceIps {
    let mut out = LocalInterfaceIps::default();
    let mut skip_adapter = false;
    for raw_line in stdout.lines() {
        let trimmed_end = raw_line.trim_end();
        if trimmed_end.is_empty() {
            continue;
        }
        let is_header = !raw_line.starts_with([' ', '\t']);
        if is_header {
            let lower = trimmed_end.to_ascii_lowercase();
            skip_adapter = lower.contains("loopback") || lower.contains("回环");
            continue;
        }
        if skip_adapter {
            continue;
        }
        let Some((_label, value)) = trimmed_end.split_once(": ") else {
            continue;
        };
        let mut cand = value.trim();
        if let Some((prefix, _)) = cand.split_once('(') {
            cand = prefix.trim();
        }
        if let Some(v4) = parse_ipv4_token(cand) {
            push_unique_v4(&mut out.ipv4s, v4);
        } else if let Some(v6) = parse_ipv6_token(cand) {
            push_unique_global_v6(&mut out.global_ipv6s, v6);
        }
    }
    out
}

fn discover_os_interface_ips() -> LocalInterfaceIps {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("ifconfig").output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                return parse_macos_ifconfig_output(&text);
            }
        }
        LocalInterfaceIps::default()
    }
    #[cfg(target_os = "linux")]
    {
        let mut out = LocalInterfaceIps::default();
        if let Ok(output) = Command::new("ip")
            .args(["-o", "addr", "show", "up"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                out = parse_linux_ip_addr_show(&text);
            }
        }
        if let Ok(proc_v6) = std::fs::read_to_string("/proc/net/if_inet6") {
            for v6 in parse_proc_if_inet6(&proc_v6) {
                push_unique_global_v6(&mut out.global_ipv6s, v6);
            }
        }
        out
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("ipconfig").output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                return parse_windows_ipconfig_output(&text);
            }
        }
        LocalInterfaceIps::default()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        LocalInterfaceIps::default()
    }
}

/// 枚举本机全部 UP 非回环网卡上的可用 IPv4（含多网卡/VPN 网段）与全球单播 IPv6（`2000::/3`）。
///
/// 全实现基于纯安全 Rust（`#![deny(unsafe_code)]`、零第三方 crate），先通过 UDP `connect`
/// 路由探测保证首选出向路由地址排在最前，再并入操作系统全网卡枚举出的其余私网/VPN/全球 IPv6 地址，
/// 自动过滤回环（`127.0.0.0/8`、`::1`）、未指定（`0.0.0.0`、`::`）、链路本地（`169.254.0.0/16`、`fe80::/10`）、
/// IPv6 ULA（`fc00::/7`）与多播/广播地址。
pub fn detect_local_interface_ips_for_targets(
    preferred_targets: &[SocketAddr],
) -> LocalInterfaceIps {
    let mut out = LocalInterfaceIps::default();

    // 1. 首选出向路由 IPv4 排最前，保证与既有单网卡排序完全一致
    for v4 in discover_local_lan_ipv4s(preferred_targets) {
        push_unique_v4(&mut out.ipv4s, v4);
    }

    // 2. 首选出向全球单播 IPv6 排最前
    for target in preferred_targets {
        if let IpAddr::V6(v6) = target.ip().to_canonical() {
            if !v6.is_unspecified() && !v6.is_loopback() && !v6.is_multicast() {
                let port = if target.port() == 0 { 9 } else { target.port() };
                if let Some(src) = probe_route_local_ipv6(SocketAddrV6::new(v6, port, 0, 0)) {
                    push_unique_global_v6(&mut out.global_ipv6s, src);
                }
            }
        }
    }
    for v6_probe in DEFAULT_V6_ROUTE_PROBE_TARGETS {
        if let Some(src) = probe_route_local_ipv6(SocketAddrV6::new(v6_probe, 80, 0, 0)) {
            push_unique_global_v6(&mut out.global_ipv6s, src);
        }
    }

    // 3. 并入全部 UP 非回环网卡上的多网卡 / VPN IPv4 与全球单播 IPv6
    let os_ips = discover_os_interface_ips();
    for v4 in os_ips.ipv4s {
        push_unique_v4(&mut out.ipv4s, v4);
    }
    for v6 in os_ips.global_ipv6s {
        push_unique_global_v6(&mut out.global_ipv6s, v6);
    }

    out
}

/// 枚举本机全部 UP 非回环网卡上的可用 IPv4（含多网卡/VPN 网段）与全球单播 IPv6。
pub fn detect_local_interface_ips() -> LocalInterfaceIps {
    detect_local_interface_ips_for_targets(&[])
}

/// 获取本机可读设备名（优先 macOS `scutil`，次选 `HOSTNAME` 环境变量，兜底 `"本机 Mac"`）。
pub fn local_hostname() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("scutil")
            .args(["--get", "ComputerName"])
            .output()
        {
            if output.status.success() {
                if let Ok(name) = String::from_utf8(output.stdout) {
                    let trimmed = name.trim();
                    if !trimmed.is_empty() {
                        return trimmed.to_string();
                    }
                }
            }
        }
    }
    if let Ok(name) = std::env::var("HOSTNAME") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "本机 Mac".to_string()
}

/// 发现句柄与后台线程共享状态。
struct DiscoveryShared {
    advertising: Mutex<Option<(u16, bool)>>,
    local_device_id: Mutex<Option<String>>,
    advertising_dirty: AtomicBool,
    peers: Mutex<PeerTable>,
    refresh_gen: AtomicU64,
    refresh_applied_gen: AtomicU64,
    stop_flag: AtomicBool,
}

/// 局域网发现后台线程句柄。
///
/// 同时负责接收同网段其他 RabbitControl 实例的信标与按需广播本机被控端信息；
/// 若多播端口 `19999` 被占用或多播不可用，自动静默降级，绝不 panic 或阻塞应用启动。
pub struct LanDiscoveryHandle {
    shared: Arc<DiscoveryShared>,
    thread: Option<JoinHandle<()>>,
}

impl LanDiscoveryHandle {
    /// 启动局域网发现后台线程（默认不广播，仅监听；调用 [`Self::set_advertising`] 开启广播）。
    pub fn spawn(instance_id: u64, device_name: String) -> Self {
        let shared = Arc::new(DiscoveryShared {
            advertising: Mutex::new(None),
            local_device_id: Mutex::new(None),
            advertising_dirty: AtomicBool::new(false),
            peers: Mutex::new(PeerTable::new(instance_id)),
            refresh_gen: AtomicU64::new(0),
            refresh_applied_gen: AtomicU64::new(0),
            stop_flag: AtomicBool::new(false),
        });
        let t_shared = Arc::clone(&shared);

        let handle = thread::Builder::new()
            .name("rc-ui-lan-discovery".to_string())
            .spawn(move || {
                run_discovery_loop(instance_id, device_name, t_shared);
            })
            .expect("spawn rc-ui-lan-discovery thread");

        Self {
            shared,
            thread: Some(handle),
        }
    }

    /// 设置本机广播状态：`Some((listen_port, requires_password))` 开启广播，`None` 停止广播。
    pub fn set_advertising(&self, target: Option<(u16, bool)>) {
        *self
            .shared
            .advertising
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = target;
        self.shared.advertising_dirty.store(true, Ordering::Release);
    }

    /// 设置本机关联的 9 位数字设备码（仅合法 9 位数字会随局域网信标广播）。
    pub fn set_local_device_id(&self, device_id: Option<String>) {
        let normalized = device_id
            .map(|s| s.trim().to_string())
            .filter(|s| is_valid_beacon_device_id(s));
        *self
            .shared
            .local_device_id
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = normalized;
        self.shared.advertising_dirty.store(true, Ordering::Release);
    }

    /// 获取当前在线局域网节点快照。
    pub fn peers(&self) -> Vec<LanPeer> {
        self.shared
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot()
    }

    /// 查询指定 9 位设备码最近活跃的局域网直连地址（`UDP LAN` 路由快查）。
    pub fn lookup_lan_addr(&self, device_id: &str) -> Option<SocketAddr> {
        self.shared
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lookup_addr(device_id)
    }

    /// 切网后立刻清空已缓存的局域网节点表，并通知后台线程重新探测多播网卡且立即重发发现广播。
    ///
    /// 用于在网络切换（如 Wi-Fi 切热点/蜂窝、切换子网或系统休眠唤醒）时立即丢弃旧网段 IP，
    /// 避免残留的旧局域网地址误导 Tier 1 探测。
    pub fn clear_and_refresh(&self) {
        // 先推进刷新代次再持锁清空，配合后台线程在持锁 upsert 前复检代次，
        // 避免切网前在途收到的旧网段信标在清空后写回 peers 表。
        self.shared.refresh_gen.fetch_add(1, Ordering::AcqRel);
        self.shared
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// 停止发现线程并等待回收（幂等）。
    pub fn stop(&mut self) {
        self.shared.stop_flag.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LanDiscoveryHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 多播套接字与网卡加入状态（用于 U-M4 周期复检与重加组）。
struct DiscoverySocket {
    sock: UdpSocket,
    can_recv: bool,
    lan_iface: Option<Ipv4Addr>,
    joined_ok: bool,
}

impl DiscoverySocket {
    /// 绑定多播套接字：通过 `socket2` 开启 `SO_REUSEADDR`（Unix 下同时开启 `SO_REUSEPORT`）
    /// 后绑定 `0.0.0.0:19999` 收发双向；绑定失败时降级为临时端口只发送（U-M3 / U-M4）。
    fn bind() -> Option<Self> {
        let lan_iface = detect_local_lan_ipv4();
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MULTICAST_PORT);

        if let Ok(raw) = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            let _ = raw.set_reuse_address(true);
            #[cfg(unix)]
            let _ = raw.set_reuse_port(true);
            if raw.bind(&bind_addr.into()).is_ok() {
                let sock: UdpSocket = raw.into();
                let _ = sock.set_read_timeout(Some(RECV_POLL_TIMEOUT));
                // 开启多播回环，依靠 `PeerTable::self_instance_id` 过滤自身回环包，
                // 从而支持同机多实例互发现（U-M3）。
                let _ = sock.set_multicast_loop_v4(true);
                if let Some(ip) = lan_iface {
                    let _ = SockRef::from(&sock).set_multicast_if_v4(&ip);
                }
                let join_iface = lan_iface.unwrap_or(Ipv4Addr::UNSPECIFIED);
                let joined_ok = sock.join_multicast_v4(&MULTICAST_ADDR, &join_iface).is_ok();
                return Some(Self {
                    sock,
                    can_recv: true,
                    lan_iface,
                    joined_ok,
                });
            }
        }

        if let Ok(sock) = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) {
            let _ = sock.set_read_timeout(Some(RECV_POLL_TIMEOUT));
            let _ = sock.set_multicast_loop_v4(true);
            if let Some(ip) = lan_iface {
                let _ = SockRef::from(&sock).set_multicast_if_v4(&ip);
            }
            return Some(Self {
                sock,
                can_recv: false,
                lan_iface,
                joined_ok: false,
            });
        }
        None
    }

    /// 检查本机局域网 IPv4 是否变化或首次入组失败；必要时重新设置出向网卡并重加多播组（U-M4）。
    fn refresh_multicast_iface(&mut self) {
        self.refresh_multicast_iface_inner(false);
    }

    /// 按需或强制（切网/唤醒触发）重新探测出向网卡并重加多播组。
    fn refresh_multicast_iface_inner(&mut self, force: bool) {
        let current_lan = detect_local_lan_ipv4();
        let iface_changed = current_lan != self.lan_iface;
        if !force && !iface_changed && (!self.can_recv || self.joined_ok) {
            return;
        }
        if self.can_recv && self.joined_ok && (iface_changed || force) {
            let old_iface = self.lan_iface.unwrap_or(Ipv4Addr::UNSPECIFIED);
            let _ = self.sock.leave_multicast_v4(&MULTICAST_ADDR, &old_iface);
            self.joined_ok = false;
        }
        self.lan_iface = current_lan;
        if let Some(ip) = current_lan {
            let _ = SockRef::from(&self.sock).set_multicast_if_v4(&ip);
        }
        if self.can_recv {
            let join_iface = current_lan.unwrap_or(Ipv4Addr::UNSPECIFIED);
            self.joined_ok = self
                .sock
                .join_multicast_v4(&MULTICAST_ADDR, &join_iface)
                .is_ok();
        }
    }
}

fn run_discovery_loop(instance_id: u64, device_name: String, shared: Arc<DiscoveryShared>) {
    let origin = Instant::now();
    let target = SocketAddrV4::new(MULTICAST_ADDR, MULTICAST_PORT);
    let mut socket_opt = DiscoverySocket::bind();
    let mut last_broadcast: Option<Instant> = None;
    let mut last_iface_check = Instant::now();
    let mut seen_refresh_gen = 0u64;
    let mut recv_buf = [0u8; 256];

    while !shared.stop_flag.load(Ordering::Acquire) {
        let now_ms = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let current_refresh_gen = shared.refresh_gen.load(Ordering::Acquire);
        let refresh_requested = current_refresh_gen != seen_refresh_gen;
        if refresh_requested {
            seen_refresh_gen = current_refresh_gen;
            last_broadcast = None;
            last_iface_check = Instant::now();
            if let Some(ref mut ds) = socket_opt {
                ds.refresh_multicast_iface_inner(true);
            } else {
                socket_opt = DiscoverySocket::bind();
            }
        }

        if let Some(ref mut ds) = socket_opt {
            if !refresh_requested && last_iface_check.elapsed() >= MULTICAST_IFACE_CHECK_INTERVAL {
                last_iface_check = Instant::now();
                ds.refresh_multicast_iface();
            }

            // 1) 定期或在状态变更 / 切网刷新时发送本机信标。
            let adv = *shared.advertising.lock().unwrap_or_else(|e| e.into_inner());
            let dirty = shared.advertising_dirty.swap(false, Ordering::AcqRel);
            let should_send = dirty
                || last_broadcast
                    .map(|t| t.elapsed() >= BROADCAST_INTERVAL)
                    .unwrap_or(true);
            if should_send {
                if let Some((listen_port, requires_password)) = adv {
                    let device_id = shared
                        .local_device_id
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    let pkt = encode_beacon(&Beacon {
                        instance_id,
                        listen_port,
                        requires_password,
                        name: device_name.clone(),
                        device_id,
                    });
                    let _ = ds.sock.send_to(&pkt, target);
                    last_broadcast = Some(Instant::now());
                } else {
                    last_broadcast = None;
                }
            }

            if refresh_requested {
                shared
                    .refresh_applied_gen
                    .store(seen_refresh_gen, Ordering::Release);
            }

            // 2) 接收同网段信标（100ms 超时分片，兼顾切网快速响应与停机回收）。
            if ds.can_recv {
                match ds.sock.recv_from(&mut recv_buf) {
                    Ok((len, src)) => {
                        if let Some(beacon) = decode_beacon(&recv_buf[..len]) {
                            let rx_ms =
                                u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
                            let mut guard = shared.peers.lock().unwrap_or_else(|e| e.into_inner());
                            if shared.refresh_gen.load(Ordering::Acquire) == seen_refresh_gen {
                                guard.upsert(src.ip(), beacon, rx_ms);
                            }
                        }
                    }
                    Err(_) => {
                        // 超时或临时网络错误静默忽略。
                    }
                }
            } else {
                thread::sleep(RECV_POLL_TIMEOUT);
            }
        } else {
            if refresh_requested {
                shared
                    .refresh_applied_gen
                    .store(seen_refresh_gen, Ordering::Release);
            }
            // 极端受限环境无法绑定任何 UDP 套接字：降级空转等待退出。
            thread::sleep(RECV_POLL_TIMEOUT);
        }

        // 3) 清理过期节点。
        shared
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prune(now_ms, DEFAULT_PEER_TTL_MS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_roundtrip_and_truncation() {
        let normal = Beacon {
            instance_id: 0x0123_4567_89AB_CDEF,
            listen_port: 9901,
            requires_password: true,
            name: "Studio Mac".to_string(),
            device_id: None,
        };
        let encoded = encode_beacon(&normal);
        assert_eq!(&encoded[0..4], b"RCBC");
        assert_eq!(encoded[4], 1);
        assert_eq!(decode_beacon(&encoded), Some(normal));

        // 带合法 9 位设备码的编码/解码往返
        let with_id = Beacon {
            instance_id: 0x1122_3344_5566_7788,
            listen_port: 9901,
            requires_password: false,
            name: "Studio Mac".to_string(),
            device_id: Some("604928235".to_string()),
        };
        let encoded_with_id = encode_beacon(&with_id);
        assert_eq!(encoded_with_id.len(), encoded.len() + 10);
        assert_eq!(decode_beacon(&encoded_with_id), Some(with_id));

        // 旧版 v1 载荷（无尾部段）仍可解码且 device_id == None
        assert_eq!(decode_beacon(&encoded).and_then(|b| b.device_id), None);

        // 非法 device_id 在编码时被忽略（不附带尾部段，与 v1 字节数完全一致）
        for bad_id in ["12345678", "1234567890", "604 928 235", "60492823a", ""] {
            let invalid = Beacon {
                instance_id: 42,
                listen_port: 9901,
                requires_password: false,
                name: "BadId".to_string(),
                device_id: Some(bad_id.to_string()),
            };
            let pkt = encode_beacon(&invalid);
            assert_eq!(pkt.len(), BEACON_HEADER_LEN + "BadId".len());
            assert_eq!(decode_beacon(&pkt).and_then(|b| b.device_id), None);
        }

        // 畸形尾部设备码段必须拒绝
        let mut bad_tail_len = encoded_with_id.clone();
        bad_tail_len[encoded.len()] = 8;
        assert_eq!(decode_beacon(&bad_tail_len), None);

        let mut bad_tail_digit = encoded_with_id;
        let tail_last = bad_tail_digit.len() - 1;
        bad_tail_digit[tail_last] = b'x';
        assert_eq!(decode_beacon(&bad_tail_digit), None);

        // 多字节 UTF-8 超长名称（每个中文字符 3 字节，25 个 = 75 字节 > 64）须按字符边界截断至 63 字节。
        let long_name = "兔".repeat(25);
        assert_eq!(long_name.len(), 75);
        let long_beacon = Beacon {
            instance_id: 42,
            listen_port: 19901,
            requires_password: false,
            name: long_name,
            device_id: Some("100200300".to_string()),
        };
        let encoded_long = encode_beacon(&long_beacon);
        let decoded_long = decode_beacon(&encoded_long).expect("truncated beacon should decode");
        assert!(decoded_long.name.len() <= MAX_BEACON_NAME_LEN);
        assert_eq!(decoded_long.name.len(), 63);
        assert_eq!(decoded_long.name, "兔".repeat(21));
        assert!(!decoded_long.requires_password);
        assert_eq!(decoded_long.device_id.as_deref(), Some("100200300"));

        // 非法魔数、错误版本、尾部截断、额外尾字节、非法 UTF-8 均应拒绝。
        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        assert_eq!(decode_beacon(&bad_magic), None);

        let mut bad_ver = encoded.clone();
        bad_ver[4] = 2;
        assert_eq!(decode_beacon(&bad_ver), None);

        assert_eq!(decode_beacon(&encoded[..encoded.len() - 1]), None);

        let mut extra_tail = encoded.clone();
        extra_tail.push(0);
        assert_eq!(decode_beacon(&extra_tail), None);

        let mut bad_utf8 = encoded;
        let last = bad_utf8.len() - 1;
        bad_utf8[last] = 0xFF;
        assert_eq!(decode_beacon(&bad_utf8), None);
    }

    #[test]
    fn peer_table_ignores_self_and_expires_by_injected_clock() {
        let mut table = PeerTable::new(100);
        let ip_a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

        // 自身回环信标必须忽略。
        table.upsert(
            ip_a,
            Beacon {
                instance_id: 100,
                listen_port: 9901,
                requires_password: true,
                name: "Self".to_string(),
                device_id: Some("111222333".to_string()),
            },
            1_000,
        );
        assert!(table.snapshot().is_empty());

        // 端口 0 的无效信标必须忽略。
        table.upsert(
            ip_a,
            Beacon {
                instance_id: 200,
                listen_port: 0,
                requires_password: false,
                name: "ZeroPort".to_string(),
                device_id: None,
            },
            1_000,
        );
        assert!(table.snapshot().is_empty());

        // 正常插入两个远端节点。
        table.upsert(
            ip_b,
            Beacon {
                instance_id: 202,
                listen_port: 9902,
                requires_password: false,
                name: "Beta Mac".to_string(),
                device_id: None,
            },
            1_000,
        );
        table.upsert(
            ip_a,
            Beacon {
                instance_id: 201,
                listen_port: 9901,
                requires_password: true,
                name: "Alpha Mac".to_string(),
                device_id: Some("604928235".to_string()),
            },
            2_500,
        );

        let snap = table.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].name, "Alpha Mac");
        assert_eq!(snap[0].addr, "192.168.1.10:9901");
        assert!(snap[0].requires_password);
        assert_eq!(snap[0].device_id.as_deref(), Some("604928235"));
        assert_eq!(snap[1].name, "Beta Mac");
        assert_eq!(snap[1].addr, "192.168.1.20:9902");
        assert!(!snap[1].requires_password);
        assert_eq!(snap[1].device_id, None);

        // 注入时钟推进到 7_000ms（TTL=6_000ms）：Beta(1_000) 刚好到期被清除，Alpha(2_500) 保留。
        table.prune(7_000, DEFAULT_PEER_TTL_MS);
        let snap2 = table.snapshot();
        assert_eq!(snap2.len(), 1);
        assert_eq!(snap2[0].instance_id, 201);

        // 注入时钟推进到 8_500ms：Alpha(2_500) 也到期清空。
        table.prune(8_500, DEFAULT_PEER_TTL_MS);
        assert!(table.snapshot().is_empty());
    }

    /// 回归测试（U-M3）：开启 `SO_REUSEADDR`/`SO_REUSEPORT` 与多播回环后，
    /// 同一主机上两个发现实例可同时绑定端口 19999 并启用回环接收。
    #[test]
    fn discovery_socket_supports_multi_instance_reuse_and_loopback() {
        let a = DiscoverySocket::bind().expect("first discovery socket");
        let b = DiscoverySocket::bind().expect("second discovery socket");
        assert!(a.can_recv, "首个实例应成功绑定多播端口");
        #[cfg(unix)]
        assert!(
            b.can_recv,
            "Unix 下开启 SO_REUSEPORT 后第二实例也应绑定成功"
        );
        assert!(a.sock.multicast_loop_v4().unwrap_or(false));
        assert!(b.sock.multicast_loop_v4().unwrap_or(false));
    }

    #[test]
    fn peer_table_lookup_addr_normalizes_and_picks_freshest() {
        let mut table = PeerTable::new(100);
        table.upsert(
            IpAddr::V4(Ipv4Addr::new(192, 168, 10, 5)),
            Beacon {
                instance_id: 1,
                listen_port: 9901,
                requires_password: false,
                name: "Old".to_string(),
                device_id: Some("604928235".to_string()),
            },
            1_000,
        );
        table.upsert(
            IpAddr::V4(Ipv4Addr::new(192, 168, 10, 6)),
            Beacon {
                instance_id: 2,
                listen_port: 9902,
                requires_password: true,
                name: "New".to_string(),
                device_id: Some("604928235".to_string()),
            },
            2_000,
        );

        assert_eq!(
            table.lookup_addr("604 928-235"),
            Some("192.168.10.6:9902".parse().unwrap())
        );
        assert_eq!(table.lookup_addr("999999999"), None);
        assert_eq!(table.lookup_addr("bad"), None);
    }

    #[test]
    fn is_usable_lan_ipv4_filters_non_routable_ranges() {
        assert!(!is_usable_lan_ipv4(Ipv4Addr::UNSPECIFIED));
        assert!(!is_usable_lan_ipv4(Ipv4Addr::LOCALHOST));
        assert!(!is_usable_lan_ipv4(Ipv4Addr::new(127, 1, 2, 3)));
        assert!(!is_usable_lan_ipv4(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!is_usable_lan_ipv4(MULTICAST_ADDR));
        assert!(!is_usable_lan_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_usable_lan_ipv4(Ipv4Addr::BROADCAST));

        assert!(is_usable_lan_ipv4(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(is_usable_lan_ipv4(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(is_usable_lan_ipv4(Ipv4Addr::new(172, 16, 0, 5)));
        assert!(is_usable_lan_ipv4(Ipv4Addr::new(198, 51, 100, 10)));
    }

    #[test]
    fn discover_local_lan_ipv4s_filters_targets_and_deduplicates_usable_ips() {
        let skipped_targets: Vec<SocketAddr> = vec![
            "0.0.0.0:9".parse().unwrap(),
            "127.0.0.1:21116".parse().unwrap(),
            "[::ffff:127.0.0.1]:21116".parse().unwrap(),
            "224.0.0.1:9".parse().unwrap(),
            "[::1]:21116".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ];
        let baseline = discover_local_lan_ipv4s(&[]);
        let with_skipped = discover_local_lan_ipv4s(&skipped_targets);
        assert_eq!(with_skipped, baseline);

        for ip in &with_skipped {
            assert!(is_usable_lan_ipv4(*ip));
        }
        let mut unique = with_skipped.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), with_skipped.len());

        let mapped_targets: Vec<SocketAddr> = vec![
            "[::ffff:192.0.2.10]:21116".parse().unwrap(),
            "192.0.2.10:21116".parse().unwrap(),
        ];
        let mapped_res = discover_local_lan_ipv4s(&mapped_targets);
        for ip in &mapped_res {
            assert!(is_usable_lan_ipv4(*ip));
        }
        let mut mapped_unique = mapped_res.clone();
        mapped_unique.sort_unstable();
        mapped_unique.dedup();
        assert_eq!(mapped_unique.len(), mapped_res.len());

        assert_eq!(
            detect_local_lan_ipv4(),
            detect_local_lan_ipv4_for_targets(&[])
        );
        assert_eq!(detect_local_lan_ipv4(), baseline.into_iter().next());
    }

    #[test]
    fn clear_and_refresh_immediately_clears_peers_and_advances_generation() {
        let mut handle = LanDiscoveryHandle::spawn(100, "Test Host".to_string());

        // 预置旧网段缓存节点。
        handle
            .shared
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upsert(
                IpAddr::V4(Ipv4Addr::new(192, 168, 88, 42)),
                Beacon {
                    instance_id: 201,
                    listen_port: 9901,
                    requires_password: true,
                    name: "Old LAN Peer".to_string(),
                    device_id: Some("604928235".to_string()),
                },
                1_000,
            );
        assert_eq!(handle.peers().len(), 1);
        assert_eq!(
            handle.lookup_lan_addr("604928235"),
            Some("192.168.88.42:9901".parse().unwrap())
        );
        assert_eq!(handle.shared.refresh_gen.load(Ordering::Acquire), 0);

        // 调用 clear_and_refresh 必须同步清空缓存并递增刷新代次。
        handle.clear_and_refresh();
        assert!(handle.peers().is_empty());
        assert_eq!(handle.lookup_lan_addr("604928235"), None);
        assert_eq!(handle.shared.refresh_gen.load(Ordering::Acquire), 1);

        // 等待后台线程在下一个短周期内消化刷新代次（远小于 5s 周期复检）。
        let deadline = Instant::now() + Duration::from_secs(2);
        while handle.shared.refresh_applied_gen.load(Ordering::Acquire) < 1
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            handle.shared.refresh_applied_gen.load(Ordering::Acquire),
            1,
            "后台发现线程应在切网刷新后迅速消费 refresh_gen"
        );

        // 连续二次刷新应继续单调推进代次并再次被消费。
        handle.clear_and_refresh();
        assert_eq!(handle.shared.refresh_gen.load(Ordering::Acquire), 2);
        let deadline2 = Instant::now() + Duration::from_secs(2);
        while handle.shared.refresh_applied_gen.load(Ordering::Acquire) < 2
            && Instant::now() < deadline2
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(handle.shared.refresh_applied_gen.load(Ordering::Acquire), 2);

        handle.stop();
    }

    #[test]
    fn os_interface_parsers_collect_multi_nic_vpn_v4_and_only_global_v6() {
        let mac_sample = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet6 fe80::a1b2:c3ff:fe01:203%en0 prefixlen 64 secured scopeid 0x6
\tinet6 fd12:3456:789a::10 prefixlen 64
\tinet6 2408:8207:1901:1111::1 prefixlen 64 deprecated
\tinet6 2408:8207:1901:1111::42 prefixlen 64 autoconf temporary
\tinet 192.168.50.10 netmask 0xffffff00 broadcast 192.168.50.255
\tstatus: active
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.20.30.40 netmask 0xffffff00 broadcast 10.20.30.255
\tstatus: inactive
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420
\tinet 100.64.12.34 --> 100.64.12.34 netmask 0xffffffff
\tinet 172.24.8.9 --> 172.24.8.1 netmask 0xffff0000
";
        let mac_ips = parse_macos_ifconfig_output(mac_sample);
        assert_eq!(
            mac_ips.ipv4s,
            vec![
                Ipv4Addr::new(192, 168, 50, 10),
                Ipv4Addr::new(100, 64, 12, 34),
                Ipv4Addr::new(172, 24, 8, 9),
            ]
        );
        assert_eq!(
            mac_ips.global_ipv6s,
            vec!["2408:8207:1901:1111::42".parse::<Ipv6Addr>().unwrap()]
        );

        let linux_ip_sample = "\
1: lo    inet 127.0.0.1/8 scope host lo
1: lo    inet6 ::1/128 scope host
2: eth0    inet 192.168.10.25/24 brd 192.168.10.255 scope global eth0
2: eth0    inet6 2409:8a00:1:2::99/64 scope global dynamic
2: eth0    inet6 fe80::1234/64 scope link
3: wg0    inet 10.88.0.2/24 scope global wg0
3: wg0    inet6 fd00:10::2/64 scope global
";
        let linux_ips = parse_linux_ip_addr_show(linux_ip_sample);
        assert_eq!(
            linux_ips.ipv4s,
            vec![Ipv4Addr::new(192, 168, 10, 25), Ipv4Addr::new(10, 88, 0, 2)]
        );
        assert_eq!(
            linux_ips.global_ipv6s,
            vec!["2409:8a00:1:2::99".parse::<Ipv6Addr>().unwrap()]
        );

        let proc_v6 = "\
00000000000000000000000000000001 01 80 10 80       lo
fe800000000000000000000000000001 02 40 20 80     eth0
fd000000000000000000000000000002 02 40 00 80     eth0
20010db8000000000000000000000001 02 40 00 20     eth0
24088207000100020000000000000088 02 40 00 00     eth0
";
        assert_eq!(
            parse_proc_if_inet6(proc_v6),
            vec!["2408:8207:1:2::88".parse::<Ipv6Addr>().unwrap()]
        );

        let win_sample = "\
Ethernet adapter Ethernet:
   IPv6 Address. . . . . . . . . . . : 240e:3b0:1234::77(Preferred)
   Link-local IPv6 Address . . . . . : fe80::1234:5678%12(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.1.55(Preferred)
   Autoconfiguration IPv4 Address. . : 169.254.11.22(Preferred)

Unknown adapter Tailscale:
   IPv6 Address. . . . . . . . . . . : fd7a:115c:a1e0::1(Preferred)
   IPv4 Address. . . . . . . . . . . : 100.64.5.9(Preferred)

Loopback Pseudo-Interface 1:
   IPv4 Address. . . . . . . . . . . : 127.0.0.1
   IPv6 Address. . . . . . . . . . . : ::1
";
        let win_ips = parse_windows_ipconfig_output(win_sample);
        assert_eq!(
            win_ips.ipv4s,
            vec![Ipv4Addr::new(192, 168, 1, 55), Ipv4Addr::new(100, 64, 5, 9)]
        );
        assert_eq!(
            win_ips.global_ipv6s,
            vec!["240e:3b0:1234::77".parse::<Ipv6Addr>().unwrap()]
        );
    }

    #[test]
    fn detect_local_interface_ips_filters_invalid_and_matches_primary() {
        let ips = detect_local_interface_ips();
        for ip in &ips.ipv4s {
            assert!(is_usable_lan_ipv4(*ip));
        }
        for v6 in &ips.global_ipv6s {
            assert!(crate::nat::is_global_unicast_ipv6(*v6));
        }
        if let Some(primary) = detect_local_lan_ipv4() {
            assert_eq!(ips.ipv4s.first().copied(), Some(primary));
        }
    }
}
