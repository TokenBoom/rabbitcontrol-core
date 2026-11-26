//! 跨平台 UPnP IGD（v2/v1）与 NAT-PMP（RFC 6886）自动 UDP 端口映射模块。
//!
//! 零外部协议 crate 依赖，纯安全 Rust（`#![deny(unsafe_code)]`、`#![deny(missing_docs)]`），
//! 100% 跨平台（Linux / macOS / Windows）。核心特性：
//! - 优先通过 SSDP `M-SEARCH` 发现局域网 UPnP IGD 网关（`WANIPConnection:2` → `WANIPConnection:1` → `WANPPPConnection:1`）；
//! - 严格 **SSRF 防护**：仅允许 `http://` 协议且目标为局域网私有 IPv4（RFC 1918 或非云元数据链路本地）的 `LOCATION` 与 `controlURL`，拒绝公网、回环及域名；
//! - 严格 **CGNAT / 内网假外网拦截**：[`is_public_ipv4`] 拒绝 RFC 1918、CGNAT（`100.64.0.0/10`）、回环、链路本地、保留与文档网段；
//! - 端口冲突自动回退：首试与 `internal_port` 同号，失败后再试动态分配 `0` 或随机高位端口（`30000..60000`）；
//! - UPnP IGD 失败时自动回退 NAT-PMP（RFC 6886，UDP 5351）；
//! - 支持基于租约元数据的续租（[`renew_udp_mapping`]）与尽力退租（[`unmap_udp_port`]）。

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use rand::Rng;

/// SSDP 多播地址（`239.255.255.250:1900`）。
const SSDP_MULTICAST_ADDR: SocketAddrV4 =
    SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);

/// NAT-PMP 默认网关端口（RFC 6886）。
const NAT_PMP_PORT: u16 = 5351;

/// HTTP 响应最大读取字节上限（512 KiB，防止异常局域网设备耗尽内存）。
const MAX_HTTP_RESPONSE_BYTES: usize = 512 * 1024;

/// SSDP 发现阶段最多保留的候选 `LOCATION` 条目数，防止局域网洪泛响应耗尽内存与超时预算。
const MAX_SSDP_LOCATIONS: usize = 32;

/// 单次 XML 标签块提取上限，防止恶意超大响应触发过度分配或扫描。
const MAX_XML_BLOCKS: usize = 64;

/// 端口冲突回退时随机高位端口区间下界（含）。
const FALLBACK_PORT_MIN: u16 = 30_000;

/// 端口冲突回退时随机高位端口区间上界（不含）。
const FALLBACK_PORT_MAX: u16 = 60_000;

/// UPnP IGD 支持的按优先级排序的服务类型。
const UPNP_SERVICE_TYPES: &[(&str, UpnpProtocol)] = &[
    (
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        UpnpProtocol::UpnpIgdV2,
    ),
    (
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        UpnpProtocol::UpnpIgdV1,
    ),
    (
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        UpnpProtocol::UpnpIgdV1,
    ),
];

/// SSDP `M-SEARCH` 广播使用的搜索目标列表。
const SSDP_SEARCH_TARGETS: &[&str] = &[
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
];

/// 端口映射所使用的网关协商协议类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpnpProtocol {
    /// UPnP Internet Gateway Device v1（`WANIPConnection:1` / `WANPPPConnection:1`）。
    UpnpIgdV1,
    /// UPnP Internet Gateway Device v2（`WANIPConnection:2`）。
    UpnpIgdV2,
    /// NAT Port Mapping Protocol（RFC 6886）。
    NatPmp,
}

impl UpnpProtocol {
    /// 返回协议的标准可读标识字符串（`"upnp_igd_v1"` / `"upnp_igd_v2"` / `"nat_pmp"`）。
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UpnpIgdV1 => "upnp_igd_v1",
            Self::UpnpIgdV2 => "upnp_igd_v2",
            Self::NatPmp => "nat_pmp",
        }
    }
}

/// 客户端当前 UPnP / NAT-PMP 端口映射状态快照（面向 IPC 与设置页展示）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpnpStatus {
    /// 用户已关闭自动端口映射。
    Disabled,
    /// 正在探测局域网网关并协商端口映射。
    Discovering,
    /// 已成功建立公网 UDP 端口映射。
    Mapped {
        /// 网关分配的公网地址（`ip:port`）。
        external_addr: String,
        /// 生效协议名称（如 `"upnp_igd_v2"` / `"upnp_igd_v1"` / `"nat_pmp"`）。
        protocol: String,
    },
    /// 网关不支持、处于 CGNAT 后方或映射失败。
    Unavailable {
        /// 不可用原因说明。
        reason: String,
    },
}

/// 租约关联的私有网关信息（用于续租与退租，避免重复 SSDP 发现）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum LeaseGateway {
    UpnpIgd {
        control_host: Ipv4Addr,
        control_port: u16,
        control_path: String,
        service_type: String,
        internal_client: Ipv4Addr,
    },
    NatPmp {
        gateway_addr: SocketAddrV4,
    },
}

/// 网关协商成功的 UDP 端口映射租约（持有续租与退租所需私有网关信息）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpnpMappingLease {
    /// 映射后的公网 UDP 地址（经 [`is_public_ipv4`] 校验通过）。
    pub external_addr: SocketAddr,
    /// 本机局域网监听端口。
    pub internal_port: u16,
    /// 网关侧对外暴露端口。
    pub external_port: u16,
    /// 建立本租约所使用的协议类型。
    pub protocol: UpnpProtocol,
    gateway: LeaseGateway,
}

/// 校验一个 IPv4 地址是否为可路由的全球公网单播地址。
///
/// 严格拒绝以下全部非公网网段：
/// - `0.0.0.0/8`（未指定 / 本网络，RFC 1122）
/// - `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`（RFC 1918 私有网段）
/// - `100.64.0.0/10`（RFC 6598 运营商级 NAT / CGNAT）
/// - `127.0.0.0/8`（回环地址）
/// - `169.254.0.0/16`（链路本地地址）
/// - `192.0.0.0/24`（IETF 协议保留）
/// - `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`（RFC 5737 文档网段）
/// - `192.88.99.0/24`（废弃 6to4 中继任播）
/// - `198.18.0.0/15`（RFC 2544 基准测试网段）
/// - `224.0.0.0/4`（多播）与 `240.0.0.0/4`（未来保留及 `255.255.255.255` 广播）
pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();
    if a == 0 {
        return false;
    }
    if a == 10 {
        return false;
    }
    if a == 100 && (b & 0xC0) == 64 {
        return false;
    }
    if a == 127 {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && b == 0 && (c == 0 || c == 2) {
        return false;
    }
    if a == 192 && b == 88 && c == 99 {
        return false;
    }
    if a == 192 && b == 168 {
        return false;
    }
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    if a == 198 && b == 51 && c == 100 {
        return false;
    }
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    if a >= 224 {
        return false;
    }
    true
}

/// 校验一个 IPv4 地址是否为合法的局域网网关地址（RFC 1918 或非云元数据链路本地）。
fn is_lan_gateway_ipv4(ip: Ipv4Addr, allow_loopback: bool) -> bool {
    if allow_loopback && ip.is_loopback() {
        return true;
    }
    if ip.is_private() {
        return true;
    }
    // 允许常规链路本地地址，但显式拒绝常见云厂商 IMDS 元数据地址 `169.254.169.254`。
    ip.is_link_local() && ip != Ipv4Addr::new(169, 254, 169, 254)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedHttpUrl {
    host: Ipv4Addr,
    port: u16,
    path: String,
}

/// 严格解析并执行 SSRF 校验的 HTTP URL 解析器。
///
/// 要求：
/// 1. 仅允许 `http://` 协议；
/// 2. 禁止控制字符、空白字符与 `@`（userinfo 注入）；
/// 3. 主机必须为字面量 IPv4（拒绝域名以防 DNS Rebinding）且通过 [`is_lan_gateway_ipv4`] 校验。
fn parse_and_validate_location_url(
    raw: &str,
    allow_loopback: bool,
) -> Result<ParsedHttpUrl, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("LOCATION URL 为空".to_string());
    }
    if trimmed
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("LOCATION URL 包含非法空白或控制字符".to_string());
    }

    let scheme_end = trimmed
        .find("://")
        .ok_or_else(|| "LOCATION URL 缺少协议头".to_string())?;
    let scheme = &trimmed[..scheme_end];
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(format!("SSRF 防护拦截：仅允许 http 协议，拒绝 {scheme:?}"));
    }

    let after_scheme = &trimmed[scheme_end + 3..];
    let after_scheme = after_scheme.split('#').next().unwrap_or(after_scheme);
    let authority_end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.contains('[') {
        return Err(format!("SSRF 防护拦截：非法主机 authority {authority:?}"));
    }

    let (host_str, port) = match authority.rsplit_once(':') {
        Some((h, p_str)) => {
            let p: u16 = p_str
                .parse()
                .map_err(|_| format!("LOCATION 端口无效：{p_str:?}"))?;
            if p == 0 {
                return Err("LOCATION 端口不能为 0".to_string());
            }
            (h, p)
        }
        None => (authority, 80),
    };

    let host: Ipv4Addr = host_str.parse().map_err(|_| {
        format!("SSRF 防护拦截：LOCATION 主机必须为 IPv4 字面量，拒绝 {host_str:?}")
    })?;
    if !is_lan_gateway_ipv4(host, allow_loopback) {
        return Err(format!(
            "SSRF 防护拦截：LOCATION 主机 {host} 非局域网私有 IPv4"
        ));
    }

    let rest = &after_scheme[authority_end..];
    let path = if rest.is_empty() {
        "/".to_string()
    } else if rest.starts_with('?') {
        format!("/{rest}")
    } else {
        rest.to_string()
    };

    Ok(ParsedHttpUrl { host, port, path })
}

/// 将设备描述 XML 中的 `controlURL`（支持绝对 URL、根相对路径或目录相对路径）解析并校验为安全目标。
fn resolve_control_url(
    base: &ParsedHttpUrl,
    url_base_raw: Option<&str>,
    control_url: &str,
    allow_loopback: bool,
) -> Result<ParsedHttpUrl, String> {
    let trimmed = control_url.trim();
    if trimmed.is_empty() {
        return Err("controlURL 为空".to_string());
    }
    if trimmed
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("controlURL 包含非法字符".to_string());
    }

    let effective_base = match url_base_raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(ub) => {
            let parsed = parse_and_validate_location_url(ub, allow_loopback)?;
            if parsed.host != base.host {
                return Err(format!(
                    "SSRF 防护拦截：URLBase 主机 {} 与 LOCATION 主机 {} 不一致",
                    parsed.host, base.host
                ));
            }
            parsed
        }
        None => base.clone(),
    };

    if trimmed.contains("://") {
        let parsed = parse_and_validate_location_url(trimmed, allow_loopback)?;
        if parsed.host != base.host {
            return Err(format!(
                "SSRF 防护拦截：controlURL 主机 {} 与 LOCATION 主机 {} 不一致",
                parsed.host, base.host
            ));
        }
        return Ok(parsed);
    }

    let resolved_path = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        let base_no_query = effective_base
            .path
            .split('?')
            .next()
            .unwrap_or(&effective_base.path);
        let dir = match base_no_query.rfind('/') {
            Some(pos) => &base_no_query[..=pos],
            None => "/",
        };
        format!("{dir}{trimmed}")
    };

    Ok(ParsedHttpUrl {
        host: effective_base.host,
        port: effective_base.port,
        path: resolved_path,
    })
}

/// 尝试为本机 `internal_port` 申请公网 UDP 端口映射（租期 `lease_secs` 秒）。
///
/// 优先尝试 UPnP IGD（`WANIPConnection:2` / `WANIPConnection:1` / `WANPPPConnection:1`），
/// 失败时自动回退 NAT-PMP（RFC 6886）。若网关处于 CGNAT 后方或返回非公网 IP，
/// 将明确返回错误而不产生无效映射。
pub fn map_udp_port(
    internal_port: u16,
    lease_secs: u32,
    timeout: Duration,
) -> Result<UpnpMappingLease, String> {
    let nat_pmp_gateways = discover_nat_pmp_gateways();
    map_udp_port_internal(
        internal_port,
        lease_secs,
        timeout,
        SocketAddr::V4(SSDP_MULTICAST_ADDR),
        &nat_pmp_gateways,
        false,
    )
}

/// 使用已有租约中的私有网关元数据续租 UDP 端口映射（无需重跑 SSDP 发现）。
pub fn renew_udp_mapping(
    lease: &UpnpMappingLease,
    lease_secs: u32,
    timeout: Duration,
) -> Result<UpnpMappingLease, String> {
    if lease.internal_port == 0 {
        return Err("内部端口不能为 0".to_string());
    }
    let deadline = Instant::now() + timeout.max(Duration::from_millis(50));

    match &lease.gateway {
        LeaseGateway::UpnpIgd {
            control_host,
            control_port,
            control_path,
            service_type,
            internal_client,
        } => {
            let ext_ip = soap_get_external_ip(
                *control_host,
                *control_port,
                control_path,
                service_type,
                deadline,
            )?;
            if !is_public_ipv4(ext_ip) {
                return Err(format!(
                    "UPnP 网关返回非公网 IP（疑似 CGNAT 或双层 NAT）：{ext_ip}"
                ));
            }
            let mapped_ext_port = soap_add_port_mapping_with_fallback(
                *control_host,
                *control_port,
                control_path,
                service_type,
                *internal_client,
                lease.internal_port,
                lease.external_port,
                lease_secs,
                deadline,
            )?;
            Ok(UpnpMappingLease {
                external_addr: SocketAddr::V4(SocketAddrV4::new(ext_ip, mapped_ext_port)),
                internal_port: lease.internal_port,
                external_port: mapped_ext_port,
                protocol: lease.protocol,
                gateway: lease.gateway.clone(),
            })
        }
        LeaseGateway::NatPmp { gateway_addr } => nat_pmp_map_udp(
            *gateway_addr,
            lease.internal_port,
            lease.external_port,
            lease_secs,
            deadline,
        ),
    }
}

/// 尽力释放已申请的 UDP 端口映射（UPnP `DeletePortMapping` 或 NAT-PMP `lifetime = 0`）。
///
/// 失败时静默忽略，绝不阻塞超过 `timeout`。
pub fn unmap_udp_port(lease: &UpnpMappingLease, timeout: Duration) {
    let deadline = Instant::now() + timeout.max(Duration::from_millis(50));
    match &lease.gateway {
        LeaseGateway::UpnpIgd {
            control_host,
            control_port,
            control_path,
            service_type,
            ..
        } => {
            let body = format!(
                "<NewRemoteHost></NewRemoteHost>\
                 <NewExternalPort>{}</NewExternalPort>\
                 <NewProtocol>UDP</NewProtocol>",
                lease.external_port
            );
            let _ = send_soap_request(
                *control_host,
                *control_port,
                control_path,
                service_type,
                "DeletePortMapping",
                &body,
                deadline,
            );
        }
        LeaseGateway::NatPmp { gateway_addr } => {
            let _ = nat_pmp_unmap_udp(*gateway_addr, lease.internal_port, deadline);
        }
    }
}

fn remaining_timeout(deadline: Instant) -> Result<Duration, String> {
    let now = Instant::now();
    if now >= deadline {
        return Err("UPnP / NAT-PMP 操作超时".to_string());
    }
    Ok(deadline.saturating_duration_since(now))
}

fn map_udp_port_internal(
    internal_port: u16,
    lease_secs: u32,
    timeout: Duration,
    ssdp_target: SocketAddr,
    nat_pmp_gateways: &[SocketAddrV4],
    allow_loopback: bool,
) -> Result<UpnpMappingLease, String> {
    if internal_port == 0 {
        return Err("内部端口不能为 0".to_string());
    }
    let eff_timeout = timeout.max(Duration::from_millis(50));
    let total_deadline = Instant::now() + eff_timeout;

    // 1) 优先 UPnP IGD（分配约 65% 时间预算给 SSDP + 描述拉取 + SOAP，若失败立即转入 NAT-PMP）
    let upnp_budget = if nat_pmp_gateways.is_empty() {
        eff_timeout
    } else {
        eff_timeout.mul_f32(0.65).max(Duration::from_millis(40))
    };
    let upnp_deadline = (Instant::now() + upnp_budget).min(total_deadline);
    let upnp_err = match try_upnp_igd_map(
        internal_port,
        lease_secs,
        ssdp_target,
        upnp_deadline,
        allow_loopback,
    ) {
        Ok(lease) => return Ok(lease),
        Err(err) => err,
    };

    // 2) 回退 NAT-PMP（RFC 6886）
    if nat_pmp_gateways.is_empty() {
        return Err(format!(
            "UPnP IGD 失败（{upnp_err}），且未探测到可用的 NAT-PMP 局域网网关"
        ));
    }

    let mut last_pmp_err = String::new();
    for &gw in nat_pmp_gateways {
        if !is_lan_gateway_ipv4(*gw.ip(), allow_loopback) {
            continue;
        }
        if Instant::now() >= total_deadline {
            last_pmp_err = "NAT-PMP 探测超时".to_string();
            break;
        }
        match nat_pmp_map_udp(gw, internal_port, internal_port, lease_secs, total_deadline) {
            Ok(lease) => return Ok(lease),
            Err(err) => last_pmp_err = err,
        }
    }

    Err(format!(
        "UPnP IGD 失败（{upnp_err}）；NAT-PMP 失败（{last_pmp_err}）"
    ))
}

fn try_upnp_igd_map(
    internal_port: u16,
    lease_secs: u32,
    ssdp_target: SocketAddr,
    deadline: Instant,
    allow_loopback: bool,
) -> Result<UpnpMappingLease, String> {
    let ssdp_budget = remaining_timeout(deadline)?
        .mul_f32(0.45)
        .max(Duration::from_millis(30));
    let ssdp_deadline = (Instant::now() + ssdp_budget).min(deadline);

    let candidates = ssdp_discover_locations(ssdp_target, ssdp_deadline)?;
    if candidates.is_empty() {
        return Err("SSDP 未发现支持 UPnP IGD 的网关".to_string());
    }

    let mut last_err = String::from("未找到有效的 UPnP IGD 网关");
    for location in candidates {
        if Instant::now() >= deadline {
            return Err("UPnP IGD 协商超时".to_string());
        }
        let loc_url = match parse_and_validate_location_url(&location, allow_loopback) {
            Ok(u) => u,
            Err(err) => {
                last_err = err;
                continue;
            }
        };

        let (xml_body, local_ip) = match http_get_xml(&loc_url, deadline) {
            Ok(v) => v,
            Err(err) => {
                last_err = err;
                continue;
            }
        };

        let service = match parse_igd_service_from_xml(&xml_body, &loc_url, allow_loopback) {
            Ok(svc) => svc,
            Err(err) => {
                last_err = err;
                continue;
            }
        };

        let ext_ip = match soap_get_external_ip(
            service.control.host,
            service.control.port,
            &service.control.path,
            &service.service_type,
            deadline,
        ) {
            Ok(ip) => ip,
            Err(err) => {
                last_err = err;
                continue;
            }
        };

        if !is_public_ipv4(ext_ip) {
            last_err = format!("UPnP 网关返回非公网 IP（疑似 CGNAT 或双层 NAT）：{ext_ip}");
            continue;
        }

        let internal_client =
            resolve_local_ipv4_for_peer(service.control.host, service.control.port)
                .unwrap_or(local_ip);

        let mapped_ext_port = match soap_add_port_mapping_with_fallback(
            service.control.host,
            service.control.port,
            &service.control.path,
            &service.service_type,
            internal_client,
            internal_port,
            internal_port,
            lease_secs,
            deadline,
        ) {
            Ok(p) => p,
            Err(err) => {
                last_err = err;
                continue;
            }
        };

        return Ok(UpnpMappingLease {
            external_addr: SocketAddr::V4(SocketAddrV4::new(ext_ip, mapped_ext_port)),
            internal_port,
            external_port: mapped_ext_port,
            protocol: service.protocol,
            gateway: LeaseGateway::UpnpIgd {
                control_host: service.control.host,
                control_port: service.control.port,
                control_path: service.control.path,
                service_type: service.service_type,
                internal_client,
            },
        });
    }

    Err(last_err)
}

fn ssdp_discover_locations(
    ssdp_target: SocketAddr,
    deadline: Instant,
) -> Result<Vec<String>, String> {
    let bind_addr = if ssdp_target.ip().is_loopback() {
        SocketAddr::from(([127, 0, 0, 1], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("绑定 SSDP UDP 套接字失败：{e}"))?;
    let mx = remaining_timeout(deadline)?.as_secs().clamp(1, 3);
    let host_header = if ssdp_target.ip().is_loopback() {
        ssdp_target.to_string()
    } else {
        "239.255.255.250:1900".to_string()
    };

    let mut sent_any = false;
    for st in SSDP_SEARCH_TARGETS {
        let req = format!(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: {host_header}\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: {mx}\r\n\
             ST: {st}\r\n\
             \r\n"
        );
        if sock.send_to(req.as_bytes(), ssdp_target).is_ok() {
            sent_any = true;
        }
    }
    if !sent_any {
        return Err("发送 SSDP M-SEARCH 请求失败".to_string());
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut ranked: Vec<(u8, String)> = Vec::new();
    let mut buf = [0u8; 4096];
    let mut first_hit_at: Option<Instant> = None;

    loop {
        let now = Instant::now();
        // 收到首个响应后仅再短等最多 40ms 收集可能更优的 v2 响应，避免白白耗尽整个超时预算。
        let effective_deadline = match first_hit_at {
            Some(t) => (t + Duration::from_millis(40)).min(deadline),
            None => deadline,
        };
        if now >= effective_deadline {
            break;
        }
        let wait = effective_deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(100));
        let _ = sock.set_read_timeout(Some(wait.max(Duration::from_millis(1))));

        match sock.recv_from(&mut buf) {
            Ok((n, _src)) => {
                if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                    if let Some((rank, loc)) = parse_ssdp_response_location(text) {
                        if seen.insert(loc.clone()) {
                            ranked.push((rank, loc));
                            if first_hit_at.is_none() {
                                first_hit_at = Some(Instant::now());
                            }
                            if ranked.len() >= MAX_SSDP_LOCATIONS {
                                break;
                            }
                        }
                    }
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if first_hit_at.is_some() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    ranked.sort_by_key(|(rank, _)| *rank);
    Ok(ranked.into_iter().map(|(_, loc)| loc).collect())
}

fn parse_ssdp_response_location(resp: &str) -> Option<(u8, String)> {
    let mut location: Option<String> = None;
    let mut st_rank: u8 = 3;
    for line in resp.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("location") && !val.is_empty() {
                location = Some(val.to_string());
            } else if key.eq_ignore_ascii_case("st") {
                if val.contains("WANIPConnection:2") {
                    st_rank = 0;
                } else if val.contains("WANIPConnection:1") {
                    st_rank = 1;
                } else if val.contains("WANPPPConnection:1") {
                    st_rank = 2;
                }
            }
        }
    }
    location.map(|loc| (st_rank, loc))
}

#[derive(Debug, Clone)]
struct HttpResponse {
    status_code: u16,
    body: String,
    local_ip: Option<Ipv4Addr>,
}

fn http_request(
    host: Ipv4Addr,
    port: u16,
    raw_request: &[u8],
    deadline: Instant,
) -> Result<HttpResponse, String> {
    let rem = remaining_timeout(deadline)?;
    let addr = SocketAddr::V4(SocketAddrV4::new(host, port));
    let mut stream =
        TcpStream::connect_timeout(&addr, rem).map_err(|e| format!("连接网关 {addr} 失败：{e}"))?;
    let local_ip = match stream.local_addr().ok().map(|a| a.ip()) {
        Some(IpAddr::V4(v4)) => Some(v4),
        _ => None,
    };

    let io_rem = remaining_timeout(deadline)?;
    let _ = stream.set_write_timeout(Some(io_rem));
    let _ = stream.set_read_timeout(Some(io_rem));

    stream
        .write_all(raw_request)
        .map_err(|e| format!("向网关 {addr} 写入 HTTP 请求失败：{e}"))?;

    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut header_end: Option<usize> = None;
    let mut expected_content_len: Option<usize> = None;
    let mut is_chunked = false;

    loop {
        let now = Instant::now();
        if now >= deadline {
            if raw.is_empty() {
                return Err(format!("读取网关 {addr} HTTP 响应超时"));
            }
            break;
        }
        let step_timeout = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(200));
        let _ = stream.set_read_timeout(Some(step_timeout.max(Duration::from_millis(1))));

        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let take = n.min(MAX_HTTP_RESPONSE_BYTES.saturating_sub(raw.len()));
                raw.extend_from_slice(&chunk[..take]);
                if header_end.is_none() {
                    if let Some(pos) = find_subslice(&raw, b"\r\n\r\n") {
                        let end = pos + 4;
                        header_end = Some(end);
                        let hdr_text = String::from_utf8_lossy(&raw[..pos]);
                        for line in hdr_text.lines().skip(1) {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    expected_content_len = v.trim().parse::<usize>().ok();
                                } else if k.trim().eq_ignore_ascii_case("transfer-encoding")
                                    && v.to_ascii_lowercase().contains("chunked")
                                {
                                    is_chunked = true;
                                }
                            }
                        }
                    }
                }
                if let (Some(h_end), Some(cl)) = (header_end, expected_content_len) {
                    if raw.len().saturating_sub(h_end) >= cl {
                        break;
                    }
                }
                if is_chunked {
                    if let Some(h_end) = header_end {
                        if decode_chunked_body(&raw[h_end..]).is_some() {
                            break;
                        }
                    }
                }
                if raw.len() >= MAX_HTTP_RESPONSE_BYTES {
                    break;
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if header_end.is_some() && expected_content_len.is_none() && !is_chunked {
                    break;
                }
            }
            Err(err) => {
                if raw.is_empty() {
                    return Err(format!("读取网关 {addr} HTTP 响应失败：{err}"));
                }
                break;
            }
        }
    }

    let h_end = header_end.ok_or_else(|| "网关 HTTP 响应缺少头部结束标记".to_string())?;
    let header_str = String::from_utf8_lossy(&raw[..h_end - 4]);
    let status_line = header_str
        .lines()
        .next()
        .ok_or_else(|| "网关 HTTP 响应缺少状态行".to_string())?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("无法解析 HTTP 状态行：{status_line:?}"))?;

    let body_slice = &raw[h_end..];
    let body_bytes = if is_chunked {
        decode_chunked_body(body_slice).unwrap_or_else(|| body_slice.to_vec())
    } else if let Some(cl) = expected_content_len {
        body_slice[..cl.min(body_slice.len())].to_vec()
    } else {
        body_slice.to_vec()
    };

    Ok(HttpResponse {
        status_code,
        body: String::from_utf8_lossy(&body_bytes).into_owned(),
        local_ip,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn decode_chunked_body(mut input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let crlf = find_subslice(input, b"\r\n")?;
        let size_line = std::str::from_utf8(&input[..crlf]).ok()?;
        let size_hex = size_line.split(';').next()?.trim();
        let chunk_len = usize::from_str_radix(size_hex, 16).ok()?;
        input = &input[crlf + 2..];
        if chunk_len == 0 {
            return Some(out);
        }
        let need = chunk_len.checked_add(2)?;
        if input.len() < need {
            return None;
        }
        let next_total = out.len().checked_add(chunk_len)?;
        if next_total > MAX_HTTP_RESPONSE_BYTES {
            return None;
        }
        out.extend_from_slice(&input[..chunk_len]);
        if &input[chunk_len..need] != b"\r\n" {
            return None;
        }
        input = &input[need..];
    }
}

fn http_get_xml(url: &ParsedHttpUrl, deadline: Instant) -> Result<(String, Ipv4Addr), String> {
    let req = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         User-Agent: RabbitControl/1.0 UPnP/1.1\r\n\
         Connection: close\r\n\
         \r\n",
        url.path, url.host, url.port
    );
    let resp = http_request(url.host, url.port, req.as_bytes(), deadline)?;
    if !(200..300).contains(&resp.status_code) {
        return Err(format!("拉取设备描述 XML 失败：HTTP {}", resp.status_code));
    }
    Ok((
        resp.body,
        resp.local_ip.unwrap_or(Ipv4Addr::new(127, 0, 0, 1)),
    ))
}

#[derive(Debug, Clone)]
struct IgdServiceEndpoint {
    service_type: String,
    protocol: UpnpProtocol,
    control: ParsedHttpUrl,
}

fn parse_igd_service_from_xml(
    xml: &str,
    location: &ParsedHttpUrl,
    allow_loopback: bool,
) -> Result<IgdServiceEndpoint, String> {
    let url_base = extract_xml_tag_value(xml, "URLBase");
    let services = extract_xml_blocks(xml, "service");

    let mut found: Vec<(usize, IgdServiceEndpoint)> = Vec::new();
    let mut last_ctrl_err: Option<String> = None;
    'services: for svc_block in services {
        let Some(svc_type) = extract_xml_tag_value(svc_block, "serviceType") else {
            continue;
        };
        let Some(ctrl_url) = extract_xml_tag_value(svc_block, "controlURL") else {
            continue;
        };
        let svc_type_clean = svc_type.trim();
        for (priority, (expected, proto)) in UPNP_SERVICE_TYPES.iter().enumerate() {
            if svc_type_clean.eq_ignore_ascii_case(expected) {
                let control = match resolve_control_url(
                    location,
                    url_base.as_deref(),
                    &ctrl_url,
                    allow_loopback,
                ) {
                    Ok(c) => c,
                    Err(err) => {
                        last_ctrl_err = Some(err);
                        continue 'services;
                    }
                };
                found.push((
                    priority,
                    IgdServiceEndpoint {
                        service_type: (*expected).to_string(),
                        protocol: *proto,
                        control,
                    },
                ));
                break;
            }
        }
    }

    found.sort_by_key(|(prio, _)| *prio);
    found.into_iter().next().map(|(_, ep)| ep).ok_or_else(|| {
        last_ctrl_err.unwrap_or_else(|| {
            "设备描述 XML 中未找到 WANIPConnection / WANPPPConnection 服务".to_string()
        })
    })
}

/// 从 XML 文本中提取所有匹配指定本地标签名（忽略命名空间前缀与大小写）的元素内部切片。
fn extract_xml_blocks<'a>(xml: &'a str, local_tag: &str) -> Vec<&'a str> {
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    let bytes = xml.as_bytes();
    while cursor < bytes.len() && blocks.len() < MAX_XML_BLOCKS {
        let Some(rel_lt) = xml[cursor..].find('<') else {
            break;
        };
        let open_start = cursor + rel_lt;
        let Some(rel_gt) = xml[open_start..].find('>') else {
            break;
        };
        let open_end = open_start + rel_gt;
        let tag_inner = xml[open_start + 1..open_end].trim();
        if tag_inner.starts_with('/')
            || tag_inner.starts_with('?')
            || tag_inner.starts_with('!')
            || tag_inner.ends_with('/')
        {
            cursor = open_end + 1;
            continue;
        }
        let raw_name = tag_inner
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or("");
        let stripped = raw_name.rsplit(':').next().unwrap_or(raw_name);
        if !stripped.eq_ignore_ascii_case(local_tag) {
            cursor = open_end + 1;
            continue;
        }

        let content_start = open_end + 1;
        let mut search = content_start;
        let mut found_close = None;
        while search < bytes.len() {
            let Some(rel_cl) = xml[search..].find("</") else {
                break;
            };
            let close_start = search + rel_cl;
            let Some(rel_cgt) = xml[close_start..].find('>') else {
                break;
            };
            let close_end = close_start + rel_cgt;
            let close_name = xml[close_start + 2..close_end].trim();
            let close_stripped = close_name.rsplit(':').next().unwrap_or(close_name);
            if close_stripped.eq_ignore_ascii_case(local_tag) {
                found_close = Some((close_start, close_end + 1));
                break;
            }
            search = close_end + 1;
        }

        if let Some((close_start, next_cursor)) = found_close {
            blocks.push(&xml[content_start..close_start]);
            cursor = next_cursor;
        } else {
            // 内层已扫描至文末仍未找到对应闭合标签，后续同名开标签亦不可能闭合，直接退出消除 O(N^2)。
            break;
        }
    }
    blocks
}

fn extract_xml_tag_value(xml: &str, local_tag: &str) -> Option<String> {
    extract_xml_blocks(xml, local_tag)
        .into_iter()
        .next()
        .map(|s| s.trim().to_string())
}

fn send_soap_request(
    host: Ipv4Addr,
    port: u16,
    path: &str,
    service_type: &str,
    action: &str,
    body_xml: &str,
    deadline: Instant,
) -> Result<HttpResponse, String> {
    let envelope = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{service_type}\">{body_xml}</u:{action}></s:Body>\
         </s:Envelope>"
    );
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         Content-Length: {}\r\n\
         SOAPACTION: \"{service_type}#{action}\"\r\n\
         Connection: close\r\n\
         \r\n\
         {envelope}",
        envelope.len()
    );
    http_request(host, port, req.as_bytes(), deadline)
}

fn format_soap_fault(resp: &HttpResponse, action: &str) -> (Option<u32>, String) {
    let code = extract_xml_tag_value(&resp.body, "errorCode").and_then(|s| s.parse::<u32>().ok());
    let desc = extract_xml_tag_value(&resp.body, "errorDescription");
    let msg = match (code, desc) {
        (Some(c), Some(d)) => format!(
            "SOAP {action} 失败（HTTP {}, UPnP 错误 {c}: {d}）",
            resp.status_code
        ),
        (Some(c), None) => format!(
            "SOAP {action} 失败（HTTP {}, UPnP 错误 {c}）",
            resp.status_code
        ),
        _ => format!("SOAP {action} 失败（HTTP {}）", resp.status_code),
    };
    (code, msg)
}

fn soap_get_external_ip(
    host: Ipv4Addr,
    port: u16,
    path: &str,
    service_type: &str,
    deadline: Instant,
) -> Result<Ipv4Addr, String> {
    let resp = send_soap_request(
        host,
        port,
        path,
        service_type,
        "GetExternalIPAddress",
        "",
        deadline,
    )?;
    if !(200..300).contains(&resp.status_code) {
        let (_, msg) = format_soap_fault(&resp, "GetExternalIPAddress");
        return Err(msg);
    }
    let ip_str = extract_xml_tag_value(&resp.body, "NewExternalIPAddress")
        .ok_or_else(|| "GetExternalIPAddress 响应缺少 NewExternalIPAddress 字段".to_string())?;
    ip_str
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("GetExternalIPAddress 返回非法 IPv4：{ip_str:?}"))
}

#[allow(clippy::too_many_arguments)]
fn soap_add_port_mapping_once(
    host: Ipv4Addr,
    port: u16,
    path: &str,
    service_type: &str,
    internal_client: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    lease_secs: u32,
    deadline: Instant,
) -> Result<u16, (Option<u32>, String)> {
    let body = format!(
        "<NewRemoteHost></NewRemoteHost>\
         <NewExternalPort>{external_port}</NewExternalPort>\
         <NewProtocol>UDP</NewProtocol>\
         <NewInternalPort>{internal_port}</NewInternalPort>\
         <NewInternalClient>{internal_client}</NewInternalClient>\
         <NewEnabled>1</NewEnabled>\
         <NewPortMappingDescription>RabbitControl</NewPortMappingDescription>\
         <NewLeaseDuration>{lease_secs}</NewLeaseDuration>"
    );
    let resp = send_soap_request(
        host,
        port,
        path,
        service_type,
        "AddPortMapping",
        &body,
        deadline,
    )
    .map_err(|e| (None, e))?;

    if !(200..300).contains(&resp.status_code) {
        return Err(format_soap_fault(&resp, "AddPortMapping"));
    }

    if external_port != 0 {
        return Ok(external_port);
    }

    // 申请动态端口 `0` 时，必须从响应中解析出非零分配端口；否则视为未给出可用端口。
    let assigned = extract_xml_tag_value(&resp.body, "NewReservedPort")
        .or_else(|| extract_xml_tag_value(&resp.body, "NewExternalPort"))
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&p| p > 0);
    assigned.ok_or_else(|| (None, "网关接受动态端口 0 但未返回分配端口号".to_string()))
}

#[allow(clippy::too_many_arguments)]
fn soap_add_port_mapping_with_fallback(
    host: Ipv4Addr,
    port: u16,
    path: &str,
    service_type: &str,
    internal_client: Ipv4Addr,
    internal_port: u16,
    preferred_external_port: u16,
    lease_secs: u32,
    deadline: Instant,
) -> Result<u16, String> {
    let mut effective_lease = lease_secs;
    // 1) 首选与目标一致的外部端口
    match soap_add_port_mapping_once(
        host,
        port,
        path,
        service_type,
        internal_client,
        internal_port,
        preferred_external_port,
        effective_lease,
        deadline,
    ) {
        Ok(p) => return Ok(p),
        Err((Some(725), _)) if effective_lease > 0 => {
            // UPnP 725 OnlyPermanentLeasesSupported：降级为永久租期 0 重试
            effective_lease = 0;
            if let Ok(p) = soap_add_port_mapping_once(
                host,
                port,
                path,
                service_type,
                internal_client,
                internal_port,
                preferred_external_port,
                0,
                deadline,
            ) {
                return Ok(p);
            }
        }
        Err(_) => {}
    }

    // 2) 端口冲突或失败：先尝试动态端口 `0`
    if Instant::now() < deadline {
        if let Ok(p) = soap_add_port_mapping_once(
            host,
            port,
            path,
            service_type,
            internal_client,
            internal_port,
            0,
            effective_lease,
            deadline,
        ) {
            return Ok(p);
        }
    }

    // 3) 再尝试最多 3 个随机高位端口（30000..60000）
    let mut rng = rand::thread_rng();
    let mut tried = HashSet::new();
    tried.insert(preferred_external_port);
    let mut last_err = String::from("AddPortMapping 端口冲突且回退失败");

    for _ in 0..3 {
        if Instant::now() >= deadline {
            break;
        }
        let mut candidate = rng.gen_range(FALLBACK_PORT_MIN..FALLBACK_PORT_MAX);
        while !tried.insert(candidate) {
            candidate = rng.gen_range(FALLBACK_PORT_MIN..FALLBACK_PORT_MAX);
        }
        match soap_add_port_mapping_once(
            host,
            port,
            path,
            service_type,
            internal_client,
            internal_port,
            candidate,
            effective_lease,
            deadline,
        ) {
            Ok(p) => return Ok(p),
            Err((_, err)) => last_err = err,
        }
    }

    Err(last_err)
}

/// 借助操作系统路由表查询访问 `peer_ip:peer_port` 时的本机出站 IPv4 地址（零发包、全平台通用）。
fn resolve_local_ipv4_for_peer(peer_ip: Ipv4Addr, peer_port: u16) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).ok()?;
    sock.connect(SocketAddr::V4(SocketAddrV4::new(peer_ip, peer_port.max(1))))
        .ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// 探测本机默认网关作为 NAT-PMP（UDP 5351）候选目标列表。
fn discover_nat_pmp_gateways() -> Vec<SocketAddrV4> {
    let mut ips: Vec<Ipv4Addr> = Vec::new();

    #[cfg(target_os = "linux")]
    if let Some(gw) = parse_linux_default_gateway() {
        if is_lan_gateway_ipv4(gw, false) && !ips.contains(&gw) {
            ips.push(gw);
        }
    }

    if let Some(local_ip) = resolve_local_ipv4_for_peer(Ipv4Addr::new(1, 1, 1, 1), 53) {
        if local_ip.is_private() {
            let [a, b, c, _] = local_ip.octets();
            let dot1 = Ipv4Addr::new(a, b, c, 1);
            if dot1 != local_ip && !ips.contains(&dot1) {
                ips.push(dot1);
            }
            if c != 0 && (a == 10 || (a == 172 && (16..=31).contains(&b))) {
                let net1 = Ipv4Addr::new(a, b, 0, 1);
                if net1 != local_ip && !ips.contains(&net1) {
                    ips.push(net1);
                }
            }
        }
    }

    ips.into_iter()
        .map(|ip| SocketAddrV4::new(ip, NAT_PMP_PORT))
        .collect()
}

#[cfg(target_os = "linux")]
fn parse_linux_default_gateway() -> Option<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && cols[1] == "00000000" {
            let raw = u32::from_str_radix(cols[2], 16).ok()?;
            let ip = Ipv4Addr::from(raw.to_ne_bytes());
            if !ip.is_unspecified() {
                return Some(ip);
            }
        }
    }
    None
}

fn nat_pmp_exchange(
    sock: &UdpSocket,
    gateway: SocketAddrV4,
    request: &[u8],
    expected_op: u8,
    min_resp_len: usize,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; 64];
    for attempt in 0..2 {
        let rem = remaining_timeout(deadline)?;
        let step = if attempt == 0 {
            rem.min(Duration::from_millis(400))
        } else {
            rem
        };
        sock.send_to(request, gateway)
            .map_err(|e| format!("向 {gateway} 发送 NAT-PMP 请求失败：{e}"))?;
        let _ = sock.set_read_timeout(Some(step.max(Duration::from_millis(1))));

        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if src != SocketAddr::V4(gateway) || n < min_resp_len {
                    continue;
                }
                if buf[0] != 0 || buf[1] != expected_op {
                    continue;
                }
                return Ok(buf[..n].to_vec());
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(err) => return Err(format!("接收 NAT-PMP 响应失败：{err}")),
        }
    }
    Err(format!("等待 NAT-PMP 网关 {gateway} 响应超时"))
}

fn nat_pmp_map_udp(
    gateway: SocketAddrV4,
    internal_port: u16,
    suggested_external_port: u16,
    lease_secs: u32,
    deadline: Instant,
) -> Result<UpnpMappingLease, String> {
    let bind_addr = if gateway.ip().is_loopback() {
        SocketAddr::from(([127, 0, 0, 1], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("绑定 NAT-PMP 套接字失败：{e}"))?;

    // 1) RFC 6886 §3.2：2 字节请求外网地址（vers=0, op=0）
    let pub_resp = nat_pmp_exchange(&sock, gateway, &[0u8, 0u8], 128, 12, deadline)?;
    let pub_result = u16::from_be_bytes([pub_resp[2], pub_resp[3]]);
    if pub_result != 0 {
        return Err(format!("NAT-PMP 获取外网地址失败：错误码 {pub_result}"));
    }
    let ext_ip = Ipv4Addr::new(pub_resp[8], pub_resp[9], pub_resp[10], pub_resp[11]);
    if !is_public_ipv4(ext_ip) {
        return Err(format!(
            "NAT-PMP 网关返回非公网 IP（疑似 CGNAT 或双层 NAT）：{ext_ip}"
        ));
    }

    // 2) RFC 6886 §3.3：12 字节 UDP 端口映射请求（vers=0, op=1）
    let mut map_req = [0u8; 12];
    map_req[0] = 0;
    map_req[1] = 1; // UDP
    map_req[4..6].copy_from_slice(&internal_port.to_be_bytes());
    map_req[6..8].copy_from_slice(&suggested_external_port.to_be_bytes());
    map_req[8..12].copy_from_slice(&lease_secs.to_be_bytes());

    let map_resp = nat_pmp_exchange(&sock, gateway, &map_req, 129, 16, deadline)?;
    let map_result = u16::from_be_bytes([map_resp[2], map_resp[3]]);
    if map_result != 0 {
        return Err(format!("NAT-PMP 申请 UDP 映射失败：错误码 {map_result}"));
    }
    let mapped_internal = u16::from_be_bytes([map_resp[8], map_resp[9]]);
    let mapped_external = u16::from_be_bytes([map_resp[10], map_resp[11]]);
    let granted_lifetime =
        u32::from_be_bytes([map_resp[12], map_resp[13], map_resp[14], map_resp[15]]);
    if mapped_internal != internal_port
        || mapped_external == 0
        || (lease_secs > 0 && granted_lifetime == 0)
    {
        return Err(format!(
            "NAT-PMP 返回无效映射参数：internal={mapped_internal}, external={mapped_external}, lifetime={granted_lifetime}"
        ));
    }

    Ok(UpnpMappingLease {
        external_addr: SocketAddr::V4(SocketAddrV4::new(ext_ip, mapped_external)),
        internal_port,
        external_port: mapped_external,
        protocol: UpnpProtocol::NatPmp,
        gateway: LeaseGateway::NatPmp {
            gateway_addr: gateway,
        },
    })
}

fn nat_pmp_unmap_udp(
    gateway: SocketAddrV4,
    internal_port: u16,
    deadline: Instant,
) -> Result<(), String> {
    let bind_addr = if gateway.ip().is_loopback() {
        SocketAddr::from(([127, 0, 0, 1], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("绑定 NAT-PMP 套接字失败：{e}"))?;

    // RFC 6886 §3.4：suggested_external_port = 0 且 lifetime = 0 表示删除映射
    let mut unmap_req = [0u8; 12];
    unmap_req[0] = 0;
    unmap_req[1] = 1; // UDP
    unmap_req[4..6].copy_from_slice(&internal_port.to_be_bytes());
    let _ = nat_pmp_exchange(&sock, gateway, &unmap_req, 129, 16, deadline);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn is_public_ipv4_covers_all_special_and_public_ranges() {
        // 真实公网单播 IPv4
        for ip in [
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(100, 63, 255, 255),
            Ipv4Addr::new(100, 128, 0, 0),
            Ipv4Addr::new(172, 15, 255, 255),
            Ipv4Addr::new(172, 32, 0, 0),
            Ipv4Addr::new(192, 167, 255, 255),
            Ipv4Addr::new(198, 17, 255, 255),
            Ipv4Addr::new(198, 20, 0, 0),
            Ipv4Addr::new(203, 0, 114, 1),
            Ipv4Addr::new(223, 255, 255, 254),
        ] {
            assert!(is_public_ipv4(ip), "expected public IPv4: {ip}");
        }

        // 私有、CGNAT、回环、链路本地、文档、基准、多播、广播与保留网段全部拒绝
        for ip in [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 10, 20, 30),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 255, 255, 254),
            Ipv4Addr::new(100, 64, 0, 0),
            Ipv4Addr::new(100, 64, 12, 34),
            Ipv4Addr::new(100, 127, 255, 255),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(127, 255, 255, 254),
            Ipv4Addr::new(169, 254, 0, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(172, 31, 255, 254),
            Ipv4Addr::new(192, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 88, 99, 1),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(192, 168, 255, 254),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 19, 255, 254),
            Ipv4Addr::new(198, 51, 100, 42),
            Ipv4Addr::new(203, 0, 113, 7),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(239, 255, 255, 250),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        ] {
            assert!(!is_public_ipv4(ip), "expected non-public IPv4: {ip}");
        }
    }

    #[test]
    fn upnp_protocol_and_status_serde_format() {
        assert_eq!(UpnpProtocol::UpnpIgdV1.as_str(), "upnp_igd_v1");
        assert_eq!(UpnpProtocol::UpnpIgdV2.as_str(), "upnp_igd_v2");
        assert_eq!(UpnpProtocol::NatPmp.as_str(), "nat_pmp");

        let mapped = UpnpStatus::Mapped {
            external_addr: "203.0.114.9:49000".to_string(),
            protocol: UpnpProtocol::UpnpIgdV2.as_str().to_string(),
        };
        let v = serde_json::to_value(&mapped).unwrap();
        assert_eq!(v["state"], "mapped");
        assert_eq!(v["external_addr"], "203.0.114.9:49000");
        assert_eq!(v["protocol"], "upnp_igd_v2");
        assert_eq!(serde_json::from_value::<UpnpStatus>(v).unwrap(), mapped);

        let disabled: UpnpStatus = serde_json::from_str(r#"{"state":"disabled"}"#).unwrap();
        assert_eq!(disabled, UpnpStatus::Disabled);
        let discovering: UpnpStatus = serde_json::from_str(r#"{"state":"discovering"}"#).unwrap();
        assert_eq!(discovering, UpnpStatus::Discovering);
        let unavail = UpnpStatus::Unavailable {
            reason: "CGNAT".to_string(),
        };
        let vu = serde_json::to_value(&unavail).unwrap();
        assert_eq!(vu["state"], "unavailable");
        assert_eq!(vu["reason"], "CGNAT");
    }

    #[test]
    fn ssrf_validator_rejects_public_loopback_schemes_and_hostnames() {
        // 生产模式允许 RFC 1918 与非 IMDS 链路本地 http URL
        assert_eq!(
            parse_and_validate_location_url("http://192.168.1.1:5000/rootDesc.xml", false).unwrap(),
            ParsedHttpUrl {
                host: Ipv4Addr::new(192, 168, 1, 1),
                port: 5000,
                path: "/rootDesc.xml".to_string(),
            }
        );
        assert!(parse_and_validate_location_url("http://10.0.0.1/igd.xml", false).is_ok());
        assert!(parse_and_validate_location_url("http://172.16.8.1:49152/desc.xml", false).is_ok());
        assert!(parse_and_validate_location_url("http://169.254.10.2:8080/igd.xml", false).is_ok());

        // 生产模式严格拒绝公网、回环、CGNAT、云元数据、非 http、域名与 userinfo 注入
        for bad in [
            "http://8.8.8.8:5000/rootDesc.xml",
            "http://1.1.1.1/desc.xml",
            "http://127.0.0.1:5000/rootDesc.xml",
            "http://100.64.0.1:5000/rootDesc.xml",
            "http://169.254.169.254/latest/meta-data",
            "https://192.168.1.1:5000/rootDesc.xml",
            "file:///etc/passwd",
            "http://router.local:5000/rootDesc.xml",
            "http://192.168.1.1@8.8.8.8/desc.xml",
            "http://192.168.1.1:0/desc.xml",
            "http://192.168.1.1:5000/bad\r\nHost: evil",
        ] {
            assert!(
                parse_and_validate_location_url(bad, false).is_err(),
                "SSRF guard should reject {bad:?}"
            );
        }
    }

    #[derive(Clone)]
    struct MockIgdConfig {
        service_type: String,
        control_url: String,
        external_ip: String,
        conflict_port: Option<u16>,
        accept_zero_reserved_port: Option<u16>,
        chunked_xml: bool,
    }

    struct MockIgdHandle {
        ssdp_addr: SocketAddr,
        http_hits: Arc<AtomicUsize>,
        recorded_actions: Arc<Mutex<Vec<(String, u16, u32)>>>,
        stop: Arc<AtomicBool>,
        threads: Vec<thread::JoinHandle<()>>,
    }

    impl Drop for MockIgdHandle {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            while let Some(h) = self.threads.pop() {
                let _ = h.join();
            }
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> Option<String> {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        let mut header_end = None;
        let mut content_len = 0usize;
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                            let hdr = String::from_utf8_lossy(&buf[..pos]);
                            for line in hdr.lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(he) = header_end {
                        if buf.len() >= he + content_len {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        (!buf.is_empty()).then(|| String::from_utf8_lossy(&buf).into_owned())
    }

    fn spawn_mock_igd(cfg: MockIgdConfig, override_location: Option<String>) -> MockIgdHandle {
        let stop = Arc::new(AtomicBool::new(false));
        let http_hits = Arc::new(AtomicUsize::new(0));
        let recorded_actions: Arc<Mutex<Vec<(String, u16, u32)>>> =
            Arc::new(Mutex::new(Vec::new()));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock IGD TCP");
        listener.set_nonblocking(true).unwrap();
        let http_addr = listener.local_addr().unwrap();

        let ssdp_sock = UdpSocket::bind("127.0.0.1:0").expect("bind mock SSDP UDP");
        ssdp_sock
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let ssdp_addr = ssdp_sock.local_addr().unwrap();

        let location = override_location.unwrap_or_else(|| {
            format!(
                "http://{}:{}/rootDesc.xml",
                http_addr.ip(),
                http_addr.port()
            )
        });

        let stop_ssdp = Arc::clone(&stop);
        let svc_type_ssdp = cfg.service_type.clone();
        let t_ssdp = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !stop_ssdp.load(Ordering::SeqCst) {
                if let Ok((n, src)) = ssdp_sock.recv_from(&mut buf) {
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.starts_with("M-SEARCH") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\n\
                             CACHE-CONTROL: max-age=120\r\n\
                             ST: {svc_type_ssdp}\r\n\
                             LOCATION: {location}\r\n\
                             \r\n"
                        );
                        let _ = ssdp_sock.send_to(resp.as_bytes(), src);
                    }
                }
            }
        });

        let stop_http = Arc::clone(&stop);
        let hits_http = Arc::clone(&http_hits);
        let actions_http = Arc::clone(&recorded_actions);
        let t_http = thread::spawn(move || {
            while !stop_http.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        hits_http.fetch_add(1, Ordering::SeqCst);
                        let Some(req) = read_http_request(&mut stream) else {
                            continue;
                        };
                        let first_line = req.lines().next().unwrap_or("");
                        if first_line.starts_with("GET ") {
                            let xml = format!(
                                "<?xml version=\"1.0\"?>\
                                 <root><device><serviceList><service>\
                                 <serviceType>{}</serviceType>\
                                 <controlURL>{}</controlURL>\
                                 </service></serviceList></device></root>",
                                cfg.service_type, cfg.control_url
                            );
                            if cfg.chunked_xml {
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: text/xml\r\n\
                                     Transfer-Encoding: chunked\r\n\
                                     Connection: close\r\n\r\n\
                                     {:x}\r\n{}\r\n0\r\n\r\n",
                                    xml.len(),
                                    xml
                                );
                                let _ = stream.write_all(resp.as_bytes());
                            } else {
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: text/xml\r\n\
                                     Content-Length: {}\r\n\
                                     Connection: close\r\n\r\n{}",
                                    xml.len(),
                                    xml
                                );
                                let _ = stream.write_all(resp.as_bytes());
                            }
                        } else if first_line.starts_with("POST ") {
                            if req.contains("GetExternalIPAddress") {
                                actions_http.lock().unwrap().push((
                                    "GetExternalIPAddress".to_string(),
                                    0,
                                    0,
                                ));
                                let body = format!(
                                    "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>\
                                     <NewExternalIPAddress>{}</NewExternalIPAddress>\
                                     </u:GetExternalIPAddressResponse></s:Body></s:Envelope>",
                                    cfg.external_ip
                                );
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let _ = stream.write_all(resp.as_bytes());
                            } else if req.contains("AddPortMapping") {
                                let ext_port = extract_xml_tag_value(&req, "NewExternalPort")
                                    .and_then(|s| s.parse::<u16>().ok())
                                    .unwrap_or(0);
                                let lease = extract_xml_tag_value(&req, "NewLeaseDuration")
                                    .and_then(|s| s.parse::<u32>().ok())
                                    .unwrap_or(0);
                                actions_http.lock().unwrap().push((
                                    "AddPortMapping".to_string(),
                                    ext_port,
                                    lease,
                                ));

                                if cfg.conflict_port == Some(ext_port) {
                                    let fault = "<s:Envelope><s:Body><s:Fault><detail>\
                                        <UPnPError><errorCode>718</errorCode>\
                                        <errorDescription>ConflictInMappingEntry</errorDescription>\
                                        </UPnPError></detail></s:Fault></s:Body></s:Envelope>";
                                    let resp = format!(
                                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        fault.len(),
                                        fault
                                    );
                                    let _ = stream.write_all(resp.as_bytes());
                                } else if ext_port == 0 {
                                    if let Some(reserved) = cfg.accept_zero_reserved_port {
                                        let body = format!(
                                            "<s:Envelope><s:Body><u:AddPortMappingResponse>\
                                             <NewReservedPort>{reserved}</NewReservedPort>\
                                             </u:AddPortMappingResponse></s:Body></s:Envelope>"
                                        );
                                        let resp = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            body.len(),
                                            body
                                        );
                                        let _ = stream.write_all(resp.as_bytes());
                                    } else {
                                        let fault = "<s:Envelope><s:Body><s:Fault><detail>\
                                            <UPnPError><errorCode>716</errorCode>\
                                            <errorDescription>WildCardNotPermittedInExtPort</errorDescription>\
                                            </UPnPError></detail></s:Fault></s:Body></s:Envelope>";
                                        let resp = format!(
                                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            fault.len(),
                                            fault
                                        );
                                        let _ = stream.write_all(resp.as_bytes());
                                    }
                                } else {
                                    let body = "<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>";
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        body.len(),
                                        body
                                    );
                                    let _ = stream.write_all(resp.as_bytes());
                                }
                            } else if req.contains("DeletePortMapping") {
                                let ext_port = extract_xml_tag_value(&req, "NewExternalPort")
                                    .and_then(|s| s.parse::<u16>().ok())
                                    .unwrap_or(0);
                                actions_http.lock().unwrap().push((
                                    "DeletePortMapping".to_string(),
                                    ext_port,
                                    0,
                                ));
                                let body = "<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>";
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let _ = stream.write_all(resp.as_bytes());
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        MockIgdHandle {
            ssdp_addr,
            http_hits,
            recorded_actions,
            stop,
            threads: vec![t_ssdp, t_http],
        }
    }

    #[test]
    fn upnp_igd_full_map_renew_unmap_flow_with_chunked_xml() {
        let mock = spawn_mock_igd(
            MockIgdConfig {
                service_type: "urn:schemas-upnp-org:service:WANIPConnection:2".to_string(),
                control_url: "/ctl/IPConn".to_string(),
                external_ip: "203.0.114.42".to_string(),
                conflict_port: None,
                accept_zero_reserved_port: None,
                chunked_xml: true,
            },
            None,
        );

        let lease = map_udp_port_internal(
            49123,
            3600,
            Duration::from_secs(2),
            mock.ssdp_addr,
            &[],
            true,
        )
        .expect("UPnP IGD map should succeed");

        assert_eq!(lease.protocol, UpnpProtocol::UpnpIgdV2);
        assert_eq!(lease.internal_port, 49123);
        assert_eq!(lease.external_port, 49123);
        assert_eq!(
            lease.external_addr,
            SocketAddr::from(([203, 0, 114, 42], 49123))
        );

        let renewed = renew_udp_mapping(&lease, 7200, Duration::from_secs(2))
            .expect("UPnP IGD renew should succeed");
        assert_eq!(renewed.external_addr, lease.external_addr);
        assert_eq!(renewed.protocol, UpnpProtocol::UpnpIgdV2);

        unmap_udp_port(&renewed, Duration::from_secs(2));

        let actions = mock.recorded_actions.lock().unwrap().clone();
        assert!(actions
            .iter()
            .any(|(a, p, l)| a == "AddPortMapping" && *p == 49123 && *l == 3600));
        assert!(actions
            .iter()
            .any(|(a, p, l)| a == "AddPortMapping" && *p == 49123 && *l == 7200));
        assert!(actions
            .iter()
            .any(|(a, p, _)| a == "DeletePortMapping" && *p == 49123));
    }

    #[test]
    fn upnp_port_conflict_falls_back_to_random_high_port_and_zero_port() {
        // 1) 网关拒绝同号端口和动态端口 0 → 自动回退至 30000..60000 随机高位端口
        let mock_rand = spawn_mock_igd(
            MockIgdConfig {
                service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".to_string(),
                control_url: "ctl/IPConn".to_string(),
                external_ip: "1.1.1.2".to_string(),
                conflict_port: Some(45000),
                accept_zero_reserved_port: None,
                chunked_xml: false,
            },
            None,
        );

        let lease = map_udp_port_internal(
            45000,
            1800,
            Duration::from_secs(2),
            mock_rand.ssdp_addr,
            &[],
            true,
        )
        .expect("conflict fallback to random port should succeed");
        assert_eq!(lease.protocol, UpnpProtocol::UpnpIgdV1);
        assert_eq!(lease.internal_port, 45000);
        assert_ne!(lease.external_port, 45000);
        assert!((FALLBACK_PORT_MIN..FALLBACK_PORT_MAX).contains(&lease.external_port));
        assert_eq!(
            lease.external_addr,
            SocketAddr::from(([1, 1, 1, 2], lease.external_port))
        );

        // 2) 网关拒绝同号端口但支持动态端口 0 并返回 NewReservedPort
        let mock_zero = spawn_mock_igd(
            MockIgdConfig {
                service_type: "urn:schemas-upnp-org:service:WANPPPConnection:1".to_string(),
                control_url: "/ctl/PPPConn".to_string(),
                external_ip: "8.8.4.4".to_string(),
                conflict_port: Some(45001),
                accept_zero_reserved_port: Some(52345),
                chunked_xml: false,
            },
            None,
        );

        let lease_zero = map_udp_port_internal(
            45001,
            1800,
            Duration::from_secs(2),
            mock_zero.ssdp_addr,
            &[],
            true,
        )
        .expect("conflict fallback to dynamic port 0 should succeed");
        assert_eq!(lease_zero.external_port, 52345);
        assert_eq!(
            lease_zero.external_addr,
            SocketAddr::from(([8, 8, 4, 4], 52345))
        );
    }

    #[test]
    fn upnp_ssrf_blocks_non_private_and_loopback_location_in_production_mode() {
        // SSDP 返回 127.0.0.1 LOCATION，但 allow_loopback=false（生产模式）必须拦截且绝不发起 HTTP 请求
        let mock_loopback = spawn_mock_igd(
            MockIgdConfig {
                service_type: "urn:schemas-upnp-org:service:WANIPConnection:2".to_string(),
                control_url: "/ctl/IPConn".to_string(),
                external_ip: "1.1.1.1".to_string(),
                conflict_port: None,
                accept_zero_reserved_port: None,
                chunked_xml: false,
            },
            None,
        );

        let err = map_udp_port_internal(
            49001,
            3600,
            Duration::from_millis(500),
            mock_loopback.ssdp_addr,
            &[],
            false,
        )
        .expect_err("production mode must reject loopback LOCATION");
        assert!(err.contains("SSRF"), "unexpected error: {err}");
        assert_eq!(
            mock_loopback.http_hits.load(Ordering::SeqCst),
            0,
            "SSRF guard must block before TCP connect"
        );

        // SSDP 返回公网 LOCATION，同样必须拦截
        let mock_public = spawn_mock_igd(
            MockIgdConfig {
                service_type: "urn:schemas-upnp-org:service:WANIPConnection:2".to_string(),
                control_url: "/ctl/IPConn".to_string(),
                external_ip: "1.1.1.1".to_string(),
                conflict_port: None,
                accept_zero_reserved_port: None,
                chunked_xml: false,
            },
            Some("http://8.8.8.8:5000/rootDesc.xml".to_string()),
        );
        let err_pub = map_udp_port_internal(
            49002,
            3600,
            Duration::from_millis(500),
            mock_public.ssdp_addr,
            &[],
            false,
        )
        .expect_err("production mode must reject public LOCATION");
        assert!(err_pub.contains("SSRF"), "unexpected error: {err_pub}");
    }

    #[test]
    fn upnp_rejects_cgnat_and_private_external_ip_without_adding_mapping() {
        for fake_ip in ["100.64.20.5", "192.168.100.2"] {
            let mock = spawn_mock_igd(
                MockIgdConfig {
                    service_type: "urn:schemas-upnp-org:service:WANIPConnection:2".to_string(),
                    control_url: "/ctl/IPConn".to_string(),
                    external_ip: fake_ip.to_string(),
                    conflict_port: None,
                    accept_zero_reserved_port: None,
                    chunked_xml: false,
                },
                None,
            );

            let err = map_udp_port_internal(
                49200,
                3600,
                Duration::from_secs(1),
                mock.ssdp_addr,
                &[],
                true,
            )
            .expect_err("CGNAT/private external IP must be rejected");
            assert!(
                err.contains("非公网 IP") || err.contains("CGNAT"),
                "unexpected error for {fake_ip}: {err}"
            );

            let actions = mock.recorded_actions.lock().unwrap();
            assert!(
                !actions.iter().any(|(a, _, _)| a == "AddPortMapping"),
                "must not call AddPortMapping when external IP {fake_ip} is not public"
            );
        }
    }

    struct MockNatPmpHandle {
        addr: SocketAddrV4,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl Drop for MockNatPmpHandle {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(h) = self.thread.take() {
                let _ = h.join();
            }
        }
    }

    fn spawn_mock_nat_pmp(
        external_ip: Ipv4Addr,
        granted_ext_port: Option<u16>,
    ) -> MockNatPmpHandle {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind mock NAT-PMP UDP");
        sock.set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let addr = match sock.local_addr().unwrap() {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => unreachable!(),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop_bg = Arc::clone(&stop);
        let reqs_bg = Arc::clone(&requests);

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            while !stop_bg.load(Ordering::SeqCst) {
                if let Ok((n, src)) = sock.recv_from(&mut buf) {
                    let pkt = buf[..n].to_vec();
                    reqs_bg.lock().unwrap().push(pkt.clone());
                    if n >= 2 && pkt[0] == 0 && pkt[1] == 0 {
                        // Public Address Response (12B)
                        let mut resp = [0u8; 12];
                        resp[0] = 0;
                        resp[1] = 128;
                        resp[4..8].copy_from_slice(&12345u32.to_be_bytes());
                        resp[8..12].copy_from_slice(&external_ip.octets());
                        let _ = sock.send_to(&resp, src);
                    } else if n >= 12 && pkt[0] == 0 && pkt[1] == 1 {
                        // UDP Mapping Response (16B)
                        let internal_port = u16::from_be_bytes([pkt[4], pkt[5]]);
                        let suggested_ext = u16::from_be_bytes([pkt[6], pkt[7]]);
                        let lifetime = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
                        let out_ext = if lifetime == 0 {
                            0
                        } else {
                            granted_ext_port.unwrap_or(if suggested_ext == 0 {
                                internal_port
                            } else {
                                suggested_ext
                            })
                        };
                        let mut resp = [0u8; 16];
                        resp[0] = 0;
                        resp[1] = 129;
                        resp[4..8].copy_from_slice(&12346u32.to_be_bytes());
                        resp[8..10].copy_from_slice(&internal_port.to_be_bytes());
                        resp[10..12].copy_from_slice(&out_ext.to_be_bytes());
                        resp[12..16].copy_from_slice(&lifetime.to_be_bytes());
                        let _ = sock.send_to(&resp, src);
                    }
                }
            }
        });

        MockNatPmpHandle {
            addr,
            requests,
            stop,
            thread: Some(handle),
        }
    }

    #[test]
    fn nat_pmp_fallback_full_map_renew_unmap_and_cgnat_rejection() {
        // 哑 SSDP 端口（无回复），迫使自动回退至 NAT-PMP
        let silent_ssdp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let silent_ssdp_addr = silent_ssdp.local_addr().unwrap();

        let mock_pmp = spawn_mock_nat_pmp(Ipv4Addr::new(9, 9, 9, 9), Some(51234));
        let lease = map_udp_port_internal(
            49321,
            3600,
            Duration::from_millis(600),
            silent_ssdp_addr,
            &[mock_pmp.addr],
            true,
        )
        .expect("NAT-PMP fallback mapping should succeed");

        assert_eq!(lease.protocol, UpnpProtocol::NatPmp);
        assert_eq!(lease.internal_port, 49321);
        assert_eq!(lease.external_port, 51234);
        assert_eq!(lease.external_addr, SocketAddr::from(([9, 9, 9, 9], 51234)));

        let renewed = renew_udp_mapping(&lease, 7200, Duration::from_millis(500))
            .expect("NAT-PMP renew should succeed");
        assert_eq!(renewed.external_addr, lease.external_addr);

        unmap_udp_port(&renewed, Duration::from_millis(500));

        let reqs = mock_pmp.requests.lock().unwrap();
        assert!(
            reqs.iter().any(|p| p.len() == 2 && p[0] == 0 && p[1] == 0),
            "expected NAT-PMP public address query"
        );
        assert!(
            reqs.iter().any(|p| {
                p.len() == 12
                    && p[0] == 0
                    && p[1] == 1
                    && u16::from_be_bytes([p[4], p[5]]) == 49321
                    && u32::from_be_bytes([p[8], p[9], p[10], p[11]]) == 3600
            }),
            "expected NAT-PMP initial mapping request"
        );
        assert!(
            reqs.iter().any(|p| {
                p.len() == 12
                    && p[0] == 0
                    && p[1] == 1
                    && u16::from_be_bytes([p[4], p[5]]) == 49321
                    && u16::from_be_bytes([p[6], p[7]]) == 0
                    && u32::from_be_bytes([p[8], p[9], p[10], p[11]]) == 0
            }),
            "expected NAT-PMP unmap request with lifetime=0"
        );

        // NAT-PMP 返回 CGNAT 外网 IP 时必须拦截
        let mock_cgnat = spawn_mock_nat_pmp(Ipv4Addr::new(100, 100, 1, 5), None);
        let err = map_udp_port_internal(
            49322,
            3600,
            Duration::from_millis(500),
            silent_ssdp_addr,
            &[mock_cgnat.addr],
            true,
        )
        .expect_err("NAT-PMP CGNAT IP must be rejected");
        assert!(
            err.contains("非公网 IP") || err.contains("CGNAT"),
            "unexpected NAT-PMP CGNAT error: {err}"
        );
    }

    #[test]
    fn decode_chunked_body_guards_integer_overflow_and_max_size() {
        // 畸形极大 chunk_len（usize::MAX / usize::MAX - 1 与 64 位字面量）不得溢出或越界 panic
        assert_eq!(decode_chunked_body(b"ffffffffffffffff\r\nabcd\r\n"), None);
        assert_eq!(decode_chunked_body(b"fffffffffffffffe\r\nabcd\r\n"), None);
        let max_payload = format!("{:x}\r\nabcd\r\n", usize::MAX);
        assert_eq!(decode_chunked_body(max_payload.as_bytes()), None);
        let max_m1_payload = format!("{:x}\r\nabcd\r\n", usize::MAX - 1);
        assert_eq!(decode_chunked_body(max_m1_payload.as_bytes()), None);

        // 累计解块长度超过 MAX_HTTP_RESPONSE_BYTES 时必须拒绝并返回 None
        let half = MAX_HTTP_RESPONSE_BYTES / 2 + 1;
        let part = vec![b'a'; half];
        let mut oversized = Vec::new();
        oversized.extend_from_slice(format!("{half:x}\r\n").as_bytes());
        oversized.extend_from_slice(&part);
        oversized.extend_from_slice(b"\r\n");
        oversized.extend_from_slice(format!("{half:x}\r\n").as_bytes());
        oversized.extend_from_slice(&part);
        oversized.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(decode_chunked_body(&oversized), None);

        // 正常多块解码保持可用
        assert_eq!(
            decode_chunked_body(b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n"),
            Some(b"hello world".to_vec())
        );
    }

    #[test]
    fn extract_xml_blocks_avoids_quadratic_scan_and_caps_block_count() {
        // 大量未闭合 <service> 标签（~450 KiB）应在毫秒级线性返回空列表，避免 O(N^2) CPU 卡顿
        let unclosed = "<service>".repeat(50_000);
        let start = Instant::now();
        let blocks = extract_xml_blocks(&unclosed, "service");
        let elapsed = start.elapsed();
        assert!(blocks.is_empty());
        assert!(
            elapsed < Duration::from_millis(500),
            "unclosed tags took too long: {elapsed:?}"
        );

        // 合法块数受 MAX_XML_BLOCKS 上限约束
        let many_valid = "<service>x</service>".repeat(MAX_XML_BLOCKS + 30);
        let capped = extract_xml_blocks(&many_valid, "service");
        assert_eq!(capped.len(), MAX_XML_BLOCKS);
    }

    #[test]
    fn parse_igd_service_skips_bad_control_url_and_ssdp_caps_locations() {
        let base = ParsedHttpUrl {
            host: Ipv4Addr::new(192, 168, 1, 1),
            port: 5000,
            path: "/rootDesc.xml".to_string(),
        };
        // 第一个 WANIPConnection:2 的 controlURL 触发 SSRF 拦截，必须 continue 而非阻断同 XML 内后续合法服务
        let xml = r#"<root><device><serviceList>
            <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
                <controlURL>http://8.8.8.8:80/evil</controlURL>
            </service>
            <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/ctl/IPConn</controlURL>
            </service>
        </serviceList></device></root>"#;
        let ep = parse_igd_service_from_xml(xml, &base, false)
            .expect("valid second service must still be selected");
        assert_eq!(ep.protocol, UpnpProtocol::UpnpIgdV1);
        assert_eq!(ep.control.path, "/ctl/IPConn");

        // SSDP 发现候选数受 MAX_SSDP_LOCATIONS (32) 上限保护
        let mock_ssdp = UdpSocket::bind("127.0.0.1:0").unwrap();
        mock_ssdp
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mock_addr = mock_ssdp.local_addr().unwrap();
        let flooder = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((_n, src)) = mock_ssdp.recv_from(&mut buf) {
                for i in 0..(MAX_SSDP_LOCATIONS + 20) {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\n\
                         ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
                         LOCATION: http://192.168.1.1:{}/desc.xml\r\n\r\n",
                        40000 + i
                    );
                    let _ = mock_ssdp.send_to(resp.as_bytes(), src);
                }
            }
        });
        let locs = ssdp_discover_locations(mock_addr, Instant::now() + Duration::from_secs(1))
            .expect("ssdp discovery should succeed");
        flooder.join().unwrap();
        assert!(
            !locs.is_empty() && locs.len() <= MAX_SSDP_LOCATIONS,
            "expected 1..={MAX_SSDP_LOCATIONS} locations, got {}",
            locs.len()
        );
    }
}
