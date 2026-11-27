//! NAT 类型分类、端口步长预测与双栈公网地址判定工具。
//!
//! 本模块提供纯确定性、无 I/O、零 `unsafe` 的 NAT 行为分析能力，供信令探测与
//! UDP 打洞引擎（[`crate::p2p`]）共享使用：
//! - 通过双探测端口映射差异识别锥形 NAT（`Cone`）、顺序步长对称 NAT（`SymmetricSeq`）
//!   与随机对称 NAT（`SymmetricRandom`）；
//! - 为顺序对称 NAT、未知 NAT 与随机对称 NAT 生成限流端口预测序列；
//! - 判定全球单播 IPv6（`2000::/3`）与规范化比对可路由公网 IP（拦截 RFC 1918、CGNAT 等）。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// 顺序对称 NAT 判定的最大端口绝对步长（`|delta| <= 64`）。
const MAX_SEQ_PORT_DELTA: i32 = 64;

/// 随机对称 NAT 端口预测下界（跳过 0..=1023 系统保留端口）。
const RANDOM_PORT_MIN: usize = 1024;

/// 随机对称 NAT 端口预测范围跨度（`1024..=65535`，共 64512 个端口）。
const RANDOM_PORT_SPAN: usize = 65535 - RANDOM_PORT_MIN + 1;

/// 与 `RANDOM_PORT_SPAN`（`64512 = 2^10 * 3^2 * 7`）互素的黄金比例近似步长（`39877 / 64512 ≈ 0.61813`），
/// 确保任意前缀长度都能在 `1024..=65535` 范围内均匀低差异分布且不重复。
const RANDOM_PORT_WEYL_STEP: usize = 39_877;

/// 客户端 NAT 类型分类结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    /// 未知或尚未完成双端口探测。
    #[default]
    Unknown,
    /// 锥形 NAT（双探测端口保持同一外网 IP 与同一映射端口）。
    Cone,
    /// 顺序步长对称 NAT（同 IP 且端口差值稳定在 `1 <= |delta| <= 64`）。
    SymmetricSeq,
    /// 随机对称 NAT（外网 IP 变化或端口跳变超过顺序阈值）。
    SymmetricRandom,
}

impl NatType {
    /// 返回规范化小写蛇形命名字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Cone => "cone",
            Self::SymmetricSeq => "symmetric_seq",
            Self::SymmetricRandom => "symmetric_random",
        }
    }

    /// 宽松解析字符串为 [`NatType`]（大小写与首尾空白不敏感，未知值安全回退 [`NatType::Unknown`]）。
    pub fn parse_lossy(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "cone" => Self::Cone,
            "symmetric_seq" => Self::SymmetricSeq,
            "symmetric_random" => Self::SymmetricRandom,
            _ => Self::Unknown,
        }
    }
}

/// 本端探测收敛后的 NAT 画像与双栈公网端点。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NatProfile {
    /// 判定的 NAT 类型。
    pub nat_type: NatType,
    /// 顺序对称 NAT 的单次分配端口步长（`Cone` 时为 `Some(0)`，其余非顺序情况为 `None`）。
    pub port_delta: Option<i16>,
    /// 主探测收敛到的公网 IPv4 端点（如有）。
    pub public_v4: Option<SocketAddr>,
    /// 主探测收敛到的公网 IPv6 端点（如有）。
    pub public_v6: Option<SocketAddr>,
}

/// 将 [`IpAddr`] 规范化，自动解包 `::ffff:a.b.c.d`（IPv4-mapped IPv6）为原生 IPv4。
pub(crate) fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// 将 [`SocketAddr`] 规范化，自动解包 IPv4-mapped IPv6 地址。
pub(crate) fn canonicalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonicalize_ip(addr.ip()), addr.port())
}

/// 判断给定 IPv4 地址是否为可路由公网 IPv4（排除私网、回环、CGNAT `100.64.0.0/10`、
/// 链路本地、未指定 `0.0.0.0/8`、多播、广播及 `240.0.0.0/4` 保留段）。
pub(crate) fn is_routable_public_ipv4(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    let is_cgnat = a == 100 && (64..=127).contains(&b);
    let is_reserved_high = a >= 240;
    !v4.is_private()
        && !v4.is_loopback()
        && !v4.is_link_local()
        && !v4.is_unspecified()
        && a != 0
        && !v4.is_multicast()
        && !v4.is_broadcast()
        && !is_cgnat
        && !is_reserved_high
}

/// 判断规范化后的 [`IpAddr`] 是否为可路由公网单播地址。
pub(crate) fn is_routable_public_ip(ip: IpAddr) -> bool {
    match canonicalize_ip(ip) {
        IpAddr::V4(v4) => is_routable_public_ipv4(v4),
        IpAddr::V6(v6) => is_global_unicast_ipv6(v6),
    }
}

/// 基于主/副两台 STUN-lite 探测端点返回的外网观测地址，确定性判定 NAT 类型与端口步长。
///
/// - 同 IP 且同端口 -> `(NatType::Cone, Some(0))`
/// - 同 IP 且 `1 <= |delta| <= 64`（含动态段 `1024..=65535` 与全非零段 `1..=65535` 端口回绕）
///   -> `(NatType::SymmetricSeq, Some(delta))`
/// - 其他情况（不同 IP 或端口跳变过大）-> `(NatType::SymmetricRandom, None)`
pub fn classify_nat_mapping(primary: SocketAddr, secondary: SocketAddr) -> (NatType, Option<i16>) {
    let p = canonicalize_socket_addr(primary);
    let s = canonicalize_socket_addr(secondary);
    if p.ip() != s.ip() {
        return (NatType::SymmetricRandom, None);
    }

    let raw = i32::from(s.port()) - i32::from(p.port());
    let mut candidates = Vec::with_capacity(5);
    candidates.push(raw);
    if p.port() >= 1024 && s.port() >= 1024 {
        const DYNAMIC_PORT_SPAN: i32 = 64_512;
        candidates.push(raw + DYNAMIC_PORT_SPAN);
        candidates.push(raw - DYNAMIC_PORT_SPAN);
    }
    if p.port() >= 1 && s.port() >= 1 {
        const FULL_NONZERO_PORT_SPAN: i32 = 65_535;
        candidates.push(raw + FULL_NONZERO_PORT_SPAN);
        candidates.push(raw - FULL_NONZERO_PORT_SPAN);
    }

    let best = candidates
        .into_iter()
        .min_by_key(|c| c.abs())
        .unwrap_or(raw);

    if best == 0 {
        (NatType::Cone, Some(0))
    } else if (1..=MAX_SEQ_PORT_DELTA).contains(&best.abs()) {
        (NatType::SymmetricSeq, i16::try_from(best).ok())
    } else {
        (NatType::SymmetricRandom, None)
    }
}

/// 为对称 NAT 或未知 NAT 对端生成去重后的候选探测端口序列（不含 `0` 与 `base_port`）。
///
/// - `SymmetricSeq` 且具备非零 `delta`：先按 `base + k * delta`（`k = 1..=16`）生成步长序列，
///   再补充 `±1..±4` 小邻域，去重截断至 `max_ports`。
/// - `Unknown`（或 `SymmetricSeq` 缺少有效非零步长）：生成 `+1..=12` 与 `-1..=-6` 邻域并截断。
/// - `SymmetricRandom`：在 `1024..=65535` 区间生成均匀分布候选端口并截断至 `max_ports`。
/// - `Cone`：无需猜测端口，返回空列表。
pub fn predict_symmetric_ports(
    base_port: u16,
    nat_type: NatType,
    delta: Option<i16>,
    max_ports: usize,
) -> Vec<u16> {
    if max_ports == 0 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(max_ports.min(64));
    let mut seen = HashSet::with_capacity(max_ports.min(64));
    let base_i32 = i32::from(base_port);

    let push_if_valid = |out: &mut Vec<u16>, seen: &mut HashSet<u16>, raw: i32| {
        if out.len() >= max_ports {
            return;
        }
        if (1..=65535).contains(&raw) {
            let port = raw as u16;
            if port != base_port && seen.insert(port) {
                out.push(port);
            }
        }
    };

    match nat_type {
        NatType::Cone => {}
        NatType::SymmetricSeq => {
            if let Some(step) = delta.filter(|&d| d != 0) {
                let step_i32 = i32::from(step);
                for k in 1..=16 {
                    push_if_valid(&mut out, &mut seen, base_i32 + k * step_i32);
                }
                for offset in 1..=4 {
                    push_if_valid(&mut out, &mut seen, base_i32 + offset);
                    push_if_valid(&mut out, &mut seen, base_i32 - offset);
                }
            } else {
                for offset in 1..=12 {
                    push_if_valid(&mut out, &mut seen, base_i32 + offset);
                }
                for offset in 1..=6 {
                    push_if_valid(&mut out, &mut seen, base_i32 - offset);
                }
            }
        }
        NatType::Unknown => {
            for offset in 1..=12 {
                push_if_valid(&mut out, &mut seen, base_i32 + offset);
            }
            for offset in 1..=6 {
                push_if_valid(&mut out, &mut seen, base_i32 - offset);
            }
        }
        NatType::SymmetricRandom => {
            let start = usize::from(base_port) % RANDOM_PORT_SPAN;
            let limit = max_ports.min(RANDOM_PORT_SPAN);
            for i in 0..RANDOM_PORT_SPAN {
                if out.len() >= limit {
                    break;
                }
                let offset = (start + i * RANDOM_PORT_WEYL_STEP) % RANDOM_PORT_SPAN;
                let port = (RANDOM_PORT_MIN + offset) as u16;
                if port != base_port && seen.insert(port) {
                    out.push(port);
                }
            }
        }
    }

    out
}

/// 判断 [`Ipv6Addr`] 是否为全球单播 IPv6 地址（`2000::/3`）。
///
/// 严格拒绝未指定 `::`、回环 `::1`、多播 `ff00::/8`、链路本地 `fe80::/10`、
/// 唯一本地地址 ULA `fc00::/7` 及 IPv4-mapped `::ffff:0:0/96`。
pub fn is_global_unicast_ipv6(ip: Ipv6Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && ip.to_ipv4_mapped().is_none()
        && (ip.segments()[0] & 0xe000) == 0x2000
}

fn parse_routable_public_ip(raw: Option<&str>) -> Option<IpAddr> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() {
        return None;
    }
    let ip = trimmed
        .parse::<SocketAddr>()
        .map(|s| s.ip())
        .or_else(|_| trimmed.parse::<IpAddr>())
        .ok()?;
    let canon = canonicalize_ip(ip);
    if is_routable_public_ip(canon) {
        Some(canon)
    } else {
        None
    }
}

/// 比对两个端点字符串（支持 `SocketAddr` 或纯 `IpAddr`，自动解包 IPv4-mapped）是否拥有同一可路由公网 IP。
///
/// 仅当两侧均能解析为可路由公网 IP（排除私网、回环、CGNAT `100.64.0.0/10`、链路本地、未指定与多播）
/// 且属于同一 IP 地址族时返回 `Some(ip_a == ip_b)`；若跨族（IPv6 vs IPv4）或任一侧不可解析则返回 `None`。
pub fn same_public_ip(a: Option<&str>, b: Option<&str>) -> Option<bool> {
    let ip_a = parse_routable_public_ip(a)?;
    let ip_b = parse_routable_public_ip(b)?;
    if ip_a.is_ipv6() != ip_b.is_ipv6() {
        return None;
    }
    Some(ip_a == ip_b)
}

fn collect_routable_public_ips(addrs: &[&str]) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let mut v4s = Vec::new();
    let mut v6s = Vec::new();
    for raw in addrs {
        if let Some(ip) = parse_routable_public_ip(Some(raw)) {
            match ip {
                IpAddr::V4(v4) => v4s.push(v4),
                IpAddr::V6(v6) => v6s.push(v6),
            }
        }
    }
    (v4s, v6s)
}

/// 在双栈候选列表之间比对是否存在同一可路由公网 IP（按同地址族分族比对）。
///
/// 先比对 IPv4-vs-IPv4 对，再比对 IPv6-vs-IPv6 对：
/// - 若任一同族对相等，返回 `Some(true)`；
/// - 若至少存在一对同族可路由公网 IP 且均不相等，返回 `Some(false)`；
/// - 若没有任何同族可路由公网 IP 对（如一侧仅 IPv6、另一侧仅 IPv4 或含私网地址），返回 `None`。
pub fn same_public_ip_any(self_addrs: &[&str], peer_addrs: &[&str]) -> Option<bool> {
    let (self_v4, self_v6) = collect_routable_public_ips(self_addrs);
    let (peer_v4, peer_v6) = collect_routable_public_ips(peer_addrs);

    for a in &self_v4 {
        if peer_v4.contains(a) {
            return Some(true);
        }
    }
    for a in &self_v6 {
        if peer_v6.contains(a) {
            return Some(true);
        }
    }

    if (!self_v4.is_empty() && !peer_v4.is_empty()) || (!self_v6.is_empty() && !peer_v6.is_empty())
    {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_type_serde_as_str_and_parse_lossy() {
        assert_eq!(NatType::default(), NatType::Unknown);
        assert_eq!(NatType::Unknown.as_str(), "unknown");
        assert_eq!(NatType::Cone.as_str(), "cone");
        assert_eq!(NatType::SymmetricSeq.as_str(), "symmetric_seq");
        assert_eq!(NatType::SymmetricRandom.as_str(), "symmetric_random");

        assert_eq!(NatType::parse_lossy("cone"), NatType::Cone);
        assert_eq!(NatType::parse_lossy("  CONE  "), NatType::Cone);
        assert_eq!(NatType::parse_lossy("Symmetric_Seq"), NatType::SymmetricSeq);
        assert_eq!(
            NatType::parse_lossy("symmetric_random"),
            NatType::SymmetricRandom
        );
        assert_eq!(NatType::parse_lossy("unknown"), NatType::Unknown);
        assert_eq!(NatType::parse_lossy("garbage"), NatType::Unknown);
        assert_eq!(NatType::parse_lossy(""), NatType::Unknown);

        let profile = NatProfile {
            nat_type: NatType::SymmetricSeq,
            port_delta: Some(3),
            public_v4: Some("198.51.100.10:50000".parse().unwrap()),
            public_v6: Some("[2001:db8::1]:50000".parse().unwrap()),
        };
        let json = serde_json::to_string(&profile).unwrap();
        assert!(json.contains("\"symmetric_seq\""));
        let decoded: NatProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, profile);
    }

    #[test]
    fn classify_nat_mapping_handles_cone_seq_negative_high_ports_and_random() {
        let p_cone: SocketAddr = "198.51.100.2:45000".parse().unwrap();
        let s_cone: SocketAddr = "[::ffff:198.51.100.2]:45000".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_cone, s_cone),
            (NatType::Cone, Some(0))
        );

        // 正步长与高位端口（>32768）不溢出
        let p_seq: SocketAddr = "198.51.100.2:50000".parse().unwrap();
        let s_seq_pos: SocketAddr = "198.51.100.2:50003".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_seq_pos),
            (NatType::SymmetricSeq, Some(3))
        );

        // 负步长且边界 64
        let s_seq_neg: SocketAddr = "198.51.100.2:49936".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_seq_neg),
            (NatType::SymmetricSeq, Some(-64))
        );

        // 超过 64 视为随机对称
        let s_far: SocketAddr = "198.51.100.2:50065".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_far),
            (NatType::SymmetricRandom, None)
        );
        let s_far_neg: SocketAddr = "198.51.100.2:49935".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_far_neg),
            (NatType::SymmetricRandom, None)
        );

        // 不同 IP（多出口 NAT 池）视为随机对称
        let s_diff_ip: SocketAddr = "198.51.100.3:50000".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_diff_ip),
            (NatType::SymmetricRandom, None)
        );

        // 动态段 1024..=65535 端口边界回绕（65534 -> 1025 => +3，1025 -> 65534 => -3）
        assert_eq!(
            classify_nat_mapping(
                "198.51.100.2:65534".parse().unwrap(),
                "198.51.100.2:1025".parse().unwrap(),
            ),
            (NatType::SymmetricSeq, Some(3))
        );
        assert_eq!(
            classify_nat_mapping(
                "198.51.100.2:1025".parse().unwrap(),
                "198.51.100.2:65534".parse().unwrap(),
            ),
            (NatType::SymmetricSeq, Some(-3))
        );

        // 全非零段 1..=65535 端口边界回绕（65535 -> 1 => +1，1 -> 65535 => -1）
        assert_eq!(
            classify_nat_mapping(
                "198.51.100.2:65535".parse().unwrap(),
                "198.51.100.2:1".parse().unwrap(),
            ),
            (NatType::SymmetricSeq, Some(1))
        );
        assert_eq!(
            classify_nat_mapping(
                "198.51.100.2:1".parse().unwrap(),
                "198.51.100.2:65535".parse().unwrap(),
            ),
            (NatType::SymmetricSeq, Some(-1))
        );
    }

    #[test]
    fn predict_symmetric_ports_covers_seq_unknown_random_and_truncates() {
        // Cone 返回空
        assert!(predict_symmetric_ports(40000, NatType::Cone, Some(0), 16).is_empty());

        // SymmetricSeq +3：先 1..=16 步长，再补 ±1..±4 并去重排除 base 与 0（+3 与 k=1 重合故共 23 个）
        let seq = predict_symmetric_ports(40000, NatType::SymmetricSeq, Some(3), 24);
        assert_eq!(seq.len(), 23);
        assert_eq!(seq[0], 40003);
        assert_eq!(seq[1], 40006);
        assert_eq!(seq[15], 40048);
        assert!(!seq.contains(&40000));
        assert!(!seq.contains(&0));
        let uniq: HashSet<u16> = seq.iter().copied().collect();
        assert_eq!(uniq.len(), seq.len());
        assert_eq!(
            predict_symmetric_ports(40000, NatType::SymmetricSeq, Some(3), 20).len(),
            20
        );

        // SymmetricSeq 接近 65535 时越界过滤、不生成 0
        let edge_seq = predict_symmetric_ports(65530, NatType::SymmetricSeq, Some(3), 16);
        assert!(edge_seq.contains(&65533));
        assert!(!edge_seq.contains(&0));
        assert!(!edge_seq.contains(&65530));

        // Unknown：+1..=12，-1..=-6
        let unk = predict_symmetric_ports(10000, NatType::Unknown, None, 32);
        assert_eq!(unk.len(), 18);
        assert_eq!(
            &unk[..12],
            &[10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010, 10011, 10012]
        );
        assert_eq!(&unk[12..], &[9999, 9998, 9997, 9996, 9995, 9994]);

        // Unknown 截断
        let unk_cap = predict_symmetric_ports(10000, NatType::Unknown, None, 5);
        assert_eq!(unk_cap, vec![10001, 10002, 10003, 10004, 10005]);

        // SymmetricRandom：1024..=65535 均匀分布、无重复、不含 base_port
        let rnd = predict_symmetric_ports(34567, NatType::SymmetricRandom, None, 64);
        assert_eq!(rnd.len(), 64);
        assert!(!rnd.contains(&34567));
        assert!(rnd.iter().all(|&p| p >= 1024));
        let rnd_uniq: HashSet<u16> = rnd.iter().copied().collect();
        assert_eq!(rnd_uniq.len(), 64);
        // 确认跨全端口段分布而非聚集在局部
        let low = rnd.iter().filter(|&&p| p < 16384).count();
        let mid_low = rnd.iter().filter(|&&p| (16384..32768).contains(&p)).count();
        let mid_high = rnd.iter().filter(|&&p| (32768..49152).contains(&p)).count();
        let high = rnd.iter().filter(|&&p| p >= 49152).count();
        assert!(low >= 8 && mid_low >= 8 && mid_high >= 8 && high >= 8);
    }

    #[test]
    fn is_global_unicast_ipv6_accepts_2000_slash_3_and_rejects_special() {
        assert!(is_global_unicast_ipv6("2001:db8::1".parse().unwrap()));
        assert!(is_global_unicast_ipv6("240e:3b0:2a1::1".parse().unwrap()));
        assert!(is_global_unicast_ipv6("3fff::1".parse().unwrap()));

        assert!(!is_global_unicast_ipv6("::".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("fe80::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("febf::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("fc00::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("fd12:3456::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("ff02::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6(
            "::ffff:198.51.100.1".parse().unwrap()
        ));
        assert!(!is_global_unicast_ipv6("1000::1".parse().unwrap()));
    }

    #[test]
    fn same_public_ip_compares_routable_public_ips_only() {
        assert_eq!(
            same_public_ip(Some("198.51.100.22:60123"), Some("198.51.100.22:50001")),
            Some(true)
        );
        // IPv4-mapped IPv6 与 IPv4 视为同一公网 IP
        assert_eq!(
            same_public_ip(Some("[::ffff:198.51.100.22]:60123"), Some("198.51.100.22")),
            Some(true)
        );
        assert_eq!(
            same_public_ip(Some("198.51.100.22:60123"), Some("203.0.113.9:60123")),
            Some(false)
        );
        // 全球单播 IPv6
        assert_eq!(
            same_public_ip(Some("[240e:3b0:1::10]:40000"), Some("240e:3b0:1::10")),
            Some(true)
        );
        assert_eq!(
            same_public_ip(
                Some("[240e:3b0:1::10]:40000"),
                Some("[240e:3b0:1::11]:40000")
            ),
            Some(false)
        );

        // 非可路由公网 IP 一律返回 None
        for bad in [
            "10.0.0.1:5000",
            "172.16.5.4:5000",
            "192.168.1.1:5000",
            "100.64.0.1:5000",
            "100.127.255.254:5000",
            "127.0.0.1:5000",
            "169.254.1.2:5000",
            "0.0.0.0:5000",
            "224.0.0.1:5000",
            "[::1]:5000",
            "[fe80::1]:5000",
            "[fd00::1]:5000",
            "[ff02::1]:5000",
            "not-an-ip",
            "",
        ] {
            assert_eq!(
                same_public_ip(Some(bad), Some("198.51.100.22:60123")),
                None,
                "expected None for {bad}"
            );
            assert_eq!(
                same_public_ip(Some("198.51.100.22:60123"), Some(bad)),
                None,
                "expected None for {bad}"
            );
        }
        assert_eq!(same_public_ip(None, Some("198.51.100.22")), None);
        assert_eq!(same_public_ip(Some("198.51.100.22"), None), None);

        // 跨族 (v6, v4) / (v4, v6) 无法证明处于不同 NAT 网关后，必须返回 None
        assert_eq!(
            same_public_ip(Some("[240e:3b0:1::10]:40000"), Some("198.51.100.22:50001")),
            None
        );
        assert_eq!(
            same_public_ip(Some("198.51.100.22:50001"), Some("[240e:3b0:1::10]:40000")),
            None
        );
    }

    #[test]
    fn same_public_ip_any_compares_by_family_and_handles_dual_stack() {
        // 同族 IPv4 命中
        assert_eq!(
            same_public_ip_any(
                &["[240e:3b0:1::10]:40000", "198.51.100.22:60000"],
                &["198.51.100.22:50001"],
            ),
            Some(true)
        );
        // IPv4 不同但 IPv6 相同 -> 任一同族相等即返回 Some(true)
        assert_eq!(
            same_public_ip_any(
                &["198.51.100.22:60000", "[240e:3b0:1::10]:40000"],
                &["203.0.113.9:50001", "240e:3b0:1::10"],
            ),
            Some(true)
        );
        // 至少存在一对同族公网 IP 且均不相等 -> Some(false)
        assert_eq!(
            same_public_ip_any(
                &["198.51.100.22:60000", "192.168.1.10:5000"],
                &["203.0.113.9:50001", "10.0.0.1:5000"],
            ),
            Some(false)
        );
        assert_eq!(
            same_public_ip_any(&["[240e:3b0:1::10]:40000"], &["[240e:3b0:1::11]:40000"]),
            Some(false)
        );
        // 仅跨族 (v6, v4) 或含私网地址 -> None
        assert_eq!(
            same_public_ip_any(&["[240e:3b0:1::10]:40000"], &["198.51.100.22:50001"]),
            None
        );
        assert_eq!(
            same_public_ip_any(&["192.168.1.2:5000"], &["198.51.100.22:50001"]),
            None
        );
        assert_eq!(same_public_ip_any(&[], &["198.51.100.22:50001"]), None);
    }
}
