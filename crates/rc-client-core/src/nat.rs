//! NAT 类型分类、端口步长预测、端口区间推断与双栈公网地址判定工具。
//!
//! 本模块提供纯确定性、无 I/O、零 `unsafe` 的 NAT 行为分析能力，供信令探测与
//! UDP 打洞引擎（[`crate::p2p`]）共享使用：
//! - 基于纯私有 4 样本 + 可选私有副公网 IP 探测识别：
//!   `Public`、`ConeVerified`、`ConeUnverified`、`AdmSeq`、`AdmRandom`、
//!   `ApdmSeq`、`ApdmRandom`、`UdpBlocked` 与 `Unknown`；
//! - 推断与校验 NAT 临时端口区间 [`PortRangeHint`]（`LinuxEphemeral` / `IanaDynamic` /
//!   `Custom` / `Full`），为对称 NAT 生成「先偏好端口段再扩至全段」的采样序列；
//! - 判定全球单播 IPv6（`2000::/3`）与规范化比对可路由公网 IP（拦截 RFC 1918、CGNAT 等）。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 顺序对称 NAT 判定的最大端口绝对步长（`|delta| <= 64`）。
const MAX_SEQ_PORT_DELTA: i32 = 64;

/// 随机对称 NAT 端口预测下界（跳过 0..=1023 系统保留端口）。
const RANDOM_PORT_MIN: usize = 1024;

/// 随机对称 NAT 端口预测范围跨度（`1024..=65535`，共 64512 个端口）。
const RANDOM_PORT_SPAN: usize = 65535 - RANDOM_PORT_MIN + 1;

/// 与 `RANDOM_PORT_SPAN`（`64512 = 2^10 * 3^2 * 7`）互素的黄金比例近似步长（`39877 / 64512 ≈ 0.61813`），
/// 确保任意前缀长度都能在 `1024..=65535` 范围内均匀低差异分布且不重复。
const RANDOM_PORT_WEYL_STEP: usize = 39_877;

/// 客户端 NAT 类型细化分类结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NatType {
    /// 直连公网 IP（外网观测 IP 等于本机接口可路由公网 IP 且无端口映射）。
    Public,
    /// 已验证完全锥形 NAT（双端口同映射且跨私有副公网 IP 仍保持相同外网端口）。
    ConeVerified,
    /// 未跨副 IP 验证的锥形 NAT（双探测端口保持同一外网 IP 与同一端口，可能为锥形或 ADM）。
    ConeUnverified,
    /// 地址相关映射（ADM）且端口按固定小步长顺序递增/递减。
    AdmSeq,
    /// 地址相关映射（ADM）且端口随机跳变或切换出口 IP。
    AdmRandom,
    /// 地址与端口相关映射（APDM）且跨样本验证步长恒定（`1 <= |delta| <= 64`）。
    ApdmSeq,
    /// 地址与端口相关映射（APDM）且端口随机跳变、步长不恒定或多出口 IP。
    ApdmRandom,
    /// UDP 探测全部超时，疑似 UDP 被防火墙或运营商阻断。
    UdpBlocked,
    /// 未知或尚未完成双端口探测。
    #[default]
    Unknown,
}

impl NatType {
    /// 返回规范化小写蛇形命名字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::ConeVerified => "cone_verified",
            Self::ConeUnverified => "cone_unverified",
            Self::AdmSeq => "adm_seq",
            Self::AdmRandom => "adm_random",
            Self::ApdmSeq => "apdm_seq",
            Self::ApdmRandom => "apdm_random",
            Self::UdpBlocked => "udp_blocked",
            Self::Unknown => "unknown",
        }
    }

    /// 宽松解析字符串为 [`NatType`]（大小写与首尾空白不敏感，兼容旧版 `"cone"` / `"symmetric_seq"` /
    /// `"symmetric_random"`，未知值安全回退 [`NatType::Unknown`]）。
    pub fn parse_lossy(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "public" => Self::Public,
            "cone_verified" => Self::ConeVerified,
            "cone" | "cone_unverified" => Self::ConeUnverified,
            "adm_seq" => Self::AdmSeq,
            "adm_random" => Self::AdmRandom,
            "symmetric_seq" | "apdm_seq" => Self::ApdmSeq,
            "symmetric_random" | "apdm_random" => Self::ApdmRandom,
            "udp_blocked" => Self::UdpBlocked,
            _ => Self::Unknown,
        }
    }

    /// 是否属于锥形 NAT（含已验证与未验证）。
    pub const fn is_cone(self) -> bool {
        matches!(self, Self::ConeVerified | Self::ConeUnverified)
    }

    /// 是否属于顺序步长对称 NAT（`AdmSeq` 或 `ApdmSeq`）。
    pub const fn is_symmetric_seq(self) -> bool {
        matches!(self, Self::AdmSeq | Self::ApdmSeq)
    }

    /// 是否属于随机对称 NAT（`AdmRandom` 或 `ApdmRandom`）。
    pub const fn is_symmetric_random(self) -> bool {
        matches!(self, Self::AdmRandom | Self::ApdmRandom)
    }

    /// 是否属于任意对称 NAT（ADM 或 APDM）。
    pub const fn is_symmetric(self) -> bool {
        self.is_symmetric_seq() || self.is_symmetric_random()
    }
}

impl Serialize for NatType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NatType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::parse_lossy(&raw))
    }
}

/// NAT 外部映射端口分配范围提示（用于对称 NAT 端口预测优先采样对应分段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortRangeHint {
    /// Linux 常见临时端口段：`32768..=60999`。
    LinuxEphemeral,
    /// IANA / Windows / macOS 动态端口段：`49152..=65535`。
    IanaDynamic,
    /// 自定义端口区间：`min..=max`（要求 `1 <= min <= max <= 65535`）。
    Custom {
        /// 区间下界（包含，`>= 1`）。
        min: u16,
        /// 区间上界（包含，`>= min`）。
        max: u16,
    },
    /// 全非系统端口段：`1024..=65535`。
    #[default]
    Full,
}

impl PortRangeHint {
    /// 返回区间 `[min, max]` 边界。
    pub const fn bounds(self) -> (u16, u16) {
        match self {
            Self::LinuxEphemeral => (32_768, 60_999),
            Self::IanaDynamic => (49_152, 65_535),
            Self::Custom { min, max } => (min, max),
            Self::Full => (1_024, 65_535),
        }
    }

    /// 若边界合法（`1 <= min <= max`）则返回 `Some(self)`，否则返回 `None`。
    pub const fn validated(self) -> Option<Self> {
        let (min, max) = self.bounds();
        if min >= 1 && min <= max {
            Some(self)
        } else {
            None
        }
    }

    /// 编码为线缆 `[min, max]` 数组。
    pub const fn to_wire_pair(self) -> [u16; 2] {
        let (min, max) = self.bounds();
        [min, max]
    }

    /// 从线缆 `[min, max]` 解码并校验 `1 <= min <= max <= 65535`；非法区间返回 `None`。
    pub const fn from_wire_pair(pair: [u16; 2]) -> Option<Self> {
        let [min, max] = pair;
        if min < 1 || min > max {
            return None;
        }
        Some(match (min, max) {
            (32_768, 60_999) => Self::LinuxEphemeral,
            (49_152, 65_535) => Self::IanaDynamic,
            (1_024, 65_535) => Self::Full,
            _ => Self::Custom { min, max },
        })
    }
}

impl Serialize for PortRangeHint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let valid = self
            .validated()
            .ok_or_else(|| serde::ser::Error::custom("invalid PortRangeHint bounds"))?;
        valid.to_wire_pair().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PortRangeHint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let pair = <[u16; 2]>::deserialize(deserializer)?;
        Self::from_wire_pair(pair)
            .ok_or_else(|| serde::de::Error::custom("invalid NAT port range [min, max]"))
    }
}

/// 本端探测收敛后的 NAT 画像与双栈公网端点。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NatProfile {
    /// 判定的 NAT 类型。
    pub nat_type: NatType,
    /// 顺序对称 NAT 的单次分配端口步长（锥形 NAT 时为 `Some(0)`，其余非顺序情况为 `None`）。
    pub port_delta: Option<i16>,
    /// 观测到的对称 NAT 外网端口分配区间提示（如有）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_range: Option<PortRangeHint>,
    /// 主探测收敛到的公网 IPv4 端点（如有）。
    pub public_v4: Option<SocketAddr>,
    /// 主探测收敛到的公网 IPv6 端点（如有）。
    pub public_v6: Option<SocketAddr>,
}

/// 纯私有 4 样本 + 可选私有副公网 IP 的 NAT 画像探测输入。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NatProbeSamples {
    /// 主持久化 socket 探测主端点 (`:21116`) 观测到的外网映射 `m1`。
    pub primary: Option<SocketAddr>,
    /// 主持久化 socket 探测副端口 (`:21119`) 观测到的外网映射 `m2`。
    pub secondary: Option<SocketAddr>,
    /// 当 `m1 != m2` 时，临时 socket 连发主端口观测到的外网映射 `m3`。
    pub aux_primary: Option<SocketAddr>,
    /// 当 `m1 != m2` 时，临时 socket 连发副端口观测到的外网映射 `m4`。
    pub aux_secondary: Option<SocketAddr>,
    /// 当 `m1 == m2` 时，主持久化 socket 探测私有副公网 IP 观测到的外网映射 `m_alt_ip`。
    pub alt_ip: Option<SocketAddr>,
    /// 本机接口当前持有的可路由公网 IP 列表（用于判定无 NAT 直连 `Public`）。
    pub local_public_ips: Vec<IpAddr>,
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

/// 从一组观测到的映射端口推断最匹配的 [`PortRangeHint`]。
pub fn infer_port_range_hint(ports: &[u16]) -> Option<PortRangeHint> {
    let valid: Vec<u16> = ports.iter().copied().filter(|&p| p != 0).collect();
    if valid.is_empty() {
        return None;
    }
    if valid.iter().all(|&p| p >= 49_152) {
        Some(PortRangeHint::IanaDynamic)
    } else if valid.iter().all(|&p| (32_768..=60_999).contains(&p)) {
        Some(PortRangeHint::LinuxEphemeral)
    } else if valid.iter().all(|&p| p >= 1_024) {
        Some(PortRangeHint::Full)
    } else {
        Some(PortRangeHint::Custom {
            min: 1,
            max: 65_535,
        })
    }
}

/// 计算同 IP 两端点的最小端口步长（仅当同 IP 且 `1 <= |delta| <= 64` 时返回 `Some(delta)`）。
fn classify_port_step(first: SocketAddr, second: SocketAddr) -> Option<i16> {
    let p = canonicalize_socket_addr(first);
    let s = canonicalize_socket_addr(second);
    if p.ip() != s.ip() {
        return None;
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

    if (1..=MAX_SEQ_PORT_DELTA).contains(&best.abs()) {
        i16::try_from(best).ok()
    } else {
        None
    }
}

/// 基于纯私有 4 样本 `(m1, m2, m3, m4)`、可选副公网 IP 样本 `m_alt_ip` 及本机公网 IP 集合，
/// 确定性判定细化 [`NatType`]、端口步长与 [`PortRangeHint`]。
///
/// 判定优先级与分支：
/// 1. 全部样本均为空（超时）-> `(NatType::UdpBlocked, None, None)`；
/// 2. `m1` 的规范化 IP 属于可路由公网 IP 且存在于 `local_public_ips`（且若 `m2` 存在则 `m2 == m1`）
///    -> `(NatType::Public, None, None)`；
/// 3. `m1` 或 `m2` 缺失（无法双端口比对）-> `(NatType::Unknown, None, None)`；
/// 4. `m1 == m2`：
///    - 若 `m_alt_ip == Some(m1)` -> `(NatType::ConeVerified, Some(0), None)`；
///    - 若 `m_alt_ip == Some(alt)` 且 `alt != m1` -> 判定 `AdmSeq`（同 IP 且 `1 <= |delta| <= 64`）或 `AdmRandom`；
///    - 若 `m_alt_ip` 为 `None` -> `(NatType::ConeUnverified, Some(0), None)`；
/// 5. `m1 != m2`（APDM）：
///    - 结合所有有效映射端口推断 [`PortRangeHint`]；
///    - 若 `(m3, m4)` 均存在，则仅当 `m3/m4` 同属于 `m1.ip()` 且步长 `d34 == d12`（`1 <= |d12| <= 64`）时
///      判定为 `ApdmSeq`，否则降级为 `ApdmRandom`；
///    - 若 `(m3, m4)` 缺失，则依据 `(m1, m2)` 步长判定 `ApdmSeq` 或 `ApdmRandom`。
pub fn classify_nat_samples(
    samples: &NatProbeSamples,
) -> (NatType, Option<i16>, Option<PortRangeHint>) {
    let m1 = samples.primary.map(canonicalize_socket_addr);
    let m2 = samples.secondary.map(canonicalize_socket_addr);
    let m3 = samples.aux_primary.map(canonicalize_socket_addr);
    let m4 = samples.aux_secondary.map(canonicalize_socket_addr);
    let m_alt = samples.alt_ip.map(canonicalize_socket_addr);

    if m1.is_none() && m2.is_none() && m3.is_none() && m4.is_none() && m_alt.is_none() {
        return (NatType::UdpBlocked, None, None);
    }

    let Some(m1) = m1 else {
        return (NatType::Unknown, None, None);
    };

    if is_routable_public_ip(m1.ip()) {
        let is_local_pub = samples
            .local_public_ips
            .iter()
            .any(|ip| canonicalize_ip(*ip) == m1.ip());
        if is_local_pub && m2.map_or(true, |s| s == m1) && m_alt.map_or(true, |a| a == m1) {
            return (NatType::Public, None, None);
        }
    }

    let Some(m2) = m2 else {
        return (NatType::Unknown, None, None);
    };

    if m1 == m2 {
        return match m_alt {
            Some(alt) if alt == m1 => (NatType::ConeVerified, Some(0), None),
            Some(alt) => {
                let range = infer_port_range_hint(&[m1.port(), alt.port()]);
                match classify_port_step(m1, alt) {
                    Some(delta) => (NatType::AdmSeq, Some(delta), range),
                    None => (NatType::AdmRandom, None, range),
                }
            }
            None => (NatType::ConeUnverified, Some(0), None),
        };
    }

    let mut ports = vec![m1.port(), m2.port()];
    if let Some(a3) = m3 {
        ports.push(a3.port());
    }
    if let Some(a4) = m4 {
        ports.push(a4.port());
    }
    let range = infer_port_range_hint(&ports);
    let d12 = classify_port_step(m1, m2);

    match (m3, m4) {
        (Some(a3), Some(a4)) => {
            let d34 = classify_port_step(a3, a4);
            if a3.ip() == m1.ip() && a4.ip() == m1.ip() {
                if let (Some(delta12), Some(delta34)) = (d12, d34) {
                    if delta12 == delta34 {
                        return (NatType::ApdmSeq, Some(delta12), range);
                    }
                }
            }
            (NatType::ApdmRandom, None, range)
        }
        _ => match d12 {
            Some(delta) => (NatType::ApdmSeq, Some(delta), range),
            None => (NatType::ApdmRandom, None, range),
        },
    }
}

/// 基于主/副两台 STUN-lite 探测端点返回的外网观测地址，确定性判定 NAT 类型与端口步长。
///
/// - 同 IP 且同端口 -> `(NatType::ConeUnverified, Some(0))`
/// - 同 IP 且 `1 <= |delta| <= 64`（含动态段 `1024..=65535` 与全非零段 `1..=65535` 端口回绕）
///   -> `(NatType::ApdmSeq, Some(delta))`
/// - 其他情况（不同 IP 或端口跳变过大）-> `(NatType::ApdmRandom, None)`
pub fn classify_nat_mapping(primary: SocketAddr, secondary: SocketAddr) -> (NatType, Option<i16>) {
    let (nat_type, delta, _) = classify_nat_samples(&NatProbeSamples {
        primary: Some(primary),
        secondary: Some(secondary),
        ..Default::default()
    });
    (nat_type, delta)
}

fn gcd_usize(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

fn coprime_weyl_step(span: usize) -> usize {
    if span <= 1 {
        return 1;
    }
    if span == RANDOM_PORT_SPAN {
        return RANDOM_PORT_WEYL_STEP;
    }
    let approx = ((span as u64) * 618_034 / 1_000_000).max(1) as usize;
    for offset in 0..span {
        let up = (approx + offset) % span;
        if up > 0 && gcd_usize(up, span) == 1 {
            return up;
        }
        if approx > offset {
            let down = approx - offset;
            if down > 0 && gcd_usize(down, span) == 1 {
                return down;
            }
        }
    }
    1
}

/// 为对称 NAT 或未知 NAT 对端生成去重后的候选探测端口序列（不含 `0` 与 `base_port`）。
///
/// 等价于以 `range_hint = None` 调用 [`predict_symmetric_ports_in_range`]。
pub fn predict_symmetric_ports(
    base_port: u16,
    nat_type: NatType,
    delta: Option<i16>,
    max_ports: usize,
) -> Vec<u16> {
    predict_symmetric_ports_in_range(base_port, nat_type, delta, None, max_ports)
}

/// 结合 [`PortRangeHint`] 为对称 NAT 或未知 NAT 对端生成去重后的候选探测端口序列（不含 `0` 与 `base_port`）。
///
/// - `AdmSeq` / `ApdmSeq` 且具备非零 `delta`：先按 `base + k * delta`（`k = 1..=16`，
///   若存在 `range_hint` 且 `base` 在区间内，优先在区间边界回绕）生成步长序列，
///   再补充 `±1..±4` 小邻域，去重截断至 `max_ports`。
/// - `Unknown`（或顺序对称缺少有效非零步长）：生成 `+1..=12` 与 `-1..=-6` 邻域并截断。
/// - `AdmRandom` / `ApdmRandom`：若提供窄于 `Full` 的合法 `range_hint`，优先在该区间内低差异
///   均匀采样（不重复），再按需扩展至 `1024..=65535` 全非系统端口段；否则直接在 `1024..=65535`
///   均匀分布采样并截断至 `max_ports`。
/// - `Public` / `ConeVerified` / `ConeUnverified` / `UdpBlocked`：无需猜测端口，返回空列表。
pub fn predict_symmetric_ports_in_range(
    base_port: u16,
    nat_type: NatType,
    delta: Option<i16>,
    range_hint: Option<PortRangeHint>,
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

    let valid_hint = range_hint.and_then(PortRangeHint::validated);

    match nat_type {
        NatType::Public | NatType::ConeVerified | NatType::ConeUnverified | NatType::UdpBlocked => {
        }
        NatType::AdmSeq | NatType::ApdmSeq => {
            if let Some(step) = delta.filter(|&d| d != 0) {
                let step_i32 = i32::from(step);
                if let Some(hint) = valid_hint {
                    let (min_p, max_p) = hint.bounds();
                    if base_port >= min_p && base_port <= max_p {
                        let span = i32::from(max_p) - i32::from(min_p) + 1;
                        let min_i32 = i32::from(min_p);
                        for k in 1..=16 {
                            let wrapped =
                                min_i32 + (base_i32 - min_i32 + k * step_i32).rem_euclid(span);
                            push_if_valid(&mut out, &mut seen, wrapped);
                        }
                    }
                }
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
        NatType::AdmRandom | NatType::ApdmRandom => {
            if let Some(hint) = valid_hint {
                let (min_p, max_p) = hint.bounds();
                let min_usize = usize::from(min_p);
                let span = usize::from(max_p) - min_usize + 1;
                if min_usize != RANDOM_PORT_MIN || span != RANDOM_PORT_SPAN {
                    let start = usize::from(base_port) % span;
                    let step = coprime_weyl_step(span);
                    for i in 0..span {
                        if out.len() >= max_ports {
                            break;
                        }
                        let offset = (start + i * step) % span;
                        let port = (min_usize + offset) as u16;
                        if port != base_port && seen.insert(port) {
                            out.push(port);
                        }
                    }
                }
            }

            let start = usize::from(base_port) % RANDOM_PORT_SPAN;
            for i in 0..RANDOM_PORT_SPAN {
                if out.len() >= max_ports {
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
    fn nat_type_serde_backward_and_forward_compat() {
        assert_eq!(NatType::default(), NatType::Unknown);
        assert_eq!(NatType::Public.as_str(), "public");
        assert_eq!(NatType::ConeVerified.as_str(), "cone_verified");
        assert_eq!(NatType::ConeUnverified.as_str(), "cone_unverified");
        assert_eq!(NatType::AdmSeq.as_str(), "adm_seq");
        assert_eq!(NatType::AdmRandom.as_str(), "adm_random");
        assert_eq!(NatType::ApdmSeq.as_str(), "apdm_seq");
        assert_eq!(NatType::ApdmRandom.as_str(), "apdm_random");
        assert_eq!(NatType::UdpBlocked.as_str(), "udp_blocked");
        assert_eq!(NatType::Unknown.as_str(), "unknown");

        // 旧版兼容
        assert_eq!(NatType::parse_lossy("cone"), NatType::ConeUnverified);
        assert_eq!(NatType::parse_lossy("  CONE  "), NatType::ConeUnverified);
        assert_eq!(NatType::parse_lossy("Symmetric_Seq"), NatType::ApdmSeq);
        assert_eq!(
            NatType::parse_lossy("symmetric_random"),
            NatType::ApdmRandom
        );
        assert_eq!(NatType::parse_lossy("unknown"), NatType::Unknown);
        assert_eq!(NatType::parse_lossy("garbage"), NatType::Unknown);
        assert_eq!(NatType::parse_lossy(""), NatType::Unknown);

        // JSON 双向兼容反序列化（旧字符串、新字符串、未来未知字符串）
        assert_eq!(
            serde_json::from_str::<NatType>("\"cone\"").unwrap(),
            NatType::ConeUnverified
        );
        assert_eq!(
            serde_json::from_str::<NatType>("\"symmetric_seq\"").unwrap(),
            NatType::ApdmSeq
        );
        assert_eq!(
            serde_json::from_str::<NatType>("\"symmetric_random\"").unwrap(),
            NatType::ApdmRandom
        );
        assert_eq!(
            serde_json::from_str::<NatType>("\"future_nat_v9\"").unwrap(),
            NatType::Unknown
        );

        let profile = NatProfile {
            nat_type: NatType::ApdmSeq,
            port_delta: Some(3),
            port_range: Some(PortRangeHint::LinuxEphemeral),
            public_v4: Some("198.51.100.10:50000".parse().unwrap()),
            public_v6: Some("[2001:db8::1]:50000".parse().unwrap()),
        };
        let json = serde_json::to_string(&profile).unwrap();
        assert!(json.contains("\"apdm_seq\""));
        assert!(json.contains("[32768,60999]"));
        let decoded: NatProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, profile);
    }

    #[test]
    fn port_range_hint_wire_validation_and_inference() {
        assert_eq!(PortRangeHint::LinuxEphemeral.to_wire_pair(), [32768, 60999]);
        assert_eq!(PortRangeHint::IanaDynamic.to_wire_pair(), [49152, 65535]);
        assert_eq!(PortRangeHint::Full.to_wire_pair(), [1024, 65535]);
        assert_eq!(
            PortRangeHint::Custom {
                min: 20000,
                max: 30000
            }
            .to_wire_pair(),
            [20000, 30000]
        );

        assert_eq!(
            PortRangeHint::from_wire_pair([32768, 60999]),
            Some(PortRangeHint::LinuxEphemeral)
        );
        assert_eq!(
            PortRangeHint::from_wire_pair([49152, 65535]),
            Some(PortRangeHint::IanaDynamic)
        );
        assert_eq!(
            PortRangeHint::from_wire_pair([1024, 65535]),
            Some(PortRangeHint::Full)
        );
        assert_eq!(
            PortRangeHint::from_wire_pair([10000, 20000]),
            Some(PortRangeHint::Custom {
                min: 10000,
                max: 20000
            })
        );
        assert_eq!(PortRangeHint::from_wire_pair([0, 20000]), None);
        assert_eq!(PortRangeHint::from_wire_pair([30000, 20000]), None);
        assert!(serde_json::from_str::<PortRangeHint>("[0, 1000]").is_err());
        assert!(serde_json::from_str::<PortRangeHint>("[5000, 4000]").is_err());

        assert_eq!(
            infer_port_range_hint(&[50000, 52000, 64000]),
            Some(PortRangeHint::IanaDynamic)
        );
        assert_eq!(
            infer_port_range_hint(&[33000, 48000, 59000]),
            Some(PortRangeHint::LinuxEphemeral)
        );
        assert_eq!(
            infer_port_range_hint(&[10000, 40000, 62000]),
            Some(PortRangeHint::Full)
        );
        assert_eq!(infer_port_range_hint(&[]), None);
    }

    #[test]
    fn classify_nat_samples_covers_all_variants_and_4_sample_consistency() {
        // 1) 全超时 -> UdpBlocked
        assert_eq!(
            classify_nat_samples(&NatProbeSamples::default()),
            (NatType::UdpBlocked, None, None)
        );

        // 2) 外网映射 IP 等于本机可路由公网 IP -> Public
        assert_eq!(
            classify_nat_samples(&NatProbeSamples {
                primary: Some("198.51.100.10:50000".parse().unwrap()),
                secondary: Some("198.51.100.10:50000".parse().unwrap()),
                local_public_ips: vec!["198.51.100.10".parse().unwrap()],
                ..Default::default()
            }),
            (NatType::Public, None, None)
        );

        // 3) 仅有 m1 无 m2 且非本机公网 IP -> Unknown
        assert_eq!(
            classify_nat_samples(&NatProbeSamples {
                primary: Some("198.51.100.10:50000".parse().unwrap()),
                ..Default::default()
            }),
            (NatType::Unknown, None, None)
        );

        // 4) m1 == m2 且无 m_alt_ip -> ConeUnverified
        assert_eq!(
            classify_nat_samples(&NatProbeSamples {
                primary: Some("198.51.100.10:50000".parse().unwrap()),
                secondary: Some("198.51.100.10:50000".parse().unwrap()),
                ..Default::default()
            }),
            (NatType::ConeUnverified, Some(0), None)
        );

        // 5) m1 == m2 且 m_alt_ip == m1 -> ConeVerified
        assert_eq!(
            classify_nat_samples(&NatProbeSamples {
                primary: Some("198.51.100.10:50000".parse().unwrap()),
                secondary: Some("198.51.100.10:50000".parse().unwrap()),
                alt_ip: Some("198.51.100.10:50000".parse().unwrap()),
                ..Default::default()
            }),
            (NatType::ConeVerified, Some(0), None)
        );

        // 6) m1 == m2 且 m_alt_ip 发生顺序步长变化 -> AdmSeq
        assert_eq!(
            classify_nat_samples(&NatProbeSamples {
                primary: Some("198.51.100.10:50000".parse().unwrap()),
                secondary: Some("198.51.100.10:50000".parse().unwrap()),
                alt_ip: Some("198.51.100.10:50004".parse().unwrap()),
                ..Default::default()
            }),
            (NatType::AdmSeq, Some(4), Some(PortRangeHint::IanaDynamic))
        );

        // 7) m1 == m2 且 m_alt_ip 大跳变或切换出口 IP -> AdmRandom
        assert_eq!(
            classify_nat_samples(&NatProbeSamples {
                primary: Some("198.51.100.10:40000".parse().unwrap()),
                secondary: Some("198.51.100.10:40000".parse().unwrap()),
                alt_ip: Some("198.51.100.11:55000".parse().unwrap()),
                ..Default::default()
            }),
            (
                NatType::AdmRandom,
                None,
                Some(PortRangeHint::LinuxEphemeral)
            )
        );

        // 8) m1 != m2 且 (m3, m4) 步长一致 -> ApdmSeq
        assert_eq!(
            classify_nat_samples(&NatProbeSamples {
                primary: Some("198.51.100.10:40000".parse().unwrap()),
                secondary: Some("198.51.100.10:40003".parse().unwrap()),
                aux_primary: Some("198.51.100.10:41000".parse().unwrap()),
                aux_secondary: Some("198.51.100.10:41003".parse().unwrap()),
                ..Default::default()
            }),
            (
                NatType::ApdmSeq,
                Some(3),
                Some(PortRangeHint::LinuxEphemeral)
            )
        );

        // 9) m1 != m2 看似步长 +3，但 (m3, m4) 步长不一致 -> 否定顺序步长并归类为 ApdmRandom
        assert_eq!(
            classify_nat_samples(&NatProbeSamples {
                primary: Some("198.51.100.10:50000".parse().unwrap()),
                secondary: Some("198.51.100.10:50003".parse().unwrap()),
                aux_primary: Some("198.51.100.10:52000".parse().unwrap()),
                aux_secondary: Some("198.51.100.10:52019".parse().unwrap()),
                ..Default::default()
            }),
            (NatType::ApdmRandom, None, Some(PortRangeHint::IanaDynamic))
        );
    }

    #[test]
    fn classify_nat_mapping_handles_cone_seq_negative_high_ports_and_random() {
        let p_cone: SocketAddr = "198.51.100.2:45000".parse().unwrap();
        let s_cone: SocketAddr = "[::ffff:198.51.100.2]:45000".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_cone, s_cone),
            (NatType::ConeUnverified, Some(0))
        );

        // 正步长与高位端口（>32768）不溢出
        let p_seq: SocketAddr = "198.51.100.2:50000".parse().unwrap();
        let s_seq_pos: SocketAddr = "198.51.100.2:50003".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_seq_pos),
            (NatType::ApdmSeq, Some(3))
        );

        // 负步长且边界 64
        let s_seq_neg: SocketAddr = "198.51.100.2:49936".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_seq_neg),
            (NatType::ApdmSeq, Some(-64))
        );

        // 超过 64 视为随机对称
        let s_far: SocketAddr = "198.51.100.2:50065".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_far),
            (NatType::ApdmRandom, None)
        );
        let s_far_neg: SocketAddr = "198.51.100.2:49935".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_far_neg),
            (NatType::ApdmRandom, None)
        );

        // 不同 IP（多出口 NAT 池）视为随机对称
        let s_diff_ip: SocketAddr = "198.51.100.3:50000".parse().unwrap();
        assert_eq!(
            classify_nat_mapping(p_seq, s_diff_ip),
            (NatType::ApdmRandom, None)
        );

        // 动态段 1024..=65535 端口边界回绕（65534 -> 1025 => +3，1025 -> 65534 => -3）
        assert_eq!(
            classify_nat_mapping(
                "198.51.100.2:65534".parse().unwrap(),
                "198.51.100.2:1025".parse().unwrap(),
            ),
            (NatType::ApdmSeq, Some(3))
        );
        assert_eq!(
            classify_nat_mapping(
                "198.51.100.2:1025".parse().unwrap(),
                "198.51.100.2:65534".parse().unwrap(),
            ),
            (NatType::ApdmSeq, Some(-3))
        );

        // 全非零段 1..=65535 端口边界回绕（65535 -> 1 => +1，1 -> 65535 => -1）
        assert_eq!(
            classify_nat_mapping(
                "198.51.100.2:65535".parse().unwrap(),
                "198.51.100.2:1".parse().unwrap(),
            ),
            (NatType::ApdmSeq, Some(1))
        );
        assert_eq!(
            classify_nat_mapping(
                "198.51.100.2:1".parse().unwrap(),
                "198.51.100.2:65535".parse().unwrap(),
            ),
            (NatType::ApdmSeq, Some(-1))
        );
    }

    #[test]
    fn predict_symmetric_ports_covers_seq_unknown_random_range_hint_and_truncates() {
        // Cone / Public / UdpBlocked 返回空
        assert!(predict_symmetric_ports(40000, NatType::ConeVerified, Some(0), 16).is_empty());
        assert!(predict_symmetric_ports(40000, NatType::ConeUnverified, Some(0), 16).is_empty());
        assert!(predict_symmetric_ports(40000, NatType::Public, None, 16).is_empty());
        assert!(predict_symmetric_ports(40000, NatType::UdpBlocked, None, 16).is_empty());

        // ApdmSeq +3：先 1..=16 步长，再补 ±1..±4 并去重排除 base 与 0（+3 与 k=1 重合故共 23 个）
        let seq = predict_symmetric_ports(40000, NatType::ApdmSeq, Some(3), 24);
        assert_eq!(seq.len(), 23);
        assert_eq!(seq[0], 40003);
        assert_eq!(seq[1], 40006);
        assert_eq!(seq[15], 40048);
        assert!(!seq.contains(&40000));
        assert!(!seq.contains(&0));
        let uniq: HashSet<u16> = seq.iter().copied().collect();
        assert_eq!(uniq.len(), seq.len());
        assert_eq!(
            predict_symmetric_ports(40000, NatType::ApdmSeq, Some(3), 20).len(),
            20
        );

        // 带 PortRangeHint 的顺序回绕（LinuxEphemeral 上界 60999 -> 32768）
        let wrapped_seq = predict_symmetric_ports_in_range(
            60998,
            NatType::ApdmSeq,
            Some(3),
            Some(PortRangeHint::LinuxEphemeral),
            8,
        );
        assert_eq!(wrapped_seq[0], 32769);
        assert_eq!(wrapped_seq[1], 32772);

        // ApdmSeq 接近 65535 时越界过滤、不生成 0
        let edge_seq = predict_symmetric_ports(65530, NatType::ApdmSeq, Some(3), 16);
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

        // ApdmRandom（无范围提示）：1024..=65535 均匀分布、无重复、不含 base_port
        let rnd = predict_symmetric_ports(34567, NatType::ApdmRandom, None, 64);
        assert_eq!(rnd.len(), 64);
        assert!(!rnd.contains(&34567));
        assert!(rnd.iter().all(|&p| p >= 1024));
        let rnd_uniq: HashSet<u16> = rnd.iter().copied().collect();
        assert_eq!(rnd_uniq.len(), 64);
        let low = rnd.iter().filter(|&&p| p < 16384).count();
        let mid_low = rnd.iter().filter(|&&p| (16384..32768).contains(&p)).count();
        let mid_high = rnd.iter().filter(|&&p| (32768..49152).contains(&p)).count();
        let high = rnd.iter().filter(|&&p| p >= 49152).count();
        assert!(low >= 8 && mid_low >= 8 && mid_high >= 8 && high >= 8);

        // 范围感知采样：先采满 Custom { 50000..=50019 }（排除 base=50005 共 19 个），再扩至全段
        let ranged = predict_symmetric_ports_in_range(
            50005,
            NatType::AdmRandom,
            None,
            Some(PortRangeHint::Custom {
                min: 50000,
                max: 50019,
            }),
            40,
        );
        assert_eq!(ranged.len(), 40);
        assert!(!ranged.contains(&50005));
        assert!(ranged[..19].iter().all(|&p| (50000..=50019).contains(&p)));
        let ranged_uniq: HashSet<u16> = ranged.iter().copied().collect();
        assert_eq!(ranged_uniq.len(), 40);
        assert!(ranged[19..].iter().any(|&p| !(50000..=50019).contains(&p)));
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
        assert_eq!(
            same_public_ip(Some("[::ffff:198.51.100.22]:60123"), Some("198.51.100.22")),
            Some(true)
        );
        assert_eq!(
            same_public_ip(Some("198.51.100.22:60123"), Some("203.0.113.9:60123")),
            Some(false)
        );
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
        assert_eq!(
            same_public_ip_any(
                &["[240e:3b0:1::10]:40000", "198.51.100.22:60000"],
                &["198.51.100.22:50001"],
            ),
            Some(true)
        );
        assert_eq!(
            same_public_ip_any(
                &["198.51.100.22:60000", "[240e:3b0:1::10]:40000"],
                &["203.0.113.9:50001", "240e:3b0:1::10"],
            ),
            Some(true)
        );
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
