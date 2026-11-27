//! P2P UDP 打洞与直连 QUIC 建连引擎（`RCP2` 打洞协议 + `QuicEndpoint::from_socket`）。
//!
//! 本模块负责在信令协调（`punch_coord`）下发对端候选地址后，于极短窗口内完成
//! 双向 UDP 打洞并直接在已打通的 `UdpSocket` 上建立 QUIC 连接；若遇到对称 NAT
//! 或 UDP 阻断，则在超时或取消后快速失败，由上层无缝回退至 TCP 中继。
//!
//! # `RCP2` 29 字节打洞包布局
//!
//! ```text
//! [0..4]   magic:        b"RCP2"
//! [4]      version:      u8 = 1
//! [5]      role:         u8 (1 = Host, 2 = Client)
//! [6]      ack:          u8 (0 = Probe, 1 = Ack)
//! [7..23]  session_hash: [u8; 16]（由 session_id 确定性派生）
//! [23..29] nonce:        [u8; 6]（本次打洞随机防重放标记）
//! ```

//! # `RCP2 v2` 48 字节认证打洞包布局（提供 `punch_secret` 时默认启用；缺失/非法时平滑回退 `v1` 29 字节）
//!
//! ```text
//! [0..4]   magic:        b"RCP2"
//! [4]      version:      u8 = 2
//! [5]      role:         u8 (1 = Host, 2 = Client)
//! [6]      flags:        u8 (bit0 = Ack)
//! [7]      reserved:     u8 = 0
//! [8..16]  session_hash: [u8; 8]  = SHA256(session_id)[..8]
//! [16..24] sender_nonce: [u8; 8]
//! [24..32] echo_nonce:   [u8; 8]  （Probe 固定 [0; 8]；Ack 回显对端 sender_nonce）
//! [32..48] mac_tag:      [u8; 16] = HMAC-SHA256(punch_secret, bytes[0..32])[..16]
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use rc_net::mtls::{MtlsConfig, PeerMtlsIdentity};
use rc_net::quic::{Identity, QuicEndpoint, QuicTransport};
use rc_net::{NetConfig, NetEvent, NetStats, Role, Transport};
use ring::hmac;
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::nat::{
    canonicalize_ip, canonicalize_socket_addr, is_global_unicast_ipv6, is_routable_public_ip,
    predict_symmetric_ports_in_range, NatType, PortRangeHint,
};

/// UDP 打洞包魔数（`RCP2`）。
pub const PUNCH_MAGIC: &[u8; 4] = b"RCP2";

/// `RCP2 v1` 兼容打洞协议版本（29 字节无 MAC）。
pub const PUNCH_VERSION: u8 = 1;

/// `RCP2 v2` HMAC 认证打洞协议版本（48 字节）。
pub const PUNCH_VERSION_V2: u8 = 2;

/// `RCP2 v1` 打洞包定长字节数（4 + 1 + 1 + 1 + 16 + 6 = 29）。
pub const PUNCH_PACKET_LEN: usize = 29;

/// `RCP2 v2` 认证打洞包定长字节数（4 + 1 + 1 + 1 + 1 + 8 + 8 + 8 + 16 = 48）。
pub const PUNCH_V2_PACKET_LEN: usize = 48;

/// `RCP2 v2` `flags` 字段确认位掩码（`bit 0 = Ack`）。
pub const PUNCH_V2_FLAG_ACK: u8 = 0x01;

/// `RCP2 v2` 单源 IP 回复 Ack 的最小限频间隔（严格 1.0x 等长 48B 回复，防反射放大）。
const ACK_RATE_MIN_INTERVAL: Duration = Duration::from_millis(20);

/// `RCP2 v2` 单源 IP 限频表最大跟踪 IP 数。
const MAX_ACK_RATE_TRACKED_IPS: usize = 128;

/// 默认 UDP 打洞超时（超时后上层回退 TCP 中继）。
pub const DEFAULT_PUNCH_TIMEOUT: Duration = Duration::from_millis(2_400);

/// 打洞成功后默认的 QUIC 握手超时。
pub const DEFAULT_QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// 探测包周期发送间隔。
const PROBE_INTERVAL: Duration = Duration::from_millis(30);

/// Phase 1 主候选地址高速探测窗口时长（超时未收敛则切入后续阶段）。
const PHASE1_DURATION: Duration = Duration::from_millis(350);

/// `ConeUnverified ↔ ConeUnverified` Phase 2a（窄邻域探测）结束时间点。
const PHASE2A_END: Duration = Duration::from_millis(1_200);

/// `ConeUnverified ↔ ConeUnverified` 激活 Phase 2b（角色交替喷洒）所需的最小总超时门槛。
const PHASE2B_MIN_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

/// RTT 同步起跑最大允许延迟上限（毫秒）。
const MAX_START_AFTER_MS: u16 = 500;

/// 辅助临时 UDP 套接字硬上限（防止耗尽进程 FD）。
const MAX_AUX_SOCKETS_HARD_CAP: usize = 96;

/// `Cone* ↔ ApdmSeq/AdmSeq` 对称侧辅助套接字数量。
const AUX_SEQ_TO_CONE_COUNT: usize = 8;

/// `ApdmSeq ↔ ApdmSeq`（`|delta| == 1`）定向会师辅助套接字数量。
const AUX_APDM_SEQ_DELTA1_COUNT: usize = 48;

/// `ApdmSeq ↔ ApdmSeq`（`2 <= |delta| <= 4`）定向会师辅助套接字数量。
const AUX_APDM_SEQ_DELTA2_4_COUNT: usize = 24;

/// 单个 tick 内 Cone 侧最多发送的预测端口数（`6 / 30ms = 200 pps` 上限）。
const MAX_PREDICTED_PORTS_PER_TICK: usize = 6;

/// 单波次 Cone 侧随机端口扫描预算。
const CONE_SCAN_BUDGET_PER_WAVE: usize = 512;

/// 单次 tick 最多轮转发送探测包的辅助套接字数量（抑制突发 UDP 洪泛）。
const MAX_AUX_PROBES_PER_TICK: usize = 24;

/// 接收轮询与取消检查步长。
const POLL_STEP: Duration = Duration::from_millis(5);

/// 收到有效包时立即连发 Ack 的次数（对抗弱网单包丢失）。
const IMMEDIATE_ACK_BURST: usize = 3;

/// Happy Eyeballs v2（RFC 8305）双栈探测时全球单播 IPv6 的领先起跑窗口（50ms），
/// 期满后立即与 LAN/IPv4 并发探测，IPv6 不可达或超时对 IPv4 打洞 0 阻塞。
const HAPPY_EYEBALLS_V6_HEAD_START: Duration = Duration::from_millis(50);

/// P2P 打洞角色（与信令协调中的 `host` / `client` 一一对应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum P2pRole {
    /// 被控端：打洞成功后作为 QUIC 服务端调用 `accept`。
    Host = 1,
    /// 控制端：打洞成功后作为 QUIC 客户端调用 `connect`。
    Client = 2,
}

impl P2pRole {
    /// 返回对端应具备的角色（仅接受异侧角色包，防止自环或同侧误匹配）。
    pub const fn opposite(self) -> Self {
        match self {
            Self::Host => Self::Client,
            Self::Client => Self::Host,
        }
    }

    /// 从线缆字节解析角色。
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Host),
            2 => Some(Self::Client),
            _ => None,
        }
    }
}

/// P2P 建连所需的对端候选地址与本地端口提示。
#[derive(Debug, Clone, Default)]
pub struct P2pCandidates {
    /// 信令协调下发的会话标识（用于派生会话哈希）。
    pub session_id: String,
    /// 信令服务器观测到的对端公网 UDP 地址（如 `"198.51.100.22:60123"`）。
    pub peer_public_addr: Option<String>,
    /// 信令服务器观测到的对端双栈公网 UDP 地址列表（IPv6 + IPv4）。
    pub peer_public_addrs: Vec<String>,
    /// 对端上报的局域网候选地址列表（优先级高于公网地址）。
    pub peer_lan_addrs: Vec<String>,
    /// 本端持久化 UDP `RCSP` 探测套接字绑定的本地端口（优先复用以对齐 NAT 映射）。
    pub local_udp_port: Option<u16>,
    /// 本端探测到的 NAT 类型。
    pub self_nat_type: NatType,
    /// 本端顺序对称 NAT 分配端口步长（如有）。
    pub self_nat_port_delta: Option<i16>,
    /// 本端 NAT 外网端口区间提示（如有）。
    pub self_nat_port_range: Option<PortRangeHint>,
    /// 对端上报的 NAT 类型。
    pub peer_nat_type: NatType,
    /// 对端顺序对称 NAT 分配端口步长（如有）。
    pub peer_nat_port_delta: Option<i16>,
    /// 对端 NAT 外网端口区间提示（如有）。
    pub peer_nat_port_range: Option<PortRangeHint>,
    /// 服务端下发的会话共享 `RCP2 v2` HMAC 密钥（32 位十六进制字符串，缺失或非法时回退 `v1`）。
    pub punch_secret: Option<String>,
    /// 服务端协调的快侧打洞起跑延迟（毫秒）。
    pub start_after_ms: Option<u16>,
    /// 服务端协调的并发中继回退延迟（毫秒）。
    pub relay_fallback_after_ms: Option<u16>,
}

/// 解码后的 `RCP2 v1` 29 字节 UDP 打洞包。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchPacket {
    /// 协议版本号（固定为 [`PUNCH_VERSION`] = `1`）。
    pub version: u8,
    /// 发送方角色。
    pub role: P2pRole,
    /// 是否为确认包（`false` = Probe，`true` = Ack）。
    pub ack: bool,
    /// 会话 ID 派生的 16 字节哈希。
    pub session_hash: [u8; 16],
    /// 6 字节随机 nonce。
    pub nonce: [u8; 6],
}

/// 解码且通过 HMAC-SHA256 校验后的 `RCP2 v2` 48 字节认证打洞包。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchPacketV2 {
    /// 协议版本号（固定为 [`PUNCH_VERSION_V2`] = `2`）。
    pub version: u8,
    /// 发送方角色。
    pub role: P2pRole,
    /// 标志位（`bit 0` = Ack）。
    pub flags: u8,
    /// 保留字节（固定为 `0`）。
    pub reserved: u8,
    /// `SHA256(session_id)[..8]`。
    pub session_hash: [u8; 8],
    /// 发送方 8 字节随机 nonce。
    pub sender_nonce: [u8; 8],
    /// 回显对端 `sender_nonce`（`Probe` 固定 `[0; 8]`，`Ack` 填对端 `sender_nonce`）。
    pub echo_nonce: [u8; 8],
    /// 16 字节截断 HMAC-SHA256 标签。
    pub mac_tag: [u8; 16],
}

static LOCAL_UDP_PORT_LEASES: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();

fn local_udp_port_leases() -> &'static Mutex<HashSet<u16>> {
    LOCAL_UDP_PORT_LEASES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// 进程级本地 UDP 端口租约守卫：确保同一 `local_udp_port` 最多只有一个未 `connect` 的
/// `SO_REUSEPORT` P2P/QUIC 套接字同时存在，避免多个未连接套接字在内核分流导致随机丢包。
#[derive(Debug)]
struct LocalUdpPortLease {
    port: u16,
}

impl LocalUdpPortLease {
    fn try_acquire(port: u16) -> Option<Self> {
        if port == 0 {
            return None;
        }
        let mut set = local_udp_port_leases()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if set.insert(port) {
            Some(Self { port })
        } else {
            None
        }
    }
}

impl Drop for LocalUdpPortLease {
    fn drop(&mut self) {
        let mut set = local_udp_port_leases()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set.remove(&self.port);
    }
}

/// P2P 直连 QUIC 传输封装：对外透明实现 [`rc_net::Transport`]，内部持有
/// [`QuicEndpoint`] 以保证连接存活期间底层 UDP 端点与驱动不提前释放。
pub struct P2pQuicConnection {
    /// 底层 QUIC 传输通道（datagram + reliable + urgent）。
    pub transport: QuicTransport,
    /// 实际建连成功的对端 UDP 地址。
    pub peer_addr: SocketAddr,
    /// 建连阶段测得的 RTT 估计（微秒）。
    pub rtt_us: u32,
    /// 保持端点存活，声明顺序位于 `transport` 之后以确保 `Drop` 时先关连接再释放端点。
    _endpoint: QuicEndpoint,
    /// 本地打洞端口租约，声明顺序位于 `_endpoint` 之后以确保端点关闭后再归还端口租约。
    _port_lease: Option<LocalUdpPortLease>,
}

impl P2pQuicConnection {
    /// 若本次 P2P QUIC 握手经过 mTLS 验证，返回对端证书身份。
    pub fn peer_mtls_identity(&self) -> Option<PeerMtlsIdentity> {
        self.transport.peer_mtls_identity()
    }
}

impl Transport for P2pQuicConnection {
    fn send_datagram(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.transport.send_datagram(data)
    }

    fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.transport.send_reliable(data)
    }

    fn send_reliable_urgent(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.transport.send_reliable_urgent(data)
    }

    fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
        self.transport.poll(timeout)
    }

    fn stats(&self) -> NetStats {
        self.transport.stats()
    }

    fn set_pacing_rate(&mut self, bps: u64) {
        self.transport.set_pacing_rate(bps);
    }

    fn tx_queued_bytes(&self) -> usize {
        self.transport.tx_queued_bytes()
    }

    fn tx_dropped_datagrams(&self) -> u64 {
        self.transport.tx_dropped_datagrams()
    }
}

/// 将 [`PunchPacket`] 编码为 29 字节固定二进制包（`RCP2 v1` 兼容格式）。
pub fn encode_punch_packet(pkt: &PunchPacket) -> [u8; PUNCH_PACKET_LEN] {
    let mut out = [0u8; PUNCH_PACKET_LEN];
    out[0..4].copy_from_slice(PUNCH_MAGIC);
    out[4] = pkt.version;
    out[5] = pkt.role as u8;
    out[6] = u8::from(pkt.ack);
    out[7..23].copy_from_slice(&pkt.session_hash);
    out[23..29].copy_from_slice(&pkt.nonce);
    out
}

/// 从 UDP 载荷解码 29 字节 `RCP2 v1` 打洞包；长度、魔数、版本、角色或确认位非法均返回 `None`。
pub fn decode_punch_packet(buf: &[u8]) -> Option<PunchPacket> {
    if buf.len() != PUNCH_PACKET_LEN {
        return None;
    }
    if &buf[0..4] != PUNCH_MAGIC {
        return None;
    }
    let version = buf[4];
    if version != PUNCH_VERSION {
        return None;
    }
    let role = P2pRole::from_u8(buf[5])?;
    let ack = match buf[6] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let mut session_hash = [0u8; 16];
    session_hash.copy_from_slice(&buf[7..23]);
    let mut nonce = [0u8; 6];
    nonce.copy_from_slice(&buf[23..29]);
    Some(PunchPacket {
        version,
        role,
        ack,
        session_hash,
        nonce,
    })
}

/// 解析 32 位十六进制 `punch_secret` 为 16 字节原始 HMAC 密钥；缺失或非法时返回 `None`（回退 `RCP2 v1`）。
pub fn parse_punch_secret(raw: Option<&str>) -> Option<[u8; 16]> {
    let hex = raw?.trim();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[idx] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// 由 `session_id` 派生 `RCP2 v2` 8 字节会话哈希：`SHA256(session_id)[..8]`。
pub fn derive_session_hash_v2(session_id: &str) -> [u8; 8] {
    let digest = Sha256::digest(session_id.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// 构造并签名 48 字节 `RCP2 v2` HMAC-SHA256 认证打洞报文。
///
/// - `Probe` (`ack = false`) 中 `echo_nonce` 应为 `[0; 8]`；
/// - `Ack` (`ack = true`) 中 `echo_nonce` 回显对端 `sender_nonce`。
pub fn encode_punch_packet_v2(
    role: P2pRole,
    ack: bool,
    session_hash: [u8; 8],
    sender_nonce: [u8; 8],
    echo_nonce: [u8; 8],
    punch_secret: &[u8; 16],
) -> [u8; PUNCH_V2_PACKET_LEN] {
    let mut out = [0u8; PUNCH_V2_PACKET_LEN];
    out[0..4].copy_from_slice(PUNCH_MAGIC);
    out[4] = PUNCH_VERSION_V2;
    out[5] = role as u8;
    out[6] = if ack { PUNCH_V2_FLAG_ACK } else { 0 };
    out[7] = 0;
    out[8..16].copy_from_slice(&session_hash);
    out[16..24].copy_from_slice(&sender_nonce);
    out[24..32].copy_from_slice(&echo_nonce);

    let key = hmac::Key::new(hmac::HMAC_SHA256, punch_secret);
    let tag = hmac::sign(&key, &out[0..32]);
    out[32..48].copy_from_slice(&tag.as_ref()[..16]);
    out
}

/// 解码并常量时间验签 48 字节 `RCP2 v2` 认证打洞报文；任何字段或 MAC 失败均返回 `None`。
pub fn decode_and_verify_punch_packet_v2(
    buf: &[u8],
    punch_secret: &[u8; 16],
) -> Option<PunchPacketV2> {
    if buf.len() != PUNCH_V2_PACKET_LEN {
        return None;
    }
    if &buf[0..4] != PUNCH_MAGIC {
        return None;
    }
    if buf[4] != PUNCH_VERSION_V2 {
        return None;
    }
    let role = P2pRole::from_u8(buf[5])?;
    let flags = buf[6];
    if (flags & !PUNCH_V2_FLAG_ACK) != 0 {
        return None;
    }
    let reserved = buf[7];
    if reserved != 0 {
        return None;
    }

    let key = hmac::Key::new(hmac::HMAC_SHA256, punch_secret);
    let expected = hmac::sign(&key, &buf[0..32]);
    let expected_tag = &expected.as_ref()[..16];
    let recv_tag = &buf[32..48];
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected_tag[i] ^ recv_tag[i];
    }
    if diff != 0 {
        return None;
    }

    let mut session_hash = [0u8; 8];
    session_hash.copy_from_slice(&buf[8..16]);
    let mut sender_nonce = [0u8; 8];
    sender_nonce.copy_from_slice(&buf[16..24]);
    let mut echo_nonce = [0u8; 8];
    echo_nonce.copy_from_slice(&buf[24..32]);
    let mut mac_tag = [0u8; 16];
    mac_tag.copy_from_slice(&buf[32..48]);

    Some(PunchPacketV2 {
        version: PUNCH_VERSION_V2,
        role,
        flags,
        reserved,
        session_hash,
        sender_nonce,
        echo_nonce,
        mac_tag,
    })
}

fn parse_valid_candidate_addr(raw: &str) -> Option<SocketAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = trimmed.parse::<SocketAddr>().ok()?;
    let normalized = canonicalize_socket_addr(parsed);
    if normalized.port() == 0 || normalized.ip().is_unspecified() {
        return None;
    }
    Some(normalized)
}

/// 解析并排序对端候选 UDP 地址，自动去重并过滤非法、端口为 0 或未指定地址（`0.0.0.0` / `::`）。
///
/// - 当 `peer_public_addrs` 非空时，合并 `peer_public_addrs`、`peer_public_addr` 与 `peer_lan_addrs` 并按
///   **全球单播 IPv6 → 私有 LAN 地址 → 公网 IPv4** 排序；
/// - 当 `peer_public_addrs` 为空时，保留历史顺序（`peer_lan_addrs` 优先于 `peer_public_addr`）。
pub fn parse_candidate_addrs(candidates: &P2pCandidates) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    if candidates.peer_public_addrs.is_empty() {
        let mut global_v6 = Vec::new();
        let mut others = Vec::new();
        for lan in &candidates.peer_lan_addrs {
            if let Some(addr) = parse_valid_candidate_addr(lan) {
                if seen.insert(addr) {
                    if matches!(addr, SocketAddr::V6(v6) if is_global_unicast_ipv6(*v6.ip())) {
                        global_v6.push(addr);
                    } else {
                        others.push(addr);
                    }
                }
            }
        }
        if let Some(ref public) = candidates.peer_public_addr {
            if let Some(addr) = parse_valid_candidate_addr(public) {
                if seen.insert(addr) {
                    if matches!(addr, SocketAddr::V6(v6) if is_global_unicast_ipv6(*v6.ip())) {
                        global_v6.push(addr);
                    } else {
                        others.push(addr);
                    }
                }
            }
        }
        global_v6.extend(others);
        return global_v6;
    }

    let mut global_v6 = Vec::new();
    let mut lan_addrs = Vec::new();
    let mut public_v4 = Vec::new();

    for raw in candidates
        .peer_public_addrs
        .iter()
        .map(String::as_str)
        .chain(candidates.peer_public_addr.as_deref())
        .chain(candidates.peer_lan_addrs.iter().map(String::as_str))
    {
        let Some(addr) = parse_valid_candidate_addr(raw) else {
            continue;
        };
        if !seen.insert(addr) {
            continue;
        }
        match addr {
            SocketAddr::V6(v6) if is_global_unicast_ipv6(*v6.ip()) => global_v6.push(addr),
            _ if !is_routable_public_ip(addr.ip()) => lan_addrs.push(addr),
            _ => public_v4.push(addr),
        }
    }

    let mut out = Vec::with_capacity(global_v6.len() + lan_addrs.len() + public_v4.len());
    out.extend(global_v6);
    out.extend(lan_addrs);
    out.extend(public_v4);
    out
}

/// 由 `session_id` 确定性派生 16 字节会话哈希（零外部依赖，纯 Rust 双路域分离 FNV-1a + 终态雪崩混合）。
pub fn derive_session_hash(session_id: &str) -> [u8; 16] {
    let h0 = fnv1a_64_mixed(b"rc-p2p-session-v1-lo:", session_id.as_bytes());
    let h1 = fnv1a_64_mixed(b"rc-p2p-session-v1-hi:", session_id.as_bytes());
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&h0.to_be_bytes());
    out[8..16].copy_from_slice(&h1.to_be_bytes());
    out
}

fn fnv1a_64_mixed(domain: &[u8], data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for &b in domain.iter().chain(data.iter()) {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    // 两轮 SplitMix64 终态雪崩混合，确保任意 1 bit 输入差异扩散到全部 64 位。
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
}

/// 将地址适配为当前套接字的地址族：
/// - `AF_INET6`（含双栈）套接字绝不剥离 `::ffff:` 前缀，且将 `V4` 映射为 IPv4-mapped IPv6；
/// - `AF_INET` 套接字则统一解包为 `V4`。
fn normalize_addr_for_socket(addr: SocketAddr, socket_is_ipv6: bool) -> SocketAddr {
    if socket_is_ipv6 {
        match addr {
            SocketAddr::V6(v6) => SocketAddr::V6(v6),
            SocketAddr::V4(v4) => {
                SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
            }
        }
    } else {
        canonicalize_socket_addr(addr)
    }
}

fn map_targets_for_socket(all_targets: &[SocketAddr], socket_is_ipv6: bool) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(all_targets.len());
    for &addr in all_targets {
        if socket_is_ipv6 {
            out.push(normalize_addr_for_socket(addr, true));
        } else if addr.is_ipv4() {
            out.push(addr);
        }
    }
    out
}

fn bind_punch_socket(
    preferred_port: Option<u16>,
    use_ipv6: bool,
    require_dual_stack: bool,
) -> Result<(UdpSocket, Option<LocalUdpPortLease>), String> {
    let try_bind = |port: u16, reuse_port: bool| -> Result<UdpSocket, std::io::Error> {
        let (domain, addr) = if use_ipv6 {
            (Domain::IPV6, SocketAddr::from(([0u16; 8], port)))
        } else {
            (Domain::IPV4, SocketAddr::from(([0u8; 4], port)))
        };
        let raw = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if use_ipv6 {
            if require_dual_stack {
                raw.set_only_v6(false)?;
            } else {
                let _ = raw.set_only_v6(false);
            }
        }
        if reuse_port {
            let _ = raw.set_reuse_address(true);
            #[cfg(unix)]
            let _ = raw.set_reuse_port(true);
        }
        raw.bind(&SockAddr::from(addr))?;
        let sock: UdpSocket = raw.into();
        sock.set_nonblocking(true)?;
        Ok(sock)
    };

    if let Some(port) = preferred_port.filter(|&p| p != 0) {
        if let Some(lease) = LocalUdpPortLease::try_acquire(port) {
            if let Ok(sock) = try_bind(port, true) {
                return Ok((sock, Some(lease)));
            }
            drop(lease);
        }
    }

    // 端口租约已被同进程其他在途/活跃 P2P 连接占用，或优选端口不可用时，
    // 绝不创建第二个未 connect 的 SO_REUSEPORT 套接字：直接以无 SO_REUSEPORT 的临时端口 `0` 绑定。
    let sock = try_bind(0, false).map_err(|e| format!("绑定 P2P UDP 打洞套接字失败：{e}"))?;
    Ok((sock, None))
}

struct PunchSetup {
    socket: UdpSocket,
    port_lease: Option<LocalUdpPortLease>,
    targets: Vec<SocketAddr>,
    socket_is_ipv6: bool,
}

fn prepare_punch_socket_and_targets(
    candidates: &P2pCandidates,
    all_targets: &[SocketAddr],
) -> Result<PunchSetup, String> {
    let has_ipv6 = all_targets.iter().any(SocketAddr::is_ipv6);
    let has_ipv4 = all_targets.iter().any(SocketAddr::is_ipv4);

    if has_ipv6 {
        // 只要存在 IPv6 候选（纯 IPv6 或 IPv4+IPv6 混合），优先创建双栈 AF_INET6 套接字，
        // 保留全部 IPv6 候选并将 IPv4 候选映射为 ::ffff:a.b.c.d，绝不因存在 IPv4 LAN 地址而丢弃 IPv6 公网候选。
        match bind_punch_socket(candidates.local_udp_port, true, has_ipv4) {
            Ok((socket, port_lease)) => {
                let targets = map_targets_for_socket(all_targets, true);
                return Ok(PunchSetup {
                    socket,
                    port_lease,
                    targets,
                    socket_is_ipv6: true,
                });
            }
            Err(v6_err) => {
                if !has_ipv4 {
                    return Err(v6_err);
                }
            }
        }
    }

    let (socket, port_lease) = bind_punch_socket(candidates.local_udp_port, false, false)?;
    let targets = map_targets_for_socket(all_targets, false);
    Ok(PunchSetup {
        socket,
        port_lease,
        targets,
        socket_is_ipv6: false,
    })
}

struct PunchedSocket {
    socket: UdpSocket,
    peer_addr: SocketAddr,
    elapsed: Duration,
    port_lease: Option<LocalUdpPortLease>,
}

struct AuxPunchSocket {
    socket: UdpSocket,
    confirmed_peer: Option<SocketAddr>,
    peer_sender_nonce: Option<[u8; 8]>,
    auth: PunchAuthMode,
}

#[derive(Default)]
struct AckRateLimiter {
    last_reply_by_ip: HashMap<IpAddr, Instant>,
}

impl AckRateLimiter {
    fn allow_reply(&mut self, ip: IpAddr, now: Instant) -> bool {
        let canon_ip = canonicalize_ip(ip);
        if let Some(&last) = self.last_reply_by_ip.get(&canon_ip) {
            if now.saturating_duration_since(last) < ACK_RATE_MIN_INTERVAL {
                return false;
            }
        } else if self.last_reply_by_ip.len() >= MAX_ACK_RATE_TRACKED_IPS {
            if let Some(oldest_ip) = self
                .last_reply_by_ip
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| *k)
            {
                self.last_reply_by_ip.remove(&oldest_ip);
            }
        }
        self.last_reply_by_ip.insert(canon_ip, now);
        true
    }
}

enum PunchAuthMode {
    V1 {
        session_hash: [u8; 16],
        probe_pkt: [u8; PUNCH_PACKET_LEN],
        ack_pkt: [u8; PUNCH_PACKET_LEN],
    },
    V2 {
        role: P2pRole,
        secret: [u8; 16],
        session_hash: [u8; 8],
        local_sender_nonce: [u8; 8],
        probe_pkt: [u8; PUNCH_V2_PACKET_LEN],
        rate_limiter: AckRateLimiter,
    },
}

impl PunchAuthMode {
    fn new(role: P2pRole, session_id: &str, punch_secret: Option<&str>) -> Self {
        if let Some(secret) = parse_punch_secret(punch_secret) {
            let session_hash = derive_session_hash_v2(session_id);
            let mut local_sender_nonce = [0u8; 8];
            OsRng.fill_bytes(&mut local_sender_nonce);
            let probe_pkt = encode_punch_packet_v2(
                role,
                false,
                session_hash,
                local_sender_nonce,
                [0u8; 8],
                &secret,
            );
            Self::V2 {
                role,
                secret,
                session_hash,
                local_sender_nonce,
                probe_pkt,
                rate_limiter: AckRateLimiter::default(),
            }
        } else {
            let session_hash = derive_session_hash(session_id);
            let mut nonce = [0u8; 6];
            OsRng.fill_bytes(&mut nonce);
            let probe_pkt = encode_punch_packet(&PunchPacket {
                version: PUNCH_VERSION,
                role,
                ack: false,
                session_hash,
                nonce,
            });
            let ack_pkt = encode_punch_packet(&PunchPacket {
                version: PUNCH_VERSION,
                role,
                ack: true,
                session_hash,
                nonce,
            });
            Self::V1 {
                session_hash,
                probe_pkt,
                ack_pkt,
            }
        }
    }

    fn probe_bytes(&self) -> &[u8] {
        match self {
            Self::V1 { probe_pkt, .. } => probe_pkt,
            Self::V2 { probe_pkt, .. } => probe_pkt,
        }
    }

    fn periodic_ack_bytes(&self, peer_sender_nonce: Option<[u8; 8]>) -> Option<Vec<u8>> {
        match self {
            Self::V1 { ack_pkt, .. } => Some(ack_pkt.to_vec()),
            Self::V2 {
                role,
                secret,
                session_hash,
                local_sender_nonce,
                ..
            } => peer_sender_nonce.map(|echo| {
                encode_punch_packet_v2(
                    *role,
                    true,
                    *session_hash,
                    *local_sender_nonce,
                    echo,
                    secret,
                )
                .to_vec()
            }),
        }
    }
}

fn has_global_v6_or_explicit_lan(candidates: &P2pCandidates, all_targets: &[SocketAddr]) -> bool {
    let has_global_v6 = all_targets
        .iter()
        .any(|addr| matches!(addr, SocketAddr::V6(v6) if is_global_unicast_ipv6(*v6.ip())));
    let has_explicit_lan = candidates
        .peer_lan_addrs
        .iter()
        .any(|raw| parse_valid_candidate_addr(raw).is_some());
    has_global_v6 || has_explicit_lan
}

/// 当双端处于不同可路由公网 IP（跨站点）时，过滤掉不可达的私网/本地 LAN 候选，
/// 同时保留全球单播 IPv6 与可路由公网 IPv4（例如 UPnP 映射公网地址）。
///
/// 若双端同处同一公网 IP 或无法同族比较（如跨族 `v6` vs `v4`、`same_public_ip_any` 返回 `None`），
/// 则原样返回 `lan_addrs.to_vec()`。
pub fn filter_cross_site_lan_addrs(
    lan_addrs: &[String],
    self_public_addrs: &[&str],
    peer_public_addrs: &[&str],
) -> Vec<String> {
    if crate::nat::same_public_ip_any(self_public_addrs, peer_public_addrs) != Some(false) {
        return lan_addrs.to_vec();
    }

    lan_addrs
        .iter()
        .filter(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return false;
            }
            let Ok(ip) = trimmed
                .parse::<SocketAddr>()
                .map(|s| s.ip())
                .or_else(|_| trimmed.parse::<IpAddr>())
            else {
                return false;
            };
            is_routable_public_ip(ip)
        })
        .cloned()
        .collect()
}

fn should_use_aux_sockets(self_nat: NatType, peer_nat: NatType) -> bool {
    self_nat.is_symmetric() && (peer_nat.is_cone() || peer_nat == NatType::Unknown)
}

fn collect_peer_base_v4s(candidates: &P2pCandidates) -> Vec<std::net::SocketAddrV4> {
    let mut base_v4s = Vec::new();
    let mut seen_bases = HashSet::new();

    for raw in candidates
        .peer_public_addr
        .as_deref()
        .into_iter()
        .chain(candidates.peer_public_addrs.iter().map(String::as_str))
    {
        let Some(SocketAddr::V4(v4)) = parse_valid_candidate_addr(raw) else {
            continue;
        };
        if v4.ip().is_private() || v4.ip().is_link_local() {
            continue;
        }
        let canon = SocketAddr::V4(v4);
        if seen_bases.insert(canon) {
            base_v4s.push(v4);
        }
    }
    base_v4s
}

fn wrap_or_clamp_port(raw: i32, base_port: u16, range_hint: Option<PortRangeHint>) -> Option<u16> {
    if let Some(hint) = range_hint.and_then(PortRangeHint::validated) {
        let (min_p, max_p) = hint.bounds();
        if base_port >= min_p && base_port <= max_p {
            let span = i32::from(max_p) - i32::from(min_p) + 1;
            let min_i32 = i32::from(min_p);
            let wrapped = min_i32 + (raw - min_i32).rem_euclid(span);
            return u16::try_from(wrapped).ok().filter(|&p| p != 0);
        }
    }
    if (1..=65_535).contains(&raw) {
        Some(raw as u16)
    } else {
        None
    }
}

fn build_seq_scan_targets(
    candidates: &P2pCandidates,
    existing_targets: &[SocketAddr],
    socket_is_ipv6: bool,
    steps: i32,
    tolerance: i32,
) -> Vec<SocketAddr> {
    let mut existing: HashSet<SocketAddr> = existing_targets
        .iter()
        .copied()
        .map(canonicalize_socket_addr)
        .collect();
    let mut out = Vec::new();
    let base_v4s = collect_peer_base_v4s(candidates);

    for base in base_v4s {
        let base_i32 = i32::from(base.port());
        let mut push_port = |port: u16| {
            if port == 0 || port == base.port() {
                return;
            }
            let cand_v4 = SocketAddr::new(IpAddr::V4(*base.ip()), port);
            if existing.insert(cand_v4) {
                out.push(normalize_addr_for_socket(cand_v4, socket_is_ipv6));
            }
        };

        if let Some(step) = candidates.peer_nat_port_delta.filter(|&d| d != 0) {
            let step_i32 = i32::from(step);
            for k in 1..=steps {
                if let Some(p) = wrap_or_clamp_port(
                    base_i32 + k * step_i32,
                    base.port(),
                    candidates.peer_nat_port_range,
                ) {
                    push_port(p);
                }
                if (1..=65_535).contains(&(base_i32 + k * step_i32)) {
                    push_port((base_i32 + k * step_i32) as u16);
                }
            }
            for off in 1..=tolerance {
                for anchor in [base_i32, base_i32 + step_i32] {
                    if let Some(p) = wrap_or_clamp_port(
                        anchor + off,
                        base.port(),
                        candidates.peer_nat_port_range,
                    ) {
                        push_port(p);
                    }
                    if let Some(p) = wrap_or_clamp_port(
                        anchor - off,
                        base.port(),
                        candidates.peer_nat_port_range,
                    ) {
                        push_port(p);
                    }
                }
            }
        } else {
            for off in 1..=32 {
                for raw in [base_i32 + off, base_i32 - off] {
                    if (1..=65_535).contains(&raw) {
                        push_port(raw as u16);
                    }
                }
            }
        }
    }
    out
}

fn build_narrow_cone_targets(
    candidates: &P2pCandidates,
    existing_targets: &[SocketAddr],
    socket_is_ipv6: bool,
    radius: i32,
) -> Vec<SocketAddr> {
    let mut existing: HashSet<SocketAddr> = existing_targets
        .iter()
        .copied()
        .map(canonicalize_socket_addr)
        .collect();
    let mut out = Vec::new();
    for base in collect_peer_base_v4s(candidates) {
        let base_i32 = i32::from(base.port());
        for off in 1..=radius {
            for raw in [base_i32 + off, base_i32 - off] {
                if (1..=65_535).contains(&raw) {
                    let cand_v4 = SocketAddr::new(IpAddr::V4(*base.ip()), raw as u16);
                    if existing.insert(cand_v4) {
                        out.push(normalize_addr_for_socket(cand_v4, socket_is_ipv6));
                    }
                }
            }
        }
    }
    out
}

fn build_directed_rendezvous_targets(
    candidates: &P2pCandidates,
    multiplier: i32,
    congruence_span: i32,
    socket_is_ipv6: bool,
) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let step = i32::from(candidates.peer_nat_port_delta.unwrap_or(1));
    for base in collect_peer_base_v4s(candidates) {
        let anchor_raw = i32::from(base.port()) + multiplier * step;
        let Some(anchor_port) =
            wrap_or_clamp_port(anchor_raw, base.port(), candidates.peer_nat_port_range)
        else {
            continue;
        };
        for offset in 0..congruence_span.max(1) {
            let candidate_raw = i32::from(anchor_port) + offset;
            if let Some(p) =
                wrap_or_clamp_port(candidate_raw, base.port(), candidates.peer_nat_port_range)
            {
                let cand_v4 = SocketAddr::new(IpAddr::V4(*base.ip()), p);
                if seen.insert(cand_v4) {
                    out.push(normalize_addr_for_socket(cand_v4, socket_is_ipv6));
                }
            }
        }
    }
    out
}

fn build_random_scan_targets(
    candidates: &P2pCandidates,
    existing_targets: &[SocketAddr],
    socket_is_ipv6: bool,
    max_ports: usize,
) -> Vec<SocketAddr> {
    let mut existing: HashSet<SocketAddr> = existing_targets
        .iter()
        .copied()
        .map(canonicalize_socket_addr)
        .collect();
    let mut out = Vec::new();
    for base in collect_peer_base_v4s(candidates) {
        let ports = predict_symmetric_ports_in_range(
            base.port(),
            NatType::ApdmRandom,
            None,
            candidates.peer_nat_port_range,
            max_ports,
        );
        for port in ports {
            let cand_v4 = SocketAddr::new(IpAddr::V4(*base.ip()), port);
            if existing.insert(cand_v4) {
                out.push(normalize_addr_for_socket(cand_v4, socket_is_ipv6));
            }
        }
    }
    out
}

fn build_predicted_targets(
    candidates: &P2pCandidates,
    existing_targets: &[SocketAddr],
    socket_is_ipv6: bool,
) -> Vec<SocketAddr> {
    let max_ports = match candidates.peer_nat_type {
        NatType::Public | NatType::ConeVerified | NatType::ConeUnverified | NatType::UdpBlocked => {
            return Vec::new();
        }
        NatType::AdmSeq | NatType::ApdmSeq => 64,
        NatType::AdmRandom | NatType::ApdmRandom => CONE_SCAN_BUDGET_PER_WAVE,
        NatType::Unknown => 24,
    };

    let mut existing: HashSet<SocketAddr> = existing_targets
        .iter()
        .copied()
        .map(canonicalize_socket_addr)
        .collect();
    let mut out = Vec::new();
    for base in collect_peer_base_v4s(candidates) {
        let ports = predict_symmetric_ports_in_range(
            base.port(),
            candidates.peer_nat_type,
            candidates.peer_nat_port_delta,
            candidates.peer_nat_port_range,
            max_ports,
        );
        for port in ports {
            let cand_v4 = SocketAddr::new(IpAddr::V4(*base.ip()), port);
            if existing.insert(cand_v4) {
                out.push(normalize_addr_for_socket(cand_v4, socket_is_ipv6));
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
enum PunchStrategy {
    DirectOnly,
    MainScanImmediate {
        scan_targets: Vec<SocketAddr>,
    },
    AuxPersistent {
        aux_count: usize,
        aux_targets: Vec<SocketAddr>,
        scan_targets: Vec<SocketAddr>,
    },
    DirectedRendezvous {
        aux_count: usize,
        aux_targets: Vec<SocketAddr>,
    },
    TwoWaveBirthdayAux {
        aux_count: usize,
    },
    TwoWaveConeScan {
        wave1_targets: Vec<SocketAddr>,
        wave2_targets: Vec<SocketAddr>,
    },
    ConeUnverifiedProgressive {
        role: P2pRole,
        self_verified: bool,
        peer_verified: bool,
        narrow_targets: Vec<SocketAddr>,
        wide_targets: Vec<SocketAddr>,
    },
    LegacyPhase2 {
        want_aux: bool,
        aux_count: usize,
        scan_targets: Vec<SocketAddr>,
    },
}

fn select_punch_strategy(
    role: P2pRole,
    candidates: &P2pCandidates,
    targets: &[SocketAddr],
    all_targets: &[SocketAddr],
    socket_is_ipv6: bool,
) -> PunchStrategy {
    let self_nat = candidates.self_nat_type;
    let peer_nat = candidates.peer_nat_type;

    if self_nat == NatType::Public
        || peer_nat == NatType::Public
        || has_global_v6_or_explicit_lan(candidates, all_targets)
        || (self_nat == NatType::ConeVerified && peer_nat == NatType::ConeVerified)
    {
        return PunchStrategy::DirectOnly;
    }

    if self_nat == NatType::AdmSeq && peer_nat == NatType::AdmSeq {
        return PunchStrategy::MainScanImmediate {
            scan_targets: build_seq_scan_targets(candidates, targets, socket_is_ipv6, 64, 3),
        };
    }

    if self_nat.is_cone() && peer_nat.is_symmetric_seq() {
        return PunchStrategy::MainScanImmediate {
            scan_targets: build_seq_scan_targets(candidates, targets, socket_is_ipv6, 64, 3),
        };
    }

    if self_nat.is_symmetric_seq() && peer_nat.is_cone() {
        return PunchStrategy::AuxPersistent {
            aux_count: AUX_SEQ_TO_CONE_COUNT,
            aux_targets: targets.to_vec(),
            scan_targets: Vec::new(),
        };
    }

    if self_nat == NatType::ApdmSeq && peer_nat == NatType::ApdmSeq {
        let abs_delta = candidates
            .peer_nat_port_delta
            .map(i32::from)
            .map(i32::abs)
            .unwrap_or(0);
        if abs_delta == 1 {
            let aux_targets = build_directed_rendezvous_targets(candidates, 24, 1, socket_is_ipv6);
            if !aux_targets.is_empty() {
                return PunchStrategy::DirectedRendezvous {
                    aux_count: AUX_APDM_SEQ_DELTA1_COUNT,
                    aux_targets,
                };
            }
        } else if (2..=4).contains(&abs_delta) {
            let aux_targets =
                build_directed_rendezvous_targets(candidates, 24, abs_delta, socket_is_ipv6);
            if !aux_targets.is_empty() {
                return PunchStrategy::DirectedRendezvous {
                    aux_count: AUX_APDM_SEQ_DELTA2_4_COUNT,
                    aux_targets,
                };
            }
        }
        return PunchStrategy::AuxPersistent {
            aux_count: AUX_SEQ_TO_CONE_COUNT,
            aux_targets: targets.to_vec(),
            scan_targets: build_seq_scan_targets(candidates, targets, socket_is_ipv6, 64, 3),
        };
    }

    if self_nat.is_symmetric_random() && peer_nat.is_cone() {
        return PunchStrategy::TwoWaveBirthdayAux {
            aux_count: MAX_AUX_SOCKETS_HARD_CAP,
        };
    }

    if self_nat.is_cone() && peer_nat.is_symmetric_random() {
        let all_random = build_random_scan_targets(
            candidates,
            targets,
            socket_is_ipv6,
            CONE_SCAN_BUDGET_PER_WAVE * 2,
        );
        let split = all_random.len().min(CONE_SCAN_BUDGET_PER_WAVE);
        let wave1_targets = all_random[..split].to_vec();
        let wave2_targets = if all_random.len() > split {
            all_random[split..].to_vec()
        } else {
            wave1_targets.clone()
        };
        return PunchStrategy::TwoWaveConeScan {
            wave1_targets,
            wave2_targets,
        };
    }

    if self_nat.is_cone() && peer_nat.is_cone() {
        let narrow_targets = build_narrow_cone_targets(candidates, targets, socket_is_ipv6, 32);
        let wide_targets = build_random_scan_targets(
            candidates,
            targets,
            socket_is_ipv6,
            CONE_SCAN_BUDGET_PER_WAVE,
        );
        return PunchStrategy::ConeUnverifiedProgressive {
            role,
            self_verified: self_nat == NatType::ConeVerified,
            peer_verified: peer_nat == NatType::ConeVerified,
            narrow_targets,
            wide_targets,
        };
    }

    if self_nat.is_symmetric_seq() && peer_nat.is_symmetric_seq() {
        return PunchStrategy::AuxPersistent {
            aux_count: AUX_SEQ_TO_CONE_COUNT,
            aux_targets: targets.to_vec(),
            scan_targets: build_seq_scan_targets(candidates, targets, socket_is_ipv6, 64, 3),
        };
    }

    if self_nat.is_symmetric_random() && peer_nat.is_symmetric_seq() {
        return PunchStrategy::TwoWaveBirthdayAux {
            aux_count: MAX_AUX_SOCKETS_HARD_CAP,
        };
    }

    if self_nat.is_symmetric_seq() && peer_nat.is_symmetric_random() {
        let all_random = build_random_scan_targets(
            candidates,
            targets,
            socket_is_ipv6,
            CONE_SCAN_BUDGET_PER_WAVE * 2,
        );
        let split = all_random.len().min(CONE_SCAN_BUDGET_PER_WAVE);
        let wave1_targets = all_random[..split].to_vec();
        let wave2_targets = if all_random.len() > split {
            all_random[split..].to_vec()
        } else {
            wave1_targets.clone()
        };
        return PunchStrategy::TwoWaveConeScan {
            wave1_targets,
            wave2_targets,
        };
    }

    let want_aux = should_use_aux_sockets(self_nat, peer_nat);
    let aux_count = if self_nat.is_symmetric_random() {
        MAX_AUX_SOCKETS_HARD_CAP
    } else if want_aux {
        AUX_SEQ_TO_CONE_COUNT
    } else {
        0
    };
    PunchStrategy::LegacyPhase2 {
        want_aux,
        aux_count,
        scan_targets: build_predicted_targets(candidates, targets, socket_is_ipv6),
    }
}

fn spawn_aux_punch_sockets(
    count: usize,
    socket_is_ipv6: bool,
    has_ipv4: bool,
    role: P2pRole,
    session_id: &str,
    punch_secret: Option<&str>,
    cancel: &AtomicBool,
) -> Vec<AuxPunchSocket> {
    let capped = count.min(MAX_AUX_SOCKETS_HARD_CAP);
    let mut aux = Vec::with_capacity(capped);
    for _ in 0..capped {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        match bind_punch_socket(None, socket_is_ipv6, has_ipv4) {
            Ok((socket, _)) => aux.push(AuxPunchSocket {
                socket,
                confirmed_peer: None,
                peer_sender_nonce: None,
                auth: PunchAuthMode::new(role, session_id, punch_secret),
            }),
            // 遇到 EMFILE / ENFILE / 系统端口或绑定上限立即停止扩张并保留已绑定 socket 安全探测，绝不 panic。
            Err(_) => break,
        }
    }
    aux
}

fn wait_start_after_delay(
    start_after_ms: Option<u16>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let delay_ms = start_after_ms.unwrap_or(0).min(MAX_START_AFTER_MS);
    if delay_ms == 0 {
        return Ok(());
    }
    let target = Instant::now() + Duration::from_millis(u64::from(delay_ms));
    let wait_until = target.min(deadline);
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err("P2P 打洞已取消".to_string());
        }
        let now = Instant::now();
        if now >= wait_until {
            return Ok(());
        }
        thread::sleep(POLL_STEP.min(wait_until - now));
    }
}

fn send_paced_scan_batch(
    socket: &UdpSocket,
    scan_targets: &[SocketAddr],
    cursor: &mut usize,
    probe_bytes: &[u8],
    max_batch: usize,
) {
    if scan_targets.is_empty() || max_batch == 0 {
        return;
    }
    let batch = max_batch.min(scan_targets.len());
    for _ in 0..batch {
        *cursor %= scan_targets.len();
        let addr = scan_targets[*cursor];
        *cursor = (*cursor + 1) % scan_targets.len();
        let _ = socket.send_to(probe_bytes, addr);
    }
}

/// 执行双向 UDP 打洞，成功后返回已打通的非阻塞 `UdpSocket`、实测对端地址及打洞耗时。
///
/// - 若双端均为 [`NatType::SymmetricRandom`] 且候选地址仅含公网 IPv4，立即快速失败以零延迟回退中继；
/// - 优先在进程级端口租约保护下复用 `candidates.local_udp_port`（`SO_REUSEADDR` + `SO_REUSEPORT`），
///   若已被同进程其他在途/活跃 P2P 连接占用或绑定失败则自动降级为无 `SO_REUSEPORT` 的临时端口 `0`；
/// - 存在 IPv6 候选（含 IPv4+IPv6 混合）时自动使用双栈 `AF_INET6` 套接字，保留全部候选地址；
/// - Phase 1（`0..350ms`）每 `30ms` 向主 `targets` 发送 29 字节 `RCP2` 探测包；Phase 2（`350ms..timeout`）
///   按 [`predict_symmetric_ports`] 对对端公网 IPv4 邻域限流探测（每 tick 最多 6 个端口），并在本端为对称
///   NAT 且对端为 Cone/Unknown 时于 Phase 2 按需开启最多 16 个辅助临时套接字（每 tick 限流 4 个）进行有界生日碰撞；
/// - 使用 `peek_from` 预检入站包以完好保留对端先发出的 QUIC `Initial` 报文；
/// - 严格要求双向连通确认（收到异侧 `ack = 1` 或已确认对端/目标发来的非 `RCP2` 报文），
///   杜绝单向 Probe 误判；
/// - `cancel` 置位时在 ~5ms 内快速中止，便于上层立刻回退 TCP 中继。
pub fn punch_udp_pair(
    role: P2pRole,
    candidates: &P2pCandidates,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<(UdpSocket, SocketAddr, Duration), String> {
    let punched = punch_udp_pair_with_lease(role, candidates, timeout, cancel)?;
    Ok((punched.socket, punched.peer_addr, punched.elapsed))
}

fn punch_udp_pair_with_lease(
    role: P2pRole,
    candidates: &P2pCandidates,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<PunchedSocket, String> {
    if cancel.load(Ordering::Acquire) {
        return Err("P2P 打洞已取消".to_string());
    }

    let all_targets = parse_candidate_addrs(candidates);
    if all_targets.is_empty() {
        return Err("没有可用的对端 UDP 候选地址".to_string());
    }

    let has_v6_or_lan = has_global_v6_or_explicit_lan(candidates, &all_targets);
    if (candidates.self_nat_type == NatType::UdpBlocked
        || candidates.peer_nat_type == NatType::UdpBlocked)
        && !has_v6_or_lan
    {
        return Err("UDP 探测受阻且无可用 IPv6/LAN 候选，跳过 UDP 打洞直接回退中继".to_string());
    }
    if candidates.self_nat_type.is_symmetric_random()
        && candidates.peer_nat_type.is_symmetric_random()
        && !has_v6_or_lan
    {
        return Err("双端均为随机对称 NAT，跳过 UDP 打洞直接回退中继".to_string());
    }

    let start = Instant::now();
    let deadline = start + timeout;
    wait_start_after_delay(candidates.start_after_ms, deadline, cancel)?;

    let PunchSetup {
        socket,
        port_lease,
        targets,
        socket_is_ipv6,
    } = prepare_punch_socket_and_targets(candidates, &all_targets)?;

    let has_ipv4 = all_targets.iter().any(SocketAddr::is_ipv4);
    let strategy = select_punch_strategy(role, candidates, &targets, &all_targets, socket_is_ipv6);
    let mut target_canons: HashSet<SocketAddr> = targets
        .iter()
        .copied()
        .map(canonicalize_socket_addr)
        .collect();
    let expected_role = role.opposite();
    let mut auth = PunchAuthMode::new(
        role,
        &candidates.session_id,
        candidates.punch_secret.as_deref(),
    );

    let mut aux_sockets: Vec<AuxPunchSocket> = Vec::new();
    let mut aux_targets_override: Option<Vec<SocketAddr>> = None;
    let mut aux_cursor = 0usize;
    let mut scan_targets: Vec<SocketAddr> = Vec::new();
    let mut pred_cursor = 0usize;

    let punch_start = Instant::now();
    let remaining_after_start = deadline.saturating_duration_since(punch_start);

    // 根据策略初始化 t=0 资源与多波次切换时间点
    let mut wave2_at: Option<Instant> = None;
    let mut wave2_done = false;
    let mut legacy_p2_done = false;
    let mut p2a_done = false;
    let mut p2b_r1_done = false;
    let mut p2b_r2_done = false;

    match &strategy {
        PunchStrategy::DirectOnly => {}
        PunchStrategy::MainScanImmediate { scan_targets: s } => {
            scan_targets = s.clone();
        }
        PunchStrategy::AuxPersistent {
            aux_count,
            aux_targets,
            scan_targets: s,
        } => {
            aux_sockets = spawn_aux_punch_sockets(
                *aux_count,
                socket_is_ipv6,
                has_ipv4,
                role,
                &candidates.session_id,
                candidates.punch_secret.as_deref(),
                cancel,
            );
            for &t in aux_targets {
                target_canons.insert(canonicalize_socket_addr(t));
            }
            aux_targets_override = Some(aux_targets.clone());
            scan_targets = s.clone();
        }
        PunchStrategy::DirectedRendezvous {
            aux_count,
            aux_targets,
        } => {
            aux_sockets = spawn_aux_punch_sockets(
                *aux_count,
                socket_is_ipv6,
                has_ipv4,
                role,
                &candidates.session_id,
                candidates.punch_secret.as_deref(),
                cancel,
            );
            for &t in aux_targets {
                target_canons.insert(canonicalize_socket_addr(t));
            }
            aux_targets_override = Some(aux_targets.clone());
        }
        PunchStrategy::TwoWaveBirthdayAux { aux_count } => {
            aux_sockets = spawn_aux_punch_sockets(
                *aux_count,
                socket_is_ipv6,
                has_ipv4,
                role,
                &candidates.session_id,
                candidates.punch_secret.as_deref(),
                cancel,
            );
            if remaining_after_start >= Duration::from_millis(1_000) {
                wave2_at = Some(punch_start + remaining_after_start / 2);
            }
        }
        PunchStrategy::TwoWaveConeScan { wave1_targets, .. } => {
            scan_targets = wave1_targets.clone();
            if remaining_after_start >= Duration::from_millis(1_000) {
                wave2_at = Some(punch_start + remaining_after_start / 2);
            }
        }
        PunchStrategy::ConeUnverifiedProgressive { .. } | PunchStrategy::LegacyPhase2 { .. } => {}
    }

    let p2b_start_at = punch_start + PHASE2A_END;
    let p2b_swap_at = if timeout >= PHASE2B_MIN_TOTAL_TIMEOUT && deadline > p2b_start_at {
        Some(p2b_start_at + deadline.saturating_duration_since(p2b_start_at) / 2)
    } else {
        None
    };

    let has_global_v6_targets = socket_is_ipv6
        && targets
            .iter()
            .any(|t| matches!(t, SocketAddr::V6(v6) if is_global_unicast_ipv6(*v6.ip())));
    let has_v4_or_lan_targets = targets
        .iter()
        .any(|t| !matches!(t, SocketAddr::V6(v6) if is_global_unicast_ipv6(*v6.ip())));
    let mut he_v4_release_at: Option<Instant> = if has_global_v6_targets
        && has_v4_or_lan_targets
        && remaining_after_start >= Duration::from_millis(150)
    {
        Some(punch_start + HAPPY_EYEBALLS_V6_HEAD_START)
    } else {
        None
    };

    let mut last_send: Option<Instant> = None;
    let mut confirmed_peer: Option<SocketAddr> = None;
    let mut peer_sender_nonce: Option<[u8; 8]> = None;
    let mut recv_buf = [0u8; 2048];

    loop {
        if cancel.load(Ordering::Acquire) {
            return Err("P2P 打洞已取消".to_string());
        }

        let now = Instant::now();
        if let Some(release_at) = he_v4_release_at {
            if now >= release_at {
                he_v4_release_at = None;
                last_send = None;
            }
        }
        let any_aux_confirmed = aux_sockets.iter().any(|a| a.confirmed_peer.is_some());

        // 处理分阶段/多波次状态迁移（仅在未确认对端前切换/滚动释放）
        if confirmed_peer.is_none() && !any_aux_confirmed {
            match &strategy {
                PunchStrategy::TwoWaveBirthdayAux { aux_count } => {
                    if !wave2_done && wave2_at.is_some_and(|t| now >= t) {
                        wave2_done = true;
                        // 先彻底 drop Wave 1 全部辅助 socket 释放 FD 与 conntrack，再开 Wave 2
                        aux_sockets.clear();
                        aux_cursor = 0;
                        aux_sockets = spawn_aux_punch_sockets(
                            *aux_count,
                            socket_is_ipv6,
                            has_ipv4,
                            role,
                            &candidates.session_id,
                            candidates.punch_secret.as_deref(),
                            cancel,
                        );
                    }
                }
                PunchStrategy::TwoWaveConeScan { wave2_targets, .. } => {
                    if !wave2_done && wave2_at.is_some_and(|t| now >= t) {
                        wave2_done = true;
                        scan_targets = wave2_targets.clone();
                        pred_cursor = 0;
                    }
                }
                PunchStrategy::ConeUnverifiedProgressive {
                    role: self_role,
                    self_verified,
                    peer_verified,
                    narrow_targets,
                    wide_targets,
                } => {
                    let elapsed = now.saturating_duration_since(punch_start);
                    if !p2a_done && elapsed >= PHASE1_DURATION {
                        p2a_done = true;
                        scan_targets = narrow_targets.clone();
                        pred_cursor = 0;
                    }
                    if timeout >= PHASE2B_MIN_TOTAL_TIMEOUT {
                        if !p2b_r1_done && now >= p2b_start_at {
                            p2b_r1_done = true;
                            let spawn_aux_r1 = if *self_verified && !*peer_verified {
                                false
                            } else if !*self_verified && *peer_verified {
                                true
                            } else {
                                *self_role == P2pRole::Host
                            };
                            if spawn_aux_r1 {
                                scan_targets.clear();
                                aux_sockets = spawn_aux_punch_sockets(
                                    MAX_AUX_SOCKETS_HARD_CAP,
                                    socket_is_ipv6,
                                    has_ipv4,
                                    role,
                                    &candidates.session_id,
                                    candidates.punch_secret.as_deref(),
                                    cancel,
                                );
                            } else {
                                scan_targets = wide_targets.clone();
                                pred_cursor = 0;
                            }
                        }
                        if !p2b_r2_done && p2b_swap_at.is_some_and(|t| now >= t) {
                            p2b_r2_done = true;
                            aux_sockets.clear();
                            aux_cursor = 0;
                            if !*self_verified && !*peer_verified {
                                // 角色互换：Round 1 为 Host 喷洒/Client 扫描，Round 2 改为 Client 喷洒/Host 扫描
                                if *self_role == P2pRole::Client {
                                    scan_targets.clear();
                                    aux_sockets = spawn_aux_punch_sockets(
                                        MAX_AUX_SOCKETS_HARD_CAP,
                                        socket_is_ipv6,
                                        has_ipv4,
                                        role,
                                        &candidates.session_id,
                                        candidates.punch_secret.as_deref(),
                                        cancel,
                                    );
                                } else {
                                    scan_targets = wide_targets.clone();
                                    pred_cursor = 0;
                                }
                            }
                        }
                    }
                }
                PunchStrategy::LegacyPhase2 {
                    want_aux,
                    aux_count,
                    scan_targets: s,
                } if !legacy_p2_done
                    && now.saturating_duration_since(punch_start) >= PHASE1_DURATION =>
                {
                    legacy_p2_done = true;
                    scan_targets = s.clone();
                    pred_cursor = 0;
                    if *want_aux && *aux_count > 0 {
                        aux_sockets = spawn_aux_punch_sockets(
                            *aux_count,
                            socket_is_ipv6,
                            has_ipv4,
                            role,
                            &candidates.session_id,
                            candidates.punch_secret.as_deref(),
                            cancel,
                        );
                    }
                }
                _ => {}
            }
        }

        if last_send.map_or(true, |t| t.elapsed() >= PROBE_INTERVAL) {
            let probe_bytes = auth.probe_bytes();
            if let Some(peer_addr) = confirmed_peer {
                if let Some(ack_bytes) = auth.periodic_ack_bytes(peer_sender_nonce) {
                    let _ = socket.send_to(&ack_bytes, peer_addr);
                }
                let peer_canon = canonicalize_socket_addr(peer_addr);
                for &target in &targets {
                    if canonicalize_socket_addr(target) != peer_canon {
                        let _ = socket.send_to(probe_bytes, target);
                    }
                }
            } else {
                if he_v4_release_at.is_some() {
                    let mut any_v6_sent_ok = false;
                    for &target in &targets {
                        if matches!(target, SocketAddr::V6(v6) if is_global_unicast_ipv6(*v6.ip()))
                            && socket.send_to(probe_bytes, target).is_ok()
                        {
                            any_v6_sent_ok = true;
                        }
                    }
                    if !any_v6_sent_ok {
                        // 若所有全球单播 IPv6 发送立即报本地不可达，0 阻塞立即放开 IPv4/LAN 并发探测
                        he_v4_release_at = None;
                    }
                }
                if he_v4_release_at.is_none() {
                    for &target in &targets {
                        let _ = socket.send_to(probe_bytes, target);
                    }
                    let scan_budget = MAX_PREDICTED_PORTS_PER_TICK
                        .saturating_sub(targets.len())
                        .max(1);
                    send_paced_scan_batch(
                        &socket,
                        &scan_targets,
                        &mut pred_cursor,
                        probe_bytes,
                        scan_budget,
                    );
                }
            }

            for aux in &aux_sockets {
                if let Some(peer_addr) = aux.confirmed_peer {
                    if let Some(ack_bytes) = aux.auth.periodic_ack_bytes(aux.peer_sender_nonce) {
                        let _ = aux.socket.send_to(&ack_bytes, peer_addr);
                    }
                }
            }
            if confirmed_peer.is_none() && !aux_sockets.is_empty() {
                let aux_dests = aux_targets_override.as_deref().unwrap_or(&targets);
                let len = aux_sockets.len();
                aux_cursor %= len;
                let mut probed = 0usize;
                for _ in 0..len {
                    if probed >= MAX_AUX_PROBES_PER_TICK {
                        break;
                    }
                    let aux = &aux_sockets[aux_cursor];
                    aux_cursor = (aux_cursor + 1) % len;
                    if aux.confirmed_peer.is_none() {
                        let aux_probe = aux.auth.probe_bytes();
                        for &target in aux_dests {
                            let _ = aux.socket.send_to(aux_probe, target);
                        }
                        probed += 1;
                    }
                }
            }
            last_send = Some(Instant::now());
        }

        let mut socket_ref = &socket;
        let drain_outcome = drain_punch_rx(
            &mut recv_buf,
            socket_is_ipv6,
            &mut auth,
            expected_role,
            role,
            &target_canons,
            &mut confirmed_peer,
            &mut peer_sender_nonce,
            &mut socket_ref,
        )?;
        if let DrainOutcome::Ready(peer_addr) = drain_outcome {
            drop(aux_sockets);
            return Ok(PunchedSocket {
                socket,
                peer_addr,
                elapsed: start.elapsed(),
                port_lease,
            });
        }

        let mut won_aux: Option<(usize, SocketAddr)> = None;
        let mut idx = 0usize;
        while idx < aux_sockets.len() {
            let outcome = {
                let aux = &mut aux_sockets[idx];
                let mut aux_ref = &aux.socket;
                drain_punch_rx(
                    &mut recv_buf,
                    socket_is_ipv6,
                    &mut aux.auth,
                    expected_role,
                    role,
                    &target_canons,
                    &mut aux.confirmed_peer,
                    &mut aux.peer_sender_nonce,
                    &mut aux_ref,
                )
            };
            match outcome {
                Ok(DrainOutcome::Ready(peer_addr)) => {
                    won_aux = Some((idx, peer_addr));
                    break;
                }
                Ok(DrainOutcome::Continue) => {
                    idx += 1;
                }
                Err(_) => {
                    aux_sockets.swap_remove(idx);
                }
            }
        }
        if let Some((win_idx, peer_addr)) = won_aux {
            let winner = aux_sockets.swap_remove(win_idx);
            drop(aux_sockets);
            drop(socket);
            drop(port_lease);
            return Ok(PunchedSocket {
                socket: winner.socket,
                peer_addr,
                elapsed: start.elapsed(),
                port_lease: None,
            });
        }

        let now_after = Instant::now();
        if now_after >= deadline {
            return Err(format!("P2P UDP 打洞超时（{timeout:?}）"));
        }

        let sleep_budget = POLL_STEP.min(deadline - now_after);
        thread::sleep(sleep_budget);
    }
}

/// 单次接收队列排空迭代允许连续吞吐的瞬态错误上限（防止死循环饿死超时与取消检查）。
const MAX_CONSECUTIVE_TRANSIENT_ERRORS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainOutcome {
    Continue,
    Ready(SocketAddr),
}

trait PunchSocketOps {
    fn peek_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send_to(&mut self, buf: &[u8], addr: SocketAddr);
}

impl PunchSocketOps for &UdpSocket {
    fn peek_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::peek_from(self, buf)
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf)
    }

    fn send_to(&mut self, buf: &[u8], addr: SocketAddr) {
        let _ = UdpSocket::send_to(self, buf, addr);
    }
}

fn handle_decoded_punch_packet(
    pkt: PunchPacket,
    from_addr: SocketAddr,
    session_hash: [u8; 16],
    expected_role: P2pRole,
    ack_pkt: &[u8],
    confirmed_peer: &mut Option<SocketAddr>,
    ops: &mut dyn PunchSocketOps,
) -> Option<SocketAddr> {
    if pkt.session_hash != session_hash || pkt.role != expected_role {
        return None;
    }
    for _ in 0..IMMEDIATE_ACK_BURST {
        ops.send_to(ack_pkt, from_addr);
    }
    if pkt.ack {
        return Some(from_addr);
    }
    if confirmed_peer.is_none() {
        *confirmed_peer = Some(from_addr);
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn classify_punch_datagram(
    recv_buf: &mut [u8],
    n: usize,
    from_addr: SocketAddr,
    already_consumed: bool,
    auth: &mut PunchAuthMode,
    expected_role: P2pRole,
    role: P2pRole,
    target_canons: &HashSet<SocketAddr>,
    confirmed_peer: &mut Option<SocketAddr>,
    peer_sender_nonce: &mut Option<[u8; 8]>,
    ops: &mut dyn PunchSocketOps,
) -> Option<SocketAddr> {
    if n >= PUNCH_MAGIC.len() && &recv_buf[..PUNCH_MAGIC.len()] == PUNCH_MAGIC {
        if !already_consumed {
            // 任意 RCP2 前缀报文先从内核接收队列消费掉：合法包按规则处理，非法/伪造包静默丢弃且零回包。
            let _ = ops.recv_from(recv_buf);
        }
        return match auth {
            PunchAuthMode::V1 {
                session_hash,
                ack_pkt,
                ..
            } => {
                let pkt = decode_punch_packet(&recv_buf[..n])?;
                handle_decoded_punch_packet(
                    pkt,
                    from_addr,
                    *session_hash,
                    expected_role,
                    ack_pkt,
                    confirmed_peer,
                    ops,
                )
            }
            PunchAuthMode::V2 {
                role: self_role,
                secret,
                session_hash,
                local_sender_nonce,
                rate_limiter,
                ..
            } => {
                let pkt = decode_and_verify_punch_packet_v2(&recv_buf[..n], secret)?;
                if pkt.session_hash != *session_hash || pkt.role != expected_role {
                    return None;
                }
                let is_ack = (pkt.flags & PUNCH_V2_FLAG_ACK) != 0;
                if is_ack {
                    if pkt.echo_nonce != *local_sender_nonce {
                        return None;
                    }
                    *peer_sender_nonce = Some(pkt.sender_nonce);
                    if confirmed_peer.is_none() {
                        *confirmed_peer = Some(from_addr);
                    }
                    if rate_limiter.allow_reply(from_addr.ip(), Instant::now()) {
                        let reply = encode_punch_packet_v2(
                            *self_role,
                            true,
                            *session_hash,
                            *local_sender_nonce,
                            pkt.sender_nonce,
                            secret,
                        );
                        ops.send_to(&reply, from_addr);
                    }
                    Some(from_addr)
                } else {
                    if pkt.echo_nonce != [0u8; 8] {
                        return None;
                    }
                    *peer_sender_nonce = Some(pkt.sender_nonce);
                    if confirmed_peer.is_none() {
                        *confirmed_peer = Some(from_addr);
                    }
                    if rate_limiter.allow_reply(from_addr.ip(), Instant::now()) {
                        let reply = encode_punch_packet_v2(
                            *self_role,
                            true,
                            *session_hash,
                            *local_sender_nonce,
                            pkt.sender_nonce,
                            secret,
                        );
                        ops.send_to(&reply, from_addr);
                    }
                    None
                }
            }
        };
    }

    let from_canon = canonicalize_socket_addr(from_addr);
    let from_confirmed = confirmed_peer.is_some_and(|p| canonicalize_socket_addr(p) == from_canon);
    let from_target = target_canons.contains(&from_canon);
    if from_confirmed || (from_target && (role == P2pRole::Host || confirmed_peer.is_some())) {
        // 对端已切入 QUIC 并发出 Initial 等非 RCP2 报文：未消费时保留在内核接收缓冲中移交给 QuicEndpoint::from_socket。
        return Some(from_addr);
    }

    if !already_consumed {
        // 未知来源的杂散非 RCP2 报文：消费丢弃，防止 peek_from 空转。
        let _ = ops.recv_from(recv_buf);
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn drain_punch_rx(
    recv_buf: &mut [u8],
    socket_is_ipv6: bool,
    auth: &mut PunchAuthMode,
    expected_role: P2pRole,
    role: P2pRole,
    target_canons: &HashSet<SocketAddr>,
    confirmed_peer: &mut Option<SocketAddr>,
    peer_sender_nonce: &mut Option<[u8; 8]>,
    ops: &mut dyn PunchSocketOps,
) -> Result<DrainOutcome, String> {
    let mut consecutive_transient_errors = 0usize;
    loop {
        match ops.peek_from(recv_buf) {
            Ok((n, raw_from)) => {
                consecutive_transient_errors = 0;
                let from_addr = normalize_addr_for_socket(raw_from, socket_is_ipv6);
                if let Some(peer) = classify_punch_datagram(
                    recv_buf,
                    n,
                    from_addr,
                    false,
                    auth,
                    expected_role,
                    role,
                    target_canons,
                    confirmed_peer,
                    peer_sender_nonce,
                    ops,
                ) {
                    return Ok(DrainOutcome::Ready(peer));
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                break;
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::Interrupted
                        | ErrorKind::ConnectionRefused
                        | ErrorKind::ConnectionReset
                ) =>
            {
                consecutive_transient_errors += 1;
                if consecutive_transient_errors > MAX_CONSECUTIVE_TRANSIENT_ERRORS {
                    break;
                }
                if matches!(
                    err.kind(),
                    ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
                ) {
                    // Windows Winsock 发送探测包至未监听端口后会异步锁存 ICMP Port Unreachable
                    // (WSAECONNRESET=10054)；MSG_PEEK 不会清除该锁存错误，必须用非 peek 的 recv_from
                    // 清掉错误状态后再继续 peek，避免后续对端真实打洞包被永久遮蔽。
                    match ops.recv_from(recv_buf) {
                        Ok((n, raw_from)) => {
                            consecutive_transient_errors = 0;
                            let from_addr = normalize_addr_for_socket(raw_from, socket_is_ipv6);
                            if let Some(peer) = classify_punch_datagram(
                                recv_buf,
                                n,
                                from_addr,
                                true,
                                auth,
                                expected_role,
                                role,
                                target_canons,
                                confirmed_peer,
                                peer_sender_nonce,
                                ops,
                            ) {
                                return Ok(DrainOutcome::Ready(peer));
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e)
                            if matches!(
                                e.kind(),
                                ErrorKind::Interrupted
                                    | ErrorKind::ConnectionRefused
                                    | ErrorKind::ConnectionReset
                            ) =>
                        {
                            continue;
                        }
                        Err(e) => {
                            return Err(format!("P2P UDP 打洞读取失败：{e}"));
                        }
                    }
                }
                continue;
            }
            Err(err) => {
                return Err(format!("P2P UDP 打洞读取失败：{err}"));
            }
        }
    }
    Ok(DrainOutcome::Continue)
}

/// 作为被控端（Host）尝试 UDP 打洞并在打通的 socket 上完成 QUIC 服务端握手。
///
/// 任意阶段失败或被 `cancel` 打断均返回可读错误字符串，供上层回退 TCP 中继。
pub fn attempt_p2p_quic_host(
    candidates: &P2pCandidates,
    punch_timeout: Duration,
    quic_timeout: Duration,
    cancel: &AtomicBool,
) -> Result<P2pQuicConnection, String> {
    attempt_p2p_quic_host_mtls(candidates, punch_timeout, quic_timeout, cancel, None)
}

/// 作为被控端（Host）尝试 UDP 打洞并在打通的 socket 上完成 QUIC 服务端握手（支持可选双向 mTLS）。
pub fn attempt_p2p_quic_host_mtls(
    candidates: &P2pCandidates,
    punch_timeout: Duration,
    quic_timeout: Duration,
    cancel: &AtomicBool,
    mtls: Option<&MtlsConfig>,
) -> Result<P2pQuicConnection, String> {
    let PunchedSocket {
        socket,
        peer_addr: punched_peer,
        elapsed: punch_elapsed,
        port_lease,
    } = punch_udp_pair_with_lease(P2pRole::Host, candidates, punch_timeout, cancel)?;
    if cancel.load(Ordering::Acquire) {
        return Err("P2P QUIC Host 握手已取消".to_string());
    }

    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("获取 P2P Host 本地地址失败：{e}"))?;
    let endpoint = if let Some(mtls_cfg) = mtls {
        QuicEndpoint::from_socket_mtls(
            socket,
            NetConfig::new(Role::Host, local_addr),
            Some(mtls_cfg),
        )
        .map_err(|e| format!("创建 P2P QUIC Host mTLS 端点失败：{e}"))?
    } else {
        let identity = rc_session::dev_cert::dev_identity()
            .map_err(|e| format!("加载 P2P Host 开发证书失败：{e}"))?;
        QuicEndpoint::from_socket(
            socket,
            NetConfig::new(Role::Host, local_addr),
            Some(identity),
        )
        .map_err(|e| format!("创建 P2P QUIC Host 端点失败：{e}"))?
    };

    let transport = endpoint
        .accept_from_cancelable(Some(punched_peer), quic_timeout, cancel)
        .map_err(|e| format!("P2P QUIC Host 握手失败：{e}"))?;

    Ok(finalize_p2p_connection(
        endpoint,
        transport,
        punch_elapsed,
        port_lease,
    ))
}

/// 作为控制端（Client）尝试 UDP 打洞并在打通的 socket 上发起 QUIC 客户端握手。
///
/// 任意阶段失败或被 `cancel` 打断均返回可读错误字符串，供上层回退 TCP 中继。
pub fn attempt_p2p_quic_client(
    candidates: &P2pCandidates,
    punch_timeout: Duration,
    quic_timeout: Duration,
    cancel: &AtomicBool,
) -> Result<P2pQuicConnection, String> {
    attempt_p2p_quic_client_mtls(candidates, punch_timeout, quic_timeout, cancel, None)
}

/// 作为控制端（Client）尝试 UDP 打洞并在打通的 socket 上发起 QUIC 客户端握手（支持可选双向 mTLS）。
pub fn attempt_p2p_quic_client_mtls(
    candidates: &P2pCandidates,
    punch_timeout: Duration,
    quic_timeout: Duration,
    cancel: &AtomicBool,
    mtls: Option<&MtlsConfig>,
) -> Result<P2pQuicConnection, String> {
    let PunchedSocket {
        socket,
        peer_addr,
        elapsed: punch_elapsed,
        port_lease,
    } = punch_udp_pair_with_lease(P2pRole::Client, candidates, punch_timeout, cancel)?;
    if cancel.load(Ordering::Acquire) {
        return Err("P2P QUIC Client 握手已取消".to_string());
    }

    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("获取 P2P Client 本地地址失败：{e}"))?;
    if let Some(mtls_cfg) = mtls {
        let endpoint = QuicEndpoint::from_socket_mtls(
            socket,
            NetConfig::new(Role::Controller, local_addr),
            None,
        )
        .map_err(|e| format!("创建 P2P QUIC Client mTLS 端点失败：{e}"))?;
        let transport = endpoint
            .connect_mtls_cancelable(peer_addr, mtls_cfg, "", quic_timeout, cancel)
            .map_err(|e| format!("P2P QUIC Client 握手失败：{e}"))?;
        Ok(finalize_p2p_connection(
            endpoint,
            transport,
            punch_elapsed,
            port_lease,
        ))
    } else {
        let endpoint =
            QuicEndpoint::from_socket(socket, NetConfig::new(Role::Controller, local_addr), None)
                .map_err(|e| format!("创建 P2P QUIC Client 端点失败：{e}"))?;
        let certs = Identity::certs_from_pem(rc_session::dev_cert::dev_server_cert_pem())
            .map_err(|e| format!("解析 P2P 受信任证书失败：{e}"))?;
        let transport = endpoint
            .connect_cancelable(
                peer_addr,
                &certs,
                rc_session::dev_cert::DEV_SERVER_NAME,
                quic_timeout,
                cancel,
            )
            .map_err(|e| format!("P2P QUIC Client 握手失败：{e}"))?;
        Ok(finalize_p2p_connection(
            endpoint,
            transport,
            punch_elapsed,
            port_lease,
        ))
    }
}

fn finalize_p2p_connection(
    endpoint: QuicEndpoint,
    transport: QuicTransport,
    punch_elapsed: Duration,
    port_lease: Option<LocalUdpPortLease>,
) -> P2pQuicConnection {
    let peer_addr = transport.remote_addr();
    let stats_rtt = transport.stats().rtt_us;
    let rtt_us = if stats_rtt > 0 {
        stats_rtt
    } else {
        u32::try_from(punch_elapsed.as_micros()).unwrap_or(u32::MAX)
    };
    P2pQuicConnection {
        transport,
        peer_addr,
        rtt_us,
        _endpoint: endpoint,
        _port_lease: port_lease,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn punch_packet_encode_decode_and_reject_invalid() {
        let hash = derive_session_hash("sess-p2p-001");
        let pkt = PunchPacket {
            version: PUNCH_VERSION,
            role: P2pRole::Host,
            ack: true,
            session_hash: hash,
            nonce: [1, 2, 3, 4, 5, 6],
        };
        let wire = encode_punch_packet(&pkt);
        assert_eq!(wire.len(), PUNCH_PACKET_LEN);
        assert_eq!(&wire[0..4], PUNCH_MAGIC);
        assert_eq!(decode_punch_packet(&wire), Some(pkt));

        // 截断或超长拒绝
        assert!(decode_punch_packet(&wire[..PUNCH_PACKET_LEN - 1]).is_none());
        let mut oversized = wire.to_vec();
        oversized.push(0);
        assert!(decode_punch_packet(&oversized).is_none());

        // 错误魔数拒绝
        let mut bad_magic = wire;
        bad_magic[0] = b'X';
        assert!(decode_punch_packet(&bad_magic).is_none());

        // 错误版本拒绝
        let mut bad_ver = wire;
        bad_ver[4] = 2;
        assert!(decode_punch_packet(&bad_ver).is_none());

        // 非法角色字节拒绝
        let mut bad_role = wire;
        bad_role[5] = 9;
        assert!(decode_punch_packet(&bad_role).is_none());

        // 非法 ack 字节拒绝
        let mut bad_ack = wire;
        bad_ack[6] = 2;
        assert!(decode_punch_packet(&bad_ack).is_none());

        // session_hash 确定性且区分不同 session_id
        assert_eq!(derive_session_hash("sess-p2p-001"), hash);
        assert_ne!(derive_session_hash("sess-p2p-002"), hash);
    }

    #[test]
    fn parse_candidate_addrs_prefers_lan_dedups_and_filters_invalid() {
        let candidates = P2pCandidates {
            session_id: "s1".to_string(),
            peer_public_addr: Some("198.51.100.22:60123".to_string()),
            peer_lan_addrs: vec![
                "  ".to_string(),
                "not-an-addr".to_string(),
                "0.0.0.0:9901".to_string(),
                "192.168.1.20:0".to_string(),
                "[::]:9901".to_string(),
                "192.168.1.20:50000".to_string(),
                "192.168.1.20:50000".to_string(),          // 重复
                "[::ffff:192.168.1.20]:50000".to_string(), // IPv4-mapped 同地址去重
                "10.0.0.8:50001".to_string(),
            ],
            local_udp_port: None,
            ..Default::default()
        };
        let parsed = parse_candidate_addrs(&candidates);
        assert_eq!(
            parsed,
            vec![
                "192.168.1.20:50000".parse::<SocketAddr>().unwrap(),
                "10.0.0.8:50001".parse::<SocketAddr>().unwrap(),
                "198.51.100.22:60123".parse::<SocketAddr>().unwrap(),
            ]
        );

        // 若 public 与某个 LAN 重复，仍只保留首次（LAN 优先位）
        let dup_pub = P2pCandidates {
            session_id: "s2".to_string(),
            peer_public_addr: Some("192.168.1.20:50000".to_string()),
            peer_lan_addrs: vec!["192.168.1.20:50000".to_string()],
            local_udp_port: None,
            ..Default::default()
        };
        assert_eq!(
            parse_candidate_addrs(&dup_pub),
            vec!["192.168.1.20:50000".parse::<SocketAddr>().unwrap()]
        );
    }

    fn reserve_ephemeral_udp_port() -> u16 {
        let s = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp");
        s.local_addr().expect("local addr").port()
    }

    #[test]
    fn punch_udp_pair_localhost_succeeds_fast_and_rejects_wrong_session_or_role() {
        let host_port = reserve_ephemeral_udp_port();
        let client_port = reserve_ephemeral_udp_port();
        assert_ne!(host_port, client_port);

        // 注入一条错误会话哈希干扰源与同侧角色干扰源，验证打洞仅认匹配的异侧对端
        let noise_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let wrong_hash_pkt = encode_punch_packet(&PunchPacket {
            version: PUNCH_VERSION,
            role: P2pRole::Client,
            ack: true,
            session_hash: derive_session_hash("wrong-session"),
            nonce: [9; 6],
        });
        let same_role_pkt = encode_punch_packet(&PunchPacket {
            version: PUNCH_VERSION,
            role: P2pRole::Host,
            ack: true,
            session_hash: derive_session_hash("punch-localhost-ok"),
            nonce: [8; 6],
        });
        let _ = noise_sock.send_to(
            &wrong_hash_pkt,
            SocketAddr::from(([127, 0, 0, 1], host_port)),
        );
        let _ = noise_sock.send_to(
            &same_role_pkt,
            SocketAddr::from(([127, 0, 0, 1], host_port)),
        );

        let host_cand = P2pCandidates {
            session_id: "punch-localhost-ok".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{client_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(host_port),
            ..Default::default()
        };
        let client_cand = P2pCandidates {
            session_id: "punch-localhost-ok".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(client_port),
            ..Default::default()
        };

        let cancel_h = Arc::new(AtomicBool::new(false));
        let cancel_c = Arc::clone(&cancel_h);

        let t0 = Instant::now();
        let host_thread = thread::spawn(move || {
            punch_udp_pair(P2pRole::Host, &host_cand, DEFAULT_PUNCH_TIMEOUT, &cancel_h)
        });
        let (client_sock, client_seen_peer, client_elapsed) = punch_udp_pair(
            P2pRole::Client,
            &client_cand,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel_c,
        )
        .expect("client punch must succeed");
        let (host_sock, host_seen_peer, host_elapsed) = host_thread
            .join()
            .expect("host thread join")
            .expect("host punch must succeed");

        let total = t0.elapsed();
        assert!(
            total < Duration::from_millis(200),
            "localhost UDP punch should succeed in < 200ms, took {total:?} (host={host_elapsed:?}, client={client_elapsed:?})"
        );
        assert_eq!(
            client_seen_peer.port(),
            host_sock.local_addr().unwrap().port()
        );
        assert_eq!(
            host_seen_peer.port(),
            client_sock.local_addr().unwrap().port()
        );
    }

    #[test]
    fn attempt_p2p_quic_localhost_roundtrip_datagram_reliable_and_urgent() {
        let host_port = reserve_ephemeral_udp_port();
        let client_port = reserve_ephemeral_udp_port();
        assert_ne!(host_port, client_port);

        let host_cand = P2pCandidates {
            session_id: "p2p-quic-e2e-001".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{client_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(host_port),
            ..Default::default()
        };
        let client_cand = P2pCandidates {
            session_id: "p2p-quic-e2e-001".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(client_port),
            ..Default::default()
        };

        let cancel_h = Arc::new(AtomicBool::new(false));
        let cancel_c = Arc::clone(&cancel_h);

        let host_thread = thread::spawn(move || {
            attempt_p2p_quic_host(
                &host_cand,
                DEFAULT_PUNCH_TIMEOUT,
                DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                &cancel_h,
            )
        });
        let client_conn = attempt_p2p_quic_client(
            &client_cand,
            DEFAULT_PUNCH_TIMEOUT,
            DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
            &cancel_c,
        )
        .expect("P2P QUIC client must connect");
        let host_conn = host_thread
            .join()
            .expect("host thread join")
            .expect("P2P QUIC host must accept");

        assert_eq!(client_conn.peer_addr.port(), host_port);
        assert_eq!(host_conn.peer_addr.port(), client_port);

        // 通过 trait object (`Box<dyn Transport>`) 验证三条通道收发与端点保活
        let mut client: Box<dyn Transport> = Box::new(client_conn);
        let mut host: Box<dyn Transport> = Box::new(host_conn);

        let dgram = b"p2p-video-slice-01".to_vec();
        let rel_h2c = b"p2p-control-host-to-client".to_vec();
        let rel_c2h = b"p2p-control-client-to-host".to_vec();
        let urg_c2h = b"p2p-input-urgent-key-a".to_vec();

        host.send_datagram(&dgram).unwrap();
        host.send_reliable(&rel_h2c).unwrap();
        client.send_reliable(&rel_c2h).unwrap();
        client.send_reliable_urgent(&urg_c2h).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got_dgram = false;
        let mut got_rel_h2c = false;
        let mut got_rel_c2h = false;
        let mut got_urg_c2h = false;

        while Instant::now() < deadline && !(got_dgram && got_rel_h2c && got_rel_c2h && got_urg_c2h)
        {
            for ev in client.poll(Duration::from_millis(20)).unwrap() {
                match ev {
                    NetEvent::Datagram(b) if b == dgram => got_dgram = true,
                    NetEvent::Reliable(b) if b == rel_h2c => got_rel_h2c = true,
                    _ => {}
                }
            }
            for ev in host.poll(Duration::from_millis(20)).unwrap() {
                match ev {
                    NetEvent::Reliable(b) if b == rel_c2h => got_rel_c2h = true,
                    NetEvent::ReliableUrgent(b) if b == urg_c2h => got_urg_c2h = true,
                    _ => {}
                }
            }
        }

        assert!(got_dgram, "client must receive datagram over P2P QUIC");
        assert!(got_rel_h2c, "client must receive reliable over P2P QUIC");
        assert!(got_rel_c2h, "host must receive reliable over P2P QUIC");
        assert!(got_urg_c2h, "host must receive urgent over P2P QUIC");
    }

    #[cfg(unix)]
    #[test]
    fn p2p_quic_succeeds_while_connected_signal_probe_sockets_hold_same_local_ports() {
        // 模拟真实运行时：两端 SignalClientHandle 各自持有已 connect 到信令 UDP 端口的
        // SO_REUSEADDR + SO_REUSEPORT 探测套接字，同时 P2P 打洞 + QUIC 复用完全相同的本地端口。
        let sig_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sig_addr = sig_udp.local_addr().unwrap();

        let make_probe_sock = || -> (UdpSocket, u16) {
            let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            raw.set_reuse_address(true).unwrap();
            #[cfg(unix)]
            raw.set_reuse_port(true).unwrap();
            raw.bind(&SockAddr::from(SocketAddr::from(([0, 0, 0, 0], 0))))
                .unwrap();
            let sock: UdpSocket = raw.into();
            let port = sock.local_addr().unwrap().port();
            sock.connect(sig_addr).unwrap();
            (sock, port)
        };

        let (_host_probe, host_port) = make_probe_sock();
        let (_client_probe, client_port) = make_probe_sock();
        assert_ne!(host_port, client_port);

        let host_cand = P2pCandidates {
            session_id: "p2p-coexist-probe-001".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{client_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(host_port),
            ..Default::default()
        };
        let client_cand = P2pCandidates {
            session_id: "p2p-coexist-probe-001".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(client_port),
            ..Default::default()
        };

        let cancel_h = Arc::new(AtomicBool::new(false));
        let cancel_c = Arc::clone(&cancel_h);

        let host_thread = thread::spawn(move || {
            attempt_p2p_quic_host(
                &host_cand,
                DEFAULT_PUNCH_TIMEOUT,
                DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                &cancel_h,
            )
        });
        let mut client = attempt_p2p_quic_client(
            &client_cand,
            DEFAULT_PUNCH_TIMEOUT,
            DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
            &cancel_c,
        )
        .expect("client P2P QUIC must coexist with persistent probe socket");
        let mut host = host_thread
            .join()
            .expect("host join")
            .expect("host P2P QUIC must coexist with persistent probe socket");

        assert_eq!(client.peer_addr.port(), host_port);
        assert_eq!(host.peer_addr.port(), client_port);

        host.send_datagram(b"coexist-dgram").unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut received = false;
        while Instant::now() < deadline && !received {
            for ev in client.poll(Duration::from_millis(20)).unwrap() {
                if matches!(ev, NetEvent::Datagram(ref b) if b == b"coexist-dgram") {
                    received = true;
                }
            }
        }
        assert!(
            received,
            "datagram must flow while probe sockets remain open"
        );
    }

    #[test]
    fn punch_cancel_aborts_fast_and_unreachable_times_out_cleanly() {
        // 1) 取消信号必须在 < 300ms 内快速返回错误
        let cancel = Arc::new(AtomicBool::new(false));
        let trigger = Arc::clone(&cancel);
        let killer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            trigger.store(true, Ordering::Release);
        });
        let dead_port = reserve_ephemeral_udp_port();
        let cand_cancel = P2pCandidates {
            session_id: "cancel-test".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{dead_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: None,
            ..Default::default()
        };
        let t0 = Instant::now();
        let res = punch_udp_pair(
            P2pRole::Client,
            &cand_cancel,
            Duration::from_secs(5),
            &cancel,
        );
        let elapsed = t0.elapsed();
        killer.join().unwrap();
        assert!(res.is_err());
        assert!(
            elapsed < Duration::from_millis(300),
            "cancel must abort in < 300ms, took {elapsed:?}"
        );

        // 2) 无响应对端在超时后干净返回 Err，供上层回退 TCP 中继
        let no_cancel = AtomicBool::new(false);
        let cand_timeout = P2pCandidates {
            session_id: "timeout-test".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{dead_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: None,
            ..Default::default()
        };
        let t1 = Instant::now();
        let err = punch_udp_pair(
            P2pRole::Host,
            &cand_timeout,
            Duration::from_millis(120),
            &no_cancel,
        )
        .unwrap_err();
        assert!(
            err.contains("超时"),
            "timeout error should explain timeout: {err}"
        );
        assert!(
            t1.elapsed() >= Duration::from_millis(100) && t1.elapsed() < Duration::from_secs(1),
            "timeout duration unexpected: {:?}",
            t1.elapsed()
        );

        // 3) 空候选列表立刻失败，不白等超时
        let empty_cand = P2pCandidates {
            session_id: "empty-test".to_string(),
            peer_public_addr: None,
            peer_lan_addrs: Vec::new(),
            local_udp_port: None,
            ..Default::default()
        };
        let t2 = Instant::now();
        assert!(attempt_p2p_quic_client(
            &empty_cand,
            Duration::from_secs(5),
            Duration::from_secs(5),
            &no_cancel,
        )
        .is_err());
        assert!(t2.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn local_udp_port_lease_prevents_double_bind_and_falls_back_to_ephemeral() {
        let preferred = reserve_ephemeral_udp_port();
        let (sock1, lease1) =
            bind_punch_socket(Some(preferred), false, false).expect("first bind must succeed");
        assert_eq!(sock1.local_addr().unwrap().port(), preferred);
        assert!(lease1.is_some(), "first bind must acquire port lease");

        // 租约仍被持有时，第二次请求同一 local_udp_port 不得双绑 SO_REUSEPORT，必须降级临时端口。
        let (sock2, lease2) =
            bind_punch_socket(Some(preferred), false, false).expect("second bind must fallback");
        assert_ne!(
            sock2.local_addr().unwrap().port(),
            preferred,
            "second bind must fall back to ephemeral port while lease is held"
        );
        assert!(lease2.is_none(), "ephemeral fallback must not hold a lease");

        // 释放第一个套接字与租约后，同一端口可重新获取租约并绑定。
        drop(sock1);
        drop(lease1);
        let (sock3, lease3) =
            bind_punch_socket(Some(preferred), false, false).expect("rebind after drop");
        assert_eq!(sock3.local_addr().unwrap().port(), preferred);
        assert!(lease3.is_some());
    }

    #[test]
    fn mixed_ipv4_and_ipv6_candidates_retain_ipv6_public_addr_and_punch_dual_stack() {
        // 混合候选同时包含 IPv4 LAN 与 IPv6 公网地址：绝不得因存在 IPv4 LAN 而丢弃 IPv6 公网候选。
        let dead_v4_port = reserve_ephemeral_udp_port();
        let host_v6_probe = UdpSocket::bind("[::1]:0").expect("bind ipv6 loopback");
        let host_v6_port = host_v6_probe.local_addr().unwrap().port();
        drop(host_v6_probe);

        let mixed_client_cand = P2pCandidates {
            session_id: "mixed-v4-v6-001".to_string(),
            peer_public_addr: Some(format!("[::1]:{host_v6_port}")),
            peer_lan_addrs: vec![format!("127.0.0.1:{dead_v4_port}")],
            local_udp_port: None,
            ..Default::default()
        };
        let all = parse_candidate_addrs(&mixed_client_cand);
        let setup = prepare_punch_socket_and_targets(&mixed_client_cand, &all)
            .expect("prepare dual-stack socket");
        assert!(
            setup.socket_is_ipv6,
            "mixed IPv4+IPv6 candidates must create AF_INET6 dual-stack socket"
        );
        assert_eq!(
            setup.targets.len(),
            2,
            "must retain both IPv4-mapped and IPv6 targets"
        );
        assert!(
            setup.targets.iter().any(|a| *a
                == format!("[::1]:{host_v6_port}")
                    .parse::<SocketAddr>()
                    .unwrap()),
            "IPv6 peer_public_addr must be retained: {:?}",
            setup.targets
        );
        assert!(
            setup.targets.iter().any(|a| {
                *a == format!("[::ffff:127.0.0.1]:{dead_v4_port}")
                    .parse::<SocketAddr>()
                    .unwrap()
            }),
            "IPv4 LAN candidate must be mapped to ::ffff: on AF_INET6 socket: {:?}",
            setup.targets
        );
        drop(setup);

        // 1) 端到端验证：混合候选 Client 通过双栈 AF_INET6 套接字打通纯 IPv6 Host（IPv4 LAN 不可达）。
        let client_v6_probe = UdpSocket::bind("[::1]:0").expect("bind ipv6 client port");
        let client_v6_port = client_v6_probe.local_addr().unwrap().port();
        drop(client_v6_probe);

        let host_v6_cand = P2pCandidates {
            session_id: "mixed-v4-v6-e2e".to_string(),
            peer_public_addr: Some(format!("[::1]:{client_v6_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(host_v6_port),
            ..Default::default()
        };
        let client_mixed_cand = P2pCandidates {
            session_id: "mixed-v4-v6-e2e".to_string(),
            peer_public_addr: Some(format!("[::1]:{host_v6_port}")),
            peer_lan_addrs: vec![format!("127.0.0.1:{dead_v4_port}")],
            local_udp_port: Some(client_v6_port),
            ..Default::default()
        };

        let cancel_h = Arc::new(AtomicBool::new(false));
        let cancel_c = Arc::clone(&cancel_h);
        let host_thread = thread::spawn(move || {
            punch_udp_pair(
                P2pRole::Host,
                &host_v6_cand,
                DEFAULT_PUNCH_TIMEOUT,
                &cancel_h,
            )
        });
        let (_c_sock, c_peer, _) = punch_udp_pair(
            P2pRole::Client,
            &client_mixed_cand,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel_c,
        )
        .expect("mixed IPv4+IPv6 client must punch IPv6 host");
        let (_h_sock, h_peer, _) = host_thread
            .join()
            .unwrap()
            .expect("IPv6 host must punch mixed client");
        assert_eq!(c_peer.port(), host_v6_port);
        assert_eq!(h_peer.port(), client_v6_port);

        // 2) 反向验证：双栈 AF_INET6 套接字也能向 IPv4-mapped (::ffff:127.0.0.1) 对端收发而不剥离前缀。
        let host_v4_port = reserve_ephemeral_udp_port();
        let client_dual_port = reserve_ephemeral_udp_port();
        let dead_v6_probe = UdpSocket::bind("[::1]:0").expect("bind dead v6");
        let dead_v6_port = dead_v6_probe.local_addr().unwrap().port();
        drop(dead_v6_probe);

        let host_v4_cand = P2pCandidates {
            session_id: "dual-to-v4-e2e".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{client_dual_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(host_v4_port),
            ..Default::default()
        };
        let client_dual_cand = P2pCandidates {
            session_id: "dual-to-v4-e2e".to_string(),
            peer_public_addr: Some(format!("[::1]:{dead_v6_port}")),
            peer_lan_addrs: vec![format!("127.0.0.1:{host_v4_port}")],
            local_udp_port: Some(client_dual_port),
            ..Default::default()
        };
        let cancel_h2 = Arc::new(AtomicBool::new(false));
        let cancel_c2 = Arc::clone(&cancel_h2);
        let host_v4_thread = thread::spawn(move || {
            punch_udp_pair(
                P2pRole::Host,
                &host_v4_cand,
                DEFAULT_PUNCH_TIMEOUT,
                &cancel_h2,
            )
        });
        let (_c2_sock, c2_peer, _) = punch_udp_pair(
            P2pRole::Client,
            &client_dual_cand,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel_c2,
        )
        .expect("dual-stack AF_INET6 socket must punch IPv4 host via ::ffff:");
        let (_h2_sock, _h2_peer, _) = host_v4_thread
            .join()
            .unwrap()
            .expect("IPv4 host must punch dual-stack client");
        assert!(
            c2_peer.is_ipv6(),
            "AF_INET6 socket must preserve ::ffff: address family instead of stripping to V4: {c2_peer}"
        );
        assert_eq!(c2_peer.port(), host_v4_port);
    }

    #[test]
    fn peek_from_preserves_peer_quic_initial_packet_in_kernel_buffer() {
        let host_port = reserve_ephemeral_udp_port();
        let peer_sock = UdpSocket::bind("127.0.0.1:0").expect("bind fake peer");
        let peer_addr = peer_sock.local_addr().unwrap();
        let junk_sock = UdpSocket::bind("127.0.0.1:0").expect("bind unknown junk");

        let session_id = "peek-preserve-quic-initial";
        let session_hash = derive_session_hash(session_id);
        let host_addr = SocketAddr::from(([127, 0, 0, 1], host_port));

        // 构造合成 QUIC Initial 长包头载荷（非 RCP2 魔数）。
        let mut fake_quic_initial = vec![0xc0, 0x00, 0x00, 0x00, 0x01];
        fake_quic_initial.extend_from_slice(b"synthetic-quic-initial-payload-must-stay-intact");
        let expected_quic = fake_quic_initial.clone();

        let peer_thread = thread::spawn(move || {
            peer_sock
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            // 先从未知来源发一条非 RCP2 杂散包，验证不会误触发或卡死。
            let _ = junk_sock.send_to(b"random-noise-from-stranger", host_addr);

            // 等待 Host 绑定并开始发送 Probe 后，发一条 Client Probe 触发 Host 确认对端。
            let mut buf = [0u8; 256];
            let _ = peer_sock.recv_from(&mut buf).expect("recv host probe");
            let probe = encode_punch_packet(&PunchPacket {
                version: PUNCH_VERSION,
                role: P2pRole::Client,
                ack: false,
                session_hash,
                nonce: [7; 6],
            });
            peer_sock.send_to(&probe, host_addr).unwrap();

            // 收到 Host 回复的 Ack 后，模拟对端 Ack 丢失但直接切入 QUIC 发出 Initial。
            let (n, _) = peer_sock.recv_from(&mut buf).expect("recv host ack");
            let pkt = decode_punch_packet(&buf[..n]).expect("valid host ack");
            assert!(pkt.ack, "host must reply with ack=true");
            peer_sock.send_to(&fake_quic_initial, host_addr).unwrap();
        });

        let host_cand = P2pCandidates {
            session_id: session_id.to_string(),
            peer_public_addr: Some(peer_addr.to_string()),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(host_port),
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        let (host_sock, punched_peer, _) =
            punch_udp_pair(P2pRole::Host, &host_cand, DEFAULT_PUNCH_TIMEOUT, &cancel)
                .expect("host punch must exit immediately when peeking peer QUIC Initial");
        peer_thread.join().unwrap();
        assert_eq!(punched_peer, peer_addr);

        // 关键断言：对端的 QUIC Initial 必须完好留在内核接收缓冲中未被 punch_udp_pair 吞掉！
        host_sock
            .set_nonblocking(false)
            .expect("set blocking for verify");
        host_sock
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut verify_buf = [0u8; 256];
        let (n, from) = host_sock
            .recv_from(&mut verify_buf)
            .expect("QUIC Initial packet must still be unread in kernel buffer");
        assert_eq!(from, peer_addr);
        assert_eq!(&verify_buf[..n], expected_quic.as_slice());
    }

    #[test]
    fn one_way_probe_without_ack_does_not_false_positive_confirm() {
        let host_port = reserve_ephemeral_udp_port();
        let peer_sock = UdpSocket::bind("127.0.0.1:0").expect("bind one-way peer");
        let peer_addr = peer_sock.local_addr().unwrap();
        let host_addr = SocketAddr::from(([127, 0, 0, 1], host_port));

        let session_id = "one-way-probe-no-ack";
        let session_hash = derive_session_hash(session_id);
        let probe = encode_punch_packet(&PunchPacket {
            version: PUNCH_VERSION,
            role: P2pRole::Client,
            ack: false,
            session_hash,
            nonce: [3; 6],
        });

        // 模拟单向链路：对端不断发送 Probe（ack=false），永远不发 Ack 也不发 QUIC Initial。
        let stop_sender = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop_sender);
        let sender = thread::spawn(move || {
            while !stop_flag.load(Ordering::Acquire) {
                let _ = peer_sock.send_to(&probe, host_addr);
                thread::sleep(Duration::from_millis(20));
            }
        });

        let host_cand = P2pCandidates {
            session_id: session_id.to_string(),
            peer_public_addr: Some(peer_addr.to_string()),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(host_port),
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        let res = punch_udp_pair(
            P2pRole::Host,
            &host_cand,
            Duration::from_millis(220),
            &cancel,
        );
        stop_sender.store(true, Ordering::Release);
        sender.join().unwrap();

        let err = res.expect_err("one-way Probe without Ack must NOT false-positive confirm");
        assert!(
            err.contains("超时"),
            "expected timeout error on one-way probe, got: {err}"
        );
    }

    #[test]
    fn p2p_quic_mtls_handshake_verifies_identity_and_rejects_mismatch() {
        use crate::relay_transport::tests::mtls_test_certs::TestCa;
        use crate::relay_transport::SessionMtlsBundle;

        let mut ca = TestCa::new("P2pMtlsCA");
        let (c_cert, c_key) = ca.issue_device("u-p2p", "111222333");
        let (h_cert, h_key) = ca.issue_device("u-p2p", "444555666");

        let client_mtls = SessionMtlsBundle {
            ca_cert_pem: ca.ca_pem.clone(),
            cert_pem: c_cert,
            key_pem: c_key,
            local_user_id: "u-p2p".to_string(),
            expected_peer_device_id: Some("444555666".to_string()),
            expected_peer_user_id: Some("u-p2p".to_string()),
        }
        .to_quic_mtls_config()
        .unwrap();
        let host_bundle = SessionMtlsBundle {
            ca_cert_pem: ca.ca_pem,
            cert_pem: h_cert,
            key_pem: h_key,
            local_user_id: "u-p2p".to_string(),
            expected_peer_device_id: Some("111222333".to_string()),
            expected_peer_user_id: Some("u-p2p".to_string()),
        };
        let host_mtls = host_bundle.to_quic_mtls_config().unwrap();

        // 1) 成功握手并验证对端身份
        let host_port = reserve_ephemeral_udp_port();
        let client_port = reserve_ephemeral_udp_port();
        let host_cand = P2pCandidates {
            session_id: "p2p-mtls-ok".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{client_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(host_port),
            ..Default::default()
        };
        let client_cand = P2pCandidates {
            session_id: "p2p-mtls-ok".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_port}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(client_port),
            ..Default::default()
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_h = Arc::clone(&cancel);
        let h_jh = thread::spawn(move || {
            attempt_p2p_quic_host_mtls(
                &host_cand,
                Duration::from_secs(2),
                Duration::from_secs(2),
                &cancel_h,
                Some(&host_mtls),
            )
            .expect("host p2p mtls must succeed")
        });
        let mut client_conn = attempt_p2p_quic_client_mtls(
            &client_cand,
            Duration::from_secs(2),
            Duration::from_secs(2),
            &cancel,
            Some(&client_mtls),
        )
        .expect("client p2p mtls must succeed");
        let mut host_conn = h_jh.join().unwrap();

        assert_eq!(
            client_conn.peer_mtls_identity().unwrap().device_id,
            "444555666"
        );
        assert_eq!(
            host_conn.peer_mtls_identity().unwrap().device_id,
            "111222333"
        );

        client_conn.transport.send_reliable(b"p2p-mtls-ok").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got_msg = false;
        while Instant::now() < deadline && !got_msg {
            for ev in host_conn.transport.poll(Duration::from_millis(50)).unwrap() {
                if ev == NetEvent::Reliable(b"p2p-mtls-ok".to_vec()) {
                    got_msg = true;
                }
            }
        }
        assert!(got_msg, "host must receive reliable message over P2P mTLS");
        drop(client_conn);
        drop(host_conn);

        // 2) expected_peer_device_id 不匹配必须拒绝
        let host_port2 = reserve_ephemeral_udp_port();
        let client_port2 = reserve_ephemeral_udp_port();
        let host_cand2 = P2pCandidates {
            session_id: "p2p-mtls-mismatch".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{client_port2}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(host_port2),
            ..Default::default()
        };
        let client_cand2 = P2pCandidates {
            session_id: "p2p-mtls-mismatch".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_port2}")),
            peer_lan_addrs: Vec::new(),
            local_udp_port: Some(client_port2),
            ..Default::default()
        };
        let mut wrong_client_mtls = client_mtls;
        wrong_client_mtls.expected_peer_device_id = Some("999999999".to_string());
        let cancel2 = Arc::new(AtomicBool::new(false));
        let cancel2_h = Arc::clone(&cancel2);
        let host_mtls2 = host_bundle.to_quic_mtls_config().unwrap();
        let h_jh2 = thread::spawn(move || {
            attempt_p2p_quic_host_mtls(
                &host_cand2,
                Duration::from_secs(2),
                Duration::from_millis(800),
                &cancel2_h,
                Some(&host_mtls2),
            )
        });
        let c_res = attempt_p2p_quic_client_mtls(
            &client_cand2,
            Duration::from_secs(2),
            Duration::from_millis(800),
            &cancel2,
            Some(&wrong_client_mtls),
        );
        assert!(c_res.is_err(), "wrong expected_peer_device_id must fail");
        let _ = h_jh2.join();
    }

    #[test]
    fn drain_punch_rx_continues_across_transient_errors_and_caps_spin() {
        struct FakePunchSocket {
            peek_results: std::collections::VecDeque<io::Result<(Vec<u8>, SocketAddr)>>,
            recv_results: std::collections::VecDeque<io::Result<(Vec<u8>, SocketAddr)>>,
            sent: usize,
            peeks: usize,
        }

        impl PunchSocketOps for FakePunchSocket {
            fn peek_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                self.peeks += 1;
                match self.peek_results.pop_front() {
                    Some(Ok((pkt, addr))) => {
                        buf[..pkt.len()].copy_from_slice(&pkt);
                        Ok((pkt.len(), addr))
                    }
                    Some(Err(e)) => Err(e),
                    None => Err(io::Error::from(ErrorKind::WouldBlock)),
                }
            }

            fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                match self.recv_results.pop_front() {
                    Some(Ok((pkt, addr))) => {
                        buf[..pkt.len()].copy_from_slice(&pkt);
                        Ok((pkt.len(), addr))
                    }
                    Some(Err(e)) => Err(e),
                    None => Err(io::Error::from(ErrorKind::WouldBlock)),
                }
            }

            fn send_to(&mut self, _buf: &[u8], _addr: SocketAddr) {
                self.sent += 1;
            }
        }

        let session_hash = derive_session_hash("sess-transient");
        let peer_addr: SocketAddr = "198.51.100.77:55555".parse().unwrap();
        let target_canons: HashSet<SocketAddr> = [peer_addr].into_iter().collect();
        let peer_ack = encode_punch_packet(&PunchPacket {
            version: PUNCH_VERSION,
            role: P2pRole::Client,
            ack: true,
            session_hash,
            nonce: [7u8; 6],
        });
        let local_ack = encode_punch_packet(&PunchPacket {
            version: PUNCH_VERSION,
            role: P2pRole::Host,
            ack: true,
            session_hash,
            nonce: [8u8; 6],
        });

        // 1) Interrupted + ConnectionReset + ConnectionRefused (< 64) 后立即继续排空并命中对端 ACK 包
        let mut recv_buf = [0u8; 128];
        let mut confirmed_peer = None;
        let mut fake1 = FakePunchSocket {
            peek_results: std::collections::VecDeque::from([
                Err(io::Error::from(ErrorKind::Interrupted)),
                Err(io::Error::from(ErrorKind::ConnectionReset)),
                Err(io::Error::from(ErrorKind::ConnectionRefused)),
                Ok((peer_ack.to_vec(), peer_addr)),
            ]),
            recv_results: std::collections::VecDeque::from([
                Err(io::Error::from(ErrorKind::ConnectionReset)),
                Err(io::Error::from(ErrorKind::Interrupted)),
                Ok((peer_ack.to_vec(), peer_addr)),
            ]),
            sent: 0,
            peeks: 0,
        };
        let mut auth1 = PunchAuthMode::V1 {
            session_hash,
            probe_pkt: local_ack,
            ack_pkt: local_ack,
        };
        let mut peer_nonce1 = None;
        let res = drain_punch_rx(
            &mut recv_buf,
            false,
            &mut auth1,
            P2pRole::Client,
            P2pRole::Host,
            &target_canons,
            &mut confirmed_peer,
            &mut peer_nonce1,
            &mut fake1,
        )
        .expect("transient errors followed by ACK must succeed");
        assert_eq!(res, DrainOutcome::Ready(peer_addr));
        assert_eq!(fake1.sent, IMMEDIATE_ACK_BURST);

        // 2) 连续超过 MAX_CONSECUTIVE_TRANSIENT_ERRORS (64) 次瞬态错误时必须主动 break，避免饿死超时/取消
        let mut confirmed_peer2 = None;
        let mut peer_nonce2 = None;
        let mut fake2 = FakePunchSocket {
            peek_results: (0..100)
                .map(|_| Err(io::Error::from(ErrorKind::Interrupted)))
                .collect(),
            recv_results: std::collections::VecDeque::new(),
            sent: 0,
            peeks: 0,
        };
        let res2 = drain_punch_rx(
            &mut recv_buf,
            false,
            &mut auth1,
            P2pRole::Client,
            P2pRole::Host,
            &target_canons,
            &mut confirmed_peer2,
            &mut peer_nonce2,
            &mut fake2,
        )
        .expect("capped transient errors must break cleanly");
        assert_eq!(res2, DrainOutcome::Continue);
        assert_eq!(fake2.peeks, MAX_CONSECUTIVE_TRANSIENT_ERRORS + 1);

        // 3) 非瞬态硬错误立即向上返回 Err
        let mut confirmed_peer3 = None;
        let mut peer_nonce3 = None;
        let mut fake3 = FakePunchSocket {
            peek_results: std::collections::VecDeque::from([Err(io::Error::from(
                ErrorKind::InvalidInput,
            ))]),
            recv_results: std::collections::VecDeque::new(),
            sent: 0,
            peeks: 0,
        };
        let err = drain_punch_rx(
            &mut recv_buf,
            false,
            &mut auth1,
            P2pRole::Client,
            P2pRole::Host,
            &target_canons,
            &mut confirmed_peer3,
            &mut peer_nonce3,
            &mut fake3,
        )
        .unwrap_err();
        assert!(err.contains("P2P UDP 打洞读取失败"));

        // 4) ConnectionReset 后由 recv_from 返回来自已知对端的非 RCP2（如 QUIC Initial）报文也必须返回 Ready
        let mut confirmed_peer4 = None;
        let mut peer_nonce4 = None;
        let quic_initial_like = b"\xc0\x00\x00\x00\x01QUIC-INITIAL".to_vec();
        let mut fake4 = FakePunchSocket {
            peek_results: std::collections::VecDeque::from([Err(io::Error::from(
                ErrorKind::ConnectionReset,
            ))]),
            recv_results: std::collections::VecDeque::from([Ok((quic_initial_like, peer_addr))]),
            sent: 0,
            peeks: 0,
        };
        let res4 = drain_punch_rx(
            &mut recv_buf,
            false,
            &mut auth1,
            P2pRole::Client,
            P2pRole::Host,
            &target_canons,
            &mut confirmed_peer4,
            &mut peer_nonce4,
            &mut fake4,
        )
        .expect(
            "non-RCP2 packet from target peer via recv_from after ConnectionReset must succeed",
        );
        assert_eq!(res4, DrainOutcome::Ready(peer_addr));

        // 5) ConnectionReset 清错路径中若 recv_from 返回非瞬态硬错误，不得吞错而应立即向上返回 Err
        let mut confirmed_peer5 = None;
        let mut peer_nonce5 = None;
        let mut fake5 = FakePunchSocket {
            peek_results: std::collections::VecDeque::from([Err(io::Error::from(
                ErrorKind::ConnectionReset,
            ))]),
            recv_results: std::collections::VecDeque::from([Err(io::Error::from(
                ErrorKind::InvalidInput,
            ))]),
            sent: 0,
            peeks: 0,
        };
        let err5 = drain_punch_rx(
            &mut recv_buf,
            false,
            &mut auth1,
            P2pRole::Client,
            P2pRole::Host,
            &target_canons,
            &mut confirmed_peer5,
            &mut peer_nonce5,
            &mut fake5,
        )
        .unwrap_err();
        assert!(err5.contains("P2P UDP 打洞读取失败"));
    }

    #[test]
    fn parse_candidate_addrs_merges_peer_public_addrs_with_priority_v6_lan_v4() {
        assert_eq!(DEFAULT_PUNCH_TIMEOUT, Duration::from_millis(2_400));

        let candidates = P2pCandidates {
            session_id: "merge-priority".to_string(),
            peer_public_addr: Some("203.0.113.5:60000".to_string()),
            peer_public_addrs: vec![
                "198.51.100.22:60123".to_string(),
                "[2001:db8::1]:60123".to_string(),
                "[::ffff:198.51.100.22]:60123".to_string(), // 与 IPv4 去重
                "[fe80::1]:60123".to_string(),              // 非全球单播 IPv6 归入 LAN 档
            ],
            peer_lan_addrs: vec![
                "192.168.1.20:50000".to_string(),
                "10.0.0.8:50001".to_string(),
                "203.0.113.5:60000".to_string(), // 去重
            ],
            local_udp_port: None,
            ..Default::default()
        };

        let parsed = parse_candidate_addrs(&candidates);
        assert_eq!(
            parsed,
            vec![
                "[2001:db8::1]:60123".parse::<SocketAddr>().unwrap(),
                "[fe80::1]:60123".parse::<SocketAddr>().unwrap(),
                "192.168.1.20:50000".parse::<SocketAddr>().unwrap(),
                "10.0.0.8:50001".parse::<SocketAddr>().unwrap(),
                "198.51.100.22:60123".parse::<SocketAddr>().unwrap(),
                "203.0.113.5:60000".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn symmetric_random_both_sides_public_ipv4_only_fails_immediately() {
        let cancel = AtomicBool::new(false);
        let cand_fast_fail = P2pCandidates {
            session_id: "sym-rand-fast-fail".to_string(),
            peer_public_addr: Some("203.0.113.10:50000".to_string()),
            peer_public_addrs: vec!["198.51.100.20:50001".to_string()],
            peer_lan_addrs: Vec::new(),
            local_udp_port: None,
            self_nat_type: NatType::ApdmRandom,
            self_nat_port_delta: None,
            peer_nat_type: NatType::ApdmRandom,
            peer_nat_port_delta: None,
            ..Default::default()
        };

        let t0 = Instant::now();
        let err = punch_udp_pair(
            P2pRole::Client,
            &cand_fast_fail,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel,
        )
        .unwrap_err();
        let elapsed = t0.elapsed();
        assert!(
            err.contains("双端均为随机对称 NAT"),
            "unexpected fast-fail err: {err}"
        );
        assert!(
            elapsed < Duration::from_millis(50),
            "fast-fail must return in < 50ms, took {elapsed:?}"
        );

        // 若存在全球 IPv6 或 LAN 候选，不得触发双随机快速失败
        let host_port = reserve_ephemeral_udp_port();
        let client_port = reserve_ephemeral_udp_port();
        let host_cand = P2pCandidates {
            session_id: "sym-rand-lan-bypass".to_string(),
            peer_public_addr: Some("203.0.113.10:50000".to_string()),
            peer_lan_addrs: vec![format!("127.0.0.1:{client_port}")],
            local_udp_port: Some(host_port),
            self_nat_type: NatType::ApdmRandom,
            peer_nat_type: NatType::ApdmRandom,
            ..Default::default()
        };
        let client_cand = P2pCandidates {
            session_id: "sym-rand-lan-bypass".to_string(),
            peer_public_addr: Some("198.51.100.20:50001".to_string()),
            peer_lan_addrs: vec![format!("127.0.0.1:{host_port}")],
            local_udp_port: Some(client_port),
            self_nat_type: NatType::ApdmRandom,
            peer_nat_type: NatType::ApdmRandom,
            ..Default::default()
        };
        let cancel_h = Arc::new(AtomicBool::new(false));
        let cancel_c = Arc::clone(&cancel_h);
        let jh = thread::spawn(move || {
            punch_udp_pair(P2pRole::Host, &host_cand, DEFAULT_PUNCH_TIMEOUT, &cancel_h)
        });
        let (_, _, c_elapsed) = punch_udp_pair(
            P2pRole::Client,
            &client_cand,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel_c,
        )
        .expect("LAN candidate must bypass symmetric_random fast-fail");
        jh.join().unwrap().expect("host punch must succeed via LAN");
        assert!(c_elapsed < Duration::from_millis(200));
    }

    #[test]
    fn punch_udp_pair_cone_to_sequential_symmetric_delta_plus_3_succeeds() {
        let sym_real_sock = UdpSocket::bind("127.0.0.1:0").expect("bind sym real sock");
        let sym_real_port = sym_real_sock.local_addr().unwrap().port();
        assert!(sym_real_port > 100);
        let sym_stun_port = sym_real_port - 3;
        let host_port = reserve_ephemeral_udp_port();

        let session_id = "cone-vs-seq-sym-plus-3";
        let session_hash = derive_session_hash(session_id);

        let peer_thread = thread::spawn(move || {
            sym_real_sock
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 256];
            // 仅在 Host Phase 2 预测到 sym_stun_port + 3 时才能收到探测包
            let (n, from_addr) = sym_real_sock
                .recv_from(&mut buf)
                .expect("must receive Phase 2 predicted probe on base+3");
            let pkt = decode_punch_packet(&buf[..n]).expect("valid host probe");
            assert_eq!(pkt.role, P2pRole::Host);
            assert!(!pkt.ack);

            let client_ack = encode_punch_packet(&PunchPacket {
                version: PUNCH_VERSION,
                role: P2pRole::Client,
                ack: true,
                session_hash,
                nonce: [5u8; 6],
            });
            sym_real_sock.send_to(&client_ack, from_addr).unwrap();
        });

        let host_cand = P2pCandidates {
            session_id: session_id.to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{sym_stun_port}")),
            local_udp_port: Some(host_port),
            self_nat_type: NatType::ConeVerified,
            peer_nat_type: NatType::ApdmSeq,
            peer_nat_port_delta: Some(3),
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        let (_host_sock, punched_peer, elapsed) =
            punch_udp_pair(P2pRole::Host, &host_cand, DEFAULT_PUNCH_TIMEOUT, &cancel)
                .expect("Cone -> Sequential Symmetric (+3) must succeed in Phase 2");
        peer_thread.join().unwrap();

        assert_eq!(punched_peer.port(), sym_real_port);
        assert!(
            elapsed < Duration::from_millis(1_500),
            "expected immediate t=0 seq scan hit, took {elapsed:?}"
        );
    }

    #[cfg(unix)]
    fn open_fd_count() -> Option<usize> {
        let dir = if std::path::Path::new("/proc/self/fd").exists() {
            "/proc/self/fd"
        } else if std::path::Path::new("/dev/fd").exists() {
            "/dev/fd"
        } else {
            return None;
        };
        std::fs::read_dir(dir).ok().map(|entries| entries.count())
    }

    #[test]
    fn punch_udp_pair_cone_to_random_symmetric_birthday_succeeds_without_fd_leak() {
        #[cfg(unix)]
        let fd_before = open_fd_count();

        let host_sock = UdpSocket::bind("127.0.0.1:0").expect("bind host sock");
        let host_port = host_sock.local_addr().unwrap().port();
        let client_primary_port = reserve_ephemeral_udp_port();
        assert_ne!(host_port, client_primary_port);

        let session_id = "cone-vs-rand-sym-birthday";
        let session_hash = derive_session_hash(session_id);
        let fake_quic_initial = b"\xc0\x00\x00\x00\x01birthday-aux-quic-initial".to_vec();
        let expected_quic = fake_quic_initial.clone();

        let host_thread = thread::spawn(move || {
            host_sock
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 256];
            let mut chosen_aux_addr: Option<SocketAddr> = None;

            // 模拟对端主端口被对称 NAT 映射改变而无法直通，强制选出一个辅助生日 socket 完成握手
            for _ in 0..128 {
                let (n, from) = host_sock.recv_from(&mut buf).expect("recv client probe");
                let Some(pkt) = decode_punch_packet(&buf[..n]) else {
                    continue;
                };
                if pkt.session_hash != session_hash || pkt.role != P2pRole::Client {
                    continue;
                }
                if from.port() == client_primary_port {
                    continue;
                }
                chosen_aux_addr = Some(from);
                break;
            }
            let aux_addr = chosen_aux_addr.expect("must receive probe from an aux birthday socket");

            let host_probe = encode_punch_packet(&PunchPacket {
                version: PUNCH_VERSION,
                role: P2pRole::Host,
                ack: false,
                session_hash,
                nonce: [4u8; 6],
            });
            host_sock.send_to(&host_probe, aux_addr).unwrap();

            // 等待辅助 socket 回复 RCP2 Ack，再发合成 QUIC Initial（Ack 已覆盖或由 peek_from 保留）
            let mut got_ack = false;
            for _ in 0..64 {
                let (n, from) = host_sock.recv_from(&mut buf).expect("recv aux ack");
                if from == aux_addr {
                    if let Some(pkt) = decode_punch_packet(&buf[..n]) {
                        if pkt.ack
                            && pkt.role == P2pRole::Client
                            && pkt.session_hash == session_hash
                        {
                            got_ack = true;
                            break;
                        }
                    }
                }
            }
            assert!(got_ack, "winning aux socket must reply with RCP2 Ack");
            host_sock.send_to(&fake_quic_initial, aux_addr).unwrap();
            aux_addr.port()
        });

        let client_cand = P2pCandidates {
            session_id: session_id.to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_port}")),
            local_udp_port: Some(client_primary_port),
            self_nat_type: NatType::ApdmRandom,
            peer_nat_type: NatType::ConeUnverified,
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        let (client_sock, punched_peer, elapsed) = punch_udp_pair(
            P2pRole::Client,
            &client_cand,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel,
        )
        .expect("Random Symmetric -> Cone birthday aux socket must succeed");

        let winning_aux_port = host_thread.join().unwrap();
        assert_eq!(punched_peer.port(), host_port);
        assert_eq!(client_sock.local_addr().unwrap().port(), winning_aux_port);
        assert_ne!(winning_aux_port, client_primary_port);
        assert!(
            elapsed < Duration::from_millis(1_500),
            "birthday aux punch must start at t=0 (Wave 1) and finish promptly, took {elapsed:?}"
        );

        // 主 socket 及其端口租约必须在 aux 胜出后立即释放
        assert!(
            LocalUdpPortLease::try_acquire(client_primary_port).is_some(),
            "primary local_udp_port lease must be released when aux socket wins"
        );
        assert!(
            UdpSocket::bind(("127.0.0.1", client_primary_port)).is_ok(),
            "primary socket must be dropped without FD leak"
        );

        // 校验胜出辅助 socket 同样通过 peek_from 完好保留了 QUIC Initial
        client_sock.set_nonblocking(false).unwrap();
        client_sock
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut verify_buf = [0u8; 256];
        let (n, from) = client_sock
            .recv_from(&mut verify_buf)
            .expect("winning aux socket must preserve QUIC Initial via peek_from");
        assert_eq!(from.port(), host_port);
        assert_eq!(&verify_buf[..n], expected_quic.as_slice());

        drop(client_sock);
        #[cfg(unix)]
        if let (Some(before), Some(after)) = (fd_before, open_fd_count()) {
            assert_eq!(
                after, before,
                "all aux and primary sockets must be closed without FD leak (before={before}, after={after})"
            );
        }
    }

    #[test]
    fn phase2_predicted_port_ignores_stray_non_rcp2_datagram_without_hijack() {
        let stray_sock = UdpSocket::bind("127.0.0.1:0").expect("bind stray sock");
        let stray_port = stray_sock.local_addr().unwrap().port();
        assert!(stray_port > 100);
        let stun_port = stray_port - 3;
        let host_port = reserve_ephemeral_udp_port();

        let stray_thread = thread::spawn(move || {
            stray_sock
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = [0u8; 256];
            if let Ok((_n, from_addr)) = stray_sock.recv_from(&mut buf) {
                // 回一个非 RCP2 杂散 UDP 包，绝不能让 Host 在未确认 RCP2 前误判打洞成功
                let _ = stray_sock.send_to(b"NOT_RCP2_STRAY_DNS_REPLY", from_addr);
            }
        });

        let host_cand = P2pCandidates {
            session_id: "phase2-stray-non-rcp2".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{stun_port}")),
            local_udp_port: Some(host_port),
            self_nat_type: NatType::ConeVerified,
            peer_nat_type: NatType::ApdmSeq,
            peer_nat_port_delta: Some(3),
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        let err = punch_udp_pair(
            P2pRole::Host,
            &host_cand,
            Duration::from_millis(550),
            &cancel,
        )
        .unwrap_err();
        stray_thread.join().unwrap();
        assert!(
            err.contains("超时"),
            "Host must ignore non-RCP2 packet from Phase 2 predicted port and time out, got: {err}"
        );
    }

    #[test]
    fn should_use_aux_sockets_only_on_symmetric_to_cone_or_unknown() {
        assert!(!should_use_aux_sockets(
            NatType::ConeVerified,
            NatType::ApdmRandom
        ));
        assert!(!should_use_aux_sockets(
            NatType::ConeUnverified,
            NatType::ApdmSeq
        ));
        assert!(!should_use_aux_sockets(
            NatType::ConeVerified,
            NatType::ConeVerified
        ));
        assert!(!should_use_aux_sockets(
            NatType::ConeUnverified,
            NatType::Unknown
        ));
        assert!(!should_use_aux_sockets(
            NatType::Unknown,
            NatType::ConeVerified
        ));
        assert!(!should_use_aux_sockets(
            NatType::ApdmRandom,
            NatType::ApdmRandom
        ));
        assert!(!should_use_aux_sockets(NatType::AdmSeq, NatType::ApdmSeq));

        assert!(should_use_aux_sockets(
            NatType::ApdmRandom,
            NatType::ConeVerified
        ));
        assert!(should_use_aux_sockets(NatType::AdmRandom, NatType::Unknown));
        assert!(should_use_aux_sockets(
            NatType::ApdmSeq,
            NatType::ConeUnverified
        ));
        assert!(should_use_aux_sockets(NatType::AdmSeq, NatType::Unknown));
    }

    #[test]
    fn has_global_v6_or_explicit_lan_rejects_link_local_and_ula_v6() {
        let empty = P2pCandidates::default();
        assert!(!has_global_v6_or_explicit_lan(
            &empty,
            &[
                "[fe80::1]:50000".parse().unwrap(),
                "[fc00::1]:50000".parse().unwrap(),
                "[fd12:3456::1]:50000".parse().unwrap(),
                "198.51.100.10:50000".parse().unwrap(),
            ]
        ));
        assert!(has_global_v6_or_explicit_lan(
            &empty,
            &["[2001:db8::1]:50000".parse().unwrap()]
        ));
        let with_lan = P2pCandidates {
            peer_lan_addrs: vec!["192.168.1.20:50000".to_string()],
            ..Default::default()
        };
        assert!(has_global_v6_or_explicit_lan(&with_lan, &[]));
    }

    #[test]
    fn filter_cross_site_lan_addrs_filters_private_on_diff_public_ip_and_preserves_otherwise() {
        let lan = vec![
            "192.168.1.20:50000".to_string(),
            "10.0.0.8:50001".to_string(),
            "172.16.1.9:50002".to_string(),
            "100.64.1.2:50003".to_string(),
            "169.254.1.2:50004".to_string(),
            "127.0.0.1:50005".to_string(),
            "[fe80::1]:50006".to_string(),
            "[fd00::1]:50007".to_string(),
            "203.0.113.45:51234".to_string(),     // UPnP 公网 IPv4
            "[240e:3b0:1::10]:51235".to_string(), // 全球单播 IPv6
        ];

        // 公网 IPv4 不同 -> 剔除 RFC 1918 / CGNAT / 链路本地 / 回环 / 非全球 IPv6，保留 UPnP 公网 IPv4 与全球 IPv6
        let filtered =
            filter_cross_site_lan_addrs(&lan, &["198.51.100.22:60000"], &["203.0.113.9:60001"]);
        assert_eq!(
            filtered,
            vec![
                "203.0.113.45:51234".to_string(),
                "[240e:3b0:1::10]:51235".to_string(),
            ]
        );

        // 同公网 IP -> 原样保留 RFC 1918
        assert_eq!(
            filter_cross_site_lan_addrs(&lan, &["198.51.100.22:60000"], &["198.51.100.22:60001"],),
            lan
        );

        // 跨族 (v6, v4) -> 原样保留 RFC 1918
        assert_eq!(
            filter_cross_site_lan_addrs(&lan, &["[240e:3b0:1::20]:60000"], &["203.0.113.9:60001"],),
            lan
        );
    }

    #[test]
    fn rcp2_v2_packet_encode_decode_hmac_verify_and_tamper_rejection() {
        let secret_hex = "0123456789abcdef0123456789abcdef";
        let secret = parse_punch_secret(Some(secret_hex)).expect("valid secret hex");
        assert_eq!(
            parse_punch_secret(Some("  0123456789ABCDEF0123456789ABCDEF  ")),
            Some(secret)
        );
        assert!(parse_punch_secret(None).is_none());
        assert!(parse_punch_secret(Some("")).is_none());
        assert!(parse_punch_secret(Some("012345")).is_none());
        assert!(parse_punch_secret(Some("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")).is_none());

        let sh = derive_session_hash_v2("sess-rcp2-v2");
        assert_eq!(sh, derive_session_hash_v2("sess-rcp2-v2"));
        assert_ne!(sh, derive_session_hash_v2("sess-rcp2-v2-other"));

        let sender_nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let echo_nonce = [9, 10, 11, 12, 13, 14, 15, 16];
        let wire =
            encode_punch_packet_v2(P2pRole::Client, true, sh, sender_nonce, echo_nonce, &secret);
        assert_eq!(wire.len(), PUNCH_V2_PACKET_LEN);
        assert_eq!(&wire[0..4], PUNCH_MAGIC);
        assert_eq!(wire[4], PUNCH_VERSION_V2);
        assert_eq!(wire[5], P2pRole::Client as u8);
        assert_eq!(wire[6], PUNCH_V2_FLAG_ACK);
        assert_eq!(wire[7], 0);
        assert_eq!(&wire[8..16], &sh);
        assert_eq!(&wire[16..24], &sender_nonce);
        assert_eq!(&wire[24..32], &echo_nonce);

        let decoded = decode_and_verify_punch_packet_v2(&wire, &secret).expect("valid v2");
        assert_eq!(decoded.version, PUNCH_VERSION_V2);
        assert_eq!(decoded.role, P2pRole::Client);
        assert_eq!(decoded.flags, PUNCH_V2_FLAG_ACK);
        assert_eq!(decoded.reserved, 0);
        assert_eq!(decoded.session_hash, sh);
        assert_eq!(decoded.sender_nonce, sender_nonce);
        assert_eq!(decoded.echo_nonce, echo_nonce);

        // 错误密钥 / 篡改载荷 / 篡改 MAC / 非法字段均拒绝
        let wrong_secret = [0xAAu8; 16];
        assert!(decode_and_verify_punch_packet_v2(&wire, &wrong_secret).is_none());

        let mut tampered_body = wire;
        tampered_body[16] ^= 0x01;
        assert!(decode_and_verify_punch_packet_v2(&tampered_body, &secret).is_none());

        let mut tampered_mac = wire;
        tampered_mac[47] ^= 0x80;
        assert!(decode_and_verify_punch_packet_v2(&tampered_mac, &secret).is_none());

        let mut bad_reserved = wire;
        bad_reserved[7] = 1;
        assert!(decode_and_verify_punch_packet_v2(&bad_reserved, &secret).is_none());

        let mut bad_flags = wire;
        bad_flags[6] = 0x02;
        assert!(decode_and_verify_punch_packet_v2(&bad_flags, &secret).is_none());

        assert!(decode_and_verify_punch_packet_v2(&wire[..47], &secret).is_none());
    }

    #[test]
    fn rcp2_v2_auth_failures_silent_drop_echo_nonce_and_1x_rate_limit() {
        struct CaptureSocket {
            peek_results: std::collections::VecDeque<io::Result<(Vec<u8>, SocketAddr)>>,
            recv_results: std::collections::VecDeque<io::Result<(Vec<u8>, SocketAddr)>>,
            sent_packets: Vec<(Vec<u8>, SocketAddr)>,
        }

        impl PunchSocketOps for CaptureSocket {
            fn peek_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                match self.peek_results.pop_front() {
                    Some(Ok((pkt, addr))) => {
                        buf[..pkt.len()].copy_from_slice(&pkt);
                        Ok((pkt.len(), addr))
                    }
                    Some(Err(e)) => Err(e),
                    None => Err(io::Error::from(ErrorKind::WouldBlock)),
                }
            }

            fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                match self.recv_results.pop_front() {
                    Some(Ok((pkt, addr))) => {
                        buf[..pkt.len()].copy_from_slice(&pkt);
                        Ok((pkt.len(), addr))
                    }
                    Some(Err(e)) => Err(e),
                    None => Err(io::Error::from(ErrorKind::WouldBlock)),
                }
            }

            fn send_to(&mut self, buf: &[u8], addr: SocketAddr) {
                self.sent_packets.push((buf.to_vec(), addr));
            }
        }

        let secret = [0x33u8; 16];
        let wrong_secret = [0x44u8; 16];
        let sh = derive_session_hash_v2("sess-v2-auth");
        let other_sh = derive_session_hash_v2("sess-v2-other");
        let local_nonce = [0x11u8; 8];
        let peer_nonce = [0x22u8; 8];
        let peer_addr: SocketAddr = "198.51.100.44:50000".parse().unwrap();
        let target_canons: HashSet<SocketAddr> = [peer_addr].into_iter().collect();

        let mut auth = PunchAuthMode::V2 {
            role: P2pRole::Host,
            secret,
            session_hash: sh,
            local_sender_nonce: local_nonce,
            probe_pkt: encode_punch_packet_v2(
                P2pRole::Host,
                false,
                sh,
                local_nonce,
                [0u8; 8],
                &secret,
            ),
            rate_limiter: AckRateLimiter::default(),
        };

        // 1) 伪造 MAC、错误 session_hash、同侧 role、错误 echo_nonce 的 Ack 均必须静默丢弃且零回包，
        //    即使来自 target_canons 也不得误判为 QUIC Initial Ready。
        let bad_mac = encode_punch_packet_v2(
            P2pRole::Client,
            false,
            sh,
            peer_nonce,
            [0u8; 8],
            &wrong_secret,
        );
        let bad_sh = encode_punch_packet_v2(
            P2pRole::Client,
            false,
            other_sh,
            peer_nonce,
            [0u8; 8],
            &secret,
        );
        let same_role =
            encode_punch_packet_v2(P2pRole::Host, false, sh, peer_nonce, [0u8; 8], &secret);
        let wrong_echo_ack =
            encode_punch_packet_v2(P2pRole::Client, true, sh, peer_nonce, [0x99u8; 8], &secret);

        let mut recv_buf = [0u8; 128];
        let mut confirmed_peer = None;
        let mut peer_sender_nonce = None;
        let mut sock_bad = CaptureSocket {
            peek_results: std::collections::VecDeque::from([
                Ok((bad_mac.to_vec(), peer_addr)),
                Ok((bad_sh.to_vec(), peer_addr)),
                Ok((same_role.to_vec(), peer_addr)),
                Ok((wrong_echo_ack.to_vec(), peer_addr)),
            ]),
            recv_results: std::collections::VecDeque::from([
                Ok((bad_mac.to_vec(), peer_addr)),
                Ok((bad_sh.to_vec(), peer_addr)),
                Ok((same_role.to_vec(), peer_addr)),
                Ok((wrong_echo_ack.to_vec(), peer_addr)),
            ]),
            sent_packets: Vec::new(),
        };
        let out_bad = drain_punch_rx(
            &mut recv_buf,
            false,
            &mut auth,
            P2pRole::Client,
            P2pRole::Host,
            &target_canons,
            &mut confirmed_peer,
            &mut peer_sender_nonce,
            &mut sock_bad,
        )
        .unwrap();
        assert_eq!(out_bad, DrainOutcome::Continue);
        assert!(confirmed_peer.is_none());
        assert!(
            sock_bad.sent_packets.is_empty(),
            "invalid packets must yield zero replies"
        );

        // 2) 合法 Probe 连发 5 次：第 1 次严格回复 1 个等长 48B Ack（1.0x 放大系数），
        //    其余在限频窗口内静默限频不回包。
        let valid_probe =
            encode_punch_packet_v2(P2pRole::Client, false, sh, peer_nonce, [0u8; 8], &secret);
        let mut sock_rate = CaptureSocket {
            peek_results: (0..5)
                .map(|_| Ok((valid_probe.to_vec(), peer_addr)))
                .collect(),
            recv_results: (0..5)
                .map(|_| Ok((valid_probe.to_vec(), peer_addr)))
                .collect(),
            sent_packets: Vec::new(),
        };
        let out_probe = drain_punch_rx(
            &mut recv_buf,
            false,
            &mut auth,
            P2pRole::Client,
            P2pRole::Host,
            &target_canons,
            &mut confirmed_peer,
            &mut peer_sender_nonce,
            &mut sock_rate,
        )
        .unwrap();
        assert_eq!(out_probe, DrainOutcome::Continue);
        assert_eq!(confirmed_peer, Some(peer_addr));
        assert_eq!(peer_sender_nonce, Some(peer_nonce));
        assert_eq!(
            sock_rate.sent_packets.len(),
            1,
            "must enforce strict 1.0x + per-IP rate limit"
        );
        let (ack_wire, ack_dst) = &sock_rate.sent_packets[0];
        assert_eq!(ack_wire.len(), PUNCH_V2_PACKET_LEN);
        assert_eq!(*ack_dst, peer_addr);
        let ack_decoded = decode_and_verify_punch_packet_v2(ack_wire, &secret).unwrap();
        assert_eq!(ack_decoded.flags, PUNCH_V2_FLAG_ACK);
        assert_eq!(ack_decoded.echo_nonce, peer_nonce);

        // 3) 超过限频窗口后收到携带正确 echo_nonce == local_nonce 的 Ack -> Ready
        thread::sleep(ACK_RATE_MIN_INTERVAL + Duration::from_millis(5));
        let valid_ack =
            encode_punch_packet_v2(P2pRole::Client, true, sh, peer_nonce, local_nonce, &secret);
        let mut sock_ok = CaptureSocket {
            peek_results: std::collections::VecDeque::from([Ok((valid_ack.to_vec(), peer_addr))]),
            recv_results: std::collections::VecDeque::from([Ok((valid_ack.to_vec(), peer_addr))]),
            sent_packets: Vec::new(),
        };
        let out_ready = drain_punch_rx(
            &mut recv_buf,
            false,
            &mut auth,
            P2pRole::Client,
            P2pRole::Host,
            &target_canons,
            &mut confirmed_peer,
            &mut peer_sender_nonce,
            &mut sock_ok,
        )
        .unwrap();
        assert_eq!(out_ready, DrainOutcome::Ready(peer_addr));
        assert_eq!(sock_ok.sent_packets.len(), 1);
    }

    #[test]
    fn rcp2_v2_punch_udp_pair_localhost_and_v1_fallback_on_invalid_secret() {
        let host_port = reserve_ephemeral_udp_port();
        let client_port = reserve_ephemeral_udp_port();
        assert_ne!(host_port, client_port);

        let secret = "0123456789abcdef0123456789abcdef".to_string();
        let host_cand = P2pCandidates {
            session_id: "rcp2-v2-e2e".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{client_port}")),
            local_udp_port: Some(host_port),
            punch_secret: Some(secret.clone()),
            ..Default::default()
        };
        let client_cand = P2pCandidates {
            session_id: "rcp2-v2-e2e".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_port}")),
            local_udp_port: Some(client_port),
            punch_secret: Some(secret),
            ..Default::default()
        };

        let cancel_h = Arc::new(AtomicBool::new(false));
        let cancel_c = Arc::clone(&cancel_h);
        let h_jh = thread::spawn(move || {
            punch_udp_pair(P2pRole::Host, &host_cand, DEFAULT_PUNCH_TIMEOUT, &cancel_h)
        });
        let (c_sock, c_peer, _) = punch_udp_pair(
            P2pRole::Client,
            &client_cand,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel_c,
        )
        .expect("RCP2 v2 client punch must succeed");
        let (h_sock, h_peer, _) = h_jh
            .join()
            .unwrap()
            .expect("RCP2 v2 host punch must succeed");
        assert_eq!(c_peer.port(), host_port);
        assert_eq!(h_peer.port(), client_port);
        drop(c_sock);
        drop(h_sock);

        // punch_secret 非法时平滑回退 RCP2 v1 (29B) 并成功打洞
        let host_port2 = reserve_ephemeral_udp_port();
        let client_port2 = reserve_ephemeral_udp_port();
        let host_fallback = P2pCandidates {
            session_id: "rcp2-v1-fallback".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{client_port2}")),
            local_udp_port: Some(host_port2),
            punch_secret: Some("invalid-not-32-hex".to_string()),
            ..Default::default()
        };
        let client_fallback = P2pCandidates {
            session_id: "rcp2-v1-fallback".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_port2}")),
            local_udp_port: Some(client_port2),
            punch_secret: None,
            ..Default::default()
        };
        let cancel2 = Arc::new(AtomicBool::new(false));
        let cancel2_c = Arc::clone(&cancel2);
        let h_jh2 = thread::spawn(move || {
            punch_udp_pair(
                P2pRole::Host,
                &host_fallback,
                DEFAULT_PUNCH_TIMEOUT,
                &cancel2,
            )
        });
        punch_udp_pair(
            P2pRole::Client,
            &client_fallback,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel2_c,
        )
        .expect("invalid/missing punch_secret must smoothly fallback to v1");
        h_jh2
            .join()
            .unwrap()
            .expect("host v1 fallback must succeed");
    }

    #[test]
    fn build_predicted_targets_prioritizes_peer_nat_port_range() {
        let candidates = P2pCandidates {
            session_id: "range-hint-pred".to_string(),
            peer_public_addr: Some("198.51.100.20:50005".to_string()),
            peer_nat_type: NatType::ApdmRandom,
            peer_nat_port_range: Some(PortRangeHint::Custom {
                min: 50000,
                max: 50031,
            }),
            ..Default::default()
        };
        let predicted = build_predicted_targets(&candidates, &[], false);
        assert_eq!(predicted.len(), 512);
        assert!(predicted[..31]
            .iter()
            .all(|a| (50000..=50031).contains(&a.port())));
    }

    #[test]
    fn start_after_delay_clamps_to_500ms_and_aborts_immediately_on_cancel() {
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_bg = Arc::clone(&cancel);
        let jh = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            cancel_bg.store(true, Ordering::Release);
        });
        let started = Instant::now();
        let res = wait_start_after_delay(
            Some(10_000),
            started + Duration::from_secs(5),
            cancel.as_ref(),
        );
        jh.join().unwrap();
        assert!(res.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "cancel must interrupt start_after_ms quickly, took {:?}",
            started.elapsed()
        );

        let cancel_ok = AtomicBool::new(false);
        let t0 = Instant::now();
        wait_start_after_delay(Some(5_000), t0 + Duration::from_secs(5), &cancel_ok).unwrap();
        let waited = t0.elapsed();
        assert!(
            waited >= Duration::from_millis(450) && waited < Duration::from_millis(750),
            "start_after_ms=5000 must clamp to 500ms, waited {waited:?}"
        );
    }

    #[test]
    fn udp_blocked_fast_fails_unless_ipv6_or_lan_present() {
        let port = reserve_ephemeral_udp_port();
        let blocked = P2pCandidates {
            session_id: "udp-blocked-fast-fail".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{port}")),
            self_nat_type: NatType::UdpBlocked,
            peer_nat_type: NatType::ConeVerified,
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        let t0 = Instant::now();
        let err = punch_udp_pair(P2pRole::Client, &blocked, Duration::from_secs(3), &cancel)
            .expect_err("UdpBlocked without IPv6/LAN must fast-fail");
        assert!(err.contains("受阻"), "unexpected error: {err}");
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "UdpBlocked fast-fail must take ~0ms, took {:?}",
            t0.elapsed()
        );

        // 带显式 LAN 候选时不得 fast-fail，应直接命中 LAN
        let host_port = reserve_ephemeral_udp_port();
        let client_port = reserve_ephemeral_udp_port();
        let host_lan = P2pCandidates {
            session_id: "udp-blocked-with-lan".to_string(),
            peer_lan_addrs: vec![format!("127.0.0.1:{client_port}")],
            local_udp_port: Some(host_port),
            self_nat_type: NatType::UdpBlocked,
            peer_nat_type: NatType::ConeVerified,
            ..Default::default()
        };
        let client_lan = P2pCandidates {
            session_id: "udp-blocked-with-lan".to_string(),
            peer_lan_addrs: vec![format!("127.0.0.1:{host_port}")],
            local_udp_port: Some(client_port),
            self_nat_type: NatType::ConeVerified,
            peer_nat_type: NatType::UdpBlocked,
            ..Default::default()
        };
        let cancel2 = Arc::new(AtomicBool::new(false));
        let cancel2_c = Arc::clone(&cancel2);
        let h_jh = thread::spawn(move || {
            punch_udp_pair(P2pRole::Host, &host_lan, DEFAULT_PUNCH_TIMEOUT, &cancel2)
        });
        punch_udp_pair(
            P2pRole::Client,
            &client_lan,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel2_c,
        )
        .expect("UdpBlocked with usable explicit LAN must punch directly");
        h_jh.join().unwrap().unwrap();
    }

    #[test]
    fn select_punch_strategy_matrix_matches_item3_design() {
        let base_target: SocketAddr = "198.51.100.10:40000".parse().unwrap();
        let targets = vec![base_target];

        // 1. ConeVerified <-> ConeVerified => DirectOnly
        let c1 = P2pCandidates {
            peer_public_addr: Some(base_target.to_string()),
            self_nat_type: NatType::ConeVerified,
            peer_nat_type: NatType::ConeVerified,
            ..Default::default()
        };
        assert!(matches!(
            select_punch_strategy(P2pRole::Host, &c1, &targets, &targets, false),
            PunchStrategy::DirectOnly
        ));

        // 2. AdmSeq <-> AdmSeq => MainScanImmediate (0 aux)
        let c2 = P2pCandidates {
            peer_public_addr: Some(base_target.to_string()),
            self_nat_type: NatType::AdmSeq,
            peer_nat_type: NatType::AdmSeq,
            peer_nat_port_delta: Some(2),
            ..Default::default()
        };
        match select_punch_strategy(P2pRole::Host, &c2, &targets, &targets, false) {
            PunchStrategy::MainScanImmediate { scan_targets } => {
                assert!(!scan_targets.is_empty());
            }
            other => panic!("expected MainScanImmediate, got {other:?}"),
        }

        // 3. Cone* <-> ApdmSeq => Cone scans at t=0; Sym spawns 8 aux
        let c3_cone = P2pCandidates {
            peer_public_addr: Some(base_target.to_string()),
            self_nat_type: NatType::ConeVerified,
            peer_nat_type: NatType::ApdmSeq,
            peer_nat_port_delta: Some(3),
            ..Default::default()
        };
        assert!(matches!(
            select_punch_strategy(P2pRole::Host, &c3_cone, &targets, &targets, false),
            PunchStrategy::MainScanImmediate { .. }
        ));
        let c3_sym = P2pCandidates {
            peer_public_addr: Some(base_target.to_string()),
            self_nat_type: NatType::ApdmSeq,
            peer_nat_type: NatType::ConeUnverified,
            ..Default::default()
        };
        match select_punch_strategy(P2pRole::Client, &c3_sym, &targets, &targets, false) {
            PunchStrategy::AuxPersistent {
                aux_count,
                scan_targets,
                ..
            } => {
                assert_eq!(aux_count, AUX_SEQ_TO_CONE_COUNT);
                assert!(scan_targets.is_empty());
            }
            other => panic!("expected AuxPersistent(8), got {other:?}"),
        }

        // 4. ApdmSeq <-> ApdmSeq => DirectedRendezvous (delta=1 -> 48 aux, delta=3 -> 24 aux x 3 targets)
        let c4_d1 = P2pCandidates {
            peer_public_addr: Some(base_target.to_string()),
            self_nat_type: NatType::ApdmSeq,
            peer_nat_type: NatType::ApdmSeq,
            peer_nat_port_delta: Some(1),
            ..Default::default()
        };
        match select_punch_strategy(P2pRole::Host, &c4_d1, &targets, &targets, false) {
            PunchStrategy::DirectedRendezvous {
                aux_count,
                aux_targets,
            } => {
                assert_eq!(aux_count, AUX_APDM_SEQ_DELTA1_COUNT);
                assert_eq!(aux_targets.len(), 1);
                assert_eq!(aux_targets[0].port(), 40024);
            }
            other => panic!("expected DirectedRendezvous(48), got {other:?}"),
        }
        let c4_d3 = P2pCandidates {
            peer_public_addr: Some(base_target.to_string()),
            self_nat_type: NatType::ApdmSeq,
            peer_nat_type: NatType::ApdmSeq,
            peer_nat_port_delta: Some(3),
            ..Default::default()
        };
        match select_punch_strategy(P2pRole::Host, &c4_d3, &targets, &targets, false) {
            PunchStrategy::DirectedRendezvous {
                aux_count,
                aux_targets,
            } => {
                assert_eq!(aux_count, AUX_APDM_SEQ_DELTA2_4_COUNT);
                assert_eq!(aux_targets.len(), 3);
                assert_eq!(
                    aux_targets.iter().map(SocketAddr::port).collect::<Vec<_>>(),
                    vec![40072, 40073, 40074]
                );
            }
            other => panic!("expected DirectedRendezvous(24, 3 targets), got {other:?}"),
        }

        // 5. Cone* <-> ApdmRandom => TwoWaveConeScan / TwoWaveBirthdayAux
        let c5_cone = P2pCandidates {
            peer_public_addr: Some(base_target.to_string()),
            self_nat_type: NatType::ConeVerified,
            peer_nat_type: NatType::ApdmRandom,
            peer_nat_port_range: Some(PortRangeHint::LinuxEphemeral),
            ..Default::default()
        };
        match select_punch_strategy(P2pRole::Host, &c5_cone, &targets, &targets, false) {
            PunchStrategy::TwoWaveConeScan {
                wave1_targets,
                wave2_targets,
            } => {
                assert_eq!(wave1_targets.len(), CONE_SCAN_BUDGET_PER_WAVE);
                assert_eq!(wave2_targets.len(), CONE_SCAN_BUDGET_PER_WAVE);
            }
            other => panic!("expected TwoWaveConeScan, got {other:?}"),
        }
        let c5_sym = P2pCandidates {
            peer_public_addr: Some(base_target.to_string()),
            self_nat_type: NatType::ApdmRandom,
            peer_nat_type: NatType::ConeVerified,
            ..Default::default()
        };
        match select_punch_strategy(P2pRole::Client, &c5_sym, &targets, &targets, false) {
            PunchStrategy::TwoWaveBirthdayAux { aux_count } => {
                assert_eq!(aux_count, MAX_AUX_SOCKETS_HARD_CAP);
            }
            other => panic!("expected TwoWaveBirthdayAux(96), got {other:?}"),
        }

        // 6. ConeUnverified <-> ConeUnverified => ConeUnverifiedProgressive
        let c6 = P2pCandidates {
            peer_public_addr: Some(base_target.to_string()),
            self_nat_type: NatType::ConeUnverified,
            peer_nat_type: NatType::ConeUnverified,
            ..Default::default()
        };
        match select_punch_strategy(P2pRole::Host, &c6, &targets, &targets, false) {
            PunchStrategy::ConeUnverifiedProgressive {
                narrow_targets,
                wide_targets,
                ..
            } => {
                assert_eq!(narrow_targets.len(), 64);
                assert_eq!(wide_targets.len(), CONE_SCAN_BUDGET_PER_WAVE);
            }
            other => panic!("expected ConeUnverifiedProgressive, got {other:?}"),
        }
    }

    #[test]
    fn directed_rendezvous_apdm_seq_succeeds_with_independent_aux_nonces() {
        let host_secret = "00112233445566778899aabbccddeeff";
        let secret_bytes = parse_punch_secret(Some(host_secret)).unwrap();
        let session_hash = derive_session_hash_v2("directed-apdm-seq");

        let host_rendezvous = UdpSocket::bind("127.0.0.1:0").unwrap();
        host_rendezvous.set_nonblocking(true).unwrap();
        let host_target_port = host_rendezvous.local_addr().unwrap().port();
        // 选择 peer_last = host_target_port - 24（delta=+1 时定向到 host_target_port）
        assert!(host_target_port > 1024);
        let peer_last_for_client = host_target_port - 24;

        let client_primary_port = reserve_ephemeral_udp_port();
        let client_cand = P2pCandidates {
            session_id: "directed-apdm-seq".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{peer_last_for_client}")),
            local_udp_port: Some(client_primary_port),
            self_nat_type: NatType::ApdmSeq,
            peer_nat_type: NatType::ApdmSeq,
            peer_nat_port_delta: Some(1),
            punch_secret: Some(host_secret.to_string()),
            ..Default::default()
        };

        let host_thread = thread::spawn(move || {
            let mut buf = [0u8; 256];
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut seen_nonces = HashSet::new();
            let host_nonce = [0x99u8; 8];
            let mut ack_pkt = None;
            let mut reply_target = None;
            while Instant::now() < deadline {
                match host_rendezvous.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        if let Some(pkt) =
                            decode_and_verify_punch_packet_v2(&buf[..len], &secret_bytes).filter(
                                |p| p.session_hash == session_hash && p.role == P2pRole::Client,
                            )
                        {
                            seen_nonces.insert(pkt.sender_nonce);
                            if ack_pkt.is_none() {
                                reply_target = Some(src);
                                ack_pkt = Some(encode_punch_packet_v2(
                                    P2pRole::Host,
                                    true,
                                    session_hash,
                                    host_nonce,
                                    pkt.sender_nonce,
                                    &secret_bytes,
                                ));
                            }
                            if seen_nonces.len() >= 2 && ack_pkt.is_some() {
                                break;
                            }
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) => panic!("host_rendezvous recv error: {err}"),
                }
            }
            let target = reply_target.expect("must receive RCP2 v2 Probe from client aux socket");
            let ack = ack_pkt.unwrap();
            let _ = host_rendezvous.send_to(&ack, target);
            // 再发一个 Probe 等待客户端回 Ack
            let probe = encode_punch_packet_v2(
                P2pRole::Host,
                false,
                session_hash,
                host_nonce,
                [0u8; 8],
                &secret_bytes,
            );
            let _ = host_rendezvous.send_to(&probe, target);
            (seen_nonces.len(), target.port())
        });

        let cancel = AtomicBool::new(false);
        let (won_sock, peer_addr, _elapsed) = punch_udp_pair(
            P2pRole::Client,
            &client_cand,
            DEFAULT_PUNCH_TIMEOUT,
            &cancel,
        )
        .expect("ApdmSeq directed rendezvous must complete RCP2 v2 handshake");
        let (nonce_count, won_port) = host_thread.join().unwrap();
        assert_eq!(peer_addr.port(), host_target_port);
        assert_eq!(won_sock.local_addr().unwrap().port(), won_port);
        assert!(
            nonce_count >= 2,
            "multiple aux sockets must carry distinct sender_nonce values, saw {nonce_count}"
        );
    }

    #[test]
    fn two_wave_birthday_aux_drops_wave1_before_wave2_and_caps_at_96() {
        let cancel = AtomicBool::new(false);
        let capped = spawn_aux_punch_sockets(
            200,
            false,
            true,
            P2pRole::Client,
            "cap-check",
            None,
            &cancel,
        );
        assert_eq!(capped.len(), MAX_AUX_SOCKETS_HARD_CAP);
        drop(capped);

        // 模拟 Wave 2 才开始监听的 Cone 对端（在 Wave 1 期间拒绝/丢弃，等待 600ms 后才绑定并收发）
        let host_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let host_port = host_sock.local_addr().unwrap().port();
        drop(host_sock); // 先释放端口，等 Wave 2 窗口再监听

        let client_port = reserve_ephemeral_udp_port();
        let secret_hex = "ffeeddccbbaa99887766554433221100";
        let secret_bytes = parse_punch_secret(Some(secret_hex)).unwrap();
        let session_hash = derive_session_hash_v2("two-wave-rolling");
        let client_cand = P2pCandidates {
            session_id: "two-wave-rolling".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_port}")),
            local_udp_port: Some(client_port),
            self_nat_type: NatType::ApdmRandom,
            peer_nat_type: NatType::ConeVerified,
            punch_secret: Some(secret_hex.to_string()),
            ..Default::default()
        };

        let host_jh = thread::spawn(move || {
            // 等待进入 Wave 2 (timeout=1.4s -> wave2_at=700ms)
            thread::sleep(Duration::from_millis(800));
            let sock = UdpSocket::bind(("127.0.0.1", host_port)).unwrap();
            sock.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut buf = [0u8; 256];
            let host_nonce = [0x42u8; 8];
            while Instant::now() < deadline {
                match sock.recv_from(&mut buf) {
                    Ok((len, src)) if src.port() != client_port => {
                        if let Some(pkt) =
                            decode_and_verify_punch_packet_v2(&buf[..len], &secret_bytes).filter(
                                |p| p.session_hash == session_hash && p.role == P2pRole::Client,
                            )
                        {
                            let ack = encode_punch_packet_v2(
                                P2pRole::Host,
                                true,
                                session_hash,
                                host_nonce,
                                pkt.sender_nonce,
                                &secret_bytes,
                            );
                            let _ = sock.send_to(&ack, src);
                            let probe = encode_punch_packet_v2(
                                P2pRole::Host,
                                false,
                                session_hash,
                                host_nonce,
                                [0u8; 8],
                                &secret_bytes,
                            );
                            let _ = sock.send_to(&probe, src);
                            return src.port();
                        }
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) => panic!("host wave2 recv error: {err}"),
                }
            }
            panic!("host never received Wave 2 aux probe");
        });

        let cancel_run = AtomicBool::new(false);
        let (won_sock, peer, elapsed) = punch_udp_pair(
            P2pRole::Client,
            &client_cand,
            Duration::from_millis(1_400),
            &cancel_run,
        )
        .expect("Wave 2 rolling release aux punch must succeed");
        let wave2_port = host_jh.join().unwrap();
        assert_eq!(peer.port(), host_port);
        assert_eq!(won_sock.local_addr().unwrap().port(), wave2_port);
        assert!(
            elapsed >= Duration::from_millis(650),
            "must wait until Wave 2 activates, elapsed={elapsed:?}"
        );
    }

    #[test]
    fn cone_unverified_phase2a_narrow_neighborhood_hits_after_350ms() {
        let host_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        host_sock.set_nonblocking(true).unwrap();
        let host_real_port = host_sock.local_addr().unwrap().port();
        assert!(host_real_port > 1030);
        // 偏移 +7 在 ±32 窄邻域内
        let mapped_guess_port = host_real_port - 7;

        let client_primary = reserve_ephemeral_udp_port();
        let client_cand = P2pCandidates {
            session_id: "cone-unverified-p2a".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{mapped_guess_port}")),
            local_udp_port: Some(client_primary),
            self_nat_type: NatType::ConeUnverified,
            peer_nat_type: NatType::ConeUnverified,
            ..Default::default()
        };

        let session_hash = derive_session_hash("cone-unverified-p2a");
        let host_jh = thread::spawn(move || {
            let mut buf = [0u8; 256];
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match host_sock.recv_from(&mut buf) {
                    Ok((len, src)) if decode_punch_packet(&buf[..len]).is_some() => {
                        let ack = encode_punch_packet(&PunchPacket {
                            version: PUNCH_VERSION,
                            role: P2pRole::Host,
                            ack: true,
                            session_hash,
                            nonce: [0x17u8; 6],
                        });
                        let _ = host_sock.send_to(&ack, src);
                        let probe = encode_punch_packet(&PunchPacket {
                            version: PUNCH_VERSION,
                            role: P2pRole::Host,
                            ack: false,
                            session_hash,
                            nonce: [0x17u8; 6],
                        });
                        let _ = host_sock.send_to(&probe, src);
                        return src.port();
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) => panic!("host recv error: {err}"),
                }
            }
            panic!("host never received Phase 2a narrow scan packet");
        });

        let cancel = AtomicBool::new(false);
        let (sock, peer, elapsed) = punch_udp_pair(
            P2pRole::Client,
            &client_cand,
            Duration::from_secs(2),
            &cancel,
        )
        .expect("ConeUnverified Phase 2a ±32 scan must hit");
        let observed_src_port = host_jh.join().unwrap();
        assert_eq!(peer.port(), host_real_port);
        assert_eq!(sock.local_addr().unwrap().port(), client_primary);
        assert_eq!(observed_src_port, client_primary);
        assert!(
            elapsed >= Duration::from_millis(300) && elapsed < Duration::from_millis(1_500),
            "Phase 2a narrow scan must trigger after 350ms with 0 aux sockets, elapsed={elapsed:?}"
        );
    }

    #[test]
    fn happy_eyeballs_v2_global_v6_head_start_does_not_block_ipv4_fallback() {
        let host_v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        host_v4.set_nonblocking(true).unwrap();
        let host_v4_port = host_v4.local_addr().unwrap().port();
        let client_port = reserve_ephemeral_udp_port();

        // 包含不可达的全球单播 IPv6（RFC 3849 文档网段 2001:db8::99）与可达的 IPv4（127.0.0.1）
        let client_cand = P2pCandidates {
            session_id: "happy-eyeballs-v2".to_string(),
            peer_public_addr: Some(format!("127.0.0.1:{host_v4_port}")),
            peer_lan_addrs: vec![format!("[2001:db8::99]:{host_v4_port}")],
            local_udp_port: Some(client_port),
            ..Default::default()
        };
        let parsed = parse_candidate_addrs(&client_cand);
        assert_eq!(
            parsed[0],
            format!("[2001:db8::99]:{host_v4_port}")
                .parse::<SocketAddr>()
                .unwrap(),
            "global unicast IPv6 must sort before IPv4 even when peer_public_addrs is empty"
        );

        let session_hash = derive_session_hash("happy-eyeballs-v2");
        let host_jh = thread::spawn(move || {
            let mut buf = [0u8; 256];
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match host_v4.recv_from(&mut buf) {
                    Ok((len, src)) if decode_punch_packet(&buf[..len]).is_some() => {
                        let ack = encode_punch_packet(&PunchPacket {
                            version: PUNCH_VERSION,
                            role: P2pRole::Host,
                            ack: true,
                            session_hash,
                            nonce: [0x22u8; 6],
                        });
                        let _ = host_v4.send_to(&ack, src);
                        let probe = encode_punch_packet(&PunchPacket {
                            version: PUNCH_VERSION,
                            role: P2pRole::Host,
                            ack: false,
                            session_hash,
                            nonce: [0x22u8; 6],
                        });
                        let _ = host_v4.send_to(&probe, src);
                        return;
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("host_v4 recv error: {e}"),
                }
            }
            panic!("unreachable global IPv6 blocked IPv4 punching");
        });

        let cancel = AtomicBool::new(false);
        let (_sock, peer_addr, elapsed) = punch_udp_pair(
            P2pRole::Client,
            &client_cand,
            Duration::from_secs(2),
            &cancel,
        )
        .expect("IPv4 punch must succeed quickly despite blackholed/unreachable global IPv6");
        host_jh.join().unwrap();
        assert_eq!(canonicalize_socket_addr(peer_addr).port(), host_v4_port);
        assert!(
            elapsed < Duration::from_millis(500),
            "Happy Eyeballs v2 must race IPv4 after <=50ms without waiting on IPv6 timeout, elapsed={elapsed:?}"
        );
    }
}
