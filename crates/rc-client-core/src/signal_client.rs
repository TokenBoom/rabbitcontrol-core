//! 原生 TCP 定长帧信令客户端与 UDP `RCSP` 公网地址探测。
//!
//! 严格对齐 `server/docs/02-protocol-and-api.md`（**不使用 WebSocket**）：
//! - TCP 信令端口（默认 `:21116`）：`[u32 BE len (1..=65536)][UTF-8 JSON]`；
//! - UDP 探测端口（默认 `:21116`）：22 字节 `RCSP` 请求包 `[b"RCSP"][0x01][device_id 9B][nonce 8B]`；
//! - 断线指数退避重连：`1s -> 2s -> 5s -> 10s` 上限（仅当连接健康持续 `>= 30s` 且非被踢时重置退避）；
//! - 全模块 `#![deny(unsafe_code)]` 与 `#![deny(missing_docs)]`。

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use rc_net::{NetEvent, NetStats, Transport};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, TcpKeepalive, Type};

use crate::cert_manager::OwnerGrantPayload;
use crate::nat::{
    canonicalize_socket_addr, classify_nat_samples, is_global_unicast_ipv6, is_routable_public_ip,
    NatProbeSamples, NatProfile, NatType, PortRangeHint,
};
use crate::p2p::P2pQuicConnection;
use crate::server_config::{
    format_device_id, format_host_port, next_status_revision, parse_device_id_input,
    parse_server_input, ServerConfig, ServerConnectionState, ServerStatusSnapshot,
};
use crate::upnp::{map_udp_port, renew_udp_mapping, unmap_udp_port, UpnpMappingLease, UpnpStatus};

/// 单条 TCP 信令 JSON 帧的最大字节数（对齐服务端 `MAX_SIGNAL_FRAME_LEN`）。
pub const MAX_SIGNAL_FRAME_LEN: usize = 65_536;

/// UDP `RCSP` 探测包魔数。
const UDP_PROBE_MAGIC: &[u8; 4] = b"RCSP";
/// UDP `RCSP` v1 探测协议版本。
const UDP_PROTO_VERSION: u8 = 1;
/// UDP `RCSP` v2 探测协议版本（携带 16 字节认证 token，支持多出口 NAT 与双栈探测）。
const UDP_PROTO_VERSION_V2: u8 = 2;
/// UDP `RCSA` 响应包魔数。
const UDP_ANSWER_MAGIC: &[u8; 4] = b"RCSA";
/// UDP `RCSA` 响应包版本号。
const UDP_ANSWER_VERSION: u8 = 1;
/// UDP `RCSP` v1 探测包定长字节数。
pub const UDP_PROBE_LEN: usize = 22;
/// UDP `RCSP` v2 探测包定长字节数（4B magic + 1B ver + 9B device_id + 8B nonce + 16B token）。
pub const UDP_PROBE_V2_LEN: usize = 38;

/// 心跳与 UDP 探测发送周期（10 秒）。
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// 服务端失活判定阈值（`2 * 10s + 5s`）：超时无任何入站帧视为半开死链并重连。
const SERVER_ACTIVITY_TIMEOUT: Duration = Duration::from_secs(25);
/// 判定连接健康稳定、可重置退避的最短持续时长（30 秒）。
const STABLE_CONNECTION_THRESHOLD: Duration = Duration::from_secs(30);
/// 切网或主动触发快速重连后的短退避窗口（200ms）。
const FAST_RECONNECT_DELAY: Duration = Duration::from_millis(200);
/// 请求超时触发重连的冷却期（5 秒），防止并发或连续超时引发重连与 UPnP 风暴。
const TIMEOUT_RECONNECT_COOLDOWN: Duration = Duration::from_secs(5);
/// 若距上次收到服务端入站帧未超过该阈值（3 秒），判定信令链路活跃、单次请求超时不盲目切断连接。
const TIMEOUT_RECONNECT_ACTIVITY_GRACE: Duration = Duration::from_secs(3);
/// UPnP / NAT-PMP 自动端口映射租期（1800 秒）。
const UPNP_LEASE_SECS: u32 = 1800;
/// UPnP / NAT-PMP 探测、映射与续租超时上限（1500ms）。
const UPNP_MAP_TIMEOUT: Duration = Duration::from_millis(1500);
/// UPnP / NAT-PMP 长连期间异步续租周期（900 秒，租期一半）。
const UPNP_RENEW_INTERVAL: Duration = Duration::from_secs(900);
/// UPnP / NAT-PMP 尽力退租超时上限（500ms）。
const UPNP_UNMAP_TIMEOUT: Duration = Duration::from_millis(500);
/// 建连与首包注册握手超时。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 读循环空闲检查粒度（用于响应 `stop()`、心跳、失活超时并最小化 TLS 写端等待）。
const READ_POLL_TIMEOUT: Duration = Duration::from_millis(15);
/// 已读到半帧后允许补齐整帧的上限时间。
const PARTIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
/// 断线重连退避序列（1s -> 2s -> 5s -> 10s 上限）。
const RECONNECT_BACKOFFS: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
];
/// 入站中继队列最大容量（满载丢最旧，防止内存增长）。
const INCOMING_QUEUE_CAP: usize = 64;
/// 状态快照通知队列最大容量（满载丢最旧）。
const STATUS_QUEUE_CAP: usize = 32;
/// 同账号设备状态变更事件队列最大容量（满载丢最旧）。
const DEVICE_STATUS_QUEUE_CAP: usize = 128;
/// 踢线原因通知队列最大容量（满载丢最旧）。
const KICKED_REASON_QUEUE_CAP: usize = 16;
/// TCP Keepalive 空闲探测时间（30s）。
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
/// TCP Keepalive 探测间隔（10s）。
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// 上报给服务端的 `hostname` 最大 UTF-8 字节数。
const MAX_HOSTNAME_BYTES: usize = 128;
/// 上报给服务端的单条 `lan_addr` 最大字节数。
const MAX_LAN_ADDR_BYTES: usize = 64;
/// 上报给服务端的 `lan_addrs` 最大条数。
const MAX_LAN_ADDRS: usize = 16;

/// 协助开关原子编码：未显式设置（沿用服务端已有记录）。
const ASSIST_UNSET: u8 = 0;
/// 协助开关原子编码：关闭他人远程协助。
const ASSIST_FALSE: u8 = 1;
/// 协助开关原子编码：允许他人远程协助。
const ASSIST_TRUE: u8 = 2;

/// 远控总开关原子编码：未显式设置（沿用服务端按平台推导或已有记录）。
const REMOTE_CTRL_UNSET: u8 = 0;
/// 远控总开关原子编码：禁止被远程控制（含同账号本人自控）。
const REMOTE_CTRL_FALSE: u8 = 1;
/// 远控总开关原子编码：允许被远程控制。
const REMOTE_CTRL_TRUE: u8 = 2;

/// Wake-on-LAN 开关原子编码：未显式设置（沿用服务端已有记录）。
const WOL_UNSET: u8 = 0;
/// Wake-on-LAN 开关原子编码：关闭远程开机。
const WOL_FALSE: u8 = 1;
/// Wake-on-LAN 开关原子编码：开启远程开机。
const WOL_TRUE: u8 = 2;

/// 本机代发 `wol_relay` 魔术包的最大并发后台线程数上限。
const MAX_CONCURRENT_WOL_RELAYS: usize = 4;
/// 本机代发 `wol_relay` 滑动限流时间窗口（10 秒）。
const WOL_RELAY_RATE_WINDOW: Duration = Duration::from_secs(10);
/// 本机代发 `wol_relay` 在滑动窗口内允许的最大次数（防异常或滥用刷包）。
const WOL_RELAY_RATE_MAX: usize = 10;

/// 服务端推送的入站中继会话请求（本端作为被控端 `host` 接收）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelayIncoming {
    /// 服务端分配或透传的会话标识。
    pub session_id: String,
    /// 中继服务器 TCP 地址（如 `"172.16.1.2:21117"`）。
    pub relay_addr: String,
    /// 一次性 `RCR1` 中继令牌。
    pub relay_token: String,
    /// 发起连接的对端 9 位设备码。
    pub peer_id: String,
    /// 信令服务器观测到的对端公网 UDP 地址（空串归一化为 `None`）。
    pub peer_public_addr: Option<String>,
    /// 信令服务器观测到的对端双栈公网 UDP 地址列表（IPv6 + IPv4）。
    pub peer_public_addrs: Vec<String>,
    /// 信令服务器观测到的本端公网 UDP 地址（用于同公网 IP 判定）。
    pub self_public_addr: Option<String>,
    /// 本端探测分类得到的 NAT 类型。
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
    /// 服务端下发的会话共享 `RCP2 v2` HMAC 密钥（32 位十六进制字符串，如有）。
    pub punch_secret: Option<String>,
    /// 服务端协调的快侧打洞起跑延迟（毫秒）。
    pub start_after_ms: Option<u16>,
    /// 服务端协调的并发中继回退延迟（毫秒）。
    pub relay_fallback_after_ms: Option<u16>,
    /// 对端上报的局域网候选地址列表。
    pub peer_lan_addrs: Vec<String>,
    /// 本端持久化 UDP `RCSP` 探测套接字绑定的本地端口（供 P2P 同端口复用以对齐 NAT 映射）。
    pub local_udp_port: Option<u16>,
    /// 可选同账号自控一次性免密票据载荷（一般仅控制端下发，被控端通常为 `None`）。
    pub owner_grant: Option<OwnerGrantPayload>,
    /// 本次连接是否为同一登录账号的自控连接。
    pub is_owner_connection: bool,
    /// 是否为服务端显式 `relay_ready`（强制中继/切中继，而非 `punch_coord`）。
    pub is_relay_alloc: bool,
}

/// 出站连接请求获批后返回的中继/打洞凭据（本端作为控制端 `client` 接收）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConnectGrant {
    /// 会话标识。
    pub session_id: String,
    /// 中继服务器 TCP 地址（如 `"172.16.1.2:21117"`）。
    pub relay_addr: String,
    /// 一次性 `RCR1` 中继令牌。
    pub relay_token: String,
    /// 目标被控端的 9 位设备码。
    pub target_id: String,
    /// 信令服务器观测到的对端公网 UDP 地址（空串归一化为 `None`）。
    pub peer_public_addr: Option<String>,
    /// 信令服务器观测到的对端双栈公网 UDP 地址列表（IPv6 + IPv4）。
    #[serde(default)]
    pub peer_public_addrs: Vec<String>,
    /// 信令服务器观测到的本端公网 UDP 地址（用于同公网 IP 判定）。
    #[serde(default)]
    pub self_public_addr: Option<String>,
    /// 本端探测分类得到的 NAT 类型。
    #[serde(default)]
    pub self_nat_type: NatType,
    /// 本端顺序对称 NAT 分配端口步长（如有）。
    #[serde(default)]
    pub self_nat_port_delta: Option<i16>,
    /// 本端 NAT 外网端口区间提示（如有）。
    #[serde(default)]
    pub self_nat_port_range: Option<PortRangeHint>,
    /// 对端上报的 NAT 类型。
    #[serde(default)]
    pub peer_nat_type: NatType,
    /// 对端顺序对称 NAT 分配端口步长（如有）。
    #[serde(default)]
    pub peer_nat_port_delta: Option<i16>,
    /// 对端 NAT 外网端口区间提示（如有）。
    #[serde(default)]
    pub peer_nat_port_range: Option<PortRangeHint>,
    /// 服务端下发的会话共享 `RCP2 v2` HMAC 密钥（32 位十六进制字符串，如有）。
    #[serde(default)]
    pub punch_secret: Option<String>,
    /// 服务端协调的快侧打洞起跑延迟（毫秒）。
    #[serde(default)]
    pub start_after_ms: Option<u16>,
    /// 服务端协调的并发中继回退延迟（毫秒）。
    #[serde(default)]
    pub relay_fallback_after_ms: Option<u16>,
    /// 对端上报的局域网候选地址列表。
    pub peer_lan_addrs: Vec<String>,
    /// 本端持久化 UDP `RCSP` 探测套接字绑定的本地端口（供 P2P 同端口复用以对齐 NAT 映射）。
    pub local_udp_port: Option<u16>,
    /// 同账号自控时由服务端签发的一次性 `OwnerGrant` 票据载荷。
    pub owner_grant: Option<OwnerGrantPayload>,
    /// 本次连接是否为同一登录账号的自控连接。
    pub is_owner_connection: bool,
}

/// 同账号其他设备的上下线与远程协助状态变更通知（由信令服务端广播）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceStatusEvent {
    /// 9 位纯数字设备码。
    pub device_id: String,
    /// 当前是否在线。
    pub online: bool,
    /// 设备主机名。
    pub hostname: String,
    /// 用户自定义设备别名。
    pub alias: String,
    /// 操作系统名称。
    pub os: String,
    /// 设备应用版本号（旧服务端未推送时为空串）。
    pub app_version: String,
    /// 设备 CPU 架构（旧服务端未推送时为空串）。
    pub arch: String,
    /// 是否允许他人远程协助。
    pub allow_remote_assist: bool,
    /// 是否允许被远程控制（含同账号本人自控；老服务端未推送时按操作系统推导）。
    pub allow_remote_control: bool,
}

impl<'de> Deserialize<'de> for DeviceStatusEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawDeviceStatusEvent {
            device_id: String,
            online: bool,
            hostname: String,
            alias: String,
            os: String,
            #[serde(default)]
            app_version: String,
            #[serde(default)]
            arch: String,
            allow_remote_assist: bool,
            #[serde(default)]
            allow_remote_control: Option<bool>,
        }

        let raw = RawDeviceStatusEvent::deserialize(deserializer)?;
        let allow_remote_control = raw
            .allow_remote_control
            .unwrap_or_else(|| crate::default_allow_remote_control_for_os(&raw.os));
        Ok(Self {
            device_id: raw.device_id,
            online: raw.online,
            hostname: raw.hostname,
            alias: raw.alias,
            os: raw.os,
            app_version: raw.app_version,
            arch: raw.arch,
            allow_remote_assist: raw.allow_remote_assist,
            allow_remote_control,
        })
    }
}

/// 同账号设备的 Wake-on-LAN 能力增量状态事件（由 `device_status_changed` 同步解析）。
///
/// 独立于 [`DeviceStatusEvent`] 暴露，避免向既有公开结构体新增字段破坏下游字面量构造兼容性。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceWolCapabilityEvent {
    /// 9 位纯数字设备码。
    pub device_id: String,
    /// 设备当前是否在线。
    pub online: bool,
    /// 目标设备是否具备远程开机能力（`wol_enabled && valid(mac_addr)`）。
    #[serde(default)]
    pub wol_capable: bool,
}

/// 发起 `wol_request` 后由服务端返回的 Wake-on-LAN 唤醒结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WolAckResult {
    /// 目标 9 位设备码。
    pub target_device_id: String,
    /// 唤醒请求是否成功。
    pub ok: bool,
    /// 唤醒方式（`"already_online"` / `"lan_peer"` / `"server"` / `"none"`）。
    pub method: String,
    /// 失败时的服务端 wire 错误码（成功时为 `None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// 服务端返回的描述消息。
    pub message: String,
    /// 失败时映射后的规范结构化 [`crate::ui_error::UiError`]（成功时为 `None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_error: Option<crate::ui_error::UiError>,
}

/// 动态 Access Token 提供器类型（由上层接入 `AuthSessionManager::ensure_valid_access_token`）。
pub type TokenProvider = Arc<dyn Fn() -> Result<String, String> + Send + Sync>;

/// 当注册被服务端以 `token_expired` 拒绝时，强制刷新失效 Access Token 的回调类型
/// （入参为刚被拒绝的过期令牌，由上层接入 `AuthSessionManager::refresh_after_unauthorized`）。
pub type TokenRefresher = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// 信令客户端启动扩展参数（注入动态 Token 提供器、设备公钥、远程控制/协助、动态局域网与 UPnP 开关）。
#[derive(Clone, Default)]
pub struct SignalClientOptions {
    /// 可选动态 Access Token 提供器；每次建连与断线重连注册时自动拉取最新（必要时已轮换的）令牌。
    pub token_provider: Option<TokenProvider>,
    /// 可选强制刷新回调；当注册因 `token_expired`（例如设备休眠恢复或时钟偏差）失败时触发强制刷新。
    pub token_refresher: Option<TokenRefresher>,
    /// 可选本机设备 Ed25519 公钥（64 位小写十六进制）。
    pub device_pubkey: Option<String>,
    /// 初始是否允许他人远程协助（默认 `false`）。
    pub allow_remote_assist: bool,
    /// 可选初始「允许被远程控制（含本人自控）」状态（`None` 时注册帧不携带，由服务端按平台/已有记录处理）。
    pub allow_remote_control: Option<bool>,
    /// 是否按信令出向路由动态探测本机局域网 IPv4 候选并前置于静态 `lan_addrs`（默认 `false`）。
    pub dynamic_lan_discovery: bool,
    /// 是否启用 UPnP IGD / NAT-PMP 自动 UDP 端口映射（默认 `false`，避免离线测试向真实局域网发送 SSDP 广播）。
    pub upnp_enabled: bool,
}

impl fmt::Debug for SignalClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignalClientOptions")
            .field("has_token_provider", &self.token_provider.is_some())
            .field("has_token_refresher", &self.token_refresher.is_some())
            .field("device_pubkey", &self.device_pubkey)
            .field("allow_remote_assist", &self.allow_remote_assist)
            .field("allow_remote_control", &self.allow_remote_control)
            .field("dynamic_lan_discovery", &self.dynamic_lan_discovery)
            .field("upnp_enabled", &self.upnp_enabled)
            .finish()
    }
}

/// 客户端 -> 服务端信令帧（`type` 标签 `snake_case`）。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OutgoingSignalMsg {
    Register {
        #[serde(skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        device_key: String,
        hostname: String,
        os: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        app_version: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        arch: String,
        device_group: String,
        lan_addrs: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        access_token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        device_pubkey: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        allow_remote_assist: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        allow_remote_control: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mac_addr: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        wol_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nat_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nat_port_delta: Option<i16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nat_port_range: Option<[u16; 2]>,
        rcp2_v2: bool,
    },
    Heartbeat {
        lan_addrs: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mac_addr: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        wol_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nat_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nat_port_delta: Option<i16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nat_port_range: Option<[u16; 2]>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rtt_ms: Option<u32>,
    },
    UpdateAssistState {
        #[serde(skip_serializing_if = "Option::is_none")]
        allow_remote_assist: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        allow_remote_control: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mac_addr: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        wol_enabled: Option<bool>,
    },
    ConnectRequest {
        target_id: String,
        session_id: String,
        lan_addrs: Vec<String>,
        nonce: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        nat_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nat_port_delta: Option<i16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nat_port_range: Option<[u16; 2]>,
    },
    RelayAlloc {
        target_id: String,
        session_id: String,
    },
    WolRequest {
        request_id: String,
        target_device_id: String,
    },
}

/// 服务端 -> 客户端信令帧（`type` 标签 `snake_case`）。
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum IncomingSignalMsg {
    Registered {
        device_id: String,
        #[serde(default)]
        formatted_id: Option<String>,
        #[serde(default)]
        udp_probe_addr: Option<String>,
        #[serde(default)]
        udp_probe_alt_addr: Option<String>,
        #[serde(default)]
        udp_probe_alt_ip_addr: Option<String>,
        #[serde(default)]
        udp_probe_token: Option<String>,
        #[serde(default)]
        relay_addr: Option<String>,
    },
    HeartbeatAck {},
    DeviceStatusChanged {
        device_id: String,
        #[serde(default)]
        online: bool,
        #[serde(default)]
        hostname: String,
        #[serde(default)]
        alias: String,
        #[serde(default)]
        os: String,
        #[serde(default)]
        app_version: String,
        #[serde(default)]
        arch: String,
        #[serde(default)]
        allow_remote_assist: bool,
        #[serde(default)]
        allow_remote_control: Option<bool>,
        #[serde(default)]
        wol_capable: bool,
    },
    PunchCoord {
        session_id: String,
        #[serde(default)]
        role: String,
        peer_id: String,
        #[serde(default, alias = "peer_public_addr")]
        peer_public_udp_addr: Option<String>,
        #[serde(default)]
        peer_public_udp_addrs: Vec<String>,
        #[serde(default)]
        self_public_udp_addr: Option<String>,
        #[serde(default)]
        peer_nat_type: Option<String>,
        #[serde(default)]
        peer_nat_port_delta: Option<i16>,
        #[serde(default)]
        self_nat_port_range: Option<[u16; 2]>,
        #[serde(default)]
        peer_nat_port_range: Option<[u16; 2]>,
        #[serde(default)]
        peer_lan_addrs: Vec<String>,
        #[serde(default)]
        punch_secret: Option<String>,
        #[serde(default)]
        start_after_ms: Option<u16>,
        #[serde(default)]
        relay_fallback_after_ms: Option<u16>,
        relay_token: String,
        #[serde(default)]
        relay_addr: String,
        #[serde(default)]
        owner_grant: Option<OwnerGrantPayload>,
        #[serde(default)]
        is_owner_connection: bool,
    },
    RelayReady {
        session_id: String,
        #[serde(default)]
        role: String,
        peer_id: String,
        relay_token: String,
        #[serde(default)]
        relay_addr: String,
        #[serde(default)]
        owner_grant: Option<OwnerGrantPayload>,
        #[serde(default)]
        is_owner_connection: bool,
    },
    PeerOffline {
        target_id: String,
        #[serde(default)]
        session_id: String,
    },
    Kicked {
        #[serde(default)]
        reason: String,
    },
    WolAck {
        #[serde(default)]
        request_id: Option<String>,
        #[serde(default)]
        target_device_id: String,
        #[serde(default)]
        ok: bool,
        #[serde(default)]
        method: String,
        #[serde(default)]
        code: Option<String>,
        #[serde(default)]
        message: String,
    },
    WolRelay {
        #[serde(default)]
        #[allow(dead_code)]
        request_id: String,
        #[serde(default)]
        #[allow(dead_code)]
        target_device_id: String,
        #[serde(default)]
        mac_addr: String,
        #[serde(default)]
        target_lan_addrs: Vec<String>,
    },
    Error {
        #[serde(default)]
        code: String,
        #[serde(default)]
        message: String,
    },
}

#[derive(Clone, Copy)]
struct SignalTiming {
    heartbeat_interval: Duration,
    activity_timeout: Duration,
    stable_threshold: Duration,
    backoffs: [Duration; 4],
}

impl Default for SignalTiming {
    fn default() -> Self {
        Self {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: RECONNECT_BACKOFFS,
        }
    }
}

struct PendingConnect {
    target_id: String,
    tx: mpsc::SyncSender<Result<ConnectGrant, String>>,
}

type SharedTlsStream = Arc<Mutex<Option<Box<StreamOwned<ClientConnection, TcpStream>>>>>;

struct WriterWaitingGuard<'a>(&'a AtomicUsize);

impl<'a> WriterWaitingGuard<'a> {
    fn enter(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::Release);
        Self(counter)
    }
}

impl Drop for WriterWaitingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

enum SignalWriter {
    Plain(TcpStream),
    Tls {
        stream: SharedTlsStream,
        writer_waiting: Arc<AtomicUsize>,
    },
}

impl SignalWriter {
    fn write_msg(&mut self, msg: &OutgoingSignalMsg) -> Result<(), String> {
        match self {
            Self::Plain(stream) => write_signal_frame(stream, msg),
            Self::Tls {
                stream: shared_tls,
                writer_waiting,
            } => {
                let _wait_guard = WriterWaitingGuard::enter(writer_waiting);
                let mut guard = shared_tls.lock().unwrap_or_else(|e| e.into_inner());
                let Some(tls) = guard.as_mut() else {
                    return Err("信令 TLS 连接已关闭".to_string());
                };
                let res = write_signal_frame_tls(tls, msg);
                if res.is_err() {
                    if let Some(broken) = guard.take() {
                        let _ = broken.sock.shutdown(Shutdown::Both);
                    }
                }
                res
            }
        }
    }

    fn shutdown_and_close(self) {
        match self {
            Self::Plain(s) => {
                let _ = s.shutdown(Shutdown::Both);
            }
            Self::Tls {
                stream: shared_tls, ..
            } => {
                let mut guard = shared_tls.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(tls) = guard.take() {
                    let _ = tls.sock.shutdown(Shutdown::Both);
                }
            }
        }
    }
}

#[cfg(test)]
type WolRelayTestSink = Mutex<Option<mpsc::Sender<(String, Vec<String>)>>>;

struct SharedState {
    status: Mutex<ServerStatusSnapshot>,
    status_updates: Mutex<VecDeque<ServerStatusSnapshot>>,
    incoming: Mutex<VecDeque<RelayIncoming>>,
    device_status_events: Mutex<VecDeque<DeviceStatusEvent>>,
    kicked_reasons: Mutex<VecDeque<String>>,
    pending_connects: Mutex<HashMap<String, PendingConnect>>,
    active_writer: Mutex<Option<SignalWriter>>,
    /// 独立于 `active_writer` 的关闭句柄：`signal_stop()` / `trigger_reconnect()` 永不等待写锁即可瞬间切断套接字。
    shutdown_stream: Mutex<Option<TcpStream>>,
    stop_flag: AtomicBool,
    stop_lock: Mutex<bool>,
    stop_cv: Condvar,
    /// 快速重连标记：由 `trigger_reconnect` / 超时触发置位。
    fast_reconnect: AtomicBool,
    /// 重连时是否重置退避阶梯：外部显式 `trigger_reconnect` 置 `true`，请求超时自动触发置 `false`。
    reset_backoff_on_reconnect: AtomicBool,
    /// 重连代际计数器：每次 `trigger_reconnect` 递增，用于立即打断拨号、握手、读循环与退避等待。
    reconnect_epoch: AtomicU64,
    /// 最近一次触发快速重连的原因说明（供状态日志展示）。
    reconnect_reason: Mutex<Option<String>>,
    /// 最近一次在活跃连接读循环中收到服务端入站帧的时刻（断线清零）。
    last_server_activity: Mutex<Option<Instant>>,
    /// 上一次因 `request_connect` 超时触发重连的时刻（用于冷却期防风暴）。
    last_timeout_reconnect: Mutex<Option<Instant>>,
    /// 持久化 UDP `RCSP` 探测套接字的本地端口（0 表示未绑定）。
    local_udp_port: AtomicU16,
    /// 持久化 UDP `RCSP` 探测套接字是否绑定在 IPv6 地址族（仅在 `local_udp_port != 0` 时有效）。
    local_udp_is_ipv6: AtomicBool,
    /// 本端经 `RCSP`/`RCSA` 探测分类出的 NAT 画像与双栈观测公网端点。
    nat_profile: Mutex<NatProfile>,
    /// 客户端测量到的信令/UDP EWMA RTT 估算（毫秒，范围 `0..=10_000`）。
    rtt_ms: Mutex<Option<u32>>,
    /// 最近一次发送 `Heartbeat` 的时刻（用于计算 `HeartbeatAck` RTT 样本）。
    last_heartbeat_sent_at: Mutex<Option<Instant>>,
    /// 当前活跃连接持有的持久化 UDP 探测句柄（用于 `ConnectRequest` / `PunchCoord` 轻量热刷新）。
    active_probe: Mutex<Option<Arc<PersistentUdpProbe>>>,
    /// 是否在已连接状态下启用按路由动态局域网 IPv4 探测。
    dynamic_lan_discovery: bool,
    /// 当前信令连接对应的 UDP 探测与 TCP 对端目标列表（用于动态局域网出向网卡路由探测）。
    connected_probe_targets: Mutex<Vec<SocketAddr>>,
    /// 当前信令 TCP 对端是否位于回环地址（仅在同机联调时允许上报回环候选）。
    server_is_loopback: AtomicBool,
    /// 是否启用 UPnP / NAT-PMP 自动端口映射。
    upnp_enabled: AtomicBool,
    /// 当前 UPnP / NAT-PMP 端口映射状态快照。
    upnp_status: Mutex<UpnpStatus>,
    /// 当前生效的 UPnP / NAT-PMP 公网 UDP 地址（`ip:port`）。
    upnp_external_addr: Mutex<Option<String>>,
    /// 当前生效的 UPnP / NAT-PMP 端口映射租约（用于周期续租与断开退租）。
    upnp_lease: Mutex<Option<UpnpMappingLease>>,
    /// UPnP 映射代际号：每次绑定新 UDP 端口、切网重连或开关切换递增，过期后台线程结果自动丢弃并退租。
    upnp_gen: AtomicU64,
    /// UPnP 映射成功后置位，促使信令循环尽快发一次增量 `Heartbeat` 把新公网候选同步给服务端。
    upnp_heartbeat_needed: AtomicBool,
    lan_addrs: Vec<String>,
    enabled: bool,
    token_provider: Option<TokenProvider>,
    token_refresher: Option<TokenRefresher>,
    device_pubkey: Option<String>,
    allow_remote_assist: AtomicU8,
    allow_remote_control: AtomicU8,
    wol_enabled: AtomicU8,
    mac_addr: Mutex<Option<String>>,
    device_wol_events: Mutex<VecDeque<DeviceWolCapabilityEvent>>,
    device_wol_capable: Mutex<HashMap<String, bool>>,
    pending_wols:
        Mutex<HashMap<String, mpsc::SyncSender<Result<WolAckResult, crate::ui_error::UiError>>>>,
    wol_relay_inflight: Arc<AtomicUsize>,
    wol_relay_history: Mutex<VecDeque<Instant>>,
    proxy_override: Mutex<Option<crate::proxy::ProxyConfig>>,
    proxy_active: AtomicBool,
    #[cfg(test)]
    wol_relay_test_sink: WolRelayTestSink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SleepWake {
    TimedOut,
    Reconnect,
    Stopped,
}

fn snapshots_same_payload(a: &ServerStatusSnapshot, b: &ServerStatusSnapshot) -> bool {
    a.enabled == b.enabled
        && a.server_host == b.server_host
        && a.signal_port == b.signal_port
        && a.relay_port == b.relay_port
        && a.state == b.state
        && a.device_id == b.device_id
        && a.device_id_formatted == b.device_id_formatted
        && a.error_message == b.error_message
        && a.ui_error == b.ui_error
        && a.signal_addr == b.signal_addr
        && a.relay_addr == b.relay_addr
}

impl SharedState {
    fn set_status(
        &self,
        mut snapshot: ServerStatusSnapshot,
        on_status: &mut dyn FnMut(ServerStatusSnapshot),
    ) {
        {
            let mut guard = self.status.lock().unwrap_or_else(|e| e.into_inner());
            if snapshots_same_payload(&guard, &snapshot) {
                return;
            }
            snapshot.revision = next_status_revision();
            *guard = snapshot.clone();
        }
        {
            let mut q = self
                .status_updates
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if q.len() >= STATUS_QUEUE_CAP {
                q.pop_front();
            }
            q.push_back(snapshot.clone());
        }
        on_status(snapshot);
    }

    fn push_incoming(&self, item: RelayIncoming) {
        let mut q = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= INCOMING_QUEUE_CAP {
            q.pop_front();
        }
        q.push_back(item);
    }

    fn push_device_status(&self, ev: DeviceStatusEvent) {
        let mut q = self
            .device_status_events
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if q.len() >= DEVICE_STATUS_QUEUE_CAP {
            q.pop_front();
        }
        q.push_back(ev);
    }

    fn push_kicked_reason(&self, reason: String) {
        let trimmed = reason.trim();
        if trimmed.is_empty() {
            return;
        }
        let mut q = self
            .kicked_reasons
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if q.len() >= KICKED_REASON_QUEUE_CAP {
            q.pop_front();
        }
        q.push_back(trimmed.to_string());
    }

    fn current_allow_assist_opt(&self) -> Option<bool> {
        match self.allow_remote_assist.load(Ordering::Acquire) {
            ASSIST_FALSE => Some(false),
            ASSIST_TRUE => Some(true),
            _ => None,
        }
    }

    fn current_allow_remote_control_opt(&self) -> Option<bool> {
        match self.allow_remote_control.load(Ordering::Acquire) {
            REMOTE_CTRL_FALSE => Some(false),
            REMOTE_CTRL_TRUE => Some(true),
            _ => None,
        }
    }

    fn current_wol_enabled_opt(&self) -> Option<bool> {
        match self.wol_enabled.load(Ordering::Acquire) {
            WOL_FALSE => Some(false),
            WOL_TRUE => Some(true),
            _ => None,
        }
    }

    fn current_mac_addr_opt(&self) -> Option<String> {
        self.mac_addr
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn effective_proxy_config(&self) -> crate::proxy::ProxyConfig {
        self.proxy_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(crate::proxy::active_proxy_config)
    }

    fn push_device_wol_event(&self, ev: DeviceWolCapabilityEvent) {
        let key =
            parse_device_id_input(&ev.device_id).unwrap_or_else(|| ev.device_id.trim().to_string());
        if !key.is_empty() {
            self.device_wol_capable
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key, ev.wol_capable);
        }
        let mut q = self
            .device_wol_events
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if q.len() >= DEVICE_STATUS_QUEUE_CAP {
            q.pop_front();
        }
        q.push_back(ev);
    }

    fn fail_all_pending(&self, reason: &str) {
        let mut pending = self
            .pending_connects
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for (_, waiter) in pending.drain() {
            let _ = waiter.tx.try_send(Err(reason.to_string()));
        }
        drop(pending);
        let ui_err =
            crate::ui_error::classify_signal_error(reason, crate::ui_error::current_platform());
        let mut pending_wols = self.pending_wols.lock().unwrap_or_else(|e| e.into_inner());
        for (_, tx) in pending_wols.drain() {
            let _ = tx.try_send(Err(ui_err.clone()));
        }
    }

    /// 取出并关闭独立的 `shutdown_stream`，不触碰 `active_writer` 锁。
    fn shutdown_active_socket(&self) {
        let stream = self
            .shutdown_stream
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(s) = stream {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    fn clear_active_writer(&self) {
        self.clear_last_server_activity();
        self.local_udp_port.store(0, Ordering::Release);
        self.local_udp_is_ipv6.store(false, Ordering::Release);
        *self.nat_profile.lock().unwrap_or_else(|e| e.into_inner()) = NatProfile::default();
        *self.rtt_ms.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .last_heartbeat_sent_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self.active_probe.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.server_is_loopback.store(false, Ordering::Release);
        self.proxy_active.store(false, Ordering::Release);
        self.connected_probe_targets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.reset_upnp_for_disconnect();
        self.shutdown_active_socket();
        let writer = self
            .active_writer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(w) = writer {
            w.shutdown_and_close();
        }
    }

    fn current_nat_profile(&self) -> NatProfile {
        self.nat_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn current_nat_wire_fields(&self) -> (Option<String>, Option<i16>, Option<[u16; 2]>) {
        let profile = self
            .nat_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if profile.nat_type == NatType::Unknown {
            (None, None, None)
        } else {
            (
                Some(profile.nat_type.as_str().to_string()),
                profile.port_delta,
                profile
                    .port_range
                    .and_then(PortRangeHint::validated)
                    .map(PortRangeHint::to_wire_pair),
            )
        }
    }

    fn record_rtt_sample(&self, sample_ms: u32) {
        record_rtt_sample_into(&self.rtt_ms, sample_ms);
    }

    fn current_rtt_ms(&self) -> Option<u32> {
        *self.rtt_ms.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn observed_public_addr_matching(&self, peer_public_addr: Option<&str>) -> Option<String> {
        let profile = self
            .nat_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let peer_is_v6 = peer_public_addr
            .and_then(|s| s.trim().parse::<SocketAddr>().ok())
            .map(canonicalize_socket_addr)
            .is_some_and(|a| a.is_ipv6());
        if peer_is_v6 {
            profile.public_v6.or(profile.public_v4)
        } else {
            profile.public_v4.or(profile.public_v6)
        }
        .map(|a| a.to_string())
    }

    fn refresh_probe_and_recover_if_blocked(self: &Arc<Self>, probe: &Arc<PersistentUdpProbe>) {
        if probe.send_lightweight_refresh(&self.nat_profile) {
            self.maybe_spawn_udp_blocked_recovery_reprobe(probe);
        }
    }

    fn maybe_spawn_udp_blocked_recovery_reprobe(self: &Arc<Self>, probe: &Arc<PersistentUdpProbe>) {
        if self.stop_flag.load(Ordering::Acquire) || self.proxy_active.load(Ordering::Acquire) {
            return;
        }
        if probe
            .reprobe_inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let shared = Arc::clone(self);
        let probe_c = Arc::clone(probe);
        let spawned = thread::Builder::new()
            .name("rc-udp-reprobe".to_string())
            .spawn(move || {
                struct InflightReset<'a>(&'a AtomicBool);
                impl Drop for InflightReset<'_> {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }
                let _reset = InflightReset(&probe_c.reprobe_inflight);
                if shared.stop_flag.load(Ordering::Acquire)
                    || shared.proxy_active.load(Ordering::Acquire)
                {
                    return;
                }
                probe_c.run_initial_probe_round(
                    &shared.nat_profile,
                    &shared.rtt_ms,
                    &shared.stop_flag,
                );
                if !shared.stop_flag.load(Ordering::Acquire)
                    && shared.current_nat_profile().nat_type != NatType::UdpBlocked
                {
                    shared.upnp_heartbeat_needed.store(true, Ordering::Release);
                }
            });
        if spawned.is_err() {
            probe.reprobe_inflight.store(false, Ordering::Release);
        }
    }

    fn trigger_lightweight_probe_refresh(self: &Arc<Self>) {
        let probe = self
            .active_probe
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(probe) = probe {
            self.refresh_probe_and_recover_if_blocked(&probe);
        }
    }

    fn record_server_activity(&self, at: Instant) {
        *self
            .last_server_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(at);
    }

    fn clear_last_server_activity(&self) {
        *self
            .last_server_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn try_acquire_timeout_reconnect_slot(&self, now: Instant) -> bool {
        let recent_activity = {
            let guard = self
                .last_server_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.is_some_and(|t| {
                now.saturating_duration_since(t) < TIMEOUT_RECONNECT_ACTIVITY_GRACE
            })
        };
        if recent_activity {
            return false;
        }
        let mut last_guard = self
            .last_timeout_reconnect
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = *last_guard {
            if now.saturating_duration_since(prev) < TIMEOUT_RECONNECT_COOLDOWN {
                return false;
            }
        }
        *last_guard = Some(now);
        true
    }

    fn disable_upnp_mapping(&self) {
        let old_lease = {
            let mut lease_guard = self.upnp_lease.lock().unwrap_or_else(|e| e.into_inner());
            self.upnp_enabled.store(false, Ordering::Release);
            self.upnp_gen.fetch_add(1, Ordering::AcqRel);
            self.upnp_heartbeat_needed.store(false, Ordering::Release);
            let old = lease_guard.take();
            *self
                .upnp_external_addr
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
            *self.upnp_status.lock().unwrap_or_else(|e| e.into_inner()) = UpnpStatus::Disabled;
            old
        };
        if let Some(lease) = old_lease {
            spawn_upnp_unmap_task(lease);
        }
    }

    fn prepare_upnp_if_enabled(
        &self,
        expected_udp_port: Option<u16>,
        next_status: UpnpStatus,
    ) -> Option<u64> {
        let (result, old_lease) = {
            let mut lease_guard = self.upnp_lease.lock().unwrap_or_else(|e| e.into_inner());
            if !self.upnp_enabled.load(Ordering::Acquire) || self.stop_flag.load(Ordering::Acquire)
            {
                return None;
            }
            if let Some(expected) = expected_udp_port {
                if self.local_udp_port.load(Ordering::Acquire) != expected {
                    return None;
                }
            }
            let next_gen = self.upnp_gen.fetch_add(1, Ordering::AcqRel) + 1;
            self.upnp_heartbeat_needed.store(false, Ordering::Release);
            let old = lease_guard.take();
            *self
                .upnp_external_addr
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
            *self.upnp_status.lock().unwrap_or_else(|e| e.into_inner()) = next_status;
            (Some(next_gen), old)
        };
        if let Some(lease) = old_lease {
            spawn_upnp_unmap_task(lease);
        }
        result
    }

    /// 持 `upnp_lease -> upnp_external_addr -> upnp_status` 锁原子开启 UPnP 并复检当前 UDP 端口与连接态，
    /// 与并发 `clear_active_writer` / `reset_upnp_for_disconnect` 串行化，避免为已清零的旧端口发起无效映射。
    fn enable_upnp_and_prepare(&self) -> Option<(u16, u64)> {
        let (spawn_args, old_lease) = {
            let mut lease_guard = self.upnp_lease.lock().unwrap_or_else(|e| e.into_inner());
            if self.stop_flag.load(Ordering::Acquire) {
                return None;
            }
            let was_enabled = self.upnp_enabled.swap(true, Ordering::AcqRel);
            let mut addr_guard = self
                .upnp_external_addr
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut status_guard = self.upnp_status.lock().unwrap_or_else(|e| e.into_inner());
            if was_enabled
                && matches!(
                    *status_guard,
                    UpnpStatus::Discovering | UpnpStatus::Mapped { .. }
                )
            {
                return None;
            }

            let port = self.local_udp_port.load(Ordering::Acquire);
            let is_ipv6 = self.local_udp_is_ipv6.load(Ordering::Acquire);
            let is_loopback = self.server_is_loopback.load(Ordering::Acquire);
            let is_proxied = self.proxy_active.load(Ordering::Acquire);

            let next_gen = self.upnp_gen.fetch_add(1, Ordering::AcqRel) + 1;
            self.upnp_heartbeat_needed.store(false, Ordering::Release);
            let old = lease_guard.take();
            *addr_guard = None;

            let (next_status, to_spawn) = if is_proxied {
                (
                    UpnpStatus::Unavailable {
                        reason: "已启用网络代理，已跳过 UPnP 网关探测".to_string(),
                    },
                    None,
                )
            } else if port == 0 {
                (UpnpStatus::Discovering, None)
            } else if is_ipv6 {
                (
                    UpnpStatus::Unavailable {
                        reason: "当前信令通道使用 IPv6，无需 IPv4 UPnP 映射".to_string(),
                    },
                    None,
                )
            } else if is_loopback {
                (
                    UpnpStatus::Unavailable {
                        reason: "本地回环调试模式已跳过 UPnP 网关探测".to_string(),
                    },
                    None,
                )
            } else {
                (UpnpStatus::Discovering, Some((port, next_gen)))
            };
            *status_guard = next_status;
            (to_spawn, old)
        };
        if let Some(lease) = old_lease {
            spawn_upnp_unmap_task(lease);
        }
        spawn_args
    }

    fn reset_upnp_for_disconnect(&self) {
        let old_lease = {
            let mut lease_guard = self.upnp_lease.lock().unwrap_or_else(|e| e.into_inner());
            self.upnp_gen.fetch_add(1, Ordering::AcqRel);
            self.upnp_heartbeat_needed.store(false, Ordering::Release);
            let old = lease_guard.take();
            *self
                .upnp_external_addr
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
            let next_status = if self.upnp_enabled.load(Ordering::Acquire)
                && !self.stop_flag.load(Ordering::Acquire)
            {
                UpnpStatus::Discovering
            } else {
                UpnpStatus::Disabled
            };
            *self.upnp_status.lock().unwrap_or_else(|e| e.into_inner()) = next_status;
            old
        };
        if let Some(lease) = old_lease {
            spawn_upnp_unmap_task(lease);
        }
    }

    fn cleanup_upnp_on_stop(&self) {
        let old_lease = {
            let mut lease_guard = self.upnp_lease.lock().unwrap_or_else(|e| e.into_inner());
            self.upnp_gen.fetch_add(1, Ordering::AcqRel);
            self.upnp_heartbeat_needed.store(false, Ordering::Release);
            let old = lease_guard.take();
            *self
                .upnp_external_addr
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = None;
            if !self.upnp_enabled.load(Ordering::Acquire) {
                *self.upnp_status.lock().unwrap_or_else(|e| e.into_inner()) = UpnpStatus::Disabled;
            }
            old
        };
        if let Some(lease) = old_lease {
            spawn_upnp_unmap_task(lease);
        }
    }

    fn format_reconnect_reason(&self) -> String {
        let reason = self
            .reconnect_reason
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match reason {
            Some(r) if !r.is_empty() => format!("触发信令快速重连 ({r})"),
            _ => "触发信令快速重连".to_string(),
        }
    }

    fn request_fast_reconnect(&self, reason: &str, reset_backoff: bool) {
        let trimmed = reason.trim();
        {
            let mut reason_guard = self
                .reconnect_reason
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *reason_guard = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        {
            let guard = self.stop_lock.lock().unwrap_or_else(|e| e.into_inner());
            if *guard || self.stop_flag.load(Ordering::Acquire) {
                return;
            }
            self.fast_reconnect.store(true, Ordering::Release);
            if reset_backoff {
                self.reset_backoff_on_reconnect
                    .store(true, Ordering::Release);
            }
            self.reconnect_epoch.fetch_add(1, Ordering::AcqRel);
            self.stop_cv.notify_all();
        }
        self.reset_upnp_for_disconnect();
        self.shutdown_active_socket();
    }

    fn current_effective_lan_addrs(
        &self,
        static_lan_addrs: &[String],
        local_udp_port: u16,
        local_udp_is_ipv6: bool,
    ) -> Vec<String> {
        if local_udp_port == 0 || self.proxy_active.load(Ordering::Acquire) {
            return Vec::new();
        }
        let allow_loopback = self.server_is_loopback.load(Ordering::Acquire);
        let mut out = if self.dynamic_lan_discovery {
            let targets = self
                .connected_probe_targets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let local_ips = crate::lan_discovery::detect_local_interface_ips_for_targets(&targets);
            let mut combined: Vec<String> = Vec::new();
            if !local_udp_is_ipv6 {
                for ip in local_ips.ipv4s {
                    let s = ip.to_string();
                    if !combined.contains(&s) {
                        combined.push(s);
                    }
                }
            }
            for v6 in local_ips.global_ipv6s {
                let s = v6.to_string();
                if !combined.contains(&s) {
                    combined.push(s);
                }
            }
            for raw in static_lan_addrs {
                if !combined.contains(raw) {
                    combined.push(raw.clone());
                }
            }
            effective_lan_addrs(&combined, local_udp_port, local_udp_is_ipv6, allow_loopback)
        } else {
            effective_lan_addrs(
                static_lan_addrs,
                local_udp_port,
                local_udp_is_ipv6,
                allow_loopback,
            )
        };

        let upnp_ext = self
            .upnp_external_addr
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(ext) = upnp_ext {
            let trimmed = ext.trim();
            let allow_family = if let Ok(sock) = trimmed.parse::<SocketAddr>() {
                match sock {
                    SocketAddr::V4(_) => !local_udp_is_ipv6,
                    SocketAddr::V6(v6) => is_global_unicast_ipv6(*v6.ip()),
                }
            } else {
                !local_udp_is_ipv6
            };
            if allow_family
                && !trimmed.is_empty()
                && trimmed.len() <= MAX_LAN_ADDR_BYTES
                && trimmed.bytes().all(|b| b.is_ascii_graphic())
                && !out.iter().any(|existing| existing == trimmed)
                && out.len() < MAX_LAN_ADDRS
            {
                out.push(trimmed.to_string());
            }
        }
        out
    }

    fn send_msg(&self, msg: &OutgoingSignalMsg) -> Result<(), String> {
        let mut writer_failed = false;
        let send_res = {
            let mut writer_guard = self.active_writer.lock().unwrap_or_else(|e| e.into_inner());
            match writer_guard.as_mut() {
                Some(writer) => {
                    let res = writer.write_msg(msg);
                    if res.is_err() {
                        writer_failed = true;
                        if let Some(broken) = writer_guard.take() {
                            broken.shutdown_and_close();
                        }
                    }
                    res
                }
                None => Err("信令服务器尚未连接完成".to_string()),
            }
        };
        if writer_failed {
            self.shutdown_active_socket();
        }
        send_res
    }

    fn sleep_or_stop(&self, duration: Duration, sleep_epoch: u64) -> SleepWake {
        let mut guard = self.stop_lock.lock().unwrap_or_else(|e| e.into_inner());
        if *guard || self.stop_flag.load(Ordering::Acquire) {
            return SleepWake::Stopped;
        }
        if self.reconnect_epoch.load(Ordering::Acquire) != sleep_epoch {
            return SleepWake::Reconnect;
        }
        let deadline = Instant::now() + duration;
        while !*guard
            && !self.stop_flag.load(Ordering::Acquire)
            && self.reconnect_epoch.load(Ordering::Acquire) == sleep_epoch
        {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (next_guard, wait_res) = self
                .stop_cv
                .wait_timeout(guard, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            guard = next_guard;
            if wait_res.timed_out() {
                break;
            }
        }
        if *guard || self.stop_flag.load(Ordering::Acquire) {
            SleepWake::Stopped
        } else if self.reconnect_epoch.load(Ordering::Acquire) != sleep_epoch {
            SleepWake::Reconnect
        } else {
            SleepWake::TimedOut
        }
    }

    fn signal_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        {
            let mut guard = self.stop_lock.lock().unwrap_or_else(|e| e.into_inner());
            *guard = true;
            self.stop_cv.notify_all();
        }
        // 先立即失败所有在途请求，再通过独立 shutdown_stream 切断套接字（绝不等待 active_writer 锁）。
        self.fail_all_pending("信令客户端已停止");
        self.shutdown_active_socket();
    }
}

fn spawn_upnp_unmap_task(lease: UpnpMappingLease) {
    let _ = thread::Builder::new()
        .name("rc-upnp-unmap".to_string())
        .spawn(move || {
            unmap_udp_port(&lease, UPNP_UNMAP_TIMEOUT);
        });
}

fn spawn_upnp_map_task(shared: Arc<SharedState>, bound_udp_port: u16, generation: u64) {
    let _ = thread::Builder::new()
        .name("rc-upnp-map".to_string())
        .spawn(move || {
            if shared.upnp_gen.load(Ordering::Acquire) != generation
                || shared.local_udp_port.load(Ordering::Acquire) != bound_udp_port
                || !shared.upnp_enabled.load(Ordering::Acquire)
                || shared.proxy_active.load(Ordering::Acquire)
                || shared.stop_flag.load(Ordering::Acquire)
            {
                return;
            }
            let res = verify_mapped_lease_or_unmap(
                &shared,
                generation,
                map_udp_port(bound_udp_port, UPNP_LEASE_SECS, UPNP_MAP_TIMEOUT),
            );
            apply_upnp_map_result(&shared, generation, res);
        });
}

fn maybe_spawn_upnp_renew(shared: &Arc<SharedState>) {
    if !shared.upnp_enabled.load(Ordering::Acquire)
        || shared.proxy_active.load(Ordering::Acquire)
        || shared.stop_flag.load(Ordering::Acquire)
    {
        return;
    }
    let (generation, lease_opt) = {
        let lease_guard = shared.upnp_lease.lock().unwrap_or_else(|e| e.into_inner());
        (shared.upnp_gen.load(Ordering::Acquire), lease_guard.clone())
    };
    let Some(lease) = lease_opt else {
        return;
    };
    let shared_bg = Arc::clone(shared);
    let _ = thread::Builder::new()
        .name("rc-upnp-renew".to_string())
        .spawn(move || {
            let res = verify_mapped_lease_or_unmap(
                &shared_bg,
                generation,
                renew_udp_mapping(&lease, UPNP_LEASE_SECS, UPNP_MAP_TIMEOUT),
            );
            apply_upnp_map_result(&shared_bg, generation, res);
        });
}

fn verify_mapped_lease_or_unmap(
    shared: &SharedState,
    generation: u64,
    result: Result<UpnpMappingLease, String>,
) -> Result<UpnpMappingLease, String> {
    let Ok(lease) = result else {
        return result;
    };
    if shared.proxy_active.load(Ordering::Acquire)
        || shared.upnp_gen.load(Ordering::Acquire) != generation
        || shared.stop_flag.load(Ordering::Acquire)
    {
        unmap_udp_port(&lease, UPNP_UNMAP_TIMEOUT);
        return Err("UPnP/PCP 自检前状态已失效或代理激活".to_string());
    }
    let probe_opt = shared
        .active_probe
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(probe) = probe_opt {
        if let ExternalMappingCheck::Unreachable(reason) = probe
            .verify_external_mapping_reachability(
                lease.external_addr,
                &shared.nat_profile,
                &shared.stop_flag,
            )
        {
            unmap_udp_port(&lease, UPNP_UNMAP_TIMEOUT);
            return Err(reason);
        }
    }
    Ok(lease)
}

fn trigger_upnp_for_bound_udp(
    shared: &Arc<SharedState>,
    bound_udp_port: u16,
    bound_udp_is_ipv6: bool,
    server_is_loopback: bool,
) {
    if !shared.upnp_enabled.load(Ordering::Acquire) || shared.stop_flag.load(Ordering::Acquire) {
        return;
    }
    if bound_udp_port == 0 {
        let _ = shared.prepare_upnp_if_enabled(
            None,
            UpnpStatus::Unavailable {
                reason: "未绑定持久化 UDP 探测端口".to_string(),
            },
        );
        return;
    }
    if bound_udp_is_ipv6 {
        let _ = shared.prepare_upnp_if_enabled(
            Some(bound_udp_port),
            UpnpStatus::Unavailable {
                reason: "当前信令通道使用 IPv6，无需 IPv4 UPnP 映射".to_string(),
            },
        );
        return;
    }
    if server_is_loopback {
        let _ = shared.prepare_upnp_if_enabled(
            Some(bound_udp_port),
            UpnpStatus::Unavailable {
                reason: "本地回环调试模式已跳过 UPnP 网关探测".to_string(),
            },
        );
        return;
    }
    if let Some(generation) =
        shared.prepare_upnp_if_enabled(Some(bound_udp_port), UpnpStatus::Discovering)
    {
        spawn_upnp_map_task(Arc::clone(shared), bound_udp_port, generation);
    }
}

fn apply_upnp_map_result(
    shared: &SharedState,
    generation: u64,
    result: Result<UpnpMappingLease, String>,
) {
    let mut lease_to_unmap: Option<UpnpMappingLease> = None;
    {
        let mut lease_guard = shared.upnp_lease.lock().unwrap_or_else(|e| e.into_inner());
        let stale = shared.upnp_gen.load(Ordering::Acquire) != generation
            || !shared.upnp_enabled.load(Ordering::Acquire)
            || shared.stop_flag.load(Ordering::Acquire);
        if stale {
            if let Ok(stale_lease) = result {
                lease_to_unmap = Some(stale_lease);
            }
        } else {
            match result {
                Ok(lease) => {
                    let ext_str = lease.external_addr.to_string();
                    let proto_str = lease.protocol.as_str().to_string();
                    let new_ext_addr = lease.external_addr;
                    if let Some(prev) = lease_guard.replace(lease) {
                        if prev.external_addr != new_ext_addr {
                            lease_to_unmap = Some(prev);
                        }
                    }
                    let mut addr_guard = shared
                        .upnp_external_addr
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let changed = addr_guard.as_deref() != Some(ext_str.as_str());
                    *addr_guard = Some(ext_str.clone());
                    let mut status_guard =
                        shared.upnp_status.lock().unwrap_or_else(|e| e.into_inner());
                    *status_guard = UpnpStatus::Mapped {
                        external_addr: ext_str,
                        protocol: proto_str,
                    };
                    if changed {
                        shared.upnp_heartbeat_needed.store(true, Ordering::Release);
                    }
                }
                Err(reason) => {
                    *lease_guard = None;
                    *shared
                        .upnp_external_addr
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = None;
                    *shared.upnp_status.lock().unwrap_or_else(|e| e.into_inner()) =
                        UpnpStatus::Unavailable { reason };
                }
            }
        }
    }
    if let Some(lease) = lease_to_unmap {
        unmap_udp_port(&lease, UPNP_UNMAP_TIMEOUT);
    }
}

/// 持久化信令客户端句柄（后台维护 TCP/TLS 1.3 长连接、注册、心跳、UDP 探测与会话协调）。
///
/// 在 `Drop` 时自动停止后台线程并释放套接字，不留僵尸线程。
pub struct SignalClientHandle {
    shared: Arc<SharedState>,
    worker: Option<JoinHandle<()>>,
}

impl SignalClientHandle {
    /// 启动信令客户端后台线程；若 `cfg.enabled == false` 或 `server_host` 为空则保持 `Disabled` 态且不建连。
    pub fn spawn(cfg: ServerConfig, hostname: String, lan_addrs: Vec<String>) -> Self {
        Self::spawn_with_callback(cfg, hostname, lan_addrs, |_| {})
    }

    /// 启动信令客户端后台线程，并在每次连接状态变化时同步触发 `on_status` 回调。
    pub fn spawn_with_callback<F>(
        cfg: ServerConfig,
        hostname: String,
        lan_addrs: Vec<String>,
        on_status: F,
    ) -> Self
    where
        F: FnMut(ServerStatusSnapshot) + Send + 'static,
    {
        Self::spawn_with_timing(
            cfg,
            hostname,
            lan_addrs,
            None,
            SignalTiming::default(),
            on_status,
        )
    }

    /// 启动携带鉴权扩展选项（动态 Token 提供器、设备公钥与远程协助开关）的信令客户端后台线程。
    pub fn spawn_with_options<F>(
        cfg: ServerConfig,
        hostname: String,
        lan_addrs: Vec<String>,
        options: SignalClientOptions,
        on_status: F,
    ) -> Self
    where
        F: FnMut(ServerStatusSnapshot) + Send + 'static,
    {
        Self::spawn_with_timing(
            cfg,
            hostname,
            lan_addrs,
            Some(options),
            SignalTiming::default(),
            on_status,
        )
    }

    fn spawn_with_timing<F>(
        cfg: ServerConfig,
        hostname: String,
        lan_addrs: Vec<String>,
        options: Option<SignalClientOptions>,
        timing: SignalTiming,
        mut on_status: F,
    ) -> Self
    where
        F: FnMut(ServerStatusSnapshot) + Send + 'static,
    {
        let clean_hostname = sanitize_hostname(&hostname);
        let clean_lan_addrs = sanitize_lan_addrs(&lan_addrs);
        let active = cfg.enabled && !cfg.server_host.trim().is_empty() && cfg.signal_port != 0;
        let initial_snapshot = if active {
            let device_id = cfg.cached_device_id.clone();
            let device_id_formatted = device_id.as_deref().map(format_device_id);
            ServerStatusSnapshot {
                enabled: true,
                server_host: cfg.server_host.clone(),
                signal_port: cfg.signal_port,
                relay_port: cfg.relay_port,
                state: ServerConnectionState::Connecting,
                device_id,
                device_id_formatted,
                error_message: None,
                ui_error: None,
                signal_addr: cfg.signal_addr(),
                relay_addr: cfg.relay_addr(),
                revision: next_status_revision(),
            }
        } else {
            cfg.disabled_snapshot()
        };

        let (
            token_provider,
            token_refresher,
            device_pubkey,
            initial_assist,
            initial_remote_ctrl,
            dynamic_lan_discovery,
            upnp_enabled,
        ) = match options {
            Some(opts) => {
                let pubkey = opts
                    .device_pubkey
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty());
                let assist = if opts.allow_remote_assist {
                    ASSIST_TRUE
                } else {
                    ASSIST_FALSE
                };
                let remote_ctrl = match opts.allow_remote_control {
                    Some(true) => REMOTE_CTRL_TRUE,
                    Some(false) => REMOTE_CTRL_FALSE,
                    None => REMOTE_CTRL_UNSET,
                };
                (
                    opts.token_provider,
                    opts.token_refresher,
                    pubkey,
                    assist,
                    remote_ctrl,
                    opts.dynamic_lan_discovery,
                    opts.upnp_enabled,
                )
            }
            None => (
                None,
                None,
                None,
                ASSIST_UNSET,
                REMOTE_CTRL_UNSET,
                false,
                false,
            ),
        };
        let initial_upnp_status = if upnp_enabled {
            UpnpStatus::Discovering
        } else {
            UpnpStatus::Disabled
        };

        let shared = Arc::new(SharedState {
            status: Mutex::new(initial_snapshot.clone()),
            status_updates: Mutex::new(VecDeque::new()),
            incoming: Mutex::new(VecDeque::new()),
            device_status_events: Mutex::new(VecDeque::new()),
            kicked_reasons: Mutex::new(VecDeque::new()),
            pending_connects: Mutex::new(HashMap::new()),
            active_writer: Mutex::new(None),
            shutdown_stream: Mutex::new(None),
            stop_flag: AtomicBool::new(false),
            stop_lock: Mutex::new(false),
            stop_cv: Condvar::new(),
            fast_reconnect: AtomicBool::new(false),
            reset_backoff_on_reconnect: AtomicBool::new(false),
            reconnect_epoch: AtomicU64::new(0),
            reconnect_reason: Mutex::new(None),
            last_server_activity: Mutex::new(None),
            last_timeout_reconnect: Mutex::new(None),
            local_udp_port: AtomicU16::new(0),
            local_udp_is_ipv6: AtomicBool::new(false),
            nat_profile: Mutex::new(NatProfile::default()),
            rtt_ms: Mutex::new(None),
            last_heartbeat_sent_at: Mutex::new(None),
            active_probe: Mutex::new(None),
            dynamic_lan_discovery,
            connected_probe_targets: Mutex::new(Vec::new()),
            server_is_loopback: AtomicBool::new(false),
            upnp_enabled: AtomicBool::new(upnp_enabled),
            upnp_status: Mutex::new(initial_upnp_status),
            upnp_external_addr: Mutex::new(None),
            upnp_lease: Mutex::new(None),
            upnp_gen: AtomicU64::new(0),
            upnp_heartbeat_needed: AtomicBool::new(false),
            lan_addrs: clean_lan_addrs.clone(),
            enabled: active,
            token_provider,
            token_refresher,
            device_pubkey,
            allow_remote_assist: AtomicU8::new(initial_assist),
            allow_remote_control: AtomicU8::new(initial_remote_ctrl),
            wol_enabled: AtomicU8::new(WOL_UNSET),
            mac_addr: Mutex::new(
                crate::platform::primary_mac_address()
                    .and_then(|m| crate::wol::normalize_mac_addr(&m)),
            ),
            device_wol_events: Mutex::new(VecDeque::new()),
            device_wol_capable: Mutex::new(HashMap::new()),
            pending_wols: Mutex::new(HashMap::new()),
            wol_relay_inflight: Arc::new(AtomicUsize::new(0)),
            wol_relay_history: Mutex::new(VecDeque::new()),
            proxy_override: Mutex::new(None),
            proxy_active: AtomicBool::new(false),
            #[cfg(test)]
            wol_relay_test_sink: Mutex::new(None),
        });

        if !active {
            return Self {
                shared,
                worker: None,
            };
        }

        let shared_clone = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("rc-signal-client".to_string())
            .spawn(move || {
                on_status(initial_snapshot);
                worker_loop(
                    shared_clone,
                    cfg,
                    clean_hostname,
                    clean_lan_addrs,
                    timing,
                    &mut on_status,
                );
            })
            .ok();

        Self { shared, worker }
    }

    /// 向服务器发起连接目标 9 位设备码的请求，阻塞等待 `punch_coord` / `relay_ready`（或立即可返回的 `peer_offline` / `error`）。
    pub fn request_connect(
        &self,
        target_id: &str,
        timeout: Duration,
    ) -> Result<ConnectGrant, String> {
        self.request_connect_inner(target_id, timeout, false)
    }

    /// 向服务器发起纯中继通道分配请求（`relay_alloc`），跳过双方 LAN 宽限与 UDP P2P 打洞，
    /// 阻塞等待 `relay_ready`（供「强制安全中转 / TCP Relay」模式使用）。
    pub fn request_relay(
        &self,
        target_id: &str,
        timeout: Duration,
    ) -> Result<ConnectGrant, String> {
        self.request_connect_inner(target_id, timeout, true)
    }

    fn request_connect_inner(
        &self,
        target_id: &str,
        timeout: Duration,
        force_relay: bool,
    ) -> Result<ConnectGrant, String> {
        if !self.shared.enabled {
            return Err("未启用信令服务器，请先在「设置 → 网络」中配置服务器".to_string());
        }
        let normalized = parse_device_id_input(target_id)
            .ok_or_else(|| "目标设备码格式无效，请输入 9 位数字设备码".to_string())?;

        let session_id = random_hex(16);
        let (tx, rx) = mpsc::sync_channel(1);

        {
            let mut pending = self
                .shared
                .pending_connects
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.shared.stop_flag.load(Ordering::Acquire) {
                return Err("信令客户端已停止".to_string());
            }
            pending.insert(
                session_id.clone(),
                PendingConnect {
                    target_id: normalized.clone(),
                    tx,
                },
            );
        }

        let msg = if force_relay {
            OutgoingSignalMsg::RelayAlloc {
                target_id: normalized,
                session_id: session_id.clone(),
            }
        } else {
            self.shared.trigger_lightweight_probe_refresh();
            let nonce = random_hex(8);
            let local_udp_port = self.shared.local_udp_port.load(Ordering::Acquire);
            let local_udp_is_ipv6 = self.shared.local_udp_is_ipv6.load(Ordering::Acquire);
            let (nat_type, nat_port_delta, nat_port_range) = self.shared.current_nat_wire_fields();
            OutgoingSignalMsg::ConnectRequest {
                target_id: normalized,
                session_id: session_id.clone(),
                lan_addrs: self.shared.current_effective_lan_addrs(
                    &self.shared.lan_addrs,
                    local_udp_port,
                    local_udp_is_ipv6,
                ),
                nonce,
                nat_type,
                nat_port_delta,
                nat_port_range,
            }
        };

        if let Err(err) = self.shared.send_msg(&msg) {
            let mut pending = self
                .shared
                .pending_connects
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            pending.remove(&session_id);
            return Err(err);
        }

        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                {
                    let mut pending = self
                        .shared
                        .pending_connects
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    pending.remove(&session_id);
                }
                if self
                    .shared
                    .try_acquire_timeout_reconnect_slot(Instant::now())
                {
                    self.trigger_reconnect_inner("connect_request_timeout", false);
                }
                Err("等待服务器下发连接凭据超时".to_string())
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let mut pending = self
                    .shared
                    .pending_connects
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                pending.remove(&session_id);
                Err("信令连接已断开".to_string())
            }
        }
    }

    fn trigger_reconnect_inner(&self, reason: &str, reset_backoff: bool) {
        if !self.shared.enabled || self.shared.stop_flag.load(Ordering::Acquire) {
            return;
        }
        self.shared.request_fast_reconnect(reason, reset_backoff);
    }

    /// 主动触发信令快速重连（适用于系统切网、休眠唤醒或检测到底层半开死连接）。
    ///
    /// 置位快速重连标记（下次退避窗口缩短为 `200ms` 并重置退避阶梯），立即关闭当前活跃的
    /// TCP/TLS 套接字并唤醒退避等待条件变量；在未连接、正在重连或未启用状态下调用均幂等安全。
    pub fn trigger_reconnect(&self, reason: &str) {
        self.trigger_reconnect_inner(reason, true);
    }

    /// 动态开启或关闭 UPnP / NAT-PMP 自动 UDP 端口映射。
    ///
    /// 关闭时立即递增代际号、清空公网映射地址、置状态为 [`UpnpStatus::Disabled`] 并在后台短线程
    /// 尽力调用 [`unmap_udp_port`] 释放旧租约；开启时若当前已绑定非零 IPv4 持久化 UDP 探测端口
    /// （且非本地回环模式），则立即触发后台异步端口映射。
    pub fn set_upnp_enabled(&self, enabled: bool) {
        if !enabled {
            self.shared.disable_upnp_mapping();
            return;
        }
        if let Some((port, generation)) = self.shared.enable_upnp_and_prepare() {
            spawn_upnp_map_task(Arc::clone(&self.shared), port, generation);
        }
    }

    /// 返回当前 UPnP / NAT-PMP 自动端口映射状态快照。
    pub fn upnp_status(&self) -> UpnpStatus {
        self.shared
            .upnp_status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 实时更新本机「允许他人远程协助」状态并同步发送 `UpdateAssistState` 信令帧（不覆写远端 `allow_remote_control`）。
    pub fn set_allow_remote_assist(&self, allow: bool) -> Result<(), String> {
        let code = if allow { ASSIST_TRUE } else { ASSIST_FALSE };
        self.shared
            .allow_remote_assist
            .store(code, Ordering::Release);
        if !self.shared.enabled {
            return Err("未启用信令服务器".to_string());
        }
        self.shared.send_msg(&OutgoingSignalMsg::UpdateAssistState {
            allow_remote_assist: Some(allow),
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
        })
    }

    /// 实时更新本机「允许被远程控制（含本人自控）」状态并同步发送 `UpdateAssistState` 信令帧（不覆写远端 `allow_remote_assist`）。
    pub fn set_allow_remote_control(&self, allow: bool) -> Result<(), String> {
        let code = if allow {
            REMOTE_CTRL_TRUE
        } else {
            REMOTE_CTRL_FALSE
        };
        self.shared
            .allow_remote_control
            .store(code, Ordering::Release);
        if !self.shared.enabled {
            return Err("未启用信令服务器".to_string());
        }
        self.shared.send_msg(&OutgoingSignalMsg::UpdateAssistState {
            allow_remote_assist: None,
            allow_remote_control: Some(allow),
            mac_addr: None,
            wol_enabled: None,
        })
    }

    /// 设置或清除本信令客户端的显式出站代理配置（`None` 表示跟随进程级 [`crate::proxy::active_proxy_config`]）。
    ///
    /// 调用方可在更新代理配置后配合 [`Self::trigger_reconnect`] 立即切换通道。
    pub fn set_proxy_config(&self, proxy: Option<crate::proxy::ProxyConfig>) {
        *self
            .shared
            .proxy_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = proxy;
    }

    /// 实时更新本机 Wake-on-LAN 远程开机开关并向服务端发送 `UpdateAssistState` 同步。
    pub fn set_wol_enabled(&self, enabled: bool) -> Result<(), String> {
        let code = if enabled { WOL_TRUE } else { WOL_FALSE };
        self.shared.wol_enabled.store(code, Ordering::Release);
        if !self.shared.enabled {
            return Err("未启用信令服务器".to_string());
        }
        let mac_addr = self.shared.current_mac_addr_opt();
        self.shared.send_msg(&OutgoingSignalMsg::UpdateAssistState {
            allow_remote_assist: None,
            allow_remote_control: None,
            mac_addr,
            wol_enabled: Some(enabled),
        })
    }

    /// 更新本机用于 Wake-on-LAN 上报的主网卡单播 MAC 地址（自动校验并规范化为 `aa:bb:cc:dd:ee:ff`）。
    ///
    /// - 传入 `Some(raw)` 时严格校验单播 MAC 格式，合法后缓存并立即经 `UpdateAssistState` 同步至服务端；
    /// - 传入 `None` 时仅清空本地缓存（不向服务端发送空负载帧）。
    pub fn set_mac_addr(&self, mac: Option<String>) -> Result<(), String> {
        let normalized = match mac {
            Some(raw) => {
                let norm = crate::wol::normalize_mac_addr(&raw).ok_or_else(|| {
                    "MAC 地址格式无效（要求冒号或短横线分隔的合法单播 MAC 地址）".to_string()
                })?;
                Some(norm)
            }
            None => None,
        };
        *self
            .shared
            .mac_addr
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = normalized.clone();
        let Some(norm_mac) = normalized else {
            return Ok(());
        };
        if !self.shared.enabled {
            return Err("未启用信令服务器".to_string());
        }
        self.shared.send_msg(&OutgoingSignalMsg::UpdateAssistState {
            allow_remote_assist: None,
            allow_remote_control: None,
            mac_addr: Some(norm_mac),
            wol_enabled: self.shared.current_wol_enabled_opt(),
        })
    }

    /// 向服务端发起 Wake-on-LAN 远程开机请求（`wol_request`）并阻塞等待匹配 `request_id` 的 `wol_ack`。
    ///
    /// - 服务端返回 `wol_ack` 时返回 `Ok(WolAckResult)`（若 `ok == false`，同步在 `ui_error` 中填充规范
    ///   [`crate::ui_error::UiError`]，如 `wol.disabled` / `wol.no_relay_peer` / `wol.send_failed` / `network.rate_limited`）；
    /// - 本地未启用信令、设备码非法、写帧失败、连接断开或等待超时时返回 `Err(UiError)`。
    #[allow(clippy::result_large_err)]
    pub fn request_wol(
        &self,
        target_device_id: &str,
        timeout: Duration,
    ) -> Result<WolAckResult, crate::ui_error::UiError> {
        let platform = crate::ui_error::current_platform();
        if !self.shared.enabled {
            return Err(crate::ui_error::resolve_ui_error(
                crate::ui_error::codes::NETWORK_UNREACHABLE,
                platform,
                &[],
                None,
                Some("未启用信令服务器，无法发送远程开机指令".to_string()),
            ));
        }
        let normalized = parse_device_id_input(target_device_id).ok_or_else(|| {
            crate::ui_error::resolve_ui_error(
                crate::ui_error::codes::VALIDATION_INVALID_INPUT,
                platform,
                &[],
                None,
                Some("目标设备码格式无效，请输入 9 位数字设备码".to_string()),
            )
        })?;

        let request_id = format!("wol-{}", random_hex(8));
        let (tx, rx) = mpsc::sync_channel(1);
        {
            let mut pending = self
                .shared
                .pending_wols
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.shared.stop_flag.load(Ordering::Acquire) {
                return Err(crate::ui_error::resolve_ui_error(
                    crate::ui_error::codes::SESSION_CANCELLED,
                    platform,
                    &[],
                    None,
                    Some("信令客户端已停止".to_string()),
                ));
            }
            pending.insert(request_id.clone(), tx);
        }

        let msg = OutgoingSignalMsg::WolRequest {
            request_id: request_id.clone(),
            target_device_id: normalized,
        };
        if let Err(err) = self.shared.send_msg(&msg) {
            self.shared
                .pending_wols
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&request_id);
            return Err(crate::ui_error::classify_signal_error(&err, platform));
        }

        match rx.recv_timeout(timeout) {
            Ok(res) => res,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.shared
                    .pending_wols
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                Err(crate::ui_error::resolve_ui_error(
                    crate::ui_error::codes::NETWORK_TIMEOUT,
                    platform,
                    &[],
                    None,
                    Some("等待服务器返回远程开机响应超时".to_string()),
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.shared
                    .pending_wols
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id);
                Err(crate::ui_error::resolve_ui_error(
                    crate::ui_error::codes::SESSION_DISCONNECTED,
                    platform,
                    &[],
                    None,
                    Some("信令连接已断开".to_string()),
                ))
            }
        }
    }

    /// 查询最近一次 `device_status_changed` 广播记录的目标设备 `wol_capable` 状态。
    pub fn device_wol_capable(&self, device_id: &str) -> Option<bool> {
        let key = parse_device_id_input(device_id).unwrap_or_else(|| device_id.trim().to_string());
        self.shared
            .device_wol_capable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .copied()
    }

    /// 返回当前已缓存的同账号设备 `wol_capable` 状态快照（键为 9 位规范设备码）。
    pub fn device_wol_capable_snapshot(&self) -> HashMap<String, bool> {
        self.shared
            .device_wol_capable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 非阻塞拉取一条同账号设备 Wake-on-LAN 能力增量状态事件（有界队列）。
    pub fn try_recv_device_wol_status(&self) -> Option<DeviceWolCapabilityEvent> {
        self.shared
            .device_wol_events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    /// 返回当前信令连接状态快照。
    pub fn status(&self) -> ServerStatusSnapshot {
        self.shared
            .status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 非阻塞拉取一条服务端推送的入站中继会话（本端作为被控端接收）。
    pub fn try_recv_incoming(&self) -> Option<RelayIncoming> {
        self.shared
            .incoming
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    /// 非阻塞拉取一条状态变化快照（供无回调模式轮询状态更新）。
    pub fn try_recv_status(&self) -> Option<ServerStatusSnapshot> {
        self.shared
            .status_updates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    /// 非阻塞拉取一条同账号设备上下线/协助状态变更通知（有界队列）。
    pub fn try_recv_device_status(&self) -> Option<DeviceStatusEvent> {
        self.shared
            .device_status_events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    /// 非阻塞拉取一条服务端强制踢线原始原因码（如 `account_disabled`、`device_unbound`、`cert_revoked` 等）。
    pub fn try_recv_kicked_reason(&self) -> Option<String> {
        self.shared
            .kicked_reasons
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    /// 触发后台信令线程立即停止并唤醒所有在途连接请求（不阻塞等待线程 `join`）。
    ///
    /// 适用于 `Arc<SignalClientHandle>` 仍存在其他短生命周期引用时，确保旧 TCP 连接
    /// 在启动新客户端前立刻断开，避免触发服务端 `duplicate_login`。
    pub fn request_stop(&self) {
        self.shared.signal_stop();
    }

    /// 优雅停止后台信令线程并等待其退出，同时尽力异步清理残留 UPnP 映射租约。
    pub fn stop(&mut self) {
        self.shared.signal_stop();
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
        self.shared.cleanup_upnp_on_stop();
    }

    /// 轻量触发 `RCSP` 探测刷新并返回当前已知的本地 UDP 端口、公网/LAN 候选与 NAT 画像（供运行期 `Relay -> P2P` 复探）。
    pub fn snapshot_p2p_reprobe_info(
        &self,
    ) -> (
        Option<u16>,
        Vec<String>,
        NatType,
        Option<i16>,
        Option<PortRangeHint>,
    ) {
        if self.shared.proxy_active.load(Ordering::Acquire) {
            return (None, Vec::new(), NatType::Unknown, None, None);
        }
        self.shared.trigger_lightweight_probe_refresh();
        thread::sleep(Duration::from_millis(20));
        self.shared.trigger_lightweight_probe_refresh();

        let port = self.shared.local_udp_port.load(Ordering::Acquire);
        let is_v6 = self.shared.local_udp_is_ipv6.load(Ordering::Acquire);
        let profile = self
            .shared
            .nat_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (nat_type, nat_delta, nat_range) =
            (profile.nat_type, profile.port_delta, profile.port_range);

        let mut addrs = Vec::new();
        for pub_addr in [profile.public_v4, profile.public_v6].into_iter().flatten() {
            let s = canonicalize_socket_addr(pub_addr).to_string();
            if !addrs.contains(&s) {
                addrs.push(s);
            }
        }
        for lan in self
            .shared
            .current_effective_lan_addrs(&self.shared.lan_addrs, port, is_v6)
        {
            if !addrs.contains(&lan) {
                addrs.push(lan);
            }
        }
        (
            (port != 0).then_some(port),
            addrs,
            nat_type,
            nat_delta,
            nat_range,
        )
    }
}

impl std::fmt::Debug for SignalClientHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalClientHandle")
            .field("enabled", &self.shared.enabled)
            .field(
                "local_udp_port",
                &self.shared.local_udp_port.load(Ordering::Acquire),
            )
            .finish()
    }
}

impl Drop for SignalClientHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 清洗上报的 `hostname`：去除控制字符与 `\0`，裁剪首尾空白并按 UTF-8 字符边界截断至 `<= 128` 字节。
fn sanitize_hostname(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|&ch| !ch.is_control() && ch != '\0')
        .collect();
    let trimmed = cleaned.trim();
    let mut end = 0usize;
    for (idx, ch) in trimmed.char_indices() {
        let next = idx + ch.len_utf8();
        if next > MAX_HOSTNAME_BYTES {
            break;
        }
        end = next;
    }
    trimmed[..end].to_string()
}

/// 清洗上报的 `lan_addrs`：仅保留 `1..=64` 字节且全部为 ASCII 可见图形字符的项，最多取 16 条。
fn sanitize_lan_addrs(addrs: &[String]) -> Vec<String> {
    addrs
        .iter()
        .filter(|s| {
            !s.is_empty()
                && s.len() <= MAX_LAN_ADDR_BYTES
                && s.bytes().all(|b| b.is_ascii_graphic())
        })
        .take(MAX_LAN_ADDRS)
        .cloned()
        .collect()
}

/// 判断候选 IP 是否允许上报给信令作为打洞候选地址：
/// - 拒绝未指定、多播、IPv4 广播、IPv4 链路本地 (`169.254.0.0/16`) 与 IPv6 单播链路本地 (`fe80::/10`)；
/// - 仅当 `allow_loopback == true`（连接回环信令服务器做同机联调）时允许回环地址 (`127.0.0.0/8` / `::1`)。
fn is_usable_candidate_ip(ip: IpAddr, allow_loopback: bool) -> bool {
    match canonicalize_ip(ip) {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                allow_loopback
            } else {
                crate::lan_discovery::is_usable_lan_ipv4(v4)
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            if v6.is_loopback() {
                return allow_loopback;
            }
            true
        }
    }
}

/// 将清洗后的 `lan_addrs` 端口改写为持久化 UDP 探测端口，并按探测套接字地址族与可用性过滤：
/// - 当 `local_udp_port == 0`（初始注册尚未绑定探测端口，或探测绑定失败）时返回空列表，
///   绝不泄漏 Host QUIC 直连端口（如 `:9901`）作为 P2P 打洞候选；
/// - 当 `local_udp_port != 0` 时，改写并上报与 `local_udp_is_ipv6` 同地址族且通过 [`is_usable_candidate_ip`]
///   校验的局域网地址，并始终保留通过 [`is_global_unicast_ipv6`] 的全球单播 IPv6 地址
///   （即使 `local_udp_is_ipv6 == false` 也不丢弃，仍严格过滤链路本地/ULA/回环）。
fn effective_lan_addrs(
    lan_addrs: &[String],
    local_udp_port: u16,
    local_udp_is_ipv6: bool,
    allow_loopback: bool,
) -> Vec<String> {
    if local_udp_port == 0 {
        return Vec::new();
    }
    let cleaned = sanitize_lan_addrs(lan_addrs);
    let mut out = Vec::with_capacity(cleaned.len());
    for raw in cleaned {
        let Some(ip) = extract_canonical_lan_ip(&raw, local_udp_port) else {
            continue;
        };
        let is_global_v6 = matches!(ip, IpAddr::V6(v6) if is_global_unicast_ipv6(v6));
        if (!is_global_v6 && ip.is_ipv6() != local_udp_is_ipv6)
            || !is_usable_candidate_ip(ip, allow_loopback)
        {
            continue;
        }
        let rewritten = format_host_port(&ip.to_string(), local_udp_port);
        if rewritten.len() <= MAX_LAN_ADDR_BYTES && !out.contains(&rewritten) {
            out.push(rewritten);
        }
    }
    out
}

fn extract_canonical_lan_ip(raw: &str, fallback_port: u16) -> Option<IpAddr> {
    if let Ok(sock) = raw.parse::<SocketAddr>() {
        return Some(canonicalize_ip(sock.ip()));
    }
    let trimmed = raw.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(canonicalize_ip(ip));
    }
    if let Ok((host, _)) = parse_server_input(raw, fallback_port) {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(canonicalize_ip(ip));
        }
    }
    None
}

fn is_public_routable_ip(ip: IpAddr) -> bool {
    match canonicalize_ip(ip) {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            let is_link_local = (seg0 & 0xffc0) == 0xfe80;
            let is_ula = (seg0 & 0xfe00) == 0xfc00;
            !v6.is_loopback()
                && !is_link_local
                && !is_ula
                && !v6.is_unspecified()
                && !v6.is_multicast()
        }
    }
}

/// 将候选地址列表拆分为公网候选与局域网候选（按需补齐初始信令观测到的备用公网端点）。
pub(crate) fn split_public_and_lan_addrs(
    addrs: &[String],
    fallback_public: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut public_addrs = Vec::new();
    let mut lan_addrs = Vec::new();
    for raw in addrs {
        let Ok(sock) = raw.trim().parse::<SocketAddr>() else {
            continue;
        };
        let sock = canonicalize_socket_addr(sock);
        if sock.port() == 0 {
            continue;
        }
        let s = sock.to_string();
        if is_public_routable_ip(sock.ip()) {
            if !public_addrs.contains(&s) {
                public_addrs.push(s);
            }
        } else if !lan_addrs.contains(&s) {
            lan_addrs.push(s);
        }
    }
    let has_v4 = public_addrs
        .iter()
        .any(|a| a.parse::<SocketAddr>().is_ok_and(|s| s.is_ipv4()));
    let has_v6 = public_addrs
        .iter()
        .any(|a| a.parse::<SocketAddr>().is_ok_and(|s| s.is_ipv6()));
    for raw in fallback_public {
        let Ok(sock) = raw.trim().parse::<SocketAddr>() else {
            continue;
        };
        let sock = canonicalize_socket_addr(sock);
        if sock.port() == 0 || !is_public_routable_ip(sock.ip()) {
            continue;
        }
        if (sock.is_ipv4() && has_v4) || (sock.is_ipv6() && has_v6) {
            continue;
        }
        let s = sock.to_string();
        if !public_addrs.contains(&s) {
            public_addrs.push(s);
        }
    }
    (public_addrs, lan_addrs)
}

fn validate_udp_probe_device_id(device_id: &str) -> Result<&[u8], String> {
    let id_bytes = device_id.as_bytes();
    let valid = id_bytes.len() == 9
        && id_bytes.iter().all(u8::is_ascii_digit)
        && (id_bytes == b"000000000" || matches!(id_bytes[0], b'1'..=b'9'));
    if !valid {
        return Err("UDP 探测包要求 9 位数字设备码".to_string());
    }
    Ok(id_bytes)
}

/// 构造 22 字节 UDP `RCSP` v1 公网端点探测包：
/// `[b"RCSP"][0x01][device_id 9B ASCII][nonce 8B]`。
///
/// 接受匿名探测码 `"000000000"` 或首位为 `'1'..='9'` 的 9 位永久设备码（对齐 `server/docs/02-protocol-and-api.md` §3.1）。
pub fn build_udp_probe_packet(
    device_id: &str,
    nonce: [u8; 8],
) -> Result<[u8; UDP_PROBE_LEN], String> {
    let id_bytes = validate_udp_probe_device_id(device_id)?;
    let mut pkt = [0u8; UDP_PROBE_LEN];
    pkt[0..4].copy_from_slice(UDP_PROBE_MAGIC);
    pkt[4] = UDP_PROTO_VERSION;
    pkt[5..14].copy_from_slice(id_bytes);
    pkt[14..22].copy_from_slice(&nonce);
    Ok(pkt)
}

/// 构造 38 字节 UDP `RCSP` v2 令牌认证公网端点探测包：
/// `[b"RCSP"(4B)][0x02(1B)][device_id(9B)][nonce(8B)][token(16B)]`。
///
/// 用于跨 IP 族双栈探测及多出口 NAT 场景，服务端校验 16 字节随机令牌后免除 TCP/UDP 同 IP 限制。
pub fn build_udp_probe_packet_v2(
    device_id: &str,
    nonce: [u8; 8],
    token: [u8; 16],
) -> Result<[u8; UDP_PROBE_V2_LEN], String> {
    let id_bytes = validate_udp_probe_device_id(device_id)?;
    let mut pkt = [0u8; UDP_PROBE_V2_LEN];
    pkt[0..4].copy_from_slice(UDP_PROBE_MAGIC);
    pkt[4] = UDP_PROTO_VERSION_V2;
    pkt[5..14].copy_from_slice(id_bytes);
    pkt[14..22].copy_from_slice(&nonce);
    pkt[22..38].copy_from_slice(&token);
    Ok(pkt)
}

/// 解析 20 字节（IPv4）或 32 字节（IPv6）UDP `RCSA` 响应包，校验魔数、版本与 `ip_len` 并返回 `(观测公网 SocketAddr, 回显 nonce)`。
pub fn parse_udp_answer_packet(buf: &[u8]) -> Option<(SocketAddr, [u8; 8])> {
    if buf.len() < 20 || &buf[0..4] != UDP_ANSWER_MAGIC || buf[4] != UDP_ANSWER_VERSION {
        return None;
    }
    let ip_len = usize::from(buf[5]);
    if ip_len != 4 && ip_len != 16 {
        return None;
    }
    let expected_len = 6 + ip_len + 2 + 8;
    if buf.len() != expected_len {
        return None;
    }
    let ip = if ip_len == 4 {
        IpAddr::V4(Ipv4Addr::new(buf[6], buf[7], buf[8], buf[9]))
    } else {
        let octets: [u8; 16] = buf[6..22].try_into().ok()?;
        canonicalize_ip(IpAddr::V6(Ipv6Addr::from(octets)))
    };
    let port_offset = 6 + ip_len;
    let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
    let nonce: [u8; 8] = buf[port_offset + 2..port_offset + 10].try_into().ok()?;
    Some((SocketAddr::new(ip, port), nonce))
}

fn parse_udp_probe_token(raw: Option<&str>) -> Option<[u8; 16]> {
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

/// 测试信令端口与中继端口的 TCP 连通性，并返回含实测 RTT（毫秒）的可读结果文案。
///
/// 自动遵循进程级活跃出站代理配置 [`crate::proxy::active_proxy_config`]。
pub fn probe_server_connectivity(
    host: &str,
    signal_port: u16,
    relay_port: u16,
    timeout: Duration,
) -> Result<String, String> {
    let proxy = crate::proxy::active_proxy_config();
    probe_server_connectivity_with_proxy(host, signal_port, relay_port, timeout, &proxy)
}

/// 使用显式出站代理配置测试信令端口与中继端口的 TCP 连通性，返回含实测 RTT（毫秒）的可读结果文案。
pub fn probe_server_connectivity_with_proxy(
    host: &str,
    signal_port: u16,
    relay_port: u16,
    timeout: Duration,
    proxy: &crate::proxy::ProxyConfig,
) -> Result<String, String> {
    let (clean_host, effective_signal_port) = parse_server_input(host, signal_port)?;
    if effective_signal_port == 0 || relay_port == 0 {
        return Err("信令端口与中继端口必须为 1–65535".to_string());
    }

    let signal_addr = format_host_port(&clean_host, effective_signal_port);
    let relay_addr = format_host_port(&clean_host, relay_port);

    let signal_ms = tcp_probe_once(&clean_host, effective_signal_port, timeout, proxy)
        .map_err(|e| format!("信令端口 {signal_addr} 不可达：{e}"))?;
    let relay_ms = tcp_probe_once(&clean_host, relay_port, timeout, proxy).map_err(|e| {
        format!("信令端口可达 ({signal_ms}ms)，但中继端口 {relay_addr} 不可达：{e}")
    })?;

    Ok(format!(
        "连接正常 · 信令 {signal_addr} ({signal_ms}ms) / 中继 {relay_addr} ({relay_ms}ms)"
    ))
}

fn tcp_probe_once(
    host: &str,
    port: u16,
    timeout: Duration,
    proxy: &crate::proxy::ProxyConfig,
) -> Result<u128, String> {
    let start = Instant::now();
    let stream = crate::proxy::dial_tcp_with_proxy(host, port, timeout, None, proxy)
        .map_err(|e| e.to_string())?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(start.elapsed().as_millis())
}

fn should_reset_backoff(
    healthy_duration: Duration,
    kicked: bool,
    stable_threshold: Duration,
) -> bool {
    !kicked && healthy_duration >= stable_threshold
}

/// 将服务端下发的踢线/拒绝原因枚举映射为 `(是否终止重连, 本地化中文说明)`。
pub fn classify_kicked_reason(reason: &str) -> (bool, String) {
    let trimmed = reason.trim();
    if trimmed.eq_ignore_ascii_case("replaced_by_new_connection") {
        (
            true,
            "当前设备已在其他位置登录，信令连接已被替换，已停止自动重连".to_string(),
        )
    } else if trimmed.eq_ignore_ascii_case("disabled_by_admin") {
        (true, "当前设备已被管理员禁用，已停止自动重连".to_string())
    } else if trimmed.eq_ignore_ascii_case("account_disabled") {
        (true, "当前账号已被禁用，已停止自动重连".to_string())
    } else if trimmed.eq_ignore_ascii_case("account_deleted")
        || trimmed.eq_ignore_ascii_case("user_deleted")
    {
        (true, "当前账号已被删除，已停止自动重连".to_string())
    } else if trimmed.eq_ignore_ascii_case("password_changed")
        || trimmed.eq_ignore_ascii_case("account_updated")
        || trimmed.eq_ignore_ascii_case("token_revoked")
    {
        (true, "账号凭证或安全状态已变更，请重新登录".to_string())
    } else if trimmed.eq_ignore_ascii_case("device_unbound") {
        (true, "当前设备已被解绑，请重新登录绑定".to_string())
    } else if trimmed.eq_ignore_ascii_case("cert_revoked") {
        (true, "当前设备证书已被吊销，请重新登录".to_string())
    } else if trimmed.eq_ignore_ascii_case("user_logout") {
        (true, "当前会话已退出登录，已停止自动重连".to_string())
    } else if trimmed.is_empty() {
        (false, "连接已被服务器断开".to_string())
    } else {
        (false, format!("被服务器断开：{trimmed}"))
    }
}

/// 若信令踢线/拒绝原因为账号失效或凭证吊销（需强制退登重登），返回对应的中文提示。
///
/// 排除 `server_shutdown`（服务器维护关闭）与 `replaced_by_new_connection`（同设备连接替换）。
pub fn classify_auth_revocation_kick(reason: &str) -> Option<String> {
    let trimmed = reason.trim();
    if trimmed.eq_ignore_ascii_case("server_shutdown")
        || trimmed.eq_ignore_ascii_case("replaced_by_new_connection")
    {
        return None;
    }
    let (is_terminal, msg) = classify_kicked_reason(trimmed);
    if is_terminal {
        Some(msg)
    } else {
        None
    }
}

fn worker_loop(
    shared: Arc<SharedState>,
    cfg: ServerConfig,
    hostname: String,
    lan_addrs: Vec<String>,
    timing: SignalTiming,
    on_status: &mut dyn FnMut(ServerStatusSnapshot),
) {
    let mut backoff_idx = 0usize;
    let mut cached_device_id = cfg.cached_device_id.clone();
    let mut expired_token: Option<String> = None;
    let default_signal_addr = format_host_port(&cfg.server_host, cfg.signal_port);
    let default_relay_addr = format_host_port(&cfg.server_host, cfg.relay_port);

    while !shared.stop_flag.load(Ordering::Acquire) {
        shared.set_status(
            build_snapshot(
                &cfg,
                ServerConnectionState::Connecting,
                cached_device_id.clone(),
                None,
                Some(default_signal_addr.clone()),
                Some(default_relay_addr.clone()),
            ),
            on_status,
        );

        match run_single_connection(
            &shared,
            &cfg,
            &hostname,
            &lan_addrs,
            &mut cached_device_id,
            &mut expired_token,
            &default_signal_addr,
            &default_relay_addr,
            timing,
            on_status,
        ) {
            ConnectionOutcome::Stopped => break,
            ConnectionOutcome::TerminalError(reason) => {
                shared.clear_active_writer();
                shared.fail_all_pending(&reason);
                if !shared.stop_flag.load(Ordering::Acquire) {
                    shared.set_status(
                        build_snapshot(
                            &cfg,
                            ServerConnectionState::Error,
                            cached_device_id.clone(),
                            Some(reason),
                            Some(default_signal_addr.clone()),
                            Some(default_relay_addr.clone()),
                        ),
                        on_status,
                    );
                }
                break;
            }
            ConnectionOutcome::ConnectedThenDropped {
                reason,
                healthy_duration,
                kicked,
            } => {
                if should_reset_backoff(healthy_duration, kicked, timing.stable_threshold) {
                    backoff_idx = 0;
                }
                shared.clear_active_writer();
                shared.fail_all_pending(&reason);
                if shared.stop_flag.load(Ordering::Acquire) {
                    break;
                }
                shared.set_status(
                    build_snapshot(
                        &cfg,
                        ServerConnectionState::Error,
                        cached_device_id.clone(),
                        Some(reason),
                        Some(default_signal_addr.clone()),
                        Some(default_relay_addr.clone()),
                    ),
                    on_status,
                );
            }
            ConnectionOutcome::ConnectFailed(reason) => {
                shared.clear_active_writer();
                shared.fail_all_pending(&reason);
                if shared.stop_flag.load(Ordering::Acquire) {
                    break;
                }
                shared.set_status(
                    build_snapshot(
                        &cfg,
                        ServerConnectionState::Error,
                        cached_device_id.clone(),
                        Some(reason),
                        Some(default_signal_addr.clone()),
                        Some(default_relay_addr.clone()),
                    ),
                    on_status,
                );
            }
        }

        let (wait, sleep_epoch) = {
            let _guard = shared.stop_lock.lock().unwrap_or_else(|e| e.into_inner());
            let epoch = shared.reconnect_epoch.load(Ordering::Acquire);
            let fast = shared.fast_reconnect.swap(false, Ordering::AcqRel);
            let reset_backoff = shared
                .reset_backoff_on_reconnect
                .swap(false, Ordering::AcqRel);
            if reset_backoff {
                backoff_idx = 0;
                (FAST_RECONNECT_DELAY, epoch)
            } else if fast && backoff_idx == 0 {
                backoff_idx = (backoff_idx + 1).min(timing.backoffs.len() - 1);
                (FAST_RECONNECT_DELAY, epoch)
            } else {
                let w = timing.backoffs[backoff_idx];
                backoff_idx = (backoff_idx + 1).min(timing.backoffs.len() - 1);
                (w, epoch)
            }
        };
        match shared.sleep_or_stop(wait, sleep_epoch) {
            SleepWake::Stopped => break,
            SleepWake::Reconnect => {
                let _guard = shared.stop_lock.lock().unwrap_or_else(|e| e.into_inner());
                shared.fast_reconnect.store(false, Ordering::Release);
                if shared
                    .reset_backoff_on_reconnect
                    .swap(false, Ordering::AcqRel)
                {
                    backoff_idx = 0;
                }
            }
            SleepWake::TimedOut => {}
        }
    }

    shared.clear_active_writer();
    shared.fail_all_pending("信令客户端已停止");
}

enum ConnectionOutcome {
    Stopped,
    ConnectFailed(String),
    ConnectedThenDropped {
        reason: String,
        healthy_duration: Duration,
        kicked: bool,
    },
    TerminalError(String),
}

enum IncomingAction {
    Continue,
    Disconnect { reason: String, kicked: bool },
    Terminal(String),
}

fn build_signal_tls_config(ca_cert_pem: &str) -> Result<ClientConfig, String> {
    let mut reader = io::BufReader::new(ca_cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| format!("解析信令 Root CA PEM 失败：{e}"))?;
    if certs.is_empty() {
        return Err("信令 Root CA PEM 不包含任何证书".to_string());
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| format!("添加信令 Root CA 证书失败：{e}"))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("配置信令 TLS 1.3 版本失败：{e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth()
        .pipe_ok()
}

trait SignalPipeOk: Sized {
    fn pipe_ok<E>(self) -> Result<Self, E> {
        Ok(self)
    }
}
impl SignalPipeOk for ClientConfig {}

fn parse_signal_server_name(host: &str) -> Result<ServerName<'static>, String> {
    let clean = host
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host.trim());
    ServerName::try_from(clean.to_string())
        .map_err(|e| format!("无效信令 TLS 主机名 {host:?}：{e}"))
}

enum TlsHandshakeErr {
    Stopped,
    Reconnecting,
    Failed(String),
}

fn complete_tls_handshake(
    conn: &mut ClientConnection,
    tcp: &mut TcpStream,
    deadline: Instant,
    stop_flag: &AtomicBool,
    reconnect_epoch: (&AtomicU64, u64),
) -> Result<(), TlsHandshakeErr> {
    while conn.is_handshaking() {
        if stop_flag.load(Ordering::Acquire) {
            return Err(TlsHandshakeErr::Stopped);
        }
        if reconnect_epoch.0.load(Ordering::Acquire) != reconnect_epoch.1 {
            return Err(TlsHandshakeErr::Reconnecting);
        }
        if Instant::now() >= deadline {
            return Err(TlsHandshakeErr::Failed("信令 TLS 1.3 握手超时".to_string()));
        }
        match conn.complete_io(tcp) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue;
            }
            Err(e) => {
                if reconnect_epoch.0.load(Ordering::Acquire) != reconnect_epoch.1 {
                    return Err(TlsHandshakeErr::Reconnecting);
                }
                return Err(TlsHandshakeErr::Failed(format!(
                    "信令 TLS 1.3 握手失败：{e}"
                )));
            }
        }
    }
    Ok(())
}

enum SignalReader {
    Plain(TcpStream),
    Tls {
        stream: SharedTlsStream,
        writer_waiting: Arc<AtomicUsize>,
    },
}

impl SignalReader {
    fn read_frame(&mut self, stop_flag: &AtomicBool) -> FrameRead {
        match self {
            Self::Plain(stream) => read_signal_frame_from_io(stream, stop_flag),
            Self::Tls {
                stream: shared_tls,
                writer_waiting,
            } => {
                // 若写线程正排队等待发送信令请求（如 `request_connect`），短暂让出避免非公平互斥锁饥饿。
                if writer_waiting.load(Ordering::Acquire) > 0 {
                    thread::sleep(Duration::from_millis(1));
                }
                let mut guard = shared_tls.lock().unwrap_or_else(|e| e.into_inner());
                let Some(tls) = guard.as_mut() else {
                    return FrameRead::Eof;
                };
                read_signal_frame_from_io(&mut **tls, stop_flag)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_single_connection(
    shared: &Arc<SharedState>,
    cfg: &ServerConfig,
    hostname: &str,
    lan_addrs: &[String],
    cached_device_id: &mut Option<String>,
    expired_token: &mut Option<String>,
    default_signal_addr: &str,
    default_relay_addr: &str,
    timing: SignalTiming,
    on_status: &mut dyn FnMut(ServerStatusSnapshot),
) -> ConnectionOutcome {
    if shared.stop_flag.load(Ordering::Acquire) {
        return ConnectionOutcome::Stopped;
    }
    let conn_reconnect_epoch = shared.reconnect_epoch.load(Ordering::Acquire);

    // 在拨号建连前完成 Access Token 获取/强制刷新，避免 HTTP 刷新往返挤占服务端
    // handshake_timeout（10s），并在刷新瞬态失败时保留 expired_token 供下轮重试。
    let access_token = match (&shared.token_refresher, expired_token.take()) {
        (Some(refresher), Some(stale)) => match refresher(&stale) {
            Ok(token) => Some(token),
            Err(err) => {
                *expired_token = Some(stale);
                return ConnectionOutcome::ConnectFailed(format!(
                    "刷新失效信令认证令牌失败：{err}"
                ));
            }
        },
        _ => match &shared.token_provider {
            Some(provider) => match provider() {
                Ok(token) => Some(token),
                Err(err) => {
                    return ConnectionOutcome::ConnectFailed(format!(
                        "获取信令认证令牌失败：{err}"
                    ));
                }
            },
            None => None,
        },
    };
    if shared.stop_flag.load(Ordering::Acquire) {
        return ConnectionOutcome::Stopped;
    }
    if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
        return ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason());
    }
    let mut sent_access_token = access_token.clone();

    let effective_proxy = shared.effective_proxy_config();
    let (stream, used_proxy) = match dial_tcp_with_epoch_and_proxy(
        default_signal_addr,
        HANDSHAKE_TIMEOUT,
        &shared.stop_flag,
        Some((&shared.reconnect_epoch, conn_reconnect_epoch)),
        &effective_proxy,
    ) {
        Ok(s) => s,
        Err(DialError::Stopped) => return ConnectionOutcome::Stopped,
        Err(DialError::Reconnecting) => {
            return ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason());
        }
        Err(DialError::Failed(err)) => return ConnectionOutcome::ConnectFailed(err),
    };
    shared.proxy_active.store(used_proxy, Ordering::Release);
    if shared.stop_flag.load(Ordering::Acquire) {
        let _ = stream.shutdown(Shutdown::Both);
        return ConnectionOutcome::Stopped;
    }
    if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
        let _ = stream.shutdown(Shutdown::Both);
        return ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason());
    }

    let _ = stream.set_nodelay(true);
    configure_tcp_keepalive(&stream);
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_read_timeout(Some(READ_POLL_TIMEOUT));
    let peer_addr = stream.peer_addr().ok();

    // 在握手前即注册独立 shutdown_stream，确保 stop() / trigger_reconnect() 可瞬间打断握手读写。
    let shutdown_clone = match stream.try_clone() {
        Ok(s) => s,
        Err(err) => {
            return ConnectionOutcome::ConnectFailed(format!("克隆信令关闭句柄失败：{err}"));
        }
    };
    {
        let mut shutdown_guard = shared
            .shutdown_stream
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if shared.stop_flag.load(Ordering::Acquire) {
            drop(shutdown_guard);
            let _ = stream.shutdown(Shutdown::Both);
            return ConnectionOutcome::Stopped;
        }
        if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
            drop(shutdown_guard);
            let _ = stream.shutdown(Shutdown::Both);
            return ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason());
        }
        *shutdown_guard = Some(shutdown_clone);
    }

    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    if cfg.use_https && cfg.ca_cert_pem.is_none() {
        let _ = stream.shutdown(Shutdown::Both);
        return ConnectionOutcome::ConnectFailed(
            "已开启 TLS/HTTPS 安全传输，但缺少服务器 Root CA 证书，拒绝降级明文信令连接"
                .to_string(),
        );
    }
    let use_tls = cfg.use_https && cfg.ca_cert_pem.is_some();
    let (mut reader, writer_template) = if use_tls {
        let ca_pem = cfg.ca_cert_pem.as_deref().expect("checked is_some");
        let tls_cfg = match build_signal_tls_config(ca_pem) {
            Ok(c) => c,
            Err(err) => return ConnectionOutcome::ConnectFailed(err),
        };
        let server_name = match parse_signal_server_name(&cfg.server_host) {
            Ok(s) => s,
            Err(err) => return ConnectionOutcome::ConnectFailed(err),
        };
        let mut conn = match ClientConnection::new(Arc::new(tls_cfg), server_name) {
            Ok(c) => c,
            Err(err) => {
                return ConnectionOutcome::ConnectFailed(format!("初始化信令 TLS 会话失败：{err}"));
            }
        };
        let mut tcp_for_tls = stream;
        if let Err(err) = complete_tls_handshake(
            &mut conn,
            &mut tcp_for_tls,
            handshake_deadline,
            &shared.stop_flag,
            (&shared.reconnect_epoch, conn_reconnect_epoch),
        ) {
            let _ = tcp_for_tls.shutdown(Shutdown::Both);
            return match err {
                TlsHandshakeErr::Stopped => ConnectionOutcome::Stopped,
                TlsHandshakeErr::Reconnecting => {
                    ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason())
                }
                TlsHandshakeErr::Failed(msg) => ConnectionOutcome::ConnectFailed(msg),
            };
        }
        let shared_tls = Arc::new(Mutex::new(Some(Box::new(StreamOwned::new(
            conn,
            tcp_for_tls,
        )))));
        let writer_waiting = Arc::new(AtomicUsize::new(0));
        (
            SignalReader::Tls {
                stream: Arc::clone(&shared_tls),
                writer_waiting: Arc::clone(&writer_waiting),
            },
            SignalWriter::Tls {
                stream: shared_tls,
                writer_waiting,
            },
        )
    } else {
        let writer_clone = match stream.try_clone() {
            Ok(s) => s,
            Err(err) => {
                return ConnectionOutcome::ConnectFailed(format!("克隆信令套接字失败：{err}"));
            }
        };
        (
            SignalReader::Plain(stream),
            SignalWriter::Plain(writer_clone),
        )
    };

    let clean_hostname = sanitize_hostname(hostname);
    let clean_lan_addrs = sanitize_lan_addrs(lan_addrs);
    let (nat_type, nat_port_delta, nat_port_range) = shared.current_nat_wire_fields();
    // 初始注册时尚未绑定持久化 UDP 探测端口（local_udp_port == 0），必须上报空列表，
    // 绝不把未改写的 `:9901` 泄漏为 P2P 打洞目标；待 `Registered` 后由紧随的 Heartbeat 同步。
    let reg_msg = OutgoingSignalMsg::Register {
        device_id: cached_device_id.clone(),
        device_key: cfg.device_key.clone(),
        hostname: clean_hostname,
        os: std::env::consts::OS.to_string(),
        app_version: crate::platform::current_app_version(),
        arch: crate::platform::current_app_arch().to_string(),
        device_group: "default".to_string(),
        lan_addrs: Vec::new(),
        access_token,
        device_pubkey: shared.device_pubkey.clone(),
        allow_remote_assist: shared.current_allow_assist_opt(),
        allow_remote_control: shared.current_allow_remote_control_opt(),
        mac_addr: shared.current_mac_addr_opt(),
        wol_enabled: shared.current_wol_enabled_opt(),
        nat_type,
        nat_port_delta,
        nat_port_range,
        rcp2_v2: true,
    };
    let reg_sent_at = Instant::now();
    let send_reg_res = match &reader {
        SignalReader::Plain(_) => match &writer_template {
            SignalWriter::Plain(w) => match w.try_clone() {
                Ok(mut w_clone) => write_signal_frame_plain(&mut w_clone, &reg_msg),
                Err(e) => Err(format!("克隆信令写流失败：{e}")),
            },
            SignalWriter::Tls { .. } => unreachable!(),
        },
        SignalReader::Tls {
            stream: shared_tls, ..
        } => {
            let mut guard = shared_tls.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_mut() {
                Some(tls) => write_signal_frame_tls(tls, &reg_msg),
                None => Err("信令 TLS 连接已关闭".to_string()),
            }
        }
    };
    if let Err(err) = send_reg_res {
        if shared.stop_flag.load(Ordering::Acquire) {
            return ConnectionOutcome::Stopped;
        }
        if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
            return ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason());
        }
        return ConnectionOutcome::ConnectFailed(format!("发送注册请求失败：{err}"));
    }

    // 等待服务端首帧返回 `registered`（或 `error`）。
    let (
        assigned_id,
        formatted_id,
        effective_relay_addr,
        effective_udp_probe_addr,
        effective_udp_alt_addr,
        effective_udp_alt_ip_addr,
        udp_probe_token,
    ) = loop {
        if shared.stop_flag.load(Ordering::Acquire) {
            return ConnectionOutcome::Stopped;
        }
        if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
            return ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason());
        }
        if Instant::now() >= handshake_deadline {
            return ConnectionOutcome::ConnectFailed("等待服务器注册响应超时".to_string());
        }
        match reader.read_frame(&shared.stop_flag) {
            FrameRead::IdleTick => continue,
            FrameRead::Stopped => return ConnectionOutcome::Stopped,
            FrameRead::Eof => {
                if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
                    return ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason());
                }
                return ConnectionOutcome::ConnectFailed("服务器在注册阶段关闭了连接".to_string());
            }
            FrameRead::Error(err) => {
                if shared.stop_flag.load(Ordering::Acquire) {
                    return ConnectionOutcome::Stopped;
                }
                if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
                    return ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason());
                }
                return ConnectionOutcome::ConnectFailed(format!("读取注册响应失败：{err}"));
            }
            FrameRead::Message(msg) => match *msg {
                IncomingSignalMsg::Registered {
                    device_id,
                    formatted_id,
                    udp_probe_addr,
                    udp_probe_alt_addr,
                    udp_probe_alt_ip_addr,
                    udp_probe_token,
                    relay_addr,
                } => {
                    shared.record_rtt_sample(reg_sent_at.elapsed().as_millis().min(10_000) as u32);
                    let fmt_id = formatted_id
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| format_device_id(&device_id));
                    let eff_relay = resolve_advertised_addr(
                        relay_addr.as_deref().unwrap_or(""),
                        &cfg.server_host,
                        cfg.relay_port,
                    );
                    let eff_udp = resolve_advertised_addr(
                        udp_probe_addr.as_deref().unwrap_or(""),
                        &cfg.server_host,
                        cfg.signal_port,
                    );
                    let eff_alt = udp_probe_alt_addr
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| resolve_advertised_addr(s, &cfg.server_host, cfg.signal_port));
                    let eff_alt_ip = udp_probe_alt_ip_addr
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| resolve_advertised_addr(s, &cfg.server_host, cfg.signal_port));
                    let token = parse_udp_probe_token(udp_probe_token.as_deref());
                    break (
                        device_id, fmt_id, eff_relay, eff_udp, eff_alt, eff_alt_ip, token,
                    );
                }
                IncomingSignalMsg::Error { code, message } => {
                    if code == "token_expired" {
                        *expired_token = sent_access_token.take();
                    }
                    if code == "device_id_mismatch" {
                        // 本地缓存的设备码与服务端记录不一致，清空缓存以便下轮重新签发。
                        *cached_device_id = None;
                    }
                    if matches!(
                        code.as_str(),
                        "account_disabled" | "user_deleted" | "token_revoked"
                    ) {
                        let (_, zh_msg) = classify_kicked_reason(&code);
                        shared.push_kicked_reason(code);
                        return ConnectionOutcome::TerminalError(zh_msg);
                    }
                    return ConnectionOutcome::ConnectFailed(format!(
                        "注册被拒绝 ({code})：{message}"
                    ));
                }
                _ => {
                    return ConnectionOutcome::ConnectFailed(
                        "注册阶段收到非预期信令消息".to_string(),
                    );
                }
            },
        }
    };

    *cached_device_id = Some(assigned_id.clone());

    {
        let mut writer_guard = shared
            .active_writer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if shared.stop_flag.load(Ordering::Acquire) {
            drop(writer_guard);
            shared.clear_active_writer();
            return ConnectionOutcome::Stopped;
        }
        if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
            drop(writer_guard);
            shared.clear_active_writer();
            return ConnectionOutcome::ConnectFailed(shared.format_reconnect_reason());
        }
        *writer_guard = Some(writer_template);
    }

    if shared.stop_flag.load(Ordering::Acquire) {
        return ConnectionOutcome::Stopped;
    }

    let connected_at = Instant::now();
    let mut last_server_activity = connected_at;
    shared.clear_last_server_activity();

    // 先判定是否启用出站代理：代理激活时完全跳过 UDP 探测目标 DNS 解析、UDP `RCSP` 绑定与 UPnP，
    // 杜绝无公网 DNS 环境阻塞或域名泄露，且 `server_is_loopback` 必须按真实目标主机判定而非代理地址。
    let proxy_active = used_proxy
        || crate::proxy::is_proxy_active_for_target(
            &effective_proxy,
            &cfg.server_host,
            cfg.signal_port,
        );
    shared.proxy_active.store(proxy_active, Ordering::Release);

    let (
        udp_probe_target,
        udp_alt_target,
        udp_alt_ip_target,
        udp_dual_stack_target,
        server_is_loopback,
    ) = if proxy_active {
        (None, None, None, None, is_loopback_host(&cfg.server_host))
    } else {
        // 在 Registered 时一次性解析 UDP 探测目标（主目标、副端口、副私有 IP 与跨地址族双栈目标），避免每 10s 阻塞 DNS。
        let resolved_primary_list: Vec<SocketAddr> = effective_udp_probe_addr
            .to_socket_addrs()
            .map(|it| it.collect())
            .unwrap_or_default();
        let primary = pick_preferred_socket_addr(&resolved_primary_list, peer_addr);
        let alt = effective_udp_alt_addr
            .as_deref()
            .and_then(|s| resolve_udp_probe_target(s, primary.or(peer_addr)))
            .filter(|&alt_addr| match primary {
                Some(p) => canonicalize_socket_addr(alt_addr) != canonicalize_socket_addr(p),
                None => true,
            });
        let alt_ip = effective_udp_alt_ip_addr
            .as_deref()
            .and_then(|s| resolve_udp_probe_target(s, primary.or(peer_addr)))
            .filter(|&alt_ip_addr| {
                let canon_alt_ip = canonicalize_socket_addr(alt_ip_addr);
                primary.map_or(true, |p| canon_alt_ip != canonicalize_socket_addr(p))
                    && alt.map_or(true, |a| canon_alt_ip != canonicalize_socket_addr(a))
            });
        let dual_stack = if udp_probe_token.is_some() {
            resolve_dual_stack_udp_target(
                &resolved_primary_list,
                primary,
                &cfg.server_host,
                &clean_lan_addrs,
            )
        } else {
            None
        };
        (
            primary,
            alt,
            alt_ip,
            dual_stack,
            peer_addr.is_some_and(|addr| canonicalize_ip(addr.ip()).is_loopback()),
        )
    };
    shared
        .server_is_loopback
        .store(server_is_loopback, Ordering::Release);
    {
        let mut targets = shared
            .connected_probe_targets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        targets.clear();
        if !proxy_active {
            for cand in [udp_probe_target, peer_addr].into_iter().flatten() {
                if !targets.contains(&cand) {
                    targets.push(cand);
                }
            }
        }
    }

    // 注册成功后绑定单一未连接双栈持久化 UDP 探测套接字（三平台零 SO_REUSEPORT 冲突），
    // 执行首轮 `RCSP`（v2 优先 / v1 回退）+ 纯私有 4 样本 / 副公网 IP NAT 分类 + 跨族双栈探测，
    // 随后发送携带改写后 `lan_addrs`、细化 NAT 画像与 RTT 估算的 `Heartbeat`。
    let udp_probe = if proxy_active {
        None
    } else {
        udp_probe_target.and_then(|target| {
            let local_public_ips = collect_local_public_ips(&clean_lan_addrs, target);
            PersistentUdpProbe::bind_with_options(
                target,
                assigned_id.clone(),
                udp_probe_token,
                udp_alt_target,
                udp_alt_ip_target,
                udp_dual_stack_target,
                local_public_ips,
            )
            .map(Arc::new)
        })
    };
    *shared
        .active_probe
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = udp_probe.clone();
    let bound_udp_port = udp_probe.as_ref().map_or(0, |p| p.local_port());
    let bound_udp_is_ipv6 = udp_probe.as_ref().is_some_and(|p| p.is_ipv6());
    shared
        .local_udp_is_ipv6
        .store(bound_udp_is_ipv6, Ordering::Release);
    shared
        .local_udp_port
        .store(bound_udp_port, Ordering::Release);
    if let Some(ref probe) = udp_probe {
        probe.run_initial_probe_round(&shared.nat_profile, &shared.rtt_ms, &shared.stop_flag);
        if shared.stop_flag.load(Ordering::Acquire) {
            return ConnectionOutcome::Stopped;
        }
        if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
            return ConnectionOutcome::ConnectedThenDropped {
                reason: shared.format_reconnect_reason(),
                healthy_duration: connected_at.elapsed(),
                kicked: false,
            };
        }
        if let Err(err) = send_heartbeat_frame(
            shared,
            shared.current_effective_lan_addrs(&clean_lan_addrs, bound_udp_port, bound_udp_is_ipv6),
        ) {
            shared.shutdown_active_socket();
            if shared.stop_flag.load(Ordering::Acquire) {
                return ConnectionOutcome::Stopped;
            }
            if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
                return ConnectionOutcome::ConnectedThenDropped {
                    reason: shared.format_reconnect_reason(),
                    healthy_duration: connected_at.elapsed(),
                    kicked: false,
                };
            }
            return ConnectionOutcome::ConnectedThenDropped {
                reason: format!("发送初始心跳失败：{err}"),
                healthy_duration: connected_at.elapsed(),
                kicked: false,
            };
        }
    }

    // 异步非阻塞启动 UPnP / NAT-PMP 端口映射（绝不阻塞注册、心跳与 Connected 宣告）；代理激活时跳过。
    if proxy_active {
        if shared.upnp_enabled.load(Ordering::Acquire) {
            let _ = shared.prepare_upnp_if_enabled(
                None,
                UpnpStatus::Unavailable {
                    reason: "已启用网络代理，已跳过 UPnP 网关探测".to_string(),
                },
            );
        }
    } else {
        trigger_upnp_for_bound_udp(
            shared,
            bound_udp_port,
            bound_udp_is_ipv6,
            server_is_loopback,
        );
    }

    shared.set_status(
        ServerStatusSnapshot {
            enabled: cfg.enabled,
            server_host: cfg.server_host.clone(),
            signal_port: cfg.signal_port,
            relay_port: cfg.relay_port,
            state: ServerConnectionState::Connected,
            device_id: Some(assigned_id.clone()),
            device_id_formatted: Some(formatted_id),
            error_message: None,
            ui_error: None,
            signal_addr: Some(default_signal_addr.to_string()),
            relay_addr: Some(effective_relay_addr.clone()),
            revision: 0,
        },
        on_status,
    );

    if shared.stop_flag.load(Ordering::Acquire) {
        return ConnectionOutcome::Stopped;
    }

    let mut last_heartbeat = Instant::now();
    let mut last_upnp_renew = Instant::now();

    loop {
        if shared.stop_flag.load(Ordering::Acquire) {
            return ConnectionOutcome::Stopped;
        }
        if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
            return ConnectionOutcome::ConnectedThenDropped {
                reason: shared.format_reconnect_reason(),
                healthy_duration: connected_at.elapsed(),
                kicked: false,
            };
        }

        if last_server_activity.elapsed() >= timing.activity_timeout {
            return ConnectionOutcome::ConnectedThenDropped {
                reason: "信令服务器心跳响应超时，正在重连".to_string(),
                healthy_duration: connected_at.elapsed(),
                kicked: false,
            };
        }

        if last_upnp_renew.elapsed() >= UPNP_RENEW_INTERVAL {
            last_upnp_renew = Instant::now();
            maybe_spawn_upnp_renew(shared);
        }

        let upnp_hb_due = shared.upnp_heartbeat_needed.swap(false, Ordering::AcqRel);
        let periodic_hb_due = last_heartbeat.elapsed() >= timing.heartbeat_interval;
        if periodic_hb_due || upnp_hb_due {
            let current_udp_port = shared.local_udp_port.load(Ordering::Acquire);
            let current_udp_is_ipv6 = shared.local_udp_is_ipv6.load(Ordering::Acquire);
            if let Err(err) = send_heartbeat_frame(
                shared,
                shared.current_effective_lan_addrs(
                    &clean_lan_addrs,
                    current_udp_port,
                    current_udp_is_ipv6,
                ),
            ) {
                shared.shutdown_active_socket();
                if shared.stop_flag.load(Ordering::Acquire) {
                    return ConnectionOutcome::Stopped;
                }
                if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
                    return ConnectionOutcome::ConnectedThenDropped {
                        reason: shared.format_reconnect_reason(),
                        healthy_duration: connected_at.elapsed(),
                        kicked: false,
                    };
                }
                return ConnectionOutcome::ConnectedThenDropped {
                    reason: format!("发送心跳失败：{err}"),
                    healthy_duration: connected_at.elapsed(),
                    kicked: false,
                };
            }
            if periodic_hb_due {
                if let Some(ref probe) = udp_probe {
                    shared.refresh_probe_and_recover_if_blocked(probe);
                }
                last_heartbeat = Instant::now();
            }
        }

        match reader.read_frame(&shared.stop_flag) {
            FrameRead::IdleTick => continue,
            FrameRead::Stopped => return ConnectionOutcome::Stopped,
            FrameRead::Eof => {
                if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
                    return ConnectionOutcome::ConnectedThenDropped {
                        reason: shared.format_reconnect_reason(),
                        healthy_duration: connected_at.elapsed(),
                        kicked: false,
                    };
                }
                return ConnectionOutcome::ConnectedThenDropped {
                    reason: "信令服务器断开连接".to_string(),
                    healthy_duration: connected_at.elapsed(),
                    kicked: false,
                };
            }
            FrameRead::Error(err) => {
                if shared.stop_flag.load(Ordering::Acquire) {
                    return ConnectionOutcome::Stopped;
                }
                if shared.reconnect_epoch.load(Ordering::Acquire) != conn_reconnect_epoch {
                    return ConnectionOutcome::ConnectedThenDropped {
                        reason: shared.format_reconnect_reason(),
                        healthy_duration: connected_at.elapsed(),
                        kicked: false,
                    };
                }
                return ConnectionOutcome::ConnectedThenDropped {
                    reason: format!("读取信令帧失败：{err}"),
                    healthy_duration: connected_at.elapsed(),
                    kicked: false,
                };
            }
            FrameRead::Message(msg) => {
                let now = Instant::now();
                last_server_activity = now;
                shared.record_server_activity(now);
                match handle_incoming_message(
                    shared,
                    &assigned_id,
                    *msg,
                    &cfg.server_host,
                    cfg.relay_port,
                    &effective_relay_addr,
                    default_relay_addr,
                ) {
                    IncomingAction::Continue => {}
                    IncomingAction::Disconnect { reason, kicked } => {
                        return ConnectionOutcome::ConnectedThenDropped {
                            reason,
                            healthy_duration: connected_at.elapsed(),
                            kicked,
                        };
                    }
                    IncomingAction::Terminal(reason) => {
                        return ConnectionOutcome::TerminalError(reason);
                    }
                }
            }
        }
    }
}

fn handle_incoming_message(
    shared: &Arc<SharedState>,
    local_device_id: &str,
    msg: IncomingSignalMsg,
    server_host: &str,
    relay_port: u16,
    registered_relay_addr: &str,
    default_relay_addr: &str,
) -> IncomingAction {
    match msg {
        IncomingSignalMsg::Registered { .. } => IncomingAction::Continue,
        IncomingSignalMsg::HeartbeatAck {} => {
            if let Some(sent_at) = shared
                .last_heartbeat_sent_at
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                shared.record_rtt_sample(sent_at.elapsed().as_millis().min(10_000) as u32);
            }
            IncomingAction::Continue
        }
        IncomingSignalMsg::DeviceStatusChanged {
            device_id,
            online,
            hostname,
            alias,
            os,
            app_version,
            arch,
            allow_remote_assist,
            allow_remote_control,
            wol_capable,
        } => {
            let allow_remote_control = allow_remote_control
                .unwrap_or_else(|| crate::default_allow_remote_control_for_os(&os));
            let same_local_device = match (
                parse_device_id_input(&device_id),
                parse_device_id_input(local_device_id),
            ) {
                (Some(a), Some(b)) => a == b,
                _ => !local_device_id.is_empty() && device_id.trim() == local_device_id.trim(),
            };
            if same_local_device {
                shared.allow_remote_assist.store(
                    if allow_remote_assist {
                        ASSIST_TRUE
                    } else {
                        ASSIST_FALSE
                    },
                    Ordering::Release,
                );
                shared.allow_remote_control.store(
                    if allow_remote_control {
                        REMOTE_CTRL_TRUE
                    } else {
                        REMOTE_CTRL_FALSE
                    },
                    Ordering::Release,
                );
            }
            shared.push_device_wol_event(DeviceWolCapabilityEvent {
                device_id: device_id.clone(),
                online,
                wol_capable,
            });
            shared.push_device_status(DeviceStatusEvent {
                device_id,
                online,
                hostname,
                alias,
                os,
                app_version,
                arch,
                allow_remote_assist,
                allow_remote_control,
            });
            IncomingAction::Continue
        }
        IncomingSignalMsg::PunchCoord {
            session_id,
            role,
            peer_id,
            peer_public_udp_addr,
            peer_public_udp_addrs,
            self_public_udp_addr,
            peer_nat_type,
            peer_nat_port_delta,
            self_nat_port_range,
            peer_nat_port_range,
            peer_lan_addrs,
            punch_secret,
            start_after_ms,
            relay_fallback_after_ms,
            relay_token,
            relay_addr,
            owner_grant,
            is_owner_connection,
        } => {
            shared.trigger_lightweight_probe_refresh();
            let eff_relay = pick_relay_addr(
                &relay_addr,
                registered_relay_addr,
                server_host,
                relay_port,
                default_relay_addr,
            );
            dispatch_coord(
                shared,
                CoordPayload {
                    session_id,
                    role,
                    peer_id,
                    relay_addr: eff_relay,
                    relay_token,
                    peer_public_addr: peer_public_udp_addr,
                    peer_public_addrs: peer_public_udp_addrs,
                    self_public_addr: self_public_udp_addr,
                    peer_nat_type,
                    peer_nat_port_delta,
                    self_nat_port_range,
                    peer_nat_port_range,
                    peer_lan_addrs,
                    punch_secret,
                    start_after_ms,
                    relay_fallback_after_ms,
                    owner_grant,
                    is_owner_connection,
                    is_relay_alloc: false,
                },
            );
            IncomingAction::Continue
        }
        IncomingSignalMsg::RelayReady {
            session_id,
            role,
            peer_id,
            relay_token,
            relay_addr,
            owner_grant,
            is_owner_connection,
        } => {
            let eff_relay = pick_relay_addr(
                &relay_addr,
                registered_relay_addr,
                server_host,
                relay_port,
                default_relay_addr,
            );
            dispatch_coord(
                shared,
                CoordPayload {
                    session_id,
                    role,
                    peer_id,
                    relay_addr: eff_relay,
                    relay_token,
                    peer_public_addr: None,
                    peer_public_addrs: Vec::new(),
                    self_public_addr: None,
                    peer_nat_type: None,
                    peer_nat_port_delta: None,
                    self_nat_port_range: None,
                    peer_nat_port_range: None,
                    peer_lan_addrs: Vec::new(),
                    punch_secret: None,
                    start_after_ms: None,
                    relay_fallback_after_ms: None,
                    owner_grant,
                    is_owner_connection,
                    is_relay_alloc: true,
                },
            );
            IncomingAction::Continue
        }
        IncomingSignalMsg::PeerOffline {
            target_id,
            session_id,
        } => {
            let err_msg = format!("目标设备 {} 当前不在线", format_device_id(&target_id));
            let mut pending = shared
                .pending_connects
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !session_id.is_empty() {
                if let Some(waiter) = pending.remove(&session_id) {
                    let _ = waiter.tx.try_send(Err(err_msg));
                }
            } else if let Some(key) = pending
                .iter()
                .find(|(_, v)| v.target_id == target_id)
                .map(|(k, _)| k.clone())
            {
                if let Some(waiter) = pending.remove(&key) {
                    let _ = waiter.tx.try_send(Err(err_msg));
                }
            }
            IncomingAction::Continue
        }
        IncomingSignalMsg::WolAck {
            request_id,
            target_device_id,
            ok,
            method,
            code,
            message,
        } => {
            let norm_code = code.map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
            let ui_error = if ok {
                None
            } else {
                Some(map_wol_ack_error(norm_code.as_deref(), &message))
            };
            let result = WolAckResult {
                target_device_id,
                ok,
                method,
                code: norm_code,
                message,
                ui_error,
            };
            let mut pending = shared
                .pending_wols
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(req_id) = request_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if let Some(tx) = pending.remove(req_id) {
                    let _ = tx.try_send(Ok(result));
                }
            }
            IncomingAction::Continue
        }
        IncomingSignalMsg::WolRelay {
            mac_addr,
            target_lan_addrs,
            ..
        } => {
            handle_incoming_wol_relay(shared, &mac_addr, target_lan_addrs);
            IncomingAction::Continue
        }
        IncomingSignalMsg::Error { code, message } => {
            let detail = format_signal_error(&code, &message);
            shared.fail_all_pending(&detail);
            IncomingAction::Continue
        }
        IncomingSignalMsg::Kicked { reason } => {
            shared.push_kicked_reason(reason.clone());
            let (is_terminal, msg) = classify_kicked_reason(&reason);
            if is_terminal {
                IncomingAction::Terminal(msg)
            } else {
                IncomingAction::Disconnect {
                    reason: msg,
                    kicked: true,
                }
            }
        }
    }
}

fn format_signal_error(code: &str, message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        match code {
            "remote_control_disabled" => {
                "服务器拒绝请求 (remote_control_disabled)：对方未开启允许远程控制".to_string()
            }
            "assist_disabled" => {
                "服务器拒绝请求 (assist_disabled)：对方未开启允许他人远程协助".to_string()
            }
            _ => format!("服务器返回错误 ({code})"),
        }
    } else {
        format!("服务器拒绝请求 ({code})：{trimmed}")
    }
}

#[derive(Default)]
struct CoordPayload {
    session_id: String,
    role: String,
    peer_id: String,
    relay_addr: String,
    relay_token: String,
    peer_public_addr: Option<String>,
    peer_public_addrs: Vec<String>,
    self_public_addr: Option<String>,
    peer_nat_type: Option<String>,
    peer_nat_port_delta: Option<i16>,
    self_nat_port_range: Option<[u16; 2]>,
    peer_nat_port_range: Option<[u16; 2]>,
    peer_lan_addrs: Vec<String>,
    punch_secret: Option<String>,
    start_after_ms: Option<u16>,
    relay_fallback_after_ms: Option<u16>,
    owner_grant: Option<OwnerGrantPayload>,
    is_owner_connection: bool,
    is_relay_alloc: bool,
}

fn normalize_optional_addr(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn normalize_addr_list(raw: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let trimmed = item.trim();
        if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn dispatch_coord(shared: &SharedState, coord: CoordPayload) {
    let CoordPayload {
        session_id,
        role,
        peer_id,
        relay_addr,
        relay_token,
        peer_public_addr,
        peer_public_addrs,
        self_public_addr,
        peer_nat_type,
        peer_nat_port_delta,
        self_nat_port_range,
        peer_nat_port_range,
        peer_lan_addrs,
        punch_secret,
        start_after_ms,
        relay_fallback_after_ms,
        owner_grant,
        is_owner_connection,
        is_relay_alloc,
    } = coord;
    let peer_public_addr = normalize_optional_addr(peer_public_addr);
    let peer_public_addrs = normalize_addr_list(peer_public_addrs);
    let self_public_addr = normalize_optional_addr(self_public_addr)
        .or_else(|| shared.observed_public_addr_matching(peer_public_addr.as_deref()));
    let nat_profile = shared.current_nat_profile();
    let peer_nat_type = peer_nat_type
        .as_deref()
        .map(NatType::parse_lossy)
        .unwrap_or(NatType::Unknown);
    let self_nat_port_range = self_nat_port_range
        .and_then(PortRangeHint::from_wire_pair)
        .or(nat_profile.port_range);
    let peer_nat_port_range = peer_nat_port_range.and_then(PortRangeHint::from_wire_pair);
    let punch_secret = punch_secret
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let local_port = shared.local_udp_port.load(Ordering::Acquire);
    let local_udp_port = (local_port != 0).then_some(local_port);

    let is_host_role = role.eq_ignore_ascii_case("host");
    if is_host_role {
        shared.push_incoming(RelayIncoming {
            session_id,
            relay_addr,
            relay_token,
            peer_id,
            peer_public_addr,
            peer_public_addrs,
            self_public_addr,
            self_nat_type: nat_profile.nat_type,
            self_nat_port_delta: nat_profile.port_delta,
            self_nat_port_range,
            peer_nat_type,
            peer_nat_port_delta,
            peer_nat_port_range,
            peer_lan_addrs,
            local_udp_port,
            punch_secret,
            start_after_ms,
            relay_fallback_after_ms,
            owner_grant,
            is_owner_connection,
            is_relay_alloc,
        });
        return;
    }

    if !role.is_empty() && !role.eq_ignore_ascii_case("client") {
        // 未知角色直接丢弃，绝不误入 incoming 队列或污染出站连接。
        return;
    }

    let mut pending = shared
        .pending_connects
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let matched = if !session_id.is_empty() {
        pending.remove(&session_id)
    } else if role.eq_ignore_ascii_case("client") {
        let key = pending
            .iter()
            .find(|(_, v)| v.target_id == peer_id)
            .map(|(k, _)| k.clone());
        key.and_then(|k| pending.remove(&k))
    } else {
        None
    };
    if let Some(waiter) = matched {
        let _ = waiter.tx.try_send(Ok(ConnectGrant {
            session_id,
            relay_addr,
            relay_token,
            target_id: peer_id,
            peer_public_addr,
            peer_public_addrs,
            self_public_addr,
            self_nat_type: nat_profile.nat_type,
            self_nat_port_delta: nat_profile.port_delta,
            self_nat_port_range,
            peer_nat_type,
            peer_nat_port_delta,
            peer_nat_port_range,
            peer_lan_addrs,
            local_udp_port,
            punch_secret,
            start_after_ms,
            relay_fallback_after_ms,
            owner_grant,
            is_owner_connection,
        }));
    }
    // 未匹配的 client / 空角色协调消息干净丢弃，绝不推入 incoming。
}

fn pick_relay_addr(
    msg_relay_addr: &str,
    registered_relay_addr: &str,
    server_host: &str,
    relay_port: u16,
    default_relay_addr: &str,
) -> String {
    if !msg_relay_addr.trim().is_empty() {
        return resolve_advertised_addr(msg_relay_addr, server_host, relay_port);
    }
    if !registered_relay_addr.trim().is_empty() {
        return registered_relay_addr.to_string();
    }
    default_relay_addr.to_string()
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

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed
        .parse::<IpAddr>()
        .map(canonicalize_ip)
        .is_ok_and(|ip| ip.is_loopback())
}

fn is_unspecified_host(host: &str) -> bool {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed
        .parse::<IpAddr>()
        .map(canonicalize_ip)
        .is_ok_and(|ip| ip.is_unspecified())
}

fn resolve_advertised_addr(advertised: &str, fallback_host: &str, fallback_port: u16) -> String {
    let trimmed = advertised.trim();
    if trimmed.is_empty() {
        return format_host_port(fallback_host, fallback_port);
    }
    let fallback_is_loopback = is_loopback_host(fallback_host);

    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        let ip = canonicalize_ip(sock.ip());
        let port = if sock.port() == 0 {
            fallback_port
        } else {
            sock.port()
        };
        if ip.is_unspecified() || (ip.is_loopback() && !fallback_is_loopback) {
            return format_host_port(fallback_host, port);
        }
        return format_host_port(&ip.to_string(), port);
    }

    // 非 SocketAddr 字符串（如 bare hostname/IP："localhost"、"0.0.0.0"、"::1"、"relay.example.com" 或带 `:0`）：
    // 统一通过 `parse_server_input` 规范化并执行同样的回环/未指定地址替换与非零端口保留。
    let parsed = parse_server_input(trimmed, fallback_port).or_else(|_| {
        trimmed
            .strip_suffix(":0")
            .ok_or_else(|| "invalid".to_string())
            .and_then(|without_zero| parse_server_input(without_zero, fallback_port))
    });

    if let Ok((host, port)) = parsed {
        let effective_port = if port == 0 { fallback_port } else { port };
        if is_unspecified_host(&host) || (is_loopback_host(&host) && !fallback_is_loopback) {
            return format_host_port(fallback_host, effective_port);
        }
        let normalized_host = host
            .parse::<IpAddr>()
            .map(|ip| canonicalize_ip(ip).to_string())
            .unwrap_or(host);
        return format_host_port(&normalized_host, effective_port);
    }

    format_host_port(fallback_host, fallback_port)
}

fn pick_preferred_socket_addr(
    addrs: &[SocketAddr],
    peer_addr: Option<SocketAddr>,
) -> Option<SocketAddr> {
    if addrs.is_empty() {
        return None;
    }
    if let Some(peer) = peer_addr {
        let prefer_v6 = peer.is_ipv6();
        if let Some(&matching) = addrs.iter().find(|a| a.is_ipv6() == prefer_v6) {
            return Some(matching);
        }
    }
    addrs.first().copied()
}

fn resolve_udp_probe_target(
    udp_probe_addr: &str,
    peer_addr: Option<SocketAddr>,
) -> Option<SocketAddr> {
    let addrs: Vec<SocketAddr> = udp_probe_addr.to_socket_addrs().ok()?.collect();
    pick_preferred_socket_addr(&addrs, peer_addr)
}

fn has_local_global_unicast_ipv6(lan_addrs: &[String]) -> bool {
    if lan_addrs.iter().any(|raw| {
        extract_canonical_lan_ip(raw, 1)
            .is_some_and(|ip| matches!(ip, IpAddr::V6(v6) if is_global_unicast_ipv6(v6)))
    }) {
        return true;
    }
    if let Ok(sock) = UdpSocket::bind("[::]:0") {
        if sock.connect("[2001:4860:4860::8888]:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                if let IpAddr::V6(v6) = canonicalize_ip(local.ip()) {
                    return is_global_unicast_ipv6(v6);
                }
            }
        }
    }
    false
}

fn resolve_dual_stack_udp_target(
    resolved_primary_list: &[SocketAddr],
    primary: Option<SocketAddr>,
    server_host: &str,
    lan_addrs: &[String],
) -> Option<SocketAddr> {
    let primary = primary?;
    let want_v6 = !primary.is_ipv6();
    if let Some(&other) = resolved_primary_list
        .iter()
        .find(|a| a.is_ipv6() == want_v6)
    {
        return Some(other);
    }
    let clean_host = server_host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if clean_host.parse::<IpAddr>().is_err()
        && (!want_v6
            || has_local_global_unicast_ipv6(lan_addrs)
            || resolved_primary_list.is_empty())
    {
        if let Ok(addrs) = (clean_host, primary.port()).to_socket_addrs() {
            if let Some(other) = addrs.into_iter().find(|a| a.is_ipv6() == want_v6) {
                return Some(other);
            }
        }
    }
    None
}

fn send_heartbeat_frame(shared: &SharedState, lan_addrs: Vec<String>) -> Result<(), String> {
    let (nat_type, nat_port_delta, nat_port_range) = shared.current_nat_wire_fields();
    let rtt_ms = shared.current_rtt_ms();
    *shared
        .last_heartbeat_sent_at
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    let hb = OutgoingSignalMsg::Heartbeat {
        lan_addrs,
        mac_addr: shared.current_mac_addr_opt(),
        wol_enabled: shared.current_wol_enabled_opt(),
        nat_type,
        nat_port_delta,
        nat_port_range,
        rtt_ms,
    };
    shared.send_msg(&hb)
}

fn map_wol_ack_error(code: Option<&str>, message: &str) -> crate::ui_error::UiError {
    let platform = crate::ui_error::current_platform();
    let detail = if message.trim().is_empty() {
        code.map(|c| c.to_string())
    } else {
        Some(message.trim().to_string())
    };
    let canonical = match code.map(|c| c.trim().to_ascii_lowercase()).as_deref() {
        Some("wol_disabled") => crate::ui_error::codes::WOL_DISABLED,
        Some("wol_no_relay_peer") => crate::ui_error::codes::WOL_NO_RELAY_PEER,
        Some("wol_send_failed") => crate::ui_error::codes::WOL_SEND_FAILED,
        Some("rate_limited") => crate::ui_error::codes::NETWORK_RATE_LIMITED,
        Some("unauthorized") => crate::ui_error::codes::AUTH_UNAUTHORIZED,
        Some("forbidden") => crate::ui_error::codes::AUTH_FORBIDDEN,
        Some("device_not_found") => crate::ui_error::codes::SIGNAL_PEER_NOT_FOUND,
        Some("device_disabled") => crate::ui_error::codes::DEVICE_DISABLED,
        Some("invalid_input") => crate::ui_error::codes::VALIDATION_INVALID_INPUT,
        Some(other) => crate::ui_error::resolve_wire_alias(other)
            .unwrap_or(crate::ui_error::codes::WOL_SEND_FAILED),
        None => crate::ui_error::codes::WOL_SEND_FAILED,
    };
    crate::ui_error::resolve_ui_error(canonical, platform, &[], None, detail)
}

struct WolRelayInflightGuard(Arc<AtomicUsize>);

impl Drop for WolRelayInflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_incoming_wol_relay(shared: &SharedState, mac_addr: &str, target_lan_addrs: Vec<String>) {
    let Some(norm_mac) = crate::wol::normalize_mac_addr(mac_addr) else {
        return;
    };
    let clean_addrs = sanitize_lan_addrs(&target_lan_addrs);

    // 滑动时间窗频率限制（每 10 秒最多 10 次）防恶意或异常刷包。
    {
        let now = Instant::now();
        let mut hist = shared
            .wol_relay_history
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        while let Some(&front) = hist.front() {
            if now.saturating_duration_since(front) >= WOL_RELAY_RATE_WINDOW {
                hist.pop_front();
            } else {
                break;
            }
        }
        if hist.len() >= WOL_RELAY_RATE_MAX {
            return;
        }
        hist.push_back(now);
    }

    // 并发线程数上限控制（最多 4 个在途代发线程），CAS 原子占位。
    let inflight = Arc::clone(&shared.wol_relay_inflight);
    loop {
        let cur = inflight.load(Ordering::Acquire);
        if cur >= MAX_CONCURRENT_WOL_RELAYS {
            return;
        }
        if inflight
            .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }

    #[cfg(test)]
    let test_sink = shared
        .wol_relay_test_sink
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let spawn_res = thread::Builder::new()
        .name("rc-wol-relay".to_string())
        .spawn(move || {
            let _guard = WolRelayInflightGuard(inflight);
            #[cfg(test)]
            if let Some(sink) = test_sink {
                let _ = sink.send((norm_mac, clean_addrs));
                return;
            }
            let _ = crate::wol::send_magic_packet(&norm_mac, &clean_addrs);
        });
    if spawn_res.is_err() {
        shared.wol_relay_inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 探测发送后的超时与重试退避（初始等待 250ms，最多重试 2 次分别为 450ms 与 700ms）。
const UDP_PROBE_RETRY_WAITS: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_millis(450),
    Duration::from_millis(700),
];

/// 单次 `RCSA` 读取轮询粒度。
const UDP_PROBE_POLL_STEP: Duration = Duration::from_millis(5);

static ACTIVE_UDP_PROBE_SLOTS: OnceLock<Mutex<HashMap<u16, Arc<UdpProbeSlot>>>> = OnceLock::new();

fn active_udp_probe_slots() -> &'static Mutex<HashMap<u16, Arc<UdpProbeSlot>>> {
    ACTIVE_UDP_PROBE_SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

struct UdpProbeSlotState {
    sock: Option<UdpSocket>,
    pause_count: usize,
    closed: bool,
}

struct UdpProbeSlot {
    port: u16,
    primary_is_ipv6: bool,
    socket_is_ipv6: bool,
    target: SocketAddr,
    state: Mutex<UdpProbeSlotState>,
}

fn normalize_probe_addr_for_socket(addr: SocketAddr, socket_is_ipv6: bool) -> SocketAddr {
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

fn record_rtt_sample_into(rtt_ms: &Mutex<Option<u32>>, sample_ms: u32) {
    let clamped = sample_ms.min(10_000);
    let mut guard = rtt_ms.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(match *guard {
        Some(prev) => (prev.saturating_mul(3).saturating_add(clamped)) / 4,
        None => clamped,
    });
}

fn collect_local_public_ips(clean_lan_addrs: &[String], target: SocketAddr) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut push_if_pub = |ip: IpAddr| {
        let canon = canonicalize_ip(ip);
        if is_routable_public_ip(canon) && !out.contains(&canon) {
            out.push(canon);
        }
    };
    for raw in clean_lan_addrs {
        if let Some(ip) = extract_canonical_lan_ip(raw, 1) {
            push_if_pub(ip);
        }
    }
    let bind_addr = if target.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0u8; 4], 0))
    };
    if let Ok(sock) = UdpSocket::bind(bind_addr) {
        if sock.connect(target).is_ok() {
            if let Ok(local) = sock.local_addr() {
                push_if_pub(local.ip());
            }
        }
    }
    out
}

impl UdpProbeSlot {
    /// 绑定单一未连接（unconnected）双栈 UDP 探测套接字（三平台零 `SO_REUSEPORT` 冲突）。
    ///
    /// 优先绑定 `AF_INET6`（`[::]:port`，`IPV6_V6ONLY = false`）以在单套接字上同时承载
    /// IPv4（`::ffff:a.b.c.d`）与 IPv6 探测包；若双栈不可用且主目标为 IPv4 则回退纯 `AF_INET`。
    fn bind_unconnected_probe_socket(
        port: u16,
        primary_target: SocketAddr,
    ) -> Option<(UdpSocket, bool)> {
        let try_v6_dual = || -> Option<(UdpSocket, bool)> {
            let raw = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).ok()?;
            let dual_ok = raw.set_only_v6(false).is_ok();
            if primary_target.is_ipv4() && !dual_ok {
                return None;
            }
            #[cfg(unix)]
            let _ = raw.set_reuse_address(true);
            raw.bind(&SockAddr::from(SocketAddr::from(([0u16; 8], port))))
                .ok()?;
            let sock: UdpSocket = raw.into();
            let _ = sock.set_nonblocking(true);
            Some((sock, true))
        };

        if let Some(res) = try_v6_dual() {
            return Some(res);
        }

        if primary_target.is_ipv4() {
            let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
            #[cfg(unix)]
            let _ = raw.set_reuse_address(true);
            raw.bind(&SockAddr::from(SocketAddr::from(([0u8; 4], port))))
                .ok()?;
            let sock: UdpSocket = raw.into();
            let _ = sock.set_nonblocking(true);
            return Some((sock, false));
        }

        None
    }

    fn acquire_port_hold(self: &Arc<Self>) -> SlotPortHold {
        {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.pause_count = guard.pause_count.saturating_add(1);
            // 跨三平台（Linux / macOS / Windows）统一释放并关闭占用 `local_udp_port` 的未连接探测套接字，
            // 让随后启动的 P2P 打洞/QUIC 套接字独占绑定同一本地端口，避免任何 SO_REUSEPORT 分流冲突。
            drop(guard.sock.take());
        }
        SlotPortHold {
            slot: Arc::clone(self),
        }
    }
}

struct SlotPortHold {
    slot: Arc<UdpProbeSlot>,
}

impl Drop for SlotPortHold {
    fn drop(&mut self) {
        let mut guard = self.slot.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.pause_count = guard.pause_count.saturating_sub(1);
        if guard.pause_count == 0 && !guard.closed && guard.sock.is_none() {
            guard.sock =
                UdpProbeSlot::bind_unconnected_probe_socket(self.slot.port, self.slot.target)
                    .map(|(s, _)| s);
        }
    }
}

/// P2P 打洞与直连期间持有的本地 UDP 端口暂停租约（三平台统一独占释放/恢复探测套接字）。
pub(crate) struct LocalUdpPortHoldGuard(#[allow(dead_code)] Option<SlotPortHold>);

/// 在三平台（Linux / macOS / Windows）执行 P2P 打洞前临时释放同端口的持久化 UDP 探测套接字；
/// 当返回的守卫被 `Drop`（打洞失败或 P2P 会话结束）时自动重新绑定同一本地端口。
pub(crate) fn acquire_local_udp_port_for_p2p(port: Option<u16>) -> LocalUdpPortHoldGuard {
    let Some(p) = port.filter(|&v| v != 0) else {
        return LocalUdpPortHoldGuard(None);
    };
    let slot = active_udp_probe_slots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&p)
        .cloned();
    LocalUdpPortHoldGuard(slot.map(|s| s.acquire_port_hold()))
}

/// 绑定了端口协调租约的 P2P QUIC 传输包装：确保在 `P2pQuicConnection` 彻底释放底层
/// UDP 端点后，才归还 [`LocalUdpPortHoldGuard`] 以便探测套接字安全恢复绑定。
pub(crate) struct P2pHeldTransport {
    conn: P2pQuicConnection,
    _port_hold: LocalUdpPortHoldGuard,
}

impl P2pHeldTransport {
    pub(crate) fn new(conn: P2pQuicConnection, port_hold: LocalUdpPortHoldGuard) -> Self {
        Self {
            conn,
            _port_hold: port_hold,
        }
    }

    pub(crate) fn peer_mtls_identity(&self) -> Option<rc_net::mtls::PeerMtlsIdentity> {
        self.conn.peer_mtls_identity()
    }
}

impl Transport for P2pHeldTransport {
    fn send_datagram(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.conn.send_datagram(data)
    }

    fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.conn.send_reliable(data)
    }

    fn send_reliable_urgent(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.conn.send_reliable_urgent(data)
    }

    fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
        self.conn.poll(timeout)
    }

    fn stats(&self) -> NetStats {
        self.conn.stats()
    }

    fn set_pacing_rate(&mut self, bps: u64) {
        self.conn.set_pacing_rate(bps);
    }

    fn tx_queued_bytes(&self) -> usize {
        self.conn.tx_queued_bytes()
    }

    fn tx_dropped_datagrams(&self) -> u64 {
        self.conn.tx_dropped_datagrams()
    }
}

fn build_probe_bytes_for_mode(
    device_id: &str,
    nonce: [u8; 8],
    token: Option<[u8; 16]>,
) -> Option<Vec<u8>> {
    match token {
        Some(tok) => build_udp_probe_packet_v2(device_id, nonce, tok)
            .ok()
            .map(|p| p.to_vec()),
        None => build_udp_probe_packet(device_id, nonce)
            .ok()
            .map(|p| p.to_vec()),
    }
}

fn update_nat_profile_observed(nat_profile: &Mutex<NatProfile>, observed: SocketAddr) -> bool {
    let canon = canonicalize_socket_addr(observed);
    if canon.port() == 0 || canon.ip().is_unspecified() {
        return false;
    }
    let mut guard = nat_profile.lock().unwrap_or_else(|e| e.into_inner());
    if canon.is_ipv6() {
        guard.public_v6 = Some(canon);
    } else {
        guard.public_v4 = Some(canon);
    }
    if guard.nat_type == NatType::UdpBlocked {
        // 收到有效 RCSA 响应即清除过期的 UdpBlocked 锁死（如休眠唤醒/开机丢包后恢复），降级为 ConeUnverified。
        guard.nat_type = NatType::ConeUnverified;
        true
    } else {
        false
    }
}

fn probe_once_unconnected_to_target(
    sock: &UdpSocket,
    socket_is_ipv6: bool,
    target: SocketAddr,
    device_id: &str,
    token: Option<[u8; 16]>,
    stop_flag: &AtomicBool,
) -> Option<(SocketAddr, u32)> {
    if !socket_is_ipv6 && target.is_ipv6() {
        return None;
    }
    let mut sent_nonces = [[0u8; 8]; 3];
    let mut sent_times = [Instant::now(); 3];
    let mut buf = [0u8; 128];
    let expected_peer = canonicalize_socket_addr(target);
    let send_target = normalize_probe_addr_for_socket(expected_peer, socket_is_ipv6);
    for (attempt, &wait_budget) in UDP_PROBE_RETRY_WAITS.iter().enumerate() {
        if stop_flag.load(Ordering::Acquire) {
            return None;
        }
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        sent_nonces[attempt] = nonce;
        sent_times[attempt] = Instant::now();
        let pkt = build_probe_bytes_for_mode(device_id, nonce, token)?;
        let _ = sock.send_to(&pkt, send_target);

        let deadline = Instant::now() + wait_budget;
        loop {
            if stop_flag.load(Ordering::Acquire) {
                return None;
            }
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if canonicalize_socket_addr(from) == expected_peer => {
                    if let Some((observed, ans_nonce)) = parse_udp_answer_packet(&buf[..n]) {
                        if let Some(idx) =
                            sent_nonces[..=attempt].iter().position(|n| *n == ans_nonce)
                        {
                            let canon = canonicalize_socket_addr(observed);
                            if canon.port() != 0 && !canon.ip().is_unspecified() {
                                let rtt = sent_times[idx].elapsed().as_millis().min(10_000) as u32;
                                return Some((canon, rtt));
                            }
                        }
                    }
                }
                Ok(_) => continue,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    thread::sleep(UDP_PROBE_POLL_STEP.min(deadline - now));
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
                    ) =>
                {
                    if attempt >= 1 {
                        return None;
                    }
                    break;
                }
                Err(_) => return None,
            }
        }
    }
    None
}

/// 当 `m1 != m2` 时使用 1 个临时未连接 UDP socket 在 `< 5ms` 内连续发送主/副端口探测包，
/// 采集 `(m3, m4)` 以验证对称 NAT 步长恒定性。
fn probe_aux_pair_burst(
    primary_target: SocketAddr,
    alt_target: SocketAddr,
    device_id: &str,
    token: Option<[u8; 16]>,
    stop_flag: &AtomicBool,
) -> (Option<SocketAddr>, Option<SocketAddr>) {
    let Some((temp_sock, temp_is_ipv6)) =
        UdpProbeSlot::bind_unconnected_probe_socket(0, primary_target)
    else {
        return (None, None);
    };
    if !temp_is_ipv6 && alt_target.is_ipv6() {
        return (None, None);
    }

    let primary_canon = canonicalize_socket_addr(primary_target);
    let alt_canon = canonicalize_socket_addr(alt_target);
    let mut nonce3 = [0u8; 8];
    let mut nonce4 = [0u8; 8];
    OsRng.fill_bytes(&mut nonce3);
    OsRng.fill_bytes(&mut nonce4);
    while nonce4 == nonce3 {
        OsRng.fill_bytes(&mut nonce4);
    }

    let Some(pkt3) = build_probe_bytes_for_mode(device_id, nonce3, token) else {
        return (None, None);
    };
    let Some(pkt4) = build_probe_bytes_for_mode(device_id, nonce4, token) else {
        return (None, None);
    };

    let send_p = normalize_probe_addr_for_socket(primary_canon, temp_is_ipv6);
    let send_a = normalize_probe_addr_for_socket(alt_canon, temp_is_ipv6);
    let _ = temp_sock.send_to(&pkt3, send_p);
    let _ = temp_sock.send_to(&pkt4, send_a);

    let mut m3 = None;
    let mut m4 = None;
    let mut buf = [0u8; 128];
    let deadline = Instant::now() + Duration::from_millis(500);

    while m3.is_none() || m4.is_none() {
        if stop_flag.load(Ordering::Acquire) {
            break;
        }
        match temp_sock.recv_from(&mut buf) {
            Ok((n, raw_from)) => {
                let from = canonicalize_socket_addr(raw_from);
                if let Some((observed, ans_nonce)) = parse_udp_answer_packet(&buf[..n]) {
                    let canon = canonicalize_socket_addr(observed);
                    if canon.port() != 0 && !canon.ip().is_unspecified() {
                        if from == primary_canon && ans_nonce == nonce3 && m3.is_none() {
                            m3 = Some(canon);
                        } else if from == alt_canon && ans_nonce == nonce4 && m4.is_none() {
                            m4 = Some(canon);
                        }
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                thread::sleep(UDP_PROBE_POLL_STEP.min(deadline - now));
            }
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
            Err(_) => break,
        }
    }
    (m3, m4)
}

/// 轻量 `RCSP` 刷新保留的最近已发送 nonce 环形缓冲上限，避免连续刷新覆盖导致在途 `RCSA` 被误丢。
const RECENT_LIGHTWEIGHT_NONCE_CAP: usize = 4;

/// 持久化 UDP `RCSP` 探测套接字：使用单一未连接（unconnected）双栈 UDP 套接字
/// （零 `SO_REUSEPORT` 冲突），使信令服务器学习到的公网 NAT `(ip, port)` 与 P2P 打洞共享同一本地端口；
/// 收包时严格校验来源 `IP:port` 属于允许目标集合且 `RCSA` nonce 合法，P2P 建连期间通过
/// [`acquire_local_udp_port_for_p2p`] 独占释放并在结束后恢复。
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExternalMappingCheck {
    Reachable,
    Unreachable(String),
    Skipped,
}

const SELF_CHECK_RETRY_WAITS: [Duration; 2] =
    [Duration::from_millis(250), Duration::from_millis(450)];

struct PersistentUdpProbe {
    slot: Arc<UdpProbeSlot>,
    device_id: String,
    token: Option<[u8; 16]>,
    alt_target: Option<SocketAddr>,
    alt_ip_target: Option<SocketAddr>,
    dual_stack_target: Option<SocketAddr>,
    local_public_ips: Vec<IpAddr>,
    recent_nonces: Mutex<VecDeque<[u8; 8]>>,
    dual_stack_nonces: Mutex<VecDeque<[u8; 8]>>,
    probe_rx_lock: Mutex<()>,
    reprobe_inflight: AtomicBool,
}

impl PersistentUdpProbe {
    #[cfg(test)]
    fn bind(target: SocketAddr) -> Option<Self> {
        Self::bind_with_options(
            target,
            "000000000".to_string(),
            None,
            None,
            None,
            None,
            Vec::new(),
        )
    }

    fn bind_with_options(
        target: SocketAddr,
        device_id: String,
        token: Option<[u8; 16]>,
        alt_target: Option<SocketAddr>,
        alt_ip_target: Option<SocketAddr>,
        dual_stack_target: Option<SocketAddr>,
        local_public_ips: Vec<IpAddr>,
    ) -> Option<Self> {
        if target.port() == 0 || target.ip().is_unspecified() {
            return None;
        }
        let primary_canon = canonicalize_socket_addr(target);
        let primary_is_ipv6 = primary_canon.is_ipv6();
        let (sock, socket_is_ipv6) = UdpProbeSlot::bind_unconnected_probe_socket(0, primary_canon)?;
        let port = sock.local_addr().ok()?.port();
        if port == 0 {
            return None;
        }
        let slot = Arc::new(UdpProbeSlot {
            port,
            primary_is_ipv6,
            socket_is_ipv6,
            target: primary_canon,
            state: Mutex::new(UdpProbeSlotState {
                sock: Some(sock),
                pause_count: 0,
                closed: false,
            }),
        });
        active_udp_probe_slots()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(port, Arc::clone(&slot));
        Some(Self {
            slot,
            device_id,
            token,
            alt_target: alt_target.map(canonicalize_socket_addr),
            alt_ip_target: alt_ip_target.map(canonicalize_socket_addr),
            dual_stack_target: dual_stack_target.map(canonicalize_socket_addr),
            local_public_ips,
            recent_nonces: Mutex::new(VecDeque::with_capacity(RECENT_LIGHTWEIGHT_NONCE_CAP)),
            dual_stack_nonces: Mutex::new(VecDeque::with_capacity(RECENT_LIGHTWEIGHT_NONCE_CAP)),
            probe_rx_lock: Mutex::new(()),
            reprobe_inflight: AtomicBool::new(false),
        })
    }

    fn local_port(&self) -> u16 {
        self.slot.port
    }

    fn is_ipv6(&self) -> bool {
        self.slot.primary_is_ipv6
    }

    fn is_allowed_source(&self, canon_from: SocketAddr) -> bool {
        canon_from == self.slot.target
            || self.alt_target.is_some_and(|a| canon_from == a)
            || self.alt_ip_target.is_some_and(|a| canon_from == a)
            || self.dual_stack_target.is_some_and(|a| canon_from == a)
    }

    #[cfg(test)]
    fn send_probe(&self, device_id: &str) {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let Some(pkt) = build_probe_bytes_for_mode(device_id, nonce, self.token) else {
            return;
        };
        let guard = self.slot.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.pause_count > 0 || guard.closed {
            return;
        }
        if let Some(ref sock) = guard.sock {
            let dest = normalize_probe_addr_for_socket(self.slot.target, self.slot.socket_is_ipv6);
            let _ = sock.send_to(&pkt, dest);
        }
    }

    /// 执行一次非阻塞 `RCSA` 排空并发送轻量保活探测包；若本次收到的合法 `RCSA` 将状态从
    /// `NatType::UdpBlocked` 恢复为 `NatType::ConeUnverified`，返回 `true` 以便上层按需触发异步重探。
    fn send_lightweight_refresh(&self, nat_profile: &Mutex<NatProfile>) -> bool {
        let Ok(_rx_guard) = self.probe_rx_lock.try_lock() else {
            return false;
        };
        let mut buf = [0u8; 128];
        let guard = self.slot.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.pause_count > 0 || guard.closed {
            return false;
        }
        let Some(ref sock) = guard.sock else {
            return false;
        };

        let mut recovered_from_udp_blocked = false;
        // 先非阻塞排空滞留的 `RCSA` 响应：严格校验来源 IP:port 在允许目标集合内且 nonce 命中。
        while let Ok((n, raw_from)) = sock.recv_from(&mut buf) {
            let from = canonicalize_socket_addr(raw_from);
            if !self.is_allowed_source(from) {
                continue;
            }
            if let Some((observed, ans_nonce)) = parse_udp_answer_packet(&buf[..n]) {
                let matched_primary = self
                    .recent_nonces
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&ans_nonce);
                let matched_ds = self
                    .dual_stack_nonces
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&ans_nonce);
                if (matched_primary || matched_ds)
                    && update_nat_profile_observed(nat_profile, observed)
                {
                    recovered_from_udp_blocked = true;
                }
            }
        }

        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        if let Some(pkt) = build_probe_bytes_for_mode(&self.device_id, nonce, self.token) {
            {
                let mut ring = self.recent_nonces.lock().unwrap_or_else(|e| e.into_inner());
                while ring.len() >= RECENT_LIGHTWEIGHT_NONCE_CAP {
                    ring.pop_front();
                }
                ring.push_back(nonce);
            }
            let dest = normalize_probe_addr_for_socket(self.slot.target, self.slot.socket_is_ipv6);
            let _ = sock.send_to(&pkt, dest);
        }

        if let (Some(tok), Some(ds_target)) = (self.token, self.dual_stack_target) {
            if self.slot.socket_is_ipv6 || ds_target.is_ipv4() {
                let mut ds_nonce = [0u8; 8];
                OsRng.fill_bytes(&mut ds_nonce);
                if let Ok(pkt) = build_udp_probe_packet_v2(&self.device_id, ds_nonce, tok) {
                    {
                        let mut ring = self
                            .dual_stack_nonces
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        while ring.len() >= RECENT_LIGHTWEIGHT_NONCE_CAP {
                            ring.pop_front();
                        }
                        ring.push_back(ds_nonce);
                    }
                    let dest = normalize_probe_addr_for_socket(ds_target, self.slot.socket_is_ipv6);
                    let _ = sock.send_to(&pkt, dest);
                }
            }
        }
        recovered_from_udp_blocked
    }

    /// 轻量异步外部可达自检：复用自有 `rc-server` 私有 `RCSP` 探测口验证网关映射公网 IP 的真实可达性与一致性
    /// （绝不启用第三方公有 STUN）；不可达或遭遇双层 NAT 假公网时返回 `Unreachable`，避免误报假公网候选。
    fn verify_external_mapping_reachability(
        &self,
        mapped_addr: SocketAddr,
        nat_profile: &Mutex<NatProfile>,
        stop_flag: &AtomicBool,
    ) -> ExternalMappingCheck {
        let want_v6 = mapped_addr.is_ipv6();
        let target = if self.slot.target.is_ipv6() == want_v6 {
            self.slot.target
        } else if let Some(ds) = self.dual_stack_target.filter(|a| a.is_ipv6() == want_v6) {
            ds
        } else {
            return ExternalMappingCheck::Skipped;
        };
        if !self.slot.socket_is_ipv6 && target.is_ipv6() {
            return ExternalMappingCheck::Skipped;
        }

        let _rx_guard = self.probe_rx_lock.lock().unwrap_or_else(|e| e.into_inner());
        let probe_sock = {
            let guard = self.slot.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.pause_count > 0 || guard.closed {
                None
            } else {
                guard.sock.as_ref().and_then(|s| s.try_clone().ok())
            }
        };
        let Some(ref sock) = probe_sock else {
            return ExternalMappingCheck::Skipped;
        };

        let expected_peer = canonicalize_socket_addr(target);
        let send_target = normalize_probe_addr_for_socket(expected_peer, self.slot.socket_is_ipv6);
        let mut sent_nonces = [[0u8; 8]; 2];
        let mut buf = [0u8; 128];

        for (attempt, &wait_budget) in SELF_CHECK_RETRY_WAITS.iter().enumerate() {
            if stop_flag.load(Ordering::Acquire) {
                return ExternalMappingCheck::Skipped;
            }
            let mut nonce = [0u8; 8];
            OsRng.fill_bytes(&mut nonce);
            sent_nonces[attempt] = nonce;
            let Some(pkt) = build_probe_bytes_for_mode(&self.device_id, nonce, self.token) else {
                return ExternalMappingCheck::Skipped;
            };
            if sock.send_to(&pkt, send_target).is_err() {
                continue;
            }

            let deadline = Instant::now() + wait_budget;
            loop {
                if stop_flag.load(Ordering::Acquire) {
                    return ExternalMappingCheck::Skipped;
                }
                match sock.recv_from(&mut buf) {
                    Ok((n, raw_from)) => {
                        let from = canonicalize_socket_addr(raw_from);
                        if !self.is_allowed_source(from) {
                            continue;
                        }
                        if let Some((observed, ans_nonce)) = parse_udp_answer_packet(&buf[..n]) {
                            let matched_self = sent_nonces[..=attempt].contains(&ans_nonce);
                            if matched_self && from == expected_peer {
                                let canon_obs = canonicalize_socket_addr(observed);
                                update_nat_profile_observed(nat_profile, canon_obs);
                                let obs_ip = canonicalize_ip(canon_obs.ip());
                                let mapped_ip = canonicalize_ip(mapped_addr.ip());
                                if obs_ip == mapped_ip {
                                    return ExternalMappingCheck::Reachable;
                                }
                                return ExternalMappingCheck::Unreachable(format!(
                                    "映射公网 IP ({mapped_ip}) 与自有 RCSP 观测公网 IP ({obs_ip}) 不一致（疑似双层 NAT / 假公网）"
                                ));
                            }
                            let matched_recent = self
                                .recent_nonces
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .contains(&ans_nonce)
                                || self
                                    .dual_stack_nonces
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .contains(&ans_nonce);
                            if matched_recent {
                                update_nat_profile_observed(nat_profile, observed);
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        let now = Instant::now();
                        if now >= deadline {
                            break;
                        }
                        thread::sleep(UDP_PROBE_POLL_STEP.min(deadline - now));
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }

        ExternalMappingCheck::Unreachable(
            "UPnP/PCP/NAT-PMP 映射外部可达自检超时（自有 rc-server RCSP 未收到响应，避开假公网映射）"
                .to_string(),
        )
    }

    fn run_initial_probe_round(
        &self,
        nat_profile: &Mutex<NatProfile>,
        rtt_ms: &Mutex<Option<u32>>,
        stop_flag: &AtomicBool,
    ) {
        let _rx_guard = self.probe_rx_lock.lock().unwrap_or_else(|e| e.into_inner());
        let probe_sock = {
            let guard = self.slot.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.pause_count > 0 || guard.closed {
                None
            } else {
                guard.sock.as_ref().and_then(|s| s.try_clone().ok())
            }
        };
        let Some(ref sock) = probe_sock else {
            return;
        };

        let m1 = probe_once_unconnected_to_target(
            sock,
            self.slot.socket_is_ipv6,
            self.slot.target,
            &self.device_id,
            self.token,
            stop_flag,
        )
        .map(|(obs, sample_rtt)| {
            record_rtt_sample_into(rtt_ms, sample_rtt);
            update_nat_profile_observed(nat_profile, obs);
            obs
        });

        let mut m2 = None;
        let mut m3 = None;
        let mut m4 = None;
        let mut m_alt_ip = None;

        if let (Some(o1), Some(alt_target)) = (m1, self.alt_target) {
            if alt_target != self.slot.target && o1.is_ipv6() == alt_target.is_ipv6() {
                m2 = probe_once_unconnected_to_target(
                    sock,
                    self.slot.socket_is_ipv6,
                    alt_target,
                    &self.device_id,
                    self.token,
                    stop_flag,
                )
                .map(|(obs, _)| obs);

                if let Some(o2) = m2 {
                    if o1 == o2 {
                        if let Some(alt_ip_target) = self.alt_ip_target {
                            if alt_ip_target != self.slot.target
                                && alt_ip_target != alt_target
                                && o1.is_ipv6() == alt_ip_target.is_ipv6()
                            {
                                m_alt_ip = probe_once_unconnected_to_target(
                                    sock,
                                    self.slot.socket_is_ipv6,
                                    alt_ip_target,
                                    &self.device_id,
                                    self.token,
                                    stop_flag,
                                )
                                .map(|(obs, _)| obs);
                            }
                        }
                    } else {
                        let (aux_p, aux_s) = probe_aux_pair_burst(
                            self.slot.target,
                            alt_target,
                            &self.device_id,
                            self.token,
                            stop_flag,
                        );
                        m3 = aux_p;
                        m4 = aux_s;
                    }
                }
            }
        }

        if stop_flag.load(Ordering::Acquire) {
            return;
        }

        let samples = NatProbeSamples {
            primary: m1,
            secondary: m2,
            aux_primary: m3,
            aux_secondary: m4,
            alt_ip: m_alt_ip,
            local_public_ips: self.local_public_ips.clone(),
        };
        let (nat_type, port_delta, port_range) = classify_nat_samples(&samples);
        {
            let mut guard = nat_profile.lock().unwrap_or_else(|e| e.into_inner());
            guard.nat_type = nat_type;
            guard.port_delta = port_delta;
            guard.port_range = port_range;
        }

        if self.token.is_some() {
            if let Some(ds_target) = self.dual_stack_target {
                if let Some((ds_obs, _)) = probe_once_unconnected_to_target(
                    sock,
                    self.slot.socket_is_ipv6,
                    ds_target,
                    &self.device_id,
                    self.token,
                    stop_flag,
                ) {
                    update_nat_profile_observed(nat_profile, ds_obs);
                }
            }
        }
    }
}

impl Drop for PersistentUdpProbe {
    fn drop(&mut self) {
        {
            let mut guard = self.slot.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.closed = true;
            drop(guard.sock.take());
        }
        let mut slots = active_udp_probe_slots()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = slots.get(&self.slot.port) {
            if Arc::ptr_eq(existing, &self.slot) {
                slots.remove(&self.slot.port);
            }
        }
    }
}

fn build_snapshot(
    cfg: &ServerConfig,
    state: ServerConnectionState,
    device_id: Option<String>,
    error_message: Option<String>,
    signal_addr: Option<String>,
    relay_addr: Option<String>,
) -> ServerStatusSnapshot {
    let device_id_formatted = device_id.as_deref().map(format_device_id);
    let ui_error = error_message.as_deref().map(|msg| {
        crate::ui_error::classify_signal_error(msg, crate::ui_error::current_platform())
    });
    ServerStatusSnapshot {
        enabled: cfg.enabled,
        server_host: cfg.server_host.clone(),
        signal_port: cfg.signal_port,
        relay_port: cfg.relay_port,
        state,
        device_id,
        device_id_formatted,
        error_message,
        ui_error,
        signal_addr,
        relay_addr,
        revision: 0,
    }
}

fn configure_tcp_keepalive(stream: &TcpStream) {
    let sock_ref = SockRef::from(stream);
    let _ = sock_ref.set_keepalive(true);
    let ka = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    let _ = sock_ref.set_tcp_keepalive(&ka);
}

#[derive(Debug)]
enum DialError {
    Stopped,
    Reconnecting,
    Failed(String),
}

/// 判断非阻塞 `connect()` 返回的 `io::Error` 是否表示握手仍在进行中（`EINPROGRESS` / `EALREADY` / `WSAEWOULDBLOCK` 等）。
pub(crate) fn is_connect_in_progress(err: &io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) || {
        #[cfg(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            matches!(err.raw_os_error(), Some(36 | 37))
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            matches!(err.raw_os_error(), Some(115 | 114))
        }
        #[cfg(windows)]
        {
            matches!(err.raw_os_error(), Some(10035..=10037))
        }
        #[cfg(not(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "linux",
            target_os = "android",
            windows
        )))]
        {
            false
        }
    }
}

#[cfg(test)]
fn dial_tcp(
    addr_str: &str,
    timeout: Duration,
    stop_flag: &AtomicBool,
) -> Result<TcpStream, DialError> {
    let proxy = crate::proxy::ProxyConfig::default();
    dial_tcp_with_epoch_and_proxy(addr_str, timeout, stop_flag, None, &proxy).map(|(s, _)| s)
}

fn dial_tcp_with_epoch_and_proxy(
    addr_str: &str,
    timeout: Duration,
    stop_flag: &AtomicBool,
    reconnect_epoch: Option<(&AtomicU64, u64)>,
    proxy: &crate::proxy::ProxyConfig,
) -> Result<(TcpStream, bool), DialError> {
    if stop_flag.load(Ordering::Acquire) {
        return Err(DialError::Stopped);
    }
    if reconnect_epoch.is_some_and(|(atom, expected)| atom.load(Ordering::Acquire) != expected) {
        return Err(DialError::Reconnecting);
    }
    let (host, port) = crate::proxy::split_host_port(addr_str)
        .map_err(|e| DialError::Failed(format!("解析信令地址 {addr_str} 失败：{e}")))?;

    match crate::proxy::dial_tcp_with_proxy_interruptible(&host, port, timeout, proxy, || {
        stop_flag.load(Ordering::Acquire)
            || reconnect_epoch
                .is_some_and(|(atom, expected)| atom.load(Ordering::Acquire) != expected)
    }) {
        Ok(res) => Ok(res),
        Err(crate::proxy::ProxyDialError::Cancelled) => {
            if stop_flag.load(Ordering::Acquire) {
                Err(DialError::Stopped)
            } else {
                Err(DialError::Reconnecting)
            }
        }
        Err(crate::proxy::ProxyDialError::Timeout(msg)) => Err(DialError::Failed(format!(
            "连接信令服务器 {addr_str} 超时：{msg}"
        ))),
        Err(crate::proxy::ProxyDialError::AuthFailed(msg)) => {
            Err(DialError::Failed(format!("代理认证失败 (407)：{msg}")))
        }
        Err(crate::proxy::ProxyDialError::Config(msg))
        | Err(crate::proxy::ProxyDialError::ConfigConflict(msg)) => Err(DialError::Failed(
            format!("proxy_config_conflict: 代理配置无效：{msg}"),
        )),
        Err(crate::proxy::ProxyDialError::ConnectFailed(msg)) => Err(DialError::Failed(format!(
            "通过代理连接信令服务器 {addr_str} 失败：{msg}"
        ))),
        Err(crate::proxy::ProxyDialError::DnsFailed(msg)) => Err(DialError::Failed(format!(
            "解析信令地址 {addr_str} 失败：{msg}"
        ))),
        Err(crate::proxy::ProxyDialError::TargetConnectFailed(msg)) => Err(DialError::Failed(
            format!("连接信令服务器 {addr_str} 失败：{msg}"),
        )),
    }
}

fn encode_outgoing_signal_frame(msg: &OutgoingSignalMsg) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_vec(msg).map_err(|e| format!("编码信令 JSON 失败：{e}"))?;
    if payload.is_empty() || payload.len() > MAX_SIGNAL_FRAME_LEN {
        return Err(format!(
            "信令帧长度 {} 越界（要求 1..={MAX_SIGNAL_FRAME_LEN}）",
            payload.len()
        ));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn write_signal_frame_plain(stream: &mut TcpStream, msg: &OutgoingSignalMsg) -> Result<(), String> {
    let frame = encode_outgoing_signal_frame(msg)?;
    write_all_retry(stream, &frame).map_err(|e| format!("写入信令帧失败：{e}"))?;
    stream.flush().map_err(|e| format!("刷新信令缓冲失败：{e}"))
}

fn write_signal_frame(stream: &mut TcpStream, msg: &OutgoingSignalMsg) -> Result<(), String> {
    write_signal_frame_plain(stream, msg)
}

fn write_signal_frame_tls(
    tls: &mut StreamOwned<ClientConnection, TcpStream>,
    msg: &OutgoingSignalMsg,
) -> Result<(), String> {
    let frame = encode_outgoing_signal_frame(msg)?;
    let mut pos = 0usize;
    while pos < frame.len() || tls.conn.wants_write() {
        if pos < frame.len() {
            let written = tls
                .conn
                .writer()
                .write(&frame[pos..])
                .map_err(|e| format!("加密信令帧失败：{e}"))?;
            if written == 0 {
                return Err("加密信令帧返回 0 字节".to_string());
            }
            pos += written;
        }
        while tls.conn.wants_write() {
            match tls.conn.write_tls(&mut tls.sock) {
                Ok(0) => {
                    return Err("写入信令 TLS 数据返回 0 字节".to_string());
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("写入信令 TLS 帧失败：{e}")),
            }
        }
    }
    loop {
        match tls.sock.flush() {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("刷新信令 TLS 缓冲失败：{e}")),
        }
    }
}

enum FrameRead {
    Message(Box<IncomingSignalMsg>),
    IdleTick,
    Eof,
    Stopped,
    Error(String),
}

fn read_signal_frame_from_io<S: Read>(stream: &mut S, stop_flag: &AtomicBool) -> FrameRead {
    let mut len_buf = [0u8; 4];
    let mut filled = 0usize;
    let mut partial_deadline: Option<Instant> = None;

    while filled < 4 {
        if stop_flag.load(Ordering::Acquire) {
            return FrameRead::Stopped;
        }
        match stream.read(&mut len_buf[filled..]) {
            Ok(0) => return FrameRead::Eof,
            Ok(n) => {
                filled += n;
                if filled < 4 && partial_deadline.is_none() {
                    partial_deadline = Some(Instant::now() + PARTIAL_FRAME_TIMEOUT);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if filled == 0 {
                    return FrameRead::IdleTick;
                }
                if partial_deadline.is_some_and(|d| Instant::now() >= d) {
                    return FrameRead::Error("读取信令帧长度头超时".to_string());
                }
            }
            Err(e) if filled == 0 && e.kind() == ErrorKind::UnexpectedEof => {
                return FrameRead::Eof;
            }
            Err(e) => return FrameRead::Error(e.to_string()),
        }
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_SIGNAL_FRAME_LEN {
        return FrameRead::Error(format!(
            "非法信令帧长度 {len}（允许 1..={MAX_SIGNAL_FRAME_LEN}）"
        ));
    }

    let mut payload = vec![0u8; len];
    let mut pos = 0usize;
    let payload_deadline = Instant::now() + PARTIAL_FRAME_TIMEOUT;
    while pos < len {
        if stop_flag.load(Ordering::Acquire) {
            return FrameRead::Stopped;
        }
        match stream.read(&mut payload[pos..]) {
            Ok(0) => return FrameRead::Eof,
            Ok(n) => pos += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if Instant::now() >= payload_deadline {
                    return FrameRead::Error("读取信令帧负载超时".to_string());
                }
            }
            Err(e) => return FrameRead::Error(e.to_string()),
        }
    }

    match serde_json::from_slice::<IncomingSignalMsg>(&payload) {
        Ok(msg) => FrameRead::Message(Box::new(msg)),
        Err(err) => FrameRead::Error(format!("解析信令 JSON 失败：{err}")),
    }
}

fn write_all_retry(stream: &mut TcpStream, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match stream.write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "write zero on signal tcp stream",
                ));
            }
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn random_hex(num_bytes: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = vec![0u8; num_bytes];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(num_bytes * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn read_test_frame(stream: &mut TcpStream) -> serde_json::Value {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn write_test_frame(stream: &mut TcpStream, val: &serde_json::Value) {
        let body = serde_json::to_vec(val).unwrap();
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        stream.write_all(&frame).unwrap();
        stream.flush().unwrap();
    }

    fn wait_until_connected(
        handle: &SignalClientHandle,
        timeout: Duration,
    ) -> ServerStatusSnapshot {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let snap = handle.status();
            if snap.state == ServerConnectionState::Connected {
                return snap;
            }
            thread::sleep(Duration::from_millis(15));
        }
        panic!(
            "timed out waiting for Connected; last={:?}",
            handle.status()
        );
    }

    #[test]
    fn mock_signal_server_register_connect_request_and_incoming_flow() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let signal_addr = listener.local_addr().unwrap();
        let udp_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp_sock.local_addr().unwrap();
        udp_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let fake_relay_addr = "127.0.0.1:21117".to_string();
        let relay_for_server = fake_relay_addr.clone();
        let udp_for_server = udp_addr.to_string();

        let server_thread = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let _ = conn.set_nodelay(true);

            let reg = read_test_frame(&mut conn);
            assert_eq!(reg["type"], "register");
            assert_eq!(reg["hostname"], "macbook-test");
            assert_eq!(reg["device_key"].as_str().unwrap().len(), 64);
            assert_eq!(
                reg["lan_addrs"],
                serde_json::json!([]),
                "initial Register must not leak :9901 before PersistentUdpProbe binds"
            );

            write_test_frame(
                &mut conn,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "604928235",
                    "formatted_id": "604 928 235",
                    "server_time": "2026-11-22T12:00:00Z",
                    "udp_probe_addr": udp_for_server,
                    "relay_addr": relay_for_server,
                }),
            );

            // 注册成功后客户端立即发送携带持久化 local_udp_port 的 Heartbeat 同步局域网打洞地址
            let hb0 = read_test_frame(&mut conn);
            assert_eq!(hb0["type"], "heartbeat");
            let hb0_lan = hb0["lan_addrs"].as_array().unwrap();
            assert_eq!(hb0_lan.len(), 1);
            let hb0_addr = hb0_lan[0].as_str().unwrap().to_string();
            assert!(
                hb0_addr.starts_with("192.168.1.10:") && !hb0_addr.ends_with(":9901"),
                "immediate heartbeat must rewrite lan_addr port to local_udp_port: {hb0_addr}"
            );

            // 第 1 次 connect_request：在线对端 -> 返回 punch_coord（同样携带改写后的 local_udp_port）
            let req1 = read_test_frame(&mut conn);
            assert_eq!(req1["type"], "connect_request");
            assert_eq!(req1["target_id"], "987654321");
            assert_eq!(req1["lan_addrs"], serde_json::json!([hb0_addr]));
            let sid1 = req1["session_id"].as_str().unwrap().to_string();

            write_test_frame(
                &mut conn,
                &serde_json::json!({
                    "type": "punch_coord",
                    "session_id": sid1,
                    "role": "client",
                    "peer_id": "987654321",
                    "peer_public_udp_addr": "198.51.100.22:60123",
                    "peer_lan_addrs": ["192.168.1.20:9901"],
                    "nonce": "deadbeef",
                    "relay_token": "tok-outbound-001",
                    "relay_addr": relay_for_server,
                }),
            );

            // 推送一条入站 host 通知（另一台设备来连我们）
            write_test_frame(
                &mut conn,
                &serde_json::json!({
                    "type": "punch_coord",
                    "session_id": "incoming-sess-42",
                    "role": "host",
                    "peer_id": "111222333",
                    "peer_public_udp_addr": "203.0.113.9:51234",
                    "peer_lan_addrs": ["192.168.1.30:9901"],
                    "nonce": "cafebabe",
                    "relay_token": "tok-inbound-002",
                    "relay_addr": relay_for_server,
                }),
            );

            // 第 2 次 connect_request：离线对端 -> 返回 peer_offline
            let req2 = read_test_frame(&mut conn);
            assert_eq!(req2["type"], "connect_request");
            assert_eq!(req2["target_id"], "999888777");
            let sid2 = req2["session_id"].as_str().unwrap().to_string();

            write_test_frame(
                &mut conn,
                &serde_json::json!({
                    "type": "peer_offline",
                    "target_id": "999888777",
                    "session_id": sid2,
                }),
            );

            // 等待客户端 stop() 关闭连接
            let mut sink = [0u8; 16];
            let _ = conn.read(&mut sink);
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: signal_addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            cached_device_id: None,
            ..ServerConfig::default()
        };

        let mut client = SignalClientHandle::spawn(
            cfg,
            "macbook-test".to_string(),
            vec!["192.168.1.10:9901".to_string()],
        );

        let snap = wait_until_connected(&client, Duration::from_secs(3));
        assert_eq!(snap.device_id.as_deref(), Some("604928235"));
        assert_eq!(snap.device_id_formatted.as_deref(), Some("604 928 235"));
        assert_eq!(snap.relay_addr.as_deref(), Some("127.0.0.1:21117"));
        assert!(snap.revision > 0);

        // 验证注册后自动发出合法 22 字节 UDP RCSP 探测包，并记住其持久化本地端口
        let mut udp_buf = [0u8; 64];
        let (n, probe_from) = udp_sock
            .recv_from(&mut udp_buf)
            .expect("expected UDP RCSP probe after register");
        assert_eq!(n, UDP_PROBE_LEN);
        assert_eq!(&udp_buf[0..4], b"RCSP");
        assert_eq!(udp_buf[4], 1);
        assert_eq!(&udp_buf[5..14], b"604928235");
        let probe_port = probe_from.port();
        assert_ne!(probe_port, 0);

        // 发起出站连接请求（带空格格式化的 9 位设备码也能被规范化）
        let grant = client
            .request_connect("987 654 321", Duration::from_secs(2))
            .expect("connect_request must resolve with ConnectGrant");
        assert_eq!(grant.target_id, "987654321");
        assert_eq!(grant.relay_token, "tok-outbound-001");
        assert_eq!(grant.relay_addr, "127.0.0.1:21117");
        assert_eq!(
            grant.peer_public_addr.as_deref(),
            Some("198.51.100.22:60123")
        );
        assert_eq!(grant.peer_lan_addrs, vec!["192.168.1.20:9901".to_string()]);
        assert_eq!(grant.local_udp_port, Some(probe_port));

        // 验证入站 host 通知被放入 try_recv_incoming() 队列
        let incoming = {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(inc) = client.try_recv_incoming() {
                    break inc;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for RelayIncoming"
                );
                thread::sleep(Duration::from_millis(10));
            }
        };
        assert_eq!(
            incoming,
            RelayIncoming {
                session_id: "incoming-sess-42".to_string(),
                relay_addr: "127.0.0.1:21117".to_string(),
                relay_token: "tok-inbound-002".to_string(),
                peer_id: "111222333".to_string(),
                peer_public_addr: Some("203.0.113.9:51234".to_string()),
                peer_lan_addrs: vec!["192.168.1.30:9901".to_string()],
                local_udp_port: Some(probe_port),
                self_nat_type: NatType::UdpBlocked,
                owner_grant: None,
                is_owner_connection: false,
                is_relay_alloc: false,
                ..RelayIncoming::default()
            }
        );

        // 验证 peer_offline 立即以可读错误返回
        let offline_err = client
            .request_connect("999 888 777", Duration::from_secs(2))
            .unwrap_err();
        assert!(
            offline_err.contains("999 888 777") && offline_err.contains("不在线"),
            "unexpected offline error: {offline_err}"
        );

        client.stop();
        server_thread.join().unwrap();
    }

    #[test]
    fn disabled_config_stays_disabled_and_rejects_connect() {
        let cfg = ServerConfig::default();
        let mut handle = SignalClientHandle::spawn(cfg, "host".to_string(), Vec::new());
        assert_eq!(handle.status().state, ServerConnectionState::Disabled);
        assert!(handle.status().revision > 0);
        assert!(handle
            .request_connect("604928235", Duration::from_millis(200))
            .is_err());
        handle.stop();
    }

    #[test]
    fn probe_server_connectivity_checks_both_ports_and_honors_inline_port() {
        let sig_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let rel_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sig_port = sig_listener.local_addr().unwrap().port();
        let rel_port = rel_listener.local_addr().unwrap().port();

        let msg =
            probe_server_connectivity("127.0.0.1", sig_port, rel_port, Duration::from_secs(2))
                .expect("both listening ports must probe ok");
        assert!(msg.contains("ms"), "expected latency in probe msg: {msg}");

        // L1: host 中携带显式端口时应优先使用解析出的端口（即使传入的 signal_port 不同）
        let inline_host = format!("127.0.0.1:{sig_port}");
        let msg_inline =
            probe_server_connectivity(&inline_host, 1, rel_port, Duration::from_secs(2))
                .expect("inline signal port in host must be honored");
        assert!(msg_inline.contains(&format!("127.0.0.1:{sig_port}")));

        // 关闭中继监听后应报错
        drop(rel_listener);
        let err =
            probe_server_connectivity("127.0.0.1", sig_port, rel_port, Duration::from_secs(1))
                .unwrap_err();
        assert!(err.contains("中继端口"), "unexpected error: {err}");
        drop(sig_listener);
    }

    #[test]
    fn build_udp_probe_packet_layout_and_device_id_validation() {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let pkt = build_udp_probe_packet("604928235", nonce).unwrap();
        assert_eq!(&pkt[0..4], b"RCSP");
        assert_eq!(pkt[4], 1);
        assert_eq!(&pkt[5..14], b"604928235");
        assert_eq!(&pkt[14..22], &nonce);

        // 协议允许匿名探测码 "000000000"
        let anon = build_udp_probe_packet("000000000", nonce).unwrap();
        assert_eq!(&anon[5..14], b"000000000");

        // 拒绝其余以 '0' 开头的非法 9 位码与格式错误输入
        assert!(build_udp_probe_packet("012345678", nonce).is_err());
        assert!(build_udp_probe_packet("000000001", nonce).is_err());
        assert!(build_udp_probe_packet("short", nonce).is_err());
        assert!(build_udp_probe_packet("60492823a", nonce).is_err());
    }

    #[test]
    fn relay_ready_and_status_callback_monotonic_revision() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let signal_addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let _ = read_test_frame(&mut conn);
            write_test_frame(
                &mut conn,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "222333444",
                    "formatted_id": "222 333 444",
                    "server_time": "2026-11-22T12:00:00Z",
                    "udp_probe_addr": "0.0.0.0:21116",
                    "relay_addr": "0.0.0.0:21117",
                }),
            );

            let hb = read_test_frame(&mut conn);
            assert_eq!(hb["type"], "heartbeat");

            let req = read_test_frame(&mut conn);
            assert_eq!(req["type"], "connect_request");
            let sid = req["session_id"].as_str().unwrap().to_string();
            write_test_frame(
                &mut conn,
                &serde_json::json!({
                    "type": "relay_ready",
                    "session_id": sid,
                    "role": "client",
                    "peer_id": "555666777",
                    "relay_token": "tok-relay-ready",
                    "relay_addr": "0.0.0.0:21117",
                    "expires_in_sec": 60,
                }),
            );

            let mut sink = [0u8; 8];
            let _ = conn.read(&mut sink);
        });

        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = Arc::clone(&seen);

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: signal_addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            cached_device_id: None,
            ..ServerConfig::default()
        };

        let mut client = SignalClientHandle::spawn_with_callback(
            cfg.clone(),
            "cb-test".to_string(),
            Vec::new(),
            move |snap| {
                seen_clone.lock().unwrap().push((snap.state, snap.revision));
            },
        );

        let snap = wait_until_connected(&client, Duration::from_secs(3));
        assert_eq!(snap.relay_addr.as_deref(), Some("127.0.0.1:21117"));

        let grant = client
            .request_connect("555666777", Duration::from_secs(2))
            .expect("relay_ready must resolve pending request_connect");
        assert_eq!(grant.relay_token, "tok-relay-ready");
        assert_eq!(grant.relay_addr, "127.0.0.1:21117");
        assert_eq!(grant.target_id, "555666777");

        let pairs = seen.lock().unwrap().clone();
        assert!(pairs.len() >= 2);
        assert_eq!(pairs[0].0, ServerConnectionState::Connecting);
        assert_eq!(pairs[1].0, ServerConnectionState::Connected);
        // M9: revision 严格单调递增
        for w in pairs.windows(2) {
            assert!(
                w[1].1 > w[0].1,
                "revision must strictly increase: {pairs:?}"
            );
        }

        // 重启/禁用快照的 revision 仍严格大于旧句柄
        let next_disabled = cfg.disabled_snapshot();
        assert!(next_disabled.revision > pairs.last().unwrap().1);

        client.stop();
        server.join().unwrap();
    }

    #[test]
    fn resolve_advertised_addr_handles_loopback_unspecified_ipv4_mapped_and_bare_hosts() {
        assert_eq!(
            resolve_advertised_addr("127.0.0.1:21117", "172.16.1.2", 21117),
            "172.16.1.2:21117"
        );
        assert_eq!(
            resolve_advertised_addr("127.0.0.1:31117", "172.16.1.2", 21117),
            "172.16.1.2:31117"
        );
        assert_eq!(
            resolve_advertised_addr("[::1]:21116", "172.16.1.2", 21116),
            "172.16.1.2:21116"
        );
        assert_eq!(
            resolve_advertised_addr("localhost:21117", "172.16.1.2", 21117),
            "172.16.1.2:21117"
        );
        assert_eq!(
            resolve_advertised_addr("0.0.0.0:21117", "172.16.1.2", 21117),
            "172.16.1.2:21117"
        );
        assert_eq!(
            resolve_advertised_addr("127.0.0.1:21117", "2001:db8::1", 21117),
            "[2001:db8::1]:21117"
        );
        // When fallback itself is loopback, keep advertised loopback addr as-is.
        assert_eq!(
            resolve_advertised_addr("127.0.0.1:54321", "127.0.0.1", 21117),
            "127.0.0.1:54321"
        );
        assert_eq!(
            resolve_advertised_addr("127.0.0.1:54321", "localhost", 21117),
            "127.0.0.1:54321"
        );
        // Explicit public IP from server is preserved.
        assert_eq!(
            resolve_advertised_addr("198.51.100.5:21117", "172.16.1.2", 21117),
            "198.51.100.5:21117"
        );

        // M3: IPv4-mapped IPv6 规范化后识别回环与未指定地址
        assert_eq!(
            resolve_advertised_addr("[::ffff:127.0.0.1]:21117", "172.16.1.2", 21117),
            "172.16.1.2:21117"
        );
        assert_eq!(
            resolve_advertised_addr("[::ffff:0.0.0.0]:31117", "172.16.1.2", 21117),
            "172.16.1.2:31117"
        );
        assert_eq!(
            resolve_advertised_addr("[::ffff:198.51.100.5]:21117", "172.16.1.2", 21117),
            "198.51.100.5:21117"
        );

        // M3: port == 0 在所有路径（含非回环与回环对回环）下均替换为 fallback_port
        assert_eq!(
            resolve_advertised_addr("198.51.100.5:0", "172.16.1.2", 21117),
            "198.51.100.5:21117"
        );
        assert_eq!(
            resolve_advertised_addr("127.0.0.1:0", "127.0.0.1", 21117),
            "127.0.0.1:21117"
        );
        assert_eq!(
            resolve_advertised_addr("relay.example.com:0", "172.16.1.2", 21117),
            "relay.example.com:21117"
        );

        // M3: 裸主机名 / 裸 IP 补全端口并执行回环/未指定重写
        assert_eq!(
            resolve_advertised_addr("localhost", "172.16.1.2", 21117),
            "172.16.1.2:21117"
        );
        assert_eq!(
            resolve_advertised_addr("0.0.0.0", "172.16.1.2", 21117),
            "172.16.1.2:21117"
        );
        assert_eq!(
            resolve_advertised_addr("::1", "172.16.1.2", 21117),
            "172.16.1.2:21117"
        );
        assert_eq!(
            resolve_advertised_addr("relay.example.com", "172.16.1.2", 21117),
            "relay.example.com:21117"
        );
    }

    #[test]
    fn sanitize_hostname_and_lan_addrs_enforce_bounds_and_strip_control_chars() {
        assert_eq!(sanitize_hostname("  my\nhost\0\x1bname  "), "myhostname");

        // 多字节 UTF-8 截断不得切在字符中间，且字节数 <= 128
        let long_cjk = "中文主机名".repeat(20); // 100 字符 = 300 字节
        let truncated = sanitize_hostname(&long_cjk);
        assert!(truncated.len() <= MAX_HOSTNAME_BYTES);
        assert!(truncated.len() >= MAX_HOSTNAME_BYTES - 3);
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());

        // lan_addrs 过滤空串、超 64B、含空白/控制/非 ASCII 字符，最多保留 16 条
        let mut raw = vec![
            "".to_string(),
            "192.168.1.1:9901\n".to_string(),
            "192.168.1.1 9901".to_string(),
            "a".repeat(65),
            "中文:9901".to_string(),
        ];
        for i in 1..=20 {
            raw.push(format!("192.168.1.{i}:9901"));
        }
        let cleaned = sanitize_lan_addrs(&raw);
        assert_eq!(cleaned.len(), MAX_LAN_ADDRS);
        assert_eq!(cleaned[0], "192.168.1.1:9901");
        assert_eq!(cleaned[15], "192.168.1.16:9901");
    }

    #[test]
    fn dispatch_coord_and_peer_offline_enforce_strict_role_and_session_matching() {
        let cfg = ServerConfig::default();
        let shared = Arc::new(SharedState {
            status: Mutex::new(cfg.disabled_snapshot()),
            status_updates: Mutex::new(VecDeque::new()),
            incoming: Mutex::new(VecDeque::new()),
            device_status_events: Mutex::new(VecDeque::new()),
            kicked_reasons: Mutex::new(VecDeque::new()),
            pending_connects: Mutex::new(HashMap::new()),
            active_writer: Mutex::new(None),
            shutdown_stream: Mutex::new(None),
            stop_flag: AtomicBool::new(false),
            stop_lock: Mutex::new(false),
            stop_cv: Condvar::new(),
            fast_reconnect: AtomicBool::new(false),
            reset_backoff_on_reconnect: AtomicBool::new(false),
            reconnect_epoch: AtomicU64::new(0),
            reconnect_reason: Mutex::new(None),
            last_server_activity: Mutex::new(None),
            last_timeout_reconnect: Mutex::new(None),
            local_udp_port: AtomicU16::new(45678),
            local_udp_is_ipv6: AtomicBool::new(false),
            nat_profile: Mutex::new(NatProfile::default()),
            rtt_ms: Mutex::new(None),
            last_heartbeat_sent_at: Mutex::new(None),
            active_probe: Mutex::new(None),
            dynamic_lan_discovery: false,
            connected_probe_targets: Mutex::new(Vec::new()),
            server_is_loopback: AtomicBool::new(false),
            upnp_enabled: AtomicBool::new(false),
            upnp_status: Mutex::new(UpnpStatus::Disabled),
            upnp_external_addr: Mutex::new(None),
            upnp_lease: Mutex::new(None),
            upnp_gen: AtomicU64::new(0),
            upnp_heartbeat_needed: AtomicBool::new(false),
            lan_addrs: Vec::new(),
            enabled: true,
            token_provider: None,
            token_refresher: None,
            device_pubkey: None,
            allow_remote_assist: AtomicU8::new(ASSIST_UNSET),
            allow_remote_control: AtomicU8::new(REMOTE_CTRL_UNSET),
            wol_enabled: AtomicU8::new(WOL_UNSET),
            mac_addr: Mutex::new(None),
            device_wol_events: Mutex::new(VecDeque::new()),
            device_wol_capable: Mutex::new(HashMap::new()),
            pending_wols: Mutex::new(HashMap::new()),
            wol_relay_inflight: Arc::new(AtomicUsize::new(0)),
            wol_relay_history: Mutex::new(VecDeque::new()),
            proxy_override: Mutex::new(None),
            proxy_active: AtomicBool::new(false),
            wol_relay_test_sink: Mutex::new(None),
        });

        let (tx1, rx1) = mpsc::sync_channel(1);
        shared.pending_connects.lock().unwrap().insert(
            "sess-A".to_string(),
            PendingConnect {
                target_id: "987654321".to_string(),
                tx: tx1,
            },
        );

        // H5: 非空但未匹配的 session_id 不得误匹配同一 target_id 的其他 pending 会话，也不得推入 incoming
        dispatch_coord(
            &shared,
            CoordPayload {
                session_id: "sess-OTHER".to_string(),
                role: "client".to_string(),
                peer_id: "987654321".to_string(),
                relay_addr: "127.0.0.1:21117".to_string(),
                relay_token: "tok-wrong".to_string(),
                ..CoordPayload::default()
            },
        );
        assert!(rx1.try_recv().is_err());
        assert!(shared.incoming.lock().unwrap().is_empty());

        // H5: 未知角色不得推入 incoming 也不得匹配 pending
        dispatch_coord(
            &shared,
            CoordPayload {
                session_id: "sess-A".to_string(),
                role: "observer".to_string(),
                peer_id: "987654321".to_string(),
                relay_addr: "127.0.0.1:21117".to_string(),
                relay_token: "tok-bogus".to_string(),
                ..CoordPayload::default()
            },
        );
        assert!(rx1.try_recv().is_err());
        assert!(shared.incoming.lock().unwrap().is_empty());

        // H5: PeerOffline 携带不匹配的 session_id 不得误杀 sess-A
        handle_incoming_message(
            &shared,
            "111222333",
            IncomingSignalMsg::PeerOffline {
                target_id: "987654321".to_string(),
                session_id: "sess-OTHER".to_string(),
            },
            "127.0.0.1",
            21117,
            "127.0.0.1:21117",
            "127.0.0.1:21117",
        );
        assert!(rx1.try_recv().is_err());

        // 仅当 session_id 为空时才按 target_id 兜底匹配；空串 peer_public_addr 清洗为 None
        dispatch_coord(
            &shared,
            CoordPayload {
                session_id: "".to_string(),
                role: "client".to_string(),
                peer_id: "987654321".to_string(),
                relay_addr: "127.0.0.1:21117".to_string(),
                relay_token: "tok-ok".to_string(),
                peer_public_addr: Some("   ".to_string()),
                peer_lan_addrs: vec!["10.0.0.2:50000".to_string()],
                ..CoordPayload::default()
            },
        );
        let grant = rx1.try_recv().unwrap().unwrap();
        assert_eq!(grant.relay_token, "tok-ok");
        assert_eq!(grant.peer_public_addr, None);
        assert_eq!(grant.peer_lan_addrs, vec!["10.0.0.2:50000".to_string()]);
        assert_eq!(grant.local_udp_port, Some(45678));
        assert!(shared.incoming.lock().unwrap().is_empty());

        // 只有 role == "host" 才进入 incoming
        dispatch_coord(
            &shared,
            CoordPayload {
                session_id: "in-1".to_string(),
                role: "host".to_string(),
                peer_id: "111222333".to_string(),
                relay_addr: "127.0.0.1:21117".to_string(),
                relay_token: "tok-in".to_string(),
                peer_public_addr: Some("198.51.100.7:44444".to_string()),
                peer_lan_addrs: vec!["192.168.1.9:9901".to_string()],
                ..CoordPayload::default()
            },
        );
        let inc = shared.incoming.lock().unwrap().pop_front().unwrap();
        assert_eq!(inc.peer_public_addr.as_deref(), Some("198.51.100.7:44444"));
        assert_eq!(inc.peer_lan_addrs, vec!["192.168.1.9:9901".to_string()]);
        assert_eq!(inc.local_udp_port, Some(45678));
        assert!(!inc.is_relay_alloc);

        // 验证 handle_incoming_message 对 RelayReady 设置 is_relay_alloc=true、对 PunchCoord 设置 is_relay_alloc=false
        handle_incoming_message(
            &shared,
            "987654321",
            IncomingSignalMsg::RelayReady {
                session_id: "in-relay-ready".to_string(),
                role: "host".to_string(),
                peer_id: "111222333".to_string(),
                relay_token: "tok-relay-alloc".to_string(),
                relay_addr: "127.0.0.1:21117".to_string(),
                owner_grant: None,
                is_owner_connection: true,
            },
            "127.0.0.1",
            21117,
            "127.0.0.1:21117",
            "127.0.0.1:21117",
        );
        let inc_relay = shared.incoming.lock().unwrap().pop_front().unwrap();
        assert!(inc_relay.is_relay_alloc);
        assert_eq!(inc_relay.relay_token, "tok-relay-alloc");

        handle_incoming_message(
            &shared,
            "987654321",
            IncomingSignalMsg::PunchCoord {
                session_id: "in-punch".to_string(),
                role: "host".to_string(),
                peer_id: "111222333".to_string(),
                peer_public_udp_addr: None,
                peer_public_udp_addrs: Vec::new(),
                self_public_udp_addr: None,
                peer_nat_type: None,
                peer_nat_port_delta: None,
                self_nat_port_range: None,
                peer_nat_port_range: None,
                peer_lan_addrs: Vec::new(),
                punch_secret: None,
                start_after_ms: None,
                relay_fallback_after_ms: None,
                relay_token: "tok-punch".to_string(),
                relay_addr: "127.0.0.1:21117".to_string(),
                owner_grant: None,
                is_owner_connection: true,
            },
            "127.0.0.1",
            21117,
            "127.0.0.1:21117",
            "127.0.0.1:21117",
        );
        let inc_punch = shared.incoming.lock().unwrap().pop_front().unwrap();
        assert!(!inc_punch.is_relay_alloc);
        assert_eq!(inc_punch.relay_token, "tok-punch");
    }

    #[test]
    fn kicked_terminal_reasons_stop_reconnecting_and_backoff_policy_is_strict() {
        assert!(!should_reset_backoff(
            Duration::from_secs(10),
            false,
            STABLE_CONNECTION_THRESHOLD
        ));
        assert!(should_reset_backoff(
            Duration::from_secs(30),
            false,
            STABLE_CONNECTION_THRESHOLD
        ));
        assert!(!should_reset_backoff(
            Duration::from_secs(300),
            true,
            STABLE_CONNECTION_THRESHOLD
        ));
        assert!(classify_kicked_reason("replaced_by_new_connection").0);
        assert!(classify_kicked_reason("disabled_by_admin").0);
        assert!(!classify_kicked_reason("server_shutdown").0);

        // 端到端验证：收到 Kicked(replaced_by_new_connection) 后发出 Error 且不再重连
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let signal_addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        listener.set_nonblocking(false).unwrap();

        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            accept_count_srv.fetch_add(1, Ordering::SeqCst);
            let _ = read_test_frame(&mut conn);
            write_test_frame(
                &mut conn,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "333444555",
                    "formatted_id": "333 444 555",
                }),
            );
            write_test_frame(
                &mut conn,
                &serde_json::json!({
                    "type": "kicked",
                    "reason": "replaced_by_new_connection",
                }),
            );
            // 若客户端错误地自动重连，这里会接到第 2 次连接
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_millis(350);
            while Instant::now() < deadline {
                if listener.accept().is_ok() {
                    accept_count_srv.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: signal_addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            cached_device_id: None,
            ..ServerConfig::default()
        };
        let fast_timing = SignalTiming {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: [
                Duration::from_millis(30),
                Duration::from_millis(60),
                Duration::from_millis(120),
                Duration::from_millis(240),
            ],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "kick-test".to_string(),
            Vec::new(),
            None,
            fast_timing,
            |_| {},
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if client.status().state == ServerConnectionState::Error {
                break;
            }
            thread::sleep(Duration::from_millis(15));
        }
        let snap = client.status();
        assert_eq!(snap.state, ServerConnectionState::Error);
        assert!(
            snap.error_message
                .as_deref()
                .unwrap_or("")
                .contains("已停止自动重连"),
            "unexpected kicked error msg: {:?}",
            snap.error_message
        );

        server.join().unwrap();
        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            1,
            "terminal Kicked must not auto-reconnect"
        );
        client.stop();
    }

    #[test]
    fn dead_connection_without_server_activity_triggers_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let signal_addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);

        let server = thread::spawn(move || {
            for round in 0..2 {
                let (mut conn, _) = listener.accept().unwrap();
                let _ = read_test_frame(&mut conn);
                write_test_frame(
                    &mut conn,
                    &serde_json::json!({
                        "type": "registered",
                        "device_id": "444555666",
                        "formatted_id": "444 555 666",
                    }),
                );
                accept_count_srv.fetch_add(1, Ordering::SeqCst);
                // 第 1 轮故意不回 HeartbeatAck（模拟半开死链），等待客户端超时重连
                if round == 0 {
                    let mut sink = [0u8; 64];
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
                    while matches!(conn.read(&mut sink), Ok(n) if n > 0) {}
                } else {
                    let mut sink = [0u8; 16];
                    let _ = conn.read(&mut sink);
                }
            }
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: signal_addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            cached_device_id: None,
            ..ServerConfig::default()
        };
        let fast_timing = SignalTiming {
            heartbeat_interval: Duration::from_millis(80),
            activity_timeout: Duration::from_millis(250),
            stable_threshold: Duration::from_secs(30),
            backoffs: [
                Duration::from_millis(40),
                Duration::from_millis(80),
                Duration::from_millis(120),
                Duration::from_millis(200),
            ],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "m4-dead-conn".to_string(),
            Vec::new(),
            None,
            fast_timing,
            |_| {},
        );

        let deadline = Instant::now() + Duration::from_secs(3);
        while accept_count.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            2,
            "client should detect dead connection via activity timeout and reconnect"
        );

        client.stop();
        server.join().unwrap();
    }

    #[test]
    fn dial_tcp_and_signal_stop_interrupt_promptly_without_waiting_on_writer_lock() {
        // H2: 预先置位 stop_flag 时 dial_tcp 立即返回 Stopped
        let stop = AtomicBool::new(true);
        assert!(matches!(
            dial_tcp("127.0.0.1:1", Duration::from_secs(5), &stop),
            Err(DialError::Stopped)
        ));

        // H2: 对已关闭端口的非阻塞拨号必须快速返回 Failed（而非耗尽整个 5s 超时）
        let temp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_addr = temp_listener.local_addr().unwrap();
        drop(temp_listener);
        let no_stop = AtomicBool::new(false);
        let t0 = Instant::now();
        assert!(matches!(
            dial_tcp(&closed_addr.to_string(), Duration::from_secs(5), &no_stop),
            Err(DialError::Failed(_))
        ));
        let fast_fail_limit = if cfg!(windows) {
            Duration::from_secs(4)
        } else {
            Duration::from_secs(2)
        };
        assert!(
            t0.elapsed() < fast_fail_limit,
            "closed port dial should fail fast, took {:?}",
            t0.elapsed()
        );

        // H2: 拨号过程中外部置位 stop_flag 应迅速中断（测试黑洞地址 RFC 5737 TEST-NET-1）
        let cancel_mid = Arc::new(AtomicBool::new(false));
        let cancel_trigger = Arc::clone(&cancel_mid);
        let trigger_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            cancel_trigger.store(true, Ordering::Release);
        });
        let t1 = Instant::now();
        let mid_res = dial_tcp("192.0.2.1:21116", Duration::from_secs(5), &cancel_mid);
        assert!(mid_res.is_err());
        assert!(
            t1.elapsed() < Duration::from_secs(2),
            "in-flight dial must abort promptly on stop_flag, took {:?}",
            t1.elapsed()
        );
        let _ = trigger_thread.join();

        // H7/M2: 即使 active_writer 锁被占用，signal_stop() 仍能立刻失败 pending 并关闭 shutdown_stream
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8];
            let _ = s.read(&mut buf);
        });
        let stream = TcpStream::connect(addr).unwrap();
        let shutdown_clone = stream.try_clone().unwrap();

        let cfg = ServerConfig::default();
        let shared = Arc::new(SharedState {
            status: Mutex::new(cfg.disabled_snapshot()),
            status_updates: Mutex::new(VecDeque::new()),
            incoming: Mutex::new(VecDeque::new()),
            device_status_events: Mutex::new(VecDeque::new()),
            kicked_reasons: Mutex::new(VecDeque::new()),
            pending_connects: Mutex::new(HashMap::new()),
            active_writer: Mutex::new(Some(SignalWriter::Plain(stream))),
            shutdown_stream: Mutex::new(Some(shutdown_clone)),
            stop_flag: AtomicBool::new(false),
            stop_lock: Mutex::new(false),
            stop_cv: Condvar::new(),
            fast_reconnect: AtomicBool::new(false),
            reset_backoff_on_reconnect: AtomicBool::new(false),
            reconnect_epoch: AtomicU64::new(0),
            reconnect_reason: Mutex::new(None),
            last_server_activity: Mutex::new(None),
            last_timeout_reconnect: Mutex::new(None),
            local_udp_port: AtomicU16::new(0),
            local_udp_is_ipv6: AtomicBool::new(false),
            nat_profile: Mutex::new(NatProfile::default()),
            rtt_ms: Mutex::new(None),
            last_heartbeat_sent_at: Mutex::new(None),
            active_probe: Mutex::new(None),
            dynamic_lan_discovery: false,
            connected_probe_targets: Mutex::new(Vec::new()),
            server_is_loopback: AtomicBool::new(false),
            upnp_enabled: AtomicBool::new(false),
            upnp_status: Mutex::new(UpnpStatus::Disabled),
            upnp_external_addr: Mutex::new(None),
            upnp_lease: Mutex::new(None),
            upnp_gen: AtomicU64::new(0),
            upnp_heartbeat_needed: AtomicBool::new(false),
            lan_addrs: Vec::new(),
            enabled: true,
            token_provider: None,
            token_refresher: None,
            device_pubkey: None,
            allow_remote_assist: AtomicU8::new(ASSIST_UNSET),
            allow_remote_control: AtomicU8::new(REMOTE_CTRL_UNSET),
            wol_enabled: AtomicU8::new(WOL_UNSET),
            mac_addr: Mutex::new(None),
            device_wol_events: Mutex::new(VecDeque::new()),
            device_wol_capable: Mutex::new(HashMap::new()),
            pending_wols: Mutex::new(HashMap::new()),
            wol_relay_inflight: Arc::new(AtomicUsize::new(0)),
            wol_relay_history: Mutex::new(VecDeque::new()),
            proxy_override: Mutex::new(None),
            proxy_active: AtomicBool::new(false),
            wol_relay_test_sink: Mutex::new(None),
        });

        let (tx, rx) = mpsc::sync_channel(1);
        shared.pending_connects.lock().unwrap().insert(
            "s1".to_string(),
            PendingConnect {
                target_id: "604928235".to_string(),
                tx,
            },
        );

        // 故意持有 active_writer 锁，验证另一线程调用 signal_stop() 不会死锁/阻塞
        let _held_writer = shared.active_writer.lock().unwrap();
        let shared_for_stop = Arc::clone(&shared);
        let stopper = thread::spawn(move || {
            shared_for_stop.signal_stop();
        });
        stopper.join().unwrap();

        let pending_res = rx.recv_timeout(Duration::from_millis(500)).unwrap();
        assert!(pending_res.is_err());
        assert!(shared.shutdown_stream.lock().unwrap().is_none());
        drop(_held_writer);
        srv.join().unwrap();
    }

    #[test]
    fn resolve_udp_probe_target_prefers_matching_ip_family() {
        let v4_peer: SocketAddr = "127.0.0.1:21116".parse().unwrap();
        let target = resolve_udp_probe_target("127.0.0.1:21116", Some(v4_peer)).unwrap();
        assert!(target.is_ipv4());
        assert_eq!(target, v4_peer);
    }

    #[test]
    fn persistent_udp_probe_keeps_stable_port_and_releases_exclusively_for_p2p() {
        let sig_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sig_addr = sig_udp.local_addr().unwrap();
        sig_udp
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let probe = PersistentUdpProbe::bind(sig_addr).expect("bind persistent probe");
        let port = probe.local_port();
        assert_ne!(port, 0);

        // 连续两次探测均从同一本地端口发出
        let mut buf = [0u8; 64];
        probe.send_probe("604928235");
        let (n1, from1) = sig_udp.recv_from(&mut buf).unwrap();
        assert_eq!(n1, UDP_PROBE_LEN);
        assert_eq!(from1.port(), port);

        probe.send_probe("604928235");
        let (n2, from2) = sig_udp.recv_from(&mut buf).unwrap();
        assert_eq!(n2, UDP_PROBE_LEN);
        assert_eq!(from2.port(), port);

        // 通过 acquire_local_udp_port_for_p2p 统一在全平台独占释放探测端口，
        // P2P 无需 SO_REUSEPORT 即可独占绑定同一端口；释放守卫后自动恢复探测端口。
        let hold = acquire_local_udp_port_for_p2p(Some(port));
        let p2p_sock = UdpSocket::bind(SocketAddr::from(([0u8; 4], port)))
            .expect("P2P socket must exclusively bind local_udp_port while hold is active");
        p2p_sock
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0u8..5 {
            let payload = [b'P', b'2', b'P', i];
            peer.send_to(&payload, SocketAddr::from(([127, 0, 0, 1], port)))
                .unwrap();
            let (rn, rfrom) = p2p_sock
                .recv_from(&mut buf)
                .expect("p2p must recv peer pkt");
            assert_eq!(&buf[..rn], &payload);
            assert_eq!(rfrom, peer.local_addr().unwrap());
        }

        drop(p2p_sock);
        drop(hold);
        probe.send_probe("604928235");
        let (n3, from3) = sig_udp.recv_from(&mut buf).unwrap();
        assert_eq!(n3, UDP_PROBE_LEN);
        assert_eq!(from3.port(), port);
    }

    #[test]
    fn effective_lan_addrs_rewrites_ports_to_local_udp_port() {
        let raw = vec![
            "192.168.1.10:9901".to_string(),
            "[::ffff:192.168.1.10]:9901".to_string(), // IPv4-mapped 去重
            "10.0.0.5".to_string(),                   // 裸 IPv4 补全端口
            "[fd00::1]:9901".to_string(),             // IPv6 改写端口
        ];
        // H4: local_udp_port == 0 时必须返回空列表，绝不泄漏 :9901 作为打洞候选
        assert!(
            effective_lan_addrs(&raw, 0, false, false).is_empty(),
            "local_udp_port == 0 must return empty lan_addrs (IPv4)"
        );
        assert!(
            effective_lan_addrs(&raw, 0, true, false).is_empty(),
            "local_udp_port == 0 must return empty lan_addrs (IPv6)"
        );
        // H3: IPv4 探测套接字仅改写并上报 IPv4 LAN 地址（自动去重 ::ffff: 并跳过 IPv6）
        assert_eq!(
            effective_lan_addrs(&raw, 54321, false, false),
            vec![
                "192.168.1.10:54321".to_string(),
                "10.0.0.5:54321".to_string(),
            ]
        );
        // H3: IPv6 探测套接字仅改写并上报 IPv6 LAN 地址（跳过 IPv4）
        assert_eq!(
            effective_lan_addrs(&raw, 54321, true, false),
            vec!["[fd00::1]:54321".to_string()]
        );
    }

    #[test]
    fn effective_lan_addrs_filters_unusable_and_gates_loopback() {
        let raw_v4 = vec![
            "0.0.0.0:9901".to_string(),
            "127.0.0.1:9901".to_string(),
            "[::ffff:127.0.0.1]:9901".to_string(),
            "169.254.10.20:9901".to_string(),
            "224.0.0.1:9901".to_string(),
            "255.255.255.255:9901".to_string(),
            "192.168.1.10:9901".to_string(),
        ];
        assert_eq!(
            effective_lan_addrs(&raw_v4, 41000, false, false),
            vec!["192.168.1.10:41000".to_string()]
        );
        assert_eq!(
            effective_lan_addrs(&raw_v4, 41000, false, true),
            vec![
                "127.0.0.1:41000".to_string(),
                "192.168.1.10:41000".to_string(),
            ]
        );

        let raw_v6 = vec![
            "[::]:9901".to_string(),
            "[::1]:9901".to_string(),
            "[fe80::1]:9901".to_string(),
            "[ff02::1]:9901".to_string(),
            "[fd00::2]:9901".to_string(),
        ];
        assert_eq!(
            effective_lan_addrs(&raw_v6, 41000, true, false),
            vec!["[fd00::2]:41000".to_string()]
        );
        assert_eq!(
            effective_lan_addrs(&raw_v6, 41000, true, true),
            vec!["[::1]:41000".to_string(), "[fd00::2]:41000".to_string(),]
        );
    }

    #[test]
    fn shared_state_current_effective_lan_addrs_and_clear_active_writer() {
        let opts = SignalClientOptions::default();
        assert!(!opts.dynamic_lan_discovery);
        assert!(format!("{opts:?}").contains("dynamic_lan_discovery: false"));

        let cfg = ServerConfig::default();
        let make_shared = |dynamic_lan_discovery: bool| SharedState {
            status: Mutex::new(cfg.disabled_snapshot()),
            status_updates: Mutex::new(VecDeque::new()),
            incoming: Mutex::new(VecDeque::new()),
            device_status_events: Mutex::new(VecDeque::new()),
            kicked_reasons: Mutex::new(VecDeque::new()),
            pending_connects: Mutex::new(HashMap::new()),
            active_writer: Mutex::new(None),
            shutdown_stream: Mutex::new(None),
            stop_flag: AtomicBool::new(false),
            stop_lock: Mutex::new(false),
            stop_cv: Condvar::new(),
            fast_reconnect: AtomicBool::new(false),
            reset_backoff_on_reconnect: AtomicBool::new(false),
            reconnect_epoch: AtomicU64::new(0),
            reconnect_reason: Mutex::new(None),
            last_server_activity: Mutex::new(None),
            last_timeout_reconnect: Mutex::new(None),
            local_udp_port: AtomicU16::new(50000),
            local_udp_is_ipv6: AtomicBool::new(false),
            nat_profile: Mutex::new(NatProfile::default()),
            rtt_ms: Mutex::new(None),
            last_heartbeat_sent_at: Mutex::new(None),
            active_probe: Mutex::new(None),
            dynamic_lan_discovery,
            connected_probe_targets: Mutex::new(vec!["192.0.2.10:21116".parse().unwrap()]),
            server_is_loopback: AtomicBool::new(true),
            upnp_enabled: AtomicBool::new(false),
            upnp_status: Mutex::new(UpnpStatus::Disabled),
            upnp_external_addr: Mutex::new(None),
            upnp_lease: Mutex::new(None),
            upnp_gen: AtomicU64::new(0),
            upnp_heartbeat_needed: AtomicBool::new(false),
            lan_addrs: Vec::new(),
            enabled: true,
            token_provider: None,
            token_refresher: None,
            device_pubkey: None,
            allow_remote_assist: AtomicU8::new(ASSIST_UNSET),
            allow_remote_control: AtomicU8::new(REMOTE_CTRL_UNSET),
            wol_enabled: AtomicU8::new(WOL_UNSET),
            mac_addr: Mutex::new(None),
            device_wol_events: Mutex::new(VecDeque::new()),
            device_wol_capable: Mutex::new(HashMap::new()),
            pending_wols: Mutex::new(HashMap::new()),
            wol_relay_inflight: Arc::new(AtomicUsize::new(0)),
            wol_relay_history: Mutex::new(VecDeque::new()),
            proxy_override: Mutex::new(None),
            proxy_active: AtomicBool::new(false),
            wol_relay_test_sink: Mutex::new(None),
        };

        let static_addrs = vec![
            "127.0.0.1:9901".to_string(),
            "203.0.113.50:9901".to_string(),
            "[fd00::5]:9901".to_string(),
        ];

        // dynamic_lan_discovery == false 时仅返回静态筛选结果；server_is_loopback == true 时放行 127.0.0.1
        let static_only = make_shared(false);
        assert!(static_only
            .current_effective_lan_addrs(&static_addrs, 0, false)
            .is_empty());
        assert_eq!(
            static_only.current_effective_lan_addrs(&static_addrs, 50000, false),
            vec![
                "127.0.0.1:50000".to_string(),
                "203.0.113.50:50000".to_string(),
            ]
        );

        // clear_active_writer 必须重置 local_udp_port / local_udp_is_ipv6 / server_is_loopback 与 connected_probe_targets
        static_only.clear_active_writer();
        assert_eq!(static_only.local_udp_port.load(Ordering::Acquire), 0);
        assert!(!static_only.local_udp_is_ipv6.load(Ordering::Acquire));
        assert!(!static_only.server_is_loopback.load(Ordering::Acquire));
        assert!(static_only
            .connected_probe_targets
            .lock()
            .unwrap()
            .is_empty());
        assert_eq!(
            static_only.current_effective_lan_addrs(&static_addrs, 50000, false),
            vec!["203.0.113.50:50000".to_string()]
        );

        // dynamic_lan_discovery == true 时，IPv4 会将动态探测 IP 前置于静态地址（若有可用路由），IPv6 则不前置 IPv4
        let dynamic = make_shared(true);
        let probe_targets = dynamic.connected_probe_targets.lock().unwrap().clone();
        let discovered: Vec<String> =
            crate::lan_discovery::discover_local_lan_ipv4s(&probe_targets)
                .into_iter()
                .map(|ip| format!("{ip}:50000"))
                .collect();
        let got_v4 = dynamic.current_effective_lan_addrs(&static_addrs, 50000, false);
        assert!(got_v4.ends_with(&["203.0.113.50:50000".to_string()]));
        let loopback_pos = got_v4
            .iter()
            .position(|a| a == "127.0.0.1:50000")
            .expect("loopback static entry must remain when server_is_loopback == true");
        for (idx, d) in discovered.iter().enumerate() {
            assert_eq!(got_v4.get(idx), Some(d));
            assert!(idx < loopback_pos);
        }
        let got_v6 = dynamic.current_effective_lan_addrs(&static_addrs, 50000, true);
        assert!(got_v6.contains(&"[fd00::5]:50000".to_string()));
        assert!(got_v6
            .iter()
            .all(|s| s.parse::<SocketAddr>().is_ok_and(|a| a.is_ipv6())));

        // 代理激活时 current_effective_lan_addrs 必须严格返回空列表，绝不泄漏内网/VPN/全球 IPv6/UPnP 候选
        dynamic.proxy_active.store(true, Ordering::Release);
        *dynamic.upnp_external_addr.lock().unwrap() = Some("203.0.113.88:50000".to_string());
        assert!(dynamic
            .current_effective_lan_addrs(&static_addrs, 50000, false)
            .is_empty());
    }

    #[test]
    fn persistent_udp_probe_invalid_target_returns_none_and_clears_local_udp_port() {
        let failed = PersistentUdpProbe::bind("0.0.0.0:21116".parse().unwrap());
        assert!(
            failed.is_none(),
            "unspecified target must return None and never keep a probe socket"
        );
        // 端口为 0 或未指定地址也直接返回 None
        assert!(PersistentUdpProbe::bind("0.0.0.0:0".parse().unwrap()).is_none());
        assert!(PersistentUdpProbe::bind("127.0.0.1:0".parse().unwrap()).is_none());

        // 验证当探测绑定失败时，SharedState::local_udp_port 被置为 0，下发的凭据为 None
        let cfg = ServerConfig::default();
        let shared = SharedState {
            status: Mutex::new(cfg.disabled_snapshot()),
            status_updates: Mutex::new(VecDeque::new()),
            incoming: Mutex::new(VecDeque::new()),
            device_status_events: Mutex::new(VecDeque::new()),
            kicked_reasons: Mutex::new(VecDeque::new()),
            pending_connects: Mutex::new(HashMap::new()),
            active_writer: Mutex::new(None),
            shutdown_stream: Mutex::new(None),
            stop_flag: AtomicBool::new(false),
            stop_lock: Mutex::new(false),
            stop_cv: Condvar::new(),
            fast_reconnect: AtomicBool::new(false),
            reset_backoff_on_reconnect: AtomicBool::new(false),
            reconnect_epoch: AtomicU64::new(0),
            reconnect_reason: Mutex::new(None),
            last_server_activity: Mutex::new(None),
            last_timeout_reconnect: Mutex::new(None),
            local_udp_port: AtomicU16::new(45678),
            local_udp_is_ipv6: AtomicBool::new(false),
            nat_profile: Mutex::new(NatProfile::default()),
            rtt_ms: Mutex::new(None),
            last_heartbeat_sent_at: Mutex::new(None),
            active_probe: Mutex::new(None),
            dynamic_lan_discovery: false,
            connected_probe_targets: Mutex::new(Vec::new()),
            server_is_loopback: AtomicBool::new(false),
            upnp_enabled: AtomicBool::new(false),
            upnp_status: Mutex::new(UpnpStatus::Disabled),
            upnp_external_addr: Mutex::new(None),
            upnp_lease: Mutex::new(None),
            upnp_gen: AtomicU64::new(0),
            upnp_heartbeat_needed: AtomicBool::new(false),
            lan_addrs: Vec::new(),
            enabled: true,
            token_provider: None,
            token_refresher: None,
            device_pubkey: None,
            allow_remote_assist: AtomicU8::new(ASSIST_UNSET),
            allow_remote_control: AtomicU8::new(REMOTE_CTRL_UNSET),
            wol_enabled: AtomicU8::new(WOL_UNSET),
            mac_addr: Mutex::new(None),
            device_wol_events: Mutex::new(VecDeque::new()),
            device_wol_capable: Mutex::new(HashMap::new()),
            pending_wols: Mutex::new(HashMap::new()),
            wol_relay_inflight: Arc::new(AtomicUsize::new(0)),
            wol_relay_history: Mutex::new(VecDeque::new()),
            proxy_override: Mutex::new(None),
            proxy_active: AtomicBool::new(false),
            wol_relay_test_sink: Mutex::new(None),
        };
        shared.local_udp_port.store(
            failed.as_ref().map_or(0, PersistentUdpProbe::local_port),
            Ordering::Release,
        );
        assert_eq!(shared.local_udp_port.load(Ordering::Acquire), 0);

        dispatch_coord(
            &shared,
            CoordPayload {
                session_id: "sess-no-probe".to_string(),
                role: "host".to_string(),
                peer_id: "111222333".to_string(),
                relay_addr: "127.0.0.1:21117".to_string(),
                relay_token: "tok".to_string(),
                ..CoordPayload::default()
            },
        );
        let inc = shared.incoming.lock().unwrap().pop_front().unwrap();
        assert_eq!(inc.local_udp_port, None);
    }

    #[test]
    fn tls13_signal_reconnect_fetches_rotated_token_and_handles_assist_status_owner_grant_and_kick()
    {
        use std::sync::atomic::AtomicUsize;

        let server_cert_pem = rc_session::dev_cert::dev_server_cert_pem();
        let server_key_pem = rc_session::dev_cert::DEV_KEY_PEM;
        let certs: Vec<_> = rustls_pemfile::certs(&mut server_cert_pem.as_bytes())
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut server_key_pem.as_bytes())
            .unwrap()
            .unwrap();
        let tls_server_cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let signal_addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            // Round 1: initial connection -> accept TLS, verify Register fields, drop with server_shutdown kick
            {
                let (tcp, _) = listener.accept().unwrap();
                let _ = tcp.set_read_timeout(Some(Duration::from_secs(2)));
                let conn = rustls::ServerConnection::new(Arc::clone(&tls_server_cfg)).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);

                let mut len_buf = [0u8; 4];
                tls.read_exact(&mut len_buf).unwrap();
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                tls.read_exact(&mut body).unwrap();
                let reg: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(reg["type"], "register");
                assert_eq!(reg["access_token"], "tok-round-1");
                assert_eq!(reg["device_pubkey"], "a".repeat(64));
                assert_eq!(reg["allow_remote_assist"], false);
                assert_eq!(reg["rcp2_v2"], true);

                let write_tls_json =
                    |s: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
                     val: &serde_json::Value| {
                        let b = serde_json::to_vec(val).unwrap();
                        let mut frame = Vec::with_capacity(4 + b.len());
                        frame.extend_from_slice(&(b.len() as u32).to_be_bytes());
                        frame.extend_from_slice(&b);
                        s.write_all(&frame).unwrap();
                        s.flush().unwrap();
                    };

                write_tls_json(
                    &mut tls,
                    &serde_json::json!({
                        "type": "registered",
                        "device_id": "604928235",
                        "formatted_id": "604 928 235",
                        "udp_probe_addr": "127.0.0.1:21116",
                        "relay_addr": "127.0.0.1:21117",
                    }),
                );

                // Expect server_shutdown kick to trigger reconnect with rotated token; send close_notify
                // and drain until client closes so Windows does not RST away unread TLS data.
                write_tls_json(
                    &mut tls,
                    &serde_json::json!({
                        "type": "kicked",
                        "reason": "server_shutdown",
                    }),
                );
                tls.conn.send_close_notify();
                let _ = tls.flush();
                let mut sink = [0u8; 256];
                while matches!(tls.read(&mut sink), Ok(n) if n > 0) {}
            }

            // Round 2: reconnect -> must fetch rotated token "tok-round-2", handle UpdateAssistState,
            // push DeviceStatusChanged, PunchCoord with owner_grant, and terminal kick "account_disabled".
            let (tcp, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(tls_server_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);

            let read_tls_json = |s: &mut rustls::StreamOwned<
                rustls::ServerConnection,
                TcpStream,
            >|
             -> serde_json::Value {
                let mut len_buf = [0u8; 4];
                s.read_exact(&mut len_buf).unwrap();
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                s.read_exact(&mut body).unwrap();
                serde_json::from_slice(&body).unwrap()
            };
            let write_tls_json =
                |s: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
                 val: &serde_json::Value| {
                    let b = serde_json::to_vec(val).unwrap();
                    let mut frame = Vec::with_capacity(4 + b.len());
                    frame.extend_from_slice(&(b.len() as u32).to_be_bytes());
                    frame.extend_from_slice(&b);
                    s.write_all(&frame).unwrap();
                    s.flush().unwrap();
                };

            let reg2 = read_tls_json(&mut tls);
            assert_eq!(reg2["type"], "register");
            assert_eq!(reg2["access_token"], "tok-round-2");

            write_tls_json(
                &mut tls,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "604928235",
                    "formatted_id": "604 928 235",
                    "udp_probe_addr": "127.0.0.1:21116",
                    "relay_addr": "127.0.0.1:21117",
                }),
            );

            // Read initial heartbeat
            let hb = read_tls_json(&mut tls);
            assert_eq!(hb["type"], "heartbeat");

            // Push DeviceStatusChanged
            write_tls_json(
                &mut tls,
                &serde_json::json!({
                    "type": "device_status_changed",
                    "device_id": "777888999",
                    "online": true,
                    "hostname": "Office Mini",
                    "alias": "主力机",
                    "os": "macos",
                    "allow_remote_assist": false,
                }),
            );

            // Read UpdateAssistState + ConnectRequest (order: UpdateAssistState then ConnectRequest),
            // skipping any background periodic heartbeat ticks that may interleave.
            let read_non_heartbeat = |s: &mut rustls::StreamOwned<
                rustls::ServerConnection,
                TcpStream,
            >|
             -> serde_json::Value {
                for _ in 0..16 {
                    let msg = read_tls_json(s);
                    if msg["type"] != "heartbeat" {
                        return msg;
                    }
                }
                panic!("too many heartbeats without expected signaling message");
            };
            let upd = read_non_heartbeat(&mut tls);
            assert_eq!(upd["type"], "update_assist_state");
            assert_eq!(upd["allow_remote_assist"], true);

            let req = read_non_heartbeat(&mut tls);
            assert_eq!(req["type"], "connect_request");
            let sid = req["session_id"].as_str().unwrap().to_string();
            write_tls_json(
                &mut tls,
                &serde_json::json!({
                    "type": "punch_coord",
                    "session_id": sid,
                    "role": "client",
                    "peer_id": "777888999",
                    "peer_lan_addrs": [],
                    "relay_token": "tok-owner-01",
                    "relay_addr": "127.0.0.1:21117",
                    "is_owner_connection": true,
                    "owner_grant": {
                        "ticket_id": "0123456789abcdef0123456789abcdef",
                        "user_id": "user-uuid-1",
                        "caller_device_id": "604928235",
                        "caller_pubkey_hex": "a".repeat(64),
                        "target_device_id": "777888999",
                        "session_id": sid,
                        "expires_at_unix_sec": 2_000_000_000u64,
                        "signature_hex": "b".repeat(128),
                    }
                }),
            );

            // Send terminal kick reason "account_disabled"
            write_tls_json(
                &mut tls,
                &serde_json::json!({
                    "type": "kicked",
                    "reason": "account_disabled",
                }),
            );
            tls.conn.send_close_notify();
            let _ = tls.flush();
            let mut sink = [0u8; 256];
            while matches!(tls.read(&mut sink), Ok(n) if n > 0) {}
        });

        let token_calls = Arc::new(AtomicUsize::new(0));
        let token_calls_cb = Arc::clone(&token_calls);
        let cfg = ServerConfig {
            enabled: true,
            server_host: "localhost".to_string(),
            signal_port: signal_addr.port(),
            relay_port: 21117,
            use_https: true,
            ca_cert_pem: Some(server_cert_pem.to_string()),
            ..ServerConfig::default()
        };
        let opts = SignalClientOptions {
            token_provider: Some(Arc::new(move || {
                let n = token_calls_cb.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(format!("tok-round-{n}"))
            })),
            device_pubkey: Some("A".repeat(64)),
            allow_remote_assist: false,
            dynamic_lan_discovery: false,
            ..SignalClientOptions::default()
        };
        let fast_timing = SignalTiming {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: [
                Duration::from_millis(30),
                Duration::from_millis(60),
                Duration::from_millis(120),
                Duration::from_millis(240),
            ],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "tls-test".to_string(),
            Vec::new(),
            Some(opts),
            fast_timing,
            |_| {},
        );

        // Wait until reconnect round 2 reaches Connected (token_calls >= 2)
        let deadline = Instant::now() + Duration::from_secs(12);
        while (token_calls.load(Ordering::SeqCst) < 2
            || client.status().state != ServerConnectionState::Connected)
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(15));
        }
        assert!(token_calls.load(Ordering::SeqCst) >= 2);

        // Wait for DeviceStatusChanged
        let dev_ev = {
            let d = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(ev) = client.try_recv_device_status() {
                    break ev;
                }
                assert!(
                    Instant::now() < d,
                    "timed out waiting for DeviceStatusEvent"
                );
                thread::sleep(Duration::from_millis(10));
            }
        };
        assert_eq!(dev_ev.device_id, "777888999");
        assert!(dev_ev.online);
        assert_eq!(dev_ev.alias, "主力机");

        // Send UpdateAssistState + ConnectRequest
        client.set_allow_remote_assist(true).unwrap();
        let grant = client
            .request_connect("777888999", Duration::from_secs(3))
            .expect("must receive ConnectGrant with owner_grant over TLS 1.3");
        assert!(grant.is_owner_connection);
        assert_eq!(
            grant.owner_grant.as_ref().unwrap().ticket_id,
            "0123456789abcdef0123456789abcdef"
        );

        // Collect kicked reasons ("server_shutdown", then "account_disabled")
        let mut kicked = Vec::new();
        let d2 = Instant::now() + Duration::from_secs(3);
        while Instant::now() < d2 {
            while let Some(r) = client.try_recv_kicked_reason() {
                kicked.push(r);
            }
            if kicked.iter().any(|r| r == "account_disabled")
                && client.status().state == ServerConnectionState::Error
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(kicked.contains(&"server_shutdown".to_string()));
        assert!(kicked.contains(&"account_disabled".to_string()));
        assert_eq!(client.status().state, ServerConnectionState::Error);

        client.stop();
        server_thread.join().unwrap();
    }

    #[test]
    fn refuses_plaintext_signal_when_use_https_enabled_without_ca_cert() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_jh = thread::spawn(move || {
            let _ = listener.accept();
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: true,
            ca_cert_pem: None,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };

        let mut client = SignalClientHandle::spawn(cfg, "tls-guard-test".into(), vec![]);
        let deadline = Instant::now() + Duration::from_secs(2);
        let snap = loop {
            let st = client.status();
            if st.state == ServerConnectionState::Error {
                break st;
            }
            assert!(Instant::now() < deadline, "expected TLS-no-CA error state");
            thread::sleep(Duration::from_millis(10));
        };
        assert!(
            snap.error_message
                .as_deref()
                .is_some_and(|m| m.contains("Root CA") || m.contains("拒绝降级")),
            "unexpected error_message: {:?}",
            snap.error_message
        );
        client.stop();
        let _ = accept_jh.join();
    }

    #[test]
    fn is_connect_in_progress_recognizes_platform_errno_and_rejects_fatal_errors() {
        assert!(is_connect_in_progress(&io::Error::from(
            ErrorKind::WouldBlock
        )));
        assert!(is_connect_in_progress(&io::Error::from(
            ErrorKind::Interrupted
        )));
        assert!(!is_connect_in_progress(&io::Error::from(
            ErrorKind::ConnectionRefused
        )));

        #[cfg(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            assert!(is_connect_in_progress(&io::Error::from_raw_os_error(36)));
            assert!(is_connect_in_progress(&io::Error::from_raw_os_error(37)));
            assert!(!is_connect_in_progress(&io::Error::from_raw_os_error(61)));
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            assert!(is_connect_in_progress(&io::Error::from_raw_os_error(115)));
            assert!(is_connect_in_progress(&io::Error::from_raw_os_error(114)));
            assert!(!is_connect_in_progress(&io::Error::from_raw_os_error(111)));
        }

        #[cfg(windows)]
        {
            assert!(is_connect_in_progress(&io::Error::from_raw_os_error(10035)));
            assert!(is_connect_in_progress(&io::Error::from_raw_os_error(10036)));
            assert!(is_connect_in_progress(&io::Error::from_raw_os_error(10037)));
            assert!(!is_connect_in_progress(&io::Error::from_raw_os_error(
                10061
            )));
        }
    }

    #[test]
    fn signal_client_forces_token_refresh_on_token_expired_register_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            // Round 1: reject expired token with token_expired error
            let (mut s1, _) = listener.accept().unwrap();
            let reg1 = read_test_frame(&mut s1);
            assert_eq!(reg1["type"], "register");
            assert_eq!(reg1["access_token"], "stale-tok");
            write_test_frame(
                &mut s1,
                &serde_json::json!({
                    "type": "error",
                    "code": "token_expired",
                    "message": "access token expired"
                }),
            );
            drop(s1);

            // Round 2: accept forced-refreshed token
            let (mut s2, _) = listener.accept().unwrap();
            let reg2 = read_test_frame(&mut s2);
            assert_eq!(reg2["type"], "register");
            assert_eq!(reg2["access_token"], "fresh-tok");
            write_test_frame(
                &mut s2,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "123456789",
                    "formatted_id": "123 456 789",
                    "udp_probe_addr": "",
                    "relay_addr": ""
                }),
            );
            let _ = s2.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 64];
            while matches!(s2.read(&mut buf), Ok(n) if n > 0) {}
        });

        let refresh_called = Arc::new(Mutex::new(Vec::<String>::new()));
        let refresh_log = Arc::clone(&refresh_called);

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let opts = SignalClientOptions {
            token_provider: Some(Arc::new(|| Ok("stale-tok".to_string()))),
            token_refresher: Some(Arc::new(move |stale| {
                refresh_log.lock().unwrap().push(stale.to_string());
                Ok("fresh-tok".to_string())
            })),
            ..SignalClientOptions::default()
        };
        let fast_timing = SignalTiming {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: [
                Duration::from_millis(25),
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(200),
            ],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "refresh-test".to_string(),
            Vec::new(),
            Some(opts),
            fast_timing,
            |_| {},
        );

        let snap = wait_until_connected(&client, Duration::from_secs(4));
        assert_eq!(snap.device_id.as_deref(), Some("123456789"));
        assert_eq!(refresh_called.lock().unwrap().as_slice(), &["stale-tok"]);
        client.stop();
        server_thread.join().unwrap();
    }

    #[test]
    fn signal_client_preserves_expired_token_and_skips_dial_when_refresh_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);

        let server_thread = thread::spawn(move || {
            // Round 1: reject stale-tok with token_expired
            let (mut s1, _) = listener.accept().unwrap();
            accept_count_srv.fetch_add(1, Ordering::SeqCst);
            let reg1 = read_test_frame(&mut s1);
            assert_eq!(reg1["type"], "register");
            assert_eq!(reg1["access_token"], "stale-tok");
            write_test_frame(
                &mut s1,
                &serde_json::json!({
                    "type": "error",
                    "code": "token_expired",
                    "message": "access token expired"
                }),
            );
            drop(s1);

            // Round 2 (refresh failed) must NOT dial TCP; the very next accepted socket
            // must already carry the refreshed token from Round 3.
            let (mut s2, _) = listener.accept().unwrap();
            accept_count_srv.fetch_add(1, Ordering::SeqCst);
            let reg2 = read_test_frame(&mut s2);
            assert_eq!(reg2["type"], "register");
            assert_eq!(reg2["access_token"], "fresh-tok-after-retry");
            write_test_frame(
                &mut s2,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "234567890",
                    "formatted_id": "234 567 890",
                    "udp_probe_addr": "",
                    "relay_addr": ""
                }),
            );
            let _ = s2.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 64];
            while matches!(s2.read(&mut buf), Ok(n) if n > 0) {}
        });

        let provider_calls = Arc::new(AtomicUsize::new(0));
        let provider_calls_cb = Arc::clone(&provider_calls);
        let refresh_attempts = Arc::new(Mutex::new(Vec::<String>::new()));
        let refresh_attempts_cb = Arc::clone(&refresh_attempts);

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let opts = SignalClientOptions {
            token_provider: Some(Arc::new(move || {
                provider_calls_cb.fetch_add(1, Ordering::SeqCst);
                Ok("stale-tok".to_string())
            })),
            token_refresher: Some(Arc::new(move |stale| {
                let mut log = refresh_attempts_cb.lock().unwrap();
                log.push(stale.to_string());
                if log.len() == 1 {
                    Err("transient refresh failure".to_string())
                } else {
                    Ok("fresh-tok-after-retry".to_string())
                }
            })),
            ..SignalClientOptions::default()
        };
        let fast_timing = SignalTiming {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: [
                Duration::from_millis(25),
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(200),
            ],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "refresh-retry-test".to_string(),
            Vec::new(),
            Some(opts),
            fast_timing,
            |_| {},
        );

        let snap = wait_until_connected(&client, Duration::from_secs(4));
        assert_eq!(snap.device_id.as_deref(), Some("234567890"));
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(accept_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            refresh_attempts.lock().unwrap().as_slice(),
            &["stale-tok", "stale-tok"]
        );
        client.stop();
        server_thread.join().unwrap();
    }

    #[test]
    fn allow_remote_control_wire_serialization_and_reconnect_and_legacy_status_fallback() {
        // 1. OutgoingSignalMsg::Register & UpdateAssistState serialization (None omitted, Some included)
        let reg_none = serde_json::to_value(&OutgoingSignalMsg::Register {
            device_id: None,
            device_key: "k".repeat(64),
            hostname: "phone".into(),
            os: "android".into(),
            app_version: String::new(),
            arch: String::new(),
            device_group: "default".into(),
            lan_addrs: Vec::new(),
            access_token: None,
            device_pubkey: None,
            allow_remote_assist: Some(false),
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
            nat_port_range: None,
            rcp2_v2: true,
        })
        .unwrap();
        assert!(
            reg_none.get("allow_remote_control").is_none(),
            "None 时 Register 不得序列化 allow_remote_control"
        );
        assert_eq!(reg_none["rcp2_v2"], true);

        let reg_false = serde_json::to_value(&OutgoingSignalMsg::Register {
            device_id: None,
            device_key: "k".repeat(64),
            hostname: "phone".into(),
            os: "android".into(),
            app_version: String::new(),
            arch: String::new(),
            device_group: "default".into(),
            lan_addrs: Vec::new(),
            access_token: None,
            device_pubkey: None,
            allow_remote_assist: Some(false),
            allow_remote_control: Some(false),
            mac_addr: None,
            wol_enabled: None,
            nat_type: None,
            nat_port_delta: None,
            nat_port_range: None,
            rcp2_v2: true,
        })
        .unwrap();
        assert_eq!(reg_false["allow_remote_control"], false);
        assert_eq!(reg_false["rcp2_v2"], true);

        let upd_assist_only = serde_json::to_value(&OutgoingSignalMsg::UpdateAssistState {
            allow_remote_assist: Some(true),
            allow_remote_control: None,
            mac_addr: None,
            wol_enabled: None,
        })
        .unwrap();
        assert_eq!(upd_assist_only["allow_remote_assist"], true);
        assert!(upd_assist_only.get("allow_remote_control").is_none());

        let upd_ctrl_only = serde_json::to_value(&OutgoingSignalMsg::UpdateAssistState {
            allow_remote_assist: None,
            allow_remote_control: Some(true),
            mac_addr: None,
            wol_enabled: None,
        })
        .unwrap();
        assert!(upd_ctrl_only.get("allow_remote_assist").is_none());
        assert_eq!(upd_ctrl_only["allow_remote_control"], true);

        // DeviceStatusEvent direct JSON deserialization derives missing allow_remote_control from os
        let direct_android: DeviceStatusEvent = serde_json::from_value(serde_json::json!({
            "device_id": "200000010",
            "online": true,
            "hostname": "Pixel",
            "alias": "Phone",
            "os": "android",
            "allow_remote_assist": false
        }))
        .unwrap();
        assert!(!direct_android.allow_remote_control);
        let direct_ios: DeviceStatusEvent = serde_json::from_value(serde_json::json!({
            "device_id": "200000011",
            "online": true,
            "hostname": "iPhone",
            "alias": "iOS",
            "os": "iOS 18",
            "allow_remote_assist": false
        }))
        .unwrap();
        assert!(!direct_ios.allow_remote_control);
        let direct_macos: DeviceStatusEvent = serde_json::from_value(serde_json::json!({
            "device_id": "200000012",
            "online": true,
            "hostname": "Mac",
            "alias": "Desktop",
            "os": "macos",
            "allow_remote_assist": false
        }))
        .unwrap();
        assert!(direct_macos.allow_remote_control);
        let direct_android_explicit: DeviceStatusEvent =
            serde_json::from_value(serde_json::json!({
                "device_id": "200000013",
                "online": true,
                "hostname": "Pixel",
                "alias": "PhoneOn",
                "os": "android",
                "allow_remote_assist": false,
                "allow_remote_control": true
            }))
            .unwrap();
        assert!(direct_android_explicit.allow_remote_control);

        // 2. End-to-end TCP signal server:
        //    - Round 1: initial Register carries allow_remote_control = false
        //    - Push DeviceStatusChanged (new server explicit false/true + legacy missing field android->false, macos->true)
        //    - Call set_allow_remote_control(true) & set_allow_remote_assist(true) -> both carry allow_remote_control=true
        //    - request_connect receives Error { code: "remote_control_disabled" } -> clear error returned
        //    - Kick with server_shutdown -> Round 2 Register carries latest allow_remote_control = true
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let round2_registered = Arc::new(AtomicBool::new(false));
        let round2_registered_srv = Arc::clone(&round2_registered);

        let server_thread = thread::spawn(move || {
            // Round 1
            {
                let (mut s, _) = listener.accept().unwrap();
                let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                let reg1 = read_test_frame(&mut s);
                assert_eq!(reg1["type"], "register");
                assert_eq!(reg1["allow_remote_assist"], false);
                assert_eq!(reg1["allow_remote_control"], false);

                write_test_frame(
                    &mut s,
                    &serde_json::json!({
                        "type": "registered",
                        "device_id": "111222333",
                        "formatted_id": "111 222 333",
                        "udp_probe_addr": "",
                        "relay_addr": ""
                    }),
                );

                // Push 4 DeviceStatusChanged frames:
                // (a) legacy server missing field + android -> false
                write_test_frame(
                    &mut s,
                    &serde_json::json!({
                        "type": "device_status_changed",
                        "device_id": "200000001",
                        "online": true,
                        "hostname": "Pixel",
                        "alias": "AndroidLegacy",
                        "os": "android",
                        "allow_remote_assist": false
                    }),
                );
                // (b) legacy server missing field + macos -> true
                write_test_frame(
                    &mut s,
                    &serde_json::json!({
                        "type": "device_status_changed",
                        "device_id": "200000002",
                        "online": true,
                        "hostname": "Mac",
                        "alias": "MacLegacy",
                        "os": "macos",
                        "allow_remote_assist": false
                    }),
                );
                // (c) new server explicit true on android -> true
                write_test_frame(
                    &mut s,
                    &serde_json::json!({
                        "type": "device_status_changed",
                        "device_id": "200000003",
                        "online": true,
                        "hostname": "Pixel2",
                        "alias": "AndroidEnabled",
                        "os": "android",
                        "allow_remote_assist": false,
                        "allow_remote_control": true
                    }),
                );
                // (d) new server explicit false on macos -> false
                write_test_frame(
                    &mut s,
                    &serde_json::json!({
                        "type": "device_status_changed",
                        "device_id": "200000004",
                        "online": true,
                        "hostname": "Mac2",
                        "alias": "MacDisabled",
                        "os": "macos",
                        "allow_remote_assist": false,
                        "allow_remote_control": false
                    }),
                );

                let read_non_hb = |stream: &mut TcpStream| -> serde_json::Value {
                    for _ in 0..16 {
                        let m = read_test_frame(stream);
                        if m["type"] != "heartbeat" {
                            return m;
                        }
                    }
                    panic!("too many heartbeats");
                };

                // set_allow_remote_control(true) sends ONLY allow_remote_control (decoupled from allow_remote_assist)
                let upd1 = read_non_hb(&mut s);
                assert_eq!(upd1["type"], "update_assist_state");
                assert!(upd1.get("allow_remote_assist").is_none());
                assert_eq!(upd1["allow_remote_control"], true);

                // set_allow_remote_assist(true) sends ONLY allow_remote_assist (decoupled from allow_remote_control)
                let upd2 = read_non_hb(&mut s);
                assert_eq!(upd2["type"], "update_assist_state");
                assert_eq!(upd2["allow_remote_assist"], true);
                assert!(upd2.get("allow_remote_control").is_none());

                // ConnectRequest #1 -> error with message
                let req1 = read_non_hb(&mut s);
                assert_eq!(req1["type"], "connect_request");
                write_test_frame(
                    &mut s,
                    &serde_json::json!({
                        "type": "error",
                        "code": "remote_control_disabled",
                        "message": "对方未开启允许远程控制"
                    }),
                );

                // ConnectRequest #2 -> error with empty message (fallback Chinese message)
                let req2 = read_non_hb(&mut s);
                assert_eq!(req2["type"], "connect_request");
                write_test_frame(
                    &mut s,
                    &serde_json::json!({
                        "type": "error",
                        "code": "remote_control_disabled",
                        "message": ""
                    }),
                );

                // Kick to trigger reconnect; half-close write end and drain so Windows does not RST unread frames.
                write_test_frame(
                    &mut s,
                    &serde_json::json!({
                        "type": "kicked",
                        "reason": "server_shutdown"
                    }),
                );
                let _ = s.shutdown(Shutdown::Write);
                let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
                let mut sink = [0u8; 64];
                while matches!(s.read(&mut sink), Ok(n) if n > 0) {}
            }

            // Round 2: reconnect Register must carry updated allow_remote_control=true & allow_remote_assist=true
            {
                let (mut s2, _) = listener.accept().unwrap();
                let _ = s2.set_read_timeout(Some(Duration::from_secs(3)));
                let reg2 = read_test_frame(&mut s2);
                assert_eq!(reg2["type"], "register");
                assert_eq!(reg2["allow_remote_assist"], true);
                assert_eq!(reg2["allow_remote_control"], true);
                write_test_frame(
                    &mut s2,
                    &serde_json::json!({
                        "type": "registered",
                        "device_id": "111222333",
                        "formatted_id": "111 222 333",
                        "udp_probe_addr": "",
                        "relay_addr": ""
                    }),
                );
                round2_registered_srv.store(true, Ordering::Release);
                let _ = s2.set_read_timeout(Some(Duration::from_millis(200)));
                let mut sink = [0u8; 64];
                while matches!(s2.read(&mut sink), Ok(n) if n > 0) {}
            }
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let opts = SignalClientOptions {
            allow_remote_assist: false,
            allow_remote_control: Some(false),
            ..SignalClientOptions::default()
        };
        let fast_timing = SignalTiming {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: [
                Duration::from_millis(25),
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(200),
            ],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "perm-test".to_string(),
            Vec::new(),
            Some(opts),
            fast_timing,
            |_| {},
        );

        let snap = wait_until_connected(&client, Duration::from_secs(4));
        assert_eq!(snap.device_id.as_deref(), Some("111222333"));

        // Collect all 4 DeviceStatusEvent notifications
        let mut events = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while events.len() < 4 && Instant::now() < deadline {
            if let Some(ev) = client.try_recv_device_status() {
                events.push(ev);
            } else {
                thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].device_id, "200000001");
        assert!(!events[0].allow_remote_control);
        assert_eq!(events[1].device_id, "200000002");
        assert!(events[1].allow_remote_control);
        assert_eq!(events[2].device_id, "200000003");
        assert!(events[2].allow_remote_control);
        assert_eq!(events[3].device_id, "200000004");
        assert!(!events[3].allow_remote_control);

        client.set_allow_remote_control(true).unwrap();
        client.set_allow_remote_assist(true).unwrap();

        let err1 = client
            .request_connect("200000001", Duration::from_secs(3))
            .expect_err("remote_control_disabled must fail request_connect");
        assert!(err1.contains("remote_control_disabled"), "err1={err1}");
        assert!(err1.contains("对方未开启允许远程控制"), "err1={err1}");

        let err2 = client
            .request_connect("200000001", Duration::from_secs(3))
            .expect_err("remote_control_disabled with empty msg must fail with Chinese fallback");
        assert!(err2.contains("remote_control_disabled"), "err2={err2}");
        assert!(err2.contains("对方未开启允许远程控制"), "err2={err2}");

        // Wait until Round 2 actually completes Register + Registered on the server before stopping
        let reconnect_deadline = Instant::now() + Duration::from_secs(5);
        while !round2_registered.load(Ordering::Acquire) && Instant::now() < reconnect_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            round2_registered.load(Ordering::Acquire),
            "client must reconnect and send updated allow_remote_control=true in Round 2 Register"
        );

        client.stop();
        server_thread.join().unwrap();
    }

    #[test]
    fn self_device_status_changed_syncs_cached_policy_for_reconnect_register() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let round2_registered = Arc::new(AtomicBool::new(false));
        let round2_registered_srv = Arc::clone(&round2_registered);
        let (allow_kick_tx, allow_kick_rx) = mpsc::channel::<()>();

        let server_thread = thread::spawn(move || {
            // Round 1: client initially registers with allow_remote_control=true, allow_remote_assist=true.
            // Server then pushes self DeviceStatusChanged (simulating REST PATCH disabling both),
            // waits until the client confirms receipt of both DeviceStatusChanged frames, and only then
            // sends kicked + half-closes so Windows TCP does not RST away unread frames.
            {
                let (mut s1, _) = listener.accept().unwrap();
                let _ = s1.set_read_timeout(Some(Duration::from_secs(3)));
                let reg1 = read_test_frame(&mut s1);
                assert_eq!(reg1["type"], "register");
                assert_eq!(reg1["allow_remote_control"], true);
                assert_eq!(reg1["allow_remote_assist"], true);

                write_test_frame(
                    &mut s1,
                    &serde_json::json!({
                        "type": "registered",
                        "device_id": "555666777",
                        "formatted_id": "555 666 777",
                        "udp_probe_addr": "",
                        "relay_addr": ""
                    }),
                );

                // Push another device's status change first (must NOT affect local cache)
                write_test_frame(
                    &mut s1,
                    &serde_json::json!({
                        "type": "device_status_changed",
                        "device_id": "999888777",
                        "online": true,
                        "hostname": "Other",
                        "alias": "Other",
                        "os": "android",
                        "allow_remote_assist": false,
                        "allow_remote_control": false
                    }),
                );

                // Push self DeviceStatusChanged (with formatted spaces to test normalization)
                write_test_frame(
                    &mut s1,
                    &serde_json::json!({
                        "type": "device_status_changed",
                        "device_id": "555 666 777",
                        "online": true,
                        "hostname": "Self",
                        "alias": "Self",
                        "os": "macos",
                        "allow_remote_assist": false,
                        "allow_remote_control": false
                    }),
                );

                allow_kick_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("client must receive self DeviceStatusChanged before Round 1 closes");

                write_test_frame(
                    &mut s1,
                    &serde_json::json!({
                        "type": "kicked",
                        "reason": "server_shutdown"
                    }),
                );
                let _ = s1.shutdown(Shutdown::Write);
                let _ = s1.set_read_timeout(Some(Duration::from_secs(1)));
                let mut sink = [0u8; 64];
                while matches!(s1.read(&mut sink), Ok(n) if n > 0) {}
            }

            // Round 2: reconnect Register MUST send synced allow_remote_control=false & allow_remote_assist=false
            {
                let (mut s2, _) = listener.accept().unwrap();
                let _ = s2.set_read_timeout(Some(Duration::from_secs(3)));
                let reg2 = read_test_frame(&mut s2);
                assert_eq!(reg2["type"], "register");
                assert_eq!(
                    reg2["allow_remote_control"], false,
                    "重连 Register 必须上报经自身 DeviceStatusChanged 同步后的 allow_remote_control=false"
                );
                assert_eq!(
                    reg2["allow_remote_assist"], false,
                    "重连 Register 必须上报经自身 DeviceStatusChanged 同步后的 allow_remote_assist=false"
                );
                write_test_frame(
                    &mut s2,
                    &serde_json::json!({
                        "type": "registered",
                        "device_id": "555666777",
                        "formatted_id": "555 666 777",
                        "udp_probe_addr": "",
                        "relay_addr": ""
                    }),
                );
                round2_registered_srv.store(true, Ordering::Release);
                let _ = s2.set_read_timeout(Some(Duration::from_millis(200)));
                let mut sink = [0u8; 64];
                while matches!(s2.read(&mut sink), Ok(n) if n > 0) {}
            }
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let opts = SignalClientOptions {
            allow_remote_assist: true,
            allow_remote_control: Some(true),
            ..SignalClientOptions::default()
        };
        let fast_timing = SignalTiming {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: [
                Duration::from_millis(25),
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(200),
            ],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "self-sync-test".to_string(),
            Vec::new(),
            Some(opts),
            fast_timing,
            |_| {},
        );

        // Wait until the client has processed both DeviceStatusChanged frames (including self) before letting Round 1 close.
        let mut received = Vec::new();
        let recv_deadline = Instant::now() + Duration::from_secs(5);
        while received.len() < 2 && Instant::now() < recv_deadline {
            if let Some(ev) = client.try_recv_device_status() {
                received.push(ev);
            } else {
                thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(
            received.len(),
            2,
            "must receive both DeviceStatusChanged events"
        );
        assert_eq!(received[1].device_id, "555 666 777");
        assert!(!received[1].allow_remote_control);
        assert!(!received[1].allow_remote_assist);
        allow_kick_tx.send(()).expect("signal server to kick");

        let deadline = Instant::now() + Duration::from_secs(5);
        while !round2_registered.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            round2_registered.load(Ordering::Acquire),
            "client must reconnect and complete Round 2 Register with synced policy"
        );

        client.stop();
        server_thread.join().unwrap();
    }

    #[test]
    fn request_relay_sends_relay_alloc_and_receives_relay_ready_without_lan_candidates() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let reg = read_test_frame(&mut s);
            assert_eq!(reg["type"], "register");
            write_test_frame(
                &mut s,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "111222333",
                    "formatted_id": "111 222 333",
                    "udp_probe_addr": "",
                    "relay_addr": "127.0.0.1:21117"
                }),
            );

            let req = loop {
                let frame = read_test_frame(&mut s);
                if frame["type"] == "heartbeat" {
                    write_test_frame(&mut s, &serde_json::json!({ "type": "heartbeat_ack" }));
                    continue;
                }
                break frame;
            };
            assert_eq!(req["type"], "relay_alloc");
            assert_eq!(req["target_id"], "999888777");
            let sid = req["session_id"].as_str().unwrap().to_string();
            assert!(!sid.is_empty());

            write_test_frame(
                &mut s,
                &serde_json::json!({
                    "type": "relay_ready",
                    "session_id": sid,
                    "role": "client",
                    "peer_id": "999888777",
                    "relay_token": "tok-pure-relay-123",
                    "relay_addr": "127.0.0.1:21117",
                    "expires_in_sec": 30,
                    "is_owner_connection": true
                }),
            );

            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut sink = [0u8; 64];
            while matches!(s.read(&mut sink), Ok(n) if n > 0) {}
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let mut client = SignalClientHandle::spawn(
            cfg,
            "relay-alloc-test".to_string(),
            vec!["192.168.1.10:9901".to_string()],
        );

        let deadline = Instant::now() + Duration::from_secs(3);
        while client.status().state != ServerConnectionState::Connected && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(client.status().state, ServerConnectionState::Connected);

        let grant = client
            .request_relay("999 888 777", Duration::from_secs(3))
            .expect("request_relay must succeed");
        assert_eq!(grant.target_id, "999888777");
        assert_eq!(grant.relay_token, "tok-pure-relay-123");
        assert_eq!(grant.relay_addr, "127.0.0.1:21117");
        assert!(grant.peer_public_addr.is_none());
        assert!(grant.peer_lan_addrs.is_empty());
        assert!(grant.is_owner_connection);

        client.stop();
        server_thread.join().unwrap();
    }

    #[test]
    fn heartbeat_and_activity_timeout_constants_are_tightened() {
        assert_eq!(HEARTBEAT_INTERVAL, Duration::from_secs(10));
        assert_eq!(SERVER_ACTIVITY_TIMEOUT, Duration::from_secs(25));
        assert_eq!(FAST_RECONNECT_DELAY, Duration::from_millis(200));
        assert_eq!(UPNP_LEASE_SECS, 1800);
        assert_eq!(UPNP_MAP_TIMEOUT, Duration::from_millis(1500));
        assert_eq!(UPNP_RENEW_INTERVAL, Duration::from_secs(900));
    }

    #[test]
    fn trigger_reconnect_interrupts_active_connection_and_long_backoff_promptly() {
        // 1) 未启用客户端调用 trigger_reconnect 幂等安全且不 panic
        let mut disabled = SignalClientHandle::spawn(
            ServerConfig::default(),
            "disabled-reconnect".to_string(),
            Vec::new(),
        );
        disabled.trigger_reconnect("noop");
        disabled.stop();
        disabled.trigger_reconnect("after_stop");

        // 2) 活跃连接 + 大退避 [10s; 4]：调用 trigger_reconnect 立即切断当前连接并在 ~200ms 快速重连
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let round2_connected = Arc::new(AtomicBool::new(false));
        let round2_connected_srv = Arc::clone(&round2_connected);

        let server = thread::spawn(move || {
            // Round 1: 正常注册后保持空闲等待客户端主动切断
            let (mut s1, _) = listener.accept().unwrap();
            let _ = s1.set_read_timeout(Some(Duration::from_secs(3)));
            let reg1 = read_test_frame(&mut s1);
            assert_eq!(reg1["type"], "register");
            write_test_frame(
                &mut s1,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "611222333",
                    "formatted_id": "611 222 333",
                    "udp_probe_addr": "",
                    "relay_addr": ""
                }),
            );
            let mut sink = [0u8; 64];
            while matches!(s1.read(&mut sink), Ok(n) if n > 0) {}

            // Round 2: 客户端快速重连进入第 2 轮
            let (mut s2, _) = listener.accept().unwrap();
            let _ = s2.set_read_timeout(Some(Duration::from_secs(3)));
            let reg2 = read_test_frame(&mut s2);
            assert_eq!(reg2["type"], "register");
            write_test_frame(
                &mut s2,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "611222333",
                    "formatted_id": "611 222 333",
                    "udp_probe_addr": "",
                    "relay_addr": ""
                }),
            );
            round2_connected_srv.store(true, Ordering::Release);
            let mut sink2 = [0u8; 64];
            while matches!(s2.read(&mut sink2), Ok(n) if n > 0) {}
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let huge_backoff_timing = SignalTiming {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: [Duration::from_secs(10); 4],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "fast-reconnect-test".to_string(),
            Vec::new(),
            None,
            huge_backoff_timing,
            |_| {},
        );

        let snap1 = wait_until_connected(&client, Duration::from_secs(3));
        assert_eq!(snap1.device_id.as_deref(), Some("611222333"));

        let t0 = Instant::now();
        client.trigger_reconnect("network_switched");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !round2_connected.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(15));
        }
        assert!(
            round2_connected.load(Ordering::Acquire),
            "trigger_reconnect must interrupt active connection and reconnect promptly"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "fast reconnect must bypass 10s backoff, took {:?}",
            t0.elapsed()
        );
        client.stop();
        server.join().unwrap();

        // 3) 正在大退避睡眠（10s）中调用 trigger_reconnect，必须立即唤醒 condvar 重连
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let round1_dropped = Arc::new(AtomicBool::new(false));
        let round1_dropped_srv = Arc::clone(&round1_dropped);
        let woke_connected = Arc::new(AtomicBool::new(false));
        let woke_connected_srv = Arc::clone(&woke_connected);

        let server2 = thread::spawn(move || {
            // Round 1: 接受连接后立刻关闭，迫使客户端进入 10s 退避睡眠
            let (s1, _) = listener2.accept().unwrap();
            drop(s1);
            round1_dropped_srv.store(true, Ordering::Release);

            // Round 2: 被 trigger_reconnect 唤醒后注册成功
            let (mut s2, _) = listener2.accept().unwrap();
            let _ = s2.set_read_timeout(Some(Duration::from_secs(3)));
            let reg = read_test_frame(&mut s2);
            assert_eq!(reg["type"], "register");
            write_test_frame(
                &mut s2,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "622333444",
                    "formatted_id": "622 333 444",
                    "udp_probe_addr": "",
                    "relay_addr": ""
                }),
            );
            woke_connected_srv.store(true, Ordering::Release);
            let mut sink = [0u8; 64];
            while matches!(s2.read(&mut sink), Ok(n) if n > 0) {}
        });

        let cfg2 = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr2.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let mut client2 = SignalClientHandle::spawn_with_timing(
            cfg2,
            "wake-backoff-test".to_string(),
            Vec::new(),
            None,
            huge_backoff_timing,
            |_| {},
        );
        let d_drop = Instant::now() + Duration::from_secs(3);
        while (!round1_dropped.load(Ordering::Acquire)
            || client2.status().state != ServerConnectionState::Error)
            && Instant::now() < d_drop
        {
            thread::sleep(Duration::from_millis(15));
        }
        // 等客户端进入 10s stop_cv.wait_timeout
        thread::sleep(Duration::from_millis(80));
        let t1 = Instant::now();
        client2.trigger_reconnect("wifi_recovered");
        let d_wake = Instant::now() + Duration::from_secs(3);
        while !woke_connected.load(Ordering::Acquire) && Instant::now() < d_wake {
            thread::sleep(Duration::from_millis(15));
        }
        assert!(
            woke_connected.load(Ordering::Acquire),
            "trigger_reconnect must wake backoff condvar immediately"
        );
        assert!(
            t1.elapsed() < Duration::from_secs(3),
            "condvar wakeup reconnect took too long: {:?}",
            t1.elapsed()
        );
        client2.stop();
        server2.join().unwrap();
    }

    #[test]
    fn request_connect_timeout_triggers_fast_reconnect_to_break_half_open_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let round2_registered = Arc::new(AtomicBool::new(false));
        let round2_registered_srv = Arc::clone(&round2_registered);

        let server = thread::spawn(move || {
            // Round 1: 接受 connect_request 但故意不回复，模拟半开死连接
            {
                let (mut s1, _) = listener.accept().unwrap();
                let _ = s1.set_read_timeout(Some(Duration::from_secs(3)));
                let reg1 = read_test_frame(&mut s1);
                assert_eq!(reg1["type"], "register");
                write_test_frame(
                    &mut s1,
                    &serde_json::json!({
                        "type": "registered",
                        "device_id": "633444555",
                        "formatted_id": "633 444 555",
                        "udp_probe_addr": "",
                        "relay_addr": "127.0.0.1:21117"
                    }),
                );
                let req = loop {
                    let frame = read_test_frame(&mut s1);
                    if frame["type"] == "heartbeat" {
                        continue;
                    }
                    break frame;
                };
                assert_eq!(req["type"], "connect_request");
                // 不回复 punch_coord，等待客户端超时触发重连并关闭套接字
                let mut sink = [0u8; 64];
                while matches!(s1.read(&mut sink), Ok(n) if n > 0) {}
            }

            // Round 2: 客户端因 request_connect 超时自动快速重连并恢复正常连接
            {
                let (mut s2, _) = listener.accept().unwrap();
                let _ = s2.set_read_timeout(Some(Duration::from_secs(3)));
                let reg2 = read_test_frame(&mut s2);
                assert_eq!(reg2["type"], "register");
                write_test_frame(
                    &mut s2,
                    &serde_json::json!({
                        "type": "registered",
                        "device_id": "633444555",
                        "formatted_id": "633 444 555",
                        "udp_probe_addr": "",
                        "relay_addr": "127.0.0.1:21117"
                    }),
                );
                round2_registered_srv.store(true, Ordering::Release);
                let req2 = loop {
                    let frame = read_test_frame(&mut s2);
                    if frame["type"] == "heartbeat" {
                        continue;
                    }
                    break frame;
                };
                assert_eq!(req2["type"], "connect_request");
                let sid = req2["session_id"].as_str().unwrap().to_string();
                write_test_frame(
                    &mut s2,
                    &serde_json::json!({
                        "type": "punch_coord",
                        "session_id": sid,
                        "role": "client",
                        "peer_id": "987654321",
                        "peer_lan_addrs": [],
                        "relay_token": "tok-after-timeout-reconnect",
                        "relay_addr": "127.0.0.1:21117"
                    }),
                );
                let mut sink = [0u8; 64];
                while matches!(s2.read(&mut sink), Ok(n) if n > 0) {}
            }
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let huge_backoff_timing = SignalTiming {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: [Duration::from_secs(10); 4],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "connect-timeout-reconnect".to_string(),
            Vec::new(),
            None,
            huge_backoff_timing,
            |_| {},
        );

        wait_until_connected(&client, Duration::from_secs(3));
        let t0 = Instant::now();
        let timeout_err = client
            .request_connect("987654321", Duration::from_millis(150))
            .expect_err("silent server must trigger request_connect timeout");
        assert!(
            timeout_err.contains("超时"),
            "unexpected err: {timeout_err}"
        );

        // 超时后必须通过 trigger_reconnect("connect_request_timeout") 在 ~200ms 内完成第 2 轮重连
        let deadline = Instant::now() + Duration::from_secs(3);
        while (!round2_registered.load(Ordering::Acquire)
            || client.status().state != ServerConnectionState::Connected)
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(15));
        }
        assert!(
            round2_registered.load(Ordering::Acquire),
            "request_connect timeout must trigger fast reconnect"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "reconnect after timeout must not wait 10s backoff, took {:?}",
            t0.elapsed()
        );

        let grant = client
            .request_connect("987654321", Duration::from_secs(2))
            .expect("second connect_request on fresh connection must succeed");
        assert_eq!(grant.relay_token, "tok-after-timeout-reconnect");

        client.stop();
        server.join().unwrap();
    }

    #[test]
    fn upnp_external_addr_injected_into_effective_lan_addrs_with_dedup_cap_and_heartbeat() {
        let opts = SignalClientOptions::default();
        assert!(!opts.upnp_enabled);
        assert!(format!("{opts:?}").contains("upnp_enabled: false"));

        let cfg = ServerConfig::default();
        let shared = SharedState {
            status: Mutex::new(cfg.disabled_snapshot()),
            status_updates: Mutex::new(VecDeque::new()),
            incoming: Mutex::new(VecDeque::new()),
            device_status_events: Mutex::new(VecDeque::new()),
            kicked_reasons: Mutex::new(VecDeque::new()),
            pending_connects: Mutex::new(HashMap::new()),
            active_writer: Mutex::new(None),
            shutdown_stream: Mutex::new(None),
            stop_flag: AtomicBool::new(false),
            stop_lock: Mutex::new(false),
            stop_cv: Condvar::new(),
            fast_reconnect: AtomicBool::new(false),
            reset_backoff_on_reconnect: AtomicBool::new(false),
            reconnect_epoch: AtomicU64::new(0),
            reconnect_reason: Mutex::new(None),
            last_server_activity: Mutex::new(None),
            last_timeout_reconnect: Mutex::new(None),
            local_udp_port: AtomicU16::new(50000),
            local_udp_is_ipv6: AtomicBool::new(false),
            nat_profile: Mutex::new(NatProfile::default()),
            rtt_ms: Mutex::new(None),
            last_heartbeat_sent_at: Mutex::new(None),
            active_probe: Mutex::new(None),
            dynamic_lan_discovery: false,
            connected_probe_targets: Mutex::new(Vec::new()),
            server_is_loopback: AtomicBool::new(false),
            upnp_enabled: AtomicBool::new(true),
            upnp_status: Mutex::new(UpnpStatus::Mapped {
                external_addr: "198.51.100.77:41234".to_string(),
                protocol: "upnp_igd_v2".to_string(),
            }),
            upnp_external_addr: Mutex::new(Some("198.51.100.77:41234".to_string())),
            upnp_lease: Mutex::new(None),
            upnp_gen: AtomicU64::new(1),
            upnp_heartbeat_needed: AtomicBool::new(false),
            lan_addrs: Vec::new(),
            enabled: true,
            token_provider: None,
            token_refresher: None,
            device_pubkey: None,
            allow_remote_assist: AtomicU8::new(ASSIST_UNSET),
            allow_remote_control: AtomicU8::new(REMOTE_CTRL_UNSET),
            wol_enabled: AtomicU8::new(WOL_UNSET),
            mac_addr: Mutex::new(None),
            device_wol_events: Mutex::new(VecDeque::new()),
            device_wol_capable: Mutex::new(HashMap::new()),
            pending_wols: Mutex::new(HashMap::new()),
            wol_relay_inflight: Arc::new(AtomicUsize::new(0)),
            wol_relay_history: Mutex::new(VecDeque::new()),
            proxy_override: Mutex::new(None),
            proxy_active: AtomicBool::new(false),
            wol_relay_test_sink: Mutex::new(None),
        };

        // 1) 追加 UPnP 外网地址且保留其外网端口（不改写为 local_udp_port）
        let static_addrs = vec!["192.168.1.10:9901".to_string()];
        assert_eq!(
            shared.current_effective_lan_addrs(&static_addrs, 50000, false),
            vec![
                "192.168.1.10:50000".to_string(),
                "198.51.100.77:41234".to_string(),
            ]
        );

        // 2) 去重：静态列表改写后已包含相同地址时不重复追加
        *shared.upnp_external_addr.lock().unwrap() = Some("192.168.1.10:50000".to_string());
        assert_eq!(
            shared.current_effective_lan_addrs(&static_addrs, 50000, false),
            vec!["192.168.1.10:50000".to_string()]
        );

        // 3) 总数不超过服务端 MAX_LAN_ADDRS (16) 上限
        *shared.upnp_external_addr.lock().unwrap() = Some("203.0.113.99:49999".to_string());
        let sixteen: Vec<String> = (1..=MAX_LAN_ADDRS)
            .map(|i| format!("192.168.10.{i}:9901"))
            .collect();
        let capped = shared.current_effective_lan_addrs(&sixteen, 50000, false);
        assert_eq!(capped.len(), MAX_LAN_ADDRS);

        // 4) IPv6 与 local_udp_port == 0 时不追加 IPv4 UPnP 地址
        assert!(shared
            .current_effective_lan_addrs(&static_addrs, 0, false)
            .is_empty());
        assert_eq!(
            shared.current_effective_lan_addrs(&["[fd00::1]:9901".to_string()], 50000, true),
            vec!["[fd00::1]:50000".to_string()]
        );

        // 5) 端到端验证：置位 upnp_heartbeat_needed 后信令循环立即补发增量 Heartbeat 携带 upnp_external_addr
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let udp_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp_sock.local_addr().unwrap().to_string();
        let seen_upnp_hb = Arc::new(AtomicBool::new(false));
        let seen_upnp_hb_srv = Arc::clone(&seen_upnp_hb);

        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            let reg = read_test_frame(&mut s);
            assert_eq!(reg["type"], "register");
            write_test_frame(
                &mut s,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "644555666",
                    "formatted_id": "644 555 666",
                    "udp_probe_addr": udp_addr,
                    "relay_addr": "127.0.0.1:21117"
                }),
            );
            // 读取初始心跳和增量 UPnP 心跳
            for _ in 0..8 {
                let frame = read_test_frame(&mut s);
                if frame["type"] == "heartbeat" {
                    let addrs = frame["lan_addrs"].as_array().cloned().unwrap_or_default();
                    if addrs
                        .iter()
                        .any(|v| v.as_str() == Some("198.51.100.88:54321"))
                    {
                        seen_upnp_hb_srv.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            let mut sink = [0u8; 64];
            while matches!(s.read(&mut sink), Ok(n) if n > 0) {}
        });

        let srv_cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let mut client = SignalClientHandle::spawn(
            srv_cfg,
            "upnp-hb-test".to_string(),
            vec!["192.168.1.10:9901".to_string()],
        );
        wait_until_connected(&client, Duration::from_secs(3));
        *client.shared.upnp_external_addr.lock().unwrap() = Some("198.51.100.88:54321".to_string());
        client
            .shared
            .upnp_heartbeat_needed
            .store(true, Ordering::Release);

        let deadline = Instant::now() + Duration::from_secs(2);
        while !seen_upnp_hb.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(15));
        }
        assert!(
            seen_upnp_hb.load(Ordering::Acquire),
            "setting upnp_heartbeat_needed must promptly emit incremental Heartbeat with upnp_external_addr"
        );
        client.stop();
        server.join().unwrap();
    }

    #[test]
    fn set_upnp_enabled_false_clears_state_and_generation_guards_stale_results() {
        // 默认 options.upnp_enabled == false -> 初始状态为 Disabled
        let mut client_off = SignalClientHandle::spawn_with_options(
            ServerConfig::default(),
            "upnp-off".to_string(),
            Vec::new(),
            SignalClientOptions::default(),
            |_| {},
        );
        assert_eq!(client_off.upnp_status(), UpnpStatus::Disabled);

        // options.upnp_enabled == true -> 初始状态为 Discovering（未启用信令时不发 SSDP）
        let mut client_on = SignalClientHandle::spawn_with_options(
            ServerConfig::default(),
            "upnp-on".to_string(),
            Vec::new(),
            SignalClientOptions {
                upnp_enabled: true,
                ..SignalClientOptions::default()
            },
            |_| {},
        );
        assert_eq!(client_on.upnp_status(), UpnpStatus::Discovering);

        // 模拟已映射状态并调用 set_upnp_enabled(false)
        let gen_before = client_on.shared.upnp_gen.load(Ordering::Acquire);
        *client_on.shared.upnp_external_addr.lock().unwrap() =
            Some("203.0.113.42:45000".to_string());
        *client_on.shared.upnp_status.lock().unwrap() = UpnpStatus::Mapped {
            external_addr: "203.0.113.42:45000".to_string(),
            protocol: "upnp_igd_v2".to_string(),
        };
        client_on
            .shared
            .upnp_heartbeat_needed
            .store(true, Ordering::Release);

        client_on.set_upnp_enabled(false);
        assert!(
            client_on.shared.upnp_gen.load(Ordering::Acquire) > gen_before,
            "set_upnp_enabled(false) must increment upnp_gen"
        );
        assert_eq!(client_on.upnp_status(), UpnpStatus::Disabled);
        assert!(client_on
            .shared
            .upnp_external_addr
            .lock()
            .unwrap()
            .is_none());
        assert!(client_on.shared.upnp_lease.lock().unwrap().is_none());
        assert!(!client_on
            .shared
            .upnp_heartbeat_needed
            .load(Ordering::Acquire));

        // 过期代际结果到达不得覆写 Disabled 状态
        apply_upnp_map_result(
            &client_on.shared,
            gen_before,
            Err("stale gateway timeout".to_string()),
        );
        assert_eq!(client_on.upnp_status(), UpnpStatus::Disabled);

        // 重新开启（未绑定 UDP 端口）进入 Discovering，同代际失败正确写入 Unavailable，过期代际被丢弃
        client_on.set_upnp_enabled(true);
        assert_eq!(client_on.upnp_status(), UpnpStatus::Discovering);
        let active_gen = client_on.shared.upnp_gen.load(Ordering::Acquire);
        apply_upnp_map_result(
            &client_on.shared,
            active_gen.saturating_sub(1),
            Err("old gen error".to_string()),
        );
        assert_eq!(client_on.upnp_status(), UpnpStatus::Discovering);

        apply_upnp_map_result(
            &client_on.shared,
            active_gen,
            Err("CGNAT detected".to_string()),
        );
        assert_eq!(
            client_on.upnp_status(),
            UpnpStatus::Unavailable {
                reason: "CGNAT detected".to_string()
            }
        );

        // 回环模式下开启 UPnP 必须跳过真实 SSDP 探测并标记 Unavailable
        client_off
            .shared
            .local_udp_port
            .store(51234, Ordering::Release);
        client_off
            .shared
            .server_is_loopback
            .store(true, Ordering::Release);
        client_off.set_upnp_enabled(true);
        assert!(matches!(
            client_off.upnp_status(),
            UpnpStatus::Unavailable { .. }
        ));
        client_off.set_upnp_enabled(false);
        assert_eq!(client_off.upnp_status(), UpnpStatus::Disabled);

        client_on.stop();
        client_off.stop();
    }

    #[test]
    fn request_connect_timeout_respects_cooldown_recent_activity_and_does_not_reset_backoff() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        let stop_srv = Arc::new(AtomicBool::new(false));
        let stop_srv_bg = Arc::clone(&stop_srv);

        let server = thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            let mut conns = Vec::new();
            let mut round = 0usize;
            while !stop_srv_bg.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        round += 1;
                        let _ = s.set_nonblocking(false);
                        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                        let reg = read_test_frame(&mut s);
                        assert_eq!(reg["type"], "register");
                        write_test_frame(
                            &mut s,
                            &serde_json::json!({
                                "type": "registered",
                                "device_id": "655666777",
                                "formatted_id": "655 666 777",
                                "udp_probe_addr": "",
                                "relay_addr": "127.0.0.1:21117"
                            }),
                        );
                        if round == 1 {
                            // Round 1 主动回一帧 HeartbeatAck 证明链路存活，随后不回 punch_coord
                            write_test_frame(
                                &mut s,
                                &serde_json::json!({ "type": "heartbeat_ack" }),
                            );
                        }
                        accept_count_srv.store(round, Ordering::Release);
                        conns.push(s);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: 21117,
            use_https: false,
            device_key: crate::server_config::generate_device_key(),
            ..ServerConfig::default()
        };
        let timing = SignalTiming {
            heartbeat_interval: HEARTBEAT_INTERVAL,
            activity_timeout: SERVER_ACTIVITY_TIMEOUT,
            stable_threshold: STABLE_CONNECTION_THRESHOLD,
            backoffs: [
                Duration::from_millis(100),
                Duration::from_millis(800),
                Duration::from_secs(2),
                Duration::from_secs(5),
            ],
        };
        let mut client = SignalClientHandle::spawn_with_timing(
            cfg,
            "timeout-storm-guard".to_string(),
            Vec::new(),
            None,
            timing,
            |_| {},
        );

        wait_until_connected(&client, Duration::from_secs(3));
        // 等待 Round 1 收到服务端 heartbeat_ack 并记录 last_server_activity
        let wait_act = Instant::now() + Duration::from_secs(2);
        while client.shared.last_server_activity.lock().unwrap().is_none()
            && Instant::now() < wait_act
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(client.shared.last_server_activity.lock().unwrap().is_some());

        // 1) 刚收到服务端响应（< 3s），单次短超时不得切断活跃连接
        let epoch_before = client.shared.reconnect_epoch.load(Ordering::Acquire);
        let err1 = client
            .request_connect("987654321", Duration::from_millis(80))
            .expect_err("should timeout");
        assert!(err1.contains("超时"));
        assert_eq!(
            client.shared.reconnect_epoch.load(Ordering::Acquire),
            epoch_before,
            "recent server activity must suppress timeout-triggered reconnect"
        );
        assert_eq!(accept_count.load(Ordering::Acquire), 1);

        // 2) 模拟服务端活动已超过 3s 静默，首次超时允许触发重连（进入 Round 2）
        *client.shared.last_server_activity.lock().unwrap() =
            Some(Instant::now() - TIMEOUT_RECONNECT_ACTIVITY_GRACE - Duration::from_secs(1));
        let err2 = client
            .request_connect("987654321", Duration::from_millis(80))
            .expect_err("should timeout");
        assert!(err2.contains("超时"));
        assert_eq!(
            client.shared.reconnect_epoch.load(Ordering::Acquire),
            epoch_before + 1
        );

        let wait_r2 = Instant::now() + Duration::from_secs(3);
        while (accept_count.load(Ordering::Acquire) < 2
            || client.status().state != ServerConnectionState::Connected)
            && Instant::now() < wait_r2
        {
            thread::sleep(Duration::from_millis(15));
        }
        assert_eq!(accept_count.load(Ordering::Acquire), 2);

        // 3) 冷却期（5s）内连续超时必须被抑制，绝不触发重连风暴
        let epoch_r2 = client.shared.reconnect_epoch.load(Ordering::Acquire);
        for _ in 0..3 {
            let err_cool = client
                .request_connect("987654321", Duration::from_millis(60))
                .expect_err("should timeout during cooldown");
            assert!(err_cool.contains("超时"));
        }
        assert_eq!(
            client.shared.reconnect_epoch.load(Ordering::Acquire),
            epoch_r2,
            "consecutive timeouts within cooldown must not trigger reconnect"
        );
        assert_eq!(accept_count.load(Ordering::Acquire), 2);

        // 4) 冷却期满后再次超时触发重连：因不重置 backoff_idx，此次必须走退避阶梯（backoffs[1] = 800ms），而非 200ms 快速重连
        *client.shared.last_timeout_reconnect.lock().unwrap() =
            Some(Instant::now() - TIMEOUT_RECONNECT_COOLDOWN - Duration::from_secs(1));
        let t_r3 = Instant::now();
        let err3 = client
            .request_connect("987654321", Duration::from_millis(60))
            .expect_err("should timeout after cooldown");
        assert!(err3.contains("超时"));
        assert_eq!(
            client.shared.reconnect_epoch.load(Ordering::Acquire),
            epoch_r2 + 1
        );
        let wait_r3 = Instant::now() + Duration::from_secs(3);
        while accept_count.load(Ordering::Acquire) < 3 && Instant::now() < wait_r3 {
            thread::sleep(Duration::from_millis(15));
        }
        assert_eq!(accept_count.load(Ordering::Acquire), 3);
        assert!(
            t_r3.elapsed() >= Duration::from_millis(700),
            "second timeout reconnect must obey non-reset backoff (expected >=700ms, got {:?})",
            t_r3.elapsed()
        );

        stop_srv.store(true, Ordering::Release);
        client.stop();
        server.join().unwrap();
    }

    #[test]
    fn set_upnp_enabled_rechecks_port_under_lease_lock_and_skips_cleared_port() {
        let mut client = SignalClientHandle::spawn_with_options(
            ServerConfig::default(),
            "upnp-port-recheck".to_string(),
            Vec::new(),
            SignalClientOptions::default(),
            |_| {},
        );
        // 模拟并发断连刚将 local_udp_port 清零后调用 set_upnp_enabled(true)：不得为旧端口触发映射
        client.shared.local_udp_port.store(0, Ordering::Release);
        assert!(client.shared.enable_upnp_and_prepare().is_none());
        assert_eq!(client.upnp_status(), UpnpStatus::Discovering);

        // 当端口被清零后，旧端口的 prepare_upnp_if_enabled(Some(old_port), ...) 必须被拒绝
        client.shared.local_udp_port.store(50123, Ordering::Release);
        client.shared.clear_active_writer();
        assert_eq!(client.shared.local_udp_port.load(Ordering::Acquire), 0);
        assert!(client
            .shared
            .prepare_upnp_if_enabled(Some(50123), UpnpStatus::Discovering)
            .is_none());

        client.stop();
    }

    fn try_read_test_frame(stream: &mut TcpStream) -> Option<serde_json::Value> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).ok()?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).ok()?;
        serde_json::from_slice(&body).ok()
    }

    #[test]
    fn wol_request_ack_mapping_relay_dispatch_and_device_wol_status_e2e() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock wol signal");
        let addr = listener.local_addr().unwrap();
        let received_updates = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let updates_srv = Arc::clone(&received_updates);

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

            // 1) 读取 Register 并回 Registered
            let reg = read_test_frame(&mut stream);
            assert_eq!(reg["type"], "register");
            write_test_frame(
                &mut stream,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "100000001",
                    "formatted_id": "100 000 001",
                    "relay_addr": format!("127.0.0.1:{}", addr.port()),
                    "udp_probe_addr": format!("127.0.0.1:{}", addr.port()),
                }),
            );

            // 2) 推送带 wol_capable 的 DeviceStatusChanged 与 2 条 wol_relay（1 条合法，1 条非法多播应忽略）
            write_test_frame(
                &mut stream,
                &serde_json::json!({
                    "type": "device_status_changed",
                    "device_id": "200000002",
                    "online": false,
                    "hostname": "Office-Mac",
                    "alias": "",
                    "os": "macos",
                    "allow_remote_assist": false,
                    "allow_remote_control": true,
                    "wol_capable": true
                }),
            );
            write_test_frame(
                &mut stream,
                &serde_json::json!({
                    "type": "wol_relay",
                    "request_id": "relay-bad-1",
                    "target_device_id": "200000002",
                    "mac_addr": "01:00:5e:00:00:01",
                    "target_lan_addrs": ["192.168.1.20:50000"]
                }),
            );
            write_test_frame(
                &mut stream,
                &serde_json::json!({
                    "type": "wol_relay",
                    "request_id": "relay-ok-1",
                    "target_device_id": "200000002",
                    "mac_addr": "AA-BB-CC-DD-EE-FF",
                    "target_lan_addrs": ["192.168.1.20:50000"]
                }),
            );

            // 3) 处理后续 update_assist_state 与 5 个 wol_request（依次返回 ok / wol_disabled / wol_no_relay_peer / wol_send_failed / rate_limited）
            let mut wol_count = 0usize;
            while let Some(frame) = try_read_test_frame(&mut stream) {
                match frame["type"].as_str() {
                    Some("heartbeat") => {
                        write_test_frame(
                            &mut stream,
                            &serde_json::json!({"type": "heartbeat_ack"}),
                        );
                    }
                    Some("update_assist_state") => {
                        updates_srv.lock().unwrap().push(frame);
                    }
                    Some("wol_request") => {
                        let req_id = frame["request_id"].as_str().unwrap_or("").to_string();
                        let target_id =
                            frame["target_device_id"].as_str().unwrap_or("").to_string();
                        wol_count += 1;
                        let ack = match wol_count {
                            1 => serde_json::json!({
                                "type": "wol_ack",
                                "request_id": req_id,
                                "target_device_id": target_id,
                                "ok": true,
                                "method": "lan_peer",
                                "message": "relayed via same-LAN peer"
                            }),
                            2 => serde_json::json!({
                                "type": "wol_ack",
                                "request_id": req_id,
                                "target_device_id": target_id,
                                "ok": false,
                                "method": "none",
                                "code": "wol_disabled",
                                "message": "target wol disabled"
                            }),
                            3 => serde_json::json!({
                                "type": "wol_ack",
                                "request_id": req_id,
                                "target_device_id": target_id,
                                "ok": false,
                                "method": "none",
                                "code": "wol_no_relay_peer",
                                "message": "no online peer in same LAN"
                            }),
                            4 => serde_json::json!({
                                "type": "wol_ack",
                                "request_id": req_id,
                                "target_device_id": target_id,
                                "ok": false,
                                "method": "none",
                                "code": "wol_send_failed",
                                "message": "udp send failed"
                            }),
                            _ => serde_json::json!({
                                "type": "wol_ack",
                                "request_id": req_id,
                                "target_device_id": target_id,
                                "ok": false,
                                "method": "none",
                                "code": "rate_limited",
                                "message": "too many requests"
                            }),
                        };
                        write_test_frame(&mut stream, &ack);
                        if wol_count >= 5 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            signal_port: addr.port(),
            relay_port: addr.port(),
            use_https: false,
            ..ServerConfig::default()
        };
        let mut client = SignalClientHandle::spawn_with_options(
            cfg,
            "wol-tester".to_string(),
            Vec::new(),
            SignalClientOptions::default(),
            |_| {},
        );
        let (relay_tx, relay_rx) = mpsc::channel();
        *client.shared.wol_relay_test_sink.lock().unwrap() = Some(relay_tx);

        // 等待 Connected
        let wait_conn = Instant::now() + Duration::from_secs(3);
        while client.status().state != ServerConnectionState::Connected
            && Instant::now() < wait_conn
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(client.status().state, ServerConnectionState::Connected);

        // 验证 wol_relay 仅投递合法规范化 MAC（忽略非法多播）
        let (relayed_mac, relayed_addrs) = relay_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("must receive relayed WOL task");
        assert_eq!(relayed_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(relayed_addrs, vec!["192.168.1.20:50000".to_string()]);
        assert!(
            relay_rx.try_recv().is_err(),
            "multicast wol_relay must be ignored"
        );

        // 验证 DeviceStatusChanged 的 wol_capable 解析与查询 API
        let wait_wol = Instant::now() + Duration::from_secs(2);
        while client.device_wol_capable("200000002").is_none() && Instant::now() < wait_wol {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(client.device_wol_capable("200 000 002"), Some(true));
        let wol_ev = client
            .try_recv_device_wol_status()
            .expect("must enqueue DeviceWolCapabilityEvent");
        assert_eq!(wol_ev.device_id, "200000002");
        assert!(wol_ev.wol_capable);

        // 验证 set_mac_addr 拒绝非法 MAC，接受合法 MAC 并与 set_wol_enabled 同步
        assert!(client
            .set_mac_addr(Some("ff:ff:ff:ff:ff:ff".into()))
            .is_err());
        client
            .set_mac_addr(Some("02-11-22-33-44-55".into()))
            .expect("valid mac");
        client.set_wol_enabled(true).expect("enable wol");

        // 验证 5 种 wol_ack 结果与 UiError 映射
        let ok_ack = client
            .request_wol("200 000 002", Duration::from_secs(2))
            .expect("wol ok");
        assert!(ok_ack.ok);
        assert_eq!(ok_ack.method, "lan_peer");
        assert!(ok_ack.ui_error.is_none());

        let expected_codes = [
            ("wol_disabled", crate::ui_error::codes::WOL_DISABLED),
            (
                "wol_no_relay_peer",
                crate::ui_error::codes::WOL_NO_RELAY_PEER,
            ),
            ("wol_send_failed", crate::ui_error::codes::WOL_SEND_FAILED),
            ("rate_limited", crate::ui_error::codes::NETWORK_RATE_LIMITED),
        ];
        for (wire, canonical) in expected_codes {
            let ack = client
                .request_wol("200000002", Duration::from_secs(2))
                .expect("wol_ack should decode cleanly");
            assert!(!ack.ok);
            assert_eq!(ack.code.as_deref(), Some(wire));
            let ui_err = ack.ui_error.expect("failed wol_ack must attach UiError");
            assert_eq!(ui_err.code, canonical);
        }

        client.stop();
        server.join().unwrap();

        let updates = received_updates.lock().unwrap();
        assert!(
            updates.iter().any(|u| u["mac_addr"] == "02:11:22:33:44:55"),
            "expected normalized mac_addr in update_assist_state: {updates:?}"
        );
        assert!(
            updates.iter().any(|u| u["wol_enabled"] == true),
            "expected wol_enabled=true in update_assist_state: {updates:?}"
        );
    }

    #[test]
    fn signal_client_with_active_proxy_skips_udp_probe_and_upnp() {
        // 1) 本地 Mock 信令服务器
        let sig_listener = TcpListener::bind("127.0.0.1:0").expect("bind mock signal");
        let sig_addr = sig_listener.local_addr().unwrap();
        let sig_srv = thread::spawn(move || {
            let (mut s, _) = sig_listener.accept().expect("accept via proxy");
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let reg = read_test_frame(&mut s);
            assert_eq!(reg["type"], "register");
            write_test_frame(
                &mut s,
                &serde_json::json!({
                    "type": "registered",
                    "device_id": "300000003",
                    "formatted_id": "300 000 003",
                    "relay_addr": "signal.corp.internal:21117",
                    "udp_probe_addr": "signal.corp.internal:21116"
                }),
            );
            // 保持连接直到客户端断开
            let _ = try_read_test_frame(&mut s);
        });

        // 2) 本地 Mock SOCKS5 代理，将不存在的 `signal.corp.internal` 隧道转发至 sig_addr
        let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind mock socks5");
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_srv = thread::spawn(move || {
            let (mut c, _) = proxy_listener.accept().expect("accept socks5");
            let mut g = [0u8; 3];
            c.read_exact(&mut g).unwrap();
            c.write_all(&[0x05, 0x00]).unwrap();
            let mut hdr = [0u8; 4];
            c.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[3], 0x03); // 必须域名透传
            let mut l = [0u8; 1];
            c.read_exact(&mut l).unwrap();
            let mut dom = vec![0u8; usize::from(l[0])];
            c.read_exact(&mut dom).unwrap();
            let mut port = [0u8; 2];
            c.read_exact(&mut port).unwrap();
            assert_eq!(&dom, b"signal.corp.internal");
            c.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .unwrap();

            let mut backend = TcpStream::connect(sig_addr).expect("connect mock signal");
            let mut c_r = c.try_clone().unwrap();
            let mut b_w = backend.try_clone().unwrap();
            let t = thread::spawn(move || {
                let _ = io::copy(&mut c_r, &mut b_w);
                let _ = b_w.shutdown(Shutdown::Write);
            });
            let _ = io::copy(&mut backend, &mut c);
            let _ = c.shutdown(Shutdown::Write);
            let _ = t.join();
        });

        struct GlobalProxyResetGuard;
        impl Drop for GlobalProxyResetGuard {
            fn drop(&mut self) {
                crate::proxy::set_global_proxy_config(crate::proxy::ProxyConfig::default());
            }
        }
        let _guard = GlobalProxyResetGuard;
        crate::proxy::set_global_proxy_config(crate::proxy::ProxyConfig {
            mode: crate::proxy::ProxyMode::Manual,
            protocol: Some(crate::proxy::ProxyProtocol::Socks5),
            host: "127.0.0.1".to_string(),
            port: proxy_addr.port(),
            username: None,
            password: None,
        });

        let cfg = ServerConfig {
            enabled: true,
            server_host: "signal.corp.internal".to_string(),
            signal_port: 21116,
            relay_port: 21117,
            use_https: false,
            ..ServerConfig::default()
        };
        let mut client = SignalClientHandle::spawn_with_options(
            cfg,
            "proxied-host".to_string(),
            Vec::new(),
            SignalClientOptions {
                upnp_enabled: true,
                ..SignalClientOptions::default()
            },
            |_| {},
        );

        let wait_conn = Instant::now() + Duration::from_secs(3);
        while client.status().state != ServerConnectionState::Connected
            && Instant::now() < wait_conn
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(client.status().state, ServerConnectionState::Connected);
        assert_eq!(
            client.shared.local_udp_port.load(Ordering::Acquire),
            0,
            "proxy active must skip UDP RCSP probe binding"
        );
        assert!(
            matches!(client.upnp_status(), UpnpStatus::Unavailable { ref reason } if reason.contains("代理")),
            "proxy active must skip UPnP and report Unavailable: {:?}",
            client.upnp_status()
        );
        assert!(
            client.shared.connected_probe_targets.lock().unwrap().is_empty(),
            "proxy active must skip UDP probe DNS resolution and leave connected_probe_targets empty"
        );
        assert!(
            !client.shared.server_is_loopback.load(Ordering::Acquire),
            "proxy active must derive server_is_loopback from cfg.server_host instead of proxy socket peer_addr"
        );

        // Low 2: 验证 WolAck 携带显式 JSON null 的 request_id 时可正常反序列化不触发协议报错
        let null_req_ack: IncomingSignalMsg = serde_json::from_value(serde_json::json!({
            "type": "wol_ack",
            "request_id": null,
            "target_device_id": "300000003",
            "ok": false,
            "method": "none",
            "code": "wol_disabled",
            "message": "disabled"
        }))
        .expect("WolAck with null request_id must deserialize cleanly");
        assert!(matches!(
            null_req_ack,
            IncomingSignalMsg::WolAck {
                request_id: None,
                ..
            }
        ));

        client.stop();
        let _ = proxy_srv.join();
        let _ = sig_srv.join();
    }

    fn build_test_rcsa(addr: SocketAddr, nonce: [u8; 8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(UDP_ANSWER_MAGIC);
        out.push(UDP_ANSWER_VERSION);
        match addr.ip() {
            IpAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(16);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&addr.port().to_be_bytes());
        out.extend_from_slice(&nonce);
        out
    }

    #[test]
    fn build_udp_probe_packet_v2_and_parse_udp_answer_packet_roundtrip() {
        let nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let token = [0xAAu8; 16];
        let pkt = build_udp_probe_packet_v2("604928235", nonce, token).unwrap();
        assert_eq!(pkt.len(), UDP_PROBE_V2_LEN);
        assert_eq!(&pkt[0..4], b"RCSP");
        assert_eq!(pkt[4], 2);
        assert_eq!(&pkt[5..14], b"604928235");
        assert_eq!(&pkt[14..22], &nonce);
        assert_eq!(&pkt[22..38], &token);

        let anon = build_udp_probe_packet_v2("000000000", nonce, token).unwrap();
        assert_eq!(&anon[5..14], b"000000000");
        assert!(build_udp_probe_packet_v2("012345678", nonce, token).is_err());
        assert!(build_udp_probe_packet_v2("bad", nonce, token).is_err());

        // 20B IPv4 RCSA 往返
        let v4_addr: SocketAddr = "198.51.100.42:54321".parse().unwrap();
        let rcsa_v4 = build_test_rcsa(v4_addr, nonce);
        assert_eq!(rcsa_v4.len(), 20);
        assert_eq!(parse_udp_answer_packet(&rcsa_v4), Some((v4_addr, nonce)));

        // 32B IPv6 RCSA 往返与 ::ffff: 解包
        let v6_addr: SocketAddr = "[2001:db8::9]:61234".parse().unwrap();
        let rcsa_v6 = build_test_rcsa(v6_addr, nonce);
        assert_eq!(rcsa_v6.len(), 32);
        assert_eq!(parse_udp_answer_packet(&rcsa_v6), Some((v6_addr, nonce)));

        let mapped_v6: SocketAddr = "[::ffff:198.51.100.42]:54321".parse().unwrap();
        let rcsa_mapped = build_test_rcsa(mapped_v6, nonce);
        assert_eq!(
            parse_udp_answer_packet(&rcsa_mapped),
            Some((v4_addr, nonce))
        );

        // 非法 magic / ver / ip_len / 长度一律拒绝
        let mut bad_magic = rcsa_v4.clone();
        bad_magic[0] = b'X';
        assert!(parse_udp_answer_packet(&bad_magic).is_none());

        let mut bad_ver = rcsa_v4.clone();
        bad_ver[4] = 2;
        assert!(parse_udp_answer_packet(&bad_ver).is_none());

        let mut bad_iplen = rcsa_v4.clone();
        bad_iplen[5] = 8;
        assert!(parse_udp_answer_packet(&bad_iplen).is_none());

        assert!(parse_udp_answer_packet(&rcsa_v4[..19]).is_none());
        let mut oversized = rcsa_v4;
        oversized.push(0);
        assert!(parse_udp_answer_packet(&oversized).is_none());
    }

    #[test]
    fn effective_lan_addrs_retains_global_unicast_ipv6_under_ipv4_probe() {
        let raw = vec![
            "192.168.1.10:9901".to_string(),
            "[2001:db8::10]:9901".to_string(), // 全球单播 IPv6（2000::/3）
            "[240e:3b0:1::5]:9901".to_string(),
            "[fe80::1]:9901".to_string(), // 链路本地必须过滤
            "[fd00::1]:9901".to_string(), // ULA 在 IPv4 探测下按原规则跳过
            "[ff02::1]:9901".to_string(), // 多播必须过滤
            "[::1]:9901".to_string(),     // 回环在 allow_loopback=false 时过滤
        ];
        assert_eq!(
            effective_lan_addrs(&raw, 54321, false, false),
            vec![
                "192.168.1.10:54321".to_string(),
                "[2001:db8::10]:54321".to_string(),
                "[240e:3b0:1::5]:54321".to_string(),
            ]
        );
        // allow_loopback=true 时，IPv4 探测下 ::1 仍不放行（仅全球 IPv6 跨族保留）
        assert_eq!(
            effective_lan_addrs(&raw, 54321, false, true),
            vec![
                "192.168.1.10:54321".to_string(),
                "[2001:db8::10]:54321".to_string(),
                "[240e:3b0:1::5]:54321".to_string(),
            ]
        );
        // IPv6 探测下同时保留 ULA 与全球单播 IPv6
        assert_eq!(
            effective_lan_addrs(&raw, 54321, true, false),
            vec![
                "[2001:db8::10]:54321".to_string(),
                "[240e:3b0:1::5]:54321".to_string(),
                "[fd00::1]:54321".to_string(),
            ]
        );
    }

    #[test]
    fn udp_probe_slot_pause_and_resume_allows_exclusive_rebind() {
        let sig_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sig_addr = sig_udp.local_addr().unwrap();
        sig_udp
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let probe = PersistentUdpProbe::bind(sig_addr).expect("bind persistent probe");
        let port = probe.local_port();
        assert_ne!(port, 0);

        probe.send_probe("604928235");
        let mut buf = [0u8; 64];
        let (n1, from1) = sig_udp.recv_from(&mut buf).unwrap();
        assert_eq!(n1, UDP_PROBE_LEN);
        assert_eq!(from1.port(), port);

        // 暂停探测端口后，原探测 socket 已释放，无 SO_REUSEPORT 的独占绑定必须能占用同一端口。
        let hold = probe.slot.acquire_port_hold();
        probe.send_probe("604928235"); // 暂停期间安全跳过，不重绑也不 panic
        let exclusive = UdpSocket::bind(SocketAddr::from(([0u8; 4], port)))
            .expect("exclusive bind on same port must succeed while probe is paused");
        assert_eq!(exclusive.local_addr().unwrap().port(), port);
        drop(exclusive);

        // 释放暂停租约后自动恢复绑定同一本地端口并继续收发探测包。
        drop(hold);
        probe.send_probe("604928235");
        let (n2, from2) = sig_udp.recv_from(&mut buf).unwrap();
        assert_eq!(n2, UDP_PROBE_LEN);
        assert_eq!(from2.port(), port);
    }

    #[test]
    fn mock_server_rcsp_v2_nat_classification_cone_seq_random_retry_and_refresh() {
        for (case_name, alt_port_offset, expected_nat, expected_delta, expected_wire_nat) in [
            (
                "cone_unverified",
                0i32,
                NatType::ConeUnverified,
                Some(0i16),
                "cone_unverified",
            ),
            ("apdm_seq", 3i32, NatType::ApdmSeq, Some(3i16), "apdm_seq"),
            (
                "apdm_random",
                500i32,
                NatType::ApdmRandom,
                None,
                "apdm_random",
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let signal_addr = listener.local_addr().unwrap();

            let primary_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let primary_addr = primary_udp.local_addr().unwrap();
            primary_udp
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();

            let alt_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let alt_addr = alt_udp.local_addr().unwrap();
            alt_udp
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();

            let token_bytes = [0x42u8; 16];
            let token_hex = "42".repeat(16);
            let observed_primary: SocketAddr = "198.51.100.55:45000".parse().unwrap();
            let observed_alt: SocketAddr = SocketAddr::new(
                observed_primary.ip(),
                u16::try_from(i32::from(observed_primary.port()) + alt_port_offset).unwrap(),
            );

            let primary_probes_seen = Arc::new(AtomicUsize::new(0));
            let primary_probes_srv = Arc::clone(&primary_probes_seen);
            let primary_stop = Arc::new(AtomicBool::new(false));
            let primary_stop_bg = Arc::clone(&primary_stop);

            let primary_thread = thread::spawn(move || {
                let mut buf = [0u8; 64];
                let mut first = true;
                while !primary_stop_bg.load(Ordering::Acquire) {
                    match primary_udp.recv_from(&mut buf) {
                        Ok((n, from)) => {
                            if n == UDP_PROBE_V2_LEN
                                && &buf[0..4] == b"RCSP"
                                && buf[4] == 2
                                && &buf[5..14] == b"604928235"
                                && buf[22..38] == token_bytes
                            {
                                let count = primary_probes_srv.fetch_add(1, Ordering::SeqCst) + 1;
                                // 故意丢弃第 1 个探测包，验证客户端 40ms/80ms 快速重试并在第 2 包收到 RCSA。
                                if first {
                                    first = false;
                                    continue;
                                }
                                let _ = count;
                                let mut nonce = [0u8; 8];
                                nonce.copy_from_slice(&buf[14..22]);
                                let ans = build_test_rcsa(observed_primary, nonce);
                                let _ = primary_udp.send_to(&ans, from);
                            }
                        }
                        Err(e)
                            if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                        Err(_) => break,
                    }
                }
            });

            let alt_same_port = Arc::new(AtomicU16::new(0));
            let alt_same_port_srv = Arc::clone(&alt_same_port);
            let alt_thread = thread::spawn(move || {
                let mut buf = [0u8; 64];
                if let Ok((n, from)) = alt_udp.recv_from(&mut buf) {
                    assert_eq!(n, UDP_PROBE_V2_LEN, "alt port must receive RCSP v2");
                    assert_eq!(&buf[0..4], b"RCSP");
                    assert_eq!(buf[4], 2);
                    assert_eq!(&buf[22..38], &token_bytes);
                    alt_same_port_srv.store(from.port(), Ordering::SeqCst);
                    let mut nonce = [0u8; 8];
                    nonce.copy_from_slice(&buf[14..22]);
                    let ans = build_test_rcsa(observed_alt, nonce);
                    let _ = alt_udp.send_to(&ans, from);
                }
            });

            let server_thread = thread::spawn(move || {
                let (mut conn, _) = listener.accept().unwrap();
                let _ = conn.set_nodelay(true);
                let _ = conn.set_read_timeout(Some(Duration::from_secs(3)));

                let reg = read_test_frame(&mut conn);
                assert_eq!(reg["type"], "register");
                assert!(reg.get("nat_type").is_none());

                write_test_frame(
                    &mut conn,
                    &serde_json::json!({
                        "type": "registered",
                        "device_id": "604928235",
                        "formatted_id": "604 928 235",
                        "udp_probe_addr": primary_addr.to_string(),
                        "udp_probe_alt_addr": alt_addr.to_string(),
                        "udp_probe_token": token_hex,
                        "relay_addr": "127.0.0.1:21117",
                    }),
                );

                let hb0 = read_test_frame(&mut conn);
                assert_eq!(hb0["type"], "heartbeat", "case {case_name}");
                assert_eq!(
                    hb0["nat_type"].as_str(),
                    Some(expected_wire_nat),
                    "case {case_name}: initial heartbeat must carry classified nat_type"
                );
                assert_eq!(
                    hb0["nat_port_delta"].as_i64(),
                    expected_delta.map(i64::from),
                    "case {case_name}"
                );

                let req = read_test_frame(&mut conn);
                assert_eq!(req["type"], "connect_request", "case {case_name}");
                assert_eq!(req["nat_type"].as_str(), Some(expected_wire_nat));
                assert_eq!(
                    req["nat_port_delta"].as_i64(),
                    expected_delta.map(i64::from)
                );
                let sid = req["session_id"].as_str().unwrap().to_string();

                write_test_frame(
                    &mut conn,
                    &serde_json::json!({
                        "type": "punch_coord",
                        "session_id": sid,
                        "role": "client",
                        "peer_id": "987654321",
                        "peer_public_udp_addr": "203.0.113.88:50001",
                        "peer_public_udp_addrs": ["[2001:db8::88]:50002", "203.0.113.88:50001"],
                        "self_public_udp_addr": observed_primary.to_string(),
                        "peer_nat_type": "symmetric_seq",
                        "peer_nat_port_delta": 4,
                        "self_nat_port_range": [32768, 60999],
                        "peer_nat_port_range": [49152, 65535],
                        "peer_lan_addrs": ["192.168.1.20:50000"],
                        "punch_secret": "0123456789abcdef0123456789abcdef",
                        "start_after_ms": 35,
                        "relay_fallback_after_ms": 400,
                        "relay_token": "tok-nat-001",
                        "relay_addr": "127.0.0.1:21117",
                    }),
                );

                write_test_frame(
                    &mut conn,
                    &serde_json::json!({
                        "type": "punch_coord",
                        "session_id": "incoming-nat-01",
                        "role": "host",
                        "peer_id": "111222333",
                        "peer_public_udp_addr": "203.0.113.99:51111",
                        "peer_public_udp_addrs": ["203.0.113.99:51111"],
                        "self_public_udp_addr": observed_primary.to_string(),
                        "peer_nat_type": "cone",
                        "peer_nat_port_delta": 0,
                        "self_nat_port_range": [49152, 65535],
                        "peer_nat_port_range": [32768, 60999],
                        "peer_lan_addrs": ["192.168.1.30:50000"],
                        "punch_secret": "fedcba9876543210fedcba9876543210",
                        "start_after_ms": 0,
                        "relay_fallback_after_ms": 400,
                        "relay_token": "tok-nat-002",
                        "relay_addr": "127.0.0.1:21117",
                    }),
                );

                let mut sink = [0u8; 16];
                let _ = conn.read(&mut sink);
            });

            let cfg = ServerConfig {
                enabled: true,
                server_host: "127.0.0.1".to_string(),
                signal_port: signal_addr.port(),
                relay_port: 21117,
                use_https: false,
                ..ServerConfig::default()
            };
            let mut client = SignalClientHandle::spawn(
                cfg,
                format!("nat-{case_name}"),
                vec!["192.168.1.10:9901".to_string()],
            );

            wait_until_connected(&client, Duration::from_secs(3));
            let local_port = client.shared.local_udp_port.load(Ordering::Acquire);
            assert_ne!(local_port, 0);
            alt_thread.join().unwrap();
            assert_eq!(
                alt_same_port.load(Ordering::SeqCst),
                local_port,
                "alt probe must originate from same local_udp_port"
            );

            let probes_before_req = primary_probes_seen.load(Ordering::SeqCst);
            assert!(
                probes_before_req >= 2,
                "initial probe must retry after dropped RCSA packet (seen={probes_before_req})"
            );

            let grant = client
                .request_connect("987654321", Duration::from_secs(3))
                .expect("connect_request must resolve");
            assert_eq!(grant.self_nat_type, expected_nat);
            assert_eq!(grant.self_nat_port_delta, expected_delta);
            assert_eq!(
                grant.self_public_addr.as_deref(),
                Some("198.51.100.55:45000")
            );
            assert_eq!(
                grant.peer_public_addrs,
                vec![
                    "[2001:db8::88]:50002".to_string(),
                    "203.0.113.88:50001".to_string()
                ]
            );
            assert_eq!(grant.peer_nat_type, NatType::ApdmSeq);
            assert_eq!(grant.peer_nat_port_delta, Some(4));
            assert_eq!(
                grant.self_nat_port_range,
                Some(PortRangeHint::LinuxEphemeral)
            );
            assert_eq!(grant.peer_nat_port_range, Some(PortRangeHint::IanaDynamic));
            assert_eq!(
                grant.punch_secret.as_deref(),
                Some("0123456789abcdef0123456789abcdef")
            );
            assert_eq!(grant.start_after_ms, Some(35));
            assert_eq!(grant.relay_fallback_after_ms, Some(400));

            let inc = {
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    if let Some(item) = client.try_recv_incoming() {
                        break item;
                    }
                    assert!(Instant::now() < deadline, "timed out waiting for incoming");
                    thread::sleep(Duration::from_millis(10));
                }
            };
            assert_eq!(inc.self_nat_type, expected_nat);
            assert_eq!(inc.self_nat_port_delta, expected_delta);
            assert_eq!(inc.peer_nat_type, NatType::ConeUnverified);
            assert_eq!(inc.peer_nat_port_delta, Some(0));
            assert_eq!(inc.self_nat_port_range, Some(PortRangeHint::IanaDynamic));
            assert_eq!(inc.peer_nat_port_range, Some(PortRangeHint::LinuxEphemeral));
            assert_eq!(
                inc.punch_secret.as_deref(),
                Some("fedcba9876543210fedcba9876543210")
            );
            assert_eq!(inc.start_after_ms, Some(0));
            assert_eq!(inc.relay_fallback_after_ms, Some(400));
            assert_eq!(
                inc.peer_public_addrs,
                vec!["203.0.113.99:51111".to_string()]
            );

            // 验证 ConnectRequest 前与收到 PunchCoord 时至少额外触发了轻量 RCSP 刷新
            let wait_refresh = Instant::now() + Duration::from_secs(1);
            while primary_probes_seen.load(Ordering::SeqCst) < probes_before_req + 2
                && Instant::now() < wait_refresh
            {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                primary_probes_seen.load(Ordering::SeqCst) >= probes_before_req + 2,
                "expected lightweight RCSP refreshes on ConnectRequest and PunchCoord"
            );

            primary_stop.store(true, Ordering::Release);
            client.stop();
            let _ = primary_thread.join();
            server_thread.join().unwrap();
        }
    }

    #[test]
    fn mock_server_dual_stack_probe_and_legacy_compat() {
        // 1) 双栈解析辅助测试 + 若本机支持 [::1] 则验证 RCSP v2 双栈探测记录 v4 + v6
        let v4: SocketAddr = "127.0.0.1:21116".parse().unwrap();
        let v6: SocketAddr = "[::1]:21116".parse().unwrap();
        assert_eq!(
            resolve_dual_stack_udp_target(&[v4, v6], Some(v4), "127.0.0.1", &[]),
            Some(v6)
        );
        assert_eq!(
            resolve_dual_stack_udp_target(&[v4, v6], Some(v6), "127.0.0.1", &[]),
            Some(v4)
        );
        assert_eq!(
            resolve_dual_stack_udp_target(&[v4], Some(v4), "127.0.0.1", &[]),
            None
        );

        if let Ok(v6_udp) = UdpSocket::bind("[::1]:0") {
            let v6_addr = v6_udp.local_addr().unwrap();
            let _ = v6_udp.set_read_timeout(Some(Duration::from_secs(2)));
            let v4_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let v4_addr = v4_udp.local_addr().unwrap();
            let _ = v4_udp.set_read_timeout(Some(Duration::from_secs(2)));

            let token = [0x77u8; 16];
            let obs_v4: SocketAddr = "198.51.100.70:41000".parse().unwrap();
            let obs_v6: SocketAddr = "[2001:db8::70]:41000".parse().unwrap();

            let t4 = thread::spawn(move || {
                let mut buf = [0u8; 64];
                if let Ok((n, from)) = v4_udp.recv_from(&mut buf) {
                    if n == UDP_PROBE_V2_LEN {
                        let mut nonce = [0u8; 8];
                        nonce.copy_from_slice(&buf[14..22]);
                        let _ = v4_udp.send_to(&build_test_rcsa(obs_v4, nonce), from);
                    }
                }
            });
            let t6 = thread::spawn(move || {
                let mut buf = [0u8; 64];
                if let Ok((n, from)) = v6_udp.recv_from(&mut buf) {
                    if n == UDP_PROBE_V2_LEN {
                        let mut nonce = [0u8; 8];
                        nonce.copy_from_slice(&buf[14..22]);
                        let _ = v6_udp.send_to(&build_test_rcsa(obs_v6, nonce), from);
                    }
                }
            });

            let probe = PersistentUdpProbe::bind_with_options(
                v4_addr,
                "604928235".to_string(),
                Some(token),
                None,
                None,
                Some(v6_addr),
                Vec::new(),
            )
            .expect("bind v4+v6 dual-stack probe");
            let nat_profile = Mutex::new(NatProfile::default());
            let rtt_ms = Mutex::new(None);
            let stop_flag = AtomicBool::new(false);
            probe.run_initial_probe_round(&nat_profile, &rtt_ms, &stop_flag);
            let prof = nat_profile.lock().unwrap().clone();
            assert_eq!(prof.public_v4, Some(obs_v4));
            assert_eq!(prof.public_v6, Some(obs_v6));
            let _ = t4.join();
            let _ = t6.join();
        }

        // 2) 老服务端（无 udp_probe_alt_addr / udp_probe_token，PunchCoord 缺失全部新字段）向后兼容
        let legacy_punch: IncomingSignalMsg = serde_json::from_value(serde_json::json!({
            "type": "punch_coord",
            "session_id": "legacy-sess",
            "role": "client",
            "peer_id": "222333444",
            "peer_public_udp_addr": "198.51.100.12:55555",
            "peer_lan_addrs": ["192.168.1.5:50000"],
            "relay_token": "tok-legacy",
            "relay_addr": "127.0.0.1:21117"
        }))
        .expect("legacy punch_coord must deserialize");
        match legacy_punch {
            IncomingSignalMsg::PunchCoord {
                peer_public_udp_addrs,
                self_public_udp_addr,
                peer_nat_type,
                peer_nat_port_delta,
                ..
            } => {
                assert!(peer_public_udp_addrs.is_empty());
                assert!(self_public_udp_addr.is_none());
                assert!(peer_nat_type.is_none());
                assert!(peer_nat_port_delta.is_none());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn alt_target_matching_primary_skips_alt_probe_and_avoids_cone() {
        let primary_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let primary_addr = primary_udp.local_addr().unwrap();
        let _ = primary_udp.set_read_timeout(Some(Duration::from_millis(300)));

        let packets_seen = Arc::new(AtomicUsize::new(0));
        let packets_seen_bg = Arc::clone(&packets_seen);
        let obs: SocketAddr = "198.51.100.42:45000".parse().unwrap();
        let srv = thread::spawn(move || {
            let mut buf = [0u8; 64];
            for _ in 0..4 {
                match primary_udp.recv_from(&mut buf) {
                    Ok((n, from)) if n >= UDP_PROBE_LEN => {
                        packets_seen_bg.fetch_add(1, Ordering::SeqCst);
                        let mut nonce = [0u8; 8];
                        nonce.copy_from_slice(&buf[14..22]);
                        let _ = primary_udp.send_to(&build_test_rcsa(obs, nonce), from);
                    }
                    _ => break,
                }
            }
        });

        let probe = PersistentUdpProbe::bind_with_options(
            primary_addr,
            "604928235".to_string(),
            None,
            Some(primary_addr),
            None,
            None,
            Vec::new(),
        )
        .expect("bind probe");

        let nat_profile = Mutex::new(NatProfile::default());
        let rtt_ms = Mutex::new(None);
        let stop_flag = AtomicBool::new(false);
        probe.run_initial_probe_round(&nat_profile, &rtt_ms, &stop_flag);
        drop(probe);
        srv.join().unwrap();

        let prof = nat_profile.lock().unwrap().clone();
        assert_eq!(prof.public_v4, Some(obs));
        assert_eq!(
            prof.nat_type,
            NatType::Unknown,
            "alt_target equal to primary must be skipped and never misclassified as Cone"
        );
        assert_eq!(packets_seen.load(Ordering::SeqCst), 1);

        let mapped_v6: SocketAddr = format!("[::ffff:127.0.0.1]:{}", primary_addr.port())
            .parse()
            .unwrap();
        assert_eq!(
            canonicalize_socket_addr(mapped_v6),
            canonicalize_socket_addr(primary_addr)
        );
    }

    #[test]
    fn lightweight_refresh_recent_nonces_4_slot_ring_accepts_delayed_rcsa_and_evicts_oldest() {
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let srv_addr = srv.local_addr().unwrap();
        let _ = srv.set_read_timeout(Some(Duration::from_secs(2)));

        let probe = PersistentUdpProbe::bind(srv_addr).expect("bind probe");
        let nat_profile = Mutex::new(NatProfile::default());

        // 连发 2 次轻量刷新（模拟 ConnectRequest 与 PunchCoord 连续触发）
        probe.send_lightweight_refresh(&nat_profile);
        probe.send_lightweight_refresh(&nat_profile);

        let recv_pkt = || -> ([u8; 8], SocketAddr) {
            let mut buf = [0u8; 64];
            let (n, from) = srv.recv_from(&mut buf).expect("recv RCSP");
            assert!(n >= UDP_PROBE_LEN);
            let mut nonce = [0u8; 8];
            nonce.copy_from_slice(&buf[14..22]);
            (nonce, from)
        };

        let (nonce1, from1) = recv_pkt();
        let (nonce2, _from2) = recv_pkt();
        assert_ne!(nonce1, nonce2);

        // 首条刷新的延迟 RCSA 此时才飞回，仍应被 4 槽环接受并更新 NatProfile
        let obs1: SocketAddr = "198.51.100.77:42001".parse().unwrap();
        srv.send_to(&build_test_rcsa(obs1, nonce1), from1).unwrap();
        thread::sleep(Duration::from_millis(20));
        probe.send_lightweight_refresh(&nat_profile);
        assert_eq!(nat_profile.lock().unwrap().public_v4, Some(obs1));

        // 再连发 3 次（加上第 3 次共发出 nonce3..nonce6，4 槽环满且已淘汰 nonce1、nonce2）
        let (_nonce3, _) = recv_pkt();
        probe.send_lightweight_refresh(&nat_profile);
        let (nonce4, from4) = recv_pkt();
        probe.send_lightweight_refresh(&nat_profile);
        let (_nonce5, _) = recv_pkt();
        probe.send_lightweight_refresh(&nat_profile);
        let (_nonce6, _) = recv_pkt();

        // 已淘汰的 nonce2 必须被拒绝
        let obs_evicted: SocketAddr = "198.51.100.88:42002".parse().unwrap();
        srv.send_to(&build_test_rcsa(obs_evicted, nonce2), from1)
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        probe.send_lightweight_refresh(&nat_profile);
        let (_nonce7, _) = recv_pkt();
        assert_eq!(nat_profile.lock().unwrap().public_v4, Some(obs1));

        // 仍在 4 槽环内的 nonce4 必须被接受
        let obs_kept: SocketAddr = "198.51.100.99:42003".parse().unwrap();
        srv.send_to(&build_test_rcsa(obs_kept, nonce4), from4)
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        probe.send_lightweight_refresh(&nat_profile);
        let (_nonce8, _) = recv_pkt();
        assert_eq!(nat_profile.lock().unwrap().public_v4, Some(obs_kept));
    }

    #[test]
    fn unconnected_dual_stack_probe_reuses_single_port_and_rejects_unlisted_source() {
        let Ok(v6_srv) = UdpSocket::bind("[::1]:0") else {
            return;
        };
        let v6_addr = v6_srv.local_addr().unwrap();
        let _ = v6_srv.set_read_timeout(Some(Duration::from_secs(2)));
        let v4_srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let v4_addr = v4_srv.local_addr().unwrap();
        let _ = v4_srv.set_read_timeout(Some(Duration::from_secs(2)));
        let rogue_srv = UdpSocket::bind("127.0.0.1:0").unwrap();

        let probe = PersistentUdpProbe::bind_with_options(
            v6_addr,
            "604928235".to_string(),
            Some([0x55u8; 16]),
            None,
            None,
            Some(v4_addr),
            Vec::new(),
        )
        .expect("bind dual-stack unconnected probe");

        let nat_profile = Mutex::new(NatProfile::default());
        probe.send_lightweight_refresh(&nat_profile);

        let mut buf = [0u8; 64];
        let (n6, from6) = v6_srv.recv_from(&mut buf).expect("v6 recv");
        assert_eq!(n6, UDP_PROBE_V2_LEN);
        assert_eq!(from6.port(), probe.local_port());
        let nonce6: [u8; 8] = buf[14..22].try_into().unwrap();

        let (n4, from4) = v4_srv.recv_from(&mut buf).expect("v4 recv");
        assert_eq!(n4, UDP_PROBE_V2_LEN);
        assert_eq!(from4.port(), probe.local_port());
        let nonce4: [u8; 8] = buf[14..22].try_into().unwrap();

        // 非白名单来源伪造 RCSA（即使携带正确 nonce6）也必须被严格丢弃
        let rogue_obs: SocketAddr = "198.51.100.250:59999".parse().unwrap();
        let probe_v4_dst = SocketAddr::from(([127, 0, 0, 1], probe.local_port()));
        rogue_srv
            .send_to(&build_test_rcsa(rogue_obs, nonce6), probe_v4_dst)
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        probe.send_lightweight_refresh(&nat_profile);
        assert!(nat_profile.lock().unwrap().public_v6.is_none());
        assert!(nat_profile.lock().unwrap().public_v4.is_none());

        // 合法白名单双栈目标回包均通过同一个未连接双栈 socket 收包更新
        let obs_v4: SocketAddr = "198.51.100.11:41111".parse().unwrap();
        let obs_v6: SocketAddr = "[2001:db8::11]:41111".parse().unwrap();
        v4_srv
            .send_to(&build_test_rcsa(obs_v4, nonce4), from4)
            .unwrap();
        v6_srv
            .send_to(&build_test_rcsa(obs_v6, nonce6), from6)
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        probe.send_lightweight_refresh(&nat_profile);
        let prof = nat_profile.lock().unwrap().clone();
        assert_eq!(prof.public_v4, Some(obs_v4));
        assert_eq!(prof.public_v6, Some(obs_v6));
    }

    #[test]
    fn mock_server_4_sample_and_alt_ip_nat_classification() {
        // 1) ConeVerified & AdmSeq via udp_probe_alt_ip_addr
        for (case_name, alt_ip_obs_str, expected_nat, expected_delta) in [
            (
                "cone_verified",
                "198.51.100.55:45000",
                NatType::ConeVerified,
                Some(0i16),
            ),
            (
                "adm_seq",
                "198.51.100.55:45005",
                NatType::AdmSeq,
                Some(5i16),
            ),
            (
                "adm_random",
                "198.51.100.99:59000",
                NatType::AdmRandom,
                None,
            ),
        ] {
            let primary_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let alt_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let alt_ip_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let _ = primary_udp.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = alt_udp.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = alt_ip_udp.set_read_timeout(Some(Duration::from_secs(2)));

            let p_addr = primary_udp.local_addr().unwrap();
            let a_addr = alt_udp.local_addr().unwrap();
            let aip_addr = alt_ip_udp.local_addr().unwrap();

            let obs_p: SocketAddr = "198.51.100.55:45000".parse().unwrap();
            let obs_aip: SocketAddr = alt_ip_obs_str.parse().unwrap();

            let tp = thread::spawn(move || {
                let mut buf = [0u8; 64];
                if let Ok((n, from)) = primary_udp.recv_from(&mut buf) {
                    if n >= UDP_PROBE_LEN {
                        let nonce: [u8; 8] = buf[14..22].try_into().unwrap();
                        let _ = primary_udp.send_to(&build_test_rcsa(obs_p, nonce), from);
                    }
                }
            });
            let ta = thread::spawn(move || {
                let mut buf = [0u8; 64];
                if let Ok((n, from)) = alt_udp.recv_from(&mut buf) {
                    if n >= UDP_PROBE_LEN {
                        let nonce: [u8; 8] = buf[14..22].try_into().unwrap();
                        let _ = alt_udp.send_to(&build_test_rcsa(obs_p, nonce), from);
                    }
                }
            });
            let taip = thread::spawn(move || {
                let mut buf = [0u8; 64];
                if let Ok((n, from)) = alt_ip_udp.recv_from(&mut buf) {
                    if n >= UDP_PROBE_LEN {
                        let nonce: [u8; 8] = buf[14..22].try_into().unwrap();
                        let _ = alt_ip_udp.send_to(&build_test_rcsa(obs_aip, nonce), from);
                    }
                }
            });

            let probe = PersistentUdpProbe::bind_with_options(
                p_addr,
                "604928235".to_string(),
                Some([0x11u8; 16]),
                Some(a_addr),
                Some(aip_addr),
                None,
                Vec::new(),
            )
            .expect("bind probe");
            let nat_profile = Mutex::new(NatProfile::default());
            let rtt_ms = Mutex::new(None);
            let stop_flag = AtomicBool::new(false);
            probe.run_initial_probe_round(&nat_profile, &rtt_ms, &stop_flag);
            tp.join().unwrap();
            ta.join().unwrap();
            taip.join().unwrap();

            let prof = nat_profile.lock().unwrap().clone();
            assert_eq!(prof.nat_type, expected_nat, "case {case_name}");
            assert_eq!(prof.port_delta, expected_delta, "case {case_name}");
        }

        // 2) 4 样本补采 (m3, m4)：m1->m2 为 +3，若临时 socket m3->m4 为 +17 则修正为 ApdmRandom
        let primary_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let alt_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let _ = primary_udp.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = alt_udp.set_read_timeout(Some(Duration::from_secs(2)));
        let p_addr = primary_udp.local_addr().unwrap();
        let a_addr = alt_udp.local_addr().unwrap();

        let tp = thread::spawn(move || {
            let mut buf = [0u8; 64];
            for idx in 0..2 {
                if let Ok((n, from)) = primary_udp.recv_from(&mut buf) {
                    if n >= UDP_PROBE_LEN {
                        let nonce: [u8; 8] = buf[14..22].try_into().unwrap();
                        let obs: SocketAddr = if idx == 0 {
                            "198.51.100.55:50000".parse().unwrap()
                        } else {
                            "198.51.100.55:52000".parse().unwrap()
                        };
                        let _ = primary_udp.send_to(&build_test_rcsa(obs, nonce), from);
                    }
                }
            }
        });
        let ta = thread::spawn(move || {
            let mut buf = [0u8; 64];
            for idx in 0..2 {
                if let Ok((n, from)) = alt_udp.recv_from(&mut buf) {
                    if n >= UDP_PROBE_LEN {
                        let nonce: [u8; 8] = buf[14..22].try_into().unwrap();
                        let obs: SocketAddr = if idx == 0 {
                            "198.51.100.55:50003".parse().unwrap()
                        } else {
                            "198.51.100.55:52017".parse().unwrap()
                        };
                        let _ = alt_udp.send_to(&build_test_rcsa(obs, nonce), from);
                    }
                }
            }
        });

        let probe = PersistentUdpProbe::bind_with_options(
            p_addr,
            "604928235".to_string(),
            Some([0x22u8; 16]),
            Some(a_addr),
            None,
            None,
            Vec::new(),
        )
        .expect("bind 4-sample probe");
        let nat_profile = Mutex::new(NatProfile::default());
        let rtt_ms = Mutex::new(None);
        let stop_flag = AtomicBool::new(false);
        probe.run_initial_probe_round(&nat_profile, &rtt_ms, &stop_flag);
        tp.join().unwrap();
        ta.join().unwrap();

        let prof = nat_profile.lock().unwrap().clone();
        assert_eq!(prof.nat_type, NatType::ApdmRandom);
        assert_eq!(prof.port_delta, None);
        assert_eq!(prof.port_range, Some(PortRangeHint::IanaDynamic));

        // 3) 全超时 -> UdpBlocked
        let dead_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead_udp.local_addr().unwrap();
        drop(dead_udp);
        let blocked_probe = PersistentUdpProbe::bind(dead_addr).expect("bind blocked probe");
        let blocked_profile = Mutex::new(NatProfile::default());
        let blocked_rtt = Mutex::new(None);
        blocked_probe.run_initial_probe_round(&blocked_profile, &blocked_rtt, &stop_flag);
        assert_eq!(
            blocked_profile.lock().unwrap().nat_type,
            NatType::UdpBlocked
        );
    }

    #[test]
    fn external_reachability_self_check_uses_private_rcsp_and_detects_double_nat() {
        let srv_ok = UdpSocket::bind("127.0.0.1:0").unwrap();
        let srv_ok_addr = srv_ok.local_addr().unwrap();
        let _ = srv_ok.set_read_timeout(Some(Duration::from_millis(20)));
        let stop_ok = Arc::new(AtomicBool::new(false));
        let stop_ok_bg = Arc::clone(&stop_ok);
        let jh_ok = thread::spawn(move || {
            let mut buf = [0u8; 128];
            while !stop_ok_bg.load(Ordering::Acquire) {
                if let Ok((n, from)) = srv_ok.recv_from(&mut buf) {
                    if n >= UDP_PROBE_V2_LEN && &buf[0..4] == b"RCSP" {
                        let nonce: [u8; 8] = buf[14..22].try_into().unwrap();
                        let obs: SocketAddr = "9.9.9.10:54321".parse().unwrap();
                        let _ = srv_ok.send_to(&build_test_rcsa(obs, nonce), from);
                    }
                }
            }
        });

        let probe = PersistentUdpProbe::bind_with_options(
            srv_ok_addr,
            "604928235".to_string(),
            Some([0x33u8; 16]),
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("bind self-check probe");
        let nat_profile = Mutex::new(NatProfile::default());
        let stop_flag = AtomicBool::new(false);

        // 1) RCSA 观测公网 IP 与映射公网 IP 一致 => Reachable
        assert_eq!(
            probe.verify_external_mapping_reachability(
                "9.9.9.10:49000".parse().unwrap(),
                &nat_profile,
                &stop_flag,
            ),
            ExternalMappingCheck::Reachable
        );

        // 2) 双层 NAT 假公网（映射声称 8.8.8.8，自有 RCSP 实际观测 9.9.9.10）=> Unreachable
        let fake_res = probe.verify_external_mapping_reachability(
            "8.8.8.8:49000".parse().unwrap(),
            &nat_profile,
            &stop_flag,
        );
        assert!(
            matches!(fake_res, ExternalMappingCheck::Unreachable(ref r) if r.contains("双层 NAT") || r.contains("不一致")),
            "expected double-NAT fake-public rejection, got {fake_res:?}"
        );
        stop_ok.store(true, Ordering::Release);
        jh_ok.join().unwrap();

        // 3) 自有 RCSP 超时无响应 => Unreachable（避开假公网）
        let dead_srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead_srv.local_addr().unwrap();
        drop(dead_srv);
        let dead_probe = PersistentUdpProbe::bind_with_options(
            dead_addr,
            "604928235".to_string(),
            Some([0x33u8; 16]),
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("bind dead self-check probe");
        let timeout_res = dead_probe.verify_external_mapping_reachability(
            "9.9.9.10:49000".parse().unwrap(),
            &nat_profile,
            &stop_flag,
        );
        assert!(
            matches!(timeout_res, ExternalMappingCheck::Unreachable(ref r) if r.contains("超时")),
            "expected timeout Unreachable, got {timeout_res:?}"
        );
    }

    #[test]
    fn reprobe_snapshot_and_split_include_public_v4_v6_and_lan_candidates() {
        let mixed = vec![
            "192.168.1.50:51000".to_string(),
            "198.51.100.20:51000".to_string(),
            "[fd00::5]:51000".to_string(),
            "[2001:db8::20]:51000".to_string(),
            "198.51.100.20:51000".to_string(),
            "bad-addr".to_string(),
        ];
        let (pubs, lans) = split_public_and_lan_addrs(&mixed, &["203.0.113.9:52000".to_string()]);
        assert_eq!(
            pubs,
            vec![
                "198.51.100.20:51000".to_string(),
                "[2001:db8::20]:51000".to_string()
            ]
        );
        assert_eq!(
            lans,
            vec![
                "192.168.1.50:51000".to_string(),
                "[fd00::5]:51000".to_string()
            ]
        );

        let lan_only = vec!["192.168.1.50:51000".to_string()];
        let (pubs_fb, lans_fb) =
            split_public_and_lan_addrs(&lan_only, &["203.0.113.9:52000".to_string()]);
        assert_eq!(pubs_fb, vec!["203.0.113.9:52000".to_string()]);
        assert_eq!(lans_fb, vec!["192.168.1.50:51000".to_string()]);

        let handle = SignalClientHandle::spawn(
            ServerConfig::default(),
            "reprobe-host".to_string(),
            vec!["192.168.1.50".to_string()],
        );
        handle.shared.local_udp_port.store(51234, Ordering::Release);
        {
            let mut np = handle.shared.nat_profile.lock().unwrap();
            np.public_v4 = Some("198.51.100.77:51234".parse().unwrap());
            np.public_v6 = Some("[2001:db8::77]:51234".parse().unwrap());
            np.nat_type = NatType::ConeVerified;
        }
        let (port, addrs, nat_type, _delta, _range) = handle.snapshot_p2p_reprobe_info();
        assert_eq!(port, Some(51234));
        assert_eq!(nat_type, NatType::ConeVerified);
        assert!(addrs.contains(&"198.51.100.77:51234".to_string()));
        assert!(addrs.contains(&"[2001:db8::77]:51234".to_string()));
        assert!(addrs.contains(&"192.168.1.50:51234".to_string()));
    }

    #[test]
    fn valid_rcsa_recovers_from_udp_blocked_and_probe_timeouts_are_relaxed() {
        assert_eq!(
            UDP_PROBE_RETRY_WAITS,
            [
                Duration::from_millis(250),
                Duration::from_millis(450),
                Duration::from_millis(700),
            ]
        );
        assert_eq!(
            SELF_CHECK_RETRY_WAITS,
            [Duration::from_millis(250), Duration::from_millis(450)]
        );

        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let srv_addr = srv.local_addr().unwrap();
        let _ = srv.set_read_timeout(Some(Duration::from_secs(2)));

        let probe = PersistentUdpProbe::bind(srv_addr).expect("bind probe");
        let nat_profile = Mutex::new(NatProfile {
            nat_type: NatType::UdpBlocked,
            ..NatProfile::default()
        });

        // 1) 发送轻量刷新探测；此时尚未收到 RCSA，仍为 UdpBlocked
        assert!(!probe.send_lightweight_refresh(&nat_profile));
        assert_eq!(nat_profile.lock().unwrap().nat_type, NatType::UdpBlocked);

        let mut buf = [0u8; 64];
        let (n, from) = srv.recv_from(&mut buf).expect("recv RCSP");
        assert!(n >= UDP_PROBE_LEN);
        let nonce: [u8; 8] = buf[14..22].try_into().unwrap();

        // 2) 回包有效 RCSA -> 再次轻量刷新收包后必须立即脱离 UdpBlocked 降级为 ConeUnverified
        let obs: SocketAddr = "198.51.100.66:43210".parse().unwrap();
        srv.send_to(&build_test_rcsa(obs, nonce), from).unwrap();
        thread::sleep(Duration::from_millis(20));

        assert!(
            probe.send_lightweight_refresh(&nat_profile),
            "valid RCSA while cached UdpBlocked must report recovery"
        );
        let prof = nat_profile.lock().unwrap().clone();
        assert_eq!(prof.nat_type, NatType::ConeUnverified);
        assert_eq!(prof.public_v4, Some(obs));
    }
}
