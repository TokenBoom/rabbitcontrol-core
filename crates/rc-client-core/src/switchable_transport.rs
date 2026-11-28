//! 运行期无损传输切换封装（[`SwitchableTransport`]）与双向迟滞路径监控（[`RuntimePathMonitor`]）。
//!
//! 职责边界：
//! - 完全位于 `rc-session` 下层、实现 [`rc_net::Transport`]，**绝不触碰** `rc-sched` / `rc-capture` /
//!   `rc-encode` / `rc-decode` / `rc-render` 媒体热路径；
//! - **向后兼容老端**：自动通过非侵入式 `RCSW` 能力探测协商（使用 `Datagram` 握手指引 + `Reliable`
//!   激活确认），老版本 `ClientSession` / `HostSession` 收到未知 `Datagram` 会直接丢弃，不激活帧封装、
//!   保持零开销纯透传；
//! - **Make-Before-Break 无损热切**：候选传输必须先完成全量建连与等效安全校验（`require_mtls == true` 时
//!   严禁降级，必须已验证双向 mTLS 且携带对端证书指纹），再通过至少 3 个 RTT `HealthPing/HealthPong`
//!   探活后触发 `SwitchPrepare -> SwitchDrainAck -> SwitchCommit` 有序排空与原子切换，随后保留
//!   `2s` 旧通道排空窗口；任一阶段超时（默认 `1.5s`）或候选通道断连立即中止并回滚至原传输，
//!   原传输毫发无损继续运行。
//! - **严格保序 / 零丢包 / 零重复**：分别对 `send_reliable` 与 `send_reliable_urgent` 两条流维护单调
//!   `seq: u64`（保留控制流与输入流独立优先级语义）；切换窗口内新出站帧入有序内存缓冲，提交瞬间
//!   顺序刷入新通道，接收端按单调 `rx_seq` 严格去重。

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngCore;
use rc_net::{NetEvent, NetStats, Role, Transport};
use rc_types::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::nat::{NatType, PortRangeHint};

/// `SwitchableTransport` 线协议魔数（`RCSW`：`[0x52, 0x43, 0x53, 0x57]`）。
const SWITCH_MAGIC: &[u8; 4] = b"RCSW";
/// 线协议版本号。
const SWITCH_VERSION: u8 = 1;

const KIND_CAP_REQ: u8 = 0x01;
const KIND_CAP_ACK: u8 = 0x02;
const KIND_CAP_ENABLE: u8 = 0x03;
const KIND_DATA_RELIABLE: u8 = 0x10;
const KIND_DATA_URGENT: u8 = 0x11;
const KIND_HEALTH_PING: u8 = 0x20;
const KIND_HEALTH_PONG: u8 = 0x21;
const KIND_SWITCH_PREPARE: u8 = 0x22;
const KIND_SWITCH_DRAIN_ACK: u8 = 0x23;
const KIND_SWITCH_COMMIT: u8 = 0x24;
const KIND_SWITCH_URGENT_MARK: u8 = 0x25;
const KIND_TUNNEL_CONTROL: u8 = 0x30;

/// 能力探测消息最小长度（magic 4B + ver 1B + kind 1B + nonce 8B = 14B）。
const CAP_FRAME_LEN: usize = 14;
/// 数据帧头长度（magic 4B + ver 1B + kind 1B + seq 8B = 14B）。
const DATA_HEADER_LEN: usize = 14;
/// 探活帧长度（magic 4B + ver 1B + kind 1B + switch_id 8B + idx 4B + nonce 8B = 26B）。
const HEALTH_FRAME_LEN: usize = 26;
/// `SwitchPrepare` 长度（magic 4B + ver 1B + kind 1B + switch_id 8B + rel_seq 8B + urg_seq 8B = 30B）。
const PREPARE_FRAME_LEN: usize = 30;
/// `SwitchDrainAck` 长度（magic 4B + ver 1B + kind 1B + switch_id 8B + ack_rel 8B + ack_urg 8B + peer_rel 8B + peer_urg 8B = 46B）。
const DRAIN_ACK_FRAME_LEN: usize = 46;
/// `SwitchCommit` 长度（magic 4B + ver 1B + kind 1B + switch_id 8B = 14B）。
const COMMIT_FRAME_LEN: usize = 14;
/// `SwitchUrgentMark` 长度（magic 4B + ver 1B + kind 1B + switch_id 8B + urg_seq 8B = 22B）。
const URGENT_MARK_FRAME_LEN: usize = 22;

/// `HealthPing` 需要通过的最小有效 RTT 样本数量。
pub const DEFAULT_HEALTH_PING_COUNT: u32 = 3;
/// 单阶段热切超时上限（含探活 + 排空 + 提交，超时立即中止并保留原传输）。
pub const DEFAULT_SWITCH_STAGE_TIMEOUT: Duration = Duration::from_millis(1_500);
/// 提交新传输后旧传输保留的排空宽限时长（2s）。
pub const DEFAULT_OLD_DRAIN_GRACE: Duration = Duration::from_secs(2);
/// 单次 `HealthPing` 未应答判定丢包的超时门槛（避免正常高 RTT > 200ms 在 5s 保持期内被后续 ping 覆盖误判丢包）。
const DEFAULT_HEALTH_PING_LOSS_TIMEOUT: Duration = Duration::from_millis(1_000);
/// 能力协商期重复发送 `CapReq` 数据报的最大间隔。
const CAP_PROBE_RETRY_INTERVAL: Duration = Duration::from_millis(25);
/// 能力协商总探测窗口（超时后自动退化为仅按需被动应答，不浪费 CPU）。
const CAP_PROBE_WINDOW: Duration = Duration::from_secs(3);

/// 当前底层激活路径类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportPathKind {
    /// 局域网直连 QUIC。
    #[default]
    Lan,
    /// 局域网双向 mTLS QUIC。
    MtlsLan,
    /// 公网 UDP 打洞 P2P QUIC。
    P2p,
    /// TCP `:21117` 中继（含外层 mTLS 与可选内层 E2EE）。
    Relay,
}

impl TransportPathKind {
    /// 返回面向 UI / HUD 展示的标准路径名称。
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Lan => "UDP LAN",
            Self::MtlsLan => "UDP LAN (mTLS)",
            Self::P2p => "UDP P2P",
            Self::Relay => "TCP Relay",
        }
    }

    /// 返回渲染/传输状态后缀标签。
    pub const fn backend_suffix(self) -> Option<&'static str> {
        match self {
            Self::Lan | Self::MtlsLan => None,
            Self::P2p => Some("(P2P 直连)"),
            Self::Relay => Some("(中继)"),
        }
    }

    /// 返回被控端连接日志与状态推送使用的可读标识。
    pub fn host_label(self, peer_id: &str) -> String {
        match self {
            Self::Lan => format!("设备 {peer_id} (局域网直连)"),
            Self::MtlsLan => format!("设备 {peer_id} (局域网 mTLS)"),
            Self::P2p => format!("设备 {peer_id} (P2P 直连)"),
            Self::Relay => format!("设备 {peer_id} (中继)"),
        }
    }

    /// 是否属于直连路径（LAN / mTLS LAN / UDP P2P）。
    pub const fn is_direct(self) -> bool {
        !matches!(self, Self::Relay)
    }
}

/// 路径成功热切后上抛给会话桥与 UI 的变更事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchPathEvent {
    /// 切换后的新路径类型。
    pub kind: TransportPathKind,
    /// 新路径 HUD 标签。
    pub label: &'static str,
    /// 新路径状态后缀。
    pub backend_suffix: Option<&'static str>,
    /// 新路径是否处于双向 mTLS 加密保护下。
    pub mtls_active: bool,
    /// 对端设备证书 SHA-256 指纹（如有）。
    pub peer_cert_fingerprint: Option<String>,
    /// 本次热切前探测到的候选 RTT 均值（微秒）。
    pub rtt_us: u32,
}

/// 经 [`SwitchableTransport`] 加密隧道传递的运行期控制消息（供 `Relay <-> P2P` 协调候选与 Token）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SwitchControlMsg {
    /// 控制端通知被控端使用初始 `relay_token` 拨号中继以准备 `P2P -> Relay` 无损降级。
    UseInitialRelay,
    /// 控制端已向信令服务器申请新的 `RelayReady`，通知被控端从入站队列消费同 `session_id` 中继通道并准备热切。
    RelayAllocReady {
        /// 新分配的中继会话 ID。
        session_id: String,
    },
    /// 发起 `Relay -> P2P` 后台复探候选交换（由当前已认证通道携带，防伪造）。
    P2pReprobeOffer {
        /// 本次复探会话 ID。
        probe_id: String,
        /// 发起方绑定的本地 UDP 打洞端口。
        local_udp_port: u16,
        /// 发起方候选地址列表。
        addrs: Vec<String>,
        /// 发起方当前 NAT 类型。
        nat_type: NatType,
        /// 发起方端口步长（如有）。
        nat_port_delta: Option<i16>,
        /// 发起方端口范围提示（如有）。
        nat_port_range: Option<PortRangeHint>,
        /// 本次复探共享 `RCP2 v2` HMAC 密钥（32 位十六进制）。
        punch_secret: String,
    },
    /// 被控端响应 `Relay -> P2P` 复探候选。
    P2pReprobeAnswer {
        /// 对应复探会话 ID。
        probe_id: String,
        /// 被控端绑定的本地 UDP 打洞端口。
        local_udp_port: u16,
        /// 被控端候选地址列表。
        addrs: Vec<String>,
        /// 被控端当前 NAT 类型。
        nat_type: NatType,
        /// 被控端端口步长（如有）。
        nat_port_delta: Option<i16>,
        /// 被控端端口范围提示（如有）。
        nat_port_range: Option<PortRangeHint>,
    },
}

/// 提交给 [`SwitchableTransport`] 的候选新传输封装。
pub struct CandidateTransport {
    /// 已完成传输握手（含 QUIC 或 TCP+E2EE）的通道实例。
    pub transport: Box<dyn Transport>,
    /// 候选路径类型。
    pub kind: TransportPathKind,
    /// 该候选通道是否已完成等同于会话加密策略的双向 mTLS + 对端身份校验。
    pub mtls_verified: bool,
    /// 对端设备证书 SHA-256 指纹（当 `mtls_verified == true` 时应提供）。
    pub peer_cert_fingerprint: Option<String>,
}

struct PendingCandidateRequest {
    candidate: CandidateTransport,
    as_initiator: bool,
    stage_timeout: Duration,
    min_health_hold: Duration,
    max_rtt_us: Option<u32>,
    max_loss_rate: Option<f32>,
}

struct SwitchSharedState {
    active_kind: Mutex<TransportPathKind>,
    switch_capable: AtomicBool,
    switch_inflight: AtomicBool,
    pending_candidate: Mutex<Option<PendingCandidateRequest>>,
    outbound_control: Mutex<VecDeque<Vec<u8>>>,
    inbound_control: Mutex<VecDeque<Vec<u8>>>,
    path_events: Mutex<VecDeque<SwitchPathEvent>>,
    last_rx_epoch_ms: AtomicU64,
    switches_committed: AtomicU64,
    switches_aborted: AtomicU64,
    candidate_rejected_security: AtomicU64,
    candidate_rejected_busy: AtomicU64,
    anchor: Instant,
}

impl SwitchSharedState {
    fn new(initial_kind: TransportPathKind) -> Self {
        Self {
            active_kind: Mutex::new(initial_kind),
            switch_capable: AtomicBool::new(false),
            switch_inflight: AtomicBool::new(false),
            pending_candidate: Mutex::new(None),
            outbound_control: Mutex::new(VecDeque::new()),
            inbound_control: Mutex::new(VecDeque::new()),
            path_events: Mutex::new(VecDeque::new()),
            last_rx_epoch_ms: AtomicU64::new(0),
            switches_committed: AtomicU64::new(0),
            switches_aborted: AtomicU64::new(0),
            candidate_rejected_security: AtomicU64::new(0),
            candidate_rejected_busy: AtomicU64::new(0),
            anchor: Instant::now(),
        }
    }

    fn touch_rx(&self) {
        let ms = Instant::now()
            .saturating_duration_since(self.anchor)
            .as_millis() as u64;
        self.last_rx_epoch_ms.store(ms, Ordering::Release);
    }

    fn silence_duration(&self) -> Duration {
        let last = self.last_rx_epoch_ms.load(Ordering::Acquire);
        let now_ms = self.anchor.elapsed().as_millis() as u64;
        Duration::from_millis(now_ms.saturating_sub(last))
    }
}

/// [`SwitchableTransport`] 的跨线程控制句柄（供会话桥提交候选、收发隧道控制帧与观测状态）。
#[derive(Clone)]
pub struct SwitchHandle {
    shared: Arc<SwitchSharedState>,
    require_mtls: bool,
}

impl SwitchHandle {
    /// 返回当前是否已完成热切能力协商（老端兼容性门禁）。
    pub fn is_switch_capable(&self) -> bool {
        self.shared.switch_capable.load(Ordering::Acquire)
    }

    /// 返回当前生效传输路径类型。
    pub fn active_kind(&self) -> TransportPathKind {
        *self
            .shared
            .active_kind
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// 以发起方身份提交一条已建连（且按需通过 mTLS）的候选传输并启动 Make-Before-Break 热切。
    pub fn initiate_switch(&self, candidate: CandidateTransport) -> Result<()> {
        self.submit_candidate(candidate, true, DEFAULT_SWITCH_STAGE_TIMEOUT)
    }

    /// 以响应方身份挂载一条待接管的候选传输（等待对端 `HealthPing` 与 `SwitchPrepare`）。
    pub fn accept_switch_candidate(&self, candidate: CandidateTransport) -> Result<()> {
        self.submit_candidate(candidate, false, DEFAULT_SWITCH_STAGE_TIMEOUT)
    }

    /// 带自定义超时的候选提交接口（便于单元/故障注入测试快速验证超时回滚）。
    pub fn submit_candidate(
        &self,
        candidate: CandidateTransport,
        as_initiator: bool,
        stage_timeout: Duration,
    ) -> Result<()> {
        self.submit_candidate_with_hold(
            candidate,
            as_initiator,
            stage_timeout,
            Duration::ZERO,
            None,
            None,
        )
    }

    /// 带健康连续保持期与 RTT/丢包门槛的候选提交接口（用于 `Relay -> P2P` 5s 连续达标校验）。
    pub fn submit_candidate_with_hold(
        &self,
        candidate: CandidateTransport,
        as_initiator: bool,
        stage_timeout: Duration,
        min_health_hold: Duration,
        max_rtt_us: Option<u32>,
        max_loss_rate: Option<f32>,
    ) -> Result<()> {
        if self.require_mtls
            && (!candidate.mtls_verified || candidate.peer_cert_fingerprint.is_none())
        {
            self.shared
                .candidate_rejected_security
                .fetch_add(1, Ordering::AcqRel);
            return Err(Error::Network(
                "安全策略开启 mTLS，拒绝未通过双向 mTLS 与证书指纹校验的候选传输".to_string(),
            ));
        }
        let mut slot = self
            .shared
            .pending_candidate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if slot.is_some() || self.shared.switch_inflight.load(Ordering::Acquire) {
            self.shared
                .candidate_rejected_busy
                .fetch_add(1, Ordering::AcqRel);
            return Err(Error::Network(
                "已有热切候选在途或等待消费，拒绝并发覆盖".to_string(),
            ));
        }
        self.shared.switch_inflight.store(true, Ordering::Release);
        *slot = Some(PendingCandidateRequest {
            candidate,
            as_initiator,
            stage_timeout: stage_timeout.max(Duration::from_millis(20)),
            min_health_hold,
            max_rtt_us,
            max_loss_rate,
        });
        Ok(())
    }

    /// 排空已就绪的路径切换通知事件（供会话桥同步更新 HUD 与 UI 状态）。
    pub fn drain_path_events(&self) -> Vec<SwitchPathEvent> {
        self.shared
            .path_events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect()
    }

    /// 排队发送一条仅在 [`SwitchableTransport`] 之间消费的隧道控制消息（受当前激活加密通道保护）。
    pub fn send_control_msg(&self, msg: &SwitchControlMsg) -> Result<()> {
        let bytes = serde_json::to_vec(msg)
            .map_err(|e| Error::Network(format!("序列化 SwitchControlMsg 失败: {e}")))?;
        let mut q = self
            .shared
            .outbound_control
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if q.len() >= 64 {
            q.pop_front();
        }
        q.push_back(bytes);
        Ok(())
    }

    /// 排空对端发来的隧道控制消息。
    pub fn drain_control_msgs(&self) -> Vec<SwitchControlMsg> {
        let raw: Vec<Vec<u8>> = self
            .shared
            .inbound_control
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        raw.into_iter()
            .filter_map(|b| serde_json::from_slice::<SwitchControlMsg>(&b).ok())
            .collect()
    }

    /// 返回自上次收到任意对端有效数据包以来的静默时间（用于 2s 静默降级判定）。
    pub fn rx_silence(&self) -> Duration {
        self.shared.silence_duration()
    }

    /// 返回当前累计成功提交的热切次数（诊断/单测观测）。
    pub fn switches_committed(&self) -> u64 {
        self.shared.switches_committed.load(Ordering::Acquire)
    }

    /// 返回当前累计中止回滚的热切次数（诊断/单测观测）。
    pub fn switches_aborted(&self) -> u64 {
        self.shared.switches_aborted.load(Ordering::Acquire)
    }

    /// 返回因安全策略（缺少 mTLS / 指纹）被拒收的候选次数。
    pub fn candidate_rejected_security(&self) -> u64 {
        self.shared
            .candidate_rejected_security
            .load(Ordering::Acquire)
    }

    /// 返回当前是否已有候选在待消费或热切状态机在途。
    pub fn is_switch_inflight(&self) -> bool {
        self.shared.switch_inflight.load(Ordering::Acquire)
    }

    /// 返回因已有候选在途而被拒绝覆盖的次数（防并发复探覆盖）。
    pub fn candidate_rejected_busy(&self) -> u64 {
        self.shared.candidate_rejected_busy.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapState {
    /// 尚未确认对端能力：发送端保持零包裹透传，通过 Datagram 探测并兼容被动应答。
    Pending,
    /// 已收到对端合法 `CapReq`/`CapAck`/`CapEnable`：双端启用 `RCSW` 序列号帧包裹。
    Capable,
    /// 已收到对端原始非 `RCSW` 控制帧且未收到能力标识：对端为老客户端/老服务端，锁定纯透传模式。
    Legacy,
}

#[derive(Debug, Clone)]
enum SwitchState {
    Idle,
    /// 候选已挂载：发起方发送 3 次 `HealthPing` 并等待 `HealthPong`；响应方回复 `HealthPong` 与等待 `SwitchPrepare`。
    HealthProbing {
        switch_id: u64,
        candidate_kind: TransportPathKind,
        candidate_mtls: bool,
        candidate_fp: Option<String>,
        as_initiator: bool,
        pings_sent: u32,
        pongs_received: u32,
        last_ping_sent_at: Option<Instant>,
        inflight_pings: HashMap<u32, (u64, Instant)>,
        rtts_us: Vec<u32>,
        probing_started_at: Instant,
        min_health_hold: Duration,
        max_rtt_us: Option<u32>,
        max_loss_rate: Option<f32>,
        deadline: Instant,
        stage_timeout: Duration,
    },
    /// 发起方已暂停新出站可靠帧并在旧链路上发出 `SwitchPrepare`，等待旧链路余量排空及对端新链 `SwitchDrainAck`。
    InitiatorDraining {
        switch_id: u64,
        candidate_kind: TransportPathKind,
        candidate_mtls: bool,
        candidate_fp: Option<String>,
        avg_rtt_us: u32,
        drain_ack_received: bool,
        peer_last_rel_seq: u64,
        peer_last_urg_seq: u64,
        deadline: Instant,
    },
    /// 响应方已在旧链路上收到 `SwitchPrepare`，排空至 `(peer_last_rel_seq, peer_last_urg_seq)` 后经新链回 `SwitchDrainAck` 并等待 `SwitchCommit`。
    ResponderDraining {
        switch_id: u64,
        candidate_kind: TransportPathKind,
        candidate_mtls: bool,
        candidate_fp: Option<String>,
        avg_rtt_us: u32,
        peer_last_rel_seq: u64,
        peer_last_urg_seq: u64,
        drain_ack_sent: bool,
        deadline: Instant,
    },
}

enum ParsedSwFrame<'a> {
    CapReq {
        nonce: u64,
    },
    CapAck {
        nonce: u64,
    },
    CapEnable {
        _nonce: u64,
    },
    DataReliable {
        seq: u64,
        payload: &'a [u8],
    },
    DataUrgent {
        seq: u64,
        payload: &'a [u8],
    },
    HealthPing {
        switch_id: u64,
        idx: u32,
        nonce: u64,
    },
    HealthPong {
        switch_id: u64,
        idx: u32,
        nonce: u64,
    },
    SwitchPrepare {
        switch_id: u64,
        last_rel_seq: u64,
        last_urg_seq: u64,
    },
    SwitchDrainAck {
        switch_id: u64,
        _ack_rel_seq: u64,
        _ack_urg_seq: u64,
        peer_last_rel_seq: u64,
        peer_last_urg_seq: u64,
    },
    SwitchCommit {
        switch_id: u64,
    },
    SwitchUrgentMark {
        _switch_id: u64,
        _last_urg_seq: u64,
    },
    TunnelControl {
        payload: &'a [u8],
    },
}

fn encode_cap_frame(kind: u8, nonce: u64) -> [u8; CAP_FRAME_LEN] {
    let mut out = [0u8; CAP_FRAME_LEN];
    out[0..4].copy_from_slice(SWITCH_MAGIC);
    out[4] = SWITCH_VERSION;
    out[5] = kind;
    out[6..14].copy_from_slice(&nonce.to_be_bytes());
    out
}

fn encode_data_frame(kind: u8, seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_HEADER_LEN + payload.len());
    out.extend_from_slice(SWITCH_MAGIC);
    out.push(SWITCH_VERSION);
    out.push(kind);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn encode_tunnel_control(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + payload.len());
    out.extend_from_slice(SWITCH_MAGIC);
    out.push(SWITCH_VERSION);
    out.push(KIND_TUNNEL_CONTROL);
    out.extend_from_slice(payload);
    out
}

fn encode_health_frame(kind: u8, switch_id: u64, idx: u32, nonce: u64) -> [u8; HEALTH_FRAME_LEN] {
    let mut out = [0u8; HEALTH_FRAME_LEN];
    out[0..4].copy_from_slice(SWITCH_MAGIC);
    out[4] = SWITCH_VERSION;
    out[5] = kind;
    out[6..14].copy_from_slice(&switch_id.to_be_bytes());
    out[14..18].copy_from_slice(&idx.to_be_bytes());
    out[18..26].copy_from_slice(&nonce.to_be_bytes());
    out
}

fn encode_prepare_frame(switch_id: u64, last_rel: u64, last_urg: u64) -> [u8; PREPARE_FRAME_LEN] {
    let mut out = [0u8; PREPARE_FRAME_LEN];
    out[0..4].copy_from_slice(SWITCH_MAGIC);
    out[4] = SWITCH_VERSION;
    out[5] = KIND_SWITCH_PREPARE;
    out[6..14].copy_from_slice(&switch_id.to_be_bytes());
    out[14..22].copy_from_slice(&last_rel.to_be_bytes());
    out[22..30].copy_from_slice(&last_urg.to_be_bytes());
    out
}

fn encode_urgent_mark_frame(switch_id: u64, last_urg: u64) -> [u8; URGENT_MARK_FRAME_LEN] {
    let mut out = [0u8; URGENT_MARK_FRAME_LEN];
    out[0..4].copy_from_slice(SWITCH_MAGIC);
    out[4] = SWITCH_VERSION;
    out[5] = KIND_SWITCH_URGENT_MARK;
    out[6..14].copy_from_slice(&switch_id.to_be_bytes());
    out[14..22].copy_from_slice(&last_urg.to_be_bytes());
    out
}

fn encode_drain_ack_frame(
    switch_id: u64,
    ack_rel: u64,
    ack_urg: u64,
    peer_rel: u64,
    peer_urg: u64,
) -> [u8; DRAIN_ACK_FRAME_LEN] {
    let mut out = [0u8; DRAIN_ACK_FRAME_LEN];
    out[0..4].copy_from_slice(SWITCH_MAGIC);
    out[4] = SWITCH_VERSION;
    out[5] = KIND_SWITCH_DRAIN_ACK;
    out[6..14].copy_from_slice(&switch_id.to_be_bytes());
    out[14..22].copy_from_slice(&ack_rel.to_be_bytes());
    out[22..30].copy_from_slice(&ack_urg.to_be_bytes());
    out[30..38].copy_from_slice(&peer_rel.to_be_bytes());
    out[38..46].copy_from_slice(&peer_urg.to_be_bytes());
    out
}

fn encode_commit_frame(switch_id: u64) -> [u8; COMMIT_FRAME_LEN] {
    let mut out = [0u8; COMMIT_FRAME_LEN];
    out[0..4].copy_from_slice(SWITCH_MAGIC);
    out[4] = SWITCH_VERSION;
    out[5] = KIND_SWITCH_COMMIT;
    out[6..14].copy_from_slice(&switch_id.to_be_bytes());
    out
}

fn parse_sw_frame(buf: &[u8]) -> Option<ParsedSwFrame<'_>> {
    if buf.len() < 6 || &buf[0..4] != SWITCH_MAGIC || buf[4] != SWITCH_VERSION {
        return None;
    }
    let kind = buf[5];
    match kind {
        KIND_CAP_REQ if buf.len() == CAP_FRAME_LEN => Some(ParsedSwFrame::CapReq {
            nonce: u64::from_be_bytes(buf[6..14].try_into().ok()?),
        }),
        KIND_CAP_ACK if buf.len() == CAP_FRAME_LEN => Some(ParsedSwFrame::CapAck {
            nonce: u64::from_be_bytes(buf[6..14].try_into().ok()?),
        }),
        KIND_CAP_ENABLE if buf.len() == CAP_FRAME_LEN => Some(ParsedSwFrame::CapEnable {
            _nonce: u64::from_be_bytes(buf[6..14].try_into().ok()?),
        }),
        KIND_DATA_RELIABLE if buf.len() >= DATA_HEADER_LEN => Some(ParsedSwFrame::DataReliable {
            seq: u64::from_be_bytes(buf[6..14].try_into().ok()?),
            payload: &buf[DATA_HEADER_LEN..],
        }),
        KIND_DATA_URGENT if buf.len() >= DATA_HEADER_LEN => Some(ParsedSwFrame::DataUrgent {
            seq: u64::from_be_bytes(buf[6..14].try_into().ok()?),
            payload: &buf[DATA_HEADER_LEN..],
        }),
        KIND_HEALTH_PING if buf.len() == HEALTH_FRAME_LEN => Some(ParsedSwFrame::HealthPing {
            switch_id: u64::from_be_bytes(buf[6..14].try_into().ok()?),
            idx: u32::from_be_bytes(buf[14..18].try_into().ok()?),
            nonce: u64::from_be_bytes(buf[18..26].try_into().ok()?),
        }),
        KIND_HEALTH_PONG if buf.len() == HEALTH_FRAME_LEN => Some(ParsedSwFrame::HealthPong {
            switch_id: u64::from_be_bytes(buf[6..14].try_into().ok()?),
            idx: u32::from_be_bytes(buf[14..18].try_into().ok()?),
            nonce: u64::from_be_bytes(buf[18..26].try_into().ok()?),
        }),
        KIND_SWITCH_PREPARE if buf.len() == PREPARE_FRAME_LEN => {
            Some(ParsedSwFrame::SwitchPrepare {
                switch_id: u64::from_be_bytes(buf[6..14].try_into().ok()?),
                last_rel_seq: u64::from_be_bytes(buf[14..22].try_into().ok()?),
                last_urg_seq: u64::from_be_bytes(buf[22..30].try_into().ok()?),
            })
        }
        KIND_SWITCH_DRAIN_ACK if buf.len() == DRAIN_ACK_FRAME_LEN => {
            Some(ParsedSwFrame::SwitchDrainAck {
                switch_id: u64::from_be_bytes(buf[6..14].try_into().ok()?),
                _ack_rel_seq: u64::from_be_bytes(buf[14..22].try_into().ok()?),
                _ack_urg_seq: u64::from_be_bytes(buf[22..30].try_into().ok()?),
                peer_last_rel_seq: u64::from_be_bytes(buf[30..38].try_into().ok()?),
                peer_last_urg_seq: u64::from_be_bytes(buf[38..46].try_into().ok()?),
            })
        }
        KIND_SWITCH_COMMIT if buf.len() == COMMIT_FRAME_LEN => Some(ParsedSwFrame::SwitchCommit {
            switch_id: u64::from_be_bytes(buf[6..14].try_into().ok()?),
        }),
        KIND_SWITCH_URGENT_MARK if buf.len() == URGENT_MARK_FRAME_LEN => {
            Some(ParsedSwFrame::SwitchUrgentMark {
                _switch_id: u64::from_be_bytes(buf[6..14].try_into().ok()?),
                _last_urg_seq: u64::from_be_bytes(buf[14..22].try_into().ok()?),
            })
        }
        KIND_TUNNEL_CONTROL => Some(ParsedSwFrame::TunnelControl { payload: &buf[6..] }),
        _ => None,
    }
}

/// 支持运行期无损 Make-Before-Break 热切的 [`rc_net::Transport`] 包装器。
pub struct SwitchableTransport {
    role: Role,
    active: Box<dyn Transport>,
    active_kind: TransportPathKind,
    candidate: Option<Box<dyn Transport>>,
    draining_old: Option<(Box<dyn Transport>, Instant)>,
    shared: Arc<SwitchSharedState>,
    cap_state: CapState,
    cap_nonce: u64,
    cap_started_at: Instant,
    last_cap_probe_at: Option<Instant>,
    tx_rel_seq: u64,
    tx_urg_seq: u64,
    rx_rel_seq: u64,
    rx_urg_seq: u64,
    paused_tx: VecDeque<(bool, Vec<u8>)>,
    switch_state: SwitchState,
    next_switch_id: u64,
    buffered_events: VecDeque<NetEvent>,
    pacing_rate_bps: u64,
    active_wake: WakeHandleSlot,
}

type WakeHandleSlot = Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandEventOutcome {
    Continue,
    Committed,
    Aborted,
}

#[allow(clippy::too_many_arguments)]
fn evaluate_health_probing_gate(
    now: Instant,
    probing_started_at: Instant,
    min_health_hold: Duration,
    pongs_received: u32,
    inflight_pings: &HashMap<u32, (u64, Instant)>,
    rtts_us: &[u32],
    max_rtt_us: Option<u32>,
    max_loss_rate: Option<f32>,
) -> Option<std::result::Result<u32, ()>> {
    if now.saturating_duration_since(probing_started_at) < min_health_hold {
        return None;
    }
    let timed_out_pings = inflight_pings
        .values()
        .filter(|(_, sent_at)| {
            now.saturating_duration_since(*sent_at) >= DEFAULT_HEALTH_PING_LOSS_TIMEOUT
        })
        .count() as u32;
    if pongs_received < DEFAULT_HEALTH_PING_COUNT {
        if timed_out_pings >= DEFAULT_HEALTH_PING_COUNT {
            return Some(Err(()));
        }
        return None;
    }
    let settled = pongs_received.saturating_add(timed_out_pings);
    let avg_rtt_us =
        (rtts_us.iter().map(|v| u64::from(*v)).sum::<u64>() / (rtts_us.len().max(1) as u64)) as u32;
    let loss_rate = if settled > 0 {
        (timed_out_pings as f32) / (settled as f32)
    } else {
        0.0
    };
    let rtt_ok = max_rtt_us.map_or(true, |limit| avg_rtt_us <= limit);
    let loss_ok = max_loss_rate.map_or(true, |limit| loss_rate < limit);
    if rtt_ok && loss_ok {
        Some(Ok(avg_rtt_us))
    } else {
        Some(Err(()))
    }
}

impl SwitchableTransport {
    /// 以初始激活传输与角色构造 [`SwitchableTransport`]，同步返回跨线程控制句柄 [`SwitchHandle`]。
    ///
    /// - `require_mtls == true` 时对后续热切候选强制执行双向 mTLS + 指纹校验；
    /// - 对老版本未启用热切的对端自动回退为纯透传模式（零阻塞、零额外可靠帧）。
    pub fn new(
        initial: Box<dyn Transport>,
        role: Role,
        initial_kind: TransportPathKind,
        require_mtls: bool,
    ) -> (Self, SwitchHandle) {
        let shared = Arc::new(SwitchSharedState::new(initial_kind));
        let handle = SwitchHandle {
            shared: Arc::clone(&shared),
            require_mtls,
        };
        let cap_nonce = rand::thread_rng().next_u64().max(1);
        let switch_base = if role == Role::Controller {
            1
        } else {
            0x8000_0000_0000_0001
        };
        let active_wake = Arc::new(Mutex::new(initial.wake_handle()));
        let mut me = Self {
            role,
            active: initial,
            active_kind: initial_kind,
            candidate: None,
            draining_old: None,
            shared,
            cap_state: CapState::Pending,
            cap_nonce,
            cap_started_at: Instant::now(),
            last_cap_probe_at: None,
            tx_rel_seq: 0,
            tx_urg_seq: 0,
            rx_rel_seq: 0,
            rx_urg_seq: 0,
            paused_tx: VecDeque::new(),
            switch_state: SwitchState::Idle,
            next_switch_id: switch_base,
            buffered_events: VecDeque::new(),
            pacing_rate_bps: 0,
            active_wake,
        };
        me.maybe_send_cap_probe(Instant::now());
        (me, handle)
    }

    /// 预载入从建连前握手中已经收到的首包事件（用于 Host 侧防分裂脑 `ClientHello` 重放）。
    pub fn push_prebuffered_events(&mut self, events: impl IntoIterator<Item = NetEvent>) {
        self.buffered_events.extend(events);
    }

    fn is_tx_paused(&self) -> bool {
        matches!(
            self.switch_state,
            SwitchState::InitiatorDraining { .. } | SwitchState::ResponderDraining { .. }
        )
    }

    fn maybe_send_cap_probe(&mut self, now: Instant) {
        if self.cap_state != CapState::Pending || self.role != Role::Controller {
            return;
        }
        if now.saturating_duration_since(self.cap_started_at) > CAP_PROBE_WINDOW {
            self.cap_state = CapState::Legacy;
            return;
        }
        let due = self.last_cap_probe_at.map_or(true, |last| {
            now.saturating_duration_since(last) >= CAP_PROBE_RETRY_INTERVAL
        });
        if due {
            let pkt = encode_cap_frame(KIND_CAP_REQ, self.cap_nonce);
            let _ = self.active.send_datagram(&pkt);
            self.last_cap_probe_at = Some(now);
        }
    }

    fn flush_outbound_control(&mut self) {
        if self.cap_state != CapState::Capable || self.is_tx_paused() {
            return;
        }
        let msgs: Vec<Vec<u8>> = self
            .shared
            .outbound_control
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        for raw in msgs {
            let frame = encode_tunnel_control(&raw);
            let _ = self.active.send_reliable(&frame);
        }
    }

    fn send_reliable_wire(&mut self, urgent: bool, data: &[u8]) -> Result<()> {
        if self.is_tx_paused() {
            self.paused_tx.push_back((urgent, data.to_vec()));
            return Ok(());
        }
        if self.cap_state == CapState::Capable {
            if urgent {
                self.tx_urg_seq = self.tx_urg_seq.saturating_add(1);
                let frame = encode_data_frame(KIND_DATA_URGENT, self.tx_urg_seq, data);
                self.active.send_reliable_urgent(&frame)
            } else {
                self.tx_rel_seq = self.tx_rel_seq.saturating_add(1);
                let frame = encode_data_frame(KIND_DATA_RELIABLE, self.tx_rel_seq, data);
                self.active.send_reliable(&frame)
            }
        } else if urgent {
            self.tx_urg_seq = self.tx_urg_seq.saturating_add(1);
            self.active.send_reliable_urgent(data)
        } else {
            self.tx_rel_seq = self.tx_rel_seq.saturating_add(1);
            self.active.send_reliable(data)
        }
    }

    fn flush_paused_onto_active(&mut self) -> Result<()> {
        let paused: Vec<(bool, Vec<u8>)> = self.paused_tx.drain(..).collect();
        for (urgent, payload) in paused {
            if self.cap_state == CapState::Capable {
                if urgent {
                    self.tx_urg_seq = self.tx_urg_seq.saturating_add(1);
                    let frame = encode_data_frame(KIND_DATA_URGENT, self.tx_urg_seq, &payload);
                    self.active.send_reliable_urgent(&frame)?;
                } else {
                    self.tx_rel_seq = self.tx_rel_seq.saturating_add(1);
                    let frame = encode_data_frame(KIND_DATA_RELIABLE, self.tx_rel_seq, &payload);
                    self.active.send_reliable(&frame)?;
                }
            } else if urgent {
                self.tx_urg_seq = self.tx_urg_seq.saturating_add(1);
                self.active.send_reliable_urgent(&payload)?;
            } else {
                self.tx_rel_seq = self.tx_rel_seq.saturating_add(1);
                self.active.send_reliable(&payload)?;
            }
        }
        Ok(())
    }

    fn abort_switch_and_rollback(&mut self) {
        if !matches!(self.switch_state, SwitchState::Idle) {
            self.shared.switches_aborted.fetch_add(1, Ordering::AcqRel);
        }
        self.candidate = None;
        self.switch_state = SwitchState::Idle;
        self.shared.switch_inflight.store(false, Ordering::Release);
        let _ = self.flush_paused_onto_active();
    }

    fn commit_switch_to_candidate(
        &mut self,
        candidate_kind: TransportPathKind,
        candidate_mtls: bool,
        candidate_fp: Option<String>,
        avg_rtt_us: u32,
    ) {
        let Some(mut new_transport) = self.candidate.take() else {
            self.abort_switch_and_rollback();
            return;
        };
        if self.pacing_rate_bps > 0 {
            new_transport.set_pacing_rate(self.pacing_rate_bps);
        }
        let next_wake = new_transport.wake_handle();
        let old_transport = std::mem::replace(&mut self.active, new_transport);
        *self.active_wake.lock().unwrap_or_else(|e| e.into_inner()) = next_wake;
        self.draining_old = Some((old_transport, Instant::now() + DEFAULT_OLD_DRAIN_GRACE));
        self.active_kind = candidate_kind;
        *self
            .shared
            .active_kind
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = candidate_kind;
        self.switch_state = SwitchState::Idle;
        self.shared.switch_inflight.store(false, Ordering::Release);
        self.shared
            .switches_committed
            .fetch_add(1, Ordering::AcqRel);
        self.shared.touch_rx();
        let _ = self.flush_paused_onto_active();
        self.flush_outbound_control();

        let mut events = self
            .shared
            .path_events
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        events.push_back(SwitchPathEvent {
            kind: candidate_kind,
            label: candidate_kind.as_label(),
            backend_suffix: candidate_kind.backend_suffix(),
            mtls_active: candidate_mtls,
            peer_cert_fingerprint: candidate_fp,
            rtt_us: avg_rtt_us,
        });
    }

    fn accept_pending_candidate_if_idle(&mut self, now: Instant) {
        if !matches!(self.switch_state, SwitchState::Idle) {
            return;
        }
        let req = self
            .shared
            .pending_candidate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let Some(req) = req else {
            return;
        };
        if self.cap_state != CapState::Capable {
            self.shared.switches_aborted.fetch_add(1, Ordering::AcqRel);
            self.shared.switch_inflight.store(false, Ordering::Release);
            return;
        }
        let switch_id = self.next_switch_id;
        self.next_switch_id = self.next_switch_id.wrapping_add(1).max(1);
        let probe_budget = if req.as_initiator {
            req.min_health_hold + req.stage_timeout
        } else {
            req.stage_timeout.max(Duration::from_secs(8))
        };
        self.candidate = Some(req.candidate.transport);
        self.switch_state = SwitchState::HealthProbing {
            switch_id,
            candidate_kind: req.candidate.kind,
            candidate_mtls: req.candidate.mtls_verified,
            candidate_fp: req.candidate.peer_cert_fingerprint,
            as_initiator: req.as_initiator,
            pings_sent: 0,
            pongs_received: 0,
            last_ping_sent_at: None,
            inflight_pings: HashMap::with_capacity(8),
            rtts_us: Vec::with_capacity(DEFAULT_HEALTH_PING_COUNT as usize),
            probing_started_at: now,
            min_health_hold: req.min_health_hold,
            max_rtt_us: req.max_rtt_us,
            max_loss_rate: req.max_loss_rate,
            deadline: now + probe_budget,
            stage_timeout: req.stage_timeout,
        };
    }

    fn handle_active_event(&mut self, ev: NetEvent, now: Instant, out: &mut Vec<NetEvent>) {
        match ev {
            NetEvent::Datagram(bytes) => {
                self.shared.touch_rx();
                if let Some(frame) = parse_sw_frame(&bytes) {
                    match frame {
                        ParsedSwFrame::CapReq { nonce } => {
                            if self.role == Role::Host && self.cap_state != CapState::Legacy {
                                let ack = encode_cap_frame(KIND_CAP_ACK, nonce);
                                let _ = self.active.send_datagram(&ack);
                            }
                        }
                        ParsedSwFrame::CapAck { nonce }
                            if self.role == Role::Controller
                                && self.cap_state == CapState::Pending
                                && nonce == self.cap_nonce =>
                        {
                            let enable = encode_cap_frame(KIND_CAP_ENABLE, nonce);
                            if self.active.send_reliable(&enable).is_ok() {
                                self.cap_state = CapState::Capable;
                                self.shared.switch_capable.store(true, Ordering::Release);
                                self.flush_outbound_control();
                            }
                        }
                        _ => {}
                    }
                    return;
                }
                out.push(NetEvent::Datagram(bytes));
            }
            NetEvent::Reliable(bytes) => {
                self.shared.touch_rx();
                if let Some(frame) = parse_sw_frame(&bytes) {
                    match frame {
                        ParsedSwFrame::CapEnable { .. } => {
                            if self.cap_state != CapState::Legacy {
                                self.cap_state = CapState::Capable;
                                self.shared.switch_capable.store(true, Ordering::Release);
                                self.flush_outbound_control();
                            }
                        }
                        ParsedSwFrame::DataReliable { seq, payload } => {
                            if self.cap_state == CapState::Pending {
                                self.cap_state = CapState::Capable;
                                self.shared.switch_capable.store(true, Ordering::Release);
                            }
                            if seq > self.rx_rel_seq {
                                self.rx_rel_seq = seq;
                                out.push(NetEvent::Reliable(payload.to_vec()));
                            }
                        }
                        ParsedSwFrame::TunnelControl { payload } => {
                            let mut q = self
                                .shared
                                .inbound_control
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if q.len() >= 64 {
                                q.pop_front();
                            }
                            q.push_back(payload.to_vec());
                        }
                        ParsedSwFrame::SwitchPrepare {
                            switch_id,
                            last_rel_seq,
                            last_urg_seq,
                        } => {
                            self.on_switch_prepare_from_peer(
                                switch_id,
                                last_rel_seq,
                                last_urg_seq,
                                now,
                            );
                        }
                        _ => {}
                    }
                    return;
                }
                // 切勿因建连首包 `Hello (0x01)` 在 0.5 RTT 先于 `CapEnable` 到达就锁定 Legacy；
                // 老端绝不会发送带 `RCSW` 魔数的能力帧或数据帧，因此 Pending 在收到对端 `CapEnable` / `RCSW`
                // 数据帧前保持零包裹透传即可。
                out.push(NetEvent::Reliable(bytes));
            }
            NetEvent::ReliableUrgent(bytes) => {
                self.shared.touch_rx();
                if let Some(frame) = parse_sw_frame(&bytes) {
                    match frame {
                        ParsedSwFrame::DataUrgent { seq, payload } => {
                            if self.cap_state == CapState::Pending {
                                self.cap_state = CapState::Capable;
                                self.shared.switch_capable.store(true, Ordering::Release);
                            }
                            if seq > self.rx_urg_seq {
                                self.rx_urg_seq = seq;
                                out.push(NetEvent::ReliableUrgent(payload.to_vec()));
                            }
                        }
                        ParsedSwFrame::SwitchUrgentMark { .. } => {}
                        _ => {}
                    }
                    return;
                }
                out.push(NetEvent::ReliableUrgent(bytes));
            }
            other => out.push(other),
        }
    }

    fn handle_draining_old_event(&mut self, ev: NetEvent, out: &mut Vec<NetEvent>) {
        match ev {
            NetEvent::Datagram(bytes) => {
                if parse_sw_frame(&bytes).is_none() {
                    out.push(NetEvent::Datagram(bytes));
                }
            }
            NetEvent::Reliable(bytes) => {
                if let Some(frame) = parse_sw_frame(&bytes) {
                    match frame {
                        ParsedSwFrame::DataReliable { seq, payload } if seq > self.rx_rel_seq => {
                            self.rx_rel_seq = seq;
                            out.push(NetEvent::Reliable(payload.to_vec()));
                        }
                        ParsedSwFrame::TunnelControl { payload } => {
                            let mut q = self
                                .shared
                                .inbound_control
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if q.len() >= 64 {
                                q.pop_front();
                            }
                            q.push_back(payload.to_vec());
                        }
                        _ => {}
                    }
                }
            }
            NetEvent::ReliableUrgent(bytes) => {
                if let Some(ParsedSwFrame::DataUrgent { seq, payload }) = parse_sw_frame(&bytes) {
                    if seq > self.rx_urg_seq {
                        self.rx_urg_seq = seq;
                        out.push(NetEvent::ReliableUrgent(payload.to_vec()));
                    }
                }
            }
            // 旧传输在排空期断开或迁移属于预期行为，绝不向上层报错/断流。
            NetEvent::Disconnected { .. } | NetEvent::Connected | NetEvent::PathChanged => {}
        }
    }

    fn on_switch_prepare_from_peer(
        &mut self,
        switch_id: u64,
        peer_last_rel_seq: u64,
        peer_last_urg_seq: u64,
        now: Instant,
    ) {
        match &mut self.switch_state {
            SwitchState::HealthProbing {
                candidate_kind,
                candidate_mtls,
                candidate_fp,
                rtts_us,
                stage_timeout,
                ..
            } => {
                let avg = if rtts_us.is_empty() {
                    0
                } else {
                    (rtts_us.iter().map(|v| u64::from(*v)).sum::<u64>() / (rtts_us.len() as u64))
                        as u32
                };
                self.switch_state = SwitchState::ResponderDraining {
                    switch_id,
                    candidate_kind: *candidate_kind,
                    candidate_mtls: *candidate_mtls,
                    candidate_fp: candidate_fp.clone(),
                    avg_rtt_us: avg,
                    peer_last_rel_seq,
                    peer_last_urg_seq,
                    drain_ack_sent: false,
                    deadline: now + *stage_timeout,
                };
            }
            // 双方同时发起热切碰撞：按角色确定性仲裁（Host 退让为响应方接管对端 switch_id；Controller 忽略对端冲突 Prepare）。
            SwitchState::InitiatorDraining {
                candidate_kind,
                candidate_mtls,
                candidate_fp,
                avg_rtt_us,
                deadline,
                ..
            } if self.role == Role::Host => {
                self.switch_state = SwitchState::ResponderDraining {
                    switch_id,
                    candidate_kind: *candidate_kind,
                    candidate_mtls: *candidate_mtls,
                    candidate_fp: candidate_fp.clone(),
                    avg_rtt_us: *avg_rtt_us,
                    peer_last_rel_seq,
                    peer_last_urg_seq,
                    drain_ack_sent: false,
                    deadline: *deadline,
                };
            }
            _ => {}
        }
    }

    fn handle_candidate_event(
        &mut self,
        ev: NetEvent,
        now: Instant,
        out: &mut Vec<NetEvent>,
    ) -> CandEventOutcome {
        match ev {
            NetEvent::Disconnected { .. } => {
                self.abort_switch_and_rollback();
                return CandEventOutcome::Aborted;
            }
            NetEvent::Reliable(bytes) => {
                if let Some(frame) = parse_sw_frame(&bytes) {
                    match frame {
                        ParsedSwFrame::HealthPing {
                            switch_id,
                            idx,
                            nonce,
                        } => {
                            let pong = encode_health_frame(KIND_HEALTH_PONG, switch_id, idx, nonce);
                            if let Some(ref mut cand) = self.candidate {
                                if cand.send_reliable(&pong).is_err() {
                                    self.abort_switch_and_rollback();
                                    return CandEventOutcome::Aborted;
                                }
                            }
                        }
                        ParsedSwFrame::HealthPong {
                            switch_id,
                            idx,
                            nonce,
                        } => {
                            self.on_health_pong(switch_id, idx, nonce, now);
                        }
                        ParsedSwFrame::SwitchDrainAck {
                            switch_id,
                            peer_last_rel_seq,
                            peer_last_urg_seq,
                            ..
                        } => {
                            if let SwitchState::InitiatorDraining {
                                switch_id: my_id,
                                drain_ack_received,
                                peer_last_rel_seq: slot_rel,
                                peer_last_urg_seq: slot_urg,
                                ..
                            } = &mut self.switch_state
                            {
                                if *my_id == switch_id {
                                    *drain_ack_received = true;
                                    *slot_rel = peer_last_rel_seq;
                                    *slot_urg = peer_last_urg_seq;
                                }
                            }
                        }
                        ParsedSwFrame::SwitchCommit { switch_id } => {
                            if let SwitchState::ResponderDraining {
                                switch_id: my_id,
                                candidate_kind,
                                candidate_mtls,
                                candidate_fp,
                                avg_rtt_us,
                                ..
                            } = &self.switch_state
                            {
                                if *my_id == switch_id {
                                    self.commit_switch_to_candidate(
                                        *candidate_kind,
                                        *candidate_mtls,
                                        candidate_fp.clone(),
                                        *avg_rtt_us,
                                    );
                                    return CandEventOutcome::Committed;
                                }
                            }
                        }
                        ParsedSwFrame::DataReliable { seq, payload } => {
                            if seq > self.rx_rel_seq {
                                self.rx_rel_seq = seq;
                                out.push(NetEvent::Reliable(payload.to_vec()));
                            }
                        }
                        ParsedSwFrame::TunnelControl { payload } => {
                            let mut q = self
                                .shared
                                .inbound_control
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if q.len() >= 64 {
                                q.pop_front();
                            }
                            q.push_back(payload.to_vec());
                        }
                        _ => {}
                    }
                }
            }
            NetEvent::ReliableUrgent(bytes) => {
                if let Some(ParsedSwFrame::DataUrgent { seq, payload }) = parse_sw_frame(&bytes) {
                    if seq > self.rx_urg_seq {
                        self.rx_urg_seq = seq;
                        out.push(NetEvent::ReliableUrgent(payload.to_vec()));
                    }
                }
            }
            NetEvent::Datagram(bytes) => {
                if parse_sw_frame(&bytes).is_none() {
                    out.push(NetEvent::Datagram(bytes));
                }
            }
            NetEvent::Connected | NetEvent::PathChanged => {}
        }
        CandEventOutcome::Continue
    }

    fn on_health_pong(&mut self, switch_id: u64, idx: u32, nonce: u64, now: Instant) {
        let decision = {
            let SwitchState::HealthProbing {
                switch_id: my_id,
                as_initiator,
                pongs_received,
                inflight_pings,
                rtts_us,
                probing_started_at,
                min_health_hold,
                max_rtt_us,
                max_loss_rate,
                ..
            } = &mut self.switch_state
            else {
                return;
            };
            if !*as_initiator || *my_id != switch_id {
                return;
            }
            let Some((expected_nonce, sent_at)) = inflight_pings.get(&idx).copied() else {
                return;
            };
            if expected_nonce != nonce {
                return;
            }
            inflight_pings.remove(&idx);
            let rtt_us = now
                .saturating_duration_since(sent_at)
                .as_micros()
                .min(u32::MAX as u128) as u32;
            rtts_us.push(rtt_us);
            *pongs_received += 1;

            evaluate_health_probing_gate(
                now,
                *probing_started_at,
                *min_health_hold,
                *pongs_received,
                inflight_pings,
                rtts_us,
                *max_rtt_us,
                *max_loss_rate,
            )
        };
        if let Some(d) = decision {
            self.apply_health_probing_decision(d, now);
        }
    }

    fn apply_health_probing_decision(
        &mut self,
        decision: std::result::Result<u32, ()>,
        now: Instant,
    ) {
        let Ok(avg_rtt_us) = decision else {
            self.abort_switch_and_rollback();
            return;
        };

        let SwitchState::HealthProbing {
            switch_id: my_id,
            candidate_kind,
            candidate_mtls,
            candidate_fp,
            stage_timeout,
            ..
        } = &self.switch_state
        else {
            return;
        };

        let last_rel = self.tx_rel_seq;
        let last_urg = self.tx_urg_seq;
        let prep = encode_prepare_frame(*my_id, last_rel, last_urg);
        let urg_mark = encode_urgent_mark_frame(*my_id, last_urg);
        let send_ok = self.active.send_reliable(&prep).is_ok()
            && self.active.send_reliable_urgent(&urg_mark).is_ok();
        if !send_ok {
            self.abort_switch_and_rollback();
            return;
        }
        self.switch_state = SwitchState::InitiatorDraining {
            switch_id: *my_id,
            candidate_kind: *candidate_kind,
            candidate_mtls: *candidate_mtls,
            candidate_fp: candidate_fp.clone(),
            avg_rtt_us,
            drain_ack_received: false,
            peer_last_rel_seq: 0,
            peer_last_urg_seq: 0,
            deadline: now + *stage_timeout,
        };
    }

    fn step_switch_machine(&mut self, now: Instant, out: &mut Vec<NetEvent>) {
        // 1) 超时检查：任一阶段超时立即回滚，原传输无损继续
        let expired = match &self.switch_state {
            SwitchState::Idle => false,
            SwitchState::HealthProbing { deadline, .. }
            | SwitchState::InitiatorDraining { deadline, .. }
            | SwitchState::ResponderDraining { deadline, .. } => now >= *deadline,
        };
        if expired {
            self.abort_switch_and_rollback();
            return;
        }

        // 2) 发起方按需发送下一个 HealthPing（至少 3 次；若存在 min_health_hold 则持续每 200ms 探测直到 hold 期满，
        //    并将每条在途 nonce 记录在 inflight_pings 中，避免 RTT > 200ms 时被下一条 ping 覆盖误判丢包）
        if let SwitchState::HealthProbing {
            switch_id,
            as_initiator: true,
            pings_sent,
            last_ping_sent_at,
            inflight_pings,
            probing_started_at,
            min_health_hold,
            ..
        } = &mut self.switch_state
        {
            let hold_pending =
                now.saturating_duration_since(*probing_started_at) < *min_health_hold;
            let want_more = *pings_sent < DEFAULT_HEALTH_PING_COUNT || hold_pending;
            let interval_due = if *pings_sent < DEFAULT_HEALTH_PING_COUNT {
                inflight_pings.is_empty()
            } else {
                last_ping_sent_at.map_or(true, |t| {
                    now.saturating_duration_since(t) >= Duration::from_millis(200)
                })
            };
            if want_more && interval_due {
                let idx = *pings_sent;
                let nonce = rand::thread_rng().next_u64();
                let ping = encode_health_frame(KIND_HEALTH_PING, *switch_id, idx, nonce);
                if let Some(ref mut cand) = self.candidate {
                    if cand.send_reliable(&ping).is_err() {
                        self.abort_switch_and_rollback();
                        return;
                    }
                    inflight_pings.insert(idx, (nonce, now));
                    *pings_sent += 1;
                    *last_ping_sent_at = Some(now);
                }
            }
        }

        // 3) 非阻塞轮询候选传输并驱动回包/提交
        if let Some(mut cand) = self.candidate.take() {
            match cand.poll(Duration::ZERO) {
                Ok(cand_events) => {
                    self.candidate = Some(cand);
                    let mut promoted_to_active = false;
                    for ev in cand_events {
                        if promoted_to_active {
                            self.handle_active_event(ev, now, out);
                            continue;
                        }
                        match self.handle_candidate_event(ev, now, out) {
                            CandEventOutcome::Continue => {}
                            CandEventOutcome::Committed => {
                                promoted_to_active = true;
                            }
                            CandEventOutcome::Aborted => break,
                        }
                    }
                }
                Err(_) => {
                    self.abort_switch_and_rollback();
                    return;
                }
            }
        }

        // 3.5) 周期复核 hold 到期或已超时 ping 的损失裁决（即使在两个 pong 间隔之间刚过 hold_elapsed 也能立即推进）
        let timer_decision = if let SwitchState::HealthProbing {
            as_initiator: true,
            pongs_received,
            inflight_pings,
            rtts_us,
            probing_started_at,
            min_health_hold,
            max_rtt_us,
            max_loss_rate,
            ..
        } = &self.switch_state
        {
            evaluate_health_probing_gate(
                now,
                *probing_started_at,
                *min_health_hold,
                *pongs_received,
                inflight_pings,
                rtts_us,
                *max_rtt_us,
                *max_loss_rate,
            )
        } else {
            None
        };
        if let Some(d) = timer_decision {
            self.apply_health_probing_decision(d, now);
            return;
        }

        // 4) 检查响应方是否已排空旧流并应答 SwitchDrainAck
        if let SwitchState::ResponderDraining {
            switch_id,
            peer_last_rel_seq,
            peer_last_urg_seq,
            drain_ack_sent,
            ..
        } = &mut self.switch_state
        {
            if !*drain_ack_sent
                && self.rx_rel_seq >= *peer_last_rel_seq
                && self.rx_urg_seq >= *peer_last_urg_seq
            {
                let ack = encode_drain_ack_frame(
                    *switch_id,
                    *peer_last_rel_seq,
                    *peer_last_urg_seq,
                    self.tx_rel_seq,
                    self.tx_urg_seq,
                );
                if let Some(ref mut cand) = self.candidate {
                    if cand.send_reliable(&ack).is_err() {
                        self.abort_switch_and_rollback();
                        return;
                    }
                    *drain_ack_sent = true;
                }
            }
        }

        // 5) 检查发起方是否已收到 SwitchDrainAck 且双向旧流排空完毕 -> 发 SwitchCommit 并提交
        let commit_ready = match &self.switch_state {
            SwitchState::InitiatorDraining {
                switch_id,
                candidate_kind,
                candidate_mtls,
                candidate_fp,
                avg_rtt_us,
                drain_ack_received: true,
                peer_last_rel_seq,
                peer_last_urg_seq,
                ..
            } if self.rx_rel_seq >= *peer_last_rel_seq && self.rx_urg_seq >= *peer_last_urg_seq => {
                Some((
                    *switch_id,
                    *candidate_kind,
                    *candidate_mtls,
                    candidate_fp.clone(),
                    *avg_rtt_us,
                ))
            }
            _ => None,
        };
        if let Some((switch_id, kind, mtls, fp, avg_rtt_us)) = commit_ready {
            let commit = encode_commit_frame(switch_id);
            if let Some(ref mut cand) = self.candidate {
                if cand.send_reliable(&commit).is_err() {
                    self.abort_switch_and_rollback();
                    return;
                }
                self.commit_switch_to_candidate(kind, mtls, fp, avg_rtt_us);
            }
        }
    }
}

impl Transport for SwitchableTransport {
    fn send_datagram(&mut self, data: &[u8]) -> Result<()> {
        self.active.send_datagram(data)
    }

    fn send_datagrams_batch(&mut self, datagrams: &[Vec<u8>]) -> Result<usize> {
        self.active.send_datagrams_batch(datagrams)
    }

    fn send_reliable(&mut self, data: &[u8]) -> Result<()> {
        self.send_reliable_wire(false, data)
    }

    fn send_reliable_urgent(&mut self, data: &[u8]) -> Result<()> {
        self.send_reliable_wire(true, data)
    }

    fn poll(&mut self, timeout: Duration) -> Result<Vec<NetEvent>> {
        let now = Instant::now();
        let mut out: Vec<NetEvent> = Vec::new();
        // 先将建连初期捕获并灌入的 prebuffer 事件逐条经 handle_active_event 过滤/更新状态机，
        // 严禁把 `RCSW` 能力帧或包裹帧直接泄露给上层 HostSession::handshake()。
        let prebuf: Vec<NetEvent> = self.buffered_events.drain(..).collect();
        for ev in prebuf {
            self.handle_active_event(ev, now, &mut out);
        }

        self.maybe_send_cap_probe(now);
        self.accept_pending_candidate_if_idle(now);
        self.flush_outbound_control();

        // 有候选热切在途时，缩短主 poll 超时以便毫秒级推进健康探测与状态机
        let effective_timeout = if matches!(self.switch_state, SwitchState::Idle) {
            timeout
        } else {
            timeout.min(Duration::from_millis(5))
        };

        let active_events = self.active.poll(effective_timeout)?;
        for ev in active_events {
            self.handle_active_event(ev, Instant::now(), &mut out);
        }

        // 旧传输 2s 宽限排空窗口
        if let Some((mut old, drain_until)) = self.draining_old.take() {
            if Instant::now() < drain_until {
                if let Ok(old_events) = old.poll(Duration::ZERO) {
                    for ev in old_events {
                        self.handle_draining_old_event(ev, &mut out);
                    }
                    self.draining_old = Some((old, drain_until));
                }
            }
        }

        self.step_switch_machine(Instant::now(), &mut out);
        Ok(out)
    }

    fn stats(&self) -> NetStats {
        self.active.stats()
    }

    fn set_pacing_rate(&mut self, bps: u64) {
        self.pacing_rate_bps = bps;
        self.active.set_pacing_rate(bps);
        if let Some(ref mut cand) = self.candidate {
            cand.set_pacing_rate(bps);
        }
    }

    fn tx_queued_bytes(&self) -> usize {
        self.active.tx_queued_bytes()
    }

    fn tx_dropped_datagrams(&self) -> u64 {
        self.active.tx_dropped_datagrams()
    }

    fn reliable_tx_queued_len(&self) -> usize {
        self.active.reliable_tx_queued_len()
    }

    fn has_live_rtt(&self) -> bool {
        self.active.has_live_rtt()
    }

    fn wake_handle(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let active_wake = Arc::clone(&self.active_wake);
        Some(Arc::new(move || {
            let cb = active_wake
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(wake) = cb {
                wake();
            }
        }))
    }
}

/// 运行期双向迟滞切换参数配置（对齐 P1-1 设计门槛）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HysteresisConfig {
    /// P2P 劣化统计滑动窗口（默认 5s）。
    pub degrade_window: Duration,
    /// 劣化评估所需最小样本数（默认 15）。
    pub min_samples: usize,
    /// 丢包率触发降级阈值（默认 >= 0.08 即 8%）。
    pub loss_degrade_threshold: f32,
    /// RTT 绝对触发门槛（毫秒，默认 >= 250ms）。
    pub rtt_degrade_abs_ms: u32,
    /// RTT 相对基线恶化门槛（毫秒，默认 >= +100ms）。
    pub rtt_degrade_delta_ms: u32,
    /// 抖动触发门槛（毫秒，默认 >= 60ms）。
    pub jitter_degrade_ms: u32,
    /// 连续零收包静默降级阈值（默认 2s）。
    pub silence_degrade: Duration,
    /// `P2P -> Relay` 降级后冷却时间（默认 30s）。
    pub recovery_cooldown: Duration,
    /// 冷却后每次后台复探 P2P 的最小周期（默认 60s）。
    pub reprobe_interval: Duration,
    /// `Relay -> P2P` 回切前候选 P2P 必须连续达标的观测窗口（默认 5s）。
    pub recovery_hold_window: Duration,
    /// 候选 P2P 恢复要求的丢包率上界（严格小于 2% 即 `< 0.02`）。
    pub recovery_max_loss: f32,
    /// 候选 P2P 允许超出中继 RTT 的容忍余量（毫秒，默认 +40ms）。
    pub recovery_rtt_margin_ms: u32,
}

impl Default for HysteresisConfig {
    fn default() -> Self {
        Self {
            degrade_window: Duration::from_secs(5),
            min_samples: 15,
            loss_degrade_threshold: 0.08,
            rtt_degrade_abs_ms: 250,
            rtt_degrade_delta_ms: 100,
            jitter_degrade_ms: 60,
            silence_degrade: Duration::from_secs(2),
            recovery_cooldown: Duration::from_secs(30),
            reprobe_interval: Duration::from_secs(60),
            recovery_hold_window: Duration::from_secs(5),
            recovery_max_loss: 0.02,
            recovery_rtt_margin_ms: 40,
        }
    }
}

/// 单个运行期网络采样点（可由调用方注入时间戳以支撑纯确定性单测）。
#[derive(Debug, Clone, Copy)]
struct NetSample {
    at: Instant,
    rtt_ms: u32,
    loss_rate: f32,
    jitter_ms: u32,
}

/// 运行期双向迟滞决策动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HysteresisDecision {
    /// 维持当前路径。
    Hold,
    /// P2P 出现持续劣化或 2s 静默，触发 Make-Before-Break 降级到 Relay。
    TriggerDegradeToRelay {
        /// 人类可读触发原因（用于 HUD / 诊断日志）。
        reason: String,
    },
    /// 已过 30s 冷却与 60s 周期，发起低开销后台 P2P 复探。
    TriggerP2pReprobe,
}

/// 运行期双向迟滞状态机（遵循外部时钟注入以便纯确定性测试 30s/60s 边界）。
pub struct RuntimePathMonitor {
    cfg: HysteresisConfig,
    samples: VecDeque<NetSample>,
    baseline_rtt_ms: Option<u32>,
    prev_rtt_ms: Option<u32>,
    last_degraded_at: Option<Instant>,
    last_reprobe_at: Option<Instant>,
    relay_rtt_baseline_ms: Option<u32>,
    recovery_good_since: Option<Instant>,
    p2p_degrade_inflight: bool,
    reprobe_inflight: bool,
}

impl RuntimePathMonitor {
    /// 以指定迟滞配置构造监控器。
    pub fn new(cfg: HysteresisConfig) -> Self {
        Self {
            cfg,
            samples: VecDeque::with_capacity(64),
            baseline_rtt_ms: None,
            prev_rtt_ms: None,
            last_degraded_at: None,
            last_reprobe_at: None,
            relay_rtt_baseline_ms: None,
            recovery_good_since: None,
            p2p_degrade_inflight: false,
            reprobe_inflight: false,
        }
    }

    /// 结合会话初始激活路径构造监控器：若以 `Relay` 起流（`Relay-first`），将 `last_reprobe_at` 锚定到当前时刻，避免与后台 14s 升迁并发或刚起流即触发冗余复探。
    pub fn with_initial_path(
        cfg: HysteresisConfig,
        initial_kind: TransportPathKind,
        now: Instant,
    ) -> Self {
        let mut me = Self::new(cfg);
        if initial_kind == TransportPathKind::Relay {
            me.last_reprobe_at = Some(now);
        }
        me
    }

    /// 评估主传输统计并给出当前决策（`rx_silence` 由 [`SwitchHandle::rx_silence`] 提供）。
    pub fn evaluate(
        &mut self,
        now: Instant,
        kind: TransportPathKind,
        stats: NetStats,
        rx_silence: Duration,
    ) -> HysteresisDecision {
        let rtt_ms = stats.rtt_us / 1_000;
        let jitter_ms = self
            .prev_rtt_ms
            .map(|prev| rtt_ms.abs_diff(prev))
            .unwrap_or(0);
        self.prev_rtt_ms = Some(rtt_ms);

        let cutoff = now.checked_sub(self.cfg.degrade_window);
        while let Some(front) = self.samples.front() {
            if cutoff.is_some_and(|c| front.at < c) {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        if rtt_ms > 0 || stats.loss_rate > 0.0 {
            self.samples.push_back(NetSample {
                at: now,
                rtt_ms,
                loss_rate: stats.loss_rate,
                jitter_ms,
            });
        }

        match kind {
            TransportPathKind::P2p => {
                if rtt_ms > 0 && stats.loss_rate < self.cfg.recovery_max_loss {
                    self.baseline_rtt_ms =
                        Some(self.baseline_rtt_ms.map_or(rtt_ms, |b| b.min(rtt_ms)));
                }
                if self.p2p_degrade_inflight {
                    return HysteresisDecision::Hold;
                }
                if rx_silence >= self.cfg.silence_degrade {
                    self.p2p_degrade_inflight = true;
                    return HysteresisDecision::TriggerDegradeToRelay {
                        reason: format!("P2P 连续 {}ms 无收包", rx_silence.as_millis()),
                    };
                }
                if self.samples.len() >= self.cfg.min_samples {
                    let count = self.samples.len() as f32;
                    let avg_loss = self.samples.iter().map(|s| s.loss_rate).sum::<f32>() / count;
                    let avg_rtt = (self
                        .samples
                        .iter()
                        .map(|s| u64::from(s.rtt_ms))
                        .sum::<u64>()
                        / (self.samples.len() as u64)) as u32;
                    let max_jitter = self.samples.iter().map(|s| s.jitter_ms).max().unwrap_or(0);

                    if avg_loss >= self.cfg.loss_degrade_threshold {
                        self.p2p_degrade_inflight = true;
                        return HysteresisDecision::TriggerDegradeToRelay {
                            reason: format!("P2P 丢包率恶化 ({:.1}%)", avg_loss * 100.0),
                        };
                    }
                    let base = self.baseline_rtt_ms.unwrap_or(avg_rtt);
                    if avg_rtt >= self.cfg.rtt_degrade_abs_ms
                        && avg_rtt >= base.saturating_add(self.cfg.rtt_degrade_delta_ms)
                    {
                        self.p2p_degrade_inflight = true;
                        return HysteresisDecision::TriggerDegradeToRelay {
                            reason: format!("P2P RTT 恶化 ({avg_rtt}ms, 基线 {base}ms)"),
                        };
                    }
                    if max_jitter >= self.cfg.jitter_degrade_ms {
                        self.p2p_degrade_inflight = true;
                        return HysteresisDecision::TriggerDegradeToRelay {
                            reason: format!("P2P 抖动过大 ({max_jitter}ms)"),
                        };
                    }
                }
                HysteresisDecision::Hold
            }
            TransportPathKind::Relay => {
                if rtt_ms > 0 {
                    self.relay_rtt_baseline_ms = Some(rtt_ms);
                }
                if self.reprobe_inflight {
                    return HysteresisDecision::Hold;
                }
                if let Some(degraded_at) = self.last_degraded_at {
                    if now.saturating_duration_since(degraded_at) < self.cfg.recovery_cooldown {
                        return HysteresisDecision::Hold;
                    }
                }
                let due = self.last_reprobe_at.map_or(true, |last| {
                    now.saturating_duration_since(last) >= self.cfg.reprobe_interval
                });
                if due {
                    self.last_reprobe_at = Some(now);
                    self.reprobe_inflight = true;
                    return HysteresisDecision::TriggerP2pReprobe;
                }
                HysteresisDecision::Hold
            }
            TransportPathKind::Lan | TransportPathKind::MtlsLan => HysteresisDecision::Hold,
        }
    }

    /// 评估已建立的候选 P2P 链路是否连续满足 5s 回切迟滞门槛（`loss < 2%` 且 `rtt_p2p <= rtt_relay + 40ms`）。
    pub fn evaluate_candidate_recovery(
        &mut self,
        now: Instant,
        p2p_loss_rate: f32,
        p2p_rtt_ms: u32,
        relay_rtt_ms_override: Option<u32>,
    ) -> bool {
        let relay_rtt = relay_rtt_ms_override
            .or(self.relay_rtt_baseline_ms)
            .unwrap_or(p2p_rtt_ms);
        let good = p2p_loss_rate < self.cfg.recovery_max_loss
            && p2p_rtt_ms <= relay_rtt.saturating_add(self.cfg.recovery_rtt_margin_ms);
        if !good {
            self.recovery_good_since = None;
            return false;
        }
        let since = *self.recovery_good_since.get_or_insert(now);
        now.saturating_duration_since(since) >= self.cfg.recovery_hold_window
    }

    /// 标记降级切换已完成（或中止）并开启 30s 冷却计时。
    pub fn on_degrade_finished(&mut self, committed: bool, now: Instant) {
        self.p2p_degrade_inflight = false;
        self.samples.clear();
        self.recovery_good_since = None;
        if committed {
            self.last_degraded_at = Some(now);
        }
    }

    /// 标记一轮后台 P2P 复探已结束（无论成功或失败），解除 in-flight 占位并重置 5s 达标窗口。
    pub fn on_reprobe_finished(&mut self, now: Instant) {
        self.reprobe_inflight = false;
        self.recovery_good_since = None;
        self.last_reprobe_at = Some(now);
    }

    /// 供重探与外部判断当前记录到的 Relay RTT（毫秒）。
    pub fn relay_rtt_ms(&self) -> Option<u32> {
        self.relay_rtt_baseline_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    struct ChannelEndpoint {
        tx: mpsc::Sender<NetEvent>,
        rx: mpsc::Receiver<NetEvent>,
        stats: Arc<Mutex<NetStats>>,
        dead: Arc<AtomicBool>,
        drop_datagrams: bool,
    }

    type DuplexPair = (
        Box<dyn Transport>,
        Box<dyn Transport>,
        Arc<AtomicBool>,
        Arc<AtomicBool>,
    );

    fn make_duplex_pair(drop_datagrams_a: bool, drop_datagrams_b: bool) -> DuplexPair {
        let (tx_a_to_b, rx_b) = mpsc::channel();
        let (tx_b_to_a, rx_a) = mpsc::channel();
        let dead_a = Arc::new(AtomicBool::new(false));
        let dead_b = Arc::new(AtomicBool::new(false));
        let ta = Box::new(ChannelEndpoint {
            tx: tx_a_to_b,
            rx: rx_a,
            stats: Arc::new(Mutex::new(NetStats::default())),
            dead: Arc::clone(&dead_a),
            drop_datagrams: drop_datagrams_a,
        });
        let tb = Box::new(ChannelEndpoint {
            tx: tx_b_to_a,
            rx: rx_b,
            stats: Arc::new(Mutex::new(NetStats::default())),
            dead: Arc::clone(&dead_b),
            drop_datagrams: drop_datagrams_b,
        });
        (ta, tb, dead_a, dead_b)
    }

    impl Transport for ChannelEndpoint {
        fn send_datagram(&mut self, data: &[u8]) -> Result<()> {
            if self.dead.load(Ordering::Acquire) {
                return Err(Error::Network("channel closed".into()));
            }
            if !self.drop_datagrams {
                let _ = self.tx.send(NetEvent::Datagram(data.to_vec()));
            }
            Ok(())
        }

        fn send_reliable(&mut self, data: &[u8]) -> Result<()> {
            if self.dead.load(Ordering::Acquire) {
                return Err(Error::Network("channel closed".into()));
            }
            self.tx
                .send(NetEvent::Reliable(data.to_vec()))
                .map_err(|_| Error::Network("peer closed".into()))
        }

        fn send_reliable_urgent(&mut self, data: &[u8]) -> Result<()> {
            if self.dead.load(Ordering::Acquire) {
                return Err(Error::Network("channel closed".into()));
            }
            self.tx
                .send(NetEvent::ReliableUrgent(data.to_vec()))
                .map_err(|_| Error::Network("peer closed".into()))
        }

        fn poll(&mut self, timeout: Duration) -> Result<Vec<NetEvent>> {
            if self.dead.load(Ordering::Acquire) {
                return Ok(vec![NetEvent::Disconnected {
                    reason: "injected disconnect".into(),
                }]);
            }
            let mut out = Vec::new();
            match self.rx.recv_timeout(timeout) {
                Ok(ev) => {
                    out.push(ev);
                    while let Ok(more) = self.rx.try_recv() {
                        out.push(more);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    out.push(NetEvent::Disconnected {
                        reason: "peer dropped".into(),
                    });
                }
            }
            Ok(out)
        }

        fn stats(&self) -> NetStats {
            *self.stats.lock().unwrap()
        }
    }

    #[test]
    fn switchable_transport_make_before_break_250_msgs_zero_loss_zero_reorder_zero_dup() {
        let (init_c, init_h, _, _) = make_duplex_pair(false, false);
        let (mut sw_c, h_c) =
            SwitchableTransport::new(init_c, Role::Controller, TransportPathKind::Relay, true);
        let (mut sw_h, h_h) =
            SwitchableTransport::new(init_h, Role::Host, TransportPathKind::Relay, true);

        // 完成能力协商（几拍空 poll 即完成）
        for _ in 0..10 {
            let _ = sw_c.poll(Duration::from_millis(1)).unwrap();
            let _ = sw_h.poll(Duration::from_millis(1)).unwrap();
            if h_c.is_switch_capable() && h_h.is_switch_capable() {
                break;
            }
        }
        assert!(h_c.is_switch_capable());
        assert!(h_h.is_switch_capable());

        // 未携带 mTLS 校验的候选必须被 fail-closed 拒绝
        let (bad_c, _bad_h, _, _) = make_duplex_pair(false, false);
        let sec_err = h_c.initiate_switch(CandidateTransport {
            transport: bad_c,
            kind: TransportPathKind::P2p,
            mtls_verified: false,
            peer_cert_fingerprint: None,
        });
        assert!(sec_err.is_err());
        assert_eq!(h_c.candidate_rejected_security(), 1);

        // 建立已过 mTLS 校验的新候选传输
        let (new_c, new_h, _, _) = make_duplex_pair(false, false);
        h_c.initiate_switch(CandidateTransport {
            transport: new_c,
            kind: TransportPathKind::P2p,
            mtls_verified: true,
            peer_cert_fingerprint: Some("aa:bb:cc".to_string()),
        })
        .unwrap();
        h_h.accept_switch_candidate(CandidateTransport {
            transport: new_h,
            kind: TransportPathKind::P2p,
            mtls_verified: true,
            peer_cert_fingerprint: Some("11:22:33".to_string()),
        })
        .unwrap();

        // 在 Make-Before-Break 切换全过程持续双向发送 260 条可靠消息（含 urgent）
        let mut h_recv_rel = Vec::new();
        let mut h_recv_urg = Vec::new();
        let mut c_recv_rel = Vec::new();
        let mut sent_rel = 0u32;
        let mut sent_urg = 0u32;
        let mut host_sent_rel = 0u32;

        for step in 0..120 {
            if sent_rel < 200 {
                for _ in 0..3 {
                    if sent_rel < 200 {
                        sw_c.send_reliable(format!("rel-{sent_rel}").as_bytes())
                            .unwrap();
                        sent_rel += 1;
                    }
                }
            }
            if sent_urg < 60 {
                sw_c.send_reliable_urgent(format!("urg-{sent_urg}").as_bytes())
                    .unwrap();
                sent_urg += 1;
            }
            if host_sent_rel < 50 && step % 2 == 0 {
                sw_h.send_reliable(format!("host-{host_sent_rel}").as_bytes())
                    .unwrap();
                host_sent_rel += 1;
            }

            for ev in sw_c.poll(Duration::from_millis(1)).unwrap() {
                if let NetEvent::Reliable(b) = ev {
                    c_recv_rel.push(String::from_utf8(b).unwrap());
                }
            }
            for ev in sw_h.poll(Duration::from_millis(1)).unwrap() {
                match ev {
                    NetEvent::Reliable(b) => h_recv_rel.push(String::from_utf8(b).unwrap()),
                    NetEvent::ReliableUrgent(b) => h_recv_urg.push(String::from_utf8(b).unwrap()),
                    _ => {}
                }
            }
            if h_c.switches_committed() == 1
                && h_h.switches_committed() == 1
                && h_recv_rel.len() == 200
                && h_recv_urg.len() == 60
                && c_recv_rel.len() == 50
            {
                break;
            }
        }

        assert_eq!(h_c.switches_committed(), 1);
        assert_eq!(h_h.switches_committed(), 1);
        assert_eq!(h_c.active_kind(), TransportPathKind::P2p);
        assert_eq!(h_h.active_kind(), TransportPathKind::P2p);
        assert_eq!(
            h_recv_rel,
            (0..200).map(|i| format!("rel-{i}")).collect::<Vec<_>>()
        );
        assert_eq!(
            h_recv_urg,
            (0..60).map(|i| format!("urg-{i}")).collect::<Vec<_>>()
        );
        assert_eq!(
            c_recv_rel,
            (0..50).map(|i| format!("host-{i}")).collect::<Vec<_>>()
        );
        assert!(matches!(
            h_c.drain_path_events().as_slice(),
            [SwitchPathEvent {
                kind: TransportPathKind::P2p,
                label: "UDP P2P",
                mtls_active: true,
                ..
            }]
        ));
    }

    #[test]
    fn switchable_transport_aborts_and_rolls_back_when_candidate_disconnects_or_times_out() {
        let (init_c, init_h, _, _) = make_duplex_pair(false, false);
        let (mut sw_c, h_c) =
            SwitchableTransport::new(init_c, Role::Controller, TransportPathKind::P2p, false);
        let (mut sw_h, h_h) =
            SwitchableTransport::new(init_h, Role::Host, TransportPathKind::P2p, false);

        for _ in 0..10 {
            let _ = sw_c.poll(Duration::from_millis(1)).unwrap();
            let _ = sw_h.poll(Duration::from_millis(1)).unwrap();
            if h_c.is_switch_capable() && h_h.is_switch_capable() {
                break;
            }
        }

        // 注入新传输在 HealthProbing/Draining 期断开（dead_cand_c = true）
        let (new_c, new_h, dead_new_c, _dead_new_h) = make_duplex_pair(false, false);
        dead_new_c.store(true, Ordering::Release);

        h_c.submit_candidate(
            CandidateTransport {
                transport: new_c,
                kind: TransportPathKind::Relay,
                mtls_verified: false,
                peer_cert_fingerprint: None,
            },
            true,
            Duration::from_millis(60),
        )
        .unwrap();
        h_h.submit_candidate(
            CandidateTransport {
                transport: new_h,
                kind: TransportPathKind::Relay,
                mtls_verified: false,
                peer_cert_fingerprint: None,
            },
            false,
            Duration::from_millis(60),
        )
        .unwrap();

        for _ in 0..20 {
            let _ = sw_c.poll(Duration::from_millis(5)).unwrap();
            let _ = sw_h.poll(Duration::from_millis(5)).unwrap();
        }
        assert_eq!(h_c.switches_committed(), 0);
        assert!(h_c.switches_aborted() >= 1);
        assert_eq!(h_c.active_kind(), TransportPathKind::P2p);

        // 原传输必须毫发无损继续正常收发
        sw_c.send_reliable(b"after-rollback-ok").unwrap();
        let mut got = Vec::new();
        for _ in 0..10 {
            for ev in sw_h.poll(Duration::from_millis(2)).unwrap() {
                if let NetEvent::Reliable(b) = ev {
                    got.push(b);
                }
            }
        }
        assert_eq!(got, vec![b"after-rollback-ok".to_vec()]);
    }

    #[test]
    fn switchable_transport_remains_transparent_with_legacy_peer() {
        let (init_c, mut legacy_h, _, _) = make_duplex_pair(false, false);
        let (mut sw_c, h_c) =
            SwitchableTransport::new(init_c, Role::Controller, TransportPathKind::Lan, false);

        // 模拟老端发送原始 Hello/Welcome 且忽略未知 Datagram
        sw_c.send_reliable(b"\x01HELLO_BYTES").unwrap();
        let mut h_saw_reliable = Vec::new();
        for ev in legacy_h.poll(Duration::from_millis(5)).unwrap() {
            if let NetEvent::Reliable(b) = ev {
                h_saw_reliable.push(b);
            }
        }
        assert_eq!(h_saw_reliable, vec![b"\x01HELLO_BYTES".to_vec()]);
        assert!(!h_c.is_switch_capable());

        legacy_h.send_reliable(b"\x02WELCOME_BYTES").unwrap();
        let mut c_saw = Vec::new();
        for ev in sw_c.poll(Duration::from_millis(5)).unwrap() {
            if let NetEvent::Reliable(b) = ev {
                c_saw.push(b);
            }
        }
        assert_eq!(c_saw, vec![b"\x02WELCOME_BYTES".to_vec()]);
        assert!(!h_c.is_switch_capable());
    }

    #[test]
    fn hysteresis_monitor_or_degrade_conditions_and_30s_cooldown_prevent_pingpong() {
        let cfg = HysteresisConfig::default();
        let base = Instant::now();

        // 1) 丢包 >= 8% (5s 窗内 15 个样本) 触发降级
        let mut m1 = RuntimePathMonitor::new(cfg);
        for i in 0..15u64 {
            let d = m1.evaluate(
                base + Duration::from_millis(i * 200),
                TransportPathKind::P2p,
                NetStats {
                    rtt_us: 25_000,
                    loss_rate: 0.09,
                    ..Default::default()
                },
                Duration::from_millis(10),
            );
            if i < 14 {
                assert_eq!(d, HysteresisDecision::Hold);
            } else {
                assert!(matches!(
                    d,
                    HysteresisDecision::TriggerDegradeToRelay { .. }
                ));
            }
        }

        // 2) RTT >= 250ms 且较基线恶化 >= 100ms 触发降级；如果基线本来就 200ms 且当前 260ms (+60ms < 100ms) 则不触发
        let mut m2 = RuntimePathMonitor::new(cfg);
        for i in 0..15u64 {
            assert_eq!(
                m2.evaluate(
                    base + Duration::from_millis(i * 100),
                    TransportPathKind::P2p,
                    NetStats {
                        rtt_us: 200_000,
                        loss_rate: 0.0,
                        ..Default::default()
                    },
                    Duration::ZERO,
                ),
                HysteresisDecision::Hold
            );
        }
        // 突然恶化到 310ms (+110ms >= 100ms 且 >= 250ms)
        let mut triggered = false;
        for i in 15..30u64 {
            let d = m2.evaluate(
                base + Duration::from_millis(i * 250),
                TransportPathKind::P2p,
                NetStats {
                    rtt_us: 310_000,
                    loss_rate: 0.0,
                    ..Default::default()
                },
                Duration::ZERO,
            );
            if matches!(d, HysteresisDecision::TriggerDegradeToRelay { .. }) {
                triggered = true;
                break;
            }
        }
        assert!(
            triggered,
            "RTT >= 250ms & delta >= 100ms must trigger degrade"
        );

        // 3) 连续 2s 零收包静默立即触发降级，并验证 30s 冷却防震荡 + 60s 周期复探 + 5s 连续达标门槛
        let mut m3 = RuntimePathMonitor::new(cfg);
        let d_silence = m3.evaluate(
            base + Duration::from_secs(3),
            TransportPathKind::P2p,
            NetStats {
                rtt_us: 30_000,
                loss_rate: 0.0,
                ..Default::default()
            },
            Duration::from_secs(2),
        );
        assert!(matches!(
            d_silence,
            HysteresisDecision::TriggerDegradeToRelay { .. }
        ));
        let degraded_at = base + Duration::from_secs(3);
        m3.on_degrade_finished(true, degraded_at);

        // 冷却期 29s 内绝对不触发复探
        assert_eq!(
            m3.evaluate(
                degraded_at + Duration::from_secs(29),
                TransportPathKind::Relay,
                NetStats {
                    rtt_us: 50_000,
                    ..Default::default()
                },
                Duration::ZERO,
            ),
            HysteresisDecision::Hold
        );
        // 满 30s 冷却后触发一次复探
        assert_eq!(
            m3.evaluate(
                degraded_at + Duration::from_secs(30),
                TransportPathKind::Relay,
                NetStats {
                    rtt_us: 50_000,
                    ..Default::default()
                },
                Duration::ZERO,
            ),
            HysteresisDecision::TriggerP2pReprobe
        );
        m3.on_reprobe_finished(degraded_at + Duration::from_secs(31));

        // 60s 内不重复触发，满 60s 后再触发下一次复探
        assert_eq!(
            m3.evaluate(
                degraded_at + Duration::from_secs(90),
                TransportPathKind::Relay,
                NetStats {
                    rtt_us: 50_000,
                    ..Default::default()
                },
                Duration::ZERO,
            ),
            HysteresisDecision::Hold
        );
        assert_eq!(
            m3.evaluate(
                degraded_at + Duration::from_secs(91),
                TransportPathKind::Relay,
                NetStats {
                    rtt_us: 50_000,
                    ..Default::default()
                },
                Duration::ZERO,
            ),
            HysteresisDecision::TriggerP2pReprobe
        );

        // 候选 P2P 回切需要连续 5s 满足 loss < 2% 且 rtt <= relay + 40ms
        let t_hold = degraded_at + Duration::from_secs(92);
        assert!(!m3.evaluate_candidate_recovery(t_hold, 0.01, 80, Some(50)));
        assert!(!m3.evaluate_candidate_recovery(
            t_hold + Duration::from_secs(4),
            0.01,
            80,
            Some(50)
        ));
        assert!(m3.evaluate_candidate_recovery(
            t_hold + Duration::from_secs(5),
            0.01,
            80,
            Some(50)
        ));
        // 若中途 RTT 突增超过 relay + 40ms，5s 计数必须清零
        assert!(!m3.evaluate_candidate_recovery(
            t_hold + Duration::from_secs(6),
            0.01,
            95,
            Some(50)
        ));
    }

    #[test]
    fn hysteresis_monitor_triggers_degrade_on_jitter_ge_60ms() {
        let mut monitor = RuntimePathMonitor::new(HysteresisConfig::default());
        let base = Instant::now();
        // 前 14 拍（< 15 样本）即使抖动 >= 60ms 也保持 Hold
        for idx in 0..14u64 {
            let rtt_us = if idx % 2 == 0 { 20_000 } else { 85_000 };
            let decision = monitor.evaluate(
                base + Duration::from_millis(idx * 200),
                TransportPathKind::P2p,
                NetStats {
                    rtt_us,
                    loss_rate: 0.0,
                    ..Default::default()
                },
                Duration::ZERO,
            );
            assert_eq!(decision, HysteresisDecision::Hold);
        }
        // 第 15 个样本进入窗口（avg_rtt ~ 52ms < 250ms, avg_loss = 0%），
        // 但相邻样本抖动 65ms >= 60ms，按 OR 逻辑触发 P2P -> Relay 降级
        let decision = monitor.evaluate(
            base + Duration::from_millis(14 * 200),
            TransportPathKind::P2p,
            NetStats {
                rtt_us: 20_000,
                loss_rate: 0.0,
                ..Default::default()
            },
            Duration::ZERO,
        );
        assert!(matches!(
            decision,
            HysteresisDecision::TriggerDegradeToRelay { .. }
        ));
    }

    #[test]
    fn switchable_transport_simultaneous_dual_initiation_resolves_via_role_tiebreak() {
        let (init_c, init_h, _, _) = make_duplex_pair(false, false);
        let (mut sw_c, h_c) =
            SwitchableTransport::new(init_c, Role::Controller, TransportPathKind::Relay, true);
        let (mut sw_h, h_h) =
            SwitchableTransport::new(init_h, Role::Host, TransportPathKind::Relay, true);

        for _ in 0..10 {
            let _ = sw_c.poll(Duration::from_millis(1)).unwrap();
            let _ = sw_h.poll(Duration::from_millis(1)).unwrap();
            if h_c.is_switch_capable() && h_h.is_switch_capable() {
                break;
            }
        }
        assert!(h_c.is_switch_capable() && h_h.is_switch_capable());

        // Controller 与 Host 同时对同一对已建立候选传输调用 initiate_switch
        let (cand_c, cand_h, _, _) = make_duplex_pair(false, false);
        h_c.initiate_switch(CandidateTransport {
            transport: cand_c,
            kind: TransportPathKind::P2p,
            mtls_verified: true,
            peer_cert_fingerprint: Some("c-fp".to_string()),
        })
        .unwrap();
        h_h.initiate_switch(CandidateTransport {
            transport: cand_h,
            kind: TransportPathKind::P2p,
            mtls_verified: true,
            peer_cert_fingerprint: Some("h-fp".to_string()),
        })
        .unwrap();

        let mut c_recv = Vec::new();
        let mut h_recv = Vec::new();
        for i in 0..80u32 {
            if i < 40 {
                sw_c.send_reliable(format!("c2h-{i}").as_bytes()).unwrap();
                sw_h.send_reliable(format!("h2c-{i}").as_bytes()).unwrap();
            }
            for ev in sw_c.poll(Duration::from_millis(1)).unwrap() {
                if let NetEvent::Reliable(b) = ev {
                    c_recv.push(String::from_utf8(b).unwrap());
                }
            }
            for ev in sw_h.poll(Duration::from_millis(1)).unwrap() {
                if let NetEvent::Reliable(b) = ev {
                    h_recv.push(String::from_utf8(b).unwrap());
                }
            }
            if h_c.switches_committed() == 1
                && h_h.switches_committed() == 1
                && c_recv.len() == 40
                && h_recv.len() == 40
            {
                break;
            }
        }

        assert_eq!(h_c.switches_committed(), 1);
        assert_eq!(h_h.switches_committed(), 1);
        assert_eq!(h_c.switches_aborted(), 0);
        assert_eq!(h_h.switches_aborted(), 0);
        assert_eq!(h_c.active_kind(), TransportPathKind::P2p);
        assert_eq!(h_h.active_kind(), TransportPathKind::P2p);
        let expected_h: Vec<String> = (0..40).map(|i| format!("c2h-{i}")).collect();
        let expected_c: Vec<String> = (0..40).map(|i| format!("h2c-{i}")).collect();
        assert_eq!(h_recv, expected_h);
        assert_eq!(c_recv, expected_c);
    }

    #[test]
    fn runtime_path_monitor_relay_first_waits_60s_before_reprobe() {
        let cfg = HysteresisConfig::default();
        let t0 = Instant::now();
        let mut monitor = RuntimePathMonitor::with_initial_path(cfg, TransportPathKind::Relay, t0);
        // Relay-first 起流后 t = 600ms、t = 14s、t = 59s 均不得触发冗余 TriggerP2pReprobe
        for secs in [1u64, 14, 30, 59] {
            let decision = monitor.evaluate(
                t0 + Duration::from_secs(secs),
                TransportPathKind::Relay,
                NetStats {
                    rtt_us: 40_000,
                    ..Default::default()
                },
                Duration::ZERO,
            );
            assert_eq!(
                decision,
                HysteresisDecision::Hold,
                "unexpected reprobe at +{secs}s"
            );
        }
        let decision = monitor.evaluate(
            t0 + Duration::from_secs(60),
            TransportPathKind::Relay,
            NetStats {
                rtt_us: 40_000,
                ..Default::default()
            },
            Duration::ZERO,
        );
        assert_eq!(decision, HysteresisDecision::TriggerP2pReprobe);
    }

    #[test]
    fn switchable_transport_rejects_concurrent_candidate_overwrite_without_clobbering() {
        let (init_c, init_h, _, _) = make_duplex_pair(false, false);
        let (mut sw_c, h_c) =
            SwitchableTransport::new(init_c, Role::Controller, TransportPathKind::Relay, false);
        let (mut sw_h, h_h) =
            SwitchableTransport::new(init_h, Role::Host, TransportPathKind::Relay, false);

        for _ in 0..10 {
            let _ = sw_c.poll(Duration::from_millis(1)).unwrap();
            let _ = sw_h.poll(Duration::from_millis(1)).unwrap();
            if h_c.is_switch_capable() && h_h.is_switch_capable() {
                break;
            }
        }
        assert!(h_c.is_switch_capable() && h_h.is_switch_capable());

        let (cand1_c, cand1_h, _, _) = make_duplex_pair(false, false);
        let (cand2_c, _cand2_h, _, _) = make_duplex_pair(false, false);
        h_c.initiate_switch(CandidateTransport {
            transport: cand1_c,
            kind: TransportPathKind::P2p,
            mtls_verified: true,
            peer_cert_fingerprint: None,
        })
        .unwrap();
        assert!(h_c.is_switch_inflight());

        // 并发第二次 submit 必须被拒收且不得覆盖第一条候选
        let dup_err = h_c.submit_candidate_with_hold(
            CandidateTransport {
                transport: cand2_c,
                kind: TransportPathKind::Relay,
                mtls_verified: false,
                peer_cert_fingerprint: None,
            },
            true,
            DEFAULT_SWITCH_STAGE_TIMEOUT,
            Duration::ZERO,
            None,
            None,
        );
        assert!(dup_err.is_err());
        assert_eq!(h_c.candidate_rejected_busy(), 1);

        h_h.accept_switch_candidate(CandidateTransport {
            transport: cand1_h,
            kind: TransportPathKind::P2p,
            mtls_verified: true,
            peer_cert_fingerprint: None,
        })
        .unwrap();

        for _ in 0..50 {
            let _ = sw_c.poll(Duration::from_millis(1)).unwrap();
            let _ = sw_h.poll(Duration::from_millis(1)).unwrap();
            if h_c.switches_committed() == 1 && h_h.switches_committed() == 1 {
                break;
            }
        }
        assert_eq!(h_c.switches_committed(), 1);
        assert_eq!(h_h.switches_committed(), 1);
        assert!(!h_c.is_switch_inflight());
        assert_eq!(h_c.active_kind(), TransportPathKind::P2p);
    }

    struct DelayedReliableTransport {
        inner: Box<dyn Transport>,
        delay: Duration,
        delayed: VecDeque<(Instant, NetEvent)>,
    }

    impl DelayedReliableTransport {
        fn new(inner: Box<dyn Transport>, delay: Duration) -> Self {
            Self {
                inner,
                delay,
                delayed: VecDeque::new(),
            }
        }
    }

    impl Transport for DelayedReliableTransport {
        fn send_datagram(&mut self, data: &[u8]) -> Result<()> {
            self.inner.send_datagram(data)
        }
        fn send_reliable(&mut self, data: &[u8]) -> Result<()> {
            self.inner.send_reliable(data)
        }
        fn send_reliable_urgent(&mut self, data: &[u8]) -> Result<()> {
            self.inner.send_reliable_urgent(data)
        }
        fn poll(&mut self, timeout: Duration) -> Result<Vec<NetEvent>> {
            let now = Instant::now();
            for ev in self.inner.poll(timeout)? {
                match ev {
                    NetEvent::Reliable(_) => self.delayed.push_back((now + self.delay, ev)),
                    other => self.delayed.push_back((now, other)),
                }
            }
            let mut ready = Vec::new();
            while let Some((due, _)) = self.delayed.front() {
                if *due <= now {
                    if let Some((_, ev)) = self.delayed.pop_front() {
                        ready.push(ev);
                    }
                } else {
                    break;
                }
            }
            Ok(ready)
        }
        fn stats(&self) -> NetStats {
            self.inner.stats()
        }
    }

    #[test]
    fn health_probing_5s_hold_tolerates_rtt_above_200ms_without_false_loss() {
        let (init_c, init_h, _, _) = make_duplex_pair(false, false);
        let (mut sw_c, h_c) =
            SwitchableTransport::new(init_c, Role::Controller, TransportPathKind::Relay, false);
        let (mut sw_h, h_h) =
            SwitchableTransport::new(init_h, Role::Host, TransportPathKind::Relay, false);

        for _ in 0..10 {
            let _ = sw_c.poll(Duration::from_millis(1)).unwrap();
            let _ = sw_h.poll(Duration::from_millis(1)).unwrap();
            if h_c.is_switch_capable() && h_h.is_switch_capable() {
                break;
            }
        }
        assert!(h_c.is_switch_capable() && h_h.is_switch_capable());

        // 单程延迟 115ms（往返 ~230ms > 200ms 探测发送周期），验证多在途 HealthPing 不会互相覆盖误判丢包
        let (cand_c, cand_h, _, _) = make_duplex_pair(false, false);
        let cand_c = Box::new(DelayedReliableTransport::new(
            cand_c,
            Duration::from_millis(115),
        ));
        let cand_h = Box::new(DelayedReliableTransport::new(
            cand_h,
            Duration::from_millis(115),
        ));

        h_c.submit_candidate_with_hold(
            CandidateTransport {
                transport: cand_c,
                kind: TransportPathKind::P2p,
                mtls_verified: true,
                peer_cert_fingerprint: None,
            },
            true,
            Duration::from_secs(2),
            Duration::from_millis(900),
            Some(800_000),
            Some(0.02),
        )
        .unwrap();
        h_h.accept_switch_candidate(CandidateTransport {
            transport: cand_h,
            kind: TransportPathKind::P2p,
            mtls_verified: true,
            peer_cert_fingerprint: None,
        })
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            let _ = sw_c.poll(Duration::from_millis(10)).unwrap();
            let _ = sw_h.poll(Duration::from_millis(10)).unwrap();
            if h_c.switches_committed() == 1 && h_h.switches_committed() == 1 {
                break;
            }
            if h_c.switches_aborted() > 0 || h_h.switches_aborted() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(h_c.switches_aborted(), 0);
        assert_eq!(h_h.switches_aborted(), 0);
        assert_eq!(h_c.switches_committed(), 1);
        assert_eq!(h_h.switches_committed(), 1);
        assert_eq!(h_c.active_kind(), TransportPathKind::P2p);
    }

    #[test]
    fn switchable_transport_push_prebuffered_events_filters_rcsw_frames() {
        let (_init_c, init_h, _, _) = make_duplex_pair(false, false);
        let (mut sw_h, h_h) =
            SwitchableTransport::new(init_h, Role::Host, TransportPathKind::P2p, false);
        let cap_req = encode_cap_frame(KIND_CAP_REQ, 42);
        let cap_enable = encode_cap_frame(KIND_CAP_ENABLE, 42);
        let hello = vec![0x01, 0xAA, 0xBB];
        // 模拟建连初期 prebuffer 乱序包含 Hello(0x01) + CapEnable + CapReq
        sw_h.push_prebuffered_events(vec![
            NetEvent::Datagram(cap_req.to_vec()),
            NetEvent::Reliable(hello.clone()),
            NetEvent::Reliable(cap_enable.to_vec()),
        ]);
        let events = sw_h.poll(Duration::from_millis(1)).unwrap();
        // RCSW 帧不得泄露给上层会话，且 Hello(0x01) 绝不会把 Host 锁死在 Legacy
        assert_eq!(events, vec![NetEvent::Reliable(hello)]);
        assert!(h_h.is_switch_capable());
    }

    #[test]
    fn real_host_and_client_session_handshake_with_prebuf_achieves_dual_switch_capable() {
        use rc_capture::{FakeBackend, FakeBackendConfig};
        use rc_decode::{FakeDecoder, FakeDecoderConfig};
        use rc_encode::{EncoderConfig, FakeEncoder};
        use rc_render::{FakeRenderer, FakeRendererConfig};
        use rc_session::proto::SessionParams;
        use rc_session::testkit::RecordingInjector;
        use rc_session::{
            AutoApprover, ClientSession, ClientSessionConfig, HostAuthConfig, HostSession,
            HostSessionConfig, SessionClock, ToolPermissions,
        };
        use rc_types::{DisplayId, Resolution};

        struct NoopCapture;
        impl rc_input::InputCapture for NoopCapture {
            fn next_events(
                &mut self,
                _timeout: Duration,
            ) -> rc_types::Result<Vec<rc_input::InputEvent>> {
                Ok(Vec::new())
            }
        }

        let (init_c, mut raw_h, _, _) = make_duplex_pair(false, false);
        let (sw_c, h_c) =
            SwitchableTransport::new(init_c, Role::Controller, TransportPathKind::P2p, false);

        let clock: SessionClock = Arc::new(|| 0);
        let res = Resolution::new(64, 64);
        let params = SessionParams {
            width: 64,
            height: 64,
            fps: 60,
            bitrate_bps: 4_000_000,
        };
        let mut client_cfg = ClientSessionConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            params,
            101,
            Box::new(NoopCapture),
        );
        client_cfg.handshake_timeout = Duration::from_secs(5);
        let mut client = ClientSession::with_parts(
            client_cfg,
            Box::new(sw_c),
            Box::new(
                FakeDecoder::new(FakeDecoderConfig {
                    resolution: res,
                    ..Default::default()
                })
                .unwrap(),
            ),
            Box::new(
                FakeRenderer::new(FakeRendererConfig {
                    size: (res.width, res.height),
                    ..Default::default()
                })
                .unwrap(),
            ),
            Arc::clone(&clock),
        )
        .unwrap();

        let stop_client = Arc::new(AtomicBool::new(false));
        let stop_client_bg = Arc::clone(&stop_client);
        let client_handshaked = Arc::new(AtomicBool::new(false));
        let client_hs_bg = Arc::clone(&client_handshaked);
        let client_jh = std::thread::spawn(move || {
            client.handshake().expect("client handshake");
            client_hs_bg.store(true, Ordering::Release);
            let t0 = Instant::now();
            let _ = client.run(&mut || {
                stop_client_bg.load(Ordering::Acquire) || t0.elapsed() >= Duration::from_secs(2)
            });
            client
        });

        // 模拟 host_bridge try_poll_for_first_hello 预读阶段：先收到 CapReq/Hello 放入 prebuf，并回 CapAck
        let mut prebuf = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_hello = false;
        while !saw_hello && Instant::now() < deadline {
            for ev in raw_h.poll(Duration::from_millis(2)).unwrap() {
                if let NetEvent::Datagram(ref b) = ev {
                    if b.len() == 14 && &b[0..4] == b"RCSW" && b[4] == 1 && b[5] == 0x01 {
                        let mut ack = b.clone();
                        ack[5] = 0x02;
                        let _ = raw_h.send_datagram(&ack);
                    }
                }
                if let NetEvent::Reliable(ref b) = ev {
                    if !(b.len() >= 6 && &b[0..4] == b"RCSW" && matches!(b[5], 0x01..=0x03)) {
                        saw_hello = true;
                    }
                }
                prebuf.push(ev);
            }
        }
        assert!(saw_hello, "host must receive ClientHello");
        // 给 Controller 留足时间发出 CapEnable，使 CapEnable 也有机会混入 prebuf 或紧随其后到达
        std::thread::sleep(Duration::from_millis(20));
        prebuf.extend(raw_h.poll(Duration::from_millis(2)).unwrap());

        let (mut sw_h, h_h) =
            SwitchableTransport::new(raw_h, Role::Host, TransportPathKind::P2p, false);
        sw_h.push_prebuffered_events(prebuf);

        let host_cfg = HostSessionConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            mtu: rc_session::DEFAULT_SESSION_MTU,
            caps: params,
            pipeline: rc_pipeline::PipelineConfig {
                resolution: res,
                fps: 60,
                bitrate_bps: 4_000_000,
                prefer_hardware: false,
                ..Default::default()
            },
            handshake_timeout: Duration::from_secs(5),
            injector: Box::new(RecordingInjector::default()),
            pace_capture: false,
            auth: HostAuthConfig::default(),
            approver: Box::new(AutoApprover),
            tool_permissions: ToolPermissions::all_allowed(),
        };
        let mut host = HostSession::with_parts(
            host_cfg,
            Box::new(sw_h),
            Box::new(
                FakeBackend::new(FakeBackendConfig {
                    display: rc_capture::DisplayInfo {
                        id: DisplayId(0),
                        resolution: res,
                        scale: 1.0,
                        hdr: false,
                    },
                    fps: 60,
                    content: rc_capture::FakeContent::Dynamic,
                    dirty_rect: None,
                })
                .unwrap(),
            ),
            Box::new(
                FakeEncoder::with_tuning(
                    EncoderConfig {
                        resolution: res,
                        fps: 60,
                        bitrate_bps: 4_000_000,
                        ..Default::default()
                    },
                    500,
                    512,
                )
                .unwrap(),
            ),
            clock,
        )
        .unwrap();
        host.handshake()
            .expect("host handshake must succeed with prebuf");

        let t0 = Instant::now();
        let _ = host.run(&mut || {
            (client_handshaked.load(Ordering::Acquire)
                && h_c.is_switch_capable()
                && h_h.is_switch_capable())
                || t0.elapsed() >= Duration::from_secs(2)
        });
        stop_client.store(true, Ordering::Release);
        let _client = client_jh.join().unwrap();
        assert!(
            h_c.is_switch_capable(),
            "controller switch_capable must be true"
        );
        assert!(h_h.is_switch_capable(), "host switch_capable must be true");
    }

    #[test]
    fn switch_shared_state_rx_silence_is_lock_free_and_accurate() {
        let mut shared = SwitchSharedState::new(TransportPathKind::P2p);
        shared.anchor = Instant::now() - Duration::from_millis(120);
        let initial_silence = shared.silence_duration();
        assert!(
            initial_silence >= Duration::from_millis(100),
            "expected silence >= 100ms, got {initial_silence:?}"
        );

        shared.touch_rx();
        let after_touch = shared.silence_duration();
        assert!(
            after_touch < Duration::from_millis(50),
            "touch_rx must reset silence near zero, got {after_touch:?}"
        );
    }
}
