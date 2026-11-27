//! UI ↔ 被控端会话桥接层（一体化 All-in-One 模式）。
//!
//! 本模块**严禁引入 `tauri` 类型**，全模块 `#![deny(unsafe_code)]`，
//! 复用 T19 唯一审批 trait [`rc_session::auth::ConnectionApprover`]，
//! 使 `cargo test -p rc-ui` 离线集成测试无需窗口与事件循环。
//!
//! # 设计要点
//! - 启动时在 `HostHandle::spawn` 内即完成首轮 `HostSession` 绑定（默认 `9901` 端口
//!   若被占用自动回退到同 IP 临时端口 `0`），使 [`HostHandle::listen_addr`] 立即可用；
//! - 工作线程单会话串行循环 accept：每轮 accept 分片前重锚 `ClockOrigin::Pending`，
//!   管线工厂按裁定参数构建硬件/假后端并重锚会话钟；
//! - [`UiApprover`] 实现 [`ConnectionApprover`]：代次单调递增防过期裁决串台，
//!   `submit` / `cancel` 直接推送 [`HostUpdate::ApprovalRequested`] /
//!   [`HostUpdate::ApprovalCancelled`]；
//! - [`HostHandle::stop`] 与 `Drop` 自动拒绝在途审批并触发 `HostSession::run` 优雅停机，
//!   回收工作线程不留僵尸线程。

#![deny(unsafe_code)]

use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use rc_audio::{encode_ima_adpcm, AudioCapture, AudioSilenceGate};
use rc_net::quic::QuicEndpoint;
use rc_net::{NetConfig, NetEvent, NetStats, Role, Transport};
use rc_pipeline::{DiffMode, PipelineConfig};
use rc_session::auth::{
    ApprovalRequest, ApprovalVerdict, ConnectionApprover, OwnerTicketVerifier,
    DEFAULT_AUTH_ITERATIONS,
};
use rc_session::dev_cert::{DEV_CERT_PEM, DEV_KEY_PEM};
use rc_session::proto::{ByeReason, SessionParams};
use rc_session::testkit::RecordingInjector;
use rc_session::{
    AudioFramePacket, AutoApprover, ClipboardBackend, DetachOutcome, HostAuthConfig, HostSession,
    HostSessionConfig, SessionClock, SessionState, StopReason, AUDIO_CODEC_IMA_ADPCM,
    TOOL_CHANNEL_AUDIO_CTRL, TOOL_CHANNEL_DISPLAY_CTRL, TOOL_CHANNEL_FILE, TOOL_CHANNEL_PORTMAP,
    TOOL_CHANNEL_TERMINAL,
};
use rc_tools::{FileHostEngine, PortMapHostEngine, TerminalHostEngine};
use rc_types::Resolution;

use crate::codec_selector::{self, HostCodecNegotiator, NetworkHint, ResolutionTier, StreamTarget};
use crate::display_ctrl::{self, DisplayControlMsg, DisplayDescriptor, DisplayPreset};
use crate::lan_discovery;
use crate::p2p::{self, P2pCandidates};
pub use crate::relay_transport::SessionMtlsBundle;
use crate::relay_transport::{
    E2eeRelayTransport, RelayE2eeMode, RelayRole, RelayShutdownHandle, TcpRelayTransport,
};
use crate::signal_client::RelayIncoming;

/// 默认被控端监听端口（被占用时回退临时端口 `0`）。
pub const DEFAULT_HOST_PORT: u16 = 9901;

/// 被控端更新通道容量上限（有界非阻塞，满载丢最旧）。
pub const HOST_UPDATE_CHANNEL_CAP: usize = 64;

/// 入站中继请求有界队列容量（有界非阻塞，满载丢最旧，符合铁律 1）。
const RELAY_INCOMING_QUEUE_CAP: usize = 8;

/// 入站中继请求的存活有效期（超时未消费的过期令牌自动丢弃）。
const RELAY_INCOMING_TTL: Duration = Duration::from_secs(20);

/// LAN / mTLS LAN 模式下 `HostSession` 的 `Detached` 断线保持窗口（短窗口，避免长期占线）。
const HOST_LAN_RESUME_TTL: Duration = Duration::from_secs(6);

/// 串流/断线期巡检入站抢占候选的时间间隔（~100ms）。
const PREEMPT_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// 同账号自控新入站连接触发旧会话失活抢占的静默阈值（3s）。
const PREEMPT_OWNER_IDLE_THRESHOLD_US: u64 = 3_000_000;

/// 任意入站连接触发旧会话半开失活抢占的静默阈值（4s）。
const PREEMPT_ANY_IDLE_THRESHOLD_US: u64 = 4_000_000;

/// 系统音频采集异常中断/初始化失败的退避序列（300ms -> 1s -> 2s）。
const AUDIO_RECOVERY_INITIAL_BACKOFF: Duration = Duration::from_millis(300);
const AUDIO_RECOVERY_MID_BACKOFF: Duration = Duration::from_secs(1);
const AUDIO_RECOVERY_MAX_BACKOFF: Duration = Duration::from_secs(2);
/// 系统音频采集器判定为「稳定存活」、可将重试退避复位回 300ms 的最短连续运行时长（5s）。
const AUDIO_RECOVERY_STABLE_WINDOW: Duration = Duration::from_secs(5);

/// 临时验证码长度（8 位无歧义大写字母数字，排除 `0`/`O`/`1`/`I`）。
pub const TEMP_CODE_LEN: usize = 8;

/// 临时验证码字符表（32 个字符 = 2^5，按低 5 位索引零模偏差）。
const TEMP_CODE_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// 单次等待入站连接的短分片超时（与 QUIC 握手预算解耦，兼顾中继入站响应速度与 `stop()` 回收）。
const HOST_ACCEPT_SLICE: Duration = Duration::from_millis(150);

/// 收到入站 `Incoming` 后执行 QUIC/mTLS 握手与两条引导流的独立超时预算（与 `HOST_ACCEPT_SLICE` 解耦）。
const HOST_QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

/// 中继传输层建连与 `RCR1` 握手超时。
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// fake 编码器的单帧编码成本（微秒，对齐 `rc-cli/src/cmd/host.rs`）。
const FAKE_ENCODE_COST_US: u32 = 500;

/// 单拍每个工具引擎最多发送的线帧数量（避免工具吞吐饿死视频与控制面）。
const MAX_TOOL_FRAMES_PER_TICK: usize = 8;

/// Host 侧专用文件传输工作线程的出入站有界通道容量（H12）。
const FILE_HOST_WORKER_CHAN_CAP: usize = 64;

/// 单拍最多泵送的音频帧数量（20ms/帧，4 帧 = 80ms 突发上限）。
const MAX_AUDIO_FRAMES_PER_TICK: usize = 4;

/// 生成 8 位无歧义大写字母数字临时验证码（使用 OS 熵源，排除 `0`/`O`/`1`/`I`）。
pub fn generate_temp_code() -> String {
    let mut bytes = [0u8; TEMP_CODE_LEN];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(TEMP_CODE_LEN);
    for b in bytes {
        out.push(TEMP_CODE_ALPHABET[usize::from(b & 0x1F)] as char);
    }
    out
}

/// UI 被控端启动配置。
#[derive(Clone)]
pub struct UiHostConfig {
    /// 期望监听地址（若端口为 [`DEFAULT_HOST_PORT`] 且被占用，自动回退到同 IP 临时端口 `0`）。
    pub listen_addr: SocketAddr,
    /// 访问密码（`None` = 无密码；`Some` = 启用 PBKDF2 挑战应答）。
    pub password: Option<String>,
    /// 机主人工审批超时（微秒）。
    pub approval_timeout_us: u64,
    /// 优先硬件采集/编码/注入（macOS: SCK + VT + CGEvent），不可用时优雅降级假后端。
    pub prefer_hardware: bool,
    /// 是否需要机主审批弹窗（`false` 时使用 [`AutoApprover`] 自动通过）。
    pub require_approval: bool,
    /// 密码校验通过时是否自动放行而不弹出机主审批弹窗（无密码连接仍需机主审批）。
    pub auto_accept_with_password: bool,
    /// 会话结束后是否自动轮换临时验证码（使用临时验证码时为 `true`，自定义密码为 `false`）。
    pub auto_rotate_password: bool,
    /// 是否启用双向剪贴板同步（仅 `prefer_hardware == true` 时挂接本机真实系统剪贴板）。
    pub clipboard_enabled: bool,
    /// 是否启用系统音频采集与编码串流（仅 `prefer_hardware == true` 时采集真实系统音频）。
    pub audio_enabled: bool,
    /// 是否允许本机被远程控制（含同账号本人凭 `OwnerTicket` 自控及他人远程协助的总门控，默认 `true`）。
    pub allow_owner_control: bool,
    /// 是否允许非同账号他人的远程协助（`false` 时仅允许已登录同账号凭 `OwnerTicket` PoP 自控）。
    pub allow_remote_assist: bool,
    /// 同账号本人自控 `OwnerTicket` 公钥验签器（当 `allow_owner_control == true` 时允许本人免密免审批直通）。
    pub owner_verifier: Option<Arc<dyn OwnerTicketVerifier>>,
    /// 双向 mTLS 证书与身份校验束（用于外层 `:21117` 中转、P2P mTLS、内层 E2EE 及可选 LAN mTLS）。
    pub mtls_config: Option<SessionMtlsBundle>,
    /// LAN 直连监听器是否强制启用 mTLS（需配合 `mtls_config: Some(...)`）。
    pub accept_mtls_lan: bool,
    /// 禁用无密码 `AutoApprover` 兜底（仅 `LoginWindow` 无头服务开启：无固定密码且无审批窗口时强制拒绝匿名协助）。
    pub forbid_passwordless_auto_approve: bool,
    /// 可选 W2 文件传输默认接收目录（`None` 时沿用宿主默认主目录）。
    pub file_transfer_dir: Option<PathBuf>,
    /// 他人远程协助本机时是否允许使用 W2 文件传输通道（默认 `true`；同账号本人 `OwnerTicket` 自控始终豁免）。
    pub allow_assist_file_transfer: bool,
}

impl Default for UiHostConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_HOST_PORT)),
            password: None,
            approval_timeout_us: rc_session::auth::DEFAULT_AUTH_TIMEOUT_US,
            prefer_hardware: false,
            require_approval: false,
            auto_accept_with_password: false,
            auto_rotate_password: false,
            clipboard_enabled: true,
            audio_enabled: true,
            allow_owner_control: true,
            allow_remote_assist: true,
            owner_verifier: None,
            mtls_config: None,
            accept_mtls_lan: false,
            forbid_passwordless_auto_approve: false,
            file_transfer_dir: None,
            allow_assist_file_transfer: true,
        }
    }
}

impl fmt::Debug for UiHostConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UiHostConfig")
            .field("listen_addr", &self.listen_addr)
            .field("has_password", &self.password.is_some())
            .field("approval_timeout_us", &self.approval_timeout_us)
            .field("prefer_hardware", &self.prefer_hardware)
            .field("require_approval", &self.require_approval)
            .field("auto_accept_with_password", &self.auto_accept_with_password)
            .field("auto_rotate_password", &self.auto_rotate_password)
            .field("clipboard_enabled", &self.clipboard_enabled)
            .field("audio_enabled", &self.audio_enabled)
            .field("allow_owner_control", &self.allow_owner_control)
            .field("allow_remote_assist", &self.allow_remote_assist)
            .field("has_owner_verifier", &self.owner_verifier.is_some())
            .field("has_mtls_config", &self.mtls_config.is_some())
            .field("accept_mtls_lan", &self.accept_mtls_lan)
            .field("file_transfer_dir", &self.file_transfer_dir)
            .field(
                "allow_assist_file_transfer",
                &self.allow_assist_file_transfer,
            )
            .finish()
    }
}

/// 推送至 UI 的连接审批请求载荷。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostApprovalPrompt {
    /// 单调递增审批代次（前端回传时用于防过期弹窗裁决串台）。
    pub generation: u64,
    /// 控制端 `Hello.session_id`。
    pub session_id: u64,
    /// 控制端传输层来源地址。
    pub remote_addr: String,
    /// 控制端请求的分辨率（如 `"1920x1080"`）。
    pub requested_res: String,
    /// 控制端请求的帧率（fps）。
    pub requested_fps: u32,
    /// 密码校验是否已通过（未启用密码时为 `false`）。
    pub password_verified: bool,
}

/// 被控端工作线程 → UI 的状态更新（经 Tauri event 转发到前端）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostUpdate {
    /// 已开始监听，等待控制端连接。
    Listening {
        /// 实际绑定的监听地址。
        listen_addr: String,
        /// 供本机展示给对端的连接地址（`0.0.0.0` 会替换为探测到的本机局域网 IPv4）。
        display_addr: String,
        /// 后端模式标签。
        backend: String,
    },
    /// 收到新的连接审批请求。
    ApprovalRequested(HostApprovalPrompt),
    /// 在途连接审批已被取消（对端断开或超时）。
    ApprovalCancelled {
        /// 被取消的审批代次。
        generation: u64,
    },
    /// 控制端已通过鉴权与审批，进入串流。
    ClientConnected {
        /// 控制端来源地址。
        remote_addr: String,
    },
    /// 本人同账号自控会话已通过 `OwnerTicket` PoP 免密直通。
    OwnerConnected {
        /// 发起自控的对端设备码。
        caller_device_id: String,
        /// 控制端来源地址或通道标签。
        remote_addr: String,
    },
    /// 控制端已断开连接（被控端回到等待状态）。
    ClientDisconnected {
        /// 人类可读的断开原因。
        reason: String,
    },
    /// 会话结束后工作线程已原子轮换临时验证码（零窗口防止下一次连入复用旧码）。
    PasswordRotated {
        /// 新生效的 8 位临时验证码。
        password: String,
    },
    /// 被控端服务已停止。
    Stopped,
    /// 被控端运行出错。
    Error {
        /// 错误描述。
        message: String,
        /// 结构化用户可读错误模型（可选，向下兼容旧端 JSON）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ui_error: Option<crate::ui_error::UiError>,
    },
}

impl HostUpdate {
    /// 构造带自动归因 [`crate::ui_error::UiError`] 的 [`HostUpdate::Error`]。
    pub fn error(message: impl Into<String>) -> Self {
        let message = message.into();
        let ui_error = Some(crate::ui_error::classify_host_error(
            &message,
            crate::ui_error::current_platform(),
        ));
        Self::Error { message, ui_error }
    }
}

// ─────────────────────────────────────────────────────────────────
// 有界更新队列
// ─────────────────────────────────────────────────────────────────

struct BoundedHostUpdateQueue {
    cap: usize,
    inner: Mutex<VecDeque<HostUpdate>>,
}

impl BoundedHostUpdateQueue {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    fn push(&self, item: HostUpdate) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        while q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(item);
    }

    fn try_pop(&self) -> Option<HostUpdate> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.pop_front()
    }
}

/// 入站中继请求有界队列（满载丢最旧，符合铁律 1，且按 TTL 自动过滤过期令牌）。
struct BoundedRelayIncomingQueue {
    cap: usize,
    inner: Mutex<VecDeque<(Instant, RelayIncoming)>>,
}

impl BoundedRelayIncomingQueue {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    fn push(&self, item: RelayIncoming) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // 同对端发起新连接或动态切换传输模式时，队列中尚未消费的旧入站凭据必然已作废；
        // 立即替换避免被控端先拨号过期旧令牌浪费 11.5s 导致新会话中继配对超时。
        if !item.peer_id.is_empty() {
            q.retain(|(_, existing)| existing.peer_id != item.peer_id);
        }
        while q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back((Instant::now(), item));
    }

    fn pop_ready(&self, ttl: Duration, lan_grace: Duration) -> Option<RelayIncoming> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut deferred = VecDeque::new();
        let mut picked = None;
        while let Some((enqueued_at, item)) = q.pop_front() {
            let elapsed = enqueued_at.elapsed();
            if elapsed > ttl {
                continue;
            }
            if !item.is_relay_alloc && !item.peer_lan_addrs.is_empty() && elapsed < lan_grace {
                deferred.push_back((enqueued_at, item));
                continue;
            }
            picked = Some(item);
            break;
        }
        while let Some(front) = deferred.pop_back() {
            q.push_front(front);
        }
        picked
    }

    fn purge_expired(&self, ttl: Duration) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.retain(|(enqueued_at, _)| enqueued_at.elapsed() <= ttl);
    }

    fn purge_for_peer_before(&self, peer_device_id: Option<&str>, cutoff: Instant, ttl: Duration) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.retain(|(enqueued_at, item)| {
            enqueued_at.elapsed() <= ttl
                && (peer_device_id != Some(item.peer_id.as_str()) || *enqueued_at >= cutoff)
        });
    }

    /// 主动清理当前 LAN / mTLS LAN 会话初始宽限期内到达的同对端陈旧 `PunchCoord`（`!is_relay_alloc`），
    /// 防止其滞留满 20s TTL 后在 `Detached` 期复活误抢占并打断 6s 续传；
    /// 严格保留显式切中继（`is_relay_alloc == true`）、宽限期之后的新请求及其他对端条目。
    fn purge_stale_lan_punch_for_peer(
        &self,
        peer_device_id: Option<&str>,
        lan_grace_cutoff: Instant,
        ttl: Duration,
    ) {
        let Some(cur_peer) = peer_device_id.filter(|id| !id.is_empty()) else {
            return;
        };
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.retain(|(enqueued_at, item)| {
            enqueued_at.elapsed() <= ttl
                && !(item.peer_id == cur_peer
                    && !item.is_relay_alloc
                    && *enqueued_at <= lan_grace_cutoff)
        });
    }

    /// 只读检查入站队列中是否存在可立即抢占当前旧会话的新连接候选：
    /// 1. 同设备重连（`active_peer_id` 非空且与 `item.peer_id` 相同）；
    /// 2. 同账号自控失活抢占（`item.is_owner_connection` 且 `is_detached || active_idle_us >= 3s`）；
    /// 3. 旧会话已失活（`is_detached || active_idle_us >= 4s`）。
    ///
    /// 若旧会话活跃（`!is_detached && active_idle_us < 3s`）且到达的是不同设备，返回 `false` 保护当前活跃用户。
    #[cfg(test)]
    fn has_preempt_candidate(
        &self,
        ttl: Duration,
        active_peer_id: Option<&str>,
        active_idle_us: u64,
        is_detached: bool,
    ) -> bool {
        self.has_preempt_candidate_filtered(ttl, active_peer_id, active_idle_us, is_detached, None)
    }

    fn has_preempt_candidate_filtered(
        &self,
        ttl: Duration,
        active_peer_id: Option<&str>,
        active_idle_us: u64,
        is_detached: bool,
        ignore_same_peer_lan_before: Option<Instant>,
    ) -> bool {
        let q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.iter()
            .filter(|(enqueued_at, _)| enqueued_at.elapsed() <= ttl)
            .any(|(enqueued_at, item)| {
                let same_peer =
                    active_peer_id.is_some_and(|cur| !cur.is_empty() && cur == item.peer_id);
                // LAN / mTLS LAN 初始宽限期内到达的同对端普通 PunchCoord（!is_relay_alloc）
                // 一律视为本次 LAN 建连同源迟到的旧信令：无论 peer_lan_addrs 是否为空、
                // 无论是否满 3s/4s、无论当前处于 Streaming 还是 Detached，绝不触发误抢占。
                if same_peer
                    && !item.is_relay_alloc
                    && ignore_same_peer_lan_before.is_some_and(|cutoff| *enqueued_at <= cutoff)
                {
                    return false;
                }
                same_peer
                    || (item.is_owner_connection
                        && (is_detached || active_idle_us >= PREEMPT_OWNER_IDLE_THRESHOLD_US))
                    || is_detached
                    || active_idle_us >= PREEMPT_ANY_IDLE_THRESHOLD_US
            })
    }
}

/// LAN 建连后容忍广域网信令迟到推送的旧 `PunchCoord` 清理宽限（3s）。
const LAN_STALE_SIGNAL_GRACE: Duration = Duration::from_secs(3);
/// 保护会话刚断开前 500ms 内到达的新切换请求（兼容尚未等待旧连接完全退出的老客户端）。
const SWITCH_SIGNAL_PROTECT_WINDOW: Duration = Duration::from_millis(500);

/// 计算 LAN / mTLS LAN 会话结束后的旧信令清理截止点：
/// LAN 直连往往比 WAN 信令 `PunchCoord` 提前 50–300ms 完成建连，若仅用 `session_started_at`
/// 会漏清同一次初始连接产生的迟到旧令牌；将截止点向后延展至多 3s 且不超过断连前 500ms，
/// 既清掉初始迟到旧令牌又保护临近断连时的新切换请求。
fn lan_stale_signal_cutoff(session_started_at: Instant, session_ended_at: Instant) -> Instant {
    session_ended_at
        .checked_sub(SWITCH_SIGNAL_PROTECT_WINDOW)
        .map(|guard| (session_started_at + LAN_STALE_SIGNAL_GRACE).min(guard))
        .unwrap_or(session_started_at)
}

struct PasswordState {
    password: Option<String>,
    auto_rotate: bool,
}

#[derive(Clone)]
struct AuthRuntimeState {
    allow_owner_control: bool,
    allow_remote_assist: bool,
    owner_verifier: Option<Arc<dyn OwnerTicketVerifier>>,
    owner_replay_cache: Arc<Mutex<rc_session::OwnerReplayCache>>,
    mtls_config: Option<SessionMtlsBundle>,
    accept_mtls_lan: bool,
}

fn emit_peer_connected(host: &HostSession, remote_addr: &str, updates: &BoundedHostUpdateQueue) {
    if let Some(owner) = host.authenticated_owner() {
        updates.push(HostUpdate::OwnerConnected {
            caller_device_id: owner.caller_device_id.clone(),
            remote_addr: remote_addr.to_string(),
        });
    } else {
        updates.push(HostUpdate::ClientConnected {
            remote_addr: remote_addr.to_string(),
        });
    }
}

/// 跨控制端断线/重连持久化的机主级后台终端托管槽位（按 `user_id` 严格隔离，仅机主本人可继承）。
struct PersistentOwnerTerminals {
    owner_user_id: Option<String>,
    engine: TerminalHostEngine,
}

impl PersistentOwnerTerminals {
    fn new() -> Self {
        Self {
            owner_user_id: None,
            engine: TerminalHostEngine::new(),
        }
    }

    fn clear(&mut self) {
        if self.owner_user_id.is_some() || self.engine.active_count() > 0 {
            self.owner_user_id = None;
            self.engine = TerminalHostEngine::new();
        }
    }

    fn sync_auth_and_poll(&mut self, auth_state: Option<&Mutex<AuthRuntimeState>>) {
        if let Some(lock) = auth_state {
            let (has_verifier, expected_uid) = {
                let st = lock.lock().unwrap_or_else(|e| e.into_inner());
                let uid = st
                    .owner_verifier
                    .as_ref()
                    .and_then(|v| v.expected_user_id())
                    .map(str::to_string);
                (st.owner_verifier.is_some(), uid)
            };
            if !has_verifier {
                self.clear();
                return;
            }
            if let (Some(cur), Some(exp)) = (self.owner_user_id.as_deref(), expected_uid.as_deref())
            {
                if cur != exp {
                    self.clear();
                    return;
                }
            }
        }
        self.engine.poll_background();
    }

    fn detach_all(&mut self) {
        self.engine.detach_all();
    }

    fn bind_for_owner(&mut self, user_id: &str) -> &mut TerminalHostEngine {
        if self.owner_user_id.as_deref() != Some(user_id) {
            self.owner_user_id = Some(user_id.to_string());
            self.engine = TerminalHostEngine::new();
        }
        &mut self.engine
    }
}

#[derive(Clone)]
enum ActiveRelayInterrupt {
    Dialing(Arc<AtomicBool>),
    Connected(RelayShutdownHandle),
}

impl ActiveRelayInterrupt {
    fn interrupt(&self) {
        match self {
            Self::Dialing(cancel) => cancel.store(true, Ordering::Release),
            Self::Connected(handle) => handle.shutdown(),
        }
    }
}

struct RelayInterruptSlotGuard<'a> {
    slot: &'a Mutex<Option<ActiveRelayInterrupt>>,
}

impl Drop for RelayInterruptSlotGuard<'_> {
    fn drop(&mut self) {
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

// ─────────────────────────────────────────────────────────────────
// UiApprover：实现 T19 唯一 ConnectionApprover trait
// ─────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct ApproverState {
    in_flight: bool,
    /// 当前在途审批是否实际向 UI 推送了 [`HostUpdate::ApprovalRequested`] 弹窗（避免自动放行后误推取消事件）。
    prompted: bool,
    generation: u64,
    verdict: Option<ApprovalVerdict>,
    /// 实时「允许他人远程协助」门控；关停后 `submit` 即使遇到 `auto_accept_with_password` 也立即拒绝。
    remote_assist_enabled: bool,
    /// 粘性停机标记（U-M2）：一旦置位，后续 `submit` / `poll_verdict` 立刻返回拒绝，不再弹窗。
    stopped: bool,
    /// 可选来源地址覆盖（中继会话无直连 peer SocketAddr，用于向机主展示对端设备码）。
    remote_addr_override: Option<String>,
}

/// UI 侧连接审批器（实现 [`ConnectionApprover`]，全方法非阻塞）。
///
/// 当 `auto_accept_with_password == true` 且 `req.password_verified == true` 时，
/// [`ConnectionApprover::submit`] 直接写入 [`ApprovalVerdict::Accepted`] 而不推送
/// [`HostUpdate::ApprovalRequested`]；其余场景（如无密码连接）递增单调代次 `generation`
/// 并发射 [`HostUpdate::ApprovalRequested`]；[`Self::resolve`] 仅当仍在途且代次精确匹配时
/// 生效；[`ConnectionApprover::cancel`] 清除在途状态并在已弹窗时发射
/// [`HostUpdate::ApprovalCancelled`]。
#[derive(Clone)]
pub struct UiApprover {
    state: Arc<Mutex<ApproverState>>,
    updates: Arc<BoundedHostUpdateQueue>,
    auto_accept_with_password: bool,
}

impl UiApprover {
    fn new(
        updates: Arc<BoundedHostUpdateQueue>,
        auto_accept_with_password: bool,
        remote_assist_enabled: bool,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ApproverState {
                remote_assist_enabled,
                ..ApproverState::default()
            })),
            updates,
            auto_accept_with_password,
        }
    }

    fn set_remote_assist_enabled(&self, enabled: bool) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.remote_assist_enabled = enabled;
    }

    /// 设置或清除中继会话握手期的来源地址覆盖文案。
    fn set_remote_addr_override(&self, label: Option<String>) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.remote_addr_override = label;
    }

    /// 按代次回写机主审批裁决；仅当未停机、在途且 `generation` 精确匹配时返回 `true`。
    pub fn resolve(&self, generation: u64, accepted: bool) -> bool {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !guard.stopped && guard.in_flight && guard.generation == generation {
            guard.verdict = Some(if accepted {
                ApprovalVerdict::Accepted
            } else {
                ApprovalVerdict::Rejected
            });
            true
        } else {
            false
        }
    }

    /// 停机时置位粘性 `stopped` 标记，并立即唤醒阻塞在审批阶段的 `HostSession::handshake`（U-M2）。
    fn mark_stopped(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.stopped = true;
        if guard.in_flight && guard.verdict.is_none() {
            guard.verdict = Some(ApprovalVerdict::Rejected);
        }
    }

    /// 关闭远程协助时立即拒绝并取消当前在途审批，防止旧握手窗口期内继续放行连接。
    fn reject_in_flight(&self) {
        let cancelled_gen = {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.in_flight {
                guard.in_flight = false;
                guard.verdict = Some(ApprovalVerdict::Rejected);
                let was_prompted = std::mem::replace(&mut guard.prompted, false);
                if was_prompted {
                    Some(guard.generation)
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(generation) = cancelled_gen {
            self.updates
                .push(HostUpdate::ApprovalCancelled { generation });
        }
    }
}

impl ConnectionApprover for UiApprover {
    fn submit(&mut self, req: &ApprovalRequest) {
        let prompt = {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.stopped || !guard.remote_assist_enabled {
                guard.in_flight = false;
                guard.prompted = false;
                guard.verdict = Some(ApprovalVerdict::Rejected);
                return;
            }
            guard.generation = guard.generation.wrapping_add(1);
            guard.in_flight = true;
            if self.auto_accept_with_password && req.password_verified {
                guard.prompted = false;
                guard.verdict = Some(ApprovalVerdict::Accepted);
                None
            } else {
                guard.prompted = true;
                guard.verdict = None;
                let remote_addr = guard
                    .remote_addr_override
                    .clone()
                    .unwrap_or_else(|| req.remote_addr.to_string());
                let requested_res = if req.requested.width == 0 && req.requested.height == 0 {
                    "本机当前分辨率".to_string()
                } else {
                    format!("{}x{}", req.requested.width, req.requested.height)
                };
                Some(HostApprovalPrompt {
                    generation: guard.generation,
                    session_id: req.session_id,
                    remote_addr,
                    requested_res,
                    requested_fps: req.requested.fps,
                    password_verified: req.password_verified,
                })
            }
        };
        if let Some(prompt) = prompt {
            self.updates.push(HostUpdate::ApprovalRequested(prompt));
        }
    }

    fn poll_verdict(&mut self) -> Option<ApprovalVerdict> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.stopped {
            guard.in_flight = false;
            guard.prompted = false;
            guard.verdict = None;
            return Some(ApprovalVerdict::Rejected);
        }
        let verdict = guard.verdict.take()?;
        guard.in_flight = false;
        guard.prompted = false;
        Some(verdict)
    }

    fn cancel(&mut self) {
        let cancelled_gen = {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.in_flight {
                guard.in_flight = false;
                guard.verdict = None;
                let was_prompted = std::mem::replace(&mut guard.prompted, false);
                if was_prompted {
                    Some(guard.generation)
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(generation) = cancelled_gen {
            self.updates
                .push(HostUpdate::ApprovalCancelled { generation });
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// 会话钟原点与后端管线构造（对齐 rc-cli/src/cmd/host.rs）
// ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum ClockOrigin {
    /// 握手/审批阶段：以每次 accept 分片前的墙钟推进，保证审批超时准确触发。
    Pending(Instant),
    /// 假后端：与 `WallCapture` 共用单次采样锚点。
    Fake(Instant),
    /// 真后端：锚定主机钟 µs（与 SCK PTS 同域同零点）。
    HostClock(u64),
}

fn make_session_clock(origin: Arc<Mutex<ClockOrigin>>) -> SessionClock {
    Arc::new(move || {
        let guard = origin.lock().unwrap_or_else(|e| e.into_inner());
        match *guard {
            ClockOrigin::Pending(i) | ClockOrigin::Fake(i) => {
                u32::try_from(i.elapsed().as_micros()).unwrap_or(u32::MAX)
            }
            ClockOrigin::HostClock(o) => {
                u32::try_from(rc_pipeline::host_clock_us().unwrap_or(o).saturating_sub(o))
                    .unwrap_or(u32::MAX)
            }
        }
    })
}

type SharedWakeGuard = Arc<Mutex<Option<Box<dyn Any + Send>>>>;
type SharedFileTransferDir = Arc<RwLock<Option<PathBuf>>>;

/// 在 `SharedWakeGuard` 中替换新守卫，并在锁外析构旧守卫（避免持有互斥锁时调用平台释放 FFI）。
fn replace_wake_guard(slot: &SharedWakeGuard, new_guard: Option<Box<dyn Any + Send>>) {
    let old = {
        let mut g = slot.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::replace(&mut *g, new_guard)
    };
    drop(old);
}

struct WakeGuardReleaser {
    slot: SharedWakeGuard,
}

impl Drop for WakeGuardReleaser {
    fn drop(&mut self) {
        replace_wake_guard(&self.slot, None);
    }
}

struct MidSessionWakeResult {
    guard: Option<Box<dyn Any + Send>>,
    still_asleep: bool,
    err: Option<String>,
}

struct AtomicFlagReset(Arc<AtomicBool>);

impl Drop for AtomicFlagReset {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// 会话中单在途非阻塞唤醒驱动器：
/// - 绝不在 `rc-ui-host` 主循环内同步阻塞等待显示器唤醒（最长可达 2.5s）；
/// - 同一时刻最多一个后台唤醒线程在途，完成后经 `try_recv()` 交换守卫并在锁外释放旧守卫；
/// - 若会话在后台唤醒返回前结束，本驱动器析构关闭接收端，后台线程 `send` 失败立即析构新守卫，零泄漏；
/// - 冷却期从唤醒**完成时刻**起算：唤醒超时/仍熄屏退避 15s，成功亮屏冷却 5s。
struct MidSessionWakeDriver {
    in_flight: Arc<AtomicBool>,
    rx: Option<mpsc::Receiver<MidSessionWakeResult>>,
    next_allowed_at: Option<Instant>,
}

impl MidSessionWakeDriver {
    const WAKE_SUCCESS_COOLDOWN: Duration = Duration::from_secs(5);
    const WAKE_TIMEOUT_BACKOFF: Duration = Duration::from_secs(15);

    fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicBool::new(false)),
            rx: None,
            next_allowed_at: None,
        }
    }

    fn poll_completed(&mut self, wake_guard: &SharedWakeGuard, now: Instant) {
        let Some(ref rx) = self.rx else {
            return;
        };
        match rx.try_recv() {
            Ok(res) => {
                self.rx = None;
                if let Some(ref err) = res.err {
                    eprintln!("[rc-ui-host] 会话中重新唤醒显示器失败: {err}");
                }
                if let Some(new_guard) = res.guard {
                    replace_wake_guard(wake_guard, Some(new_guard));
                }
                let cooldown = if res.still_asleep || res.err.is_some() {
                    Self::WAKE_TIMEOUT_BACKOFF
                } else {
                    Self::WAKE_SUCCESS_COOLDOWN
                };
                self.next_allowed_at = Some(now + cooldown);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.rx = None;
                self.next_allowed_at = Some(now + Self::WAKE_TIMEOUT_BACKOFF);
            }
        }
    }

    fn maybe_spawn<F>(&mut self, now: Instant, wake_fn: F) -> bool
    where
        F: FnOnce() -> (Result<Option<Box<dyn Any + Send>>, String>, bool) + Send + 'static,
    {
        if self.rx.is_some() || self.in_flight.load(Ordering::Acquire) {
            return false;
        }
        if self.next_allowed_at.is_some_and(|t| now < t) {
            return false;
        }
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let (tx, rx) = mpsc::sync_channel::<MidSessionWakeResult>(1);
        let flag = Arc::clone(&self.in_flight);
        match thread::Builder::new()
            .name("rc-mid-session-wake".to_string())
            .spawn(move || {
                let _reset = AtomicFlagReset(flag);
                let (res, still_asleep) = wake_fn();
                let msg = match res {
                    Ok(guard) => MidSessionWakeResult {
                        guard,
                        still_asleep,
                        err: None,
                    },
                    Err(e) => MidSessionWakeResult {
                        guard: None,
                        still_asleep: true,
                        err: Some(e),
                    },
                };
                // 若会话已结束并丢弃 rx，SendError 携带的 msg（含守卫）会在此立刻析构，零泄漏。
                let _ = tx.send(msg);
            }) {
            Ok(_) => {
                self.rx = Some(rx);
                true
            }
            Err(e) => {
                self.in_flight.store(false, Ordering::Release);
                self.next_allowed_at = Some(now + Self::WAKE_TIMEOUT_BACKOFF);
                eprintln!("[rc-ui-host] 派发后台显示器唤醒线程失败: {e}");
                false
            }
        }
    }
}

#[derive(Clone)]
struct HostClockAnchor {
    origin: Arc<Mutex<ClockOrigin>>,
    /// 指示下一次管线工厂构造必须放弃旧纪元零点并重新锚定（供 `Bye(Refresh)` 与 `DetachOutcome::Replaced` 跨纪元复位）。
    reanchor_next_build: Arc<AtomicBool>,
}

impl HostClockAnchor {
    fn new_pending() -> Self {
        Self {
            origin: Arc::new(Mutex::new(ClockOrigin::Pending(Instant::now()))),
            reanchor_next_build: Arc::new(AtomicBool::new(false)),
        }
    }

    fn reset_pending(&self) {
        *self.origin.lock().unwrap_or_else(|e| e.into_inner()) =
            ClockOrigin::Pending(Instant::now());
    }
}

struct BuiltUiHost {
    host: HostSession,
    clock: SessionClock,
    clock_anchor: HostClockAnchor,
    backend_label: Arc<Mutex<String>>,
    hardware_video_active: Arc<AtomicBool>,
    wake_guard: SharedWakeGuard,
}

/// 查询硬件主显示器逻辑分辨率（`prefer_hardware == true` 且平台钩子已注册时生效）。
fn host_hardware_display_caps(prefer_hardware: bool) -> Option<Resolution> {
    if !prefer_hardware {
        return None;
    }
    crate::platform::main_display_logical_resolution()
}

/// 查询硬件主显示器物理像素分辨率（backing pixels；`prefer_hardware == true` 且平台钩子已注册时生效）。
fn host_hardware_display_backing(prefer_hardware: bool) -> Option<Resolution> {
    if !prefer_hardware {
        return None;
    }
    crate::platform::main_display_backing_resolution()
}

/// HiDPI/Retina 宿主在 HEVC 会话下的默认清晰度上限（2560×1600，兼顾文本锐利度与 144fps 高刷甜点 600M px/s）。
const DEFAULT_HIDPI_STREAM_MAX_WIDTH: u32 = 2560;
const DEFAULT_HIDPI_STREAM_MAX_HEIGHT: u32 = 1600;

/// 计算 Retina/HiDPI 宿主在双端确认使用 HEVC 后的清晰度甜点分辨率：
/// - 严格保持 `logical` 宽高比、偶数对齐，且不超过物理 `backing` 与 `(2560×1600)`；
/// - 当 `fps >= HIGH_REFRESH_FPS_THRESHOLD (90)` 时同步受 `HEVC_HIGH_REFRESH_MAX_PIXEL_RATE (600M px/s)` 约束，
///   确保默认 `144fps` 下不会触发「超出高刷甜点」告警（例如 14" MBP `1512×982` → `2464×1600`，`567.7M px/s <= 600M`）；
/// - 退化输入（`< 2px`）或非 HiDPI 屏严格沿用 `logical.to_even()`。
fn compute_hevc_hidpi_target(
    logical: Resolution,
    backing: Option<Resolution>,
    fps: u32,
) -> Resolution {
    let logical_even = logical.to_even();
    let Some(backing_even) = backing.map(|b| b.to_even()) else {
        return logical_even;
    };
    if logical_even.width < 2
        || logical_even.height < 2
        || backing_even.width <= logical_even.width
        || backing_even.height <= logical_even.height
    {
        return logical_even;
    }
    let mut cap_w = backing_even
        .width
        .min(DEFAULT_HIDPI_STREAM_MAX_WIDTH)
        .max(logical_even.width);
    let mut cap_h = backing_even
        .height
        .min(DEFAULT_HIDPI_STREAM_MAX_HEIGHT)
        .max(logical_even.height);
    if fps >= display_ctrl::HIGH_REFRESH_FPS_THRESHOLD {
        let max_pixels = display_ctrl::HEVC_HIGH_REFRESH_MAX_PIXEL_RATE / u64::from(fps.max(1));
        let logical_pixels =
            u64::from(logical_even.width).saturating_mul(u64::from(logical_even.height));
        if max_pixels <= logical_pixels {
            return logical_even;
        }
        let scale = (max_pixels as f64 / logical_pixels as f64).sqrt();
        let budget_w = ((f64::from(logical_even.width) * scale).floor() as u32) & !1;
        let budget_h = ((f64::from(logical_even.height) * scale).floor() as u32) & !1;
        cap_w = cap_w.min(budget_w.max(logical_even.width));
        cap_h = cap_h.min(budget_h.max(logical_even.height));
    }
    let (w, h) =
        display_ctrl::fit_within_cap(cap_w, cap_h, logical_even.width, logical_even.height);
    Resolution::new(w.max(logical_even.width), h.max(logical_even.height)).to_even()
}

/// 为主屏未手动固定分辨率的会话计算编解码器/帧率切换后的目标 `(width, height, next_auto_hidpi_active)`：
/// - `Codec::Hevc`：当此前已处于自动 HiDPI 或当前分辨率与原生逻辑分辨率一致（`<= 2px`）时，
///   按新 `eff_fps` 计算不超 HEVC 600M px/s 高刷预算的 2K 锐利甜点（不误放大显式较低分辨率）；
/// - `Codec::H264`：当此前处于自动 HiDPI 或当前分辨率高于原生逻辑分辨率时回退至原生逻辑分辨率。
fn resolve_auto_hidpi_resolution(
    cur_width: u32,
    cur_height: u32,
    native_res: Resolution,
    max_res: Resolution,
    eff_fps: u32,
    eff_codec: rc_encode::Codec,
    auto_hidpi_active: bool,
) -> (u32, u32, bool) {
    match eff_codec {
        rc_encode::Codec::Hevc
            if auto_hidpi_active
                || (cur_width.abs_diff(native_res.width) <= 2
                    && cur_height.abs_diff(native_res.height) <= 2) =>
        {
            let hi = compute_hevc_hidpi_target(native_res, Some(max_res), eff_fps);
            let upgraded = hi.width > native_res.width || hi.height > native_res.height;
            (hi.width, hi.height, upgraded)
        }
        rc_encode::Codec::H264
            if auto_hidpi_active
                || cur_width > native_res.width
                || cur_height > native_res.height =>
        {
            (native_res.width, native_res.height, false)
        }
        _ => (cur_width, cur_height, auto_hidpi_active),
    }
}

/// 若给定 `native/max/fps` 在 HEVC 下存在高于原生的 2K 锐利甜点档位，将其并入预设列表（去重且降序），
/// 确保菜单中高亮当前分辨率并允许用户切回 2K 锐利档。
fn ensure_hevc_hidpi_preset(
    presets: &mut Vec<DisplayPreset>,
    native_res: Resolution,
    max_res: Resolution,
    fps: u32,
    hevc_available: bool,
) {
    if !hevc_available {
        return;
    }
    let hi = compute_hevc_hidpi_target(native_res, Some(max_res), fps);
    if hi.width <= native_res.width.saturating_add(2)
        || hi.height <= native_res.height.saturating_add(2)
    {
        return;
    }
    if presets.is_empty() {
        *presets = display_ctrl::build_resolution_presets(
            native_res.width,
            native_res.height,
            max_res.width,
            max_res.height,
        );
    }
    let already_present = presets
        .iter()
        .any(|p| p.width.abs_diff(hi.width) <= 2 && p.height.abs_diff(hi.height) <= 2);
    if !already_present {
        presets.push(DisplayPreset {
            width: hi.width,
            height: hi.height,
            label: format!("{} × {} (HiDPI)", hi.width, hi.height),
            is_native: false,
            is_hidpi: true,
        });
        presets.sort_by(|a, b| b.width.cmp(&a.width).then_with(|| b.height.cmp(&a.height)));
    }
}

#[allow(clippy::too_many_arguments)]
fn default_host_session_config(
    listen_addr: SocketAddr,
    password: Option<String>,
    approval_timeout_us: u64,
    prefer_hardware: bool,
    allow_owner_control: bool,
    allow_remote_assist: bool,
    owner_verifier: Option<Arc<dyn OwnerTicketVerifier>>,
    owner_replay_cache: Arc<Mutex<rc_session::OwnerReplayCache>>,
    approver: Box<dyn ConnectionApprover>,
) -> (HostSessionConfig, bool) {
    let injector: Box<dyn rc_input::InputInjector> = build_injector(prefer_hardware);

    // 初始握手仍保持 1× 逻辑分辨率，保证不支持 HEVC 的对端与 H.264 路径严格留在 H.264 高刷甜点内；
    // 双端确认切入 HEVC（SetCodec("hevc")）时再在同一次热重建中一步升至 HiDPI 2K 锐利甜点。
    let hw_display_res = host_hardware_display_caps(prefer_hardware);
    let (cap_w, cap_h, preserve_aspect) = match hw_display_res {
        Some(res) => (res.width, res.height, true),
        None => (3840, 2160, false),
    };
    let caps = SessionParams {
        width: cap_w,
        height: cap_h,
        fps: 380,
        bitrate_bps: 150_000_000,
    };
    let pipeline = PipelineConfig {
        resolution: hw_display_res.unwrap_or_else(|| Resolution::new(1920, 1080)),
        fps: 144,
        bitrate_bps: 40_000_000,
        prefer_hardware,
        target_latency_us: 22_000,
        trace_capacity: 4096,
        diff: DiffMode::TrustPlatform,
        clock_origin_us: None,
        max_packet_payload: rc_pipeline::MAX_PAYLOAD,
        ..PipelineConfig::default()
    };
    let cfg = HostSessionConfig {
        listen_addr,
        mtu: rc_session::DEFAULT_SESSION_MTU,
        caps,
        pipeline,
        handshake_timeout: Duration::from_secs(10),
        injector,
        pace_capture: true,
        auth: HostAuthConfig {
            password,
            iterations: DEFAULT_AUTH_ITERATIONS,
            approval_timeout_us,
            allow_owner_control,
            allow_remote_assist,
            owner_verifier,
            replay_cache: Some(owner_replay_cache),
            ..HostAuthConfig::default()
        },
        approver,
        tool_permissions: rc_session::ToolPermissions::all_allowed(),
    };
    (cfg, preserve_aspect)
}

type HostPipelineFactory =
    Box<dyn FnMut(&PipelineConfig) -> rc_types::Result<rc_pipeline::HostPipeline> + Send>;

fn make_host_pipeline_factory(
    prefer_hardware: bool,
    clock_anchor: HostClockAnchor,
    backend_label: Arc<Mutex<String>>,
    hardware_video_active: Arc<AtomicBool>,
    wake_guard: SharedWakeGuard,
    updates: Arc<BoundedHostUpdateQueue>,
) -> HostPipelineFactory {
    Box::new(
        move |pcfg: &PipelineConfig| -> rc_types::Result<rc_pipeline::HostPipeline> {
            // 同会话热切换分辨率/帧率/编解码器时复用既有零点，保证会话钟与采集 PTS 严格单调连续；
            // 发生 `Bye(Refresh)` / `DetachOutcome::Replaced` 纪元重置时放弃旧零点并重新锚定，
            // 防止 71.58 分钟 `u32::MAX` 饱和导致 8s 看门狗与采集时间戳永久卡死。
            let force_reanchor = clock_anchor
                .reanchor_next_build
                .swap(false, Ordering::AcqRel);
            let existing_origin = if force_reanchor {
                ClockOrigin::Pending(Instant::now())
            } else {
                clock_anchor
                    .origin
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
            };
            if prefer_hardware {
                match crate::platform::wake_display_if_asleep() {
                    Ok(Some(guard)) => {
                        replace_wake_guard(&wake_guard, Some(guard));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("[rc-ui-host] 唤醒熄屏显示器失败（将继续尝试硬件采集）: {e}");
                    }
                }
                let mut hw_cfg = pcfg.clone();
                hw_cfg.prefer_hardware = true;
                let existing_host_us = match existing_origin {
                    ClockOrigin::HostClock(o) => Some(o),
                    _ => None,
                };
                let mut final_try = real_host_stack(&hw_cfg, existing_host_us);
                if final_try.is_err() {
                    for fb_fps in [240u32, 144, 120, 60] {
                        if fb_fps < hw_cfg.fps {
                            let mut fb_cfg = hw_cfg.clone();
                            fb_cfg.fps = fb_fps;
                            final_try = real_host_stack(&fb_cfg, existing_host_us);
                            if final_try.is_ok() {
                                break;
                            }
                        }
                    }
                }
                match final_try {
                    Ok((p, l, origin_us)) => {
                        *backend_label.lock().unwrap_or_else(|e| e.into_inner()) = l;
                        *clock_anchor
                            .origin
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = ClockOrigin::HostClock(origin_us);
                        hardware_video_active.store(true, Ordering::Release);
                        return Ok(p);
                    }
                    Err(err) => {
                        if hardware_video_active.load(Ordering::Acquire) {
                            // 活跃硬件会话热切换失败时绝不降级到 FakeEncoder（否则对端 VtDecoder
                            // 持续收到非 H.264 伪帧导致黑屏），直接返回错误；
                            // 若本次是 HEVC 尝试，HostSession 会透明回退 H.264，因此仅记录 stderr 不弹错误横幅。
                            let message = format!("硬件分辨率/帧率热切换失败：{err}");
                            eprintln!("[rc-ui-host] {message}");
                            if hw_cfg.codec != rc_encode::Codec::Hevc {
                                updates.push(HostUpdate::error(message));
                            }
                            return Err(err);
                        }
                        // 注意：在 macOS 上若 SCK / VideoToolbox 初始化失败（常见原因：缺少「屏幕录制」
                        // 权限或授权后尚未重启进程），降级为 FakeEncoder 会发送非 H.264/HEVC 伪帧，
                        // 对端若启用硬件 VtDecoder 将无法解出真实画面（表现为黑屏）。
                        // 因此绝不静默吞错：同时输出 stderr 诊断并向 UI 推送 `HostUpdate::Error`。
                        let message = format!(
                            "硬件屏幕采集/编码初始化失败（请确认已授予屏幕/录制权限），已降级为测试后端：{err}"
                        );
                        eprintln!("[rc-ui-host] {message}");
                        updates.push(HostUpdate::error(message));

                        hardware_video_active.store(false, Ordering::Release);
                        *backend_label.lock().unwrap_or_else(|e| e.into_inner()) =
                            "fake(降级)".to_string();
                        let existing_fake = match existing_origin {
                            ClockOrigin::Fake(a) => Some(a),
                            _ => None,
                        };
                        let (p, anchor) = fake_stack_anchored(pcfg, existing_fake)?;
                        *clock_anchor
                            .origin
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = ClockOrigin::Fake(anchor);
                        return Ok(p);
                    }
                }
            }
            hardware_video_active.store(false, Ordering::Release);
            *backend_label.lock().unwrap_or_else(|e| e.into_inner()) = "fake".to_string();
            let existing_fake = match existing_origin {
                ClockOrigin::Fake(a) => Some(a),
                _ => None,
            };
            let (p, anchor) = fake_stack_anchored(pcfg, existing_fake)?;
            *clock_anchor
                .origin
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = ClockOrigin::Fake(anchor);
            Ok(p)
        },
    )
}

/// 按平台与硬件偏好构造剪贴板后端：仅 `prefer_hardware == true` 时挂接本机真实剪贴板，
/// 离线假后端测试绝不触碰开发者真实系统剪贴板。
fn create_clipboard_backend(prefer_hardware: bool) -> Option<Box<dyn ClipboardBackend>> {
    if !prefer_hardware {
        return None;
    }
    rc_session::create_system_clipboard().ok()
}

/// 握手期可中断的传输层包装：在 `streaming_started == false` 期间响应 `stop_flag` / `disconnect_flag`，
/// 使 P2P QUIC 与 TCP 中继会话在握手/审批阶段均可在数毫秒内中止。
struct CancellableHostTransport {
    inner: Box<dyn Transport>,
    stop_flag: Arc<AtomicBool>,
    disconnect_flag: Arc<AtomicBool>,
    streaming_started: Arc<AtomicBool>,
}

impl Transport for CancellableHostTransport {
    fn send_datagram(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.inner.send_datagram(data)
    }

    fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.inner.send_reliable(data)
    }

    fn send_reliable_urgent(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.inner.send_reliable_urgent(data)
    }

    fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
        if !self.streaming_started.load(Ordering::Acquire)
            && (self.stop_flag.load(Ordering::Acquire)
                || self.disconnect_flag.load(Ordering::Acquire))
        {
            return Ok(vec![NetEvent::Disconnected {
                reason: "本机主动断开".to_string(),
            }]);
        }
        self.inner.poll(timeout)
    }

    fn stats(&self) -> NetStats {
        self.inner.stats()
    }

    fn set_pacing_rate(&mut self, bps: u64) {
        self.inner.set_pacing_rate(bps);
    }

    fn tx_queued_bytes(&self) -> usize {
        self.inner.tx_queued_bytes()
    }

    fn tx_dropped_datagrams(&self) -> u64 {
        self.inner.tx_dropped_datagrams()
    }
}

/// 构造一轮直连 QUIC `HostSession`（优先硬件注入/采集/编码，无权限或非 macOS 自动降级假栈）。
#[allow(clippy::too_many_arguments)]
fn build_host_session(
    listen_addr: SocketAddr,
    password: Option<String>,
    approval_timeout_us: u64,
    prefer_hardware: bool,
    clipboard_enabled: bool,
    allow_owner_control: bool,
    allow_remote_assist: bool,
    owner_verifier: Option<Arc<dyn OwnerTicketVerifier>>,
    owner_replay_cache: Arc<Mutex<rc_session::OwnerReplayCache>>,
    approver: Box<dyn ConnectionApprover>,
    updates: Arc<BoundedHostUpdateQueue>,
) -> Result<BuiltUiHost, String> {
    let (host_cfg, preserve_aspect) = default_host_session_config(
        listen_addr,
        password,
        approval_timeout_us,
        prefer_hardware,
        allow_owner_control,
        allow_remote_assist,
        owner_verifier,
        owner_replay_cache,
        approver,
    );

    let clock_anchor = HostClockAnchor::new_pending();
    let clock = make_session_clock(Arc::clone(&clock_anchor.origin));
    let backend_label: Arc<Mutex<String>> = Arc::new(Mutex::new(if prefer_hardware {
        "auto".to_string()
    } else {
        "fake".to_string()
    }));
    let hardware_video_active = Arc::new(AtomicBool::new(false));
    let wake_guard: SharedWakeGuard = Arc::new(Mutex::new(None));

    let factory = make_host_pipeline_factory(
        prefer_hardware,
        clock_anchor.clone(),
        Arc::clone(&backend_label),
        Arc::clone(&hardware_video_active),
        Arc::clone(&wake_guard),
        updates,
    );

    let mut host = HostSession::new(host_cfg, DEV_CERT_PEM, DEV_KEY_PEM, Arc::clone(&clock))
        .map_err(|e| format!("host 会话构造失败: {e}"))?;
    let _ = host.set_reconnect(rc_session::ReconnectConfig {
        resume_ttl: host_resume_ttl(HostTransportKind::Lan),
        ..rc_session::ReconnectConfig::default()
    });
    host.set_preserve_caps_aspect(preserve_aspect);
    host.set_pipeline_factory_for(factory);
    if clipboard_enabled {
        if let Some(cb) = create_clipboard_backend(prefer_hardware) {
            host.enable_clipboard(cb);
        }
    }

    Ok(BuiltUiHost {
        host,
        clock,
        clock_anchor,
        backend_label,
        hardware_video_active,
        wake_guard,
    })
}

/// 构造一轮基于已建立传输层（LAN mTLS、P2P QUIC 或 TCP `RCR1` 中继）的 `HostSession`。
#[allow(clippy::too_many_arguments)]
fn build_transport_host_session(
    listen_addr: SocketAddr,
    transport: Box<dyn Transport>,
    transport_kind: HostTransportKind,
    password: Option<String>,
    approval_timeout_us: u64,
    prefer_hardware: bool,
    clipboard_enabled: bool,
    allow_owner_control: bool,
    allow_remote_assist: bool,
    owner_verifier: Option<Arc<dyn OwnerTicketVerifier>>,
    owner_replay_cache: Arc<Mutex<rc_session::OwnerReplayCache>>,
    approver: Box<dyn ConnectionApprover>,
    updates: Arc<BoundedHostUpdateQueue>,
) -> Result<BuiltUiHost, String> {
    let (host_cfg, preserve_aspect) = default_host_session_config(
        listen_addr,
        password,
        approval_timeout_us,
        prefer_hardware,
        allow_owner_control,
        allow_remote_assist,
        owner_verifier,
        owner_replay_cache,
        approver,
    );

    let clock_anchor = HostClockAnchor::new_pending();
    let clock = make_session_clock(Arc::clone(&clock_anchor.origin));
    let backend_label: Arc<Mutex<String>> = Arc::new(Mutex::new(if prefer_hardware {
        "auto".to_string()
    } else {
        "fake".to_string()
    }));
    let hardware_video_active = Arc::new(AtomicBool::new(false));
    let wake_guard: SharedWakeGuard = Arc::new(Mutex::new(None));

    // 占位后端仅用于满足 `HostSession::with_parts` 签名；握手成功后优先执行
    // `set_pipeline_factory_for`，按裁定参数构建硬件/假栈并锚定会话钟零点。
    let placeholder_res = Resolution::new(64, 64);
    let dummy_capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
        display: rc_capture::DisplayInfo {
            id: rc_types::DisplayId(0),
            resolution: placeholder_res,
            scale: 1.0,
            hdr: false,
        },
        fps: 30,
        content: rc_capture::FakeContent::Static,
        dirty_rect: None,
    })
    .map_err(|e| format!("会话占位采集构造失败: {e}"))?;
    let dummy_encoder = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
        resolution: placeholder_res,
        fps: 30,
        bitrate_bps: 2_000_000,
        ..rc_encode::EncoderConfig::default()
    })
    .map_err(|e| format!("会话占位编码构造失败: {e}"))?;

    let mut host = HostSession::with_parts(
        host_cfg,
        transport,
        Box::new(dummy_capture),
        Box::new(dummy_encoder),
        Arc::clone(&clock),
    )
    .map_err(|e| format!("信令 host 会话构造失败: {e}"))?;
    let _ = host.set_reconnect(rc_session::ReconnectConfig {
        resume_ttl: host_resume_ttl(transport_kind),
        ..rc_session::ReconnectConfig::default()
    });
    host.set_preserve_caps_aspect(preserve_aspect);

    let factory = make_host_pipeline_factory(
        prefer_hardware,
        clock_anchor.clone(),
        Arc::clone(&backend_label),
        Arc::clone(&hardware_video_active),
        Arc::clone(&wake_guard),
        updates,
    );
    host.set_pipeline_factory_for(factory);
    if clipboard_enabled {
        if let Some(cb) = create_clipboard_backend(prefer_hardware) {
            host.enable_clipboard(cb);
        }
    }

    Ok(BuiltUiHost {
        host,
        clock,
        clock_anchor,
        backend_label,
        hardware_video_active,
        wake_guard,
    })
}

fn build_injector(prefer_hardware: bool) -> Box<dyn rc_input::InputInjector> {
    if prefer_hardware {
        if let Some(injector) = crate::platform::create_main_display_injector() {
            return injector;
        }
    }
    Box::new(RecordingInjector::new())
}

fn real_host_stack(
    hw_cfg: &PipelineConfig,
    existing_origin_us: Option<u64>,
) -> rc_types::Result<(rc_pipeline::HostPipeline, String, u64)> {
    let (encoder, el) = rc_pipeline::select_encoder_labeled(hw_cfg)?;
    let origin_us = match existing_origin_us {
        Some(o) => o,
        None => rc_pipeline::host_clock_us()
            .ok_or_else(|| rc_types::Error::InvalidConfig("平台未注册低延迟主机时钟".into()))?,
    };
    // 顺序红线：先锚定原点再建 SCK 流，保证硬件 PTS 与会话钟同域同零点。
    let mut pcfg = hw_cfg.clone();
    pcfg.clock_origin_us = Some(origin_us);
    let (capture, cl) = rc_pipeline::select_capture_labeled(&pcfg)?;
    if el == "fake" || cl == "fake" {
        return Err(rc_types::Error::InvalidConfig(format!(
            "real 后端要求真实硬件采集与编码，实际 {cl}+{el}"
        )));
    }
    let pipeline = rc_pipeline::HostPipeline::with_backends_paced(pcfg, capture, encoder, false)?;
    Ok((pipeline, format!("{cl}+{el}"), origin_us))
}

fn fake_stack_anchored(
    pcfg: &PipelineConfig,
    existing_anchor: Option<Instant>,
) -> rc_types::Result<(rc_pipeline::HostPipeline, Instant)> {
    let anchor = existing_anchor.unwrap_or_else(Instant::now);
    let capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
        display: rc_capture::DisplayInfo {
            id: rc_types::DisplayId(0),
            resolution: pcfg.resolution,
            scale: 1.0,
            hdr: false,
        },
        fps: pcfg.fps,
        content: rc_capture::FakeContent::Dynamic,
        dirty_rect: None,
    })?;
    let pixels = pcfg.resolution.width as usize * pcfg.resolution.height as usize;
    const SINGLE_PACKET_PAYLOAD: usize = 1_088;
    let output_bytes = (pixels / 8).clamp(128, SINGLE_PACKET_PAYLOAD);
    let encoder = rc_encode::FakeEncoder::with_tuning(
        rc_encode::EncoderConfig {
            resolution: pcfg.resolution,
            fps: pcfg.fps,
            bitrate_bps: pcfg.bitrate_bps,
            ..rc_encode::EncoderConfig::default()
        },
        FAKE_ENCODE_COST_US,
        output_bytes,
    )?;
    let pipeline = rc_pipeline::HostPipeline::with_backends_paced(
        pcfg.clone(),
        Box::new(WallCapture {
            inner: Box::new(capture),
            anchor,
        }),
        Box::new(encoder),
        true,
    )?;
    Ok((pipeline, anchor))
}

struct WallCapture {
    inner: Box<dyn rc_capture::CaptureBackend>,
    anchor: Instant,
}

impl rc_capture::CaptureBackend for WallCapture {
    fn next_frame(
        &mut self,
        timeout: Duration,
    ) -> rc_types::Result<Option<rc_capture::CapturedFrame>> {
        match self.inner.next_frame(timeout)? {
            Some(mut frame) => {
                frame.timestamp = rc_types::Timestamp(
                    u32::try_from(self.anchor.elapsed().as_micros()).unwrap_or(u32::MAX),
                );
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    fn poll_invalidation(&mut self) -> Option<rc_capture::InvalidationReason> {
        self.inner.poll_invalidation()
    }

    fn rebuild(&mut self) -> rc_types::Result<()> {
        self.inner.rebuild()
    }

    fn display_info(&self) -> rc_capture::DisplayInfo {
        self.inner.display_info()
    }

    fn last_dirty_rects(&self) -> &[rc_types::Rect] {
        self.inner.last_dirty_rects()
    }
}

fn format_display_addr(actual: SocketAddr) -> String {
    if actual.ip().is_unspecified() {
        let ip = lan_discovery::detect_local_lan_ipv4().unwrap_or(Ipv4Addr::LOCALHOST);
        format!("{ip}:{}", actual.port())
    } else {
        actual.to_string()
    }
}

// ─────────────────────────────────────────────────────────────────
// HostHandle（公开 API）
// ─────────────────────────────────────────────────────────────────

/// 被控端向控制端回传 `ToolPermissionDenied` 的单通道最小节流间隔（1s）。
const TOOL_PERMISSION_DENIED_THROTTLE: Duration = Duration::from_secs(1);

/// 按会话归属（是否通过 Ed25519 PoP `OwnerTicket` 自控认证）与远程协助文件开关计算生效工具权限。
///
/// 安全红线：仅 `is_owner_session == true` 豁免保持全开；所有非 Owner 会话均受 `allow_assist_file_transfer` 门控。
fn compute_effective_tool_permissions(
    is_owner_session: bool,
    allow_assist_file_transfer: bool,
) -> rc_session::ToolPermissions {
    if is_owner_session {
        rc_session::ToolPermissions::all_allowed()
    } else {
        rc_session::ToolPermissions {
            allow_file_transfer: allow_assist_file_transfer,
            allow_terminal: true,
            allow_port_map: true,
        }
    }
}

fn encode_tool_permissions_state(perms: rc_session::ToolPermissions) -> Option<Vec<u8>> {
    display_ctrl::encode_display_ctrl(&DisplayControlMsg::ToolPermissionsState {
        allow_file_transfer: perms.allow_file_transfer,
        allow_terminal: perms.allow_terminal,
        allow_port_map: perms.allow_port_map,
    })
}

/// UI 侧被控端服务句柄：管理单会话循环工作线程、审批桥与优雅停机。
pub struct HostHandle {
    listen_addr: Arc<Mutex<SocketAddr>>,
    updates: Arc<BoundedHostUpdateQueue>,
    approver: UiApprover,
    password_state: Arc<Mutex<PasswordState>>,
    password_version: Arc<AtomicU64>,
    auth_state: Arc<Mutex<AuthRuntimeState>>,
    config_version: Arc<AtomicU64>,
    relay_incoming: Arc<BoundedRelayIncomingQueue>,
    active_relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    disconnect_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    close_reason: Arc<AtomicU8>,
    running: Arc<AtomicBool>,
    lock_screen_count: Arc<AtomicU64>,
    file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

enum HostListener {
    Plain(Box<BuiltUiHost>),
    MtlsLan { endpoint: QuicEndpoint },
    AwaitingMtlsCert,
}

fn bind_mtls_lan_endpoint(
    listen_addr: SocketAddr,
    bundle: &SessionMtlsBundle,
) -> Result<QuicEndpoint, String> {
    // LAN 直连监听端接受任意同 CA 设备（客户端证书 SAN 验证其身份）；expected_peer_device_id 置 None。
    let mut server_bundle = bundle.clone();
    server_bundle.expected_peer_device_id = None;
    server_bundle.expected_peer_user_id = None;
    let mtls_cfg = server_bundle.to_quic_mtls_config()?;
    QuicEndpoint::new_mtls(&NetConfig::new(Role::Host, listen_addr), &mtls_cfg)
        .map_err(|e| format!("mTLS LAN 监听器绑定失败: {e}"))
}

impl HostHandle {
    /// 启动被控端服务：先同步绑定 QUIC 监听端口（默认 `9901` 冲突时自动回退临时端口），
    /// 随后派发后台单会话循环线程。
    pub fn spawn(cfg: UiHostConfig) -> Result<Self, String> {
        let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
        let approver = UiApprover::new(
            Arc::clone(&updates),
            cfg.auto_accept_with_password,
            cfg.allow_owner_control && cfg.allow_remote_assist,
        );
        let password_state = Arc::new(Mutex::new(PasswordState {
            password: cfg.password.clone(),
            auto_rotate: cfg.auto_rotate_password,
        }));
        let password_version = Arc::new(AtomicU64::new(0));
        let shared_owner_replay = Arc::new(Mutex::new(rc_session::OwnerReplayCache::new()));
        let auth_state = Arc::new(Mutex::new(AuthRuntimeState {
            allow_owner_control: cfg.allow_owner_control,
            allow_remote_assist: cfg.allow_remote_assist,
            owner_verifier: cfg.owner_verifier.clone(),
            owner_replay_cache: Arc::clone(&shared_owner_replay),
            mtls_config: cfg.mtls_config.clone(),
            accept_mtls_lan: cfg.accept_mtls_lan,
        }));
        let config_version = Arc::new(AtomicU64::new(0));
        let relay_incoming = Arc::new(BoundedRelayIncomingQueue::new(RELAY_INCOMING_QUEUE_CAP));
        let active_relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>> =
            Arc::new(Mutex::new(None));
        let disconnect_flag = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let close_reason = Arc::new(AtomicU8::new(ByeReason::Normal as u8));
        let running = Arc::new(AtomicBool::new(true));
        let lock_screen_count = Arc::new(AtomicU64::new(0));
        let file_transfer_dir: SharedFileTransferDir =
            Arc::new(RwLock::new(cfg.file_transfer_dir.clone()));
        let allow_assist_file_transfer = Arc::new(AtomicBool::new(cfg.allow_assist_file_transfer));

        let make_approver = |require: bool, ui: &UiApprover| -> Box<dyn ConnectionApprover> {
            if require {
                Box::new(ui.clone())
            } else {
                Box::new(AutoApprover)
            }
        };

        // 先在 spawn 内绑定首轮监听器（普通 QUIC HostSession 或 mTLS LAN QuicEndpoint），使 listen_addr() 同步立即可用。
        // 在系统后台服务切换会话（LoginWindow → Aqua）时，短轮询退避等待旧 Agent 释放 9901 端口，避免落入临时随机端口。
        let service_bind_retries = if cfg.listen_addr.port() == DEFAULT_HOST_PORT
            && crate::config_paths::is_service_managed()
        {
            8
        } else {
            0
        };
        let (first_listener, actual_addr) = if cfg.accept_mtls_lan {
            match cfg.mtls_config.as_ref() {
                Some(bundle) => {
                    let mut ep_res = bind_mtls_lan_endpoint(cfg.listen_addr, bundle);
                    for _ in 0..service_bind_retries {
                        if ep_res.is_ok() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(80));
                        ep_res = bind_mtls_lan_endpoint(cfg.listen_addr, bundle);
                    }
                    let ep = match ep_res {
                        Ok(ep) => ep,
                        Err(_) if cfg.listen_addr.port() == DEFAULT_HOST_PORT => {
                            let fallback_addr = SocketAddr::new(cfg.listen_addr.ip(), 0);
                            bind_mtls_lan_endpoint(fallback_addr, bundle)?
                        }
                        Err(e) => return Err(e),
                    };
                    let actual = ep
                        .local_addr()
                        .map_err(|e| format!("无法获取 mTLS LAN 实际监听地址: {e}"))?;
                    (HostListener::MtlsLan { endpoint: ep }, actual)
                }
                None => {
                    let resolved_addr = if cfg.listen_addr.port() == 0 {
                        std::net::UdpSocket::bind(cfg.listen_addr)
                            .and_then(|s| s.local_addr())
                            .unwrap_or(cfg.listen_addr)
                    } else {
                        cfg.listen_addr
                    };
                    (HostListener::AwaitingMtlsCert, resolved_addr)
                }
            }
        } else {
            let initial_allow_remote = cfg.allow_owner_control
                && cfg.allow_remote_assist
                && (!cfg.forbid_passwordless_auto_approve
                    || cfg.require_approval
                    || cfg.password.is_some());
            let mut built_res = build_host_session(
                cfg.listen_addr,
                cfg.password.clone(),
                cfg.approval_timeout_us,
                cfg.prefer_hardware,
                cfg.clipboard_enabled,
                cfg.allow_owner_control,
                initial_allow_remote,
                cfg.owner_verifier.clone(),
                Arc::clone(&shared_owner_replay),
                make_approver(cfg.require_approval, &approver),
                Arc::clone(&updates),
            );
            for _ in 0..service_bind_retries {
                if built_res.is_ok() {
                    break;
                }
                thread::sleep(Duration::from_millis(80));
                built_res = build_host_session(
                    cfg.listen_addr,
                    cfg.password.clone(),
                    cfg.approval_timeout_us,
                    cfg.prefer_hardware,
                    cfg.clipboard_enabled,
                    cfg.allow_owner_control,
                    initial_allow_remote,
                    cfg.owner_verifier.clone(),
                    Arc::clone(&shared_owner_replay),
                    make_approver(cfg.require_approval, &approver),
                    Arc::clone(&updates),
                );
            }
            let first_built = match built_res {
                Ok(built) => built,
                Err(_) if cfg.listen_addr.port() == DEFAULT_HOST_PORT => {
                    let fallback_addr = SocketAddr::new(cfg.listen_addr.ip(), 0);
                    build_host_session(
                        fallback_addr,
                        cfg.password.clone(),
                        cfg.approval_timeout_us,
                        cfg.prefer_hardware,
                        cfg.clipboard_enabled,
                        cfg.allow_owner_control,
                        initial_allow_remote,
                        cfg.owner_verifier.clone(),
                        Arc::clone(&shared_owner_replay),
                        make_approver(cfg.require_approval, &approver),
                        Arc::clone(&updates),
                    )?
                }
                Err(e) => return Err(e),
            };
            let actual = first_built
                .host
                .local_addr()
                .map_err(|e| format!("无法获取实际监听地址: {e}"))?;
            (HostListener::Plain(Box::new(first_built)), actual)
        };

        let worker_opts = HostWorkerOptions {
            approval_timeout_us: cfg.approval_timeout_us,
            prefer_hardware: cfg.prefer_hardware,
            require_approval: cfg.require_approval,
            clipboard_enabled: cfg.clipboard_enabled,
            audio_enabled: cfg.audio_enabled,
            forbid_passwordless_auto_approve: cfg.forbid_passwordless_auto_approve,
            ephemeral_listen_port: cfg.listen_addr.port() == 0,
            allow_assist_file_transfer: Arc::clone(&allow_assist_file_transfer),
        };

        let t_updates = Arc::clone(&updates);
        let t_approver = approver.clone();
        let t_password_state = Arc::clone(&password_state);
        let t_pw_ver = Arc::clone(&password_version);
        let t_auth_state = Arc::clone(&auth_state);
        let t_cfg_ver = Arc::clone(&config_version);
        let t_relay_incoming = Arc::clone(&relay_incoming);
        let t_active_relay_interrupt = Arc::clone(&active_relay_interrupt);
        let t_disconnect = Arc::clone(&disconnect_flag);
        let t_stop = Arc::clone(&stop_flag);
        let t_close_reason = Arc::clone(&close_reason);
        let t_running = Arc::clone(&running);
        let t_lock_screen_count = Arc::clone(&lock_screen_count);
        let t_file_transfer_dir = Arc::clone(&file_transfer_dir);

        let listen_addr_shared = Arc::new(Mutex::new(actual_addr));
        let t_listen_addr = Arc::clone(&listen_addr_shared);

        let handle = thread::Builder::new()
            .name("rc-ui-host".to_string())
            .spawn(move || {
                crate::platform::promote_current_thread_qos();

                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_host_worker(
                        actual_addr,
                        t_listen_addr,
                        worker_opts,
                        first_listener,
                        Arc::clone(&t_updates),
                        t_approver,
                        t_password_state,
                        t_pw_ver,
                        t_auth_state,
                        t_cfg_ver,
                        t_relay_incoming,
                        t_active_relay_interrupt,
                        t_disconnect,
                        t_stop,
                        t_close_reason,
                        t_lock_screen_count,
                        t_file_transfer_dir,
                    )
                }));
                if res.is_err() {
                    t_updates.push(HostUpdate::error("被控端工作线程异常退出"));
                }
                // M8：先清除 running 标记再推送 Stopped，消除轮询器读到 Stopped 时 is_running 仍为 true 的竞态。
                t_running.store(false, Ordering::Release);
                t_updates.push(HostUpdate::Stopped);
            })
            .expect("spawn rc-ui-host thread");

        Ok(Self {
            listen_addr: listen_addr_shared,
            updates,
            approver,
            password_state,
            password_version,
            auth_state,
            config_version,
            relay_incoming,
            active_relay_interrupt,
            disconnect_flag,
            stop_flag,
            close_reason,
            running,
            lock_screen_count,
            file_transfer_dir,
            allow_assist_file_transfer,
            thread: Some(handle),
        })
    }

    /// 统计本 Host 实例收到并执行的远端锁屏请求次数（供集成测试与诊断验证）。
    pub fn lock_screen_count(&self) -> u64 {
        self.lock_screen_count.load(Ordering::Acquire)
    }

    /// 返回实际绑定的监听地址（已解析临时端口，并在端口回退后实时更新）。
    pub fn listen_addr(&self) -> SocketAddr {
        *self.listen_addr.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 工作线程是否仍在运行。
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// 非阻塞拉取一条被控端状态更新。
    pub fn try_recv_update(&self) -> Option<HostUpdate> {
        self.updates.try_pop()
    }

    /// 向被控端工作线程投递一条信令服务器下发的入站中继会话请求（有界非阻塞，容量 8，满载丢最旧）。
    pub fn offer_relay_incoming(&self, incoming: RelayIncoming) {
        self.relay_incoming.push(incoming);
    }

    /// 回写机主连接审批裁决（仅在途且代次匹配时生效）。
    pub fn respond_approval(&self, generation: u64, accepted: bool) -> bool {
        self.approver.resolve(generation, accepted)
    }

    /// 更新访问密码与会话结束自动轮换策略（对下一次新握手生效）。
    pub fn set_password_mode(&self, password: Option<String>, auto_rotate: bool) {
        {
            let mut st = self
                .password_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            st.password = password;
            st.auto_rotate = auto_rotate;
        }
        self.password_version.fetch_add(1, Ordering::AcqRel);
    }

    /// 更新访问密码（保留既有自动轮换策略，对下一次新握手生效）。
    pub fn set_password(&self, password: Option<String>) {
        {
            let mut st = self
                .password_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            st.password = password;
        }
        self.password_version.fetch_add(1, Ordering::AcqRel);
    }

    /// 运行时切换是否允许本机被远程控制（含同账号本人自控与他人远程协助总门控；对下一次新握手生效，关闭时同步拒收在途审批）。
    pub fn set_allow_owner_control(&self, allow: bool) {
        let effective_assist = {
            let mut st = self.auth_state.lock().unwrap_or_else(|e| e.into_inner());
            st.allow_owner_control = allow;
            st.allow_owner_control && st.allow_remote_assist
        };
        self.approver.set_remote_assist_enabled(effective_assist);
        self.config_version.fetch_add(1, Ordering::AcqRel);
        if !allow {
            self.approver.reject_in_flight();
        }
    }

    /// 运行时切换是否允许他人远程协助（对下一次新握手生效，关闭时同步拒收在途审批，本人同账号自控不受影响）。
    pub fn set_allow_remote_assist(&self, allow: bool) {
        let effective_assist = {
            let mut st = self.auth_state.lock().unwrap_or_else(|e| e.into_inner());
            st.allow_remote_assist = allow;
            st.allow_owner_control && st.allow_remote_assist
        };
        self.approver.set_remote_assist_enabled(effective_assist);
        self.config_version.fetch_add(1, Ordering::AcqRel);
        if !effective_assist {
            self.approver.reject_in_flight();
        }
    }

    /// 运行时注入或清除同账号 `OwnerTicket` 验签器（对下一次新握手生效，切换账号或置 `None` 时立即吊销旧账号的后台终端）。
    pub fn set_owner_verifier(&self, verifier: Option<Arc<dyn OwnerTicketVerifier>>) {
        {
            let mut st = self.auth_state.lock().unwrap_or_else(|e| e.into_inner());
            st.owner_verifier = verifier;
        }
        self.config_version.fetch_add(1, Ordering::AcqRel);
    }

    /// 运行时更新双向 mTLS 证书束与 LAN mTLS 监听开关（对下一次监听与入站会话生效）。
    pub fn set_mtls_config(&self, mtls_config: Option<SessionMtlsBundle>, accept_mtls_lan: bool) {
        {
            let mut st = self.auth_state.lock().unwrap_or_else(|e| e.into_inner());
            st.mtls_config = mtls_config;
            st.accept_mtls_lan = accept_mtls_lan;
        }
        self.config_version.fetch_add(1, Ordering::AcqRel);
    }

    /// 动态更新被控端 W2 文件传输默认接收目录（对当前及后续会话实时生效）。
    pub fn set_file_transfer_dir(&self, dir: Option<PathBuf>) {
        let mut guard = self
            .file_transfer_dir
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = dir;
    }

    /// 运行期热更新「他人远程协助时是否允许文件传输」（即时对当前活跃非 Owner 会话及后续会话生效，不中断会话）。
    ///
    /// 同账号本人通过 Ed25519 PoP `OwnerTicket` 建立的自控会话始终豁免保持全开。
    pub fn set_allow_assist_file_transfer(&self, allowed: bool) {
        self.allow_assist_file_transfer
            .store(allowed, Ordering::Release);
    }

    /// 查询当前「他人远程协助时是否允许文件传输」配置开关。
    pub fn allow_assist_file_transfer(&self) -> bool {
        self.allow_assist_file_transfer.load(Ordering::Acquire)
    }

    /// 主动断开当前已连接的控制端会话（触发优雅 `Bye` / 中继即时断流，被控端继续等待新连接）。
    pub fn disconnect_client(&self) {
        self.disconnect_flag.store(true, Ordering::Release);
        let interrupt = self
            .active_relay_interrupt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(h) = interrupt {
            h.interrupt();
        }
    }

    /// 停止被控端服务并指定向在途控制端发送的 `ByeReason`（供 LoginWindow→Aqua 切换通知自动重连）。
    pub fn stop_with_reason(&mut self, reason: ByeReason) {
        self.close_reason.store(reason as u8, Ordering::Release);
        self.stop();
    }

    /// 停止被控端服务并等待工作线程回收（幂等；常规停机可立即中断在途中继拨号与会话）。
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Release);
        self.disconnect_flag.store(true, Ordering::Release);
        self.approver.mark_stopped();
        let preserve_connected_for_bye =
            self.close_reason.load(Ordering::Acquire) != ByeReason::Normal as u8;
        let interrupt = self
            .active_relay_interrupt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(h) = interrupt {
            match h {
                ActiveRelayInterrupt::Dialing(_) => h.interrupt(),
                ActiveRelayInterrupt::Connected(_) if !preserve_connected_for_bye => h.interrupt(),
                // 会话切换时先保留已建立的中继 TCP 流，`stop_flag` 会在 <=2ms 内驱动工作线程优雅发出 `Bye(SessionSwitching)`。
                ActiveRelayInterrupt::Connected(_) => {}
            }
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug, Clone)]
struct HostWorkerOptions {
    approval_timeout_us: u64,
    prefer_hardware: bool,
    require_approval: bool,
    clipboard_enabled: bool,
    audio_enabled: bool,
    forbid_passwordless_auto_approve: bool,
    ephemeral_listen_port: bool,
    allow_assist_file_transfer: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostTransportKind {
    Lan,
    MtlsLan,
    P2p,
    Relay,
}

fn host_resume_ttl(transport_kind: HostTransportKind) -> Duration {
    match transport_kind {
        HostTransportKind::Relay | HostTransportKind::P2p => Duration::ZERO,
        HostTransportKind::Lan | HostTransportKind::MtlsLan => HOST_LAN_RESUME_TTL,
    }
}

fn next_audio_recovery_backoff(cur: Duration) -> Duration {
    if cur < AUDIO_RECOVERY_MID_BACKOFF {
        AUDIO_RECOVERY_MID_BACKOFF
    } else {
        AUDIO_RECOVERY_MAX_BACKOFF
    }
}

/// 在独立后台线程异步拉起系统音频采集器，绝不在 `Welcome` 后同步阻塞首帧出图（H13）。
/// 若会话在后台线程完成前退出并丢弃接收端，后台线程立即停止并释放刚创建的采集器。
fn spawn_audio_capture_init() -> mpsc::Receiver<Box<dyn AudioCapture>> {
    spawn_audio_capture_init_with(rc_audio::create_system_audio_capture)
}

fn spawn_audio_capture_init_with<F>(creator: F) -> mpsc::Receiver<Box<dyn AudioCapture>>
where
    F: FnOnce() -> Result<Box<dyn AudioCapture>, String> + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel::<Box<dyn AudioCapture>>(1);
    let _ = thread::Builder::new()
        .name("rc-audio-cap-init".to_string())
        .spawn(move || {
            if let Ok(cap) = creator() {
                if let Err(mpsc::SendError(mut cap)) = tx.send(cap) {
                    cap.stop();
                    drop(cap);
                }
            }
        });
    rx
}

type AudioCaptureCreator = Arc<dyn Fn() -> Result<Box<dyn AudioCapture>, String> + Send + Sync>;

/// 被控端音频采集生命周期与有界退避自愈管理器（`300ms -> 1s -> 2s`）：
/// - 检测底层 `AudioCapture::is_stopped()`（如 macOS 改物理分辨率或切屏导致 SCStream 中止）时立即停止并重建；
/// - 异步初始化失败（如锁屏期无音频流）按有界退避重试；
/// - 纯工具态 `media_paused == true` 时主动停流且禁止拉起自愈。
struct HostAudioManager {
    enabled: bool,
    capture: Option<Box<dyn AudioCapture>>,
    started_at: Option<Instant>,
    init_rx: Option<mpsc::Receiver<Box<dyn AudioCapture>>>,
    retry_at: Option<Instant>,
    retry_backoff: Duration,
    creator: Option<AudioCaptureCreator>,
}

impl HostAudioManager {
    fn new(enabled: bool) -> Self {
        let mut mgr = Self {
            enabled,
            capture: None,
            started_at: None,
            init_rx: None,
            retry_at: None,
            retry_backoff: AUDIO_RECOVERY_INITIAL_BACKOFF,
            creator: None,
        };
        if enabled {
            mgr.start_init();
        }
        mgr
    }

    #[cfg(test)]
    fn with_creator(
        enabled: bool,
        initial_capture: Option<Box<dyn AudioCapture>>,
        creator: AudioCaptureCreator,
    ) -> Self {
        let started_at = initial_capture.as_ref().map(|_| Instant::now());
        let mut mgr = Self {
            enabled,
            capture: initial_capture,
            started_at,
            init_rx: None,
            retry_at: None,
            retry_backoff: AUDIO_RECOVERY_INITIAL_BACKOFF,
            creator: Some(creator),
        };
        if enabled && mgr.capture.is_none() {
            mgr.start_init();
        }
        mgr
    }

    fn start_init(&mut self) {
        if !self.enabled {
            return;
        }
        let rx = match &self.creator {
            Some(factory) => {
                let f = Arc::clone(factory);
                spawn_audio_capture_init_with(move || f())
            }
            None => spawn_audio_capture_init(),
        };
        self.init_rx = Some(rx);
    }

    fn pause(&mut self, silence_gate: &mut AudioSilenceGate) {
        self.stop_all();
        silence_gate.reset();
        self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
    }

    fn resume(&mut self, silence_gate: &mut AudioSilenceGate) {
        if !self.enabled {
            return;
        }
        silence_gate.reset();
        self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
        self.retry_at = None;
        if self.capture.is_none() && self.init_rx.is_none() {
            self.start_init();
        }
    }

    fn reset_backoff_for_display_change(&mut self, now: Instant) {
        self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
        let fast_at = now + AUDIO_RECOVERY_INITIAL_BACKOFF;
        if self.retry_at.is_some_and(|at| at > fast_at) {
            self.retry_at = Some(fast_at);
        }
    }

    fn poll_and_recover(
        &mut self,
        now: Instant,
        media_paused: bool,
        silence_gate: &mut AudioSilenceGate,
    ) {
        if !self.enabled || media_paused {
            return;
        }

        if let Some(cap) = self.capture.as_ref() {
            let stable = self.started_at.is_some_and(|at| {
                now.saturating_duration_since(at) >= AUDIO_RECOVERY_STABLE_WINDOW
            });
            if cap.is_stopped() {
                if stable {
                    self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
                }
                if let Some(mut old) = self.capture.take() {
                    old.stop();
                }
                self.started_at = None;
                silence_gate.reset();
                let delay = self.retry_backoff;
                self.retry_at = Some(now + delay);
                self.retry_backoff = next_audio_recovery_backoff(delay);
                eprintln!(
                    "[rc-ui-host] 检测到系统音频采集已中止，预约 {}ms 后自动重建",
                    delay.as_millis()
                );
            } else if stable {
                self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
            }
        }

        if self.capture.is_none() {
            if let Some(ref rx) = self.init_rx {
                match rx.try_recv() {
                    Ok(cap) => {
                        self.capture = Some(cap);
                        self.started_at = Some(now);
                        self.init_rx = None;
                        self.retry_at = None;
                        // 不在刚创建时立即复位 retry_backoff：需稳定存活 >= 5s 后才复位回 300ms，
                        // 防止采集器刚创建即 is_stopped() 退化为固定 300ms 高频重建抖动。
                        silence_gate.reset();
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.init_rx = None;
                        let delay = self.retry_backoff;
                        self.retry_at = Some(now + delay);
                        self.retry_backoff = next_audio_recovery_backoff(delay);
                    }
                }
            }
        }

        if self.capture.is_none()
            && self.init_rx.is_none()
            && self.retry_at.is_some_and(|at| now >= at)
        {
            self.retry_at = None;
            self.start_init();
        }
    }

    fn capture_mut(&mut self) -> Option<&mut Box<dyn AudioCapture>> {
        self.capture.as_mut()
    }

    fn stop_all(&mut self) {
        // 先释放异步初始化接收端，确保尚未完成的 `rc-audio-cap-init` 线程立即感知并停止释放采集器（H13）。
        self.init_rx = None;
        if let Some(ref mut cap) = self.capture {
            cap.stop();
        }
        self.capture = None;
        self.started_at = None;
        self.retry_at = None;
    }
}

impl Drop for HostAudioManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}

struct DriveSessionOutcome {
    reason: String,
    preempted_by_incoming: bool,
}

/// 单通道无丢帧重试冲刷：
/// - 若 `pending` 非空，先冲刷待重试帧且不继续拉取引擎（避免回压期无界堆积）；
/// - 仅当 `pending` 为空时从引擎最多拉取 `max_frames` 帧；
/// - 任意帧发送返回 `Err`（如 TCP 中继背压）时立即停止并保留该帧及后续已拉取帧，
///   下一拍严格按 FIFO 顺序重试，确保可靠工具通道零丢块。
fn flush_tool_channel_with_retry_checked<E>(
    pending: &mut VecDeque<Vec<u8>>,
    max_frames: usize,
    poll_fn: impl FnOnce(usize) -> Vec<Vec<u8>>,
    mut send_fn: impl FnMut(Vec<u8>) -> Result<(), E>,
    is_fatal_err: impl Fn(&E) -> bool,
) -> bool {
    if pending.is_empty() {
        pending.extend(poll_fn(max_frames));
    }
    let mut sent_any = false;
    while let Some(front) = pending.front() {
        match send_fn(front.clone()) {
            Ok(()) => {
                pending.pop_front();
                sent_any = true;
            }
            Err(ref e) if is_fatal_err(e) => {
                pending.pop_front();
            }
            Err(_) => break,
        }
    }
    sent_any
}

fn flush_tool_channel_with_retry<E>(
    pending: &mut VecDeque<Vec<u8>>,
    max_frames: usize,
    poll_fn: impl FnOnce(usize) -> Vec<Vec<u8>>,
    send_fn: impl FnMut(Vec<u8>) -> Result<(), E>,
) -> bool {
    flush_tool_channel_with_retry_checked(pending, max_frames, poll_fn, send_fn, |_| false)
}

/// Host 侧专用文件传输工作线程（H12）：将 `list_local_dir` / `write_all` / `sync_all` (`F_FULLFSYNC`)
/// 与 `fs::rename` 全部移出 60fps 视频采集/编码主线程，出入站均采用有界通道（容量 64），
/// 会话结束或权限热关闭析构时立即置位 `cancel`、丢弃 `in_rx` 缓冲帧并回收线程，确保 `FileHostEngine::drop`
/// 及时清理未完成 `.rcpart` 且绝不继续写盘或 `fs::rename` 落盘。
struct FileHostWorker {
    in_tx: Option<mpsc::SyncSender<Vec<u8>>>,
    out_rx: Option<mpsc::Receiver<Vec<u8>>>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FileHostWorker {
    fn spawn(default_receive_dir: SharedFileTransferDir) -> Self {
        let (in_tx, in_rx) = mpsc::sync_channel::<Vec<u8>>(FILE_HOST_WORKER_CHAN_CAP);
        let (out_tx, out_rx) = mpsc::sync_channel::<Vec<u8>>(FILE_HOST_WORKER_CHAN_CAP);
        let cancel = Arc::new(AtomicBool::new(false));
        let t_cancel = Arc::clone(&cancel);
        let handle = thread::Builder::new()
            .name("rc-file-host-worker".to_string())
            .spawn(move || {
                let mut applied_dir = default_receive_dir
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                let mut engine =
                    FileHostEngine::new().with_default_receive_dir(applied_dir.clone());
                let mut pending_out: VecDeque<Vec<u8>> = VecDeque::new();
                let sync_receive_dir =
                    |shared: &RwLock<Option<PathBuf>>,
                     applied: &mut Option<PathBuf>,
                     engine: &mut FileHostEngine| {
                        let guard = shared.read().unwrap_or_else(|e| e.into_inner());
                        if &*guard != applied {
                            let current = guard.clone();
                            drop(guard);
                            *applied = current.clone();
                            engine.set_default_receive_dir(current);
                        }
                    };

                loop {
                    if t_cancel.load(Ordering::Acquire) {
                        return;
                    }
                    let mut did_work = false;

                    // 1) 每轮最多先处理 MAX_TOOL_FRAMES_PER_TICK 条入站线帧，避免饿死出站 ACK/Cancel。
                    //    每次消费前均复查 cancel，防止 Drop 关闭发送端后仍排空 in_rx 缓冲的 UploadChunk/UploadFinish 写盘落盘。
                    for _ in 0..MAX_TOOL_FRAMES_PER_TICK {
                        if t_cancel.load(Ordering::Acquire) {
                            return;
                        }
                        match in_rx.try_recv() {
                            Ok(payload) => {
                                if t_cancel.load(Ordering::Acquire) {
                                    return;
                                }
                                sync_receive_dir(
                                    &default_receive_dir,
                                    &mut applied_dir,
                                    &mut engine,
                                );
                                engine.handle_incoming(&payload);
                                did_work = true;
                            }
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => return,
                        }
                    }

                    if t_cancel.load(Ordering::Acquire) {
                        return;
                    }

                    // 2) 待发送缓冲为空时从引擎拉取一批出站线帧。
                    if pending_out.is_empty() {
                        let frames = engine.poll_outgoing(MAX_TOOL_FRAMES_PER_TICK);
                        if !frames.is_empty() {
                            pending_out.extend(frames);
                            did_work = true;
                        }
                    }

                    // 3) 非阻塞投递至有界出站通道；满载时暂停投递并继续监听入站 Cancel。
                    let mut out_full = false;
                    while let Some(front) = pending_out.front() {
                        if t_cancel.load(Ordering::Acquire) {
                            return;
                        }
                        match out_tx.try_send(front.clone()) {
                            Ok(()) => {
                                pending_out.pop_front();
                                did_work = true;
                            }
                            Err(mpsc::TrySendError::Full(_)) => {
                                out_full = true;
                                break;
                            }
                            Err(mpsc::TrySendError::Disconnected(_)) => return,
                        }
                    }

                    // 4) 背压或完全空闲时高效泊车，不空转 CPU。
                    let has_more_work =
                        !pending_out.is_empty() || engine.active_download_count() > 0;
                    if out_full {
                        match in_rx.recv_timeout(Duration::from_millis(2)) {
                            Ok(payload) => {
                                if t_cancel.load(Ordering::Acquire) {
                                    return;
                                }
                                sync_receive_dir(
                                    &default_receive_dir,
                                    &mut applied_dir,
                                    &mut engine,
                                );
                                engine.handle_incoming(&payload);
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                            Err(mpsc::RecvTimeoutError::Disconnected) => return,
                        }
                    } else if !did_work && !has_more_work {
                        match in_rx.recv() {
                            Ok(payload) => {
                                if t_cancel.load(Ordering::Acquire) {
                                    return;
                                }
                                sync_receive_dir(
                                    &default_receive_dir,
                                    &mut applied_dir,
                                    &mut engine,
                                );
                                engine.handle_incoming(&payload);
                            }
                            Err(_) => return,
                        }
                    }
                }
            })
            .expect("spawn rc-file-host-worker thread");

        Self {
            in_tx: Some(in_tx),
            out_rx: Some(out_rx),
            cancel,
            thread: Some(handle),
        }
    }

    fn try_send_incoming(&self, frame: Vec<u8>) -> Result<(), mpsc::TrySendError<Vec<u8>>> {
        match self.in_tx.as_ref() {
            Some(tx) => tx.try_send(frame),
            None => Err(mpsc::TrySendError::Disconnected(frame)),
        }
    }

    fn try_recv_outgoing(&self, max_frames: usize) -> Vec<Vec<u8>> {
        let Some(rx) = self.out_rx.as_ref() else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(max_frames.min(MAX_TOOL_FRAMES_PER_TICK));
        for _ in 0..max_frames {
            match rx.try_recv() {
                Ok(frame) => out.push(frame),
                Err(_) => break,
            }
        }
        out
    }
}

impl Drop for FileHostWorker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        self.in_tx.take();
        self.out_rx.take();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// 解析来自控制端 `TOOL_CHANNEL_AUDIO_CTRL` 的静音控制 JSON（`{"muted": bool}`）。
fn parse_audio_ctrl_muted(payload: &[u8]) -> Option<bool> {
    let val: serde_json::Value = serde_json::from_slice(payload).ok()?;
    val.get("muted").and_then(serde_json::Value::as_bool)
}

/// 计算本会话被控端的原生逻辑分辨率与最高输出分辨率上界（封顶 3840×2160）。
fn compute_host_display_bounds(
    host: &HostSession,
    prefer_hardware: bool,
    hardware_video_active: bool,
) -> (Resolution, Resolution) {
    let neg = host.negotiated().unwrap_or_else(|| host.caps());
    let caps = host.caps();
    if prefer_hardware && hardware_video_active {
        let native = host_hardware_display_caps(true)
            .unwrap_or_else(|| Resolution::new(neg.width, neg.height).to_even());
        let backing = host_hardware_display_backing(true).unwrap_or(native);
        let (mw, mh) = display_ctrl::fit_within_cap(
            backing.width.min(display_ctrl::MAX_STREAM_WIDTH),
            backing.height.min(display_ctrl::MAX_STREAM_HEIGHT),
            native.width,
            native.height,
        );
        let max_res = Resolution::new(mw.max(native.width), mh.max(native.height));
        (native, max_res)
    } else {
        let native = Resolution::new(neg.width, neg.height).to_even();
        let max_res = Resolution::new(
            caps.width.min(display_ctrl::MAX_STREAM_WIDTH),
            caps.height.min(display_ctrl::MAX_STREAM_HEIGHT),
        )
        .to_even();
        (native, max_res)
    }
}

/// 组装本机硬件显示器预设列表，并在原生逻辑分辨率处标记 `is_native = true`。
fn build_hardware_display_presets(
    prefer_hardware: bool,
    hardware_video_active: bool,
    original_native: Option<Resolution>,
) -> Vec<DisplayPreset> {
    if !(prefer_hardware && hardware_video_active) {
        return Vec::new();
    }
    let modes = crate::platform::list_main_display_modes();
    if modes.is_empty() {
        return Vec::new();
    }
    let native_res = original_native.or_else(crate::platform::main_display_logical_resolution);
    let mut presets: Vec<DisplayPreset> = Vec::with_capacity(modes.len());
    for m in modes {
        let is_native = native_res
            .is_some_and(|n| n.width.abs_diff(m.width) <= 2 && n.height.abs_diff(m.height) <= 2);
        let label = if m.is_hidpi {
            format!("{} × {} (HiDPI)", m.width, m.height)
        } else {
            format!("{} × {}", m.width, m.height)
        };
        presets.push(DisplayPreset {
            width: m.width,
            height: m.height,
            label,
            is_native,
            is_hidpi: m.is_hidpi,
        });
    }
    presets
}

/// 编码器连续过载/丢帧触发被控端会话级熔断降级的阈值（连续失败 N 帧且当前非 H.264 时降级下一档）。
const HOST_ENCODE_OVERLOAD_TRIP_LIMIT: u32 = 15;

/// 计算当前被控端对外声明支持的视频编解码器列表（按当前分辨率档位排除已熔断项）。
fn host_supported_codecs(
    negotiator: &HostCodecNegotiator,
    tier: ResolutionTier,
    hevc_available: bool,
) -> Vec<String> {
    let mut out = Vec::with_capacity(3);
    if negotiator.is_codec_selectable(rc_encode::Codec::Av1, tier) {
        out.push("av1".to_string());
    }
    if hevc_available && negotiator.is_codec_selectable(rc_encode::Codec::Hevc, tier) {
        out.push("hevc".to_string());
    }
    out.push("h264".to_string());
    out
}

/// 编码当前被控端 `DisplayControlMsg::Capabilities` 载荷（含非对称能力明细、扩展标志位声明、权威编解码代次与静止补帧流纪元）。
#[allow(clippy::too_many_arguments)]
fn encode_host_display_caps(
    host: &HostSession,
    native_res: Resolution,
    max_res: Resolution,
    mut presets: Vec<DisplayPreset>,
    hevc_available: bool,
    negotiator: &HostCodecNegotiator,
    hardware_media_active: bool,
    still_stream_epoch: u64,
) -> Option<Vec<u8>> {
    let cur = host.negotiated()?;
    let tier = ResolutionTier::from_dimensions(cur.width, cur.height);
    let max_fps = host.caps().fps.max(1);
    let current_codec = Some(host.active_codec().as_str().to_string());
    let supported_codecs = host_supported_codecs(negotiator, tier, hevc_available);
    ensure_hevc_hidpi_preset(&mut presets, native_res, max_res, cur.fps, hevc_available);
    let encode_caps = negotiator.host_encode_caps().to_vec();
    let decode_caps = codec_selector::cached_or_platform_decode_caps(hardware_media_active);
    let refinement_caps = Some(codec_selector::cached_or_platform_refinement_caps(
        hardware_media_active,
    ));
    display_ctrl::encode_display_ctrl(&DisplayControlMsg::Capabilities {
        current_width: cur.width,
        current_height: cur.height,
        current_fps: cur.fps,
        native_width: native_res.width,
        native_height: native_res.height,
        max_width: max_res.width,
        max_height: max_res.height,
        max_fps,
        presets,
        current_codec,
        supported_codecs,
        encode_caps,
        decode_caps,
        refinement_caps,
        supports_ext_codec_flags: true,
        codec_generation: negotiator.codec_generation(),
        still_stream_epoch,
    })
}

struct HostDisplayModeSession {
    guard: Option<Box<dyn crate::platform::DisplayModeSessionGuard>>,
}

impl HostDisplayModeSession {
    fn capture(prefer_hardware: bool, hardware_video_active: bool) -> Self {
        let guard = if prefer_hardware && hardware_video_active {
            crate::platform::capture_display_mode_guard()
        } else {
            None
        };
        Self { guard }
    }

    fn original_resolution(&self) -> Option<Resolution> {
        self.guard.as_ref().map(|g| g.original_resolution())
    }

    fn switch_to(&mut self, target_w: u32, target_h: u32) -> Result<Resolution, String> {
        match self.guard.as_mut() {
            Some(g) => g.switch_to(target_w, target_h),
            None => Err("显示器模式守卫未激活".to_string()),
        }
    }

    fn restore(&mut self) {
        if let Some(g) = self.guard.as_mut() {
            g.restore();
        }
    }
}

fn spawn_wallpaper_fetcher() -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(1);
    let _ = thread::Builder::new()
        .name("rc-host-wallpaper".to_string())
        .spawn(move || {
            if let Some(jpeg) = crate::platform::capture_wallpaper_jpeg(640, 400) {
                if !jpeg.is_empty() {
                    let _ = tx.send(jpeg);
                }
            }
        });
    rx
}

/// 单拍泵送主机侧音频采集：`suppress_send == false` 且通过静音抑制门控（DTX）时编码 IMA-ADPCM 并发送；
/// 静音、Stream A 工具通道背压（`suppress_send == true`）或连续无声期仅排空陈旧缓冲不发送，
/// 消除空闲桌面持续 ~384–410 Kbps 的无效静音音频带宽占用（M9）。
fn pump_host_audio(
    host: &mut HostSession,
    capture: &mut dyn AudioCapture,
    suppress_send: bool,
    silence_gate: &mut AudioSilenceGate,
    audio_seq: &mut u32,
) -> bool {
    let mut busy = false;
    for _ in 0..MAX_AUDIO_FRAMES_PER_TICK {
        let Some(frame) = capture.try_recv_frame() else {
            break;
        };
        busy = true;
        if suppress_send || frame.samples.is_empty() {
            continue;
        }
        if !silence_gate.should_transmit(&frame.samples) {
            continue;
        }
        let data = encode_ima_adpcm(&frame.samples, frame.channels);
        let seq = *audio_seq;
        *audio_seq = audio_seq.wrapping_add(1);
        let _ = host.send_audio_frame(AudioFramePacket {
            seq,
            timestamp_us: frame.timestamp_us,
            sample_rate: frame.sample_rate,
            channels: frame.channels,
            codec: AUDIO_CODEC_IMA_ADPCM,
            data,
        });
    }
    busy
}

/// 单个远控会话最多允许创建的虚拟显示器数量上限（防止异常/恶意对端耗尽 WindowServer 虚拟屏资源）。
const MAX_VIRTUAL_DISPLAYS_PER_SESSION: usize = 4;

/// 校验隐私屏保自定义图片魔数（仅放行非空 PNG / JPEG / WebP）。
fn is_valid_privacy_image_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
        || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        || (bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP")
}

/// 被控端会话级硬件副作用清理守卫（隐私幕布 / 系统静音恢复 / 虚拟显示器销毁）。
///
/// 无论会话正常结束、断线、报错还是 panic，[`Drop`] 均会确定性清理全部本会话创建的硬件状态。
struct HostHardwareCleanupGuard {
    prefer_hardware: bool,
    privacy_active: bool,
    host_audio_modified: bool,
    restore_audio_on_exit: bool,
    virtual_display_count: usize,
}

impl HostHardwareCleanupGuard {
    fn new(prefer_hardware: bool) -> Self {
        Self {
            prefer_hardware,
            privacy_active: false,
            host_audio_modified: false,
            restore_audio_on_exit: true,
            virtual_display_count: 0,
        }
    }

    fn cleanup_now(&mut self) {
        if !self.prefer_hardware {
            self.privacy_active = false;
            self.host_audio_modified = false;
            self.restore_audio_on_exit = true;
            self.virtual_display_count = 0;
            return;
        }
        if self.privacy_active {
            crate::platform::clear_privacy_curtain();
            self.privacy_active = false;
        }
        if self.host_audio_modified {
            if self.restore_audio_on_exit {
                crate::platform::restore_host_system_audio();
            } else {
                crate::platform::clear_host_audio_snapshot();
            }
        }
        self.host_audio_modified = false;
        self.restore_audio_on_exit = true;
        if self.virtual_display_count > 0 {
            crate::platform::destroy_all_virtual_displays();
            self.virtual_display_count = 0;
        }
    }
}

impl Drop for HostHardwareCleanupGuard {
    fn drop(&mut self) {
        self.cleanup_now();
    }
}

fn encode_host_displays_state(active_display_id: Option<u32>) -> Option<Vec<u8>> {
    let raw = crate::platform::list_displays();
    if raw.is_empty() {
        return None;
    }
    let resolved_active = active_display_id
        .filter(|id| raw.iter().any(|d| d.id == *id))
        .or_else(|| raw.iter().find(|d| d.is_main).map(|d| d.id))
        .unwrap_or(raw[0].id);
    let displays = raw
        .into_iter()
        .map(|d| DisplayDescriptor {
            id: d.id,
            name: d.name,
            width: d.width,
            height: d.height,
            is_main: d.is_main,
            is_virtual: d.is_virtual,
        })
        .collect();
    display_ctrl::encode_display_ctrl(&DisplayControlMsg::DisplaysState {
        displays,
        active_display_id: resolved_active,
    })
}

fn trigger_host_lock_screen(lock_screen_count: &AtomicU64, prefer_hardware: bool) {
    lock_screen_count.fetch_add(1, Ordering::AcqRel);
    if prefer_hardware {
        let ok = crate::platform::lock_screen_now();
        if !ok {
            eprintln!("[rc-ui-host] 锁定本机屏幕失败");
        }
    }
}

/// U-H1：显式驱动已建立的 `HostSession`（`Streaming` 调 `tick`，`Detached` 调 `tick_detached`）。
///
/// 在以下任一条件满足时立即退出驱动循环并收尾，让外层 accept 循环回到监听态：
/// - `stop_flag` 或 `disconnect_flag` 置位；
/// - `Streaming` 期收到对端 `Bye`（`r.closed.is_some()`）；
/// - `Detached` 期重连窗口到期拆除管线（`DetachOutcome::TornDown`）；
/// - `Detached` 期密码版本（`password_version != observed_pw_ver`）或鉴权配置版本（`config_version != observed_cfg_ver`）发生变更，需重建以使新配置生效。
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn drive_ui_host_session(
    host: &mut HostSession,
    clock: &SessionClock,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
) -> String {
    let lock_screen_count = AtomicU64::new(0);
    let close_reason = AtomicU8::new(ByeReason::Normal as u8);
    let mut owner_terminals = PersistentOwnerTerminals::new();
    let wake_guard: SharedWakeGuard = Arc::new(Mutex::new(None));
    let file_transfer_dir: SharedFileTransferDir = Arc::new(RwLock::new(None));
    let allow_assist_file_transfer = AtomicBool::new(true);
    drive_ui_host_session_inner(
        host,
        clock,
        None,
        updates,
        password_version,
        observed_pw_ver,
        config_version,
        observed_cfg_ver,
        disconnect_flag,
        stop_flag,
        &close_reason,
        HostTransportKind::Lan,
        false,
        false,
        false,
        &lock_screen_count,
        None,
        &mut owner_terminals,
        wake_guard,
        file_transfer_dir,
        &allow_assist_file_transfer,
        None,
        None,
        Instant::now(),
    )
    .reason
}

const RELAY_MIN_BITRATE_BPS: u32 = 2_000_000;
const RELAY_QUEUE_HIGH_BYTES: usize = 192 * 1024;
const RELAY_QUEUE_LOW_BYTES: usize = 32 * 1024;
const RELAY_HIGH_QUEUE_HOLD: Duration = Duration::from_millis(150);
const RELAY_BACKOFF_COOLDOWN: Duration = Duration::from_millis(500);
const RELAY_RAMP_INTERVAL: Duration = Duration::from_secs(2);

/// 被控端 TCP Relay 连续码率控制器：将手动上限、`local_bps`（发送队列/淘汰 AIMD）与
/// 对端控制端 RTT 限速上限（`remote_probe_cap_bps`）解耦，恒取三者最小值以避免双端抢权互盖。
struct RelayBitrateController {
    manual_cap_bps: u32,
    local_bps: u32,
    remote_probe_cap_bps: Option<u32>,
    last_dropped: u64,
    high_queue_since: Option<Instant>,
    last_adjust: Instant,
    clean_since: Instant,
    last_manual_seen: Option<(u64, u32)>,
    last_remote_probe_seen: Option<u32>,
}

impl RelayBitrateController {
    fn new(initial_bps: u32, now: Instant) -> Self {
        let cap = initial_bps.max(1);
        Self {
            manual_cap_bps: cap,
            local_bps: cap,
            remote_probe_cap_bps: None,
            last_dropped: 0,
            high_queue_since: None,
            last_adjust: now,
            clean_since: now,
            last_manual_seen: None,
            last_remote_probe_seen: None,
        }
    }

    fn effective_bps(&self) -> u32 {
        self.local_bps
            .min(self.remote_probe_cap_bps.unwrap_or(self.manual_cap_bps))
            .min(self.manual_cap_bps)
            .max(1)
    }

    fn sync_external_caps(
        &mut self,
        manual: Option<(u64, u32)>,
        remote_probe_bps: Option<u32>,
        current_host_bps: u32,
        now: Instant,
    ) -> Option<u32> {
        if let Some((gen, m)) = manual {
            if self.last_manual_seen != Some((gen, m)) {
                self.last_manual_seen = Some((gen, m));
                self.manual_cap_bps = m.max(1);
                self.local_bps = self.manual_cap_bps;
                self.remote_probe_cap_bps = None;
                self.last_remote_probe_seen = remote_probe_bps;
                self.high_queue_since = None;
                self.last_adjust = now;
                self.clean_since = now;
            }
        }
        if self.last_remote_probe_seen != remote_probe_bps {
            self.last_remote_probe_seen = remote_probe_bps;
            self.remote_probe_cap_bps = remote_probe_bps.map(|v| v.clamp(1, self.manual_cap_bps));
        }
        let target = self.effective_bps();
        (current_host_bps.max(1) != target).then_some(target)
    }

    fn poll(&mut self, now: Instant, queued_bytes: usize, dropped_total: u64) -> Option<u32> {
        let prev_eff = self.effective_bps();
        let has_new_drops = dropped_total > self.last_dropped;
        self.last_dropped = dropped_total;

        if queued_bytes >= RELAY_QUEUE_HIGH_BYTES {
            self.high_queue_since.get_or_insert(now);
        } else {
            self.high_queue_since = None;
        }
        let sustained_high_queue = self
            .high_queue_since
            .is_some_and(|since| now.saturating_duration_since(since) >= RELAY_HIGH_QUEUE_HOLD);

        if has_new_drops || sustained_high_queue {
            self.clean_since = now;
            if now.saturating_duration_since(self.last_adjust) >= RELAY_BACKOFF_COOLDOWN {
                let floor = RELAY_MIN_BITRATE_BPS.min(self.manual_cap_bps).max(1);
                let next =
                    (((self.local_bps as f64) * 0.75) as u32).clamp(floor, self.manual_cap_bps);
                self.last_adjust = now;
                self.high_queue_since = None;
                self.local_bps = next;
                let next_eff = self.effective_bps();
                if next_eff != prev_eff {
                    return Some(next_eff);
                }
            }
            return None;
        }

        if queued_bytes <= RELAY_QUEUE_LOW_BYTES {
            if self.local_bps < self.manual_cap_bps
                && now.saturating_duration_since(self.clean_since) >= RELAY_RAMP_INTERVAL
                && now.saturating_duration_since(self.last_adjust) >= RELAY_RAMP_INTERVAL
            {
                let step = (self.local_bps / 7).max(2_000_000);
                let next = self.local_bps.saturating_add(step).min(self.manual_cap_bps);
                self.last_adjust = now;
                self.clean_since = now;
                self.local_bps = next;
                let next_eff = self.effective_bps();
                if next_eff != prev_eff {
                    return Some(next_eff);
                }
            }
        } else {
            self.clean_since = now;
        }

        None
    }
}

#[allow(clippy::too_many_arguments)]
fn drive_ui_host_session_inner(
    host: &mut HostSession,
    clock: &SessionClock,
    clock_anchor: Option<&HostClockAnchor>,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
    close_reason: &AtomicU8,
    transport_kind: HostTransportKind,
    prefer_hardware: bool,
    audio_enabled: bool,
    hardware_video_active: bool,
    lock_screen_count: &AtomicU64,
    auth_state: Option<&Mutex<AuthRuntimeState>>,
    owner_terminals: &mut PersistentOwnerTerminals,
    wake_guard: SharedWakeGuard,
    file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: &AtomicBool,
    incoming_relay: Option<&Arc<BoundedRelayIncomingQueue>>,
    active_peer_id: Option<&str>,
    session_started_at: Instant,
) -> DriveSessionOutcome {
    let audio_mgr =
        HostAudioManager::new(audio_enabled && prefer_hardware && hardware_video_active);
    drive_ui_host_session_with_audio(
        host,
        clock,
        clock_anchor,
        updates,
        password_version,
        observed_pw_ver,
        config_version,
        observed_cfg_ver,
        disconnect_flag,
        stop_flag,
        close_reason,
        transport_kind,
        prefer_hardware,
        hardware_video_active,
        lock_screen_count,
        auth_state,
        owner_terminals,
        wake_guard,
        file_transfer_dir,
        allow_assist_file_transfer,
        incoming_relay,
        active_peer_id,
        session_started_at,
        audio_mgr,
    )
}

#[allow(clippy::too_many_arguments)]
fn drive_ui_host_session_with_audio(
    host: &mut HostSession,
    clock: &SessionClock,
    clock_anchor: Option<&HostClockAnchor>,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
    close_reason: &AtomicU8,
    transport_kind: HostTransportKind,
    prefer_hardware: bool,
    hardware_video_active: bool,
    lock_screen_count: &AtomicU64,
    auth_state: Option<&Mutex<AuthRuntimeState>>,
    owner_terminals: &mut PersistentOwnerTerminals,
    wake_guard: SharedWakeGuard,
    file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: &AtomicBool,
    incoming_relay: Option<&Arc<BoundedRelayIncomingQueue>>,
    active_peer_id: Option<&str>,
    mut session_started_at: Instant,
    mut audio_mgr: HostAudioManager,
) -> DriveSessionOutcome {
    // 启用 8s 应用层客户端失活看门狗（控制端在静屏与纯工具模式下每 1s 发送 ProbePing 心跳）。
    host.set_client_idle_timeout_us(HostSession::CLIENT_IDLE_TIMEOUT_US);

    let _wake_guard_releaser = WakeGuardReleaser {
        slot: Arc::clone(&wake_guard),
    };
    let _activity =
        crate::platform::begin_latency_critical_activity("RabbitControl 被控会话", true);
    let mut hw_cleanup = HostHardwareCleanupGuard::new(prefer_hardware);
    let mut active_display_id: Option<u32> = None;
    let mut shows_cursor = false;
    let mut user_pinned_resolution = false;
    let mut auto_hidpi_active = false;
    let mut active_peer_id: Option<String> = active_peer_id.map(str::to_string);

    let mut detached_reason: Option<String> = None;
    let mut drive_err: Option<String> = None;
    let mut pending_lock_on_exit = false;
    let mut preempted_by_incoming = false;
    let mut last_preempt_check = Instant::now();
    let mut epoch_reanchored_in_detached = false;

    // 文件 I/O 与端口映射严格绑定单次控制端会话（断线清理 .rcpart 与监听套接字）；
    // W3 终端在机主（OwnerTicket）身份下复用 `owner_terminals` 跨重连保活，访客会话仅使用会话级 `guest_term_host`。
    let mut file_worker = FileHostWorker::spawn(Arc::clone(&file_transfer_dir));
    let mut guest_term_host = TerminalHostEngine::new();
    let mut use_owner_terminals = match host.authenticated_owner() {
        Some(owner) => {
            let _ = owner_terminals.bind_for_owner(&owner.user_id);
            true
        }
        None => false,
    };
    let mut portmap_host = PortMapHostEngine::new();
    let mut update_worker = crate::updater::HostUpdateWorker::new();
    let mut pending_file_in: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_file_tx: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_term_tx: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_portmap_tx: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_display_tx: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_update_tx = crate::updater::PendingUpdateTxQueue::new();
    let (mut session_native_res, mut session_max_res) =
        compute_host_display_bounds(host, prefer_hardware, hardware_video_active);
    let mut display_mode_session =
        HostDisplayModeSession::capture(prefer_hardware, hardware_video_active);
    let original_native_res = display_mode_session
        .original_resolution()
        .or(Some(session_native_res));
    let mut wallpaper_rx = if prefer_hardware && hardware_video_active {
        Some(spawn_wallpaper_fetcher())
    } else {
        None
    };

    let hardware_media_active = prefer_hardware && hardware_video_active;
    let host_encode_caps = codec_selector::cached_or_platform_encode_caps(hardware_media_active);
    let mut codec_negotiator = HostCodecNegotiator::new(host_encode_caps.clone());
    let host_refinement_supported =
        codec_selector::cached_or_platform_refinement_caps(hardware_media_active).supported;
    let init_stream_dims = host
        .negotiated()
        .map(|n| (n.width, n.height))
        .unwrap_or((session_native_res.width, session_native_res.height));
    let mut still_refine = crate::still_refine::HostStillRefineController::new(
        1,
        init_stream_dims.0,
        init_stream_dims.1,
        host_refinement_supported,
    );
    let mut still_loss_window_at = Instant::now();
    let mut still_window_sent_dgrams: u64 = 0;
    let mut still_window_dropped_dgrams: u64 = 0;
    let mut still_last_dropped_total: u64 = host.transport_tx_dropped_datagrams();
    let mut hevc_runtime_failed = false;
    let host_hevc_available =
        |failed: bool| hardware_media_active && !failed && rc_pipeline::platform_supports_hevc();
    let current_net_hint = |host: &HostSession| NetworkHint {
        is_relay: transport_kind == HostTransportKind::Relay,
        is_lan: transport_kind == HostTransportKind::Lan,
        estimated_bitrate_bps: host.current_bitrate_bps(),
        rtt_us: 0,
    };

    let mut last_reported_screen_state: Option<(bool, bool)> = None;
    let mut last_screen_state_check = Instant::now();
    let mut mid_session_wake = MidSessionWakeDriver::new();
    let mut current_tool_perms = compute_effective_tool_permissions(
        host.authenticated_owner().is_some(),
        allow_assist_file_transfer.load(Ordering::Acquire),
    );
    host.set_tool_permissions(current_tool_perms);
    let mut last_tool_denied_sent: [Option<Instant>; 8] = [None; 8];

    if host.state() == SessionState::Streaming {
        if let Some(perm_payload) = encode_tool_permissions_state(current_tool_perms) {
            pending_display_tx.push_back(perm_payload);
        }
        let presets = build_hardware_display_presets(
            prefer_hardware,
            hardware_video_active,
            original_native_res,
        );
        if let Some(payload) = encode_host_display_caps(
            host,
            original_native_res.unwrap_or(session_native_res),
            session_max_res,
            presets,
            host_hevc_available(hevc_runtime_failed),
            &codec_negotiator,
            hardware_media_active,
            still_refine.stream_epoch(),
        ) {
            pending_display_tx.push_back(payload);
        }
        if prefer_hardware && hardware_video_active {
            if let Some(disp_payload) = encode_host_displays_state(active_display_id) {
                pending_display_tx.push_back(disp_payload);
            }
        }
        let init_screen_state = (
            crate::platform::is_screen_locked(),
            host.is_capture_suspended(),
        );
        if init_screen_state.0 || init_screen_state.1 {
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::HostScreenState {
                    locked: init_screen_state.0,
                    capture_suspended: init_screen_state.1,
                })
            {
                pending_display_tx.push_back(payload);
            }
        }
        last_reported_screen_state = Some(init_screen_state);
        let ver_msg = crate::updater::HostUpdateWorker::build_version_info_msg(
            host.authenticated_owner().is_some(),
        );
        pending_update_tx.enqueue(&ver_msg, host.authenticated_owner().is_some());
    }

    let mut audio_muted = false;
    let mut audio_silence_gate = AudioSilenceGate::default();
    let mut audio_seq: u32 = 0;
    let mut last_busy = true;
    let mut relay_bitrate_ctrl = (transport_kind == HostTransportKind::Relay)
        .then(|| RelayBitrateController::new(host.current_bitrate_bps().max(1), Instant::now()));
    let mut last_relay_bwe_at = Instant::now();

    while !stop_flag.load(Ordering::Acquire)
        && !disconnect_flag.load(Ordering::Acquire)
        && host.state() != SessionState::Closed
    {
        match host.state() {
            SessionState::Streaming => {
                // 运行期工具通道权限热更新（不中断会话；撤销文件传输权限时立即中止在途传输并丢弃待投递帧）。
                let desired_tool_perms = compute_effective_tool_permissions(
                    host.authenticated_owner().is_some(),
                    allow_assist_file_transfer.load(Ordering::Acquire),
                );
                if desired_tool_perms != current_tool_perms {
                    let file_revoked = current_tool_perms.allow_file_transfer
                        && !desired_tool_perms.allow_file_transfer;
                    current_tool_perms = desired_tool_perms;
                    host.set_tool_permissions(current_tool_perms);
                    if file_revoked {
                        pending_file_in.clear();
                        pending_file_tx.clear();
                        file_worker = FileHostWorker::spawn(Arc::clone(&file_transfer_dir));
                    }
                    if let Some(perm_payload) = encode_tool_permissions_state(current_tool_perms) {
                        pending_display_tx.push_back(perm_payload);
                    }
                }

                let poll_budget = if last_busy || host.has_pending_pipeline_work() {
                    Duration::ZERO
                } else {
                    Duration::from_millis(1)
                };
                match host.tick(poll_budget) {
                    Ok(r) => {
                        if r.closed.is_some() {
                            for (channel, payload) in host.drain_tool_messages() {
                                if channel == TOOL_CHANNEL_DISPLAY_CTRL
                                    && matches!(
                                        display_ctrl::decode_display_ctrl(&payload),
                                        Some(DisplayControlMsg::LockScreen)
                                    )
                                {
                                    pending_lock_on_exit = true;
                                }
                            }
                            break;
                        }
                        if host.state() != SessionState::Streaming {
                            continue;
                        }

                        // 修正 #5：收到任意输入事件或产出新动态帧时，毫秒级立即抢占清空待发静止补帧并推进状态机。
                        if r.events_injected > 0 {
                            still_refine.on_input_event();
                        }
                        if r.datagrams_sent > 0 {
                            let now_ms = u64::try_from(session_started_at.elapsed().as_millis())
                                .unwrap_or(u64::MAX);
                            let seq = host.last_sent_frame_seq().unwrap_or(0);
                            still_refine.on_dynamic_frame(now_ms, seq, host.last_dirty_rects());
                            still_window_sent_dgrams =
                                still_window_sent_dgrams.saturating_add(r.datagrams_sent as u64);
                        }
                        let cur_dropped_total = host.transport_tx_dropped_datagrams();
                        let dropped_delta =
                            cur_dropped_total.saturating_sub(still_last_dropped_total);
                        still_last_dropped_total = cur_dropped_total;
                        still_window_dropped_dgrams =
                            still_window_dropped_dgrams.saturating_add(dropped_delta);
                        if still_loss_window_at.elapsed() >= Duration::from_secs(1) {
                            let total = still_window_sent_dgrams
                                .saturating_add(still_window_dropped_dgrams);
                            let loss_rate = if total > 0 {
                                still_window_dropped_dgrams as f32 / total as f32
                            } else {
                                0.0
                            };
                            still_refine.update_network(host.current_bitrate_bps(), loss_rate);
                            still_window_sent_dgrams = 0;
                            still_window_dropped_dgrams = 0;
                            still_loss_window_at = Instant::now();
                        } else if dropped_delta > 0 {
                            let total = still_window_sent_dgrams
                                .saturating_add(still_window_dropped_dgrams)
                                .max(1);
                            let loss_rate = still_window_dropped_dgrams as f32 / total as f32;
                            still_refine.update_network(host.current_bitrate_bps(), loss_rate);
                        }

                        // 编码侧连续过载熔断：当前非 H.264 且连续编码过载达到阈值时，立即熔断并顺延下一档。
                        if host.active_codec() != rc_encode::Codec::H264
                            && host.consecutive_encode_overloads()
                                >= HOST_ENCODE_OVERLOAD_TRIP_LIMIT
                        {
                            if let Some(cur) = host.negotiated() {
                                let failed_codec = host.active_codec();
                                let target = StreamTarget {
                                    width: cur.width,
                                    height: cur.height,
                                    fps: cur.fps,
                                };
                                let fb_plan = codec_negotiator.on_encode_failure(
                                    failed_codec,
                                    "consecutive encoder overload",
                                    failed_codec,
                                    target,
                                    current_net_hint(host),
                                );
                                if failed_codec == rc_encode::Codec::Hevc {
                                    hevc_runtime_failed = true;
                                }
                                let (tw, th) = if fb_plan.codec == rc_encode::Codec::H264
                                    && !user_pinned_resolution
                                    && active_display_id.is_none()
                                    && (cur.width > session_native_res.width
                                        || cur.height > session_native_res.height)
                                {
                                    auto_hidpi_active = false;
                                    (session_native_res.width, session_native_res.height)
                                } else {
                                    (cur.width, cur.height)
                                };
                                let prev_codec = host.active_codec();
                                let _ = host.reconfigure_stream_with_codec(
                                    tw,
                                    th,
                                    Some(cur.fps),
                                    Some(session_max_res),
                                    Some(fb_plan.codec),
                                );
                                if host.active_codec() != prev_codec {
                                    codec_negotiator.bump_generation();
                                }
                                if let Some(n) = host.negotiated() {
                                    still_refine.on_stream_reset(n.width, n.height);
                                }
                                let (caps_native, presets) = if active_display_id.is_some() {
                                    (
                                        session_native_res,
                                        display_ctrl::build_resolution_presets(
                                            session_native_res.width,
                                            session_native_res.height,
                                            session_max_res.width,
                                            session_max_res.height,
                                        ),
                                    )
                                } else {
                                    (
                                        original_native_res.unwrap_or(session_native_res),
                                        build_hardware_display_presets(
                                            prefer_hardware,
                                            hardware_video_active,
                                            original_native_res,
                                        ),
                                    )
                                };
                                if let Some(cp) = encode_host_display_caps(
                                    host,
                                    caps_native,
                                    session_max_res,
                                    presets,
                                    host_hevc_available(hevc_runtime_failed),
                                    &codec_negotiator,
                                    hardware_media_active,
                                    still_refine.stream_epoch(),
                                ) {
                                    pending_display_tx.push_back(cp);
                                }
                            }
                        }

                        if let Some(ref mut ctrl) = relay_bitrate_ctrl {
                            let now_bwe = Instant::now();
                            let manual_cap = host
                                .last_manual_bitrate_bps()
                                .map(|bps| (host.last_manual_bitrate_gen(), bps));
                            if let Some(clamped_bps) = ctrl.sync_external_caps(
                                manual_cap,
                                host.last_remote_probe_bitrate_bps(),
                                host.current_bitrate_bps().max(1),
                                now_bwe,
                            ) {
                                let _ = host.on_set_bitrate(
                                    clamped_bps,
                                    rc_session::proto::BitrateReason::Probe as u8,
                                );
                            }
                            if now_bwe.saturating_duration_since(last_relay_bwe_at)
                                >= Duration::from_millis(100)
                            {
                                last_relay_bwe_at = now_bwe;
                                if let Some(next_bps) = ctrl.poll(
                                    now_bwe,
                                    host.transport_tx_queued_bytes(),
                                    host.transport_tx_dropped_datagrams(),
                                ) {
                                    let _ = host.on_set_bitrate(
                                        next_bps,
                                        rc_session::proto::BitrateReason::Probe as u8,
                                    );
                                }
                            }
                        }

                        // 0) 非阻塞检查后台音频采集初始化/自愈重建（H13）与桌面壁纸初始化是否就绪。
                        audio_mgr.poll_and_recover(
                            Instant::now(),
                            host.is_media_paused(),
                            &mut audio_silence_gate,
                        );
                        if let Some(ref rx) = wallpaper_rx {
                            match rx.try_recv() {
                                Ok(jpeg) => {
                                    wallpaper_rx = None;
                                    let data_base64 = display_ctrl::base64_encode(&jpeg);
                                    if let Some(wp_payload) = display_ctrl::encode_display_ctrl(
                                        &DisplayControlMsg::Wallpaper {
                                            mime: "image/jpeg".to_string(),
                                            data_base64,
                                        },
                                    ) {
                                        pending_display_tx.push_back(wp_payload);
                                    }
                                }
                                Err(mpsc::TryRecvError::Empty) => {}
                                Err(mpsc::TryRecvError::Disconnected) => {
                                    wallpaper_rx = None;
                                }
                            }
                        }

                        // 1) 剪贴板本机侧轮询泵。
                        let _ = host.pump_clipboard(u64::from(clock()));

                        // 2) 工具复用通道入站分发（W2 文件异步交由专用工作线程 / W3 终端 / W4 端口映射 / 音频控制）。
                        let incoming_tools = host.drain_tool_messages();
                        let rejected_channels = host.drain_rejected_tool_channels();
                        let mut tools_busy =
                            !incoming_tools.is_empty() || !rejected_channels.is_empty();
                        if !rejected_channels.is_empty() {
                            let now_denied = Instant::now();
                            for ch in rejected_channels {
                                let idx = usize::from(ch);
                                let should_send = if idx < last_tool_denied_sent.len() {
                                    match last_tool_denied_sent[idx] {
                                        None => true,
                                        Some(prev) => {
                                            now_denied.saturating_duration_since(prev)
                                                >= TOOL_PERMISSION_DENIED_THROTTLE
                                        }
                                    }
                                } else {
                                    true
                                };
                                if should_send {
                                    if idx < last_tool_denied_sent.len() {
                                        last_tool_denied_sent[idx] = Some(now_denied);
                                    }
                                    if let Some(denied_payload) = display_ctrl::encode_display_ctrl(
                                        &DisplayControlMsg::ToolPermissionDenied {
                                            channel: ch,
                                            reason: Some(format!(
                                                "被控端已禁止本次远程协助使用{}",
                                                crate::ui_error::tool_channel_name_zh(ch)
                                            )),
                                        },
                                    ) {
                                        pending_display_tx.push_back(denied_payload);
                                    }
                                }
                            }
                            while pending_display_tx.len() > 64 {
                                pending_display_tx.pop_front();
                            }
                        }
                        for (channel, payload) in incoming_tools {
                            match channel {
                                TOOL_CHANNEL_FILE => {
                                    if current_tool_perms.allow_file_transfer {
                                        pending_file_in.push_back(payload);
                                    }
                                }
                                TOOL_CHANNEL_TERMINAL => {
                                    if use_owner_terminals {
                                        owner_terminals.engine.handle_incoming(&payload);
                                    } else {
                                        guest_term_host.handle_incoming(&payload);
                                    }
                                }
                                TOOL_CHANNEL_PORTMAP => portmap_host.handle_incoming(&payload),
                                TOOL_CHANNEL_AUDIO_CTRL => {
                                    if let Some(muted) = parse_audio_ctrl_muted(&payload) {
                                        if audio_muted && !muted {
                                            audio_silence_gate.reset();
                                        }
                                        audio_muted = muted;
                                    }
                                }
                                TOOL_CHANNEL_DISPLAY_CTRL => {
                                    match display_ctrl::decode_display_ctrl(&payload) {
                                        Some(DisplayControlMsg::SetStream {
                                            width,
                                            height,
                                            fps,
                                            codec,
                                        }) => {
                                            if let Some(cur) = host.negotiated() {
                                                let target_fps = (fps > 0).then_some(fps);
                                                let prev_codec = host.active_codec();
                                                if width > 0 && height > 0 {
                                                    codec_negotiator
                                                        .reset_breaker_on_manual_or_res_change();
                                                    hevc_runtime_failed = false;
                                                }
                                                let cur_tier = ResolutionTier::from_dimensions(
                                                    if width > 0 { width } else { cur.width },
                                                    if height > 0 { height } else { cur.height },
                                                );
                                                let requested_codec = codec
                                                    .as_deref()
                                                    .and_then(
                                                        display_ctrl::StreamCodec::parse_lossy,
                                                    )
                                                    .and_then(|c| match c {
                                                        display_ctrl::StreamCodec::Av1 => {
                                                            codec_negotiator
                                                                .is_codec_selectable(
                                                                    rc_encode::Codec::Av1,
                                                                    cur_tier,
                                                                )
                                                                .then_some(rc_encode::Codec::Av1)
                                                        }
                                                        display_ctrl::StreamCodec::Hevc => {
                                                            host_hevc_available(hevc_runtime_failed)
                                                                .then_some(rc_encode::Codec::Hevc)
                                                        }
                                                        display_ctrl::StreamCodec::H264 => {
                                                            Some(rc_encode::Codec::H264)
                                                        }
                                                    });
                                                let attempted_codec = requested_codec
                                                    .unwrap_or_else(|| host.active_codec());
                                                if width > 0 && height > 0 {
                                                    let switched_main =
                                                        if active_display_id.is_none() {
                                                            display_mode_session
                                                                .switch_to(width, height)
                                                                .ok()
                                                        } else {
                                                            None
                                                        };
                                                    if let Some(switched_res) = switched_main {
                                                        audio_mgr.reset_backoff_for_display_change(
                                                            Instant::now(),
                                                        );
                                                        user_pinned_resolution = true;
                                                        auto_hidpi_active = false;
                                                        host.set_injector_screen_size(
                                                            switched_res.width,
                                                            switched_res.height,
                                                        );
                                                        session_native_res = switched_res;
                                                        let cur_backing =
                                                            host_hardware_display_backing(true)
                                                                .unwrap_or(switched_res);
                                                        session_max_res = Resolution {
                                                            width: cur_backing
                                                                .width
                                                                .max(switched_res.width),
                                                            height: cur_backing
                                                                .height
                                                                .max(switched_res.height),
                                                        };
                                                        if let Err(err) = host
                                                            .reconfigure_stream_with_codec(
                                                                switched_res.width,
                                                                switched_res.height,
                                                                target_fps,
                                                                Some(switched_res),
                                                                requested_codec,
                                                            )
                                                        {
                                                            eprintln!(
                                                        "[rc-ui-host] 热切换流参数 ({}x{}@{fps}fps, {requested_codec:?}) 失败: {err}",
                                                        switched_res.width, switched_res.height
                                                    );
                                                        }
                                                    } else {
                                                        let (target_w, target_h) =
                                                            display_ctrl::fit_target_preserving_aspect(
                                                                width,
                                                                height,
                                                                session_native_res.width,
                                                                session_native_res.height,
                                                                session_max_res.width,
                                                                session_max_res.height,
                                                            );
                                                        match host.reconfigure_stream_with_codec(
                                                            target_w,
                                                            target_h,
                                                            target_fps,
                                                            Some(session_max_res),
                                                            requested_codec,
                                                        ) {
                                                            Ok(_) => {
                                                                user_pinned_resolution = true;
                                                                auto_hidpi_active = false;
                                                            }
                                                            Err(err) => {
                                                                eprintln!(
                                                        "[rc-ui-host] 热切换流参数 ({target_w}x{target_h}@{fps}fps, {requested_codec:?}) 失败: {err}"
                                                    );
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    let eff_codec = attempted_codec;
                                                    let eff_fps = target_fps
                                                        .unwrap_or(cur.fps)
                                                        .clamp(1, host.caps().fps.max(1));
                                                    let (target_w, target_h, next_auto_hidpi) =
                                                        if !user_pinned_resolution
                                                            && active_display_id.is_none()
                                                            && prefer_hardware
                                                            && hardware_video_active
                                                        {
                                                            resolve_auto_hidpi_resolution(
                                                                cur.width,
                                                                cur.height,
                                                                session_native_res,
                                                                session_max_res,
                                                                eff_fps,
                                                                eff_codec,
                                                                auto_hidpi_active,
                                                            )
                                                        } else {
                                                            (
                                                                cur.width,
                                                                cur.height,
                                                                auto_hidpi_active,
                                                            )
                                                        };
                                                    match host.reconfigure_stream_with_codec(
                                                        target_w,
                                                        target_h,
                                                        target_fps,
                                                        Some(session_max_res),
                                                        requested_codec,
                                                    ) {
                                                        Ok(_) => {
                                                            auto_hidpi_active = next_auto_hidpi
                                                                && host.active_codec()
                                                                    == rc_encode::Codec::Hevc;
                                                        }
                                                        Err(err) => {
                                                            eprintln!(
                                                                "[rc-ui-host] 热切换流参数 ({target_w}x{target_h}@{fps}fps, {requested_codec:?}) 失败: {err}"
                                                            );
                                                        }
                                                    }
                                                }
                                                if attempted_codec != rc_encode::Codec::H264
                                                    && host.active_codec() != attempted_codec
                                                {
                                                    let fail_target = StreamTarget {
                                                        width: cur.width,
                                                        height: cur.height,
                                                        fps: target_fps.unwrap_or(cur.fps),
                                                    };
                                                    let _ = codec_negotiator.on_encode_failure(
                                                        attempted_codec,
                                                        "reconfigure stream encoder init failed",
                                                        host.active_codec(),
                                                        fail_target,
                                                        current_net_hint(host),
                                                    );
                                                    if attempted_codec == rc_encode::Codec::Hevc {
                                                        hevc_runtime_failed = true;
                                                    }
                                                    auto_hidpi_active = false;
                                                    if host.active_codec() == rc_encode::Codec::H264
                                                        && !user_pinned_resolution
                                                        && active_display_id.is_none()
                                                        && host.negotiated().is_some_and(|n| {
                                                            n.width > session_native_res.width
                                                                || n.height
                                                                    > session_native_res.height
                                                        })
                                                    {
                                                        let _ = host.reconfigure_stream_with_codec(
                                                            session_native_res.width,
                                                            session_native_res.height,
                                                            target_fps.or(Some(cur.fps)),
                                                            Some(session_max_res),
                                                            Some(rc_encode::Codec::H264),
                                                        );
                                                    }
                                                }
                                                if host.active_codec() != prev_codec {
                                                    codec_negotiator.bump_generation();
                                                }
                                                if let Some(n) = host.negotiated() {
                                                    still_refine.on_stream_reset(n.width, n.height);
                                                }
                                                let (caps_native, presets) =
                                                    if active_display_id.is_some() {
                                                        (
                                                            session_native_res,
                                                            display_ctrl::build_resolution_presets(
                                                                session_native_res.width,
                                                                session_native_res.height,
                                                                session_max_res.width,
                                                                session_max_res.height,
                                                            ),
                                                        )
                                                    } else {
                                                        (
                                                            original_native_res
                                                                .unwrap_or(session_native_res),
                                                            build_hardware_display_presets(
                                                                prefer_hardware,
                                                                hardware_video_active,
                                                                original_native_res,
                                                            ),
                                                        )
                                                    };
                                                if let Some(caps_payload) = encode_host_display_caps(
                                                    host,
                                                    caps_native,
                                                    session_max_res,
                                                    presets,
                                                    host_hevc_available(hevc_runtime_failed),
                                                    &codec_negotiator,
                                                    hardware_media_active,
                                                    still_refine.stream_epoch(),
                                                ) {
                                                    pending_display_tx.push_back(caps_payload);
                                                }
                                            }
                                        }
                                        Some(DisplayControlMsg::ClientMediaCaps {
                                            decode_caps,
                                            refinement_caps,
                                            pref,
                                            supports_ext_codec_flags,
                                        }) => {
                                            still_refine.on_client_media_caps(
                                                refinement_caps.as_ref(),
                                                pref,
                                            );
                                            if let Some(cur) = host.negotiated() {
                                                let prev_codec = host.active_codec();
                                                let prev_dims = (cur.width, cur.height);
                                                let target = StreamTarget {
                                                    width: cur.width,
                                                    height: cur.height,
                                                    fps: cur.fps,
                                                };
                                                let plan = codec_negotiator.on_client_media_caps(
                                                    decode_caps,
                                                    refinement_caps,
                                                    pref,
                                                    supports_ext_codec_flags,
                                                    target,
                                                    current_net_hint(host),
                                                );
                                                if plan.codec != prev_codec {
                                                    let (target_w, target_h, next_auto_hidpi) =
                                                        if !user_pinned_resolution
                                                            && active_display_id.is_none()
                                                            && prefer_hardware
                                                            && hardware_video_active
                                                        {
                                                            resolve_auto_hidpi_resolution(
                                                                cur.width,
                                                                cur.height,
                                                                session_native_res,
                                                                session_max_res,
                                                                cur.fps,
                                                                plan.codec,
                                                                auto_hidpi_active,
                                                            )
                                                        } else {
                                                            (
                                                                cur.width,
                                                                cur.height,
                                                                auto_hidpi_active,
                                                            )
                                                        };
                                                    match host.reconfigure_stream_with_codec(
                                                        target_w,
                                                        target_h,
                                                        Some(cur.fps),
                                                        Some(session_max_res),
                                                        Some(plan.codec),
                                                    ) {
                                                        Ok(_) => {
                                                            auto_hidpi_active = next_auto_hidpi
                                                                && host.active_codec()
                                                                    == rc_encode::Codec::Hevc;
                                                        }
                                                        Err(err) => {
                                                            eprintln!(
                                                                "[rc-ui-host] ClientMediaCaps 自动选型切换 ({:?}) 失败: {err}",
                                                                plan.codec
                                                            );
                                                        }
                                                    }
                                                    if host.active_codec() != plan.codec {
                                                        let _ = codec_negotiator.on_encode_failure(
                                                            plan.codec,
                                                            "selected codec encoder init failed",
                                                            host.active_codec(),
                                                            target,
                                                            current_net_hint(host),
                                                        );
                                                        if plan.codec == rc_encode::Codec::Hevc {
                                                            hevc_runtime_failed = true;
                                                        }
                                                    }
                                                    if host.active_codec() != prev_codec {
                                                        codec_negotiator.bump_generation();
                                                    }
                                                    if let Some(n) = host.negotiated() {
                                                        if host.active_codec() != prev_codec
                                                            || (n.width, n.height) != prev_dims
                                                        {
                                                            still_refine
                                                                .on_stream_reset(n.width, n.height);
                                                        }
                                                    }
                                                }
                                            }
                                            let (caps_native, presets) =
                                                if active_display_id.is_some() {
                                                    (
                                                        session_native_res,
                                                        display_ctrl::build_resolution_presets(
                                                            session_native_res.width,
                                                            session_native_res.height,
                                                            session_max_res.width,
                                                            session_max_res.height,
                                                        ),
                                                    )
                                                } else {
                                                    (
                                                        original_native_res
                                                            .unwrap_or(session_native_res),
                                                        build_hardware_display_presets(
                                                            prefer_hardware,
                                                            hardware_video_active,
                                                            original_native_res,
                                                        ),
                                                    )
                                                };
                                            if let Some(caps_payload) = encode_host_display_caps(
                                                host,
                                                caps_native,
                                                session_max_res,
                                                presets,
                                                host_hevc_available(hevc_runtime_failed),
                                                &codec_negotiator,
                                                hardware_media_active,
                                                still_refine.stream_epoch(),
                                            ) {
                                                pending_display_tx.push_back(caps_payload);
                                            }
                                        }
                                        Some(DisplayControlMsg::StillRefineConfig { enabled }) => {
                                            still_refine.on_still_refine_config(enabled);
                                        }
                                        Some(DisplayControlMsg::CodecDecodeFailed {
                                            codec,
                                            generation,
                                            reason,
                                        }) => {
                                            if let (Some(failed_codec), Some(cur)) = (
                                                rc_encode::Codec::parse_lossy(&codec),
                                                host.negotiated(),
                                            ) {
                                                let target = StreamTarget {
                                                    width: cur.width,
                                                    height: cur.height,
                                                    fps: cur.fps,
                                                };
                                                let prev_codec = host.active_codec();
                                                if let Some(fallback_plan) = codec_negotiator
                                                    .on_codec_decode_failed(
                                                        failed_codec,
                                                        generation,
                                                        reason,
                                                        prev_codec,
                                                        target,
                                                        current_net_hint(host),
                                                    )
                                                {
                                                    if failed_codec == rc_encode::Codec::Hevc {
                                                        hevc_runtime_failed = true;
                                                    }
                                                    let (tw, th) = if fallback_plan.codec
                                                        == rc_encode::Codec::H264
                                                        && !user_pinned_resolution
                                                        && active_display_id.is_none()
                                                        && (cur.width > session_native_res.width
                                                            || cur.height
                                                                > session_native_res.height)
                                                    {
                                                        auto_hidpi_active = false;
                                                        (
                                                            session_native_res.width,
                                                            session_native_res.height,
                                                        )
                                                    } else {
                                                        (cur.width, cur.height)
                                                    };
                                                    let _ = host.reconfigure_stream_with_codec(
                                                        tw,
                                                        th,
                                                        Some(cur.fps),
                                                        Some(session_max_res),
                                                        Some(fallback_plan.codec),
                                                    );
                                                    // 若降级目标（如 HEVC）在编码侧同样构造失败并被 HostSession 内部顺延 H.264，
                                                    // 同步记录熔断、更新 hevc_runtime_failed 并按需回退自动 HiDPI 分辨率。
                                                    if fallback_plan.codec != rc_encode::Codec::H264
                                                        && host.active_codec()
                                                            != fallback_plan.codec
                                                    {
                                                        let _ = codec_negotiator.on_encode_failure(
                                                            fallback_plan.codec,
                                                            "fallback codec encoder init failed",
                                                            host.active_codec(),
                                                            target,
                                                            current_net_hint(host),
                                                        );
                                                        if fallback_plan.codec
                                                            == rc_encode::Codec::Hevc
                                                        {
                                                            hevc_runtime_failed = true;
                                                        }
                                                        auto_hidpi_active = false;
                                                        if host.active_codec()
                                                            == rc_encode::Codec::H264
                                                            && !user_pinned_resolution
                                                            && active_display_id.is_none()
                                                            && host.negotiated().is_some_and(|n| {
                                                                n.width > session_native_res.width
                                                                    || n.height
                                                                        > session_native_res.height
                                                            })
                                                        {
                                                            let _ = host
                                                                .reconfigure_stream_with_codec(
                                                                    session_native_res.width,
                                                                    session_native_res.height,
                                                                    Some(cur.fps),
                                                                    Some(session_max_res),
                                                                    Some(rc_encode::Codec::H264),
                                                                );
                                                        }
                                                    }
                                                    if host.active_codec() != prev_codec {
                                                        codec_negotiator.bump_generation();
                                                    }
                                                    let (caps_native, presets) =
                                                        if active_display_id.is_some() {
                                                            (
                                                                session_native_res,
                                                                display_ctrl::build_resolution_presets(
                                                                    session_native_res.width,
                                                                    session_native_res.height,
                                                                    session_max_res.width,
                                                                    session_max_res.height,
                                                                ),
                                                            )
                                                        } else {
                                                            (
                                                                original_native_res
                                                                    .unwrap_or(session_native_res),
                                                                build_hardware_display_presets(
                                                                    prefer_hardware,
                                                                    hardware_video_active,
                                                                    original_native_res,
                                                                ),
                                                            )
                                                        };
                                                    if let Some(n) = host.negotiated() {
                                                        still_refine
                                                            .on_stream_reset(n.width, n.height);
                                                    }
                                                    if let Some(caps_payload) =
                                                        encode_host_display_caps(
                                                            host,
                                                            caps_native,
                                                            session_max_res,
                                                            presets,
                                                            host_hevc_available(
                                                                hevc_runtime_failed,
                                                            ),
                                                            &codec_negotiator,
                                                            hardware_media_active,
                                                            still_refine.stream_epoch(),
                                                        )
                                                    {
                                                        pending_display_tx.push_back(caps_payload);
                                                    }
                                                }
                                            }
                                        }
                                        Some(DisplayControlMsg::LockScreen) => {
                                            trigger_host_lock_screen(
                                                lock_screen_count,
                                                prefer_hardware,
                                            );
                                        }
                                        Some(DisplayControlMsg::SetCodec { codec }) => {
                                            codec_negotiator
                                                .reset_breaker_on_manual_or_res_change();
                                            hevc_runtime_failed = false;
                                            let cur_tier = host.negotiated().map_or(
                                                ResolutionTier::Fhd1080,
                                                |n| {
                                                    ResolutionTier::from_dimensions(
                                                        n.width, n.height,
                                                    )
                                                },
                                            );
                                            let target_codec =
                                                display_ctrl::StreamCodec::parse_lossy(&codec)
                                                    .and_then(|c| match c {
                                                        display_ctrl::StreamCodec::Av1 => {
                                                            codec_negotiator
                                                                .is_codec_selectable(
                                                                    rc_encode::Codec::Av1,
                                                                    cur_tier,
                                                                )
                                                                .then_some(rc_encode::Codec::Av1)
                                                        }
                                                        display_ctrl::StreamCodec::Hevc => {
                                                            host_hevc_available(hevc_runtime_failed)
                                                                .then_some(rc_encode::Codec::Hevc)
                                                        }
                                                        display_ctrl::StreamCodec::H264 => {
                                                            Some(rc_encode::Codec::H264)
                                                        }
                                                    });
                                            if let (Some(c), Some(cur)) =
                                                (target_codec, host.negotiated())
                                            {
                                                codec_negotiator.set_manual_pref(c);
                                                let prev_codec = host.active_codec();
                                                // 双端协商切入 HEVC 且用户尚未手动固定分辨率时，在同一次管线重建中一步升级到
                                                // Retina HiDPI 2K 甜点（满足当前 fps 的 HEVC 高刷预算）；切回 H.264 时若此前自动升过级，
                                                // 同步回退到原生逻辑分辨率，避免非 HEVC/H.264 掉帧。
                                                let (target_w, target_h, next_auto_hidpi) =
                                                    if !user_pinned_resolution
                                                        && active_display_id.is_none()
                                                        && prefer_hardware
                                                        && hardware_video_active
                                                    {
                                                        resolve_auto_hidpi_resolution(
                                                            cur.width,
                                                            cur.height,
                                                            session_native_res,
                                                            session_max_res,
                                                            cur.fps,
                                                            c,
                                                            auto_hidpi_active,
                                                        )
                                                    } else {
                                                        (cur.width, cur.height, auto_hidpi_active)
                                                    };
                                                match host.reconfigure_stream_with_codec(
                                                    target_w,
                                                    target_h,
                                                    Some(cur.fps),
                                                    Some(session_max_res),
                                                    Some(c),
                                                ) {
                                                    Ok(_) => {
                                                        auto_hidpi_active = next_auto_hidpi
                                                            && host.active_codec()
                                                                == rc_encode::Codec::Hevc;
                                                    }
                                                    Err(err) => {
                                                        eprintln!(
                                                            "[rc-ui-host] 热切换编解码器 ({c:?}) 失败（保持当前管线）: {err}"
                                                        );
                                                    }
                                                }
                                                if c != rc_encode::Codec::H264
                                                    && host.active_codec() != c
                                                {
                                                    let fail_target = StreamTarget {
                                                        width: cur.width,
                                                        height: cur.height,
                                                        fps: cur.fps,
                                                    };
                                                    let _ = codec_negotiator.on_encode_failure(
                                                        c,
                                                        "manual SetCodec encoder init failed",
                                                        host.active_codec(),
                                                        fail_target,
                                                        current_net_hint(host),
                                                    );
                                                    if c == rc_encode::Codec::Hevc {
                                                        hevc_runtime_failed = true;
                                                    }
                                                    auto_hidpi_active = false;
                                                    // 若 HEVC/AV1 启动失败且管线回退为 H.264 但分辨率已被升至 2K，立即回退到原生逻辑分辨率。
                                                    if host.active_codec() == rc_encode::Codec::H264
                                                        && !user_pinned_resolution
                                                        && active_display_id.is_none()
                                                        && host.negotiated().is_some_and(|n| {
                                                            n.width > session_native_res.width
                                                                || n.height
                                                                    > session_native_res.height
                                                        })
                                                    {
                                                        let _ = host.reconfigure_stream_with_codec(
                                                            session_native_res.width,
                                                            session_native_res.height,
                                                            Some(cur.fps),
                                                            Some(session_max_res),
                                                            Some(rc_encode::Codec::H264),
                                                        );
                                                    }
                                                }
                                                if host.active_codec() != prev_codec {
                                                    codec_negotiator.bump_generation();
                                                    if let Some(n) = host.negotiated() {
                                                        still_refine
                                                            .on_stream_reset(n.width, n.height);
                                                    }
                                                }
                                            }
                                            // 无论切换成功、幂等或拒绝，均回推最新 Capabilities，让控制端获知权威生效 codec。
                                            let (caps_native, presets) =
                                                if active_display_id.is_some() {
                                                    (
                                                        session_native_res,
                                                        display_ctrl::build_resolution_presets(
                                                            session_native_res.width,
                                                            session_native_res.height,
                                                            session_max_res.width,
                                                            session_max_res.height,
                                                        ),
                                                    )
                                                } else {
                                                    (
                                                        original_native_res
                                                            .unwrap_or(session_native_res),
                                                        build_hardware_display_presets(
                                                            prefer_hardware,
                                                            hardware_video_active,
                                                            original_native_res,
                                                        ),
                                                    )
                                                };
                                            if let Some(caps_payload) = encode_host_display_caps(
                                                host,
                                                caps_native,
                                                session_max_res,
                                                presets,
                                                host_hevc_available(hevc_runtime_failed),
                                                &codec_negotiator,
                                                hardware_media_active,
                                                still_refine.stream_epoch(),
                                            ) {
                                                pending_display_tx.push_back(caps_payload);
                                            }
                                        }
                                        Some(DisplayControlMsg::SetPrivacyMode {
                                            mode,
                                            preset,
                                            custom_image_base64,
                                        }) => {
                                            let norm_mode = match mode.as_str() {
                                                "privacy" | "black" => mode.as_str(),
                                                _ => "off",
                                            };
                                            let norm_preset = match preset.as_str() {
                                                "preset-1" | "preset-2" | "preset-3"
                                                | "preset-4" | "preset-5" | "preset-6"
                                                | "custom" => preset.as_str(),
                                                _ => "preset-1",
                                            };
                                            let mut hevc_fell_back = false;
                                            let (applied_mode, applied_preset, supported) =
                                                if !(prefer_hardware && hardware_video_active) {
                                                    ("off", norm_preset, false)
                                                } else if norm_mode == "off" {
                                                    let was_active = hw_cleanup.privacy_active;
                                                    if was_active {
                                                        crate::platform::clear_privacy_curtain();
                                                        hw_cleanup.privacy_active = false;
                                                        if let Some(cur) = host.negotiated() {
                                                            let wanted_hevc = host.active_codec()
                                                                == rc_encode::Codec::Hevc;
                                                            let _ = host.force_reconfigure_stream(
                                                                cur.width,
                                                                cur.height,
                                                                Some(cur.fps),
                                                                Some(session_max_res),
                                                                None,
                                                            );
                                                            if wanted_hevc
                                                                && host.active_codec()
                                                                    != rc_encode::Codec::Hevc
                                                            {
                                                                hevc_runtime_failed = true;
                                                                auto_hidpi_active = false;
                                                                hevc_fell_back = true;
                                                                if !user_pinned_resolution
                                                                    && active_display_id.is_none()
                                                                    && host.negotiated().is_some_and(
                                                                        |n| {
                                                                            n.width
                                                                                > session_native_res
                                                                                    .width
                                                                                || n.height
                                                                                    > session_native_res
                                                                                        .height
                                                                        },
                                                                    )
                                                                {
                                                                    let _ = host
                                                                        .reconfigure_stream_with_codec(
                                                                            session_native_res.width,
                                                                            session_native_res
                                                                                .height,
                                                                            Some(cur.fps),
                                                                            Some(session_max_res),
                                                                            Some(
                                                                                rc_encode::Codec::H264,
                                                                            ),
                                                                        );
                                                                }
                                                            }
                                                        }
                                                    }
                                                    ("off", norm_preset, true)
                                                } else {
                                                    let decoded_custom = custom_image_base64
                                                        .as_deref()
                                                        .and_then(display_ctrl::base64_decode)
                                                        .filter(|b| {
                                                            is_valid_privacy_image_bytes(b)
                                                        });
                                                    let eff_preset = if norm_preset == "custom"
                                                        && decoded_custom.is_none()
                                                    {
                                                        "preset-1"
                                                    } else {
                                                        norm_preset
                                                    };
                                                    match crate::platform::set_privacy_curtain(
                                                        norm_mode,
                                                        eff_preset,
                                                        decoded_custom.as_deref(),
                                                    ) {
                                                        Ok(()) => {
                                                            hw_cleanup.privacy_active = true;
                                                            // 重建 SCK 流使 SCContentFilter 立即排除新创建的幕布窗口。
                                                            if let Some(cur) = host.negotiated() {
                                                                let wanted_hevc = host
                                                                    .active_codec()
                                                                    == rc_encode::Codec::Hevc;
                                                                let _ = host
                                                                    .force_reconfigure_stream(
                                                                        cur.width,
                                                                        cur.height,
                                                                        Some(cur.fps),
                                                                        Some(session_max_res),
                                                                        None,
                                                                    );
                                                                if wanted_hevc
                                                                    && host.active_codec()
                                                                        != rc_encode::Codec::Hevc
                                                                {
                                                                    hevc_runtime_failed = true;
                                                                    auto_hidpi_active = false;
                                                                    hevc_fell_back = true;
                                                                    if !user_pinned_resolution
                                                                        && active_display_id
                                                                            .is_none()
                                                                        && host
                                                                            .negotiated()
                                                                            .is_some_and(|n| {
                                                                                n.width
                                                                                    > session_native_res
                                                                                        .width
                                                                                    || n.height
                                                                                        > session_native_res
                                                                                            .height
                                                                            })
                                                                    {
                                                                        let _ = host
                                                                            .reconfigure_stream_with_codec(
                                                                                session_native_res
                                                                                    .width,
                                                                                session_native_res
                                                                                    .height,
                                                                                Some(cur.fps),
                                                                                Some(
                                                                                    session_max_res,
                                                                                ),
                                                                                Some(
                                                                                    rc_encode::Codec::H264,
                                                                                ),
                                                                            );
                                                                    }
                                                                }
                                                            }
                                                            (norm_mode, eff_preset, true)
                                                        }
                                                        Err(err) => {
                                                            eprintln!(
                                                                "[rc-ui-host] 设置防窥隐私幕布失败: {err}"
                                                            );
                                                            if hw_cleanup.privacy_active {
                                                                crate::platform::clear_privacy_curtain();
                                                                hw_cleanup.privacy_active = false;
                                                            }
                                                            ("off", eff_preset, false)
                                                        }
                                                    }
                                                };
                                            if let Some(p) = display_ctrl::encode_display_ctrl(
                                                &DisplayControlMsg::PrivacyState {
                                                    mode: applied_mode.to_string(),
                                                    preset: applied_preset.to_string(),
                                                    supported,
                                                },
                                            ) {
                                                pending_display_tx.push_back(p);
                                            }
                                            if hevc_fell_back {
                                                let (caps_native, presets) =
                                                    if active_display_id.is_some() {
                                                        (
                                                            session_native_res,
                                                            display_ctrl::build_resolution_presets(
                                                                session_native_res.width,
                                                                session_native_res.height,
                                                                session_max_res.width,
                                                                session_max_res.height,
                                                            ),
                                                        )
                                                    } else {
                                                        (
                                                            original_native_res
                                                                .unwrap_or(session_native_res),
                                                            build_hardware_display_presets(
                                                                prefer_hardware,
                                                                hardware_video_active,
                                                                original_native_res,
                                                            ),
                                                        )
                                                    };
                                                if let Some(n) = host.negotiated() {
                                                    still_refine.on_stream_reset(n.width, n.height);
                                                }
                                                if let Some(cp) = encode_host_display_caps(
                                                    host,
                                                    caps_native,
                                                    session_max_res,
                                                    presets,
                                                    host_hevc_available(hevc_runtime_failed),
                                                    &codec_negotiator,
                                                    hardware_media_active,
                                                    still_refine.stream_epoch(),
                                                ) {
                                                    pending_display_tx.push_back(cp);
                                                }
                                            }
                                        }
                                        Some(DisplayControlMsg::SetHostMute {
                                            muted,
                                            restore_on_exit,
                                        }) => {
                                            hw_cleanup.restore_audio_on_exit = restore_on_exit;
                                            let (eff_muted, supported) = if !prefer_hardware {
                                                (false, false)
                                            } else {
                                                match crate::platform::set_host_system_muted(muted)
                                                {
                                                    Ok(actual) => {
                                                        hw_cleanup.host_audio_modified = true;
                                                        (actual, true)
                                                    }
                                                    Err(err) => {
                                                        eprintln!(
                                                            "[rc-ui-host] 设置被控端系统静音失败: {err}"
                                                        );
                                                        (false, false)
                                                    }
                                                }
                                            };
                                            if let Some(p) = display_ctrl::encode_display_ctrl(
                                                &DisplayControlMsg::HostMuteState {
                                                    muted: eff_muted,
                                                    supported,
                                                },
                                            ) {
                                                pending_display_tx.push_back(p);
                                            }
                                        }
                                        Some(DisplayControlMsg::SetMouseMode { mode }) => {
                                            let norm = match mode.as_str() {
                                                "remote" => "remote",
                                                "local" => "local",
                                                _ => "smart",
                                            };
                                            let want_cursor = norm == "remote";
                                            let mut hevc_fell_back = false;
                                            if want_cursor != shows_cursor {
                                                let prev_cursor = shows_cursor;
                                                shows_cursor = want_cursor;
                                                host.set_capture_options(
                                                    active_display_id,
                                                    shows_cursor,
                                                );
                                                if let Some(cur) = host.negotiated() {
                                                    let wanted_hevc = host.active_codec()
                                                        == rc_encode::Codec::Hevc;
                                                    if let Err(err) = host.force_reconfigure_stream(
                                                        cur.width,
                                                        cur.height,
                                                        Some(cur.fps),
                                                        Some(session_max_res),
                                                        None,
                                                    ) {
                                                        eprintln!(
                                                            "[rc-ui-host] 切换鼠标光标采集失败（回滚）: {err}"
                                                        );
                                                        shows_cursor = prev_cursor;
                                                        host.set_capture_options(
                                                            active_display_id,
                                                            shows_cursor,
                                                        );
                                                    }
                                                    if wanted_hevc
                                                        && host.active_codec()
                                                            != rc_encode::Codec::Hevc
                                                    {
                                                        hevc_runtime_failed = true;
                                                        auto_hidpi_active = false;
                                                        hevc_fell_back = true;
                                                        if !user_pinned_resolution
                                                            && active_display_id.is_none()
                                                            && host.negotiated().is_some_and(|n| {
                                                                n.width > session_native_res.width
                                                                    || n.height
                                                                        > session_native_res.height
                                                            })
                                                        {
                                                            let _ = host
                                                                .reconfigure_stream_with_codec(
                                                                    session_native_res.width,
                                                                    session_native_res.height,
                                                                    Some(cur.fps),
                                                                    Some(session_max_res),
                                                                    Some(rc_encode::Codec::H264),
                                                                );
                                                        }
                                                    }
                                                }
                                            }
                                            let reported_mode = if shows_cursor {
                                                "remote"
                                            } else if norm == "local" {
                                                "local"
                                            } else {
                                                "smart"
                                            };
                                            if let Some(p) = display_ctrl::encode_display_ctrl(
                                                &DisplayControlMsg::MouseModeState {
                                                    mode: reported_mode.to_string(),
                                                },
                                            ) {
                                                pending_display_tx.push_back(p);
                                            }
                                            if hevc_fell_back {
                                                let (caps_native, presets) =
                                                    if active_display_id.is_some() {
                                                        (
                                                            session_native_res,
                                                            display_ctrl::build_resolution_presets(
                                                                session_native_res.width,
                                                                session_native_res.height,
                                                                session_max_res.width,
                                                                session_max_res.height,
                                                            ),
                                                        )
                                                    } else {
                                                        (
                                                            original_native_res
                                                                .unwrap_or(session_native_res),
                                                            build_hardware_display_presets(
                                                                prefer_hardware,
                                                                hardware_video_active,
                                                                original_native_res,
                                                            ),
                                                        )
                                                    };
                                                if let Some(n) = host.negotiated() {
                                                    still_refine.on_stream_reset(n.width, n.height);
                                                }
                                                if let Some(cp) = encode_host_display_caps(
                                                    host,
                                                    caps_native,
                                                    session_max_res,
                                                    presets,
                                                    host_hevc_available(hevc_runtime_failed),
                                                    &codec_negotiator,
                                                    hardware_media_active,
                                                    still_refine.stream_epoch(),
                                                ) {
                                                    pending_display_tx.push_back(cp);
                                                }
                                            }
                                        }
                                        Some(DisplayControlMsg::ListDisplays) => {
                                            if prefer_hardware && hardware_video_active {
                                                if let Some(p) =
                                                    encode_host_displays_state(active_display_id)
                                                {
                                                    pending_display_tx.push_back(p);
                                                }
                                            }
                                        }
                                        Some(DisplayControlMsg::SwitchDisplay { display_id }) => {
                                            if prefer_hardware && hardware_video_active {
                                                let displays = crate::platform::list_displays();
                                                if let Some(target) =
                                                    displays.iter().find(|d| d.id == display_id)
                                                {
                                                    let prev_active = active_display_id;
                                                    let prev_native = session_native_res;
                                                    let prev_max = session_max_res;
                                                    let next_active = if target.is_main {
                                                        None
                                                    } else {
                                                        Some(target.id)
                                                    };
                                                    let disp_res = Resolution::new(
                                                        target.width,
                                                        target.height,
                                                    )
                                                    .to_even();
                                                    let next_max = if target.is_main {
                                                        compute_host_display_bounds(
                                                            host,
                                                            prefer_hardware,
                                                            hardware_video_active,
                                                        )
                                                        .1
                                                    } else {
                                                        Resolution::new(
                                                            disp_res.width.saturating_mul(2).min(
                                                                display_ctrl::MAX_STREAM_WIDTH,
                                                            ),
                                                            disp_res.height.saturating_mul(2).min(
                                                                display_ctrl::MAX_STREAM_HEIGHT,
                                                            ),
                                                        )
                                                    };
                                                    host.set_capture_options(
                                                        next_active,
                                                        shows_cursor,
                                                    );
                                                    let wanted_hevc = host.active_codec()
                                                        == rc_encode::Codec::Hevc;
                                                    let cur_fps = host.negotiated().map(|c| c.fps);
                                                    let (reconfig_ok, next_auto_hidpi) =
                                                        if let Some(cur) = host.negotiated() {
                                                            let (tw, th, is_hi) = if target.is_main
                                                                && wanted_hevc
                                                            {
                                                                let hi = compute_hevc_hidpi_target(
                                                                    disp_res,
                                                                    Some(next_max),
                                                                    cur.fps,
                                                                );
                                                                (
                                                                    hi.width,
                                                                    hi.height,
                                                                    hi.width > disp_res.width
                                                                        || hi.height
                                                                            > disp_res.height,
                                                                )
                                                            } else {
                                                                (
                                                                    disp_res.width,
                                                                    disp_res.height,
                                                                    false,
                                                                )
                                                            };
                                                            (
                                                                host.force_reconfigure_stream(
                                                                    tw,
                                                                    th,
                                                                    Some(cur.fps),
                                                                    Some(next_max),
                                                                    None,
                                                                )
                                                                .is_ok(),
                                                                is_hi,
                                                            )
                                                        } else {
                                                            (true, false)
                                                        };
                                                    if reconfig_ok {
                                                        audio_mgr.reset_backoff_for_display_change(
                                                            Instant::now(),
                                                        );
                                                        active_display_id = next_active;
                                                        session_native_res = disp_res;
                                                        session_max_res = next_max;
                                                        user_pinned_resolution = false;
                                                        auto_hidpi_active = next_auto_hidpi
                                                            && host.active_codec()
                                                                == rc_encode::Codec::Hevc;
                                                        if wanted_hevc
                                                            && host.active_codec()
                                                                != rc_encode::Codec::Hevc
                                                        {
                                                            hevc_runtime_failed = true;
                                                            auto_hidpi_active = false;
                                                            if target.is_main
                                                                && host.negotiated().is_some_and(
                                                                    |n| {
                                                                        n.width
                                                                            > session_native_res
                                                                                .width
                                                                            || n.height
                                                                                > session_native_res
                                                                                    .height
                                                                    },
                                                                )
                                                            {
                                                                let _ = host
                                                                    .reconfigure_stream_with_codec(
                                                                        session_native_res.width,
                                                                        session_native_res.height,
                                                                        cur_fps,
                                                                        Some(session_max_res),
                                                                        Some(
                                                                            rc_encode::Codec::H264,
                                                                        ),
                                                                    );
                                                            }
                                                        }
                                                        host.set_injector_screen_bounds(
                                                            target.origin_x,
                                                            target.origin_y,
                                                            target.width,
                                                            target.height,
                                                        );
                                                        let (caps_native, presets) = if target
                                                            .is_main
                                                        {
                                                            let nat = original_native_res
                                                                .unwrap_or(disp_res);
                                                            (
                                                                nat,
                                                                build_hardware_display_presets(
                                                                    prefer_hardware,
                                                                    hardware_video_active,
                                                                    Some(nat),
                                                                ),
                                                            )
                                                        } else {
                                                            (
                                                                    disp_res,
                                                                    display_ctrl::build_resolution_presets(
                                                                        disp_res.width,
                                                                        disp_res.height,
                                                                        session_max_res.width,
                                                                        session_max_res.height,
                                                                    ),
                                                                )
                                                        };
                                                        if let Some(n) = host.negotiated() {
                                                            still_refine
                                                                .on_stream_reset(n.width, n.height);
                                                        }
                                                        if let Some(cp) = encode_host_display_caps(
                                                            host,
                                                            caps_native,
                                                            session_max_res,
                                                            presets,
                                                            host_hevc_available(
                                                                hevc_runtime_failed,
                                                            ),
                                                            &codec_negotiator,
                                                            hardware_media_active,
                                                            still_refine.stream_epoch(),
                                                        ) {
                                                            pending_display_tx.push_back(cp);
                                                        }
                                                    } else {
                                                        active_display_id = prev_active;
                                                        session_native_res = prev_native;
                                                        session_max_res = prev_max;
                                                        host.set_capture_options(
                                                            prev_active,
                                                            shows_cursor,
                                                        );
                                                    }
                                                }
                                                if let Some(dp) =
                                                    encode_host_displays_state(active_display_id)
                                                {
                                                    pending_display_tx.push_back(dp);
                                                }
                                            }
                                        }
                                        Some(DisplayControlMsg::CreateVirtualDisplay {
                                            width,
                                            height,
                                            hidpi,
                                        }) => {
                                            if !(prefer_hardware && hardware_video_active) {
                                                if let Some(ep) =
                                                    display_ctrl::encode_display_ctrl(
                                                        &DisplayControlMsg::VirtualDisplayError {
                                                            message: "当前会话未启用硬件视频管线，无法创建虚拟屏"
                                                                .to_string(),
                                                        },
                                                    )
                                                {
                                                    pending_display_tx.push_back(ep);
                                                }
                                            } else if hw_cleanup.virtual_display_count
                                                >= MAX_VIRTUAL_DISPLAYS_PER_SESSION
                                            {
                                                if let Some(ep) =
                                                    display_ctrl::encode_display_ctrl(
                                                        &DisplayControlMsg::VirtualDisplayError {
                                                            message: format!(
                                                                "单次会话最多创建 {MAX_VIRTUAL_DISPLAYS_PER_SESSION} 个虚拟显示器"
                                                            ),
                                                        },
                                                    )
                                                {
                                                    pending_display_tx.push_back(ep);
                                                }
                                            } else {
                                                let req_w = if width >= 640 {
                                                    width.min(3840)
                                                } else {
                                                    1920
                                                };
                                                let req_h = if height >= 480 {
                                                    height.min(2160)
                                                } else {
                                                    1080
                                                };
                                                match crate::platform::create_virtual_display(
                                                    req_w, req_h, hidpi,
                                                ) {
                                                    Ok(vinfo) => {
                                                        hw_cleanup.virtual_display_count =
                                                            hw_cleanup
                                                                .virtual_display_count
                                                                .saturating_add(1);
                                                        // 等待 WindowServer 将新虚拟屏注册到 CG/SCK 列表。
                                                        thread::sleep(Duration::from_millis(260));
                                                        let fresh_list =
                                                            crate::platform::list_displays();
                                                        let resolved = fresh_list
                                                            .iter()
                                                            .find(|d| d.id == vinfo.id)
                                                            .cloned()
                                                            .unwrap_or(vinfo);
                                                        let prev_active = active_display_id;
                                                        let prev_native = session_native_res;
                                                        let prev_max = session_max_res;
                                                        let vres = Resolution::new(
                                                            resolved.width,
                                                            resolved.height,
                                                        )
                                                        .to_even();
                                                        let next_max = Resolution::new(
                                                            vres.width
                                                                .saturating_mul(2)
                                                                .min(
                                                                    display_ctrl::MAX_STREAM_WIDTH,
                                                                ),
                                                            vres.height
                                                                .saturating_mul(2)
                                                                .min(
                                                                    display_ctrl::MAX_STREAM_HEIGHT,
                                                                ),
                                                        );
                                                        host.set_capture_options(
                                                            Some(resolved.id),
                                                            shows_cursor,
                                                        );
                                                        let wanted_hevc = host.active_codec()
                                                            == rc_encode::Codec::Hevc;
                                                        let switch_res = if let Some(cur) =
                                                            host.negotiated()
                                                        {
                                                            host.force_reconfigure_stream(
                                                                vres.width,
                                                                vres.height,
                                                                Some(cur.fps),
                                                                Some(next_max),
                                                                None,
                                                            )
                                                            .map(|_| ())
                                                        } else {
                                                            Ok(())
                                                        };
                                                        match switch_res {
                                                            Ok(()) => {
                                                                audio_mgr
                                                                    .reset_backoff_for_display_change(
                                                                        Instant::now(),
                                                                    );
                                                                active_display_id =
                                                                    Some(resolved.id);
                                                                session_native_res = vres;
                                                                session_max_res = next_max;
                                                                user_pinned_resolution = false;
                                                                auto_hidpi_active = false;
                                                                if wanted_hevc
                                                                    && host.active_codec()
                                                                        != rc_encode::Codec::Hevc
                                                                {
                                                                    hevc_runtime_failed = true;
                                                                }
                                                                host.set_injector_screen_bounds(
                                                                    resolved.origin_x,
                                                                    resolved.origin_y,
                                                                    resolved.width,
                                                                    resolved.height,
                                                                );
                                                                let presets =
                                                                    display_ctrl::build_resolution_presets(
                                                                        vres.width,
                                                                        vres.height,
                                                                        session_max_res.width,
                                                                        session_max_res.height,
                                                                    );
                                                                if let Some(n) = host.negotiated() {
                                                                    still_refine.on_stream_reset(
                                                                        n.width, n.height,
                                                                    );
                                                                }
                                                                if let Some(cp) =
                                                                    encode_host_display_caps(
                                                                        host,
                                                                        vres,
                                                                        session_max_res,
                                                                        presets,
                                                                        host_hevc_available(
                                                                            hevc_runtime_failed,
                                                                        ),
                                                                        &codec_negotiator,
                                                                        hardware_media_active,
                                                                        still_refine.stream_epoch(),
                                                                    )
                                                                {
                                                                    pending_display_tx
                                                                        .push_back(cp);
                                                                }
                                                            }
                                                            Err(err) => {
                                                                eprintln!(
                                                                    "[rc-ui-host] 切换至虚拟屏失败（回滚）: {err}"
                                                                );
                                                                active_display_id = prev_active;
                                                                session_native_res = prev_native;
                                                                session_max_res = prev_max;
                                                                host.set_capture_options(
                                                                    prev_active,
                                                                    shows_cursor,
                                                                );
                                                                if let Some(ep) =
                                                                    display_ctrl::encode_display_ctrl(
                                                                        &DisplayControlMsg::VirtualDisplayError {
                                                                            message: format!(
                                                                                "虚拟屏已创建但切换采集失败：{err}"
                                                                            ),
                                                                        },
                                                                    )
                                                                {
                                                                    pending_display_tx
                                                                        .push_back(ep);
                                                                }
                                                            }
                                                        }
                                                        if let Some(dp) =
                                                            encode_host_displays_state(
                                                                active_display_id,
                                                            )
                                                        {
                                                            pending_display_tx.push_back(dp);
                                                        }
                                                    }
                                                    Err(msg) => {
                                                        if let Some(ep) =
                                                            display_ctrl::encode_display_ctrl(
                                                                &DisplayControlMsg::VirtualDisplayError {
                                                                    message: msg,
                                                                },
                                                            )
                                                        {
                                                            pending_display_tx.push_back(ep);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Some(DisplayControlMsg::RemoveVirtualDisplay {
                                            display_id,
                                        }) if prefer_hardware && hardware_video_active => {
                                            let was_active = active_display_id == Some(display_id);
                                            let removed = crate::platform::destroy_virtual_display(
                                                display_id,
                                            );
                                            if removed {
                                                audio_mgr.reset_backoff_for_display_change(
                                                    Instant::now(),
                                                );
                                                hw_cleanup.virtual_display_count = hw_cleanup
                                                    .virtual_display_count
                                                    .saturating_sub(1);
                                            }
                                            if removed && was_active {
                                                active_display_id = None;
                                                host.set_capture_options(None, shows_cursor);
                                                let (main_native, main_max) =
                                                    compute_host_display_bounds(
                                                        host,
                                                        prefer_hardware,
                                                        hardware_video_active,
                                                    );
                                                let caps_native =
                                                    original_native_res.unwrap_or(main_native);
                                                session_native_res = main_native;
                                                session_max_res = main_max;
                                                user_pinned_resolution = false;
                                                auto_hidpi_active = false;
                                                let main_origin = crate::platform::list_displays()
                                                    .into_iter()
                                                    .find(|d| d.is_main)
                                                    .map(|d| (d.origin_x, d.origin_y))
                                                    .unwrap_or((0.0, 0.0));
                                                host.set_injector_screen_bounds(
                                                    main_origin.0,
                                                    main_origin.1,
                                                    main_native.width,
                                                    main_native.height,
                                                );
                                                if let Some(cur) = host.negotiated() {
                                                    let wanted_hevc = host.active_codec()
                                                        == rc_encode::Codec::Hevc;
                                                    let (tw, th, is_hi) = if wanted_hevc {
                                                        let hi = compute_hevc_hidpi_target(
                                                            main_native,
                                                            Some(session_max_res),
                                                            cur.fps,
                                                        );
                                                        (
                                                            hi.width,
                                                            hi.height,
                                                            hi.width > main_native.width
                                                                || hi.height > main_native.height,
                                                        )
                                                    } else {
                                                        (
                                                            main_native.width,
                                                            main_native.height,
                                                            false,
                                                        )
                                                    };
                                                    if host
                                                        .force_reconfigure_stream(
                                                            tw,
                                                            th,
                                                            Some(cur.fps),
                                                            Some(session_max_res),
                                                            None,
                                                        )
                                                        .is_ok()
                                                    {
                                                        auto_hidpi_active = is_hi
                                                            && host.active_codec()
                                                                == rc_encode::Codec::Hevc;
                                                    }
                                                    if wanted_hevc
                                                        && host.active_codec()
                                                            != rc_encode::Codec::Hevc
                                                    {
                                                        hevc_runtime_failed = true;
                                                        auto_hidpi_active = false;
                                                        if host.negotiated().is_some_and(|n| {
                                                            n.width > session_native_res.width
                                                                || n.height
                                                                    > session_native_res.height
                                                        }) {
                                                            let _ = host
                                                                .reconfigure_stream_with_codec(
                                                                    session_native_res.width,
                                                                    session_native_res.height,
                                                                    Some(cur.fps),
                                                                    Some(session_max_res),
                                                                    Some(rc_encode::Codec::H264),
                                                                );
                                                        }
                                                    }
                                                }
                                                let presets = build_hardware_display_presets(
                                                    prefer_hardware,
                                                    hardware_video_active,
                                                    Some(caps_native),
                                                );
                                                if let Some(n) = host.negotiated() {
                                                    still_refine.on_stream_reset(n.width, n.height);
                                                }
                                                if let Some(cp) = encode_host_display_caps(
                                                    host,
                                                    caps_native,
                                                    session_max_res,
                                                    presets,
                                                    host_hevc_available(hevc_runtime_failed),
                                                    &codec_negotiator,
                                                    hardware_media_active,
                                                    still_refine.stream_epoch(),
                                                ) {
                                                    pending_display_tx.push_back(cp);
                                                }
                                            }
                                            if let Some(dp) =
                                                encode_host_displays_state(active_display_id)
                                            {
                                                pending_display_tx.push_back(dp);
                                            }
                                        }
                                        Some(DisplayControlMsg::SetMediaPaused { paused }) => {
                                            if paused {
                                                still_refine.on_input_event();
                                                host.pause_media();
                                                audio_mgr.pause(&mut audio_silence_gate);
                                                if let Some(mp) = display_ctrl::encode_display_ctrl(
                                                    &DisplayControlMsg::MediaState { paused: true },
                                                ) {
                                                    pending_display_tx.push_back(mp);
                                                }
                                            } else {
                                                let wanted_hevc =
                                                    host.active_codec() == rc_encode::Codec::Hevc;
                                                match host.resume_media() {
                                                    Ok(()) => {
                                                        if wanted_hevc
                                                            && host.active_codec()
                                                                != rc_encode::Codec::Hevc
                                                        {
                                                            hevc_runtime_failed = true;
                                                            auto_hidpi_active = false;
                                                        }
                                                        let (caps_native, presets) =
                                                            if active_display_id.is_some() {
                                                                (
                                                                    session_native_res,
                                                                    display_ctrl::build_resolution_presets(
                                                                        session_native_res.width,
                                                                        session_native_res.height,
                                                                        session_max_res.width,
                                                                        session_max_res.height,
                                                                    ),
                                                                )
                                                            } else {
                                                                (
                                                                    original_native_res.unwrap_or(
                                                                        session_native_res,
                                                                    ),
                                                                    build_hardware_display_presets(
                                                                        prefer_hardware,
                                                                        hardware_video_active,
                                                                        original_native_res,
                                                                    ),
                                                                )
                                                            };
                                                        if let Some(n) = host.negotiated() {
                                                            still_refine
                                                                .on_stream_reset(n.width, n.height);
                                                        }
                                                        if let Some(cp) = encode_host_display_caps(
                                                            host,
                                                            caps_native,
                                                            session_max_res,
                                                            presets,
                                                            host_hevc_available(
                                                                hevc_runtime_failed,
                                                            ),
                                                            &codec_negotiator,
                                                            hardware_media_active,
                                                            still_refine.stream_epoch(),
                                                        ) {
                                                            pending_display_tx.push_back(cp);
                                                        }
                                                        if prefer_hardware && hardware_video_active
                                                        {
                                                            if let Some(dp) =
                                                                encode_host_displays_state(
                                                                    active_display_id,
                                                                )
                                                            {
                                                                pending_display_tx.push_back(dp);
                                                            }
                                                        }
                                                        let screen_state = (
                                                            crate::platform::is_screen_locked(),
                                                            host.is_capture_suspended(),
                                                        );
                                                        if let Some(sp) =
                                                            display_ctrl::encode_display_ctrl(
                                                                &DisplayControlMsg::HostScreenState {
                                                                    locked: screen_state.0,
                                                                    capture_suspended: screen_state.1,
                                                                },
                                                            )
                                                        {
                                                            pending_display_tx.push_back(sp);
                                                        }
                                                        last_reported_screen_state =
                                                            Some(screen_state);
                                                        last_screen_state_check = Instant::now();
                                                        audio_mgr.resume(&mut audio_silence_gate);
                                                        if let Some(mp) =
                                                            display_ctrl::encode_display_ctrl(
                                                                &DisplayControlMsg::MediaState {
                                                                    paused: false,
                                                                },
                                                            )
                                                        {
                                                            pending_display_tx.push_back(mp);
                                                        }
                                                    }
                                                    Err(err) => {
                                                        eprintln!(
                                                            "[rc-ui-host] 恢复媒体管线失败: {err}"
                                                        );
                                                        if let Some(mp) =
                                                            display_ctrl::encode_display_ctrl(
                                                                &DisplayControlMsg::MediaState {
                                                                    paused: host.is_media_paused(),
                                                                },
                                                            )
                                                        {
                                                            pending_display_tx.push_back(mp);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Some(
                                            upd_msg @ (DisplayControlMsg::UpdateTrigger { .. }
                                            | DisplayControlMsg::UpdateCancel
                                            | DisplayControlMsg::UpdateChunkBegin {
                                                ..
                                            }
                                            | DisplayControlMsg::UpdateChunkData {
                                                ..
                                            }
                                            | DisplayControlMsg::UpdateChunkEnd
                                            | DisplayControlMsg::UpdateChunkAbort {
                                                ..
                                            }),
                                        ) => {
                                            update_worker.handle_message(
                                                upd_msg,
                                                host.authenticated_owner().is_some(),
                                            );
                                        }
                                        _ => {}
                                    }
                                    while pending_display_tx.len() > 64 {
                                        pending_display_tx.pop_front();
                                    }
                                }
                                _ => {}
                            }
                        }

                        let is_owner_for_update = host.authenticated_owner().is_some();
                        for umsg in update_worker.poll_outgoing() {
                            if pending_update_tx.enqueue(&umsg, is_owner_for_update) {
                                tools_busy = true;
                            }
                        }

                        // H12：非阻塞冲刷入站文件帧至 `rc-file-host-worker` 有界通道（满载时留待下拍重试，零丢帧）。
                        if current_tool_perms.allow_file_transfer {
                            while let Some(front) = pending_file_in.front() {
                                match file_worker.try_send_incoming(front.clone()) {
                                    Ok(()) => {
                                        pending_file_in.pop_front();
                                        tools_busy = true;
                                    }
                                    Err(mpsc::TrySendError::Full(_)) => break,
                                    Err(mpsc::TrySendError::Disconnected(_)) => {
                                        pending_file_in.clear();
                                        break;
                                    }
                                }
                            }
                        } else {
                            pending_file_in.clear();
                        }

                        // 2.5) 接收后台唤醒结果并节流巡检被控端锁屏与采集挂起态（250ms）：
                        // 变化时通知控制端；熄屏且未锁屏时异步派发单在途后台唤醒，绝不阻塞会话主循环。
                        mid_session_wake.poll_completed(&wake_guard, Instant::now());
                        if last_screen_state_check.elapsed() >= Duration::from_millis(250) {
                            let now_screen = Instant::now();
                            last_screen_state_check = now_screen;
                            let screen_locked = crate::platform::is_screen_locked();
                            let capture_suspended = host.is_capture_suspended();
                            let cur_state = (screen_locked, capture_suspended);
                            let should_emit = match last_reported_screen_state {
                                None => screen_locked || capture_suspended,
                                Some(prev) => prev != cur_state,
                            };
                            if should_emit {
                                if let Some(payload) = display_ctrl::encode_display_ctrl(
                                    &DisplayControlMsg::HostScreenState {
                                        locked: screen_locked,
                                        capture_suspended,
                                    },
                                ) {
                                    pending_display_tx.push_back(payload);
                                    while pending_display_tx.len() > 64 {
                                        pending_display_tx.pop_front();
                                    }
                                }
                            }
                            last_reported_screen_state = Some(cur_state);

                            if prefer_hardware
                                && capture_suspended
                                && !screen_locked
                                && crate::platform::is_display_asleep()
                            {
                                mid_session_wake.maybe_spawn(now_screen, || {
                                    let res = crate::platform::wake_display_if_asleep();
                                    let still_asleep = crate::platform::is_display_asleep();
                                    (res, still_asleep)
                                });
                            }
                        }

                        // 3) 工具复用通道出站节流泵（每引擎单拍最多 8 帧 + 背压重试队列，零丢块且不饿死视频/输入）。
                        if current_tool_perms.allow_file_transfer {
                            if flush_tool_channel_with_retry(
                                &mut pending_file_tx,
                                MAX_TOOL_FRAMES_PER_TICK,
                                |n| file_worker.try_recv_outgoing(n),
                                |frame| host.send_tool_message(TOOL_CHANNEL_FILE, frame),
                            ) {
                                tools_busy = true;
                            }
                        } else {
                            pending_file_tx.clear();
                        }
                        if flush_tool_channel_with_retry(
                            &mut pending_term_tx,
                            MAX_TOOL_FRAMES_PER_TICK,
                            |n| {
                                if use_owner_terminals {
                                    owner_terminals.engine.poll_outgoing(n)
                                } else {
                                    guest_term_host.poll_outgoing(n)
                                }
                            },
                            |frame| host.send_tool_message(TOOL_CHANNEL_TERMINAL, frame),
                        ) {
                            tools_busy = true;
                        }
                        if !use_owner_terminals {
                            owner_terminals.sync_auth_and_poll(auth_state);
                        }
                        if flush_tool_channel_with_retry(
                            &mut pending_portmap_tx,
                            MAX_TOOL_FRAMES_PER_TICK,
                            |n| portmap_host.poll_outgoing(n),
                            |frame| host.send_tool_message(TOOL_CHANNEL_PORTMAP, frame),
                        ) {
                            tools_busy = true;
                        }
                        if flush_tool_channel_with_retry_checked(
                            &mut pending_display_tx,
                            MAX_TOOL_FRAMES_PER_TICK,
                            |_| Vec::new(),
                            |frame| host.send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, frame),
                            |e| matches!(e, rc_types::Error::InvalidConfig(_)),
                        ) {
                            tools_busy = true;
                        }
                        if pending_update_tx.flush(
                            MAX_TOOL_FRAMES_PER_TICK,
                            |frame| host.send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, frame),
                            |e| matches!(e, rc_types::Error::InvalidConfig(_)),
                        ) {
                            tools_busy = true;
                        }

                        // 4) 系统音频采集 → IMA-ADPCM 编码 → AudioFramePacket 发送。
                        //    M9：当文件/端口映射/更新中转通道存在背压待重试帧时，本拍跳过发送音频帧避免加剧 Stream A 拥塞。
                        let stream_a_congested = !pending_file_tx.is_empty()
                            || !pending_portmap_tx.is_empty()
                            || !pending_update_tx.is_empty();
                        // 3.5) 静止无损 Tile 补帧低优先级限速发送（仅当控制面空闲且无 Stream A 拥塞时最多发送 1 片，
                        //      保证控制消息、输入与动态视频流零阻塞，且输入/新帧抢占可瞬间清空未发队列）。
                        if !host.is_media_paused()
                            && pending_display_tx.is_empty()
                            && !stream_a_congested
                            && still_refine.is_active()
                        {
                            let now_ms = u64::try_from(session_started_at.elapsed().as_millis())
                                .unwrap_or(u64::MAX);
                            if let Some(tile_msg) = still_refine.poll_next_display_ctrl_msg(now_ms)
                            {
                                if let Some(tile_payload) =
                                    display_ctrl::encode_display_ctrl(&tile_msg)
                                {
                                    if host
                                        .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, tile_payload)
                                        .is_ok()
                                    {
                                        tools_busy = true;
                                    }
                                }
                            }
                        }
                        let audio_busy = if host.is_media_paused() {
                            false
                        } else {
                            match audio_mgr.capture_mut() {
                                Some(cap) => pump_host_audio(
                                    host,
                                    cap.as_mut(),
                                    audio_muted || stream_a_congested,
                                    &mut audio_silence_gate,
                                    &mut audio_seq,
                                ),
                                None => false,
                            }
                        };

                        if !host.is_media_paused() && !host.has_pipeline() {
                            drive_err =
                                Some("硬件视频管线热重建失败且无法恢复，会话已终止".to_string());
                            break;
                        }

                        if let Some(relay_q) = incoming_relay {
                            if last_preempt_check.elapsed() >= PREEMPT_CHECK_INTERVAL {
                                last_preempt_check = Instant::now();
                                let idle_us = host.idle_since_last_client_rx_us(u64::from(clock()));
                                let ignore_lan_before = matches!(
                                    transport_kind,
                                    HostTransportKind::Lan | HostTransportKind::MtlsLan
                                )
                                .then_some(session_started_at + LAN_STALE_SIGNAL_GRACE);
                                if let Some(cutoff) = ignore_lan_before {
                                    // 主动清掉本次 LAN 建连同源迟到的旧 PunchCoord（!is_relay_alloc），
                                    // 防止其滞留满 20s 后在 Detached 期复活误抢占、打断 6s 续传。
                                    relay_q.purge_stale_lan_punch_for_peer(
                                        active_peer_id.as_deref(),
                                        cutoff,
                                        RELAY_INCOMING_TTL,
                                    );
                                }
                                if relay_q.has_preempt_candidate_filtered(
                                    RELAY_INCOMING_TTL,
                                    active_peer_id.as_deref(),
                                    idle_us,
                                    false,
                                    ignore_lan_before,
                                ) {
                                    preempted_by_incoming = true;
                                    break;
                                }
                            }
                        }

                        last_busy = r.busy || tools_busy || audio_busy;
                        if !last_busy && host.state() == SessionState::Streaming {
                            let wait_ms = if pending_file_in.is_empty()
                                && pending_display_tx.is_empty()
                                && pending_update_tx.is_empty()
                            {
                                if host.is_media_paused() {
                                    3
                                } else {
                                    2
                                }
                            } else {
                                1
                            };
                            if host.has_pipeline() {
                                host.pipeline().wait_event(Duration::from_millis(wait_ms));
                            } else if host.is_media_paused() {
                                thread::sleep(Duration::from_millis(wait_ms));
                            }
                        }
                    }
                    Err(e) => {
                        drive_err = Some(format!("会话运行异常: {e}"));
                        break;
                    }
                }
            }
            SessionState::Detached => {
                match transport_kind {
                    HostTransportKind::P2p => {
                        detached_reason = Some("P2P 连接已断开".to_string());
                        break;
                    }
                    HostTransportKind::Relay => {
                        // 一次性 RCR1 中继令牌不可在原连接上续传，断链后直接收尾回到监听态。
                        detached_reason = Some("中继连接已断开".to_string());
                        break;
                    }
                    HostTransportKind::MtlsLan => {
                        detached_reason = Some("mTLS LAN 连接已断开".to_string());
                        break;
                    }
                    HostTransportKind::Lan => {}
                }
                if host.is_media_paused() && !host.is_pending_epoch_reset() {
                    detached_reason = Some("纯工具连接已断开".to_string());
                    break;
                }
                if password_version.load(Ordering::Acquire) != observed_pw_ver {
                    detached_reason = Some("密码已变更，重置监听".to_string());
                    break;
                }
                if config_version.load(Ordering::Acquire) != observed_cfg_ver {
                    detached_reason = Some("鉴权配置已变更，重置监听".to_string());
                    break;
                }
                if let Some(relay_q) = incoming_relay {
                    if last_preempt_check.elapsed() >= PREEMPT_CHECK_INTERVAL {
                        last_preempt_check = Instant::now();
                        let idle_us = host.idle_since_last_client_rx_us(u64::from(clock()));
                        let ignore_lan_before = matches!(
                            transport_kind,
                            HostTransportKind::Lan | HostTransportKind::MtlsLan
                        )
                        .then_some(session_started_at + LAN_STALE_SIGNAL_GRACE);
                        if let Some(cutoff) = ignore_lan_before {
                            relay_q.purge_stale_lan_punch_for_peer(
                                active_peer_id.as_deref(),
                                cutoff,
                                RELAY_INCOMING_TTL,
                            );
                        }
                        if relay_q.has_preempt_candidate_filtered(
                            RELAY_INCOMING_TTL,
                            active_peer_id.as_deref(),
                            idle_us,
                            true,
                            ignore_lan_before,
                        ) {
                            preempted_by_incoming = true;
                            break;
                        }
                    }
                }
                // 70 分钟 `Bye(Refresh)` 触发后立即重锚会话钟原点并复位活动钟，
                // 避免 71.58 分钟 `u32::MAX` 饱和导致 Detached 候选超时与新纪元 8s 看门狗失明。
                if host.is_pending_epoch_reset() && !epoch_reanchored_in_detached {
                    if let Some(anchor) = clock_anchor {
                        anchor.reset_pending();
                    }
                    host.reset_activity_clock(u64::from(clock()));
                    epoch_reanchored_in_detached = true;
                }
                if let Some(anchor) = clock_anchor {
                    anchor.reanchor_next_build.store(true, Ordering::Release);
                }
                let now_us = u64::from(clock());
                let detach_res = host.tick_detached(now_us);
                let factory_consumed_reanchor = clock_anchor
                    .map(|anchor| !anchor.reanchor_next_build.swap(false, Ordering::AcqRel))
                    .unwrap_or(false);
                match detach_res {
                    Ok(DetachOutcome::TornDown) => {
                        detached_reason = Some("控制端重连超时已断开".to_string());
                        break;
                    }
                    Ok(DetachOutcome::Resumed) => {
                        epoch_reanchored_in_detached = false;
                        host.reset_clipboard_epoch();
                        last_busy = true;
                        pending_display_tx.clear();
                        let (caps_native, presets) = if active_display_id.is_some() {
                            (
                                session_native_res,
                                display_ctrl::build_resolution_presets(
                                    session_native_res.width,
                                    session_native_res.height,
                                    session_max_res.width,
                                    session_max_res.height,
                                ),
                            )
                        } else {
                            (
                                original_native_res.unwrap_or(session_native_res),
                                build_hardware_display_presets(
                                    prefer_hardware,
                                    hardware_video_active,
                                    original_native_res,
                                ),
                            )
                        };
                        still_refine.on_input_event();
                        if let Some(payload) = encode_host_display_caps(
                            host,
                            caps_native,
                            session_max_res,
                            presets,
                            host_hevc_available(hevc_runtime_failed),
                            &codec_negotiator,
                            hardware_media_active,
                            still_refine.stream_epoch(),
                        ) {
                            pending_display_tx.push_back(payload);
                        }
                        if prefer_hardware && hardware_video_active {
                            if let Some(dp) = encode_host_displays_state(active_display_id) {
                                pending_display_tx.push_back(dp);
                            }
                        }
                        if update_worker.has_active_or_pending_relay() {
                            pending_update_tx.clear();
                            update_worker.abort_relay_on_transport_resume(
                                "连接短暂中断导致安装包中转中断，请重试",
                            );
                        }
                        let ver_msg = crate::updater::HostUpdateWorker::build_version_info_msg(
                            host.authenticated_owner().is_some(),
                        );
                        pending_update_tx.enqueue(&ver_msg, host.authenticated_owner().is_some());
                        let resumed_screen_state = (
                            crate::platform::is_screen_locked(),
                            host.is_capture_suspended(),
                        );
                        // 断线恢复后无条件重发一次最新状态（含 `(false, false)`），避免对端卡死在断线前收到的锁屏/挂起提示。
                        if let Some(payload) =
                            display_ctrl::encode_display_ctrl(&DisplayControlMsg::HostScreenState {
                                locked: resumed_screen_state.0,
                                capture_suspended: resumed_screen_state.1,
                            })
                        {
                            pending_display_tx.push_back(payload);
                        }
                        last_reported_screen_state = Some(resumed_screen_state);
                        last_screen_state_check = Instant::now();
                        current_tool_perms = compute_effective_tool_permissions(
                            host.authenticated_owner().is_some(),
                            allow_assist_file_transfer.load(Ordering::Acquire),
                        );
                        host.set_tool_permissions(current_tool_perms);
                        if !current_tool_perms.allow_file_transfer {
                            pending_file_in.clear();
                            pending_file_tx.clear();
                            file_worker = FileHostWorker::spawn(Arc::clone(&file_transfer_dir));
                        }
                        if let Some(perm_payload) =
                            encode_tool_permissions_state(current_tool_perms)
                        {
                            pending_display_tx.push_back(perm_payload);
                        }
                        emit_peer_connected(host, &host.peer_addr().to_string(), updates);
                    }
                    Ok(DetachOutcome::Replaced) => {
                        // 新会话落成（含 70 分钟 Bye(Refresh) 跨纪元重建）：确保时钟原点已重锚
                        // 且被控端 8s 失活看门狗与刷新基准以新纪元零点起算。
                        epoch_reanchored_in_detached = false;
                        session_started_at = Instant::now();
                        if !factory_consumed_reanchor {
                            if let Some(anchor) = clock_anchor {
                                anchor.reset_pending();
                            }
                        }
                        host.reset_activity_clock(u64::from(clock()));
                        // M9：新控制端顶替旧会话时复位隐私幕布/被控端静音/虚拟屏、音频静音与全部会话级工具引擎，
                        // 避免新客户端继承旧客户端的隐私/音频/虚拟屏状态、终端 PTY 或陈旧线帧。
                        // `finalize_session` 已基于 `cfg.pipeline` 基线模板在主屏上启动新管线，
                        // 仅当旧会话曾启用隐私幕布时需在清理幕布后重建一次 SCK 过滤器。
                        let had_privacy_curtain = hw_cleanup.privacy_active;
                        hw_cleanup.cleanup_now();
                        active_display_id = None;
                        shows_cursor = false;
                        host.set_capture_options(None, false);
                        display_mode_session.restore();
                        let main_origin = if prefer_hardware && hardware_video_active {
                            crate::platform::list_displays()
                                .into_iter()
                                .find(|d| d.is_main)
                                .map(|d| (d.origin_x, d.origin_y))
                                .unwrap_or((0.0, 0.0))
                        } else {
                            (0.0, 0.0)
                        };
                        if let Some(orig) = original_native_res {
                            host.set_injector_screen_bounds(
                                main_origin.0,
                                main_origin.1,
                                orig.width,
                                orig.height,
                            );
                        }
                        hevc_runtime_failed = false;
                        codec_negotiator = HostCodecNegotiator::new(host_encode_caps.clone());
                        let replaced_dims = host
                            .negotiated()
                            .map(|n| (n.width, n.height))
                            .unwrap_or((session_native_res.width, session_native_res.height));
                        still_refine = crate::still_refine::HostStillRefineController::new(
                            1,
                            replaced_dims.0,
                            replaced_dims.1,
                            host_refinement_supported,
                        );
                        still_window_sent_dgrams = 0;
                        still_window_dropped_dgrams = 0;
                        still_last_dropped_total = host.transport_tx_dropped_datagrams();
                        still_loss_window_at = Instant::now();
                        user_pinned_resolution = false;
                        auto_hidpi_active = false;
                        last_busy = true;
                        host.reset_clipboard_epoch();
                        audio_muted = false;
                        audio_silence_gate.reset();
                        audio_seq = 0;
                        audio_mgr.resume(&mut audio_silence_gate);
                        active_peer_id = host
                            .authenticated_owner()
                            .map(|o| o.caller_device_id.clone());
                        pending_file_in.clear();
                        pending_file_tx.clear();
                        pending_term_tx.clear();
                        pending_portmap_tx.clear();
                        pending_display_tx.clear();
                        pending_update_tx.clear();
                        (session_native_res, session_max_res) = compute_host_display_bounds(
                            host,
                            prefer_hardware,
                            hardware_video_active,
                        );
                        if had_privacy_curtain {
                            if let Some(cur) = host.negotiated() {
                                let _ = host.force_reconfigure_stream(
                                    cur.width,
                                    cur.height,
                                    Some(cur.fps),
                                    Some(session_max_res),
                                    None,
                                );
                            }
                        }
                        let presets = build_hardware_display_presets(
                            prefer_hardware,
                            hardware_video_active,
                            original_native_res,
                        );
                        if let Some(payload) = encode_host_display_caps(
                            host,
                            original_native_res.unwrap_or(session_native_res),
                            session_max_res,
                            presets,
                            host_hevc_available(hevc_runtime_failed),
                            &codec_negotiator,
                            hardware_media_active,
                            still_refine.stream_epoch(),
                        ) {
                            pending_display_tx.push_back(payload);
                        }
                        if prefer_hardware && hardware_video_active {
                            if let Some(dp) = encode_host_displays_state(active_display_id) {
                                pending_display_tx.push_back(dp);
                            }
                        }
                        update_worker.reset();
                        let ver_msg = crate::updater::HostUpdateWorker::build_version_info_msg(
                            host.authenticated_owner().is_some(),
                        );
                        pending_update_tx.enqueue(&ver_msg, host.authenticated_owner().is_some());
                        wallpaper_rx = if prefer_hardware && hardware_video_active {
                            Some(spawn_wallpaper_fetcher())
                        } else {
                            None
                        };
                        let replaced_screen_state = (
                            crate::platform::is_screen_locked(),
                            host.is_capture_suspended(),
                        );
                        if replaced_screen_state.0 || replaced_screen_state.1 {
                            if let Some(payload) = display_ctrl::encode_display_ctrl(
                                &DisplayControlMsg::HostScreenState {
                                    locked: replaced_screen_state.0,
                                    capture_suspended: replaced_screen_state.1,
                                },
                            ) {
                                pending_display_tx.push_back(payload);
                            }
                        }
                        last_reported_screen_state = Some(replaced_screen_state);
                        last_screen_state_check = Instant::now();
                        current_tool_perms = compute_effective_tool_permissions(
                            host.authenticated_owner().is_some(),
                            allow_assist_file_transfer.load(Ordering::Acquire),
                        );
                        host.set_tool_permissions(current_tool_perms);
                        last_tool_denied_sent = [None; 8];
                        if let Some(perm_payload) =
                            encode_tool_permissions_state(current_tool_perms)
                        {
                            pending_display_tx.push_back(perm_payload);
                        }
                        file_worker = FileHostWorker::spawn(Arc::clone(&file_transfer_dir));
                        if use_owner_terminals {
                            owner_terminals.detach_all();
                        } else {
                            guest_term_host = TerminalHostEngine::new();
                        }
                        use_owner_terminals = match host.authenticated_owner() {
                            Some(owner) => {
                                let _ = owner_terminals.bind_for_owner(&owner.user_id);
                                true
                            }
                            None => false,
                        };
                        portmap_host = PortMapHostEngine::new();
                        emit_peer_connected(host, &host.peer_addr().to_string(), updates);
                    }
                    Ok(DetachOutcome::Waiting) => {
                        owner_terminals.sync_auth_and_poll(auth_state);
                        if !use_owner_terminals {
                            guest_term_host.poll_background();
                        }
                    }
                    Err(e) => {
                        drive_err = Some(format!("会话运行异常: {e}"));
                        break;
                    }
                }
            }
            SessionState::Init
            | SessionState::Connected
            | SessionState::Reconnecting
            | SessionState::Closed => break,
        }
    }

    // 停止并释放音频采集器与在途初始化接收端（H13）。
    audio_mgr.stop_all();
    drop(audio_mgr);
    drop(file_worker);
    if use_owner_terminals {
        owner_terminals.detach_all();
    }
    drop(guest_term_host);
    drop(portmap_host);
    display_mode_session.restore();
    drop(display_mode_session);
    if pending_lock_on_exit {
        trigger_host_lock_screen(lock_screen_count, prefer_hardware);
    }

    let user_disconnected = disconnect_flag.load(Ordering::Acquire);
    let bye_reason = if stop_flag.load(Ordering::Acquire) {
        match close_reason.load(Ordering::Acquire) {
            1 => ByeReason::Refresh,
            2 => ByeReason::SessionSwitching,
            _ => ByeReason::Normal,
        }
    } else {
        ByeReason::Normal
    };
    let close_res = host.close(bye_reason);
    let reason = if preempted_by_incoming {
        "收到新的远控连接，已切换会话".to_string()
    } else if user_disconnected {
        "本机主动断开".to_string()
    } else if let Some(err) = drive_err {
        err
    } else if let Some(reason) = detached_reason {
        reason
    } else {
        match close_res {
            Ok(summary) => match summary.stop_reason {
                StopReason::Requested => "本机主动断开".to_string(),
                StopReason::ByeReceived(_) => "控制端已断开".to_string(),
                StopReason::Disconnected(r) => format!("连接中断 ({r})"),
            },
            Err(e) => format!("会话运行异常: {e}"),
        }
    };
    DriveSessionOutcome {
        reason,
        preempted_by_incoming,
    }
}

/// 会话结束后若启用临时验证码自动轮换（且未停机），在工作线程内原子生成新码并推进版本号，
/// 确保紧随其后的下一条入站请求不可能复用已过期的旧临时验证码（M7）。
fn maybe_rotate_password_after_session(
    password_state: &Mutex<PasswordState>,
    password_version: &AtomicU64,
    updates: &BoundedHostUpdateQueue,
    stop_flag: &AtomicBool,
) {
    if stop_flag.load(Ordering::Acquire) {
        return;
    }
    let rotated = {
        let mut st = password_state.lock().unwrap_or_else(|e| e.into_inner());
        if !st.auto_rotate {
            None
        } else {
            let prev = st.password.clone();
            let mut next = generate_temp_code();
            if prev.as_deref() == Some(next.as_str()) {
                next = generate_temp_code();
            }
            st.password = Some(next.clone());
            password_version.fetch_add(1, Ordering::AcqRel);
            Some(next)
        }
    };
    if let Some(password) = rotated {
        updates.push(HostUpdate::PasswordRotated { password });
    }
}

/// 判定 P2P 握手失败错误是否属于「传输层超时/断连」导致的分裂脑场景（H4）：
/// 仅在 `Timeout` / `Network` / `Io` 错误时允许回退至 TCP 中继重试握手；
/// 鉴权拒绝 / 协议错误（`Protocol`）或非法配置（`InvalidConfig`）绝不回退重试。
fn is_p2p_handshake_fallback_eligible(err: &rc_types::Error) -> bool {
    matches!(
        err,
        rc_types::Error::Timeout(_) | rc_types::Error::Network(_) | rc_types::Error::Io(_)
    )
}

struct EstablishedIncomingHost {
    built: Box<BuiltUiHost>,
    streaming_started: Arc<AtomicBool>,
    live_pw_ver: u64,
    live_cfg_ver: u64,
    transport_kind: HostTransportKind,
    peer_label: String,
}

enum HandshakeTransportOutcome {
    Ready {
        built: Box<BuiltUiHost>,
        streaming_started: Arc<AtomicBool>,
        live_pw_ver: u64,
        live_cfg_ver: u64,
    },
    Failed(rc_types::Error),
    BuildError,
}

#[allow(clippy::too_many_arguments)]
fn build_and_handshake_transport(
    raw_transport: Box<dyn Transport>,
    transport_kind: HostTransportKind,
    peer_label: &str,
    actual_addr: SocketAddr,
    opts: &HostWorkerOptions,
    updates: &Arc<BoundedHostUpdateQueue>,
    approver: &UiApprover,
    password_state: &Mutex<PasswordState>,
    password_version: &AtomicU64,
    auth_state: &Mutex<AuthRuntimeState>,
    config_version: &AtomicU64,
    disconnect_flag: &Arc<AtomicBool>,
    stop_flag: &Arc<AtomicBool>,
) -> HandshakeTransportOutcome {
    let streaming_started = Arc::new(AtomicBool::new(false));
    let transport: Box<dyn Transport> = Box::new(CancellableHostTransport {
        inner: raw_transport,
        stop_flag: Arc::clone(stop_flag),
        disconnect_flag: Arc::clone(disconnect_flag),
        streaming_started: Arc::clone(&streaming_started),
    });

    let live_pw_ver = password_version.load(Ordering::Acquire);
    let live_cfg_ver = config_version.load(Ordering::Acquire);
    let live_pw = password_state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .password
        .clone();
    let live_auth = auth_state.lock().unwrap_or_else(|e| e.into_inner()).clone();

    let box_approver: Box<dyn ConnectionApprover> = if opts.require_approval {
        approver.set_remote_addr_override(Some(peer_label.to_string()));
        Box::new(approver.clone())
    } else {
        Box::new(AutoApprover)
    };

    let effective_allow_remote = live_auth.allow_owner_control
        && live_auth.allow_remote_assist
        && (!opts.forbid_passwordless_auto_approve || opts.require_approval || live_pw.is_some());
    let mut built = match build_transport_host_session(
        actual_addr,
        transport,
        transport_kind,
        live_pw,
        opts.approval_timeout_us,
        opts.prefer_hardware,
        opts.clipboard_enabled,
        live_auth.allow_owner_control,
        effective_allow_remote,
        live_auth.owner_verifier,
        live_auth.owner_replay_cache,
        box_approver,
        Arc::clone(updates),
    ) {
        Ok(b) => b,
        Err(e) => {
            approver.set_remote_addr_override(None);
            if !stop_flag.load(Ordering::Acquire) {
                updates.push(HostUpdate::error(e));
            }
            return HandshakeTransportOutcome::BuildError;
        }
    };

    built.clock_anchor.reset_pending();
    let handshake_res = built.host.handshake();
    approver.set_remote_addr_override(None);

    match handshake_res {
        Ok(_) => HandshakeTransportOutcome::Ready {
            built: Box::new(built),
            streaming_started,
            live_pw_ver,
            live_cfg_ver,
        },
        Err(err) => {
            // 显式释放已失效的 HostSession（自动取消在途审批并关闭底层传输）。
            drop(built);
            HandshakeTransportOutcome::Failed(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dial_relay_for_incoming(
    incoming: &RelayIncoming,
    mtls_bundle: Option<&SessionMtlsBundle>,
    require_e2ee: bool,
    updates: &BoundedHostUpdateQueue,
    active_relay_interrupt: &Mutex<Option<ActiveRelayInterrupt>>,
    session_cancel: &Arc<AtomicBool>,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
) -> Option<(Box<dyn Transport>, HostTransportKind, String)> {
    if incoming.relay_addr.is_empty() {
        return None;
    }
    let (transport, shutdown_handle): (Box<dyn Transport>, RelayShutdownHandle) =
        if let Some(bundle) = mtls_bundle {
            let expected_user = incoming
                .is_owner_connection
                .then(|| bundle.local_user_id.clone());
            let peer_bundle = bundle
                .clone()
                .with_expected_peer(Some(incoming.peer_id.clone()), expected_user);
            let relay_mtls = peer_bundle.to_relay_mtls_config(None);
            let e2ee_mode = if require_e2ee {
                RelayE2eeMode::HostRequired(peer_bundle)
            } else {
                RelayE2eeMode::HostAuto(peer_bundle)
            };
            let t = match E2eeRelayTransport::connect_cancellable(
                &incoming.relay_addr,
                RelayRole::Host,
                &incoming.relay_token,
                RELAY_CONNECT_TIMEOUT,
                Arc::clone(session_cancel),
                Some(&relay_mtls),
                e2ee_mode,
            ) {
                Ok(t) => t,
                Err(e) => {
                    disconnect_flag.store(false, Ordering::Release);
                    if !stop_flag.load(Ordering::Acquire) && !session_cancel.load(Ordering::Acquire)
                    {
                        let friendly = crate::session_bridge::classify_relay_connect_error(
                            &e,
                            require_e2ee,
                            true,
                        );
                        updates.push(HostUpdate::error(format!(
                            "{friendly} ({})",
                            incoming.peer_id
                        )));
                    }
                    return None;
                }
            };
            let h = t.shutdown_handle();
            (Box::new(t), h)
        } else {
            let t = match TcpRelayTransport::connect_cancellable(
                &incoming.relay_addr,
                RelayRole::Host,
                &incoming.relay_token,
                RELAY_CONNECT_TIMEOUT,
                Arc::clone(session_cancel),
            ) {
                Ok(t) => t,
                Err(e) => {
                    disconnect_flag.store(false, Ordering::Release);
                    if !stop_flag.load(Ordering::Acquire) && !session_cancel.load(Ordering::Acquire)
                    {
                        updates.push(HostUpdate::error(format!(
                            "中继通道连接失败 ({}): {e}",
                            incoming.peer_id
                        )));
                    }
                    return None;
                }
            };
            let h = t.shutdown_handle();
            (Box::new(t), h)
        };

    *active_relay_interrupt
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        Some(ActiveRelayInterrupt::Connected(shutdown_handle.clone()));

    // 注册中断句柄后立刻复核停机/断连标志，消除建连完成与 stop()/disconnect_client() 之间的竞态（H3）。
    if stop_flag.load(Ordering::Acquire) || disconnect_flag.load(Ordering::Acquire) {
        shutdown_handle.shutdown();
        disconnect_flag.store(false, Ordering::Release);
        return None;
    }

    Some((
        transport,
        HostTransportKind::Relay,
        format!("设备 {} (中继)", incoming.peer_id),
    ))
}

/// 处理一条入站信令会话请求：
/// 1) 若对端提供 UDP 候选地址，优先尝试 P2P UDP 打洞 + QUIC 直连（配置了 mTLS 时自动走双向 mTLS）；
/// 2) 打洞或 QUIC 失败，或 P2P 建连后握手阶段因超时/断链在进入 `Streaming` 前失败（H4 分裂脑恢复），
///    均自动无缝回退至 TCP `RCR1` 中继并重新握手（配置了 mTLS 时强制走外层 mTLS，内层 `HostAuto` 自动兼容客户端开关）；
/// 3) 完成鉴权与机主审批 → 串流驱动（含剪贴板/音频/W2/W3/W4 工具引擎）→ 干净收尾。
fn build_host_p2p_candidates(incoming: &RelayIncoming) -> P2pCandidates {
    let self_pubs: Vec<&str> = incoming.self_public_addr.as_deref().into_iter().collect();
    let peer_pubs: Vec<&str> = incoming
        .peer_public_addr
        .as_deref()
        .into_iter()
        .chain(incoming.peer_public_addrs.iter().map(String::as_str))
        .collect();
    let filtered_peer_lan_addrs =
        p2p::filter_cross_site_lan_addrs(&incoming.peer_lan_addrs, &self_pubs, &peer_pubs);
    P2pCandidates {
        session_id: incoming.session_id.clone(),
        peer_public_addr: incoming.peer_public_addr.clone(),
        peer_public_addrs: incoming.peer_public_addrs.clone(),
        peer_lan_addrs: filtered_peer_lan_addrs,
        local_udp_port: incoming.local_udp_port,
        self_nat_type: incoming.self_nat_type,
        self_nat_port_delta: incoming.self_nat_port_delta,
        peer_nat_type: incoming.peer_nat_type,
        peer_nat_port_delta: incoming.peer_nat_port_delta,
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_relay_incoming(
    incoming: RelayIncoming,
    incoming_relay: &Arc<BoundedRelayIncomingQueue>,
    actual_addr: SocketAddr,
    display_addr: &str,
    opts: &HostWorkerOptions,
    updates: &Arc<BoundedHostUpdateQueue>,
    approver: &UiApprover,
    password_state: &Mutex<PasswordState>,
    password_version: &AtomicU64,
    auth_state: &Mutex<AuthRuntimeState>,
    config_version: &AtomicU64,
    active_relay_interrupt: &Mutex<Option<ActiveRelayInterrupt>>,
    disconnect_flag: &Arc<AtomicBool>,
    stop_flag: &Arc<AtomicBool>,
    close_reason: &Arc<AtomicU8>,
    lock_screen_count: &AtomicU64,
    owner_terminals: &mut PersistentOwnerTerminals,
    file_transfer_dir: &SharedFileTransferDir,
) {
    if stop_flag.load(Ordering::Acquire) {
        return;
    }
    // 清除此前空闲期残留的 disconnect 标记，确保本次新入站会话能正常建连；
    // 若建连/握手期间再次调用 disconnect_client() 则可即时中断。
    disconnect_flag.store(false, Ordering::Release);

    // 使用每会话独立的取消原子量（绝不直接传入 HostHandle::stop_flag，避免 TcpRelayTransport::drop
    // 置位 cancel 时误杀外层被控端工作线程）。
    let session_cancel = Arc::new(AtomicBool::new(false));
    *active_relay_interrupt
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        Some(ActiveRelayInterrupt::Dialing(Arc::clone(&session_cancel)));
    let _interrupt_guard = RelayInterruptSlotGuard {
        slot: active_relay_interrupt,
    };

    if stop_flag.load(Ordering::Acquire) || disconnect_flag.load(Ordering::Acquire) {
        disconnect_flag.store(false, Ordering::Release);
        return;
    }

    let auth_snapshot = auth_state.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mtls_bundle = auth_snapshot.mtls_config.clone();
    let p2p_mtls = if auth_snapshot.accept_mtls_lan {
        match &mtls_bundle {
            Some(bundle) => {
                let expected_user = incoming
                    .is_owner_connection
                    .then(|| bundle.local_user_id.clone());
                match bundle
                    .clone()
                    .with_expected_peer(Some(incoming.peer_id.clone()), expected_user)
                    .to_quic_mtls_config()
                {
                    Ok(cfg) => Some(cfg),
                    Err(e) => {
                        updates.push(HostUpdate::error(format!(
                            "mTLS 配置无效 ({}): {e}",
                            incoming.peer_id
                        )));
                        return;
                    }
                }
            }
            None => {
                updates.push(HostUpdate::error(format!(
                    "已开启加密连接但缺少 mTLS 设备证书，已拒绝入站会话 ({})",
                    incoming.peer_id
                )));
                return;
            }
        }
    } else {
        None
    };

    // 1) 优先尝试 P2P UDP 打洞 + QUIC 直连；若当前启用了针对中继目标的有效出站代理则直接跳过 UDP P2P
    //    走 TCP 中继隧道；否则若 QUIC 建连成功但应用层握手前断连/超时（H4 分裂脑：控制端 P2P 刚好超时已切中继），
    //    释放死 P2P 会话并自动回退至 TCP 中继重试握手。
    let active_proxy = crate::proxy::active_proxy_config();
    let skip_p2p_for_proxy = match crate::proxy::split_host_port(&incoming.relay_addr) {
        Ok((relay_host, relay_port)) => {
            crate::proxy::is_proxy_active_for_target(&active_proxy, &relay_host, relay_port)
        }
        Err(_) => matches!(
            crate::proxy::resolve_effective_proxy(&active_proxy),
            Ok(Some(_))
        ),
    };
    let candidates = build_host_p2p_candidates(&incoming);
    let mut established: Option<EstablishedIncomingHost> = None;

    if !skip_p2p_for_proxy
        && !p2p::parse_candidate_addrs(&candidates).is_empty()
        && !stop_flag.load(Ordering::Acquire)
        && !disconnect_flag.load(Ordering::Acquire)
    {
        let port_hold =
            crate::signal_client::acquire_local_udp_port_for_p2p(candidates.local_udp_port);
        if let Ok(p2p_conn) = p2p::attempt_p2p_quic_host_mtls(
            &candidates,
            p2p::DEFAULT_PUNCH_TIMEOUT,
            p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
            &session_cancel,
            p2p_mtls.as_ref(),
        ) {
            if stop_flag.load(Ordering::Acquire)
                || disconnect_flag.load(Ordering::Acquire)
                || session_cancel.load(Ordering::Acquire)
            {
                drop(p2p_conn);
                drop(port_hold);
                disconnect_flag.store(false, Ordering::Release);
                return;
            }
            let held_p2p = crate::signal_client::P2pHeldTransport::new(p2p_conn, port_hold);
            let peer_label = format!("设备 {} (P2P 直连)", incoming.peer_id);
            match build_and_handshake_transport(
                Box::new(held_p2p),
                HostTransportKind::P2p,
                &peer_label,
                actual_addr,
                opts,
                updates,
                approver,
                password_state,
                password_version,
                auth_state,
                config_version,
                disconnect_flag,
                stop_flag,
            ) {
                HandshakeTransportOutcome::Ready {
                    built,
                    streaming_started,
                    live_pw_ver,
                    live_cfg_ver,
                } => {
                    established = Some(EstablishedIncomingHost {
                        built,
                        streaming_started,
                        live_pw_ver,
                        live_cfg_ver,
                        transport_kind: HostTransportKind::P2p,
                        peer_label,
                    });
                }
                HandshakeTransportOutcome::Failed(err) => {
                    let can_fallback_relay = is_p2p_handshake_fallback_eligible(&err)
                        && !stop_flag.load(Ordering::Acquire)
                        && !disconnect_flag.load(Ordering::Acquire)
                        && !session_cancel.load(Ordering::Acquire)
                        && !incoming.relay_addr.is_empty();
                    if !can_fallback_relay {
                        disconnect_flag.store(false, Ordering::Release);
                        return;
                    }
                }
                HandshakeTransportOutcome::BuildError => {
                    disconnect_flag.store(false, Ordering::Release);
                    return;
                }
            }
        }
    }

    if stop_flag.load(Ordering::Acquire)
        || disconnect_flag.load(Ordering::Acquire)
        || session_cancel.load(Ordering::Acquire)
    {
        disconnect_flag.store(false, Ordering::Release);
        return;
    }

    // 2) 若 P2P 未成功或握手前因分裂脑回退，无缝拨号 TCP RCR1 中继并构造新 HostSession 重试握手。
    let EstablishedIncomingHost {
        built,
        streaming_started,
        live_pw_ver,
        live_cfg_ver,
        transport_kind,
        peer_label,
    } = match established {
        Some(ready) => ready,
        None => {
            // 中继内层始终采用 `HostAuto`（保留 `:21117` 外层强制 mTLS），以便关闭了 S3 加密开关的客户端也可连通。
            let require_e2ee = false;
            let Some((raw_transport, transport_kind, peer_label)) = dial_relay_for_incoming(
                &incoming,
                mtls_bundle.as_ref(),
                require_e2ee,
                updates,
                active_relay_interrupt,
                &session_cancel,
                disconnect_flag,
                stop_flag,
            ) else {
                disconnect_flag.store(false, Ordering::Release);
                return;
            };
            match build_and_handshake_transport(
                raw_transport,
                transport_kind,
                &peer_label,
                actual_addr,
                opts,
                updates,
                approver,
                password_state,
                password_version,
                auth_state,
                config_version,
                disconnect_flag,
                stop_flag,
            ) {
                HandshakeTransportOutcome::Ready {
                    built,
                    streaming_started,
                    live_pw_ver,
                    live_cfg_ver,
                } => EstablishedIncomingHost {
                    built,
                    streaming_started,
                    live_pw_ver,
                    live_cfg_ver,
                    transport_kind,
                    peer_label,
                },
                HandshakeTransportOutcome::Failed(_) | HandshakeTransportOutcome::BuildError => {
                    disconnect_flag.store(false, Ordering::Release);
                    return;
                }
            }
        }
    };

    let BuiltUiHost {
        mut host,
        clock,
        clock_anchor,
        backend_label,
        hardware_video_active,
        wake_guard,
    } = *built;

    streaming_started.store(true, Ordering::Release);
    emit_peer_connected(&host, &peer_label, updates);

    let outcome = drive_ui_host_session_inner(
        &mut host,
        &clock,
        Some(&clock_anchor),
        updates,
        password_version,
        live_pw_ver,
        config_version,
        live_cfg_ver,
        disconnect_flag,
        stop_flag,
        close_reason,
        transport_kind,
        opts.prefer_hardware,
        opts.audio_enabled,
        hardware_video_active.load(Ordering::Acquire),
        lock_screen_count,
        Some(auth_state),
        owner_terminals,
        wake_guard,
        Arc::clone(file_transfer_dir),
        &opts.allow_assist_file_transfer,
        Some(incoming_relay),
        Some(incoming.peer_id.as_str()),
        Instant::now(),
    );
    let reason = outcome.reason;
    let last_backend = backend_label
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    disconnect_flag.store(false, Ordering::Release);
    drop(host);

    // M7：先于 ClientDisconnected 与下一次连接原子轮换临时密码。
    maybe_rotate_password_after_session(password_state, password_version, updates, stop_flag);
    updates.push(HostUpdate::ClientDisconnected { reason });
    if !stop_flag.load(Ordering::Acquire) {
        updates.push(HostUpdate::Listening {
            listen_addr: actual_addr.to_string(),
            display_addr: display_addr.to_string(),
            backend: last_backend,
        });
    }
}

/// 可随时被 `stop_flag` 打断的有界短退避，防止恶意/故障客户端高频触发 accept 错误导致 tight-loop 烧 CPU。
fn sleep_cancelable(duration: Duration, stop_flag: &AtomicBool) {
    let deadline = Instant::now() + duration;
    while !stop_flag.load(Ordering::Acquire) {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

/// 根据连续 accept 非超时错误次数计算有界退避时长（前 2 次零退避，第 3 次起 20ms→40ms→50ms）。
fn accept_error_backoff(consecutive_errors: u32) -> Option<Duration> {
    if consecutive_errors < 3 {
        None
    } else {
        let ms = 20u64
            .saturating_mul(u64::from(consecutive_errors - 2))
            .min(50);
        Some(Duration::from_millis(ms))
    }
}

#[allow(clippy::too_many_arguments)]
fn run_host_worker(
    mut actual_addr: SocketAddr,
    listen_addr_shared: Arc<Mutex<SocketAddr>>,
    opts: HostWorkerOptions,
    first_listener: HostListener,
    updates: Arc<BoundedHostUpdateQueue>,
    approver: UiApprover,
    password_state: Arc<Mutex<PasswordState>>,
    password_version: Arc<AtomicU64>,
    auth_state: Arc<Mutex<AuthRuntimeState>>,
    config_version: Arc<AtomicU64>,
    incoming_relay: Arc<BoundedRelayIncomingQueue>,
    active_relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    disconnect_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    close_reason: Arc<AtomicU8>,
    lock_screen_count: Arc<AtomicU64>,
    file_transfer_dir: SharedFileTransferDir,
) {
    let mut display_addr = format_display_addr(actual_addr);
    let initial_backend = match &first_listener {
        HostListener::Plain(b) => b
            .backend_label
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone(),
        HostListener::MtlsLan { .. } | HostListener::AwaitingMtlsCert => {
            if opts.prefer_hardware {
                "auto".to_string()
            } else {
                "fake".to_string()
            }
        }
    };
    updates.push(HostUpdate::Listening {
        listen_addr: actual_addr.to_string(),
        display_addr: display_addr.clone(),
        backend: initial_backend,
    });

    let mut next_listener = Some(first_listener);
    let mut pending_listening_notify = false;
    // U-M1：`first_listener` 在 `HostHandle::spawn` 时以初始版本 0 构造；
    // 若在工作线程进入此处前调用方已调用 `set_password` 或修改鉴权配置，必须立即可见并重建。
    let mut observed_pw_ver = 0u64;
    let mut observed_cfg_ver = 0u64;
    let mut owner_terminals = PersistentOwnerTerminals::new();

    while !stop_flag.load(Ordering::Acquire) {
        owner_terminals.sync_auth_and_poll(Some(auth_state.as_ref()));
        let listener = match next_listener.take() {
            Some(l) => l,
            None => {
                observed_pw_ver = password_version.load(Ordering::Acquire);
                observed_cfg_ver = config_version.load(Ordering::Acquire);
                let cur_pw = password_state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .password
                    .clone();
                let cur_auth = auth_state.lock().unwrap_or_else(|e| e.into_inner()).clone();
                if cur_auth.accept_mtls_lan && cur_auth.mtls_config.is_none() {
                    HostListener::AwaitingMtlsCert
                } else {
                    // 前一轮 `HostSession` / `QuicEndpoint` 在 tokio 后台异步释放 UDP 端口，
                    // 立即重绑 `actual_addr` 可能短暂遇到 `AddrInUse`；短退避重试至多 25 次（~500ms）。
                    let mut last_err = String::new();
                    let mut rebuilt = None;
                    let mut emitted_fallback_listening = false;
                    for attempt in 0..25 {
                        if stop_flag.load(Ordering::Acquire) {
                            break;
                        }
                        let res = if cur_auth.accept_mtls_lan {
                            match cur_auth.mtls_config.as_ref() {
                                Some(bundle) => bind_mtls_lan_endpoint(actual_addr, bundle)
                                    .map(|endpoint| HostListener::MtlsLan { endpoint }),
                                None => {
                                    Err("启用 accept_mtls_lan 时必须提供 mtls_config".to_string())
                                }
                            }
                        } else {
                            let box_approver: Box<dyn ConnectionApprover> = if opts.require_approval
                            {
                                Box::new(approver.clone())
                            } else {
                                Box::new(AutoApprover)
                            };
                            let effective_allow_remote = cur_auth.allow_owner_control
                                && cur_auth.allow_remote_assist
                                && (!opts.forbid_passwordless_auto_approve
                                    || opts.require_approval
                                    || cur_pw.is_some());
                            build_host_session(
                                actual_addr,
                                cur_pw.clone(),
                                opts.approval_timeout_us,
                                opts.prefer_hardware,
                                opts.clipboard_enabled,
                                cur_auth.allow_owner_control,
                                effective_allow_remote,
                                cur_auth.owner_verifier.clone(),
                                Arc::clone(&cur_auth.owner_replay_cache),
                                box_approver,
                                Arc::clone(&updates),
                            )
                            .map(|b| HostListener::Plain(Box::new(b)))
                        };
                        match res {
                            Ok(l) => {
                                rebuilt = Some(l);
                                break;
                            }
                            Err(e) => {
                                last_err = e;
                                if attempt < 24 {
                                    thread::sleep(Duration::from_millis(20));
                                }
                            }
                        }
                    }
                    if rebuilt.is_none()
                        && (actual_addr.port() == DEFAULT_HOST_PORT || opts.ephemeral_listen_port)
                        && !stop_flag.load(Ordering::Acquire)
                    {
                        let fallback_addr = SocketAddr::new(actual_addr.ip(), 0);
                        let fallback_res = if cur_auth.accept_mtls_lan {
                            match cur_auth.mtls_config.as_ref() {
                                Some(bundle) => bind_mtls_lan_endpoint(fallback_addr, bundle)
                                    .map(|endpoint| HostListener::MtlsLan { endpoint }),
                                None => Err(last_err.clone()),
                            }
                        } else {
                            let box_approver: Box<dyn ConnectionApprover> = if opts.require_approval
                            {
                                Box::new(approver.clone())
                            } else {
                                Box::new(AutoApprover)
                            };
                            let effective_allow_remote = cur_auth.allow_owner_control
                                && cur_auth.allow_remote_assist
                                && (!opts.forbid_passwordless_auto_approve
                                    || opts.require_approval
                                    || cur_pw.is_some());
                            build_host_session(
                                fallback_addr,
                                cur_pw.clone(),
                                opts.approval_timeout_us,
                                opts.prefer_hardware,
                                opts.clipboard_enabled,
                                cur_auth.allow_owner_control,
                                effective_allow_remote,
                                cur_auth.owner_verifier.clone(),
                                Arc::clone(&cur_auth.owner_replay_cache),
                                box_approver,
                                Arc::clone(&updates),
                            )
                            .map(|b| HostListener::Plain(Box::new(b)))
                        };
                        if let Ok(fb_listener) = fallback_res {
                            let bound_addr = match &fb_listener {
                                HostListener::Plain(b) => b.host.local_addr().ok(),
                                HostListener::MtlsLan { endpoint } => endpoint.local_addr().ok(),
                                HostListener::AwaitingMtlsCert => None,
                            };
                            if let Some(new_addr) = bound_addr {
                                actual_addr = new_addr;
                                *listen_addr_shared.lock().unwrap_or_else(|e| e.into_inner()) =
                                    new_addr;
                                display_addr = format_display_addr(new_addr);
                                let backend = match &fb_listener {
                                    HostListener::Plain(b) => b
                                        .backend_label
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .clone(),
                                    HostListener::MtlsLan { .. }
                                    | HostListener::AwaitingMtlsCert => {
                                        if opts.prefer_hardware {
                                            "auto".to_string()
                                        } else {
                                            "fake".to_string()
                                        }
                                    }
                                };
                                updates.push(HostUpdate::Listening {
                                    listen_addr: actual_addr.to_string(),
                                    display_addr: display_addr.clone(),
                                    backend,
                                });
                                emitted_fallback_listening = true;
                            }
                            rebuilt = Some(fb_listener);
                        }
                    }
                    match rebuilt {
                        Some(l) => {
                            if pending_listening_notify
                                && !emitted_fallback_listening
                                && !stop_flag.load(Ordering::Acquire)
                            {
                                let backend = match &l {
                                    HostListener::Plain(b) => b
                                        .backend_label
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .clone(),
                                    HostListener::MtlsLan { .. }
                                    | HostListener::AwaitingMtlsCert => {
                                        if opts.prefer_hardware {
                                            "auto".to_string()
                                        } else {
                                            "fake".to_string()
                                        }
                                    }
                                };
                                updates.push(HostUpdate::Listening {
                                    listen_addr: actual_addr.to_string(),
                                    display_addr: display_addr.clone(),
                                    backend,
                                });
                            }
                            pending_listening_notify = false;
                            l
                        }
                        None => {
                            if !stop_flag.load(Ordering::Acquire) {
                                updates.push(HostUpdate::error(last_err));
                            }
                            break;
                        }
                    }
                }
            }
        };

        match listener {
            HostListener::Plain(built) => {
                let BuiltUiHost {
                    mut host,
                    clock,
                    clock_anchor,
                    backend_label,
                    hardware_video_active,
                    wake_guard,
                } = *built;

                // 1) 分片 accept + 握手循环（同时轮询信令下发的入站中继/P2P 会话）。
                let mut consecutive_accept_errors: u32 = 0;
                let accepted = loop {
                    if stop_flag.load(Ordering::Acquire) {
                        break false;
                    }
                    owner_terminals.sync_auth_and_poll(Some(auth_state.as_ref()));
                    if let Some(incoming) =
                        incoming_relay.pop_ready(RELAY_INCOMING_TTL, Duration::from_millis(180))
                    {
                        serve_relay_incoming(
                            incoming,
                            &incoming_relay,
                            actual_addr,
                            &display_addr,
                            &opts,
                            &updates,
                            &approver,
                            &password_state,
                            &password_version,
                            &auth_state,
                            &config_version,
                            &active_relay_interrupt,
                            &disconnect_flag,
                            &stop_flag,
                            &close_reason,
                            &lock_screen_count,
                            &mut owner_terminals,
                            &file_transfer_dir,
                        );
                        // M6：中继会话结束后清理过期入站令牌，并重建空闲 LAN HostSession 清除期间积压的过期 QUIC 连接。
                        incoming_relay.purge_expired(RELAY_INCOMING_TTL);
                        break false;
                    }
                    if password_version.load(Ordering::Acquire) != observed_pw_ver
                        || config_version.load(Ordering::Acquire) != observed_cfg_ver
                    {
                        // 密码或鉴权配置在等待期间被刷新：重建 HostSession 使新配置对下一次握手生效。
                        pending_listening_notify = true;
                        break false;
                    }
                    // 每轮 accept 分片前重锚 Pending 墙钟并刷新当前显示器分辨率能力，避免外接屏/分辨率切换后使用陈旧 caps。
                    if opts.prefer_hardware && consecutive_accept_errors == 0 {
                        if let Some(live_res) = host_hardware_display_caps(true) {
                            host.update_caps_resolution(live_res.width, live_res.height);
                        }
                    }
                    clock_anchor.reset_pending();

                    match host.accept_and_handshake_with_timeout_cancelable(
                        HOST_ACCEPT_SLICE,
                        HOST_QUIC_HANDSHAKE_TIMEOUT,
                        &stop_flag,
                    ) {
                        Ok(_) => break true,
                        Err(rc_types::Error::Timeout(_)) if host.state() == SessionState::Init => {
                            consecutive_accept_errors = 0;
                            continue;
                        }
                        Err(ref e)
                            if host.state() == SessionState::Init
                                && !stop_flag.load(Ordering::Acquire)
                                && !rc_net::quic::is_endpoint_stopped_error(e) =>
                        {
                            // 单个非法/半开客户端在 QUIC 握手阶段失败，端点仍健康；
                            // 连续失败 >= 3 次时做有界短退避，防高频恶意连接空转烧 CPU。
                            consecutive_accept_errors = consecutive_accept_errors.saturating_add(1);
                            if let Some(backoff) = accept_error_backoff(consecutive_accept_errors) {
                                sleep_cancelable(backoff, &stop_flag);
                            }
                            continue;
                        }
                        Err(_) => {
                            // 端点已停止 / 鉴权失败 / 机主拒绝 / 握手超时 / 对端中途断开：本轮结束，回到监听。
                            break false;
                        }
                    }
                };

                if !accepted {
                    replace_wake_guard(&wake_guard, None);
                    drop(host);
                    continue;
                }

                // 2) 进入串流会话（U-H1：显式驱动循环，覆盖 Streaming 与 Detached 退出）。
                let session_started_at = Instant::now();
                disconnect_flag.store(false, Ordering::Release);
                let remote_addr = host.peer_addr().to_string();
                let initial_lan_peer_did = host
                    .authenticated_owner()
                    .map(|o| o.caller_device_id.clone());
                emit_peer_connected(&host, &remote_addr, &updates);

                let outcome = drive_ui_host_session_inner(
                    &mut host,
                    &clock,
                    Some(&clock_anchor),
                    &updates,
                    &password_version,
                    observed_pw_ver,
                    &config_version,
                    observed_cfg_ver,
                    &disconnect_flag,
                    &stop_flag,
                    &close_reason,
                    HostTransportKind::Lan,
                    opts.prefer_hardware,
                    opts.audio_enabled,
                    hardware_video_active.load(Ordering::Acquire),
                    &lock_screen_count,
                    Some(auth_state.as_ref()),
                    &mut owner_terminals,
                    wake_guard,
                    Arc::clone(&file_transfer_dir),
                    &opts.allow_assist_file_transfer,
                    Some(&incoming_relay),
                    initial_lan_peer_did.as_deref(),
                    session_started_at,
                );
                let reason = outcome.reason;
                let lan_peer_did = host
                    .authenticated_owner()
                    .map(|o| o.caller_device_id.clone())
                    .or(initial_lan_peer_did);
                let last_backend = backend_label
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                disconnect_flag.store(false, Ordering::Release);
                drop(host);

                // M7：LAN 会话结束后原子轮换临时密码，再通知 UI 并清理同对端残留及过期入站中继令牌（M6/M12）。
                maybe_rotate_password_after_session(
                    &password_state,
                    &password_version,
                    &updates,
                    &stop_flag,
                );
                let _ = last_backend;
                updates.push(HostUpdate::ClientDisconnected { reason });
                if !stop_flag.load(Ordering::Acquire) {
                    // 等外层循环真正完成新 UDP/QUIC 监听重绑后再发出 `Listening`，
                    // 避免对端在旧 quinn::Endpoint 异步释放窗口内重连撞上 CONNECTION_REFUSED。
                    pending_listening_notify = true;
                }
                if outcome.preempted_by_incoming {
                    // 被入站新连接抢占时绝不调用 purge_for_peer_before 误删刚到达的抢占凭据。
                    incoming_relay.purge_expired(RELAY_INCOMING_TTL);
                } else {
                    incoming_relay.purge_for_peer_before(
                        lan_peer_did.as_deref(),
                        lan_stale_signal_cutoff(session_started_at, Instant::now()),
                        RELAY_INCOMING_TTL,
                    );
                }
            }
            HostListener::AwaitingMtlsCert => {
                while !stop_flag.load(Ordering::Acquire) {
                    owner_terminals.sync_auth_and_poll(Some(auth_state.as_ref()));
                    if let Some(incoming) =
                        incoming_relay.pop_ready(RELAY_INCOMING_TTL, Duration::from_millis(180))
                    {
                        updates.push(HostUpdate::error(format!(
                            "已开启加密连接但缺少 mTLS 设备证书，已拒绝入站会话 ({})",
                            incoming.peer_id
                        )));
                        incoming_relay.purge_expired(RELAY_INCOMING_TTL);
                        continue;
                    }
                    if config_version.load(Ordering::Acquire) != observed_cfg_ver {
                        pending_listening_notify = true;
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
            HostListener::MtlsLan { endpoint } => {
                // mTLS LAN 监听循环：保持 endpoint 复用，直到需要切回 Plain、config_version 变更或收到信令入站会话。
                let mut need_rebind = false;
                let mut consecutive_accept_errors: u32 = 0;
                while !stop_flag.load(Ordering::Acquire) {
                    owner_terminals.sync_auth_and_poll(Some(auth_state.as_ref()));
                    if let Some(incoming) =
                        incoming_relay.pop_ready(RELAY_INCOMING_TTL, Duration::from_millis(180))
                    {
                        serve_relay_incoming(
                            incoming,
                            &incoming_relay,
                            actual_addr,
                            &display_addr,
                            &opts,
                            &updates,
                            &approver,
                            &password_state,
                            &password_version,
                            &auth_state,
                            &config_version,
                            &active_relay_interrupt,
                            &disconnect_flag,
                            &stop_flag,
                            &close_reason,
                            &lock_screen_count,
                            &mut owner_terminals,
                            &file_transfer_dir,
                        );
                        incoming_relay.purge_expired(RELAY_INCOMING_TTL);
                        continue;
                    }
                    if config_version.load(Ordering::Acquire) != observed_cfg_ver {
                        need_rebind = true;
                        pending_listening_notify = true;
                        break;
                    }
                    observed_pw_ver = password_version.load(Ordering::Acquire);
                    match endpoint.accept_with_handshake_timeout(
                        HOST_ACCEPT_SLICE,
                        HOST_QUIC_HANDSHAKE_TIMEOUT,
                        Some(&stop_flag),
                    ) {
                        Ok(quic_transport) => {
                            consecutive_accept_errors = 0;
                            let session_started_at = Instant::now();
                            disconnect_flag.store(false, Ordering::Release);
                            let mtls_peer_did = quic_transport
                                .peer_mtls_identity()
                                .map(|id| id.device_id.clone());
                            let peer_label = match mtls_peer_did.as_deref() {
                                Some(did) => format!(
                                    "设备 {} (LAN mTLS @ {})",
                                    did,
                                    quic_transport.remote_addr()
                                ),
                                None => format!("{} (LAN mTLS)", quic_transport.remote_addr()),
                            };
                            match build_and_handshake_transport(
                                Box::new(quic_transport),
                                HostTransportKind::MtlsLan,
                                &peer_label,
                                actual_addr,
                                &opts,
                                &updates,
                                &approver,
                                &password_state,
                                &password_version,
                                &auth_state,
                                &config_version,
                                &disconnect_flag,
                                &stop_flag,
                            ) {
                                HandshakeTransportOutcome::Ready {
                                    built,
                                    streaming_started,
                                    live_pw_ver,
                                    live_cfg_ver,
                                } => {
                                    let BuiltUiHost {
                                        mut host,
                                        clock,
                                        clock_anchor,
                                        backend_label,
                                        hardware_video_active,
                                        wake_guard,
                                    } = *built;
                                    streaming_started.store(true, Ordering::Release);
                                    emit_peer_connected(&host, &peer_label, &updates);
                                    let outcome = drive_ui_host_session_inner(
                                        &mut host,
                                        &clock,
                                        Some(&clock_anchor),
                                        &updates,
                                        &password_version,
                                        live_pw_ver,
                                        &config_version,
                                        live_cfg_ver,
                                        &disconnect_flag,
                                        &stop_flag,
                                        &close_reason,
                                        HostTransportKind::MtlsLan,
                                        opts.prefer_hardware,
                                        opts.audio_enabled,
                                        hardware_video_active.load(Ordering::Acquire),
                                        &lock_screen_count,
                                        Some(auth_state.as_ref()),
                                        &mut owner_terminals,
                                        wake_guard,
                                        Arc::clone(&file_transfer_dir),
                                        &opts.allow_assist_file_transfer,
                                        Some(&incoming_relay),
                                        mtls_peer_did.as_deref(),
                                        session_started_at,
                                    );
                                    let reason = outcome.reason;
                                    let last_backend = backend_label
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .clone();
                                    disconnect_flag.store(false, Ordering::Release);
                                    drop(host);
                                    maybe_rotate_password_after_session(
                                        &password_state,
                                        &password_version,
                                        &updates,
                                        &stop_flag,
                                    );
                                    updates.push(HostUpdate::ClientDisconnected { reason });
                                    if !stop_flag.load(Ordering::Acquire) {
                                        updates.push(HostUpdate::Listening {
                                            listen_addr: actual_addr.to_string(),
                                            display_addr: display_addr.clone(),
                                            backend: last_backend,
                                        });
                                    }
                                    if outcome.preempted_by_incoming {
                                        incoming_relay.purge_expired(RELAY_INCOMING_TTL);
                                    } else {
                                        incoming_relay.purge_for_peer_before(
                                            mtls_peer_did.as_deref(),
                                            lan_stale_signal_cutoff(
                                                session_started_at,
                                                Instant::now(),
                                            ),
                                            RELAY_INCOMING_TTL,
                                        );
                                    }
                                }
                                HandshakeTransportOutcome::Failed(_)
                                | HandshakeTransportOutcome::BuildError => {
                                    disconnect_flag.store(false, Ordering::Release);
                                }
                            }
                        }
                        Err(rc_types::Error::Timeout(_)) => {
                            consecutive_accept_errors = 0;
                            continue;
                        }
                        Err(err) if rc_net::quic::is_endpoint_stopped_error(&err) => {
                            need_rebind = true;
                            pending_listening_notify = true;
                            break;
                        }
                        Err(_) => {
                            // 单个非法/半开客户端握手失败不得重建整个 UDP 端点；
                            // 连续失败 >= 3 次时做有界短退避，防高频恶意连接空转烧 CPU。
                            consecutive_accept_errors = consecutive_accept_errors.saturating_add(1);
                            if let Some(backoff) = accept_error_backoff(consecutive_accept_errors) {
                                sleep_cancelable(backoff, &stop_flag);
                            }
                            continue;
                        }
                    }
                }
                drop(endpoint);
                if !need_rebind && stop_flag.load(Ordering::Acquire) {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_code_is_8_unambiguous_alnum() {
        let forbidden = ['0', 'O', '1', 'I'];
        for _ in 0..32 {
            let code = generate_temp_code();
            assert_eq!(code.len(), TEMP_CODE_LEN);
            assert!(code
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
            for bad in forbidden {
                assert!(
                    !code.contains(bad),
                    "验证码不应包含易混淆字符 {bad}: {code}"
                );
            }
        }
    }

    #[test]
    fn ui_approver_enforces_monotonic_generation_and_emits_updates() {
        let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
        let mut approver = UiApprover::new(Arc::clone(&updates), false, true);
        let req = ApprovalRequest {
            session_id: 77,
            remote_addr: "127.0.0.1:50000".parse().unwrap(),
            requested: SessionParams {
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_bps: 12_000_000,
            },
            auth_method: rc_session::proto::AuthMethod::Password,
            password_verified: true,
        };

        // 第 1 次 submit → generation = 1，发射 ApprovalRequested。
        approver.submit(&req);
        match updates.try_pop() {
            Some(HostUpdate::ApprovalRequested(p)) => {
                assert_eq!(p.generation, 1);
                assert_eq!(p.session_id, 77);
                assert_eq!(p.requested_res, "1920x1080");
                assert_eq!(p.requested_fps, 60);
                assert!(p.password_verified);
            }
            other => panic!("expected ApprovalRequested, got {other:?}"),
        }

        // 错误代次被拒绝。
        assert!(!approver.resolve(999, true));
        assert_eq!(approver.poll_verdict(), None);

        // cancel 发射 ApprovalCancelled 并清除在途态。
        approver.cancel();
        assert_eq!(
            updates.try_pop(),
            Some(HostUpdate::ApprovalCancelled { generation: 1 })
        );
        // 过期代次 resolve 无效。
        assert!(!approver.resolve(1, true));

        // 第 2 次 submit → generation = 2，正确代次 resolve 生效。
        approver.submit(&req);
        match updates.try_pop() {
            Some(HostUpdate::ApprovalRequested(p)) => assert_eq!(p.generation, 2),
            other => panic!("expected second ApprovalRequested, got {other:?}"),
        }
        assert!(approver.resolve(2, true));
        assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Accepted));
    }

    /// 回归测试（U-M2）：`UiApprover::mark_stopped()` 置位粘性停机标记后，
    /// 后续 `submit()` 不再发射 `ApprovalRequested`，`poll_verdict()` 立即返回 `Rejected`，
    /// `resolve()` 恒返回 `false`。
    #[test]
    fn ui_approver_sticky_stop_rejects_future_submits_and_polls() {
        let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
        let mut approver = UiApprover::new(Arc::clone(&updates), false, true);
        let req = ApprovalRequest {
            session_id: 88,
            remote_addr: "127.0.0.1:50001".parse().unwrap(),
            requested: SessionParams {
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_bps: 12_000_000,
            },
            auth_method: rc_session::proto::AuthMethod::None,
            password_verified: false,
        };

        // 停机前先标记 stopped。
        approver.mark_stopped();

        // 停机后再 submit：绝不推送 ApprovalRequested 弹窗。
        approver.submit(&req);
        assert_eq!(updates.try_pop(), None, "停机后不得发射 ApprovalRequested");

        // poll_verdict 立即返回 Rejected，resolve 返回 false。
        assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Rejected));
        assert!(!approver.resolve(1, true));
    }

    #[test]
    fn ui_approver_auto_accepts_password_verified_without_emitting_prompt() {
        let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
        let mut approver = UiApprover::new(Arc::clone(&updates), true, true);
        let req_verified = ApprovalRequest {
            session_id: 91,
            remote_addr: "127.0.0.1:50010".parse().unwrap(),
            requested: SessionParams {
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_bps: 12_000_000,
            },
            auth_method: rc_session::proto::AuthMethod::Password,
            password_verified: true,
        };

        // 密码已校验且启用 auto_accept_with_password：立即放行且绝不推送审批弹窗。
        approver.submit(&req_verified);
        assert_eq!(
            updates.try_pop(),
            None,
            "密码验证通过自动放行时不得推送 ApprovalRequested"
        );
        assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Accepted));
        assert_eq!(updates.try_pop(), None);

        // 若在 poll_verdict 之前调用 cancel，因未弹窗也不应推送冗余 ApprovalCancelled。
        approver.submit(&req_verified);
        approver.cancel();
        assert_eq!(updates.try_pop(), None);

        // 若关停远程协助，即使 auto_accept_with_password == true 且密码已验，submit 也必须立即拒绝。
        approver.set_remote_assist_enabled(false);
        approver.submit(&req_verified);
        assert_eq!(updates.try_pop(), None);
        assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Rejected));
        approver.set_remote_assist_enabled(true);

        // 无密码连接（password_verified == false）：仍须推送 ApprovalRequested 并等待人工裁决。
        let req_passwordless = ApprovalRequest {
            session_id: 92,
            remote_addr: "127.0.0.1:50011".parse().unwrap(),
            requested: SessionParams {
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_bps: 12_000_000,
            },
            auth_method: rc_session::proto::AuthMethod::None,
            password_verified: false,
        };
        approver.submit(&req_passwordless);
        let generation = match updates.try_pop() {
            Some(HostUpdate::ApprovalRequested(p)) => {
                assert_eq!(p.session_id, 92);
                assert!(!p.password_verified);
                p.generation
            }
            other => panic!("无密码连接必须推送 ApprovalRequested，实际: {other:?}"),
        };
        assert_eq!(approver.poll_verdict(), None);
        assert!(approver.resolve(generation, true));
        assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Accepted));

        // 停机后即使 password_verified == true 也必须拒绝，绝不放行。
        approver.mark_stopped();
        approver.submit(&req_verified);
        assert_eq!(updates.try_pop(), None);
        assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Rejected));
    }

    /// 回归测试（U-H1）：`drive_ui_host_session` 在 `Detached` 态下：
    /// 1) 重连保持窗口到期（`DetachOutcome::TornDown`）时立刻退出并关闭会话；
    /// 2) 密码版本变更（`password_version != observed_pw_ver`）时立刻退出并关闭会话。
    #[test]
    fn drive_ui_host_session_breaks_on_detached_torn_down_and_password_change() {
        use rc_session::proto::{AuthMethod, ControlMessage, Hello, PROTOCOL_VERSION};
        use rc_session::testkit::MockTransport;
        use rc_session::ReconnectConfig;
        use std::sync::atomic::AtomicU32;

        fn build_handshaken_offline(clock: SessionClock) -> HostSession {
            let requested = SessionParams {
                width: 320,
                height: 240,
                fps: 30,
                bitrate_bps: 2_000_000,
            };
            let hello_msg = ControlMessage::Hello(Hello {
                version: PROTOCOL_VERSION,
                session_id: 1,
                requested,
                auth_method: AuthMethod::None,
                auth_payload: Vec::new(),
            });

            let mut mock = MockTransport::new();
            mock.deliver_reliable(&hello_msg);

            let capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
                display: rc_capture::DisplayInfo {
                    id: rc_types::DisplayId(0),
                    resolution: Resolution::new(320, 240),
                    scale: 1.0,
                    hdr: false,
                },
                fps: 30,
                content: rc_capture::FakeContent::Static,
                dirty_rect: None,
            })
            .expect("fake capture");
            let encoder = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
                resolution: Resolution::new(320, 240),
                fps: 30,
                bitrate_bps: 2_000_000,
                ..rc_encode::EncoderConfig::default()
            })
            .expect("fake encoder");

            let cfg = HostSessionConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                mtu: rc_session::DEFAULT_SESSION_MTU,
                caps: requested,
                pipeline: PipelineConfig {
                    resolution: Resolution::new(320, 240),
                    fps: 30,
                    bitrate_bps: 2_000_000,
                    prefer_hardware: false,
                    target_latency_us: 22_000,
                    trace_capacity: 64,
                    diff: DiffMode::TrustPlatform,
                    clock_origin_us: None,
                    max_packet_payload: rc_pipeline::MAX_PAYLOAD,
                    ..PipelineConfig::default()
                },
                handshake_timeout: Duration::from_secs(5),
                injector: Box::new(RecordingInjector::new()),
                pace_capture: false,
                auth: HostAuthConfig::default(),
                approver: Box::new(AutoApprover),
                tool_permissions: rc_session::ToolPermissions::all_allowed(),
            };
            let mut host = HostSession::with_parts(
                cfg,
                Box::new(mock),
                Box::new(capture),
                Box::new(encoder),
                clock,
            )
            .expect("with_parts");
            host.set_reconnect(ReconnectConfig {
                resume_ttl: Duration::from_millis(50),
                ..ReconnectConfig::default()
            })
            .expect("set_reconnect");
            host.handshake().expect("handshake");
            assert_eq!(host.state(), SessionState::Streaming);
            host
        }

        // 场景 A：Detached 窗口到期（TornDown）立即跳出驱动循环。
        let now_us = Arc::new(AtomicU32::new(10_000));
        let clk_a: SessionClock = {
            let n = Arc::clone(&now_us);
            Arc::new(move || n.load(Ordering::Acquire))
        };
        let mut host_a = build_handshaken_offline(Arc::clone(&clk_a));
        host_a.on_disconnected(10_000);
        assert_eq!(host_a.state(), SessionState::Detached);
        // 推进注入时钟超过 50ms resume_ttl。
        now_us.store(100_000, Ordering::Release);

        let updates_a = BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP);
        let pw_ver_a = AtomicU64::new(0);
        let cfg_ver_a = AtomicU64::new(0);
        let disc_a = AtomicBool::new(false);
        let stop_a = AtomicBool::new(false);
        let reason_a = drive_ui_host_session(
            &mut host_a,
            &clk_a,
            &updates_a,
            &pw_ver_a,
            0,
            &cfg_ver_a,
            0,
            &disc_a,
            &stop_a,
        );
        assert!(
            reason_a.contains("重连超时"),
            "TornDown 应返回重连超时原因，实际: {reason_a}"
        );
        assert_eq!(host_a.state(), SessionState::Closed);

        // 场景 B：Detached 期间密码版本变更，立即跳出以便重建监听。
        let clk_b: SessionClock = Arc::new(|| 10_000);
        let mut host_b = build_handshaken_offline(Arc::clone(&clk_b));
        host_b.on_disconnected(10_000);
        assert_eq!(host_b.state(), SessionState::Detached);

        let updates_b = BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP);
        let pw_ver_b = AtomicU64::new(1); // 与 observed_pw_ver = 0 不一致
        let cfg_ver_b = AtomicU64::new(0);
        let disc_b = AtomicBool::new(false);
        let stop_b = AtomicBool::new(false);
        let reason_b = drive_ui_host_session(
            &mut host_b,
            &clk_b,
            &updates_b,
            &pw_ver_b,
            0,
            &cfg_ver_b,
            0,
            &disc_b,
            &stop_b,
        );
        assert!(
            reason_b.contains("密码已变更"),
            "Detached 期间密码变更应立即跳出，实际: {reason_b}"
        );
        assert_eq!(host_b.state(), SessionState::Closed);

        // 场景 C：Detached 期间鉴权配置版本变更（如 set_allow_owner_control(false)），立即跳出以便重建监听并拦截后续重连。
        let clk_c: SessionClock = Arc::new(|| 10_000);
        let mut host_c = build_handshaken_offline(Arc::clone(&clk_c));
        host_c.on_disconnected(10_000);
        assert_eq!(host_c.state(), SessionState::Detached);

        let updates_c = BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP);
        let pw_ver_c = AtomicU64::new(0);
        let cfg_ver_c = AtomicU64::new(1); // 与 observed_cfg_ver = 0 不一致
        let disc_c = AtomicBool::new(false);
        let stop_c = AtomicBool::new(false);
        let reason_c = drive_ui_host_session(
            &mut host_c,
            &clk_c,
            &updates_c,
            &pw_ver_c,
            0,
            &cfg_ver_c,
            0,
            &disc_c,
            &stop_c,
        );
        assert!(
            reason_c.contains("鉴权配置已变更"),
            "Detached 期间鉴权配置变更应立即跳出，实际: {reason_c}"
        );
        assert_eq!(host_c.state(), SessionState::Closed);
    }

    /// 回归测试（U-M1）：`HostHandle::spawn` 返回后立即调用 `set_password`，
    /// 工作线程因 `observed_pw_ver = 0` 必然检测到版本变化并使新密码生效。
    #[test]
    fn set_password_immediately_after_spawn_is_observed_by_worker() {
        let mut host = HostHandle::spawn(UiHostConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            password: Some("OLD-PASS-1".to_string()),
            approval_timeout_us: rc_session::auth::DEFAULT_AUTH_TIMEOUT_US,
            prefer_hardware: false,
            require_approval: false,
            auto_accept_with_password: false,
            auto_rotate_password: false,
            clipboard_enabled: false,
            audio_enabled: false,
            ..UiHostConfig::default()
        })
        .expect("spawn host");
        // 紧接 spawn 立即改密，覆盖 spawn → worker 启动竞态窗口。
        host.set_password(Some("NEW-PASS-2".to_string()));
        let addr = host.listen_addr();

        // 等待工作线程完成至多一轮 accept 分片（500ms）并重建 HostSession 使新密码生效。
        thread::sleep(Duration::from_millis(650));

        let client =
            crate::session_bridge::SessionHandle::spawn(crate::session_bridge::UiSessionConfig {
                connect_addr: addr,
                password: Some("NEW-PASS-2".to_string()),
                watch_only: true,
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
                prefer_hardware: false,
                clipboard_enabled: false,
                audio_enabled: false,
                force_relay: false,
                relay_grant: None,
                ..crate::session_bridge::UiSessionConfig::default()
            });
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut negotiated = false;
        while Instant::now() < deadline {
            if let Some(upd) = client.try_recv_update() {
                match upd {
                    crate::session_bridge::SessionUpdate::Negotiated { .. } => {
                        negotiated = true;
                        break;
                    }
                    crate::session_bridge::SessionUpdate::Ended { reason, .. } => {
                        panic!("使用新密码握手不应失败: {reason}");
                    }
                    _ => {}
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        client.send(crate::session_bridge::SessionCommand::Disconnect);
        client.join();
        host.stop();
        assert!(negotiated, "紧接 spawn 调用 set_password 后新密码必须生效");
    }

    #[test]
    fn flush_tool_channel_with_retry_preserves_order_and_drops_nothing_on_backpressure() {
        let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
        let mut source: VecDeque<Vec<u8>> = (1u8..=5).map(|i| vec![i]).collect();
        let mut sent: Vec<Vec<u8>> = Vec::new();
        let mut poll_calls = 0usize;

        // 第 1 拍：拉出前 3 帧，第 2 帧遇到背压返回 Err -> 第 1 帧发出，第 2、3 帧留在 pending。
        let mut attempt = 0usize;
        let busy1 = flush_tool_channel_with_retry(
            &mut pending,
            3,
            |n| {
                poll_calls += 1;
                (0..n).filter_map(|_| source.pop_front()).collect()
            },
            |frame| {
                attempt += 1;
                if attempt == 2 {
                    Err("backpressure")
                } else {
                    sent.push(frame);
                    Ok(())
                }
            },
        );
        assert!(busy1);
        assert_eq!(poll_calls, 1);
        assert_eq!(sent, vec![vec![1]]);
        assert_eq!(pending.len(), 2);

        // 第 2 拍：继续背压 -> 不得再次 poll 引擎，pending 保持 2 帧。
        let busy2 = flush_tool_channel_with_retry(
            &mut pending,
            3,
            |_| {
                poll_calls += 1;
                Vec::new()
            },
            |_| Err::<(), _>("still busy"),
        );
        assert!(!busy2);
        assert_eq!(poll_calls, 1);
        assert_eq!(pending.len(), 2);

        // 第 3 拍：背压解除 -> 先发出 2、3（仍不 poll 新帧）；第 4 拍再拉出 4、5 全部送达。
        let busy3 = flush_tool_channel_with_retry(
            &mut pending,
            3,
            |_| {
                poll_calls += 1;
                Vec::new()
            },
            |frame| {
                sent.push(frame);
                Ok::<(), ()>(())
            },
        );
        assert!(busy3);
        assert_eq!(poll_calls, 1);
        assert!(pending.is_empty());

        let busy4 = flush_tool_channel_with_retry(
            &mut pending,
            3,
            |n| {
                poll_calls += 1;
                (0..n).filter_map(|_| source.pop_front()).collect()
            },
            |frame| {
                sent.push(frame);
                Ok::<(), ()>(())
            },
        );
        assert!(busy4);
        assert_eq!(poll_calls, 2);
        assert_eq!(sent, vec![vec![1], vec![2], vec![3], vec![4], vec![5]]);
    }

    #[test]
    fn p2p_handshake_fallback_eligibility_matches_transport_errors_only() {
        assert!(is_p2p_handshake_fallback_eligible(
            &rc_types::Error::Timeout(Duration::from_secs(5))
        ));
        assert!(is_p2p_handshake_fallback_eligible(
            &rc_types::Error::Network("peer disconnected".to_string())
        ));
        assert!(is_p2p_handshake_fallback_eligible(&rc_types::Error::Io(
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset")
        )));
        assert!(!is_p2p_handshake_fallback_eligible(
            &rc_types::Error::Protocol {
                offset: 0,
                msg: "authentication rejected".to_string(),
            }
        ));
        assert!(!is_p2p_handshake_fallback_eligible(
            &rc_types::Error::InvalidConfig("bad cfg".to_string())
        ));
    }

    #[test]
    fn file_host_worker_handles_list_dir_off_thread_and_stops_cleanly() {
        let dir = std::env::temp_dir().join(format!(
            "rc-ui-file-host-worker-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        std::fs::write(dir.join("probe.txt"), b"hello").expect("write probe file");

        let shared_dir: SharedFileTransferDir = Arc::new(RwLock::new(None));
        let worker = FileHostWorker::spawn(shared_dir);
        let req = rc_tools::FileWireMsg::ListDir {
            path: Some(dir.to_string_lossy().into_owned()),
        }
        .encode()
        .expect("encode ListDir");
        worker
            .try_send_incoming(req)
            .expect("send incoming ListDir to worker");

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut resp_frame = None;
        while Instant::now() < deadline {
            let frames = worker.try_recv_outgoing(4);
            if let Some(f) = frames.into_iter().next() {
                resp_frame = Some(f);
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let frame = resp_frame.expect("worker must reply with ListDirResp");
        match rc_tools::FileWireMsg::decode(&frame).expect("decode ListDirResp") {
            rc_tools::FileWireMsg::ListDirResp { entries, error, .. } => {
                assert!(error.is_none(), "unexpected list_dir error: {error:?}");
                assert!(entries.iter().any(|e| e.name == "probe.txt"));
            }
            other => panic!("expected ListDirResp, got {other:?}"),
        }

        drop(worker);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relay_incoming_purge_before_keeps_new_switch_tokens_from_same_peer() {
        let queue = BoundedRelayIncomingQueue::new(8);
        let make_item = |peer_id: &str, token: &str| RelayIncoming {
            session_id: format!("sess-{token}"),
            peer_id: peer_id.to_string(),
            relay_addr: "127.0.0.1:21117".to_string(),
            relay_token: token.to_string(),
            peer_public_addr: None,
            peer_lan_addrs: Vec::new(),
            local_udp_port: None,
            owner_grant: None,
            is_owner_connection: true,
            is_relay_alloc: false,
            ..RelayIncoming::default()
        };

        queue.push(make_item("111222333", "old-token"));
        thread::sleep(Duration::from_millis(10));
        let session_started_at = Instant::now();
        thread::sleep(Duration::from_millis(10));
        queue.push(make_item("111222333", "new-relay-switch-token"));
        queue.push(make_item("444555666", "other-peer-token"));

        queue.purge_for_peer_before(
            Some("111222333"),
            session_started_at,
            Duration::from_secs(30),
        );

        let first = queue
            .pop_ready(Duration::from_secs(30), Duration::ZERO)
            .expect("new switch token must survive purge");
        assert_eq!(first.relay_token, "new-relay-switch-token");
        let second = queue
            .pop_ready(Duration::from_secs(30), Duration::ZERO)
            .expect("other peer token must survive purge");
        assert_eq!(second.relay_token, "other-peer-token");
        assert!(queue
            .pop_ready(Duration::from_secs(30), Duration::ZERO)
            .is_none());
    }

    #[test]
    fn relay_bitrate_controller_backs_off_on_queue_or_drops_and_ramps_back_up() {
        let t0 = Instant::now();
        let mut ctrl = RelayBitrateController::new(14_000_000, t0);

        // 1) 持续高排队 150ms + 冷却 500ms 后触发回退（×0.75 = 10.5 Mbps）
        assert_eq!(
            ctrl.poll(t0 + Duration::from_millis(50), 200 * 1024, 0),
            None
        );
        assert_eq!(
            ctrl.poll(t0 + Duration::from_millis(520), 200 * 1024, 0),
            Some(10_500_000)
        );

        // 2) 丢包淘汰同样触发回退（冷却期外）：10.5M * 0.75 = 7.875M
        assert_eq!(
            ctrl.poll(t0 + Duration::from_millis(1_100), 16 * 1024, 3),
            Some(7_875_000)
        );

        // 3) 排队清空并维持低水位 >= 2s 后逐步爬坡恢复
        assert_eq!(
            ctrl.poll(t0 + Duration::from_millis(2_000), 8 * 1024, 3),
            None
        );
        let ramped = ctrl.poll(t0 + Duration::from_millis(3_200), 8 * 1024, 3);
        assert_eq!(ramped, Some(9_875_000));

        // 4) 用户手动下调码率后，上限同步刷新且不再超过新上限
        assert_eq!(
            ctrl.sync_external_caps(
                Some((1, 8_000_000)),
                None,
                8_000_000,
                t0 + Duration::from_millis(3_300),
            ),
            None
        );
        assert_eq!(ctrl.poll(t0 + Duration::from_millis(6_000), 0, 3), None);

        // 5) 控制端 RTT 探针要求降至 4M，且本机排队清空时不得覆盖抬高；
        //    随后即使控制端试图用 Probe 拉高至 7.5M，但宿主自身排队回退至 6M 时必须立刻钳制回 6M。
        assert_eq!(
            ctrl.sync_external_caps(
                Some((1, 8_000_000)),
                Some(4_000_000),
                4_000_000,
                t0 + Duration::from_millis(6_100),
            ),
            None
        );
        assert_eq!(ctrl.poll(t0 + Duration::from_millis(9_000), 0, 3), None);
        assert_eq!(
            ctrl.sync_external_caps(
                Some((1, 8_000_000)),
                Some(7_000_000),
                7_000_000,
                t0 + Duration::from_millis(9_100),
            ),
            None
        );
        assert_eq!(
            ctrl.poll(t0 + Duration::from_millis(9_600), 0, 4),
            Some(6_000_000)
        );
        assert_eq!(
            ctrl.sync_external_caps(
                Some((1, 8_000_000)),
                Some(7_500_000),
                7_500_000,
                t0 + Duration::from_millis(9_700),
            ),
            Some(6_000_000)
        );

        // 6) 用户再次显式手选同数值 8M（manual_gen 递增为 2）：必须识别为新手动指令，
        //    重置本机/远端拥塞上限，不得在下一拍把 8M 覆回 6M。
        assert_eq!(
            ctrl.sync_external_caps(
                Some((2, 8_000_000)),
                None,
                8_000_000,
                t0 + Duration::from_millis(9_800),
            ),
            None
        );
        assert_eq!(ctrl.effective_bps(), 8_000_000);
    }

    #[test]
    fn compute_hevc_hidpi_target_respects_fps_pixel_budget_and_edge_cases() {
        // 14" MBP Retina (1512x982 logical, 3024x1964 backing) @ 144fps -> 2464x1600 (567.7M px/s <= 600M!)
        let mbp14_144 = compute_hevc_hidpi_target(
            Resolution::new(1512, 982),
            Some(Resolution::new(3024, 1964)),
            144,
        );
        assert_eq!(mbp14_144, Resolution::new(2464, 1600));
        assert!(display_ctrl::is_within_high_refresh_sweet_spot(
            mbp14_144.width,
            mbp14_144.height,
            144,
            display_ctrl::StreamCodec::Hevc,
        ));

        // 16" MBP Retina @ 144fps stays within 600M px/s budget
        let mbp16_144 = compute_hevc_hidpi_target(
            Resolution::new(1728, 1117),
            Some(Resolution::new(3456, 2234)),
            144,
        );
        assert!(display_ctrl::is_within_high_refresh_sweet_spot(
            mbp16_144.width,
            mbp16_144.height,
            144,
            display_ctrl::StreamCodec::Hevc,
        ));
        assert!(mbp16_144.width > 2400);

        // 14" MBP @ 240fps scales cleanly to stay within 600M px/s budget
        let mbp14_240 = compute_hevc_hidpi_target(
            Resolution::new(1512, 982),
            Some(Resolution::new(3024, 1964)),
            240,
        );
        assert!(display_ctrl::is_within_high_refresh_sweet_spot(
            mbp14_240.width,
            mbp14_240.height,
            240,
            display_ctrl::StreamCodec::Hevc,
        ));

        // 4K scaled to 1080p logical (1920x1080 logical, 3840x2160 backing) @ 144fps -> 2560x1440
        let hidpi_16_9 = compute_hevc_hidpi_target(
            Resolution::new(1920, 1080),
            Some(Resolution::new(3840, 2160)),
            144,
        );
        assert_eq!(hidpi_16_9, Resolution::new(2560, 1440));
        assert!(display_ctrl::is_within_high_refresh_sweet_spot(
            hidpi_16_9.width,
            hidpi_16_9.height,
            144,
            display_ctrl::StreamCodec::Hevc,
        ));

        // 5K Studio Display (2560x1440 logical, 5120x2880 backing) -> stays 2560x1440
        assert_eq!(
            compute_hevc_hidpi_target(
                Resolution::new(2560, 1440),
                Some(Resolution::new(5120, 2880)),
                144,
            ),
            Resolution::new(2560, 1440)
        );

        // Non-Retina 1080p & degenerate <2px logical stay unchanged
        assert_eq!(
            compute_hevc_hidpi_target(
                Resolution::new(1920, 1080),
                Some(Resolution::new(1920, 1080)),
                144,
            ),
            Resolution::new(1920, 1080)
        );
        assert_eq!(
            compute_hevc_hidpi_target(
                Resolution::new(0, 0),
                Some(Resolution::new(3024, 1964)),
                144,
            ),
            Resolution::new(0, 0)
        );

        // ensure_hevc_hidpi_preset adds 2464x1600 to hardware presets so menu highlights & allows re-selection
        let mut presets = vec![
            DisplayPreset {
                width: 3024,
                height: 1964,
                label: "3024 × 1964".to_string(),
                is_native: false,
                is_hidpi: false,
            },
            DisplayPreset {
                width: 1512,
                height: 982,
                label: "1512 × 982 (HiDPI)".to_string(),
                is_native: true,
                is_hidpi: true,
            },
        ];
        ensure_hevc_hidpi_preset(
            &mut presets,
            Resolution::new(1512, 982),
            Resolution::new(3024, 1964),
            144,
            true,
        );
        assert!(presets.iter().any(|p| p.width == 2464 && p.height == 1600));

        // resolve_auto_hidpi_resolution tracks FPS changes (144->240->144) and H.264 revert cleanly
        let native = Resolution::new(1512, 982);
        let max_res = Resolution::new(3024, 1964);
        let (w1, h1, hi1) = resolve_auto_hidpi_resolution(
            1512,
            982,
            native,
            max_res,
            144,
            rc_encode::Codec::Hevc,
            false,
        );
        assert_eq!((w1, h1, hi1), (2464, 1600, true));
        let (w2, h2, hi2) = resolve_auto_hidpi_resolution(
            w1,
            h1,
            native,
            max_res,
            240,
            rc_encode::Codec::Hevc,
            hi1,
        );
        assert!(hi2 && w2 < w1);
        assert!(display_ctrl::is_within_high_refresh_sweet_spot(
            w2,
            h2,
            240,
            display_ctrl::StreamCodec::Hevc,
        ));
        let (w3, h3, hi3) = resolve_auto_hidpi_resolution(
            w2,
            h2,
            native,
            max_res,
            144,
            rc_encode::Codec::Hevc,
            hi2,
        );
        assert_eq!((w3, h3, hi3), (2464, 1600, true));
        let (w4, h4, hi4) = resolve_auto_hidpi_resolution(
            w3,
            h3,
            native,
            max_res,
            144,
            rc_encode::Codec::H264,
            hi3,
        );
        assert_eq!((w4, h4, hi4), (1512, 982, false));
        // Does NOT inflate an explicit lower Hello resolution (e.g. 1280x720)
        assert_eq!(
            resolve_auto_hidpi_resolution(
                1280,
                720,
                native,
                max_res,
                144,
                rc_encode::Codec::Hevc,
                false,
            ),
            (1280, 720, false)
        );
    }

    #[test]
    fn host_handle_set_file_transfer_dir_and_worker_dynamic_update_plumbing() {
        let base = std::env::temp_dir().join(format!(
            "rc-ui-ft-dir-plumbing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let dir_a = base.join("dir_a");
        let dir_b = base.join("dir_b");

        let mut host = HostHandle::spawn(UiHostConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            file_transfer_dir: Some(dir_a.clone()),
            ..UiHostConfig::default()
        })
        .expect("spawn host handle");

        assert_eq!(
            *host
                .file_transfer_dir
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            Some(dir_a.clone())
        );

        let worker = FileHostWorker::spawn(Arc::clone(&host.file_transfer_dir));

        let send_empty_dir_upload = |worker: &FileHostWorker, id: u64, name: &str, body: &[u8]| {
            let start = rc_tools::FileWireMsg::UploadStart {
                id,
                remote_dir: String::new(),
                file_name: name.to_string(),
                total_bytes: body.len() as u64,
            }
            .encode()
            .unwrap();
            let chunk = rc_tools::FileWireMsg::UploadChunk {
                id,
                offset: 0,
                data: body.to_vec(),
            }
            .encode()
            .unwrap();
            let finish = rc_tools::FileWireMsg::UploadFinish { id }.encode().unwrap();
            worker.try_send_incoming(start).unwrap();
            worker.try_send_incoming(chunk).unwrap();
            worker.try_send_incoming(finish).unwrap();

            let deadline = Instant::now() + Duration::from_secs(3);
            let mut got_done = false;
            while Instant::now() < deadline {
                for frame in worker.try_recv_outgoing(8) {
                    if let Ok(rc_tools::FileWireMsg::UploadDone {
                        id: done_id,
                        ok,
                        error,
                    }) = rc_tools::FileWireMsg::decode(&frame)
                    {
                        assert_eq!(done_id, id);
                        assert!(ok, "upload failed: {error:?}");
                        got_done = true;
                    }
                }
                if got_done {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            assert!(got_done, "timed out waiting for UploadDone for id={id}");
        };

        send_empty_dir_upload(&worker, 1, "first.txt", b"payload-a");
        assert_eq!(
            std::fs::read(dir_a.join("first.txt")).unwrap(),
            b"payload-a"
        );

        // Dynamically switch via HostHandle::set_file_transfer_dir and verify worker picks it up
        host.set_file_transfer_dir(Some(dir_b.clone()));
        assert_eq!(
            *host
                .file_transfer_dir
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            Some(dir_b.clone())
        );

        send_empty_dir_upload(&worker, 2, "second.txt", b"payload-b");
        assert_eq!(
            std::fs::read(dir_b.join("second.txt")).unwrap(),
            b"payload-b"
        );

        drop(worker);
        host.stop();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn mid_session_wake_driver_is_nonblocking_replaces_guard_and_drops_on_session_exit() {
        struct DropCounter(Arc<AtomicU64>);
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let drops = Arc::new(AtomicU64::new(0));
        let wake_guard: SharedWakeGuard =
            Arc::new(Mutex::new(Some(Box::new(DropCounter(Arc::clone(&drops))))));
        let mut driver = MidSessionWakeDriver::new();

        // 1) Spawning a slow wake must return immediately (non-blocking) and enforce single-in-flight
        let t0 = Instant::now();
        let drops_for_new = Arc::clone(&drops);
        let spawned = driver.maybe_spawn(t0, move || {
            thread::sleep(Duration::from_millis(60));
            (Ok(Some(Box::new(DropCounter(drops_for_new)))), true)
        });
        assert!(spawned);
        assert!(
            t0.elapsed() < Duration::from_millis(40),
            "maybe_spawn must not block caller thread"
        );
        // Second call while in flight is rejected
        assert!(!driver.maybe_spawn(Instant::now(), || (Ok(None), false)));

        // Wait for background thread to finish and poll_completed to swap guards
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && drops.load(Ordering::SeqCst) == 0 {
            driver.poll_completed(&wake_guard, Instant::now());
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "previous wake guard must be dropped upon swap"
        );
        // Because still_asleep == true, backoff is 15s -> immediate retry at +6s is suppressed
        assert!(
            !driver.maybe_spawn(Instant::now() + Duration::from_secs(6), || (
                Ok(None),
                false
            ))
        );

        // 2) If driver is dropped while a wake thread is in flight, the new guard is dropped immediately (zero leak)
        let mut driver2 = MidSessionWakeDriver::new();
        let drops_exit = Arc::clone(&drops);
        assert!(driver2.maybe_spawn(Instant::now(), move || {
            thread::sleep(Duration::from_millis(40));
            (Ok(Some(Box::new(DropCounter(drops_exit)))), false)
        }));
        drop(driver2);
        let leak_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < leak_deadline && drops.load(Ordering::SeqCst) < 2 {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            drops.load(Ordering::SeqCst),
            2,
            "in-flight guard must be dropped immediately when session drops MidSessionWakeDriver"
        );

        // 3) WakeGuardReleaser drops remaining stored guard cleanly
        {
            let _releaser = WakeGuardReleaser {
                slot: Arc::clone(&wake_guard),
            };
        }
        assert_eq!(drops.load(Ordering::SeqCst), 3);

        // 4) Unread completed rx must block maybe_spawn even after in_flight flips false,
        //    preserving the completed guard until poll_completed drains it and sets cooldown.
        let mut driver3 = MidSessionWakeDriver::new();
        let drops_unread = Arc::new(AtomicU64::new(0));
        let drops_unread_clone = Arc::clone(&drops_unread);
        assert!(driver3.maybe_spawn(Instant::now(), move || {
            (Ok(Some(Box::new(DropCounter(drops_unread_clone)))), false)
        }));
        let wait_done = Instant::now() + Duration::from_secs(2);
        while Instant::now() < wait_done && driver3.in_flight.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(
            !driver3.in_flight.load(Ordering::Acquire),
            "background wake should have finished and cleared in_flight"
        );
        // rx is still unread: maybe_spawn must return false and not drop the completed guard
        assert!(!driver3.maybe_spawn(Instant::now(), || (Ok(None), false)));
        assert_eq!(
            drops_unread.load(Ordering::SeqCst),
            0,
            "unread completed wake guard must not be dropped by maybe_spawn"
        );
        // Draining via poll_completed installs the guard and arms the 5s cooldown
        let unread_slot: SharedWakeGuard = Arc::new(Mutex::new(None));
        let drain_at = Instant::now();
        driver3.poll_completed(&unread_slot, drain_at);
        assert!(unread_slot.lock().unwrap().is_some());
        assert_eq!(drops_unread.load(Ordering::SeqCst), 0);
        assert!(!driver3.maybe_spawn(drain_at + Duration::from_secs(2), || (Ok(None), false)));
        replace_wake_guard(&unread_slot, None);
        assert_eq!(drops_unread.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn set_allow_owner_control_updates_state_and_rejects_in_flight_approval() {
        let def = UiHostConfig::default();
        assert!(def.allow_owner_control);
        assert!(format!("{def:?}").contains("allow_owner_control: true"));

        let mut host = HostHandle::spawn(UiHostConfig {
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            require_approval: true,
            allow_owner_control: true,
            allow_remote_assist: true,
            ..UiHostConfig::default()
        })
        .expect("spawn host");

        // Submit a synthetic in-flight approval via the shared approver
        let mut approver_clone = host.approver.clone();
        approver_clone.submit(&ApprovalRequest {
            session_id: 42,
            remote_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 54321)),
            requested: SessionParams {
                width: 1280,
                height: 720,
                fps: 60,
                bitrate_bps: 4_000_000,
            },
            auth_method: rc_session::proto::AuthMethod::None,
            password_verified: false,
        });

        // Turning off allow_owner_control must immediately reject in-flight approval and gate future submits
        host.set_allow_owner_control(false);
        assert!(!host.auth_state.lock().unwrap().allow_owner_control);
        assert_eq!(
            approver_clone.poll_verdict(),
            Some(ApprovalVerdict::Rejected)
        );

        // Even if set_allow_remote_assist(true) is called while allow_owner_control == false,
        // approver must remain closed until allow_owner_control is re-enabled.
        host.set_allow_remote_assist(true);
        approver_clone.submit(&ApprovalRequest {
            session_id: 43,
            remote_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 54322)),
            requested: SessionParams {
                width: 1280,
                height: 720,
                fps: 60,
                bitrate_bps: 4_000_000,
            },
            auth_method: rc_session::proto::AuthMethod::None,
            password_verified: false,
        });
        assert_eq!(
            approver_clone.poll_verdict(),
            Some(ApprovalVerdict::Rejected)
        );

        // Re-enabling allow_owner_control restores allow_remote_assist gating
        host.set_allow_owner_control(true);
        assert!(host.auth_state.lock().unwrap().allow_owner_control);
        assert!(host.approver.state.lock().unwrap().remote_assist_enabled);

        host.stop();
    }

    #[test]
    fn detached_set_allow_owner_control_false_rebuilds_listener_and_blocks_reconnect() {
        use rc_input::{InputCapture, InputEvent};
        use rc_session::{ClientAuthConfig, ClientSession, ClientSessionConfig};

        struct EmptyInput;
        impl InputCapture for EmptyInput {
            fn next_events(&mut self, _timeout: Duration) -> rc_types::Result<Vec<InputEvent>> {
                Ok(Vec::new())
            }
        }

        let mut host = HostHandle::spawn(UiHostConfig {
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            password: None,
            require_approval: false,
            allow_owner_control: true,
            allow_remote_assist: true,
            ..UiHostConfig::default()
        })
        .expect("spawn host");
        let addr = host.listen_addr();

        let connect_once = |sid: u64| {
            let mut ccfg = ClientSessionConfig::new(
                addr,
                SessionParams {
                    width: 64,
                    height: 64,
                    fps: 30,
                    bitrate_bps: 1_000_000,
                },
                sid,
                Box::new(EmptyInput),
            );
            ccfg.handshake_timeout = Duration::from_secs(3);
            ccfg.connect_timeout = Duration::from_secs(3);
            ccfg.auth = ClientAuthConfig::default();
            let clock: SessionClock = Arc::new(|| 0);
            let mut client = ClientSession::new(
                ccfg,
                DEV_CERT_PEM,
                DEV_KEY_PEM,
                DEV_CERT_PEM,
                "rabbitcontrol",
                clock,
            )
            .expect("client new");
            client.connect_and_handshake().map(|_| client)
        };

        // 1) Initial connection succeeds, then abrupt drop (without Bye) pushes host into Detached
        let client1 = connect_once(7701).expect("initial handshake must succeed");
        let conn_deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_connected = false;
        while Instant::now() < conn_deadline {
            if matches!(
                host.try_recv_update(),
                Some(HostUpdate::ClientConnected { .. })
            ) {
                saw_connected = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(saw_connected, "host must observe initial ClientConnected");

        // Drop client without Bye so host transitions into Detached instead of Closed
        drop(client1);
        thread::sleep(Duration::from_millis(80));

        // 2) Flip allow_owner_control=false while Detached -> must break Detached and rebuild HostSession
        host.set_allow_owner_control(false);

        let rebuild_deadline = Instant::now() + Duration::from_secs(5);
        let mut saw_disconnected = false;
        let mut saw_rebuilt_listening = false;
        while Instant::now() < rebuild_deadline {
            match host.try_recv_update() {
                Some(HostUpdate::ClientDisconnected { .. }) => saw_disconnected = true,
                Some(HostUpdate::Listening { .. }) if saw_disconnected => {
                    saw_rebuilt_listening = true;
                    break;
                }
                Some(_) => {}
                None => thread::sleep(Duration::from_millis(10)),
            }
        }
        assert!(
            saw_disconnected && saw_rebuilt_listening,
            "set_allow_owner_control(false) during Detached must promptly tear down and rebuild listener (disconnected={saw_disconnected}, listening={saw_rebuilt_listening})"
        );

        // 3) Reconnect attempt after rebuild must be rejected
        assert!(
            connect_once(7702).is_err(),
            "connection after allow_owner_control=false must be rejected"
        );

        host.stop();
    }

    #[test]
    fn relay_incoming_queue_supersedes_older_entry_from_same_peer_preserving_others() {
        let q = BoundedRelayIncomingQueue::new(4);
        let mk = |peer: &str, token: &str, lan: Vec<&str>| RelayIncoming {
            session_id: format!("sid-{token}"),
            peer_id: peer.to_string(),
            relay_addr: "127.0.0.1:21117".to_string(),
            relay_token: token.to_string(),
            peer_public_addr: None,
            peer_lan_addrs: lan.into_iter().map(str::to_string).collect(),
            local_udp_port: None,
            owner_grant: None,
            is_owner_connection: true,
            is_relay_alloc: false,
            ..RelayIncoming::default()
        };

        q.push(mk("111222333", "stale-lan-token", vec!["192.168.1.5:9901"]));
        q.push(mk("444555666", "other-peer-token", vec![]));
        q.push(mk("111222333", "fresh-relay-token", vec![]));

        let first = q
            .pop_ready(Duration::from_secs(20), Duration::from_millis(180))
            .expect("other peer entry preserved");
        assert_eq!(first.peer_id, "444555666");
        assert_eq!(first.relay_token, "other-peer-token");

        let second = q
            .pop_ready(Duration::from_secs(20), Duration::from_millis(180))
            .expect("fresh relay entry for peer 111222333 must immediately pop without lan_grace");
        assert_eq!(second.peer_id, "111222333");
        assert_eq!(second.relay_token, "fresh-relay-token");

        assert!(q
            .pop_ready(Duration::from_secs(20), Duration::from_millis(180))
            .is_none());
    }

    #[test]
    fn lan_stale_signal_cutoff_purges_late_wan_signal_while_protecting_recent_switch() {
        let started = Instant::now();
        let ended_6s = started + Duration::from_secs(6);
        let cutoff = lan_stale_signal_cutoff(started, ended_6s);
        let late_wan_signal = started + Duration::from_millis(200);
        let recent_switch_signal = ended_6s - Duration::from_millis(100);
        assert!(
            late_wan_signal < cutoff,
            "late WAN PunchCoord arriving 200ms after LAN start must be purged"
        );
        assert!(
            recent_switch_signal >= cutoff,
            "fresh switch signal arriving right before disconnect must be preserved"
        );
    }

    struct ChannelTestTransport {
        in_rx: mpsc::Receiver<NetEvent>,
        out_reliable_tx: mpsc::Sender<Vec<u8>>,
        out_datagram_count: Arc<AtomicU64>,
    }

    impl Transport for ChannelTestTransport {
        fn send_datagram(&mut self, _data: &[u8]) -> rc_types::Result<()> {
            self.out_datagram_count.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
            let _ = self.out_reliable_tx.send(data.to_vec());
            Ok(())
        }

        fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
            let mut events = Vec::new();
            match self.in_rx.recv_timeout(timeout) {
                Ok(ev) => {
                    events.push(ev);
                    while let Ok(more) = self.in_rx.try_recv() {
                        events.push(more);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    events.push(NetEvent::Disconnected {
                        reason: "channel closed".to_string(),
                    });
                }
            }
            Ok(events)
        }

        fn stats(&self) -> NetStats {
            NetStats::default()
        }
    }

    struct ScriptedAudioCapture {
        inner: rc_audio::FakeAudioCapture,
        stopped: Arc<AtomicBool>,
        stop_calls: Arc<AtomicU64>,
    }

    impl AudioCapture for ScriptedAudioCapture {
        fn try_recv_frame(&mut self) -> Option<rc_audio::PcmFrame> {
            if self.stopped.load(Ordering::Acquire) {
                return None;
            }
            self.inner.try_recv_frame()
        }

        fn sample_rate(&self) -> u32 {
            self.inner.sample_rate()
        }

        fn channels(&self) -> u8 {
            self.inner.channels()
        }

        fn stop(&mut self) {
            self.stopped.store(true, Ordering::Release);
            self.stop_calls.fetch_add(1, Ordering::AcqRel);
            self.inner.stop();
        }

        fn is_stopped(&self) -> bool {
            self.stopped.load(Ordering::Acquire) || self.inner.is_stopped()
        }
    }

    fn build_streaming_channel_host(
        clock: SessionClock,
    ) -> (
        HostSession,
        mpsc::Sender<NetEvent>,
        mpsc::Receiver<Vec<u8>>,
        Arc<AtomicU64>,
    ) {
        use rc_session::proto::{AuthMethod, ControlMessage, Hello, PROTOCOL_VERSION};

        let requested = SessionParams {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 2_000_000,
        };
        let hello_msg = ControlMessage::Hello(Hello {
            version: PROTOCOL_VERSION,
            session_id: 42,
            requested,
            auth_method: AuthMethod::None,
            auth_payload: Vec::new(),
        });
        let mut hello_bytes = Vec::new();
        hello_msg.encode(&mut hello_bytes);

        let (in_tx, in_rx) = mpsc::channel::<NetEvent>();
        let (out_reliable_tx, out_reliable_rx) = mpsc::channel::<Vec<u8>>();
        let out_datagram_count = Arc::new(AtomicU64::new(0));
        in_tx
            .send(NetEvent::Reliable(hello_bytes))
            .expect("queue hello");

        let transport = ChannelTestTransport {
            in_rx,
            out_reliable_tx,
            out_datagram_count: Arc::clone(&out_datagram_count),
        };
        let capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
            display: rc_capture::DisplayInfo {
                id: rc_types::DisplayId(0),
                resolution: Resolution::new(320, 240),
                scale: 1.0,
                hdr: false,
            },
            fps: 30,
            content: rc_capture::FakeContent::Dynamic,
            dirty_rect: None,
        })
        .expect("fake capture");
        let encoder = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
            resolution: Resolution::new(320, 240),
            fps: 30,
            bitrate_bps: 2_000_000,
            ..rc_encode::EncoderConfig::default()
        })
        .expect("fake encoder");

        let cfg = HostSessionConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            mtu: rc_session::DEFAULT_SESSION_MTU,
            caps: requested,
            pipeline: PipelineConfig {
                resolution: Resolution::new(320, 240),
                fps: 30,
                bitrate_bps: 2_000_000,
                prefer_hardware: false,
                target_latency_us: 22_000,
                trace_capacity: 64,
                diff: DiffMode::TrustPlatform,
                clock_origin_us: None,
                max_packet_payload: rc_pipeline::MAX_PAYLOAD,
                ..PipelineConfig::default()
            },
            handshake_timeout: Duration::from_secs(5),
            injector: Box::new(RecordingInjector::new()),
            pace_capture: false,
            auth: HostAuthConfig::default(),
            approver: Box::new(AutoApprover),
            tool_permissions: rc_session::ToolPermissions::all_allowed(),
        };
        let mut host = HostSession::with_parts(
            cfg,
            Box::new(transport),
            Box::new(capture),
            Box::new(encoder),
            clock,
        )
        .expect("with_parts");
        host.set_pipeline_factory_for(Box::new(|pcfg| {
            let (p, _) = fake_stack_anchored(pcfg, None)?;
            Ok(p)
        }));
        host.handshake().expect("handshake");
        assert_eq!(host.state(), SessionState::Streaming);
        (host, in_tx, out_reliable_rx, out_datagram_count)
    }

    fn send_display_ctrl_event(tx: &mpsc::Sender<NetEvent>, msg: &DisplayControlMsg) {
        let payload = display_ctrl::encode_display_ctrl(msg).expect("encode display ctrl");
        let mut wire = Vec::new();
        rc_session::proto::ControlMessage::ToolChannel {
            channel: TOOL_CHANNEL_DISPLAY_CTRL,
            payload,
        }
        .encode(&mut wire);
        tx.send(NetEvent::Reliable(wire)).expect("send tool event");
    }

    fn recv_display_ctrl_until(
        rx: &mpsc::Receiver<Vec<u8>>,
        timeout: Duration,
        mut pred: impl FnMut(&DisplayControlMsg) -> bool,
    ) -> Vec<DisplayControlMsg> {
        let deadline = Instant::now() + timeout;
        let mut collected = Vec::new();
        while Instant::now() < deadline {
            let rem = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(rem.min(Duration::from_millis(20))) {
                Ok(raw) => {
                    if let Ok(rc_session::proto::ControlMessage::ToolChannel {
                        channel: TOOL_CHANNEL_DISPLAY_CTRL,
                        payload,
                    }) = rc_session::proto::ControlMessage::decode(&raw)
                    {
                        if let Some(msg) = display_ctrl::decode_display_ctrl(&payload) {
                            let matched = pred(&msg);
                            collected.push(msg);
                            if matched {
                                return collected;
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        collected
    }

    #[test]
    fn set_media_paused_toggles_pipeline_without_exiting_and_emits_media_state() {
        assert_eq!(host_resume_ttl(HostTransportKind::Relay), Duration::ZERO);
        assert_eq!(host_resume_ttl(HostTransportKind::P2p), Duration::ZERO);
        assert_eq!(
            host_resume_ttl(HostTransportKind::Lan),
            Duration::from_secs(6)
        );
        assert_eq!(
            host_resume_ttl(HostTransportKind::MtlsLan),
            Duration::from_secs(6)
        );

        let clock: SessionClock = Arc::new(|| 10_000);
        let (mut host, in_tx, out_rx, out_dgrams) =
            build_streaming_channel_host(Arc::clone(&clock));

        let cap1_stopped = Arc::new(AtomicBool::new(false));
        let cap1_stop_calls = Arc::new(AtomicU64::new(0));
        let created_count = Arc::new(AtomicU64::new(0));
        let initial_cap: Box<dyn AudioCapture> = Box::new(ScriptedAudioCapture {
            inner: rc_audio::FakeAudioCapture::new(),
            stopped: Arc::clone(&cap1_stopped),
            stop_calls: Arc::clone(&cap1_stop_calls),
        });
        let creator_counter = Arc::clone(&created_count);
        let audio_mgr = HostAudioManager::with_creator(
            true,
            Some(initial_cap),
            Arc::new(move || {
                creator_counter.fetch_add(1, Ordering::AcqRel);
                Ok(Box::new(rc_audio::FakeAudioCapture::new()))
            }),
        );

        let stop_flag = Arc::new(AtomicBool::new(false));
        let t_stop = Arc::clone(&stop_flag);
        let t_clock = Arc::clone(&clock);
        let driver = thread::spawn(move || {
            let updates = BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP);
            let pw_ver = AtomicU64::new(0);
            let cfg_ver = AtomicU64::new(0);
            let disc = AtomicBool::new(false);
            let close_reason = AtomicU8::new(ByeReason::Normal as u8);
            let lock_cnt = AtomicU64::new(0);
            let mut owner_terms = PersistentOwnerTerminals::new();
            let wake_guard: SharedWakeGuard = Arc::new(Mutex::new(None));
            let ft_dir: SharedFileTransferDir = Arc::new(RwLock::new(None));
            let allow_assist_ft = AtomicBool::new(true);
            let outcome = drive_ui_host_session_with_audio(
                &mut host,
                &t_clock,
                None,
                &updates,
                &pw_ver,
                0,
                &cfg_ver,
                0,
                &disc,
                &t_stop,
                &close_reason,
                HostTransportKind::Lan,
                false,
                false,
                &lock_cnt,
                None,
                &mut owner_terms,
                wake_guard,
                ft_dir,
                &allow_assist_ft,
                None,
                None,
                Instant::now(),
                audio_mgr,
            );
            (outcome, host.client_idle_timeout_us())
        });

        // 1) 发送 SetMediaPaused { paused: true } -> 回执 MediaState { paused: true }，停管线与音频，不退出会话。
        send_display_ctrl_event(&in_tx, &DisplayControlMsg::SetMediaPaused { paused: true });
        let paused_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(m, DisplayControlMsg::MediaState { paused: true })
        });
        assert!(
            paused_msgs
                .iter()
                .any(|m| matches!(m, DisplayControlMsg::MediaState { paused: true })),
            "must emit MediaState(paused=true), got: {paused_msgs:?}"
        );
        assert!(
            cap1_stopped.load(Ordering::Acquire) && cap1_stop_calls.load(Ordering::Acquire) >= 1,
            "pausing media must immediately stop and drop active audio capture"
        );

        // 暂停后继续空转一段时间：不应产出新视频数据报，也不应因 !has_pipeline() 异常退出。
        let dgrams_after_pause = out_dgrams.load(Ordering::Acquire);
        thread::sleep(Duration::from_millis(80));
        assert_eq!(
            out_dgrams.load(Ordering::Acquire),
            dgrams_after_pause,
            "media_paused must produce zero new video datagrams"
        );
        assert!(
            !driver.is_finished(),
            "host loop must stay alive in pure-tool paused state without pipeline"
        );

        // 2) 发送 SetMediaPaused { paused: false } -> 重建管线、补发 Capabilities/HostScreenState、拉起新音频、回执 MediaState { paused: false }。
        send_display_ctrl_event(&in_tx, &DisplayControlMsg::SetMediaPaused { paused: false });
        let resumed_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(m, DisplayControlMsg::MediaState { paused: false })
        });
        assert!(
            resumed_msgs
                .iter()
                .any(|m| matches!(m, DisplayControlMsg::Capabilities { .. })),
            "resume must re-emit Capabilities, got: {resumed_msgs:?}"
        );
        assert!(
            resumed_msgs
                .iter()
                .any(|m| matches!(m, DisplayControlMsg::HostScreenState { .. })),
            "resume must re-emit HostScreenState, got: {resumed_msgs:?}"
        );
        assert!(
            resumed_msgs
                .iter()
                .any(|m| matches!(m, DisplayControlMsg::MediaState { paused: false })),
            "resume must emit MediaState(paused=false), got: {resumed_msgs:?}"
        );

        let resume_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < resume_deadline
            && (out_dgrams.load(Ordering::Acquire) <= dgrams_after_pause
                || created_count.load(Ordering::Acquire) == 0)
        {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            out_dgrams.load(Ordering::Acquire) > dgrams_after_pause,
            "resumed pipeline must produce video datagrams again"
        );
        assert!(
            created_count.load(Ordering::Acquire) >= 1,
            "resume must respawn audio capture"
        );

        stop_flag.store(true, Ordering::Release);
        let (outcome, idle_timeout) = driver.join().expect("join driver");
        assert_eq!(idle_timeout, HostSession::CLIENT_IDLE_TIMEOUT_US);
        assert!(!outcome.preempted_by_incoming);
        assert!(
            !outcome.reason.contains("热重建失败"),
            "clean stop must not report pipeline failure: {}",
            outcome.reason
        );
    }

    #[test]
    fn relay_incoming_has_preempt_candidate_covers_same_peer_idle_and_active_third_party() {
        let mk =
            |peer_id: &str, is_owner: bool, lan: Vec<&str>, is_relay_alloc: bool| RelayIncoming {
                session_id: format!("sid-{peer_id}"),
                peer_id: peer_id.to_string(),
                relay_addr: "127.0.0.1:21117".to_string(),
                relay_token: format!("tok-{peer_id}"),
                peer_public_addr: None,
                peer_lan_addrs: lan.into_iter().map(str::to_string).collect(),
                local_udp_port: None,
                owner_grant: None,
                is_owner_connection: is_owner,
                is_relay_alloc,
                ..RelayIncoming::default()
            };

        let ttl = Duration::from_secs(20);
        let q = BoundedRelayIncomingQueue::new(8);
        assert!(!q.has_preempt_candidate(ttl, Some("peer-a"), 0, false));

        // 1) 同设备重连：即使旧会话活跃（idle=0, !detached）也立即允许抢占。
        q.push(mk("peer-a", false, vec![], false));
        assert!(q.has_preempt_candidate(ttl, Some("peer-a"), 0, false));
        // 空 active_peer_id 不得误匹配。
        assert!(!q.has_preempt_candidate(ttl, Some(""), 0, false));

        // 过期条目自动忽略。
        thread::sleep(Duration::from_millis(5));
        assert!(!q.has_preempt_candidate(Duration::ZERO, Some("peer-a"), 0, false));

        // 2) 不同设备的普通协助连接：旧会话活跃（< 4s 且未 Detached）时拒绝抢占；>= 4s 或 Detached 时放行。
        let q_guest = BoundedRelayIncomingQueue::new(8);
        q_guest.push(mk("peer-b", false, vec![], false));
        assert!(!q_guest.has_preempt_candidate(ttl, Some("peer-a"), 0, false));
        assert!(!q_guest.has_preempt_candidate(ttl, Some("peer-a"), 2_999_999, false));
        assert!(!q_guest.has_preempt_candidate(ttl, Some("peer-a"), 3_500_000, false));
        assert!(q_guest.has_preempt_candidate(ttl, Some("peer-a"), 4_000_000, false));
        assert!(q_guest.has_preempt_candidate(ttl, Some("peer-a"), 0, true));

        // 3) 不同设备的同账号自控连接：活跃（< 3s 且未 Detached）时保护当前用户；>= 3s 或 Detached 时抢占。
        let q_owner = BoundedRelayIncomingQueue::new(8);
        q_owner.push(mk("peer-owner-2", true, vec![], false));
        assert!(!q_owner.has_preempt_candidate(ttl, Some("peer-a"), 0, false));
        assert!(!q_owner.has_preempt_candidate(ttl, Some("peer-a"), 2_999_999, false));
        assert!(q_owner.has_preempt_candidate(ttl, Some("peer-a"), 3_000_000, false));
        assert!(q_owner.has_preempt_candidate(ttl, Some("peer-a"), 0, true));

        // 4) LAN 刚建连的 3s 宽限期内：无论 peer_lan_addrs 是否为空、无论 idle 是否 >= 3s/4s、
        //    无论 Streaming 还是 Detached，同对端普通 PunchCoord（is_relay_alloc=false）一律忽略；
        //    仅当显式切中继（is_relay_alloc=true）或晚于宽限期的新请求才触发抢占。
        let q_lan_guard = BoundedRelayIncomingQueue::new(8);
        let session_started = Instant::now();
        let cutoff = session_started + LAN_STALE_SIGNAL_GRACE;
        q_lan_guard.push(mk("peer-a", true, vec![], false));
        assert!(!q_lan_guard.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            0,
            false,
            Some(cutoff),
        ));
        assert!(!q_lan_guard.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            5_000_000,
            false,
            Some(cutoff),
        ));
        assert!(!q_lan_guard.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            0,
            true,
            Some(cutoff),
        ));
        q_lan_guard.push(mk("peer-a", true, vec![], true));
        assert!(q_lan_guard.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            0,
            false,
            Some(cutoff),
        ));
        assert!(q_lan_guard.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            0,
            true,
            Some(cutoff),
        ));

        // 5) 端到端验证：drive_ui_host_session_inner 检测到同设备新入站连接时迅速抢占退出且不删队列凭据。
        let clock: SessionClock = Arc::new(|| 10_000);
        let (mut host, _in_tx, _out_rx, _out_dgrams) =
            build_streaming_channel_host(Arc::clone(&clock));
        let incoming_q = Arc::new(BoundedRelayIncomingQueue::new(8));
        incoming_q.push(mk("peer-a", true, vec![], true));
        let t_q = Arc::clone(&incoming_q);
        let t_clock = Arc::clone(&clock);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let t_stop = Arc::clone(&stop_flag);
        let started = Instant::now();
        let outcome = drive_ui_host_session_inner(
            &mut host,
            &t_clock,
            None,
            &BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP),
            &AtomicU64::new(0),
            0,
            &AtomicU64::new(0),
            0,
            &AtomicBool::new(false),
            &t_stop,
            &AtomicU8::new(ByeReason::Normal as u8),
            HostTransportKind::Relay,
            false,
            false,
            false,
            &AtomicU64::new(0),
            None,
            &mut PersistentOwnerTerminals::new(),
            Arc::new(Mutex::new(None)),
            Arc::new(RwLock::new(None)),
            &AtomicBool::new(true),
            Some(&t_q),
            Some("peer-a"),
            started,
        );
        assert!(
            outcome.preempted_by_incoming,
            "same-peer RelayIncoming must preempt active Relay session"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "preemption must complete promptly, took {:?}",
            started.elapsed()
        );
        let preserved = incoming_q
            .pop_ready(ttl, Duration::ZERO)
            .expect("preempting RelayIncoming token must remain intact in queue");
        assert_eq!(preserved.peer_id, "peer-a");
    }

    #[test]
    fn audio_capture_is_stopped_triggers_automatic_self_healing_and_resumes_sending() {
        // Part A：端到端验证旧 AudioCapture::is_stopped() == true 后自动停止旧采集器、
        // 300ms 后异步创建新采集器并恢复向对端发送 AudioFrame。
        let clock: SessionClock = Arc::new(|| 10_000);
        let (mut host, _in_tx, out_rx, _out_dgrams) =
            build_streaming_channel_host(Arc::clone(&clock));

        let cap1_stopped = Arc::new(AtomicBool::new(false));
        let cap1_stop_calls = Arc::new(AtomicU64::new(0));
        let rebuilt_count = Arc::new(AtomicU64::new(0));

        let cap1: Box<dyn AudioCapture> = Box::new(ScriptedAudioCapture {
            inner: rc_audio::FakeAudioCapture::new(),
            stopped: Arc::clone(&cap1_stopped),
            stop_calls: Arc::clone(&cap1_stop_calls),
        });
        let t_rebuilt = Arc::clone(&rebuilt_count);
        let audio_mgr = HostAudioManager::with_creator(
            true,
            Some(cap1),
            Arc::new(move || {
                t_rebuilt.fetch_add(1, Ordering::AcqRel);
                Ok(Box::new(rc_audio::FakeAudioCapture::new()))
            }),
        );

        let stop_flag = Arc::new(AtomicBool::new(false));
        let t_stop = Arc::clone(&stop_flag);
        let t_clock = Arc::clone(&clock);
        let driver = thread::spawn(move || {
            drive_ui_host_session_with_audio(
                &mut host,
                &t_clock,
                None,
                &BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP),
                &AtomicU64::new(0),
                0,
                &AtomicU64::new(0),
                0,
                &AtomicBool::new(false),
                &t_stop,
                &AtomicU8::new(ByeReason::Normal as u8),
                HostTransportKind::Lan,
                false,
                false,
                &AtomicU64::new(0),
                None,
                &mut PersistentOwnerTerminals::new(),
                Arc::new(Mutex::new(None)),
                Arc::new(RwLock::new(None)),
                &AtomicBool::new(true),
                None,
                None,
                Instant::now(),
                audio_mgr,
            )
        });

        let wait_audio_seq = |rx: &mpsc::Receiver<Vec<u8>>, min_seq: u32, timeout: Duration| {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                let rem = deadline.saturating_duration_since(Instant::now());
                if let Ok(raw) = rx.recv_timeout(rem.min(Duration::from_millis(20))) {
                    if let Ok(rc_session::proto::ControlMessage::AudioFrame { seq, .. }) =
                        rc_session::proto::ControlMessage::decode(&raw)
                    {
                        if seq >= min_seq {
                            return Some(seq);
                        }
                    }
                }
            }
            None
        };

        // 1) 旧采集器先正常送出音频帧。
        let before_seq =
            wait_audio_seq(&out_rx, 1, Duration::from_secs(2)).expect("initial audio frames");

        // 2) 模拟改分辨率/切屏导致底层 SCStream 中止：cap1.is_stopped() -> true。
        cap1_stopped.store(true, Ordering::Release);

        // 等待旧采集器被 stop() 释放并完成异步自愈重建（~300ms）。
        let heal_deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < heal_deadline && rebuilt_count.load(Ordering::Acquire) == 0 {
            thread::sleep(Duration::from_millis(15));
        }
        assert!(
            cap1_stop_calls.load(Ordering::Acquire) >= 1,
            "stopped audio capture must be explicitly stopped and replaced"
        );
        assert!(
            rebuilt_count.load(Ordering::Acquire) >= 1,
            "audio manager must spawn a replacement AudioCapture after 300ms"
        );

        // 排空重建前可能已入队的旧帧，确认新采集器持续产出递增 seq 的 AudioFrame。
        let mut max_seen = before_seq;
        while let Ok(raw) = out_rx.try_recv() {
            if let Ok(rc_session::proto::ControlMessage::AudioFrame { seq, .. }) =
                rc_session::proto::ControlMessage::decode(&raw)
            {
                max_seen = max_seen.max(seq);
            }
        }
        let after_seq = wait_audio_seq(&out_rx, max_seen.saturating_add(2), Duration::from_secs(2))
            .expect("replacement audio capture must resume sending AudioFrame packets");
        assert!(after_seq > max_seen);

        stop_flag.store(true, Ordering::Release);
        let _ = driver.join().expect("join driver");

        // Part B：验证初始化失败时的有界退避序列（300ms -> 1s -> 2s -> 2s）及 media_paused 抑制。
        let attempts = Arc::new(AtomicU64::new(0));
        let t_attempts = Arc::clone(&attempts);
        let mut mgr = HostAudioManager::with_creator(
            true,
            None,
            Arc::new(move || {
                t_attempts.fetch_add(1, Ordering::AcqRel);
                Err("locked screen".to_string())
            }),
        );
        let mut gate = AudioSilenceGate::default();
        let t0 = Instant::now();
        // 等待首次异步失败线程退出并被 poll 消费 -> 预约 t0 + 300ms，下次退避升至 1s。
        let wait_init_fail = Instant::now() + Duration::from_secs(1);
        while Instant::now() < wait_init_fail && mgr.retry_at.is_none() {
            mgr.poll_and_recover(t0, false, &mut gate);
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(mgr.retry_at, Some(t0 + Duration::from_millis(300)));
        assert_eq!(mgr.retry_backoff, Duration::from_secs(1));

        // 推进虚拟时间至 +300ms 触发第 2 次失败 -> 预约 +1s，下次退避升至 2s。
        let t1 = t0 + Duration::from_millis(300);
        mgr.poll_and_recover(t1, false, &mut gate);
        let wait_fail2 = Instant::now() + Duration::from_secs(1);
        while Instant::now() < wait_fail2 && mgr.retry_at.is_none() {
            mgr.poll_and_recover(t1, false, &mut gate);
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(mgr.retry_at, Some(t1 + Duration::from_secs(1)));
        assert_eq!(mgr.retry_backoff, Duration::from_secs(2));

        // 推进虚拟时间至 +1s 触发第 3 次失败 -> 封顶 2s。
        let t2 = t1 + Duration::from_secs(1);
        mgr.poll_and_recover(t2, false, &mut gate);
        let wait_fail3 = Instant::now() + Duration::from_secs(1);
        while Instant::now() < wait_fail3 && mgr.retry_at.is_none() {
            mgr.poll_and_recover(t2, false, &mut gate);
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(mgr.retry_at, Some(t2 + Duration::from_secs(2)));
        assert_eq!(mgr.retry_backoff, Duration::from_secs(2));

        // 显示器切换后退避重置为 300ms，且 media_paused == true 时绝不拉起自愈。
        mgr.reset_backoff_for_display_change(t2);
        assert_eq!(mgr.retry_backoff, Duration::from_millis(300));
        assert_eq!(mgr.retry_at, Some(t2 + Duration::from_millis(300)));
        let attempts_before_paused = attempts.load(Ordering::Acquire);
        mgr.poll_and_recover(t2 + Duration::from_secs(10), true, &mut gate);
        assert_eq!(
            attempts.load(Ordering::Acquire),
            attempts_before_paused,
            "media_paused must suppress audio self-healing retries"
        );
    }

    #[test]
    fn lan_stale_punch_coord_empty_addrs_never_preempts_and_is_purged_while_relay_alloc_and_post_grace_preempt(
    ) {
        let mk = |peer_id: &str, token: &str, lan: Vec<&str>, is_relay_alloc: bool| RelayIncoming {
            session_id: format!("sid-{token}"),
            peer_id: peer_id.to_string(),
            relay_addr: "127.0.0.1:21117".to_string(),
            relay_token: token.to_string(),
            peer_public_addr: None,
            peer_lan_addrs: lan.into_iter().map(str::to_string).collect(),
            local_udp_port: None,
            owner_grant: None,
            is_owner_connection: true,
            is_relay_alloc,
            ..RelayIncoming::default()
        };

        let ttl = Duration::from_secs(20);
        let q = BoundedRelayIncomingQueue::new(8);
        let session_started = Instant::now();
        let lan_grace_cutoff = session_started + Duration::from_millis(80);

        // 1) 同对端迟到的普通 PunchCoord（is_relay_alloc=false）即使 peer_lan_addrs 为空，
        //    在 Streaming（含 idle>=3s/4s）和 Detached 两态均绝不抢占。
        q.push(mk("peer-a", "stale-empty-lan", vec![], false));
        assert!(!q.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            0,
            false,
            Some(lan_grace_cutoff),
        ));
        assert!(!q.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            3_500_000,
            false,
            Some(lan_grace_cutoff),
        ));
        assert!(!q.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            5_000_000,
            false,
            Some(lan_grace_cutoff),
        ));
        assert!(!q.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            0,
            true,
            Some(lan_grace_cutoff),
        ));

        // 2) purge_stale_lan_punch_for_peer 主动清掉同对端陈旧 PunchCoord，同时保留其他对端条目。
        q.push(mk("peer-other", "other-token", vec![], false));
        q.purge_stale_lan_punch_for_peer(Some("peer-a"), lan_grace_cutoff, ttl);
        let remaining = q
            .pop_ready(ttl, Duration::ZERO)
            .expect("other peer entry must survive stale LAN punch purge");
        assert_eq!(remaining.peer_id, "peer-other");
        assert!(q.pop_ready(ttl, Duration::ZERO).is_none());

        // 3) 显式切中继（is_relay_alloc=true）在宽限期内也不被清理，且在 Streaming 与 Detached 均立即抢占。
        q.push(mk("peer-a", "explicit-relay", vec![], true));
        q.purge_stale_lan_punch_for_peer(Some("peer-a"), lan_grace_cutoff, ttl);
        assert!(q.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            0,
            false,
            Some(lan_grace_cutoff),
        ));
        assert!(q.has_preempt_candidate_filtered(
            ttl,
            Some("peer-a"),
            0,
            true,
            Some(lan_grace_cutoff),
        ));
        let preserved_relay = q
            .pop_ready(ttl, Duration::ZERO)
            .expect("explicit RelayReady must survive stale LAN purge");
        assert_eq!(preserved_relay.relay_token, "explicit-relay");

        // 4) 明确晚于宽限期的新 PunchCoord（enqueued_at > lan_grace_cutoff）不被清理，且立即抢占。
        let past_cutoff = Instant::now();
        thread::sleep(Duration::from_millis(5));
        q.push(mk("peer-a", "post-grace-punch", vec![], false));
        q.purge_stale_lan_punch_for_peer(Some("peer-a"), past_cutoff, ttl);
        assert!(q.has_preempt_candidate_filtered(ttl, Some("peer-a"), 0, false, Some(past_cutoff),));
        assert!(q.has_preempt_candidate_filtered(ttl, Some("peer-a"), 0, true, Some(past_cutoff),));

        // 5) 端到端验证：LAN 会话驱动循环收到 peer_lan_addrs 为空的同源旧 PunchCoord 时绝不误抢占，
        //    且在 Streaming 巡检后主动将其从队列中清理干净。
        let clock: SessionClock = Arc::new(|| 10_000);
        let (mut host, _in_tx, _out_rx, _out_dgrams) =
            build_streaming_channel_host(Arc::clone(&clock));
        let incoming_q = Arc::new(BoundedRelayIncomingQueue::new(8));
        let started = Instant::now();
        incoming_q.push(mk("peer-a", "late-same-origin", vec![], false));
        let t_q = Arc::clone(&incoming_q);
        let t_clock = Arc::clone(&clock);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let t_stop = Arc::clone(&stop_flag);
        let driver = thread::spawn(move || {
            drive_ui_host_session_inner(
                &mut host,
                &t_clock,
                None,
                &BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP),
                &AtomicU64::new(0),
                0,
                &AtomicU64::new(0),
                0,
                &AtomicBool::new(false),
                &t_stop,
                &AtomicU8::new(ByeReason::Normal as u8),
                HostTransportKind::Lan,
                false,
                false,
                false,
                &AtomicU64::new(0),
                None,
                &mut PersistentOwnerTerminals::new(),
                Arc::new(Mutex::new(None)),
                Arc::new(RwLock::new(None)),
                &AtomicBool::new(true),
                Some(&t_q),
                Some("peer-a"),
                started,
            )
        });

        // 超过 PREEMPT_CHECK_INTERVAL (100ms) 后，旧 PunchCoord 应已被清理且会话未被误抢占。
        thread::sleep(Duration::from_millis(220));
        assert!(
            !driver.is_finished(),
            "stale same-peer PunchCoord with empty peer_lan_addrs must not preempt LAN session"
        );
        assert!(
            incoming_q.pop_ready(ttl, Duration::ZERO).is_none(),
            "stale same-peer PunchCoord must be actively purged during LAN Streaming"
        );

        stop_flag.store(true, Ordering::Release);
        let outcome = driver.join().expect("join driver");
        assert!(!outcome.preempted_by_incoming);
    }

    #[test]
    fn host_audio_manager_immediate_stop_escalates_backoff_and_resets_after_stable_window() {
        let should_start_stopped = Arc::new(AtomicBool::new(true));
        let t_stopped_flag = Arc::clone(&should_start_stopped);
        let created = Arc::new(AtomicU64::new(0));
        let t_created = Arc::clone(&created);

        let mut mgr = HostAudioManager::with_creator(
            true,
            None,
            Arc::new(move || {
                t_created.fetch_add(1, Ordering::AcqRel);
                let stopped = Arc::new(AtomicBool::new(t_stopped_flag.load(Ordering::Acquire)));
                Ok(Box::new(ScriptedAudioCapture {
                    inner: rc_audio::FakeAudioCapture::new(),
                    stopped,
                    stop_calls: Arc::new(AtomicU64::new(0)),
                }))
            }),
        );
        let mut gate = AudioSilenceGate::default();
        let t0 = Instant::now();

        // 第 1 次创建成功但刚创建即 is_stopped() -> 预约 +300ms，下次退避升至 1s。
        let wait1 = Instant::now() + Duration::from_secs(1);
        while Instant::now() < wait1 && mgr.capture.is_none() {
            mgr.poll_and_recover(t0, false, &mut gate);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(mgr.capture.is_some());
        mgr.poll_and_recover(t0 + Duration::from_millis(10), false, &mut gate);
        assert!(mgr.capture.is_none());
        assert_eq!(
            mgr.retry_at,
            Some(t0 + Duration::from_millis(10) + Duration::from_millis(300))
        );
        assert_eq!(mgr.retry_backoff, Duration::from_secs(1));

        // 第 2 次刚创建即 is_stopped() -> 不回退到 300ms，预约 +1s，下次退避升至 2s。
        let t1 = t0 + Duration::from_millis(310);
        mgr.poll_and_recover(t1, false, &mut gate);
        let wait2 = Instant::now() + Duration::from_secs(1);
        while Instant::now() < wait2 && mgr.capture.is_none() {
            mgr.poll_and_recover(t1, false, &mut gate);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(mgr.capture.is_some());
        assert_eq!(
            mgr.retry_backoff,
            Duration::from_secs(1),
            "receiving Ok(cap) must not prematurely reset retry_backoff before stable window"
        );
        mgr.poll_and_recover(t1 + Duration::from_millis(10), false, &mut gate);
        assert!(mgr.capture.is_none());
        assert_eq!(
            mgr.retry_at,
            Some(t1 + Duration::from_millis(10) + Duration::from_secs(1))
        );
        assert_eq!(mgr.retry_backoff, Duration::from_secs(2));

        // 第 3 次刚创建即 is_stopped() -> 预约 +2s，封顶 2s。
        let t2 = t1 + Duration::from_millis(1010);
        mgr.poll_and_recover(t2, false, &mut gate);
        let wait3 = Instant::now() + Duration::from_secs(1);
        while Instant::now() < wait3 && mgr.capture.is_none() {
            mgr.poll_and_recover(t2, false, &mut gate);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(mgr.capture.is_some());
        mgr.poll_and_recover(t2 + Duration::from_millis(10), false, &mut gate);
        assert!(mgr.capture.is_none());
        assert_eq!(
            mgr.retry_at,
            Some(t2 + Duration::from_millis(10) + Duration::from_secs(2))
        );
        assert_eq!(mgr.retry_backoff, Duration::from_secs(2));

        // 第 4 次创建健康采集器并稳定存活 >= 5s -> 退避复位回 300ms。
        should_start_stopped.store(false, Ordering::Release);
        let t3 = t2 + Duration::from_millis(2010);
        mgr.poll_and_recover(t3, false, &mut gate);
        let wait4 = Instant::now() + Duration::from_secs(1);
        while Instant::now() < wait4 && mgr.capture.is_none() {
            mgr.poll_and_recover(t3, false, &mut gate);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(mgr.capture.is_some());
        mgr.poll_and_recover(t3 + Duration::from_secs(4), false, &mut gate);
        assert_eq!(
            mgr.retry_backoff,
            Duration::from_secs(2),
            "backoff must remain elevated before reaching 5s stable window"
        );
        mgr.poll_and_recover(t3 + AUDIO_RECOVERY_STABLE_WINDOW, false, &mut gate);
        assert_eq!(
            mgr.retry_backoff, AUDIO_RECOVERY_INITIAL_BACKOFF,
            "backoff must reset to 300ms once capture survives >= 5s"
        );
        assert_eq!(created.load(Ordering::Acquire), 4);
    }

    #[test]
    fn pure_tool_epoch_refresh_stays_detached_reanchors_clock_and_preserves_watchdog() {
        use rc_session::auth::ClientAuthConfig;
        use rc_session::{ClientSession, ClientSessionConfig, ReconnectConfig};

        struct EmptyInput;
        impl rc_input::InputCapture for EmptyInput {
            fn next_events(
                &mut self,
                _timeout: Duration,
            ) -> rc_types::Result<Vec<rc_input::InputEvent>> {
                Ok(Vec::new())
            }
        }

        let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
        let owner_replay = Arc::new(Mutex::new(rc_session::OwnerReplayCache::new()));
        let BuiltUiHost {
            mut host,
            clock,
            clock_anchor,
            ..
        } = build_host_session(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            None,
            rc_session::auth::DEFAULT_AUTH_TIMEOUT_US,
            false,
            false,
            true,
            true,
            None,
            owner_replay,
            Box::new(AutoApprover),
            Arc::clone(&updates),
        )
        .expect("build_host_session");

        // 将饱和刷新阈值缩短至 150ms，确定性离线触发 Bye(Refresh) 跨纪元重建。
        host.set_reconnect(ReconnectConfig {
            resume_ttl: Duration::from_secs(6),
            refresh_guard_us: 150_000,
            ..ReconnectConfig::default()
        })
        .expect("set_reconnect");
        let addr = host.local_addr().expect("local_addr");

        let connect_client = |sid: u64| {
            let mut ccfg = ClientSessionConfig::new(
                addr,
                SessionParams {
                    width: 64,
                    height: 64,
                    fps: 30,
                    bitrate_bps: 1_000_000,
                },
                sid,
                Box::new(EmptyInput),
            );
            ccfg.handshake_timeout = Duration::from_secs(3);
            ccfg.connect_timeout = Duration::from_secs(3);
            ccfg.auth = ClientAuthConfig::default();
            let cclock: SessionClock = Arc::new(|| 0);
            let mut client = ClientSession::new(
                ccfg,
                DEV_CERT_PEM,
                DEV_KEY_PEM,
                DEV_CERT_PEM,
                "rabbitcontrol",
                cclock,
            )
            .expect("client new");
            let welcome = client.connect_and_handshake().expect("client handshake");
            (client, welcome)
        };

        let stop_flag = Arc::new(AtomicBool::new(false));
        let t_stop = Arc::clone(&stop_flag);
        let t_updates = Arc::clone(&updates);
        let t_clock_anchor = clock_anchor.clone();
        let host_thread = thread::spawn(move || {
            t_clock_anchor.reset_pending();
            host.accept_and_handshake(Duration::from_secs(3))
                .expect("host accept_and_handshake");
            // 进入纯工具模式（media_paused == true）。
            host.pause_media();
            assert!(host.is_media_paused());

            let outcome = drive_ui_host_session_inner(
                &mut host,
                &clock,
                Some(&t_clock_anchor),
                &t_updates,
                &AtomicU64::new(0),
                0,
                &AtomicU64::new(0),
                0,
                &AtomicBool::new(false),
                &t_stop,
                &AtomicU8::new(ByeReason::Normal as u8),
                HostTransportKind::Lan,
                false,
                false,
                false,
                &AtomicU64::new(0),
                None,
                &mut PersistentOwnerTerminals::new(),
                Arc::new(Mutex::new(None)),
                Arc::new(RwLock::new(None)),
                &AtomicBool::new(true),
                None,
                None,
                Instant::now(),
            );
            (outcome, host.reconnect_stats(), clock())
        });

        // 1) 初始连接建立后记录首纪元 Fake(anchor1)，再等待被控端在纯工具态满 150ms 触发 Bye(Refresh)。
        let (mut client1, _w1) = connect_client(9101);
        let first_anchor = match &*clock_anchor
            .origin
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            ClockOrigin::Fake(a) => *a,
            other => panic!("expected Fake clock origin after first handshake, got {other:?}"),
        };
        let refresh_deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_refresh = false;
        while Instant::now() < refresh_deadline {
            match client1.tick(Duration::from_millis(10), Instant::now()) {
                Ok(rep) => {
                    if matches!(
                        rep.closed,
                        Some(StopReason::ByeReceived(ByeReason::Refresh))
                    ) || client1.state() == SessionState::Reconnecting
                    {
                        saw_refresh = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        assert!(
            saw_refresh,
            "client1 must observe Bye(Refresh) while host is in pure-tool mode"
        );
        // 丢弃旧连接，让被控端进入 Detached 等待新纪元 Hello（不得因 media_paused 误退出！）。
        drop(client1);
        thread::sleep(Duration::from_millis(60));
        assert!(
            !host_thread.is_finished(),
            "pure-tool host must stay in Detached during Bye(Refresh) instead of breaking"
        );

        // 发起新纪元连接，验证新会话落成后 clock_origin 已重锚为严格更新的 Fake(anchor2) 而非复用旧零点。
        let (client2, _w2) = connect_client(9102);
        let second_anchor = match &*clock_anchor
            .origin
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            ClockOrigin::Fake(a) => *a,
            other => panic!("expected Fake clock origin after epoch rebuild, got {other:?}"),
        };
        assert!(
            second_anchor > first_anchor,
            "clock_origin must be strictly re-anchored after Bye(Refresh) rebuild (first={first_anchor:?}, second={second_anchor:?})"
        );
        let clock_after_reconnect = make_session_clock(Arc::clone(&clock_anchor.origin))();
        assert!(
            clock_after_reconnect < 500_000,
            "re-anchored session clock must restart near 0, got {clock_after_reconnect}us"
        );
        let _ = client2;

        stop_flag.store(true, Ordering::Release);
        let (outcome, rstats, _final_clock) = host_thread.join().expect("join host_thread");
        assert!(
            rstats.refreshes >= 1 && rstats.rebuilds >= 1,
            "must record both refresh and rebuild across pure-tool epoch refresh: {rstats:?}"
        );
        assert_ne!(
            outcome.reason, "纯工具连接已断开",
            "pure-tool epoch refresh must not abort Detached with ordinary tool disconnect"
        );

        // 额外验证：纯工具态普通断线（非 Bye(Refresh)）仍立刻退出 Detached。
        let clock_plain: SessionClock = Arc::new(|| 10_000);
        let (mut host_plain, in_tx, _out_rx, _out_dgrams) =
            build_streaming_channel_host(Arc::clone(&clock_plain));
        host_plain.pause_media();
        in_tx
            .send(NetEvent::Disconnected {
                reason: "ordinary drop".to_string(),
            })
            .expect("send disconnect");
        let plain_outcome = drive_ui_host_session_inner(
            &mut host_plain,
            &clock_plain,
            None,
            &BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP),
            &AtomicU64::new(0),
            0,
            &AtomicU64::new(0),
            0,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &AtomicU8::new(ByeReason::Normal as u8),
            HostTransportKind::Lan,
            false,
            false,
            false,
            &AtomicU64::new(0),
            None,
            &mut PersistentOwnerTerminals::new(),
            Arc::new(Mutex::new(None)),
            Arc::new(RwLock::new(None)),
            &AtomicBool::new(true),
            None,
            None,
            Instant::now(),
        );
        assert_eq!(plain_outcome.reason, "纯工具连接已断开");
    }

    #[test]
    fn mtls_lan_survives_invalid_client_handshake_without_rebind_and_accepts_valid_client() {
        use crate::relay_transport::tests::mtls_test_certs::TestCa;
        use rc_session::{ClientAuthConfig, ClientSession, ClientSessionConfig};

        struct EmptyInput;
        impl rc_input::InputCapture for EmptyInput {
            fn next_events(
                &mut self,
                _timeout: Duration,
            ) -> rc_types::Result<Vec<rc_input::InputEvent>> {
                Ok(Vec::new())
            }
        }

        let mut ca = TestCa::new("MtlsLanHostCA");
        let (host_cert, host_key) = ca.issue_device("user-lan", "200000001");
        let (good_cert, good_key) = ca.issue_device("user-lan", "100000001");

        let mut rogue_ca = TestCa::new("RogueClientCA");
        let (rogue_cert, rogue_key) = rogue_ca.issue_device("attacker", "999999999");

        let host_bundle = SessionMtlsBundle {
            ca_cert_pem: ca.ca_pem.clone(),
            cert_pem: host_cert,
            key_pem: host_key,
            local_user_id: "user-lan".to_string(),
            expected_peer_device_id: None,
            expected_peer_user_id: None,
        };
        let good_bundle = SessionMtlsBundle {
            ca_cert_pem: ca.ca_pem.clone(),
            cert_pem: good_cert,
            key_pem: good_key,
            local_user_id: "user-lan".to_string(),
            expected_peer_device_id: Some("200000001".to_string()),
            expected_peer_user_id: Some("user-lan".to_string()),
        };
        let rogue_bundle = SessionMtlsBundle {
            ca_cert_pem: ca.ca_pem.clone(),
            cert_pem: rogue_cert,
            key_pem: rogue_key,
            local_user_id: "attacker".to_string(),
            expected_peer_device_id: Some("200000001".to_string()),
            expected_peer_user_id: None,
        };

        let mut host = HostHandle::spawn(UiHostConfig {
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            password: None,
            prefer_hardware: false,
            require_approval: false,
            clipboard_enabled: false,
            audio_enabled: false,
            mtls_config: Some(host_bundle),
            accept_mtls_lan: true,
            ..UiHostConfig::default()
        })
        .expect("spawn MtlsLan host");

        // 1) 等待初始 Listening 事件并记录绑定端口。
        let listen_deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_initial_listening = false;
        while Instant::now() < listen_deadline {
            if let Some(HostUpdate::Listening { .. }) = host.try_recv_update() {
                saw_initial_listening = true;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(saw_initial_listening, "host must emit initial Listening");
        let host_addr = host.listen_addr();

        // 2) 非法客户端（不受信任 CA 签发的客户端证书）尝试 mTLS 握手：
        //    TLS 1.3 客户端在发出 ClientFinished 后可能先返回 Ok，随后立刻收到服务端拒收证书的
        //    TLS Alert / CONNECTION_CLOSE；无论在 connect 阶段或随后的 poll 阶段都必须被服务端拒连。
        let dev_id = rc_net::quic::Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");
        let rogue_ep = QuicEndpoint::new(
            &NetConfig::new(Role::Controller, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            &dev_id,
        )
        .expect("rogue ep");
        let rogue_mtls = rogue_bundle.to_quic_mtls_config().expect("rogue mtls cfg");
        match rogue_ep.connect_mtls(host_addr, &rogue_mtls, "", Duration::from_secs(2)) {
            Err(_) => {}
            Ok(mut rogue_t) => {
                let rej_deadline = Instant::now() + Duration::from_secs(2);
                let mut rejected = false;
                while Instant::now() < rej_deadline && !rejected {
                    match rogue_t.poll(Duration::from_millis(20)) {
                        Ok(events) => {
                            if events
                                .iter()
                                .any(|ev| matches!(ev, NetEvent::Disconnected { .. }))
                            {
                                rejected = true;
                            }
                        }
                        Err(_) => {
                            rejected = true;
                        }
                    }
                }
                assert!(
                    rejected,
                    "rogue untrusted client must be rejected by MtlsLan server"
                );
            }
        }
        drop(rogue_ep);

        // 等待短暂窗口，验证 MtlsLan 端点未触发重建（无额外 Listening 重绑事件，也无 ClientConnected，端口保持不变）。
        thread::sleep(Duration::from_millis(120));
        let mut rebind_listening_count = 0usize;
        let mut rogue_connected = false;
        while let Some(upd) = host.try_recv_update() {
            match upd {
                HostUpdate::Listening { .. } => rebind_listening_count += 1,
                HostUpdate::ClientConnected { .. } | HostUpdate::OwnerConnected { .. } => {
                    rogue_connected = true;
                }
                _ => {}
            }
        }
        assert!(
            !rogue_connected,
            "rogue untrusted client must never reach ClientConnected"
        );
        assert_eq!(
            rebind_listening_count, 0,
            "single invalid client handshake must not rebuild MtlsLan endpoint"
        );
        assert_eq!(
            host.listen_addr(),
            host_addr,
            "MtlsLan endpoint address must stay unchanged after invalid client"
        );

        // 3) 随后合法 mTLS 客户端连接到同一地址，必须正常完成 mTLS + Hello/Welcome 握手。
        let good_ep = QuicEndpoint::new(
            &NetConfig::new(Role::Controller, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            &dev_id,
        )
        .expect("good ep");
        let good_mtls = good_bundle.to_quic_mtls_config().expect("good mtls cfg");
        let good_transport = good_ep
            .connect_mtls(host_addr, &good_mtls, "", Duration::from_secs(3))
            .expect("valid mTLS client must connect to surviving MtlsLan endpoint");
        assert_eq!(
            good_transport
                .peer_mtls_identity()
                .expect("peer identity")
                .device_id,
            "200000001"
        );

        let mut ccfg = ClientSessionConfig::new(
            host_addr,
            SessionParams {
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
            },
            4242,
            Box::new(EmptyInput),
        );
        ccfg.handshake_timeout = Duration::from_secs(3);
        ccfg.auth = ClientAuthConfig::default();
        let placeholder_res = Resolution::new(64, 64);
        let dummy_dec = rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
            resolution: placeholder_res,
            ..rc_decode::FakeDecoderConfig::default()
        })
        .expect("dummy dec");
        let dummy_ren = rc_render::FakeRenderer::new(rc_render::FakeRendererConfig {
            size: (placeholder_res.width, placeholder_res.height),
            ..rc_render::FakeRendererConfig::default()
        })
        .expect("dummy ren");
        let cclock: SessionClock = Arc::new(|| 0);
        let mut client = ClientSession::with_parts(
            ccfg,
            Box::new(good_transport),
            Box::new(dummy_dec),
            Box::new(dummy_ren),
            cclock,
        )
        .expect("client with_parts");
        let granted = client
            .handshake()
            .expect("valid client session handshake must succeed");
        assert_eq!(granted.width, 640);
        assert_eq!(granted.height, 360);

        let conn_deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_connected = false;
        while Instant::now() < conn_deadline {
            if let Some(HostUpdate::ClientConnected { remote_addr }) = host.try_recv_update() {
                assert!(
                    remote_addr.contains("LAN mTLS"),
                    "expected LAN mTLS label, got {remote_addr}"
                );
                saw_connected = true;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            saw_connected,
            "host must report ClientConnected for valid mTLS client"
        );

        drop(client);
        drop(good_ep);
        host.stop();
    }

    #[test]
    fn accept_error_backoff_bounds_tight_loop_and_respects_stop_flag() {
        assert_eq!(accept_error_backoff(0), None);
        assert_eq!(accept_error_backoff(1), None);
        assert_eq!(accept_error_backoff(2), None);
        assert_eq!(accept_error_backoff(3), Some(Duration::from_millis(20)));
        assert_eq!(accept_error_backoff(4), Some(Duration::from_millis(40)));
        assert_eq!(accept_error_backoff(5), Some(Duration::from_millis(50)));
        assert_eq!(accept_error_backoff(100), Some(Duration::from_millis(50)));

        let stop = AtomicBool::new(true);
        let t0 = Instant::now();
        sleep_cancelable(Duration::from_secs(2), &stop);
        assert!(
            t0.elapsed() < Duration::from_millis(50),
            "sleep_cancelable must exit immediately when stop_flag is set"
        );
    }

    #[test]
    fn tool_permissions_owner_exempt_vs_non_owner_and_runtime_hot_toggle() {
        // 1) 纯归属判定红线：仅 Owner 会话（authenticated_owner().is_some()）豁免保持全开；
        //    非 Owner 会话严格受 allow_assist_file_transfer 门控。
        assert_eq!(
            compute_effective_tool_permissions(true, false),
            rc_session::ToolPermissions::all_allowed()
        );
        assert_eq!(
            compute_effective_tool_permissions(true, true),
            rc_session::ToolPermissions::all_allowed()
        );
        assert_eq!(
            compute_effective_tool_permissions(false, true),
            rc_session::ToolPermissions::all_allowed()
        );
        assert_eq!(
            compute_effective_tool_permissions(false, false),
            rc_session::ToolPermissions {
                allow_file_transfer: false,
                allow_terminal: true,
                allow_port_map: true,
            }
        );

        // 2) 非 Owner 串流会话：初始允许 -> 运行期热关闭（不断会话）-> 立即推 ToolPermissionsState(false)
        //    -> 控制端绕过前置拦截直接发 TOOL_CHANNEL_FILE 帧 -> 被控端硬拦截并节流回传 ToolPermissionDenied。
        let clock: SessionClock = Arc::new(|| 10_000);
        let (mut host, in_tx, out_rx, _out_dgrams) =
            build_streaming_channel_host(Arc::clone(&clock));
        assert!(host.authenticated_owner().is_none());

        let stop_flag = Arc::new(AtomicBool::new(false));
        let allow_assist_ft = Arc::new(AtomicBool::new(true));
        let t_stop = Arc::clone(&stop_flag);
        let t_allow_ft = Arc::clone(&allow_assist_ft);
        let t_clock = Arc::clone(&clock);
        let driver = thread::spawn(move || {
            drive_ui_host_session_inner(
                &mut host,
                &t_clock,
                None,
                &BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP),
                &AtomicU64::new(0),
                0,
                &AtomicU64::new(0),
                0,
                &AtomicBool::new(false),
                &t_stop,
                &AtomicU8::new(ByeReason::Normal as u8),
                HostTransportKind::Lan,
                false,
                false,
                false,
                &AtomicU64::new(0),
                None,
                &mut PersistentOwnerTerminals::new(),
                Arc::new(Mutex::new(None)),
                Arc::new(RwLock::new(None)),
                &t_allow_ft,
                None,
                None,
                Instant::now(),
            )
        });

        let init_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(
                m,
                DisplayControlMsg::ToolPermissionsState {
                    allow_file_transfer: true,
                    allow_terminal: true,
                    allow_port_map: true,
                }
            )
        });
        assert!(
            init_msgs.iter().any(|m| matches!(
                m,
                DisplayControlMsg::ToolPermissionsState {
                    allow_file_transfer: true,
                    ..
                }
            )),
            "entering Streaming must push initial ToolPermissionsState(true): {init_msgs:?}"
        );

        // 运行期热关闭协助文件传输，会话不中断且立即推送 ToolPermissionsState(false)。
        allow_assist_ft.store(false, Ordering::Release);
        let revoked_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(
                m,
                DisplayControlMsg::ToolPermissionsState {
                    allow_file_transfer: false,
                    allow_terminal: true,
                    allow_port_map: true,
                }
            )
        });
        assert!(
            revoked_msgs.iter().any(|m| matches!(
                m,
                DisplayControlMsg::ToolPermissionsState {
                    allow_file_transfer: false,
                    ..
                }
            )),
            "hot toggle to false must immediately push ToolPermissionsState(false): {revoked_msgs:?}"
        );
        assert!(
            !driver.is_finished(),
            "toggling allow_assist_file_transfer must not terminate active session"
        );

        // 模拟绕过控制端拦截的恶意/旧版客户端直发 TOOL_CHANNEL_FILE 帧。
        let mut wire_file = Vec::new();
        rc_session::proto::ControlMessage::ToolChannel {
            channel: TOOL_CHANNEL_FILE,
            payload: b"bypass-attempt".to_vec(),
        }
        .encode(&mut wire_file);
        in_tx
            .send(NetEvent::Reliable(wire_file))
            .expect("inject file frame");

        let denied_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(
                m,
                DisplayControlMsg::ToolPermissionDenied {
                    channel: TOOL_CHANNEL_FILE,
                    ..
                }
            )
        });
        assert!(
            denied_msgs.iter().any(|m| matches!(
                m,
                DisplayControlMsg::ToolPermissionDenied {
                    channel: TOOL_CHANNEL_FILE,
                    ..
                }
            )),
            "host must hard-reject TOOL_CHANNEL_FILE and reply ToolPermissionDenied: {denied_msgs:?}"
        );

        stop_flag.store(true, Ordering::Release);
        let _ = driver.join().expect("join driver");
    }

    #[test]
    fn file_host_worker_cancel_on_drop_discards_buffered_upload_frames_and_cleans_rcpart() {
        let base = std::env::temp_dir().join(format!(
            "rc-host-file-cancel-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let recv_dir: SharedFileTransferDir = Arc::new(RwLock::new(Some(base.clone())));

        // 场景 A：cancel 置位时，即便 in_rx 中已有完整 UploadStart + UploadChunk + UploadFinish 缓冲帧，
        // Drop 也不得继续消费写盘或 fs::rename 落盘最终文件。
        let worker_a = FileHostWorker::spawn(Arc::clone(&recv_dir));
        worker_a.cancel.store(true, Ordering::Release);
        let start = rc_tools::FileWireMsg::UploadStart {
            id: 701,
            remote_dir: base.to_string_lossy().to_string(),
            file_name: "must_not_exist.bin".to_string(),
            total_bytes: 8,
        }
        .encode()
        .unwrap();
        let chunk = rc_tools::FileWireMsg::UploadChunk {
            id: 701,
            offset: 0,
            data: b"12345678".to_vec(),
        }
        .encode()
        .unwrap();
        let finish = rc_tools::FileWireMsg::UploadFinish { id: 701 }
            .encode()
            .unwrap();
        let _ = worker_a.try_send_incoming(start);
        let _ = worker_a.try_send_incoming(chunk);
        let _ = worker_a.try_send_incoming(finish);
        drop(worker_a);
        assert!(
            !base.join("must_not_exist.bin").exists(),
            "cancelled FileHostWorker::drop must not process buffered UploadFinish into final file"
        );

        // 场景 B：进行中上传已创建 `.rcpart`，Drop 时立即回收并清理 `.rcpart` 不留残留。
        let worker_b = FileHostWorker::spawn(Arc::clone(&recv_dir));
        let start_b = rc_tools::FileWireMsg::UploadStart {
            id: 702,
            remote_dir: base.to_string_lossy().to_string(),
            file_name: "partial.bin".to_string(),
            total_bytes: 1024,
        }
        .encode()
        .unwrap();
        let chunk_b = rc_tools::FileWireMsg::UploadChunk {
            id: 702,
            offset: 0,
            data: vec![0x55u8; 64],
        }
        .encode()
        .unwrap();
        worker_b.try_send_incoming(start_b).unwrap();
        worker_b.try_send_incoming(chunk_b).unwrap();
        // 等待 UploadAck 确认 UploadStart + UploadChunk 已在 worker 线程处理并生成 `.rcpart`。
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_ack = false;
        while Instant::now() < deadline && !saw_ack {
            if !worker_b.try_recv_outgoing(8).is_empty() {
                saw_ack = true;
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
        assert!(saw_ack, "expected UploadAck before simulating hot revoke");
        drop(worker_b);
        assert!(!base.join("partial.bin").exists());
        let lingering_parts: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".rcpart"))
            .collect();
        assert!(
            lingering_parts.is_empty(),
            "dropping FileHostWorker must clean up in-flight .rcpart: {lingering_parts:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn detached_resume_revokes_file_transfer_and_clears_pending_file_state() {
        use rc_session::auth::ClientAuthConfig;
        use rc_session::{ClientSession, ClientSessionConfig, ReconnectConfig};

        struct EmptyInput;
        impl rc_input::InputCapture for EmptyInput {
            fn next_events(
                &mut self,
                _timeout: Duration,
            ) -> rc_types::Result<Vec<rc_input::InputEvent>> {
                Ok(Vec::new())
            }
        }

        let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
        let owner_replay = Arc::new(Mutex::new(rc_session::OwnerReplayCache::new()));
        let BuiltUiHost {
            mut host,
            clock,
            clock_anchor,
            ..
        } = build_host_session(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            None,
            rc_session::auth::DEFAULT_AUTH_TIMEOUT_US,
            false,
            false,
            true,
            true,
            None,
            owner_replay,
            Box::new(AutoApprover),
            Arc::clone(&updates),
        )
        .expect("build_host_session");
        host.set_reconnect(ReconnectConfig {
            resume_ttl: Duration::from_secs(6),
            ..ReconnectConfig::default()
        })
        .expect("set_reconnect");
        let addr = host.local_addr().expect("local_addr");

        let allow_assist_ft = Arc::new(AtomicBool::new(true));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let t_allow = Arc::clone(&allow_assist_ft);
        let t_stop = Arc::clone(&stop_flag);
        let t_updates = Arc::clone(&updates);
        let t_anchor = clock_anchor.clone();
        let host_thread = thread::spawn(move || {
            t_anchor.reset_pending();
            host.accept_and_handshake(Duration::from_secs(5))
                .expect("accept_and_handshake");
            drive_ui_host_session_inner(
                &mut host,
                &clock,
                Some(&t_anchor),
                &t_updates,
                &AtomicU64::new(0),
                0,
                &AtomicU64::new(0),
                0,
                &AtomicBool::new(false),
                &t_stop,
                &AtomicU8::new(ByeReason::Normal as u8),
                HostTransportKind::Lan,
                false,
                false,
                false,
                &AtomicU64::new(0),
                None,
                &mut PersistentOwnerTerminals::new(),
                Arc::new(Mutex::new(None)),
                Arc::new(RwLock::new(None)),
                &t_allow,
                None,
                None,
                Instant::now(),
            )
        });

        // 1) 建立非 Owner 会话（初始 allow_file_transfer == true）。
        let mut ccfg = ClientSessionConfig::new(
            addr,
            SessionParams {
                width: 64,
                height: 64,
                fps: 30,
                bitrate_bps: 1_000_000,
            },
            7788,
            Box::new(EmptyInput),
        );
        ccfg.handshake_timeout = Duration::from_secs(3);
        ccfg.connect_timeout = Duration::from_secs(3);
        ccfg.auth = ClientAuthConfig::default();
        let cclock: SessionClock = Arc::new(|| 0);
        let mut client1 = ClientSession::new(
            ccfg,
            DEV_CERT_PEM,
            DEV_KEY_PEM,
            DEV_CERT_PEM,
            "rabbitcontrol",
            Arc::clone(&cclock),
        )
        .expect("client1 new");
        client1.connect_and_handshake().expect("client1 handshake");

        // 等待初始 ToolPermissionsState(true)。
        let mut saw_true = false;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && !saw_true {
            let _ = client1.tick(Duration::from_millis(10), Instant::now());
            for (ch, payload) in client1.drain_tool_messages() {
                if ch == TOOL_CHANNEL_DISPLAY_CTRL
                    && matches!(
                        display_ctrl::decode_display_ctrl(&payload),
                        Some(DisplayControlMsg::ToolPermissionsState {
                            allow_file_transfer: true,
                            ..
                        })
                    )
                {
                    saw_true = true;
                }
            }
        }
        assert!(saw_true, "expected initial ToolPermissionsState(true)");

        // 2) 模拟意外断网（直接 drop client1 不发 Bye）使 host 进入 Detached，期间将开关置 false。
        drop(client1);
        thread::sleep(Duration::from_millis(80));
        allow_assist_ft.store(false, Ordering::Release);

        // 3) 以同一 session_id 发起 ReconnectRequest 命中 DetachOutcome::Resumed：
        //    必须立即收到 ToolPermissionsState(false)，且发送 TOOL_CHANNEL_FILE 帧必须被拦截并回传 ToolPermissionDenied。
        let dev_id = rc_net::quic::Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).unwrap();
        let ep = rc_net::quic::QuicEndpoint::new(
            &NetConfig::new(Role::Controller, "127.0.0.1:0".parse().unwrap()),
            &dev_id,
        )
        .expect("reconnect ep");
        let server_certs = rc_net::quic::Identity::certs_from_pem(DEV_CERT_PEM).unwrap();
        let mut t2 = ep
            .connect(addr, &server_certs, "rabbitcontrol", Duration::from_secs(3))
            .expect("reconnect connect");
        let mut req_buf = Vec::new();
        rc_session::proto::ControlMessage::ReconnectRequest {
            session_id: 7788,
            resume: true,
        }
        .encode(&mut req_buf);
        t2.send_reliable(&req_buf).expect("send reconnect req");

        let mut saw_resumed_welcome = false;
        let mut saw_revoked_state = false;
        let mut saw_file_denied = false;
        let mut sent_probe_file = false;
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline
            && !(saw_resumed_welcome && saw_revoked_state && saw_file_denied)
        {
            if let Ok(evs) = t2.poll(Duration::from_millis(20)) {
                for ev in evs {
                    if let NetEvent::Reliable(raw) = ev {
                        match rc_session::proto::ControlMessage::decode(&raw) {
                            Ok(rc_session::proto::ControlMessage::Welcome(w))
                                if w.host_flags.resume_accepted() =>
                            {
                                saw_resumed_welcome = true;
                            }
                            Ok(rc_session::proto::ControlMessage::ToolChannel {
                                channel: TOOL_CHANNEL_DISPLAY_CTRL,
                                payload,
                            }) => match display_ctrl::decode_display_ctrl(&payload) {
                                Some(DisplayControlMsg::ToolPermissionsState {
                                    allow_file_transfer: false,
                                    ..
                                }) => {
                                    saw_revoked_state = true;
                                    if !sent_probe_file {
                                        sent_probe_file = true;
                                        let mut file_wire = Vec::new();
                                        rc_session::proto::ControlMessage::ToolChannel {
                                            channel: TOOL_CHANNEL_FILE,
                                            payload: b"post-resume-file".to_vec(),
                                        }
                                        .encode(&mut file_wire);
                                        let _ = t2.send_reliable(&file_wire);
                                    }
                                }
                                Some(DisplayControlMsg::ToolPermissionDenied {
                                    channel: TOOL_CHANNEL_FILE,
                                    ..
                                }) => {
                                    saw_file_denied = true;
                                }
                                _ => {}
                            },
                            Ok(rc_session::proto::ControlMessage::ToolChannel {
                                channel: TOOL_CHANNEL_FILE,
                                ..
                            }) => {
                                panic!("host must not emit TOOL_CHANNEL_FILE after resume revoke");
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        assert!(
            saw_resumed_welcome,
            "reconnect must hit DetachOutcome::Resumed"
        );
        assert!(
            saw_revoked_state,
            "DetachOutcome::Resumed must immediately push ToolPermissionsState(false)"
        );
        assert!(
            saw_file_denied,
            "post-resume TOOL_CHANNEL_FILE must be hard-rejected with ToolPermissionDenied"
        );

        stop_flag.store(true, Ordering::Release);
        drop(t2);
        drop(ep);
        let _ = host_thread.join().expect("join host_thread");
    }

    #[test]
    fn host_bridge_client_media_caps_and_codec_decode_failed_generation_handling() {
        let clock: SessionClock = Arc::new(|| 10_000);
        let (mut host, in_tx, out_rx, _out_dgrams) =
            build_streaming_channel_host(Arc::clone(&clock));
        let audio_mgr = HostAudioManager::with_creator(
            false,
            None,
            Arc::new(|| Ok(Box::new(rc_audio::FakeAudioCapture::new()))),
        );
        let stop_flag = Arc::new(AtomicBool::new(false));
        let t_stop = Arc::clone(&stop_flag);
        let t_clock = Arc::clone(&clock);
        let driver = thread::spawn(move || {
            let updates = BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP);
            let pw_ver = AtomicU64::new(0);
            let cfg_ver = AtomicU64::new(0);
            let disc = AtomicBool::new(false);
            let close_reason = AtomicU8::new(ByeReason::Normal as u8);
            let lock_cnt = AtomicU64::new(0);
            let mut owner_terms = PersistentOwnerTerminals::new();
            let wake_guard: SharedWakeGuard = Arc::new(Mutex::new(None));
            let ft_dir: SharedFileTransferDir = Arc::new(RwLock::new(None));
            let allow_assist_ft = AtomicBool::new(true);
            drive_ui_host_session_with_audio(
                &mut host,
                &t_clock,
                None,
                &updates,
                &pw_ver,
                0,
                &cfg_ver,
                0,
                &disc,
                &t_stop,
                &close_reason,
                HostTransportKind::Lan,
                false,
                false,
                &lock_cnt,
                None,
                &mut owner_terms,
                wake_guard,
                ft_dir,
                &allow_assist_ft,
                None,
                None,
                Instant::now(),
                audio_mgr,
            )
        });

        // 1) 初始 Capabilities 必须携带 supports_ext_codec_flags=true、codec_generation=1 及非空 encode_caps/decode_caps。
        let init_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(m, DisplayControlMsg::Capabilities { .. })
        });
        let init_gen = init_msgs
            .iter()
            .find_map(|m| match m {
                DisplayControlMsg::Capabilities {
                    supports_ext_codec_flags,
                    codec_generation,
                    encode_caps,
                    decode_caps,
                    ..
                } => {
                    assert!(
                        *supports_ext_codec_flags,
                        "新版被控端必须声明 supports_ext_codec_flags=true"
                    );
                    assert!(!encode_caps.is_empty());
                    assert!(!decode_caps.is_empty());
                    Some(*codec_generation)
                }
                _ => None,
            })
            .expect("must receive initial Capabilities");
        assert_eq!(init_gen, 1);

        // 2) 发送 supports_ext_codec_flags=false 的 ClientMediaCaps：不启用 AV1 且正常回传 Capabilities。
        send_display_ctrl_event(
            &in_tx,
            &DisplayControlMsg::ClientMediaCaps {
                decode_caps: rc_pipeline::default_codec_capabilities(true),
                refinement_caps: None,
                pref: crate::codec_selector::CodecSelectionPref::OfficeClear,
                supports_ext_codec_flags: false,
            },
        );
        let caps_after_client = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(m, DisplayControlMsg::Capabilities { .. })
        });
        let cur_gen = caps_after_client
            .iter()
            .find_map(|m| match m {
                DisplayControlMsg::Capabilities {
                    current_codec,
                    codec_generation,
                    ..
                } => {
                    assert_ne!(
                        current_codec.as_deref(),
                        Some("av1"),
                        "supports_ext_codec_flags=false 时绝不允许启用 AV1"
                    );
                    Some(*codec_generation)
                }
                _ => None,
            })
            .expect("must emit Capabilities after ClientMediaCaps");

        // 3) 发送过期 generation 的 CodecDecodeFailed：必须被忽略（不产生新 Capabilities 递增）。
        send_display_ctrl_event(
            &in_tx,
            &DisplayControlMsg::CodecDecodeFailed {
                codec: "av1".to_string(),
                generation: cur_gen + 99,
                reason: "stale generation".to_string(),
            },
        );
        let stale_msgs = recv_display_ctrl_until(&out_rx, Duration::from_millis(120), |m| {
            matches!(m, DisplayControlMsg::Capabilities { .. })
        });
        assert!(
            stale_msgs
                .iter()
                .all(|m| !matches!(m, DisplayControlMsg::Capabilities { .. })),
            "过期 generation 的 CodecDecodeFailed 不得触发降级重推: {stale_msgs:?}"
        );

        // 4) 发送不匹配 active_codec（当前 H.264）的 CodecDecodeFailed(hevc)：按严格回声拦截被忽略。
        send_display_ctrl_event(
            &in_tx,
            &DisplayControlMsg::CodecDecodeFailed {
                codec: "hevc".to_string(),
                generation: cur_gen,
                reason: "mismatched codec echo".to_string(),
            },
        );
        let mismatch_msgs = recv_display_ctrl_until(&out_rx, Duration::from_millis(120), |m| {
            matches!(m, DisplayControlMsg::Capabilities { .. })
        });
        assert!(
            mismatch_msgs
                .iter()
                .all(|m| !matches!(m, DisplayControlMsg::Capabilities { .. })),
            "与当前 active_codec 不符的 CodecDecodeFailed 必须忽略: {mismatch_msgs:?}"
        );

        // 5) 发送匹配当前 active_codec=h264 且匹配 generation 的 CodecDecodeFailed：
        //    保持 H.264（绝不反向升级至 HEVC）且因 active_codec 未变更不虚增 codec_generation，回推权威 Capabilities。
        send_display_ctrl_event(
            &in_tx,
            &DisplayControlMsg::CodecDecodeFailed {
                codec: "h264".to_string(),
                generation: cur_gen,
                reason: "simulated h264 decode failure".to_string(),
            },
        );
        let fb_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(m, DisplayControlMsg::Capabilities { .. })
        });
        assert!(
            fb_msgs.iter().any(|m| matches!(
                m,
                DisplayControlMsg::Capabilities {
                    current_codec: Some(c),
                    codec_generation,
                    ..
                } if c == "h264" && *codec_generation == cur_gen
            )),
            "H.264 兜底态收到匹配 CodecDecodeFailed 应保持 h264 且不虚增 generation: {fb_msgs:?}"
        );

        stop_flag.store(true, Ordering::Release);
        let _ = driver.join().expect("join host driver");
    }
}
