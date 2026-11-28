use std::any::Any;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use rand::rngs::OsRng;
use rand::RngCore;
use rc_session::auth::OwnerTicketVerifier;

use crate::relay_transport::{RelayShutdownHandle, SessionMtlsBundle};
use crate::signal_client::{ActiveControllerSummary, RelayIncoming};
use crate::switchable_transport::SwitchHandle;

use super::queues::BoundedHostUpdateQueue;

pub use crate::bridge_shared::DEFAULT_HOST_PORT;

/// 被控端更新通道容量上限（有界非阻塞，满载丢最旧）。
pub const HOST_UPDATE_CHANNEL_CAP: usize = 64;

/// 入站中继请求有界队列容量（有界非阻塞，满载丢最旧，符合铁律 1）。
pub(super) const RELAY_INCOMING_QUEUE_CAP: usize = 8;

/// 入站中继请求的存活有效期（超时未消费的过期令牌自动丢弃）。
pub(super) const RELAY_INCOMING_TTL: Duration = Duration::from_secs(20);

/// LAN / mTLS LAN 模式下 `HostSession` 的 `Detached` 断线保持窗口（短窗口，避免长期占线）。
pub(super) const HOST_LAN_RESUME_TTL: Duration = Duration::from_secs(6);

/// 串流/断线期巡检入站抢占候选的时间间隔（~100ms）。
pub(super) const PREEMPT_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// 同账号自控新入站连接触发旧会话失活抢占的静默阈值（3s）。
pub(super) const PREEMPT_OWNER_IDLE_THRESHOLD_US: u64 = 3_000_000;

/// 任意入站连接触发旧会话半开失活抢占的静默阈值（4s）。
pub(super) const PREEMPT_ANY_IDLE_THRESHOLD_US: u64 = 4_000_000;

/// 系统音频采集异常中断/初始化失败的退避序列（300ms -> 1s -> 2s）。
pub(super) const AUDIO_RECOVERY_INITIAL_BACKOFF: Duration = Duration::from_millis(300);
pub(super) const AUDIO_RECOVERY_MID_BACKOFF: Duration = Duration::from_secs(1);
pub(super) const AUDIO_RECOVERY_MAX_BACKOFF: Duration = Duration::from_secs(2);
/// 系统音频采集器判定为「稳定存活」、可将重试退避复位回 300ms 的最短连续运行时长（5s）。
pub(super) const AUDIO_RECOVERY_STABLE_WINDOW: Duration = Duration::from_secs(5);

/// 临时验证码长度（8 位无歧义大写字母数字，排除 `0`/`O`/`1`/`I`）。
pub const TEMP_CODE_LEN: usize = 8;

/// 临时验证码字符表（32 个字符 = 2^5，按低 5 位索引零模偏差）。
const TEMP_CODE_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// 单次等待入站连接的短分片超时（与 QUIC 握手预算解耦，兼顾中继入站响应速度与 `stop()` 回收）。
pub(super) const HOST_ACCEPT_SLICE: Duration = Duration::from_millis(150);

/// 收到入站 `Incoming` 后执行 QUIC/mTLS 握手与两条引导流的独立超时预算（与 `HOST_ACCEPT_SLICE` 解耦）。
pub(super) const HOST_QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

/// 中继传输层建连与 `RCR1` 握手超时。
pub(super) const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// fake 编码器的单帧编码成本（微秒，对齐 `rc-cli/src/cmd/host.rs`）。
pub(super) const FAKE_ENCODE_COST_US: u32 = 500;

/// 单拍每个工具引擎最多发送的线帧数量（避免工具吞吐饿死视频与控制面）。
pub(super) const MAX_TOOL_FRAMES_PER_TICK: usize = 8;

/// Host 侧专用文件传输工作线程的出入站有界通道容量（H12）。
pub(super) const FILE_HOST_WORKER_CHAN_CAP: usize = 64;

/// 单拍最多泵送的音频帧数量（20ms/帧，4 帧 = 80ms 突发上限）。
pub(super) const MAX_AUDIO_FRAMES_PER_TICK: usize = 4;

/// LAN 建连后容忍广域网信令迟到推送的旧 `PunchCoord` 清理宽限（3s）。
pub(super) const LAN_STALE_SIGNAL_GRACE: Duration = Duration::from_secs(3);

/// 保护会话刚断开前 500ms 内到达的新切换请求（兼容尚未等待旧连接完全退出的老客户端）。
pub(super) const SWITCH_SIGNAL_PROTECT_WINDOW: Duration = Duration::from_millis(500);

/// 被控端向控制端回传 `ToolPermissionDenied` 的单通道最小节流间隔（1s）。
pub(super) const TOOL_PERMISSION_DENIED_THROTTLE: Duration = Duration::from_secs(1);

pub(super) const DISPLAY_CTRL_QUEUE_CAP: usize = 64;

/// 编码器连续过载/丢帧触发被控端会话级熔断降级的阈值（连续失败 N 帧且当前非 H.264 时降级下一档）。
pub(super) const HOST_ENCODE_OVERLOAD_TRIP_LIMIT: u32 = 15;

/// 单个远控会话最多允许创建的虚拟显示器数量上限（防止异常/恶意对端耗尽 WindowServer 虚拟屏资源）。
pub(super) const MAX_VIRTUAL_DISPLAYS_PER_SESSION: usize = 4;

pub(super) const RELAY_MIN_BITRATE_BPS: u32 = 2_000_000;
pub(super) const RELAY_QUEUE_HIGH_BYTES: usize = 256 * 1024;
pub(super) const RELAY_QUEUE_LOW_BYTES: usize = 48 * 1024;
pub(super) const RELAY_HIGH_QUEUE_HOLD: Duration = Duration::from_millis(200);
pub(super) const RELAY_BACKOFF_COOLDOWN: Duration = Duration::from_millis(500);
pub(super) const RELAY_RAMP_INTERVAL: Duration = Duration::from_secs(1);
/// 单拍至少累计淘汰 12 个数据报（整帧级淘汰）或连续 2 拍有淘汰才触发降速，避免孤立单帧溢出误杀码率。
pub(super) const RELAY_DROP_BURST_THRESHOLD: u64 = 12;

/// 后台 P2P 穿透升直连窗口（允许 `ConeUnverified` Phase 2b 与两波次生日攻击完成）。
pub(super) const BACKGROUND_P2P_UPGRADE_WINDOW: Duration = Duration::from_secs(14);
/// 默认双端同步 `Relay-first` 等待直连起跑窗口（400ms）。
pub(super) const DEFAULT_RELAY_FIRST_AFTER_MS: u64 = 400;

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
    /// 是否需要机主审批弹窗（`false` 时使用 [`rc_session::AutoApprover`] 自动通过）。
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
    /// 可选信令客户端句柄（供运行期 `Relay -> P2P` 复探刷新 STUN 公网映射并重用 UDP 端口）。
    pub signal_client: Option<Arc<crate::signal_client::SignalClientHandle>>,
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
            signal_client: None,
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
            .field("has_signal_client", &self.signal_client.is_some())
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

/// 当前连接到本机的活跃控制端会话摘要（供「本机被控中」状态感知与管理）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveControllerSession {
    /// 控制端会话唯一标识。
    pub session_id: String,
    /// 控制端设备 ID（如 9 位设备码；未知时为空）。
    pub controller_device_id: String,
    /// 控制端显示名称（优先 `ControllerMeta.device_name`，其次 `RelayIncoming.peer_name`，
    /// 再退化为 `caller_device_id` 或 `remote_addr`）。
    pub controller_device_name: String,
    /// 控制端操作系统标识（来自 `ControllerMeta.os`，未知时为空字符串）。
    pub controller_os: String,
    /// 是否为同账号本人自控（通过 `OwnerTicket` PoP 认证）。
    pub is_owner: bool,
    /// 当前会话模式：`"remote_control"` / `"watch_only"` / `"tools"`。
    pub mode: String,
    /// 建立连接的 Unix 毫秒时间戳。
    pub connected_at_ms: u64,
}

impl From<&ActiveControllerSession> for ActiveControllerSummary {
    fn from(s: &ActiveControllerSession) -> Self {
        Self {
            session_id: s.session_id.clone(),
            controller_device_id: s.controller_device_id.clone(),
            controller_device_name: s.controller_device_name.clone(),
            controller_os: s.controller_os.clone(),
            is_owner: s.is_owner,
            mode: s.mode.clone(),
            connected_at_ms: s.connected_at_ms,
        }
    }
}

impl From<ActiveControllerSession> for ActiveControllerSummary {
    fn from(s: ActiveControllerSession) -> Self {
        Self::from(&s)
    }
}

/// UI → 被控端工作线程的低频控制命令。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostCommand {
    /// 主动断开指定或全部活跃控制端远控连接。
    DisconnectController {
        /// 目标会话 ID；`None` 表示断开当前所有（活跃）远控连接，
        /// `Some(sid)` 表示仅当与当前活跃会话 `session_id` 匹配时断开。
        #[serde(default)]
        session_id: Option<String>,
    },
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
    /// 当前活跃控制端列表变更（进入 `Streaming`、`ControllerMeta` 更新或会话结束时推送）。
    ActiveControllersChanged {
        /// 当前活跃控制端会话列表（无连接时为 `vec![]`）。
        controllers: Vec<ActiveControllerSession>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreemptDecision {
    None,
    SamePeerOrIdle,
    TakeoverOwner,
}

pub(super) struct PasswordState {
    pub(super) password: Option<String>,
    pub(super) auto_rotate: bool,
}

#[derive(Clone)]
pub(super) struct AuthRuntimeState {
    pub(super) allow_owner_control: bool,
    pub(super) allow_remote_assist: bool,
    pub(super) owner_verifier: Option<Arc<dyn OwnerTicketVerifier>>,
    pub(super) owner_replay_cache: Arc<Mutex<rc_session::OwnerReplayCache>>,
    pub(super) mtls_config: Option<SessionMtlsBundle>,
    pub(super) accept_mtls_lan: bool,
}

pub(super) type SharedActiveControllers = Arc<Mutex<Vec<ActiveControllerSession>>>;
pub(super) type SharedWakeGuard = Arc<Mutex<Option<Box<dyn Any + Send>>>>;
pub(super) type SharedFileTransferDir = Arc<RwLock<Option<PathBuf>>>;
pub(super) type SharedSignalClient =
    Arc<RwLock<Option<Arc<crate::signal_client::SignalClientHandle>>>>;

#[derive(Clone, Default)]
pub(super) struct ActiveControllerPeerHints {
    pub(super) session_id_hint: Option<String>,
    pub(super) relay_peer_id: Option<String>,
    pub(super) relay_peer_name: Option<String>,
    pub(super) relay_peer_hostname: Option<String>,
    pub(super) relay_peer_os: Option<String>,
    pub(super) mtls_peer_did: Option<String>,
    pub(super) remote_addr: String,
}

#[derive(Clone)]
pub(super) enum ActiveRelayInterrupt {
    Dialing(Arc<AtomicBool>),
    Connected(RelayShutdownHandle),
}

impl ActiveRelayInterrupt {
    pub(super) fn interrupt(&self) {
        match self {
            Self::Dialing(cancel) => cancel.store(true, Ordering::Release),
            Self::Connected(handle) => handle.shutdown(),
        }
    }
}

pub(super) struct RelayInterruptSlotGuard<'a> {
    pub(super) slot: &'a Mutex<Option<ActiveRelayInterrupt>>,
}

impl Drop for RelayInterruptSlotGuard<'_> {
    fn drop(&mut self) {
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

pub(super) struct AtomicFlagReset(pub(super) Arc<AtomicBool>);

impl Drop for AtomicFlagReset {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Debug, Clone)]
pub(super) struct HostWorkerOptions {
    pub(super) approval_timeout_us: u64,
    pub(super) prefer_hardware: bool,
    pub(super) require_approval: bool,
    pub(super) clipboard_enabled: bool,
    pub(super) audio_enabled: bool,
    pub(super) forbid_passwordless_auto_approve: bool,
    pub(super) ephemeral_listen_port: bool,
    pub(super) allow_assist_file_transfer: Arc<AtomicBool>,
    pub(super) signal_client: SharedSignalClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostTransportKind {
    Lan,
    MtlsLan,
    P2p,
    Relay,
}

pub(super) fn host_resume_ttl(transport_kind: HostTransportKind) -> Duration {
    match transport_kind {
        HostTransportKind::Relay | HostTransportKind::P2p => Duration::ZERO,
        HostTransportKind::Lan | HostTransportKind::MtlsLan => HOST_LAN_RESUME_TTL,
    }
}

pub(super) struct DriveSessionOutcome {
    pub(super) reason: String,
    pub(super) preempted_by_incoming: bool,
}

pub(super) struct HostSwitchRuntime {
    pub(super) handle: SwitchHandle,
    pub(super) incoming: RelayIncoming,
    pub(super) mtls_bundle: Option<SessionMtlsBundle>,
    pub(super) require_mtls: bool,
    pub(super) skip_p2p_for_proxy: bool,
    pub(super) updates: Arc<BoundedHostUpdateQueue>,
    pub(super) disconnect_flag: Arc<AtomicBool>,
    pub(super) stop_flag: Arc<AtomicBool>,
    pub(super) active_relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    pub(super) bg_cancel: Arc<AtomicBool>,
    pub(super) signal_client: SharedSignalClient,
}

pub(super) struct HostControllerTracking {
    pub(super) active_controllers: SharedActiveControllers,
    pub(super) peer_hints: ActiveControllerPeerHints,
    pub(super) signal_client: SharedSignalClient,
}
