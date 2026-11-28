//! UI ↔ 会话层唯一通道（T21 API 契约 §1）。
//!
//! 本模块**严禁引入 `tauri` 类型**，仅依赖 `std` + `rc-session` + `rc-net` +
//! `rc-pipeline` + `rc-input` + `rc-render` + `rc-decode` + `rc-trace`，
//! 从而使 `cargo test -p rc-ui` 的离线单测与进程内集成测试无需窗口与事件循环。
//!
//! # 硬性纪律
//! - 全模块 `#![deny(unsafe_code)]`（`CAMetalLayer` 借用指针以 `usize` 传递，不解引用）；
//! - 铁律 1（UI 侧延伸 / U6）：命令通道容量 `64`、输入通道容量 `256`、更新通道容量 `64`，
//!   满载一律非阻塞丢最旧；输入通道满载时优先保留关键事件（`Key` / `MouseButton` / `MouseWheel`），
//!   优先淘汰非关键的 `MouseMove` / `Sync`；
//! - U3：会话协议零改动，S3 手动调码率仅发送既有 `SetBitrate { reason: Manual }`；
//! - U5：HUD 数字全部由会话线程调用 [`HudSnapshot::derive`] 差分聚合后推送；
//! - U8：使用 `rc_session::dev_cert` 零配置直连，`ConnectPhase` 起点在 Endpoint 创建之前；
//! - U9：`watch_only == true` 时双层拦截输入（`send_input` + `BridgeInputCapture`）；
//! - U10：`join` 与 `Drop` 均自动发 `Disconnect` 并回收会话线程，不留僵尸线程。

#![deny(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};
use std::ffi::c_void;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rc_audio::{decode_ima_adpcm, AudioPlayer, NullAudioPlayer, PcmFrame};
use rc_input::{InputCapture, InputEvent};
use rc_net::quic::{Identity, QuicEndpoint};
use rc_net::{NetConfig, NetEvent, NetStats, Role, Transport};
use rc_pipeline::{ControllerPipeline, DiffMode, PipelineConfig};
use rc_render::Renderer;
use rc_session::auth::OwnerTicketSigner;
use rc_session::dev_cert::{dev_server_cert_pem, DEV_CERT_PEM, DEV_KEY_PEM, DEV_SERVER_NAME};
use rc_session::proto::{BitrateReason, ByeReason, ControlMessage, SessionParams};
use rc_session::{
    AudioFramePacket, ClientAuthConfig, ClientSession, ClientSessionConfig, ClipboardBackend,
    ReconnectOutcome, SessionClock, SessionState, ToolPermissions, AUDIO_CODEC_IMA_ADPCM,
    AUDIO_CODEC_PCM16, TOOL_CHANNEL_AUDIO_CTRL, TOOL_CHANNEL_DISPLAY_CTRL, TOOL_CHANNEL_FILE,
    TOOL_CHANNEL_PORTMAP, TOOL_CHANNEL_TERMINAL,
};
use rc_tools::{
    validate_terminal_name, FileClientEngine, FileEvent, PortMapClientEngine, PortMapRuleSnapshot,
    TerminalClientEngine, TerminalEvent, TransferDirection, TransferItem, TransferStatus,
};
use rc_types::Resolution;

use crate::app_prefs::ConnectionMode;
use crate::cert_manager::OwnerGrantPayload;
use crate::codec_selector::{self, CodecSelectionPref};
use crate::display_ctrl::{
    self, DisplayControlMsg, DisplayDescriptor, DisplayPreset, HighRefreshAdvisory, StreamCodec,
};
use crate::hud::{HudSample, HudSnapshot};
use crate::lan_discovery;
use crate::p2p::{self, P2pCandidates};
use crate::platform::PreallocatedRenderSurface;
pub use crate::relay_transport::SessionMtlsBundle;
use crate::relay_transport::{
    E2eeRelayTransport, RelayE2eeMode, RelayRole, RelayShutdownHandle, TcpRelayTransport,
};
use crate::signal_client::{ConnectGrant, SignalClientHandle};
use crate::switchable_transport::{
    CandidateTransport, HysteresisConfig, HysteresisDecision, RuntimePathMonitor, SwitchControlMsg,
    SwitchHandle, SwitchableTransport, TransportPathKind, DEFAULT_SWITCH_STAGE_TIMEOUT,
};
use crate::ui_error::{IntoUiError, UiError};

/// 命令通道容量上限（T21 U6 / 铁律 1 UI 侧延伸）。
pub const COMMAND_CHANNEL_CAP: usize = 64;

/// 输入通道容量上限（T21 U6，对齐 `rc-input-macos` `CgCapture` tap 通道容量）。
pub const INPUT_CHANNEL_CAP: usize = 256;

/// 会话线程 → UI 状态更新通道容量上限（T21 U6）。
pub const UPDATE_CHANNEL_CAP: usize = 64;

/// 常规 poll 预算（对齐 `rc-cli/src/cmd/client.rs`）。
const RUN_POLL_BUDGET: Duration = Duration::from_millis(1);
/// 空闲拍放宽的 poll 预算（4ms 以支撑 120/144fps 高刷唤醒不卡顿）。
const RUN_IDLE_POLL_BUDGET: Duration = Duration::from_millis(4);
/// `Reconnecting` 退避等待的最大睡眠粒度。
const RUN_RECONNECT_SLEEP: Duration = Duration::from_millis(20);
/// HUD 推送节流周期（1 秒）。
const HUD_INTERVAL: Duration = Duration::from_secs(1);
/// 硬件解码器在 `displayed == 0` 期间连续 `Outcome::DecodeError` 的判定阈值
/// （例如远端被控端未授屏幕录制权限而降级到 `FakeEncoder` 发送非 Annex-B 码流）。
const CONSECUTIVE_DECODE_ERROR_LIMIT: usize = 30;
/// 触发持续硬件解码失败终止前的最短串流观察时长（避免首帧短暂丢包误判）。
const PERSISTENT_DECODE_ERROR_MIN_ELAPSED: Duration = Duration::from_secs(3);
/// 最近窗口用于计算 `e2e_p50_ms` 的最大样本数。
const E2E_WINDOW_FRAMES: usize = 60;
/// W2 文件传输事件队列容量上限（有界 drop-oldest）。
const FILE_EVENT_CHANNEL_CAP: usize = 256;
/// W3 远程终端事件队列容量上限（有界 drop-oldest）。
const TERMINAL_EVENT_CHANNEL_CAP: usize = 512;
/// 单拍每个工具引擎最多发送的线帧数（避免工具吞吐饿死视频/输入）。
const MAX_TOOL_FRAMES_PER_TICK: usize = 8;
/// 控制端专用文件工作线程的有界通道容量（H12）。
const FILE_CLIENT_WORKER_CHAN_CAP: usize = 64;
/// 远程终端允许的最大行列尺寸（M10）。
const MAX_TERMINAL_DIM: u16 = 512;
/// 单次远程终端输入字节上限（64 KiB，M10）。
const MAX_TERMINAL_INPUT_BYTES: usize = 64 * 1024;
/// 上传进度推送最小间隔（平滑刷新 W2 进度条，不刷屏）。
const UPLOAD_PROGRESS_EMIT_INTERVAL: Duration = Duration::from_millis(100);
/// W4 端口映射统计快照比对间隔。
const PORTMAP_SNAPSHOT_INTERVAL: Duration = Duration::from_millis(200);
/// 控制端本地前置权限拦截推送 `SessionUpdate::ToolPermissionDenied` 的单通道最小节流间隔（1s）。
const LOCAL_TOOL_DENIED_THROTTLE: Duration = Duration::from_secs(1);

fn serialize_tool_permissions<S>(perms: &ToolPermissions, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    #[derive(serde::Serialize)]
    struct ToolPermissionsWire {
        allow_file_transfer: bool,
        allow_terminal: bool,
        allow_port_map: bool,
    }
    serde::Serialize::serialize(
        &ToolPermissionsWire {
            allow_file_transfer: perms.allow_file_transfer,
            allow_terminal: perms.allow_terminal,
            allow_port_map: perms.allow_port_map,
        },
        serializer,
    )
}

fn default_true() -> bool {
    true
}

/// UI 会话配置（P2 / S1 连接表单的并集）。
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct UiSessionConfig {
    /// 对端地址（`ip:port` 直连，M2 无信令；由 `model::parse_connect_target` 校验）。
    pub connect_addr: SocketAddr,
    /// 可选访问密码（`None` = 无密码握手；`Some` = 启用 PBKDF2 挑战应答）。
    #[serde(default)]
    pub password: Option<String>,
    /// 观看模式：不 pump 输入（U9）。
    pub watch_only: bool,
    /// 请求画面宽度（像素；实际以 Welcome 裁定为准）。
    pub width: u32,
    /// 请求画面高度（像素；实际以 Welcome 裁定为准）。
    pub height: u32,
    /// 请求帧率（fps；实际以 Welcome 裁定为准）。
    pub fps: u32,
    /// 请求码率（bps；实际以 Welcome 裁定为准）。
    pub bitrate_bps: u32,
    /// 优先硬件后端（VT 解码 + Metal 呈现），失败降级假后端并如实上报标签。
    pub prefer_hardware: bool,
    /// 是否启用双向剪贴板同步（默认 `true`；仅 `prefer_hardware == true` 时挂接本机真实系统剪贴板）。
    #[serde(default = "default_true")]
    pub clipboard_enabled: bool,
    /// 是否启用远端音频流接收与播放（默认 `true`）。
    #[serde(default = "default_true")]
    pub audio_enabled: bool,
    /// 可选中继/P2P 会话凭据（`Some` 时按 LAN → P2P → 中继三阶路由建连，忽略 `connect_addr`）。
    #[serde(skip)]
    pub relay_grant: Option<ConnectGrant>,
    /// 是否强制跳过 LAN / P2P，直接使用 `TCP Relay` 中继连接（仅在存在 `relay_grant` 时生效；保留以兼容旧配置）。
    #[serde(default)]
    pub force_relay: bool,
    /// 连接路由模式（`Auto` 自动三阶、`P2pOnly` 仅直连/P2P 禁止中继、`TcpRelay` 强制中继）。
    #[serde(default)]
    pub connection_mode: ConnectionMode,
    /// 纯工具模式：仅建立控制与工具通道，不初始化硬件视频解码/渲染管线并通知被控端暂停视频推流，
    /// 后续可通过 [`SessionHandle::upgrade_to_desktop`] 原地热升级为桌面控屏。
    #[serde(default)]
    pub tools_only: bool,
    /// 是否开启端到端双向 mTLS / E2EE 加密连接（默认 `false` 兼容旧离线无证书单测；由上层配置注入）。
    #[serde(default)]
    pub encrypt_connection: bool,
    /// 双向 mTLS 证书与身份校验束（`encrypt_connection == true` 时必填；存在时亦用于 `:21117` 外层 mTLS 中转）。
    #[serde(skip)]
    pub mtls_config: Option<SessionMtlsBundle>,
    /// 可选本人同账号自控票据载荷（随信令 `PunchCoord`/`RelayReady` 下发，配合 `owner_signer` 做 PoP）。
    #[serde(skip)]
    pub owner_grant: Option<OwnerGrantPayload>,
    /// 同账号本人自控 `OwnerTicket` 签名器（存在时向被控端发起免密免审批 PoP 鉴权）。
    #[serde(skip)]
    pub owner_signer: Option<Arc<dyn OwnerTicketSigner>>,
    /// 局域网多播发现命中的同局域网被控端直连地址（三阶路由 Tier 1 `UDP LAN` 优先探测）。
    #[serde(default)]
    pub lan_direct_addr: Option<SocketAddr>,
    /// 可选信令客户端句柄（供运行期 `P2P -> Relay` 降级在初始 60s `relay_token` 过期后向服务端申请新 `RelayReady`）。
    #[serde(skip)]
    pub signal_client: Option<Arc<SignalClientHandle>>,
    /// 可选目标 9 位设备码（配合 `signal_client` 发起运行期 `request_relay`）。
    #[serde(skip)]
    pub target_device_id: Option<String>,
}

impl Default for UiSessionConfig {
    fn default() -> Self {
        Self {
            connect_addr: SocketAddr::from(([127, 0, 0, 1], 9901)),
            password: None,
            watch_only: false,
            width: 0,
            height: 0,
            fps: 60,
            bitrate_bps: 14_000_000,
            prefer_hardware: false,
            clipboard_enabled: true,
            audio_enabled: true,
            relay_grant: None,
            force_relay: false,
            connection_mode: ConnectionMode::Auto,
            tools_only: false,
            encrypt_connection: false,
            mtls_config: None,
            owner_grant: None,
            owner_signer: None,
            lan_direct_addr: None,
            signal_client: None,
            target_device_id: None,
        }
    }
}

impl UiSessionConfig {
    /// 返回切换了 `encrypt_connection` 开关且保留全部其余会话参数的副本（供会话中动态重连切换 mTLS）。
    pub fn with_encrypt_connection(&self, encrypt_connection: bool) -> Self {
        let mut cloned = self.clone();
        cloned.encrypt_connection = encrypt_connection;
        cloned
    }
}

impl fmt::Debug for UiSessionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UiSessionConfig")
            .field("connect_addr", &self.connect_addr)
            .field("has_password", &self.password.is_some())
            .field("watch_only", &self.watch_only)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("fps", &self.fps)
            .field("bitrate_bps", &self.bitrate_bps)
            .field("prefer_hardware", &self.prefer_hardware)
            .field("clipboard_enabled", &self.clipboard_enabled)
            .field("audio_enabled", &self.audio_enabled)
            .field("has_relay_grant", &self.relay_grant.is_some())
            .field("force_relay", &self.force_relay)
            .field("connection_mode", &self.connection_mode)
            .field("tools_only", &self.tools_only)
            .field("encrypt_connection", &self.encrypt_connection)
            .field("has_mtls_config", &self.mtls_config.is_some())
            .field("has_owner_grant", &self.owner_grant.is_some())
            .field("has_owner_signer", &self.owner_signer.is_some())
            .field("lan_direct_addr", &self.lan_direct_addr)
            .field("has_signal_client", &self.signal_client.is_some())
            .field("target_device_id", &self.target_device_id)
            .finish()
    }
}

/// UI → 会话线程的低频控制命令。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionCommand {
    /// 断开会话：发 `Bye(Normal)` 正常关闭，线程随后退出。
    Disconnect,
    /// 手动设置码率（S3 画质子菜单 → `SetBitrate { reason: Manual }`）。
    SetBitrate {
        /// 目标码率（bps）。
        bps: u32,
    },
    /// 画面容器矩形变化（物理像素），转发到 `Renderer::resize`。
    StageRect {
        /// 容器宽度（物理像素）。
        width: u32,
        /// 容器高度（物理像素）。
        height: u32,
    },
    /// 动态开启或暂停剪贴板双向同步。
    SetClipboardEnabled {
        /// `true` = 开启同步，`false` = 暂停同步。
        enabled: bool,
    },
    /// 动态静音或恢复远端音频播放，并通知主机端暂停/恢复音频编码。
    SetAudioMuted {
        /// `true` = 静音，`false` = 恢复播放。
        muted: bool,
    },
    /// 热切换远端视频流分辨率与帧率（经 `TOOL_CHANNEL_DISPLAY_CTRL` 下发被控端）。
    SetStreamParams {
        /// 目标视频宽度（像素；`0` 表示保持当前分辨率）。
        width: u32,
        /// 目标视频高度（像素；`0` 表示保持当前分辨率）。
        height: u32,
        /// 目标帧率（fps；`0` 表示保持当前帧率）。
        fps: u32,
    },
    /// 热切换远端视频流编解码器（`h264` / `hevc`，经 `TOOL_CHANNEL_DISPLAY_CTRL` 下发被控端）。
    SetCodec {
        /// 目标视频编码器。
        codec: StreamCodec,
    },
    /// 请求立即锁定被控端屏幕（经 `TOOL_CHANNEL_DISPLAY_CTRL` 发送）。
    LockRemoteScreen,
    /// 暂停或恢复远端视频媒体流（纯工具模式 / 原地热升级桌面）。
    SetMediaPaused {
        /// `true` = 暂停视频采集与解码，`false` = 恢复或原地热升级视频管线。
        paused: bool,
    },
    /// 立即触发一次快速链路探测（切网 2s 快检看门狗）。
    ProbeNow,
    /// 运行期开关静止画面 Tile 级无损文字锐化补帧（经 `TOOL_CHANNEL_DISPLAY_CTRL` 下发被控端）。
    SetStillRefinementEnabled {
        /// `true` = 开启静止无损增强；`false` = 关闭并立即清空本地叠加层与远端待发队列。
        enabled: bool,
    },
}

/// 连接进度（对齐 T18 计时口径：起点 = Endpoint 创建之前）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectPhase {
    /// 正在创建 QUIC Endpoint（计时起点之后的第一步）。
    EndpointCreating,
    /// QUIC 握手中。
    Connecting,
    /// `Hello` 已发，等待 `Welcome` 裁定。
    AwaitingWelcome,
    /// `Welcome` 已收，等待首帧上屏。
    FirstFramePending,
}

/// 会话线程 → UI 的状态推送（经 Tauri event `session://update` 转发到前端）。
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum SessionUpdate {
    /// 连接进度变更。
    Connecting {
        /// 当前所处连接阶段。
        phase: ConnectPhase,
        /// 是否观看模式（只读不注入输入，U-M7）。
        watch_only: bool,
    },
    /// `Welcome` 裁定参数（S1 屏幕 tab 文案 / HUD 分辨率行以此为准）。
    Negotiated {
        /// 裁定宽度（像素）。
        width: u32,
        /// 裁定高度（像素）。
        height: u32,
        /// 裁定帧率（fps）。
        fps: u32,
        /// 裁定码率（bps）。
        bitrate_bps: u32,
        /// 实际启用的解码 + 呈现后端标签（如 `"videotoolbox+metal"` / `"fake"` / `"fake(降级)"`）。
        backend: String,
        /// 是否观看模式（只读不注入输入，U-M7）。
        watch_only: bool,
        /// 实际传输通道标签（如 `"UDP LAN"` / `"UDP P2P"` / `"TCP Relay"`）。
        transport: String,
        /// 端到端/QUIC mTLS 加密是否已激活。
        mtls_active: bool,
        /// 对端设备证书 SHA-256 指纹（启用 mTLS/E2EE 且握手提取到对端证书时填充）。
        peer_cert_fingerprint: Option<String>,
    },
    /// HUD 快照（会话线程 1s 节流推送；铁律 4：数字在会话侧算好，前端只格式化）。
    Hud(HudSnapshot),
    /// 被控端显示能力与当前生效流参数（首次入流及每次热切换后由被控端权威回传）。
    DisplayConfig {
        /// 当前生效视频宽度（像素）。
        width: u32,
        /// 当前生效视频高度（像素）。
        height: u32,
        /// 当前生效帧率（fps）。
        fps: u32,
        /// 被控端主显示器原生逻辑宽度（像素）。
        native_width: u32,
        /// 被控端主显示器原生逻辑高度（像素）。
        native_height: u32,
        /// 被控端支持的最高帧率（fps）。
        max_fps: u32,
        /// 严格保持原生宽高比、由高到低排列的分辨率预设列表。
        presets: Vec<DisplayPreset>,
        /// 当前生效视频编码器（`"hevc"` / `"h264"`；旧版被控端未上报时为 `None`）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codec: Option<String>,
        /// 被控端声明支持的视频编码器列表（如 `["hevc", "h264"]`）。
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        supported_codecs: Vec<String>,
        /// 当前控制端硬件解码路径是否支持 HEVC。
        #[serde(default)]
        client_supports_hevc: bool,
        /// 针对当前分辨率、帧率与编码器的高刷满帧甜点与 HEVC 建议。
        #[serde(default)]
        advisory: HighRefreshAdvisory,
    },
    /// 被控端推送的当前桌面壁纸缩略图（`data:image/jpeg;base64,...` / `data:image/png;base64,...`）。
    Wallpaper {
        /// 内联 Data URL。
        data_url: String,
    },
    /// 被控端回传当前生效的防窥隐私幕布状态。
    PrivacyState {
        /// 防窥模式（`"off"` | `"privacy"` | `"black"`）。
        mode: String,
        /// 当前预设 ID。
        preset: String,
        /// 被控端是否支持隐私幕布。
        supported: bool,
    },
    /// 被控端回传本机静音运行状态。
    HostMuteState {
        /// 当前是否静音。
        muted: bool,
        /// 被控端是否支持系统静音控制。
        supported: bool,
    },
    /// 被控端回传鼠标光标模式。
    MouseModeState {
        /// 当前生效鼠标模式（`"smart"` | `"remote"` | `"local"`）。
        mode: String,
    },
    /// 被控端回传全部可用显示器列表及当前活动显示器 ID。
    DisplaysState {
        /// 可用物理屏与虚拟屏列表。
        displays: Vec<DisplayDescriptor>,
        /// 当前正在采集的显示器 ID。
        active_display_id: u32,
    },
    /// 虚拟显示器创建或切换失败提示。
    VirtualDisplayError {
        /// 错误原因。
        message: String,
    },
    /// 被控端上报的版本号、架构、更新能力与同账号自控状态。
    HostVersion(crate::updater::RemoteHostVersion),
    /// 远端更新或控制端中转推送的实时进度快照。
    RemoteUpdateStatus(crate::updater::UpdateProgress),
    /// 被控端锁屏与屏幕采集挂起状态变更通知。
    HostScreenState {
        /// 被控端当前是否处于系统锁屏界面。
        locked: bool,
        /// 被控端屏幕采集当前是否处于挂起/待恢复态。
        capture_suspended: bool,
    },
    /// 当收到对端 `ByeReason::SessionSwitching` 时先推送 `SessionSwitching` 通知前端自动短延迟重连。
    SessionSwitching {
        /// 人类可读的切换提示。
        reason: String,
    },
    /// 纯 IP 直连会话在检测到断链后进入自动重连阶段（按重连尝试次数发射，避免 UI 静默卡死）。
    Reconnecting {
        /// 当前正在进行的重连尝试序号（从 1 开始）。
        attempt: u32,
        /// 本轮自动重连允许的最大尝试次数。
        max_attempts: u32,
        /// 人类可读的重连状态说明。
        reason: String,
    },
    /// 当前会话视频媒体流暂停/恢复状态变更通知（控制端切换或被控端 `MediaState` 回执）。
    MediaState {
        /// `true` = 媒体流已暂停（纯工具态），`false` = 媒体流运行中。
        paused: bool,
    },
    /// 媒体流从纯工具态原地热升级或从暂停恢复就绪通知（携带最新后端标签与画面参数）。
    MediaResumed {
        /// 实际生效的解码 + 呈现后端标签（如 `"videotoolbox+metal"` / `"fake"` / `"fake(降级)"`）。
        backend: String,
        /// 当前生效画面宽度（像素）。
        width: u32,
        /// 当前生效画面高度（像素）。
        height: u32,
        /// 当前生效帧率（fps）。
        fps: u32,
    },
    /// 被控端下发的当前会话工具通道权限集合变更通知。
    ToolPermissionsUpdated(#[serde(serialize_with = "serialize_tool_permissions")] ToolPermissions),
    /// 控制端前置拦截或收到被控端回传的工具权限拒绝通知（携带结构化 `tool.forbidden` [`UiError`]）。
    ToolPermissionDenied {
        /// 被拒绝的工具复用子通道号（如 `TOOL_CHANNEL_FILE`）。
        channel: u8,
        /// 结构化用户可读错误模型（错误码为 `tool.forbidden`）。
        ui_error: UiError,
    },
    /// 被控端通告的本人远程终端锁屏校验状态。
    TerminalLockState {
        /// 是否需要完成一次系统密码校验方可使用终端。
        required: bool,
        /// 当前会话终端是否已解锁放行。
        unlocked: bool,
        /// 被控端系统登录用户名（可选）。
        username: Option<String>,
        /// 防爆破冷却剩余秒数。
        retry_after_secs: u32,
    },
    /// 被控端返回的终端系统密码校验结果。
    TerminalUnlockResult {
        /// 校验是否通过。
        ok: bool,
        /// 失败原因。
        error: Option<String>,
        /// 防爆破冷却剩余秒数。
        retry_after_secs: u32,
    },
    /// 会话结束（正常 `Bye` / 对端断开 / 驱动错误 / 线程 panic）。
    Ended {
        /// 人类可读的结束原因。
        reason: String,
        /// 是否属于可由上层自动触发无感重连恢复的意外断网/链路中断终态。
        #[serde(default)]
        recoverable: bool,
        /// 结构化用户可读错误模型（可选，向下兼容旧端 JSON）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ui_error: Option<UiError>,
    },
}

/// 远端桌面会话切换（macOS LoginWindow ↔ Aqua）时约定的提示文案。
pub const SESSION_SWITCHING_REASON: &str = "远端正在切换系统桌面，自动重连中…";

// ─────────────────────────────────────────────────────────────────
// 有界非阻塞队列（铁律 1 UI 侧延伸：命令 64 / 输入 256 / 更新 64）
// ─────────────────────────────────────────────────────────────────

/// 通用有界 drop-oldest 队列（永不阻塞生产端或消费端）。
struct BoundedQueue<T> {
    cap: usize,
    inner: Mutex<VecDeque<T>>,
}

impl<T> BoundedQueue<T> {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    fn push_drop_oldest(&self, item: T) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        while q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(item);
    }

    fn drain_all(&self) -> Vec<T> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.drain(..).collect()
    }

    fn try_pop(&self) -> Option<T> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.pop_front()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// 状态更新专用有界队列：满载时优先丢弃最旧的 `Hud` / `Connecting`，保护 `Negotiated` / `Ended`。
struct BoundedUpdateQueue {
    cap: usize,
    inner: Mutex<VecDeque<SessionUpdate>>,
}

impl BoundedUpdateQueue {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    fn push(&self, item: SessionUpdate) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= self.cap {
            if let Some(pos) = q
                .iter()
                .position(|u| matches!(u, SessionUpdate::Hud(_) | SessionUpdate::Connecting { .. }))
            {
                q.remove(pos);
            } else {
                q.pop_front();
            }
        }
        q.push_back(item);
    }

    fn try_pop(&self) -> Option<SessionUpdate> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.pop_front()
    }
}

/// 判定一条输入事件是否为关键事件（不可轻易因移动事件挤占而丢弃）。
fn is_critical_input(ev: &InputEvent) -> bool {
    !matches!(ev, InputEvent::MouseMove { .. } | InputEvent::Sync)
}

/// 输入专用有界队列（容量 256）：满载丢最旧的非关键事件，优先保留关键事件（U6）。
struct BoundedInputQueue {
    cap: usize,
    inner: Mutex<VecDeque<InputEvent>>,
}

impl BoundedInputQueue {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    fn push(&self, ev: InputEvent) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= self.cap {
            if is_critical_input(&ev) {
                // 关键事件：优先挤掉队列中最旧的非关键事件；若全为关键事件则丢最旧。
                if let Some(pos) = q.iter().position(|e| !is_critical_input(e)) {
                    q.remove(pos);
                } else {
                    q.pop_front();
                }
                q.push_back(ev);
            } else {
                // 非关键事件（MouseMove/Sync）：只淘汰最旧的非关键事件；
                // 若队列已满载关键事件则丢弃本条移动事件，不挤占关键输入。
                if let Some(pos) = q.iter().position(|e| !is_critical_input(e)) {
                    q.remove(pos);
                    q.push_back(ev);
                }
            }
        } else {
            q.push_back(ev);
        }
    }

    fn drain_all(&self) -> Vec<InputEvent> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.drain(..).collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// 由有界输入队列喂给 `ClientSession` 的自定义 `InputCapture`。
struct BridgeInputCapture {
    queue: Arc<BoundedInputQueue>,
    watch_only: Arc<AtomicBool>,
}

impl InputCapture for BridgeInputCapture {
    fn next_events(&mut self, _timeout: Duration) -> rc_types::Result<Vec<InputEvent>> {
        if self.watch_only.load(Ordering::Acquire) {
            let _ = self.queue.drain_all();
            return Ok(Vec::new());
        }
        Ok(self.queue.drain_all())
    }
}

// ─────────────────────────────────────────────────────────────────
// 渲染器与传输层桥接包装（零改动 rc-pipeline / rc-session）
// ─────────────────────────────────────────────────────────────────

/// 共享渲染器句柄（会话线程用于 `StageRect` resize，不改 `ControllerPipeline` API）。
type RendererHandle = Arc<Mutex<Box<dyn Renderer>>>;

/// 保持离屏 `CAMetalLayer` 存活的渲染器租约（纯安全封装，零 `unsafe`）。
///
/// 内部持有底层 [`Renderer`] 的强引用：只要任意 `LayerLease` 存活，底层 `MetalRenderer`
/// 及其 `CAMetalLayer` 就绝不会被释放。跨线程派发到主线程的 `attach_layer` /
/// `sync_layer_frame` / `detach_layer` 闭包持有本租约的 clone，彻底消除主线程闭包与
/// 会话线程退出（含 `Ended` / 窗口销毁 / 并发重连）之间的 use-after-free 竞态。
#[derive(Clone)]
pub struct LayerLease {
    renderer: RendererHandle,
    layer_addr: usize,
}

impl LayerLease {
    /// 由共享渲染器句柄与借用 `CAMetalLayer` 地址构造保活租约；`layer_addr == 0` 返回 `None`。
    pub fn from_renderer(
        renderer: Arc<Mutex<Box<dyn Renderer>>>,
        layer_addr: usize,
    ) -> Option<Self> {
        if layer_addr == 0 {
            None
        } else {
            Some(Self {
                renderer,
                layer_addr,
            })
        }
    }

    /// 返回借用的 `CAMetalLayer` 原始指针（调用方须在持有本租约存活期间于主线程使用）。
    pub fn as_ptr(&self) -> *mut c_void {
        self.layer_addr as *mut c_void
    }

    /// 返回借用地址（仅用于日志/比较，不解引用）。
    pub fn addr(&self) -> usize {
        self.layer_addr
    }

    /// 判断两份租约是否指向同一渲染器实例的同一 `CAMetalLayer`（防地址复用 ABA）。
    pub fn same_layer(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.renderer, &other.renderer) && self.layer_addr == other.layer_addr
    }
}

impl fmt::Debug for LayerLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LayerLease")
            .field("layer_addr", &format_args!("{:#x}", self.layer_addr))
            .finish()
    }
}

/// 管线工厂构建产物。
struct BuiltPipeline {
    pipeline: ControllerPipeline,
    backend_label: String,
    renderer: RendererHandle,
    pending_resize: Arc<AtomicU64>,
    layer_addr: usize,
    is_hardware: bool,
}

fn pack_stage_rect(width: u32, height: u32) -> u64 {
    (u64::from(width) << 32) | u64::from(height)
}

fn unpack_stage_rect(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, (packed & 0xffff_ffff) as u32)
}

fn apply_stage_rect_nonblocking(
    rend: &RendererHandle,
    pending_resize: &AtomicU64,
    width: u32,
    height: u32,
) -> bool {
    match rend.try_lock() {
        Ok(mut guard) => {
            pending_resize.store(0, Ordering::Release);
            let _ = guard.resize((width, height));
            true
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            pending_resize.store(pack_stage_rect(width, height), Ordering::Release);
            false
        }
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            let mut guard = poisoned.into_inner();
            pending_resize.store(0, Ordering::Release);
            let _ = guard.resize((width, height));
            true
        }
    }
}

fn apply_stage_rect_to_slot(
    renderer_handle: &Mutex<Option<RendererHandle>>,
    renderer_pending_resize: &Mutex<Arc<AtomicU64>>,
    width: u32,
    height: u32,
) {
    let rend_opt = renderer_handle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let pending = Arc::clone(
        &renderer_pending_resize
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
    );
    if let Some(rend) = rend_opt {
        apply_stage_rect_nonblocking(&rend, &pending, width, height);
    }
}

/// 共享渲染器包装：让会话线程在不改 `ControllerPipeline` API 的前提下无阻塞响应 `StageRect` resize。
struct SharedRenderer {
    inner: RendererHandle,
    pending_resize: Arc<AtomicU64>,
}

impl Renderer for SharedRenderer {
    fn present(&mut self, frame: rc_decode::DecodedFrame) -> rc_types::Result<rc_types::Timestamp> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let packed = self.pending_resize.swap(0, Ordering::AcqRel);
        if packed != 0 {
            let (w, h) = unpack_stage_rect(packed);
            if w > 0 && h > 0 {
                let _ = guard.resize((w, h));
            }
        }
        guard.present(frame)
    }

    fn resize(&mut self, size: (u32, u32)) -> rc_types::Result<()> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.pending_resize.store(0, Ordering::Release);
        guard.resize(size)
    }

    fn set_vsync(&mut self, on: bool) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_vsync(on);
    }

    fn set_cursor(&mut self, pos: (i32, i32), visible: bool) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_cursor(pos, visible);
    }

    fn apply_still_tile(&mut self, patch: &rc_render::StillTilePatch) -> rc_types::Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .apply_still_tile(patch)
    }

    fn invalidate_still_tiles(&mut self, dirty_rects: &[rc_types::Rect]) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .invalidate_still_tiles(dirty_rects);
    }

    fn clear_still_tiles(&mut self) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear_still_tiles();
    }
}

/// 按平台与硬件偏好构造剪贴板后端：仅 `prefer_hardware == true` 时挂接本机真实系统剪贴板，
/// 离线假后端测试绝不触碰开发者真实剪贴板。
fn create_clipboard_backend(prefer_hardware: bool) -> Option<Box<dyn ClipboardBackend>> {
    if !prefer_hardware {
        return None;
    }
    rc_session::create_system_clipboard().ok()
}

/// 可动态开关的剪贴板后端包装（供 `SessionCommand::SetClipboardEnabled` 运行期切换）。
struct ToggleableClipboardBackend {
    inner: Box<dyn ClipboardBackend>,
    enabled: Arc<AtomicBool>,
    last_count: u64,
}

impl ToggleableClipboardBackend {
    fn new(inner: Box<dyn ClipboardBackend>, enabled: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            enabled,
            last_count: 0,
        }
    }
}

impl ClipboardBackend for ToggleableClipboardBackend {
    fn change_count(&mut self) -> rc_types::Result<u64> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(self.last_count);
        }
        let c = self.inner.change_count()?;
        self.last_count = c;
        Ok(c)
    }

    fn read_text(&mut self) -> rc_types::Result<Option<String>> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(None);
        }
        self.inner.read_text()
    }

    fn write_text(&mut self, text: &str) -> rc_types::Result<()> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(());
        }
        self.inner.write_text(text)
    }
}

/// 包装底层 [`Transport`]（`QuicTransport`、`P2pQuicConnection` 或 `TcpRelayTransport`）：
/// - 在 `poll` 入口响应本地断连标记（H3：握手期即时中止 45s 等待并取消远端审批弹窗，中继态即时切断套接字）；
/// - 在 `poll` 入口排空上层排队的手动控制消息（如 `SetBitrate(Manual)`），
///   无需改动 `rc-session` 状态机或协议。
struct BridgeTransport {
    inner: Box<dyn Transport>,
    pending_control: Arc<Mutex<VecDeque<Vec<u8>>>>,
    disconnect_flag: Arc<AtomicBool>,
    relay_shutdown: Option<RelayShutdownHandle>,
    streaming_started: Arc<AtomicBool>,
}

impl BridgeTransport {
    fn flush_pending_control(&mut self) {
        let msgs: Vec<Vec<u8>> = {
            let mut q = self
                .pending_control
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            q.drain(..).collect()
        };
        for msg in msgs {
            let _ = self.inner.send_reliable(&msg);
        }
    }
}

impl Transport for BridgeTransport {
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
        if self.disconnect_flag.load(Ordering::Acquire)
            && (self.relay_shutdown.is_some() || !self.streaming_started.load(Ordering::Acquire))
        {
            if let Some(ref handle) = self.relay_shutdown {
                handle.shutdown();
            }
            return Ok(vec![NetEvent::Disconnected {
                reason: "用户主动断开".to_string(),
            }]);
        }
        self.flush_pending_control();
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

/// 会话级非文件工具客户端枢纽（W3 远程终端 + W4 TCP 端口映射）。
///
/// W2 文件传输已拆分至独立专用线程 `rc-file-client-worker`（H12），
/// 保证持有 `tools_hub` 锁时绝不执行任何磁盘 I/O（`canonicalize` / `open` / `write_all` / `sync_all`）。
struct ToolClientHub {
    terminal: TerminalClientEngine,
    portmap: PortMapClientEngine,
    host_live_ids: BTreeSet<u32>,
    active_terminals: BTreeSet<u32>,
    attached_terminals: BTreeSet<u32>,
    pending_opens: VecDeque<(u32, bool)>,
    pending_attaches: BTreeSet<u32>,
}

impl ToolClientHub {
    fn new() -> Self {
        Self {
            terminal: TerminalClientEngine::new(),
            portmap: PortMapClientEngine::new(),
            host_live_ids: BTreeSet::new(),
            active_terminals: BTreeSet::new(),
            attached_terminals: BTreeSet::new(),
            pending_opens: VecDeque::new(),
            pending_attaches: BTreeSet::new(),
        }
    }

    fn reset_terminal(&mut self) {
        self.terminal = TerminalClientEngine::new();
        self.host_live_ids.clear();
        self.active_terminals.clear();
        self.attached_terminals.clear();
        self.pending_opens.clear();
        self.pending_attaches.clear();
    }

    fn apply_terminal_event(&mut self, ev: &TerminalEvent) {
        match ev {
            TerminalEvent::SessionList { sessions } => {
                let live_ids: BTreeSet<u32> = sessions.iter().map(|s| s.term_id).collect();
                let live_attached: BTreeSet<u32> = sessions
                    .iter()
                    .filter(|s| s.attached)
                    .map(|s| s.term_id)
                    .collect();
                self.host_live_ids = live_ids.clone();
                self.active_terminals = live_ids;
                self.attached_terminals = live_attached;
                let pending_open_ids: Vec<(u32, bool)> =
                    self.pending_opens.iter().copied().collect();
                for (req_id, want_attach) in pending_open_ids {
                    if req_id != 0 {
                        self.active_terminals.insert(req_id);
                        if want_attach {
                            self.attached_terminals.insert(req_id);
                        }
                    }
                }
                let pending_att_ids: Vec<u32> = self.pending_attaches.iter().copied().collect();
                for tid in pending_att_ids {
                    self.active_terminals.insert(tid);
                    self.attached_terminals.insert(tid);
                }
            }
            TerminalEvent::Opened {
                term_id,
                attached,
                ok: true,
                ..
            } => {
                let want_attach = match self.pending_opens.pop_front() {
                    Some((req_id, want)) => {
                        if req_id != 0 && req_id != *term_id {
                            self.attached_terminals.remove(&req_id);
                            if !self.host_live_ids.contains(&req_id) {
                                self.active_terminals.remove(&req_id);
                            }
                        }
                        want
                    }
                    None => *attached,
                };
                self.host_live_ids.insert(*term_id);
                self.active_terminals.insert(*term_id);
                if *attached && want_attach {
                    self.attached_terminals.insert(*term_id);
                } else {
                    self.attached_terminals.remove(term_id);
                    if *attached && !want_attach {
                        self.terminal.detach(*term_id);
                    }
                }
            }
            TerminalEvent::Opened {
                term_id, ok: false, ..
            } => {
                if let Some((req_id, _)) = self.pending_opens.pop_front() {
                    if req_id != 0 && !self.host_live_ids.contains(&req_id) {
                        self.active_terminals.remove(&req_id);
                        self.attached_terminals.remove(&req_id);
                    }
                }
                if !self.host_live_ids.contains(term_id) {
                    self.active_terminals.remove(term_id);
                    self.attached_terminals.remove(term_id);
                }
            }
            TerminalEvent::Attached {
                term_id, ok: true, ..
            } => {
                self.pending_attaches.remove(term_id);
                self.host_live_ids.insert(*term_id);
                self.active_terminals.insert(*term_id);
                self.attached_terminals.insert(*term_id);
            }
            TerminalEvent::Attached {
                term_id, ok: false, ..
            } => {
                self.pending_attaches.remove(term_id);
                self.host_live_ids.remove(term_id);
                self.active_terminals.remove(term_id);
                self.attached_terminals.remove(term_id);
            }
            TerminalEvent::Exited { term_id, .. } => {
                self.pending_attaches.remove(term_id);
                self.host_live_ids.remove(term_id);
                self.active_terminals.remove(term_id);
                self.attached_terminals.remove(term_id);
            }
            _ => {}
        }
    }
}

/// 轻量条件变量唤醒器，用于 `rc-file-client-worker` 零空转低延迟响应命令、线帧与停机。
#[derive(Clone)]
struct WorkerWake {
    inner: Arc<(Mutex<u64>, Condvar)>,
}

impl WorkerWake {
    fn new() -> Self {
        Self {
            inner: Arc::new((Mutex::new(0), Condvar::new())),
        }
    }

    fn seq(&self) -> u64 {
        *self.inner.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn notify(&self) {
        let mut guard = self.inner.0.lock().unwrap_or_else(|e| e.into_inner());
        *guard = guard.wrapping_add(1);
        self.inner.1.notify_one();
    }

    fn wait_if_unchanged(&self, observed: u64, timeout: Duration) {
        let guard = self.inner.0.lock().unwrap_or_else(|e| e.into_inner());
        if *guard == observed {
            let _ = self.inner.1.wait_timeout(guard, timeout);
        }
    }
}

enum FileWorkerCmd {
    ListRemote {
        path: Option<String>,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    MkdirRemote {
        parent: String,
        name: String,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    DeleteRemote {
        path: String,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    RenameRemote {
        path: String,
        new_name: String,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    StartUpload {
        local_path: String,
        remote_dir: String,
        reply: mpsc::SyncSender<Result<u64, String>>,
    },
    StartDownload {
        remote_path: String,
        local_dir: String,
        reply: mpsc::SyncSender<Result<u64, String>>,
    },
    Cancel {
        id: u64,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    ClearFinished {
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    Remove {
        id: u64,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    Shutdown,
}

#[derive(Clone)]
struct FileClientHandle {
    cmd_tx: mpsc::SyncSender<FileWorkerCmd>,
    cached_transfers: Arc<Mutex<Vec<TransferItem>>>,
    wake: WorkerWake,
}

impl FileClientHandle {
    fn send_cmd<R>(
        &self,
        make_cmd: impl FnOnce(mpsc::SyncSender<Result<R, String>>) -> FileWorkerCmd,
    ) -> Result<R, String> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.cmd_tx
            .send(make_cmd(reply_tx))
            .map_err(|_| "请先建立远控会话".to_string())?;
        self.wake.notify();
        reply_rx
            .recv()
            .map_err(|_| "请先建立远控会话".to_string())?
    }
}

/// 控制端专用文件传输工作线程（H12）：独立拥有 [`FileClientEngine`]，
/// 将本地文件打开/校验、分块读写、落盘 `sync_all()` 与重命名全部移出 60fps 视频/输入线程与 UI IPC 线程。
struct FileClientWorker {
    wire_in_tx: Option<mpsc::SyncSender<Vec<u8>>>,
    wire_out_rx: Option<mpsc::Receiver<Vec<u8>>>,
    cmd_tx: mpsc::SyncSender<FileWorkerCmd>,
    stop: Arc<AtomicBool>,
    abort_reason: Arc<Mutex<Option<String>>>,
    wake: WorkerWake,
    cached_transfers: Arc<Mutex<Vec<TransferItem>>>,
    thread: Option<JoinHandle<()>>,
}

impl FileClientWorker {
    fn spawn(file_events: Arc<BoundedQueue<FileEvent>>) -> (Self, FileClientHandle) {
        let (cmd_tx, cmd_rx) = mpsc::sync_channel::<FileWorkerCmd>(FILE_CLIENT_WORKER_CHAN_CAP);
        let (wire_in_tx, wire_in_rx) = mpsc::sync_channel::<Vec<u8>>(FILE_CLIENT_WORKER_CHAN_CAP);
        let (wire_out_tx, wire_out_rx) = mpsc::sync_channel::<Vec<u8>>(FILE_CLIENT_WORKER_CHAN_CAP);
        let cached_transfers = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let abort_reason: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let wake = WorkerWake::new();

        let t_cached = Arc::clone(&cached_transfers);
        let t_stop = Arc::clone(&stop);
        let t_abort_reason = Arc::clone(&abort_reason);
        let t_wake = wake.clone();

        let handle = thread::Builder::new()
            .name("rc-file-client-worker".to_string())
            .spawn(move || {
                let mut engine = FileClientEngine::new();
                let mut pending_out: VecDeque<Vec<u8>> = VecDeque::new();
                let mut last_upload_progress_at = Instant::now();

                loop {
                    if t_stop.load(Ordering::Acquire) {
                        return;
                    }
                    let wake_seq = t_wake.seq();
                    let mut did_work = false;
                    let mut transfers_dirty = false;

                    // 0) 权限热撤销中止信号优先于一切线帧收发：立即清理 `.rcpart`、释放文件句柄、
                    //    排空残留入站帧、清空出站待发队列并向 UI 推送失败态，杜绝僵尸 Active 任务。
                    if let Some(reason) = t_abort_reason
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .take()
                    {
                        pending_out.clear();
                        while wire_in_rx.try_recv().is_ok() {}
                        for ev in engine.abort_all_active(&reason) {
                            file_events.push_drop_oldest(ev);
                        }
                        *t_cached.lock().unwrap_or_else(|e| e.into_inner()) = engine.transfers();
                        did_work = true;
                    }

                    // 1) 优先排空所有就绪的控制命令（不被下载数据块饿死）。
                    loop {
                        match cmd_rx.try_recv() {
                            Ok(FileWorkerCmd::ListRemote { path, reply }) => {
                                engine.request_list_dir(path);
                                did_work = true;
                                let _ = reply.send(Ok(()));
                            }
                            Ok(FileWorkerCmd::MkdirRemote {
                                parent,
                                name,
                                reply,
                            }) => {
                                engine.request_mkdir(parent, name);
                                did_work = true;
                                let _ = reply.send(Ok(()));
                            }
                            Ok(FileWorkerCmd::DeleteRemote { path, reply }) => {
                                engine.request_delete(path);
                                did_work = true;
                                let _ = reply.send(Ok(()));
                            }
                            Ok(FileWorkerCmd::RenameRemote {
                                path,
                                new_name,
                                reply,
                            }) => {
                                engine.request_rename(path, new_name);
                                did_work = true;
                                let _ = reply.send(Ok(()));
                            }
                            Ok(FileWorkerCmd::StartUpload {
                                local_path,
                                remote_dir,
                                reply,
                            }) => {
                                let res = engine.start_upload(&local_path, &remote_dir);
                                if let Ok(id) = res {
                                    let transfers = engine.transfers();
                                    if let Some(it) = transfers.iter().find(|t| t.id == id).cloned()
                                    {
                                        file_events
                                            .push_drop_oldest(FileEvent::TransferUpdated(it));
                                    }
                                    *t_cached.lock().unwrap_or_else(|e| e.into_inner()) = transfers;
                                    did_work = true;
                                }
                                let _ = reply.send(res);
                            }
                            Ok(FileWorkerCmd::StartDownload {
                                remote_path,
                                local_dir,
                                reply,
                            }) => {
                                let res = engine.start_download(&remote_path, &local_dir);
                                if let Ok(id) = res {
                                    let transfers = engine.transfers();
                                    if let Some(it) = transfers.iter().find(|t| t.id == id).cloned()
                                    {
                                        file_events
                                            .push_drop_oldest(FileEvent::TransferUpdated(it));
                                    }
                                    *t_cached.lock().unwrap_or_else(|e| e.into_inner()) = transfers;
                                    did_work = true;
                                }
                                let _ = reply.send(res);
                            }
                            Ok(FileWorkerCmd::Cancel { id, reply }) => {
                                engine.cancel_transfer(id);
                                let transfers = engine.transfers();
                                if let Some(it) = transfers.iter().find(|t| t.id == id).cloned() {
                                    file_events.push_drop_oldest(FileEvent::TransferUpdated(it));
                                }
                                *t_cached.lock().unwrap_or_else(|e| e.into_inner()) = transfers;
                                did_work = true;
                                let _ = reply.send(Ok(()));
                            }
                            Ok(FileWorkerCmd::ClearFinished { reply }) => {
                                engine.clear_finished();
                                *t_cached.lock().unwrap_or_else(|e| e.into_inner()) =
                                    engine.transfers();
                                did_work = true;
                                let _ = reply.send(Ok(()));
                            }
                            Ok(FileWorkerCmd::Remove { id, reply }) => {
                                engine.remove_transfer(id);
                                *t_cached.lock().unwrap_or_else(|e| e.into_inner()) =
                                    engine.transfers();
                                did_work = true;
                                let _ = reply.send(Ok(()));
                            }
                            Ok(FileWorkerCmd::Shutdown) => return,
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => return,
                        }
                    }

                    // 2) 每轮最多处理 MAX_TOOL_FRAMES_PER_TICK 条入站线帧。
                    for _ in 0..MAX_TOOL_FRAMES_PER_TICK {
                        match wire_in_rx.try_recv() {
                            Ok(payload) => {
                                for ev in engine.handle_incoming(&payload) {
                                    file_events.push_drop_oldest(ev);
                                }
                                did_work = true;
                                transfers_dirty = true;
                            }
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => return,
                        }
                    }

                    // 3) 待发送缓冲为空时从引擎拉取一批出站线帧，并收集本地事件与上传进度。
                    if pending_out.is_empty() {
                        let frames = engine.poll_outgoing(MAX_TOOL_FRAMES_PER_TICK);
                        let local_evs = engine.drain_local_events();
                        if !local_evs.is_empty() {
                            for ev in local_evs {
                                file_events.push_drop_oldest(ev);
                            }
                            transfers_dirty = true;
                            did_work = true;
                        }
                        if !frames.is_empty() {
                            pending_out.extend(frames);
                            did_work = true;
                            transfers_dirty = true;
                            if last_upload_progress_at.elapsed() >= UPLOAD_PROGRESS_EMIT_INTERVAL {
                                last_upload_progress_at = Instant::now();
                                for item in engine.transfers() {
                                    if item.direction == TransferDirection::Upload
                                        && item.status == TransferStatus::Active
                                    {
                                        file_events
                                            .push_drop_oldest(FileEvent::TransferUpdated(item));
                                    }
                                }
                            }
                        }
                    }

                    if transfers_dirty {
                        *t_cached.lock().unwrap_or_else(|e| e.into_inner()) = engine.transfers();
                    }

                    // 4) 非阻塞冲刷出站线帧到有界通道。
                    let mut out_full = false;
                    while let Some(front) = pending_out.front() {
                        match wire_out_tx.try_send(front.clone()) {
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

                    // 5) 输出满载或空闲时条件变量泊车，零空转且可被命令/线帧/排空/停机即时唤醒。
                    if out_full {
                        t_wake.wait_if_unchanged(wake_seq, Duration::from_millis(2));
                    } else if !did_work && pending_out.is_empty() {
                        t_wake.wait_if_unchanged(wake_seq, Duration::from_millis(20));
                    }
                }
            })
            .expect("spawn rc-file-client-worker thread");

        let client_handle = FileClientHandle {
            cmd_tx: cmd_tx.clone(),
            cached_transfers: Arc::clone(&cached_transfers),
            wake: wake.clone(),
        };
        let worker = Self {
            wire_in_tx: Some(wire_in_tx),
            wire_out_rx: Some(wire_out_rx),
            cmd_tx,
            stop,
            abort_reason,
            wake,
            cached_transfers,
            thread: Some(handle),
        };
        (worker, client_handle)
    }

    /// 立即中止所有在途上传/下载任务、清理 `.rcpart` 并丢弃已排队的出站线帧（非阻塞，不受命令队列背压影响）。
    fn abort_all_active(&self, reason: impl Into<String>) {
        *self.abort_reason.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason.into());
        if let Some(rx) = self.wire_out_rx.as_ref() {
            while rx.try_recv().is_ok() {}
        }
        self.wake.notify();
    }

    fn try_send_incoming(&self, frame: Vec<u8>) -> Result<(), mpsc::TrySendError<Vec<u8>>> {
        let Some(tx) = self.wire_in_tx.as_ref() else {
            return Err(mpsc::TrySendError::Disconnected(frame));
        };
        let res = tx.try_send(frame);
        if res.is_ok() {
            self.wake.notify();
        }
        res
    }

    fn try_recv_outgoing(&self, max_frames: usize) -> Vec<Vec<u8>> {
        let Some(rx) = self.wire_out_rx.as_ref() else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(max_frames.min(MAX_TOOL_FRAMES_PER_TICK));
        for _ in 0..max_frames {
            match rx.try_recv() {
                Ok(frame) => out.push(frame),
                Err(_) => break,
            }
        }
        if !out.is_empty() {
            self.wake.notify();
        }
        out
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.wire_in_tx.take();
        self.wire_out_rx.take();
        let _ = self.cmd_tx.try_send(FileWorkerCmd::Shutdown);
        self.wake.notify();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        self.cached_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

impl Drop for FileClientWorker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 线程安全的控制端工具调用句柄（供 Tauri IPC 命令直接调用，不在 `AppState::session` 锁内阻塞）。
#[derive(Clone)]
pub struct ToolClientHandle {
    hub: Arc<Mutex<ToolClientHub>>,
    file: FileClientHandle,
    portmap_latest: Arc<Mutex<Option<Vec<PortMapRuleSnapshot>>>>,
    running: Arc<AtomicBool>,
    tool_permissions: Arc<Mutex<ToolPermissions>>,
    update_tx: Arc<BoundedUpdateQueue>,
}

impl ToolClientHandle {
    fn ensure_running(&self) -> Result<(), String> {
        if self.running.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err("请先建立远控会话".to_string())
        }
    }

    fn ensure_tool_allowed(&self, channel: u8) -> Result<(), String> {
        let perms = *self
            .tool_permissions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if perms.allows_channel(channel) {
            Ok(())
        } else {
            Err(self.emit_tool_forbidden(channel))
        }
    }

    fn emit_tool_forbidden(&self, channel: u8) -> String {
        let ui_error = crate::ui_error::tool_forbidden_ui_error(
            channel,
            crate::ui_error::current_platform(),
            None,
        );
        let msg = ui_error.message.clone();
        self.update_tx
            .push(SessionUpdate::ToolPermissionDenied { channel, ui_error });
        msg
    }

    /// 原子持锁后校验通道权限，严格遵循 `tools_hub -> tool_permissions -> portmap_latest` 全局锁序，
    /// 消除授权撤销（如 `ToolPermissionsState`）与 `ToolClientHandle` 并发操作的 TOCTOU 竞态。
    fn lock_hub_for_channel(
        &self,
        channel: u8,
    ) -> Result<std::sync::MutexGuard<'_, ToolClientHub>, String> {
        let hub = self.hub.lock().unwrap_or_else(|e| e.into_inner());
        let perms = *self
            .tool_permissions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if perms.allows_channel(channel) {
            Ok(hub)
        } else {
            drop(hub);
            Err(self.emit_tool_forbidden(channel))
        }
    }

    /// 请求列举远端目录（结果通过 `file://event` 推送，在专用文件工作线程执行）。
    pub fn file_list_remote(&self, path: Option<String>) -> Result<(), String> {
        self.ensure_running()?;
        self.ensure_tool_allowed(TOOL_CHANNEL_FILE)?;
        self.file
            .send_cmd(|reply| FileWorkerCmd::ListRemote { path, reply })
    }

    /// 请求在远端创建目录（结果通过 `file://event` 推送，在专用文件工作线程执行）。
    pub fn file_mkdir_remote(&self, parent: String, name: String) -> Result<(), String> {
        self.ensure_running()?;
        self.ensure_tool_allowed(TOOL_CHANNEL_FILE)?;
        self.file.send_cmd(|reply| FileWorkerCmd::MkdirRemote {
            parent,
            name,
            reply,
        })
    }

    /// 请求删除远端文件或目录（结果通过 `file://event` 推送）。
    pub fn file_delete_remote(&self, path: String) -> Result<(), String> {
        self.ensure_running()?;
        self.ensure_tool_allowed(TOOL_CHANNEL_FILE)?;
        self.file
            .send_cmd(|reply| FileWorkerCmd::DeleteRemote { path, reply })
    }

    /// 请求重命名远端文件或目录（结果通过 `file://event` 推送）。
    pub fn file_rename_remote(&self, path: String, new_name: String) -> Result<(), String> {
        self.ensure_running()?;
        self.ensure_tool_allowed(TOOL_CHANNEL_FILE)?;
        self.file.send_cmd(|reply| FileWorkerCmd::RenameRemote {
            path,
            new_name,
            reply,
        })
    }

    /// 发起本地文件上传到远端目录，返回传输任务 ID（磁盘 I/O 在专用文件工作线程执行，不触碰 `tools_hub` 锁）。
    pub fn file_upload(&self, local_path: &str, remote_dir: &str) -> Result<u64, String> {
        self.ensure_running()?;
        self.ensure_tool_allowed(TOOL_CHANNEL_FILE)?;
        let local_path = local_path.to_string();
        let remote_dir = remote_dir.to_string();
        self.file.send_cmd(|reply| FileWorkerCmd::StartUpload {
            local_path,
            remote_dir,
            reply,
        })
    }

    /// 发起远端文件下载到本地目录，返回传输任务 ID（磁盘 I/O 在专用文件工作线程执行，不触碰 `tools_hub` 锁）。
    pub fn file_download(&self, remote_path: &str, local_dir: &str) -> Result<u64, String> {
        self.ensure_running()?;
        self.ensure_tool_allowed(TOOL_CHANNEL_FILE)?;
        let remote_path = remote_path.to_string();
        let local_dir = local_dir.to_string();
        self.file.send_cmd(|reply| FileWorkerCmd::StartDownload {
            remote_path,
            local_dir,
            reply,
        })
    }

    /// 取消进行中的传输任务。
    pub fn file_cancel(&self, id: u64) -> Result<(), String> {
        self.ensure_running()?;
        self.file
            .send_cmd(|reply| FileWorkerCmd::Cancel { id, reply })
    }

    /// 返回当前全部文件传输任务快照（读取轻量缓存副本，永不阻塞文件磁盘 I/O 或视频线程）。
    pub fn file_list_transfers(&self) -> Vec<TransferItem> {
        if !self.running.load(Ordering::Acquire) {
            return Vec::new();
        }
        self.file
            .cached_transfers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 清除已终态的传输任务记录。
    pub fn file_clear_finished(&self) -> Result<(), String> {
        self.ensure_running()?;
        self.file
            .send_cmd(|reply| FileWorkerCmd::ClearFinished { reply })
    }

    /// 移除指定传输任务记录（若仍活跃会先取消）。
    pub fn file_remove_transfer(&self, id: u64) -> Result<(), String> {
        self.ensure_running()?;
        self.file
            .send_cmd(|reply| FileWorkerCmd::Remove { id, reply })
    }

    /// 请求远端开启一个新的 PTY 终端会话（默认立即附着输出流），返回分配的 `term_id`。
    pub fn terminal_open(&self, cols: u16, rows: u16) -> Result<u32, String> {
        self.terminal_open_with_options(cols, rows, None, true)
    }

    /// 请求远端开启新的 PTY 终端会话（支持自定义名称与后台不附着模式）。
    pub fn terminal_open_with_options(
        &self,
        cols: u16,
        rows: u16,
        name: Option<String>,
        attach: bool,
    ) -> Result<u32, String> {
        if cols == 0 || rows == 0 || cols > MAX_TERMINAL_DIM || rows > MAX_TERMINAL_DIM {
            return Err("终端行列数必须在 1–512 之间".to_string());
        }
        let valid_name = match name {
            Some(raw) if !raw.trim().is_empty() => Some(validate_terminal_name(&raw)?),
            Some(_) => return Err("会话名称不能为空".to_string()),
            None => None,
        };
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        if !hub.terminal.can_enqueue() {
            return Err("终端控制队列繁忙，请稍后重试".to_string());
        }
        if attach {
            let term_id = hub.terminal.open_with_options(cols, rows, valid_name, true);
            hub.active_terminals.insert(term_id);
            hub.attached_terminals.insert(term_id);
            hub.pending_opens.push_back((term_id, true));
            Ok(term_id)
        } else {
            hub.terminal.open_background(cols, rows, valid_name);
            hub.pending_opens.push_back((0, false));
            Ok(0)
        }
    }

    /// 请求远端主机返回当前后台托管的活跃终端会话列表。
    pub fn terminal_list(&self) -> Result<(), String> {
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        if !hub.terminal.can_enqueue() {
            return Err("终端控制队列繁忙，请稍后重试".to_string());
        }
        hub.terminal.list();
        Ok(())
    }

    /// 请求附着至远端指定后台 PTY 终端（回放历史缓冲并开启实时输出流）。
    pub fn terminal_attach(&self, term_id: u32, cols: u16, rows: u16) -> Result<(), String> {
        if cols == 0 || rows == 0 || cols > MAX_TERMINAL_DIM || rows > MAX_TERMINAL_DIM {
            return Err("终端行列数必须在 1–512 之间".to_string());
        }
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        if !hub.terminal.can_enqueue() {
            return Err("终端控制队列繁忙，请稍后重试".to_string());
        }
        hub.active_terminals.insert(term_id);
        hub.attached_terminals.insert(term_id);
        hub.pending_attaches.insert(term_id);
        hub.terminal.attach(term_id, cols, rows);
        Ok(())
    }

    /// 请求脱离远端指定 PTY 终端视图（仅停止实时输出流，保留后台 PTY 继续运行）。
    pub fn terminal_detach(&self, term_id: u32) -> Result<(), String> {
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        hub.attached_terminals.remove(&term_id);
        hub.pending_attaches.remove(&term_id);
        for (req_id, want_attach) in &mut hub.pending_opens {
            if *req_id == term_id {
                *want_attach = false;
            }
        }
        hub.terminal.detach(term_id);
        Ok(())
    }

    /// 请求重命名远端指定 PTY 终端会话。
    pub fn terminal_rename(&self, term_id: u32, name: &str) -> Result<(), String> {
        let valid_name = validate_terminal_name(name)?;
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        if !hub.terminal.can_enqueue() {
            return Err("终端控制队列繁忙，请稍后重试".to_string());
        }
        hub.terminal.rename(term_id, valid_name);
        Ok(())
    }

    /// 请求被控端枚举其系统已安装字体列表（结果通过 `terminal://event` 的 `fontList` 推送）。
    pub fn terminal_list_remote_fonts(&self) -> Result<(), String> {
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        if !hub.terminal.can_enqueue() {
            return Err("终端控制队列繁忙，请稍后重试".to_string());
        }
        hub.terminal.request_list_fonts();
        Ok(())
    }

    /// 请求从被控端拉取指定 `font_id` 的字体字节流（完成后通过 `fontReady` 事件通知）。
    pub fn terminal_fetch_remote_font(&self, font_id: String) -> Result<u32, String> {
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        if !hub.terminal.can_enqueue() {
            return Err("终端控制队列繁忙，请稍后重试".to_string());
        }
        hub.terminal.request_fetch_font(font_id)
    }

    /// 读取已缓存到本地会话中的远程字体二进制数据。
    pub fn terminal_get_cached_remote_font(&self, font_id: &str) -> Result<Vec<u8>, String> {
        self.ensure_running()?;
        let hub = self.hub.lock().unwrap_or_else(|e| e.into_inner());
        hub.terminal
            .get_cached_font(font_id)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| "远程字体尚未下载完成或已被淘汰".to_string())
    }

    /// 查询指定 `term_id` 是否仍属于当前会话的活跃终端。
    pub fn has_active_terminal(&self, term_id: u32) -> bool {
        if !self.running.load(Ordering::Acquire) {
            return false;
        }
        self.hub
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_terminals
            .contains(&term_id)
    }

    /// 向远端指定 PTY 终端发送键盘/粘贴输入字节。
    pub fn terminal_input(&self, term_id: u32, data: &[u8]) -> Result<(), String> {
        if data.len() > MAX_TERMINAL_INPUT_BYTES {
            return Err("单次终端输入不能超过 64 KiB".to_string());
        }
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        if !hub.active_terminals.contains(&term_id) {
            return Err("目标终端会话不存在或已关闭".to_string());
        }
        let needed_frames = data.len().div_ceil(rc_tools::TERMINAL_DATA_CHUNK_SIZE);
        if needed_frames > 0 && hub.terminal.available_outgoing_slots() < needed_frames {
            return Err("终端输入队列繁忙，请稍后重试".to_string());
        }
        hub.terminal.send_input(term_id, data);
        Ok(())
    }

    /// 同步调整远端指定 PTY 终端的行列尺寸。
    pub fn terminal_resize(&self, term_id: u32, cols: u16, rows: u16) -> Result<(), String> {
        if cols == 0 || rows == 0 || cols > MAX_TERMINAL_DIM || rows > MAX_TERMINAL_DIM {
            return Err("终端行列数必须在 1–512 之间".to_string());
        }
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        hub.terminal.resize(term_id, cols, rows);
        Ok(())
    }

    /// 请求关闭并终止远端指定 PTY 终端会话。
    pub fn terminal_close(&self, term_id: u32) -> Result<(), String> {
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_TERMINAL)?;
        if !hub.terminal.can_enqueue() {
            return Err("终端控制队列繁忙，请稍后重试".to_string());
        }
        hub.host_live_ids.remove(&term_id);
        hub.active_terminals.remove(&term_id);
        hub.attached_terminals.remove(&term_id);
        hub.pending_attaches.remove(&term_id);
        hub.terminal.close(term_id);
        Ok(())
    }

    /// 返回当前仍处于开启状态的全部远端终端 ID 快照（升序）。
    pub fn active_terminal_ids(&self) -> Vec<u32> {
        self.hub
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_terminals
            .iter()
            .copied()
            .collect()
    }

    /// 脱离当前已附着的所有终端视图（不终止主机侧后台 PTY），并返回已脱离的 `term_id` 列表。
    pub fn detach_all_terminals(&self) -> Vec<u32> {
        let mut hub = self.hub.lock().unwrap_or_else(|e| e.into_inner());
        hub.pending_attaches.clear();
        for (_, want_attach) in &mut hub.pending_opens {
            *want_attach = false;
        }
        let ids: Vec<u32> = std::mem::take(&mut hub.attached_terminals)
            .into_iter()
            .collect();
        if self.running.load(Ordering::Acquire) {
            for &id in &ids {
                hub.terminal.detach(id);
            }
        }
        ids
    }

    /// 关闭当前全部活跃的远端 PTY 终端会话，并返回被关闭的 `term_id` 列表。
    pub fn close_all_terminals(&self) -> Vec<u32> {
        let mut hub = self.hub.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<u32> = std::mem::take(&mut hub.active_terminals)
            .into_iter()
            .collect();
        hub.host_live_ids.clear();
        hub.attached_terminals.clear();
        hub.pending_attaches.clear();
        hub.pending_opens.clear();
        if self.running.load(Ordering::Acquire) {
            for &id in &ids {
                hub.terminal.close(id);
            }
        }
        ids
    }

    /// 列出全部 TCP 端口映射规则快照。
    pub fn portmap_list(&self) -> Vec<PortMapRuleSnapshot> {
        if !self.running.load(Ordering::Acquire) {
            return Vec::new();
        }
        self.hub
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .portmap
            .list_rules()
    }

    /// 添加一条 TCP 端口映射规则，返回新规则与最新完整规则列表（`hub -> portmap_latest` 严格串行化）。
    pub fn portmap_add(
        &self,
        name: String,
        local_port: u16,
        target_addr: String,
        target_port: u16,
    ) -> Result<(PortMapRuleSnapshot, Vec<PortMapRuleSnapshot>), String> {
        self.portmap_add_with_enabled(name, local_port, target_addr, target_port, true)
    }

    /// 添加一条 TCP 端口映射规则并指定初始启用状态（供禁用规则恢复免短暂绑定端口使用）。
    pub fn portmap_add_with_enabled(
        &self,
        name: String,
        local_port: u16,
        target_addr: String,
        target_port: u16,
        enabled: bool,
    ) -> Result<(PortMapRuleSnapshot, Vec<PortMapRuleSnapshot>), String> {
        let name = name.trim().to_string();
        let target_addr = target_addr.trim().to_string();
        crate::model::validate_map_name(&name)?;
        if local_port == 0 || target_port == 0 {
            return Err("端口不能为 0，范围必须为 1–65535".to_string());
        }
        crate::model::validate_target_addr(&target_addr)?;
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_PORTMAP)?;
        let rule = hub.portmap.add_rule_with_enabled(
            name,
            local_port,
            target_addr,
            target_port,
            enabled,
        )?;
        let all = hub.portmap.list_rules();
        *self
            .portmap_latest
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(all.clone());
        Ok((rule, all))
    }

    /// 启用或暂停指定 TCP 端口映射规则，返回更新后的规则与最新完整规则列表（`hub -> portmap_latest` 严格串行化）。
    pub fn portmap_toggle(
        &self,
        id: u64,
        enabled: bool,
    ) -> Result<(PortMapRuleSnapshot, Vec<PortMapRuleSnapshot>), String> {
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_PORTMAP)?;
        let rule = hub.portmap.set_rule_enabled(id, enabled)?;
        let all = hub.portmap.list_rules();
        *self
            .portmap_latest
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(all.clone());
        Ok((rule, all))
    }

    /// 删除指定 TCP 端口映射规则，返回最新完整规则列表（`hub -> portmap_latest` 严格串行化）。
    pub fn portmap_delete(&self, id: u64) -> Result<Vec<PortMapRuleSnapshot>, String> {
        self.ensure_running()?;
        let mut hub = self.lock_hub_for_channel(TOOL_CHANNEL_PORTMAP)?;
        hub.portmap.delete_rule(id)?;
        let all = hub.portmap.list_rules();
        *self
            .portmap_latest
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(all.clone());
        Ok(all)
    }
}

/// 按收到音频包的 `(sample_rate, channels)` 校验/重建播放器（M9）：
/// 若格式与当前播放器不同，先调用旧播放器 `stop()` 再按新格式重建并同步静音态。
fn ensure_audio_player_for_format(
    audio_player: &mut Option<Box<dyn AudioPlayer>>,
    audio_player_format: &mut Option<(u32, u8)>,
    sample_rate: u32,
    channels: u8,
    audio_muted: bool,
    make_player: impl FnOnce(u32, u8) -> Box<dyn AudioPlayer>,
) {
    let target_format = (sample_rate, channels);
    if *audio_player_format != Some(target_format) {
        if let Some(mut old_player) = audio_player.take() {
            old_player.stop();
        }
        let mut player = make_player(sample_rate, channels);
        player.set_muted(audio_muted);
        *audio_player = Some(player);
        *audio_player_format = Some(target_format);
    }
}

/// 将收到的音频帧包解码为线性 PCM16 采样；不支持的编码或非法包返回 `None`。
fn decode_audio_packet_samples(pkt: &AudioFramePacket) -> Option<Vec<i16>> {
    match pkt.codec {
        AUDIO_CODEC_IMA_ADPCM => decode_ima_adpcm(&pkt.data, pkt.channels).ok(),
        AUDIO_CODEC_PCM16 => {
            if pkt.data.len() % 2 != 0 {
                return None;
            }
            let mut samples = Vec::with_capacity(pkt.data.len() / 2);
            for chunk in pkt.data.chunks_exact(2) {
                samples.push(i16::from_le_bytes([chunk[0], chunk[1]]));
            }
            Some(samples)
        }
        _ => None,
    }
}

/// 构造音频控制 JSON 载荷（`{"muted": bool}`）。
fn encode_audio_ctrl_muted(muted: bool) -> Vec<u8> {
    serde_json::json!({ "muted": muted })
        .to_string()
        .into_bytes()
}

/// 冲刷单个工具通道的待发送队列：遇到瞬态背压 `Err` 时停止并保留队首，
/// 遇到不可恢复的配置/超限错误（`is_fatal_err` 返回 `true`）时丢弃该非法帧以免永久阻塞后续可靠控制消息；
/// `zeroize_popped` 为 `true` 时在出队后擦除敏感帧缓冲（用于携带 `TerminalUnlockRequest` 的显示控制队列）。
fn flush_pending_tool_queue_checked<E>(
    pending: &mut VecDeque<Vec<u8>>,
    mut send_fn: impl FnMut(Vec<u8>) -> Result<(), E>,
    is_fatal_err: impl Fn(&E) -> bool,
) -> bool {
    flush_pending_tool_queue_impl(pending, false, &mut send_fn, &is_fatal_err)
}

struct ZeroizingByteQueue(VecDeque<Vec<u8>>);

impl ZeroizingByteQueue {
    fn new() -> Self {
        Self(VecDeque::new())
    }
}

impl std::ops::Deref for ZeroizingByteQueue {
    type Target = VecDeque<Vec<u8>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ZeroizingByteQueue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ZeroizingByteQueue {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for mut item in self.0.drain(..) {
            item.zeroize();
        }
    }
}

fn flush_pending_display_tx_checked<E>(
    pending: &mut VecDeque<Vec<u8>>,
    mut send_fn: impl FnMut(Vec<u8>) -> Result<(), E>,
    is_fatal_err: impl Fn(&E) -> bool,
) -> bool {
    flush_pending_tool_queue_impl(pending, true, &mut send_fn, &is_fatal_err)
}

fn flush_pending_tool_queue_impl<E>(
    pending: &mut VecDeque<Vec<u8>>,
    zeroize_popped: bool,
    send_fn: &mut impl FnMut(Vec<u8>) -> Result<(), E>,
    is_fatal_err: &impl Fn(&E) -> bool,
) -> bool {
    use zeroize::Zeroize;

    let mut sent_any = false;
    while let Some(front) = pending.front() {
        let copy = front.clone();
        match send_fn(copy) {
            Ok(()) => {
                if let Some(mut popped) = pending.pop_front() {
                    if zeroize_popped {
                        popped.zeroize();
                    }
                }
                sent_any = true;
            }
            Err(ref e) if is_fatal_err(e) => {
                if let Some(mut popped) = pending.pop_front() {
                    if zeroize_popped {
                        popped.zeroize();
                    }
                }
            }
            Err(_) => break,
        }
    }
    sent_any
}

/// 冲刷单个工具通道的待发送队列：遇到发送 `Err`（如 TCP 中继背压）时立即停止并保留队首，
/// 下一拍严格按 FIFO 顺序重试，绝不丢弃任何可靠工具帧。
fn flush_pending_tool_queue<E>(
    pending: &mut VecDeque<Vec<u8>>,
    send_fn: impl FnMut(Vec<u8>) -> Result<(), E>,
) -> bool {
    flush_pending_tool_queue_checked(pending, send_fn, |_| false)
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
// SessionHandle（公开 API）
// ─────────────────────────────────────────────────────────────────

/// UI 侧会话句柄：持有有界通道与后台会话线程。
///
/// 通道容量（铁律 1 UI 侧延伸 / U6）：
/// - 命令通道 [`COMMAND_CHANNEL_CAP`] = 64，满载丢最旧；
/// - 输入通道 [`INPUT_CHANNEL_CAP`] = 256，满载优先保留关键事件、丢最旧移动事件；
/// - 更新通道 [`UPDATE_CHANNEL_CAP`] = 64，满载优先丢最旧 `Hud`/`Connecting`。
///
/// 调用 [`SessionHandle::join`] 或直接 `Drop` 均会发送 `Disconnect` 并等待线程干净退出，
/// 绝不遗留僵尸线程（U10）。
pub struct SessionHandle {
    cmd_tx: Arc<BoundedQueue<SessionCommand>>,
    display_ctrl_tx: Arc<BoundedQueue<DisplayControlMsg>>,
    input_tx: Arc<BoundedInputQueue>,
    update_rx: Arc<BoundedUpdateQueue>,
    file_event_rx: Arc<BoundedQueue<FileEvent>>,
    terminal_event_rx: Arc<BoundedQueue<TerminalEvent>>,
    portmap_latest: Arc<Mutex<Option<Vec<PortMapRuleSnapshot>>>>,
    tools_hub: Arc<Mutex<ToolClientHub>>,
    file_handle: FileClientHandle,
    disconnect_flag: Arc<AtomicBool>,
    lock_on_disconnect: Arc<AtomicBool>,
    relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    running: Arc<AtomicBool>,
    watch_only: Arc<AtomicBool>,
    tool_permissions: Arc<Mutex<ToolPermissions>>,
    still_refine_metrics: Arc<Mutex<crate::still_refine::StillRefineMetrics>>,
    encrypt_connection: bool,
    base_config: UiSessionConfig,
    layer_lease: Arc<Mutex<Option<LayerLease>>>,
    upgrade_surface: Arc<Mutex<Option<PreallocatedRenderSurface>>>,
    thread: Option<JoinHandle<()>>,
}

impl SessionHandle {
    /// 启动会话线程（构造 `ClientSession` → 握手 → 驱动循环 → `Ended` 后自然退出）。
    ///
    /// 返回的句柄立即可用；连接进度与 HUD 更新经 [`Self::try_recv_update`] 非阻塞拉取。
    pub fn spawn(cfg: UiSessionConfig) -> Self {
        Self::spawn_with_surface(cfg, None)
    }

    /// 启动会话线程并可选传入平台主线程预分配的渲染表面（例如 macOS `CAMetalLayer`）。
    pub fn spawn_with_surface(
        cfg: UiSessionConfig,
        preallocated_surface: Option<PreallocatedRenderSurface>,
    ) -> Self {
        let cmd_tx = Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP));
        let display_ctrl_tx = Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP));
        let input_tx = Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP));
        let update_rx = Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP));
        let file_event_rx = Arc::new(BoundedQueue::new(FILE_EVENT_CHANNEL_CAP));
        let terminal_event_rx = Arc::new(BoundedQueue::new(TERMINAL_EVENT_CHANNEL_CAP));
        let portmap_latest: Arc<Mutex<Option<Vec<PortMapRuleSnapshot>>>> =
            Arc::new(Mutex::new(None));
        let tools_hub = Arc::new(Mutex::new(ToolClientHub::new()));
        let (file_worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_event_rx));
        let disconnect_flag = Arc::new(AtomicBool::new(false));
        let lock_on_disconnect = Arc::new(AtomicBool::new(false));
        let relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>> = Arc::new(Mutex::new(None));
        let running = Arc::new(AtomicBool::new(true));
        let layer_lease = Arc::new(Mutex::new(None));
        let upgrade_surface = Arc::new(Mutex::new(preallocated_surface));
        let watch_only = Arc::new(AtomicBool::new(cfg.watch_only));
        let tool_permissions = Arc::new(Mutex::new(ToolPermissions::all_allowed()));
        let still_refine_metrics = Arc::new(Mutex::new(
            crate::still_refine::StillRefineMetrics::default(),
        ));
        let encrypt_connection = cfg.encrypt_connection;
        let base_config = cfg.clone();

        let t_cmd = Arc::clone(&cmd_tx);
        let t_display_ctrl = Arc::clone(&display_ctrl_tx);
        let t_input = Arc::clone(&input_tx);
        let t_update = Arc::clone(&update_rx);
        let t_terminal_events = Arc::clone(&terminal_event_rx);
        let t_portmap_latest = Arc::clone(&portmap_latest);
        let t_tools_hub = Arc::clone(&tools_hub);
        let t_disconnect = Arc::clone(&disconnect_flag);
        let t_lock_on_disconnect = Arc::clone(&lock_on_disconnect);
        let t_relay_interrupt = Arc::clone(&relay_interrupt);
        let t_running = Arc::clone(&running);
        let t_watch_only = Arc::clone(&watch_only);
        let t_tool_permissions = Arc::clone(&tool_permissions);
        let t_still_refine_metrics = Arc::clone(&still_refine_metrics);
        let t_layer = Arc::clone(&layer_lease);
        let t_upgrade_surface = Arc::clone(&upgrade_surface);

        let handle = thread::Builder::new()
            .name("rc-ui-session".to_string())
            .spawn(move || {
                crate::platform::promote_current_thread_qos();

                let mut file_worker = file_worker;
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_session_thread(
                        cfg,
                        t_upgrade_surface,
                        t_cmd,
                        t_display_ctrl,
                        t_input,
                        Arc::clone(&t_update),
                        t_layer,
                        t_disconnect,
                        t_lock_on_disconnect,
                        t_relay_interrupt,
                        Arc::clone(&t_tools_hub),
                        &file_worker,
                        Arc::clone(&t_terminal_events),
                        t_portmap_latest,
                        t_watch_only,
                        t_tool_permissions,
                        t_still_refine_metrics,
                    )
                }));
                let end = match res {
                    Ok(Ok(e)) | Ok(Err(e)) => e,
                    Err(_) => SessionEnd::fatal("会话线程异常退出"),
                };
                // 先标记非运行并回收专用文件工作线程（确保 `.rcpart` 清理完毕），再重置本地工具枢纽。
                // 注意：主机侧后台终端继续保留在被控端供下次重连恢复，不在此伪造 Exited(-1)。
                t_running.store(false, Ordering::Release);
                file_worker.shutdown();
                {
                    let mut hub = t_tools_hub.lock().unwrap_or_else(|e| e.into_inner());
                    *hub = ToolClientHub::new();
                }
                if end.reason == SESSION_SWITCHING_REASON {
                    t_update.push(SessionUpdate::SessionSwitching {
                        reason: end.reason.clone(),
                    });
                }
                let ui_error = Some(crate::ui_error::classify_session_reason(
                    &end.reason,
                    crate::ui_error::current_platform(),
                ));
                t_update.push(SessionUpdate::Ended {
                    reason: end.reason,
                    recoverable: end.recoverable,
                    ui_error,
                });
            })
            .expect("spawn rc-ui-session thread");

        Self {
            cmd_tx,
            display_ctrl_tx,
            input_tx,
            update_rx,
            file_event_rx,
            terminal_event_rx,
            portmap_latest,
            tools_hub,
            file_handle,
            disconnect_flag,
            lock_on_disconnect,
            relay_interrupt,
            running,
            watch_only,
            tool_permissions,
            still_refine_metrics,
            encrypt_connection,
            base_config,
            layer_lease,
            upgrade_surface,
            thread: Some(handle),
        }
    }

    /// 标记本次会话在断开前向被控端发送锁屏指令（供「退出时锁定被控端」使用）。
    pub fn request_lock_on_disconnect(&self) {
        self.lock_on_disconnect.store(true, Ordering::Release);
    }

    fn trigger_disconnect(&self) {
        self.disconnect_flag.store(true, Ordering::Release);
        let interrupt = self
            .relay_interrupt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(h) = interrupt {
            h.interrupt();
        }
    }

    /// 发送控制命令；会话已结束时静默忽略（幂等，U10）。
    pub fn send(&self, cmd: SessionCommand) {
        if matches!(cmd, SessionCommand::Disconnect) {
            self.trigger_disconnect();
        }
        if !self.is_running() {
            return;
        }
        self.cmd_tx.push_drop_oldest(cmd);
    }

    /// 将纯工具态会话原地热升级为桌面控屏模式（可选传入平台主线程预分配的渲染表面）。
    ///
    /// 将预分配表面写入共享槽（若传入 `Some` 则更新共享槽供升级与后续重建复用）并投递
    /// [`SessionCommand::SetMediaPaused { paused: false }`]，
    /// 由会话线程在不断开底层连接的前提下构建真实视频管线并请求被控端恢复推流。
    pub fn upgrade_to_desktop(&self, surface: Option<PreallocatedRenderSurface>) {
        if !self.is_running() {
            return;
        }
        if let Some(surf) = surface {
            *self
                .upgrade_surface
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(surf);
        }
        self.cmd_tx
            .push_drop_oldest(SessionCommand::SetMediaPaused { paused: false });
    }

    /// 发送显示/防窥/多屏控制消息（经 `TOOL_CHANNEL_DISPLAY_CTRL` 可靠送达被控端）。
    pub fn send_display_ctrl(&self, msg: DisplayControlMsg) {
        if !self.is_running() {
            return;
        }
        self.display_ctrl_tx.push_drop_oldest(msg);
    }

    /// 经控制端用户显式确认后，下发被控端远程更新请求并武装中转兜底参数。
    pub fn trigger_remote_update(&self, req: crate::updater::RemoteUpdateRequest) {
        self.send_display_ctrl(DisplayControlMsg::UpdateTrigger {
            target_version: req.target_version,
            download_url: req.download_url,
            expected_sha256: req.expected_sha256,
            asset_name: req.asset_name,
            mirror_url: req.mirror_url,
            relay_fallback_allowed: req.relay_fallback_allowed,
            request_id: 0,
        });
    }

    /// 取消当前正在进行的远程更新或中转推送。
    pub fn cancel_remote_update(&self) {
        self.send_display_ctrl(DisplayControlMsg::UpdateCancel);
    }

    /// 提交被控端锁屏下远程终端的系统密码校验请求（仅校验系统密码，绝不解锁物理屏幕）。
    pub fn submit_terminal_unlock(
        &self,
        password: String,
        username: Option<String>,
    ) -> Result<(), String> {
        let mut password = zeroize::Zeroizing::new(password);
        if !self.is_running() {
            return Err("请先建立远控会话".to_string());
        }
        let perms = self.tool_permissions();
        if !perms.allows_channel(TOOL_CHANNEL_TERMINAL) {
            let ui_error = crate::ui_error::tool_forbidden_ui_error(
                TOOL_CHANNEL_TERMINAL,
                crate::ui_error::current_platform(),
                None,
            );
            let msg = ui_error.message.clone();
            self.update_rx.push(SessionUpdate::ToolPermissionDenied {
                channel: TOOL_CHANNEL_TERMINAL,
                ui_error,
            });
            return Err(msg);
        }
        if password.is_empty() || password.len() > 512 {
            return Err("请输入有效的系统登录密码".to_string());
        }
        self.send_display_ctrl(DisplayControlMsg::TerminalUnlockRequest {
            password: crate::display_ctrl::RedactedSecret(std::mem::take(&mut *password)),
            username: username
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty()),
        });
        Ok(())
    }

    /// 动态切换当前会话的只读观看模式标记（供 `set_session_watch_only` 同步控制输入通道与采集器）。
    pub fn set_watch_only(&self, enabled: bool) {
        self.watch_only.store(enabled, Ordering::Release);
    }

    /// 发送一条输入事件；观看模式（`watch_only`）或会话已结束时静默丢弃（U9 / U10）。
    pub fn send_input(&self, ev: InputEvent) {
        if self.watch_only.load(Ordering::Acquire) || !self.is_running() {
            return;
        }
        self.input_tx.push(ev);
    }

    /// 非阻塞拉取一条状态更新（`commands.rs` 轮询后 emit 给前端）。
    pub fn try_recv_update(&self) -> Option<SessionUpdate> {
        self.update_rx.try_pop()
    }

    /// 获取轻量可克隆的工具操作句柄（供 W2/W3/W4 IPC 命令在释放 `AppState::session` 锁后调用）。
    pub fn tools(&self) -> ToolClientHandle {
        ToolClientHandle {
            hub: Arc::clone(&self.tools_hub),
            file: self.file_handle.clone(),
            portmap_latest: Arc::clone(&self.portmap_latest),
            running: Arc::clone(&self.running),
            tool_permissions: Arc::clone(&self.tool_permissions),
            update_tx: Arc::clone(&self.update_rx),
        }
    }

    /// 非阻塞拉取一条 W2 文件传输 UI 事件（`main.rs` 轮询后 emit `"file://event"`）。
    pub fn try_recv_file_event(&self) -> Option<FileEvent> {
        self.file_event_rx.try_pop()
    }

    /// 非阻塞拉取一条 W3 远程终端 UI 事件（`main.rs` 轮询后 emit `"terminal://event"`）。
    pub fn try_recv_terminal_event(&self) -> Option<TerminalEvent> {
        self.terminal_event_rx.try_pop()
    }

    /// 非阻塞取出最新 W4 端口映射规则列表变更（`main.rs` 轮询后 emit `"portmap://update"`）。
    pub fn take_portmap_update(&self) -> Option<Vec<PortMapRuleSnapshot>> {
        self.portmap_latest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    /// 会话线程是否仍在运行。
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// 查询当前被控端通告的生效工具通道权限（默认兼容旧端全允许）。
    pub fn tool_permissions(&self) -> ToolPermissions {
        *self
            .tool_permissions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// 查询当前会话静止无损 Tile 补帧的接收端诊断指标快照（`applied_count` / `drop_stale_count` / `avg_tile_bytes`）。
    pub fn still_refine_metrics(&self) -> crate::still_refine::StillRefineMetrics {
        *self
            .still_refine_metrics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// 当前会话是否开启了双向 mTLS / E2EE 加密连接模式。
    pub fn encrypt_connection(&self) -> bool {
        self.encrypt_connection
    }

    /// 基于当前会话配置生成切换 `encrypt_connection` 后的重连配置（保持所有画面、音频、权限与地址参数不变）。
    pub fn config_with_encrypt_connection(&self, encrypt_connection: bool) -> UiSessionConfig {
        self.base_config.with_encrypt_connection(encrypt_connection)
    }

    /// 获取离屏 `MetalRenderer` 的保活租约（仅 macOS 硬件后端就绪后返回 `Some`）。
    ///
    /// 持有返回的 [`LayerLease`] 期间，即使会话线程已退出并释放自身管线，底层
    /// `MetalRenderer` 及其 `CAMetalLayer` 仍保持存活，供主线程安全完成挂载/同步/摘除。
    pub fn layer_lease(&self) -> Option<LayerLease> {
        self.layer_lease
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 获取离屏 `MetalRenderer::layer_ptr()` 借用指针（仅 macOS 硬件后端就绪后返回 `Some`）。
    ///
    /// 跨线程派发到主线程时请优先使用 [`Self::layer_lease`] 保活渲染器。
    pub fn layer_ptr(&self) -> Option<*mut c_void> {
        self.layer_lease().map(|lease| lease.as_ptr())
    }

    /// 主动断开并等待会话线程干净退出（消费句柄，U10）。
    pub fn join(mut self) {
        self.trigger_disconnect();
        if self.is_running() {
            self.cmd_tx.push_drop_oldest(SessionCommand::Disconnect);
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }

    /// 非阻塞/有界等待中止会话线程：先推送 `Disconnect` 命令并留出短优雅窗口
    /// （至多 `min(max_wait, 80ms)`，让会话线程在 TCP Relay 下优先发完 `LockScreen` 与 `Bye(Normal)`）；
    /// 若窗口期满线程仍在运行再调用 `trigger_disconnect()` 强制中断底层套接字并等待至多 `max_wait`，
    /// 超时仍未退出则将 `JoinHandle` 交由后台回收线程异步 `join`，绝不卡死调用方。
    pub fn detach_and_abort(mut self, max_wait: Duration) {
        const GRACEFUL_DISCONNECT_WINDOW: Duration = Duration::from_millis(80);

        if self.is_running() {
            self.cmd_tx.push_drop_oldest(SessionCommand::Disconnect);
        }
        let Some(handle) = self.thread.take() else {
            self.trigger_disconnect();
            return;
        };
        let start = Instant::now();
        let total_deadline = start + max_wait;
        let graceful_deadline = start + max_wait.min(GRACEFUL_DISCONNECT_WINDOW);
        while (self.is_running() || !handle.is_finished()) && Instant::now() < graceful_deadline {
            let remaining = graceful_deadline.saturating_duration_since(Instant::now());
            thread::sleep(remaining.min(Duration::from_millis(5)));
        }
        if self.is_running() || !handle.is_finished() {
            self.trigger_disconnect();
            while (self.is_running() || !handle.is_finished()) && Instant::now() < total_deadline {
                let remaining = total_deadline.saturating_duration_since(Instant::now());
                thread::sleep(remaining.min(Duration::from_millis(5)));
            }
        }
        if handle.is_finished() {
            let _ = handle.join();
        } else {
            let _ = thread::Builder::new()
                .name("rc-session-reaper".to_string())
                .spawn(move || {
                    let _ = handle.join();
                });
        }
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.thread.take() {
            self.trigger_disconnect();
            if self.is_running() {
                self.cmd_tx.push_drop_oldest(SessionCommand::Disconnect);
            }
            let _ = handle.join();
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// 会话线程主循环（照 rc-cli/src/cmd/client.rs 形态）
// ─────────────────────────────────────────────────────────────────

/// 可重锚的会话钟（同 `rc-cli/src/cmd/client.rs` 修复卡 C-1）。
fn reanchorable_clock(origin: Instant) -> (SessionClock, Arc<Mutex<Instant>>) {
    let anchor = Arc::new(Mutex::new(origin));
    let clock: SessionClock = {
        let anchor = Arc::clone(&anchor);
        Arc::new(move || {
            let a = *anchor.lock().unwrap_or_else(|e| e.into_inner());
            u32::try_from(a.elapsed().as_micros()).unwrap_or(u32::MAX)
        })
    };
    (clock, anchor)
}

/// 生成进程内唯一会话号（同 `rc-cli/src/cmd/client.rs`）。
fn derive_session_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    (u64::from(std::process::id()) << 20) | (n & 0xF_FFFF) | 0x200_000
}

const LAN_DIRECT_PROBE_TIMEOUT: Duration = Duration::from_millis(300);
/// Tier 1（`UDP LAN`）发送 `Hello` 后等待首条响应的预算（3s，兼顾冷启硬件管线耗时与 `:21117` 15s 中继配对窗口；
/// 收到 `Welcome{ChallengeRequired}` 进入鉴权/审批后自动放宽至 45s）。
const LAN_DIRECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// Tier 2（`UDP P2P`）发送 `Hello` 后等待首条响应的预算（4s，进入鉴权/审批后自动放宽至 45s）。
const P2P_DIRECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

struct LanQuicTransport {
    transport: rc_net::quic::QuicTransport,
    _endpoint: QuicEndpoint,
}

impl Transport for LanQuicTransport {
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

const RELAY_RTT_MIN_BITRATE_BPS: u32 = 2_000_000;
const RELAY_RTT_INFLATE_ABS_US: u64 = 45_000;
const RELAY_RTT_COOLDOWN: Duration = Duration::from_secs(2);
const RELAY_RTT_MIN_WINDOW: Duration = Duration::from_secs(20);

/// 控制端 TCP Relay 基于 `ProbePong` RTT 膨胀的辅助调速器（捕获 Server→Client 段 TCP 队列膨胀）。
struct RelayRttController {
    min_rtt_us: Option<u64>,
    min_rtt_updated_at: Option<Instant>,
    window_min_rtt_us: Option<u64>,
    cap_bps: u32,
    current_bps: u32,
    clean_probes: u32,
    last_pongs: u64,
    last_adjust: Instant,
}

impl RelayRttController {
    fn new(initial_bps: u32, now: Instant) -> Self {
        let cap = initial_bps.max(1);
        Self {
            min_rtt_us: None,
            min_rtt_updated_at: None,
            window_min_rtt_us: None,
            cap_bps: cap,
            current_bps: cap,
            clean_probes: 0,
            last_pongs: 0,
            last_adjust: now,
        }
    }

    fn on_manual_bitrate(&mut self, bps: u32, now: Instant) {
        let v = bps.max(1);
        self.cap_bps = v;
        self.current_bps = v;
        self.clean_probes = 0;
        self.last_adjust = now;
    }

    fn on_probe(&mut self, now: Instant, pongs_received: u64, rtt_us: Option<u64>) -> Option<u32> {
        if pongs_received <= self.last_pongs {
            return None;
        }
        self.last_pongs = pongs_received;
        let rtt = rtt_us?;
        let min_rtt = match (self.min_rtt_us, self.min_rtt_updated_at) {
            (Some(m), Some(updated_at)) => {
                if rtt <= m {
                    self.min_rtt_us = Some(rtt);
                    self.min_rtt_updated_at = Some(now);
                    self.window_min_rtt_us = None;
                    rtt
                } else {
                    let candidate = self.window_min_rtt_us.map_or(rtt, |w| w.min(rtt));
                    if now.saturating_duration_since(updated_at) >= RELAY_RTT_MIN_WINDOW {
                        self.min_rtt_us = Some(candidate);
                        self.min_rtt_updated_at = Some(now);
                        self.window_min_rtt_us = None;
                        candidate
                    } else {
                        self.window_min_rtt_us = Some(candidate);
                        m
                    }
                }
            }
            _ => {
                self.min_rtt_us = Some(rtt);
                self.min_rtt_updated_at = Some(now);
                self.window_min_rtt_us = None;
                rtt
            }
        };

        if rtt > min_rtt.saturating_add(RELAY_RTT_INFLATE_ABS_US) && rtt > min_rtt.saturating_mul(2)
        {
            self.clean_probes = 0;
            if now.saturating_duration_since(self.last_adjust) >= RELAY_RTT_COOLDOWN {
                let floor = RELAY_RTT_MIN_BITRATE_BPS.min(self.cap_bps).max(1);
                let next = (((self.current_bps as f64) * 0.75) as u32).clamp(floor, self.cap_bps);
                self.last_adjust = now;
                if next != self.current_bps {
                    self.current_bps = next;
                    return Some(next);
                }
            }
            return None;
        }

        if rtt <= min_rtt.saturating_add(15_000) {
            self.clean_probes = self.clean_probes.saturating_add(1);
            if self.clean_probes >= 3
                && self.current_bps < self.cap_bps
                && now.saturating_duration_since(self.last_adjust) >= RELAY_RTT_COOLDOWN
            {
                let step = (self.current_bps / 5).max(2_000_000);
                let next = self.current_bps.saturating_add(step).min(self.cap_bps);
                self.last_adjust = now;
                self.clean_probes = 0;
                if next != self.current_bps {
                    self.current_bps = next;
                    return Some(next);
                }
            }
        } else {
            self.clean_probes = 0;
        }

        None
    }
}

fn path_kind_from_transport_label(label: &str) -> TransportPathKind {
    match label {
        "TCP Relay" => TransportPathKind::Relay,
        "UDP P2P" => TransportPathKind::P2p,
        "UDP LAN (mTLS)" => TransportPathKind::MtlsLan,
        _ => TransportPathKind::Lan,
    }
}

fn should_run_initial_bw_probe(path_kind: TransportPathKind) -> bool {
    matches!(path_kind, TransportPathKind::P2p)
}

fn sync_relay_rtt_ctrl_for_path(
    path_kind: TransportPathKind,
    target_bps: u32,
    now: Instant,
) -> Option<RelayRttController> {
    (path_kind == TransportPathKind::Relay).then(|| RelayRttController::new(target_bps.max(1), now))
}

fn prepare_peer_mtls_bundle(
    cfg: &UiSessionConfig,
    grant: &ConnectGrant,
) -> Option<SessionMtlsBundle> {
    let mut bundle = cfg.mtls_config.clone()?;
    if bundle.expected_peer_device_id.is_none() && !grant.target_id.is_empty() {
        bundle.expected_peer_device_id = Some(grant.target_id.clone());
    }
    if bundle.expected_peer_user_id.is_none() && grant.is_owner_connection {
        bundle.expected_peer_user_id = Some(bundle.local_user_id.clone());
    }
    Some(bundle)
}

fn collect_lan_candidate_addrs(cfg: &UiSessionConfig, grant: &ConnectGrant) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut probe_targets = Vec::new();
    if let Some(addr) = cfg.lan_direct_addr {
        out.push(addr);
        probe_targets.push(addr);
    }
    // 当未配置同局域网显式直连地址且双方同族公网 IP 已确认不同时，直接跳过 RFC 1918 `/24` 猜测，
    // 消除跨网 `192.168.1.0/24` 地址重名造成的黑洞等待；跨地址族返回 `None` 时不误杀。
    let self_pubs: Vec<&str> = grant.self_public_addr.as_deref().into_iter().collect();
    let peer_pubs: Vec<&str> = grant
        .peer_public_addr
        .as_deref()
        .into_iter()
        .chain(grant.peer_public_addrs.iter().map(String::as_str))
        .collect();
    if cfg.lan_direct_addr.is_none()
        && crate::nat::same_public_ip_any(&self_pubs, &peer_pubs) == Some(false)
    {
        return out;
    }
    if let Ok(relay_addr) = grant.relay_addr.parse::<SocketAddr>() {
        if !probe_targets.contains(&relay_addr) {
            probe_targets.push(relay_addr);
        }
    }
    let local_ips = lan_discovery::detect_local_interface_ips_for_targets(&probe_targets);
    let local_v4s = local_ips.ipv4s;
    for raw in &grant.peer_lan_addrs {
        let Ok(addr) = raw.parse::<SocketAddr>() else {
            continue;
        };
        let std::net::IpAddr::V4(peer_ip) = addr.ip().to_canonical() else {
            continue;
        };
        if !lan_discovery::is_usable_lan_ipv4(peer_ip) {
            continue;
        }
        let same_subnet = local_v4s
            .iter()
            .any(|local_ip| peer_ip.octets()[..3] == local_ip.octets()[..3]);
        if same_subnet {
            let candidate = SocketAddr::new(
                std::net::IpAddr::V4(peer_ip),
                crate::host_bridge::DEFAULT_HOST_PORT,
            );
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
    }
    out
}

enum DirectTierWinner {
    Lan {
        transport: Box<dyn Transport>,
        peer_cert_fingerprint: Option<String>,
        lan_addr: SocketAddr,
        p2p_already_failed: bool,
    },
    P2p {
        transport: Box<dyn Transport>,
        peer_cert_fingerprint: Option<String>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum FirstOk {
    Lan,
    P2p,
}

enum DirectTierRaceError {
    FatalMtls(String),
    NonFatal(Vec<String>),
    Cancelled,
}

type LanDialResult =
    Result<(Box<dyn Transport>, Option<String>, SocketAddr), (Vec<String>, Option<String>)>;
type P2pDialResult = Result<(Box<dyn Transport>, Option<String>), (String, Option<String>)>;

enum RaceBranchOutcome {
    LanOk {
        transport: Box<dyn Transport>,
        peer_cert_fingerprint: Option<String>,
        lan_addr: SocketAddr,
    },
    LanErr {
        reasons: Vec<String>,
        fatal_mtls: Option<String>,
    },
    P2pOk {
        transport: Box<dyn Transport>,
        peer_cert_fingerprint: Option<String>,
    },
    P2pErr {
        reason: String,
        fatal_mtls: Option<String>,
    },
}

/// Happy Eyeballs 并发 LAN 直连拨号（单目标零额外线程；多网卡候选以 ~50ms 错峰并发尝试，任一命中即中止其余拨号）。
fn dial_lan_addrs_happy_eyeballs(
    lan_addrs: &[SocketAddr],
    mtls: Option<&rc_net::mtls::MtlsConfig>,
    encrypt_conn: bool,
    outer_cancel: &AtomicBool,
) -> LanDialResult {
    if lan_addrs.len() <= 1 {
        let mut reasons = Vec::new();
        for &lan_addr in lan_addrs {
            if outer_cancel.load(Ordering::Acquire) {
                break;
            }
            match dial_lan_direct_quic(lan_addr, mtls, outer_cancel) {
                Ok((t, fp)) => return Ok((t, fp, lan_addr)),
                Err(err) => {
                    if encrypt_conn && is_mtls_cert_or_config_error(&err) {
                        return Err((
                            reasons,
                            Some(format!("LAN mTLS 证书校验失败（严禁静默降级）: {err}")),
                        ));
                    }
                    reasons.push(err);
                }
            }
        }
        return Err((reasons, None));
    }

    let capped: Vec<SocketAddr> = lan_addrs.iter().copied().take(4).collect();
    let local_cancel = AtomicBool::new(false);
    let (tx, rx) = std::sync::mpsc::channel::<(
        SocketAddr,
        Result<(Box<dyn Transport>, Option<String>), String>,
    )>();

    std::thread::scope(|scope| {
        let total = capped.len();
        for (idx, &addr) in capped.iter().enumerate() {
            let tx_c = tx.clone();
            let cancel_ref = &local_cancel;
            scope.spawn(move || {
                if idx > 0 {
                    let delay_end = Instant::now() + Duration::from_millis((idx as u64) * 50);
                    while Instant::now() < delay_end {
                        if cancel_ref.load(Ordering::Acquire)
                            || outer_cancel.load(Ordering::Acquire)
                        {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                if cancel_ref.load(Ordering::Acquire) || outer_cancel.load(Ordering::Acquire) {
                    return;
                }
                let res = dial_lan_direct_quic(addr, mtls, cancel_ref);
                let _ = tx_c.send((addr, res));
            });
        }
        drop(tx);

        let mut reasons = Vec::new();
        let mut fatal_mtls: Option<String> = None;
        let mut received = 0usize;
        while received < total {
            if outer_cancel.load(Ordering::Acquire) {
                local_cancel.store(true, Ordering::Release);
                break;
            }
            match rx.recv_timeout(Duration::from_millis(10)) {
                Ok((addr, Ok((t, fp)))) => {
                    local_cancel.store(true, Ordering::Release);
                    return Ok((t, fp, addr));
                }
                Ok((_addr, Err(err))) => {
                    received += 1;
                    if fatal_mtls.is_none() && encrypt_conn && is_mtls_cert_or_config_error(&err) {
                        fatal_mtls = Some(format!("LAN mTLS 证书校验失败（严禁静默降级）: {err}"));
                    }
                    reasons.push(err);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        Err((reasons, fatal_mtls))
    })
}

fn race_lan_and_p2p_with<FLan, FP2p>(
    encrypt_connection: bool,
    disconnect_flag: &AtomicBool,
    dial_lan: FLan,
    dial_p2p: FP2p,
) -> Result<DirectTierWinner, DirectTierRaceError>
where
    FLan: FnOnce(&AtomicBool) -> LanDialResult + Send,
    FP2p: FnOnce(&AtomicBool) -> P2pDialResult + Send,
{
    let lan_cancel = AtomicBool::new(false);
    let p2p_cancel = AtomicBool::new(false);
    let (tx, rx) = mpsc::sync_channel::<RaceBranchOutcome>(2);

    std::thread::scope(|scope| {
        let tx_lan = tx.clone();
        let lan_cancel_ref = &lan_cancel;
        scope.spawn(move || {
            let msg = match dial_lan(lan_cancel_ref) {
                Ok((transport, peer_cert_fingerprint, lan_addr)) => RaceBranchOutcome::LanOk {
                    transport,
                    peer_cert_fingerprint,
                    lan_addr,
                },
                Err((reasons, fatal_mtls)) => RaceBranchOutcome::LanErr {
                    reasons,
                    fatal_mtls,
                },
            };
            let _ = tx_lan.send(msg);
        });

        let tx_p2p = tx;
        let p2p_cancel_ref = &p2p_cancel;
        scope.spawn(move || {
            let msg = match dial_p2p(p2p_cancel_ref) {
                Ok((transport, peer_cert_fingerprint)) => RaceBranchOutcome::P2pOk {
                    transport,
                    peer_cert_fingerprint,
                },
                Err((reason, fatal_mtls)) => RaceBranchOutcome::P2pErr { reason, fatal_mtls },
            };
            let _ = tx_p2p.send(msg);
        });

        let mut lan_res: Option<LanDialResult> = None;
        let mut p2p_res: Option<P2pDialResult> = None;
        let mut first_ok: Option<FirstOk> = None;
        let mut p2p_failed_before_lan_win = false;

        while lan_res.is_none() || p2p_res.is_none() {
            if disconnect_flag.load(Ordering::Acquire) {
                lan_cancel.store(true, Ordering::Release);
                p2p_cancel.store(true, Ordering::Release);
            }
            match rx.recv_timeout(Duration::from_millis(10)) {
                Ok(RaceBranchOutcome::LanOk {
                    transport,
                    peer_cert_fingerprint,
                    lan_addr,
                }) => {
                    if first_ok.is_none() {
                        first_ok = Some(FirstOk::Lan);
                    }
                    p2p_cancel.store(true, Ordering::Release);
                    lan_res = Some(Ok((transport, peer_cert_fingerprint, lan_addr)));
                }
                Ok(RaceBranchOutcome::LanErr {
                    reasons,
                    fatal_mtls,
                }) => {
                    if fatal_mtls.is_some() {
                        p2p_cancel.store(true, Ordering::Release);
                    }
                    lan_res = Some(Err((reasons, fatal_mtls)));
                }
                Ok(RaceBranchOutcome::P2pOk {
                    transport,
                    peer_cert_fingerprint,
                }) => {
                    if first_ok.is_none() {
                        first_ok = Some(FirstOk::P2p);
                    }
                    lan_cancel.store(true, Ordering::Release);
                    p2p_res = Some(Ok((transport, peer_cert_fingerprint)));
                }
                Ok(RaceBranchOutcome::P2pErr { reason, fatal_mtls }) => {
                    if lan_res.is_none() {
                        p2p_failed_before_lan_win = true;
                    }
                    if fatal_mtls.is_some() {
                        lan_cancel.store(true, Ordering::Release);
                    }
                    p2p_res = Some(Err((reason, fatal_mtls)));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        if disconnect_flag.load(Ordering::Acquire) {
            return Err(DirectTierRaceError::Cancelled);
        }

        if encrypt_connection {
            if let Some(Err((_, Some(mtls_err)))) = &lan_res {
                return Err(DirectTierRaceError::FatalMtls(mtls_err.clone()));
            }
            if let Some(Err((_, Some(mtls_err)))) = &p2p_res {
                return Err(DirectTierRaceError::FatalMtls(mtls_err.clone()));
            }
        }

        // 保持先到达的胜者，避免丢弃已与 Host 建好 QUIC 的 P2P 连接造成 Host 孤儿会话。
        if first_ok == Some(FirstOk::P2p) {
            if let Some(Ok((transport, peer_cert_fingerprint))) = p2p_res {
                drop(lan_res);
                return Ok(DirectTierWinner::P2p {
                    transport,
                    peer_cert_fingerprint,
                });
            }
        }

        if let Some(Ok((transport, peer_cert_fingerprint, lan_addr))) = lan_res {
            drop(p2p_res);
            return Ok(DirectTierWinner::Lan {
                transport,
                peer_cert_fingerprint,
                lan_addr,
                p2p_already_failed: p2p_failed_before_lan_win,
            });
        }

        if let Some(Ok((transport, peer_cert_fingerprint))) = p2p_res {
            return Ok(DirectTierWinner::P2p {
                transport,
                peer_cert_fingerprint,
            });
        }

        let mut all_reasons = Vec::new();
        if let Some(Err((reasons, _))) = lan_res {
            all_reasons.extend(reasons);
        }
        if let Some(Err((reason, _))) = p2p_res {
            all_reasons.push(reason);
        }
        Err(DirectTierRaceError::NonFatal(all_reasons))
    })
}

fn build_client_p2p_candidates(grant: &ConnectGrant) -> P2pCandidates {
    let self_pubs: Vec<&str> = grant.self_public_addr.as_deref().into_iter().collect();
    let peer_pubs: Vec<&str> = grant
        .peer_public_addr
        .as_deref()
        .into_iter()
        .chain(grant.peer_public_addrs.iter().map(String::as_str))
        .collect();
    let filtered_peer_lan_addrs =
        p2p::filter_cross_site_lan_addrs(&grant.peer_lan_addrs, &self_pubs, &peer_pubs);
    P2pCandidates {
        session_id: grant.session_id.clone(),
        peer_public_addr: grant.peer_public_addr.clone(),
        peer_public_addrs: grant.peer_public_addrs.clone(),
        peer_lan_addrs: filtered_peer_lan_addrs,
        local_udp_port: grant.local_udp_port,
        self_nat_type: grant.self_nat_type,
        self_nat_port_delta: grant.self_nat_port_delta,
        self_nat_port_range: grant.self_nat_port_range,
        peer_nat_type: grant.peer_nat_type,
        peer_nat_port_delta: grant.peer_nat_port_delta,
        peer_nat_port_range: grant.peer_nat_port_range,
        punch_secret: grant.punch_secret.clone(),
        start_after_ms: grant.start_after_ms,
        relay_fallback_after_ms: grant.relay_fallback_after_ms,
    }
}

fn punch_timeout_for_mode(mode: ConnectionMode) -> Duration {
    match mode {
        ConnectionMode::P2pOnly => p2p::P2P_ONLY_PUNCH_TIMEOUT,
        ConnectionMode::Auto | ConnectionMode::TcpRelay => p2p::DEFAULT_PUNCH_TIMEOUT,
    }
}

fn dial_p2p_held_transport(
    candidates: &P2pCandidates,
    quic_mtls: Option<&rc_net::mtls::MtlsConfig>,
    encrypt_connection: bool,
    cancel: &AtomicBool,
    punch_timeout: Duration,
) -> P2pDialResult {
    let port_hold = crate::signal_client::acquire_local_udp_port_for_p2p(candidates.local_udp_port);
    match p2p::attempt_p2p_quic_client_mtls(
        candidates,
        punch_timeout,
        p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
        cancel,
        quic_mtls,
    ) {
        Ok(p2p_conn) => {
            let held = crate::signal_client::P2pHeldTransport::new(p2p_conn, port_hold);
            let fp = held
                .peer_mtls_identity()
                .map(|id| id.cert_fingerprint_sha256);
            Ok((Box::new(held) as Box<dyn Transport>, fp))
        }
        Err(err) => {
            drop(port_hold);
            let fatal_mtls = (encrypt_connection && is_mtls_cert_or_config_error(&err))
                .then(|| format!("P2P mTLS 证书校验失败（严禁静默降级）: {err}"));
            Err((err, fatal_mtls))
        }
    }
}

fn dial_lan_direct_quic(
    lan_addr: SocketAddr,
    mtls: Option<&rc_net::mtls::MtlsConfig>,
    cancel: &AtomicBool,
) -> Result<(Box<dyn Transport>, Option<String>), String> {
    let identity = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM)
        .map_err(|e| format!("LAN QUIC 端点证书加载失败: {e}"))?;
    let local_addr: SocketAddr = if lan_addr.is_ipv6() {
        "[::]:0".parse().expect("[::]:0 is a valid socket addr")
    } else {
        "0.0.0.0:0"
            .parse()
            .expect("0.0.0.0:0 is a valid socket addr")
    };
    let net = NetConfig {
        role: Role::Controller,
        local_addr,
        peer_addr: Some(lan_addr),
        mtu: rc_session::DEFAULT_SESSION_MTU,
    };
    let endpoint =
        QuicEndpoint::new(&net, &identity).map_err(|e| format!("LAN QUIC 端点创建失败: {e}"))?;
    if let Some(mtls_cfg) = mtls {
        let transport = endpoint
            .connect_mtls_cancelable(lan_addr, mtls_cfg, "", LAN_DIRECT_PROBE_TIMEOUT, cancel)
            .map_err(|e| {
                let msg = e.to_string();
                if is_mtls_cert_or_config_error(&msg) {
                    format!("LAN mTLS 证书校验失败: {msg}")
                } else {
                    format!("LAN 直连失败: {msg}")
                }
            })?;
        let fp = transport
            .peer_mtls_identity()
            .map(|id| id.cert_fingerprint_sha256);
        Ok((
            Box::new(LanQuicTransport {
                transport,
                _endpoint: endpoint,
            }),
            fp,
        ))
    } else {
        let certs = Identity::certs_from_pem(dev_server_cert_pem())
            .map_err(|e| format!("LAN 受信任证书解析失败: {e}"))?;
        let transport = endpoint
            .connect_cancelable(
                lan_addr,
                &certs,
                DEV_SERVER_NAME,
                LAN_DIRECT_PROBE_TIMEOUT,
                cancel,
            )
            .map_err(|e| format!("LAN QUIC 直连失败: {e}"))?;
        Ok((
            Box::new(LanQuicTransport {
                transport,
                _endpoint: endpoint,
            }),
            None,
        ))
    }
}

/// 会话线程内部结束结果（携带是否适合上层自动重连恢复的 `recoverable` 标记）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionEnd {
    reason: String,
    recoverable: bool,
}

impl SessionEnd {
    fn fatal(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            recoverable: false,
        }
    }

    fn recoverable(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            recoverable: true,
        }
    }
}

/// 计算实际生效的连接模式（保留 `force_relay: true` 向后兼容强制映射至 `ConnectionMode::TcpRelay`）。
fn effective_connection_mode(cfg: &UiSessionConfig) -> ConnectionMode {
    if cfg.force_relay {
        ConnectionMode::TcpRelay
    } else {
        cfg.connection_mode
    }
}

/// 判定一段错误/断开文案是否属于不可自动恢复的终态（用户主动断开、密码/鉴权拒绝、mTLS 证书校验失败、仅 P2P 模式拒绝回退、硬件解码持久失败）。
fn is_non_recoverable_error_reason(msg: &str) -> bool {
    if is_mtls_cert_or_config_error(msg) {
        return true;
    }
    let lower = msg.to_ascii_lowercase();
    msg.contains("用户主动断开")
        || msg.contains("已取消")
        || lower.contains("cancelled")
        || lower.contains("proxy_config_conflict")
        || msg.contains("代理配置冲突")
        || msg.contains("代理认证失败")
        || msg.contains("仅 P2P")
        || msg.contains("远端画面解码失败")
        || msg.contains("密码")
        || msg.contains("鉴权")
        || msg.contains("认证")
        || msg.contains("拒绝")
        || lower.contains("auth")
        || lower.contains("password")
        || lower.contains("unauthorized")
        || lower.contains("rejected")
        || lower.contains("denied")
}

/// 判定 Tier 1（`UDP LAN`）/ Tier 2（`UDP P2P`）会话握手失败后，是否允许安全回退至下一级传输链路。
///
/// 严格红线：
/// - 仅当**尚未进入鉴权/审批交互**（`!entered_auth_or_approval`，未收到 `Welcome` / `AuthChallenge`）
///   且发生底层连接断开/重置或首包超时（`Error::Network` / `Error::Io` / `Error::Timeout`）时才允许回退；
/// - 严禁在用户主动断开、密码/鉴权拒绝、机主拒绝、mTLS 证书校验失败（含服务端拒收客户端证书的 QUIC
///   `CRYPTO_ERROR` alert）、协议版本不兼容、或已收到 `Welcome{ChallengeRequired}` / `AuthChallenge`
///   后的任何失败/审批超时中回退（防止被控端连弹多个审批窗）。
fn should_fallback_after_handshake_error(
    err: &rc_types::Error,
    entered_auth_or_approval: bool,
    user_disconnected: bool,
) -> bool {
    if user_disconnected || entered_auth_or_approval {
        return false;
    }
    if !matches!(
        err,
        rc_types::Error::Network(_) | rc_types::Error::Io(_) | rc_types::Error::Timeout(_)
    ) {
        return false;
    }
    let msg = err.to_string();
    if is_mtls_cert_or_config_error(&msg) || is_non_recoverable_error_reason(&msg) {
        return false;
    }
    let lower = msg.to_ascii_lowercase();
    !(lower.contains("protocol")
        || lower.contains("version")
        || lower.contains("incompatible")
        || lower.contains("unsupported"))
}

/// 信令会话进入 `Reconnecting` 退出时按当前传输通道标签生成精确文案并标记 `recoverable = true`。
fn signaling_disconnect_end(transport_label: &str) -> SessionEnd {
    let reason = match transport_label {
        "UDP LAN" => "局域网连接已断开",
        "UDP P2P" => "P2P 连接已断开",
        _ => "中继连接已断开",
    };
    SessionEnd::recoverable(reason)
}

/// 将 `ClientSession::tick` 返回的 `StopReason` 映射为 [`SessionEnd`]。
fn classify_stop_reason_end(stop: &rc_session::StopReason) -> SessionEnd {
    match stop {
        rc_session::StopReason::ByeReceived(ByeReason::SessionSwitching) => {
            SessionEnd::fatal(SESSION_SWITCHING_REASON)
        }
        rc_session::StopReason::ByeReceived(ByeReason::Normal)
        | rc_session::StopReason::Requested => SessionEnd::fatal(format!("对端已关闭 ({stop:?})")),
        rc_session::StopReason::ByeReceived(ByeReason::Refresh) => {
            SessionEnd::recoverable(format!("对端已关闭 ({stop:?})"))
        }
        rc_session::StopReason::Disconnected(msg) => {
            let reason = format!("对端已关闭 ({stop:?})");
            if is_non_recoverable_error_reason(msg) {
                SessionEnd::fatal(reason)
            } else {
                SessionEnd::recoverable(reason)
            }
        }
    }
}

/// 将纯 IP 直连 `ReconnectOutcome::GaveUp` 映射为 [`SessionEnd`]。
fn classify_gave_up_end(closed_reason: Option<&rc_session::StopReason>) -> SessionEnd {
    match closed_reason {
        Some(rc_session::StopReason::ByeReceived(ByeReason::SessionSwitching)) => {
            SessionEnd::fatal(SESSION_SWITCHING_REASON)
        }
        Some(stop @ rc_session::StopReason::ByeReceived(ByeReason::Normal)) => {
            SessionEnd::fatal(format!("对端已关闭 ({stop:?})"))
        }
        _ => SessionEnd::recoverable("重连次数已耗尽"),
    }
}

/// 将运行期驱动错误（`pump_probes` / `tick` / `tick_reconnect`）映射为 [`SessionEnd`]。
fn classify_runtime_err_end(
    prefix: &str,
    err: &rc_types::Error,
    user_disconnected: bool,
) -> SessionEnd {
    if user_disconnected {
        return SessionEnd::fatal("用户主动断开");
    }
    let raw = err.to_string();
    let reason = format!("{prefix}: {raw}");
    if is_non_recoverable_error_reason(&raw) {
        SessionEnd::fatal(reason)
    } else {
        SessionEnd::recoverable(reason)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_session_thread(
    cfg: UiSessionConfig,
    render_surface: Arc<Mutex<Option<PreallocatedRenderSurface>>>,
    cmd_rx: Arc<BoundedQueue<SessionCommand>>,
    display_ctrl_rx: Arc<BoundedQueue<DisplayControlMsg>>,
    input_rx: Arc<BoundedInputQueue>,
    update_tx: Arc<BoundedUpdateQueue>,
    layer_lease: Arc<Mutex<Option<LayerLease>>>,
    disconnect_flag: Arc<AtomicBool>,
    lock_on_disconnect: Arc<AtomicBool>,
    relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    tools_hub: Arc<Mutex<ToolClientHub>>,
    file_worker: &FileClientWorker,
    terminal_events: Arc<BoundedQueue<TerminalEvent>>,
    portmap_latest: Arc<Mutex<Option<Vec<PortMapRuleSnapshot>>>>,
    watch_only: Arc<AtomicBool>,
    tool_permissions: Arc<Mutex<ToolPermissions>>,
    still_refine_metrics: Arc<Mutex<crate::still_refine::StillRefineMetrics>>,
) -> Result<SessionEnd, SessionEnd> {
    let _relay_guard = RelayInterruptSlotGuard {
        slot: &relay_interrupt,
    };

    if disconnect_flag.load(Ordering::Acquire) {
        return Ok(SessionEnd::fatal("用户主动断开"));
    }

    // 严禁静默降级：开启加密连接但缺少 mTLS 证书束时立即拒绝建连。
    if cfg.encrypt_connection && cfg.mtls_config.is_none() {
        return Err(SessionEnd::fatal(
            "已开启「加密连接 (mTLS)」，但缺少设备证书配置，已拒绝降级连接",
        ));
    }

    let effective_mode = effective_connection_mode(&cfg);

    // ── 计时起点：Endpoint 创建之前（T21 U8 / 坑 11，对齐 T18 口径）──
    let t0 = Instant::now();
    let (clock, clock_anchor) = reanchorable_clock(t0);
    let clock_reader = Arc::clone(&clock);

    let live_watch_only = Arc::clone(&watch_only);

    let resolution = Resolution::new(
        if cfg.width == 0 { 1920 } else { cfg.width },
        if cfg.height == 0 { 1080 } else { cfg.height },
    );
    let pipeline = PipelineConfig {
        resolution,
        fps: cfg.fps.max(1),
        bitrate_bps: cfg.bitrate_bps.max(1),
        prefer_hardware: cfg.prefer_hardware,
        target_latency_us: 22_000,
        trace_capacity: 4096,
        diff: DiffMode::TrustPlatform,
        clock_origin_us: None,
        async_decode: cfg.prefer_hardware,
        max_packet_payload: rc_pipeline::MAX_PAYLOAD,
        ..PipelineConfig::default()
    };
    let make_client_cfg =
        |peer_addr: SocketAddr, handshake_timeout: Duration| ClientSessionConfig {
            peer_addr,
            mtu: rc_session::DEFAULT_SESSION_MTU,
            requested: SessionParams {
                width: cfg.width,
                height: cfg.height,
                fps: cfg.fps.max(1),
                bitrate_bps: cfg.bitrate_bps.max(1),
            },
            session_id: derive_session_id(),
            pipeline: pipeline.clone(),
            connect_timeout: Duration::from_secs(10),
            handshake_timeout,
            capture: Box::new(BridgeInputCapture {
                queue: Arc::clone(&input_rx),
                watch_only: Arc::clone(&live_watch_only),
            }),
            input_window: rc_input::DEFAULT_WINDOW,
            auth: ClientAuthConfig {
                password: cfg.password.clone(),
                owner_signer: cfg.owner_signer.clone(),
                ..ClientAuthConfig::default()
            },
        };

    let pending_control: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
    let backend_label: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let renderer_handle: Arc<Mutex<Option<RendererHandle>>> = Arc::new(Mutex::new(None));
    let renderer_pending_resize: Arc<Mutex<Arc<AtomicU64>>> =
        Arc::new(Mutex::new(Arc::new(AtomicU64::new(0))));
    let is_signaling_session = cfg.relay_grant.is_some();
    let streaming_started = Arc::new(AtomicBool::new(false));
    let clipboard_enabled_flag = Arc::new(AtomicBool::new(cfg.clipboard_enabled));
    let want_real_pipeline = Arc::new(AtomicBool::new(!cfg.tools_only));
    let real_pipeline_built = Arc::new(AtomicBool::new(false));
    let is_hw_decoder_slot = Arc::new(AtomicBool::new(false));

    let make_pipeline_factory = |backend_suffix: Option<&'static str>| {
        let label = Arc::clone(&backend_label);
        let rend_slot = Arc::clone(&renderer_handle);
        let pending_slot = Arc::clone(&renderer_pending_resize);
        let layer_slot = Arc::clone(&layer_lease);
        let want_real = Arc::clone(&want_real_pipeline);
        let built_real = Arc::clone(&real_pipeline_built);
        let hw_slot = Arc::clone(&is_hw_decoder_slot);
        let prefer_hw = cfg.prefer_hardware;
        let surface_slot = Arc::clone(&render_surface);
        Box::new(move |pcfg: &PipelineConfig| {
            if !want_real.load(Ordering::Acquire) {
                let placeholder_cfg = PipelineConfig {
                    resolution: Resolution::new(64, 64),
                    fps: pcfg.fps.max(1),
                    bitrate_bps: pcfg.bitrate_bps.max(1),
                    prefer_hardware: false,
                    async_decode: false,
                    ..pcfg.clone()
                };
                let (pipeline, _renderer, _pending_resize) =
                    fake_controller_stack(&placeholder_cfg)?;
                let final_label = match backend_suffix {
                    Some(suffix) => format!("tools-only {suffix}"),
                    None => "tools-only".to_string(),
                };
                *label.lock().unwrap_or_else(|e| e.into_inner()) = final_label;
                *rend_slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
                *pending_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                    Arc::new(AtomicU64::new(0));
                // tools_only 模式严禁创建硬件 VT/Metal，也不写入 layer_lease。
                built_real.store(false, Ordering::Release);
                hw_slot.store(false, Ordering::Release);
                return Ok(pipeline);
            }
            let pre_surface = surface_slot
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let built = build_controller_pipeline(pcfg, prefer_hw, t0, pre_surface.as_ref())?;
            let final_label = match backend_suffix {
                Some(suffix) => format!("{} {suffix}", built.backend_label),
                None => built.backend_label,
            };
            *label.lock().unwrap_or_else(|e| e.into_inner()) = final_label;
            *pending_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                Arc::clone(&built.pending_resize);
            *rend_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(Arc::clone(&built.renderer));
            *layer_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                LayerLease::from_renderer(built.renderer, built.layer_addr);
            built_real.store(true, Ordering::Release);
            hw_slot.store(built.is_hardware, Ordering::Release);
            Ok(built.pipeline)
        })
    };

    let (
        mut client,
        negotiated,
        mut transport_label,
        mut active_backend_suffix,
        mut mtls_active,
        mut peer_cert_fingerprint,
        switch_handle,
        mut bg_p2p_upgrade_rx,
        bg_p2p_cancel_slot,
        grant_obtained_at,
        mut initial_relay_token_consumed,
        proxy_active_runtime,
        runtime_mode,
    ) = if let Some(grant) = cfg.relay_grant.as_ref() {
        update_tx.push(SessionUpdate::Connecting {
            phase: ConnectPhase::Connecting,
            watch_only: live_watch_only.load(Ordering::Acquire),
        });

        let dial_cancel = Arc::new(AtomicBool::new(false));
        *relay_interrupt.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(ActiveRelayInterrupt::Dialing(Arc::clone(&dial_cancel)));
        if disconnect_flag.load(Ordering::Acquire) {
            return Ok(SessionEnd::fatal("用户主动断开"));
        }

        let peer_bundle = prepare_peer_mtls_bundle(&cfg, grant);
        let quic_mtls = if cfg.encrypt_connection {
            let bundle = peer_bundle.as_ref().ok_or_else(|| {
                SessionEnd::fatal("已开启「加密连接 (mTLS)」，但缺少设备证书配置")
            })?;
            Some(bundle.to_quic_mtls_config().map_err(SessionEnd::fatal)?)
        } else {
            None
        };

        // Tier 1（UDP LAN）→ Tier 2（UDP P2P）→ Tier 3（TCP Relay）逐级建连并完成会话握手。
        // 仅当尚未进入鉴权/审批交互且在 Welcome 前发生底层连接断开/重置时，才允许安全回退至下一级。
        struct SelectedRelayPath {
            transport: Box<dyn Transport>,
            relay_shutdown: Option<RelayShutdownHandle>,
            transport_label: &'static str,
            backend_suffix: Option<&'static str>,
            mtls_active: bool,
            peer_cert_fingerprint: Option<String>,
        }
        struct ReadySignalingSession {
            client: ClientSession,
            negotiated: SessionParams,
            transport_label: &'static str,
            backend_suffix: Option<&'static str>,
            mtls_active: bool,
            peer_cert_fingerprint: Option<String>,
            switch_handle: SwitchHandle,
        }
        enum TierHandshakeResult {
            Ready(Box<ReadySignalingSession>),
            Fallback(String),
            Abort(Result<SessionEnd, SessionEnd>),
        }

        let dial_relay_transport =
            |relay_addr: &str,
             relay_token: &str,
             peer_b: Option<&SessionMtlsBundle>,
             encrypt_conn: bool,
             cancel: Arc<AtomicBool>,
             disc_flag: &AtomicBool|
             -> Result<SelectedRelayPath, Result<SessionEnd, SessionEnd>> {
                const RELAY_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
                let (raw_transport, shutdown_handle, active, fp): (
                    Box<dyn Transport>,
                    RelayShutdownHandle,
                    bool,
                    Option<String>,
                ) = if encrypt_conn {
                    let Some(bundle) = peer_b else {
                        return Err(Err(SessionEnd::fatal(
                            "已开启「加密连接 (mTLS)」，但缺少设备证书配置",
                        )));
                    };
                    let relay_mtls = bundle.to_relay_mtls_config(None);
                    let t = E2eeRelayTransport::connect_cancellable(
                        relay_addr,
                        RelayRole::Client,
                        relay_token,
                        RELAY_CLIENT_CONNECT_TIMEOUT,
                        cancel,
                        Some(&relay_mtls),
                        RelayE2eeMode::ClientRequired(bundle.clone()),
                    )
                    .map_err(|e| {
                        if disc_flag.load(Ordering::Acquire) {
                            Ok(SessionEnd::fatal("用户主动断开"))
                        } else {
                            Err(SessionEnd::fatal(classify_relay_connect_error(
                                &e, true, true,
                            )))
                        }
                    })?;
                    let h = t.shutdown_handle();
                    let fp = t
                        .peer_mtls_identity()
                        .map(|id| id.cert_fingerprint_sha256.clone());
                    (Box::new(t), h, true, fp)
                } else if let Some(bundle) = peer_b {
                    let relay_mtls = bundle.to_relay_mtls_config(None);
                    let t = TcpRelayTransport::connect_mtls_cancellable(
                        relay_addr,
                        RelayRole::Client,
                        relay_token,
                        RELAY_CLIENT_CONNECT_TIMEOUT,
                        cancel,
                        &relay_mtls,
                    )
                    .map_err(|e| {
                        if disc_flag.load(Ordering::Acquire) {
                            Ok(SessionEnd::fatal("用户主动断开"))
                        } else {
                            Err(SessionEnd::fatal(classify_relay_connect_error(
                                &e, false, true,
                            )))
                        }
                    })?;
                    let h = t.shutdown_handle();
                    (Box::new(t), h, false, None)
                } else {
                    let t = TcpRelayTransport::connect_cancellable(
                        relay_addr,
                        RelayRole::Client,
                        relay_token,
                        RELAY_CLIENT_CONNECT_TIMEOUT,
                        cancel,
                    )
                    .map_err(|e| {
                        if disc_flag.load(Ordering::Acquire) {
                            Ok(SessionEnd::fatal("用户主动断开"))
                        } else {
                            Err(SessionEnd::fatal(classify_relay_connect_error(
                                &e, false, false,
                            )))
                        }
                    })?;
                    let h = t.shutdown_handle();
                    (Box::new(t), h, false, None)
                };
                Ok(SelectedRelayPath {
                    transport: raw_transport,
                    relay_shutdown: Some(shutdown_handle),
                    transport_label: "TCP Relay",
                    backend_suffix: Some("(中继)"),
                    mtls_active: active,
                    peer_cert_fingerprint: fp,
                })
            };

        let attempt_tier_handshake = |path: SelectedRelayPath,
                                      peer_addr: SocketAddr,
                                      handshake_timeout: Duration,
                                      allow_fallback: bool|
         -> TierHandshakeResult {
            let SelectedRelayPath {
                transport: raw_transport,
                relay_shutdown,
                transport_label: chosen_transport_label,
                backend_suffix,
                mtls_active,
                peer_cert_fingerprint: peer_fp,
            } = path;

            update_tx.push(SessionUpdate::Connecting {
                phase: ConnectPhase::AwaitingWelcome,
                watch_only: live_watch_only.load(Ordering::Acquire),
            });

            let sw_kind = path_kind_from_transport_label(chosen_transport_label);
            let (sw_transport, switch_handle) = SwitchableTransport::new(
                raw_transport,
                Role::Controller,
                sw_kind,
                cfg.encrypt_connection,
            );
            let bridge_transport = BridgeTransport {
                inner: Box::new(sw_transport),
                pending_control: Arc::clone(&pending_control),
                disconnect_flag: Arc::clone(&disconnect_flag),
                relay_shutdown,
                streaming_started: Arc::clone(&streaming_started),
            };
            // 占位解码/渲染器仅用于满足 `ClientSession::with_parts` 签名；握手成功后
            // `set_pipeline_factory_for` 会按裁定参数构造实际硬件/假栈并挂载 `LayerLease`。
            let placeholder_res = Resolution::new(64, 64);
            let dummy_decoder = match rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
                resolution: placeholder_res,
                ..rc_decode::FakeDecoderConfig::default()
            }) {
                Ok(d) => d,
                Err(e) => {
                    return TierHandshakeResult::Abort(Err(SessionEnd::fatal(format!(
                        "会话占位解码器构造失败: {e}"
                    ))));
                }
            };
            let dummy_renderer = match rc_render::FakeRenderer::new(rc_render::FakeRendererConfig {
                size: (placeholder_res.width, placeholder_res.height),
                ..rc_render::FakeRendererConfig::default()
            }) {
                Ok(r) => r,
                Err(e) => {
                    return TierHandshakeResult::Abort(Err(SessionEnd::fatal(format!(
                        "会话占位渲染器构造失败: {e}"
                    ))));
                }
            };

            let mut client = match ClientSession::with_parts(
                make_client_cfg(peer_addr, handshake_timeout),
                Box::new(bridge_transport),
                Box::new(dummy_decoder),
                Box::new(dummy_renderer),
                Arc::clone(&clock),
            ) {
                Ok(c) => c,
                Err(e) => {
                    return TierHandshakeResult::Abort(Err(SessionEnd::fatal(format!(
                        "信令会话构造失败: {e}"
                    ))));
                }
            };
            client.set_pipeline_factory_for(make_pipeline_factory(backend_suffix));
            if let Some(cb) = create_clipboard_backend(cfg.prefer_hardware) {
                client.enable_clipboard(Box::new(ToggleableClipboardBackend::new(
                    cb,
                    Arc::clone(&clipboard_enabled_flag),
                )));
            }

            match client.handshake() {
                Ok(negotiated) => TierHandshakeResult::Ready(Box::new(ReadySignalingSession {
                    client,
                    negotiated,
                    transport_label: chosen_transport_label,
                    backend_suffix,
                    mtls_active,
                    peer_cert_fingerprint: peer_fp,
                    switch_handle,
                })),
                Err(e) => {
                    let user_disc = disconnect_flag.load(Ordering::Acquire);
                    if user_disc {
                        return TierHandshakeResult::Abort(Ok(SessionEnd::fatal("用户主动断开")));
                    }
                    if allow_fallback
                        && should_fallback_after_handshake_error(
                            &e,
                            client.handshake_entered_auth(),
                            false,
                        )
                    {
                        return TierHandshakeResult::Fallback(format!(
                            "{chosen_transport_label} 握手前连接断开: {e}"
                        ));
                    }
                    TierHandshakeResult::Abort(Err(SessionEnd::fatal(format!(
                        "连接/握手失败: {e}"
                    ))))
                }
            }
        };

        let mut ready: Option<ReadySignalingSession> = None;
        let mut direct_fail_reasons: Vec<String> = Vec::new();
        let active_proxy = crate::proxy::active_proxy_config();
        let proxy_active_for_relay = match crate::proxy::split_host_port(&grant.relay_addr) {
            Ok((relay_host, relay_port)) => {
                match crate::proxy::resolve_proxy_for_target(&active_proxy, &relay_host, relay_port)
                {
                    Ok(Some(_)) => true,
                    Ok(None) => false,
                    Err(err) => {
                        return Err(SessionEnd::fatal(format!(
                            "proxy_config_conflict: 代理配置无效：{err}"
                        )));
                    }
                }
            }
            Err(_) => match crate::proxy::resolve_effective_proxy(&active_proxy) {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(err) => {
                    return Err(SessionEnd::fatal(format!(
                        "proxy_config_conflict: 代理配置无效：{err}"
                    )));
                }
            },
        };
        if proxy_active_for_relay && effective_mode == ConnectionMode::P2pOnly {
            return Err(SessionEnd::fatal(
                "proxy_config_conflict: 当前已启用出站网络代理，与「仅 P2P 直连」模式冲突，请关闭代理或切换为自动/中继模式",
            ));
        }
        let grant_obtained_at = Instant::now();
        let mut initial_relay_token_consumed = false;
        let bg_p2p_cancel = Arc::new(AtomicBool::new(false));
        type BgP2pUpgradeRx =
            std::sync::mpsc::Receiver<Result<(Box<dyn Transport>, Option<String>), String>>;
        let mut bg_p2p_upgrade_rx: Option<BgP2pUpgradeRx> = None;

        let allow_lan_and_p2p =
            effective_mode != ConnectionMode::TcpRelay && !proxy_active_for_relay;
        if allow_lan_and_p2p && !disconnect_flag.load(Ordering::Acquire) {
            let lan_addrs = collect_lan_candidate_addrs(&cfg, grant);
            let p2p_candidates = build_client_p2p_candidates(grant);
            let has_lan = !lan_addrs.is_empty();
            let has_p2p = !p2p::parse_candidate_addrs(&p2p_candidates).is_empty();
            let has_relay = !grant.relay_addr.is_empty() && !grant.relay_token.is_empty();
            let use_relay_first =
                effective_mode == ConnectionMode::Auto && has_relay && (has_lan || has_p2p);

            if use_relay_first {
                let relay_first_delay = Duration::from_millis(
                    u64::from(grant.relay_fallback_after_ms.unwrap_or(400)).clamp(50, 5_000),
                );
                let quic_mtls_c = if cfg.encrypt_connection {
                    peer_bundle
                        .as_ref()
                        .and_then(|b| b.to_quic_mtls_config().ok())
                } else {
                    None
                };
                let encrypt_conn = cfg.encrypt_connection;
                let lan_addrs_c = lan_addrs.clone();
                let p2p_cands_c = p2p_candidates.clone();
                let disc_c = Arc::clone(&disconnect_flag);
                let bg_c = Arc::clone(&bg_p2p_cancel);
                let direct_cancel = Arc::new(AtomicBool::new(false));
                let dc_watch = Arc::clone(&direct_cancel);
                type PendingDirectTransport = (
                    Box<dyn Transport>,
                    &'static str,
                    Option<&'static str>,
                    Option<String>,
                    SocketAddr,
                    Duration,
                );
                let (direct_tx, direct_rx) = std::sync::mpsc::channel::<
                    Result<PendingDirectTransport, DirectTierRaceError>,
                >();

                let _ = thread::Builder::new()
                    .name("rc-client-direct-race".to_string())
                    .spawn(move || {
                        let watch_stop = Arc::new(AtomicBool::new(false));
                        let ws_c = Arc::clone(&watch_stop);
                        let watcher = thread::spawn(move || {
                            while !ws_c.load(Ordering::Acquire) {
                                if disc_c.load(Ordering::Acquire) || bg_c.load(Ordering::Acquire) {
                                    dc_watch.store(true, Ordering::Release);
                                    break;
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                        });

                        const BG_P2P_PUNCH_TIMEOUT: Duration = Duration::from_secs(14);
                        let res = if has_lan && has_p2p {
                            match race_lan_and_p2p_with(
                                encrypt_conn,
                                &direct_cancel,
                                |lan_cancel| {
                                    dial_lan_addrs_happy_eyeballs(
                                        &lan_addrs_c,
                                        quic_mtls_c.as_ref(),
                                        encrypt_conn,
                                        lan_cancel,
                                    )
                                },
                                |p2p_cancel| {
                                    let port_hold =
                                        crate::signal_client::acquire_local_udp_port_for_p2p(
                                            p2p_cands_c.local_udp_port,
                                        );
                                    match p2p::attempt_p2p_quic_client_mtls(
                                        &p2p_cands_c,
                                        BG_P2P_PUNCH_TIMEOUT,
                                        p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                                        p2p_cancel,
                                        quic_mtls_c.as_ref(),
                                    ) {
                                        Ok(p2p_conn) => {
                                            let held = crate::signal_client::P2pHeldTransport::new(
                                                p2p_conn, port_hold,
                                            );
                                            let fp = held
                                                .peer_mtls_identity()
                                                .map(|id| id.cert_fingerprint_sha256);
                                            Ok((Box::new(held) as Box<dyn Transport>, fp))
                                        }
                                        Err(e) => {
                                            drop(port_hold);
                                            Err((e, None))
                                        }
                                    }
                                },
                            ) {
                                Ok(DirectTierWinner::Lan {
                                    transport,
                                    peer_cert_fingerprint,
                                    lan_addr,
                                    ..
                                }) => Ok((
                                    transport,
                                    "UDP LAN",
                                    None,
                                    peer_cert_fingerprint,
                                    lan_addr,
                                    LAN_DIRECT_HANDSHAKE_TIMEOUT,
                                )),
                                Ok(DirectTierWinner::P2p {
                                    transport,
                                    peer_cert_fingerprint,
                                }) => Ok((
                                    transport,
                                    "UDP P2P",
                                    Some("(P2P 直连)"),
                                    peer_cert_fingerprint,
                                    cfg.connect_addr,
                                    P2P_DIRECT_HANDSHAKE_TIMEOUT,
                                )),
                                Err(e) => Err(e),
                            }
                        } else if has_lan {
                            dial_lan_addrs_happy_eyeballs(
                                &lan_addrs_c,
                                quic_mtls_c.as_ref(),
                                encrypt_conn,
                                &direct_cancel,
                            )
                            .map(|(t, fp, lan_addr)| {
                                (
                                    t,
                                    "UDP LAN",
                                    None,
                                    fp,
                                    lan_addr,
                                    LAN_DIRECT_HANDSHAKE_TIMEOUT,
                                )
                            })
                            .map_err(|(reasons, fatal)| match fatal {
                                Some(m) => DirectTierRaceError::FatalMtls(m),
                                None => DirectTierRaceError::NonFatal(reasons),
                            })
                        } else {
                            let port_hold = crate::signal_client::acquire_local_udp_port_for_p2p(
                                p2p_cands_c.local_udp_port,
                            );
                            match p2p::attempt_p2p_quic_client_mtls(
                                &p2p_cands_c,
                                BG_P2P_PUNCH_TIMEOUT,
                                p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                                &direct_cancel,
                                quic_mtls_c.as_ref(),
                            ) {
                                Ok(p2p_conn) => {
                                    let held = crate::signal_client::P2pHeldTransport::new(
                                        p2p_conn, port_hold,
                                    );
                                    let fp = held
                                        .peer_mtls_identity()
                                        .map(|id| id.cert_fingerprint_sha256);
                                    Ok((
                                        Box::new(held) as Box<dyn Transport>,
                                        "UDP P2P",
                                        Some("(P2P 直连)"),
                                        fp,
                                        cfg.connect_addr,
                                        P2P_DIRECT_HANDSHAKE_TIMEOUT,
                                    ))
                                }
                                Err(e) => {
                                    drop(port_hold);
                                    if encrypt_conn && is_mtls_cert_or_config_error(&e) {
                                        Err(DirectTierRaceError::FatalMtls(format!(
                                            "P2P mTLS 证书校验失败（严禁静默降级）: {e}"
                                        )))
                                    } else {
                                        Err(DirectTierRaceError::NonFatal(vec![e]))
                                    }
                                }
                            }
                        };
                        watch_stop.store(true, Ordering::Release);
                        let _ = watcher.join();
                        let _ = direct_tx.send(res);
                    });

                // t = 0..400ms 优先等待直连；超时未成行则于 t = 400ms 启动 Relay 同步起流
                let relay_start_at = Instant::now() + relay_first_delay;
                let mut direct_rx_slot = Some(direct_rx);
                let mut direct_finished_early = false;
                while Instant::now() < relay_start_at && !disconnect_flag.load(Ordering::Acquire) {
                    if let Some(ref rx) = direct_rx_slot {
                        match rx.try_recv() {
                            Ok(Ok((t, lbl, suffix, fp, p_addr, hs_to))) => {
                                direct_rx_slot = None;
                                match attempt_tier_handshake(
                                    SelectedRelayPath {
                                        transport: t,
                                        relay_shutdown: None,
                                        transport_label: lbl,
                                        backend_suffix: suffix,
                                        mtls_active: cfg.encrypt_connection,
                                        peer_cert_fingerprint: fp,
                                    },
                                    p_addr,
                                    hs_to,
                                    true,
                                ) {
                                    TierHandshakeResult::Ready(sess) => {
                                        ready = Some(*sess);
                                        bg_p2p_cancel.store(true, Ordering::Release);
                                        break;
                                    }
                                    TierHandshakeResult::Fallback(reason) => {
                                        direct_fail_reasons.push(reason);
                                        direct_finished_early = true;
                                        break;
                                    }
                                    TierHandshakeResult::Abort(res) => return res,
                                }
                            }
                            Ok(Err(DirectTierRaceError::FatalMtls(msg))) => {
                                bg_p2p_cancel.store(true, Ordering::Release);
                                return Err(SessionEnd::fatal(msg));
                            }
                            Ok(Err(DirectTierRaceError::Cancelled)) => {
                                direct_rx_slot = None;
                                direct_finished_early = true;
                                break;
                            }
                            Ok(Err(DirectTierRaceError::NonFatal(reasons))) => {
                                direct_fail_reasons.extend(reasons);
                                direct_rx_slot = None;
                                direct_finished_early = true;
                                break;
                            }
                            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                direct_rx_slot = None;
                                direct_finished_early = true;
                                break;
                            }
                            Err(std::sync::mpsc::TryRecvError::Empty) => {
                                thread::sleep(Duration::from_millis(5));
                            }
                        }
                    } else {
                        break;
                    }
                }

                if ready.is_none() && !disconnect_flag.load(Ordering::Acquire) {
                    let _ = direct_finished_early;
                    let relay_addr_c = grant.relay_addr.clone();
                    let relay_tok_c = grant.relay_token.clone();
                    let peer_b_c = peer_bundle.clone();
                    let encrypt_c = cfg.encrypt_connection;
                    let relay_cancel = Arc::new(AtomicBool::new(false));
                    let rc_c = Arc::clone(&relay_cancel);
                    let dc_c = Arc::clone(&disconnect_flag);
                    let (relay_tx, relay_rx) = std::sync::mpsc::channel();
                    let _ = thread::Builder::new()
                        .name("rc-client-relay-first".to_string())
                        .spawn(move || {
                            let peer_b_ref = peer_b_c.as_ref();
                            let r = dial_relay_transport(
                                &relay_addr_c,
                                &relay_tok_c,
                                peer_b_ref,
                                encrypt_c,
                                rc_c,
                                &dc_c,
                            );
                            let _ = relay_tx.send(r);
                        });

                    let mut relay_done_err: Option<Result<SessionEnd, SessionEnd>> = None;
                    let mut relay_rx_open = true;
                    let mut pending_direct: Option<PendingDirectTransport> = None;
                    let mut relay_hs_rx: Option<mpsc::Receiver<TierHandshakeResult>> = None;
                    let mut relay_hs_shutdown: Option<crate::relay_transport::RelayShutdownHandle> =
                        None;

                    let loop_outcome: Option<Result<SessionEnd, SessionEnd>> = std::thread::scope(
                        |scope| {
                            while ready.is_none() && !disconnect_flag.load(Ordering::Acquire) {
                                if let Some(ref drx) = direct_rx_slot {
                                    match drx.try_recv() {
                                        Ok(Ok((t, lbl, suffix, fp, p_addr, hs_to))) => {
                                            direct_rx_slot = None;
                                            if relay_hs_rx.is_some() {
                                                // Relay 应用层握手已在途：保留已打通直连，若 Relay 失败立即回退直连，若 Relay 成功则立即交接无损升级
                                                pending_direct =
                                                    Some((t, lbl, suffix, fp, p_addr, hs_to));
                                            } else {
                                                relay_cancel.store(true, Ordering::Release);
                                                match attempt_tier_handshake(
                                                    SelectedRelayPath {
                                                        transport: t,
                                                        relay_shutdown: None,
                                                        transport_label: lbl,
                                                        backend_suffix: suffix,
                                                        mtls_active: cfg.encrypt_connection,
                                                        peer_cert_fingerprint: fp,
                                                    },
                                                    p_addr,
                                                    hs_to,
                                                    relay_rx_open,
                                                ) {
                                                    TierHandshakeResult::Ready(sess) => {
                                                        ready = Some(*sess);
                                                        break;
                                                    }
                                                    TierHandshakeResult::Fallback(r) => {
                                                        direct_fail_reasons.push(r);
                                                    }
                                                    TierHandshakeResult::Abort(res) => {
                                                        return Some(res);
                                                    }
                                                }
                                            }
                                        }
                                        Ok(Err(DirectTierRaceError::FatalMtls(msg))) => {
                                            relay_cancel.store(true, Ordering::Release);
                                            bg_p2p_cancel.store(true, Ordering::Release);
                                            if let Some(h) = relay_hs_shutdown.take() {
                                                h.shutdown();
                                            }
                                            return Some(Err(SessionEnd::fatal(msg)));
                                        }
                                        Ok(Err(DirectTierRaceError::Cancelled)) => {
                                            direct_rx_slot = None;
                                        }
                                        Ok(Err(DirectTierRaceError::NonFatal(reasons))) => {
                                            direct_fail_reasons.extend(reasons);
                                            direct_rx_slot = None;
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                            direct_rx_slot = None;
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                                    }
                                }

                                if relay_rx_open && relay_hs_rx.is_none() {
                                    match relay_rx.try_recv() {
                                        Ok(Ok(relay_path)) => {
                                            initial_relay_token_consumed = true;
                                            relay_rx_open = false;
                                            relay_hs_shutdown = relay_path.relay_shutdown.clone();
                                            if let Some(ref handle) = relay_path.relay_shutdown {
                                                *relay_interrupt
                                                    .lock()
                                                    .unwrap_or_else(|e| e.into_inner()) = Some(
                                                    ActiveRelayInterrupt::Connected(handle.clone()),
                                                );
                                            }
                                            let (hs_tx, hs_rx) = mpsc::sync_channel(1);
                                            let peer_c = cfg.connect_addr;
                                            let att = &attempt_tier_handshake;
                                            scope.spawn(move || {
                                                let r = att(
                                                    relay_path,
                                                    peer_c,
                                                    Duration::from_secs(10),
                                                    true,
                                                );
                                                let _ = hs_tx.send(r);
                                            });
                                            relay_hs_rx = Some(hs_rx);
                                        }
                                        Ok(Err(err_res)) => {
                                            relay_done_err = Some(err_res);
                                            relay_rx_open = false;
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                            relay_rx_open = false;
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                                    }
                                }

                                if let Some(ref hs_rx) = relay_hs_rx {
                                    match hs_rx.try_recv() {
                                        Ok(TierHandshakeResult::Ready(sess)) => {
                                            relay_hs_rx = None;
                                            relay_hs_shutdown = None;
                                            ready = Some(*sess);
                                            if let Some((t, _l, _s, fp, _, _)) =
                                                pending_direct.take()
                                            {
                                                let (up_tx, up_rx) = std::sync::mpsc::channel();
                                                let _ = up_tx.send(Ok((t, fp)));
                                                bg_p2p_upgrade_rx = Some(up_rx);
                                            } else if let Some(bg_drx) = direct_rx_slot.take() {
                                                let (up_tx, up_rx) = std::sync::mpsc::channel();
                                                let bg_c2 = Arc::clone(&bg_p2p_cancel);
                                                let disc_c2 = Arc::clone(&disconnect_flag);
                                                let _ = thread::Builder::new()
                                                    .name("rc-client-bg-p2p-wait".to_string())
                                                    .spawn(move || {
                                                        while !bg_c2.load(Ordering::Acquire)
                                                            && !disc_c2.load(Ordering::Acquire)
                                                        {
                                                            match bg_drx.recv_timeout(
                                                                Duration::from_millis(50),
                                                            ) {
                                                                Ok(Ok((t, _l, _s, fp, _, _))) => {
                                                                    let _ = up_tx.send(Ok((t, fp)));
                                                                    break;
                                                                }
                                                                Ok(Err(DirectTierRaceError::FatalMtls(e))) => {
                                                                    let _ = up_tx.send(Err(e));
                                                                    break;
                                                                }
                                                                Ok(Err(DirectTierRaceError::Cancelled)) => break,
                                                                Ok(Err(DirectTierRaceError::NonFatal(reasons))) => {
                                                                    let _ = up_tx.send(Err(reasons.join("；")));
                                                                    break;
                                                                }
                                                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                                                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                                                            }
                                                        }
                                                    });
                                                bg_p2p_upgrade_rx = Some(up_rx);
                                            }
                                            break;
                                        }
                                        Ok(TierHandshakeResult::Fallback(r)) => {
                                            relay_hs_rx = None;
                                            relay_hs_shutdown = None;
                                            relay_done_err = Some(Err(SessionEnd::fatal(format!(
                                                "连接/握手失败: {r}"
                                            ))));
                                            if let Some((t, lbl, suffix, fp, p_addr, hs_to)) =
                                                pending_direct.take()
                                            {
                                                match attempt_tier_handshake(
                                                    SelectedRelayPath {
                                                        transport: t,
                                                        relay_shutdown: None,
                                                        transport_label: lbl,
                                                        backend_suffix: suffix,
                                                        mtls_active: cfg.encrypt_connection,
                                                        peer_cert_fingerprint: fp,
                                                    },
                                                    p_addr,
                                                    hs_to,
                                                    direct_rx_slot.is_some(),
                                                ) {
                                                    TierHandshakeResult::Ready(sess) => {
                                                        ready = Some(*sess);
                                                        break;
                                                    }
                                                    TierHandshakeResult::Fallback(dr) => {
                                                        direct_fail_reasons.push(dr);
                                                    }
                                                    TierHandshakeResult::Abort(res) => {
                                                        return Some(res);
                                                    }
                                                }
                                            }
                                        }
                                        Ok(TierHandshakeResult::Abort(res)) => {
                                            relay_hs_rx = None;
                                            relay_hs_shutdown = None;
                                            return Some(res);
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                            relay_hs_rx = None;
                                            relay_hs_shutdown = None;
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                                    }
                                }

                                if direct_rx_slot.is_none()
                                    && pending_direct.is_none()
                                    && !relay_rx_open
                                    && relay_hs_rx.is_none()
                                {
                                    if let Some(err_res) = relay_done_err {
                                        return Some(err_res);
                                    }
                                    break;
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                            if let Some(h) = relay_hs_shutdown.take() {
                                h.shutdown();
                            }
                            None
                        },
                    );
                    if let Some(res) = loop_outcome {
                        return res;
                    }
                }
            } else {
                let p2p_punch_timeout = punch_timeout_for_mode(effective_mode);
                let direct_winner: Option<DirectTierWinner> = if has_lan && has_p2p {
                    let quic_mtls_ref = quic_mtls.as_ref();
                    let encrypt_conn = cfg.encrypt_connection;
                    let disc_ref = &disconnect_flag;
                    match race_lan_and_p2p_with(
                        encrypt_conn,
                        disc_ref,
                        |lan_cancel| {
                            dial_lan_addrs_happy_eyeballs(
                                &lan_addrs,
                                quic_mtls_ref,
                                encrypt_conn,
                                lan_cancel,
                            )
                        },
                        |p2p_cancel| {
                            dial_p2p_held_transport(
                                &p2p_candidates,
                                quic_mtls_ref,
                                encrypt_conn,
                                p2p_cancel,
                                p2p_punch_timeout,
                            )
                        },
                    ) {
                        Ok(winner) => Some(winner),
                        Err(DirectTierRaceError::FatalMtls(msg)) => {
                            return Err(SessionEnd::fatal(msg));
                        }
                        Err(DirectTierRaceError::Cancelled) => {
                            return Ok(SessionEnd::fatal("用户主动断开"));
                        }
                        Err(DirectTierRaceError::NonFatal(reasons)) => {
                            direct_fail_reasons.extend(reasons);
                            None
                        }
                    }
                } else if has_lan {
                    match dial_lan_addrs_happy_eyeballs(
                        &lan_addrs,
                        quic_mtls.as_ref(),
                        cfg.encrypt_connection,
                        &disconnect_flag,
                    ) {
                        Ok((t, fp, lan_addr)) => Some(DirectTierWinner::Lan {
                            transport: t,
                            peer_cert_fingerprint: fp,
                            lan_addr,
                            p2p_already_failed: false,
                        }),
                        Err((_reasons, Some(fatal_msg))) => {
                            return Err(SessionEnd::fatal(fatal_msg));
                        }
                        Err((reasons, None)) => {
                            if disconnect_flag.load(Ordering::Acquire) {
                                return Ok(SessionEnd::fatal("用户主动断开"));
                            }
                            direct_fail_reasons.extend(reasons);
                            None
                        }
                    }
                } else if has_p2p {
                    match dial_p2p_held_transport(
                        &p2p_candidates,
                        quic_mtls.as_ref(),
                        cfg.encrypt_connection,
                        &disconnect_flag,
                        p2p_punch_timeout,
                    ) {
                        Ok((transport, peer_cert_fingerprint)) => Some(DirectTierWinner::P2p {
                            transport,
                            peer_cert_fingerprint,
                        }),
                        Err((err, Some(fatal_mtls))) => {
                            let _ = err;
                            return Err(SessionEnd::fatal(fatal_mtls));
                        }
                        Err((err, None)) => {
                            direct_fail_reasons.push(err);
                            None
                        }
                    }
                } else {
                    if effective_mode == ConnectionMode::P2pOnly {
                        direct_fail_reasons.push("无可用直连或 P2P 候选地址".to_string());
                    }
                    None
                };

                if let Some(winner) = direct_winner {
                    let mut retry_p2p_on_lan_fallback = false;
                    let (path, peer_addr, handshake_timeout) = match winner {
                        DirectTierWinner::Lan {
                            transport,
                            peer_cert_fingerprint,
                            lan_addr,
                            p2p_already_failed,
                        } => {
                            retry_p2p_on_lan_fallback = !p2p_already_failed;
                            (
                                SelectedRelayPath {
                                    transport,
                                    relay_shutdown: None,
                                    transport_label: "UDP LAN",
                                    backend_suffix: None,
                                    mtls_active: cfg.encrypt_connection,
                                    peer_cert_fingerprint,
                                },
                                lan_addr,
                                LAN_DIRECT_HANDSHAKE_TIMEOUT,
                            )
                        }
                        DirectTierWinner::P2p {
                            transport,
                            peer_cert_fingerprint,
                        } => (
                            SelectedRelayPath {
                                transport,
                                relay_shutdown: None,
                                transport_label: "UDP P2P",
                                backend_suffix: Some("(P2P 直连)"),
                                mtls_active: cfg.encrypt_connection,
                                peer_cert_fingerprint,
                            },
                            cfg.connect_addr,
                            P2P_DIRECT_HANDSHAKE_TIMEOUT,
                        ),
                    };
                    match attempt_tier_handshake(path, peer_addr, handshake_timeout, true) {
                        TierHandshakeResult::Ready(session) => {
                            ready = Some(*session);
                        }
                        TierHandshakeResult::Fallback(reason) => {
                            direct_fail_reasons.push(reason);
                            update_tx.push(SessionUpdate::Connecting {
                                phase: ConnectPhase::Connecting,
                                watch_only: live_watch_only.load(Ordering::Acquire),
                            });
                            if retry_p2p_on_lan_fallback
                                && has_p2p
                                && !disconnect_flag.load(Ordering::Acquire)
                            {
                                match dial_p2p_held_transport(
                                    &p2p_candidates,
                                    quic_mtls.as_ref(),
                                    cfg.encrypt_connection,
                                    &disconnect_flag,
                                    p2p_punch_timeout,
                                ) {
                                    Ok((transport, peer_cert_fingerprint)) => {
                                        let p2p_path = SelectedRelayPath {
                                            transport,
                                            relay_shutdown: None,
                                            transport_label: "UDP P2P",
                                            backend_suffix: Some("(P2P 直连)"),
                                            mtls_active: cfg.encrypt_connection,
                                            peer_cert_fingerprint,
                                        };
                                        match attempt_tier_handshake(
                                            p2p_path,
                                            cfg.connect_addr,
                                            P2P_DIRECT_HANDSHAKE_TIMEOUT,
                                            true,
                                        ) {
                                            TierHandshakeResult::Ready(session) => {
                                                ready = Some(*session);
                                            }
                                            TierHandshakeResult::Fallback(p2p_reason) => {
                                                direct_fail_reasons.push(p2p_reason);
                                                update_tx.push(SessionUpdate::Connecting {
                                                    phase: ConnectPhase::Connecting,
                                                    watch_only: live_watch_only
                                                        .load(Ordering::Acquire),
                                                });
                                            }
                                            TierHandshakeResult::Abort(res) => return res,
                                        }
                                    }
                                    Err((_, Some(fatal_mtls))) => {
                                        return Err(SessionEnd::fatal(fatal_mtls));
                                    }
                                    Err((err, None)) => {
                                        direct_fail_reasons.push(err);
                                    }
                                }
                            }
                        }
                        TierHandshakeResult::Abort(res) => return res,
                    }
                }
            }
        }

        if ready.is_none() && disconnect_flag.load(Ordering::Acquire) {
            return Ok(SessionEnd::fatal("用户主动断开"));
        }

        // `P2pOnly` 模式严禁回退至 Tier 3 TCP Relay，直接返回明确不可恢复错误。
        if ready.is_none() && effective_mode == ConnectionMode::P2pOnly {
            let detail = if direct_fail_reasons.is_empty() {
                "未命中局域网地址且对端无可用 P2P 候选地址".to_string()
            } else {
                direct_fail_reasons.join("；")
            };
            return Err(SessionEnd::fatal(format!(
                "P2P 直连失败（当前为「仅 P2P」模式，未回退中继）：{detail}"
            )));
        }

        // Tier 3：P2P 失败/未命中或强制中继 → 回退 `:21117` 中继（有 mtls_config 强制外层 mTLS；encrypt_connection 再叠加内层 E2EE mTLS）。
        let ReadySignalingSession {
            client,
            negotiated,
            transport_label: chosen_transport_label,
            backend_suffix,
            mtls_active,
            peer_cert_fingerprint: peer_fp,
            switch_handle,
        } = match ready {
            Some(session) => session,
            None => {
                initial_relay_token_consumed = true;
                let relay_path = dial_relay_transport(
                    &grant.relay_addr,
                    &grant.relay_token,
                    peer_bundle.as_ref(),
                    cfg.encrypt_connection,
                    Arc::clone(&dial_cancel),
                    &disconnect_flag,
                )
                .map_err(|end_res| match end_res {
                    Ok(e) => Err(e),
                    Err(e) => Err(e),
                });
                let relay_path = match relay_path {
                    Ok(p) => p,
                    Err(Ok(end)) | Err(Err(end)) => {
                        return if end.recoverable { Ok(end) } else { Err(end) };
                    }
                };
                if let Some(ref shutdown_handle) = relay_path.relay_shutdown {
                    *relay_interrupt.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(ActiveRelayInterrupt::Connected(shutdown_handle.clone()));
                }
                if disconnect_flag.load(Ordering::Acquire) {
                    return Ok(SessionEnd::fatal("用户主动断开"));
                }
                match attempt_tier_handshake(
                    relay_path,
                    cfg.connect_addr,
                    Duration::from_secs(10),
                    false,
                ) {
                    TierHandshakeResult::Ready(session) => *session,
                    TierHandshakeResult::Fallback(reason) => {
                        return Err(SessionEnd::fatal(format!("连接/握手失败: {reason}")));
                    }
                    TierHandshakeResult::Abort(res) => return res,
                }
            }
        };
        (
            client,
            negotiated,
            chosen_transport_label,
            backend_suffix,
            mtls_active,
            peer_fp,
            Some(switch_handle),
            bg_p2p_upgrade_rx,
            Some(bg_p2p_cancel),
            grant_obtained_at,
            initial_relay_token_consumed,
            proxy_active_for_relay,
            effective_mode,
        )
    } else {
        let direct_mtls = if cfg.encrypt_connection {
            let bundle = cfg.mtls_config.as_ref().ok_or_else(|| {
                SessionEnd::fatal("已开启「加密连接 (mTLS)」，但缺少设备证书配置")
            })?;
            Some(bundle.to_quic_mtls_config().map_err(SessionEnd::fatal)?)
        } else {
            None
        };
        let direct_peer_fp: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

        let server_cert = dev_server_cert_pem();
        let mut client = ClientSession::new(
            make_client_cfg(cfg.connect_addr, Duration::from_secs(10)),
            DEV_CERT_PEM,
            DEV_KEY_PEM,
            server_cert,
            DEV_SERVER_NAME,
            clock,
        )
        .map_err(|e| SessionEnd::fatal(format!("会话构造失败: {e}")))?;
        if let Some(cb) = create_clipboard_backend(cfg.prefer_hardware) {
            client.enable_clipboard(Box::new(ToggleableClipboardBackend::new(
                cb,
                Arc::clone(&clipboard_enabled_flag),
            )));
        }

        // ── 自定义 connect 工厂：每次建连/重连均丢弃旧端点并重新绑定 `0.0.0.0:0`（避免切网后旧 UDP 套接字失效） ──
        {
            let peer_addr = cfg.connect_addr;
            let pending = Arc::clone(&pending_control);
            let upd = Arc::clone(&update_tx);
            let disc = Arc::clone(&disconnect_flag);
            let started = Arc::clone(&streaming_started);
            let fp_slot = Arc::clone(&direct_peer_fp);
            let watch_only_flag = Arc::clone(&live_watch_only);
            let mut first_connect = true;
            client.set_connect_factory(Box::new(move || {
                if disc.load(Ordering::Acquire) {
                    return Err(rc_types::Error::Network("用户主动断开".to_string()));
                }
                if first_connect {
                    upd.push(SessionUpdate::Connecting {
                        phase: ConnectPhase::EndpointCreating,
                        watch_only: watch_only_flag.load(Ordering::Acquire),
                    });
                }
                let identity = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM)?;
                let net = NetConfig {
                    role: Role::Controller,
                    local_addr: "0.0.0.0:0"
                        .parse()
                        .expect("0.0.0.0:0 is a valid socket addr"),
                    peer_addr: Some(peer_addr),
                    mtu: rc_session::DEFAULT_SESSION_MTU,
                };
                let endpoint = QuicEndpoint::new(&net, &identity)?;
                if first_connect {
                    upd.push(SessionUpdate::Connecting {
                        phase: ConnectPhase::Connecting,
                        watch_only: watch_only_flag.load(Ordering::Acquire),
                    });
                }
                let transport = if let Some(ref mtls_cfg) = direct_mtls {
                    let t = endpoint.connect_mtls_cancelable(
                        peer_addr,
                        mtls_cfg,
                        "",
                        Duration::from_secs(10),
                        &disc,
                    )?;
                    *fp_slot.lock().unwrap_or_else(|e| e.into_inner()) =
                        t.peer_mtls_identity().map(|id| id.cert_fingerprint_sha256);
                    t
                } else {
                    let certs = Identity::certs_from_pem(dev_server_cert_pem())?;
                    endpoint.connect_cancelable(
                        peer_addr,
                        &certs,
                        DEV_SERVER_NAME,
                        Duration::from_secs(10),
                        &disc,
                    )?
                };
                if first_connect {
                    first_connect = false;
                    upd.push(SessionUpdate::Connecting {
                        phase: ConnectPhase::AwaitingWelcome,
                        watch_only: watch_only_flag.load(Ordering::Acquire),
                    });
                }
                Ok(Box::new(BridgeTransport {
                    inner: Box::new(LanQuicTransport {
                        transport,
                        _endpoint: endpoint,
                    }),
                    pending_control: Arc::clone(&pending),
                    disconnect_flag: Arc::clone(&disc),
                    relay_shutdown: None,
                    streaming_started: Arc::clone(&started),
                }))
            }));
        }

        // ── 管线工厂：prefer_hardware 时优先 VT + 离屏 MetalRenderer，失败降级假后端；tools_only 走轻量占位管线 ──
        client.set_pipeline_factory_for(make_pipeline_factory(None));

        // ── 连接 + 握手 ──
        let negotiated = match client.connect_and_handshake() {
            Ok(n) => n,
            Err(e) => {
                if disconnect_flag.load(Ordering::Acquire) {
                    return Ok(SessionEnd::fatal("用户主动断开"));
                }
                return Err(SessionEnd::fatal(format!("连接/握手失败: {e}")));
            }
        };
        let fp = direct_peer_fp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        (
            client,
            negotiated,
            "UDP LAN",
            None,
            cfg.encrypt_connection,
            fp,
            None,
            None,
            None,
            Instant::now(),
            false,
            false,
            ConnectionMode::P2pOnly,
        )
    };
    client.set_peer_idle_timeout_us(ClientSession::PEER_IDLE_TIMEOUT_US);
    streaming_started.store(true, Ordering::Release);
    let _activity =
        crate::platform::begin_latency_critical_activity("RabbitControl 远控会话", true);
    let mut backend = backend_label
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut is_hardware_decoder = is_hw_decoder_slot.load(Ordering::Acquire);

    let live_wo = live_watch_only.load(Ordering::Acquire);
    update_tx.push(SessionUpdate::Connecting {
        phase: ConnectPhase::FirstFramePending,
        watch_only: live_wo,
    });
    update_tx.push(SessionUpdate::Negotiated {
        width: negotiated.width,
        height: negotiated.height,
        fps: negotiated.fps,
        bitrate_bps: negotiated.bitrate_bps,
        backend: backend.clone(),
        watch_only: live_wo,
        transport: transport_label.to_string(),
        mtls_active,
        peer_cert_fingerprint,
    });

    // 音频播放状态：按需懒初始化并跟踪采样率/声道数（M9），若初始关闭音频则立即通知主机端静音以节省带宽。
    let mut audio_player: Option<Box<dyn AudioPlayer>> = None;
    let mut audio_player_format: Option<(u32, u8)> = None;
    let mut audio_muted = !cfg.audio_enabled;
    let mut pending_audio_ctrl: Option<Vec<u8>> = if audio_muted {
        Some(encode_audio_ctrl_muted(true))
    } else {
        None
    };

    // 初始 HUD 快照（prev = None → fps/bitrate 均为 0.0）。
    let initial_sample = sample_hud(&client, &clock_reader, negotiated);
    update_tx.push(SessionUpdate::Hud(HudSnapshot::derive_with_transport(
        None,
        &initial_sample,
        transport_label,
    )));
    let mut prev_hud = initial_sample;
    let mut last_hud_at = Instant::now();
    let mut stream_started_at = Instant::now();
    let mut first_frame_logged = false;
    let mut decode_error_logged = false;
    let mut last_portmap_poll_at = Instant::now();
    let mut last_portmap_snapshot: Vec<PortMapRuleSnapshot> = Vec::new();
    let mut pending_file_in: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_file_tx: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_term_tx: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_portmap_tx: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_display_tx = ZeroizingByteQueue::new();
    let mut pending_update_tx: VecDeque<(bool, Vec<u8>)> = VecDeque::new();
    let mut client_decode_caps =
        codec_selector::cached_or_platform_decode_caps(cfg.prefer_hardware && is_hardware_decoder);
    let mut client_supports_hevc = cfg.prefer_hardware
        && is_hardware_decoder
        && (rc_pipeline::platform_supports_hevc()
            || client_decode_caps
                .iter()
                .any(|c| c.codec == rc_encode::Codec::Hevc && c.hardware));
    let mut client_supports_av1 = cfg.prefer_hardware
        && is_hardware_decoder
        && client_decode_caps
            .iter()
            .any(|c| c.codec == rc_encode::Codec::Av1 && c.hardware);
    let mut active_codec = StreamCodec::H264;
    let mut user_pinned_codec: Option<StreamCodec> = None;
    let mut host_supports_hevc = false;
    let mut host_supports_ext_codec_flags = false;
    let mut host_codec_generation: u64 = 1;
    let mut pending_unrecovered_decode_failure: Option<(rc_encode::Codec, u64, String)> = None;
    let mut legacy_hevc_requested = false;
    let mut still_refinement_enabled = true;
    let mut pending_still_clear = false;
    let mut still_receiver =
        crate::still_refine::StillRefineReceiver::new(1, negotiated.width, negotiated.height);
    if cfg.tools_only {
        client.set_media_paused(true);
        if let Some(payload) =
            display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetMediaPaused { paused: true })
        {
            pending_display_tx.push_back(payload);
        }
    } else if let Some(payload) = display_ctrl::encode_display_ctrl(&build_client_media_caps_msg(
        &client_decode_caps,
        cfg.prefer_hardware && is_hardware_decoder,
        CodecSelectionPref::Auto,
    )) {
        pending_display_tx.push_back(payload);
    }
    let mut hud_width = negotiated.width;
    let mut hud_height = negotiated.height;
    let mut current_fps = negotiated.fps;
    let mut active_path_kind = switch_handle.as_ref().map_or_else(
        || path_kind_from_transport_label(transport_label),
        |h| h.active_kind(),
    );
    let mut path_monitor = RuntimePathMonitor::with_initial_path(
        HysteresisConfig::default(),
        active_path_kind,
        Instant::now(),
    );
    let mut last_path_sample_at = Instant::now();
    let mut runtime_switch_inflight: Option<u8> = None; // Some(1) = P2P->Relay degrade, Some(2) = Relay->P2P reprobe
    let mut last_seen_committed = switch_handle.as_ref().map_or(0, |h| h.switches_committed());
    let mut last_seen_aborted = switch_handle.as_ref().map_or(0, |h| h.switches_aborted());
    let mut degrade_rx: Option<std::sync::mpsc::Receiver<Result<CandidateTransport, String>>> =
        None;
    let mut reprobe_rx: Option<std::sync::mpsc::Receiver<Result<CandidateTransport, String>>> =
        None;
    let mut reprobe_answer_tx: Option<std::sync::mpsc::Sender<SwitchControlMsg>> = None;

    // ── 驱动循环（无 duration 上限，直到 Disconnect 或对端 Bye/错误）──
    let mut last_manual_bitrate_bps: Option<u32> = None;
    let mut relay_rtt_ctrl =
        sync_relay_rtt_ctrl_for_path(active_path_kind, negotiated.bitrate_bps, Instant::now());
    let mut last_busy = true;
    let mut epoch_sid = client.session_id();
    let mut disconnect_requested = false;
    let mut end_state = SessionEnd::fatal("会话已结束");
    let mut in_reconnecting = false;
    let mut reconnect_base_attempts: u32 = 0;
    let mut last_emitted_reconnect_attempt: u32 = 0;
    let mut last_stage_rect: Option<(u32, u32)> = None;
    let mut pending_desktop_upgrade = false;
    let mut update_relay = crate::updater::ControllerUpdateRelay::new();
    let mut awaiting_host_relay_finish = false;
    let mut active_update_request_id: u64 = 0;
    let mut peer_tool_perms = ToolPermissions::all_allowed();
    let mut last_local_tool_denied: [Option<Instant>; 8] = [None; 8];

    while client.state() != SessionState::Closed {
        // 若上一拍因异步解码线程持锁争用未能清空静止无损叠加层，每拍开头非阻塞重试直至实际清除完成。
        if pending_still_clear {
            try_clear_still_overlay(
                &renderer_handle,
                &mut still_receiver,
                &mut pending_still_clear,
            );
        }
        // 1) 处理来自 UI 的控制命令。
        for cmd in cmd_rx.drain_all() {
            match cmd {
                SessionCommand::Disconnect => {
                    disconnect_requested = true;
                }
                SessionCommand::SetBitrate { bps } => {
                    if bps > 0 && client.state() == SessionState::Streaming {
                        last_manual_bitrate_bps = Some(bps);
                        if let Some(ref mut ctrl) = relay_rtt_ctrl {
                            ctrl.on_manual_bitrate(bps, Instant::now());
                        }
                        let mut buf = Vec::new();
                        ControlMessage::SetBitrate {
                            bps,
                            reason: BitrateReason::Manual,
                        }
                        .encode(&mut buf);
                        pending_control
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push_back(buf);
                    }
                }
                SessionCommand::StageRect { width, height } => {
                    if width > 0 && height > 0 {
                        last_stage_rect = Some((width, height));
                        apply_stage_rect_to_slot(
                            &renderer_handle,
                            &renderer_pending_resize,
                            width,
                            height,
                        );
                    }
                }
                SessionCommand::SetClipboardEnabled { enabled } => {
                    let prev = clipboard_enabled_flag.swap(enabled, Ordering::AcqRel);
                    if enabled && !prev {
                        // 重新开启时重置基线，避免把暂停期间复制的内容突发外发。
                        client.reset_clipboard_epoch();
                    }
                }
                SessionCommand::SetAudioMuted { muted } => {
                    audio_muted = muted;
                    if let Some(ref mut player) = audio_player {
                        player.set_muted(muted);
                    }
                    pending_audio_ctrl = Some(encode_audio_ctrl_muted(muted));
                }
                SessionCommand::SetStreamParams { width, height, fps } => {
                    let (eff_w, eff_h) = if width > 0 && height > 0 {
                        (width, height)
                    } else {
                        (hud_width, hud_height)
                    };
                    let eff_fps = if fps > 0 { fps } else { current_fps };
                    // 当用户未手动锁定 H.264、切入超出 H.264 高刷甜点的分辨率/帧率组合且双端均支持 HEVC 时，
                    // 通过 SetStream 附带 codec="hevc" 原子升级，避免两次硬件管线重建与中间态 Capabilities 抖动。
                    let auto_hevc = active_codec == StreamCodec::H264
                        && user_pinned_codec != Some(StreamCodec::H264)
                        && host_supports_hevc
                        && client_supports_hevc
                        && !display_ctrl::is_within_high_refresh_sweet_spot(
                            eff_w,
                            eff_h,
                            eff_fps,
                            StreamCodec::H264,
                        );
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetStream {
                            width,
                            height,
                            fps,
                            codec: auto_hevc.then(|| StreamCodec::Hevc.as_str().to_string()),
                        })
                    {
                        pending_display_tx.push_back(payload);
                        if auto_hevc {
                            active_codec = StreamCodec::Hevc;
                        }
                    }
                }
                SessionCommand::SetCodec { codec } => {
                    if codec == StreamCodec::Hevc && !client_supports_hevc {
                        continue;
                    }
                    if codec == StreamCodec::Av1
                        && (!client_supports_av1 || !host_supports_ext_codec_flags)
                    {
                        continue;
                    }
                    user_pinned_codec = Some(codec);
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetCodec {
                            codec: codec.as_str().to_string(),
                        })
                    {
                        pending_display_tx.push_back(payload);
                        active_codec = codec;
                    }
                }
                SessionCommand::LockRemoteScreen => {
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::LockScreen)
                    {
                        pending_display_tx.push_back(payload);
                    }
                }
                SessionCommand::SetMediaPaused { paused } => {
                    if client.state() != SessionState::Streaming {
                        if paused {
                            pending_desktop_upgrade = false;
                            client.set_media_paused(true);
                            try_clear_still_overlay(
                                &renderer_handle,
                                &mut still_receiver,
                                &mut pending_still_clear,
                            );
                            update_tx.push(SessionUpdate::MediaState { paused: true });
                        } else {
                            // 重连期间缓存桌面升级/恢复意图，待重连回到 Streaming 后立即执行。
                            pending_desktop_upgrade = true;
                        }
                        continue;
                    }
                    if paused {
                        pending_desktop_upgrade = false;
                        client.set_media_paused(true);
                        try_clear_still_overlay(
                            &renderer_handle,
                            &mut still_receiver,
                            &mut pending_still_clear,
                        );
                        if let Some(payload) =
                            display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetMediaPaused {
                                paused: true,
                            })
                        {
                            pending_display_tx.push_back(payload);
                        }
                        update_tx.push(SessionUpdate::MediaState { paused: true });
                    } else {
                        pending_desktop_upgrade = false;
                        let surface = render_surface
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        let _ = try_resume_or_upgrade_desktop(
                            DesktopUpgradeCtx {
                                client: &mut client,
                                real_pipeline_built: &real_pipeline_built,
                                want_real_pipeline: &want_real_pipeline,
                                is_hw_decoder_slot: &is_hw_decoder_slot,
                                backend: &mut backend,
                                backend_label: &backend_label,
                                renderer_handle: &renderer_handle,
                                renderer_pending_resize: &renderer_pending_resize,
                                layer_lease: &layer_lease,
                                active_backend_suffix,
                                is_hardware_decoder: &mut is_hardware_decoder,
                                client_supports_hevc: &mut client_supports_hevc,
                                client_supports_av1: &mut client_supports_av1,
                                client_decode_caps: &mut client_decode_caps,
                                user_pinned_codec,
                                still_refinement_enabled,
                                prefer_hardware: cfg.prefer_hardware,
                                hud_width,
                                hud_height,
                                current_fps,
                                negotiated,
                                last_stage_rect,
                                stream_started_at: &mut stream_started_at,
                                first_frame_logged: &mut first_frame_logged,
                                decode_error_logged: &mut decode_error_logged,
                                pending_display_tx: &mut pending_display_tx,
                                update_tx: &update_tx,
                            },
                            |upgrade_pcfg| {
                                build_controller_pipeline(
                                    upgrade_pcfg,
                                    cfg.prefer_hardware,
                                    t0,
                                    surface.as_ref(),
                                )
                            },
                        );
                    }
                }
                SessionCommand::ProbeNow => {
                    if client.state() == SessionState::Streaming {
                        let now_us = u64::from((clock_reader)());
                        let _ = client.trigger_fast_probe(now_us);
                    }
                }
                SessionCommand::SetStillRefinementEnabled { enabled } => {
                    still_refinement_enabled = enabled;
                    if !enabled {
                        try_clear_still_overlay(
                            &renderer_handle,
                            &mut still_receiver,
                            &mut pending_still_clear,
                        );
                    }
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::StillRefineConfig {
                            enabled,
                        })
                    {
                        pending_display_tx.push_back(payload);
                    }
                }
            }
        }
        if client.state() == SessionState::Streaming {
            for mut dmsg in display_ctrl_rx.drain_all() {
                let mut is_update_trigger = false;
                match &mut dmsg {
                    DisplayControlMsg::UpdateTrigger {
                        target_version,
                        download_url,
                        expected_sha256,
                        asset_name,
                        mirror_url,
                        relay_fallback_allowed,
                        request_id,
                    } => {
                        active_update_request_id = active_update_request_id.wrapping_add(1);
                        if active_update_request_id == 0 {
                            active_update_request_id = 1;
                        }
                        *request_id = active_update_request_id;
                        is_update_trigger = true;
                        awaiting_host_relay_finish = false;
                        update_relay.arm_confirmed_request(crate::updater::RemoteUpdateRequest {
                            target_version: target_version.clone(),
                            download_url: download_url.clone(),
                            expected_sha256: expected_sha256.clone(),
                            asset_name: asset_name.clone(),
                            mirror_url: mirror_url.clone(),
                            relay_fallback_allowed: *relay_fallback_allowed,
                        });
                    }
                    DisplayControlMsg::UpdateCancel => {
                        awaiting_host_relay_finish = false;
                        update_relay.cancel_active_relay();
                        pending_update_tx.clear();
                    }
                    _ => {}
                }
                let is_update_msg = matches!(
                    &dmsg,
                    DisplayControlMsg::UpdateTrigger { .. }
                        | DisplayControlMsg::UpdateCancel
                        | DisplayControlMsg::UpdateChunkBegin { .. }
                        | DisplayControlMsg::UpdateChunkData { .. }
                        | DisplayControlMsg::UpdateChunkEnd
                        | DisplayControlMsg::UpdateChunkAbort { .. }
                );
                if let Some(payload) = display_ctrl::encode_display_ctrl(&dmsg) {
                    if is_update_msg {
                        pending_update_tx.push_back((is_update_trigger, payload));
                    } else {
                        while pending_display_tx.len() >= COMMAND_CHANNEL_CAP {
                            if let Some(mut evicted) = pending_display_tx.pop_front() {
                                use zeroize::Zeroize;
                                evicted.zeroize();
                            }
                        }
                        pending_display_tx.push_back(payload);
                    }
                }
            }
        }
        if disconnect_requested || disconnect_flag.load(Ordering::Acquire) {
            end_state = SessionEnd::fatal("用户主动断开");
            break;
        }

        // 2) 驱动会话状态机。
        match client.state() {
            SessionState::Streaming => {
                let now_us = u64::from((clock_reader)());
                client.pump_probes(now_us).map_err(|e| {
                    classify_runtime_err_end(
                        "探测泵失败",
                        &e,
                        disconnect_flag.load(Ordering::Acquire),
                    )
                })?;
                if client.state() != SessionState::Streaming {
                    continue;
                }
                if should_run_initial_bw_probe(active_path_kind) {
                    client.start_bw_probe(now_us).map_err(|e| {
                        classify_runtime_err_end(
                            "带宽粗测失败",
                            &e,
                            disconnect_flag.load(Ordering::Acquire),
                        )
                    })?;
                }
                if let Some(ref sw_h) = switch_handle {
                    for ev in sw_h.drain_path_events() {
                        transport_label = ev.label;
                        active_backend_suffix = ev.backend_suffix;
                        mtls_active = ev.mtls_active;
                        peer_cert_fingerprint = ev.peer_cert_fingerprint.clone();
                        active_path_kind = ev.kind;
                        let mut cur_neg = client.negotiated().unwrap_or(negotiated);
                        cur_neg.width = hud_width;
                        cur_neg.height = hud_height;
                        relay_rtt_ctrl = sync_relay_rtt_ctrl_for_path(
                            active_path_kind,
                            last_manual_bitrate_bps.unwrap_or(cur_neg.bitrate_bps),
                            Instant::now(),
                        );
                        update_tx.push(SessionUpdate::Negotiated {
                            width: cur_neg.width,
                            height: cur_neg.height,
                            fps: cur_neg.fps,
                            bitrate_bps: cur_neg.bitrate_bps,
                            backend: backend.clone(),
                            watch_only: live_watch_only.load(Ordering::Acquire),
                            transport: transport_label.to_string(),
                            mtls_active,
                            peer_cert_fingerprint: peer_cert_fingerprint.clone(),
                        });
                        let cur = sample_hud(&client, &clock_reader, cur_neg);
                        let snap = HudSnapshot::derive_with_transport(
                            Some(&prev_hud),
                            &cur,
                            transport_label,
                        );
                        update_tx.push(SessionUpdate::Hud(snap));
                        prev_hud = cur;
                    }

                    for ctrl_msg in sw_h.drain_control_msgs() {
                        if matches!(ctrl_msg, SwitchControlMsg::P2pReprobeAnswer { .. }) {
                            if let Some(ref ans_tx) = reprobe_answer_tx {
                                let _ = ans_tx.send(ctrl_msg);
                            }
                        }
                    }

                    let cur_committed = sw_h.switches_committed();
                    let cur_aborted = sw_h.switches_aborted();
                    if cur_committed > last_seen_committed || cur_aborted > last_seen_aborted {
                        let committed = cur_committed > last_seen_committed;
                        last_seen_committed = cur_committed;
                        last_seen_aborted = cur_aborted;
                        match runtime_switch_inflight.take() {
                            Some(1) => path_monitor.on_degrade_finished(committed, Instant::now()),
                            Some(2) => path_monitor.on_reprobe_finished(Instant::now()),
                            _ => {}
                        }
                    }

                    if let Some(ref up_rx) = bg_p2p_upgrade_rx {
                        match up_rx.try_recv() {
                            Ok(Ok((t, fp))) => {
                                bg_p2p_upgrade_rx = None;
                                path_monitor.on_reprobe_finished(Instant::now());
                                let _ = sw_h.initiate_switch(CandidateTransport {
                                    transport: t,
                                    kind: TransportPathKind::P2p,
                                    mtls_verified: !cfg.encrypt_connection || fp.is_some(),
                                    peer_cert_fingerprint: fp,
                                });
                            }
                            Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                bg_p2p_upgrade_rx = None;
                                path_monitor.on_reprobe_finished(Instant::now());
                            }
                            Err(std::sync::mpsc::TryRecvError::Empty) => {}
                        }
                    }

                    if let Some(ref drx) = degrade_rx {
                        match drx.try_recv() {
                            Ok(Ok(cand)) => {
                                degrade_rx = None;
                                if sw_h.initiate_switch(cand).is_err() {
                                    runtime_switch_inflight = None;
                                    path_monitor.on_degrade_finished(false, Instant::now());
                                }
                            }
                            Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                degrade_rx = None;
                                runtime_switch_inflight = None;
                                path_monitor.on_degrade_finished(false, Instant::now());
                            }
                            Err(std::sync::mpsc::TryRecvError::Empty) => {}
                        }
                    }

                    if let Some(ref rrx) = reprobe_rx {
                        match rrx.try_recv() {
                            Ok(Ok(cand)) => {
                                reprobe_rx = None;
                                reprobe_answer_tx = None;
                                let max_rtt_us = path_monitor
                                    .relay_rtt_ms()
                                    .map(|r| r.saturating_add(40).saturating_mul(1_000));
                                if sw_h
                                    .submit_candidate_with_hold(
                                        cand,
                                        true,
                                        DEFAULT_SWITCH_STAGE_TIMEOUT,
                                        HysteresisConfig::default().recovery_hold_window,
                                        max_rtt_us,
                                        Some(HysteresisConfig::default().recovery_max_loss),
                                    )
                                    .is_err()
                                {
                                    runtime_switch_inflight = None;
                                    path_monitor.on_reprobe_finished(Instant::now());
                                }
                            }
                            Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                reprobe_rx = None;
                                reprobe_answer_tx = None;
                                runtime_switch_inflight = None;
                                path_monitor.on_reprobe_finished(Instant::now());
                            }
                            Err(std::sync::mpsc::TryRecvError::Empty) => {}
                        }
                    }

                    if is_signaling_session
                        && runtime_mode == ConnectionMode::Auto
                        && !proxy_active_runtime
                        && bg_p2p_upgrade_rx.is_none()
                        && sw_h.is_switch_capable()
                        && !sw_h.is_switch_inflight()
                        && runtime_switch_inflight.is_none()
                        && last_path_sample_at.elapsed() >= Duration::from_millis(200)
                    {
                        last_path_sample_at = Instant::now();
                        let stats = client.net_stats();
                        match path_monitor.evaluate(
                            last_path_sample_at,
                            sw_h.active_kind(),
                            stats,
                            sw_h.rx_silence(),
                        ) {
                            HysteresisDecision::Hold => {}
                            HysteresisDecision::TriggerDegradeToRelay { .. } => {
                                if let Some(grant) = cfg.relay_grant.as_ref() {
                                    runtime_switch_inflight = Some(1);
                                    let (dtx, drx) = std::sync::mpsc::channel();
                                    degrade_rx = Some(drx);
                                    let use_initial = !initial_relay_token_consumed
                                        && grant_obtained_at.elapsed() < Duration::from_secs(50)
                                        && !grant.relay_addr.is_empty()
                                        && !grant.relay_token.is_empty();
                                    let init_addr = grant.relay_addr.clone();
                                    let init_tok = grant.relay_token.clone();
                                    let peer_b = prepare_peer_mtls_bundle(&cfg, grant);
                                    let sig_opt = cfg.signal_client.clone();
                                    let target_id_opt = cfg
                                        .target_device_id
                                        .clone()
                                        .filter(|s| !s.is_empty())
                                        .or_else(|| {
                                            (!grant.target_id.is_empty())
                                                .then(|| grant.target_id.clone())
                                        });
                                    let encrypt_c = cfg.encrypt_connection;
                                    let sw_clone = sw_h.clone();
                                    let disc_c = Arc::clone(&disconnect_flag);
                                    if use_initial {
                                        initial_relay_token_consumed = true;
                                    }
                                    let _ = thread::Builder::new()
                                        .name("rc-runtime-degrade".to_string())
                                        .spawn(move || {
                                            let (relay_addr, relay_token) = if use_initial {
                                                let _ = sw_clone.send_control_msg(
                                                    &SwitchControlMsg::UseInitialRelay,
                                                );
                                                (init_addr, init_tok)
                                            } else if let (Some(sig), Some(tid)) =
                                                (sig_opt, target_id_opt)
                                            {
                                                match sig
                                                    .request_relay(&tid, Duration::from_secs(8))
                                                {
                                                    Ok(fresh) => {
                                                        let _ = sw_clone.send_control_msg(
                                                            &SwitchControlMsg::RelayAllocReady {
                                                                session_id: fresh.session_id,
                                                            },
                                                        );
                                                        (fresh.relay_addr, fresh.relay_token)
                                                    }
                                                    Err(e) => {
                                                        let _ = dtx.send(Err(e));
                                                        return;
                                                    }
                                                }
                                            } else {
                                                let _ = dtx
                                                    .send(Err("缺少信令句柄，无法续签中继令牌"
                                                        .to_string()));
                                                return;
                                            };

                                            let res = if encrypt_c {
                                                let Some(bundle) = peer_b else {
                                                    let _ = dtx.send(Err("缺少 mTLS 证书".into()));
                                                    return;
                                                };
                                                let relay_mtls = bundle.to_relay_mtls_config(None);
                                                E2eeRelayTransport::connect_cancellable(
                                                    &relay_addr,
                                                    RelayRole::Client,
                                                    &relay_token,
                                                    Duration::from_secs(10),
                                                    disc_c,
                                                    Some(&relay_mtls),
                                                    RelayE2eeMode::ClientRequired(bundle),
                                                )
                                                .map(|t| {
                                                    let fp = t
                                                        .peer_mtls_identity()
                                                        .map(|i| i.cert_fingerprint_sha256.clone());
                                                    CandidateTransport {
                                                        transport: Box::new(t),
                                                        kind: TransportPathKind::Relay,
                                                        mtls_verified: true,
                                                        peer_cert_fingerprint: fp,
                                                    }
                                                })
                                                .map_err(|e| format!("{e}"))
                                            } else if let Some(bundle) = peer_b {
                                                let relay_mtls = bundle.to_relay_mtls_config(None);
                                                TcpRelayTransport::connect_mtls_cancellable(
                                                    &relay_addr,
                                                    RelayRole::Client,
                                                    &relay_token,
                                                    Duration::from_secs(10),
                                                    disc_c,
                                                    &relay_mtls,
                                                )
                                                .map(|t| CandidateTransport {
                                                    transport: Box::new(t),
                                                    kind: TransportPathKind::Relay,
                                                    mtls_verified: false,
                                                    peer_cert_fingerprint: None,
                                                })
                                                .map_err(|e| format!("{e}"))
                                            } else {
                                                TcpRelayTransport::connect_cancellable(
                                                    &relay_addr,
                                                    RelayRole::Client,
                                                    &relay_token,
                                                    Duration::from_secs(10),
                                                    disc_c,
                                                )
                                                .map(|t| CandidateTransport {
                                                    transport: Box::new(t),
                                                    kind: TransportPathKind::Relay,
                                                    mtls_verified: false,
                                                    peer_cert_fingerprint: None,
                                                })
                                                .map_err(|e| format!("{e}"))
                                            };
                                            let _ = dtx.send(res);
                                        });
                                }
                            }
                            HysteresisDecision::TriggerP2pReprobe => {
                                if let Some(grant) = cfg.relay_grant.as_ref() {
                                    runtime_switch_inflight = Some(2);
                                    let (rtx, rrx) = std::sync::mpsc::channel();
                                    let (atx, arx) = std::sync::mpsc::channel();
                                    reprobe_rx = Some(rrx);
                                    reprobe_answer_tx = Some(atx);
                                    let sw_clone = sw_h.clone();
                                    let initial_nat_type = grant.self_nat_type;
                                    let initial_nat_delta = grant.self_nat_port_delta;
                                    let initial_nat_range = grant.self_nat_port_range;
                                    let initial_local_port = grant.local_udp_port;
                                    let initial_self_pub = grant.self_public_addr.clone();
                                    let initial_peer_pubs = grant.peer_public_addrs.clone();
                                    let sc_opt = cfg.signal_client.clone();
                                    let encrypt_c = cfg.encrypt_connection;
                                    let q_mtls = if encrypt_c {
                                        prepare_peer_mtls_bundle(&cfg, grant)
                                            .and_then(|b| b.to_quic_mtls_config().ok())
                                    } else {
                                        None
                                    };
                                    let disc_c = Arc::clone(&disconnect_flag);
                                    let _ = thread::Builder::new()
                                        .name("rc-runtime-p2p-reprobe".to_string())
                                        .spawn(move || {
                                            let sc_snap = sc_opt
                                                .as_ref()
                                                .map(|sc| sc.snapshot_p2p_reprobe_info());
                                            let (sc_port, sc_addrs, sc_nat, sc_delta, sc_range) =
                                                match sc_snap {
                                                    Some((p, addrs, nat, d, r)) => {
                                                        (p, addrs, Some(nat), d, r)
                                                    }
                                                    None => (None, Vec::new(), None, None, None),
                                                };
                                            let local_port = sc_port
                                                .or(initial_local_port)
                                                .filter(|&p| p != 0)
                                                .or_else(|| {
                                                    std::net::UdpSocket::bind("0.0.0.0:0")
                                                        .ok()
                                                        .and_then(|s| s.local_addr().ok())
                                                        .map(|a| a.port())
                                                        .filter(|&p| p != 0)
                                                })
                                                .unwrap_or(0);
                                            if local_port == 0 {
                                                let _ = rtx.send(Err("port 0".into()));
                                                return;
                                            }
                                            let mut sec = [0u8; 16];
                                            use rand::RngCore;
                                            rand::rngs::OsRng.fill_bytes(&mut sec);
                                            let mut secret_hex = String::with_capacity(32);
                                            for b in sec {
                                                use std::fmt::Write;
                                                let _ = write!(&mut secret_hex, "{b:02x}");
                                            }
                                            let probe_id = format!(
                                                "rp-{:08x}",
                                                rand::rngs::OsRng.next_u32()
                                            );
                                            let mut self_addrs = sc_addrs;
                                            if let Some(ref pub_raw) = initial_self_pub {
                                                if let Ok(sock) =
                                                    pub_raw.trim().parse::<SocketAddr>()
                                                {
                                                    if sock.port() != 0 {
                                                        let s = sock.to_string();
                                                        if !self_addrs.contains(&s) {
                                                            self_addrs.push(s);
                                                        }
                                                    }
                                                }
                                            }
                                            for lan in
                                                crate::host_bridge::collect_host_lan_addrs(
                                                    local_port,
                                                )
                                            {
                                                if !self_addrs.contains(&lan) {
                                                    self_addrs.push(lan);
                                                }
                                            }
                                            let self_nat_type = sc_nat
                                                .filter(|n| *n != crate::nat::NatType::Unknown)
                                                .unwrap_or(initial_nat_type);
                                            let self_nat_delta = sc_delta.or(initial_nat_delta);
                                            let self_nat_range = sc_range.or(initial_nat_range);
                                            if sw_clone
                                                .send_control_msg(&SwitchControlMsg::P2pReprobeOffer {
                                                    probe_id: probe_id.clone(),
                                                    local_udp_port: local_port,
                                                    addrs: self_addrs,
                                                    nat_type: self_nat_type,
                                                    nat_port_delta: self_nat_delta,
                                                    nat_port_range: self_nat_range,
                                                    punch_secret: secret_hex.clone(),
                                                })
                                                .is_err()
                                            {
                                                let _ = rtx.send(Err("send offer fail".into()));
                                                return;
                                            }
                                            let Ok(SwitchControlMsg::P2pReprobeAnswer {
                                                local_udp_port: _,
                                                addrs: peer_addrs,
                                                nat_type: peer_nat,
                                                nat_port_delta: peer_delta,
                                                nat_port_range: peer_range,
                                                ..
                                            }) = arx.recv_timeout(Duration::from_secs(5))
                                            else {
                                                let _ = rtx.send(Err("answer timeout".into()));
                                                return;
                                            };
                                            let (peer_public_addrs, peer_lan_addrs) =
                                                crate::signal_client::split_public_and_lan_addrs(
                                                    &peer_addrs,
                                                    &initial_peer_pubs,
                                                );
                                            let cands = P2pCandidates {
                                                session_id: format!("reprobe-{probe_id}"),
                                                peer_public_addr: peer_public_addrs.first().cloned(),
                                                peer_public_addrs,
                                                peer_lan_addrs,
                                                local_udp_port: Some(local_port),
                                                self_nat_type,
                                                self_nat_port_delta: self_nat_delta,
                                                self_nat_port_range: self_nat_range,
                                                peer_nat_type: peer_nat,
                                                peer_nat_port_delta: peer_delta,
                                                peer_nat_port_range: peer_range,
                                                punch_secret: Some(secret_hex),
                                                start_after_ms: None,
                                                relay_fallback_after_ms: None,
                                            };
                                            let port_hold = crate::signal_client::acquire_local_udp_port_for_p2p(Some(local_port));
                                            match p2p::attempt_p2p_quic_client_mtls(
                                                &cands,
                                                p2p::DEFAULT_PUNCH_TIMEOUT,
                                                p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                                                &disc_c,
                                                q_mtls.as_ref(),
                                            ) {
                                                Ok(p2p_conn) => {
                                                    let fp = p2p_conn
                                                        .peer_mtls_identity()
                                                        .map(|i| i.cert_fingerprint_sha256);
                                                    let held = crate::signal_client::P2pHeldTransport::new(
                                                        p2p_conn,
                                                        port_hold,
                                                    );
                                                    let _ = rtx.send(Ok(CandidateTransport {
                                                        transport: Box::new(held),
                                                        kind: TransportPathKind::P2p,
                                                        mtls_verified: !encrypt_c || fp.is_some(),
                                                        peer_cert_fingerprint: fp,
                                                    }));
                                                }
                                                Err(e) => {
                                                    drop(port_hold);
                                                    let _ = rtx.send(Err(e));
                                                }
                                            }
                                        });
                                }
                            }
                        }
                    }
                }
                if clipboard_enabled_flag.load(Ordering::Acquire) {
                    let _ = client.pump_clipboard(now_us);
                }
                let budget = if last_busy {
                    RUN_POLL_BUDGET
                } else {
                    RUN_IDLE_POLL_BUDGET
                };
                let tick_report = client.tick(budget, Instant::now()).map_err(|e| {
                    classify_runtime_err_end(
                        "会话运行失败",
                        &e,
                        disconnect_flag.load(Ordering::Acquire),
                    )
                })?;
                if let Some(stop) = tick_report.closed {
                    end_state = classify_stop_reason_end(&stop);
                    break;
                }
                if tick_report.frames_displayed_delta > 0 {
                    let latest_seq = client
                        .pipeline()
                        .highest_delivered_seq()
                        .map(|s| s.0)
                        .unwrap_or(0);
                    still_receiver.on_dynamic_frame(latest_seq, &[]);
                    if still_receiver.has_active_overlay() || pending_still_clear {
                        // 全屏动态帧覆盖时直接清空所有静止叠加层（防分辨率缩小时边缘残影），
                        // 若异步解码线程当前持锁，保留 pending_still_clear 在后续每拍重试直至真正清空。
                        try_clear_still_overlay(
                            &renderer_handle,
                            &mut still_receiver,
                            &mut pending_still_clear,
                        );
                    }
                }

                if let Some(ref mut ctrl) = relay_rtt_ctrl {
                    if client.state() == SessionState::Streaming {
                        let snap = client.probe_snapshot();
                        if let Some(next_bps) =
                            ctrl.on_probe(Instant::now(), snap.pongs_received, snap.rtt_us_median)
                        {
                            let mut buf = Vec::new();
                            ControlMessage::SetBitrate {
                                bps: next_bps,
                                reason: BitrateReason::Probe,
                            }
                            .encode(&mut buf);
                            pending_control
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push_back(buf);
                        }
                    }
                }

                // 2a) 音频帧解码与播放（M9：采样率/声道数变更时先 stop 旧播放器再按新格式重建）。
                let audio_packets = client.drain_audio_frames();
                let audio_busy = !audio_packets.is_empty();
                for pkt in audio_packets {
                    if audio_muted {
                        continue;
                    }
                    let Some(samples) = decode_audio_packet_samples(&pkt) else {
                        continue;
                    };
                    if samples.is_empty() {
                        continue;
                    }
                    ensure_audio_player_for_format(
                        &mut audio_player,
                        &mut audio_player_format,
                        pkt.sample_rate,
                        pkt.channels,
                        audio_muted,
                        |sr, ch| {
                            if cfg.prefer_hardware {
                                rc_audio::create_audio_player(sr, ch)
                                    .unwrap_or_else(|_| Box::new(NullAudioPlayer::new()))
                            } else {
                                Box::new(NullAudioPlayer::new())
                            }
                        },
                    );
                    if let Some(player) = audio_player.as_mut() {
                        let frame = PcmFrame {
                            sample_rate: pkt.sample_rate,
                            channels: pkt.channels,
                            timestamp_us: pkt.timestamp_us,
                            samples,
                        };
                        let _ = player.push_frame(&frame);
                    }
                }

                // 2b) W2/W3/W4 工具复用通道收发：
                //     - W2 文件通道完全不进入 `tools_hub.lock()`，仅通过非阻塞有界通道与 `rc-file-client-worker` 交换线帧（H12）；
                //     - 严格不在持有 `tools_hub` 锁期间做网络 I/O 或文件磁盘 I/O；
                //     - 各通道背压时保留待重试队列且停止拉取对应引擎，零丢块。
                let incoming_tools = client.drain_tool_messages();
                let mut tools_busy = !incoming_tools.is_empty();
                let mut new_term_events: Vec<TerminalEvent> = Vec::new();
                let poll_file = pending_file_tx.is_empty();
                let poll_term = pending_term_tx.is_empty();
                let poll_portmap = pending_portmap_tx.is_empty();

                let mut non_file_incoming: Vec<(u8, Vec<u8>)> = Vec::new();
                for (channel, payload) in incoming_tools {
                    if channel == TOOL_CHANNEL_FILE {
                        pending_file_in.push_back(payload);
                    } else if channel == TOOL_CHANNEL_DISPLAY_CTRL {
                        if let Some(msg) = display_ctrl::decode_display_ctrl(&payload) {
                            let mut suppress_update_emit = false;
                            let mut caps_ext_meta: Option<(bool, u64)> = None;
                            match &msg {
                                DisplayControlMsg::Capabilities {
                                    current_width,
                                    current_height,
                                    supports_ext_codec_flags,
                                    codec_generation,
                                    still_stream_epoch,
                                    ..
                                } => {
                                    caps_ext_meta =
                                        Some((*supports_ext_codec_flags, *codec_generation));
                                    let target_w = if *current_width > 0 {
                                        *current_width
                                    } else {
                                        hud_width
                                    };
                                    let target_h = if *current_height > 0 {
                                        *current_height
                                    } else {
                                        hud_height
                                    };
                                    let dims_changed =
                                        (target_w, target_h) != still_receiver.dimensions();
                                    let epoch_changed = *still_stream_epoch > 0
                                        && *still_stream_epoch != still_receiver.current_epoch();
                                    if epoch_changed || dims_changed {
                                        let next_epoch = if *still_stream_epoch > 0 {
                                            *still_stream_epoch
                                        } else {
                                            still_receiver.current_epoch().saturating_add(1)
                                        };
                                        still_receiver
                                            .on_stream_reset(next_epoch, target_w, target_h);
                                        try_clear_still_overlay(
                                            &renderer_handle,
                                            &mut still_receiver,
                                            &mut pending_still_clear,
                                        );
                                    }
                                }
                                DisplayControlMsg::StillTileRefine { .. } => {
                                    suppress_update_emit = true;
                                    if pending_still_clear {
                                        try_clear_still_overlay(
                                            &renderer_handle,
                                            &mut still_receiver,
                                            &mut pending_still_clear,
                                        );
                                    }
                                    if pending_still_clear
                                        || !still_refinement_enabled
                                        || client.is_media_paused()
                                    {
                                        still_receiver.record_dropped();
                                    } else if let Ok((patch, raw_len)) =
                                        still_receiver.decode_msg_without_commit(&msg)
                                    {
                                        // 绝不在持有渲染器锁期间做 QOI 解码，且以 `try_lock` 非阻塞叠加，
                                        // 若异步解码线程正在呈现新动态帧则直接让路记丢弃，零阻塞视频主循环。
                                        let applied = renderer_handle
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .as_ref()
                                            .is_some_and(|rend| {
                                                rend.try_lock().is_ok_and(|mut r| {
                                                    r.apply_still_tile(&patch).is_ok()
                                                })
                                            });
                                        if applied {
                                            still_receiver.commit_applied(raw_len);
                                        } else {
                                            still_receiver.record_dropped();
                                        }
                                    }
                                    *still_refine_metrics
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner()) =
                                        still_receiver.metrics();
                                }
                                DisplayControlMsg::UpdateChunkAck { next_offset } => {
                                    update_relay.on_chunk_ack(*next_offset);
                                }
                                DisplayControlMsg::UpdateStatus {
                                    stage,
                                    need_controller_relay,
                                    request_id,
                                    ..
                                } => {
                                    let has_unsent_trigger =
                                        pending_update_tx.iter().any(|(is_trig, _)| *is_trig);
                                    let stale_request =
                                        *request_id != 0 && *request_id != active_update_request_id;
                                    let stale_for_unsent_trigger = has_unsent_trigger
                                        && (matches!(
                                            stage,
                                            crate::updater::UpdateStage::Failed
                                                | crate::updater::UpdateStage::Succeeded
                                                | crate::updater::UpdateStage::Restarting
                                        ) || (matches!(
                                            stage,
                                            crate::updater::UpdateStage::Relaying
                                        ) && *need_controller_relay));

                                    if stale_request || stale_for_unsent_trigger {
                                        // 跨重试/跨 RTT/背压未发出新 Trigger 前到达的旧任务状态一律静默忽略。
                                        suppress_update_emit = true;
                                    } else if matches!(stage, crate::updater::UpdateStage::Relaying)
                                        && !*need_controller_relay
                                    {
                                        // 中转推送进度与本地失败均由控制端统一上报，无条件抑制主机侧
                                        // `Relaying(need_controller_relay=false)` 帧，杜绝进度回跳及覆盖本地 Failed。
                                        suppress_update_emit = true;
                                    } else if matches!(stage, crate::updater::UpdateStage::Relaying)
                                        && *need_controller_relay
                                    {
                                        update_relay.maybe_start_relay_for_host_request();
                                        if update_relay.is_active() {
                                            awaiting_host_relay_finish = true;
                                        }
                                    } else if matches!(
                                        stage,
                                        crate::updater::UpdateStage::Failed
                                            | crate::updater::UpdateStage::Succeeded
                                            | crate::updater::UpdateStage::Restarting
                                    ) {
                                        awaiting_host_relay_finish = false;
                                        update_relay.cancel_active_relay();
                                        pending_update_tx.clear();
                                    } else {
                                        awaiting_host_relay_finish = false;
                                    }
                                }
                                DisplayControlMsg::ToolPermissionsState {
                                    allow_file_transfer,
                                    allow_terminal,
                                    allow_port_map,
                                } => {
                                    peer_tool_perms = ToolPermissions {
                                        allow_file_transfer: *allow_file_transfer,
                                        allow_terminal: *allow_terminal,
                                        allow_port_map: *allow_port_map,
                                    };
                                    if !peer_tool_perms.allow_file_transfer {
                                        pending_file_in.clear();
                                        pending_file_tx.clear();
                                        file_worker.abort_all_active(
                                            "目标设备已禁用文件传输权限，当前传输已中止",
                                        );
                                    }
                                    if !peer_tool_perms.allow_terminal {
                                        pending_term_tx.clear();
                                    }
                                    if !peer_tool_perms.allow_port_map {
                                        pending_portmap_tx.clear();
                                        last_portmap_snapshot.clear();
                                    }
                                    // 严格遵循 `tools_hub -> tool_permissions -> portmap_latest` 全局锁序，
                                    // 原子更新权限标志并同步清理已撤销工具引擎状态，彻底消除 TOCTOU。
                                    let mut hub =
                                        tools_hub.lock().unwrap_or_else(|e| e.into_inner());
                                    *tool_permissions.lock().unwrap_or_else(|e| e.into_inner()) =
                                        peer_tool_perms;
                                    if !peer_tool_perms.allow_terminal {
                                        hub.reset_terminal();
                                    }
                                    if !peer_tool_perms.allow_port_map {
                                        hub.portmap = PortMapClientEngine::new();
                                        *portmap_latest.lock().unwrap_or_else(|e| e.into_inner()) =
                                            Some(Vec::new());
                                    }
                                }
                                _ => {}
                            }
                            if !suppress_update_emit {
                                if let Some(upd) = handle_display_ctrl_msg(
                                    msg,
                                    &mut hud_width,
                                    &mut hud_height,
                                    client_supports_hevc,
                                ) {
                                    if let SessionUpdate::DisplayConfig {
                                        fps,
                                        ref codec,
                                        ref supported_codecs,
                                        ..
                                    } = upd
                                    {
                                        if fps > 0 {
                                            current_fps = fps;
                                        }
                                        let reported_codec =
                                            codec.as_deref().and_then(StreamCodec::parse_lossy);
                                        active_codec = reported_codec.unwrap_or(StreamCodec::H264);
                                        host_supports_hevc = supported_codecs.iter().any(|c| {
                                            StreamCodec::parse_lossy(c) == Some(StreamCodec::Hevc)
                                        }) || reported_codec
                                            == Some(StreamCodec::Hevc);
                                        if let Some((ext_flags, codec_gen)) = caps_ext_meta {
                                            host_supports_ext_codec_flags = ext_flags;
                                            if codec_gen > 0 {
                                                host_codec_generation = codec_gen;
                                            }
                                            if let Some(reemit) =
                                                reconcile_decode_failure_on_capabilities(
                                                    &mut pending_unrecovered_decode_failure,
                                                    active_codec.into(),
                                                    host_codec_generation,
                                                )
                                            {
                                                if let Some(payload) =
                                                    display_ctrl::encode_display_ctrl(&reemit)
                                                {
                                                    pending_display_tx.push_front(payload);
                                                    tools_busy = true;
                                                }
                                            }
                                            // 兼容老版被控端（不支持 ClientMediaCaps / supports_ext_codec_flags == false）：
                                            // 若双端支持 HEVC 且当前仍为 H.264，则按旧协议发送 SetCodec("hevc")。
                                            if !ext_flags
                                                && !client.is_media_paused()
                                                && client_supports_hevc
                                                && host_supports_hevc
                                                && active_codec == StreamCodec::H264
                                                && user_pinned_codec != Some(StreamCodec::H264)
                                                && !legacy_hevc_requested
                                            {
                                                legacy_hevc_requested = true;
                                                if let Some(payload) =
                                                    display_ctrl::encode_display_ctrl(
                                                        &DisplayControlMsg::SetCodec {
                                                            codec: StreamCodec::Hevc
                                                                .as_str()
                                                                .to_string(),
                                                        },
                                                    )
                                                {
                                                    pending_display_tx.push_back(payload);
                                                    active_codec = StreamCodec::Hevc;
                                                }
                                            }
                                        }
                                    }
                                    update_tx.push(upd);
                                }
                            }
                        }
                    } else {
                        non_file_incoming.push((channel, payload));
                    }
                }

                // 在 `drain_tool_messages()` 更新 `host_codec_generation` 之后再消费控制端管线热切/解码失败事件，
                // 避免同拍抵达的 UDP 新 codec 帧与 Stream A `Capabilities` 出现代次倒置，并记录未恢复失败态以便晚到 Capabilities 补发。
                let mut decode_failure_busy = false;
                while let Some(failure) = client.take_decode_failure() {
                    let ui_err = rc_types::Error::Decoder(format!(
                        "codec {} decode failed (gen={}): {}",
                        failure.codec.as_str(),
                        host_codec_generation,
                        failure.reason
                    ))
                    .to_ui_error(crate::ui_error::current_platform());
                    eprintln!(
                        "rc-ui: [{}] {} (codec={}, gen={}, detail={})",
                        ui_err.code,
                        ui_err.title,
                        failure.codec.as_str(),
                        host_codec_generation,
                        failure.reason
                    );
                    pending_unrecovered_decode_failure =
                        Some((failure.codec, host_codec_generation, failure.reason.clone()));
                    if let Some(payload) =
                        display_ctrl::encode_display_ctrl(&DisplayControlMsg::CodecDecodeFailed {
                            codec: failure.codec.as_str().to_string(),
                            generation: host_codec_generation,
                            reason: failure.reason,
                        })
                    {
                        pending_display_tx.push_front(payload);
                        decode_failure_busy = true;
                    }
                }

                // H12：非阻塞冲刷入站文件帧至专用文件工作线程（满载时留待下拍重试，零丢帧；权限被禁时立即清空）。
                if peer_tool_perms.allow_file_transfer {
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

                // H12：在 `tools_hub.lock()` 之外非阻塞拉取文件工作线程产出的出站线帧（权限被禁时跳过拉取并清空队列，防止空读刷屏）。
                let file_out = if poll_file && peer_tool_perms.allow_file_transfer {
                    file_worker.try_recv_outgoing(MAX_TOOL_FRAMES_PER_TICK)
                } else {
                    if !peer_tool_perms.allow_file_transfer {
                        pending_file_tx.clear();
                    }
                    Vec::new()
                };

                let (term_out, pm_out) = {
                    let mut hub = tools_hub.lock().unwrap_or_else(|e| e.into_inner());
                    let mut pm_dirty = false;
                    for (channel, payload) in non_file_incoming {
                        match channel {
                            TOOL_CHANNEL_TERMINAL if peer_tool_perms.allow_terminal => {
                                let evs = hub.terminal.handle_incoming(&payload);
                                for ev in &evs {
                                    hub.apply_terminal_event(ev);
                                }
                                new_term_events.extend(evs);
                            }
                            TOOL_CHANNEL_PORTMAP
                                if peer_tool_perms.allow_port_map
                                    && hub.portmap.handle_incoming(&payload) =>
                            {
                                pm_dirty = true;
                            }
                            _ => {}
                        }
                    }

                    let t_out = if poll_term && peer_tool_perms.allow_terminal {
                        hub.terminal.poll_outgoing(MAX_TOOL_FRAMES_PER_TICK)
                    } else {
                        Vec::new()
                    };
                    let p_out = if poll_portmap && peer_tool_perms.allow_port_map {
                        hub.portmap.poll_outgoing(MAX_TOOL_FRAMES_PER_TICK)
                    } else {
                        Vec::new()
                    };

                    if (pm_dirty
                        || !p_out.is_empty()
                        || last_portmap_poll_at.elapsed() >= PORTMAP_SNAPSHOT_INTERVAL)
                        && peer_tool_perms.allow_port_map
                    {
                        last_portmap_poll_at = Instant::now();
                        let cur_rules = hub.portmap.list_rules();
                        if cur_rules != last_portmap_snapshot {
                            last_portmap_snapshot = cur_rules.clone();
                            // 与 ToolClientHandle 共享严格 `hub -> portmap_latest` 锁序，防并发乱序覆盖。
                            *portmap_latest.lock().unwrap_or_else(|e| e.into_inner()) =
                                Some(cur_rules);
                        }
                    }

                    (t_out, p_out)
                };

                pending_file_tx.extend(file_out);
                pending_term_tx.extend(term_out);
                pending_portmap_tx.extend(pm_out);

                if client.state() == SessionState::Streaming {
                    if let Some(ctrl) = pending_audio_ctrl.as_ref() {
                        if client
                            .send_tool_message(TOOL_CHANNEL_AUDIO_CTRL, ctrl.clone())
                            .is_ok()
                        {
                            pending_audio_ctrl = None;
                            tools_busy = true;
                        }
                    }
                    let mut gate_or_flush = |channel: u8, queue: &mut VecDeque<Vec<u8>>| -> bool {
                        if !peer_tool_perms.allows_channel(channel) {
                            if !queue.is_empty() {
                                queue.clear();
                                let now_denied = Instant::now();
                                let idx = usize::from(channel);
                                let should_emit = if idx < last_local_tool_denied.len() {
                                    match last_local_tool_denied[idx] {
                                        None => true,
                                        Some(prev) => {
                                            now_denied.saturating_duration_since(prev)
                                                >= LOCAL_TOOL_DENIED_THROTTLE
                                        }
                                    }
                                } else {
                                    true
                                };
                                if should_emit {
                                    if idx < last_local_tool_denied.len() {
                                        last_local_tool_denied[idx] = Some(now_denied);
                                    }
                                    update_tx.push(SessionUpdate::ToolPermissionDenied {
                                        channel,
                                        ui_error: crate::ui_error::tool_forbidden_ui_error(
                                            channel,
                                            crate::ui_error::current_platform(),
                                            None,
                                        ),
                                    });
                                }
                            }
                            false
                        } else {
                            flush_pending_tool_queue(queue, |frame| {
                                client.send_tool_message(channel, frame)
                            })
                        }
                    };
                    if gate_or_flush(TOOL_CHANNEL_FILE, &mut pending_file_tx) {
                        tools_busy = true;
                    }
                    if gate_or_flush(TOOL_CHANNEL_TERMINAL, &mut pending_term_tx) {
                        tools_busy = true;
                    }
                    if gate_or_flush(TOOL_CHANNEL_PORTMAP, &mut pending_portmap_tx) {
                        tools_busy = true;
                    }
                    let update_tx_budget = crate::updater::UPDATE_RELAY_WINDOW_CHUNKS
                        .saturating_sub(pending_update_tx.len());
                    if update_tx_budget > 0 {
                        let (relay_msgs, relay_progs) = update_relay.poll_bounded(update_tx_budget);
                        for rmsg in relay_msgs {
                            if let Some(payload) = display_ctrl::encode_display_ctrl(&rmsg) {
                                pending_update_tx.push_back((false, payload));
                                tools_busy = true;
                            }
                        }
                        for rprog in relay_progs {
                            if matches!(
                                rprog.stage,
                                crate::updater::UpdateStage::Failed
                                    | crate::updater::UpdateStage::Succeeded
                                    | crate::updater::UpdateStage::Restarting
                            ) {
                                awaiting_host_relay_finish = false;
                            }
                            update_tx.push(SessionUpdate::RemoteUpdateStatus(rprog));
                        }
                    }
                    if flush_pending_display_tx_checked(
                        &mut pending_display_tx,
                        |frame| client.send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, frame),
                        |e| matches!(e, rc_types::Error::InvalidConfig(_)),
                    ) {
                        tools_busy = true;
                    }
                    for _ in 0..MAX_TOOL_FRAMES_PER_TICK {
                        let Some((_, frame)) = pending_update_tx.front() else {
                            break;
                        };
                        match client.send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, frame.clone()) {
                            Ok(()) => {
                                pending_update_tx.pop_front();
                                tools_busy = true;
                            }
                            Err(rc_types::Error::InvalidConfig(_)) => {
                                pending_update_tx.pop_front();
                            }
                            Err(_) => break,
                        }
                    }
                }
                for ev in new_term_events {
                    terminal_events.push_drop_oldest(ev);
                }

                last_busy = tick_report.busy || tools_busy || audio_busy || decode_failure_busy;

                // 3) 首帧诊断与 1s 节流推送 HUD 快照。
                let displayed_now = client.pipeline().displayed();
                if !first_frame_logged && displayed_now > 0 {
                    first_frame_logged = true;
                    eprintln!(
                        "rc-ui: first video frame presented (backend={backend}, displayed={displayed_now})"
                    );
                }

                if last_hud_at.elapsed() >= HUD_INTERVAL {
                    let mut cur_negotiated = client.negotiated().unwrap_or(negotiated);
                    cur_negotiated.width = hud_width;
                    cur_negotiated.height = hud_height;
                    let cur = sample_hud(&client, &clock_reader, cur_negotiated);
                    let snap =
                        HudSnapshot::derive_with_transport(Some(&prev_hud), &cur, transport_label);
                    update_tx.push(SessionUpdate::Hud(snap));
                    prev_hud = cur;
                    last_hud_at = Instant::now();

                    // 当本地启用 VideoToolbox 硬件解码但远端持续产出非 H.264 码流（例如被控端
                    // 未授屏幕录制权限而降级到 FakeEncoder）时，`displayed` 恒为 0 且持续出现
                    // `Outcome::DecodeError`。达到阈值时显式报错并结束会话，避免无限静默黑屏。
                    // 媒体处于暂停态（纯工具模式）时跳过检查。
                    if !client.is_media_paused() && is_hardware_decoder && displayed_now == 0 {
                        let decode_errors = count_decode_errors(&client);
                        if decode_errors > 0 && !decode_error_logged {
                            decode_error_logged = true;
                            eprintln!(
                                "rc-ui: hardware decoder reporting decode errors before first frame \
                                 (backend={backend}, decode_errors={decode_errors})"
                            );
                        }
                        if is_persistent_decode_failure(
                            is_hardware_decoder,
                            displayed_now,
                            decode_errors,
                            stream_started_at.elapsed(),
                        ) {
                            eprintln!(
                                "rc-ui: persistent hardware decode failure \
                                 (backend={backend}, displayed=0, decode_errors={decode_errors}); \
                                 ending session"
                            );
                            end_state = SessionEnd::fatal(
                                "远端画面解码失败（请确认被控端已授予屏幕录制权限）",
                            );
                            break;
                        }
                    }
                }
            }
            SessionState::Reconnecting => {
                if is_signaling_session {
                    end_state = signaling_disconnect_end(transport_label);
                    break;
                }
                let max_attempts = client.reconnect_config().backoff_max_attempts.max(1);
                if !in_reconnecting {
                    in_reconnecting = true;
                    reconnect_base_attempts = client.reconnect_stats().reconnect_attempts;
                    last_emitted_reconnect_attempt = 1;
                    update_tx.push(SessionUpdate::Reconnecting {
                        attempt: 1,
                        max_attempts,
                        reason: "连接已中断，正在尝试重连…".to_string(),
                    });
                }
                let outcome = client
                    .tick_reconnect(u64::from((clock_reader)()))
                    .map_err(|e| {
                        classify_runtime_err_end(
                            "重连驱动失败",
                            &e,
                            disconnect_flag.load(Ordering::Acquire),
                        )
                    })?;
                let cur_attempt = client
                    .reconnect_stats()
                    .reconnect_attempts
                    .saturating_sub(reconnect_base_attempts);
                if cur_attempt > last_emitted_reconnect_attempt
                    && matches!(
                        outcome,
                        ReconnectOutcome::Connecting | ReconnectOutcome::Waiting { .. }
                    )
                {
                    let display_attempt = cur_attempt.min(max_attempts);
                    last_emitted_reconnect_attempt = cur_attempt;
                    update_tx.push(SessionUpdate::Reconnecting {
                        attempt: display_attempt,
                        max_attempts,
                        reason: format!("第 {display_attempt}/{max_attempts} 次重连尝试中…"),
                    });
                }
                match outcome {
                    ReconnectOutcome::Waiting { next_attempt_in_ms } => {
                        let nap =
                            Duration::from_millis(next_attempt_in_ms).min(RUN_RECONNECT_SLEEP);
                        thread::sleep(nap);
                    }
                    ReconnectOutcome::GaveUp => {
                        end_state = classify_gave_up_end(client.closed_reason());
                        break;
                    }
                    outcome @ (ReconnectOutcome::Resumed | ReconnectOutcome::Rebuilt) => {
                        in_reconnecting = false;
                        last_emitted_reconnect_attempt = 0;
                        client.reset_clipboard_epoch();
                        if matches!(outcome, ReconnectOutcome::Rebuilt) {
                            backend = backend_label
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone();
                            is_hardware_decoder = is_hw_decoder_slot.load(Ordering::Acquire);
                            client_decode_caps = codec_selector::cached_or_platform_decode_caps(
                                cfg.prefer_hardware && is_hardware_decoder,
                            );
                            client_supports_hevc = cfg.prefer_hardware
                                && is_hardware_decoder
                                && (rc_pipeline::platform_supports_hevc()
                                    || client_decode_caps
                                        .iter()
                                        .any(|c| c.codec == rc_encode::Codec::Hevc && c.hardware));
                            client_supports_av1 = cfg.prefer_hardware
                                && is_hardware_decoder
                                && client_decode_caps
                                    .iter()
                                    .any(|c| c.codec == rc_encode::Codec::Av1 && c.hardware);
                            active_codec = StreamCodec::H264;
                            host_supports_ext_codec_flags = false;
                            host_codec_generation = 1;
                            pending_unrecovered_decode_failure = None;
                            legacy_hevc_requested = false;
                            if let Some((w, h)) = last_stage_rect {
                                apply_stage_rect_to_slot(
                                    &renderer_handle,
                                    &renderer_pending_resize,
                                    w,
                                    h,
                                );
                            }
                        }
                        if let Some(n) = client.negotiated() {
                            hud_width = n.width;
                            hud_height = n.height;
                            if n.fps > 0 {
                                current_fps = n.fps;
                            }
                        }
                        if matches!(outcome, ReconnectOutcome::Rebuilt) {
                            still_receiver.on_stream_reset(
                                still_receiver.current_epoch().saturating_add(1),
                                hud_width,
                                hud_height,
                            );
                            try_clear_still_overlay(
                                &renderer_handle,
                                &mut still_receiver,
                                &mut pending_still_clear,
                            );
                        }
                        // M9：重连恢复或重建后若本地处于静音态，重新向主机同步静音控制消息。
                        if audio_muted {
                            pending_audio_ctrl = Some(encode_audio_ctrl_muted(true));
                        }
                        let mut upgraded_after_reconnect = false;
                        if pending_desktop_upgrade {
                            pending_desktop_upgrade = false;
                            let surface = render_surface
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone();
                            upgraded_after_reconnect = try_resume_or_upgrade_desktop(
                                DesktopUpgradeCtx {
                                    client: &mut client,
                                    real_pipeline_built: &real_pipeline_built,
                                    want_real_pipeline: &want_real_pipeline,
                                    is_hw_decoder_slot: &is_hw_decoder_slot,
                                    backend: &mut backend,
                                    backend_label: &backend_label,
                                    renderer_handle: &renderer_handle,
                                    renderer_pending_resize: &renderer_pending_resize,
                                    layer_lease: &layer_lease,
                                    active_backend_suffix,
                                    is_hardware_decoder: &mut is_hardware_decoder,
                                    client_supports_hevc: &mut client_supports_hevc,
                                    client_supports_av1: &mut client_supports_av1,
                                    client_decode_caps: &mut client_decode_caps,
                                    user_pinned_codec,
                                    still_refinement_enabled,
                                    prefer_hardware: cfg.prefer_hardware,
                                    hud_width,
                                    hud_height,
                                    current_fps,
                                    negotiated,
                                    last_stage_rect,
                                    stream_started_at: &mut stream_started_at,
                                    first_frame_logged: &mut first_frame_logged,
                                    decode_error_logged: &mut decode_error_logged,
                                    pending_display_tx: &mut pending_display_tx,
                                    update_tx: &update_tx,
                                },
                                |upgrade_pcfg| {
                                    build_controller_pipeline(
                                        upgrade_pcfg,
                                        cfg.prefer_hardware,
                                        t0,
                                        surface.as_ref(),
                                    )
                                },
                            );
                        }
                        if !upgraded_after_reconnect && client.is_media_paused() {
                            if let Some(payload) = display_ctrl::encode_display_ctrl(
                                &DisplayControlMsg::SetMediaPaused { paused: true },
                            ) {
                                pending_display_tx.push_back(payload);
                            }
                        }
                        // 重连恢复（`Resumed` 丢失在途 QUIC Stream A 分块）或重建（`Rebuilt`）后均需中止进行中的安装包中转，
                        // 避免主机接收线程死等丢失分块或控制器卡在 92%；重建时另外重新协商 HEVC。
                        let was_relaying = update_relay.is_active() || awaiting_host_relay_finish;
                        if matches!(outcome, ReconnectOutcome::Rebuilt) {
                            peer_tool_perms = ToolPermissions::all_allowed();
                            *tool_permissions.lock().unwrap_or_else(|e| e.into_inner()) =
                                peer_tool_perms;
                            last_local_tool_denied = [None; 8];
                        }
                        if matches!(outcome, ReconnectOutcome::Rebuilt) || was_relaying {
                            awaiting_host_relay_finish = false;
                            update_relay.cancel_active_relay();
                            pending_update_tx.clear();
                            if was_relaying {
                                let msg_text = if matches!(outcome, ReconnectOutcome::Rebuilt) {
                                    "会话已重建，安装包中转已中断，请重试"
                                } else {
                                    "连接短暂中断，安装包中转已中断，请重试"
                                };
                                update_tx.push(SessionUpdate::RemoteUpdateStatus(
                                    crate::updater::UpdateProgress {
                                        stage: crate::updater::UpdateStage::Failed,
                                        progress_pct: 0,
                                        downloaded_bytes: 0,
                                        total_bytes: 0,
                                        target_version: String::new(),
                                        message: msg_text.to_string(),
                                        need_controller_relay: false,
                                        error: Some(msg_text.to_string()),
                                    },
                                ));
                            }
                        }
                        if matches!(outcome, ReconnectOutcome::Rebuilt)
                            && !upgraded_after_reconnect
                            && !client.is_media_paused()
                        {
                            let pref = user_pinned_codec
                                .map(|c| CodecSelectionPref::Manual(c.into()))
                                .unwrap_or(CodecSelectionPref::Auto);
                            if let Some(payload) =
                                display_ctrl::encode_display_ctrl(&build_client_media_caps_msg(
                                    &client_decode_caps,
                                    cfg.prefer_hardware && is_hardware_decoder,
                                    pref,
                                ))
                            {
                                pending_display_tx.push_back(payload);
                            }
                            if !still_refinement_enabled {
                                if let Some(payload) = display_ctrl::encode_display_ctrl(
                                    &DisplayControlMsg::StillRefineConfig { enabled: false },
                                ) {
                                    pending_display_tx.push_back(payload);
                                }
                            }
                        }
                    }
                    ReconnectOutcome::Connecting => {}
                }
            }
            _ => break,
        }

        // 4) 纪元检测：T17 全新重建时重锚会话钟（同 rc-cli/src/cmd/client.rs）。
        if client.session_id() != epoch_sid {
            epoch_sid = client.session_id();
            *clock_anchor.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            client.reset_clipboard_epoch();
            client.reset_activity_clock(u64::from((clock_reader)()));
        }
    }

    if let Some(ref mut player) = audio_player {
        player.stop();
    }
    drop(audio_player);
    if let Some(bg_cancel) = bg_p2p_cancel_slot {
        bg_cancel.store(true, Ordering::Release);
    }

    if lock_on_disconnect.load(Ordering::Acquire) && client.state() == SessionState::Streaming {
        if let Some(payload) = display_ctrl::encode_display_ctrl(&DisplayControlMsg::LockScreen) {
            if client
                .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, payload)
                .is_ok()
            {
                let flush_until = Instant::now() + Duration::from_millis(150);
                while Instant::now() < flush_until && client.state() == SessionState::Streaming {
                    let _ = client.tick(Duration::from_millis(5), Instant::now());
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    // 优雅关闭（若尚未 Closed，发 Bye(Normal) 并执行 S6 停机序列）。
    if client.state() != SessionState::Closed {
        let _ = client.close(ByeReason::Normal);
    }

    Ok(end_state)
}

/// 非阻塞尝试清空渲染器的静止无损 Tile 叠加层，并严格仅在实际执行成功后清零
/// `pending_still_clear` 与 `still_receiver.clear_active_overlay()`。
///
/// 当异步解码线程正在 `present()` 中持有 `renderer_handle` 锁导致 `try_lock()` 返回
/// `WouldBlock` 时，保留 `*pending_still_clear = true`（且不提前清掉活跃标记），
/// 供会话循环在后续每拍开头重试直至真正清空，杜绝旧无损层永久残留鬼影。
fn try_clear_still_overlay(
    renderer_handle: &Mutex<Option<RendererHandle>>,
    still_receiver: &mut crate::still_refine::StillRefineReceiver,
    pending_still_clear: &mut bool,
) -> bool {
    *pending_still_clear = true;
    let rend = renderer_handle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match rend {
        None => {
            *pending_still_clear = false;
            still_receiver.clear_active_overlay();
            true
        }
        Some(handle) => {
            if let Ok(mut r) = handle.try_lock() {
                r.clear_still_tiles();
                *pending_still_clear = false;
                still_receiver.clear_active_overlay();
                true
            } else {
                false
            }
        }
    }
}

/// 纯工具态原地热升级为桌面控屏的上下文（用于统一 `SetMediaPaused(false)` 与重连回 `Streaming` 补升级）。
struct DesktopUpgradeCtx<'a> {
    client: &'a mut ClientSession,
    real_pipeline_built: &'a AtomicBool,
    want_real_pipeline: &'a AtomicBool,
    is_hw_decoder_slot: &'a AtomicBool,
    backend: &'a mut String,
    backend_label: &'a Mutex<String>,
    renderer_handle: &'a Mutex<Option<RendererHandle>>,
    renderer_pending_resize: &'a Mutex<Arc<AtomicU64>>,
    layer_lease: &'a Mutex<Option<LayerLease>>,
    active_backend_suffix: Option<&'static str>,
    is_hardware_decoder: &'a mut bool,
    client_supports_hevc: &'a mut bool,
    client_supports_av1: &'a mut bool,
    client_decode_caps: &'a mut Vec<rc_pipeline::CodecCapability>,
    user_pinned_codec: Option<StreamCodec>,
    still_refinement_enabled: bool,
    prefer_hardware: bool,
    hud_width: u32,
    hud_height: u32,
    current_fps: u32,
    negotiated: SessionParams,
    last_stage_rect: Option<(u32, u32)>,
    stream_started_at: &'a mut Instant,
    first_frame_logged: &'a mut bool,
    decode_error_logged: &'a mut bool,
    pending_display_tx: &'a mut VecDeque<Vec<u8>>,
    update_tx: &'a BoundedUpdateQueue,
}

/// 执行纯工具态到桌面控屏的原地热升级（或从暂停恢复媒体推流）。
///
/// 若尚未构建真实管线且 `build_pipeline` 或 `client.replace_pipeline` 任一步失败，
/// 必须保持 `media_paused = true` 并立即返回 `false`——严禁取消暂停、严禁通知被控端恢复推流、
/// 严禁向 UI 发射 `MediaResumed` / `MediaState(false)`，避免真实码流灌入 64×64 占位解码器。
fn try_resume_or_upgrade_desktop<F>(ctx: DesktopUpgradeCtx<'_>, build_pipeline: F) -> bool
where
    F: FnOnce(&PipelineConfig) -> rc_types::Result<BuiltPipeline>,
{
    if !ctx.real_pipeline_built.load(Ordering::Acquire) {
        let upgrade_w = if ctx.hud_width > 0 {
            ctx.hud_width
        } else if ctx.negotiated.width > 0 {
            ctx.negotiated.width
        } else {
            1920
        };
        let upgrade_h = if ctx.hud_height > 0 {
            ctx.hud_height
        } else if ctx.negotiated.height > 0 {
            ctx.negotiated.height
        } else {
            1080
        };
        let upgrade_fps = ctx.current_fps.max(1);
        let upgrade_pcfg = PipelineConfig {
            resolution: Resolution::new(upgrade_w, upgrade_h),
            fps: upgrade_fps,
            bitrate_bps: ctx.negotiated.bitrate_bps.max(1),
            prefer_hardware: ctx.prefer_hardware,
            target_latency_us: 22_000,
            trace_capacity: 4096,
            diff: DiffMode::TrustPlatform,
            clock_origin_us: None,
            async_decode: ctx.prefer_hardware,
            max_packet_payload: rc_pipeline::MAX_PAYLOAD,
            ..PipelineConfig::default()
        };
        let built = match build_pipeline(&upgrade_pcfg) {
            Ok(built) => built,
            Err(e) => {
                eprintln!("rc-ui: build_controller_pipeline during desktop upgrade failed: {e}");
                ctx.client.set_media_paused(true);
                return false;
            }
        };
        if let Err(e) = ctx.client.replace_pipeline(built.pipeline) {
            eprintln!("rc-ui: replace_pipeline during desktop upgrade failed: {e}");
            ctx.client.set_media_paused(true);
            return false;
        }
        let final_label = match ctx.active_backend_suffix {
            Some(suffix) => format!("{} {suffix}", built.backend_label),
            None => built.backend_label,
        };
        *ctx.backend = final_label.clone();
        *ctx.backend_label.lock().unwrap_or_else(|e| e.into_inner()) = final_label;
        *ctx.renderer_pending_resize
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Arc::clone(&built.pending_resize);
        if let Some((w, h)) = ctx.last_stage_rect {
            apply_stage_rect_nonblocking(&built.renderer, &built.pending_resize, w, h);
        }
        *ctx.renderer_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&built.renderer));
        *ctx.layer_lease.lock().unwrap_or_else(|e| e.into_inner()) =
            LayerLease::from_renderer(built.renderer, built.layer_addr);
        *ctx.is_hardware_decoder = built.is_hardware;
        ctx.is_hw_decoder_slot
            .store(built.is_hardware, Ordering::Release);
        *ctx.first_frame_logged = false;
        *ctx.decode_error_logged = false;
        ctx.real_pipeline_built.store(true, Ordering::Release);
        ctx.want_real_pipeline.store(true, Ordering::Release);
        *ctx.client_decode_caps = codec_selector::cached_or_platform_decode_caps(
            ctx.prefer_hardware && *ctx.is_hardware_decoder,
        );
        *ctx.client_supports_hevc = ctx.prefer_hardware
            && *ctx.is_hardware_decoder
            && (rc_pipeline::platform_supports_hevc()
                || ctx
                    .client_decode_caps
                    .iter()
                    .any(|c| c.codec == rc_encode::Codec::Hevc && c.hardware));
        *ctx.client_supports_av1 = ctx.prefer_hardware
            && *ctx.is_hardware_decoder
            && ctx
                .client_decode_caps
                .iter()
                .any(|c| c.codec == rc_encode::Codec::Av1 && c.hardware);
        let pref = ctx
            .user_pinned_codec
            .map(|c| CodecSelectionPref::Manual(c.into()))
            .unwrap_or(CodecSelectionPref::Auto);
        if let Some(payload) = display_ctrl::encode_display_ctrl(&build_client_media_caps_msg(
            ctx.client_decode_caps,
            ctx.prefer_hardware && *ctx.is_hardware_decoder,
            pref,
        )) {
            ctx.pending_display_tx.push_back(payload);
        }
    }
    if !ctx.still_refinement_enabled {
        if let Some(payload) =
            display_ctrl::encode_display_ctrl(&DisplayControlMsg::StillRefineConfig {
                enabled: false,
            })
        {
            ctx.pending_display_tx.push_back(payload);
        }
    }
    *ctx.stream_started_at = Instant::now();
    ctx.client.set_media_paused(false);
    if let Some(payload) =
        display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetMediaPaused { paused: false })
    {
        ctx.pending_display_tx.push_back(payload);
    }
    let _ = ctx.client.request_idr_now();
    ctx.update_tx.push(SessionUpdate::MediaResumed {
        backend: ctx.backend.clone(),
        width: ctx.hud_width,
        height: ctx.hud_height,
        fps: ctx.current_fps,
    });
    ctx.update_tx
        .push(SessionUpdate::MediaState { paused: false });
    true
}

/// 构造控制端管线（硬件优先 + 假后端降级）。
fn build_controller_pipeline(
    pcfg: &PipelineConfig,
    prefer_hardware: bool,
    session_start: Instant,
    preallocated_surface: Option<&PreallocatedRenderSurface>,
) -> rc_types::Result<BuiltPipeline> {
    if prefer_hardware {
        match try_hardware_controller_stack(pcfg, session_start, preallocated_surface) {
            Ok(hw) => return Ok(hw),
            Err(e) => {
                eprintln!(
                    "rc-ui: hardware controller stack unavailable, falling back to fake: {e}"
                );
            }
        }
        let (pipeline, renderer, pending_resize) = fake_controller_stack(pcfg)?;
        return Ok(BuiltPipeline {
            pipeline,
            backend_label: "fake(降级)".to_string(),
            renderer,
            pending_resize,
            layer_addr: 0,
            is_hardware: false,
        });
    }
    let _ = session_start;
    let (pipeline, renderer, pending_resize) = fake_controller_stack(pcfg)?;
    Ok(BuiltPipeline {
        pipeline,
        backend_label: "fake".to_string(),
        renderer,
        pending_resize,
        layer_addr: 0,
        is_hardware: false,
    })
}

/// 平台硬件解码 + 硬件渲染栈。
fn try_hardware_controller_stack(
    pcfg: &PipelineConfig,
    session_start: Instant,
    preallocated_surface: Option<&PreallocatedRenderSurface>,
) -> rc_types::Result<BuiltPipeline> {
    let mut hw_cfg = pcfg.clone();
    hw_cfg.prefer_hardware = true;
    let (decoder, dl) = rc_pipeline::select_decoder_labeled(&hw_cfg)?;
    if dl == "fake" {
        return Err(rc_types::Error::InvalidConfig(format!(
            "hardware decoder unavailable, got {dl}"
        )));
    }
    let hw_rend = crate::platform::create_hardware_renderer(
        pcfg.resolution.width,
        pcfg.resolution.height,
        session_start,
        preallocated_surface,
    )
    .map_err(rc_types::Error::InvalidConfig)?;
    let shared: RendererHandle = Arc::new(Mutex::new(hw_rend.renderer));
    let pending_resize = Arc::new(AtomicU64::new(0));
    let wrapper = SharedRenderer {
        inner: Arc::clone(&shared),
        pending_resize: Arc::clone(&pending_resize),
    };
    let pipeline = ControllerPipeline::with_backends(hw_cfg, decoder, Box::new(wrapper))?;
    Ok(BuiltPipeline {
        pipeline,
        backend_label: format!("{dl}+{}", hw_rend.label),
        renderer: shared,
        pending_resize,
        layer_addr: hw_rend.layer_addr,
        is_hardware: true,
    })
}

/// 假后端控制端栈：`FakeDecoder` + `FakeRenderer`。
fn fake_controller_stack(
    pcfg: &PipelineConfig,
) -> rc_types::Result<(ControllerPipeline, RendererHandle, Arc<AtomicU64>)> {
    let decoder = rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
        resolution: pcfg.resolution,
        ..rc_decode::FakeDecoderConfig::default()
    })?;
    let renderer = rc_render::FakeRenderer::new(rc_render::FakeRendererConfig {
        size: (pcfg.resolution.width, pcfg.resolution.height),
        ..rc_render::FakeRendererConfig::default()
    })?;
    let shared: RendererHandle = Arc::new(Mutex::new(Box::new(renderer)));
    let pending_resize = Arc::new(AtomicU64::new(0));
    let wrapper = SharedRenderer {
        inner: Arc::clone(&shared),
        pending_resize: Arc::clone(&pending_resize),
    };
    let mut fake_cfg = pcfg.clone();
    // 明确关闭假后端管线内部的 prefer_hardware，避免热切不同 codec 时误调硬件工厂报错锁死。
    fake_cfg.prefer_hardware = false;
    let pipeline =
        ControllerPipeline::with_backends(fake_cfg, Box::new(decoder), Box::new(wrapper))?;
    Ok((pipeline, shared, pending_resize))
}

/// 当晚到的 `Capabilities` 抵达时校准未恢复的解码失败记录：
/// - 若被控端已切至其他编解码器（`reported_codec != failed_codec`），清除未恢复标记；
/// - 若被控端仍处于 `failed_codec` 且携带更新的 `codec_generation > reported_gen`，
///   补发一次带最新代次的 `CodecDecodeFailed` 防止跨通道竞态黑屏。
fn reconcile_decode_failure_on_capabilities(
    pending: &mut Option<(rc_encode::Codec, u64, String)>,
    reported_codec: rc_encode::Codec,
    reported_generation: u64,
) -> Option<DisplayControlMsg> {
    let (failed_codec, reported_gen, reason) = pending.as_mut()?;
    if reported_codec != *failed_codec {
        *pending = None;
        return None;
    }
    if reported_generation > *reported_gen {
        *reported_gen = reported_generation;
        return Some(DisplayControlMsg::CodecDecodeFailed {
            codec: failed_codec.as_str().to_string(),
            generation: reported_generation,
            reason: reason.clone(),
        });
    }
    None
}

/// 统计控制端 trace 环形缓冲中 `Outcome::DecodeError` 的帧数。
fn count_decode_errors(client: &ClientSession) -> usize {
    client
        .pipeline()
        .trace()
        .frames()
        .iter()
        .filter(|f| f.outcome() == Some(rc_trace::Outcome::DecodeError))
        .count()
}

/// 判定硬件解码器是否处于持续不可恢复的码流不兼容/解码失败状态（纯逻辑，便于单测）。
///
/// 仅在本地启用 VideoToolbox 硬件解码、从未成功上屏（`displayed == 0`）、累计
/// `Outcome::DecodeError` 达到阈值且串流已持续足够时长时返回 `true`：
/// - 静止桌面（0 帧，0 解码错误）返回 `false`；
/// - 正常已出画（`displayed > 0`）返回 `false`；
/// - 假后端测试（`is_hardware_decoder == false`）返回 `false`。
fn is_persistent_decode_failure(
    is_hardware_decoder: bool,
    displayed: u64,
    decode_errors: usize,
    stream_elapsed: Duration,
) -> bool {
    is_hardware_decoder
        && displayed == 0
        && decode_errors >= CONSECUTIVE_DECODE_ERROR_LIMIT
        && stream_elapsed >= PERSISTENT_DECODE_ERROR_MIN_ELAPSED
}

/// 从 `ClientSession` 提取当前 [`HudSample`]（全注入数据，铁律 4）。
fn sample_hud(
    client: &ClientSession,
    clock: &SessionClock,
    negotiated: SessionParams,
) -> HudSample {
    let at_us = u64::from((clock)());
    let displayed = client.pipeline().displayed();
    let net = client.net_stats();
    let probe = client.probe_snapshot();
    let rtt_us = probe.rtt_us_median.and_then(|v| u32::try_from(v).ok());
    let e2e_p50_ms = compute_recent_e2e_p50_ms(client);
    HudSample {
        at_us,
        displayed,
        bytes_recv: net.bytes_recv,
        rtt_us,
        loss_rate: net.loss_rate,
        e2e_p50_ms,
        width: negotiated.width,
        height: negotiated.height,
    }
}

/// 从最近若干已上屏帧计算偏移折算后的端到端帧时间 p50（毫秒）。
fn compute_recent_e2e_p50_ms(client: &ClientSession) -> Option<f64> {
    let mut samples_ms: Vec<f64> = Vec::with_capacity(E2E_WINDOW_FRAMES);
    for frame in client.pipeline().trace().frames().iter().rev() {
        if samples_ms.len() >= E2E_WINDOW_FRAMES {
            break;
        }
        if frame.outcome() != Some(rc_trace::Outcome::Displayed) {
            continue;
        }
        let Some(captured_host) = frame.at(rc_trace::Mark::Captured) else {
            continue;
        };
        let Some(presented_local) = frame.at(rc_trace::Mark::Presented) else {
            continue;
        };
        let Some(captured_local) = client.host_to_local_us(captured_host.0) else {
            continue;
        };
        let presented_u64 = u64::from(presented_local.0);
        if presented_u64 >= captured_local {
            samples_ms.push((presented_u64 - captured_local) as f64 / 1000.0);
        }
    }
    if samples_ms.is_empty() {
        return None;
    }
    samples_ms.sort_by(|a, b| a.total_cmp(b));
    Some(samples_ms[samples_ms.len() / 2])
}

/// 构造控制端入流后上报给被控端的 `ClientMediaCaps` 协商消息（只读非阻塞缓存，不阻塞首帧）。
fn build_client_media_caps_msg(
    decode_caps: &[rc_pipeline::CodecCapability],
    prefer_hardware: bool,
    pref: CodecSelectionPref,
) -> DisplayControlMsg {
    DisplayControlMsg::ClientMediaCaps {
        decode_caps: decode_caps.to_vec(),
        refinement_caps: Some(codec_selector::cached_or_platform_refinement_caps(
            prefer_hardware,
        )),
        pref,
        supports_ext_codec_flags: true,
    }
}

/// 解析控制端收到的 [`DisplayControlMsg`]，同步更新 HUD 尺寸并产出对应的 [`SessionUpdate`]。
fn handle_display_ctrl_msg(
    msg: DisplayControlMsg,
    hud_width: &mut u32,
    hud_height: &mut u32,
    client_supports_hevc: bool,
) -> Option<SessionUpdate> {
    match msg {
        DisplayControlMsg::Capabilities {
            current_width,
            current_height,
            current_fps,
            native_width,
            native_height,
            max_width,
            max_height,
            max_fps,
            presets,
            current_codec,
            supported_codecs,
            encode_caps: _,
            decode_caps: _,
            refinement_caps: _,
            supports_ext_codec_flags: _,
            codec_generation: _,
            still_stream_epoch: _,
        } => {
            if current_width > 0 && current_height > 0 {
                *hud_width = current_width;
                *hud_height = current_height;
            }
            let resolved_presets = if presets.is_empty() {
                display_ctrl::build_resolution_presets(
                    native_width,
                    native_height,
                    max_width,
                    max_height,
                )
            } else {
                presets
            };
            let parsed_codec = current_codec
                .as_deref()
                .and_then(StreamCodec::parse_lossy)
                .unwrap_or(StreamCodec::H264);
            let host_supports_hevc = supported_codecs
                .iter()
                .any(|c| StreamCodec::parse_lossy(c) == Some(StreamCodec::Hevc))
                || parsed_codec == StreamCodec::Hevc;
            let advisory = display_ctrl::evaluate_high_refresh_advisory(
                current_width,
                current_height,
                current_fps,
                parsed_codec,
                host_supports_hevc,
                client_supports_hevc,
                &resolved_presets,
            );
            Some(SessionUpdate::DisplayConfig {
                width: current_width,
                height: current_height,
                fps: current_fps,
                native_width,
                native_height,
                max_fps,
                presets: resolved_presets,
                codec: current_codec,
                supported_codecs,
                client_supports_hevc,
                advisory,
            })
        }
        DisplayControlMsg::Wallpaper { mime, data_base64 } => {
            if matches!(mime.as_str(), "image/jpeg" | "image/png")
                && !data_base64.is_empty()
                && data_base64.len() <= 90_000
                && display_ctrl::base64_decode(&data_base64).is_some()
            {
                Some(SessionUpdate::Wallpaper {
                    data_url: format!("data:{mime};base64,{data_base64}"),
                })
            } else {
                None
            }
        }
        DisplayControlMsg::PrivacyState {
            mode,
            preset,
            supported,
        } => Some(SessionUpdate::PrivacyState {
            mode,
            preset,
            supported,
        }),
        DisplayControlMsg::HostMuteState { muted, supported } => {
            Some(SessionUpdate::HostMuteState { muted, supported })
        }
        DisplayControlMsg::MouseModeState { mode } => Some(SessionUpdate::MouseModeState { mode }),
        DisplayControlMsg::DisplaysState {
            displays,
            active_display_id,
        } => Some(SessionUpdate::DisplaysState {
            displays,
            active_display_id,
        }),
        DisplayControlMsg::VirtualDisplayError { message } => {
            Some(SessionUpdate::VirtualDisplayError { message })
        }
        DisplayControlMsg::HostVersionInfo {
            version,
            arch,
            os,
            update_capable,
            is_owner_session,
            service_installed,
        } => Some(SessionUpdate::HostVersion(
            crate::updater::RemoteHostVersion {
                version,
                arch,
                os,
                update_capable,
                is_owner_session,
                service_installed,
            },
        )),
        DisplayControlMsg::UpdateStatus {
            stage,
            progress_pct,
            downloaded_bytes,
            total_bytes,
            target_version,
            message,
            need_controller_relay,
            error,
            request_id: _,
        } => Some(SessionUpdate::RemoteUpdateStatus(
            crate::updater::UpdateProgress {
                stage,
                progress_pct,
                downloaded_bytes,
                total_bytes,
                target_version,
                message,
                need_controller_relay,
                error,
            },
        )),
        DisplayControlMsg::HostScreenState {
            locked,
            capture_suspended,
        } => Some(SessionUpdate::HostScreenState {
            locked,
            capture_suspended,
        }),
        DisplayControlMsg::MediaState { paused } => Some(SessionUpdate::MediaState { paused }),
        DisplayControlMsg::ToolPermissionsState {
            allow_file_transfer,
            allow_terminal,
            allow_port_map,
        } => Some(SessionUpdate::ToolPermissionsUpdated(ToolPermissions {
            allow_file_transfer,
            allow_terminal,
            allow_port_map,
        })),
        DisplayControlMsg::ToolPermissionDenied { channel, reason } => {
            Some(SessionUpdate::ToolPermissionDenied {
                channel,
                ui_error: crate::ui_error::tool_forbidden_ui_error(
                    channel,
                    crate::ui_error::current_platform(),
                    reason,
                ),
            })
        }
        DisplayControlMsg::TerminalLockState {
            required,
            unlocked,
            username,
            retry_after_secs,
        } => Some(SessionUpdate::TerminalLockState {
            required,
            unlocked,
            username,
            retry_after_secs,
        }),
        DisplayControlMsg::TerminalUnlockResult {
            ok,
            error,
            retry_after_secs,
        } => Some(SessionUpdate::TerminalUnlockResult {
            ok,
            error,
            retry_after_secs,
        }),
        DisplayControlMsg::SetStream { .. }
        | DisplayControlMsg::LockScreen
        | DisplayControlMsg::SetCodec { .. }
        | DisplayControlMsg::ClientMediaCaps { .. }
        | DisplayControlMsg::CodecDecodeFailed { .. }
        | DisplayControlMsg::SetPrivacyMode { .. }
        | DisplayControlMsg::SetHostMute { .. }
        | DisplayControlMsg::SetMouseMode { .. }
        | DisplayControlMsg::ListDisplays
        | DisplayControlMsg::UpdateTrigger { .. }
        | DisplayControlMsg::UpdateCancel
        | DisplayControlMsg::UpdateChunkBegin { .. }
        | DisplayControlMsg::UpdateChunkData { .. }
        | DisplayControlMsg::UpdateChunkAck { .. }
        | DisplayControlMsg::UpdateChunkEnd
        | DisplayControlMsg::UpdateChunkAbort { .. }
        | DisplayControlMsg::SwitchDisplay { .. }
        | DisplayControlMsg::CreateVirtualDisplay { .. }
        | DisplayControlMsg::RemoveVirtualDisplay { .. }
        | DisplayControlMsg::SetMediaPaused { .. }
        | DisplayControlMsg::TerminalUnlockRequest { .. }
        | DisplayControlMsg::StillTileRefine { .. }
        | DisplayControlMsg::StillRefineConfig { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_input::MouseButton;

    #[test]
    fn session_channels_are_bounded() {
        // 铁律 1 UI 侧延伸：常量钉死 64 / 256。
        assert_eq!(COMMAND_CHANNEL_CAP, 64);
        assert_eq!(INPUT_CHANNEL_CAP, 256);

        // 命令通道满载 64：再推不阻塞，丢最旧保留最新 64 条。
        let cmd_q: BoundedQueue<SessionCommand> = BoundedQueue::new(COMMAND_CHANNEL_CAP);
        for bps in 1..=100u32 {
            cmd_q.push_drop_oldest(SessionCommand::SetBitrate { bps });
        }
        assert_eq!(cmd_q.len(), COMMAND_CHANNEL_CAP);
        let drained = cmd_q.drain_all();
        assert_eq!(drained.len(), 64);
        assert_eq!(drained[0], SessionCommand::SetBitrate { bps: 37 });
        assert_eq!(drained[63], SessionCommand::SetBitrate { bps: 100 });

        // 输入通道满载 256：纯移动事件满载丢最旧、不阻塞。
        let input_q = BoundedInputQueue::new(INPUT_CHANNEL_CAP);
        for i in 0..300u16 {
            input_q.push(InputEvent::MouseMove { x: i, y: i });
        }
        assert_eq!(input_q.len(), INPUT_CHANNEL_CAP);
        let moves = input_q.drain_all();
        assert_eq!(moves.len(), 256);
        assert_eq!(moves[0], InputEvent::MouseMove { x: 44, y: 44 });
        assert_eq!(moves[255], InputEvent::MouseMove { x: 299, y: 299 });

        // 满载优先级：关键事件不被后续 MouseMove 挤掉。
        let key_ev = InputEvent::Key {
            scancode: 0x1E,
            pressed: true,
            modifiers: 0,
        };
        let click_ev = InputEvent::MouseButton {
            button: MouseButton::Left,
            pressed: true,
        };
        input_q.push(key_ev);
        input_q.push(click_ev);
        for i in 0..400u16 {
            input_q.push(InputEvent::MouseMove { x: i, y: 0 });
        }
        assert_eq!(input_q.len(), INPUT_CHANNEL_CAP);
        let mixed = input_q.drain_all();
        assert!(
            mixed.contains(&key_ev),
            "关键键盘事件不得被 MouseMove 挤占丢弃"
        );
        assert!(
            mixed.contains(&click_ev),
            "关键鼠标按键事件不得被 MouseMove 挤占丢弃"
        );
    }

    struct DropSpyRenderer {
        dropped: Arc<AtomicBool>,
    }

    impl Renderer for DropSpyRenderer {
        fn present(
            &mut self,
            _frame: rc_decode::DecodedFrame,
        ) -> rc_types::Result<rc_types::Timestamp> {
            Ok(rc_types::Timestamp(0))
        }

        fn resize(&mut self, _size: (u32, u32)) -> rc_types::Result<()> {
            Ok(())
        }

        fn set_vsync(&mut self, _on: bool) {}

        fn set_cursor(&mut self, _pos: (i32, i32), _visible: bool) {}
    }

    impl Drop for DropSpyRenderer {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn layer_lease_keeps_renderer_alive_until_last_clone_drops() {
        let dropped = Arc::new(AtomicBool::new(false));
        let renderer: RendererHandle = Arc::new(Mutex::new(Box::new(DropSpyRenderer {
            dropped: Arc::clone(&dropped),
        })));

        // 地址为 0 时不得构造租约（假后端路径）。
        assert!(LayerLease::from_renderer(Arc::clone(&renderer), 0).is_none());

        let lease = LayerLease::from_renderer(Arc::clone(&renderer), 0x1234_5678)
            .expect("non-zero layer addr should construct lease");
        assert_eq!(lease.addr(), 0x1234_5678);
        assert_eq!(lease.as_ptr() as usize, 0x1234_5678);

        // 模拟会话线程退出、释放管线与本地 RendererHandle。
        drop(renderer);
        assert!(
            !dropped.load(Ordering::SeqCst),
            "会话线程释放渲染器后，LayerLease 必须继续保活底层 MetalRenderer"
        );

        // 模拟主线程闭包 clone 租约后原持有者释放。
        let cloned = lease.clone();
        assert!(lease.same_layer(&cloned));
        drop(lease);
        assert!(
            !dropped.load(Ordering::SeqCst),
            "主线程闭包仍持有 clone 租约期间不得释放渲染器"
        );

        // 相同地址但不同渲染器实例必须判定为不同层（防 ABA）。
        let other_dropped = Arc::new(AtomicBool::new(false));
        let other_renderer: RendererHandle = Arc::new(Mutex::new(Box::new(DropSpyRenderer {
            dropped: Arc::clone(&other_dropped),
        })));
        let other_lease = LayerLease::from_renderer(other_renderer, 0x1234_5678).unwrap();
        assert!(!cloned.same_layer(&other_lease));

        drop(cloned);
        assert!(
            dropped.load(Ordering::SeqCst),
            "最后一份 LayerLease 释放后底层渲染器应立即析构"
        );
        drop(other_lease);
        assert!(other_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn toggleable_clipboard_backend_respects_enabled_flag() {
        let fake = rc_session::testkit::SharedFakeClipboard::new();
        fake.simulate_local_copy(Some("initial"));
        let flag = Arc::new(AtomicBool::new(false));
        let mut backend =
            ToggleableClipboardBackend::new(Box::new(fake.clone()), Arc::clone(&flag));

        // 禁用态：不读取真实内容，也不写回本地剪贴板。
        assert_eq!(backend.read_text().unwrap(), None);
        backend.write_text("from-peer-while-disabled").unwrap();
        assert!(fake.writes().is_empty());
        let frozen_count = backend.change_count().unwrap();
        fake.simulate_local_copy(Some("changed-while-disabled"));
        assert_eq!(backend.change_count().unwrap(), frozen_count);

        // 启用态：正常读写并推进变更计数。
        flag.store(true, Ordering::Release);
        assert!(backend.change_count().unwrap() > frozen_count);
        assert_eq!(
            backend.read_text().unwrap(),
            Some("changed-while-disabled".to_string())
        );
        backend.write_text("from-peer-enabled").unwrap();
        assert_eq!(fake.writes(), vec!["from-peer-enabled".to_string()]);
    }

    #[test]
    fn audio_packet_decoding_supports_ima_adpcm_and_pcm16() {
        use rc_audio::AudioCapture;

        let pcm = vec![1000i16, -1000, 2000, -2000, 3000, -3000];
        let mut pcm_bytes = Vec::with_capacity(pcm.len() * 2);
        for &s in &pcm {
            pcm_bytes.extend_from_slice(&s.to_le_bytes());
        }
        let pcm_pkt = AudioFramePacket {
            seq: 1,
            timestamp_us: 0,
            sample_rate: 48_000,
            channels: 2,
            codec: AUDIO_CODEC_PCM16,
            data: pcm_bytes,
        };
        assert_eq!(decode_audio_packet_samples(&pcm_pkt), Some(pcm));

        let mut cap = rc_audio::FakeAudioCapture::new();
        let frame = cap.try_recv_frame().expect("fake audio frame");
        let encoded = rc_audio::encode_ima_adpcm(&frame.samples, frame.channels);
        let adpcm_pkt = AudioFramePacket {
            seq: 2,
            timestamp_us: frame.timestamp_us,
            sample_rate: frame.sample_rate,
            channels: frame.channels,
            codec: AUDIO_CODEC_IMA_ADPCM,
            data: encoded,
        };
        let decoded = decode_audio_packet_samples(&adpcm_pkt).expect("decode IMA-ADPCM");
        assert_eq!(decoded.len(), frame.samples.len());

        let bad_pkt = AudioFramePacket {
            seq: 3,
            timestamp_us: 0,
            sample_rate: 48_000,
            channels: 2,
            codec: 99,
            data: vec![1, 2, 3, 4],
        };
        assert_eq!(decode_audio_packet_samples(&bad_pkt), None);
    }

    #[test]
    fn tool_client_handle_tracks_and_closes_active_terminals() {
        let hub = Arc::new(Mutex::new(ToolClientHub::new()));
        let file_events = Arc::new(BoundedQueue::new(16));
        let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
        let handle = ToolClientHandle {
            hub: Arc::clone(&hub),
            file: file_handle,
            portmap_latest: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
            tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
            update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
        };

        assert!(handle.active_terminal_ids().is_empty());
        assert!(handle.terminal_open(0, 24).is_err());
        assert!(handle.terminal_open(513, 24).is_err());
        let id1 = handle.terminal_open(80, 24).expect("open 1");
        let id2 = handle.terminal_open(100, 30).expect("open 2");
        assert!(handle.has_active_terminal(id1));
        assert!(handle.has_active_terminal(id2));
        assert!(!handle.has_active_terminal(999_999));
        assert_eq!(handle.active_terminal_ids(), vec![id1, id2]);

        assert!(handle.terminal_resize(id1, 0, 24).is_err());
        assert!(handle.terminal_resize(id1, 80, 513).is_err());
        assert!(handle.terminal_resize(id1, 120, 40).is_ok());

        assert!(handle.terminal_input(id1, b"ls\n").is_ok());
        assert!(handle.terminal_input(999_999, b"ls\n").is_err());
        let oversized = vec![b'x'; MAX_TERMINAL_INPUT_BYTES + 1];
        assert!(handle.terminal_input(id1, &oversized).is_err());

        handle.terminal_close(id1).expect("close 1");
        assert!(!handle.has_active_terminal(id1));
        assert!(handle.terminal_input(id1, b"after-close").is_err());
        assert_eq!(handle.active_terminal_ids(), vec![id2]);

        let closed = handle.close_all_terminals();
        assert_eq!(closed, vec![id2]);
        assert!(handle.active_terminal_ids().is_empty());

        worker.shutdown();
    }

    #[test]
    fn tool_client_handle_background_detach_and_list_sync_preserve_active_ids() {
        let hub = Arc::new(Mutex::new(ToolClientHub::new()));
        let file_events = Arc::new(BoundedQueue::new(16));
        let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
        let handle = ToolClientHandle {
            hub: Arc::clone(&hub),
            file: file_handle,
            portmap_latest: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
            tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
            update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
        };

        assert_eq!(
            handle
                .terminal_open_with_options(80, 24, Some("worker".to_string()), false)
                .unwrap(),
            0
        );
        assert!(handle
            .terminal_open_with_options(80, 24, Some("   ".to_string()), false)
            .is_err());
        assert!(handle.terminal_list().is_ok());

        handle.terminal_attach(7, 100, 30).expect("attach");
        assert!(handle.has_active_terminal(7));
        assert!(handle.terminal_rename(7, "renamed-shell").is_ok());
        assert!(handle.terminal_rename(7, "bad\nname").is_err());

        // Detaching all UI attachments keeps active_terminals intact and emits Detach frames only.
        let detached = handle.detach_all_terminals();
        assert_eq!(detached, vec![7]);
        assert!(handle.has_active_terminal(7));

        let mut decoded_msgs = Vec::new();
        {
            let mut h = hub.lock().unwrap();
            for frame in h.terminal.poll_outgoing(16) {
                decoded_msgs.push(rc_tools::TerminalWireMsg::decode(&frame).unwrap());
            }
        }
        assert!(decoded_msgs.iter().any(|m| matches!(
            m,
            rc_tools::TerminalWireMsg::Open {
                term_id: 0,
                attach: false,
                name: Some(n),
                ..
            } if n == "worker"
        )));
        assert!(decoded_msgs
            .iter()
            .any(|m| matches!(m, rc_tools::TerminalWireMsg::List)));
        assert!(decoded_msgs
            .iter()
            .any(|m| matches!(m, rc_tools::TerminalWireMsg::Attach { term_id: 7, .. })));
        assert!(decoded_msgs
            .iter()
            .any(|m| matches!(m, rc_tools::TerminalWireMsg::Detach { term_id: 7 })));
        assert!(decoded_msgs.iter().any(|m| matches!(
            m,
            rc_tools::TerminalWireMsg::Rename { term_id: 7, name } if name == "renamed-shell"
        )));
        assert!(!decoded_msgs
            .iter()
            .any(|m| matches!(m, rc_tools::TerminalWireMsg::Close { .. })));

        worker.shutdown();
    }

    #[test]
    fn tool_client_hub_reconciles_failed_open_reassignment_and_overtaken_list() {
        let hub = Arc::new(Mutex::new(ToolClientHub::new()));
        let file_events = Arc::new(BoundedQueue::new(16));
        let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
        let handle = ToolClientHandle {
            hub: Arc::clone(&hub),
            file: file_handle,
            portmap_latest: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
            tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
            update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
        };

        // 1) Failed terminal_open cleans up pre-inserted active & attached IDs.
        let bad_id = handle.terminal_open(80, 24).expect("optimistic open 1");
        assert!(handle.has_active_terminal(bad_id));
        {
            let mut h = hub.lock().unwrap();
            h.apply_terminal_event(&TerminalEvent::Opened {
                term_id: bad_id,
                name: String::new(),
                created_at_unix_sec: 0,
                title: String::new(),
                cwd: String::new(),
                attached: false,
                ok: false,
                error: Some("max terminals".to_string()),
            });
            assert!(!h.active_terminals.contains(&bad_id));
            assert!(!h.attached_terminals.contains(&bad_id));
        }

        // 2) Host reassigns conflicting ID (client guessed 2, host already has 2 live & assigns 5).
        let guessed_id = handle.terminal_open(80, 24).expect("optimistic open 2");
        {
            let mut h = hub.lock().unwrap();
            h.apply_terminal_event(&TerminalEvent::SessionList {
                sessions: vec![rc_tools::TerminalSessionInfo {
                    term_id: guessed_id,
                    name: "existing".to_string(),
                    title: "zsh".to_string(),
                    cwd: "/tmp".to_string(),
                    created_at_unix_sec: 1,
                    cols: 80,
                    rows: 24,
                    attached: false,
                }],
            });
            // In-flight optimistic open must remain in active & attached until Opened arrives.
            assert!(h.active_terminals.contains(&guessed_id));
            assert!(h.attached_terminals.contains(&guessed_id));

            h.apply_terminal_event(&TerminalEvent::Opened {
                term_id: 5,
                name: "session2".to_string(),
                created_at_unix_sec: 2,
                title: "zsh".to_string(),
                cwd: "/tmp".to_string(),
                attached: true,
                ok: true,
                error: None,
            });
            assert!(h.active_terminals.contains(&guessed_id));
            assert!(!h.attached_terminals.contains(&guessed_id));
            assert!(h.active_terminals.contains(&5));
            assert!(h.attached_terminals.contains(&5));
        }
        assert_eq!(handle.detach_all_terminals(), vec![5]);

        // 3) Failed Attach removes non-existent term_id from active & attached.
        handle.terminal_attach(99, 80, 24).expect("attach 99");
        assert!(handle.has_active_terminal(99));
        {
            let mut h = hub.lock().unwrap();
            h.apply_terminal_event(&TerminalEvent::Attached {
                term_id: 99,
                session: None,
                ok: false,
                error: Some("missing".to_string()),
            });
            assert!(!h.active_terminals.contains(&99));
            assert!(!h.attached_terminals.contains(&99));
        }

        // 4) detach_all_terminals while Open(attach=true) is in flight causes Opened to auto-detach actual host ID.
        let in_flight_req = handle.terminal_open(80, 24).expect("optimistic open 4");
        let _ = handle.detach_all_terminals();
        {
            let mut h = hub.lock().unwrap();
            let _ = h.terminal.poll_outgoing(16); // drain prior frames
            h.apply_terminal_event(&TerminalEvent::Opened {
                term_id: in_flight_req + 10,
                name: "late".to_string(),
                created_at_unix_sec: 3,
                title: "zsh".to_string(),
                cwd: "/tmp".to_string(),
                attached: true,
                ok: true,
                error: None,
            });
            assert!(h.active_terminals.contains(&(in_flight_req + 10)));
            assert!(!h.attached_terminals.contains(&(in_flight_req + 10)));
            let post_detach: Vec<_> = h
                .terminal
                .poll_outgoing(4)
                .into_iter()
                .map(|f| rc_tools::TerminalWireMsg::decode(&f).unwrap())
                .collect();
            assert!(post_detach.iter().any(|m| matches!(
                m,
                rc_tools::TerminalWireMsg::Detach { term_id } if *term_id == in_flight_req + 10
            )));
        }

        worker.shutdown();
    }

    #[test]
    fn tool_client_handle_rejects_control_ops_when_outgoing_queue_full_without_mutating_hub() {
        let hub = Arc::new(Mutex::new(ToolClientHub::new()));
        let file_events = Arc::new(BoundedQueue::new(16));
        let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
        let handle = ToolClientHandle {
            hub: Arc::clone(&hub),
            file: file_handle,
            portmap_latest: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
            tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
            update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
        };

        // Pre-insert an existing live session, then saturate the client outgoing queue.
        let existing_id = 42;
        {
            let mut h = hub.lock().unwrap();
            h.host_live_ids.insert(existing_id);
            h.active_terminals.insert(existing_id);
            for _ in 0..rc_tools::terminal::MAX_TERMINAL_OUTGOING_FRAMES {
                h.terminal.list();
            }
            assert!(!h.terminal.can_enqueue());
        }

        assert!(handle
            .terminal_open_with_options(80, 24, None, true)
            .is_err());
        assert!(handle
            .terminal_open_with_options(80, 24, Some("bg".to_string()), false)
            .is_err());
        assert!(handle.terminal_list().is_err());
        assert!(handle.terminal_attach(existing_id, 80, 24).is_err());
        assert!(handle.terminal_rename(existing_id, "new-name").is_err());
        assert!(handle.terminal_input(existing_id, b"hello").is_err());
        assert!(handle.terminal_close(existing_id).is_err());

        {
            let h = hub.lock().unwrap();
            assert!(h.pending_opens.is_empty());
            assert!(h.pending_attaches.is_empty());
            assert!(h.attached_terminals.is_empty());
            assert!(h.host_live_ids.contains(&existing_id));
            assert!(h.active_terminals.contains(&existing_id));
            assert_eq!(h.active_terminals.len(), 1);
        }

        worker.shutdown();
    }

    #[test]
    fn ensure_audio_player_recreates_and_stops_old_player_on_format_change() {
        struct SpyAudioPlayer {
            stopped: Arc<AtomicBool>,
            muted: Arc<AtomicBool>,
        }

        impl AudioPlayer for SpyAudioPlayer {
            fn push_frame(&mut self, _frame: &PcmFrame) -> Result<(), String> {
                Ok(())
            }
            fn set_muted(&mut self, muted: bool) {
                self.muted.store(muted, Ordering::SeqCst);
            }
            fn is_muted(&self) -> bool {
                self.muted.load(Ordering::SeqCst)
            }
            fn stop(&mut self) {
                self.stopped.store(true, Ordering::SeqCst);
            }
        }

        let mut player: Option<Box<dyn AudioPlayer>> = None;
        let mut format: Option<(u32, u8)> = None;
        let stopped_1 = Arc::new(AtomicBool::new(false));
        let muted_1 = Arc::new(AtomicBool::new(false));
        let stopped_2 = Arc::new(AtomicBool::new(false));
        let muted_2 = Arc::new(AtomicBool::new(false));
        let mut created_formats: Vec<(u32, u8)> = Vec::new();

        ensure_audio_player_for_format(&mut player, &mut format, 48_000, 2, false, |sr, ch| {
            created_formats.push((sr, ch));
            Box::new(SpyAudioPlayer {
                stopped: Arc::clone(&stopped_1),
                muted: Arc::clone(&muted_1),
            })
        });
        assert_eq!(format, Some((48_000, 2)));
        assert_eq!(created_formats, vec![(48_000, 2)]);
        assert!(!stopped_1.load(Ordering::SeqCst));

        // 相同格式不重建播放器。
        ensure_audio_player_for_format(&mut player, &mut format, 48_000, 2, false, |sr, ch| {
            created_formats.push((sr, ch));
            Box::new(NullAudioPlayer::new())
        });
        assert_eq!(created_formats, vec![(48_000, 2)]);
        assert!(!stopped_1.load(Ordering::SeqCst));

        // 格式切换到 44.1kHz 单声道且静音态为 true：旧播放器必须被 stop()，新播放器继承 muted=true。
        ensure_audio_player_for_format(&mut player, &mut format, 44_100, 1, true, |sr, ch| {
            created_formats.push((sr, ch));
            Box::new(SpyAudioPlayer {
                stopped: Arc::clone(&stopped_2),
                muted: Arc::clone(&muted_2),
            })
        });
        assert!(
            stopped_1.load(Ordering::SeqCst),
            "格式变更时必须先 stop() 旧 AudioPlayer"
        );
        assert_eq!(format, Some((44_100, 1)));
        assert_eq!(created_formats, vec![(48_000, 2), (44_100, 1)]);
        assert!(muted_2.load(Ordering::SeqCst));
        assert!(!stopped_2.load(Ordering::SeqCst));
    }

    #[test]
    fn file_client_worker_offloads_commands_and_updates_cached_transfers_without_hub_lock() {
        let dir = std::env::temp_dir().join(format!(
            "rc-ui-file-client-worker-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        let sample = dir.join("upload_probe.bin");
        std::fs::write(&sample, b"0123456789abcdef").expect("write probe file");

        let hub = Arc::new(Mutex::new(ToolClientHub::new()));
        let file_events = Arc::new(BoundedQueue::new(32));
        let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
        let tools = ToolClientHandle {
            hub: Arc::clone(&hub),
            file: file_handle,
            portmap_latest: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
            tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
            update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
        };

        // 即使外部正持有 tools_hub 锁，文件上传与传输列表查询也绝不阻塞（证明文件引擎完全脱离 tools_hub）。
        let _hold_hub = hub.lock().unwrap();
        let up_id = tools
            .file_upload(sample.to_string_lossy().as_ref(), "/tmp")
            .expect("file_upload must succeed while tools_hub is locked");
        let cached = tools.file_list_transfers();
        assert!(
            cached
                .iter()
                .any(|t| t.id == up_id && t.name == "upload_probe.bin"),
            "cached_transfers must reflect upload immediately, got: {cached:?}"
        );
        drop(_hold_hub);

        // 工作线程应产出 UploadStart 线帧。
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got_frame = false;
        while Instant::now() < deadline {
            if !worker.try_recv_outgoing(4).is_empty() {
                got_frame = true;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            got_frame,
            "rc-file-client-worker must emit UploadStart frame"
        );

        tools.file_cancel(up_id).expect("file_cancel");
        worker.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flush_pending_tool_queue_retains_unsent_frames_on_backpressure() {
        let mut q: VecDeque<Vec<u8>> = vec![vec![1], vec![2], vec![3]].into();
        let mut delivered = Vec::new();
        let mut calls = 0usize;

        let sent_any = flush_pending_tool_queue(&mut q, |frame| {
            calls += 1;
            if calls == 2 {
                Err("full")
            } else {
                delivered.push(frame);
                Ok(())
            }
        });
        assert!(sent_any);
        assert_eq!(delivered, vec![vec![1]]);
        assert_eq!(q.len(), 2);

        let sent_rest = flush_pending_tool_queue(&mut q, |frame| {
            delivered.push(frame);
            Ok::<(), ()>(())
        });
        assert!(sent_rest);
        assert!(q.is_empty());
        assert_eq!(delivered, vec![vec![1], vec![2], vec![3]]);
    }

    #[test]
    fn persistent_decode_failure_triggers_only_for_hw_zero_displayed_over_threshold() {
        let min = PERSISTENT_DECODE_ERROR_MIN_ELAPSED;
        let limit = CONSECUTIVE_DECODE_ERROR_LIMIT;

        // 达标场景：硬件解码器 + displayed==0 + 达到连续错误阈值与最小时长 → true。
        assert!(is_persistent_decode_failure(true, 0, limit, min));
        assert!(is_persistent_decode_failure(
            true,
            0,
            limit + 50,
            min + Duration::from_secs(2)
        ));

        // 假后端测试 / 非硬件解码器 → false。
        assert!(!is_persistent_decode_failure(false, 0, limit + 100, min));
        // 已有成功上屏帧（后续偶发解码错）→ false。
        assert!(!is_persistent_decode_failure(true, 1, limit + 100, min));
        // 静止屏幕（0 帧，0 错误）→ false。
        assert!(!is_persistent_decode_failure(
            true,
            0,
            0,
            Duration::from_secs(60)
        ));
        // 尚未达到错误次数或观察时长 → false。
        assert!(!is_persistent_decode_failure(true, 0, limit - 1, min));
        assert!(!is_persistent_decode_failure(
            true,
            0,
            limit,
            min - Duration::from_millis(1)
        ));
    }

    #[test]
    fn handle_display_ctrl_msg_supports_custom_presets_and_wallpaper_validation() {
        let mut hud_w = 1280;
        let mut hud_h = 720;

        // 1) 非空 presets 直接沿用；为空时回退 build_resolution_presets。
        let custom_presets = vec![DisplayPreset {
            width: 2560,
            height: 1600,
            label: "2560 × 1600 (HiDPI)".to_string(),
            is_native: true,
            is_hidpi: true,
        }];
        let upd = handle_display_ctrl_msg(
            DisplayControlMsg::Capabilities {
                current_width: 2560,
                current_height: 1600,
                current_fps: 120,
                native_width: 2560,
                native_height: 1600,
                max_width: 2560,
                max_height: 1600,
                max_fps: 120,
                presets: custom_presets.clone(),
                current_codec: Some("h264".to_string()),
                supported_codecs: vec!["hevc".to_string(), "h264".to_string()],
                encode_caps: Vec::new(),
                decode_caps: Vec::new(),
                refinement_caps: None,
                supports_ext_codec_flags: false,
                codec_generation: 0,
                still_stream_epoch: 0,
            },
            &mut hud_w,
            &mut hud_h,
            true,
        )
        .expect("capabilities update");
        assert_eq!((hud_w, hud_h), (2560, 1600));
        match upd {
            SessionUpdate::DisplayConfig {
                presets,
                codec,
                supported_codecs,
                client_supports_hevc,
                advisory,
                ..
            } => {
                assert_eq!(presets, custom_presets);
                assert_eq!(codec.as_deref(), Some("h264"));
                assert_eq!(supported_codecs, vec!["hevc", "h264"]);
                assert!(client_supports_hevc);
                assert_eq!(advisory.level, display_ctrl::HighRefreshLevel::SuggestHevc);
                assert!(advisory.can_enable_hevc);
            }
            other => panic!("expected DisplayConfig, got {other:?}"),
        }

        let fallback_upd = handle_display_ctrl_msg(
            DisplayControlMsg::Capabilities {
                current_width: 1920,
                current_height: 1080,
                current_fps: 60,
                native_width: 1920,
                native_height: 1080,
                max_width: 1920,
                max_height: 1080,
                max_fps: 60,
                presets: Vec::new(),
                current_codec: None,
                supported_codecs: Vec::new(),
                encode_caps: Vec::new(),
                decode_caps: Vec::new(),
                refinement_caps: None,
                supports_ext_codec_flags: false,
                codec_generation: 0,
                still_stream_epoch: 0,
            },
            &mut hud_w,
            &mut hud_h,
            false,
        )
        .expect("fallback capabilities update");
        match fallback_upd {
            SessionUpdate::DisplayConfig {
                presets, advisory, ..
            } => {
                assert!(!presets.is_empty());
                assert!(presets.iter().any(|p| p.is_native && p.width == 1920));
                assert_eq!(advisory.level, display_ctrl::HighRefreshLevel::Optimal);
            }
            other => panic!("expected DisplayConfig, got {other:?}"),
        }

        // 2) Wallpaper 支持 image/jpeg 与 image/png，拒绝非法 mime、空/超长/非法 base64。
        let b64 = display_ctrl::base64_encode(b"\xff\xd8\xff\xe0");
        let wp = handle_display_ctrl_msg(
            DisplayControlMsg::Wallpaper {
                mime: "image/jpeg".to_string(),
                data_base64: b64.clone(),
            },
            &mut hud_w,
            &mut hud_h,
            false,
        );
        assert_eq!(
            wp,
            Some(SessionUpdate::Wallpaper {
                data_url: format!("data:image/jpeg;base64,{b64}"),
            })
        );
        assert_eq!(
            handle_display_ctrl_msg(
                DisplayControlMsg::Wallpaper {
                    mime: "image/svg+xml".to_string(),
                    data_base64: b64.clone(),
                },
                &mut hud_w,
                &mut hud_h,
                false,
            ),
            None
        );
        assert_eq!(
            handle_display_ctrl_msg(
                DisplayControlMsg::Wallpaper {
                    mime: "image/png".to_string(),
                    data_base64: "not!base64".to_string(),
                },
                &mut hud_w,
                &mut hud_h,
                false,
            ),
            None
        );
        assert_eq!(
            handle_display_ctrl_msg(
                DisplayControlMsg::Wallpaper {
                    mime: "image/png".to_string(),
                    data_base64: "AAAA".repeat(22_501),
                },
                &mut hud_w,
                &mut hud_h,
                false,
            ),
            None
        );

        // 3) SessionCommand::SetCodec JSON 往返且保持 Copy 语义。
        let cmd_hevc: SessionCommand =
            serde_json::from_str(r#"{"type":"set_codec","codec":"hevc"}"#).expect("parse hevc");
        let cmd_h264: SessionCommand =
            serde_json::from_str(r#"{"type":"set_codec","codec":"h264"}"#).expect("parse h264");
        assert_eq!(
            cmd_hevc,
            SessionCommand::SetCodec {
                codec: StreamCodec::Hevc
            }
        );
        assert_eq!(
            cmd_h264,
            SessionCommand::SetCodec {
                codec: StreamCodec::H264
            }
        );
    }

    #[test]
    fn ui_session_config_defaults_force_relay_to_false() {
        let json = serde_json::json!({
            "connect_addr": "127.0.0.1:9901",
            "watch_only": false,
            "width": 1920,
            "height": 1080,
            "fps": 60,
            "bitrate_bps": 14000000,
            "prefer_hardware": true
        });
        let cfg: UiSessionConfig = serde_json::from_value(json).expect("deserialize config");
        assert!(!cfg.force_relay);
        assert_eq!(cfg.connection_mode, ConnectionMode::Auto);
        assert!(!cfg.tools_only);
        assert!(cfg.clipboard_enabled);
        assert!(cfg.audio_enabled);
    }

    #[test]
    fn collect_lan_candidate_addrs_filters_unusable_and_matches_local_subnets() {
        let direct: SocketAddr = "192.168.77.88:9901".parse().unwrap();
        let cfg = UiSessionConfig {
            lan_direct_addr: Some(direct),
            ..UiSessionConfig::default()
        };
        let mut peer_lan_addrs = vec![
            "127.0.0.1:40000".to_string(),
            "[::ffff:127.0.0.1]:40000".to_string(),
            "0.0.0.0:40000".to_string(),
            "169.254.12.34:40000".to_string(),
            "224.0.0.1:40000".to_string(),
            "255.255.255.255:40000".to_string(),
            "[fd00::10]:40000".to_string(),
        ];
        let probe_targets = vec![direct, "192.0.2.10:21116".parse().unwrap()];
        let local_ips = lan_discovery::detect_local_interface_ips_for_targets(&probe_targets);
        let local_v4s = local_ips.ipv4s;
        let expected_same_subnet = local_v4s.first().map(|local_ip| {
            let octets = local_ip.octets();
            let sibling = std::net::Ipv4Addr::new(
                octets[0],
                octets[1],
                octets[2],
                if octets[3] == 200 { 201 } else { 200 },
            );
            peer_lan_addrs.push(format!("{sibling}:51234"));
            SocketAddr::new(
                std::net::IpAddr::V4(sibling),
                crate::host_bridge::DEFAULT_HOST_PORT,
            )
        });

        let grant = ConnectGrant {
            session_id: "sess-lan".to_string(),
            target_id: "111222333".to_string(),
            relay_addr: "192.0.2.10:21117".to_string(),
            relay_token: "tok".to_string(),
            peer_lan_addrs,
            ..ConnectGrant::default()
        };
        let candidates = collect_lan_candidate_addrs(&cfg, &grant);
        assert_eq!(candidates.first().copied(), Some(direct));
        for addr in &candidates[1..] {
            if let std::net::IpAddr::V4(v4) = addr.ip() {
                assert!(lan_discovery::is_usable_lan_ipv4(v4));
            }
        }
        if let Some(expected) = expected_same_subnet {
            assert!(candidates.contains(&expected));
        }
    }

    #[test]
    fn error_classification_distinguishes_timeout_eof_reject_and_real_mtls() {
        assert!(!is_mtls_cert_or_config_error(
            "LAN 直连失败: unexpected eof"
        ));
        assert!(!is_mtls_cert_or_config_error(
            "P2P QUIC Client 握手失败：connection refused"
        ));
        assert!(is_mtls_cert_or_config_error(
            "LAN mTLS 证书校验失败: InvalidPeerCertificate(UnknownIssuer)"
        ));

        let pair_timeout = classify_relay_connect_error(
            &rc_types::Error::Timeout(Duration::from_secs(12)),
            true,
            true,
        );
        assert!(
            pair_timeout.contains("对端未响应中继配对"),
            "{pair_timeout}"
        );
        assert!(!pair_timeout.contains("mTLS"), "{pair_timeout}");

        let tcp_timeout = classify_relay_connect_error(
            &rc_types::Error::Network("connect relay tcp timed out".to_string()),
            true,
            true,
        );
        assert!(tcp_timeout.contains("连接中继服务器超时"), "{tcp_timeout}");
        assert!(!tcp_timeout.contains("mTLS"), "{tcp_timeout}");

        let eof_err = classify_relay_connect_error(
            &rc_types::Error::Network(
                "relay stream hit EOF before completing handshake".to_string(),
            ),
            true,
            true,
        );
        assert!(eof_err.contains("对端已断开或拒绝连接"), "{eof_err}");
        assert!(!eof_err.contains("mTLS"), "{eof_err}");

        let reject_err = classify_relay_connect_error(
            &rc_types::Error::Network(
                "relay handshake rejected by 1.2.3.4:21117 (reply=0x01)".to_string(),
            ),
            true,
            true,
        );
        assert!(reject_err.contains("中继服务器拒绝配对"), "{reject_err}");
        assert!(!reject_err.contains("mTLS"), "{reject_err}");

        let cert_err = classify_relay_connect_error(
            &rc_types::Error::Network(
                "E2EE mTLS handshake failed: InvalidPeerCertificate(NotValidForName)".to_string(),
            ),
            true,
            true,
        );
        assert!(cert_err.contains("mTLS 证书身份校验失败"), "{cert_err}");
    }

    #[test]
    fn relay_rtt_controller_backs_off_on_rtt_spike_and_recovers_when_clean() {
        let t0 = Instant::now();
        let mut ctrl = RelayRttController::new(14_000_000, t0);

        // 1) 基准 RTT = 22ms
        assert_eq!(
            ctrl.on_probe(t0 + Duration::from_secs(1), 1, Some(22_000)),
            None
        );
        // 2) RTT 膨胀至 95ms（> 22+45 且 > 44ms），冷却满足后触发 0.75 回退 → 10.5M
        assert_eq!(
            ctrl.on_probe(t0 + Duration::from_secs(3), 2, Some(95_000)),
            Some(10_500_000)
        );
        // 3) 连续 3 次正常 RTT（24ms <= 22+15ms）且冷却满足后逐步回升
        assert_eq!(
            ctrl.on_probe(t0 + Duration::from_secs(4), 3, Some(24_000)),
            None
        );
        assert_eq!(
            ctrl.on_probe(t0 + Duration::from_secs(5), 4, Some(24_000)),
            None
        );
        assert_eq!(
            ctrl.on_probe(t0 + Duration::from_secs(6), 5, Some(23_000)),
            Some(12_600_000)
        );
        // 4) 手动设定码率同步覆盖上限
        ctrl.on_manual_bitrate(8_000_000, t0 + Duration::from_secs(7));
        assert_eq!(
            ctrl.on_probe(t0 + Duration::from_secs(10), 6, Some(22_000)),
            None
        );
    }

    #[test]
    fn relay_rtt_controller_ages_min_rtt_after_permanent_baseline_shift() {
        let t0 = Instant::now();
        let mut ctrl = RelayRttController::new(14_000_000, t0);

        // 1) 初始低延迟基线 20ms
        assert_eq!(
            ctrl.on_probe(t0 + Duration::from_secs(1), 1, Some(20_000)),
            None
        );

        // 2) 切换热点/路由后基线永久抬升至 75ms，窗口老化前持续回退至 2 Mbps
        let mut pong = 1u64;
        for sec in (3..=19).step_by(2) {
            pong += 1;
            let _ = ctrl.on_probe(t0 + Duration::from_secs(sec), pong, Some(75_000));
        }
        assert_eq!(ctrl.current_bps, RELAY_RTT_MIN_BITRATE_BPS);

        // 3) 达到 20s 窗口后 min_rtt_us 自动老化刷新为 75ms，后续 75ms 探测可正常爬坡恢复
        let mut recovered = false;
        for sec in 21..=60 {
            pong += 1;
            if let Some(next) = ctrl.on_probe(t0 + Duration::from_secs(sec), pong, Some(75_000)) {
                if next > RELAY_RTT_MIN_BITRATE_BPS {
                    recovered = true;
                }
            }
        }
        assert!(
            recovered,
            "min_rtt aging must allow recovery after baseline shift"
        );
        assert_eq!(ctrl.current_bps, 14_000_000);
    }

    #[test]
    fn initial_bw_probe_runs_only_for_p2p_and_relay_rtt_ctrl_syncs_on_path_switch() {
        assert!(!should_run_initial_bw_probe(TransportPathKind::Lan));
        assert!(!should_run_initial_bw_probe(TransportPathKind::MtlsLan));
        assert!(!should_run_initial_bw_probe(TransportPathKind::Relay));
        assert!(should_run_initial_bw_probe(TransportPathKind::P2p));

        assert_eq!(
            path_kind_from_transport_label("UDP LAN"),
            TransportPathKind::Lan
        );
        assert_eq!(
            path_kind_from_transport_label("UDP LAN (mTLS)"),
            TransportPathKind::MtlsLan
        );
        assert_eq!(
            path_kind_from_transport_label("UDP P2P"),
            TransportPathKind::P2p
        );
        assert_eq!(
            path_kind_from_transport_label("TCP Relay"),
            TransportPathKind::Relay
        );

        let t0 = Instant::now();
        assert!(sync_relay_rtt_ctrl_for_path(TransportPathKind::Lan, 14_000_000, t0).is_none());
        assert!(sync_relay_rtt_ctrl_for_path(TransportPathKind::MtlsLan, 14_000_000, t0).is_none());
        assert!(sync_relay_rtt_ctrl_for_path(TransportPathKind::P2p, 14_000_000, t0).is_none());

        let mut ctrl = sync_relay_rtt_ctrl_for_path(TransportPathKind::Relay, 12_000_000, t0)
            .expect("Relay path must activate RelayRttController");
        assert_eq!(ctrl.cap_bps, 12_000_000);
        assert_eq!(ctrl.current_bps, 12_000_000);
        assert_eq!(
            ctrl.on_probe(t0 + Duration::from_secs(1), 1, Some(20_000)),
            None
        );
        assert_eq!(
            ctrl.on_probe(t0 + Duration::from_secs(3), 2, Some(90_000)),
            Some(9_000_000)
        );

        // Switching Relay -> Lan disables RelayRttController; Lan -> Relay recreates a clean one.
        let disabled = sync_relay_rtt_ctrl_for_path(TransportPathKind::Lan, 12_000_000, t0);
        assert!(disabled.is_none());
        let reset = sync_relay_rtt_ctrl_for_path(TransportPathKind::Relay, 8_000_000, t0)
            .expect("Lan -> Relay must recreate RelayRttController");
        assert_eq!(reset.cap_bps, 8_000_000);
        assert_eq!(reset.current_bps, 8_000_000);
    }

    #[test]
    fn handle_display_ctrl_msg_emits_host_screen_state_update() {
        let mut hud_w = 1920u32;
        let mut hud_h = 1080u32;
        let upd = handle_display_ctrl_msg(
            DisplayControlMsg::HostScreenState {
                locked: true,
                capture_suspended: false,
            },
            &mut hud_w,
            &mut hud_h,
            true,
        );
        assert_eq!(
            upd,
            Some(SessionUpdate::HostScreenState {
                locked: true,
                capture_suspended: false,
            })
        );
        assert_eq!((hud_w, hud_h), (1920, 1080));

        assert_eq!(
            handle_display_ctrl_msg(
                DisplayControlMsg::MediaState { paused: true },
                &mut hud_w,
                &mut hud_h,
                true,
            ),
            Some(SessionUpdate::MediaState { paused: true })
        );
        assert_eq!(
            handle_display_ctrl_msg(
                DisplayControlMsg::MediaState { paused: false },
                &mut hud_w,
                &mut hud_h,
                true,
            ),
            Some(SessionUpdate::MediaState { paused: false })
        );
    }

    #[test]
    fn p2p_only_fails_without_relay_fallback_and_is_not_recoverable() {
        // 1) 向后兼容：force_relay=true 覆盖 connection_mode 为 TcpRelay；否则按 connection_mode 生效。
        assert_eq!(
            effective_connection_mode(&UiSessionConfig {
                force_relay: true,
                connection_mode: ConnectionMode::P2pOnly,
                ..UiSessionConfig::default()
            }),
            ConnectionMode::TcpRelay
        );
        assert_eq!(
            effective_connection_mode(&UiSessionConfig {
                force_relay: false,
                connection_mode: ConnectionMode::P2pOnly,
                ..UiSessionConfig::default()
            }),
            ConnectionMode::P2pOnly
        );

        // 2) 本地监听一个探针 TCP 端口充当中继地址，验证 P2pOnly 失败时绝不拨号中继。
        let spy_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind spy relay");
        spy_listener
            .set_nonblocking(true)
            .expect("nonblocking spy listener");
        let spy_addr = spy_listener.local_addr().expect("spy local_addr");
        let relay_touched = Arc::new(AtomicBool::new(false));
        let spy_stop = Arc::new(AtomicBool::new(false));
        let t_touched = Arc::clone(&relay_touched);
        let t_stop = Arc::clone(&spy_stop);
        let spy_thread = thread::spawn(move || {
            while !t_stop.load(Ordering::Acquire) {
                match spy_listener.accept() {
                    Ok(_) => {
                        t_touched.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: "127.0.0.1:1".parse().unwrap(),
            connection_mode: ConnectionMode::P2pOnly,
            force_relay: false,
            tools_only: false,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            relay_grant: Some(ConnectGrant {
                session_id: "sess-p2p-only-no-fallback".to_string(),
                relay_addr: spy_addr.to_string(),
                relay_token: "unused-token".to_string(),
                target_id: "900000001".to_string(),
                peer_public_addr: None,
                peer_lan_addrs: Vec::new(),
                local_udp_port: None,
                ..ConnectGrant::default()
            }),
            ..UiSessionConfig::default()
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut ended: Option<(String, bool)> = None;
        while Instant::now() < deadline {
            if let Some(SessionUpdate::Ended {
                reason,
                recoverable,
                ..
            }) = session.try_recv_update()
            {
                ended = Some((reason, recoverable));
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        session.join();
        spy_stop.store(true, Ordering::Release);
        let _ = spy_thread.join();

        let (reason, recoverable) = ended.expect("P2pOnly 必须以 Ended 退出");
        assert!(
            reason.contains("仅 P2P") && reason.contains("未回退中继"),
            "错误文案应明确说明仅 P2P 未回退中继，实际：{reason}"
        );
        assert!(
            !recoverable,
            "P2pOnly 首次建连 P2P 失败必须 recoverable = false"
        );
        assert!(
            !relay_touched.load(Ordering::SeqCst),
            "P2pOnly 模式严禁向 Tier 3 TCP 中继发起连接"
        );
    }

    #[test]
    fn punch_timeout_for_mode_uses_8s_for_p2p_only_and_2400ms_for_auto() {
        assert_eq!(
            punch_timeout_for_mode(ConnectionMode::P2pOnly),
            p2p::P2P_ONLY_PUNCH_TIMEOUT
        );
        assert_eq!(
            punch_timeout_for_mode(ConnectionMode::P2pOnly),
            Duration::from_secs(8)
        );
        assert_eq!(
            punch_timeout_for_mode(ConnectionMode::Auto),
            p2p::DEFAULT_PUNCH_TIMEOUT
        );
        assert_eq!(
            punch_timeout_for_mode(ConnectionMode::TcpRelay),
            p2p::DEFAULT_PUNCH_TIMEOUT
        );
    }

    #[test]
    fn tools_only_startup_pauses_media_and_upgrade_to_desktop_resumes_with_media_resumed() {
        struct NoopInjector;
        impl rc_input::InputInjector for NoopInjector {
            fn inject(&mut self, _events: &[InputEvent]) -> rc_types::Result<()> {
                Ok(())
            }
            fn set_screen_size(&mut self, _width: u32, _height: u32) {}
        }

        let host_origin = Instant::now();
        let (host_clock, _) = reanchorable_clock(host_origin);
        let caps = SessionParams {
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
        };
        let mut hcfg = rc_session::HostSessionConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            caps,
            Box::new(NoopInjector),
        );
        hcfg.pipeline.prefer_hardware = false;
        hcfg.pipeline.resolution = Resolution::new(640, 360);
        hcfg.pipeline.fps = 30;
        hcfg.pace_capture = true;

        let mut host = rc_session::HostSession::new(hcfg, DEV_CERT_PEM, DEV_KEY_PEM, host_clock)
            .expect("create host session");
        let host_addr = host.local_addr().expect("host local_addr");

        let received_ctrl: Arc<Mutex<Vec<DisplayControlMsg>>> = Arc::new(Mutex::new(Vec::new()));
        let host_stop = Arc::new(AtomicBool::new(false));
        let t_received = Arc::clone(&received_ctrl);
        let t_stop = Arc::clone(&host_stop);
        let host_thread = thread::spawn(move || {
            if host.accept_and_handshake(Duration::from_secs(5)).is_err() {
                return;
            }
            while !t_stop.load(Ordering::Acquire) && host.state() == SessionState::Streaming {
                if let Ok(rep) = host.tick(Duration::from_millis(5)) {
                    if rep.closed.is_some() {
                        break;
                    }
                } else {
                    break;
                }
                for (ch, payload) in host.drain_tool_messages() {
                    if ch == TOOL_CHANNEL_DISPLAY_CTRL {
                        if let Some(msg) = display_ctrl::decode_display_ctrl(&payload) {
                            if let DisplayControlMsg::SetMediaPaused { paused } = msg {
                                if paused {
                                    host.pause_media();
                                } else {
                                    let _ = host.resume_media();
                                }
                                if let Some(ack) = display_ctrl::encode_display_ctrl(
                                    &DisplayControlMsg::MediaState { paused },
                                ) {
                                    let _ = host.send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, ack);
                                }
                            }
                            t_received.lock().unwrap().push(msg);
                        }
                    }
                }
            }
            let _ = host.close(ByeReason::Normal);
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: host_addr,
            connection_mode: ConnectionMode::Auto,
            tools_only: true,
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            ..UiSessionConfig::default()
        });

        // 1) 等待握手完成并确认 tools_only 启动不写 layer_lease、收到 Negotiated 且向被控端发出 SetMediaPaused(true)。
        let mut updates: Vec<SessionUpdate> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            while let Some(u) = session.try_recv_update() {
                updates.push(u);
            }
            let host_got_pause = received_ctrl
                .lock()
                .unwrap()
                .iter()
                .any(|m| matches!(m, DisplayControlMsg::SetMediaPaused { paused: true }));
            let ui_got_media_paused = updates
                .iter()
                .any(|u| matches!(u, SessionUpdate::MediaState { paused: true }));
            let ui_got_negotiated = updates
                .iter()
                .any(|u| matches!(u, SessionUpdate::Negotiated { .. }));
            if host_got_pause && ui_got_media_paused && ui_got_negotiated {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert!(
            session.layer_lease().is_none(),
            "tools_only 启动期间不得写入 layer_lease"
        );
        assert!(
            updates.iter().any(|u| matches!(
                u,
                SessionUpdate::Negotiated { backend, .. } if backend == "tools-only"
            )),
            "tools_only 握手 Negotiated 后端标签应为 tools-only，实际：{updates:?}"
        );
        assert!(
            received_ctrl
                .lock()
                .unwrap()
                .iter()
                .any(|m| matches!(m, DisplayControlMsg::SetMediaPaused { paused: true })),
            "tools_only 握手成功后必须发送 DisplayControlMsg::SetMediaPaused(true)"
        );
        assert!(
            updates
                .iter()
                .any(|u| matches!(u, SessionUpdate::MediaState { paused: true })),
            "被控端回传 MediaState(true) 后必须转为 SessionUpdate::MediaState(true)"
        );

        // 2) 触发原地热升级桌面（upgrade_to_desktop）并顺带验证 ProbeNow 命令不破坏会话。
        updates.clear();
        session.upgrade_to_desktop(None);
        session.send(SessionCommand::ProbeNow);

        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            while let Some(u) = session.try_recv_update() {
                updates.push(u);
            }
            let host_got_resume = received_ctrl
                .lock()
                .unwrap()
                .iter()
                .any(|m| matches!(m, DisplayControlMsg::SetMediaPaused { paused: false }));
            let ui_got_resumed = updates
                .iter()
                .any(|u| matches!(u, SessionUpdate::MediaResumed { .. }));
            let ui_got_state_false = updates
                .iter()
                .any(|u| matches!(u, SessionUpdate::MediaState { paused: false }));
            if host_got_resume && ui_got_resumed && ui_got_state_false {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert!(
            received_ctrl
                .lock()
                .unwrap()
                .iter()
                .any(|m| matches!(m, DisplayControlMsg::SetMediaPaused { paused: false })),
            "upgrade_to_desktop 必须发送 DisplayControlMsg::SetMediaPaused(false)"
        );
        assert!(
            updates.iter().any(|u| matches!(
                u,
                SessionUpdate::MediaResumed {
                    backend,
                    width: 640,
                    height: 360,
                    fps: 30,
                } if backend == "fake"
            )),
            "upgrade_to_desktop 必须推送 MediaResumed，实际：{updates:?}"
        );
        assert!(
            updates
                .iter()
                .any(|u| matches!(u, SessionUpdate::MediaState { paused: false })),
            "upgrade_to_desktop 必须推送 MediaState(false)"
        );

        // 3) 再次通过命令暂停媒体并验证 SessionUpdate::MediaState(true)。
        updates.clear();
        session.send(SessionCommand::SetMediaPaused { paused: true });
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            while let Some(u) = session.try_recv_update() {
                updates.push(u);
            }
            if updates
                .iter()
                .any(|u| matches!(u, SessionUpdate::MediaState { paused: true }))
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            updates
                .iter()
                .any(|u| matches!(u, SessionUpdate::MediaState { paused: true })),
            "SetMediaPaused(true) 必须推送 MediaState(true)"
        );

        session.send(SessionCommand::Disconnect);
        session.join();
        host_stop.store(true, Ordering::Release);
        let _ = host_thread.join();
    }

    #[test]
    fn detach_and_abort_returns_within_bounded_max_wait_for_stuck_thread() {
        let (unblock_tx, unblock_rx) = mpsc::channel::<()>();
        let cmd_tx = Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP));
        let file_event_rx = Arc::new(BoundedQueue::new(16));
        let (mut file_worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_event_rx));
        let disconnect_flag = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));

        let stuck_thread = thread::spawn(move || {
            // 模拟卡在阻塞系统调用中、不响应 disconnect_flag 的僵尸会话线程。
            let _ = unblock_rx.recv_timeout(Duration::from_secs(5));
        });

        let handle = SessionHandle {
            cmd_tx: Arc::clone(&cmd_tx),
            display_ctrl_tx: Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP)),
            input_tx: Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP)),
            update_rx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
            file_event_rx,
            terminal_event_rx: Arc::new(BoundedQueue::new(16)),
            portmap_latest: Arc::new(Mutex::new(None)),
            tools_hub: Arc::new(Mutex::new(ToolClientHub::new())),
            file_handle,
            disconnect_flag: Arc::clone(&disconnect_flag),
            lock_on_disconnect: Arc::new(AtomicBool::new(false)),
            relay_interrupt: Arc::new(Mutex::new(None)),
            running: Arc::clone(&running),
            watch_only: Arc::new(AtomicBool::new(false)),
            tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
            still_refine_metrics: Arc::new(Mutex::new(
                crate::still_refine::StillRefineMetrics::default(),
            )),
            encrypt_connection: false,
            base_config: UiSessionConfig::default(),
            layer_lease: Arc::new(Mutex::new(None)),
            upgrade_surface: Arc::new(Mutex::new(None)),
            thread: Some(stuck_thread),
        };

        let start = Instant::now();
        handle.detach_and_abort(Duration::from_millis(50));
        let elapsed = start.elapsed();

        assert!(
            disconnect_flag.load(Ordering::Acquire),
            "detach_and_abort 必须立即置位 disconnect_flag"
        );
        assert_eq!(cmd_tx.drain_all(), vec![SessionCommand::Disconnect]);
        assert!(
            elapsed < Duration::from_millis(400),
            "detach_and_abort(50ms) 对卡住线程必须有界返回，实际耗时 {elapsed:?}"
        );

        // 释放阻塞线程以便后台回收线程干净退出。
        let _ = unblock_tx.send(());
        file_worker.shutdown();
    }

    #[test]
    fn ended_recoverable_classification_covers_all_terminal_and_disconnect_cases() {
        // 1) 信令会话在 Reconnecting 退出时按 transport_label 精确文案 + recoverable = true。
        assert_eq!(
            signaling_disconnect_end("UDP LAN"),
            SessionEnd {
                reason: "局域网连接已断开".to_string(),
                recoverable: true,
            }
        );
        assert_eq!(
            signaling_disconnect_end("UDP P2P"),
            SessionEnd {
                reason: "P2P 连接已断开".to_string(),
                recoverable: true,
            }
        );
        assert_eq!(
            signaling_disconnect_end("TCP Relay"),
            SessionEnd {
                reason: "中继连接已断开".to_string(),
                recoverable: true,
            }
        );

        // 2) 纯 IP 直连 GaveUp：非 SessionSwitching → recoverable = true；SessionSwitching / ByeNormal → false。
        let gave_up = classify_gave_up_end(None);
        assert_eq!(gave_up.reason, "重连次数已耗尽");
        assert!(gave_up.recoverable);

        let gave_up_disc = classify_gave_up_end(Some(&rc_session::StopReason::Disconnected(
            "peer timeout".to_string(),
        )));
        assert!(gave_up_disc.recoverable);

        let gave_up_switch = classify_gave_up_end(Some(&rc_session::StopReason::ByeReceived(
            ByeReason::SessionSwitching,
        )));
        assert_eq!(gave_up_switch.reason, SESSION_SWITCHING_REASON);
        assert!(!gave_up_switch.recoverable);

        // 3) Streaming 期 StopReason 判定。
        assert!(
            !classify_stop_reason_end(&rc_session::StopReason::ByeReceived(ByeReason::Normal))
                .recoverable
        );
        assert!(
            !classify_stop_reason_end(&rc_session::StopReason::ByeReceived(
                ByeReason::SessionSwitching
            ))
            .recoverable
        );
        assert!(!classify_stop_reason_end(&rc_session::StopReason::Requested).recoverable);
        assert!(
            classify_stop_reason_end(&rc_session::StopReason::Disconnected(
                "connection lost".to_string()
            ))
            .recoverable
        );
        assert!(
            !classify_stop_reason_end(&rc_session::StopReason::Disconnected(
                "用户主动断开".to_string()
            ))
            .recoverable
        );
        assert!(
            !classify_stop_reason_end(&rc_session::StopReason::Disconnected(
                "InvalidPeerCertificate(UnknownIssuer)".to_string()
            ))
            .recoverable
        );
        assert!(
            !classify_stop_reason_end(&rc_session::StopReason::Disconnected(
                "密码错误，鉴权失败".to_string()
            ))
            .recoverable
        );

        // 4) 运行期驱动错误判定（断网可恢复 vs 用户断开/鉴权/mTLS 不可恢复）。
        assert!(
            classify_runtime_err_end(
                "重连驱动失败",
                &rc_types::Error::Network("transport poll failed".to_string()),
                false,
            )
            .recoverable
        );
        assert!(
            !classify_runtime_err_end(
                "重连驱动失败",
                &rc_types::Error::Network("auth rejected: wrong password".to_string()),
                false,
            )
            .recoverable
        );
        assert!(
            !classify_runtime_err_end(
                "会话运行失败",
                &rc_types::Error::Network("mTLS InvalidPeerCertificate(Revoked)".to_string()),
                false,
            )
            .recoverable
        );
        let user_end = classify_runtime_err_end(
            "会话运行失败",
            &rc_types::Error::Network("connection reset".to_string()),
            true,
        );
        assert_eq!(user_end.reason, "用户主动断开");
        assert!(!user_end.recoverable);

        // 5) 硬件解码持久失败 / P2pOnly 错误文案不可恢复。
        assert!(is_non_recoverable_error_reason(
            "远端画面解码失败（请确认被控端已授予屏幕录制权限）"
        ));
        assert!(is_non_recoverable_error_reason(
            "P2P 直连失败（当前为「仅 P2P」模式，未回退中继）：timeout"
        ));

        // 6) 新增 SessionCommand & SessionUpdate JSON 序列化形态校验。
        let cmd_pause: SessionCommand =
            serde_json::from_str(r#"{"type":"set_media_paused","paused":true}"#)
                .expect("parse set_media_paused");
        assert_eq!(cmd_pause, SessionCommand::SetMediaPaused { paused: true });
        let cmd_probe: SessionCommand =
            serde_json::from_str(r#"{"type":"probe_now"}"#).expect("parse probe_now");
        assert_eq!(cmd_probe, SessionCommand::ProbeNow);

        let ended_json = serde_json::to_value(SessionUpdate::Ended {
            reason: "局域网连接已断开".to_string(),
            recoverable: true,
            ui_error: None,
        })
        .expect("serialize Ended");
        assert_eq!(ended_json["kind"], "ended");
        assert_eq!(ended_json["data"]["recoverable"], true);

        let reconnecting_json = serde_json::to_value(SessionUpdate::Reconnecting {
            attempt: 2,
            max_attempts: 5,
            reason: "第 2/5 次重连尝试中…".to_string(),
        })
        .expect("serialize Reconnecting");
        assert_eq!(reconnecting_json["kind"], "reconnecting");
        assert_eq!(reconnecting_json["data"]["attempt"], 2);
        assert_eq!(reconnecting_json["data"]["max_attempts"], 5);

        let resumed_json = serde_json::to_value(SessionUpdate::MediaResumed {
            backend: "videotoolbox+metal".to_string(),
            width: 1920,
            height: 1080,
            fps: 60,
        })
        .expect("serialize MediaResumed");
        assert_eq!(resumed_json["kind"], "media_resumed");
        assert_eq!(resumed_json["data"]["backend"], "videotoolbox+metal");
    }

    struct StubUpgradeTransport {
        inbound: VecDeque<NetEvent>,
    }

    impl Transport for StubUpgradeTransport {
        fn send_datagram(&mut self, _data: &[u8]) -> rc_types::Result<()> {
            Ok(())
        }
        fn send_reliable(&mut self, _data: &[u8]) -> rc_types::Result<()> {
            Ok(())
        }
        fn send_reliable_urgent(&mut self, _data: &[u8]) -> rc_types::Result<()> {
            Ok(())
        }
        fn poll(&mut self, _timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
            Ok(self.inbound.drain(..).collect())
        }
        fn stats(&self) -> NetStats {
            NetStats::default()
        }
    }

    struct RecordingStageRenderer {
        resizes: Arc<Mutex<Vec<(u32, u32)>>>,
    }

    impl Renderer for RecordingStageRenderer {
        fn present(
            &mut self,
            _frame: rc_decode::DecodedFrame,
        ) -> rc_types::Result<rc_types::Timestamp> {
            Ok(rc_types::Timestamp(0))
        }
        fn resize(&mut self, size: (u32, u32)) -> rc_types::Result<()> {
            self.resizes.lock().unwrap().push(size);
            Ok(())
        }
        fn set_vsync(&mut self, _on: bool) {}
        fn set_cursor(&mut self, _pos: (i32, i32), _visible: bool) {}
    }

    fn make_streaming_tools_only_client(params: SessionParams) -> ClientSession {
        let mut welcome_buf = Vec::new();
        ControlMessage::Welcome(rc_session::proto::Welcome {
            session_id: 99,
            granted: params,
            auth_status: rc_session::proto::AuthStatus::Ok,
            host_flags: rc_session::proto::HostFlags(0),
        })
        .encode(&mut welcome_buf);
        let transport = StubUpgradeTransport {
            inbound: VecDeque::from([NetEvent::Reliable(welcome_buf)]),
        };
        let capture = Box::new(BridgeInputCapture {
            queue: Arc::new(BoundedInputQueue::new(16)),
            watch_only: Arc::new(AtomicBool::new(false)),
        });
        let mut ccfg =
            ClientSessionConfig::new("127.0.0.1:9901".parse().unwrap(), params, 99, capture);
        ccfg.pipeline.prefer_hardware = false;
        let dec = rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
            resolution: Resolution::new(64, 64),
            ..rc_decode::FakeDecoderConfig::default()
        })
        .expect("fake decoder");
        let rend = rc_render::FakeRenderer::new(rc_render::FakeRendererConfig {
            size: (64, 64),
            ..rc_render::FakeRendererConfig::default()
        })
        .expect("fake renderer");
        let clock: SessionClock = Arc::new(|| 0);
        let mut client = ClientSession::with_parts(
            ccfg,
            Box::new(transport),
            Box::new(dec),
            Box::new(rend),
            clock,
        )
        .expect("with_parts");
        client.handshake().expect("handshake");
        client.set_media_paused(true);
        client
    }

    #[test]
    fn desktop_upgrade_failure_keeps_media_paused_and_skips_media_resumed() {
        let params = SessionParams {
            width: 1280,
            height: 720,
            fps: 60,
            bitrate_bps: 8_000_000,
        };

        // 1) build_controller_pipeline 失败：必须保持 media_paused=true，不发 SetMediaPaused(false)，不发 MediaResumed/MediaState(false)。
        let mut client = make_streaming_tools_only_client(params);
        let real_pipeline_built = AtomicBool::new(false);
        let want_real_pipeline = AtomicBool::new(false);
        let is_hw_decoder_slot = AtomicBool::new(false);
        let mut backend = "tools-only".to_string();
        let backend_label = Mutex::new(backend.clone());
        let renderer_handle = Mutex::new(None);
        let renderer_pending_resize = Mutex::new(Arc::new(AtomicU64::new(0)));
        let layer_lease = Mutex::new(None);
        let mut is_hardware_decoder = false;
        let mut client_supports_hevc = false;
        let mut client_supports_av1 = false;
        let mut client_decode_caps = Vec::new();
        let mut stream_started_at = Instant::now();
        let mut first_frame_logged = false;
        let mut decode_error_logged = false;
        let mut pending_display_tx = VecDeque::new();
        let update_tx = BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP);

        let ok = try_resume_or_upgrade_desktop(
            DesktopUpgradeCtx {
                client: &mut client,
                real_pipeline_built: &real_pipeline_built,
                want_real_pipeline: &want_real_pipeline,
                is_hw_decoder_slot: &is_hw_decoder_slot,
                backend: &mut backend,
                backend_label: &backend_label,
                renderer_handle: &renderer_handle,
                renderer_pending_resize: &renderer_pending_resize,
                layer_lease: &layer_lease,
                active_backend_suffix: None,
                is_hardware_decoder: &mut is_hardware_decoder,
                client_supports_hevc: &mut client_supports_hevc,
                client_supports_av1: &mut client_supports_av1,
                client_decode_caps: &mut client_decode_caps,
                user_pinned_codec: None,
                still_refinement_enabled: true,
                prefer_hardware: false,
                hud_width: params.width,
                hud_height: params.height,
                current_fps: params.fps,
                negotiated: params,
                last_stage_rect: Some((1280, 720)),
                stream_started_at: &mut stream_started_at,
                first_frame_logged: &mut first_frame_logged,
                decode_error_logged: &mut decode_error_logged,
                pending_display_tx: &mut pending_display_tx,
                update_tx: &update_tx,
            },
            |_pcfg| {
                Err(rc_types::Error::InvalidConfig(
                    "simulated hardware init error".into(),
                ))
            },
        );
        assert!(!ok, "构建管线失败时升级必须返回 false");
        assert!(
            client.is_media_paused(),
            "构建失败后必须保持 media_paused=true"
        );
        assert!(!real_pipeline_built.load(Ordering::Acquire));
        assert!(!want_real_pipeline.load(Ordering::Acquire));
        assert!(
            pending_display_tx.is_empty(),
            "构建失败时严禁通知被控端恢复推流"
        );
        assert!(
            update_tx.try_pop().is_none(),
            "构建失败时严禁向 UI 发射 MediaResumed 或 MediaState(false)"
        );

        // 2) client.replace_pipeline 失败（例如非 Streaming 态）：同样保持暂停、不发恢复通知。
        client.on_disconnected(1_000);
        assert_eq!(client.state(), SessionState::Reconnecting);
        let ok2 = try_resume_or_upgrade_desktop(
            DesktopUpgradeCtx {
                client: &mut client,
                real_pipeline_built: &real_pipeline_built,
                want_real_pipeline: &want_real_pipeline,
                is_hw_decoder_slot: &is_hw_decoder_slot,
                backend: &mut backend,
                backend_label: &backend_label,
                renderer_handle: &renderer_handle,
                renderer_pending_resize: &renderer_pending_resize,
                layer_lease: &layer_lease,
                active_backend_suffix: None,
                is_hardware_decoder: &mut is_hardware_decoder,
                client_supports_hevc: &mut client_supports_hevc,
                client_supports_av1: &mut client_supports_av1,
                client_decode_caps: &mut client_decode_caps,
                user_pinned_codec: None,
                still_refinement_enabled: true,
                prefer_hardware: false,
                hud_width: params.width,
                hud_height: params.height,
                current_fps: params.fps,
                negotiated: params,
                last_stage_rect: Some((1280, 720)),
                stream_started_at: &mut stream_started_at,
                first_frame_logged: &mut first_frame_logged,
                decode_error_logged: &mut decode_error_logged,
                pending_display_tx: &mut pending_display_tx,
                update_tx: &update_tx,
            },
            |pcfg| build_controller_pipeline(pcfg, false, Instant::now(), None),
        );
        assert!(!ok2, "replace_pipeline 失败时升级必须返回 false");
        assert!(
            client.is_media_paused(),
            "replace_pipeline 失败后必须保持暂停"
        );
        assert!(pending_display_tx.is_empty());
        assert!(update_tx.try_pop().is_none());
        let _ = client.close(ByeReason::Normal);
    }

    #[test]
    fn desktop_upgrade_replays_cached_stage_rect_on_new_renderer() {
        let params = SessionParams {
            width: 1280,
            height: 720,
            fps: 60,
            bitrate_bps: 8_000_000,
        };
        let mut client = make_streaming_tools_only_client(params);
        let real_pipeline_built = AtomicBool::new(false);
        let want_real_pipeline = AtomicBool::new(false);
        let is_hw_decoder_slot = AtomicBool::new(false);
        let mut backend = "tools-only".to_string();
        let backend_label = Mutex::new(backend.clone());
        let renderer_handle = Mutex::new(None);
        let renderer_pending_resize = Mutex::new(Arc::new(AtomicU64::new(0)));
        let layer_lease = Mutex::new(None);
        let mut is_hardware_decoder = false;
        let mut client_supports_hevc = false;
        let mut client_supports_av1 = false;
        let mut client_decode_caps = Vec::new();
        let mut stream_started_at = Instant::now();
        let mut first_frame_logged = false;
        let mut decode_error_logged = false;
        let mut pending_display_tx = VecDeque::new();
        let update_tx = BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP);
        let resizes = Arc::new(Mutex::new(Vec::<(u32, u32)>::new()));
        let resizes_for_build = Arc::clone(&resizes);

        let ok = try_resume_or_upgrade_desktop(
            DesktopUpgradeCtx {
                client: &mut client,
                real_pipeline_built: &real_pipeline_built,
                want_real_pipeline: &want_real_pipeline,
                is_hw_decoder_slot: &is_hw_decoder_slot,
                backend: &mut backend,
                backend_label: &backend_label,
                renderer_handle: &renderer_handle,
                renderer_pending_resize: &renderer_pending_resize,
                layer_lease: &layer_lease,
                active_backend_suffix: None,
                is_hardware_decoder: &mut is_hardware_decoder,
                client_supports_hevc: &mut client_supports_hevc,
                client_supports_av1: &mut client_supports_av1,
                client_decode_caps: &mut client_decode_caps,
                user_pinned_codec: None,
                still_refinement_enabled: true,
                prefer_hardware: false,
                hud_width: params.width,
                hud_height: params.height,
                current_fps: params.fps,
                negotiated: params,
                last_stage_rect: Some((1440, 900)),
                stream_started_at: &mut stream_started_at,
                first_frame_logged: &mut first_frame_logged,
                decode_error_logged: &mut decode_error_logged,
                pending_display_tx: &mut pending_display_tx,
                update_tx: &update_tx,
            },
            move |pcfg| {
                let dec = rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
                    resolution: pcfg.resolution,
                    ..rc_decode::FakeDecoderConfig::default()
                })?;
                let shared: RendererHandle =
                    Arc::new(Mutex::new(Box::new(RecordingStageRenderer {
                        resizes: resizes_for_build,
                    })));
                let pending_resize = Arc::new(AtomicU64::new(0));
                let wrapper = SharedRenderer {
                    inner: Arc::clone(&shared),
                    pending_resize: Arc::clone(&pending_resize),
                };
                let pipeline = ControllerPipeline::with_backends(
                    pcfg.clone(),
                    Box::new(dec),
                    Box::new(wrapper),
                )?;
                Ok(BuiltPipeline {
                    pipeline,
                    backend_label: "fake".to_string(),
                    renderer: shared,
                    pending_resize,
                    layer_addr: 0,
                    is_hardware: false,
                })
            },
        );
        assert!(ok, "正常升级必须成功");
        assert!(!client.is_media_paused());
        assert!(real_pipeline_built.load(Ordering::Acquire));
        assert!(want_real_pipeline.load(Ordering::Acquire));
        assert_eq!(
            *resizes.lock().unwrap(),
            vec![(1440, 900)],
            "升级创建新 renderer_handle 后必须立即回放缓存的 StageRect 尺寸"
        );
        let mut updates = Vec::new();
        while let Some(u) = update_tx.try_pop() {
            updates.push(u);
        }
        assert!(updates.iter().any(|u| matches!(
            u,
            SessionUpdate::MediaResumed {
                width: 1280,
                height: 720,
                ..
            }
        )));
        assert!(updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::MediaState { paused: false })));
        let _ = client.close(ByeReason::Normal);
    }

    #[test]
    fn detach_and_abort_waits_graceful_window_before_triggering_force_disconnect() {
        // 场景 A：会话线程在优雅窗口内收到 Disconnect 并完成优雅发送后退出，
        // 期间 disconnect_flag 与 relay_interrupt 均不得提前置位。
        let cmd_tx = Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP));
        let file_event_rx = Arc::new(BoundedQueue::new(16));
        let (mut file_worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_event_rx));
        let disconnect_flag = Arc::new(AtomicBool::new(false));
        let relay_cancel = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        let observed_clean_graceful = Arc::new(AtomicBool::new(false));

        let t_cmd = Arc::clone(&cmd_tx);
        let t_disc = Arc::clone(&disconnect_flag);
        let t_cancel = Arc::clone(&relay_cancel);
        let t_running = Arc::clone(&running);
        let t_clean = Arc::clone(&observed_clean_graceful);
        let graceful_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if let Some(SessionCommand::Disconnect) = t_cmd.try_pop() {
                    // 模拟发完 LockScreen / Bye(Normal)
                    thread::sleep(Duration::from_millis(15));
                    if !t_disc.load(Ordering::Acquire) && !t_cancel.load(Ordering::Acquire) {
                        t_clean.store(true, Ordering::Release);
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(2));
            }
            t_running.store(false, Ordering::Release);
        });

        let handle = SessionHandle {
            cmd_tx: Arc::clone(&cmd_tx),
            display_ctrl_tx: Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP)),
            input_tx: Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP)),
            update_rx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
            file_event_rx,
            terminal_event_rx: Arc::new(BoundedQueue::new(16)),
            portmap_latest: Arc::new(Mutex::new(None)),
            tools_hub: Arc::new(Mutex::new(ToolClientHub::new())),
            file_handle,
            disconnect_flag: Arc::clone(&disconnect_flag),
            lock_on_disconnect: Arc::new(AtomicBool::new(false)),
            relay_interrupt: Arc::new(Mutex::new(Some(ActiveRelayInterrupt::Dialing(Arc::clone(
                &relay_cancel,
            ))))),
            running: Arc::clone(&running),
            watch_only: Arc::new(AtomicBool::new(false)),
            tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
            still_refine_metrics: Arc::new(Mutex::new(
                crate::still_refine::StillRefineMetrics::default(),
            )),
            encrypt_connection: false,
            base_config: UiSessionConfig::default(),
            layer_lease: Arc::new(Mutex::new(None)),
            upgrade_surface: Arc::new(Mutex::new(None)),
            thread: Some(graceful_thread),
        };

        handle.detach_and_abort(Duration::from_millis(200));
        assert!(
            observed_clean_graceful.load(Ordering::Acquire),
            "detach_and_abort 必须先给优雅窗口，让会话线程在 socket 切断前发完 LockScreen / Bye"
        );
        assert!(
            !disconnect_flag.load(Ordering::Acquire) && !relay_cancel.load(Ordering::Acquire),
            "优雅窗口内已干净退出的线程不得触发强断"
        );
        file_worker.shutdown();

        // 场景 B：线程忽略 Disconnect 卡住，超过 80ms 优雅窗口后必须触发 trigger_disconnect() 强断退出。
        let cmd_tx2 = Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP));
        let file_event_rx2 = Arc::new(BoundedQueue::new(16));
        let (mut file_worker2, file_handle2) = FileClientWorker::spawn(Arc::clone(&file_event_rx2));
        let disconnect_flag2 = Arc::new(AtomicBool::new(false));
        let relay_cancel2 = Arc::new(AtomicBool::new(false));
        let running2 = Arc::new(AtomicBool::new(true));

        let t_cancel2 = Arc::clone(&relay_cancel2);
        let t_running2 = Arc::clone(&running2);
        let force_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if t_cancel2.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(Duration::from_millis(2));
            }
            t_running2.store(false, Ordering::Release);
        });

        let handle2 = SessionHandle {
            cmd_tx: cmd_tx2,
            display_ctrl_tx: Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP)),
            input_tx: Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP)),
            update_rx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
            file_event_rx: file_event_rx2,
            terminal_event_rx: Arc::new(BoundedQueue::new(16)),
            portmap_latest: Arc::new(Mutex::new(None)),
            tools_hub: Arc::new(Mutex::new(ToolClientHub::new())),
            file_handle: file_handle2,
            disconnect_flag: Arc::clone(&disconnect_flag2),
            lock_on_disconnect: Arc::new(AtomicBool::new(false)),
            relay_interrupt: Arc::new(Mutex::new(Some(ActiveRelayInterrupt::Dialing(Arc::clone(
                &relay_cancel2,
            ))))),
            running: Arc::clone(&running2),
            watch_only: Arc::new(AtomicBool::new(false)),
            tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
            still_refine_metrics: Arc::new(Mutex::new(
                crate::still_refine::StillRefineMetrics::default(),
            )),
            encrypt_connection: false,
            base_config: UiSessionConfig::default(),
            layer_lease: Arc::new(Mutex::new(None)),
            upgrade_surface: Arc::new(Mutex::new(None)),
            thread: Some(force_thread),
        };

        let start = Instant::now();
        handle2.detach_and_abort(Duration::from_millis(300));
        let elapsed = start.elapsed();
        assert!(
            disconnect_flag2.load(Ordering::Acquire) && relay_cancel2.load(Ordering::Acquire),
            "优雅窗口超时后必须触发 trigger_disconnect() 强制中断底层 socket"
        );
        assert!(
            elapsed >= Duration::from_millis(60) && elapsed < Duration::from_millis(300),
            "强断应发生在 80ms 优雅窗口之后并在 max_wait 内返回，实际耗时 {elapsed:?}"
        );
        file_worker2.shutdown();
    }

    #[test]
    fn should_fallback_after_handshake_error_enforces_all_safety_redlines() {
        let pre_welcome_abort = rc_types::Error::Network(
            "disconnected while waiting for Welcome: aborted by peer".to_string(),
        );
        let pre_welcome_io = rc_types::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));

        // 1) 仅当尚未进入鉴权/审批交互且发生 Welcome 前底层连接断开/重置时允许回退。
        assert!(should_fallback_after_handshake_error(
            &pre_welcome_abort,
            false,
            false
        ));
        assert!(should_fallback_after_handshake_error(
            &pre_welcome_io,
            false,
            false
        ));

        // 2) 用户主动断开：严禁回退。
        assert!(!should_fallback_after_handshake_error(
            &pre_welcome_abort,
            false,
            true
        ));

        // 3) 已进入鉴权/审批交互（已收 Welcome{ChallengeRequired} 或 AuthChallenge）：
        //    无论是断连还是等待审批期超时，均严禁回退（防被控端连弹多个审批窗）。
        assert!(!should_fallback_after_handshake_error(
            &pre_welcome_abort,
            true,
            false
        ));
        assert!(!should_fallback_after_handshake_error(
            &rc_types::Error::Timeout(Duration::from_secs(45)),
            true,
            false
        ));

        // 4) Welcome 前半开黑洞超时（!entered_auth_or_approval）：允许回退下一级链路。
        assert!(should_fallback_after_handshake_error(
            &rc_types::Error::Timeout(LAN_DIRECT_HANDSHAKE_TIMEOUT),
            false,
            false
        ));

        // 5) 协议/鉴权拒绝/版本不兼容：严禁回退。
        assert!(!should_fallback_after_handshake_error(
            &rc_types::Error::Protocol {
                offset: 0,
                msg: "authentication rejected by host".to_string(),
            },
            false,
            false
        ));
        assert!(!should_fallback_after_handshake_error(
            &rc_types::Error::Network("protocol version incompatible".to_string()),
            false,
            false
        ));

        // 6) mTLS 证书校验失败（含客户端验服务端失败与服务端拒收客户端证书的 QUIC CRYPTO_ERROR alert）：严禁回退。
        assert!(!should_fallback_after_handshake_error(
            &rc_types::Error::Network("InvalidPeerCertificate(UnknownIssuer)".to_string()),
            false,
            false
        ));
        assert!(!should_fallback_after_handshake_error(
            &rc_types::Error::Network(
                "disconnected while waiting for Welcome: the cryptographic handshake failed: error 48"
                    .to_string(),
            ),
            false,
            false
        ));
        assert!(is_mtls_cert_or_config_error(
            "the cryptographic handshake failed: error 42"
        ));
        assert!(is_mtls_cert_or_config_error("crypto error: unknown ca"));
        assert!(is_mtls_cert_or_config_error("certificate required"));

        // 7) 真实 ClientSession 状态机校验：收到 Welcome{ChallengeRequired} 进入审批等待后超时，
        //    handshake_entered_auth() 必须为 true，且绝不允许回退。
        {
            struct PendingApprovalMockTransport {
                sent_challenge_required: bool,
                session_id: u64,
            }
            impl Transport for PendingApprovalMockTransport {
                fn send_datagram(&mut self, _data: &[u8]) -> rc_types::Result<()> {
                    Ok(())
                }
                fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
                    if let Ok(ControlMessage::Hello(h)) = ControlMessage::decode(data) {
                        self.session_id = h.session_id;
                    }
                    Ok(())
                }
                fn send_reliable_urgent(&mut self, _data: &[u8]) -> rc_types::Result<()> {
                    Ok(())
                }
                fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
                    if !self.sent_challenge_required && self.session_id != 0 {
                        self.sent_challenge_required = true;
                        let mut buf = Vec::new();
                        ControlMessage::Welcome(rc_session::proto::Welcome {
                            session_id: self.session_id,
                            granted: SessionParams {
                                width: 640,
                                height: 360,
                                fps: 30,
                                bitrate_bps: 2_000_000,
                            },
                            auth_status: rc_session::proto::AuthStatus::ChallengeRequired,
                            host_flags: rc_session::proto::HostFlags(0),
                        })
                        .encode(&mut buf);
                        return Ok(vec![NetEvent::Reliable(buf)]);
                    }
                    thread::sleep(timeout.min(Duration::from_millis(15)));
                    Ok(Vec::new())
                }
                fn stats(&self) -> NetStats {
                    NetStats::default()
                }
                fn set_pacing_rate(&mut self, _bps: u64) {}
            }

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
            let t0 = Instant::now();
            let (clock, _) = reanchorable_clock(t0);
            let mut ccfg = ClientSessionConfig::new(
                "127.0.0.1:9901".parse().unwrap(),
                SessionParams {
                    width: 640,
                    height: 360,
                    fps: 30,
                    bitrate_bps: 2_000_000,
                },
                7777,
                Box::new(BridgeInputCapture {
                    queue: Arc::new(BoundedInputQueue::new(16)),
                    watch_only: Arc::new(AtomicBool::new(false)),
                }),
            );
            ccfg.handshake_timeout = Duration::from_secs(3);
            ccfg.auth.auth_timeout_us = 120_000; // 120ms 审批超时
            let mut client = ClientSession::with_parts(
                ccfg,
                Box::new(PendingApprovalMockTransport {
                    sent_challenge_required: false,
                    session_id: 0,
                }),
                Box::new(dummy_dec),
                Box::new(dummy_ren),
                clock,
            )
            .expect("client with_parts");
            let err = client
                .handshake()
                .expect_err("pending approval must time out");
            assert!(
                matches!(err, rc_types::Error::Timeout(_)),
                "expected Timeout during approval wait, got {err:?}"
            );
            assert!(
                client.handshake_entered_auth(),
                "Welcome{{ChallengeRequired}} must mark handshake_entered_auth = true"
            );
            assert!(
                !should_fallback_after_handshake_error(
                    &err,
                    client.handshake_entered_auth(),
                    false
                ),
                "approval timeout after Welcome{{ChallengeRequired}} must never fall back"
            );
        }
    }

    fn spawn_loopback_rcr1_relay_server(expected_token: String) -> (SocketAddr, JoinHandle<()>) {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock rcr1 relay");
        let addr = listener.local_addr().expect("mock relay addr");
        let handle = thread::spawn(move || {
            let Ok((mut s1, _)) = listener.accept() else {
                return;
            };
            let Ok((mut s2, _)) = listener.accept() else {
                return;
            };
            let _ = s1.set_nodelay(true);
            let _ = s2.set_nodelay(true);

            let read_hs = |s: &mut std::net::TcpStream| -> Option<u8> {
                let mut head = [0u8; 6];
                s.read_exact(&mut head).ok()?;
                if &head[0..4] != b"RCR1" {
                    return None;
                }
                let role = head[4];
                let mut tok = vec![0u8; head[5] as usize];
                s.read_exact(&mut tok).ok()?;
                if std::str::from_utf8(&tok).ok()? != expected_token {
                    return None;
                }
                Some(role)
            };
            let Some(r1) = read_hs(&mut s1) else {
                return;
            };
            let Some(r2) = read_hs(&mut s2) else {
                return;
            };
            if r1 == r2 {
                return;
            }
            if s1.write_all(&[0x00]).is_err() || s2.write_all(&[0x00]).is_err() {
                return;
            }
            let Ok(mut s1_r) = s1.try_clone() else {
                return;
            };
            let Ok(mut s2_w) = s2.try_clone() else {
                return;
            };
            let t1 = thread::spawn(move || {
                let _ = std::io::copy(&mut s1_r, &mut s2_w);
                let _ = s2_w.shutdown(Shutdown::Write);
            });
            let t2 = thread::spawn(move || {
                let _ = std::io::copy(&mut s2, &mut s1);
                let _ = s1.shutdown(Shutdown::Write);
            });
            let _ = t1.join();
            let _ = t2.join();
        });
        (addr, handle)
    }

    #[test]
    fn tier1_lan_pre_welcome_disconnect_falls_back_to_relay_and_succeeds() {
        struct NoopInjector;
        impl rc_input::InputInjector for NoopInjector {
            fn inject(&mut self, _events: &[InputEvent]) -> rc_types::Result<()> {
                Ok(())
            }
            fn set_screen_size(&mut self, _width: u32, _height: u32) {}
        }

        // 1) Tier 1 模拟 LAN QUIC 端点：完成 QUIC 建连并收到 Hello 后，在发 Welcome 前主动关闭连接。
        let lan_id = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");
        let lan_ep = QuicEndpoint::new(
            &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
            &lan_id,
        )
        .expect("lan ep");
        let lan_addr = lan_ep.local_addr().expect("lan addr");
        let lan_saw_hello = Arc::new(AtomicBool::new(false));
        let t_lan_saw_hello = Arc::clone(&lan_saw_hello);
        let lan_thread = thread::spawn(move || {
            let mut transport = lan_ep
                .accept_with_handshake_timeout(Duration::from_secs(5), Duration::from_secs(5), None)
                .expect("lan accept");
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                for ev in transport.poll(Duration::from_millis(20)).expect("lan poll") {
                    if matches!(ev, NetEvent::Reliable(_)) {
                        t_lan_saw_hello.store(true, Ordering::Release);
                        // 不发 Welcome，直接 drop 关闭连接，复现 Issue #4 场景。
                        return;
                    }
                }
            }
        });

        // 2) Tier 3 模拟本地 RCR1 中继服务器 + 正常 HostSession。
        let token = "fallback-tok-1".to_string();
        let (relay_addr, relay_srv) = spawn_loopback_rcr1_relay_server(token.clone());
        let host_stop = Arc::new(AtomicBool::new(false));
        let t_host_stop = Arc::clone(&host_stop);
        let relay_addr_str = relay_addr.to_string();
        let host_thread = thread::spawn(move || {
            let transport = TcpRelayTransport::connect(
                &relay_addr_str,
                RelayRole::Host,
                &token,
                Duration::from_secs(5),
            )
            .expect("host connect relay");
            let (hclock, _) = reanchorable_clock(Instant::now());
            let caps = SessionParams {
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
            };
            let mut hcfg = rc_session::HostSessionConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                caps,
                Box::new(NoopInjector),
            );
            hcfg.handshake_timeout = Duration::from_secs(5);
            let cap = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
                display: rc_capture::DisplayInfo {
                    id: rc_types::DisplayId(0),
                    resolution: Resolution::new(640, 360),
                    scale: 1.0,
                    hdr: false,
                },
                fps: 30,
                content: rc_capture::FakeContent::Static,
                dirty_rect: None,
            })
            .expect("fake cap");
            let enc = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
                resolution: Resolution::new(640, 360),
                fps: 30,
                bitrate_bps: 2_000_000,
                ..rc_encode::EncoderConfig::default()
            })
            .expect("fake enc");
            let mut host = rc_session::HostSession::with_parts(
                hcfg,
                Box::new(transport),
                Box::new(cap),
                Box::new(enc),
                hclock,
            )
            .expect("host with_parts");
            host.handshake().expect("relay host handshake");
            let deadline = Instant::now() + Duration::from_secs(5);
            while !t_host_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                if host.tick(Duration::from_millis(10)).is_err()
                    || host.state() == SessionState::Closed
                {
                    break;
                }
            }
        });

        // 3) 控制端同时持有 Tier 1 LAN 地址与 Tier 3 Relay 凭据，验证自动回退至 TCP Relay 并握手成功。
        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: "127.0.0.1:1".parse().unwrap(),
            lan_direct_addr: Some(lan_addr),
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            connection_mode: ConnectionMode::Auto,
            relay_grant: Some(ConnectGrant {
                session_id: "sess-lan-fallback".to_string(),
                relay_addr: relay_addr.to_string(),
                relay_token: "fallback-tok-1".to_string(),
                target_id: "900000002".to_string(),
                ..ConnectGrant::default()
            }),
            ..UiSessionConfig::default()
        });

        let deadline = Instant::now() + Duration::from_secs(8);
        let mut negotiated_transport: Option<String> = None;
        while Instant::now() < deadline {
            if let Some(upd) = session.try_recv_update() {
                match upd {
                    SessionUpdate::Negotiated { transport, .. } => {
                        negotiated_transport = Some(transport);
                        break;
                    }
                    SessionUpdate::Ended { reason, .. } => {
                        panic!(
                            "expected automatic fallback to TCP Relay, but ended early: {reason}"
                        );
                    }
                    _ => {}
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        host_stop.store(true, Ordering::Release);
        session.trigger_disconnect();
        session.join();
        let _ = lan_thread.join();
        let _ = host_thread.join();
        let _ = relay_srv.join();

        assert!(
            lan_saw_hello.load(Ordering::Acquire),
            "Tier 1 LAN must have been attempted and received Hello before closing"
        );
        assert_eq!(
            negotiated_transport.as_deref(),
            Some("TCP Relay"),
            "controller must fall back to Tier 3 TCP Relay after pre-Welcome LAN disconnect"
        );
    }

    #[test]
    fn tier1_lan_auth_reject_mtls_p2p_only_and_post_challenge_never_fallback_to_relay() {
        use crate::relay_transport::tests::mtls_test_certs::TestCa;
        use rc_session::proto::{AuthChallenge, AuthStatus, HostFlags, Welcome};

        fn spawn_spy_relay() -> (SocketAddr, Arc<AtomicBool>, Arc<AtomicBool>, JoinHandle<()>) {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind spy relay");
            listener.set_nonblocking(true).expect("nonblocking");
            let addr = listener.local_addr().expect("spy addr");
            let touched = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let t_touched = Arc::clone(&touched);
            let t_stop = Arc::clone(&stop);
            let jh = thread::spawn(move || {
                while !t_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok(_) => {
                            t_touched.store(true, Ordering::SeqCst);
                            break;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            (addr, touched, stop, jh)
        }

        fn wait_session_end(session: SessionHandle) -> (String, bool) {
            let deadline = Instant::now() + Duration::from_secs(6);
            let mut ended = None;
            while Instant::now() < deadline {
                if let Some(SessionUpdate::Ended {
                    reason,
                    recoverable,
                    ..
                }) = session.try_recv_update()
                {
                    ended = Some((reason, recoverable));
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            session.join();
            ended.expect("session must terminate with Ended")
        }

        let dev_id = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");

        // 场景 A：鉴权拒绝（Welcome{Rejected}）绝不回退中继。
        {
            let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
            let lan_ep = QuicEndpoint::new(
                &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
                &dev_id,
            )
            .expect("lan ep");
            let lan_addr = lan_ep.local_addr().expect("lan addr");
            let lan_jh = thread::spawn(move || {
                let mut t = lan_ep
                    .accept_with_handshake_timeout(
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                        None,
                    )
                    .expect("lan accept");
                let deadline = Instant::now() + Duration::from_secs(3);
                while Instant::now() < deadline {
                    for ev in t.poll(Duration::from_millis(20)).expect("poll") {
                        if let NetEvent::Reliable(bytes) = ev {
                            if let Ok(ControlMessage::Hello(h)) = ControlMessage::decode(&bytes) {
                                let mut out = Vec::new();
                                ControlMessage::Welcome(Welcome {
                                    session_id: h.session_id,
                                    granted: h.requested,
                                    auth_status: AuthStatus::Rejected,
                                    host_flags: HostFlags(0),
                                })
                                .encode(&mut out);
                                let _ = t.send_reliable(&out);
                                let _ = t.poll(Duration::from_millis(50));
                                return;
                            }
                        }
                    }
                }
            });

            let session = SessionHandle::spawn(UiSessionConfig {
                connect_addr: "127.0.0.1:1".parse().unwrap(),
                lan_direct_addr: Some(lan_addr),
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
                connection_mode: ConnectionMode::Auto,
                relay_grant: Some(ConnectGrant {
                    session_id: "sess-auth-reject".to_string(),
                    relay_addr: spy_addr.to_string(),
                    relay_token: "unused".to_string(),
                    target_id: "900000003".to_string(),
                    ..ConnectGrant::default()
                }),
                ..UiSessionConfig::default()
            });
            let (reason, recoverable) = wait_session_end(session);
            spy_stop.store(true, Ordering::Release);
            let _ = spy_jh.join();
            let _ = lan_jh.join();
            assert!(!recoverable, "auth reject must be fatal: {reason}");
            assert!(
                !touched.load(Ordering::SeqCst),
                "auth rejection on Tier 1 must never fall back to Tier 3 relay"
            );
        }

        // 场景 B：已收到 Welcome{ChallengeRequired} + AuthChallenge 后对端断连/审批等待失败，绝不回退中继（防连弹审批窗）。
        {
            let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
            let lan_ep = QuicEndpoint::new(
                &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
                &dev_id,
            )
            .expect("lan ep");
            let lan_addr = lan_ep.local_addr().expect("lan addr");
            let lan_jh = thread::spawn(move || {
                let mut t = lan_ep
                    .accept_with_handshake_timeout(
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                        None,
                    )
                    .expect("lan accept");
                let deadline = Instant::now() + Duration::from_secs(3);
                while Instant::now() < deadline {
                    for ev in t.poll(Duration::from_millis(20)).expect("poll") {
                        if let NetEvent::Reliable(bytes) = ev {
                            if let Ok(ControlMessage::Hello(h)) = ControlMessage::decode(&bytes) {
                                let mut w_buf = Vec::new();
                                ControlMessage::Welcome(Welcome {
                                    session_id: h.session_id,
                                    granted: h.requested,
                                    auth_status: AuthStatus::ChallengeRequired,
                                    host_flags: HostFlags(0),
                                })
                                .encode(&mut w_buf);
                                let _ = t.send_reliable(&w_buf);
                                let mut ch_buf = Vec::new();
                                ControlMessage::AuthChallenge(AuthChallenge {
                                    salt: [0x42u8; 16],
                                    iterations: 1_000,
                                })
                                .encode(&mut ch_buf);
                                let _ = t.send_reliable(&ch_buf);
                                // 等待控制端收到挑战并回复 AuthResponse 后再关闭连接。
                                let wait_resp = Instant::now() + Duration::from_secs(2);
                                while Instant::now() < wait_resp {
                                    if t.poll(Duration::from_millis(20))
                                        .unwrap_or_default()
                                        .iter()
                                        .any(|e| matches!(e, NetEvent::Reliable(_)))
                                    {
                                        break;
                                    }
                                }
                                return;
                            }
                        }
                    }
                }
            });

            let session = SessionHandle::spawn(UiSessionConfig {
                connect_addr: "127.0.0.1:1".parse().unwrap(),
                lan_direct_addr: Some(lan_addr),
                password: Some("test-pass".to_string()),
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
                connection_mode: ConnectionMode::Auto,
                relay_grant: Some(ConnectGrant {
                    session_id: "sess-post-challenge".to_string(),
                    relay_addr: spy_addr.to_string(),
                    relay_token: "unused".to_string(),
                    target_id: "900000004".to_string(),
                    ..ConnectGrant::default()
                }),
                ..UiSessionConfig::default()
            });
            let (_reason, recoverable) = wait_session_end(session);
            spy_stop.store(true, Ordering::Release);
            let _ = spy_jh.join();
            let _ = lan_jh.join();
            assert!(!recoverable);
            assert!(
                !touched.load(Ordering::SeqCst),
                "disconnect after AuthChallenge/approval prompt must never fall back to Tier 3 relay"
            );
        }

        // 场景 C：mTLS 证书校验失败绝不回退中继。
        {
            let mut client_ca = TestCa::new("ClientTrustedCA");
            let (c_cert, c_key) = client_ca.issue_device("u1", "100000010");
            let mut rogue_ca = TestCa::new("RogueHostCA");
            let (h_cert, h_key) = rogue_ca.issue_device("u1", "200000020");

            let host_bundle = SessionMtlsBundle {
                ca_cert_pem: rogue_ca.ca_pem.clone(),
                cert_pem: h_cert,
                key_pem: h_key,
                local_user_id: "u1".to_string(),
                expected_peer_device_id: None,
                expected_peer_user_id: None,
            };
            let client_bundle = SessionMtlsBundle {
                ca_cert_pem: client_ca.ca_pem.clone(),
                cert_pem: c_cert,
                key_pem: c_key,
                local_user_id: "u1".to_string(),
                expected_peer_device_id: Some("200000020".to_string()),
                expected_peer_user_id: None,
            };

            let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
            let lan_ep = QuicEndpoint::new_mtls(
                &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
                &host_bundle.to_quic_mtls_config().expect("host mtls"),
            )
            .expect("mtls lan ep");
            let lan_addr = lan_ep.local_addr().expect("mtls lan addr");
            let lan_jh = thread::spawn(move || {
                let _ = lan_ep.accept_with_handshake_timeout(
                    Duration::from_secs(3),
                    Duration::from_secs(2),
                    None,
                );
            });

            let session = SessionHandle::spawn(UiSessionConfig {
                connect_addr: "127.0.0.1:1".parse().unwrap(),
                lan_direct_addr: Some(lan_addr),
                encrypt_connection: true,
                mtls_config: Some(client_bundle),
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
                connection_mode: ConnectionMode::Auto,
                relay_grant: Some(ConnectGrant {
                    session_id: "sess-mtls-fail".to_string(),
                    relay_addr: spy_addr.to_string(),
                    relay_token: "unused".to_string(),
                    target_id: "200000020".to_string(),
                    ..ConnectGrant::default()
                }),
                ..UiSessionConfig::default()
            });
            let (reason, recoverable) = wait_session_end(session);
            spy_stop.store(true, Ordering::Release);
            let _ = spy_jh.join();
            let _ = lan_jh.join();
            assert!(!recoverable, "mTLS failure must be fatal: {reason}");
            assert!(
                reason.contains("mTLS") || reason.contains("证书"),
                "expected mTLS error message, got: {reason}"
            );
            assert!(
                !touched.load(Ordering::SeqCst),
                "mTLS certificate verification failure must never fall back to Tier 3 relay"
            );
        }

        // 场景 D：P2pOnly 模式下 Tier 1 LAN 在 Welcome 前断连，绝不回退至 Tier 3 Relay。
        {
            let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
            let lan_ep = QuicEndpoint::new(
                &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
                &dev_id,
            )
            .expect("lan ep");
            let lan_addr = lan_ep.local_addr().expect("lan addr");
            let lan_jh = thread::spawn(move || {
                let mut t = lan_ep
                    .accept_with_handshake_timeout(
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                        None,
                    )
                    .expect("lan accept");
                let deadline = Instant::now() + Duration::from_secs(3);
                while Instant::now() < deadline {
                    if t.poll(Duration::from_millis(20))
                        .unwrap_or_default()
                        .iter()
                        .any(|e| matches!(e, NetEvent::Reliable(_)))
                    {
                        return; // 收到 Hello 后不发 Welcome 直接断开
                    }
                }
            });

            let session = SessionHandle::spawn(UiSessionConfig {
                connect_addr: "127.0.0.1:1".parse().unwrap(),
                lan_direct_addr: Some(lan_addr),
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
                connection_mode: ConnectionMode::P2pOnly,
                relay_grant: Some(ConnectGrant {
                    session_id: "sess-p2p-only-pre-welcome".to_string(),
                    relay_addr: spy_addr.to_string(),
                    relay_token: "unused".to_string(),
                    target_id: "900000005".to_string(),
                    ..ConnectGrant::default()
                }),
                ..UiSessionConfig::default()
            });
            let (reason, recoverable) = wait_session_end(session);
            spy_stop.store(true, Ordering::Release);
            let _ = spy_jh.join();
            let _ = lan_jh.join();
            assert!(!recoverable);
            assert!(
                reason.contains("仅 P2P") && reason.contains("未回退中继"),
                "expected P2pOnly refusal message, got: {reason}"
            );
            assert!(
                !touched.load(Ordering::SeqCst),
                "P2pOnly must never fall back to Tier 3 relay even after pre-Welcome LAN disconnect"
            );
        }

        // 场景 E：Tier 1 MtlsLan 服务端拒收非法客户端证书（客户端验过服务端证书并完成 TLS 1.3 ClientFinished，
        // 随后收到服务端 QUIC CRYPTO_ERROR alert），控制端绝不回退至 Tier 3 中继。
        {
            let mut trusted_ca = TestCa::new("TrustedHostCA");
            let (h_cert, h_key) = trusted_ca.issue_device("u-host", "200000030");
            let mut rogue_client_ca = TestCa::new("RogueClientCA");
            let (bad_c_cert, bad_c_key) = rogue_client_ca.issue_device("u-bad", "100000030");

            let host_bundle = SessionMtlsBundle {
                ca_cert_pem: trusted_ca.ca_pem.clone(),
                cert_pem: h_cert,
                key_pem: h_key,
                local_user_id: "u-host".to_string(),
                expected_peer_device_id: None,
                expected_peer_user_id: None,
            };
            // 客户端信任服务端 CA（所以客户端能通过服务端证书校验），但出示由 rogue_client_ca 签发的非法客户端证书。
            let rogue_client_bundle = SessionMtlsBundle {
                ca_cert_pem: trusted_ca.ca_pem.clone(),
                cert_pem: bad_c_cert,
                key_pem: bad_c_key,
                local_user_id: "u-bad".to_string(),
                expected_peer_device_id: Some("200000030".to_string()),
                expected_peer_user_id: None,
            };

            let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
            let lan_ep = QuicEndpoint::new_mtls(
                &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
                &host_bundle.to_quic_mtls_config().expect("host mtls"),
            )
            .expect("mtls lan ep");
            let lan_addr = lan_ep.local_addr().expect("mtls lan addr");
            let lan_stop = Arc::new(AtomicBool::new(false));
            let t_lan_stop = Arc::clone(&lan_stop);
            let lan_jh = thread::spawn(move || {
                let res = lan_ep.accept_with_handshake_timeout(
                    Duration::from_secs(3),
                    Duration::from_secs(2),
                    None,
                );
                assert!(
                    res.is_err(),
                    "MtlsLan server must reject untrusted client certificate"
                );
                // 保持端点存活（对齐真实 HostListener::MtlsLan 行为），确保 QUIC CRYPTO_ERROR alert 完整送达对端。
                let wait_until = Instant::now() + Duration::from_secs(3);
                while !t_lan_stop.load(Ordering::Acquire) && Instant::now() < wait_until {
                    thread::sleep(Duration::from_millis(10));
                }
            });

            let session = SessionHandle::spawn(UiSessionConfig {
                connect_addr: "127.0.0.1:1".parse().unwrap(),
                lan_direct_addr: Some(lan_addr),
                encrypt_connection: true,
                mtls_config: Some(rogue_client_bundle),
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
                connection_mode: ConnectionMode::Auto,
                relay_grant: Some(ConnectGrant {
                    session_id: "sess-server-reject-client-cert".to_string(),
                    relay_addr: spy_addr.to_string(),
                    relay_token: "unused".to_string(),
                    target_id: "200000030".to_string(),
                    ..ConnectGrant::default()
                }),
                ..UiSessionConfig::default()
            });
            let (reason, recoverable) = wait_session_end(session);
            lan_stop.store(true, Ordering::Release);
            spy_stop.store(true, Ordering::Release);
            let _ = spy_jh.join();
            let _ = lan_jh.join();
            assert!(
                !recoverable,
                "server client-cert rejection must be fatal: {reason}"
            );
            assert!(
                !touched.load(Ordering::SeqCst),
                "server rejecting client mTLS certificate must never fall back to Tier 3 relay: {reason}"
            );
        }
    }

    #[test]
    fn tier1_lan_pre_welcome_blackhole_timeout_falls_back_to_relay_and_succeeds() {
        struct NoopInjector;
        impl rc_input::InputInjector for NoopInjector {
            fn inject(&mut self, _events: &[InputEvent]) -> rc_types::Result<()> {
                Ok(())
            }
            fn set_screen_size(&mut self, _width: u32, _height: u32) {}
        }

        // 1) Tier 1 LAN 完成 QUIC 建连并收到 Hello 后保持静默黑洞（既不发 Welcome 也不发 AuthChallenge），
        //    等待 3s 超时后控制端必须自动回退至 Tier 3 TCP Relay 成功握手。
        let lan_id = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");
        let lan_ep = QuicEndpoint::new(
            &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
            &lan_id,
        )
        .expect("lan ep");
        let lan_addr = lan_ep.local_addr().expect("lan addr");
        let lan_stop = Arc::new(AtomicBool::new(false));
        let t_lan_stop = Arc::clone(&lan_stop);
        let lan_saw_hello = Arc::new(AtomicBool::new(false));
        let t_lan_saw_hello = Arc::clone(&lan_saw_hello);
        let lan_thread = thread::spawn(move || {
            let mut transport = lan_ep
                .accept_with_handshake_timeout(Duration::from_secs(5), Duration::from_secs(5), None)
                .expect("lan accept");
            let deadline = Instant::now() + Duration::from_secs(8);
            while !t_lan_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                if let Ok(events) = transport.poll(Duration::from_millis(20)) {
                    if events.iter().any(|ev| matches!(ev, NetEvent::Reliable(_))) {
                        t_lan_saw_hello.store(true, Ordering::Release);
                    }
                }
            }
        });

        let token = "fallback-timeout-tok-1".to_string();
        let (relay_addr, relay_srv) = spawn_loopback_rcr1_relay_server(token.clone());
        let host_stop = Arc::new(AtomicBool::new(false));
        let t_host_stop = Arc::clone(&host_stop);
        let relay_addr_str = relay_addr.to_string();
        let host_thread = thread::spawn(move || {
            let transport = TcpRelayTransport::connect(
                &relay_addr_str,
                RelayRole::Host,
                &token,
                Duration::from_secs(8),
            )
            .expect("host connect relay");
            let (hclock, _) = reanchorable_clock(Instant::now());
            let caps = SessionParams {
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
            };
            let mut hcfg = rc_session::HostSessionConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                caps,
                Box::new(NoopInjector),
            );
            hcfg.handshake_timeout = Duration::from_secs(5);
            let cap = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
                display: rc_capture::DisplayInfo {
                    id: rc_types::DisplayId(0),
                    resolution: Resolution::new(640, 360),
                    scale: 1.0,
                    hdr: false,
                },
                fps: 30,
                content: rc_capture::FakeContent::Static,
                dirty_rect: None,
            })
            .expect("fake cap");
            let enc = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
                resolution: Resolution::new(640, 360),
                fps: 30,
                bitrate_bps: 2_000_000,
                ..rc_encode::EncoderConfig::default()
            })
            .expect("fake enc");
            let mut host = rc_session::HostSession::with_parts(
                hcfg,
                Box::new(transport),
                Box::new(cap),
                Box::new(enc),
                hclock,
            )
            .expect("host with_parts");
            host.handshake().expect("relay host handshake");
            let deadline = Instant::now() + Duration::from_secs(5);
            while !t_host_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                if host.tick(Duration::from_millis(10)).is_err()
                    || host.state() == SessionState::Closed
                {
                    break;
                }
            }
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: "127.0.0.1:1".parse().unwrap(),
            lan_direct_addr: Some(lan_addr),
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            connection_mode: ConnectionMode::Auto,
            relay_grant: Some(ConnectGrant {
                session_id: "sess-lan-blackhole-fallback".to_string(),
                relay_addr: relay_addr.to_string(),
                relay_token: "fallback-timeout-tok-1".to_string(),
                target_id: "900000006".to_string(),
                ..ConnectGrant::default()
            }),
            ..UiSessionConfig::default()
        });

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut negotiated_transport: Option<String> = None;
        while Instant::now() < deadline {
            if let Some(upd) = session.try_recv_update() {
                match upd {
                    SessionUpdate::Negotiated { transport, .. } => {
                        negotiated_transport = Some(transport);
                        break;
                    }
                    SessionUpdate::Ended { reason, .. } => {
                        panic!("expected automatic fallback after pre-Welcome timeout, ended early: {reason}");
                    }
                    _ => {}
                }
            }
            thread::sleep(Duration::from_millis(15));
        }

        lan_stop.store(true, Ordering::Release);
        host_stop.store(true, Ordering::Release);
        session.trigger_disconnect();
        session.join();
        let _ = lan_thread.join();
        let _ = host_thread.join();
        let _ = relay_srv.join();

        assert!(
            lan_saw_hello.load(Ordering::Acquire),
            "Tier 1 LAN must have received Hello before blackhole timeout"
        );
        assert_eq!(
            negotiated_transport.as_deref(),
            Some("TCP Relay"),
            "controller must fall back to Tier 3 TCP Relay after pre-Welcome blackhole timeout"
        );
    }

    #[test]
    fn tool_permissions_state_pre_send_gate_and_remote_denied_emit_structured_ui_error() {
        // 1) handle_display_ctrl_msg 正确映射 ToolPermissionsState 与 ToolPermissionDenied -> UiError(tool.forbidden)。
        let mut w = 1280;
        let mut h = 720;
        let perms_upd = handle_display_ctrl_msg(
            DisplayControlMsg::ToolPermissionsState {
                allow_file_transfer: false,
                allow_terminal: false,
                allow_port_map: false,
            },
            &mut w,
            &mut h,
            false,
        );
        assert_eq!(
            perms_upd,
            Some(SessionUpdate::ToolPermissionsUpdated(ToolPermissions {
                allow_file_transfer: false,
                allow_terminal: false,
                allow_port_map: false,
            }))
        );
        let perms_json = serde_json::to_value(perms_upd.unwrap()).expect("serialize perms upd");
        assert_eq!(perms_json["kind"], "tool_permissions_updated");
        assert_eq!(perms_json["data"]["allow_file_transfer"], false);
        assert_eq!(perms_json["data"]["allow_terminal"], false);
        assert_eq!(perms_json["data"]["allow_port_map"], false);

        let denied_upd = handle_display_ctrl_msg(
            DisplayControlMsg::ToolPermissionDenied {
                channel: TOOL_CHANNEL_FILE,
                reason: Some("remote host denied".to_string()),
            },
            &mut w,
            &mut h,
            false,
        );
        match denied_upd {
            Some(SessionUpdate::ToolPermissionDenied { channel, ui_error }) => {
                assert_eq!(channel, TOOL_CHANNEL_FILE);
                assert_eq!(ui_error.code, crate::ui_error::codes::TOOL_FORBIDDEN);
                assert!(ui_error.message.contains("文件传输"));
                assert_eq!(ui_error.detail.as_deref(), Some("remote host denied"));
            }
            other => panic!("expected ToolPermissionDenied, got {other:?}"),
        }

        // 2) 端到端 HostHandle + SessionHandle：非 Owner 被控端禁止终端/端口映射并受协助文件开关控制 + 运行期热开关不中断会话。
        let mut host = crate::host_bridge::HostHandle::spawn(crate::host_bridge::UiHostConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            allow_assist_file_transfer: false,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            ..crate::host_bridge::UiHostConfig::default()
        })
        .expect("spawn host");
        let host_addr = host.listen_addr();

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: host_addr,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            width: 320,
            height: 240,
            fps: 30,
            ..UiSessionConfig::default()
        });

        let deadline = Instant::now() + Duration::from_secs(6);
        let mut saw_initial_denied_perm = false;
        while Instant::now() < deadline {
            while let Some(upd) = session.try_recv_update() {
                if let SessionUpdate::ToolPermissionsUpdated(p) = upd {
                    if !p.allow_file_transfer && !p.allow_terminal && !p.allow_port_map {
                        saw_initial_denied_perm = true;
                    }
                }
            }
            if saw_initial_denied_perm {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            saw_initial_denied_perm,
            "controller must receive ToolPermissionsUpdated(all false for non-owner with assist file off)"
        );
        assert!(!session.tool_permissions().allow_file_transfer);
        assert!(!session.tool_permissions().allow_terminal);
        assert!(!session.tool_permissions().allow_port_map);

        let term_err = session
            .tools()
            .terminal_open(80, 24)
            .expect_err("non-owner terminal_open must be blocked");
        assert!(term_err.contains("远程终端"), "unexpected err: {term_err}");
        let pm_err = session
            .tools()
            .portmap_add("pm".to_string(), 18080, "127.0.0.1".to_string(), 80)
            .expect_err("non-owner portmap_add must be blocked");
        assert!(pm_err.contains("端口映射"), "unexpected err: {pm_err}");

        // 控制端尝试发起文件列表与上传请求 -> ToolClientHandle 入口前置拦截，返回 Err、不创建僵尸 Active 任务，
        // 并输出结构化 UiError(tool.forbidden)。
        let list_err = session
            .tools()
            .file_list_remote(None)
            .expect_err("file_list_remote must be blocked when allow_file_transfer=false");
        assert!(list_err.contains("文件传输"), "unexpected err: {list_err}");

        let tmp_dir = std::env::temp_dir().join(format!(
            "rc-session-tool-gate-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let sample_file = tmp_dir.join("blocked_upload.bin");
        std::fs::write(&sample_file, vec![0x11u8; 4096]).unwrap();

        let upload_err = session
            .tools()
            .file_upload(sample_file.to_str().unwrap(), tmp_dir.to_str().unwrap())
            .expect_err("file_upload must be blocked at ToolClientHandle before opening file");
        assert!(upload_err.contains("文件传输"));
        assert!(
            session.tools().file_list_transfers().is_empty(),
            "blocked file_upload must never leave a zombie Active transfer entry"
        );

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut denied_err: Option<UiError> = None;
        while Instant::now() < deadline {
            while let Some(upd) = session.try_recv_update() {
                if let SessionUpdate::ToolPermissionDenied { channel, ui_error } = upd {
                    if channel == TOOL_CHANNEL_FILE {
                        denied_err = Some(ui_error);
                    }
                }
            }
            if denied_err.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let ui_err = denied_err.expect("controller must emit ToolPermissionDenied for FILE");
        assert_eq!(ui_err.code, crate::ui_error::codes::TOOL_FORBIDDEN);
        assert!(ui_err.message.contains("文件传输"));

        // 被控端运行期热开启再热关闭 allow_assist_file_transfer，会话保持存活且控制端实时同步。
        host.set_allow_assist_file_transfer(true);
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_reenabled = false;
        while Instant::now() < deadline {
            while let Some(upd) = session.try_recv_update() {
                if let SessionUpdate::ToolPermissionsUpdated(p) = upd {
                    if p.allow_file_transfer {
                        saw_reenabled = true;
                    }
                }
            }
            if saw_reenabled {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            saw_reenabled && session.is_running() && session.tool_permissions().allow_file_transfer,
            "hot-enabling allow_assist_file_transfer must sync without disconnecting"
        );

        // 验证 FileClientWorker::abort_all_active 能立即中止在途传输并推 Failed 事件（无僵尸 Active）。
        let file_events = Arc::new(BoundedQueue::new(32));
        let (mut worker, fhandle) = FileClientWorker::spawn(Arc::clone(&file_events));
        let tid = fhandle
            .send_cmd(|reply| FileWorkerCmd::StartUpload {
                local_path: sample_file.to_string_lossy().to_string(),
                remote_dir: tmp_dir.to_string_lossy().to_string(),
                reply,
            })
            .expect("start_upload on worker");
        assert!(fhandle
            .cached_transfers
            .lock()
            .unwrap()
            .iter()
            .any(|t| t.id == tid && t.status == TransferStatus::Active));
        worker.abort_all_active("host revoked file transfer");
        let abort_deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_failed_ev = false;
        while Instant::now() < abort_deadline && !saw_failed_ev {
            while let Some(ev) = file_events.try_pop() {
                if let FileEvent::TransferUpdated(item) = ev {
                    if item.id == tid && item.status == TransferStatus::Failed {
                        saw_failed_ev = true;
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            saw_failed_ev,
            "FileClientWorker::abort_all_active must emit TransferUpdated(Failed)"
        );
        assert!(
            fhandle
                .cached_transfers
                .lock()
                .unwrap()
                .iter()
                .all(|t| t.status != TransferStatus::Active),
            "no zombie Active transfers may remain after abort_all_active"
        );
        worker.shutdown();

        session.send(SessionCommand::Disconnect);
        session.join();
        host.stop();
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn client_media_caps_builder_and_av1_command_roundtrip() {
        let caps = rc_pipeline::default_codec_capabilities(true);
        let msg = build_client_media_caps_msg(&caps, true, CodecSelectionPref::OfficeClear);
        match msg {
            DisplayControlMsg::ClientMediaCaps {
                decode_caps,
                pref,
                supports_ext_codec_flags,
                ..
            } => {
                assert_eq!(decode_caps, caps);
                assert_eq!(pref, CodecSelectionPref::OfficeClear);
                assert!(supports_ext_codec_flags);
            }
            other => panic!("expected ClientMediaCaps, got {other:?}"),
        }

        let cmd = SessionCommand::SetCodec {
            codec: StreamCodec::Av1,
        };
        let copy_cmd = cmd;
        let json = serde_json::to_string(&copy_cmd).expect("serialize SetCodec(Av1)");
        let parsed: SessionCommand = serde_json::from_str(&json).expect("deserialize SetCodec");
        assert_eq!(parsed, cmd);

        // 晚到 Capabilities 补发 CodecDecodeFailed 及降级恢复后清除
        let mut pending = Some((
            rc_encode::Codec::Av1,
            1u64,
            "vt av1 unsupported".to_string(),
        ));
        // 同代不重复补发
        assert!(
            reconcile_decode_failure_on_capabilities(&mut pending, rc_encode::Codec::Av1, 1)
                .is_none()
        );
        // 晚到的新代次 Capabilities 仍在 AV1 -> 补发带新 gen=2 的 CodecDecodeFailed
        assert_eq!(
            reconcile_decode_failure_on_capabilities(&mut pending, rc_encode::Codec::Av1, 2),
            Some(DisplayControlMsg::CodecDecodeFailed {
                codec: "av1".to_string(),
                generation: 2,
                reason: "vt av1 unsupported".to_string(),
            })
        );
        // 被控端切至 HEVC 后清除未恢复状态
        assert!(
            reconcile_decode_failure_on_capabilities(&mut pending, rc_encode::Codec::Hevc, 3)
                .is_none()
        );
        assert!(pending.is_none());

        // fake_controller_stack 必须关闭内部 prefer_hardware 防止误调硬件热切
        let pcfg = PipelineConfig {
            resolution: Resolution::new(64, 64),
            prefer_hardware: true,
            ..PipelineConfig::default()
        };
        let (fake_pipe, _, _) = fake_controller_stack(&pcfg).expect("fake stack");
        assert!(!fake_pipe.config().prefer_hardware);
    }

    /// 对抗评审 High #2 回归：`rend.try_lock()` 争用期间保留 `pending_still_clear == true` 与
    /// `has_active_overlay() == true`，锁释放后重试必须真正调用 `clear_still_tiles()` 清除叠加层。
    #[test]
    fn try_clear_still_overlay_retries_after_try_lock_contention() {
        let mut fake =
            rc_render::FakeRenderer::new(rc_render::FakeRendererConfig::default()).unwrap();
        let patch = rc_render::StillTilePatch {
            stream_epoch: 1,
            base_frame_seq: 1,
            rect: rc_types::Rect::new(0, 0, 4, 4),
            format: rc_types::PixelFormat::Bgra8,
            pixels: vec![0x77; 4 * 4 * 4],
        };
        fake.apply_still_tile(&patch).expect("apply initial tile");
        assert_eq!(fake.active_still_tiles().len(), 1);

        let rend_arc: RendererHandle = Arc::new(Mutex::new(Box::new(fake)));
        let rend_slot = Mutex::new(Some(Arc::clone(&rend_arc)));
        let mut receiver = crate::still_refine::StillRefineReceiver::new(1, 1920, 1080);
        receiver
            .validate_and_accept(&patch, 32)
            .expect("accept patch");
        assert!(receiver.has_active_overlay());
        let mut pending_still_clear = false;

        // 模拟异步解码线程在 present() 期间持有渲染器锁：try_clear 必须返回 false 且不提前清零标志。
        let guard = rend_arc.lock().unwrap();
        assert!(!try_clear_still_overlay(
            &rend_slot,
            &mut receiver,
            &mut pending_still_clear
        ));
        assert!(pending_still_clear);
        assert!(receiver.has_active_overlay());
        drop(guard);

        // 异步解码线程释放锁后，下一拍重试必须真正清空渲染器叠加层并复原标志。
        assert!(try_clear_still_overlay(
            &rend_slot,
            &mut receiver,
            &mut pending_still_clear
        ));
        assert!(!pending_still_clear);
        assert!(!receiver.has_active_overlay());

        // 确认底层 FakeRenderer 的活跃叠加层确实已被清空（借用 apply/clear 行为反向验证）。
        let next_patch = rc_render::StillTilePatch {
            stream_epoch: 1,
            base_frame_seq: 2,
            rect: rc_types::Rect::new(128, 128, 4, 4),
            format: rc_types::PixelFormat::Bgra8,
            pixels: vec![0x88; 4 * 4 * 4],
        };
        rend_arc
            .lock()
            .unwrap()
            .apply_still_tile(&next_patch)
            .expect("renderer remains healthy after clear");
    }

    #[test]
    fn apply_stage_rect_nonblocking_defers_under_contention_and_applies_before_present() {
        #[derive(Debug, PartialEq, Eq)]
        enum Op {
            Resize(u32, u32),
            Present(u32),
        }

        struct RecordingOpsRenderer {
            ops: Arc<Mutex<Vec<Op>>>,
        }

        impl Renderer for RecordingOpsRenderer {
            fn present(
                &mut self,
                frame: rc_decode::DecodedFrame,
            ) -> rc_types::Result<rc_types::Timestamp> {
                self.ops
                    .lock()
                    .unwrap()
                    .push(Op::Present(frame.decode_done_ts.0));
                Ok(frame.decode_done_ts)
            }

            fn resize(&mut self, size: (u32, u32)) -> rc_types::Result<()> {
                self.ops.lock().unwrap().push(Op::Resize(size.0, size.1));
                Ok(())
            }

            fn set_vsync(&mut self, _on: bool) {}
            fn set_cursor(&mut self, _pos: (i32, i32), _visible: bool) {}
        }

        let ops = Arc::new(Mutex::new(Vec::new()));
        let inner: RendererHandle = Arc::new(Mutex::new(Box::new(RecordingOpsRenderer {
            ops: Arc::clone(&ops),
        })));
        let pending_resize = Arc::new(AtomicU64::new(0));
        let mut shared_renderer = SharedRenderer {
            inner: Arc::clone(&inner),
            pending_resize: Arc::clone(&pending_resize),
        };

        // 1) While renderer mutex is held (simulating nextDrawable stall), apply_stage_rect_nonblocking
        //    must return immediately without blocking and store packed dimensions.
        let guard = inner.lock().unwrap();
        let applied_now = apply_stage_rect_nonblocking(&inner, &pending_resize, 1600, 900);
        assert!(!applied_now);
        assert_eq!(
            pending_resize.load(Ordering::Acquire),
            pack_stage_rect(1600, 900)
        );
        // Latest contended resize overwrites earlier pending dimensions.
        assert!(!apply_stage_rect_nonblocking(
            &inner,
            &pending_resize,
            1920,
            1080
        ));
        assert_eq!(
            pending_resize.load(Ordering::Acquire),
            pack_stage_rect(1920, 1080)
        );
        assert!(ops.lock().unwrap().is_empty());
        drop(guard);

        // 2) Next SharedRenderer::present() must apply pending resize(1920, 1080) BEFORE present(frame),
        //    and clear pending_resize to 0.
        let frame = rc_decode::DecodedFrame {
            decode_done_ts: rc_types::Timestamp(150),
            width: 64,
            height: 64,
            texture: rc_capture::FrameTexture::Cpu(rc_types::CpuFrame {
                width: 64,
                height: 64,
                format: rc_types::PixelFormat::Bgra8,
                stride: 64 * 4,
                data: vec![0u8; 64 * 64 * 4],
            }),
        };
        shared_renderer.present(frame).expect("present");
        assert_eq!(pending_resize.load(Ordering::Acquire), 0);
        assert_eq!(
            *ops.lock().unwrap(),
            vec![Op::Resize(1920, 1080), Op::Present(150)]
        );

        // 3) Uncontended apply_stage_rect_nonblocking applies immediately and clears any stale pending value.
        pending_resize.store(pack_stage_rect(800, 600), Ordering::Release);
        assert!(apply_stage_rect_nonblocking(
            &inner,
            &pending_resize,
            2560,
            1440
        ));
        assert_eq!(pending_resize.load(Ordering::Acquire), 0);
        assert_eq!(
            *ops.lock().unwrap(),
            vec![
                Op::Resize(1920, 1080),
                Op::Present(150),
                Op::Resize(2560, 1440)
            ]
        );
    }

    /// 对抗评审 Medium #4 回归：纯工具态升级桌面且 `still_refinement_enabled == false` 时，
    /// 必须在发送 `ClientMediaCaps` 后同步补发 `DisplayControlMsg::StillRefineConfig { enabled: false }`。
    #[test]
    fn desktop_upgrade_emits_still_refine_disabled_config_when_off() {
        let params = SessionParams {
            width: 1280,
            height: 720,
            fps: 60,
            bitrate_bps: 8_000_000,
        };
        let mut client = make_streaming_tools_only_client(params);
        let real_pipeline_built = AtomicBool::new(false);
        let want_real_pipeline = AtomicBool::new(false);
        let is_hw_decoder_slot = AtomicBool::new(false);
        let mut backend = "tools-only".to_string();
        let backend_label = Mutex::new(backend.clone());
        let renderer_handle = Mutex::new(None);
        let renderer_pending_resize = Mutex::new(Arc::new(AtomicU64::new(0)));
        let layer_lease = Mutex::new(None);
        let mut is_hardware_decoder = false;
        let mut client_supports_hevc = false;
        let mut client_supports_av1 = false;
        let mut client_decode_caps = Vec::new();
        let mut stream_started_at = Instant::now();
        let mut first_frame_logged = false;
        let mut decode_error_logged = false;
        let mut pending_display_tx = VecDeque::new();
        let update_tx = BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP);

        let ok = try_resume_or_upgrade_desktop(
            DesktopUpgradeCtx {
                client: &mut client,
                real_pipeline_built: &real_pipeline_built,
                want_real_pipeline: &want_real_pipeline,
                is_hw_decoder_slot: &is_hw_decoder_slot,
                backend: &mut backend,
                backend_label: &backend_label,
                renderer_handle: &renderer_handle,
                renderer_pending_resize: &renderer_pending_resize,
                layer_lease: &layer_lease,
                active_backend_suffix: None,
                is_hardware_decoder: &mut is_hardware_decoder,
                client_supports_hevc: &mut client_supports_hevc,
                client_supports_av1: &mut client_supports_av1,
                client_decode_caps: &mut client_decode_caps,
                user_pinned_codec: None,
                still_refinement_enabled: false,
                prefer_hardware: false,
                hud_width: params.width,
                hud_height: params.height,
                current_fps: params.fps,
                negotiated: params,
                last_stage_rect: None,
                stream_started_at: &mut stream_started_at,
                first_frame_logged: &mut first_frame_logged,
                decode_error_logged: &mut decode_error_logged,
                pending_display_tx: &mut pending_display_tx,
                update_tx: &update_tx,
            },
            |pcfg| build_controller_pipeline(pcfg, false, Instant::now(), None),
        );
        assert!(ok);
        let msgs: Vec<DisplayControlMsg> = pending_display_tx
            .iter()
            .filter_map(|b| display_ctrl::decode_display_ctrl(b))
            .collect();
        let caps_idx = msgs
            .iter()
            .position(|m| matches!(m, DisplayControlMsg::ClientMediaCaps { .. }))
            .expect("must emit ClientMediaCaps on desktop upgrade");
        let cfg_idx = msgs
            .iter()
            .position(|m| matches!(m, DisplayControlMsg::StillRefineConfig { enabled: false }))
            .expect("must emit StillRefineConfig(false) when still refinement is disabled");
        assert!(
            cfg_idx > caps_idx,
            "StillRefineConfig(false) 必须紧跟在 ClientMediaCaps 之后发送: {msgs:?}"
        );
        let _ = client.close(ByeReason::Normal);
    }

    #[test]
    fn p2p_only_with_active_proxy_fails_fast_with_proxy_config_conflict() {
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
            port: 1080,
            username: None,
            password: None,
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: "198.51.100.10:9901".parse().unwrap(),
            connection_mode: ConnectionMode::P2pOnly,
            force_relay: false,
            tools_only: true,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            relay_grant: Some(ConnectGrant {
                session_id: "sess-proxy-conflict".to_string(),
                relay_addr: "relay.corp.internal:21117".to_string(),
                relay_token: "unused".to_string(),
                target_id: "900000099".to_string(),
                ..ConnectGrant::default()
            }),
            ..UiSessionConfig::default()
        });

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut ended_ui_error = None;
        let mut ended_recoverable = true;
        while Instant::now() < deadline {
            if let Some(SessionUpdate::Ended {
                recoverable,
                ui_error,
                ..
            }) = session.try_recv_update()
            {
                ended_recoverable = recoverable;
                ended_ui_error = ui_error;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert!(
            !ended_recoverable,
            "P2pOnly + Proxy conflict must be fatal (non-recoverable)"
        );
        let ui_err = ended_ui_error.expect("SessionUpdate::Ended must include UiError");
        assert_eq!(ui_err.code, crate::ui_error::codes::PROXY_CONFIG_CONFLICT);
    }

    #[test]
    fn collect_lan_candidate_addrs_prunes_rfc1918_when_public_ips_differ() {
        let probe_targets = vec!["192.0.2.10:21116".parse().unwrap()];
        let local_ips = lan_discovery::detect_local_interface_ips_for_targets(&probe_targets);
        let local_v4s = local_ips.ipv4s;
        let peer_same_subnet = local_v4s
            .first()
            .map(|local_ip| {
                let o = local_ip.octets();
                let last = if o[3] == 200 { 201 } else { 200 };
                format!("{}.{}.{}.{}:50000", o[0], o[1], o[2], last)
            })
            .unwrap_or_else(|| "192.168.1.88:50000".to_string());

        // 1) 公网 IP 明确不同且无 lan_direct_addr -> 彻底剪枝 RFC 1918 `/24` LAN 候选，消除黑洞等待
        let cfg_no_direct = UiSessionConfig::default();
        let grant_diff_pub = ConnectGrant {
            session_id: "sess-diff-pub".to_string(),
            target_id: "111222333".to_string(),
            relay_addr: "192.0.2.10:21117".to_string(),
            relay_token: "tok".to_string(),
            self_public_addr: Some("198.51.100.10:50000".to_string()),
            peer_public_addr: Some("203.0.113.20:60000".to_string()),
            peer_lan_addrs: vec![peer_same_subnet.clone(), "192.168.1.99:50000".to_string()],
            ..ConnectGrant::default()
        };
        assert!(
            collect_lan_candidate_addrs(&cfg_no_direct, &grant_diff_pub).is_empty(),
            "different public IPs without lan_direct_addr must prune RFC1918 LAN candidates"
        );

        // 2) 若显式配置了同网段 mDNS 发现的 lan_direct_addr，仍保留该显式地址
        let explicit_lan: SocketAddr = "192.168.77.88:9901".parse().unwrap();
        let cfg_with_direct = UiSessionConfig {
            lan_direct_addr: Some(explicit_lan),
            ..UiSessionConfig::default()
        };
        assert_eq!(
            collect_lan_candidate_addrs(&cfg_with_direct, &grant_diff_pub)[0],
            explicit_lan
        );

        // 3) 若公网 IP 相同（同 NAT 发夹或同局域网出口），保留同子网 LAN 候选
        if let Some(local_ip) = local_v4s.first() {
            let o = local_ip.octets();
            let sibling_ip =
                std::net::Ipv4Addr::new(o[0], o[1], o[2], if o[3] == 200 { 201 } else { 200 });
            let grant_same_pub = ConnectGrant {
                self_public_addr: Some("198.51.100.10:50000".to_string()),
                peer_public_addr: Some("198.51.100.10:50001".to_string()),
                ..grant_diff_pub.clone()
            };
            let cands = collect_lan_candidate_addrs(&cfg_no_direct, &grant_same_pub);
            assert!(cands.contains(&SocketAddr::new(
                std::net::IpAddr::V4(sibling_ip),
                crate::host_bridge::DEFAULT_HOST_PORT,
            )));

            // 4) 跨地址族（本端 IPv6 公网 vs 对端 IPv4 公网）时同族不可比，绝不误杀同局域网直连
            let grant_cross_family = ConnectGrant {
                self_public_addr: Some("[2001:db8::10]:50000".to_string()),
                peer_public_addr: Some("203.0.113.20:60000".to_string()),
                peer_public_addrs: vec!["203.0.113.20:60000".to_string()],
                ..grant_diff_pub.clone()
            };
            let cands_cross = collect_lan_candidate_addrs(&cfg_no_direct, &grant_cross_family);
            assert!(
                cands_cross.contains(&SocketAddr::new(
                    std::net::IpAddr::V4(sibling_ip),
                    crate::host_bridge::DEFAULT_HOST_PORT,
                )),
                "cross-family (IPv6 vs IPv4) public addrs must not prune same-subnet LAN candidates"
            );
        }

        // 5) peer_public_addr 为空但 peer_public_addrs 含不同 IPv4 时仍准确剪枝
        let grant_via_list = ConnectGrant {
            self_public_addr: Some("198.51.100.10:50000".to_string()),
            peer_public_addr: None,
            peer_public_addrs: vec![
                "[2001:db8::20]:60000".to_string(),
                "203.0.113.20:60000".to_string(),
            ],
            ..grant_diff_pub
        };
        assert!(collect_lan_candidate_addrs(&cfg_no_direct, &grant_via_list).is_empty());
    }

    #[test]
    fn build_client_p2p_candidates_filters_cross_site_rfc1918_only() {
        let grant = ConnectGrant {
            session_id: "sess-filter".to_string(),
            target_id: "111222333".to_string(),
            relay_addr: "192.0.2.10:21117".to_string(),
            relay_token: "tok".to_string(),
            self_public_addr: Some("198.51.100.10:50000".to_string()),
            peer_public_addr: Some("203.0.113.20:60000".to_string()),
            peer_public_addrs: vec!["203.0.113.20:60000".to_string()],
            peer_lan_addrs: vec![
                "192.168.1.20:9901".to_string(),
                "10.0.0.8:9901".to_string(),
                "203.0.113.21:45000".to_string(),
                "[2001:db8::20]:9901".to_string(),
            ],
            ..ConnectGrant::default()
        };
        let p2p_cands = build_client_p2p_candidates(&grant);
        assert_eq!(
            p2p_cands.peer_lan_addrs,
            vec![
                "203.0.113.21:45000".to_string(),
                "[2001:db8::20]:9901".to_string(),
                "192.168.1.20:9901".to_string(),
                "10.0.0.8:9901".to_string(),
            ]
        );
    }

    #[test]
    fn race_lan_and_p2p_cancels_loser_prefers_first_ok_and_fails_closed_on_mtls() {
        struct DropTrackTransport {
            dropped: Arc<AtomicBool>,
        }
        impl Transport for DropTrackTransport {
            fn send_datagram(&mut self, _data: &[u8]) -> rc_types::Result<()> {
                Ok(())
            }
            fn send_reliable(&mut self, _data: &[u8]) -> rc_types::Result<()> {
                Ok(())
            }
            fn send_reliable_urgent(&mut self, _data: &[u8]) -> rc_types::Result<()> {
                Ok(())
            }
            fn poll(&mut self, _timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
                Ok(Vec::new())
            }
            fn stats(&self) -> NetStats {
                NetStats::default()
            }
            fn set_pacing_rate(&mut self, _bps: u64) {}
            fn tx_queued_bytes(&self) -> usize {
                0
            }
            fn tx_dropped_datagrams(&self) -> u64 {
                0
            }
        }
        impl Drop for DropTrackTransport {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }

        let no_disc = AtomicBool::new(false);
        let lan_addr: SocketAddr = "192.168.1.20:9901".parse().unwrap();

        // 1) LAN 先成功 -> 立即置位 p2p_cancel，P2P 快速中止，采用 LAN 且 p2p_already_failed=false
        let p2p_saw_cancel = Arc::new(AtomicBool::new(false));
        let p2p_saw_cancel_bg = Arc::clone(&p2p_saw_cancel);
        let t0 = Instant::now();
        let res1 = race_lan_and_p2p_with(
            false,
            &no_disc,
            |_lan_cancel| {
                Ok((
                    Box::new(DropTrackTransport {
                        dropped: Arc::new(AtomicBool::new(false)),
                    }),
                    None,
                    lan_addr,
                ))
            },
            move |p2p_cancel| {
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline {
                    if p2p_cancel.load(Ordering::Acquire) {
                        p2p_saw_cancel_bg.store(true, Ordering::Release);
                        return Err(("cancelled".to_string(), None));
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                Err(("timed out".to_string(), None))
            },
        );
        assert!(t0.elapsed() < Duration::from_millis(300));
        assert!(p2p_saw_cancel.load(Ordering::Acquire));
        assert!(matches!(
            res1,
            Ok(DirectTierWinner::Lan {
                p2p_already_failed: false,
                ..
            })
        ));

        // 2) P2P 先成功而 LAN 黑洞等待 -> 立即置位 lan_cancel，LAN 快速中止，采用 P2P
        let lan_saw_cancel = Arc::new(AtomicBool::new(false));
        let lan_saw_cancel_bg = Arc::clone(&lan_saw_cancel);
        let t1 = Instant::now();
        let res2 = race_lan_and_p2p_with(
            false,
            &no_disc,
            move |lan_cancel| {
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline {
                    if lan_cancel.load(Ordering::Acquire) {
                        lan_saw_cancel_bg.store(true, Ordering::Release);
                        return Err((vec!["cancelled".to_string()], None));
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                Err((vec!["timed out".to_string()], None))
            },
            |_p2p_cancel| {
                Ok((
                    Box::new(DropTrackTransport {
                        dropped: Arc::new(AtomicBool::new(false)),
                    }),
                    None,
                ))
            },
        );
        assert!(t1.elapsed() < Duration::from_millis(300));
        assert!(lan_saw_cancel.load(Ordering::Acquire));
        assert!(matches!(res2, Ok(DirectTierWinner::P2p { .. })));

        // 3) LanOk 先到、P2pOk 稍晚到 -> 保持 LAN 且立即释放迟到 P2P 传输
        let p2p_dropped = Arc::new(AtomicBool::new(false));
        let p2p_dropped_bg = Arc::clone(&p2p_dropped);
        let (lan_done_tx, lan_done_rx) = mpsc::channel();
        let res3 = race_lan_and_p2p_with(
            false,
            &no_disc,
            move |_lan_cancel| {
                let _ = lan_done_tx.send(());
                Ok((
                    Box::new(DropTrackTransport {
                        dropped: Arc::new(AtomicBool::new(false)),
                    }),
                    None,
                    lan_addr,
                ))
            },
            move |p2p_cancel| {
                let _ = lan_done_rx.recv();
                while !p2p_cancel.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(1));
                }
                Ok((
                    Box::new(DropTrackTransport {
                        dropped: p2p_dropped_bg,
                    }),
                    None,
                ))
            },
        );
        assert!(matches!(
            res3,
            Ok(DirectTierWinner::Lan {
                p2p_already_failed: false,
                ..
            })
        ));
        assert!(
            p2p_dropped.load(Ordering::Acquire),
            "late P2P transport must be dropped when LanOk arrived first"
        );

        // 4) P2pOk 先到、LanOk 稍晚到 -> 保持先胜者 P2P 并丢弃迟到 LAN（绝不制造 Host 孤儿 P2P 会话）
        let lan_dropped = Arc::new(AtomicBool::new(false));
        let lan_dropped_bg = Arc::clone(&lan_dropped);
        let p2p_kept_dropped = Arc::new(AtomicBool::new(false));
        let p2p_kept_dropped_bg = Arc::clone(&p2p_kept_dropped);
        let (p2p_done_tx, p2p_done_rx) = mpsc::channel();
        let res4 = race_lan_and_p2p_with(
            false,
            &no_disc,
            move |lan_cancel| {
                let _ = p2p_done_rx.recv();
                while !lan_cancel.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(1));
                }
                Ok((
                    Box::new(DropTrackTransport {
                        dropped: lan_dropped_bg,
                    }),
                    None,
                    lan_addr,
                ))
            },
            move |_p2p_cancel| {
                let _ = p2p_done_tx.send(());
                Ok((
                    Box::new(DropTrackTransport {
                        dropped: p2p_kept_dropped_bg,
                    }),
                    None,
                ))
            },
        );
        assert!(matches!(res4, Ok(DirectTierWinner::P2p { .. })));
        assert!(
            lan_dropped.load(Ordering::Acquire),
            "late LAN transport must be dropped when P2pOk arrived first"
        );
        assert!(
            !p2p_kept_dropped.load(Ordering::Acquire),
            "winning P2P transport must stay alive"
        );
        drop(res4);

        // 5) P2P 先明确失败、随后 LAN 成功 -> p2p_already_failed=true（握手回退时不重复补试）
        let (p2p_fail_tx, p2p_fail_rx) = mpsc::channel();
        let res5 = race_lan_and_p2p_with(
            false,
            &no_disc,
            move |_lan_cancel| {
                let _ = p2p_fail_rx.recv();
                thread::sleep(Duration::from_millis(25));
                Ok((
                    Box::new(DropTrackTransport {
                        dropped: Arc::new(AtomicBool::new(false)),
                    }),
                    None,
                    lan_addr,
                ))
            },
            move |_p2p_cancel| {
                let _ = p2p_fail_tx.send(());
                Err(("punch failed".to_string(), None))
            },
        );
        assert!(matches!(
            res5,
            Ok(DirectTierWinner::Lan {
                p2p_already_failed: true,
                ..
            })
        ));

        // 6) 开启 mTLS 时任一侧出现证书校验失败 -> 严格 fail-closed 并取消另一侧
        let lan_cancelled_on_mtls = Arc::new(AtomicBool::new(false));
        let lan_cancelled_on_mtls_bg = Arc::clone(&lan_cancelled_on_mtls);
        let res6 = race_lan_and_p2p_with(
            true,
            &no_disc,
            move |lan_cancel| {
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline {
                    if lan_cancel.load(Ordering::Acquire) {
                        lan_cancelled_on_mtls_bg.store(true, Ordering::Release);
                        return Err((vec!["cancelled".to_string()], None));
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                Err((vec!["timed out".to_string()], None))
            },
            |_p2p_cancel| {
                Err((
                    "InvalidPeerCertificate".to_string(),
                    Some("P2P mTLS 证书校验失败（严禁静默降级）".to_string()),
                ))
            },
        );
        assert!(lan_cancelled_on_mtls.load(Ordering::Acquire));
        assert!(matches!(res6, Err(DirectTierRaceError::FatalMtls(_))));
    }

    #[test]
    fn tool_hub_revocation_resets_terminal_and_portmap_state_cleanly() {
        let mut hub = ToolClientHub::new();
        let tid = hub
            .terminal
            .open_with_options(80, 24, Some("sh".into()), true);
        hub.pending_opens.push_back((tid, true));
        hub.active_terminals.insert(tid);
        hub.attached_terminals.insert(tid);
        let _ = hub.terminal.poll_outgoing(8);

        hub.reset_terminal();
        assert!(hub.active_terminals.is_empty());
        assert!(hub.attached_terminals.is_empty());
        assert!(hub.pending_opens.is_empty());
        assert!(hub.terminal.poll_outgoing(8).is_empty());

        let rule = hub
            .portmap
            .add_rule_with_enabled(
                "db".to_string(),
                19432,
                "127.0.0.1".to_string(),
                5432,
                false,
            )
            .expect("rule added disabled");
        assert_eq!(rule.local_port, 19432);
        assert_eq!(hub.portmap.list_rules().len(), 1);
        hub.portmap = PortMapClientEngine::new();
        assert!(hub.portmap.list_rules().is_empty());

        // 验证 ToolClientHandle::lock_hub_for_channel 在权限撤销后持 hub 锁内原子拒绝终端与端口映射操作。
        let perms = Arc::new(Mutex::new(ToolPermissions::all_allowed()));
        let hub_arc = Arc::new(Mutex::new(ToolClientHub::new()));
        let portmap_latest = Arc::new(Mutex::new(None));
        let update_tx = Arc::new(BoundedUpdateQueue::new(16));
        let (fw, fh) = FileClientWorker::spawn(Arc::new(BoundedQueue::new(16)));
        let handle = ToolClientHandle {
            running: Arc::new(AtomicBool::new(true)),
            tool_permissions: Arc::clone(&perms),
            file: fh,
            hub: Arc::clone(&hub_arc),
            portmap_latest: Arc::clone(&portmap_latest),
            update_tx: Arc::clone(&update_tx),
        };
        {
            let _h = hub_arc.lock().unwrap();
            *perms.lock().unwrap() = ToolPermissions {
                allow_file_transfer: true,
                allow_terminal: false,
                allow_port_map: false,
            };
        }
        assert!(handle.terminal_open(80, 24).is_err());
        assert!(handle
            .portmap_add("web".into(), 18080, "127.0.0.1".into(), 8080)
            .is_err());
        assert!(hub_arc.lock().unwrap().portmap.list_rules().is_empty());
        drop(fw);
    }

    #[test]
    fn dial_lan_addrs_happy_eyeballs_does_not_block_on_unreachable_candidate() {
        // 启动一个真实测试 QUIC 服务端监听在 127.0.0.1:0
        let identity = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).unwrap();
        let net = NetConfig {
            role: Role::Host,
            local_addr: "127.0.0.1:0".parse().unwrap(),
            peer_addr: None,
            mtu: rc_session::DEFAULT_SESSION_MTU,
        };
        let host_ep = QuicEndpoint::new(&net, &identity).unwrap();
        let ok_addr = host_ep.local_addr().unwrap();
        let accept_jh = std::thread::spawn(move || {
            let _ = host_ep.accept(Duration::from_secs(2));
        });

        // 第一个候选为不可达 TEST-NET-1（黑洞，普通顺序拨号会阻塞满 LAN_DIRECT_PROBE_TIMEOUT=1500ms），
        // 第二个候选为可达的本地回环端口；Happy Eyeballs 并发必须在 <500ms 内命中 ok_addr
        let dead_addr: SocketAddr = "192.0.2.250:9901".parse().unwrap();
        let cancel = AtomicBool::new(false);
        let t0 = Instant::now();
        let (_t, _fp, won_addr) =
            dial_lan_addrs_happy_eyeballs(&[dead_addr, ok_addr], None, false, &cancel)
                .expect("Happy Eyeballs must succeed via reachable second LAN addr");
        let elapsed = t0.elapsed();
        accept_jh.join().unwrap();
        assert_eq!(won_addr, ok_addr);
        assert!(
            elapsed < Duration::from_millis(600),
            "dead first LAN candidate must not block second candidate for 1500ms, took {elapsed:?}"
        );
    }
}
