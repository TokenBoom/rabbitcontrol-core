use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rc_session::auth::OwnerTicketSigner;
use rc_session::ToolPermissions;

use crate::app_prefs::ConnectionMode;
use crate::cert_manager::OwnerGrantPayload;
use crate::display_ctrl::{DisplayDescriptor, DisplayPreset, HighRefreshAdvisory, StreamCodec};
use crate::hud::HudSnapshot;
use crate::relay_transport::SessionMtlsBundle;
use crate::signal_client::{ConnectGrant, SignalClientHandle};
use crate::ui_error::UiError;

/// 命令通道容量上限（T21 U6 / 铁律 1 UI 侧延伸）。
pub const COMMAND_CHANNEL_CAP: usize = 64;

/// 输入通道容量上限（T21 U6，对齐 `rc-input-macos` `CgCapture` tap 通道容量）。
pub const INPUT_CHANNEL_CAP: usize = 256;

/// 会话线程 → UI 状态更新通道容量上限（T21 U6）。
pub const UPDATE_CHANNEL_CAP: usize = 64;

/// 远端桌面会话切换（macOS LoginWindow ↔ Aqua）时约定的提示文案。
pub const SESSION_SWITCHING_REASON: &str = "远端正在切换系统桌面，自动重连中…";

/// 常规 poll 预算（对齐 `rc-cli/src/cmd/client.rs`）。
pub(in crate::session_bridge) const RUN_POLL_BUDGET: Duration = Duration::from_millis(1);
/// 空闲拍放宽的 poll 预算（4ms 以支撑 120/144fps 高刷唤醒不卡顿）。
pub(in crate::session_bridge) const RUN_IDLE_POLL_BUDGET: Duration = Duration::from_millis(4);
/// `Reconnecting` 退避等待的最大睡眠粒度。
pub(in crate::session_bridge) const RUN_RECONNECT_SLEEP: Duration = Duration::from_millis(20);
/// HUD 推送节流周期（1 秒）。
pub(in crate::session_bridge) const HUD_INTERVAL: Duration = Duration::from_secs(1);
/// 硬件解码器在 `displayed == 0` 期间连续 `Outcome::DecodeError` 的判定阈值
/// （例如远端被控端未授屏幕录制权限而降级到 `FakeEncoder` 发送非 Annex-B 码流）。
pub(in crate::session_bridge) const CONSECUTIVE_DECODE_ERROR_LIMIT: usize = 30;
/// 触发持续硬件解码失败终止前的最短串流观察时长（避免首帧短暂丢包误判）。
pub(in crate::session_bridge) const PERSISTENT_DECODE_ERROR_MIN_ELAPSED: Duration =
    Duration::from_secs(3);
/// 最近窗口用于计算 `e2e_p50_ms` 的最大样本数。
pub(in crate::session_bridge) const E2E_WINDOW_FRAMES: usize = 60;
/// W2 文件传输事件队列容量上限（有界 drop-oldest）。
pub(in crate::session_bridge) const FILE_EVENT_CHANNEL_CAP: usize = 256;
/// W3 远程终端事件队列容量上限（有界 drop-oldest）。
pub(in crate::session_bridge) const TERMINAL_EVENT_CHANNEL_CAP: usize = 512;
/// 单拍每个工具引擎最多发送的线帧数（避免工具吞吐饿死视频/输入）。
pub(in crate::session_bridge) const MAX_TOOL_FRAMES_PER_TICK: usize = 8;
/// 控制端专用文件工作线程的有界通道容量（H12）。
pub(in crate::session_bridge) const FILE_CLIENT_WORKER_CHAN_CAP: usize = 64;
/// 远程终端允许的最大行列尺寸（M10）。
pub(in crate::session_bridge) const MAX_TERMINAL_DIM: u16 = 512;
/// 单次远程终端输入字节上限（64 KiB，M10）。
pub(in crate::session_bridge) const MAX_TERMINAL_INPUT_BYTES: usize = 64 * 1024;
/// 上传进度推送最小间隔（平滑刷新 W2 进度条，不刷屏）。
pub(in crate::session_bridge) const UPLOAD_PROGRESS_EMIT_INTERVAL: Duration =
    Duration::from_millis(100);
/// W4 端口映射统计快照比对间隔。
pub(in crate::session_bridge) const PORTMAP_SNAPSHOT_INTERVAL: Duration =
    Duration::from_millis(200);
/// 控制端本地前置权限拦截推送 `SessionUpdate::ToolPermissionDenied` 的单通道最小节流间隔（1s）。
pub(in crate::session_bridge) const LOCAL_TOOL_DENIED_THROTTLE: Duration = Duration::from_secs(1);

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
    /// 后续可通过 [`super::SessionHandle::upgrade_to_desktop`] 原地热升级为桌面控屏。
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
    /// 本端控制端设备 ID（如 9 位设备码，供 `ControllerMeta.device_id` 上报）。
    #[serde(default)]
    pub self_device_id: Option<String>,
    /// 本端控制端设备名称（供 `ControllerMeta.device_name` 上报）。
    #[serde(default)]
    pub self_device_name: Option<String>,
    /// 本端控制端操作系统标识（供 `ControllerMeta.os` 上报；`None` 时默认使用 `std::env::consts::OS`）。
    #[serde(default)]
    pub self_os: Option<String>,
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
            self_device_id: None,
            self_device_name: None,
            self_os: None,
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
            .field("self_device_id", &self.self_device_id)
            .field("self_device_name", &self.self_device_name)
            .field("self_os", &self.self_os)
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
        /// 当前生效显示器逻辑宽度（px/pt，如 `1512`；旧被控端未上报时为 `0`）。
        #[serde(default)]
        display_width: u32,
        /// 当前生效显示器逻辑高度（px/pt，如 `982`；旧被控端未上报时为 `0`）。
        #[serde(default)]
        display_height: u32,
        /// 当前生效显示器是否处于 HiDPI 模式（`backing > logical`）。
        #[serde(default)]
        display_hidpi: bool,
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
    /// 会话断连结构化通知（紧邻 `Ended` 之前推送，透传接管、目标被控中与自动重连资格）。
    Disconnected {
        /// 人类可读的断开原因。
        reason: String,
        /// 是否因其他设备发起接管而被踢出（收到 `ByeReason::Preempted`）。
        #[serde(default)]
        preempted: bool,
        /// 目标设备是否正处于被控中（直连 `HostBusyControlled` 或信令 `target_in_session`）。
        #[serde(default)]
        busy_controlled: bool,
        /// 是否允许上层触发自动重连（`Preempted`、`HostBusyControlled`、`Normal` 主动关闭等强制为 `false`）。
        #[serde(default)]
        auto_reconnect_eligible: bool,
        /// 结构化用户可读错误模型（可选）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ui_error: Option<UiError>,
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

/// 会话线程内部结束结果（携带是否适合上层自动重连恢复的 `recoverable` 标记及接管/忙状态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::session_bridge) struct SessionEnd {
    pub(in crate::session_bridge) reason: String,
    pub(in crate::session_bridge) recoverable: bool,
    pub(in crate::session_bridge) preempted: bool,
    pub(in crate::session_bridge) busy_controlled: bool,
}

impl SessionEnd {
    pub(in crate::session_bridge) fn fatal(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            recoverable: false,
            preempted: false,
            busy_controlled: false,
        }
    }

    pub(in crate::session_bridge) fn recoverable(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            recoverable: true,
            preempted: false,
            busy_controlled: false,
        }
    }

    pub(in crate::session_bridge) fn preempted(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            recoverable: false,
            preempted: true,
            busy_controlled: false,
        }
    }

    pub(in crate::session_bridge) fn busy_controlled(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            recoverable: false,
            preempted: false,
            busy_controlled: true,
        }
    }
}
