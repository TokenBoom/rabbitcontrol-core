use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rc_input::InputEvent;
use rc_session::{ToolPermissions, TOOL_CHANNEL_TERMINAL};
use rc_tools::{FileEvent, PortMapRuleSnapshot, TerminalEvent};

use crate::display_ctrl::DisplayControlMsg;
use crate::platform::PreallocatedRenderSurface;

use super::adapters::{ActiveRelayInterrupt, LayerLease};
use super::queues::{BoundedInputQueue, BoundedQueue, BoundedUpdateQueue};
use super::session_loop::{run_session_thread, SessionThreadArgs};
use super::tools::{FileClientHandle, FileClientWorker, ToolClientHandle, ToolClientHub};
use super::types::{
    SessionCommand, SessionEnd, SessionUpdate, UiSessionConfig, COMMAND_CHANNEL_CAP,
    FILE_EVENT_CHANNEL_CAP, INPUT_CHANNEL_CAP, SESSION_SWITCHING_REASON,
    TERMINAL_EVENT_CHANNEL_CAP, UPDATE_CHANNEL_CAP,
};

// ─────────────────────────────────────────────────────────────────
// SessionHandle（公开 API）
// ─────────────────────────────────────────────────────────────────

/// 会话级滚动分发状态：持有对端是否支持像素滚轮的能力位及跨事件亚像素/亚行累加器。
pub(in crate::session_bridge) struct ScrollDispatchState {
    pub(in crate::session_bridge) peer_supports_pixel_scroll: AtomicBool,
    pub(in crate::session_bridge) wheel_accumulator: Mutex<crate::input_bridge::WheelAccumulator>,
}

impl ScrollDispatchState {
    pub(in crate::session_bridge) fn new() -> Self {
        Self {
            peer_supports_pixel_scroll: AtomicBool::new(false),
            wheel_accumulator: Mutex::new(crate::input_bridge::WheelAccumulator::new()),
        }
    }

    pub(in crate::session_bridge) fn update_peer_capability(&self, supported: bool) {
        self.peer_supports_pixel_scroll
            .store(supported, Ordering::Release);
    }

    pub(in crate::session_bridge) fn reset_accumulator(&self) {
        self.wheel_accumulator
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .reset();
    }
}

/// 轻量可克隆的高频输入发送句柄（供 UI 在不持 `AppState::session` 锁的前提下直接投递键鼠与滚轮事件）。
#[derive(Clone)]
pub struct SessionInputHandle {
    pub(in crate::session_bridge) input_tx: Arc<BoundedInputQueue>,
    pub(in crate::session_bridge) watch_only: Arc<AtomicBool>,
    pub(in crate::session_bridge) running: Arc<AtomicBool>,
    pub(in crate::session_bridge) scroll_state: Arc<ScrollDispatchState>,
}

impl SessionInputHandle {
    /// 查询会话是否仍在运行。
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// 经会话级 `WheelAccumulator` 与 `SUPPORTS_PIXEL_SCROLL` 协商能力分发 DOM / UI 输入事件。
    ///
    /// 返回 `true` 表示遇到了未收录的 DOM `KeyboardEvent.code`（已静默丢弃，供上层计数）。
    pub fn send_ui_input(
        &self,
        ev: &crate::input_bridge::UiInputEvent,
        video_size: Option<(u32, u32)>,
    ) -> bool {
        dispatch_ui_input_to_queue(
            &self.input_tx,
            &self.watch_only,
            &self.running,
            &self.scroll_state,
            ev,
            video_size,
        )
    }

    /// 发送一条原生 [`InputEvent`]；观看模式（`watch_only`）或会话已结束时静默丢弃。
    pub fn send_input(&self, ev: InputEvent) {
        if self.watch_only.load(Ordering::Acquire) || !self.is_running() {
            return;
        }
        self.input_tx.push(ev);
    }
}

pub(in crate::session_bridge) fn dispatch_ui_input_to_queue(
    input_tx: &BoundedInputQueue,
    watch_only: &AtomicBool,
    running: &AtomicBool,
    scroll_state: &ScrollDispatchState,
    ev: &crate::input_bridge::UiInputEvent,
    video_size: Option<(u32, u32)>,
) -> bool {
    if watch_only.load(Ordering::Acquire) || !running.load(Ordering::Acquire) {
        return false;
    }
    let pixel_scroll = scroll_state
        .peer_supports_pixel_scroll
        .load(Ordering::Acquire);
    let (mapped, unmapped_key) =
        if matches!(ev, crate::input_bridge::UiInputEvent::MouseWheel { .. }) {
            let mut acc = scroll_state
                .wheel_accumulator
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            crate::input_bridge::map_ui_input_event(ev, video_size, &mut acc, pixel_scroll)
        } else {
            let mut scratch = crate::input_bridge::WheelAccumulator::default();
            crate::input_bridge::map_ui_input_event(ev, video_size, &mut scratch, pixel_scroll)
        };
    for input_ev in mapped {
        input_tx.push(input_ev);
    }
    unmapped_key
}

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
    pub(in crate::session_bridge) cmd_tx: Arc<BoundedQueue<SessionCommand>>,
    pub(in crate::session_bridge) display_ctrl_tx: Arc<BoundedQueue<DisplayControlMsg>>,
    pub(in crate::session_bridge) input_tx: Arc<BoundedInputQueue>,
    pub(in crate::session_bridge) update_rx: Arc<BoundedUpdateQueue>,
    pub(in crate::session_bridge) file_event_rx: Arc<BoundedQueue<FileEvent>>,
    pub(in crate::session_bridge) terminal_event_rx: Arc<BoundedQueue<TerminalEvent>>,
    pub(in crate::session_bridge) portmap_latest: Arc<Mutex<Option<Vec<PortMapRuleSnapshot>>>>,
    pub(in crate::session_bridge) tools_hub: Arc<Mutex<ToolClientHub>>,
    pub(in crate::session_bridge) file_handle: FileClientHandle,
    pub(in crate::session_bridge) disconnect_flag: Arc<AtomicBool>,
    pub(in crate::session_bridge) lock_on_disconnect: Arc<AtomicBool>,
    pub(in crate::session_bridge) relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    pub(in crate::session_bridge) running: Arc<AtomicBool>,
    pub(in crate::session_bridge) watch_only: Arc<AtomicBool>,
    pub(in crate::session_bridge) tool_permissions: Arc<Mutex<ToolPermissions>>,
    pub(in crate::session_bridge) still_refine_metrics:
        Arc<Mutex<crate::still_refine::StillRefineMetrics>>,
    pub(in crate::session_bridge) scroll_state: Arc<ScrollDispatchState>,
    pub(in crate::session_bridge) encrypt_connection: bool,
    pub(in crate::session_bridge) base_config: UiSessionConfig,
    pub(in crate::session_bridge) layer_lease: Arc<Mutex<Option<LayerLease>>>,
    pub(in crate::session_bridge) upgrade_surface: Arc<Mutex<Option<PreallocatedRenderSurface>>>,
    pub(in crate::session_bridge) thread: Option<JoinHandle<()>>,
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
        let scroll_state = Arc::new(ScrollDispatchState::new());
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
        let t_scroll_state = Arc::clone(&scroll_state);
        let t_layer = Arc::clone(&layer_lease);
        let t_upgrade_surface = Arc::clone(&upgrade_surface);

        let handle = thread::Builder::new()
            .name("rc-ui-session".to_string())
            .spawn(move || {
                crate::platform::promote_current_thread_qos();

                let mut file_worker = file_worker;
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_session_thread(SessionThreadArgs {
                        cfg,
                        render_surface: t_upgrade_surface,
                        cmd_rx: t_cmd,
                        display_ctrl_rx: t_display_ctrl,
                        input_rx: t_input,
                        update_tx: Arc::clone(&t_update),
                        layer_lease: t_layer,
                        disconnect_flag: t_disconnect,
                        lock_on_disconnect: t_lock_on_disconnect,
                        relay_interrupt: t_relay_interrupt,
                        tools_hub: Arc::clone(&t_tools_hub),
                        file_worker: &file_worker,
                        terminal_events: Arc::clone(&t_terminal_events),
                        portmap_latest: t_portmap_latest,
                        watch_only: t_watch_only,
                        tool_permissions: t_tool_permissions,
                        still_refine_metrics: t_still_refine_metrics,
                        scroll_state: t_scroll_state,
                    })
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
                let ui_error = if end.preempted {
                    Some(crate::ui_error::preempted_ui_error(Some(
                        end.reason.clone(),
                    )))
                } else if end.busy_controlled {
                    Some(crate::ui_error::target_in_session_ui_error(Some(
                        end.reason.clone(),
                    )))
                } else {
                    Some(crate::ui_error::classify_session_reason(
                        &end.reason,
                        crate::ui_error::current_platform(),
                    ))
                };
                let auto_reconnect_eligible =
                    end.recoverable && !end.preempted && !end.busy_controlled;
                t_update.push(SessionUpdate::Disconnected {
                    reason: end.reason.clone(),
                    preempted: end.preempted,
                    busy_controlled: end.busy_controlled,
                    auto_reconnect_eligible,
                    ui_error: ui_error.clone(),
                });
                t_update.push(SessionUpdate::Ended {
                    reason: end.reason,
                    recoverable: auto_reconnect_eligible,
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
            scroll_state,
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

    pub(in crate::session_bridge) fn trigger_disconnect(&self) {
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
        if enabled {
            self.scroll_state.reset_accumulator();
        }
    }

    /// 查询对端是否支持像素级连续滚轮（`HostFlags::SUPPORTS_PIXEL_SCROLL`）。
    pub fn peer_supports_pixel_scroll(&self) -> bool {
        self.scroll_state
            .peer_supports_pixel_scroll
            .load(Ordering::Acquire)
    }

    /// 发送一条输入事件；观看模式（`watch_only`）或会话已结束时静默丢弃（U9 / U10）。
    pub fn send_input(&self, ev: InputEvent) {
        if self.watch_only.load(Ordering::Acquire) || !self.is_running() {
            return;
        }
        self.input_tx.push(ev);
    }

    /// 获取轻量可克隆的高频输入发送句柄（供 UI 绕开会话粗锁直投键鼠事件）。
    pub fn input_handle(&self) -> SessionInputHandle {
        SessionInputHandle {
            input_tx: Arc::clone(&self.input_tx),
            watch_only: Arc::clone(&self.watch_only),
            running: Arc::clone(&self.running),
            scroll_state: Arc::clone(&self.scroll_state),
        }
    }

    /// 经会话级 `WheelAccumulator` 与 `SUPPORTS_PIXEL_SCROLL` 协商能力分发 DOM / UI 输入事件。
    ///
    /// 返回 `true` 表示遇到了未收录的 DOM `KeyboardEvent.code`（已静默丢弃，供上层计数）。
    pub fn send_ui_input(
        &self,
        ev: &crate::input_bridge::UiInputEvent,
        video_size: Option<(u32, u32)>,
    ) -> bool {
        dispatch_ui_input_to_queue(
            &self.input_tx,
            &self.watch_only,
            &self.running,
            &self.scroll_state,
            ev,
            video_size,
        )
    }

    /// 便捷接口：直接发送一条滚轮事件（经会话级 `WheelAccumulator` 累积并根据对端能力分发）。
    pub fn send_wheel(
        &self,
        delta_x_px: f64,
        delta_y_px: f64,
        line_height_px: f64,
        delta_mode: u8,
    ) {
        let _ = self.send_ui_input(
            &crate::input_bridge::UiInputEvent::MouseWheel {
                delta_y_px,
                line_height_px,
                delta_x_px,
                delta_mode,
            },
            None,
        );
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
