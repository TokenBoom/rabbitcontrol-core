use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rc_tools::FileHostEngine;

use crate::display_ctrl::{self, DisplayControlMsg};

use super::queues::HostDisplayCtrlOutbox;
use super::types::{
    AtomicFlagReset, SharedFileTransferDir, FILE_HOST_WORKER_CHAN_CAP, MAX_TOOL_FRAMES_PER_TICK,
};

// (secret string zeroization handled safely via `zeroize::Zeroize` / `zeroize::Zeroizing`)

/// 本人（Owner）远程终端的锁屏安全校验门禁（对齐 UU 远程语义）：
/// - 仅在会话建立时若被控端已处于系统锁屏状态则开启拦截；
/// - 校验系统密码通过或检测到物理屏幕已解锁后放行；
/// - 仅当通过密码核验解锁（`unlocked_by_password == true`）时对重复解锁请求幂等回传 `ok: true`，
///   若因物理解锁或初始未锁屏而放行，绝不对未校验口令的请求误发 `ok: true`；
/// - **关键语义**：一旦会话内处于已放行态（初始未锁屏或已验证通过），被控期间中途锁屏
///   绝不打断或重新锁定当前已授权的终端会话（「被控期间锁屏不影响正常使用」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TerminalLockGate {
    locked: bool,
    unlocked_by_password: bool,
}

impl TerminalLockGate {
    pub(super) fn new(initial_screen_locked: bool) -> Self {
        Self {
            locked: initial_screen_locked,
            unlocked_by_password: false,
        }
    }

    pub(super) fn is_locked(&self) -> bool {
        self.locked
    }

    pub(super) fn is_unlocked_by_password(&self) -> bool {
        !self.locked && self.unlocked_by_password
    }

    /// 250ms 巡检观察到当前系统锁屏态时更新状态；仅当从待校验转为已解锁时返回 `true`。
    pub(super) fn on_screen_lock_observed(&mut self, screen_locked: bool) -> bool {
        if self.locked && !screen_locked {
            self.locked = false;
            true
        } else {
            false
        }
    }

    /// 系统密码核验通过后解除终端门禁；若原先处于待校验态则返回 `true`。
    pub(super) fn on_verified_ok(&mut self) -> bool {
        if self.locked {
            self.locked = false;
            self.unlocked_by_password = true;
            true
        } else {
            false
        }
    }
}

/// 终端系统密码核验防爆破阶梯限流器（全局跨会话共享，防止通过重连绕过）。
#[derive(Debug, Default)]
pub(super) struct TerminalUnlockRateLimiter {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
}

impl TerminalUnlockRateLimiter {
    pub(super) fn retry_after_secs(&self, now: Instant) -> u32 {
        let Some(until) = self.locked_until else {
            return 0;
        };
        if now >= until {
            return 0;
        }
        let rem = until.saturating_duration_since(now);
        let secs = rem.as_secs();
        let extra = u64::from(rem.subsec_nanos() > 0);
        u32::try_from(secs.saturating_add(extra)).unwrap_or(u32::MAX)
    }

    pub(super) fn record_failure(&mut self, now: Instant) -> u32 {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let cooldown_secs = if self.consecutive_failures >= 15 {
            120
        } else if self.consecutive_failures >= 10 {
            60
        } else if self.consecutive_failures >= 5 {
            30
        } else {
            0
        };
        if cooldown_secs > 0 {
            self.locked_until = Some(now + Duration::from_secs(u64::from(cooldown_secs)));
        }
        cooldown_secs
    }

    pub(super) fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.locked_until = None;
    }
}

pub(super) fn global_terminal_unlock_limiter() -> &'static Mutex<TerminalUnlockRateLimiter> {
    static LIMITER: std::sync::OnceLock<Mutex<TerminalUnlockRateLimiter>> =
        std::sync::OnceLock::new();
    LIMITER.get_or_init(|| Mutex::new(TerminalUnlockRateLimiter::default()))
}

/// 终端系统密码单在途后台核验驱动器：
/// - 绝不在 `rc-ui-host` 会话主循环中同步等待 OpenDirectory/PBKDF2（可能耗时数十毫秒）；
/// - 同一时刻至多一个后台核验线程在途，完成后经 `try_recv()` 非阻塞收割；
/// - 密码在后台线程核验后立刻就地清零。
pub(super) struct TerminalVerifyDriver {
    in_flight: Arc<AtomicBool>,
    rx: Option<mpsc::Receiver<Result<bool, String>>>,
}

impl TerminalVerifyDriver {
    pub(super) fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicBool::new(false)),
            rx: None,
        }
    }

    pub(super) fn is_in_flight(&self) -> bool {
        self.rx.is_some() || self.in_flight.load(Ordering::Acquire)
    }

    pub(super) fn poll_completed(&mut self) -> Option<Result<bool, String>> {
        let rx = self.rx.as_ref()?;
        match rx.try_recv() {
            Ok(res) => {
                self.rx = None;
                Some(res)
            }
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.rx = None;
                Some(Err("系统密码核验线程意外退出".to_string()))
            }
        }
    }

    pub(super) fn spawn<F>(&mut self, verify_fn: F) -> bool
    where
        F: FnOnce() -> Result<bool, String> + Send + 'static,
    {
        if self.is_in_flight() {
            return false;
        }
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let (tx, rx) = mpsc::sync_channel::<Result<bool, String>>(1);
        let flag = Arc::clone(&self.in_flight);
        match thread::Builder::new()
            .name("rc-term-verify".to_string())
            .spawn(move || {
                let _reset = AtomicFlagReset(flag);
                let res = verify_fn();
                let _ = tx.send(res);
            }) {
            Ok(_) => {
                self.rx = Some(rx);
                true
            }
            Err(e) => {
                self.in_flight.store(false, Ordering::Release);
                eprintln!("[rc-ui-host] 派发系统密码核验线程失败: {e}");
                false
            }
        }
    }
}

pub(super) fn encode_terminal_lock_state(
    is_owner: bool,
    gate: &TerminalLockGate,
) -> Option<Vec<u8>> {
    if !is_owner {
        return None;
    }
    let retry_after_secs = global_terminal_unlock_limiter()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retry_after_secs(Instant::now());
    let locked = gate.is_locked();
    display_ctrl::encode_display_ctrl(&DisplayControlMsg::TerminalLockState {
        required: locked,
        unlocked: !locked,
        username: crate::platform::current_system_username(),
        retry_after_secs,
    })
}

/// 按会话归属（是否通过 Ed25519 PoP `OwnerTicket` 自控认证）与远程协助文件开关计算生效工具权限。
///
/// 安全红线：
/// - 仅 `is_owner_session == true` 豁免保持全开（文件传输、远程终端、端口映射全部可用）；
/// - 他人远程协助（`is_owner_session == false`）仅允许远程桌面与受控文件传输，
///   硬禁用远程终端与端口映射（`allow_terminal: false, allow_port_map: false`）。
pub(super) fn compute_effective_tool_permissions(
    is_owner_session: bool,
    allow_assist_file_transfer: bool,
) -> rc_session::ToolPermissions {
    if is_owner_session {
        rc_session::ToolPermissions::all_allowed()
    } else {
        rc_session::ToolPermissions {
            allow_file_transfer: allow_assist_file_transfer,
            allow_terminal: false,
            allow_port_map: false,
        }
    }
}

pub(super) fn encode_tool_permissions_state(perms: rc_session::ToolPermissions) -> Option<Vec<u8>> {
    display_ctrl::encode_display_ctrl(&DisplayControlMsg::ToolPermissionsState {
        allow_file_transfer: perms.allow_file_transfer,
        allow_terminal: perms.allow_terminal,
        allow_port_map: perms.allow_port_map,
    })
}

pub(super) fn requested_username_matches_current(
    requested: Option<&str>,
    current: Option<&str>,
) -> bool {
    let Some(req) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    let Some(cur) = current.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    req == cur
}

pub(super) fn handle_terminal_unlock_request(
    is_owner: bool,
    password: display_ctrl::RedactedSecret,
    username: Option<String>,
    gate: &TerminalLockGate,
    verify_driver: &mut TerminalVerifyDriver,
    outbox: &mut HostDisplayCtrlOutbox,
) {
    let pw = password.into_zeroizing();
    let push_result =
        |tx: &mut HostDisplayCtrlOutbox, ok: bool, error: Option<String>, retry: u32| {
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::TerminalUnlockResult {
                    ok,
                    error,
                    retry_after_secs: retry,
                })
            {
                tx.push_transient(payload);
            }
        };

    if !is_owner {
        push_result(
            outbox,
            false,
            Some("远程终端仅限本人账号使用".to_string()),
            0,
        );
        return;
    }
    if !gate.is_locked() {
        if gate.is_unlocked_by_password() {
            push_result(outbox, true, None, 0);
        }
        if let Some(state_payload) = encode_terminal_lock_state(true, gate) {
            outbox.set_terminal_lock(state_payload);
        }
        return;
    }
    let retry = global_terminal_unlock_limiter()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retry_after_secs(Instant::now());
    if retry > 0 {
        push_result(
            outbox,
            false,
            Some(format!("密码错误次数过多，请 {retry} 秒后再试")),
            retry,
        );
        return;
    }
    if pw.is_empty() || pw.len() > 512 {
        push_result(
            outbox,
            false,
            Some("请输入有效的系统登录密码".to_string()),
            0,
        );
        return;
    }
    if !requested_username_matches_current(
        username.as_deref(),
        crate::platform::current_system_username().as_deref(),
    ) {
        let retry = global_terminal_unlock_limiter()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_failure(Instant::now());
        let err_msg = if retry > 0 {
            format!("系统用户名不匹配，请 {retry} 秒后再试")
        } else {
            "系统用户名与当前登录用户不匹配".to_string()
        };
        push_result(outbox, false, Some(err_msg), retry);
        return;
    }
    if verify_driver.is_in_flight() {
        push_result(
            outbox,
            false,
            Some("正在验证系统密码，请稍候".to_string()),
            0,
        );
        return;
    }
    let spawned = verify_driver
        .spawn(move || crate::platform::verify_system_password(username.as_deref(), &pw));
    if !spawned {
        push_result(
            outbox,
            false,
            Some("启动系统密码校验失败，请重试".to_string()),
            0,
        );
    }
}

pub(super) fn handle_terminal_verify_completion(
    verify_res: Result<bool, String>,
    is_owner: bool,
    gate: &mut TerminalLockGate,
    outbox: &mut HostDisplayCtrlOutbox,
) {
    if !gate.is_locked() {
        // 物理屏已在异步核验返回前解锁（gate 已放行）：
        // - 若本次核验恰好为 Ok(true)，正常清零限流并回传 ok=true；
        // - 若为 Ok(false) 或 Err(_)，绝不记录失败限流，也不发送 TerminalUnlockResult
        //   （既不误报失败，也不得误发 ok=true 导致客户端将错误密码保存到钥匙串），仅刷新已解锁 LockState。
        if matches!(verify_res, Ok(true)) {
            global_terminal_unlock_limiter()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_success();
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::TerminalUnlockResult {
                    ok: true,
                    error: None,
                    retry_after_secs: 0,
                })
            {
                outbox.push_transient(payload);
            }
        }
        if let Some(state_payload) = encode_terminal_lock_state(is_owner, gate) {
            outbox.set_terminal_lock(state_payload);
        }
        return;
    }

    match verify_res {
        Ok(true) => {
            global_terminal_unlock_limiter()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_success();
            gate.on_verified_ok();
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::TerminalUnlockResult {
                    ok: true,
                    error: None,
                    retry_after_secs: 0,
                })
            {
                outbox.push_transient(payload);
            }
            if let Some(state_payload) = encode_terminal_lock_state(is_owner, gate) {
                outbox.set_terminal_lock(state_payload);
            }
        }
        Ok(false) => {
            let retry = global_terminal_unlock_limiter()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_failure(Instant::now());
            let err_msg = if retry > 0 {
                format!("系统密码错误，请 {retry} 秒后再试")
            } else {
                "系统密码错误，请输入被控端系统登录密码".to_string()
            };
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::TerminalUnlockResult {
                    ok: false,
                    error: Some(err_msg),
                    retry_after_secs: retry,
                })
            {
                outbox.push_transient(payload);
            }
        }
        Err(err) => {
            if let Some(payload) =
                display_ctrl::encode_display_ctrl(&DisplayControlMsg::TerminalUnlockResult {
                    ok: false,
                    error: Some(err),
                    retry_after_secs: 0,
                })
            {
                outbox.push_transient(payload);
            }
        }
    }
}

/// 单通道无丢帧重试冲刷：
/// - 若 `pending` 非空，先冲刷待重试帧且不继续拉取引擎（避免回压期无界堆积）；
/// - 仅当 `pending` 为空时从引擎最多拉取 `max_frames` 帧；
/// - 任意帧发送返回 `Err`（如 TCP 中继背压）时立即停止并保留该帧及后续已拉取帧，
///   下一拍严格按 FIFO 顺序重试，确保可靠工具通道零丢块。
pub(super) fn flush_tool_channel_with_retry_checked<E>(
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

pub(super) fn flush_tool_channel_with_retry<E>(
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
pub(super) struct FileHostWorker {
    in_tx: Option<mpsc::SyncSender<Vec<u8>>>,
    out_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub(super) cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FileHostWorker {
    pub(super) fn spawn(default_receive_dir: SharedFileTransferDir) -> Self {
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

    pub(super) fn try_send_incoming(
        &self,
        frame: Vec<u8>,
    ) -> Result<(), mpsc::TrySendError<Vec<u8>>> {
        match self.in_tx.as_ref() {
            Some(tx) => tx.try_send(frame),
            None => Err(mpsc::TrySendError::Disconnected(frame)),
        }
    }

    pub(super) fn try_recv_outgoing(&self, max_frames: usize) -> Vec<Vec<u8>> {
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
