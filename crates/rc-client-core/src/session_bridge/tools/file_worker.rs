use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rc_tools::{FileClientEngine, FileEvent, TransferDirection, TransferItem, TransferStatus};

use super::super::queues::BoundedQueue;
use super::super::types::{
    FILE_CLIENT_WORKER_CHAN_CAP, MAX_TOOL_FRAMES_PER_TICK, UPLOAD_PROGRESS_EMIT_INTERVAL,
};

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

pub(in crate::session_bridge) enum FileWorkerCmd {
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
pub(in crate::session_bridge) struct FileClientHandle {
    pub(in crate::session_bridge) cmd_tx: mpsc::SyncSender<FileWorkerCmd>,
    pub(in crate::session_bridge) cached_transfers: Arc<Mutex<Vec<TransferItem>>>,
    wake: WorkerWake,
}

impl FileClientHandle {
    pub(in crate::session_bridge) fn send_cmd<R>(
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
pub(in crate::session_bridge) struct FileClientWorker {
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
    pub(in crate::session_bridge) fn spawn(
        file_events: Arc<BoundedQueue<FileEvent>>,
    ) -> (Self, FileClientHandle) {
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
    pub(in crate::session_bridge) fn abort_all_active(&self, reason: impl Into<String>) {
        *self.abort_reason.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason.into());
        if let Some(rx) = self.wire_out_rx.as_ref() {
            while rx.try_recv().is_ok() {}
        }
        self.wake.notify();
    }

    pub(in crate::session_bridge) fn try_send_incoming(
        &self,
        frame: Vec<u8>,
    ) -> Result<(), mpsc::TrySendError<Vec<u8>>> {
        let Some(tx) = self.wire_in_tx.as_ref() else {
            return Err(mpsc::TrySendError::Disconnected(frame));
        };
        let res = tx.try_send(frame);
        if res.is_ok() {
            self.wake.notify();
        }
        res
    }

    pub(in crate::session_bridge) fn try_recv_outgoing(&self, max_frames: usize) -> Vec<Vec<u8>> {
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

    pub(in crate::session_bridge) fn shutdown(&mut self) {
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
