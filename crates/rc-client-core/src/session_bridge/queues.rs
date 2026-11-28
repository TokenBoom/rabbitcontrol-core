use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use rc_input::InputEvent;

use super::types::SessionUpdate;

// ─────────────────────────────────────────────────────────────────
// 有界非阻塞队列（铁律 1 UI 侧延伸：命令 64 / 输入 256 / 更新 64）
// ─────────────────────────────────────────────────────────────────

/// 通用有界 drop-oldest 队列（永不阻塞生产端或消费端）。
pub(in crate::session_bridge) struct BoundedQueue<T> {
    cap: usize,
    inner: Mutex<VecDeque<T>>,
}

impl<T> BoundedQueue<T> {
    pub(in crate::session_bridge) fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    pub(in crate::session_bridge) fn push_drop_oldest(&self, item: T) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        while q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(item);
    }

    pub(in crate::session_bridge) fn drain_all(&self) -> Vec<T> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.drain(..).collect()
    }

    pub(in crate::session_bridge) fn try_pop(&self) -> Option<T> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.pop_front()
    }

    #[cfg(test)]
    pub(in crate::session_bridge) fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// 状态更新专用有界队列：满载时优先丢弃最旧的 `Hud` / `Connecting`，保护 `Negotiated` / `Ended`。
pub(in crate::session_bridge) struct BoundedUpdateQueue {
    cap: usize,
    inner: Mutex<VecDeque<SessionUpdate>>,
}

impl BoundedUpdateQueue {
    pub(in crate::session_bridge) fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    pub(in crate::session_bridge) fn push(&self, item: SessionUpdate) {
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

    pub(in crate::session_bridge) fn try_pop(&self) -> Option<SessionUpdate> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.pop_front()
    }
}

/// 判定一条输入事件是否为关键事件（不可轻易因移动事件挤占而丢弃）。
pub(in crate::session_bridge) fn is_critical_input(ev: &InputEvent) -> bool {
    !matches!(ev, InputEvent::MouseMove { .. } | InputEvent::Sync)
}

/// 输入专用有界队列（容量 256）：满载丢最旧的非关键事件，优先保留关键事件（U6）。
pub(in crate::session_bridge) struct BoundedInputQueue {
    cap: usize,
    inner: Mutex<VecDeque<InputEvent>>,
    wake: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl BoundedInputQueue {
    pub(in crate::session_bridge) fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
            wake: Mutex::new(None),
        }
    }

    pub(in crate::session_bridge) fn set_wake_handle(
        &self,
        wake: Option<Arc<dyn Fn() + Send + Sync>>,
    ) {
        *self.wake.lock().unwrap_or_else(|e| e.into_inner()) = wake;
    }

    pub(in crate::session_bridge) fn push(&self, ev: InputEvent) {
        let should_wake = {
            let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let was_empty = q.is_empty();
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
            was_empty && !q.is_empty()
        };
        if should_wake {
            let cb = self.wake.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(wake) = cb {
                wake();
            }
        }
    }

    pub(in crate::session_bridge) fn drain_all(&self) -> Vec<InputEvent> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.drain(..).collect()
    }

    #[cfg(test)]
    pub(in crate::session_bridge) fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// 离场自动擦除敏感字节帧的队列包装（用于携带 `TerminalUnlockRequest` 的显示控制发送队列）。
pub(in crate::session_bridge) struct ZeroizingByteQueue(VecDeque<Vec<u8>>);

impl ZeroizingByteQueue {
    pub(in crate::session_bridge) fn new() -> Self {
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

/// 冲刷单个工具通道的待发送队列：遇到瞬态背压 `Err` 时停止并保留队首，
/// 遇到不可恢复的配置/超限错误（`is_fatal_err` 返回 `true`）时丢弃该非法帧以免永久阻塞后续可靠控制消息；
/// `zeroize_popped` 为 `true` 时在出队后擦除敏感帧缓冲（用于携带 `TerminalUnlockRequest` 的显示控制队列）。
pub(in crate::session_bridge) fn flush_pending_tool_queue_checked<E>(
    pending: &mut VecDeque<Vec<u8>>,
    mut send_fn: impl FnMut(Vec<u8>) -> Result<(), E>,
    is_fatal_err: impl Fn(&E) -> bool,
) -> bool {
    flush_pending_tool_queue_impl(pending, false, &mut send_fn, &is_fatal_err)
}

pub(in crate::session_bridge) fn flush_pending_display_tx_checked<E>(
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
pub(in crate::session_bridge) fn flush_pending_tool_queue<E>(
    pending: &mut VecDeque<Vec<u8>>,
    send_fn: impl FnMut(Vec<u8>) -> Result<(), E>,
) -> bool {
    flush_pending_tool_queue_checked(pending, send_fn, |_| false)
}
