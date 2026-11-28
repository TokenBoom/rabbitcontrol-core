use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rc_net::quic::QuicEndpoint;
use rc_session::proto::{ByeReason, SessionParams};
use rc_session::HostSession;
use rc_tools::TerminalHostEngine;

use crate::server_config::parse_device_id_input;
use crate::signal_client::{ActiveControllerSummary, ForceDisconnectEvent, RelayIncoming};

use super::types::{
    ActiveControllerPeerHints, ActiveControllerSession, AuthRuntimeState, HostUpdate,
    PreemptDecision, SharedActiveControllers, SharedSignalClient, DISPLAY_CTRL_QUEUE_CAP,
    LAN_STALE_SIGNAL_GRACE, PREEMPT_ANY_IDLE_THRESHOLD_US, PREEMPT_CHECK_INTERVAL,
    PREEMPT_OWNER_IDLE_THRESHOLD_US, RELAY_INCOMING_TTL, SWITCH_SIGNAL_PROTECT_WINDOW,
};

// ─────────────────────────────────────────────────────────────────
// 有界更新队列
// ─────────────────────────────────────────────────────────────────

pub(super) struct BoundedHostUpdateQueue {
    cap: usize,
    inner: Mutex<VecDeque<HostUpdate>>,
}

impl BoundedHostUpdateQueue {
    pub(super) fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    pub(super) fn push(&self, item: HostUpdate) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        while q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(item);
    }

    pub(super) fn try_pop(&self) -> Option<HostUpdate> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.pop_front()
    }
}

/// 入站中继请求有界队列（满载丢最旧，符合铁律 1，且按 TTL 自动过滤过期令牌）。
pub(super) struct BoundedRelayIncomingQueue {
    cap: usize,
    inner: Mutex<VecDeque<(Instant, RelayIncoming)>>,
}

impl BoundedRelayIncomingQueue {
    pub(super) fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    pub(super) fn push(&self, item: RelayIncoming) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // 同对端发起新连接或动态切换传输模式时，队列中尚未消费的旧入站凭据必然已作废；
        // 立即替换避免被控端先拨号过期旧令牌浪费 11.5s 导致新会话中继配对超时。
        if !item.peer_id.is_empty() {
            q.retain(|(_, existing)| existing.peer_id != item.peer_id);
        }
        let is_priority_takeover = item.takeover && item.is_owner_connection;
        while q.len() >= self.cap {
            q.pop_front();
        }
        if is_priority_takeover {
            q.push_front((Instant::now(), item));
        } else {
            q.push_back((Instant::now(), item));
        }
    }

    pub(super) fn pop_ready(&self, ttl: Duration, lan_grace: Duration) -> Option<RelayIncoming> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut deferred = VecDeque::new();
        let mut picked = None;
        while let Some((enqueued_at, item)) = q.pop_front() {
            let elapsed = enqueued_at.elapsed();
            if elapsed > ttl {
                continue;
            }
            let is_priority_takeover = item.takeover && item.is_owner_connection;
            if !item.is_relay_alloc
                && !is_priority_takeover
                && !item.peer_lan_addrs.is_empty()
                && elapsed < lan_grace
            {
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

    pub(super) fn purge_expired(&self, ttl: Duration) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.retain(|(enqueued_at, _)| enqueued_at.elapsed() <= ttl);
    }

    pub(super) fn pop_by_session_id(
        &self,
        session_id: &str,
        ttl: Duration,
    ) -> Option<RelayIncoming> {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = None;
        let mut kept = VecDeque::with_capacity(q.len());
        while let Some((enqueued_at, item)) = q.pop_front() {
            if enqueued_at.elapsed() > ttl {
                continue;
            }
            if out.is_none() && item.session_id == session_id {
                out = Some(item);
            } else {
                kept.push_back((enqueued_at, item));
            }
        }
        *q = kept;
        out
    }

    pub(super) fn purge_for_peer_before(
        &self,
        peer_device_id: Option<&str>,
        cutoff: Instant,
        ttl: Duration,
    ) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.retain(|(enqueued_at, item)| {
            enqueued_at.elapsed() <= ttl
                && (peer_device_id != Some(item.peer_id.as_str()) || *enqueued_at >= cutoff)
        });
    }

    /// 主动清理当前 LAN / mTLS LAN 会话初始宽限期内到达的同对端陈旧 `PunchCoord`（`!is_relay_alloc`），
    /// 防止其滞留满 20s TTL 后在 `Detached` 期复活误抢占并打断 6s 续传；
    /// 严格保留显式切中继（`is_relay_alloc == true`）、宽限期之后的新请求及其他对端条目。
    pub(super) fn purge_stale_lan_punch_for_peer(
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

    pub(super) fn has_pending_takeover_or_same_peer(
        &self,
        peer_did: Option<&str>,
        ttl: Duration,
    ) -> bool {
        let q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        q.iter()
            .filter(|(enqueued_at, _)| enqueued_at.elapsed() <= ttl)
            .any(|(_, item)| {
                (item.takeover && item.is_owner_connection)
                    || peer_did.is_some_and(|d| !d.is_empty() && item.peer_id == d)
            })
    }

    /// 只读检查入站队列中是否存在可立即抢占当前旧会话的新连接候选：
    /// 1. 同账号显式接管（`item.takeover && item.is_owner_connection`）：无视活跃阈值立即抢占，并回传 `PreemptDecision::TakeoverOwner`；
    /// 2. 同设备重连（`active_peer_id` 非空且与 `item.peer_id` 相同）；
    /// 3. 同账号自控失活抢占（`item.is_owner_connection` 且 `is_detached || active_idle_us >= 3s`）；
    /// 4. 旧会话已失活（`is_detached || active_idle_us >= 4s`）。
    ///
    /// 若旧会话活跃（`!is_detached && active_idle_us < 3s`）且到达的是不同设备的非接管请求，返回 `false` 保护当前活跃用户。
    #[cfg(test)]
    pub(super) fn has_preempt_candidate(
        &self,
        ttl: Duration,
        active_peer_id: Option<&str>,
        active_idle_us: u64,
        is_detached: bool,
    ) -> bool {
        self.has_preempt_candidate_filtered(ttl, active_peer_id, active_idle_us, is_detached, None)
    }

    #[cfg(test)]
    pub(super) fn has_preempt_candidate_filtered(
        &self,
        ttl: Duration,
        active_peer_id: Option<&str>,
        active_idle_us: u64,
        is_detached: bool,
        ignore_same_peer_lan_before: Option<Instant>,
    ) -> bool {
        self.check_preempt_candidate_with_switch(
            ttl,
            active_peer_id,
            active_idle_us,
            is_detached,
            ignore_same_peer_lan_before,
            false,
        ) != PreemptDecision::None
    }

    pub(super) fn check_preempt_candidate_filtered(
        &self,
        ttl: Duration,
        active_peer_id: Option<&str>,
        active_idle_us: u64,
        is_detached: bool,
        ignore_same_peer_lan_before: Option<Instant>,
    ) -> PreemptDecision {
        self.check_preempt_candidate_with_switch(
            ttl,
            active_peer_id,
            active_idle_us,
            is_detached,
            ignore_same_peer_lan_before,
            false,
        )
    }

    pub(super) fn check_preempt_candidate_with_switch(
        &self,
        ttl: Duration,
        active_peer_id: Option<&str>,
        active_idle_us: u64,
        is_detached: bool,
        ignore_same_peer_lan_before: Option<Instant>,
        switch_capable: bool,
    ) -> PreemptDecision {
        let q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut decision = PreemptDecision::None;
        for (enqueued_at, item) in q
            .iter()
            .filter(|(enqueued_at, _)| enqueued_at.elapsed() <= ttl)
        {
            if item.takeover && item.is_owner_connection {
                return PreemptDecision::TakeoverOwner;
            }
            let same_peer =
                active_peer_id.is_some_and(|cur| !cur.is_empty() && cur == item.peer_id);
            // 若当前会话启用运行期热切，给同对端刚到达的 `is_relay_alloc == true` 令牌留出 2s 窗口
            // 供 `SwitchControlMsg::RelayAllocReady` 认领，避免运行期 `P2P -> Relay` 切换误触发抢占断流。
            if switch_capable
                && !is_detached
                && same_peer
                && item.is_relay_alloc
                && enqueued_at.elapsed() < Duration::from_secs(2)
            {
                continue;
            }
            // LAN / mTLS LAN 初始宽限期内到达的同对端普通 PunchCoord（!is_relay_alloc）
            // 一律视为本次 LAN 建连同源迟到的旧信令：无论 peer_lan_addrs 是否为空、
            // 无论是否满 3s/4s、无论当前处于 Streaming 还是 Detached，绝不触发误抢占。
            if same_peer
                && !item.is_relay_alloc
                && ignore_same_peer_lan_before.is_some_and(|cutoff| *enqueued_at <= cutoff)
            {
                continue;
            }
            if same_peer
                || (item.is_owner_connection
                    && (is_detached || active_idle_us >= PREEMPT_OWNER_IDLE_THRESHOLD_US))
                || is_detached
                || active_idle_us >= PREEMPT_ANY_IDLE_THRESHOLD_US
            {
                decision = PreemptDecision::SamePeerOrIdle;
            }
        }
        decision
    }
}

/// 计算 LAN / mTLS LAN 会话结束后的旧信令清理截止点：
/// LAN 直连往往比 WAN 信令 `PunchCoord` 提前 50–300ms 完成建连，若仅用 `session_started_at`
/// 会漏清同一次初始连接产生的迟到旧令牌；将截止点向后延展至多 3s 且不超过断连前 500ms，
/// 既清掉初始迟到旧令牌又保护临近断连时的新切换请求。
pub(super) fn lan_stale_signal_cutoff(
    session_started_at: Instant,
    session_ended_at: Instant,
) -> Instant {
    session_ended_at
        .checked_sub(SWITCH_SIGNAL_PROTECT_WINDOW)
        .map(|guard| (session_started_at + LAN_STALE_SIGNAL_GRACE).min(guard))
        .unwrap_or(session_started_at)
}

pub(super) fn emit_peer_connected(
    host: &HostSession,
    remote_addr: &str,
    updates: &BoundedHostUpdateQueue,
) {
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

pub(super) fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub(super) fn build_active_controller_session(
    host: &HostSession,
    hints: &ActiveControllerPeerHints,
    connected_at_ms: u64,
) -> ActiveControllerSession {
    let meta = host.controller_meta();
    let session_id = hints
        .session_id_hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| host.session_id().map(|id| id.to_string()))
        .unwrap_or_else(|| "0".to_string());
    let caller_did = host
        .authenticated_owner()
        .map(|o| o.caller_device_id.as_str())
        .or(hints.relay_peer_id.as_deref())
        .or(hints.mtls_peer_did.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let controller_device_id = meta
        .map(|m| m.device_id.trim())
        .filter(|s| !s.is_empty())
        .or(caller_did)
        .unwrap_or("")
        .to_string();
    let controller_device_name = meta
        .map(|m| m.device_name.trim())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            hints
                .relay_peer_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            hints
                .relay_peer_hostname
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .or(caller_did)
        .or_else(|| {
            let r = hints.remote_addr.trim();
            (!r.is_empty()).then_some(r)
        })
        .unwrap_or("")
        .to_string();
    let controller_os = meta
        .map(|m| m.os.trim())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            hints
                .relay_peer_os
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("")
        .to_string();
    let mode = meta.map(|m| m.mode_str().to_string()).unwrap_or_else(|| {
        if host.is_media_paused() {
            "tools".to_string()
        } else {
            "remote_control".to_string()
        }
    });
    ActiveControllerSession {
        session_id,
        controller_device_id,
        controller_device_name,
        controller_os,
        is_owner: host.authenticated_owner().is_some(),
        mode,
        connected_at_ms,
    }
}

pub(super) fn report_control_state_to_signal(
    signal_client: Option<&SharedSignalClient>,
    controllers: &[ActiveControllerSession],
) {
    let Some(shared_sig) = signal_client else {
        return;
    };
    let sig_opt = shared_sig.read().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(sig) = sig_opt {
        let summaries: Vec<ActiveControllerSummary> = controllers
            .iter()
            .map(ActiveControllerSummary::from)
            .collect();
        let _ = sig.report_control_state(summaries);
    }
}

pub(super) fn publish_active_controller(
    slot: &SharedActiveControllers,
    updates: &BoundedHostUpdateQueue,
    signal_client: Option<&SharedSignalClient>,
    session: ActiveControllerSession,
) {
    let list = vec![session];
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = list.clone();
    report_control_state_to_signal(signal_client, &list);
    updates.push(HostUpdate::ActiveControllersChanged { controllers: list });
}

pub(super) fn clear_active_controllers(
    slot: &SharedActiveControllers,
    updates: &BoundedHostUpdateQueue,
    signal_client: Option<&SharedSignalClient>,
) {
    let had_any = {
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        let had = !guard.is_empty();
        guard.clear();
        had
    };
    if had_any {
        report_control_state_to_signal(signal_client, &[]);
        updates.push(HostUpdate::ActiveControllersChanged {
            controllers: Vec::new(),
        });
    }
}

pub(super) fn force_disconnect_matches_controller(
    req: &ForceDisconnectEvent,
    active: Option<&ActiveControllerSession>,
    fallback_peer_id: Option<&str>,
    fallback_session_id: Option<&str>,
) -> bool {
    let req_cid = req
        .controller_device_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let req_sid = req
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if req_cid.is_none() && req_sid.is_none() {
        return true;
    }
    if let Some(target_sid) = req_sid {
        let cur_sid = active
            .map(|c| c.session_id.as_str())
            .or(fallback_session_id)
            .unwrap_or("")
            .trim();
        if cur_sid != target_sid {
            return false;
        }
    }
    if let Some(target_cid) = req_cid {
        let cur_cid = active
            .map(|c| c.controller_device_id.as_str())
            .or(fallback_peer_id)
            .unwrap_or("")
            .trim();
        let norm_target =
            parse_device_id_input(target_cid).unwrap_or_else(|| target_cid.to_string());
        let norm_cur = parse_device_id_input(cur_cid).unwrap_or_else(|| cur_cid.to_string());
        if norm_cur.is_empty() || norm_cur != norm_target {
            return false;
        }
    }
    true
}

pub(super) fn drain_matching_force_disconnect(
    signal_client: Option<&SharedSignalClient>,
    active_controllers: Option<&SharedActiveControllers>,
    fallback_peer_id: Option<&str>,
    fallback_session_id: Option<&str>,
) -> bool {
    let Some(shared_sig) = signal_client else {
        return false;
    };
    let sig_opt = shared_sig.read().unwrap_or_else(|e| e.into_inner()).clone();
    let Some(sig) = sig_opt else {
        return false;
    };
    let reqs = sig.drain_force_disconnect_requests();
    if reqs.is_empty() {
        return false;
    }
    let active = active_controllers.and_then(|slot| {
        slot.lock()
            .unwrap_or_else(|e| e.into_inner())
            .first()
            .cloned()
    });
    reqs.iter().any(|req| {
        force_disconnect_matches_controller(
            req,
            active.as_ref(),
            fallback_peer_id,
            fallback_session_id,
        )
    })
}

pub(super) fn reject_busy_lan_endpoint_once_with_cancel(
    ep: &QuicEndpoint,
    caps: SessionParams,
    active_controllers: Option<&SharedActiveControllers>,
    incoming_relay: Option<&Arc<BoundedRelayIncomingQueue>>,
    cancel: &AtomicBool,
) {
    if cancel.load(Ordering::Acquire) {
        return;
    }
    let active_peer_did = active_controllers.and_then(|slot| {
        let guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_empty() {
            return None;
        }
        Some(
            guard
                .first()
                .map(|c| c.controller_device_id.clone())
                .filter(|s| !s.is_empty()),
        )
    });
    let Some(active_peer_did) = active_peer_did else {
        return;
    };
    // 若入站信令队列已有同账号接管或同设备重连候选，则保留在 QUIC accept 队列中交由外层监听循环承接。
    if incoming_relay.is_some_and(|q| {
        q.has_pending_takeover_or_same_peer(active_peer_did.as_deref(), RELAY_INCOMING_TTL)
    }) {
        return;
    }
    let mut busy_transport =
        match ep.try_accept_nonblocking(Duration::from_millis(200), Some(cancel)) {
            Ok(Some(t)) => t,
            Ok(None) | Err(_) => return,
        };
    let mtls_peer_did = busy_transport
        .peer_mtls_identity()
        .map(|id| id.device_id.clone());
    let latest_active_peer_did = active_controllers.and_then(|slot| {
        slot.lock()
            .unwrap_or_else(|e| e.into_inner())
            .first()
            .map(|c| c.controller_device_id.clone())
            .filter(|s| !s.is_empty())
    });
    let same_active_peer = mtls_peer_did
        .as_deref()
        .is_some_and(|did| latest_active_peer_did.as_deref() == Some(did));
    let pending_takeover_or_same = incoming_relay.is_some_and(|q| {
        q.has_pending_takeover_or_same_peer(mtls_peer_did.as_deref(), RELAY_INCOMING_TTL)
    });
    if same_active_peer || pending_takeover_or_same {
        // 已完成 QUIC accept 时不得静默 drop 连接，显式回发 Bye(Refresh) 避免对端误判为密码拒绝或传输异常。
        let _ = rc_session::send_bye_and_drain(&mut busy_transport, ByeReason::Refresh);
        return;
    }
    let _ = rc_session::reject_transport_busy_controlled_cancelable(
        &mut busy_transport,
        caps,
        Duration::from_millis(200),
        Some(cancel),
    );
}

struct BusyLanRejectShared {
    active: AtomicBool,
    stop: AtomicBool,
    accept_cancel: AtomicBool,
    poll_lock: Mutex<()>,
    wake_lock: Mutex<()>,
    wake_cv: Condvar,
}

impl BusyLanRejectShared {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            accept_cancel: AtomicBool::new(true),
            poll_lock: Mutex::new(()),
            wake_lock: Mutex::new(()),
            wake_cv: Condvar::new(),
        }
    }
}

/// 异步后台辅助线程：在活跃 `Streaming` 期非阻塞轮询 LAN `QuicEndpoint` 并拒收额外直连请求，
/// 避免同步 `try_accept_nonblocking(200ms)` + `reject_transport_busy_controlled(200ms+50ms)` 卡顿媒体热路径。
pub(super) struct BusyLanRejectWorker {
    shared: Arc<BusyLanRejectShared>,
    handle: Option<JoinHandle<()>>,
}

impl BusyLanRejectWorker {
    pub(super) fn spawn(
        ep: QuicEndpoint,
        caps: SessionParams,
        active_controllers: Option<SharedActiveControllers>,
        incoming_relay: Option<Arc<BoundedRelayIncomingQueue>>,
    ) -> Self {
        let shared = Arc::new(BusyLanRejectShared::new());
        let worker_shared = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name("rc-busy-lan-reject".to_string())
            .spawn(move || {
                while !worker_shared.stop.load(Ordering::Acquire) {
                    if !worker_shared.active.load(Ordering::Acquire) {
                        let guard = worker_shared
                            .wake_lock
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if !worker_shared.active.load(Ordering::Acquire)
                            && !worker_shared.stop.load(Ordering::Acquire)
                        {
                            drop(worker_shared.wake_cv.wait(guard));
                        }
                        continue;
                    }

                    {
                        let _poll_guard = worker_shared
                            .poll_lock
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if worker_shared.active.load(Ordering::Acquire)
                            && !worker_shared.stop.load(Ordering::Acquire)
                        {
                            reject_busy_lan_endpoint_once_with_cancel(
                                &ep,
                                caps,
                                active_controllers.as_ref(),
                                incoming_relay.as_ref(),
                                &worker_shared.accept_cancel,
                            );
                        }
                    }

                    if worker_shared.stop.load(Ordering::Acquire) {
                        break;
                    }
                    let guard = worker_shared
                        .wake_lock
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if worker_shared.active.load(Ordering::Acquire)
                        && !worker_shared.stop.load(Ordering::Acquire)
                    {
                        drop(
                            worker_shared
                                .wake_cv
                                .wait_timeout(guard, PREEMPT_CHECK_INTERVAL),
                        );
                    }
                }
            })
            .ok();
        Self { shared, handle }
    }

    pub(super) fn set_active(&self) {
        if !self.shared.active.load(Ordering::Acquire) {
            self.shared.accept_cancel.store(false, Ordering::Release);
            self.shared.active.store(true, Ordering::Release);
            let _guard = self
                .shared
                .wake_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            self.shared.wake_cv.notify_all();
        }
    }

    pub(super) fn pause_and_sync(&self) {
        if self.shared.active.swap(false, Ordering::AcqRel) {
            self.shared.accept_cancel.store(true, Ordering::Release);
            if let Some(h) = self.handle.as_ref() {
                h.thread().unpark();
            }
            let _guard = self
                .shared
                .wake_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            self.shared.wake_cv.notify_all();
            drop(_guard);
            let _poll_guard = self
                .shared
                .poll_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
        }
    }
}

impl Drop for BusyLanRejectWorker {
    fn drop(&mut self) {
        self.shared.active.store(false, Ordering::Release);
        self.shared.stop.store(true, Ordering::Release);
        self.shared.accept_cancel.store(true, Ordering::Release);
        if let Some(h) = self.handle.as_ref() {
            h.thread().unpark();
        }
        {
            let _guard = self
                .shared
                .wake_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            self.shared.wake_cv.notify_all();
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// 跨控制端断线/重连持久化的机主级后台终端托管槽位（按 `user_id` 严格隔离，仅机主本人可继承）。
pub(super) struct PersistentOwnerTerminals {
    owner_user_id: Option<String>,
    pub(super) engine: TerminalHostEngine,
}

impl PersistentOwnerTerminals {
    pub(super) fn new() -> Self {
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

    pub(super) fn sync_auth_and_poll(&mut self, auth_state: Option<&Mutex<AuthRuntimeState>>) {
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

    pub(super) fn detach_all(&mut self) {
        self.engine.detach_all();
    }

    pub(super) fn bind_for_owner(&mut self, user_id: &str) -> &mut TerminalHostEngine {
        if self.owner_user_id.as_deref() != Some(user_id) {
            self.owner_user_id = Some(user_id.to_string());
            self.engine = TerminalHostEngine::new();
        }
        &mut self.engine
    }
}

/// 被控端显示/控制通道出站队列：
/// - 关键粘性状态（工具权限 / 终端锁屏状态 / 宿主屏幕锁屏挂起状态 / 显示能力）保存在各自覆盖最新的粘性槽位中，
///   在背压或瞬态消息满载淘汰时绝不被 FIFO 静默挤掉，且发送时优先于普通瞬态消息；
/// - 其余瞬态消息走 64 槽位有界 drop-oldest FIFO 队列。
#[derive(Default)]
pub(super) struct HostDisplayCtrlOutbox {
    pub(super) sticky_tool_perms: Option<Vec<u8>>,
    pub(super) sticky_terminal_lock: Option<Vec<u8>>,
    pub(super) sticky_screen_state: Option<Vec<u8>>,
    pub(super) sticky_caps: Option<Vec<u8>>,
    pub(super) queue: VecDeque<Vec<u8>>,
}

impl HostDisplayCtrlOutbox {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.sticky_tool_perms.is_none()
            && self.sticky_terminal_lock.is_none()
            && self.sticky_screen_state.is_none()
            && self.sticky_caps.is_none()
            && self.queue.is_empty()
    }

    pub(super) fn clear(&mut self) {
        self.sticky_tool_perms = None;
        self.sticky_terminal_lock = None;
        self.sticky_screen_state = None;
        self.sticky_caps = None;
        self.queue.clear();
    }

    pub(super) fn set_tool_perms(&mut self, payload: Vec<u8>) {
        self.sticky_tool_perms = Some(payload);
    }

    pub(super) fn set_terminal_lock(&mut self, payload: Vec<u8>) {
        self.sticky_terminal_lock = Some(payload);
    }

    pub(super) fn set_screen_state(&mut self, payload: Vec<u8>) {
        self.sticky_screen_state = Some(payload);
    }

    pub(super) fn set_caps(&mut self, payload: Vec<u8>) {
        self.sticky_caps = Some(payload);
    }

    pub(super) fn push_transient(&mut self, payload: Vec<u8>) {
        while self.queue.len() >= DISPLAY_CTRL_QUEUE_CAP {
            self.queue.pop_front();
        }
        self.queue.push_back(payload);
    }

    fn flush_slot<E>(
        slot: &mut Option<Vec<u8>>,
        remaining_budget: &mut usize,
        sent_any: &mut bool,
        send_fn: &mut impl FnMut(Vec<u8>) -> Result<(), E>,
        is_fatal_err: &impl Fn(&E) -> bool,
    ) -> bool {
        if *remaining_budget == 0 {
            return false;
        }
        let Some(frame) = slot.take() else {
            return true;
        };
        match send_fn(frame.clone()) {
            Ok(()) => {
                *sent_any = true;
                *remaining_budget -= 1;
                true
            }
            Err(ref e) if is_fatal_err(e) => true,
            Err(_) => {
                *slot = Some(frame);
                false
            }
        }
    }

    pub(super) fn flush<E>(
        &mut self,
        max_frames: usize,
        mut send_fn: impl FnMut(Vec<u8>) -> Result<(), E>,
        is_fatal_err: impl Fn(&E) -> bool,
    ) -> bool {
        let mut budget = max_frames;
        let mut sent_any = false;
        let sticky_ok = Self::flush_slot(
            &mut self.sticky_tool_perms,
            &mut budget,
            &mut sent_any,
            &mut send_fn,
            &is_fatal_err,
        ) && Self::flush_slot(
            &mut self.sticky_terminal_lock,
            &mut budget,
            &mut sent_any,
            &mut send_fn,
            &is_fatal_err,
        ) && Self::flush_slot(
            &mut self.sticky_screen_state,
            &mut budget,
            &mut sent_any,
            &mut send_fn,
            &is_fatal_err,
        ) && Self::flush_slot(
            &mut self.sticky_caps,
            &mut budget,
            &mut sent_any,
            &mut send_fn,
            &is_fatal_err,
        );
        if !sticky_ok {
            return sent_any;
        }
        while budget > 0 {
            let Some(front) = self.queue.front() else {
                break;
            };
            match send_fn(front.clone()) {
                Ok(()) => {
                    self.queue.pop_front();
                    sent_any = true;
                    budget -= 1;
                }
                Err(ref e) if is_fatal_err(e) => {
                    self.queue.pop_front();
                }
                Err(_) => break,
            }
        }
        sent_any
    }
}
