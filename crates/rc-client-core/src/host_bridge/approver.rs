use std::sync::{Arc, Mutex};

use rc_session::auth::{ApprovalRequest, ApprovalVerdict, ConnectionApprover};

use super::queues::BoundedHostUpdateQueue;
use super::types::{HostApprovalPrompt, HostUpdate};

#[derive(Debug, Default)]
pub(super) struct ApproverState {
    in_flight: bool,
    /// 当前在途审批是否实际向 UI 推送了 [`HostUpdate::ApprovalRequested`] 弹窗（避免自动放行后误推取消事件）。
    prompted: bool,
    generation: u64,
    verdict: Option<ApprovalVerdict>,
    /// 实时「允许他人远程协助」门控；关停后 `submit` 即使遇到 `auto_accept_with_password` 也立即拒绝。
    pub(super) remote_assist_enabled: bool,
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
    pub(super) state: Arc<Mutex<ApproverState>>,
    updates: Arc<BoundedHostUpdateQueue>,
    auto_accept_with_password: bool,
}

impl UiApprover {
    pub(super) fn new(
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

    pub(super) fn set_remote_assist_enabled(&self, enabled: bool) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.remote_assist_enabled = enabled;
    }

    /// 设置或清除中继会话握手期的来源地址覆盖文案。
    pub(super) fn set_remote_addr_override(&self, label: Option<String>) {
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
    pub(super) fn mark_stopped(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.stopped = true;
        if guard.in_flight && guard.verdict.is_none() {
            guard.verdict = Some(ApprovalVerdict::Rejected);
        }
    }

    /// 关闭远程协助时立即拒绝并取消当前在途审批，防止旧握手窗口期内继续放行连接。
    pub(super) fn reject_in_flight(&self) {
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
