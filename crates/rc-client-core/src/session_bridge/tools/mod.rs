use std::collections::{BTreeSet, VecDeque};

use rc_tools::{PortMapClientEngine, TerminalClientEngine, TerminalEvent};

pub(in crate::session_bridge) mod file_worker;
pub(in crate::session_bridge) mod handle;

pub(in crate::session_bridge) use file_worker::{FileClientHandle, FileClientWorker};
pub use handle::ToolClientHandle;

/// 会话级非文件工具客户端枢纽（W3 远程终端 + W4 TCP 端口映射）。
///
/// W2 文件传输已拆分至独立专用线程 `rc-file-client-worker`（H12），
/// 保证持有 `tools_hub` 锁时绝不执行任何磁盘 I/O（`canonicalize` / `open` / `write_all` / `sync_all`）。
pub(in crate::session_bridge) struct ToolClientHub {
    pub(in crate::session_bridge) terminal: TerminalClientEngine,
    pub(in crate::session_bridge) portmap: PortMapClientEngine,
    pub(in crate::session_bridge) host_live_ids: BTreeSet<u32>,
    pub(in crate::session_bridge) active_terminals: BTreeSet<u32>,
    pub(in crate::session_bridge) attached_terminals: BTreeSet<u32>,
    pub(in crate::session_bridge) pending_opens: VecDeque<(u32, bool)>,
    pub(in crate::session_bridge) pending_attaches: BTreeSet<u32>,
}

impl ToolClientHub {
    pub(in crate::session_bridge) fn new() -> Self {
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

    pub(in crate::session_bridge) fn reset_terminal(&mut self) {
        self.terminal = TerminalClientEngine::new();
        self.host_live_ids.clear();
        self.active_terminals.clear();
        self.attached_terminals.clear();
        self.pending_opens.clear();
        self.pending_attaches.clear();
    }

    pub(in crate::session_bridge) fn apply_terminal_event(&mut self, ev: &TerminalEvent) {
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
