use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rc_session::{ToolPermissions, TOOL_CHANNEL_FILE, TOOL_CHANNEL_PORTMAP, TOOL_CHANNEL_TERMINAL};
use rc_tools::{validate_terminal_name, PortMapRuleSnapshot, TransferItem};

use super::super::queues::BoundedUpdateQueue;
use super::super::types::{SessionUpdate, MAX_TERMINAL_DIM, MAX_TERMINAL_INPUT_BYTES};
use super::file_worker::{FileClientHandle, FileWorkerCmd};
use super::ToolClientHub;

/// 线程安全的控制端工具调用句柄（供 Tauri IPC 命令直接调用，不在 `AppState::session` 锁内阻塞）。
#[derive(Clone)]
pub struct ToolClientHandle {
    pub(in crate::session_bridge) hub: Arc<Mutex<ToolClientHub>>,
    pub(in crate::session_bridge) file: FileClientHandle,
    pub(in crate::session_bridge) portmap_latest: Arc<Mutex<Option<Vec<PortMapRuleSnapshot>>>>,
    pub(in crate::session_bridge) running: Arc<AtomicBool>,
    pub(in crate::session_bridge) tool_permissions: Arc<Mutex<ToolPermissions>>,
    pub(in crate::session_bridge) update_tx: Arc<BoundedUpdateQueue>,
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
