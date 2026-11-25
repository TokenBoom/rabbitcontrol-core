//! 工具通道 FFI:文件传输/终端/端口映射,全部挂在会话的 ToolClientHandle 上。
//!
//! 设计:`rc_tools_call` 统一分发(写操作),`rc_tools_poll` 统一收割
//! (事件流)。全部阻塞式,移动端后台线程调用。

use std::os::raw::c_char;

use serde::Deserialize;

use crate::{read_c_str, to_c_string};

fn err_json(e: impl std::fmt::Display) -> *mut c_char {
    to_c_string(serde_json::json!({ "error": e.to_string() }).to_string())
}

fn ok_json(v: serde_json::Value) -> *mut c_char {
    to_c_string(v.to_string())
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ToolOp {
    // ── 文件 ──
    FileListRemote {
        path: Option<String>,
    },
    FileMkdir {
        parent: String,
        name: String,
    },
    FileUpload {
        local_path: String,
        remote_dir: String,
    },
    FileDownload {
        remote_path: String,
        local_dir: String,
    },
    FileCancel {
        id: u64,
    },
    FileClearFinished,
    // ── 终端 ──
    TerminalOpen {
        cols: u16,
        rows: u16,
    },
    TerminalList,
    TerminalAttach {
        term_id: u32,
        cols: u16,
        rows: u16,
    },
    TerminalDetach {
        term_id: u32,
    },
    TerminalInput {
        term_id: u32,
        /// UTF-8 文本(移动端键盘输入的天然形态)。
        text: String,
    },
    TerminalResize {
        term_id: u32,
        cols: u16,
        rows: u16,
    },
    TerminalClose {
        term_id: u32,
    },
    // ── 端口映射 ──
    PortmapList,
    PortmapAdd {
        name: String,
        local_port: u16,
        remote_host: String,
        remote_port: u16,
        #[serde(default = "default_true")]
        enabled: bool,
    },
    PortmapRemove {
        rule_id: u64,
    },
    PortmapToggle {
        rule_id: u64,
        enabled: bool,
    },
}

fn default_true() -> bool {
    true
}

/// 工具写操作统一入口。输入 `{"op": "...", ...}`,返回 `{"ok": true, ...}` 或 `{"error": ...}`。
#[no_mangle]
pub extern "C" fn rc_tools_call(session_id: u64, json: *const c_char) -> *mut c_char {
    let result: Result<serde_json::Value, String> = (|| {
        let Some(s) = read_c_str(json) else {
            return Err("缺少 JSON 参数".to_string());
        };
        let op: ToolOp = serde_json::from_str(s).map_err(|e| format!("参数解析: {e}"))?;
        let tools = crate::session::with_session(session_id, |h| h.tools()).ok_or("会话不存在")?;
        match op {
            ToolOp::FileListRemote { path } => {
                tools.file_list_remote(path)?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::FileMkdir { parent, name } => {
                tools.file_mkdir_remote(parent, name)?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::FileUpload {
                local_path,
                remote_dir,
            } => {
                let id = tools.file_upload(&local_path, &remote_dir)?;
                Ok(serde_json::json!({ "ok": true, "transfer_id": id }))
            }
            ToolOp::FileDownload {
                remote_path,
                local_dir,
            } => {
                let id = tools.file_download(&remote_path, &local_dir)?;
                Ok(serde_json::json!({ "ok": true, "transfer_id": id }))
            }
            ToolOp::FileCancel { id } => {
                tools.file_cancel(id)?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::FileClearFinished => {
                tools.file_clear_finished()?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::TerminalOpen { cols, rows } => {
                let id = tools.terminal_open(cols, rows)?;
                Ok(serde_json::json!({ "ok": true, "term_id": id }))
            }
            ToolOp::TerminalList => {
                tools.terminal_list()?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::TerminalAttach {
                term_id,
                cols,
                rows,
            } => {
                tools.terminal_attach(term_id, cols, rows)?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::TerminalDetach { term_id } => {
                tools.terminal_detach(term_id)?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::TerminalInput { term_id, text } => {
                tools.terminal_input(term_id, text.as_bytes())?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::TerminalResize {
                term_id,
                cols,
                rows,
            } => {
                tools.terminal_resize(term_id, cols, rows)?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::TerminalClose { term_id } => {
                tools.terminal_close(term_id)?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::PortmapList => {
                let rules = tools.portmap_list();
                Ok(serde_json::json!({ "ok": true, "rules": rules }))
            }
            ToolOp::PortmapAdd {
                name,
                local_port,
                remote_host,
                remote_port,
                enabled,
            } => {
                let (rule, _all) = tools.portmap_add_with_enabled(
                    name,
                    local_port,
                    remote_host,
                    remote_port,
                    enabled,
                )?;
                Ok(serde_json::json!({ "ok": true, "rule_id": rule.id }))
            }
            ToolOp::PortmapRemove { rule_id } => {
                tools.portmap_delete(rule_id).map(|_| ())?;
                Ok(serde_json::json!({ "ok": true }))
            }
            ToolOp::PortmapToggle { rule_id, enabled } => {
                tools.portmap_toggle(rule_id, enabled).map(|_| ())?;
                Ok(serde_json::json!({ "ok": true }))
            }
        }
    })();
    match result {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

/// 收割工具事件:文件事件 + 终端事件 + 端口映射快照,一次拉空。
#[no_mangle]
pub extern "C" fn rc_tools_poll(session_id: u64) -> *mut c_char {
    let Some((file_events, terminal_events, portmap)) =
        crate::session::with_session(session_id, |h| {
            let mut fe = Vec::new();
            while let Some(ev) = h.try_recv_file_event() {
                if let Ok(v) = serde_json::to_value(&ev) {
                    fe.push(v);
                }
            }
            let mut te = Vec::new();
            while let Some(ev) = h.try_recv_terminal_event() {
                if let Ok(v) = serde_json::to_value(&ev) {
                    te.push(v);
                }
            }
            let pm = h
                .take_portmap_update()
                .map(|rules| serde_json::to_value(&rules).unwrap_or(serde_json::Value::Null));
            (fe, te, pm)
        })
    else {
        return err_json("会话不存在");
    };
    let mut out = serde_json::json!({
        "file_events": file_events,
        "terminal_events": terminal_events,
    });
    if let Some(pm) = portmap {
        out["portmap_rules"] = pm;
    }
    ok_json(out)
}
