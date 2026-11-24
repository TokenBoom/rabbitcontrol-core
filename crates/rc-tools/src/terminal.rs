//! 远程真实 PTY 终端引擎（W3）：支持多标签并发 Shell、窗口尺寸同步与优雅回收。
//!
//! 线协议采用 `[kind: u8][header_len: u32 LE][json_header][raw_bytes]`，
//! 单帧上限 [`MAX_TERMINAL_WIRE_FRAME_BYTES`]（64 KiB）。

#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};
#[cfg(unix)]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[cfg(unix)]
use crate::pty_unix::PtyProcess;

/// 单个终端线帧最大字节数（64 KiB）。
pub const MAX_TERMINAL_WIRE_FRAME_BYTES: usize = 64 * 1024;

/// 单条终端输入/输出数据块最大负载（32 KiB）。
pub const TERMINAL_DATA_CHUNK_SIZE: usize = 32 * 1024;

/// 被控端允许同时打开的最大 PTY 数量。
pub const MAX_CONCURRENT_TERMINALS: usize = 8;

/// 被控端每个后台 PTY 保留的回放缓冲上限（256 KiB）。
pub const MAX_TERMINAL_SCROLLBACK_BYTES: usize = 256 * 1024;

/// 终端会话名称允许的最大字符数。
pub const MAX_TERMINAL_NAME_CHARS: usize = 64;

/// 被控端终端引擎待发输出队列上限（帧数），防止慢网络下内存无界增长。
pub const MAX_TERMINAL_OUTGOING_FRAMES: usize = 64;

const MAX_DEFERRED_CTRL_FRAMES: usize = 32;

const FRAME_KIND_CONTROL: u8 = 1;
const FRAME_KIND_INPUT: u8 = 2;
const FRAME_KIND_OUTPUT: u8 = 3;
const FRAME_PREFIX_LEN: usize = 5;

#[cfg(unix)]
const EXIT_DRAIN_GRACE: Duration = Duration::from_millis(250);
#[cfg(unix)]
const BACKGROUND_DRAIN_CHUNK_BYTES: usize = 64 * 1024;

/// 校验并规范化终端会话名称（去除首尾空白，拒绝空串、超长或控制字符）。
pub fn validate_terminal_name(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("会话名称不能为空".to_string());
    }
    if trimmed.chars().count() > MAX_TERMINAL_NAME_CHARS {
        return Err(format!("会话名称不能超过 {MAX_TERMINAL_NAME_CHARS} 个字符"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err("会话名称不能包含控制字符".to_string());
    }
    Ok(trimmed.to_string())
}

/// 单个远端终端会话的元数据快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalSessionInfo {
    /// 终端会话 ID。
    pub term_id: u32,
    /// 用户可见会话名称（默认 `session1` 等，可重命名）。
    pub name: String,
    /// Shell 名称标题。
    pub title: String,
    /// 初始或当前工作目录。
    pub cwd: String,
    /// 会话创建时间（Unix 秒）。
    pub created_at_unix_sec: u64,
    /// 终端列数。
    pub cols: u16,
    /// 终端行数。
    pub rows: u16,
    /// 当前是否有 UI 客户端附着接收实时输出。
    pub attached: bool,
}

/// 远程终端线协议消息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalWireMsg {
    /// 客户端请求开启新的 PTY 会话。
    Open {
        /// 终端会话 ID（`0` 表示由主机自动分配未占用 ID）。
        term_id: u32,
        /// 初始列数。
        cols: u16,
        /// 初始行数。
        rows: u16,
        /// 可选自定义会话名称；为 `None` 时由主机自动生成 `sessionN`。
        name: Option<String>,
        /// 是否在打开后立即附着接收实时输出流。
        attach: bool,
    },
    /// 主机返回 PTY 开启结果。
    Opened {
        /// 终端会话 ID。
        term_id: u32,
        /// 会话名称。
        name: String,
        /// 创建时间（Unix 秒）。
        created_at_unix_sec: u64,
        /// Shell 名称标题。
        title: String,
        /// 初始工作目录。
        cwd: String,
        /// 该会话当前是否处于附着状态。
        attached: bool,
        /// 是否启动成功。
        ok: bool,
        /// 错误信息（失败时填充）。
        error: Option<String>,
    },
    /// 客户端请求列出当前主机托管的活跃终端会话。
    List,
    /// 主机返回活跃终端会话列表。
    ListResp {
        /// 当前活跃的终端会话列表。
        sessions: Vec<TerminalSessionInfo>,
    },
    /// 客户端请求附着至指定后台终端（回放历史缓冲并开启实时输出流）。
    Attach {
        /// 终端会话 ID。
        term_id: u32,
        /// 当前终端窗口列数。
        cols: u16,
        /// 当前终端窗口行数。
        rows: u16,
    },
    /// 主机返回附着结果。
    Attached {
        /// 终端会话 ID。
        term_id: u32,
        /// 成功时附带最新会话元数据。
        session: Option<TerminalSessionInfo>,
        /// 是否附着成功。
        ok: bool,
        /// 错误信息（失败时填充）。
        error: Option<String>,
    },
    /// 客户端请求脱离终端视图（仅暂停实时流，保持远端 PTY 在后台运行）。
    Detach {
        /// 终端会话 ID。
        term_id: u32,
    },
    /// 客户端请求重命名指定终端会话。
    Rename {
        /// 终端会话 ID。
        term_id: u32,
        /// 新名称。
        name: String,
    },
    /// 主机返回重命名结果。
    Renamed {
        /// 终端会话 ID。
        term_id: u32,
        /// 生效后的名称。
        name: String,
        /// 是否重命名成功。
        ok: bool,
        /// 错误信息（失败时填充）。
        error: Option<String>,
    },
    /// 客户端发送至 PTY 的输入字节流。
    Input {
        /// 终端会话 ID。
        term_id: u32,
        /// 原始键盘/粘贴字节。
        data: Vec<u8>,
    },
    /// 主机从 PTY 读取的输出字节流。
    Output {
        /// 终端会话 ID。
        term_id: u32,
        /// 原始终端输出字节（含 ANSI 转义序列）。
        data: Vec<u8>,
    },
    /// 调整终端窗口尺寸。
    Resize {
        /// 终端会话 ID。
        term_id: u32,
        /// 新列数。
        cols: u16,
        /// 新行数。
        rows: u16,
    },
    /// 客户端请求关闭并终止终端会话。
    Close {
        /// 终端会话 ID。
        term_id: u32,
    },
    /// 主机通知终端进程已退出。
    Exited {
        /// 终端会话 ID。
        term_id: u32,
        /// 退出码。
        code: i32,
    },
}

fn default_attach_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
enum TermControlPayload {
    Open {
        term_id: u32,
        cols: u16,
        rows: u16,
        #[serde(default)]
        name: Option<String>,
        #[serde(default = "default_attach_true")]
        attach: bool,
    },
    Opened {
        term_id: u32,
        #[serde(default)]
        name: String,
        #[serde(default)]
        created_at_unix_sec: u64,
        title: String,
        cwd: String,
        #[serde(default = "default_attach_true")]
        attached: bool,
        ok: bool,
        error: Option<String>,
    },
    List,
    ListResp {
        sessions: Vec<TerminalSessionInfo>,
    },
    Attach {
        term_id: u32,
        cols: u16,
        rows: u16,
    },
    Attached {
        term_id: u32,
        #[serde(default)]
        session: Option<TerminalSessionInfo>,
        ok: bool,
        error: Option<String>,
    },
    Detach {
        term_id: u32,
    },
    Rename {
        term_id: u32,
        name: String,
    },
    Renamed {
        term_id: u32,
        name: String,
        ok: bool,
        error: Option<String>,
    },
    Resize {
        term_id: u32,
        cols: u16,
        rows: u16,
    },
    Close {
        term_id: u32,
    },
    Exited {
        term_id: u32,
        code: i32,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct TermDataHeader {
    term_id: u32,
}

impl TerminalWireMsg {
    /// 编码为严格受限（`<= 64 KiB`）的二进制线帧。
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        match self {
            TerminalWireMsg::Input { term_id, data } => {
                encode_data_frame(FRAME_KIND_INPUT, *term_id, data)
            }
            TerminalWireMsg::Output { term_id, data } => {
                encode_data_frame(FRAME_KIND_OUTPUT, *term_id, data)
            }
            other => {
                let ctrl = match other {
                    TerminalWireMsg::Open {
                        term_id,
                        cols,
                        rows,
                        name,
                        attach,
                    } => TermControlPayload::Open {
                        term_id: *term_id,
                        cols: *cols,
                        rows: *rows,
                        name: name.clone(),
                        attach: *attach,
                    },
                    TerminalWireMsg::Opened {
                        term_id,
                        name,
                        created_at_unix_sec,
                        title,
                        cwd,
                        attached,
                        ok,
                        error,
                    } => TermControlPayload::Opened {
                        term_id: *term_id,
                        name: name.clone(),
                        created_at_unix_sec: *created_at_unix_sec,
                        title: title.clone(),
                        cwd: cwd.clone(),
                        attached: *attached,
                        ok: *ok,
                        error: error.clone(),
                    },
                    TerminalWireMsg::List => TermControlPayload::List,
                    TerminalWireMsg::ListResp { sessions } => TermControlPayload::ListResp {
                        sessions: sessions.clone(),
                    },
                    TerminalWireMsg::Attach {
                        term_id,
                        cols,
                        rows,
                    } => TermControlPayload::Attach {
                        term_id: *term_id,
                        cols: *cols,
                        rows: *rows,
                    },
                    TerminalWireMsg::Attached {
                        term_id,
                        session,
                        ok,
                        error,
                    } => TermControlPayload::Attached {
                        term_id: *term_id,
                        session: session.clone(),
                        ok: *ok,
                        error: error.clone(),
                    },
                    TerminalWireMsg::Detach { term_id } => {
                        TermControlPayload::Detach { term_id: *term_id }
                    }
                    TerminalWireMsg::Rename { term_id, name } => TermControlPayload::Rename {
                        term_id: *term_id,
                        name: name.clone(),
                    },
                    TerminalWireMsg::Renamed {
                        term_id,
                        name,
                        ok,
                        error,
                    } => TermControlPayload::Renamed {
                        term_id: *term_id,
                        name: name.clone(),
                        ok: *ok,
                        error: error.clone(),
                    },
                    TerminalWireMsg::Resize {
                        term_id,
                        cols,
                        rows,
                    } => TermControlPayload::Resize {
                        term_id: *term_id,
                        cols: *cols,
                        rows: *rows,
                    },
                    TerminalWireMsg::Close { term_id } => {
                        TermControlPayload::Close { term_id: *term_id }
                    }
                    TerminalWireMsg::Exited { term_id, code } => TermControlPayload::Exited {
                        term_id: *term_id,
                        code: *code,
                    },
                    TerminalWireMsg::Input { .. } | TerminalWireMsg::Output { .. } => {
                        unreachable!()
                    }
                };
                encode_control_frame(&ctrl)
            }
        }
    }

    /// 严格校验并解码二进制线帧。
    pub fn decode(frame: &[u8]) -> Result<Self, String> {
        if frame.len() < FRAME_PREFIX_LEN {
            return Err("terminal wire frame too short".to_string());
        }
        if frame.len() > MAX_TERMINAL_WIRE_FRAME_BYTES {
            return Err(format!(
                "terminal wire frame exceeds {} bytes limit ({} bytes)",
                MAX_TERMINAL_WIRE_FRAME_BYTES,
                frame.len()
            ));
        }

        let kind = frame[0];
        let hdr_len = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        let hdr_end = FRAME_PREFIX_LEN
            .checked_add(hdr_len)
            .ok_or_else(|| "terminal wire header length overflow".to_string())?;
        if hdr_end > frame.len() {
            return Err("terminal wire header length out of bounds".to_string());
        }

        let hdr_bytes = &frame[FRAME_PREFIX_LEN..hdr_end];
        let raw_bytes = &frame[hdr_end..];

        match kind {
            FRAME_KIND_CONTROL => {
                if !raw_bytes.is_empty() {
                    return Err(
                        "terminal control frame must not contain trailing bytes".to_string()
                    );
                }
                let ctrl: TermControlPayload = serde_json::from_slice(hdr_bytes)
                    .map_err(|e| format!("invalid terminal control json: {e}"))?;
                Ok(match ctrl {
                    TermControlPayload::Open {
                        term_id,
                        cols,
                        rows,
                        name,
                        attach,
                    } => TerminalWireMsg::Open {
                        term_id,
                        cols,
                        rows,
                        name,
                        attach,
                    },
                    TermControlPayload::Opened {
                        term_id,
                        name,
                        created_at_unix_sec,
                        title,
                        cwd,
                        attached,
                        ok,
                        error,
                    } => TerminalWireMsg::Opened {
                        term_id,
                        name,
                        created_at_unix_sec,
                        title,
                        cwd,
                        attached,
                        ok,
                        error,
                    },
                    TermControlPayload::List => TerminalWireMsg::List,
                    TermControlPayload::ListResp { sessions } => {
                        TerminalWireMsg::ListResp { sessions }
                    }
                    TermControlPayload::Attach {
                        term_id,
                        cols,
                        rows,
                    } => TerminalWireMsg::Attach {
                        term_id,
                        cols,
                        rows,
                    },
                    TermControlPayload::Attached {
                        term_id,
                        session,
                        ok,
                        error,
                    } => TerminalWireMsg::Attached {
                        term_id,
                        session,
                        ok,
                        error,
                    },
                    TermControlPayload::Detach { term_id } => TerminalWireMsg::Detach { term_id },
                    TermControlPayload::Rename { term_id, name } => {
                        TerminalWireMsg::Rename { term_id, name }
                    }
                    TermControlPayload::Renamed {
                        term_id,
                        name,
                        ok,
                        error,
                    } => TerminalWireMsg::Renamed {
                        term_id,
                        name,
                        ok,
                        error,
                    },
                    TermControlPayload::Resize {
                        term_id,
                        cols,
                        rows,
                    } => TerminalWireMsg::Resize {
                        term_id,
                        cols,
                        rows,
                    },
                    TermControlPayload::Close { term_id } => TerminalWireMsg::Close { term_id },
                    TermControlPayload::Exited { term_id, code } => {
                        TerminalWireMsg::Exited { term_id, code }
                    }
                })
            }
            FRAME_KIND_INPUT => {
                let hdr: TermDataHeader = serde_json::from_slice(hdr_bytes)
                    .map_err(|e| format!("invalid terminal input header: {e}"))?;
                Ok(TerminalWireMsg::Input {
                    term_id: hdr.term_id,
                    data: raw_bytes.to_vec(),
                })
            }
            FRAME_KIND_OUTPUT => {
                let hdr: TermDataHeader = serde_json::from_slice(hdr_bytes)
                    .map_err(|e| format!("invalid terminal output header: {e}"))?;
                Ok(TerminalWireMsg::Output {
                    term_id: hdr.term_id,
                    data: raw_bytes.to_vec(),
                })
            }
            _ => Err(format!("unknown terminal wire frame kind: {kind}")),
        }
    }
}

fn encode_control_frame(ctrl: &TermControlPayload) -> Result<Vec<u8>, String> {
    let header = serde_json::to_vec(ctrl).map_err(|e| format!("serialize control failed: {e}"))?;
    let total = FRAME_PREFIX_LEN + header.len();
    if total > MAX_TERMINAL_WIRE_FRAME_BYTES {
        return Err(format!(
            "terminal control frame too large ({total} > {MAX_TERMINAL_WIRE_FRAME_BYTES})"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.push(FRAME_KIND_CONTROL);
    out.extend_from_slice(&(header.len() as u32).to_le_bytes());
    out.extend_from_slice(&header);
    Ok(out)
}

fn encode_data_frame(kind: u8, term_id: u32, data: &[u8]) -> Result<Vec<u8>, String> {
    let header = serde_json::to_vec(&TermDataHeader { term_id })
        .map_err(|e| format!("serialize data header failed: {e}"))?;
    let total = FRAME_PREFIX_LEN + header.len() + data.len();
    if total > MAX_TERMINAL_WIRE_FRAME_BYTES {
        return Err(format!(
            "terminal data frame too large ({total} > {MAX_TERMINAL_WIRE_FRAME_BYTES})"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.push(kind);
    out.extend_from_slice(&(header.len() as u32).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    Ok(out)
}

/// 终端客户端面向 UI 产出的事件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TerminalEvent {
    /// 远端当前活跃终端会话列表。
    SessionList {
        /// 活跃终端会话快照（按创建顺序排序）。
        sessions: Vec<TerminalSessionInfo>,
    },
    /// 远端终端会话打开结果。
    Opened {
        /// 终端会话 ID。
        #[serde(rename = "termId")]
        term_id: u32,
        /// 会话名称。
        name: String,
        /// 创建时间（Unix 秒）。
        #[serde(rename = "createdAtUnixSec")]
        created_at_unix_sec: u64,
        /// Shell 名称标题。
        title: String,
        /// 初始工作目录。
        cwd: String,
        /// 是否处于附着状态。
        attached: bool,
        /// 是否打开成功。
        ok: bool,
        /// 错误详情（失败时填充）。
        error: Option<String>,
    },
    /// 远端终端附着结果。
    Attached {
        /// 终端会话 ID。
        #[serde(rename = "termId")]
        term_id: u32,
        /// 成功时附带会话元数据。
        session: Option<TerminalSessionInfo>,
        /// 是否附着成功。
        ok: bool,
        /// 错误详情（失败时填充）。
        error: Option<String>,
    },
    /// 远端终端重命名结果。
    Renamed {
        /// 终端会话 ID。
        #[serde(rename = "termId")]
        term_id: u32,
        /// 生效后的会话名称。
        name: String,
        /// 是否重命名成功。
        ok: bool,
        /// 错误详情（失败时填充）。
        error: Option<String>,
    },
    /// 远端终端新到达的输出内容。
    Output {
        /// 终端会话 ID。
        #[serde(rename = "termId")]
        term_id: u32,
        /// 宽松 UTF-8 解码后的文本（适合轻量 UI 渲染）。
        #[serde(rename = "textUtf8Lossy")]
        text_utf8_lossy: String,
        /// 原始输出字节（适合完整 VT100/xterm 终端模拟器）。
        bytes: Vec<u8>,
    },
    /// 远端终端进程已退出。
    Exited {
        /// 终端会话 ID。
        #[serde(rename = "termId")]
        term_id: u32,
        /// 进程退出码。
        code: i32,
    },
}

#[cfg(any(unix, test))]
fn append_scrollback(scrollback: &mut VecDeque<u8>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mut trimmed = false;
    if data.len() >= MAX_TERMINAL_SCROLLBACK_BYTES {
        scrollback.clear();
        let start = data.len() - MAX_TERMINAL_SCROLLBACK_BYTES;
        scrollback.extend(&data[start..]);
        trimmed = true;
    } else {
        scrollback.extend(data);
        while scrollback.len() > MAX_TERMINAL_SCROLLBACK_BYTES {
            scrollback.pop_front();
            trimmed = true;
        }
    }
    if trimmed {
        // 截断后优先对齐到最近换行符，避免从半行甚至半个 UTF-8 字符中间开始回放。
        let newline_pos = scrollback.iter().take(256).position(|&b| b == b'\n');
        if let Some(idx) = newline_pos {
            for _ in 0..=idx {
                scrollback.pop_front();
            }
        } else {
            let mut skipped = 0usize;
            while skipped < 4 {
                match scrollback.front().copied() {
                    Some(b) if (b & 0xC0) == 0x80 => {
                        scrollback.pop_front();
                        skipped += 1;
                    }
                    _ => break,
                }
            }
        }
    }
}

#[cfg(unix)]
struct HostPtySession {
    pty: PtyProcess,
    name: String,
    title: String,
    cwd: String,
    created_at_unix_sec: u64,
    cols: u16,
    rows: u16,
    attached: bool,
    scrollback: VecDeque<u8>,
    pending_exit: Option<(i32, Instant)>,
}

#[cfg(unix)]
impl HostPtySession {
    fn info(&self, term_id: u32) -> TerminalSessionInfo {
        TerminalSessionInfo {
            term_id,
            name: self.name.clone(),
            title: self.title.clone(),
            cwd: self.cwd.clone(),
            created_at_unix_sec: self.created_at_unix_sec,
            cols: self.cols,
            rows: self.rows,
            attached: self.attached,
        }
    }
}

#[cfg(unix)]
fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 被控端（Host）远程终端引擎，最多同时托管 [`MAX_CONCURRENT_TERMINALS`]（8）个真实 PTY。
///
/// 支持后台保活运行、断线脱离与重附着回放（每会话 [`MAX_TERMINAL_SCROLLBACK_BYTES`] 有界滚动缓冲）；
/// 析构时自动终止并回收所有存活的子 Shell 进程。
pub struct TerminalHostEngine {
    outgoing: VecDeque<Vec<u8>>,
    deferred_ctrl: VecDeque<Vec<u8>>,
    #[cfg(unix)]
    next_term_id: u32,
    #[cfg(unix)]
    next_session_seq: u32,
    #[cfg(unix)]
    sessions: BTreeMap<u32, HostPtySession>,
    #[cfg(not(unix))]
    sessions: BTreeMap<u32, ()>,
}

impl Default for TerminalHostEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalHostEngine {
    /// 创建新的被控端远程终端引擎。
    pub fn new() -> Self {
        Self {
            outgoing: VecDeque::new(),
            deferred_ctrl: VecDeque::new(),
            #[cfg(unix)]
            next_term_id: 1,
            #[cfg(unix)]
            next_session_seq: 1,
            sessions: BTreeMap::new(),
        }
    }

    /// 返回当前活跃的 PTY 会话数。
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// 列出当前全部活跃 PTY 会话元数据（按创建时间与 `term_id` 升序）。
    pub fn list_sessions(&self) -> Vec<TerminalSessionInfo> {
        #[cfg(unix)]
        {
            let mut list: Vec<TerminalSessionInfo> = self
                .sessions
                .iter()
                .map(|(&term_id, sess)| sess.info(term_id))
                .collect();
            list.sort_by_key(|s| (s.created_at_unix_sec, s.term_id));
            list
        }
        #[cfg(not(unix))]
        {
            Vec::new()
        }
    }

    /// 在无控制端附着期间持续排空后台 PTY 输出到滚动缓冲并回收已退出进程，避免子进程阻塞在写管道上。
    /// 已处于 `attached` 状态的会话由 [`Self::poll_outgoing`] 独占消费实时输出与退出通知，避免偷走实时数据。
    pub fn poll_background(&mut self) {
        #[cfg(unix)]
        {
            let mut exited_ids: Vec<u32> = Vec::new();
            for (&term_id, sess) in &mut self.sessions {
                if sess.attached {
                    continue;
                }
                let bytes = sess.pty.try_read_output_up_to(BACKGROUND_DRAIN_CHUNK_BYTES);
                if !bytes.is_empty() {
                    append_scrollback(&mut sess.scrollback, &bytes);
                }

                if sess.pending_exit.is_none() {
                    if let Some(code) = sess.pty.try_wait() {
                        sess.pending_exit = Some((code, Instant::now()));
                    }
                }

                if let Some((_code, detected_at)) = sess.pending_exit {
                    if sess.pty.is_reader_eof() || detected_at.elapsed() >= EXIT_DRAIN_GRACE {
                        let tail = sess.pty.try_read_output_up_to(BACKGROUND_DRAIN_CHUNK_BYTES);
                        if !tail.is_empty() {
                            append_scrollback(&mut sess.scrollback, &tail);
                        }
                        exited_ids.push(term_id);
                    }
                }
            }
            for term_id in exited_ids {
                self.sessions.remove(&term_id);
            }
            if self.sessions.is_empty() {
                self.next_session_seq = 1;
            }
        }
    }

    /// 脱离所有当前附着的前端视图并清空待发下行队列，同时保持所有后台 PTY 持续运行。
    pub fn detach_all(&mut self) {
        #[cfg(unix)]
        for sess in self.sessions.values_mut() {
            sess.attached = false;
        }
        self.outgoing.clear();
        self.deferred_ctrl.clear();
    }

    fn enqueue(&mut self, msg: &TerminalWireMsg) {
        if self.outgoing.len() >= MAX_TERMINAL_OUTGOING_FRAMES {
            return;
        }
        if let Ok(frame) = msg.encode() {
            self.outgoing.push_back(frame);
        }
    }

    fn flush_deferred_ctrl(&mut self) {
        while self.outgoing.len() < MAX_TERMINAL_OUTGOING_FRAMES {
            let Some(frame) = self.deferred_ctrl.pop_front() else {
                break;
            };
            self.outgoing.push_back(frame);
        }
    }

    fn enqueue_reliable_ctrl(&mut self, msg: &TerminalWireMsg) {
        self.flush_deferred_ctrl();
        if let Ok(frame) = msg.encode() {
            if self.outgoing.len() < MAX_TERMINAL_OUTGOING_FRAMES {
                self.outgoing.push_back(frame);
            } else if self.deferred_ctrl.len() < MAX_DEFERRED_CTRL_FRAMES {
                self.deferred_ctrl.push_back(frame);
            }
        }
    }

    #[cfg(unix)]
    fn allocate_term_id(&mut self, requested: u32) -> u32 {
        if requested != 0 && !self.sessions.contains_key(&requested) {
            self.next_term_id = self.next_term_id.max(requested.saturating_add(1)).max(1);
            return requested;
        }
        let mut candidate = self.next_term_id.max(1);
        while self.sessions.contains_key(&candidate) {
            candidate = candidate.checked_add(1).unwrap_or(1);
        }
        self.next_term_id = candidate.saturating_add(1).max(1);
        candidate
    }

    #[cfg(unix)]
    fn allocate_session_name(&mut self, requested: Option<String>) -> Result<String, String> {
        if let Some(raw) = requested {
            if !raw.trim().is_empty() {
                return validate_terminal_name(&raw);
            }
        }
        if self.sessions.is_empty() {
            self.next_session_seq = 1;
        }
        loop {
            let seq = self.next_session_seq.max(1);
            self.next_session_seq = seq.saturating_add(1).max(1);
            let candidate = format!("session{seq}");
            if !self.sessions.values().any(|s| s.name == candidate) {
                return Ok(candidate);
            }
        }
    }

    /// 处理一条来自控制端的二进制线帧。
    pub fn handle_incoming(&mut self, frame: &[u8]) {
        let msg = match TerminalWireMsg::decode(frame) {
            Ok(m) => m,
            Err(_) => return,
        };

        match msg {
            TerminalWireMsg::Open {
                term_id,
                cols,
                rows,
                name,
                attach,
            } => {
                self.handle_open(term_id, cols, rows, name, attach);
            }
            TerminalWireMsg::List => {
                self.handle_list();
            }
            TerminalWireMsg::Attach {
                term_id,
                cols,
                rows,
            } => {
                self.handle_attach(term_id, cols, rows);
            }
            TerminalWireMsg::Detach { term_id } => {
                #[cfg(unix)]
                if let Some(sess) = self.sessions.get_mut(&term_id) {
                    sess.attached = false;
                }
                #[cfg(not(unix))]
                {
                    let _ = term_id;
                }
            }
            TerminalWireMsg::Rename { term_id, name } => {
                self.handle_rename(term_id, &name);
            }
            TerminalWireMsg::Input { term_id, data } => {
                #[cfg(unix)]
                {
                    let mut fatal_exit: Option<(Option<Vec<u8>>, i32, bool)> = None;
                    if let Some(sess) = self.sessions.get_mut(&term_id) {
                        if let Err(err) = sess.pty.write_input(&data) {
                            // 仅在底层 PTY 写入出现致命 I/O 错误（非临时缓冲满反压）时回收会话。
                            if !err.contains("pending write buffer full") {
                                let code = sess.pty.try_wait().unwrap_or(-1);
                                // 预先为 Exited 帧保留 1 个队列槽位；队列已满时暂存 pending_exit 待 poll_outgoing 回收，绝不静默丢失 Exited。
                                if self.outgoing.len() >= MAX_TERMINAL_OUTGOING_FRAMES {
                                    if sess.pending_exit.is_none() {
                                        sess.pending_exit = Some((code, Instant::now()));
                                    }
                                } else {
                                    let tail_slots = MAX_TERMINAL_OUTGOING_FRAMES
                                        .saturating_sub(self.outgoing.len())
                                        .saturating_sub(1);
                                    let tail = if sess.attached && tail_slots > 0 {
                                        let bytes = sess.pty.try_read_output_up_to(
                                            tail_slots.saturating_mul(TERMINAL_DATA_CHUNK_SIZE),
                                        );
                                        if bytes.is_empty() {
                                            None
                                        } else {
                                            append_scrollback(&mut sess.scrollback, &bytes);
                                            Some(bytes)
                                        }
                                    } else {
                                        None
                                    };
                                    fatal_exit = Some((tail, code, sess.attached));
                                }
                            }
                        }
                    }
                    if let Some((tail, code, was_attached)) = fatal_exit {
                        if was_attached {
                            if let Some(bytes) = tail {
                                for chunk in bytes.chunks(TERMINAL_DATA_CHUNK_SIZE) {
                                    self.enqueue(&TerminalWireMsg::Output {
                                        term_id,
                                        data: chunk.to_vec(),
                                    });
                                }
                            }
                        }
                        self.sessions.remove(&term_id);
                        if self.sessions.is_empty() {
                            self.next_session_seq = 1;
                        }
                        self.enqueue(&TerminalWireMsg::Exited { term_id, code });
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = (term_id, data);
                }
            }
            TerminalWireMsg::Resize {
                term_id,
                cols,
                rows,
            } => {
                #[cfg(unix)]
                if let Some(sess) = self.sessions.get_mut(&term_id) {
                    if cols > 0 && rows > 0 && cols <= 512 && rows <= 512 {
                        sess.cols = cols;
                        sess.rows = rows;
                        let _ = sess.pty.resize(cols, rows);
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = (term_id, cols, rows);
                }
            }
            TerminalWireMsg::Close { term_id } => {
                if self.sessions.remove(&term_id).is_some() {
                    #[cfg(unix)]
                    if self.sessions.is_empty() {
                        self.next_session_seq = 1;
                    }
                    self.enqueue_reliable_ctrl(&TerminalWireMsg::Exited { term_id, code: 0 });
                }
            }
            // Host 忽略控制端专用下行帧。
            TerminalWireMsg::Opened { .. }
            | TerminalWireMsg::ListResp { .. }
            | TerminalWireMsg::Attached { .. }
            | TerminalWireMsg::Renamed { .. }
            | TerminalWireMsg::Output { .. }
            | TerminalWireMsg::Exited { .. } => {}
        }
    }

    fn handle_list(&mut self) {
        self.poll_background();
        let sessions = self.list_sessions();
        self.enqueue(&TerminalWireMsg::ListResp { sessions });
    }

    fn handle_attach(&mut self, term_id: u32, cols: u16, rows: u16) {
        #[cfg(unix)]
        {
            let mut dead_exit: Option<i32> = None;
            let mut replay_chunks: Vec<Vec<u8>> = Vec::new();
            let mut attached_info: Option<TerminalSessionInfo> = None;

            if let Some(sess) = self.sessions.get_mut(&term_id) {
                let fresh = sess.pty.try_read_output_up_to(BACKGROUND_DRAIN_CHUNK_BYTES);
                if !fresh.is_empty() {
                    append_scrollback(&mut sess.scrollback, &fresh);
                }
                if sess.pending_exit.is_none() {
                    if let Some(code) = sess.pty.try_wait() {
                        sess.pending_exit = Some((code, Instant::now()));
                    }
                }
                if let Some((code, detected_at)) = sess.pending_exit {
                    if sess.pty.is_reader_eof() || detected_at.elapsed() >= EXIT_DRAIN_GRACE {
                        dead_exit = Some(code);
                    }
                }

                if dead_exit.is_none() {
                    if self.outgoing.len() >= MAX_TERMINAL_OUTGOING_FRAMES {
                        // 出站队列已满：暂不修改 `sess.attached`，避免主机与控制端附着状态失步。
                        return;
                    }
                    if cols > 0 && rows > 0 && cols <= 512 && rows <= 512 {
                        sess.cols = cols;
                        sess.rows = rows;
                        let _ = sess.pty.resize(cols, rows);
                    }
                    sess.attached = true;
                    attached_info = Some(sess.info(term_id));
                    let buf: Vec<u8> = sess.scrollback.iter().copied().collect();
                    for chunk in buf.chunks(TERMINAL_DATA_CHUNK_SIZE) {
                        replay_chunks.push(chunk.to_vec());
                    }
                }
            } else {
                self.enqueue_reliable_ctrl(&TerminalWireMsg::Attached {
                    term_id,
                    session: None,
                    ok: false,
                    error: Some("终端会话不存在或已终止".to_string()),
                });
                return;
            }

            if let Some(code) = dead_exit {
                // 队列需同时容纳 Exited + Attached（或至少进入 deferred_ctrl），双满载时交由 poll_outgoing 回收。
                if self.outgoing.len() >= MAX_TERMINAL_OUTGOING_FRAMES
                    && self.deferred_ctrl.len() + 2 > MAX_DEFERRED_CTRL_FRAMES
                {
                    return;
                }
                self.sessions.remove(&term_id);
                if self.sessions.is_empty() {
                    self.next_session_seq = 1;
                }
                self.enqueue_reliable_ctrl(&TerminalWireMsg::Exited { term_id, code });
                self.enqueue_reliable_ctrl(&TerminalWireMsg::Attached {
                    term_id,
                    session: None,
                    ok: false,
                    error: Some("终端进程已退出".to_string()),
                });
                return;
            }

            self.enqueue(&TerminalWireMsg::Attached {
                term_id,
                session: attached_info,
                ok: true,
                error: None,
            });
            // 若受限槽位不足以回放完整历史，优先保留最新末尾输出块，避免丢失最近上下文。
            let avail_replay = MAX_TERMINAL_OUTGOING_FRAMES.saturating_sub(self.outgoing.len());
            let skip = replay_chunks.len().saturating_sub(avail_replay);
            for chunk in replay_chunks.into_iter().skip(skip) {
                self.enqueue(&TerminalWireMsg::Output {
                    term_id,
                    data: chunk,
                });
            }
        }

        #[cfg(not(unix))]
        {
            let _ = (cols, rows);
            self.enqueue_reliable_ctrl(&TerminalWireMsg::Attached {
                term_id,
                session: None,
                ok: false,
                error: Some("PTY is not supported on this platform".to_string()),
            });
        }
    }

    fn handle_rename(&mut self, term_id: u32, raw_name: &str) {
        let valid_name = match validate_terminal_name(raw_name) {
            Ok(n) => n,
            Err(err) => {
                self.enqueue_reliable_ctrl(&TerminalWireMsg::Renamed {
                    term_id,
                    name: String::new(),
                    ok: false,
                    error: Some(err),
                });
                return;
            }
        };
        #[cfg(unix)]
        {
            if let Some(sess) = self.sessions.get_mut(&term_id) {
                sess.name = valid_name.clone();
                self.enqueue_reliable_ctrl(&TerminalWireMsg::Renamed {
                    term_id,
                    name: valid_name,
                    ok: true,
                    error: None,
                });
            } else {
                self.enqueue_reliable_ctrl(&TerminalWireMsg::Renamed {
                    term_id,
                    name: String::new(),
                    ok: false,
                    error: Some("终端会话不存在或已终止".to_string()),
                });
            }
        }
        #[cfg(not(unix))]
        {
            let _ = valid_name;
            self.enqueue_reliable_ctrl(&TerminalWireMsg::Renamed {
                term_id,
                name: String::new(),
                ok: false,
                error: Some("PTY is not supported on this platform".to_string()),
            });
        }
    }

    fn handle_open(
        &mut self,
        term_id: u32,
        cols: u16,
        rows: u16,
        name: Option<String>,
        attach: bool,
    ) {
        if self.outgoing.len() >= MAX_TERMINAL_OUTGOING_FRAMES
            && self.deferred_ctrl.len() >= MAX_DEFERRED_CTRL_FRAMES
        {
            return;
        }
        if self.sessions.len() >= MAX_CONCURRENT_TERMINALS {
            self.enqueue_reliable_ctrl(&TerminalWireMsg::Opened {
                term_id,
                name: String::new(),
                created_at_unix_sec: 0,
                title: String::new(),
                cwd: String::new(),
                attached: false,
                ok: false,
                error: Some(format!(
                    "maximum concurrent terminals ({MAX_CONCURRENT_TERMINALS}) reached"
                )),
            });
            return;
        }

        #[cfg(unix)]
        {
            let assigned_name = match self.allocate_session_name(name) {
                Ok(n) => n,
                Err(err) => {
                    self.enqueue_reliable_ctrl(&TerminalWireMsg::Opened {
                        term_id,
                        name: String::new(),
                        created_at_unix_sec: 0,
                        title: String::new(),
                        cwd: String::new(),
                        attached: false,
                        ok: false,
                        error: Some(err),
                    });
                    return;
                }
            };
            let actual_id = self.allocate_term_id(term_id);
            let safe_cols = cols.clamp(1, 512);
            let safe_rows = rows.clamp(1, 512);
            match PtyProcess::spawn(safe_cols, safe_rows) {
                Ok(pty) => {
                    let title = pty.title().to_string();
                    let cwd = pty.cwd().to_string();
                    let created_at_unix_sec = current_unix_secs();
                    self.sessions.insert(
                        actual_id,
                        HostPtySession {
                            pty,
                            name: assigned_name.clone(),
                            title: title.clone(),
                            cwd: cwd.clone(),
                            created_at_unix_sec,
                            cols: safe_cols,
                            rows: safe_rows,
                            attached: attach,
                            scrollback: VecDeque::new(),
                            pending_exit: None,
                        },
                    );
                    self.enqueue_reliable_ctrl(&TerminalWireMsg::Opened {
                        term_id: actual_id,
                        name: assigned_name,
                        created_at_unix_sec,
                        title,
                        cwd,
                        attached: attach,
                        ok: true,
                        error: None,
                    });
                }
                Err(err) => {
                    self.enqueue_reliable_ctrl(&TerminalWireMsg::Opened {
                        term_id: actual_id,
                        name: String::new(),
                        created_at_unix_sec: 0,
                        title: String::new(),
                        cwd: String::new(),
                        attached: false,
                        ok: false,
                        error: Some(err),
                    });
                }
            }
        }

        #[cfg(not(unix))]
        {
            let _ = (cols, rows, name, attach);
            self.enqueue_reliable_ctrl(&TerminalWireMsg::Opened {
                term_id,
                name: String::new(),
                created_at_unix_sec: 0,
                title: String::new(),
                cwd: String::new(),
                attached: false,
                ok: false,
                error: Some("PTY is not supported on this platform".to_string()),
            });
        }
    }

    /// 轮询所有活跃 PTY 的输出与退出事件，并最多返回 `max_frames` 个待发线帧。
    pub fn poll_outgoing(&mut self, max_frames: usize) -> Vec<Vec<u8>> {
        if max_frames == 0 {
            return Vec::new();
        }
        self.flush_deferred_ctrl();

        #[cfg(unix)]
        {
            let mut exited_ids: Vec<(u32, i32)> = Vec::new();
            let mut pending_outputs: Vec<(u32, Vec<u8>)> = Vec::new();
            let mut queued_frames = self.outgoing.len();

            for (&term_id, sess) in &mut self.sessions {
                if sess.attached {
                    if queued_frames < MAX_TERMINAL_OUTGOING_FRAMES {
                        let remaining_slots = MAX_TERMINAL_OUTGOING_FRAMES - queued_frames;
                        let bytes = sess.pty.try_read_output_up_to(
                            remaining_slots.saturating_mul(TERMINAL_DATA_CHUNK_SIZE),
                        );
                        if !bytes.is_empty() {
                            append_scrollback(&mut sess.scrollback, &bytes);
                            let chunks = bytes.len().div_ceil(TERMINAL_DATA_CHUNK_SIZE);
                            queued_frames = queued_frames.saturating_add(chunks);
                            pending_outputs.push((term_id, bytes));
                        }
                    }
                } else {
                    let bytes = sess.pty.try_read_output_up_to(BACKGROUND_DRAIN_CHUNK_BYTES);
                    if !bytes.is_empty() {
                        append_scrollback(&mut sess.scrollback, &bytes);
                    }
                }

                if sess.pending_exit.is_none() {
                    if let Some(code) = sess.pty.try_wait() {
                        sess.pending_exit = Some((code, Instant::now()));
                    }
                }

                if let Some((code, detected_at)) = sess.pending_exit {
                    if (sess.pty.is_reader_eof() || detected_at.elapsed() >= EXIT_DRAIN_GRACE)
                        && queued_frames < MAX_TERMINAL_OUTGOING_FRAMES
                    {
                        // 预先为 Exited 帧保留 1 个队列槽位，确保总待发帧数绝不超过 MAX_TERMINAL_OUTGOING_FRAMES。
                        let max_tail_slots = MAX_TERMINAL_OUTGOING_FRAMES - queued_frames - 1;
                        if sess.attached {
                            if max_tail_slots > 0 {
                                let tail = sess.pty.try_read_output_up_to(
                                    max_tail_slots.saturating_mul(TERMINAL_DATA_CHUNK_SIZE),
                                );
                                if !tail.is_empty() {
                                    append_scrollback(&mut sess.scrollback, &tail);
                                    let chunks = tail.len().div_ceil(TERMINAL_DATA_CHUNK_SIZE);
                                    queued_frames = queued_frames.saturating_add(chunks);
                                    pending_outputs.push((term_id, tail));
                                }
                            }
                        } else {
                            let tail = sess.pty.try_read_output_up_to(BACKGROUND_DRAIN_CHUNK_BYTES);
                            if !tail.is_empty() {
                                append_scrollback(&mut sess.scrollback, &tail);
                            }
                        }
                        queued_frames = queued_frames.saturating_add(1);
                        exited_ids.push((term_id, code));
                    }
                }
            }

            for (term_id, bytes) in pending_outputs {
                for chunk in bytes.chunks(TERMINAL_DATA_CHUNK_SIZE) {
                    self.enqueue(&TerminalWireMsg::Output {
                        term_id,
                        data: chunk.to_vec(),
                    });
                }
            }

            for (term_id, code) in exited_ids {
                self.sessions.remove(&term_id);
                if self.sessions.is_empty() {
                    self.next_session_seq = 1;
                }
                self.enqueue(&TerminalWireMsg::Exited { term_id, code });
            }
        }

        let mut out =
            Vec::with_capacity(max_frames.min(self.outgoing.len() + self.deferred_ctrl.len()));
        while out.len() < max_frames {
            self.flush_deferred_ctrl();
            let Some(frame) = self.outgoing.pop_front() else {
                break;
            };
            out.push(frame);
        }
        self.flush_deferred_ctrl();
        out
    }
}

impl Drop for TerminalHostEngine {
    fn drop(&mut self) {
        self.sessions.clear();
    }
}

fn decode_utf8_streaming(carry: &mut Vec<u8>, chunk: &[u8]) -> String {
    if carry.is_empty() && chunk.is_empty() {
        return String::new();
    }
    let combined;
    let mut slice: &[u8] = if carry.is_empty() {
        chunk
    } else {
        combined = {
            let mut buf = Vec::with_capacity(carry.len() + chunk.len());
            buf.extend_from_slice(carry);
            buf.extend_from_slice(chunk);
            buf
        };
        carry.clear();
        &combined
    };

    let mut out = String::new();
    while !slice.is_empty() {
        match std::str::from_utf8(slice) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(err) => {
                let valid_up_to = err.valid_up_to();
                if valid_up_to > 0 {
                    if let Ok(valid) = std::str::from_utf8(&slice[..valid_up_to]) {
                        out.push_str(valid);
                    }
                }
                let rest = &slice[valid_up_to..];
                match err.error_len() {
                    Some(invalid_len) => {
                        out.push('\u{FFFD}');
                        slice = &rest[invalid_len..];
                    }
                    None => {
                        // 末尾 1..=3 字节为合法多字节 UTF-8 前缀，暂存至下一帧继续解码。
                        debug_assert!(rest.len() <= 3);
                        carry.extend_from_slice(rest);
                        break;
                    }
                }
            }
        }
    }
    out
}

/// 控制端（Client）远程终端引擎。
pub struct TerminalClientEngine {
    next_term_id: u32,
    outgoing: VecDeque<Vec<u8>>,
    utf8_carry: HashMap<u32, Vec<u8>>,
}

impl Default for TerminalClientEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalClientEngine {
    /// 创建新的控制端远程终端引擎。
    pub fn new() -> Self {
        Self {
            next_term_id: 1,
            outgoing: VecDeque::new(),
            utf8_carry: HashMap::new(),
        }
    }

    fn enqueue(&mut self, msg: &TerminalWireMsg) {
        if self.outgoing.len() >= MAX_TERMINAL_OUTGOING_FRAMES {
            return;
        }
        if let Ok(frame) = msg.encode() {
            self.outgoing.push_back(frame);
        }
    }

    /// 返回出站控制/输入队列当前剩余的可用槽位数。
    pub fn available_outgoing_slots(&self) -> usize {
        MAX_TERMINAL_OUTGOING_FRAMES.saturating_sub(self.outgoing.len())
    }

    /// 返回出站控制/输入队列当前是否仍有空位（未达到 [`MAX_TERMINAL_OUTGOING_FRAMES`] 上限）。
    pub fn can_enqueue(&self) -> bool {
        self.available_outgoing_slots() > 0
    }

    /// 请求打开一个新的远程终端会话，返回分配的 `term_id`。
    pub fn open(&mut self, cols: u16, rows: u16) -> u32 {
        self.open_with_options(cols, rows, None, true)
    }

    /// 按指定名称与附着模式打开一个新的远程终端会话，返回本地预分配的 `term_id`。
    pub fn open_with_options(
        &mut self,
        cols: u16,
        rows: u16,
        name: Option<String>,
        attach: bool,
    ) -> u32 {
        let term_id = self.next_term_id;
        self.next_term_id = self.next_term_id.saturating_add(1).max(1);
        self.enqueue(&TerminalWireMsg::Open {
            term_id,
            cols: cols.clamp(1, 512),
            rows: rows.clamp(1, 512),
            name,
            attach,
        });
        term_id
    }

    /// 请求在主机后台创建并保持一个不立即附着输出的终端会话（由主机分配权威 `term_id`）。
    pub fn open_background(&mut self, cols: u16, rows: u16, name: Option<String>) {
        self.enqueue(&TerminalWireMsg::Open {
            term_id: 0,
            cols: cols.clamp(1, 512),
            rows: rows.clamp(1, 512),
            name,
            attach: false,
        });
    }

    /// 请求主机返回当前活跃的后台终端会话列表。
    pub fn list(&mut self) {
        self.enqueue(&TerminalWireMsg::List);
    }

    /// 请求附着至指定后台终端（回放滚动缓冲并恢复实时输出）。
    pub fn attach(&mut self, term_id: u32, cols: u16, rows: u16) {
        self.utf8_carry.remove(&term_id);
        self.enqueue(&TerminalWireMsg::Attach {
            term_id,
            cols: cols.clamp(1, 512),
            rows: rows.clamp(1, 512),
        });
    }

    /// 请求脱离指定终端视图（仅停止实时输出流，保留后台 PTY 继续运行）。
    pub fn detach(&mut self, term_id: u32) {
        self.utf8_carry.remove(&term_id);
        self.enqueue(&TerminalWireMsg::Detach { term_id });
    }

    /// 请求重命名指定终端会话。
    pub fn rename(&mut self, term_id: u32, name: String) {
        self.enqueue(&TerminalWireMsg::Rename { term_id, name });
    }

    /// 向指定远程终端发送输入字节（超长输入自动按 32 KiB 切片）。
    pub fn send_input(&mut self, term_id: u32, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        for chunk in data.chunks(TERMINAL_DATA_CHUNK_SIZE) {
            self.enqueue(&TerminalWireMsg::Input {
                term_id,
                data: chunk.to_vec(),
            });
        }
    }

    /// 调整指定远程终端窗口尺寸。
    pub fn resize(&mut self, term_id: u32, cols: u16, rows: u16) {
        self.enqueue(&TerminalWireMsg::Resize {
            term_id,
            cols: cols.clamp(1, 512),
            rows: rows.clamp(1, 512),
        });
    }

    /// 关闭并终止指定远程终端会话。
    pub fn close(&mut self, term_id: u32) {
        self.utf8_carry.remove(&term_id);
        self.enqueue(&TerminalWireMsg::Close { term_id });
    }

    /// 处理一条来自被控端的线帧，返回面向 UI 的事件列表。
    pub fn handle_incoming(&mut self, frame: &[u8]) -> Vec<TerminalEvent> {
        let msg = match TerminalWireMsg::decode(frame) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };

        let mut events = Vec::new();
        match msg {
            TerminalWireMsg::ListResp { sessions } => {
                if let Some(max_id) = sessions.iter().map(|s| s.term_id).max() {
                    self.next_term_id = self.next_term_id.max(max_id.saturating_add(1)).max(1);
                }
                events.push(TerminalEvent::SessionList { sessions });
            }
            TerminalWireMsg::Opened {
                term_id,
                name,
                created_at_unix_sec,
                title,
                cwd,
                attached,
                ok,
                error,
            } => {
                if ok {
                    self.next_term_id = self.next_term_id.max(term_id.saturating_add(1)).max(1);
                }
                events.push(TerminalEvent::Opened {
                    term_id,
                    name,
                    created_at_unix_sec,
                    title,
                    cwd,
                    attached,
                    ok,
                    error,
                });
            }
            TerminalWireMsg::Attached {
                term_id,
                session,
                ok,
                error,
            } => {
                if ok {
                    self.utf8_carry.remove(&term_id);
                    self.next_term_id = self.next_term_id.max(term_id.saturating_add(1)).max(1);
                }
                events.push(TerminalEvent::Attached {
                    term_id,
                    session,
                    ok,
                    error,
                });
            }
            TerminalWireMsg::Renamed {
                term_id,
                name,
                ok,
                error,
            } => {
                events.push(TerminalEvent::Renamed {
                    term_id,
                    name,
                    ok,
                    error,
                });
            }
            TerminalWireMsg::Output { term_id, data } => {
                let carry = self.utf8_carry.entry(term_id).or_default();
                let text_utf8_lossy = decode_utf8_streaming(carry, &data);
                if carry.is_empty() {
                    self.utf8_carry.remove(&term_id);
                }
                events.push(TerminalEvent::Output {
                    term_id,
                    text_utf8_lossy,
                    bytes: data,
                });
            }
            TerminalWireMsg::Exited { term_id, code } => {
                self.utf8_carry.remove(&term_id);
                events.push(TerminalEvent::Exited { term_id, code });
            }
            // Client 忽略主机侧专用上行帧。
            TerminalWireMsg::Open { .. }
            | TerminalWireMsg::List
            | TerminalWireMsg::Attach { .. }
            | TerminalWireMsg::Detach { .. }
            | TerminalWireMsg::Rename { .. }
            | TerminalWireMsg::Input { .. }
            | TerminalWireMsg::Resize { .. }
            | TerminalWireMsg::Close { .. } => {}
        }
        events
    }

    /// 最多拉取 `max_frames` 个待发送线帧。
    pub fn poll_outgoing(&mut self, max_frames: usize) -> Vec<Vec<u8>> {
        if max_frames == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(max_frames.min(self.outgoing.len()));
        while out.len() < max_frames {
            let Some(frame) = self.outgoing.pop_front() else {
                break;
            };
            out.push(frame);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_wire_roundtrip_and_bounds() {
        let info = TerminalSessionInfo {
            term_id: 2,
            name: "build-watch".to_string(),
            title: "zsh".to_string(),
            cwd: "/Users/test".to_string(),
            created_at_unix_sec: 1_763_700_000,
            cols: 120,
            rows: 40,
            attached: true,
        };
        let msgs = [
            TerminalWireMsg::Open {
                term_id: 1,
                cols: 120,
                rows: 40,
                name: Some("session1".to_string()),
                attach: false,
            },
            TerminalWireMsg::Opened {
                term_id: 1,
                name: "session1".to_string(),
                created_at_unix_sec: 1_763_700_000,
                title: "zsh".to_string(),
                cwd: "/tmp".to_string(),
                attached: true,
                ok: true,
                error: None,
            },
            TerminalWireMsg::List,
            TerminalWireMsg::ListResp {
                sessions: vec![info.clone()],
            },
            TerminalWireMsg::Attach {
                term_id: 2,
                cols: 100,
                rows: 30,
            },
            TerminalWireMsg::Attached {
                term_id: 2,
                session: Some(info),
                ok: true,
                error: None,
            },
            TerminalWireMsg::Detach { term_id: 2 },
            TerminalWireMsg::Rename {
                term_id: 2,
                name: "deploy".to_string(),
            },
            TerminalWireMsg::Renamed {
                term_id: 2,
                name: "deploy".to_string(),
                ok: true,
                error: None,
            },
            TerminalWireMsg::Input {
                term_id: 1,
                data: b"ls -la\n".to_vec(),
            },
            TerminalWireMsg::Output {
                term_id: 1,
                data: vec![b'x'; TERMINAL_DATA_CHUNK_SIZE],
            },
            TerminalWireMsg::Resize {
                term_id: 1,
                cols: 80,
                rows: 24,
            },
            TerminalWireMsg::Close { term_id: 1 },
            TerminalWireMsg::Exited {
                term_id: 1,
                code: 0,
            },
        ];
        for m in msgs {
            let encoded = m.encode().unwrap();
            assert!(encoded.len() <= MAX_TERMINAL_WIRE_FRAME_BYTES);
            assert_eq!(TerminalWireMsg::decode(&encoded).unwrap(), m);
        }

        // Legacy Open / Opened payloads without optional fields must still decode cleanly.
        let legacy_open = br#"{"k":"open","term_id":7,"cols":90,"rows":30}"#;
        let mut legacy_frame = Vec::with_capacity(FRAME_PREFIX_LEN + legacy_open.len());
        legacy_frame.push(FRAME_KIND_CONTROL);
        legacy_frame.extend_from_slice(&(legacy_open.len() as u32).to_le_bytes());
        legacy_frame.extend_from_slice(legacy_open);
        assert_eq!(
            TerminalWireMsg::decode(&legacy_frame).unwrap(),
            TerminalWireMsg::Open {
                term_id: 7,
                cols: 90,
                rows: 30,
                name: None,
                attach: true,
            }
        );

        let oversized = vec![0u8; MAX_TERMINAL_WIRE_FRAME_BYTES + 1];
        assert!(TerminalWireMsg::decode(&oversized).is_err());
    }

    #[test]
    fn validate_terminal_name_enforces_bounds_and_control_chars() {
        assert_eq!(validate_terminal_name("  session1  ").unwrap(), "session1");
        assert!(validate_terminal_name("").is_err());
        assert!(validate_terminal_name("   \t ").is_err());
        assert!(validate_terminal_name("bad\nname").is_err());
        assert!(validate_terminal_name("bad\0name").is_err());
        let max_name = "a".repeat(MAX_TERMINAL_NAME_CHARS);
        assert_eq!(validate_terminal_name(&max_name).unwrap(), max_name);
        let too_long = "a".repeat(MAX_TERMINAL_NAME_CHARS + 1);
        assert!(validate_terminal_name(&too_long).is_err());
    }

    #[test]
    fn scrollback_ring_buffer_caps_bytes_and_avoids_split_utf8() {
        let mut buf = VecDeque::new();
        let line = "中文输出行0123456789\n";
        let iterations = (MAX_TERMINAL_SCROLLBACK_BYTES / line.len()) + 200;
        for _ in 0..iterations {
            append_scrollback(&mut buf, line.as_bytes());
        }
        assert!(buf.len() <= MAX_TERMINAL_SCROLLBACK_BYTES);
        let text = std::str::from_utf8(buf.make_contiguous())
            .expect("truncated scrollback must start on valid UTF-8 boundary");
        assert!(text.contains("中文输出行0123456789"));

        // Large single chunk without newlines must skip UTF-8 continuation bytes at front.
        let mut no_nl = VecDeque::new();
        let repeated = "中".repeat(MAX_TERMINAL_SCROLLBACK_BYTES);
        append_scrollback(&mut no_nl, repeated.as_bytes());
        assert!(no_nl.len() <= MAX_TERMINAL_SCROLLBACK_BYTES);
        let decoded = String::from_utf8_lossy(no_nl.make_contiguous());
        assert!(!decoded.starts_with('\u{FFFD}'));
    }

    #[test]
    fn split_multibyte_utf8_across_output_chunks_decodes_without_fffd() {
        let mut client = TerminalClientEngine::new();
        let bytes_cjk = "中".as_bytes(); // [0xE4, 0xB8, 0xAD]
        assert_eq!(bytes_cjk.len(), 3);

        // Split "中" across two chunks: [0xE4, 0xB8] then [0xAD]
        let f1 = TerminalWireMsg::Output {
            term_id: 1,
            data: vec![b'A', bytes_cjk[0], bytes_cjk[1]],
        }
        .encode()
        .unwrap();
        let f2 = TerminalWireMsg::Output {
            term_id: 1,
            data: vec![bytes_cjk[2], b'B'],
        }
        .encode()
        .unwrap();

        let ev1 = client.handle_incoming(&f1);
        let ev2 = client.handle_incoming(&f2);

        let mut acc = String::new();
        for ev in ev1.into_iter().chain(ev2) {
            if let TerminalEvent::Output {
                text_utf8_lossy, ..
            } = ev
            {
                assert!(
                    !text_utf8_lossy.contains('\u{FFFD}'),
                    "unexpected U+FFFD in chunk: {text_utf8_lossy:?}"
                );
                acc.push_str(&text_utf8_lossy);
            }
        }
        assert_eq!(acc, "A中B");
        assert!(!client.utf8_carry.contains_key(&1));

        // 4-byte emoji split byte-by-byte across 4 chunks
        let emoji = "🦀".as_bytes();
        assert_eq!(emoji.len(), 4);
        let mut emoji_acc = String::new();
        for &b in emoji {
            let f = TerminalWireMsg::Output {
                term_id: 2,
                data: vec![b],
            }
            .encode()
            .unwrap();
            for ev in client.handle_incoming(&f) {
                if let TerminalEvent::Output {
                    text_utf8_lossy, ..
                } = ev
                {
                    assert!(!text_utf8_lossy.contains('\u{FFFD}'));
                    emoji_acc.push_str(&text_utf8_lossy);
                }
            }
        }
        assert_eq!(emoji_acc, "🦀");

        // Leftover incomplete prefix cleared on Exited and close
        let half = TerminalWireMsg::Output {
            term_id: 3,
            data: vec![0xE4],
        }
        .encode()
        .unwrap();
        let _ = client.handle_incoming(&half);
        assert_eq!(client.utf8_carry.get(&3).map(Vec::len), Some(1));
        let exited = TerminalWireMsg::Exited {
            term_id: 3,
            code: 0,
        }
        .encode()
        .unwrap();
        let _ = client.handle_incoming(&exited);
        assert!(!client.utf8_carry.contains_key(&3));

        let half2 = TerminalWireMsg::Output {
            term_id: 4,
            data: vec![0xE4, 0xB8],
        }
        .encode()
        .unwrap();
        let _ = client.handle_incoming(&half2);
        assert_eq!(client.utf8_carry.get(&4).map(Vec::len), Some(2));
        client.close(4);
        assert!(!client.utf8_carry.contains_key(&4));
    }

    #[cfg(unix)]
    #[test]
    fn host_outgoing_queue_is_capped_at_max_terminal_outgoing_frames() {
        let mut host = TerminalHostEngine::new();
        let open = TerminalWireMsg::Open {
            term_id: 1,
            cols: 80,
            rows: 24,
            name: None,
            attach: true,
        }
        .encode()
        .unwrap();
        host.handle_incoming(&open);
        let _ = host.poll_outgoing(4); // consume Opened

        // Pre-fill outgoing queue to MAX_TERMINAL_OUTGOING_FRAMES
        for _ in 0..MAX_TERMINAL_OUTGOING_FRAMES {
            host.outgoing.push_back(vec![1, 2, 3]);
        }
        assert_eq!(host.outgoing.len(), MAX_TERMINAL_OUTGOING_FRAMES);

        // Even control-plane bursts (List) while queue is full must never push outgoing over MAX_TERMINAL_OUTGOING_FRAMES.
        let list_req = TerminalWireMsg::List.encode().unwrap();
        host.handle_incoming(&list_req);
        assert_eq!(host.outgoing.len(), MAX_TERMINAL_OUTGOING_FRAMES);

        // Produce output on the PTY and poll 1 frame: outgoing must never exceed MAX_TERMINAL_OUTGOING_FRAMES.
        let inp = TerminalWireMsg::Input {
            term_id: 1,
            data: b"echo CAP_TEST_LINE\n".to_vec(),
        }
        .encode()
        .unwrap();
        host.handle_incoming(&inp);
        std::thread::sleep(Duration::from_millis(80));

        // Polling 0 returns nothing and does not grow outgoing.
        assert!(host.poll_outgoing(0).is_empty());
        assert_eq!(host.outgoing.len(), MAX_TERMINAL_OUTGOING_FRAMES);

        // Polling 1 pops 1 frame without calling try_read_output while full (so len becomes MAX - 1).
        let polled = host.poll_outgoing(1);
        assert_eq!(polled.len(), 1);
        assert!(host.outgoing.len() <= MAX_TERMINAL_OUTGOING_FRAMES);
    }

    #[cfg(unix)]
    #[test]
    fn host_background_open_auto_names_and_allocates_unique_ids() {
        let mut client = TerminalClientEngine::new();
        let mut host = TerminalHostEngine::new();

        client.open_background(80, 24, None);
        client.open_background(80, 24, None);
        for f in client.poll_outgoing(8) {
            host.handle_incoming(&f);
        }
        let mut opened = Vec::new();
        for f in host.poll_outgoing(8) {
            opened.extend(client.handle_incoming(&f));
        }
        assert_eq!(opened.len(), 2);
        match (&opened[0], &opened[1]) {
            (
                TerminalEvent::Opened {
                    term_id: id1,
                    name: n1,
                    ok: true,
                    ..
                },
                TerminalEvent::Opened {
                    term_id: id2,
                    name: n2,
                    ok: true,
                    ..
                },
            ) => {
                assert_ne!(id1, id2);
                assert_eq!(n1, "session1");
                assert_eq!(n2, "session2");
            }
            other => panic!("expected 2 Opened events, got {other:?}"),
        }

        // Duplicate term_id on Open automatically allocates next unused ID without collision.
        let dup_open = TerminalWireMsg::Open {
            term_id: 1,
            cols: 80,
            rows: 24,
            name: None,
            attach: false,
        }
        .encode()
        .unwrap();
        host.handle_incoming(&dup_open);
        let frames = host.poll_outgoing(4);
        assert_eq!(frames.len(), 1);
        let evs = client.handle_incoming(&frames[0]);
        match &evs[0] {
            TerminalEvent::Opened {
                term_id,
                name,
                ok: true,
                ..
            } => {
                assert!(*term_id >= 3);
                assert_eq!(name, "session3");
            }
            other => panic!("expected Opened for dup request, got {other:?}"),
        }
        // List while an attached PTY has live output must NOT steal its live output or Exited notification.
        client.open(80, 24);
        let attached_id = loop {
            for f in client.poll_outgoing(4) {
                host.handle_incoming(&f);
            }
            let mut found = None;
            for f in host.poll_outgoing(4) {
                for ev in client.handle_incoming(&f) {
                    if let TerminalEvent::Opened {
                        term_id, ok: true, ..
                    } = ev
                    {
                        found = Some(term_id);
                    }
                }
            }
            if let Some(id) = found {
                break id;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        client.send_input(attached_id, b"echo LIVE_OUTPUT_PRESERVED\n");
        for f in client.poll_outgoing(4) {
            host.handle_incoming(&f);
        }
        std::thread::sleep(Duration::from_millis(100));
        client.list();
        for f in client.poll_outgoing(4) {
            host.handle_incoming(&f);
        }
        let mut live_acc = String::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && !live_acc.contains("LIVE_OUTPUT_PRESERVED") {
            for f in host.poll_outgoing(16) {
                for ev in client.handle_incoming(&f) {
                    if let TerminalEvent::Output {
                        term_id,
                        text_utf8_lossy,
                        ..
                    } = ev
                    {
                        if term_id == attached_id {
                            live_acc.push_str(&text_utf8_lossy);
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            live_acc.contains("LIVE_OUTPUT_PRESERVED"),
            "List must not steal output from attached PTY: {live_acc:?}"
        );
        assert_eq!(host.active_count(), 4);
    }

    #[cfg(unix)]
    #[test]
    fn host_close_and_open_under_full_outgoing_queue_defer_control_frames_without_leak() {
        let mut host = TerminalHostEngine::new();
        for _ in 0..MAX_TERMINAL_OUTGOING_FRAMES {
            host.outgoing.push_back(vec![1, 2, 3]);
        }
        assert_eq!(host.outgoing.len(), MAX_TERMINAL_OUTGOING_FRAMES);

        // Open while outgoing is saturated: PTY is spawned, Opened is deferred cleanly.
        let open = TerminalWireMsg::Open {
            term_id: 9,
            cols: 80,
            rows: 24,
            name: Some("full-q".to_string()),
            attach: false,
        }
        .encode()
        .unwrap();
        host.handle_incoming(&open);
        assert_eq!(host.outgoing.len(), MAX_TERMINAL_OUTGOING_FRAMES);
        assert_eq!(host.deferred_ctrl.len(), 1);
        assert_eq!(host.active_count(), 1);

        // Close while outgoing is saturated: Exited is deferred without being dropped.
        let close = TerminalWireMsg::Close { term_id: 9 }.encode().unwrap();
        host.handle_incoming(&close);
        assert_eq!(host.active_count(), 0);
        assert_eq!(host.deferred_ctrl.len(), 2);

        // Draining yields the 64 placeholder frames first, then Opened(ok=true) and Exited(code=0).
        let drained = host.poll_outgoing(MAX_TERMINAL_OUTGOING_FRAMES + 8);
        assert_eq!(drained.len(), MAX_TERMINAL_OUTGOING_FRAMES + 2);
        assert_eq!(host.deferred_ctrl.len(), 0);
        let opened = TerminalWireMsg::decode(&drained[MAX_TERMINAL_OUTGOING_FRAMES]).unwrap();
        assert!(matches!(
            opened,
            TerminalWireMsg::Opened {
                term_id: 9,
                ok: true,
                attached: false,
                ..
            }
        ));
        let exited = TerminalWireMsg::decode(&drained[MAX_TERMINAL_OUTGOING_FRAMES + 1]).unwrap();
        assert!(matches!(
            exited,
            TerminalWireMsg::Exited {
                term_id: 9,
                code: 0
            }
        ));

        // When BOTH outgoing and deferred_ctrl are saturated, Open rejects early without spawning a leaked PTY.
        for _ in 0..MAX_TERMINAL_OUTGOING_FRAMES {
            host.outgoing.push_back(vec![4, 5, 6]);
        }
        for _ in 0..MAX_DEFERRED_CTRL_FRAMES {
            host.deferred_ctrl.push_back(vec![7, 8, 9]);
        }
        let leaked_attempt = TerminalWireMsg::Open {
            term_id: 10,
            cols: 80,
            rows: 24,
            name: None,
            attach: true,
        }
        .encode()
        .unwrap();
        host.handle_incoming(&leaked_attempt);
        assert_eq!(host.active_count(), 0);
    }
}
