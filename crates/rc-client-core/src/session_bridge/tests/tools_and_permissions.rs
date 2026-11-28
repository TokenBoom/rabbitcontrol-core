use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rc_session::{ToolPermissions, TOOL_CHANNEL_FILE};
use rc_tools::{FileEvent, PortMapClientEngine, TerminalEvent, TransferStatus};

use crate::display_ctrl::DisplayControlMsg;
use crate::ui_error::UiError;

use super::super::display_ctrl::handle_display_ctrl_msg;
use super::super::handle::SessionHandle;
use super::super::queues::{BoundedQueue, BoundedUpdateQueue};
use super::super::tools::file_worker::FileWorkerCmd;
use super::super::tools::{FileClientWorker, ToolClientHandle, ToolClientHub};
use super::super::types::{
    SessionCommand, SessionUpdate, UiSessionConfig, MAX_TERMINAL_INPUT_BYTES, UPDATE_CHANNEL_CAP,
};

#[test]
fn tool_client_handle_tracks_and_closes_active_terminals() {
    let hub = Arc::new(Mutex::new(ToolClientHub::new()));
    let file_events = Arc::new(BoundedQueue::new(16));
    let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
    let handle = ToolClientHandle {
        hub: Arc::clone(&hub),
        file: file_handle,
        portmap_latest: Arc::new(Mutex::new(None)),
        running: Arc::new(AtomicBool::new(true)),
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
    };

    assert!(handle.active_terminal_ids().is_empty());
    assert!(handle.terminal_open(0, 24).is_err());
    assert!(handle.terminal_open(513, 24).is_err());
    let id1 = handle.terminal_open(80, 24).expect("open 1");
    let id2 = handle.terminal_open(100, 30).expect("open 2");
    assert!(handle.has_active_terminal(id1));
    assert!(handle.has_active_terminal(id2));
    assert!(!handle.has_active_terminal(999_999));
    assert_eq!(handle.active_terminal_ids(), vec![id1, id2]);

    assert!(handle.terminal_resize(id1, 0, 24).is_err());
    assert!(handle.terminal_resize(id1, 80, 513).is_err());
    assert!(handle.terminal_resize(id1, 120, 40).is_ok());

    assert!(handle.terminal_input(id1, b"ls\n").is_ok());
    assert!(handle.terminal_input(999_999, b"ls\n").is_err());
    let oversized = vec![b'x'; MAX_TERMINAL_INPUT_BYTES + 1];
    assert!(handle.terminal_input(id1, &oversized).is_err());

    handle.terminal_close(id1).expect("close 1");
    assert!(!handle.has_active_terminal(id1));
    assert!(handle.terminal_input(id1, b"after-close").is_err());
    assert_eq!(handle.active_terminal_ids(), vec![id2]);

    let closed = handle.close_all_terminals();
    assert_eq!(closed, vec![id2]);
    assert!(handle.active_terminal_ids().is_empty());

    worker.shutdown();
}

#[test]
fn tool_client_handle_background_detach_and_list_sync_preserve_active_ids() {
    let hub = Arc::new(Mutex::new(ToolClientHub::new()));
    let file_events = Arc::new(BoundedQueue::new(16));
    let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
    let handle = ToolClientHandle {
        hub: Arc::clone(&hub),
        file: file_handle,
        portmap_latest: Arc::new(Mutex::new(None)),
        running: Arc::new(AtomicBool::new(true)),
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
    };

    assert_eq!(
        handle
            .terminal_open_with_options(80, 24, Some("worker".to_string()), false)
            .unwrap(),
        0
    );
    assert!(handle
        .terminal_open_with_options(80, 24, Some("   ".to_string()), false)
        .is_err());
    assert!(handle.terminal_list().is_ok());

    handle.terminal_attach(7, 100, 30).expect("attach");
    assert!(handle.has_active_terminal(7));
    assert!(handle.terminal_rename(7, "renamed-shell").is_ok());
    assert!(handle.terminal_rename(7, "bad\nname").is_err());

    // Detaching all UI attachments keeps active_terminals intact and emits Detach frames only.
    let detached = handle.detach_all_terminals();
    assert_eq!(detached, vec![7]);
    assert!(handle.has_active_terminal(7));

    let mut decoded_msgs = Vec::new();
    {
        let mut h = hub.lock().unwrap();
        for frame in h.terminal.poll_outgoing(16) {
            decoded_msgs.push(rc_tools::TerminalWireMsg::decode(&frame).unwrap());
        }
    }
    assert!(decoded_msgs.iter().any(|m| matches!(
        m,
        rc_tools::TerminalWireMsg::Open {
            term_id: 0,
            attach: false,
            name: Some(n),
            ..
        } if n == "worker"
    )));
    assert!(decoded_msgs
        .iter()
        .any(|m| matches!(m, rc_tools::TerminalWireMsg::List)));
    assert!(decoded_msgs
        .iter()
        .any(|m| matches!(m, rc_tools::TerminalWireMsg::Attach { term_id: 7, .. })));
    assert!(decoded_msgs
        .iter()
        .any(|m| matches!(m, rc_tools::TerminalWireMsg::Detach { term_id: 7 })));
    assert!(decoded_msgs.iter().any(|m| matches!(
        m,
        rc_tools::TerminalWireMsg::Rename { term_id: 7, name } if name == "renamed-shell"
    )));
    assert!(!decoded_msgs
        .iter()
        .any(|m| matches!(m, rc_tools::TerminalWireMsg::Close { .. })));

    worker.shutdown();
}

#[test]
fn tool_client_hub_reconciles_failed_open_reassignment_and_overtaken_list() {
    let hub = Arc::new(Mutex::new(ToolClientHub::new()));
    let file_events = Arc::new(BoundedQueue::new(16));
    let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
    let handle = ToolClientHandle {
        hub: Arc::clone(&hub),
        file: file_handle,
        portmap_latest: Arc::new(Mutex::new(None)),
        running: Arc::new(AtomicBool::new(true)),
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
    };

    // 1) Failed terminal_open cleans up pre-inserted active & attached IDs.
    let bad_id = handle.terminal_open(80, 24).expect("optimistic open 1");
    assert!(handle.has_active_terminal(bad_id));
    {
        let mut h = hub.lock().unwrap();
        h.apply_terminal_event(&TerminalEvent::Opened {
            term_id: bad_id,
            name: String::new(),
            created_at_unix_sec: 0,
            title: String::new(),
            cwd: String::new(),
            attached: false,
            ok: false,
            error: Some("max terminals".to_string()),
        });
        assert!(!h.active_terminals.contains(&bad_id));
        assert!(!h.attached_terminals.contains(&bad_id));
    }

    // 2) Host reassigns conflicting ID (client guessed 2, host already has 2 live & assigns 5).
    let guessed_id = handle.terminal_open(80, 24).expect("optimistic open 2");
    {
        let mut h = hub.lock().unwrap();
        h.apply_terminal_event(&TerminalEvent::SessionList {
            sessions: vec![rc_tools::TerminalSessionInfo {
                term_id: guessed_id,
                name: "existing".to_string(),
                title: "zsh".to_string(),
                cwd: "/tmp".to_string(),
                created_at_unix_sec: 1,
                cols: 80,
                rows: 24,
                attached: false,
            }],
        });
        // In-flight optimistic open must remain in active & attached until Opened arrives.
        assert!(h.active_terminals.contains(&guessed_id));
        assert!(h.attached_terminals.contains(&guessed_id));

        h.apply_terminal_event(&TerminalEvent::Opened {
            term_id: 5,
            name: "session2".to_string(),
            created_at_unix_sec: 2,
            title: "zsh".to_string(),
            cwd: "/tmp".to_string(),
            attached: true,
            ok: true,
            error: None,
        });
        assert!(h.active_terminals.contains(&guessed_id));
        assert!(!h.attached_terminals.contains(&guessed_id));
        assert!(h.active_terminals.contains(&5));
        assert!(h.attached_terminals.contains(&5));
    }
    assert_eq!(handle.detach_all_terminals(), vec![5]);

    // 3) Failed Attach removes non-existent term_id from active & attached.
    handle.terminal_attach(99, 80, 24).expect("attach 99");
    assert!(handle.has_active_terminal(99));
    {
        let mut h = hub.lock().unwrap();
        h.apply_terminal_event(&TerminalEvent::Attached {
            term_id: 99,
            session: None,
            ok: false,
            error: Some("missing".to_string()),
        });
        assert!(!h.active_terminals.contains(&99));
        assert!(!h.attached_terminals.contains(&99));
    }

    // 4) detach_all_terminals while Open(attach=true) is in flight causes Opened to auto-detach actual host ID.
    let in_flight_req = handle.terminal_open(80, 24).expect("optimistic open 4");
    let _ = handle.detach_all_terminals();
    {
        let mut h = hub.lock().unwrap();
        let _ = h.terminal.poll_outgoing(16); // drain prior frames
        h.apply_terminal_event(&TerminalEvent::Opened {
            term_id: in_flight_req + 10,
            name: "late".to_string(),
            created_at_unix_sec: 3,
            title: "zsh".to_string(),
            cwd: "/tmp".to_string(),
            attached: true,
            ok: true,
            error: None,
        });
        assert!(h.active_terminals.contains(&(in_flight_req + 10)));
        assert!(!h.attached_terminals.contains(&(in_flight_req + 10)));
        let post_detach: Vec<_> = h
            .terminal
            .poll_outgoing(4)
            .into_iter()
            .map(|f| rc_tools::TerminalWireMsg::decode(&f).unwrap())
            .collect();
        assert!(post_detach.iter().any(|m| matches!(
            m,
            rc_tools::TerminalWireMsg::Detach { term_id } if *term_id == in_flight_req + 10
        )));
    }

    worker.shutdown();
}

#[test]
fn tool_client_handle_rejects_control_ops_when_outgoing_queue_full_without_mutating_hub() {
    let hub = Arc::new(Mutex::new(ToolClientHub::new()));
    let file_events = Arc::new(BoundedQueue::new(16));
    let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
    let handle = ToolClientHandle {
        hub: Arc::clone(&hub),
        file: file_handle,
        portmap_latest: Arc::new(Mutex::new(None)),
        running: Arc::new(AtomicBool::new(true)),
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
    };

    // Pre-insert an existing live session, then saturate the client outgoing queue.
    let existing_id = 42;
    {
        let mut h = hub.lock().unwrap();
        h.host_live_ids.insert(existing_id);
        h.active_terminals.insert(existing_id);
        for _ in 0..rc_tools::terminal::MAX_TERMINAL_OUTGOING_FRAMES {
            h.terminal.list();
        }
        assert!(!h.terminal.can_enqueue());
    }

    assert!(handle
        .terminal_open_with_options(80, 24, None, true)
        .is_err());
    assert!(handle
        .terminal_open_with_options(80, 24, Some("bg".to_string()), false)
        .is_err());
    assert!(handle.terminal_list().is_err());
    assert!(handle.terminal_attach(existing_id, 80, 24).is_err());
    assert!(handle.terminal_rename(existing_id, "new-name").is_err());
    assert!(handle.terminal_input(existing_id, b"hello").is_err());
    assert!(handle.terminal_close(existing_id).is_err());

    {
        let h = hub.lock().unwrap();
        assert!(h.pending_opens.is_empty());
        assert!(h.pending_attaches.is_empty());
        assert!(h.attached_terminals.is_empty());
        assert!(h.host_live_ids.contains(&existing_id));
        assert!(h.active_terminals.contains(&existing_id));
        assert_eq!(h.active_terminals.len(), 1);
    }

    worker.shutdown();
}

#[test]
fn file_client_worker_offloads_commands_and_updates_cached_transfers_without_hub_lock() {
    let dir = std::env::temp_dir().join(format!(
        "rc-ui-file-client-worker-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp test dir");
    let sample = dir.join("upload_probe.bin");
    std::fs::write(&sample, b"0123456789abcdef").expect("write probe file");

    let hub = Arc::new(Mutex::new(ToolClientHub::new()));
    let file_events = Arc::new(BoundedQueue::new(32));
    let (mut worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_events));
    let tools = ToolClientHandle {
        hub: Arc::clone(&hub),
        file: file_handle,
        portmap_latest: Arc::new(Mutex::new(None)),
        running: Arc::new(AtomicBool::new(true)),
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        update_tx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
    };

    // 即使外部正持有 tools_hub 锁，文件上传与传输列表查询也绝不阻塞（证明文件引擎完全脱离 tools_hub）。
    let _hold_hub = hub.lock().unwrap();
    let up_id = tools
        .file_upload(sample.to_string_lossy().as_ref(), "/tmp")
        .expect("file_upload must succeed while tools_hub is locked");
    let cached = tools.file_list_transfers();
    assert!(
        cached
            .iter()
            .any(|t| t.id == up_id && t.name == "upload_probe.bin"),
        "cached_transfers must reflect upload immediately, got: {cached:?}"
    );
    drop(_hold_hub);

    // 工作线程应产出 UploadStart 线帧。
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut got_frame = false;
    while Instant::now() < deadline {
        if !worker.try_recv_outgoing(4).is_empty() {
            got_frame = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        got_frame,
        "rc-file-client-worker must emit UploadStart frame"
    );

    tools.file_cancel(up_id).expect("file_cancel");
    worker.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tool_permissions_state_pre_send_gate_and_remote_denied_emit_structured_ui_error() {
    // 1) handle_display_ctrl_msg 正确映射 ToolPermissionsState 与 ToolPermissionDenied -> UiError(tool.forbidden)。
    let mut w = 1280;
    let mut h = 720;
    let perms_upd = handle_display_ctrl_msg(
        DisplayControlMsg::ToolPermissionsState {
            allow_file_transfer: false,
            allow_terminal: false,
            allow_port_map: false,
        },
        &mut w,
        &mut h,
        false,
    );
    assert_eq!(
        perms_upd,
        Some(SessionUpdate::ToolPermissionsUpdated(ToolPermissions {
            allow_file_transfer: false,
            allow_terminal: false,
            allow_port_map: false,
        }))
    );
    let perms_json = serde_json::to_value(perms_upd.unwrap()).expect("serialize perms upd");
    assert_eq!(perms_json["kind"], "tool_permissions_updated");
    assert_eq!(perms_json["data"]["allow_file_transfer"], false);
    assert_eq!(perms_json["data"]["allow_terminal"], false);
    assert_eq!(perms_json["data"]["allow_port_map"], false);

    let denied_upd = handle_display_ctrl_msg(
        DisplayControlMsg::ToolPermissionDenied {
            channel: TOOL_CHANNEL_FILE,
            reason: Some("remote host denied".to_string()),
        },
        &mut w,
        &mut h,
        false,
    );
    match denied_upd {
        Some(SessionUpdate::ToolPermissionDenied { channel, ui_error }) => {
            assert_eq!(channel, TOOL_CHANNEL_FILE);
            assert_eq!(ui_error.code, crate::ui_error::codes::TOOL_FORBIDDEN);
            assert!(ui_error.message.contains("文件传输"));
            assert_eq!(ui_error.detail.as_deref(), Some("remote host denied"));
        }
        other => panic!("expected ToolPermissionDenied, got {other:?}"),
    }

    // 2) 端到端 HostHandle + SessionHandle：非 Owner 被控端禁止终端/端口映射并受协助文件开关控制 + 运行期热开关不中断会话。
    let mut host = crate::host_bridge::HostHandle::spawn(crate::host_bridge::UiHostConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        allow_assist_file_transfer: false,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        ..crate::host_bridge::UiHostConfig::default()
    })
    .expect("spawn host");
    let host_addr = host.listen_addr();

    let session = SessionHandle::spawn(UiSessionConfig {
        connect_addr: host_addr,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        width: 320,
        height: 240,
        fps: 30,
        ..UiSessionConfig::default()
    });

    let deadline = Instant::now() + Duration::from_secs(6);
    let mut saw_initial_denied_perm = false;
    while Instant::now() < deadline {
        while let Some(upd) = session.try_recv_update() {
            if let SessionUpdate::ToolPermissionsUpdated(p) = upd {
                if !p.allow_file_transfer && !p.allow_terminal && !p.allow_port_map {
                    saw_initial_denied_perm = true;
                }
            }
        }
        if saw_initial_denied_perm {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        saw_initial_denied_perm,
        "controller must receive ToolPermissionsUpdated(all false for non-owner with assist file off)"
    );
    assert!(!session.tool_permissions().allow_file_transfer);
    assert!(!session.tool_permissions().allow_terminal);
    assert!(!session.tool_permissions().allow_port_map);

    let term_err = session
        .tools()
        .terminal_open(80, 24)
        .expect_err("non-owner terminal_open must be blocked");
    assert!(term_err.contains("远程终端"), "unexpected err: {term_err}");
    let pm_err = session
        .tools()
        .portmap_add("pm".to_string(), 18080, "127.0.0.1".to_string(), 80)
        .expect_err("non-owner portmap_add must be blocked");
    assert!(pm_err.contains("端口映射"), "unexpected err: {pm_err}");

    // 控制端尝试发起文件列表与上传请求 -> ToolClientHandle 入口前置拦截，返回 Err、不创建僵尸 Active 任务，
    // 并输出结构化 UiError(tool.forbidden)。
    let list_err = session
        .tools()
        .file_list_remote(None)
        .expect_err("file_list_remote must be blocked when allow_file_transfer=false");
    assert!(list_err.contains("文件传输"), "unexpected err: {list_err}");

    let tmp_dir = std::env::temp_dir().join(format!(
        "rc-session-tool-gate-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let sample_file = tmp_dir.join("blocked_upload.bin");
    std::fs::write(&sample_file, vec![0x11u8; 4096]).unwrap();

    let upload_err = session
        .tools()
        .file_upload(sample_file.to_str().unwrap(), tmp_dir.to_str().unwrap())
        .expect_err("file_upload must be blocked at ToolClientHandle before opening file");
    assert!(upload_err.contains("文件传输"));
    assert!(
        session.tools().file_list_transfers().is_empty(),
        "blocked file_upload must never leave a zombie Active transfer entry"
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut denied_err: Option<UiError> = None;
    while Instant::now() < deadline {
        while let Some(upd) = session.try_recv_update() {
            if let SessionUpdate::ToolPermissionDenied { channel, ui_error } = upd {
                if channel == TOOL_CHANNEL_FILE {
                    denied_err = Some(ui_error);
                }
            }
        }
        if denied_err.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let ui_err = denied_err.expect("controller must emit ToolPermissionDenied for FILE");
    assert_eq!(ui_err.code, crate::ui_error::codes::TOOL_FORBIDDEN);
    assert!(ui_err.message.contains("文件传输"));

    // 被控端运行期热开启再热关闭 allow_assist_file_transfer，会话保持存活且控制端实时同步。
    host.set_allow_assist_file_transfer(true);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_reenabled = false;
    while Instant::now() < deadline {
        while let Some(upd) = session.try_recv_update() {
            if let SessionUpdate::ToolPermissionsUpdated(p) = upd {
                if p.allow_file_transfer {
                    saw_reenabled = true;
                }
            }
        }
        if saw_reenabled {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        saw_reenabled && session.is_running() && session.tool_permissions().allow_file_transfer,
        "hot-enabling allow_assist_file_transfer must sync without disconnecting"
    );

    // 验证 FileClientWorker::abort_all_active 能立即中止在途传输并推 Failed 事件（无僵尸 Active）。
    let file_events = Arc::new(BoundedQueue::new(32));
    let (mut worker, fhandle) = FileClientWorker::spawn(Arc::clone(&file_events));
    let tid = fhandle
        .send_cmd(|reply| FileWorkerCmd::StartUpload {
            local_path: sample_file.to_string_lossy().to_string(),
            remote_dir: tmp_dir.to_string_lossy().to_string(),
            reply,
        })
        .expect("start_upload on worker");
    assert!(fhandle
        .cached_transfers
        .lock()
        .unwrap()
        .iter()
        .any(|t| t.id == tid && t.status == TransferStatus::Active));
    worker.abort_all_active("host revoked file transfer");
    let abort_deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_failed_ev = false;
    while Instant::now() < abort_deadline && !saw_failed_ev {
        while let Some(ev) = file_events.try_pop() {
            if let FileEvent::TransferUpdated(item) = ev {
                if item.id == tid && item.status == TransferStatus::Failed {
                    saw_failed_ev = true;
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        saw_failed_ev,
        "FileClientWorker::abort_all_active must emit TransferUpdated(Failed)"
    );
    assert!(
        fhandle
            .cached_transfers
            .lock()
            .unwrap()
            .iter()
            .all(|t| t.status != TransferStatus::Active),
        "no zombie Active transfers may remain after abort_all_active"
    );
    worker.shutdown();

    session.send(SessionCommand::Disconnect);
    session.join();
    host.stop();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn tool_hub_revocation_resets_terminal_and_portmap_state_cleanly() {
    let mut hub = ToolClientHub::new();
    let tid = hub
        .terminal
        .open_with_options(80, 24, Some("sh".into()), true);
    hub.pending_opens.push_back((tid, true));
    hub.active_terminals.insert(tid);
    hub.attached_terminals.insert(tid);
    let _ = hub.terminal.poll_outgoing(8);

    hub.reset_terminal();
    assert!(hub.active_terminals.is_empty());
    assert!(hub.attached_terminals.is_empty());
    assert!(hub.pending_opens.is_empty());
    assert!(hub.terminal.poll_outgoing(8).is_empty());

    let rule = hub
        .portmap
        .add_rule_with_enabled(
            "db".to_string(),
            19432,
            "127.0.0.1".to_string(),
            5432,
            false,
        )
        .expect("rule added disabled");
    assert_eq!(rule.local_port, 19432);
    assert_eq!(hub.portmap.list_rules().len(), 1);
    hub.portmap = PortMapClientEngine::new();
    assert!(hub.portmap.list_rules().is_empty());

    // 验证 ToolClientHandle::lock_hub_for_channel 在权限撤销后持 hub 锁内原子拒绝终端与端口映射操作。
    let perms = Arc::new(Mutex::new(ToolPermissions::all_allowed()));
    let hub_arc = Arc::new(Mutex::new(ToolClientHub::new()));
    let portmap_latest = Arc::new(Mutex::new(None));
    let update_tx = Arc::new(BoundedUpdateQueue::new(16));
    let (fw, fh) = FileClientWorker::spawn(Arc::new(BoundedQueue::new(16)));
    let handle = ToolClientHandle {
        running: Arc::new(AtomicBool::new(true)),
        tool_permissions: Arc::clone(&perms),
        file: fh,
        hub: Arc::clone(&hub_arc),
        portmap_latest: Arc::clone(&portmap_latest),
        update_tx: Arc::clone(&update_tx),
    };
    {
        let _h = hub_arc.lock().unwrap();
        *perms.lock().unwrap() = ToolPermissions {
            allow_file_transfer: true,
            allow_terminal: false,
            allow_port_map: false,
        };
    }
    assert!(handle.terminal_open(80, 24).is_err());
    assert!(handle
        .portmap_add("web".into(), 18080, "127.0.0.1".into(), 8080)
        .is_err());
    assert!(hub_arc.lock().unwrap().portmap.list_rules().is_empty());
    drop(fw);
}
