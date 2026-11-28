use super::mock::*;
use super::*;

#[test]
fn flush_tool_channel_with_retry_preserves_order_and_drops_nothing_on_backpressure() {
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
    let mut source: VecDeque<Vec<u8>> = (1u8..=5).map(|i| vec![i]).collect();
    let mut sent: Vec<Vec<u8>> = Vec::new();
    let mut poll_calls = 0usize;

    // 第 1 拍：拉出前 3 帧，第 2 帧遇到背压返回 Err -> 第 1 帧发出，第 2、3 帧留在 pending。
    let mut attempt = 0usize;
    let busy1 = flush_tool_channel_with_retry(
        &mut pending,
        3,
        |n| {
            poll_calls += 1;
            (0..n).filter_map(|_| source.pop_front()).collect()
        },
        |frame| {
            attempt += 1;
            if attempt == 2 {
                Err("backpressure")
            } else {
                sent.push(frame);
                Ok(())
            }
        },
    );
    assert!(busy1);
    assert_eq!(poll_calls, 1);
    assert_eq!(sent, vec![vec![1]]);
    assert_eq!(pending.len(), 2);

    // 第 2 拍：继续背压 -> 不得再次 poll 引擎，pending 保持 2 帧。
    let busy2 = flush_tool_channel_with_retry(
        &mut pending,
        3,
        |_| {
            poll_calls += 1;
            Vec::new()
        },
        |_| Err::<(), _>("still busy"),
    );
    assert!(!busy2);
    assert_eq!(poll_calls, 1);
    assert_eq!(pending.len(), 2);

    // 第 3 拍：背压解除 -> 先发出 2、3（仍不 poll 新帧）；第 4 拍再拉出 4、5 全部送达。
    let busy3 = flush_tool_channel_with_retry(
        &mut pending,
        3,
        |_| {
            poll_calls += 1;
            Vec::new()
        },
        |frame| {
            sent.push(frame);
            Ok::<(), ()>(())
        },
    );
    assert!(busy3);
    assert_eq!(poll_calls, 1);
    assert!(pending.is_empty());

    let busy4 = flush_tool_channel_with_retry(
        &mut pending,
        3,
        |n| {
            poll_calls += 1;
            (0..n).filter_map(|_| source.pop_front()).collect()
        },
        |frame| {
            sent.push(frame);
            Ok::<(), ()>(())
        },
    );
    assert!(busy4);
    assert_eq!(poll_calls, 2);
    assert_eq!(sent, vec![vec![1], vec![2], vec![3], vec![4], vec![5]]);
}

#[test]
fn file_host_worker_handles_list_dir_off_thread_and_stops_cleanly() {
    let dir = std::env::temp_dir().join(format!(
        "rc-ui-file-host-worker-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp test dir");
    std::fs::write(dir.join("probe.txt"), b"hello").expect("write probe file");

    let shared_dir: SharedFileTransferDir = Arc::new(RwLock::new(None));
    let worker = FileHostWorker::spawn(shared_dir);
    let req = rc_tools::FileWireMsg::ListDir {
        path: Some(dir.to_string_lossy().into_owned()),
    }
    .encode()
    .expect("encode ListDir");
    worker
        .try_send_incoming(req)
        .expect("send incoming ListDir to worker");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut resp_frame = None;
    while Instant::now() < deadline {
        let frames = worker.try_recv_outgoing(4);
        if let Some(f) = frames.into_iter().next() {
            resp_frame = Some(f);
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let frame = resp_frame.expect("worker must reply with ListDirResp");
    match rc_tools::FileWireMsg::decode(&frame).expect("decode ListDirResp") {
        rc_tools::FileWireMsg::ListDirResp { entries, error, .. } => {
            assert!(error.is_none(), "unexpected list_dir error: {error:?}");
            assert!(entries.iter().any(|e| e.name == "probe.txt"));
        }
        other => panic!("expected ListDirResp, got {other:?}"),
    }

    drop(worker);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn host_handle_set_file_transfer_dir_and_worker_dynamic_update_plumbing() {
    let base = std::env::temp_dir().join(format!(
        "rc-ui-ft-dir-plumbing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let dir_a = base.join("dir_a");
    let dir_b = base.join("dir_b");

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        file_transfer_dir: Some(dir_a.clone()),
        ..UiHostConfig::default()
    })
    .expect("spawn host handle");

    assert_eq!(
        *host
            .file_transfer_dir
            .read()
            .unwrap_or_else(|e| e.into_inner()),
        Some(dir_a.clone())
    );

    let worker = FileHostWorker::spawn(Arc::clone(&host.file_transfer_dir));

    let send_empty_dir_upload = |worker: &FileHostWorker, id: u64, name: &str, body: &[u8]| {
        let start = rc_tools::FileWireMsg::UploadStart {
            id,
            remote_dir: String::new(),
            file_name: name.to_string(),
            total_bytes: body.len() as u64,
        }
        .encode()
        .unwrap();
        let chunk = rc_tools::FileWireMsg::UploadChunk {
            id,
            offset: 0,
            data: body.to_vec(),
        }
        .encode()
        .unwrap();
        let finish = rc_tools::FileWireMsg::UploadFinish { id }.encode().unwrap();
        worker.try_send_incoming(start).unwrap();
        worker.try_send_incoming(chunk).unwrap();
        worker.try_send_incoming(finish).unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut got_done = false;
        while Instant::now() < deadline {
            for frame in worker.try_recv_outgoing(8) {
                if let Ok(rc_tools::FileWireMsg::UploadDone {
                    id: done_id,
                    ok,
                    error,
                }) = rc_tools::FileWireMsg::decode(&frame)
                {
                    assert_eq!(done_id, id);
                    assert!(ok, "upload failed: {error:?}");
                    got_done = true;
                }
            }
            if got_done {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(got_done, "timed out waiting for UploadDone for id={id}");
    };

    send_empty_dir_upload(&worker, 1, "first.txt", b"payload-a");
    assert_eq!(
        std::fs::read(dir_a.join("first.txt")).unwrap(),
        b"payload-a"
    );

    // Dynamically switch via HostHandle::set_file_transfer_dir and verify worker picks it up
    host.set_file_transfer_dir(Some(dir_b.clone()));
    assert_eq!(
        *host
            .file_transfer_dir
            .read()
            .unwrap_or_else(|e| e.into_inner()),
        Some(dir_b.clone())
    );

    send_empty_dir_upload(&worker, 2, "second.txt", b"payload-b");
    assert_eq!(
        std::fs::read(dir_b.join("second.txt")).unwrap(),
        b"payload-b"
    );

    drop(worker);
    host.stop();
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn tool_permissions_owner_exempt_vs_non_owner_and_runtime_hot_toggle() {
    // 1) 纯归属判定红线：仅 Owner 会话（authenticated_owner().is_some()）豁免保持全开；
    //    非 Owner 会话严格受 allow_assist_file_transfer 门控。
    assert_eq!(
        compute_effective_tool_permissions(true, false),
        rc_session::ToolPermissions::all_allowed()
    );
    assert_eq!(
        compute_effective_tool_permissions(true, true),
        rc_session::ToolPermissions::all_allowed()
    );
    assert_eq!(
        compute_effective_tool_permissions(false, true),
        rc_session::ToolPermissions {
            allow_file_transfer: true,
            allow_terminal: false,
            allow_port_map: false,
        }
    );
    assert_eq!(
        compute_effective_tool_permissions(false, false),
        rc_session::ToolPermissions {
            allow_file_transfer: false,
            allow_terminal: false,
            allow_port_map: false,
        }
    );

    // 2) 非 Owner 串流会话：初始允许 -> 运行期热关闭（不断会话）-> 立即推 ToolPermissionsState(false)
    //    -> 控制端绕过前置拦截直接发 TOOL_CHANNEL_FILE 帧 -> 被控端硬拦截并节流回传 ToolPermissionDenied。
    let clock: SessionClock = Arc::new(|| 10_000);
    let (mut host, in_tx, out_rx, _out_dgrams) = build_streaming_channel_host(Arc::clone(&clock));
    assert!(host.authenticated_owner().is_none());

    let stop_flag = Arc::new(AtomicBool::new(false));
    let allow_assist_ft = Arc::new(AtomicBool::new(true));
    let t_stop = Arc::clone(&stop_flag);
    let t_allow_ft = Arc::clone(&allow_assist_ft);
    let t_clock = Arc::clone(&clock);
    let driver = thread::spawn(move || {
        drive_ui_host_session_inner(
            &mut host,
            &t_clock,
            None,
            &BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP),
            &AtomicU64::new(0),
            0,
            &AtomicU64::new(0),
            0,
            &AtomicBool::new(false),
            &t_stop,
            &AtomicU8::new(ByeReason::Normal as u8),
            HostTransportKind::Lan,
            false,
            false,
            false,
            &AtomicU64::new(0),
            None,
            &mut PersistentOwnerTerminals::new(),
            Arc::new(Mutex::new(None)),
            Arc::new(RwLock::new(None)),
            &t_allow_ft,
            None,
            None,
            Instant::now(),
        )
    });

    let init_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::ToolPermissionsState {
                allow_file_transfer: true,
                allow_terminal: false,
                allow_port_map: false,
            }
        )
    });
    assert!(
        init_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::ToolPermissionsState {
                allow_file_transfer: true,
                allow_terminal: false,
                allow_port_map: false,
            }
        )),
        "entering Streaming must push initial ToolPermissionsState(file=true,term=false,pm=false): {init_msgs:?}"
    );

    // 运行期热关闭协助文件传输，会话不中断且立即推送 ToolPermissionsState(false)。
    allow_assist_ft.store(false, Ordering::Release);
    let revoked_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::ToolPermissionsState {
                allow_file_transfer: false,
                allow_terminal: false,
                allow_port_map: false,
            }
        )
    });
    assert!(
        revoked_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::ToolPermissionsState {
                allow_file_transfer: false,
                ..
            }
        )),
        "hot toggle to false must immediately push ToolPermissionsState(false): {revoked_msgs:?}"
    );
    assert!(
        !driver.is_finished(),
        "toggling allow_assist_file_transfer must not terminate active session"
    );

    // 模拟绕过控制端拦截的恶意/旧版客户端直发 TOOL_CHANNEL_FILE 帧。
    let mut wire_file = Vec::new();
    rc_session::proto::ControlMessage::ToolChannel {
        channel: TOOL_CHANNEL_FILE,
        payload: b"bypass-attempt".to_vec(),
    }
    .encode(&mut wire_file);
    in_tx
        .send(NetEvent::Reliable(wire_file))
        .expect("inject file frame");

    let denied_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::ToolPermissionDenied {
                channel: TOOL_CHANNEL_FILE,
                ..
            }
        )
    });
    assert!(
        denied_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::ToolPermissionDenied {
                channel: TOOL_CHANNEL_FILE,
                ..
            }
        )),
        "host must hard-reject TOOL_CHANNEL_FILE and reply ToolPermissionDenied: {denied_msgs:?}"
    );

    stop_flag.store(true, Ordering::Release);
    let _ = driver.join().expect("join driver");
}

#[test]
fn file_host_worker_cancel_on_drop_discards_buffered_upload_frames_and_cleans_rcpart() {
    let base = std::env::temp_dir().join(format!(
        "rc-host-file-cancel-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    let recv_dir: SharedFileTransferDir = Arc::new(RwLock::new(Some(base.clone())));

    // 场景 A：cancel 置位时，即便 in_rx 中已有完整 UploadStart + UploadChunk + UploadFinish 缓冲帧，
    // Drop 也不得继续消费写盘或 fs::rename 落盘最终文件。
    let worker_a = FileHostWorker::spawn(Arc::clone(&recv_dir));
    worker_a.cancel.store(true, Ordering::Release);
    let start = rc_tools::FileWireMsg::UploadStart {
        id: 701,
        remote_dir: base.to_string_lossy().to_string(),
        file_name: "must_not_exist.bin".to_string(),
        total_bytes: 8,
    }
    .encode()
    .unwrap();
    let chunk = rc_tools::FileWireMsg::UploadChunk {
        id: 701,
        offset: 0,
        data: b"12345678".to_vec(),
    }
    .encode()
    .unwrap();
    let finish = rc_tools::FileWireMsg::UploadFinish { id: 701 }
        .encode()
        .unwrap();
    let _ = worker_a.try_send_incoming(start);
    let _ = worker_a.try_send_incoming(chunk);
    let _ = worker_a.try_send_incoming(finish);
    drop(worker_a);
    assert!(
        !base.join("must_not_exist.bin").exists(),
        "cancelled FileHostWorker::drop must not process buffered UploadFinish into final file"
    );

    // 场景 B：进行中上传已创建 `.rcpart`，Drop 时立即回收并清理 `.rcpart` 不留残留。
    let worker_b = FileHostWorker::spawn(Arc::clone(&recv_dir));
    let start_b = rc_tools::FileWireMsg::UploadStart {
        id: 702,
        remote_dir: base.to_string_lossy().to_string(),
        file_name: "partial.bin".to_string(),
        total_bytes: 1024,
    }
    .encode()
    .unwrap();
    let chunk_b = rc_tools::FileWireMsg::UploadChunk {
        id: 702,
        offset: 0,
        data: vec![0x55u8; 64],
    }
    .encode()
    .unwrap();
    worker_b.try_send_incoming(start_b).unwrap();
    worker_b.try_send_incoming(chunk_b).unwrap();
    // 等待 UploadAck 确认 UploadStart + UploadChunk 已在 worker 线程处理并生成 `.rcpart`。
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_ack = false;
    while Instant::now() < deadline && !saw_ack {
        if !worker_b.try_recv_outgoing(8).is_empty() {
            saw_ack = true;
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }
    assert!(saw_ack, "expected UploadAck before simulating hot revoke");
    drop(worker_b);
    assert!(!base.join("partial.bin").exists());
    let lingering_parts: Vec<_> = std::fs::read_dir(&base)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".rcpart"))
        .collect();
    assert!(
        lingering_parts.is_empty(),
        "dropping FileHostWorker must clean up in-flight .rcpart: {lingering_parts:?}"
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn detached_resume_revokes_file_transfer_and_clears_pending_file_state() {
    use rc_session::auth::ClientAuthConfig;
    use rc_session::{ClientSession, ClientSessionConfig, ReconnectConfig};

    struct EmptyInput;
    impl rc_input::InputCapture for EmptyInput {
        fn next_events(
            &mut self,
            _timeout: Duration,
        ) -> rc_types::Result<Vec<rc_input::InputEvent>> {
            Ok(Vec::new())
        }
    }

    let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
    let owner_replay = Arc::new(Mutex::new(rc_session::OwnerReplayCache::new()));
    let BuiltUiHost {
        mut host,
        clock,
        clock_anchor,
        ..
    } = build_host_session(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        None,
        rc_session::auth::DEFAULT_AUTH_TIMEOUT_US,
        false,
        false,
        true,
        true,
        None,
        owner_replay,
        Box::new(AutoApprover),
        Arc::clone(&updates),
    )
    .expect("build_host_session");
    host.set_reconnect(ReconnectConfig {
        resume_ttl: Duration::from_secs(6),
        ..ReconnectConfig::default()
    })
    .expect("set_reconnect");
    let addr = host.local_addr().expect("local_addr");

    let allow_assist_ft = Arc::new(AtomicBool::new(true));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let t_allow = Arc::clone(&allow_assist_ft);
    let t_stop = Arc::clone(&stop_flag);
    let t_updates = Arc::clone(&updates);
    let t_anchor = clock_anchor.clone();
    let host_thread = thread::spawn(move || {
        t_anchor.reset_pending();
        host.accept_and_handshake(Duration::from_secs(5))
            .expect("accept_and_handshake");
        drive_ui_host_session_inner(
            &mut host,
            &clock,
            Some(&t_anchor),
            &t_updates,
            &AtomicU64::new(0),
            0,
            &AtomicU64::new(0),
            0,
            &AtomicBool::new(false),
            &t_stop,
            &AtomicU8::new(ByeReason::Normal as u8),
            HostTransportKind::Lan,
            false,
            false,
            false,
            &AtomicU64::new(0),
            None,
            &mut PersistentOwnerTerminals::new(),
            Arc::new(Mutex::new(None)),
            Arc::new(RwLock::new(None)),
            &t_allow,
            None,
            None,
            Instant::now(),
        )
    });

    // 1) 建立非 Owner 会话（初始 allow_file_transfer == true）。
    let mut ccfg = ClientSessionConfig::new(
        addr,
        SessionParams {
            width: 64,
            height: 64,
            fps: 30,
            bitrate_bps: 1_000_000,
        },
        7788,
        Box::new(EmptyInput),
    );
    ccfg.handshake_timeout = Duration::from_secs(3);
    ccfg.connect_timeout = Duration::from_secs(3);
    ccfg.auth = ClientAuthConfig::default();
    let cclock: SessionClock = Arc::new(|| 0);
    let mut client1 = ClientSession::new(
        ccfg,
        DEV_CERT_PEM,
        DEV_KEY_PEM,
        DEV_CERT_PEM,
        "rabbitcontrol",
        Arc::clone(&cclock),
    )
    .expect("client1 new");
    client1.connect_and_handshake().expect("client1 handshake");

    // 等待初始 ToolPermissionsState(true)。
    let mut saw_true = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !saw_true {
        let _ = client1.tick(Duration::from_millis(10), Instant::now());
        for (ch, payload) in client1.drain_tool_messages() {
            if ch == TOOL_CHANNEL_DISPLAY_CTRL
                && matches!(
                    display_ctrl::decode_display_ctrl(&payload),
                    Some(DisplayControlMsg::ToolPermissionsState {
                        allow_file_transfer: true,
                        ..
                    })
                )
            {
                saw_true = true;
            }
        }
    }
    assert!(saw_true, "expected initial ToolPermissionsState(true)");

    // 2) 模拟意外断网（直接 drop client1 不发 Bye）使 host 进入 Detached，期间将开关置 false。
    drop(client1);
    thread::sleep(Duration::from_millis(80));
    allow_assist_ft.store(false, Ordering::Release);

    // 3) 以同一 session_id 发起 ReconnectRequest 命中 DetachOutcome::Resumed：
    //    必须立即收到 ToolPermissionsState(false)，且发送 TOOL_CHANNEL_FILE 帧必须被拦截并回传 ToolPermissionDenied。
    let dev_id = rc_net::quic::Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).unwrap();
    let ep = rc_net::quic::QuicEndpoint::new(
        &NetConfig::new(Role::Controller, "127.0.0.1:0".parse().unwrap()),
        &dev_id,
    )
    .expect("reconnect ep");
    let server_certs = rc_net::quic::Identity::certs_from_pem(DEV_CERT_PEM).unwrap();
    let mut t2 = ep
        .connect(addr, &server_certs, "rabbitcontrol", Duration::from_secs(3))
        .expect("reconnect connect");
    let mut req_buf = Vec::new();
    rc_session::proto::ControlMessage::ReconnectRequest {
        session_id: 7788,
        resume: true,
    }
    .encode(&mut req_buf);
    t2.send_reliable(&req_buf).expect("send reconnect req");

    let mut saw_resumed_welcome = false;
    let mut saw_revoked_state = false;
    let mut saw_file_denied = false;
    let mut sent_probe_file = false;
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline
        && !(saw_resumed_welcome && saw_revoked_state && saw_file_denied)
    {
        if let Ok(evs) = t2.poll(Duration::from_millis(20)) {
            for ev in evs {
                if let NetEvent::Reliable(raw) = ev {
                    match rc_session::proto::ControlMessage::decode(&raw) {
                        Ok(rc_session::proto::ControlMessage::Welcome(w))
                            if w.host_flags.resume_accepted() =>
                        {
                            saw_resumed_welcome = true;
                        }
                        Ok(rc_session::proto::ControlMessage::ToolChannel {
                            channel: TOOL_CHANNEL_DISPLAY_CTRL,
                            payload,
                        }) => match display_ctrl::decode_display_ctrl(&payload) {
                            Some(DisplayControlMsg::ToolPermissionsState {
                                allow_file_transfer: false,
                                ..
                            }) => {
                                saw_revoked_state = true;
                                if !sent_probe_file {
                                    sent_probe_file = true;
                                    let mut file_wire = Vec::new();
                                    rc_session::proto::ControlMessage::ToolChannel {
                                        channel: TOOL_CHANNEL_FILE,
                                        payload: b"post-resume-file".to_vec(),
                                    }
                                    .encode(&mut file_wire);
                                    let _ = t2.send_reliable(&file_wire);
                                }
                            }
                            Some(DisplayControlMsg::ToolPermissionDenied {
                                channel: TOOL_CHANNEL_FILE,
                                ..
                            }) => {
                                saw_file_denied = true;
                            }
                            _ => {}
                        },
                        Ok(rc_session::proto::ControlMessage::ToolChannel {
                            channel: TOOL_CHANNEL_FILE,
                            ..
                        }) => {
                            panic!("host must not emit TOOL_CHANNEL_FILE after resume revoke");
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    assert!(
        saw_resumed_welcome,
        "reconnect must hit DetachOutcome::Resumed"
    );
    assert!(
        saw_revoked_state,
        "DetachOutcome::Resumed must immediately push ToolPermissionsState(false)"
    );
    assert!(
        saw_file_denied,
        "post-resume TOOL_CHANNEL_FILE must be hard-rejected with ToolPermissionDenied"
    );

    stop_flag.store(true, Ordering::Release);
    drop(t2);
    drop(ep);
    let _ = host_thread.join().expect("join host_thread");
}

#[test]
fn terminal_lock_gate_respects_initial_lock_unlock_and_mid_session_relock_without_interrupt() {
    // 1) 初始锁屏：进入待校验态；期间观察到屏幕仍锁屏不变化；物理/桌面解锁后自动放行；
    //    之后被控期间中途重新锁屏绝不重新锁定终端（「被控期间锁屏不影响正常使用」）。
    let mut gate = TerminalLockGate::new(true);
    assert!(gate.is_locked());
    assert!(!gate.on_screen_lock_observed(true));
    assert!(gate.is_locked());
    assert!(gate.on_screen_lock_observed(false));
    assert!(!gate.is_locked());
    assert!(!gate.on_screen_lock_observed(true));
    assert!(!gate.is_locked());

    // 2) 初始锁屏：系统密码核验通过后直接放行，再次核验幂等返回 false；中途锁屏仍放行。
    let mut verified_gate = TerminalLockGate::new(true);
    assert!(verified_gate.on_verified_ok());
    assert!(!verified_gate.is_locked());
    assert!(!verified_gate.on_verified_ok());
    assert!(!verified_gate.on_screen_lock_observed(true));
    assert!(!verified_gate.is_locked());

    // 3) 初始未锁屏：全程保持放行，即使中途锁屏也不拦截。
    let mut unlocked_gate = TerminalLockGate::new(false);
    assert!(!unlocked_gate.is_locked());
    assert!(!unlocked_gate.on_screen_lock_observed(true));
    assert!(!unlocked_gate.is_locked());
}

#[test]
fn terminal_unlock_rate_limiter_enforces_tiered_cooldown_and_resets_on_success() {
    let mut limiter = TerminalUnlockRateLimiter::default();
    let t0 = Instant::now();
    assert_eq!(limiter.retry_after_secs(t0), 0);

    for i in 1..=4 {
        assert_eq!(
            limiter.record_failure(t0),
            0,
            "failure #{i} must not trigger cooldown yet"
        );
        assert_eq!(limiter.retry_after_secs(t0), 0);
    }

    // 第 5 次失败触发 30s 冷却。
    assert_eq!(limiter.record_failure(t0), 30);
    assert_eq!(limiter.retry_after_secs(t0), 30);
    assert!(limiter.retry_after_secs(t0 + Duration::from_secs(29)) >= 1);
    assert_eq!(limiter.retry_after_secs(t0 + Duration::from_secs(30)), 0);

    // 第 10 次触发 60s，第 15 次触发 120s。
    for _ in 6..=9 {
        let _ = limiter.record_failure(t0);
    }
    assert_eq!(limiter.record_failure(t0), 60);
    for _ in 11..=14 {
        let _ = limiter.record_failure(t0);
    }
    assert_eq!(limiter.record_failure(t0), 120);

    // 成功后立即清零计数与冷却。
    limiter.record_success();
    assert_eq!(limiter.retry_after_secs(t0), 0);
    assert_eq!(limiter.record_failure(t0), 0);
}

#[test]
fn terminal_lock_gate_blocks_terminal_frames_until_unlocked() {
    let mut locked_gate = TerminalLockGate::new(true);
    let mut driver = TerminalVerifyDriver::new();
    let mut tx = HostDisplayCtrlOutbox::new();

    // 非 Owner 请求必须被拒绝，且不会解除 gate。
    handle_terminal_unlock_request(
        false,
        display_ctrl::RedactedSecret("pass123".to_string()),
        None,
        &locked_gate,
        &mut driver,
        &mut tx,
    );
    let denied = tx
        .queue
        .pop_front()
        .and_then(|b| display_ctrl::decode_display_ctrl(&b))
        .expect("must emit TerminalUnlockResult");
    assert!(matches!(
        denied,
        DisplayControlMsg::TerminalUnlockResult { ok: false, .. }
    ));
    assert!(locked_gate.is_locked());

    // 模拟密码通过后直接放行，再次请求幂等成功。
    assert!(locked_gate.on_verified_ok());
    handle_terminal_unlock_request(
        true,
        display_ctrl::RedactedSecret("pass123".to_string()),
        None,
        &locked_gate,
        &mut driver,
        &mut tx,
    );
    let ok_res = tx
        .queue
        .pop_front()
        .and_then(|b| display_ctrl::decode_display_ctrl(&b))
        .expect("must emit ok TerminalUnlockResult");
    assert!(matches!(
        ok_res,
        DisplayControlMsg::TerminalUnlockResult { ok: true, .. }
    ));
    let ok_state = tx
        .sticky_terminal_lock
        .take()
        .and_then(|b| display_ctrl::decode_display_ctrl(&b))
        .expect("must emit TerminalLockState");
    assert!(matches!(
        ok_state,
        DisplayControlMsg::TerminalLockState {
            required: false,
            unlocked: true,
            ..
        }
    ));
}

#[test]
fn stale_verify_failure_after_physical_unlock_neither_penalizes_nor_emits_result() {
    let mut gate = TerminalLockGate::new(true);
    // 先物理解锁，使 gate 变为已放行态。
    assert!(gate.on_screen_lock_observed(false));
    assert!(!gate.is_locked());

    let t0 = Instant::now();
    assert_eq!(
        global_terminal_unlock_limiter()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retry_after_secs(t0),
        0
    );

    let mut outbox = HostDisplayCtrlOutbox::new();
    handle_terminal_verify_completion(Ok(false), true, &mut gate, &mut outbox);

    // 既不发 TerminalUnlockResult（既不误报失败也不误发 ok=true），也不累计限流失败；仅同步已解锁状态。
    assert!(outbox.queue.is_empty());
    let state = outbox
        .sticky_terminal_lock
        .take()
        .and_then(|b| display_ctrl::decode_display_ctrl(&b))
        .expect("must refresh unlocked TerminalLockState");
    assert!(matches!(
        state,
        DisplayControlMsg::TerminalLockState {
            required: false,
            unlocked: true,
            ..
        }
    ));
    assert_eq!(
        global_terminal_unlock_limiter()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retry_after_secs(Instant::now()),
        0
    );

    // 物理解锁后若有迟到的 TerminalUnlockRequest（未经过密码核验）抵达，
    // 绝不得误发 TerminalUnlockResult { ok: true } 导致客户端保存未校验密码，仅同步 TerminalLockState。
    let mut driver = TerminalVerifyDriver::new();
    handle_terminal_unlock_request(
        true,
        display_ctrl::RedactedSecret("wrong-or-unverified".to_string()),
        None,
        &gate,
        &mut driver,
        &mut outbox,
    );
    assert!(outbox.queue.is_empty());
    let state2 = outbox
        .sticky_terminal_lock
        .take()
        .and_then(|b| display_ctrl::decode_display_ctrl(&b))
        .expect("must still emit refreshed unlocked TerminalLockState");
    assert!(matches!(
        state2,
        DisplayControlMsg::TerminalLockState {
            required: false,
            unlocked: true,
            ..
        }
    ));
}

#[test]
fn requested_username_matches_current_rejects_mismatch_only() {
    assert!(requested_username_matches_current(None, Some("alice")));
    assert!(requested_username_matches_current(
        Some("  "),
        Some("alice")
    ));
    assert!(requested_username_matches_current(Some("bob"), None));
    assert!(requested_username_matches_current(
        Some(" alice "),
        Some("alice")
    ));
    assert!(!requested_username_matches_current(
        Some("bob"),
        Some("alice")
    ));
}
