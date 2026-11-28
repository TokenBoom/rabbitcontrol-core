use super::mock::*;
use super::*;

#[test]
fn host_bridge_force_disconnect_and_busy_lan_rejection_e2e() {
    use crate::server_config::{ServerConfig, ServerConnectionState};
    use crate::session_bridge::{SessionHandle, SessionUpdate, UiSessionConfig};
    use rc_session::{ClientSession, ClientSessionConfig};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind signal");
    let signal_addr = listener.local_addr().expect("signal addr");
    let (report_tx, report_rx) = mpsc::channel::<Vec<ActiveControllerSummary>>();
    let (send_fd_tx, send_fd_rx) = mpsc::channel::<(Option<String>, Option<String>)>();
    let (stop_sig_tx, stop_sig_rx) = mpsc::channel::<()>();

    let srv_jh = thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept signal");
        conn.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set read timeout");
        let reg = read_mock_signal_frame(&mut conn);
        assert_eq!(reg["type"], "register");
        write_mock_signal_frame(
            &mut conn,
            &serde_json::json!({
                "type": "registered",
                "device_id": "900100200",
                "formatted_id": "900 100 200",
                "udp_probe_addr": "",
                "relay_addr": "127.0.0.1:21117",
            }),
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if stop_sig_rx.try_recv().is_ok() {
                break;
            }
            while let Ok((cdid, sid)) = send_fd_rx.try_recv() {
                write_mock_signal_frame(
                    &mut conn,
                    &serde_json::json!({
                        "type": "force_disconnect",
                        "requester_device_id": "111222333",
                        "controller_device_id": cdid,
                        "session_id": sid,
                    }),
                );
            }
            let mut len_buf = [0u8; 4];
            match std::io::Read::read(&mut conn, &mut len_buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut rem = n;
                    while rem < 4 {
                        let k = std::io::Read::read(&mut conn, &mut len_buf[rem..])
                            .expect("finish frame len");
                        assert!(k > 0);
                        rem += k;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; len];
                    std::io::Read::read_exact(&mut conn, &mut body).expect("read body");
                    let val: serde_json::Value = serde_json::from_slice(&body).expect("json body");
                    if val["type"] == "control_state_report" {
                        let ctrls: Vec<ActiveControllerSummary> =
                            serde_json::from_value(val["active_controllers"].clone())
                                .expect("active_controllers json");
                        let _ = report_tx.send(ctrls);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
    });

    let sig_cfg = ServerConfig {
        enabled: true,
        server_host: "127.0.0.1".to_string(),
        signal_port: signal_addr.port(),
        relay_port: 21117,
        api_port: 21118,
        use_https: false,
        ..ServerConfig::default()
    };
    let sig = crate::signal_client::SignalClientHandle::spawn(
        sig_cfg,
        "host-sig-key".to_string(),
        Vec::new(),
    );
    let sig_arc = Arc::new(sig);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if sig_arc.status().state == ServerConnectionState::Connected {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        prefer_hardware: false,
        require_approval: false,
        clipboard_enabled: false,
        audio_enabled: false,
        ..UiHostConfig::default()
    })
    .expect("spawn HostHandle");
    host.set_signal_client(Some(Arc::clone(&sig_arc)));
    let host_addr = host.listen_addr();

    // 1) 控制端 1 正常直连，信令服务端必须收到 active_controllers.len() == 1 的同步报告
    let session1 = SessionHandle::spawn(UiSessionConfig {
        connect_addr: host_addr,
        width: 64,
        height: 64,
        fps: 30,
        bitrate_bps: 1_000_000,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        self_device_id: Some("111222333".to_string()),
        self_device_name: Some("Controller One".to_string()),
        self_os: Some("macos".to_string()),
        ..UiSessionConfig::default()
    });

    let mut active_ctrl = None;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        while let Ok(ctrls) = report_rx.try_recv() {
            if let Some(first) = ctrls.into_iter().next() {
                active_ctrl = Some(first);
            }
        }
        if active_ctrl
            .as_ref()
            .is_some_and(|c| c.controller_device_id == "111222333")
        {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let ctrl = active_ctrl.expect("signal server must receive control_state_report(1)");
    assert_eq!(ctrl.controller_device_id, "111222333");
    assert_eq!(ctrl.controller_device_name, "Controller One");

    // 2) 未声明接管的新直连控制端在被控端繁忙时必须被明确拒收为 HostBusyControlled，
    //    同时原控制端 1 保持活跃不断线
    let cap2 = Box::new(rc_session::testkit::ScriptedCapture::from_timeline(Vec::new()).unwrap());
    let mut ccfg2 = ClientSessionConfig::new(
        host_addr,
        SessionParams {
            width: 64,
            height: 64,
            fps: 30,
            bitrate_bps: 1_000_000,
        },
        9901,
        cap2,
    );
    ccfg2.pipeline = PipelineConfig {
        resolution: Resolution::new(64, 64),
        fps: 30,
        bitrate_bps: 1_000_000,
        prefer_hardware: false,
        ..PipelineConfig::default()
    };
    let mut client2 = ClientSession::new(
        ccfg2,
        DEV_CERT_PEM,
        DEV_KEY_PEM,
        rc_session::dev_cert::dev_server_cert_pem(),
        rc_session::dev_cert::DEV_SERVER_NAME,
        Arc::new(|| 0),
    )
    .expect("client2");
    let err2 = client2
        .connect_and_handshake()
        .expect_err("extra LAN client must be rejected when host busy");
    assert!(
        err2.to_string().contains("HostBusyControlled"),
        "unexpected error: {err2}"
    );
    assert!(client2.handshake_busy_controlled());
    assert_eq!(host.active_controllers().len(), 1);

    // 3) 不匹配的 force_disconnect 不得断开；匹配的 force_disconnect 立即踢断并上报空列表
    send_fd_tx
        .send((Some("other-did".to_string()), Some("other-sid".to_string())))
        .unwrap();
    thread::sleep(Duration::from_millis(120));
    assert_eq!(host.active_controllers().len(), 1);

    send_fd_tx
        .send((Some("111222333".to_string()), Some(ctrl.session_id.clone())))
        .unwrap();

    let mut reported_empty = false;
    let mut session1_ended_non_recoverable = false;
    let mut session1_disc_non_recoverable = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        while let Ok(ctrls) = report_rx.try_recv() {
            if ctrls.is_empty() {
                reported_empty = true;
            }
        }
        while let Some(su) = session1.try_recv_update() {
            match su {
                SessionUpdate::Disconnected {
                    preempted,
                    busy_controlled,
                    auto_reconnect_eligible,
                    ..
                } => {
                    assert!(
                        !auto_reconnect_eligible && !preempted && !busy_controlled,
                        "ForceDisconnect must emit non-recoverable Disconnected (got preempted={preempted}, busy={busy_controlled}, auto={auto_reconnect_eligible})"
                    );
                    session1_disc_non_recoverable = true;
                }
                SessionUpdate::Ended { recoverable, .. } => {
                    assert!(
                        !recoverable,
                        "ForceDisconnect must emit Ended with recoverable=false"
                    );
                    session1_ended_non_recoverable = true;
                }
                _ => {}
            }
        }
        if reported_empty && session1_ended_non_recoverable && session1_disc_non_recoverable {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        reported_empty,
        "must report empty control_state after ForceDisconnect"
    );
    assert!(
        session1_disc_non_recoverable,
        "controller 1 must receive Disconnected with auto_reconnect_eligible=false"
    );
    assert!(
        session1_ended_non_recoverable,
        "controller 1 must receive Ended with recoverable=false"
    );
    assert!(host.active_controllers().is_empty());

    session1.join();
    host.stop();
    drop(sig_arc);
    let _ = stop_sig_tx.send(());
    srv_jh.join().unwrap();
}

#[test]
fn host_bridge_owner_takeover_preempts_active_controller_under_1500ms() {
    use crate::session_bridge::{SessionHandle, SessionUpdate, UiSessionConfig};

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        prefer_hardware: false,
        require_approval: false,
        clipboard_enabled: false,
        audio_enabled: false,
        ..UiHostConfig::default()
    })
    .expect("spawn HostHandle");
    let host_addr = host.listen_addr();

    let session1 = SessionHandle::spawn(UiSessionConfig {
        connect_addr: host_addr,
        width: 64,
        height: 64,
        fps: 30,
        bitrate_bps: 1_000_000,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        self_device_id: Some("111222333".to_string()),
        self_device_name: Some("Old Controller".to_string()),
        self_os: Some("macos".to_string()),
        ..UiSessionConfig::default()
    });

    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline && host.active_controllers().is_empty() {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(host.active_controllers().len(), 1);

    // 绑定不可达本地端口仅用于触发接管切流：验证旧控制端 <= 1.5s 收到 ByeReason::Preempted 且禁用重连
    let dead_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);

    let started = Instant::now();
    let mut inc = make_test_relay_incoming("takeover-sid-2", "222333444", true, true);
    inc.relay_addr = dead_addr.to_string();
    host.offer_relay_incoming(inc);

    let mut saw_preempted_disc = false;
    let mut saw_non_recoverable_end = false;
    let deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < deadline {
        while let Some(su) = session1.try_recv_update() {
            match su {
                SessionUpdate::Disconnected {
                    preempted,
                    busy_controlled,
                    auto_reconnect_eligible,
                    ui_error,
                    ..
                } => {
                    if preempted && !busy_controlled && !auto_reconnect_eligible {
                        assert_eq!(
                            ui_error.as_ref().map(|e| e.code.as_str()),
                            Some("session.preempted")
                        );
                        saw_preempted_disc = true;
                    }
                }
                SessionUpdate::Ended { recoverable, .. } if !recoverable => {
                    saw_non_recoverable_end = true;
                }
                _ => {}
            }
        }
        if saw_preempted_disc && saw_non_recoverable_end {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        saw_preempted_disc && saw_non_recoverable_end,
        "takeover must preempt active controller with ByeReason::Preempted in <=1.5s (elapsed={:?})",
        started.elapsed()
    );

    session1.join();
    host.stop();
}

#[test]
fn host_bridge_reconnecting_lan_client_receives_busy_controlled_when_replaced() {
    use crate::session_bridge::{SessionHandle, SessionUpdate, UiSessionConfig};
    use rc_net::quic::{Identity, QuicEndpoint};
    use rc_net::{NetConfig, Role};
    use rc_session::{ClientSession, ClientSessionConfig};

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        prefer_hardware: false,
        require_approval: false,
        clipboard_enabled: false,
        audio_enabled: false,
        ..UiHostConfig::default()
    })
    .expect("spawn HostHandle");
    let host_addr = host.listen_addr();

    // 先由控制端 2 占住被控端活跃会话。
    let session2 = SessionHandle::spawn(UiSessionConfig {
        connect_addr: host_addr,
        width: 64,
        height: 64,
        fps: 30,
        bitrate_bps: 1_000_000,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        self_device_id: Some("222333444".to_string()),
        self_device_name: Some("Active Controller".to_string()),
        self_os: Some("macos".to_string()),
        ..UiSessionConfig::default()
    });
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline && host.active_controllers().is_empty() {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(host.active_controllers().len(), 1);
    assert!(
        session2.peer_supports_pixel_scroll(),
        "HostHandle <-> SessionHandle must negotiate pixel_scroll via DisplayControlMsg::Capabilities"
    );

    // 模拟原直连 LAN 客户端处于 Reconnecting 期（发 ReconnectRequest），
    // 向已被占用的 HostHandle 重连：必须立即收到 HostBusyControlled 且不耗尽 5 次退避。
    let mut old_mock = rc_session::MockTransport::new();
    old_mock.deliver_reliable(&rc_session::proto::ControlMessage::Welcome(
        rc_session::proto::Welcome {
            session_id: 5501,
            granted: SessionParams {
                width: 64,
                height: 64,
                fps: 30,
                bitrate_bps: 1_000_000,
            },
            auth_status: rc_session::proto::AuthStatus::Ok,
            host_flags: rc_session::proto::HostFlags(0),
        },
    ));
    let mut old_handle = old_mock.clone();
    let mut old_ccfg = ClientSessionConfig::new(
        host_addr,
        SessionParams {
            width: 64,
            height: 64,
            fps: 30,
            bitrate_bps: 1_000_000,
        },
        5501,
        Box::new(rc_session::testkit::ScriptedCapture::from_timeline(Vec::new()).unwrap()),
    );
    old_ccfg.pipeline = PipelineConfig {
        resolution: Resolution::new(64, 64),
        fps: 30,
        bitrate_bps: 1_000_000,
        prefer_hardware: false,
        ..PipelineConfig::default()
    };
    let mut old_client = ClientSession::with_parts(
        old_ccfg,
        Box::new(old_mock),
        Box::new(rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig::default()).unwrap()),
        Box::new(rc_render::FakeRenderer::new(rc_render::FakeRendererConfig::default()).unwrap()),
        Arc::new(|| 0),
    )
    .expect("old_client");
    old_client.handshake().expect("initial handshake");
    old_client.set_connect_factory(Box::new(move || {
        let identity = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM)?;
        let net = NetConfig {
            role: Role::Controller,
            local_addr: "0.0.0.0:0".parse().unwrap(),
            peer_addr: Some(host_addr),
            mtu: rc_session::DEFAULT_SESSION_MTU,
        };
        let ep = QuicEndpoint::new(&net, &identity)?;
        let certs = Identity::certs_from_pem(rc_session::dev_cert::dev_server_cert_pem())?;
        let t = ep.connect(
            host_addr,
            &certs,
            rc_session::dev_cert::DEV_SERVER_NAME,
            Duration::from_secs(5),
        )?;
        Ok(Box::new(t))
    }));
    old_client.set_pipeline_factory(Box::new(|| {
        rc_pipeline::ControllerPipeline::with_backends(
            PipelineConfig {
                resolution: Resolution::new(64, 64),
                fps: 30,
                bitrate_bps: 1_000_000,
                prefer_hardware: false,
                ..PipelineConfig::default()
            },
            Box::new(rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig::default()).unwrap()),
            Box::new(
                rc_render::FakeRenderer::new(rc_render::FakeRendererConfig::default()).unwrap(),
            ),
        )
    }));
    old_handle.deliver(NetEvent::Disconnected {
        reason: "lan drop".into(),
    });
    old_client
        .tick(Duration::ZERO, Instant::now())
        .expect("enter reconnecting");
    assert_eq!(old_client.state(), SessionState::Reconnecting);

    // 第 1 拍建连并发送 ReconnectRequest，随后轮询等待 HostHandle 繁忙拒收返回。
    let first_out = old_client
        .tick_reconnect(500_000)
        .expect("first reconnect connect");
    assert_eq!(first_out, rc_session::ReconnectOutcome::Connecting);

    let mut got_err = None;
    let dl = Instant::now() + Duration::from_secs(3);
    while Instant::now() < dl {
        match old_client.tick_reconnect(500_000) {
            Ok(_) => thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                got_err = Some(e);
                break;
            }
        }
    }
    let err = got_err.expect("reconnecting LAN client must be rejected with HostBusyControlled");
    assert!(
        err.to_string().contains("HostBusyControlled"),
        "unexpected error: {err}"
    );
    assert!(old_client.handshake_busy_controlled());
    assert_eq!(old_client.state(), SessionState::Closed);
    assert_eq!(old_client.reconnect_stats().reconnect_attempts, 1);

    // 确认原活跃控制端 session2 仍保持活跃。
    assert!(
        session2
            .try_recv_update()
            .is_none_or(|u| !matches!(u, SessionUpdate::Ended { .. })),
        "active controller must stay connected"
    );
    assert_eq!(host.active_controllers().len(), 1);

    session2.send(crate::session_bridge::SessionCommand::Disconnect);
    session2.join();
    host.stop();
}

#[test]
fn busy_lan_reject_sends_bye_refresh_for_same_active_peer_and_worker_is_nonblocking() {
    use crate::relay_transport::tests::mtls_test_certs::TestCa;

    let mut ca = TestCa::new("BusyLanSamePeerCA");
    let (host_cert, host_key) = ca.issue_device("user-1", "200000001");
    let (same_cert, same_key) = ca.issue_device("user-1", "100000001");

    let host_bundle = SessionMtlsBundle {
        ca_cert_pem: ca.ca_pem.clone(),
        cert_pem: host_cert,
        key_pem: host_key,
        local_user_id: "user-1".to_string(),
        expected_peer_device_id: None,
        expected_peer_user_id: None,
    };
    let same_bundle = SessionMtlsBundle {
        ca_cert_pem: ca.ca_pem.clone(),
        cert_pem: same_cert,
        key_pem: same_key,
        local_user_id: "user-1".to_string(),
        expected_peer_device_id: Some("200000001".to_string()),
        expected_peer_user_id: Some("user-1".to_string()),
    };

    let host_ep = bind_mtls_lan_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), &host_bundle)
        .expect("bind mtls host endpoint");
    let host_addr = host_ep.local_addr().expect("host addr");

    let active_controllers: SharedActiveControllers =
        Arc::new(Mutex::new(vec![ActiveControllerSession {
            session_id: "active-sid".to_string(),
            controller_device_id: "100000001".to_string(),
            controller_device_name: "Same Controller".to_string(),
            controller_os: "macos".to_string(),
            is_owner: true,
            mode: "remote_control".to_string(),
            connected_at_ms: 1,
        }]));

    let caps = SessionParams {
        width: 64,
        height: 64,
        fps: 30,
        bitrate_bps: 1_000_000,
    };
    let t0 = Instant::now();
    let worker = BusyLanRejectWorker::spawn(
        host_ep.clone(),
        caps,
        Some(Arc::clone(&active_controllers)),
        None,
    );
    worker.set_active();
    assert!(
        t0.elapsed() < Duration::from_millis(50),
        "spawning/activating BusyLanRejectWorker must never block caller"
    );

    let dev_id = rc_net::quic::Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");
    let client_ep = QuicEndpoint::new(
        &NetConfig::new(Role::Controller, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        &dev_id,
    )
    .expect("client ep");
    let same_mtls = same_bundle.to_quic_mtls_config().expect("same mtls");
    let mut client_t = client_ep
        .connect_mtls(host_addr, &same_mtls, "", Duration::from_secs(3))
        .expect("connect_mtls");

    // 同设备重连/并发连入时不得静默 drop，必须收到显式 Bye(Refresh)。
    let mut got_bye_refresh = false;
    let dl = Instant::now() + Duration::from_secs(3);
    while Instant::now() < dl && !got_bye_refresh {
        match client_t.poll(Duration::from_millis(20)) {
            Ok(events) => {
                for ev in events {
                    if let NetEvent::Reliable(bytes) = ev {
                        if let Ok(rc_session::ControlMessage::Bye {
                            reason: ByeReason::Refresh,
                        }) = rc_session::ControlMessage::decode(&bytes)
                        {
                            got_bye_refresh = true;
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }
    assert!(
        got_bye_refresh,
        "same_active_peer arriving on busy LAN endpoint must receive explicit Bye(Refresh)"
    );

    let drop_started = Instant::now();
    drop(worker);
    assert!(
        drop_started.elapsed() < Duration::from_millis(200),
        "dropping BusyLanRejectWorker must wake and join promptly"
    );
}
