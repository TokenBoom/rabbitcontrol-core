use super::mock::*;
use super::*;

#[test]
fn active_controller_session_name_fallback_priority_and_serde() {
    let mut mock = rc_session::MockTransport::new();
    let params = SessionParams {
        width: 64,
        height: 64,
        fps: 30,
        bitrate_bps: 1_000_000,
    };
    mock.deliver_reliable(&rc_session::proto::ControlMessage::Hello(
        rc_session::proto::Hello {
            version: rc_session::proto::PROTOCOL_VERSION,
            session_id: 42,
            requested: params,
            auth_method: rc_session::AuthMethod::None,
            auth_payload: Vec::new(),
        },
    ));
    let mut handle = mock.clone();
    let capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
        display: rc_capture::DisplayInfo {
            id: rc_types::DisplayId(0),
            resolution: Resolution::new(64, 64),
            scale: 1.0,
            hdr: false,
        },
        fps: 30,
        content: rc_capture::FakeContent::Static,
        dirty_rect: None,
    })
    .unwrap();
    let encoder = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
        resolution: Resolution::new(64, 64),
        fps: 30,
        bitrate_bps: 1_000_000,
        ..rc_encode::EncoderConfig::default()
    })
    .unwrap();
    let mut host = HostSession::with_parts(
        HostSessionConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            params,
            Box::new(RecordingInjector::new()),
        ),
        Box::new(mock),
        Box::new(capture),
        Box::new(encoder),
        Arc::new(|| 0),
    )
    .unwrap();
    host.handshake().unwrap();

    // 4th fallback: remote_addr
    let hints_addr = ActiveControllerPeerHints {
        remote_addr: "192.168.1.50:55555".to_string(),
        ..Default::default()
    };
    let s4 = build_active_controller_session(&host, &hints_addr, 1_700_000_000_000);
    assert_eq!(s4.session_id, "42");
    assert_eq!(s4.controller_device_name, "192.168.1.50:55555");
    assert_eq!(s4.mode, "remote_control");

    // 3rd fallback: caller_device_id / relay_peer_id
    let hints_did = ActiveControllerPeerHints {
        relay_peer_id: Some("111222333".to_string()),
        remote_addr: "192.168.1.50:55555".to_string(),
        ..Default::default()
    };
    let s3 = build_active_controller_session(&host, &hints_did, 1_700_000_000_000);
    assert_eq!(s3.controller_device_name, "111222333");
    assert_eq!(s3.controller_device_id, "111222333");

    // 2nd fallback: RelayIncoming.peer_name
    let hints_relay_name = ActiveControllerPeerHints {
        relay_peer_id: Some("111222333".to_string()),
        relay_peer_name: Some("Office iMac".to_string()),
        remote_addr: "192.168.1.50:55555".to_string(),
        ..Default::default()
    };
    let s2 = build_active_controller_session(&host, &hints_relay_name, 1_700_000_000_000);
    assert_eq!(s2.controller_device_name, "Office iMac");

    // 1st priority: ControllerMeta.device_name
    let meta = rc_session::ControllerMeta {
        device_id: "999888777".to_string(),
        device_name: "Meta MacBook".to_string(),
        os: "macos".to_string(),
        mode: rc_session::CONTROLLER_MODE_WATCH_ONLY,
    };
    handle.deliver_reliable(&rc_session::proto::ControlMessage::controller_meta(meta).unwrap());
    host.tick(Duration::ZERO).unwrap();
    let s1 = build_active_controller_session(&host, &hints_relay_name, 1_700_000_000_000);
    assert_eq!(s1.controller_device_id, "999888777");
    assert_eq!(s1.controller_device_name, "Meta MacBook");
    assert_eq!(s1.controller_os, "macos");
    assert_eq!(s1.mode, "watch_only");

    let s_json = serde_json::to_string(&s1).unwrap();
    let s_de: ActiveControllerSession = serde_json::from_str(&s_json).unwrap();
    assert_eq!(s_de, s1);
    let cmd_json = serde_json::to_string(&HostCommand::DisconnectController {
        session_id: Some("sess-1".to_string()),
    })
    .unwrap();
    let cmd_de: HostCommand = serde_json::from_str(&cmd_json).unwrap();
    assert_eq!(
        cmd_de,
        HostCommand::DisconnectController {
            session_id: Some("sess-1".to_string()),
        }
    );
    host.close(ByeReason::Normal).unwrap();
}

#[test]
fn host_bridge_tracks_controller_meta_mode_changes_and_disconnect_controller() {
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
    let addr = host.listen_addr();

    // 1) 首次连接：watch_only = true + 完整 ControllerMeta
    let session = SessionHandle::spawn(UiSessionConfig {
        connect_addr: addr,
        watch_only: true,
        width: 64,
        height: 64,
        fps: 30,
        bitrate_bps: 1_000_000,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        self_device_id: Some("222333444".to_string()),
        self_device_name: Some("Alice MacBook".to_string()),
        self_os: Some("macos".to_string()),
        ..UiSessionConfig::default()
    });

    let mut observed_meta: Option<ActiveControllerSession> = None;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        while let Some(upd) = host.try_recv_update() {
            if let HostUpdate::ActiveControllersChanged { controllers } = upd {
                if let Some(first) = controllers.into_iter().next() {
                    if first.controller_device_name == "Alice MacBook" {
                        observed_meta = Some(first);
                    }
                }
            }
        }
        if observed_meta.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let ctrl = observed_meta.expect("host must observe ControllerMeta update");
    assert_eq!(ctrl.controller_device_id, "222333444");
    assert_eq!(ctrl.controller_device_name, "Alice MacBook");
    assert_eq!(ctrl.controller_os, "macos");
    assert_eq!(ctrl.mode, "watch_only");
    assert!(!ctrl.is_owner);
    assert!(ctrl.connected_at_ms > 0);
    assert_eq!(host.active_controllers(), vec![ctrl.clone()]);

    // 2) 运行期切换 watch_only -> remote_control，被控端应再次推送更新
    session.set_watch_only(false);
    let mut updated_mode = String::new();
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        while let Some(upd) = host.try_recv_update() {
            if let HostUpdate::ActiveControllersChanged { controllers } = upd {
                if let Some(first) = controllers.into_iter().next() {
                    if first.mode == "remote_control" {
                        updated_mode = first.mode;
                    }
                }
            }
        }
        if updated_mode == "remote_control" {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(updated_mode, "remote_control");

    // 3) 不匹配的 session_id 不得断开；匹配的 session_id 必须立即断开并推送空列表
    assert!(!host.disconnect_controller(Some("wrong-session-id".to_string())));
    assert!(!host.active_controllers().is_empty());

    assert!(host.disconnect_controller(Some(ctrl.session_id.clone())));

    let mut saw_empty = false;
    let mut saw_listening = false;
    let mut client_ended = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        while let Some(upd) = host.try_recv_update() {
            match upd {
                HostUpdate::ActiveControllersChanged { controllers } if controllers.is_empty() => {
                    saw_empty = true;
                }
                HostUpdate::Listening { .. } if saw_empty => {
                    saw_listening = true;
                }
                _ => {}
            }
        }
        while let Some(su) = session.try_recv_update() {
            if matches!(su, SessionUpdate::Ended { .. }) {
                client_ended = true;
            }
        }
        if saw_empty && saw_listening && client_ended {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        saw_empty,
        "disconnect_controller must emit empty ActiveControllersChanged"
    );
    assert!(
        saw_listening,
        "host must re-enter Listening after disconnect"
    );
    assert!(client_ended, "controller session must end");
    assert!(host.active_controllers().is_empty());
    session.join();

    // 4) 第二轮：tools_only + HostCommand::DisconnectController { session_id: None } 全断
    let addr2 = host.listen_addr();
    let session2 = SessionHandle::spawn(UiSessionConfig {
        connect_addr: addr2,
        tools_only: true,
        width: 64,
        height: 64,
        fps: 30,
        bitrate_bps: 1_000_000,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        self_device_id: Some("555666777".to_string()),
        self_device_name: Some("Tools Client".to_string()),
        self_os: Some("linux".to_string()),
        ..UiSessionConfig::default()
    });

    let mut saw_tools = false;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        while let Some(upd) = host.try_recv_update() {
            if let HostUpdate::ActiveControllersChanged { controllers } = upd {
                if controllers.first().is_some_and(|c| {
                    c.controller_device_name == "Tools Client" && c.mode == "tools"
                }) {
                    saw_tools = true;
                }
            }
        }
        if saw_tools {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        saw_tools,
        "host must report mode='tools' for tools_only session"
    );

    host.send(HostCommand::DisconnectController { session_id: None });

    let mut saw_empty2 = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        while let Some(upd) = host.try_recv_update() {
            if let HostUpdate::ActiveControllersChanged { controllers } = upd {
                if controllers.is_empty() {
                    saw_empty2 = true;
                }
            }
        }
        if saw_empty2 && !session2.is_running() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        saw_empty2,
        "DisconnectController(None) must disconnect and emit empty list"
    );
    session2.join();
    host.stop();
}

#[test]
fn host_bridge_legacy_client_without_controller_meta_still_streams_with_fallback_session() {
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
    let addr = host.listen_addr();

    let cap = Box::new(rc_session::testkit::ScriptedCapture::from_timeline(Vec::new()).unwrap());
    let mut ccfg = ClientSessionConfig::new(
        addr,
        SessionParams {
            width: 64,
            height: 64,
            fps: 30,
            bitrate_bps: 1_000_000,
        },
        777,
        cap,
    );
    ccfg.pipeline = PipelineConfig {
        resolution: Resolution::new(64, 64),
        fps: 30,
        bitrate_bps: 1_000_000,
        prefer_hardware: false,
        ..PipelineConfig::default()
    };
    let mut client = ClientSession::new(
        ccfg,
        DEV_CERT_PEM,
        DEV_KEY_PEM,
        rc_session::dev_cert::dev_server_cert_pem(),
        rc_session::dev_cert::DEV_SERVER_NAME,
        Arc::new(|| 0),
    )
    .expect("ClientSession::new");
    // 旧客户端未设置 controller_meta，握手后绝不发送 0x16 ControllerMeta。
    client.connect_and_handshake().expect("legacy handshake");
    assert_eq!(client.state(), SessionState::Streaming);

    let mut observed: Option<ActiveControllerSession> = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let _ = client.tick(Duration::from_millis(5), Instant::now());
        while let Some(upd) = host.try_recv_update() {
            if let HostUpdate::ActiveControllersChanged { controllers } = upd {
                if let Some(first) = controllers.into_iter().next() {
                    observed = Some(first);
                }
            }
        }
        if observed.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let ctrl = observed.expect("host must emit fallback ActiveControllerSession");
    assert_eq!(ctrl.session_id, "777");
    assert!(!ctrl.controller_device_name.is_empty());
    assert_eq!(ctrl.controller_os, "");
    assert_eq!(ctrl.mode, "remote_control");
    assert!(!ctrl.is_owner);

    client
        .close(ByeReason::Normal)
        .expect("close legacy client");
    host.stop();
}

#[test]
fn host_bridge_legacy_set_media_paused_refreshes_active_controllers_and_signal() {
    use crate::server_config::{ServerConfig, ServerConnectionState};
    use rc_session::{ClientSession, ClientSessionConfig};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind signal");
    let signal_addr = listener.local_addr().expect("signal addr");
    let (report_tx, report_rx) = mpsc::channel::<Vec<ActiveControllerSummary>>();
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
                "device_id": "900100201",
                "formatted_id": "900 100 201",
                "udp_probe_addr": "",
                "relay_addr": "127.0.0.1:21117",
            }),
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if stop_sig_rx.try_recv().is_ok() {
                break;
            }
            let mut len_buf = [0u8; 4];
            match std::io::Read::read(&mut conn, &mut len_buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut full = Vec::from(&len_buf[..n]);
                    while full.len() < 4 {
                        let mut more = [0u8; 4];
                        let k = std::io::Read::read(&mut conn, &mut more[..4 - full.len()])
                            .expect("read rest len");
                        if k == 0 {
                            break;
                        }
                        full.extend_from_slice(&more[..k]);
                    }
                    if full.len() < 4 {
                        break;
                    }
                    let len = u32::from_be_bytes([full[0], full[1], full[2], full[3]]) as usize;
                    let mut body = vec![0u8; len];
                    std::io::Read::read_exact(&mut conn, &mut body).expect("read body");
                    let v: serde_json::Value = serde_json::from_slice(&body).expect("json");
                    if v["type"] == "control_state_report" {
                        let ctrls: Vec<ActiveControllerSummary> =
                            serde_json::from_value(v["active_controllers"].clone())
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
    let sig_arc = Arc::new(crate::signal_client::SignalClientHandle::spawn(
        sig_cfg,
        "host-sig-legacy".to_string(),
        Vec::new(),
    ));
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

    let mut ccfg = ClientSessionConfig::new(
        host_addr,
        SessionParams {
            width: 64,
            height: 64,
            fps: 30,
            bitrate_bps: 1_000_000,
        },
        6601,
        Box::new(rc_session::testkit::ScriptedCapture::from_timeline(Vec::new()).unwrap()),
    );
    ccfg.pipeline = PipelineConfig {
        resolution: Resolution::new(64, 64),
        fps: 30,
        bitrate_bps: 1_000_000,
        prefer_hardware: false,
        ..PipelineConfig::default()
    };
    let mut client = ClientSession::new(
        ccfg,
        DEV_CERT_PEM,
        DEV_KEY_PEM,
        rc_session::dev_cert::dev_server_cert_pem(),
        rc_session::dev_cert::DEV_SERVER_NAME,
        Arc::new(|| 0),
    )
    .expect("client");
    client
        .connect_and_handshake()
        .expect("connect_and_handshake");
    // 默认 Welcome.host_flags 绝不置位超出 v0.2.7 KNOWN_MASK(0x03) 的位。
    assert!(!client.peer_supports_pixel_scroll());
    assert!(!client.peer_supports_controller_meta());

    let wait_mode = |client: &mut ClientSession, expected_mode: &str| {
        let dl = Instant::now() + Duration::from_secs(4);
        let mut saw_local = false;
        let mut saw_signal = false;
        while Instant::now() < dl {
            let _ = client.tick(Duration::from_millis(5), Instant::now());
            if host
                .active_controllers()
                .first()
                .is_some_and(|c| c.mode == expected_mode)
            {
                saw_local = true;
            }
            while let Ok(ctrls) = report_rx.try_recv() {
                if ctrls.first().is_some_and(|c| c.mode == expected_mode) {
                    saw_signal = true;
                }
            }
            if saw_local && saw_signal {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "timed out waiting for mode={expected_mode} (saw_local={saw_local}, saw_signal={saw_signal})"
        );
    };

    // 1) 初始无 ControllerMeta 时模式为 "remote_control"
    wait_mode(&mut client, "remote_control");

    // 2) 旧客户端发送 SetMediaPaused(true) -> active_controllers 与信令上报必须切为 "tools"
    let pause_payload =
        display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetMediaPaused { paused: true })
            .unwrap();
    client
        .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, pause_payload)
        .expect("send SetMediaPaused(true)");
    wait_mode(&mut client, "tools");

    // 3) 旧客户端发送 SetMediaPaused(false) -> 恢复为 "remote_control"
    let resume_payload =
        display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetMediaPaused { paused: false })
            .unwrap();
    client
        .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, resume_payload)
        .expect("send SetMediaPaused(false)");
    wait_mode(&mut client, "remote_control");

    client.close(ByeReason::Normal).expect("close client");
    host.stop();
    drop(sig_arc);
    let _ = stop_sig_tx.send(());
    srv_jh.join().unwrap();
}
