use super::mock::*;
use super::*;

#[test]
fn temp_code_is_8_unambiguous_alnum() {
    let forbidden = ['0', 'O', '1', 'I'];
    for _ in 0..32 {
        let code = generate_temp_code();
        assert_eq!(code.len(), TEMP_CODE_LEN);
        assert!(code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        for bad in forbidden {
            assert!(
                !code.contains(bad),
                "验证码不应包含易混淆字符 {bad}: {code}"
            );
        }
    }
}

#[test]
fn ui_approver_enforces_monotonic_generation_and_emits_updates() {
    let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
    let mut approver = UiApprover::new(Arc::clone(&updates), false, true);
    let req = ApprovalRequest {
        session_id: 77,
        remote_addr: "127.0.0.1:50000".parse().unwrap(),
        requested: SessionParams {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_bps: 12_000_000,
        },
        auth_method: rc_session::proto::AuthMethod::Password,
        password_verified: true,
    };

    // 第 1 次 submit → generation = 1，发射 ApprovalRequested。
    approver.submit(&req);
    match updates.try_pop() {
        Some(HostUpdate::ApprovalRequested(p)) => {
            assert_eq!(p.generation, 1);
            assert_eq!(p.session_id, 77);
            assert_eq!(p.requested_res, "1920x1080");
            assert_eq!(p.requested_fps, 60);
            assert!(p.password_verified);
        }
        other => panic!("expected ApprovalRequested, got {other:?}"),
    }

    // 错误代次被拒绝。
    assert!(!approver.resolve(999, true));
    assert_eq!(approver.poll_verdict(), None);

    // cancel 发射 ApprovalCancelled 并清除在途态。
    approver.cancel();
    assert_eq!(
        updates.try_pop(),
        Some(HostUpdate::ApprovalCancelled { generation: 1 })
    );
    // 过期代次 resolve 无效。
    assert!(!approver.resolve(1, true));

    // 第 2 次 submit → generation = 2，正确代次 resolve 生效。
    approver.submit(&req);
    match updates.try_pop() {
        Some(HostUpdate::ApprovalRequested(p)) => assert_eq!(p.generation, 2),
        other => panic!("expected second ApprovalRequested, got {other:?}"),
    }
    assert!(approver.resolve(2, true));
    assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Accepted));
}

/// 回归测试（U-M2）：`UiApprover::mark_stopped()` 置位粘性停机标记后，
/// 后续 `submit()` 不再发射 `ApprovalRequested`，`poll_verdict()` 立即返回 `Rejected`，
/// `resolve()` 恒返回 `false`。
#[test]
fn ui_approver_sticky_stop_rejects_future_submits_and_polls() {
    let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
    let mut approver = UiApprover::new(Arc::clone(&updates), false, true);
    let req = ApprovalRequest {
        session_id: 88,
        remote_addr: "127.0.0.1:50001".parse().unwrap(),
        requested: SessionParams {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_bps: 12_000_000,
        },
        auth_method: rc_session::proto::AuthMethod::None,
        password_verified: false,
    };

    // 停机前先标记 stopped。
    approver.mark_stopped();

    // 停机后再 submit：绝不推送 ApprovalRequested 弹窗。
    approver.submit(&req);
    assert_eq!(updates.try_pop(), None, "停机后不得发射 ApprovalRequested");

    // poll_verdict 立即返回 Rejected，resolve 返回 false。
    assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Rejected));
    assert!(!approver.resolve(1, true));
}

#[test]
fn ui_approver_auto_accepts_password_verified_without_emitting_prompt() {
    let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
    let mut approver = UiApprover::new(Arc::clone(&updates), true, true);
    let req_verified = ApprovalRequest {
        session_id: 91,
        remote_addr: "127.0.0.1:50010".parse().unwrap(),
        requested: SessionParams {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_bps: 12_000_000,
        },
        auth_method: rc_session::proto::AuthMethod::Password,
        password_verified: true,
    };

    // 密码已校验且启用 auto_accept_with_password：立即放行且绝不推送审批弹窗。
    approver.submit(&req_verified);
    assert_eq!(
        updates.try_pop(),
        None,
        "密码验证通过自动放行时不得推送 ApprovalRequested"
    );
    assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Accepted));
    assert_eq!(updates.try_pop(), None);

    // 若在 poll_verdict 之前调用 cancel，因未弹窗也不应推送冗余 ApprovalCancelled。
    approver.submit(&req_verified);
    approver.cancel();
    assert_eq!(updates.try_pop(), None);

    // 若关停远程协助，即使 auto_accept_with_password == true 且密码已验，submit 也必须立即拒绝。
    approver.set_remote_assist_enabled(false);
    approver.submit(&req_verified);
    assert_eq!(updates.try_pop(), None);
    assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Rejected));
    approver.set_remote_assist_enabled(true);

    // 无密码连接（password_verified == false）：仍须推送 ApprovalRequested 并等待人工裁决。
    let req_passwordless = ApprovalRequest {
        session_id: 92,
        remote_addr: "127.0.0.1:50011".parse().unwrap(),
        requested: SessionParams {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_bps: 12_000_000,
        },
        auth_method: rc_session::proto::AuthMethod::None,
        password_verified: false,
    };
    approver.submit(&req_passwordless);
    let generation = match updates.try_pop() {
        Some(HostUpdate::ApprovalRequested(p)) => {
            assert_eq!(p.session_id, 92);
            assert!(!p.password_verified);
            p.generation
        }
        other => panic!("无密码连接必须推送 ApprovalRequested，实际: {other:?}"),
    };
    assert_eq!(approver.poll_verdict(), None);
    assert!(approver.resolve(generation, true));
    assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Accepted));

    // 停机后即使 password_verified == true 也必须拒绝，绝不放行。
    approver.mark_stopped();
    approver.submit(&req_verified);
    assert_eq!(updates.try_pop(), None);
    assert_eq!(approver.poll_verdict(), Some(ApprovalVerdict::Rejected));
}

/// 回归测试（U-H1）：`drive_ui_host_session` 在 `Detached` 态下：
/// 1) 重连保持窗口到期（`DetachOutcome::TornDown`）时立刻退出并关闭会话；
/// 2) 密码版本变更（`password_version != observed_pw_ver`）时立刻退出并关闭会话。
#[test]
fn drive_ui_host_session_breaks_on_detached_torn_down_and_password_change() {
    use rc_session::proto::{AuthMethod, ControlMessage, Hello, PROTOCOL_VERSION};
    use rc_session::testkit::MockTransport;
    use rc_session::ReconnectConfig;
    use std::sync::atomic::AtomicU32;

    fn build_handshaken_offline(clock: SessionClock) -> HostSession {
        let requested = SessionParams {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 2_000_000,
        };
        let hello_msg = ControlMessage::Hello(Hello {
            version: PROTOCOL_VERSION,
            session_id: 1,
            requested,
            auth_method: AuthMethod::None,
            auth_payload: Vec::new(),
        });

        let mut mock = MockTransport::new();
        mock.deliver_reliable(&hello_msg);

        let capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
            display: rc_capture::DisplayInfo {
                id: rc_types::DisplayId(0),
                resolution: Resolution::new(320, 240),
                scale: 1.0,
                hdr: false,
            },
            fps: 30,
            content: rc_capture::FakeContent::Static,
            dirty_rect: None,
        })
        .expect("fake capture");
        let encoder = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
            resolution: Resolution::new(320, 240),
            fps: 30,
            bitrate_bps: 2_000_000,
            ..rc_encode::EncoderConfig::default()
        })
        .expect("fake encoder");

        let cfg = HostSessionConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            mtu: rc_session::DEFAULT_SESSION_MTU,
            caps: requested,
            pipeline: PipelineConfig {
                resolution: Resolution::new(320, 240),
                fps: 30,
                bitrate_bps: 2_000_000,
                prefer_hardware: false,
                target_latency_us: 22_000,
                trace_capacity: 64,
                diff: DiffMode::TrustPlatform,
                clock_origin_us: None,
                max_packet_payload: rc_pipeline::MAX_PAYLOAD,
                ..PipelineConfig::default()
            },
            handshake_timeout: Duration::from_secs(5),
            injector: Box::new(RecordingInjector::new()),
            pace_capture: false,
            auth: HostAuthConfig::default(),
            approver: Box::new(AutoApprover),
            tool_permissions: rc_session::ToolPermissions::all_allowed(),
        };
        let mut host = HostSession::with_parts(
            cfg,
            Box::new(mock),
            Box::new(capture),
            Box::new(encoder),
            clock,
        )
        .expect("with_parts");
        host.set_reconnect(ReconnectConfig {
            resume_ttl: Duration::from_millis(50),
            ..ReconnectConfig::default()
        })
        .expect("set_reconnect");
        host.handshake().expect("handshake");
        assert_eq!(host.state(), SessionState::Streaming);
        host
    }

    // 场景 A：Detached 窗口到期（TornDown）立即跳出驱动循环。
    let now_us = Arc::new(AtomicU32::new(10_000));
    let clk_a: SessionClock = {
        let n = Arc::clone(&now_us);
        Arc::new(move || n.load(Ordering::Acquire))
    };
    let mut host_a = build_handshaken_offline(Arc::clone(&clk_a));
    host_a.on_disconnected(10_000);
    assert_eq!(host_a.state(), SessionState::Detached);
    // 推进注入时钟超过 50ms resume_ttl。
    now_us.store(100_000, Ordering::Release);

    let updates_a = BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP);
    let pw_ver_a = AtomicU64::new(0);
    let cfg_ver_a = AtomicU64::new(0);
    let disc_a = AtomicBool::new(false);
    let stop_a = AtomicBool::new(false);
    let reason_a = drive_ui_host_session(
        &mut host_a,
        &clk_a,
        &updates_a,
        &pw_ver_a,
        0,
        &cfg_ver_a,
        0,
        &disc_a,
        &stop_a,
    );
    assert!(
        reason_a.contains("重连超时"),
        "TornDown 应返回重连超时原因，实际: {reason_a}"
    );
    assert_eq!(host_a.state(), SessionState::Closed);

    // 场景 B：Detached 期间密码版本变更，立即跳出以便重建监听。
    let clk_b: SessionClock = Arc::new(|| 10_000);
    let mut host_b = build_handshaken_offline(Arc::clone(&clk_b));
    host_b.on_disconnected(10_000);
    assert_eq!(host_b.state(), SessionState::Detached);

    let updates_b = BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP);
    let pw_ver_b = AtomicU64::new(1); // 与 observed_pw_ver = 0 不一致
    let cfg_ver_b = AtomicU64::new(0);
    let disc_b = AtomicBool::new(false);
    let stop_b = AtomicBool::new(false);
    let reason_b = drive_ui_host_session(
        &mut host_b,
        &clk_b,
        &updates_b,
        &pw_ver_b,
        0,
        &cfg_ver_b,
        0,
        &disc_b,
        &stop_b,
    );
    assert!(
        reason_b.contains("密码已变更"),
        "Detached 期间密码变更应立即跳出，实际: {reason_b}"
    );
    assert_eq!(host_b.state(), SessionState::Closed);

    // 场景 C：Detached 期间鉴权配置版本变更（如 set_allow_owner_control(false)），立即跳出以便重建监听并拦截后续重连。
    let clk_c: SessionClock = Arc::new(|| 10_000);
    let mut host_c = build_handshaken_offline(Arc::clone(&clk_c));
    host_c.on_disconnected(10_000);
    assert_eq!(host_c.state(), SessionState::Detached);

    let updates_c = BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP);
    let pw_ver_c = AtomicU64::new(0);
    let cfg_ver_c = AtomicU64::new(1); // 与 observed_cfg_ver = 0 不一致
    let disc_c = AtomicBool::new(false);
    let stop_c = AtomicBool::new(false);
    let reason_c = drive_ui_host_session(
        &mut host_c,
        &clk_c,
        &updates_c,
        &pw_ver_c,
        0,
        &cfg_ver_c,
        0,
        &disc_c,
        &stop_c,
    );
    assert!(
        reason_c.contains("鉴权配置已变更"),
        "Detached 期间鉴权配置变更应立即跳出，实际: {reason_c}"
    );
    assert_eq!(host_c.state(), SessionState::Closed);
}

/// 回归测试（U-M1）：`HostHandle::spawn` 返回后立即调用 `set_password`，
/// 工作线程因 `observed_pw_ver = 0` 必然检测到版本变化并使新密码生效。
#[test]
fn set_password_immediately_after_spawn_is_observed_by_worker() {
    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        password: Some("OLD-PASS-1".to_string()),
        approval_timeout_us: rc_session::auth::DEFAULT_AUTH_TIMEOUT_US,
        prefer_hardware: false,
        require_approval: false,
        auto_accept_with_password: false,
        auto_rotate_password: false,
        clipboard_enabled: false,
        audio_enabled: false,
        ..UiHostConfig::default()
    })
    .expect("spawn host");
    // 紧接 spawn 立即改密，覆盖 spawn → worker 启动竞态窗口。
    host.set_password(Some("NEW-PASS-2".to_string()));
    let addr = host.listen_addr();

    // 等待工作线程完成至多一轮 accept 分片（500ms）并重建 HostSession 使新密码生效。
    thread::sleep(Duration::from_millis(650));

    let client =
        crate::session_bridge::SessionHandle::spawn(crate::session_bridge::UiSessionConfig {
            connect_addr: addr,
            password: Some("NEW-PASS-2".to_string()),
            watch_only: true,
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            force_relay: false,
            relay_grant: None,
            ..crate::session_bridge::UiSessionConfig::default()
        });
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut negotiated = false;
    while Instant::now() < deadline {
        if let Some(upd) = client.try_recv_update() {
            match upd {
                crate::session_bridge::SessionUpdate::Negotiated { .. } => {
                    negotiated = true;
                    break;
                }
                crate::session_bridge::SessionUpdate::Ended { reason, .. } => {
                    panic!("使用新密码握手不应失败: {reason}");
                }
                _ => {}
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    client.send(crate::session_bridge::SessionCommand::Disconnect);
    client.join();
    host.stop();
    assert!(negotiated, "紧接 spawn 调用 set_password 后新密码必须生效");
}

#[test]
fn set_allow_owner_control_updates_state_and_rejects_in_flight_approval() {
    let def = UiHostConfig::default();
    assert!(def.allow_owner_control);
    assert!(format!("{def:?}").contains("allow_owner_control: true"));

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        require_approval: true,
        allow_owner_control: true,
        allow_remote_assist: true,
        ..UiHostConfig::default()
    })
    .expect("spawn host");

    // Submit a synthetic in-flight approval via the shared approver
    let mut approver_clone = host.approver.clone();
    approver_clone.submit(&ApprovalRequest {
        session_id: 42,
        remote_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 54321)),
        requested: SessionParams {
            width: 1280,
            height: 720,
            fps: 60,
            bitrate_bps: 4_000_000,
        },
        auth_method: rc_session::proto::AuthMethod::None,
        password_verified: false,
    });

    // Turning off allow_owner_control must immediately reject in-flight approval and gate future submits
    host.set_allow_owner_control(false);
    assert!(!host.auth_state.lock().unwrap().allow_owner_control);
    assert_eq!(
        approver_clone.poll_verdict(),
        Some(ApprovalVerdict::Rejected)
    );

    // Even if set_allow_remote_assist(true) is called while allow_owner_control == false,
    // approver must remain closed until allow_owner_control is re-enabled.
    host.set_allow_remote_assist(true);
    approver_clone.submit(&ApprovalRequest {
        session_id: 43,
        remote_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 54322)),
        requested: SessionParams {
            width: 1280,
            height: 720,
            fps: 60,
            bitrate_bps: 4_000_000,
        },
        auth_method: rc_session::proto::AuthMethod::None,
        password_verified: false,
    });
    assert_eq!(
        approver_clone.poll_verdict(),
        Some(ApprovalVerdict::Rejected)
    );

    // Re-enabling allow_owner_control restores allow_remote_assist gating
    host.set_allow_owner_control(true);
    assert!(host.auth_state.lock().unwrap().allow_owner_control);
    assert!(host.approver.state.lock().unwrap().remote_assist_enabled);

    host.stop();
}

#[test]
fn detached_set_allow_owner_control_false_rebuilds_listener_and_blocks_reconnect() {
    use rc_input::{InputCapture, InputEvent};
    use rc_session::{ClientAuthConfig, ClientSession, ClientSessionConfig};

    struct EmptyInput;
    impl InputCapture for EmptyInput {
        fn next_events(&mut self, _timeout: Duration) -> rc_types::Result<Vec<InputEvent>> {
            Ok(Vec::new())
        }
    }

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        password: None,
        require_approval: false,
        allow_owner_control: true,
        allow_remote_assist: true,
        ..UiHostConfig::default()
    })
    .expect("spawn host");
    let addr = host.listen_addr();

    let connect_once = |sid: u64| {
        let mut ccfg = ClientSessionConfig::new(
            addr,
            SessionParams {
                width: 64,
                height: 64,
                fps: 30,
                bitrate_bps: 1_000_000,
            },
            sid,
            Box::new(EmptyInput),
        );
        ccfg.handshake_timeout = Duration::from_secs(3);
        ccfg.connect_timeout = Duration::from_secs(3);
        ccfg.auth = ClientAuthConfig::default();
        let clock: SessionClock = Arc::new(|| 0);
        let mut client = ClientSession::new(
            ccfg,
            DEV_CERT_PEM,
            DEV_KEY_PEM,
            DEV_CERT_PEM,
            "rabbitcontrol",
            clock,
        )
        .expect("client new");
        client.connect_and_handshake().map(|_| client)
    };

    // 1) Initial connection succeeds, then abrupt drop (without Bye) pushes host into Detached
    let client1 = connect_once(7701).expect("initial handshake must succeed");
    let conn_deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_connected = false;
    while Instant::now() < conn_deadline {
        if matches!(
            host.try_recv_update(),
            Some(HostUpdate::ClientConnected { .. })
        ) {
            saw_connected = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(saw_connected, "host must observe initial ClientConnected");

    // Drop client without Bye so host transitions into Detached instead of Closed
    drop(client1);
    thread::sleep(Duration::from_millis(80));

    // 2) Flip allow_owner_control=false while Detached -> must break Detached and rebuild HostSession
    host.set_allow_owner_control(false);

    let rebuild_deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_disconnected = false;
    let mut saw_rebuilt_listening = false;
    while Instant::now() < rebuild_deadline {
        match host.try_recv_update() {
            Some(HostUpdate::ClientDisconnected { .. }) => saw_disconnected = true,
            Some(HostUpdate::Listening { .. }) if saw_disconnected => {
                saw_rebuilt_listening = true;
                break;
            }
            Some(_) => {}
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    assert!(
        saw_disconnected && saw_rebuilt_listening,
        "set_allow_owner_control(false) during Detached must promptly tear down and rebuild listener (disconnected={saw_disconnected}, listening={saw_rebuilt_listening})"
    );

    // 3) Reconnect attempt after rebuild must be rejected
    assert!(
        connect_once(7702).is_err(),
        "connection after allow_owner_control=false must be rejected"
    );

    host.stop();
}

#[test]
fn mtls_lan_survives_invalid_client_handshake_without_rebind_and_accepts_valid_client() {
    use crate::relay_transport::tests::mtls_test_certs::TestCa;
    use rc_session::{ClientAuthConfig, ClientSession, ClientSessionConfig};

    struct EmptyInput;
    impl rc_input::InputCapture for EmptyInput {
        fn next_events(
            &mut self,
            _timeout: Duration,
        ) -> rc_types::Result<Vec<rc_input::InputEvent>> {
            Ok(Vec::new())
        }
    }

    let mut ca = TestCa::new("MtlsLanHostCA");
    let (host_cert, host_key) = ca.issue_device("user-lan", "200000001");
    let (good_cert, good_key) = ca.issue_device("user-lan", "100000001");

    let mut rogue_ca = TestCa::new("RogueClientCA");
    let (rogue_cert, rogue_key) = rogue_ca.issue_device("attacker", "999999999");

    let host_bundle = SessionMtlsBundle {
        ca_cert_pem: ca.ca_pem.clone(),
        cert_pem: host_cert,
        key_pem: host_key,
        local_user_id: "user-lan".to_string(),
        expected_peer_device_id: None,
        expected_peer_user_id: None,
    };
    let good_bundle = SessionMtlsBundle {
        ca_cert_pem: ca.ca_pem.clone(),
        cert_pem: good_cert,
        key_pem: good_key,
        local_user_id: "user-lan".to_string(),
        expected_peer_device_id: Some("200000001".to_string()),
        expected_peer_user_id: Some("user-lan".to_string()),
    };
    let rogue_bundle = SessionMtlsBundle {
        ca_cert_pem: ca.ca_pem.clone(),
        cert_pem: rogue_cert,
        key_pem: rogue_key,
        local_user_id: "attacker".to_string(),
        expected_peer_device_id: Some("200000001".to_string()),
        expected_peer_user_id: None,
    };

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        password: None,
        prefer_hardware: false,
        require_approval: false,
        clipboard_enabled: false,
        audio_enabled: false,
        mtls_config: Some(host_bundle),
        accept_mtls_lan: true,
        ..UiHostConfig::default()
    })
    .expect("spawn MtlsLan host");

    // 1) 等待初始 Listening 事件并记录绑定端口。
    let listen_deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_initial_listening = false;
    while Instant::now() < listen_deadline {
        if let Some(HostUpdate::Listening { .. }) = host.try_recv_update() {
            saw_initial_listening = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(saw_initial_listening, "host must emit initial Listening");
    let host_addr = host.listen_addr();

    // 2) 非法客户端（不受信任 CA 签发的客户端证书）尝试 mTLS 握手：
    //    TLS 1.3 客户端在发出 ClientFinished 后可能先返回 Ok，随后立刻收到服务端拒收证书的
    //    TLS Alert / CONNECTION_CLOSE；无论在 connect 阶段或随后的 poll 阶段都必须被服务端拒连。
    let dev_id = rc_net::quic::Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");
    let rogue_ep = QuicEndpoint::new(
        &NetConfig::new(Role::Controller, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        &dev_id,
    )
    .expect("rogue ep");
    let rogue_mtls = rogue_bundle.to_quic_mtls_config().expect("rogue mtls cfg");
    match rogue_ep.connect_mtls(host_addr, &rogue_mtls, "", Duration::from_secs(2)) {
        Err(_) => {}
        Ok(mut rogue_t) => {
            let rej_deadline = Instant::now() + Duration::from_secs(2);
            let mut rejected = false;
            while Instant::now() < rej_deadline && !rejected {
                match rogue_t.poll(Duration::from_millis(20)) {
                    Ok(events) => {
                        if events
                            .iter()
                            .any(|ev| matches!(ev, NetEvent::Disconnected { .. }))
                        {
                            rejected = true;
                        }
                    }
                    Err(_) => {
                        rejected = true;
                    }
                }
            }
            assert!(
                rejected,
                "rogue untrusted client must be rejected by MtlsLan server"
            );
        }
    }
    drop(rogue_ep);

    // 等待短暂窗口，验证 MtlsLan 端点未触发重建（无额外 Listening 重绑事件，也无 ClientConnected，端口保持不变）。
    thread::sleep(Duration::from_millis(120));
    let mut rebind_listening_count = 0usize;
    let mut rogue_connected = false;
    while let Some(upd) = host.try_recv_update() {
        match upd {
            HostUpdate::Listening { .. } => rebind_listening_count += 1,
            HostUpdate::ClientConnected { .. } | HostUpdate::OwnerConnected { .. } => {
                rogue_connected = true;
            }
            _ => {}
        }
    }
    assert!(
        !rogue_connected,
        "rogue untrusted client must never reach ClientConnected"
    );
    assert_eq!(
        rebind_listening_count, 0,
        "single invalid client handshake must not rebuild MtlsLan endpoint"
    );
    assert_eq!(
        host.listen_addr(),
        host_addr,
        "MtlsLan endpoint address must stay unchanged after invalid client"
    );

    // 3) 随后合法 mTLS 客户端连接到同一地址，必须正常完成 mTLS + Hello/Welcome 握手。
    let good_ep = QuicEndpoint::new(
        &NetConfig::new(Role::Controller, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        &dev_id,
    )
    .expect("good ep");
    let good_mtls = good_bundle.to_quic_mtls_config().expect("good mtls cfg");
    let good_transport = good_ep
        .connect_mtls(host_addr, &good_mtls, "", Duration::from_secs(3))
        .expect("valid mTLS client must connect to surviving MtlsLan endpoint");
    assert_eq!(
        good_transport
            .peer_mtls_identity()
            .expect("peer identity")
            .device_id,
        "200000001"
    );

    let mut ccfg = ClientSessionConfig::new(
        host_addr,
        SessionParams {
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
        },
        4242,
        Box::new(EmptyInput),
    );
    ccfg.handshake_timeout = Duration::from_secs(3);
    ccfg.auth = ClientAuthConfig::default();
    let placeholder_res = Resolution::new(64, 64);
    let dummy_dec = rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
        resolution: placeholder_res,
        ..rc_decode::FakeDecoderConfig::default()
    })
    .expect("dummy dec");
    let dummy_ren = rc_render::FakeRenderer::new(rc_render::FakeRendererConfig {
        size: (placeholder_res.width, placeholder_res.height),
        ..rc_render::FakeRendererConfig::default()
    })
    .expect("dummy ren");
    let cclock: SessionClock = Arc::new(|| 0);
    let mut client = ClientSession::with_parts(
        ccfg,
        Box::new(good_transport),
        Box::new(dummy_dec),
        Box::new(dummy_ren),
        cclock,
    )
    .expect("client with_parts");
    let granted = client
        .handshake()
        .expect("valid client session handshake must succeed");
    assert_eq!(granted.width, 640);
    assert_eq!(granted.height, 360);

    let conn_deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_connected = false;
    while Instant::now() < conn_deadline {
        if let Some(HostUpdate::ClientConnected { remote_addr }) = host.try_recv_update() {
            assert!(
                remote_addr.contains("LAN mTLS"),
                "expected LAN mTLS label, got {remote_addr}"
            );
            saw_connected = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        saw_connected,
        "host must report ClientConnected for valid mTLS client"
    );

    drop(client);
    drop(good_ep);
    host.stop();
}

#[test]
fn accept_error_backoff_bounds_tight_loop_and_respects_stop_flag() {
    assert_eq!(accept_error_backoff(0), None);
    assert_eq!(accept_error_backoff(1), None);
    assert_eq!(accept_error_backoff(2), None);
    assert_eq!(accept_error_backoff(3), Some(Duration::from_millis(20)));
    assert_eq!(accept_error_backoff(4), Some(Duration::from_millis(40)));
    assert_eq!(accept_error_backoff(5), Some(Duration::from_millis(50)));
    assert_eq!(accept_error_backoff(100), Some(Duration::from_millis(50)));

    let stop = AtomicBool::new(true);
    let t0 = Instant::now();
    sleep_cancelable(Duration::from_secs(2), &stop);
    assert!(
        t0.elapsed() < Duration::from_millis(50),
        "sleep_cancelable must exit immediately when stop_flag is set"
    );
}

#[test]
fn host_handle_set_signal_client_updates_shared_runtime_slot_live() {
    let cfg = UiHostConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        prefer_hardware: false,
        require_approval: false,
        signal_client: None,
        ..UiHostConfig::default()
    };

    let mut handle = HostHandle::spawn(cfg).expect("spawn HostHandle");
    assert!(
        handle.signal_client.read().unwrap().is_none(),
        "initial signal_client slot must be None"
    );

    let sc1 = Arc::new(crate::signal_client::SignalClientHandle::spawn(
        crate::server_config::ServerConfig::default(),
        "host-sc1".to_string(),
        Vec::new(),
    ));
    handle.set_signal_client(Some(Arc::clone(&sc1)));
    let slot_after_set = handle.signal_client.read().unwrap().clone();
    assert!(
        slot_after_set
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(s, &sc1)),
        "set_signal_client(Some(sc1)) must update shared slot immediately"
    );

    let sc2 = Arc::new(crate::signal_client::SignalClientHandle::spawn(
        crate::server_config::ServerConfig::default(),
        "host-sc2".to_string(),
        Vec::new(),
    ));
    handle.set_signal_client(Some(Arc::clone(&sc2)));
    let slot_after_swap = handle.signal_client.read().unwrap().clone();
    assert!(
        slot_after_swap
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(s, &sc2)),
        "set_signal_client(Some(sc2)) must replace live slot"
    );

    handle.set_signal_client(None);
    assert!(
        handle.signal_client.read().unwrap().is_none(),
        "set_signal_client(None) must clear shared slot"
    );

    handle.stop();
}

#[test]
fn collect_host_lan_addrs_formats_multi_nic_and_global_v6_with_cap_16() {
    assert!(collect_host_lan_addrs(0).is_empty());

    let mut ips = lan_discovery::LocalInterfaceIps::default();
    for i in 1..=20u8 {
        ips.ipv4s.push(Ipv4Addr::new(192, 168, 10, i));
    }
    ips.global_ipv6s.push("2408:8207:1::5".parse().unwrap());
    let capped = format_host_lan_addrs_from_ips(&ips, DEFAULT_HOST_PORT);
    assert_eq!(capped.len(), 16);
    assert_eq!(capped[0], "192.168.10.1:9901");

    let mixed = lan_discovery::LocalInterfaceIps {
        ipv4s: vec![Ipv4Addr::new(192, 168, 1, 10), Ipv4Addr::new(100, 64, 0, 2)],
        global_ipv6s: vec!["2408:8207:1::5".parse().unwrap()],
    };
    assert_eq!(
        format_host_lan_addrs_from_ips(&mixed, 9901),
        vec![
            "192.168.1.10:9901".to_string(),
            "100.64.0.2:9901".to_string(),
            "[2408:8207:1::5]:9901".to_string(),
        ]
    );
}
