use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rc_input::InputEvent;
use rc_net::quic::{Identity, QuicEndpoint};
use rc_net::{NetConfig, NetEvent, NetStats, Role, Transport};
use rc_session::dev_cert::{DEV_CERT_PEM, DEV_KEY_PEM};
use rc_session::proto::{ControlMessage, SessionParams};
use rc_session::{ClientSession, ClientSessionConfig, SessionState};
use rc_types::Resolution;

use crate::app_prefs::ConnectionMode;
use crate::relay_transport::{RelayRole, SessionMtlsBundle, TcpRelayTransport};
use crate::signal_client::ConnectGrant;

use super::super::adapters::BridgeInputCapture;
use super::super::classify::{is_mtls_cert_or_config_error, should_fallback_after_handshake_error};
use super::super::connect::reanchorable_clock;
use super::super::handle::SessionHandle;
use super::super::queues::BoundedInputQueue;
use super::super::routing::LAN_DIRECT_HANDSHAKE_TIMEOUT;
use super::super::types::{SessionUpdate, UiSessionConfig};

#[test]
fn should_fallback_after_handshake_error_enforces_all_safety_redlines() {
    let pre_welcome_abort = rc_types::Error::Network(
        "disconnected while waiting for Welcome: aborted by peer".to_string(),
    );
    let pre_welcome_io = rc_types::Error::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "reset",
    ));

    // 1) 仅当尚未进入鉴权/审批交互且发生 Welcome 前底层连接断开/重置时允许回退。
    assert!(should_fallback_after_handshake_error(
        &pre_welcome_abort,
        false,
        false
    ));
    assert!(should_fallback_after_handshake_error(
        &pre_welcome_io,
        false,
        false
    ));

    // 2) 用户主动断开：严禁回退。
    assert!(!should_fallback_after_handshake_error(
        &pre_welcome_abort,
        false,
        true
    ));

    // 3) 已进入鉴权/审批交互（已收 Welcome{ChallengeRequired} 或 AuthChallenge）：
    //    无论是断连还是等待审批期超时，均严禁回退（防被控端连弹多个审批窗）。
    assert!(!should_fallback_after_handshake_error(
        &pre_welcome_abort,
        true,
        false
    ));
    assert!(!should_fallback_after_handshake_error(
        &rc_types::Error::Timeout(Duration::from_secs(45)),
        true,
        false
    ));

    // 4) Welcome 前半开黑洞超时（!entered_auth_or_approval）：允许回退下一级链路。
    assert!(should_fallback_after_handshake_error(
        &rc_types::Error::Timeout(LAN_DIRECT_HANDSHAKE_TIMEOUT),
        false,
        false
    ));

    // 5) 协议/鉴权拒绝/版本不兼容：严禁回退。
    assert!(!should_fallback_after_handshake_error(
        &rc_types::Error::Protocol {
            offset: 0,
            msg: "authentication rejected by host".to_string(),
        },
        false,
        false
    ));
    assert!(!should_fallback_after_handshake_error(
        &rc_types::Error::Network("protocol version incompatible".to_string()),
        false,
        false
    ));

    // 6) mTLS 证书校验失败（含客户端验服务端失败与服务端拒收客户端证书的 QUIC CRYPTO_ERROR alert）：严禁回退。
    assert!(!should_fallback_after_handshake_error(
        &rc_types::Error::Network("InvalidPeerCertificate(UnknownIssuer)".to_string()),
        false,
        false
    ));
    assert!(!should_fallback_after_handshake_error(
        &rc_types::Error::Network(
            "disconnected while waiting for Welcome: the cryptographic handshake failed: error 48"
                .to_string(),
        ),
        false,
        false
    ));
    assert!(is_mtls_cert_or_config_error(
        "the cryptographic handshake failed: error 42"
    ));
    assert!(is_mtls_cert_or_config_error("crypto error: unknown ca"));
    assert!(is_mtls_cert_or_config_error("certificate required"));

    // 7) 真实 ClientSession 状态机校验：收到 Welcome{ChallengeRequired} 进入审批等待后超时，
    //    handshake_entered_auth() 必须为 true，且绝不允许回退。
    {
        struct PendingApprovalMockTransport {
            sent_challenge_required: bool,
            session_id: u64,
        }
        impl Transport for PendingApprovalMockTransport {
            fn send_datagram(&mut self, _data: &[u8]) -> rc_types::Result<()> {
                Ok(())
            }
            fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
                if let Ok(ControlMessage::Hello(h)) = ControlMessage::decode(data) {
                    self.session_id = h.session_id;
                }
                Ok(())
            }
            fn send_reliable_urgent(&mut self, _data: &[u8]) -> rc_types::Result<()> {
                Ok(())
            }
            fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
                if !self.sent_challenge_required && self.session_id != 0 {
                    self.sent_challenge_required = true;
                    let mut buf = Vec::new();
                    ControlMessage::Welcome(rc_session::proto::Welcome {
                        session_id: self.session_id,
                        granted: SessionParams {
                            width: 640,
                            height: 360,
                            fps: 30,
                            bitrate_bps: 2_000_000,
                        },
                        auth_status: rc_session::proto::AuthStatus::ChallengeRequired,
                        host_flags: rc_session::proto::HostFlags(0),
                    })
                    .encode(&mut buf);
                    return Ok(vec![NetEvent::Reliable(buf)]);
                }
                thread::sleep(timeout.min(Duration::from_millis(15)));
                Ok(Vec::new())
            }
            fn stats(&self) -> NetStats {
                NetStats::default()
            }
            fn set_pacing_rate(&mut self, _bps: u64) {}
        }

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
        let t0 = Instant::now();
        let (clock, _) = reanchorable_clock(t0);
        let mut ccfg = ClientSessionConfig::new(
            "127.0.0.1:9901".parse().unwrap(),
            SessionParams {
                width: 640,
                height: 360,
                fps: 30,
                bitrate_bps: 2_000_000,
            },
            7777,
            Box::new(BridgeInputCapture {
                queue: Arc::new(BoundedInputQueue::new(16)),
                watch_only: Arc::new(AtomicBool::new(false)),
            }),
        );
        ccfg.handshake_timeout = Duration::from_secs(3);
        ccfg.auth.auth_timeout_us = 120_000; // 120ms 审批超时
        let mut client = ClientSession::with_parts(
            ccfg,
            Box::new(PendingApprovalMockTransport {
                sent_challenge_required: false,
                session_id: 0,
            }),
            Box::new(dummy_dec),
            Box::new(dummy_ren),
            clock,
        )
        .expect("client with_parts");
        let err = client
            .handshake()
            .expect_err("pending approval must time out");
        assert!(
            matches!(err, rc_types::Error::Timeout(_)),
            "expected Timeout during approval wait, got {err:?}"
        );
        assert!(
            client.handshake_entered_auth(),
            "Welcome{{ChallengeRequired}} must mark handshake_entered_auth = true"
        );
        assert!(
            !should_fallback_after_handshake_error(&err, client.handshake_entered_auth(), false),
            "approval timeout after Welcome{{ChallengeRequired}} must never fall back"
        );
    }
}

fn spawn_loopback_rcr1_relay_server(expected_token: String) -> (SocketAddr, JoinHandle<()>) {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock rcr1 relay");
    let addr = listener.local_addr().expect("mock relay addr");
    let handle = thread::spawn(move || {
        let Ok((mut s1, _)) = listener.accept() else {
            return;
        };
        let Ok((mut s2, _)) = listener.accept() else {
            return;
        };
        let _ = s1.set_nodelay(true);
        let _ = s2.set_nodelay(true);

        let read_hs = |s: &mut std::net::TcpStream| -> Option<u8> {
            let mut head = [0u8; 6];
            s.read_exact(&mut head).ok()?;
            if &head[0..4] != b"RCR1" {
                return None;
            }
            let role = head[4];
            let mut tok = vec![0u8; head[5] as usize];
            s.read_exact(&mut tok).ok()?;
            if std::str::from_utf8(&tok).ok()? != expected_token {
                return None;
            }
            Some(role)
        };
        let Some(r1) = read_hs(&mut s1) else {
            return;
        };
        let Some(r2) = read_hs(&mut s2) else {
            return;
        };
        if r1 == r2 {
            return;
        }
        if s1.write_all(&[0x00]).is_err() || s2.write_all(&[0x00]).is_err() {
            return;
        }
        let Ok(mut s1_r) = s1.try_clone() else {
            return;
        };
        let Ok(mut s2_w) = s2.try_clone() else {
            return;
        };
        let t1 = thread::spawn(move || {
            let _ = std::io::copy(&mut s1_r, &mut s2_w);
            let _ = s2_w.shutdown(Shutdown::Write);
        });
        let t2 = thread::spawn(move || {
            let _ = std::io::copy(&mut s2, &mut s1);
            let _ = s1.shutdown(Shutdown::Write);
        });
        let _ = t1.join();
        let _ = t2.join();
    });
    (addr, handle)
}

#[test]
fn tier1_lan_pre_welcome_disconnect_falls_back_to_relay_and_succeeds() {
    struct NoopInjector;
    impl rc_input::InputInjector for NoopInjector {
        fn inject(&mut self, _events: &[InputEvent]) -> rc_types::Result<()> {
            Ok(())
        }
        fn set_screen_size(&mut self, _width: u32, _height: u32) {}
    }

    // 1) Tier 1 模拟 LAN QUIC 端点：完成 QUIC 建连并收到 Hello 后，在发 Welcome 前主动关闭连接。
    let lan_id = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");
    let lan_ep = QuicEndpoint::new(
        &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
        &lan_id,
    )
    .expect("lan ep");
    let lan_addr = lan_ep.local_addr().expect("lan addr");
    let lan_saw_hello = Arc::new(AtomicBool::new(false));
    let t_lan_saw_hello = Arc::clone(&lan_saw_hello);
    let lan_thread = thread::spawn(move || {
        let mut transport = lan_ep
            .accept_with_handshake_timeout(Duration::from_secs(5), Duration::from_secs(5), None)
            .expect("lan accept");
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            for ev in transport.poll(Duration::from_millis(20)).expect("lan poll") {
                if matches!(ev, NetEvent::Reliable(_)) {
                    t_lan_saw_hello.store(true, Ordering::Release);
                    // 不发 Welcome，直接 drop 关闭连接，复现 Issue #4 场景。
                    return;
                }
            }
        }
    });

    // 2) Tier 3 模拟本地 RCR1 中继服务器 + 正常 HostSession。
    let token = "fallback-tok-1".to_string();
    let (relay_addr, relay_srv) = spawn_loopback_rcr1_relay_server(token.clone());
    let host_stop = Arc::new(AtomicBool::new(false));
    let t_host_stop = Arc::clone(&host_stop);
    let relay_addr_str = relay_addr.to_string();
    let host_thread = thread::spawn(move || {
        let transport = TcpRelayTransport::connect(
            &relay_addr_str,
            RelayRole::Host,
            &token,
            Duration::from_secs(5),
        )
        .expect("host connect relay");
        let (hclock, _) = reanchorable_clock(Instant::now());
        let caps = SessionParams {
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
        };
        let mut hcfg = rc_session::HostSessionConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            caps,
            Box::new(NoopInjector),
        );
        hcfg.handshake_timeout = Duration::from_secs(5);
        let cap = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
            display: rc_capture::DisplayInfo {
                id: rc_types::DisplayId(0),
                resolution: Resolution::new(640, 360),
                scale: 1.0,
                hdr: false,
            },
            fps: 30,
            content: rc_capture::FakeContent::Static,
            dirty_rect: None,
        })
        .expect("fake cap");
        let enc = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
            resolution: Resolution::new(640, 360),
            fps: 30,
            bitrate_bps: 2_000_000,
            ..rc_encode::EncoderConfig::default()
        })
        .expect("fake enc");
        let mut host = rc_session::HostSession::with_parts(
            hcfg,
            Box::new(transport),
            Box::new(cap),
            Box::new(enc),
            hclock,
        )
        .expect("host with_parts");
        host.handshake().expect("relay host handshake");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !t_host_stop.load(Ordering::Acquire) && Instant::now() < deadline {
            if host.tick(Duration::from_millis(10)).is_err() || host.state() == SessionState::Closed
            {
                break;
            }
        }
    });

    // 3) 控制端同时持有 Tier 1 LAN 地址与 Tier 3 Relay 凭据，验证自动回退至 TCP Relay 并握手成功。
    let session = SessionHandle::spawn(UiSessionConfig {
        connect_addr: "127.0.0.1:1".parse().unwrap(),
        lan_direct_addr: Some(lan_addr),
        width: 640,
        height: 360,
        fps: 30,
        bitrate_bps: 2_000_000,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        connection_mode: ConnectionMode::Auto,
        relay_grant: Some(ConnectGrant {
            session_id: "sess-lan-fallback".to_string(),
            relay_addr: relay_addr.to_string(),
            relay_token: "fallback-tok-1".to_string(),
            target_id: "900000002".to_string(),
            ..ConnectGrant::default()
        }),
        ..UiSessionConfig::default()
    });

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut negotiated_transport: Option<String> = None;
    while Instant::now() < deadline {
        if let Some(upd) = session.try_recv_update() {
            match upd {
                SessionUpdate::Negotiated { transport, .. } => {
                    negotiated_transport = Some(transport);
                    break;
                }
                SessionUpdate::Ended { reason, .. } => {
                    panic!("expected automatic fallback to TCP Relay, but ended early: {reason}");
                }
                _ => {}
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    host_stop.store(true, Ordering::Release);
    session.trigger_disconnect();
    session.join();
    let _ = lan_thread.join();
    let _ = host_thread.join();
    let _ = relay_srv.join();

    assert!(
        lan_saw_hello.load(Ordering::Acquire),
        "Tier 1 LAN must have been attempted and received Hello before closing"
    );
    assert_eq!(
        negotiated_transport.as_deref(),
        Some("TCP Relay"),
        "controller must fall back to Tier 3 TCP Relay after pre-Welcome LAN disconnect"
    );
}

#[test]
fn tier1_lan_auth_reject_mtls_p2p_only_and_post_challenge_never_fallback_to_relay() {
    use crate::relay_transport::tests::mtls_test_certs::TestCa;
    use rc_session::proto::{AuthChallenge, AuthStatus, HostFlags, Welcome};

    fn spawn_spy_relay() -> (SocketAddr, Arc<AtomicBool>, Arc<AtomicBool>, JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind spy relay");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("spy addr");
        let touched = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let t_touched = Arc::clone(&touched);
        let t_stop = Arc::clone(&stop);
        let jh = thread::spawn(move || {
            while !t_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok(_) => {
                        t_touched.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (addr, touched, stop, jh)
    }

    fn wait_session_end(session: SessionHandle) -> (String, bool) {
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut ended = None;
        while Instant::now() < deadline {
            if let Some(SessionUpdate::Ended {
                reason,
                recoverable,
                ..
            }) = session.try_recv_update()
            {
                ended = Some((reason, recoverable));
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        session.join();
        ended.expect("session must terminate with Ended")
    }

    let dev_id = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");

    // 场景 A：鉴权拒绝（Welcome{Rejected}）绝不回退中继。
    {
        let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
        let lan_ep = QuicEndpoint::new(
            &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
            &dev_id,
        )
        .expect("lan ep");
        let lan_addr = lan_ep.local_addr().expect("lan addr");
        let lan_jh = thread::spawn(move || {
            let mut t = lan_ep
                .accept_with_handshake_timeout(Duration::from_secs(5), Duration::from_secs(5), None)
                .expect("lan accept");
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                for ev in t.poll(Duration::from_millis(20)).expect("poll") {
                    if let NetEvent::Reliable(bytes) = ev {
                        if let Ok(ControlMessage::Hello(h)) = ControlMessage::decode(&bytes) {
                            let mut out = Vec::new();
                            ControlMessage::Welcome(Welcome {
                                session_id: h.session_id,
                                granted: h.requested,
                                auth_status: AuthStatus::Rejected,
                                host_flags: HostFlags(0),
                            })
                            .encode(&mut out);
                            let _ = t.send_reliable(&out);
                            let _ = t.poll(Duration::from_millis(50));
                            return;
                        }
                    }
                }
            }
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: "127.0.0.1:1".parse().unwrap(),
            lan_direct_addr: Some(lan_addr),
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
            connection_mode: ConnectionMode::Auto,
            relay_grant: Some(ConnectGrant {
                session_id: "sess-auth-reject".to_string(),
                relay_addr: spy_addr.to_string(),
                relay_token: "unused".to_string(),
                target_id: "900000003".to_string(),
                ..ConnectGrant::default()
            }),
            ..UiSessionConfig::default()
        });
        let (reason, recoverable) = wait_session_end(session);
        spy_stop.store(true, Ordering::Release);
        let _ = spy_jh.join();
        let _ = lan_jh.join();
        assert!(!recoverable, "auth reject must be fatal: {reason}");
        assert!(
            !touched.load(Ordering::SeqCst),
            "auth rejection on Tier 1 must never fall back to Tier 3 relay"
        );
    }

    // 场景 B：已收到 Welcome{ChallengeRequired} + AuthChallenge 后对端断连/审批等待失败，绝不回退中继（防连弹审批窗）。
    {
        let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
        let lan_ep = QuicEndpoint::new(
            &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
            &dev_id,
        )
        .expect("lan ep");
        let lan_addr = lan_ep.local_addr().expect("lan addr");
        let lan_jh = thread::spawn(move || {
            let mut t = lan_ep
                .accept_with_handshake_timeout(Duration::from_secs(5), Duration::from_secs(5), None)
                .expect("lan accept");
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                for ev in t.poll(Duration::from_millis(20)).expect("poll") {
                    if let NetEvent::Reliable(bytes) = ev {
                        if let Ok(ControlMessage::Hello(h)) = ControlMessage::decode(&bytes) {
                            let mut w_buf = Vec::new();
                            ControlMessage::Welcome(Welcome {
                                session_id: h.session_id,
                                granted: h.requested,
                                auth_status: AuthStatus::ChallengeRequired,
                                host_flags: HostFlags(0),
                            })
                            .encode(&mut w_buf);
                            let _ = t.send_reliable(&w_buf);
                            let mut ch_buf = Vec::new();
                            ControlMessage::AuthChallenge(AuthChallenge {
                                salt: [0x42u8; 16],
                                iterations: 1_000,
                            })
                            .encode(&mut ch_buf);
                            let _ = t.send_reliable(&ch_buf);
                            // 等待控制端收到挑战并回复 AuthResponse 后再关闭连接。
                            let wait_resp = Instant::now() + Duration::from_secs(2);
                            while Instant::now() < wait_resp {
                                if t.poll(Duration::from_millis(20))
                                    .unwrap_or_default()
                                    .iter()
                                    .any(|e| matches!(e, NetEvent::Reliable(_)))
                                {
                                    break;
                                }
                            }
                            return;
                        }
                    }
                }
            }
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: "127.0.0.1:1".parse().unwrap(),
            lan_direct_addr: Some(lan_addr),
            password: Some("test-pass".to_string()),
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
            connection_mode: ConnectionMode::Auto,
            relay_grant: Some(ConnectGrant {
                session_id: "sess-post-challenge".to_string(),
                relay_addr: spy_addr.to_string(),
                relay_token: "unused".to_string(),
                target_id: "900000004".to_string(),
                ..ConnectGrant::default()
            }),
            ..UiSessionConfig::default()
        });
        let (_reason, recoverable) = wait_session_end(session);
        spy_stop.store(true, Ordering::Release);
        let _ = spy_jh.join();
        let _ = lan_jh.join();
        assert!(!recoverable);
        assert!(
            !touched.load(Ordering::SeqCst),
            "disconnect after AuthChallenge/approval prompt must never fall back to Tier 3 relay"
        );
    }

    // 场景 C：mTLS 证书校验失败绝不回退中继。
    {
        let mut client_ca = TestCa::new("ClientTrustedCA");
        let (c_cert, c_key) = client_ca.issue_device("u1", "100000010");
        let mut rogue_ca = TestCa::new("RogueHostCA");
        let (h_cert, h_key) = rogue_ca.issue_device("u1", "200000020");

        let host_bundle = SessionMtlsBundle {
            ca_cert_pem: rogue_ca.ca_pem.clone(),
            cert_pem: h_cert,
            key_pem: h_key,
            local_user_id: "u1".to_string(),
            expected_peer_device_id: None,
            expected_peer_user_id: None,
        };
        let client_bundle = SessionMtlsBundle {
            ca_cert_pem: client_ca.ca_pem.clone(),
            cert_pem: c_cert,
            key_pem: c_key,
            local_user_id: "u1".to_string(),
            expected_peer_device_id: Some("200000020".to_string()),
            expected_peer_user_id: None,
        };

        let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
        let lan_ep = QuicEndpoint::new_mtls(
            &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
            &host_bundle.to_quic_mtls_config().expect("host mtls"),
        )
        .expect("mtls lan ep");
        let lan_addr = lan_ep.local_addr().expect("mtls lan addr");
        let lan_jh = thread::spawn(move || {
            let _ = lan_ep.accept_with_handshake_timeout(
                Duration::from_secs(3),
                Duration::from_secs(2),
                None,
            );
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: "127.0.0.1:1".parse().unwrap(),
            lan_direct_addr: Some(lan_addr),
            encrypt_connection: true,
            mtls_config: Some(client_bundle),
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
            connection_mode: ConnectionMode::Auto,
            relay_grant: Some(ConnectGrant {
                session_id: "sess-mtls-fail".to_string(),
                relay_addr: spy_addr.to_string(),
                relay_token: "unused".to_string(),
                target_id: "200000020".to_string(),
                ..ConnectGrant::default()
            }),
            ..UiSessionConfig::default()
        });
        let (reason, recoverable) = wait_session_end(session);
        spy_stop.store(true, Ordering::Release);
        let _ = spy_jh.join();
        let _ = lan_jh.join();
        assert!(!recoverable, "mTLS failure must be fatal: {reason}");
        assert!(
            reason.contains("mTLS") || reason.contains("证书"),
            "expected mTLS error message, got: {reason}"
        );
        assert!(
            !touched.load(Ordering::SeqCst),
            "mTLS certificate verification failure must never fall back to Tier 3 relay"
        );
    }

    // 场景 D：P2pOnly 模式下 Tier 1 LAN 在 Welcome 前断连，绝不回退至 Tier 3 Relay。
    {
        let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
        let lan_ep = QuicEndpoint::new(
            &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
            &dev_id,
        )
        .expect("lan ep");
        let lan_addr = lan_ep.local_addr().expect("lan addr");
        let lan_jh = thread::spawn(move || {
            let mut t = lan_ep
                .accept_with_handshake_timeout(Duration::from_secs(5), Duration::from_secs(5), None)
                .expect("lan accept");
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if t.poll(Duration::from_millis(20))
                    .unwrap_or_default()
                    .iter()
                    .any(|e| matches!(e, NetEvent::Reliable(_)))
                {
                    return; // 收到 Hello 后不发 Welcome 直接断开
                }
            }
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: "127.0.0.1:1".parse().unwrap(),
            lan_direct_addr: Some(lan_addr),
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
            connection_mode: ConnectionMode::P2pOnly,
            relay_grant: Some(ConnectGrant {
                session_id: "sess-p2p-only-pre-welcome".to_string(),
                relay_addr: spy_addr.to_string(),
                relay_token: "unused".to_string(),
                target_id: "900000005".to_string(),
                ..ConnectGrant::default()
            }),
            ..UiSessionConfig::default()
        });
        let (reason, recoverable) = wait_session_end(session);
        spy_stop.store(true, Ordering::Release);
        let _ = spy_jh.join();
        let _ = lan_jh.join();
        assert!(!recoverable);
        assert!(
            reason.contains("仅 P2P") && reason.contains("未回退中继"),
            "expected P2pOnly refusal message, got: {reason}"
        );
        assert!(
            !touched.load(Ordering::SeqCst),
            "P2pOnly must never fall back to Tier 3 relay even after pre-Welcome LAN disconnect"
        );
    }

    // 场景 E：Tier 1 MtlsLan 服务端拒收非法客户端证书（客户端验过服务端证书并完成 TLS 1.3 ClientFinished，
    // 随后收到服务端 QUIC CRYPTO_ERROR alert），控制端绝不回退至 Tier 3 中继。
    {
        let mut trusted_ca = TestCa::new("TrustedHostCA");
        let (h_cert, h_key) = trusted_ca.issue_device("u-host", "200000030");
        let mut rogue_client_ca = TestCa::new("RogueClientCA");
        let (bad_c_cert, bad_c_key) = rogue_client_ca.issue_device("u-bad", "100000030");

        let host_bundle = SessionMtlsBundle {
            ca_cert_pem: trusted_ca.ca_pem.clone(),
            cert_pem: h_cert,
            key_pem: h_key,
            local_user_id: "u-host".to_string(),
            expected_peer_device_id: None,
            expected_peer_user_id: None,
        };
        // 客户端信任服务端 CA（所以客户端能通过服务端证书校验），但出示由 rogue_client_ca 签发的非法客户端证书。
        let rogue_client_bundle = SessionMtlsBundle {
            ca_cert_pem: trusted_ca.ca_pem.clone(),
            cert_pem: bad_c_cert,
            key_pem: bad_c_key,
            local_user_id: "u-bad".to_string(),
            expected_peer_device_id: Some("200000030".to_string()),
            expected_peer_user_id: None,
        };

        let (spy_addr, touched, spy_stop, spy_jh) = spawn_spy_relay();
        let lan_ep = QuicEndpoint::new_mtls(
            &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
            &host_bundle.to_quic_mtls_config().expect("host mtls"),
        )
        .expect("mtls lan ep");
        let lan_addr = lan_ep.local_addr().expect("mtls lan addr");
        let lan_stop = Arc::new(AtomicBool::new(false));
        let t_lan_stop = Arc::clone(&lan_stop);
        let lan_jh = thread::spawn(move || {
            let res = lan_ep.accept_with_handshake_timeout(
                Duration::from_secs(3),
                Duration::from_secs(2),
                None,
            );
            assert!(
                res.is_err(),
                "MtlsLan server must reject untrusted client certificate"
            );
            // 保持端点存活（对齐真实 HostListener::MtlsLan 行为），确保 QUIC CRYPTO_ERROR alert 完整送达对端。
            let wait_until = Instant::now() + Duration::from_secs(3);
            while !t_lan_stop.load(Ordering::Acquire) && Instant::now() < wait_until {
                thread::sleep(Duration::from_millis(10));
            }
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: "127.0.0.1:1".parse().unwrap(),
            lan_direct_addr: Some(lan_addr),
            encrypt_connection: true,
            mtls_config: Some(rogue_client_bundle),
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
            connection_mode: ConnectionMode::Auto,
            relay_grant: Some(ConnectGrant {
                session_id: "sess-server-reject-client-cert".to_string(),
                relay_addr: spy_addr.to_string(),
                relay_token: "unused".to_string(),
                target_id: "200000030".to_string(),
                ..ConnectGrant::default()
            }),
            ..UiSessionConfig::default()
        });
        let (reason, recoverable) = wait_session_end(session);
        lan_stop.store(true, Ordering::Release);
        spy_stop.store(true, Ordering::Release);
        let _ = spy_jh.join();
        let _ = lan_jh.join();
        assert!(
            !recoverable,
            "server client-cert rejection must be fatal: {reason}"
        );
        assert!(
            !touched.load(Ordering::SeqCst),
            "server rejecting client mTLS certificate must never fall back to Tier 3 relay: {reason}"
        );
    }
}

#[test]
fn tier1_lan_pre_welcome_blackhole_timeout_falls_back_to_relay_and_succeeds() {
    struct NoopInjector;
    impl rc_input::InputInjector for NoopInjector {
        fn inject(&mut self, _events: &[InputEvent]) -> rc_types::Result<()> {
            Ok(())
        }
        fn set_screen_size(&mut self, _width: u32, _height: u32) {}
    }

    // 1) Tier 1 LAN 完成 QUIC 建连并收到 Hello 后保持静默黑洞（既不发 Welcome 也不发 AuthChallenge），
    //    等待 3s 超时后控制端必须自动回退至 Tier 3 TCP Relay 成功握手。
    let lan_id = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");
    let lan_ep = QuicEndpoint::new(
        &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
        &lan_id,
    )
    .expect("lan ep");
    let lan_addr = lan_ep.local_addr().expect("lan addr");
    let lan_stop = Arc::new(AtomicBool::new(false));
    let t_lan_stop = Arc::clone(&lan_stop);
    let lan_saw_hello = Arc::new(AtomicBool::new(false));
    let t_lan_saw_hello = Arc::clone(&lan_saw_hello);
    let lan_thread = thread::spawn(move || {
        let mut transport = lan_ep
            .accept_with_handshake_timeout(Duration::from_secs(5), Duration::from_secs(5), None)
            .expect("lan accept");
        let deadline = Instant::now() + Duration::from_secs(8);
        while !t_lan_stop.load(Ordering::Acquire) && Instant::now() < deadline {
            if let Ok(events) = transport.poll(Duration::from_millis(20)) {
                if events.iter().any(|ev| matches!(ev, NetEvent::Reliable(_))) {
                    t_lan_saw_hello.store(true, Ordering::Release);
                }
            }
        }
    });

    let token = "fallback-timeout-tok-1".to_string();
    let (relay_addr, relay_srv) = spawn_loopback_rcr1_relay_server(token.clone());
    let host_stop = Arc::new(AtomicBool::new(false));
    let t_host_stop = Arc::clone(&host_stop);
    let relay_addr_str = relay_addr.to_string();
    let host_thread = thread::spawn(move || {
        let transport = TcpRelayTransport::connect(
            &relay_addr_str,
            RelayRole::Host,
            &token,
            Duration::from_secs(15),
        )
        .expect("host connect relay");
        let (hclock, _) = reanchorable_clock(Instant::now());
        let caps = SessionParams {
            width: 640,
            height: 360,
            fps: 30,
            bitrate_bps: 2_000_000,
        };
        let mut hcfg = rc_session::HostSessionConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            caps,
            Box::new(NoopInjector),
        );
        hcfg.handshake_timeout = Duration::from_secs(5);
        let cap = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
            display: rc_capture::DisplayInfo {
                id: rc_types::DisplayId(0),
                resolution: Resolution::new(640, 360),
                scale: 1.0,
                hdr: false,
            },
            fps: 30,
            content: rc_capture::FakeContent::Static,
            dirty_rect: None,
        })
        .expect("fake cap");
        let enc = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
            resolution: Resolution::new(640, 360),
            fps: 30,
            bitrate_bps: 2_000_000,
            ..rc_encode::EncoderConfig::default()
        })
        .expect("fake enc");
        let mut host = rc_session::HostSession::with_parts(
            hcfg,
            Box::new(transport),
            Box::new(cap),
            Box::new(enc),
            hclock,
        )
        .expect("host with_parts");
        host.handshake().expect("relay host handshake");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !t_host_stop.load(Ordering::Acquire) && Instant::now() < deadline {
            if host.tick(Duration::from_millis(10)).is_err() || host.state() == SessionState::Closed
            {
                break;
            }
        }
    });

    let session = SessionHandle::spawn(UiSessionConfig {
        connect_addr: "127.0.0.1:1".parse().unwrap(),
        lan_direct_addr: Some(lan_addr),
        width: 640,
        height: 360,
        fps: 30,
        bitrate_bps: 2_000_000,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        connection_mode: ConnectionMode::Auto,
        relay_grant: Some(ConnectGrant {
            session_id: "sess-lan-blackhole-fallback".to_string(),
            relay_addr: relay_addr.to_string(),
            relay_token: "fallback-timeout-tok-1".to_string(),
            target_id: "900000006".to_string(),
            ..ConnectGrant::default()
        }),
        ..UiSessionConfig::default()
    });

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut negotiated_transport: Option<String> = None;
    while Instant::now() < deadline {
        if let Some(upd) = session.try_recv_update() {
            match upd {
                SessionUpdate::Negotiated { transport, .. } => {
                    negotiated_transport = Some(transport);
                    break;
                }
                SessionUpdate::Ended { reason, .. } => {
                    panic!("expected automatic fallback after pre-Welcome timeout, ended early: {reason}");
                }
                _ => {}
            }
        }
        thread::sleep(Duration::from_millis(15));
    }

    lan_stop.store(true, Ordering::Release);
    host_stop.store(true, Ordering::Release);
    session.trigger_disconnect();
    session.join();
    let _ = lan_thread.join();
    let _ = host_thread.join();
    let _ = relay_srv.join();

    assert!(
        lan_saw_hello.load(Ordering::Acquire),
        "Tier 1 LAN must have received Hello before blackhole timeout"
    );
    assert_eq!(
        negotiated_transport.as_deref(),
        Some("TCP Relay"),
        "controller must fall back to Tier 3 TCP Relay after pre-Welcome blackhole timeout"
    );
}
