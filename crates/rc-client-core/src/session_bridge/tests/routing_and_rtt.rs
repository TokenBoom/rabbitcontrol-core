use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use rc_net::quic::{Identity, QuicEndpoint};
use rc_net::{NetConfig, NetEvent, NetStats, Role, Transport};
use rc_session::dev_cert::{DEV_CERT_PEM, DEV_KEY_PEM};

use crate::app_prefs::ConnectionMode;
use crate::lan_discovery;
use crate::p2p;
use crate::signal_client::ConnectGrant;
use crate::switchable_transport::TransportPathKind;

use super::super::classify::{classify_relay_connect_error, is_mtls_cert_or_config_error};
use super::super::handle::SessionHandle;
use super::super::routing::{
    build_client_p2p_candidates, collect_lan_candidate_addrs, dial_lan_addrs_happy_eyeballs,
    effective_connection_mode, path_kind_from_transport_label, punch_timeout_for_mode,
    race_lan_and_p2p_with, should_run_initial_bw_probe, sync_relay_rtt_ctrl_for_path,
    DirectTierRaceError, DirectTierWinner, RelayRttController, RELAY_RTT_MIN_BITRATE_BPS,
};
use super::super::types::{SessionUpdate, UiSessionConfig};

#[test]
fn ui_session_config_defaults_force_relay_to_false() {
    let json = serde_json::json!({
        "connect_addr": "127.0.0.1:9901",
        "watch_only": false,
        "width": 1920,
        "height": 1080,
        "fps": 60,
        "bitrate_bps": 14000000,
        "prefer_hardware": true
    });
    let cfg: UiSessionConfig = serde_json::from_value(json).expect("deserialize config");
    assert!(!cfg.force_relay);
    assert_eq!(cfg.connection_mode, ConnectionMode::Auto);
    assert!(!cfg.tools_only);
    assert!(cfg.clipboard_enabled);
    assert!(cfg.audio_enabled);
}

#[test]
fn collect_lan_candidate_addrs_filters_unusable_and_matches_local_subnets() {
    let direct: SocketAddr = "192.168.77.88:9901".parse().unwrap();
    let cfg = UiSessionConfig {
        lan_direct_addr: Some(direct),
        ..UiSessionConfig::default()
    };
    let mut peer_lan_addrs = vec![
        "127.0.0.1:40000".to_string(),
        "[::ffff:127.0.0.1]:40000".to_string(),
        "0.0.0.0:40000".to_string(),
        "169.254.12.34:40000".to_string(),
        "224.0.0.1:40000".to_string(),
        "255.255.255.255:40000".to_string(),
        "[fd00::10]:40000".to_string(),
    ];
    let probe_targets = vec![direct, "192.0.2.10:21116".parse().unwrap()];
    let local_ips = lan_discovery::detect_local_interface_ips_for_targets(&probe_targets);
    let local_v4s = local_ips.ipv4s;
    let expected_same_subnet = local_v4s.first().map(|local_ip| {
        let octets = local_ip.octets();
        let sibling = std::net::Ipv4Addr::new(
            octets[0],
            octets[1],
            octets[2],
            if octets[3] == 200 { 201 } else { 200 },
        );
        peer_lan_addrs.push(format!("{sibling}:51234"));
        SocketAddr::new(
            std::net::IpAddr::V4(sibling),
            crate::host_bridge::DEFAULT_HOST_PORT,
        )
    });

    let grant = ConnectGrant {
        session_id: "sess-lan".to_string(),
        target_id: "111222333".to_string(),
        relay_addr: "192.0.2.10:21117".to_string(),
        relay_token: "tok".to_string(),
        peer_lan_addrs,
        ..ConnectGrant::default()
    };
    let candidates = collect_lan_candidate_addrs(&cfg, &grant);
    assert_eq!(candidates.first().copied(), Some(direct));
    for addr in &candidates[1..] {
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            assert!(lan_discovery::is_usable_lan_ipv4(v4));
        }
    }
    if let Some(expected) = expected_same_subnet {
        assert!(candidates.contains(&expected));
    }
}

#[test]
fn error_classification_distinguishes_timeout_eof_reject_and_real_mtls() {
    assert!(!is_mtls_cert_or_config_error(
        "LAN 直连失败: unexpected eof"
    ));
    assert!(!is_mtls_cert_or_config_error(
        "P2P QUIC Client 握手失败：connection refused"
    ));
    assert!(is_mtls_cert_or_config_error(
        "LAN mTLS 证书校验失败: InvalidPeerCertificate(UnknownIssuer)"
    ));

    let pair_timeout = classify_relay_connect_error(
        &rc_types::Error::Timeout(Duration::from_secs(12)),
        true,
        true,
    );
    assert!(
        pair_timeout.contains("对端未响应中继配对"),
        "{pair_timeout}"
    );
    assert!(!pair_timeout.contains("mTLS"), "{pair_timeout}");

    let tcp_timeout = classify_relay_connect_error(
        &rc_types::Error::Network("connect relay tcp timed out".to_string()),
        true,
        true,
    );
    assert!(tcp_timeout.contains("连接中继服务器超时"), "{tcp_timeout}");
    assert!(!tcp_timeout.contains("mTLS"), "{tcp_timeout}");

    let eof_err = classify_relay_connect_error(
        &rc_types::Error::Network("relay stream hit EOF before completing handshake".to_string()),
        true,
        true,
    );
    assert!(eof_err.contains("对端已断开或拒绝连接"), "{eof_err}");
    assert!(!eof_err.contains("mTLS"), "{eof_err}");

    let reject_err = classify_relay_connect_error(
        &rc_types::Error::Network(
            "relay handshake rejected by 1.2.3.4:21117 (reply=0x01)".to_string(),
        ),
        true,
        true,
    );
    assert!(reject_err.contains("中继服务器拒绝配对"), "{reject_err}");
    assert!(!reject_err.contains("mTLS"), "{reject_err}");

    let cert_err = classify_relay_connect_error(
        &rc_types::Error::Network(
            "E2EE mTLS handshake failed: InvalidPeerCertificate(NotValidForName)".to_string(),
        ),
        true,
        true,
    );
    assert!(cert_err.contains("mTLS 证书身份校验失败"), "{cert_err}");
}

#[test]
fn relay_rtt_controller_backs_off_on_rtt_spike_and_recovers_when_clean() {
    let t0 = Instant::now();
    let mut ctrl = RelayRttController::new(14_000_000, t0);

    // 1) 基准 RTT = 22ms
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(1), 1, Some(22_000)),
        None
    );
    // 2) 单次孤立 RTT 尖峰不误降速；连续 2 次 RTT 膨胀至 95ms（> 22+45 且 > 44ms）才触发 0.75 回退 → 10.5M
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(3), 2, Some(95_000)),
        None
    );
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(4), 3, Some(95_000)),
        Some(10_500_000)
    );
    // 3) 连续 2 次正常 RTT（24ms <= 22+15ms）且冷却（1s）满足后迅速回升（+1/3 = 14.0M）
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(5), 4, Some(24_000)),
        None
    );
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(6), 5, Some(23_000)),
        Some(14_000_000)
    );
    // 4) 手动设定码率同步覆盖上限
    ctrl.on_manual_bitrate(8_000_000, t0 + Duration::from_secs(7));
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(10), 6, Some(22_000)),
        None
    );
}

#[test]
fn relay_rtt_controller_ages_min_rtt_after_permanent_baseline_shift() {
    let t0 = Instant::now();
    let mut ctrl = RelayRttController::new(14_000_000, t0);

    // 1) 初始低延迟基线 20ms
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(1), 1, Some(20_000)),
        None
    );

    // 2) 切换热点/路由后基线永久抬升至 75ms，窗口老化（10s）前持续回退
    let mut pong = 1u64;
    for sec in 2..=10 {
        pong += 1;
        let _ = ctrl.on_probe(t0 + Duration::from_secs(sec), pong, Some(75_000));
    }
    assert!(ctrl.current_bps < 14_000_000);

    // 3) 达到 10s 窗口后 min_rtt_us 自动老化刷新为 75ms，后续 75ms 探测可快速爬坡恢复满额
    let mut recovered = false;
    for sec in 11..=30 {
        pong += 1;
        if let Some(next) = ctrl.on_probe(t0 + Duration::from_secs(sec), pong, Some(75_000)) {
            if next > RELAY_RTT_MIN_BITRATE_BPS {
                recovered = true;
            }
        }
    }
    assert!(
        recovered,
        "min_rtt aging must allow recovery after baseline shift"
    );
    assert_eq!(ctrl.current_bps, 14_000_000);
}

#[test]
fn initial_bw_probe_runs_only_for_p2p_and_relay_rtt_ctrl_syncs_on_path_switch() {
    assert!(!should_run_initial_bw_probe(TransportPathKind::Lan));
    assert!(!should_run_initial_bw_probe(TransportPathKind::MtlsLan));
    assert!(!should_run_initial_bw_probe(TransportPathKind::Relay));
    assert!(should_run_initial_bw_probe(TransportPathKind::P2p));

    assert_eq!(
        path_kind_from_transport_label("UDP LAN"),
        TransportPathKind::Lan
    );
    assert_eq!(
        path_kind_from_transport_label("UDP LAN (mTLS)"),
        TransportPathKind::MtlsLan
    );
    assert_eq!(
        path_kind_from_transport_label("UDP P2P"),
        TransportPathKind::P2p
    );
    assert_eq!(
        path_kind_from_transport_label("TCP Relay"),
        TransportPathKind::Relay
    );

    let t0 = Instant::now();
    assert!(sync_relay_rtt_ctrl_for_path(TransportPathKind::Lan, 14_000_000, t0).is_none());
    assert!(sync_relay_rtt_ctrl_for_path(TransportPathKind::MtlsLan, 14_000_000, t0).is_none());
    assert!(sync_relay_rtt_ctrl_for_path(TransportPathKind::P2p, 14_000_000, t0).is_none());

    let mut ctrl = sync_relay_rtt_ctrl_for_path(TransportPathKind::Relay, 12_000_000, t0)
        .expect("Relay path must activate RelayRttController");
    assert_eq!(ctrl.cap_bps, 12_000_000);
    assert_eq!(ctrl.current_bps, 12_000_000);
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(1), 1, Some(20_000)),
        None
    );
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(2), 2, Some(90_000)),
        None,
        "单次 RTT 尖刺应经滞回防抖，不得立刻砍码率"
    );
    assert_eq!(
        ctrl.on_probe(t0 + Duration::from_secs(3), 3, Some(90_000)),
        Some(9_000_000)
    );

    // Switching Relay -> Lan disables RelayRttController; Lan -> Relay recreates a clean one.
    let disabled = sync_relay_rtt_ctrl_for_path(TransportPathKind::Lan, 12_000_000, t0);
    assert!(disabled.is_none());
    let reset = sync_relay_rtt_ctrl_for_path(TransportPathKind::Relay, 8_000_000, t0)
        .expect("Lan -> Relay must recreate RelayRttController");
    assert_eq!(reset.cap_bps, 8_000_000);
    assert_eq!(reset.current_bps, 8_000_000);
}

#[test]
fn p2p_only_fails_without_relay_fallback_and_is_not_recoverable() {
    // 1) 向后兼容：force_relay=true 覆盖 connection_mode 为 TcpRelay；否则按 connection_mode 生效。
    assert_eq!(
        effective_connection_mode(&UiSessionConfig {
            force_relay: true,
            connection_mode: ConnectionMode::P2pOnly,
            ..UiSessionConfig::default()
        }),
        ConnectionMode::TcpRelay
    );
    assert_eq!(
        effective_connection_mode(&UiSessionConfig {
            force_relay: false,
            connection_mode: ConnectionMode::P2pOnly,
            ..UiSessionConfig::default()
        }),
        ConnectionMode::P2pOnly
    );

    // 2) 本地监听一个探针 TCP 端口充当中继地址，验证 P2pOnly 失败时绝不拨号中继。
    let spy_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind spy relay");
    spy_listener
        .set_nonblocking(true)
        .expect("nonblocking spy listener");
    let spy_addr = spy_listener.local_addr().expect("spy local_addr");
    let relay_touched = Arc::new(AtomicBool::new(false));
    let spy_stop = Arc::new(AtomicBool::new(false));
    let t_touched = Arc::clone(&relay_touched);
    let t_stop = Arc::clone(&spy_stop);
    let spy_thread = thread::spawn(move || {
        while !t_stop.load(Ordering::Acquire) {
            match spy_listener.accept() {
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

    let session = SessionHandle::spawn(UiSessionConfig {
        connect_addr: "127.0.0.1:1".parse().unwrap(),
        connection_mode: ConnectionMode::P2pOnly,
        force_relay: false,
        tools_only: false,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        relay_grant: Some(ConnectGrant {
            session_id: "sess-p2p-only-no-fallback".to_string(),
            relay_addr: spy_addr.to_string(),
            relay_token: "unused-token".to_string(),
            target_id: "900000001".to_string(),
            peer_public_addr: None,
            peer_lan_addrs: Vec::new(),
            local_udp_port: None,
            ..ConnectGrant::default()
        }),
        ..UiSessionConfig::default()
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ended: Option<(String, bool)> = None;
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
    spy_stop.store(true, Ordering::Release);
    let _ = spy_thread.join();

    let (reason, recoverable) = ended.expect("P2pOnly 必须以 Ended 退出");
    assert!(
        reason.contains("仅 P2P") && reason.contains("未回退中继"),
        "错误文案应明确说明仅 P2P 未回退中继，实际：{reason}"
    );
    assert!(
        !recoverable,
        "P2pOnly 首次建连 P2P 失败必须 recoverable = false"
    );
    assert!(
        !relay_touched.load(Ordering::SeqCst),
        "P2pOnly 模式严禁向 Tier 3 TCP 中继发起连接"
    );
}

#[test]
fn punch_timeout_for_mode_uses_8s_for_p2p_only_and_2400ms_for_auto() {
    assert_eq!(
        punch_timeout_for_mode(ConnectionMode::P2pOnly),
        p2p::P2P_ONLY_PUNCH_TIMEOUT
    );
    assert_eq!(
        punch_timeout_for_mode(ConnectionMode::P2pOnly),
        Duration::from_secs(8)
    );
    assert_eq!(
        punch_timeout_for_mode(ConnectionMode::Auto),
        p2p::DEFAULT_PUNCH_TIMEOUT
    );
    assert_eq!(
        punch_timeout_for_mode(ConnectionMode::TcpRelay),
        p2p::DEFAULT_PUNCH_TIMEOUT
    );
}

#[test]
fn p2p_only_with_active_proxy_fails_fast_with_proxy_config_conflict() {
    struct GlobalProxyResetGuard;
    impl Drop for GlobalProxyResetGuard {
        fn drop(&mut self) {
            crate::proxy::set_global_proxy_config(crate::proxy::ProxyConfig::default());
        }
    }
    let _guard = GlobalProxyResetGuard;
    crate::proxy::set_global_proxy_config(crate::proxy::ProxyConfig {
        mode: crate::proxy::ProxyMode::Manual,
        protocol: Some(crate::proxy::ProxyProtocol::Socks5),
        host: "127.0.0.1".to_string(),
        port: 1080,
        username: None,
        password: None,
    });

    let session = SessionHandle::spawn(UiSessionConfig {
        connect_addr: "198.51.100.10:9901".parse().unwrap(),
        connection_mode: ConnectionMode::P2pOnly,
        force_relay: false,
        tools_only: true,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        relay_grant: Some(ConnectGrant {
            session_id: "sess-proxy-conflict".to_string(),
            relay_addr: "relay.corp.internal:21117".to_string(),
            relay_token: "unused".to_string(),
            target_id: "900000099".to_string(),
            ..ConnectGrant::default()
        }),
        ..UiSessionConfig::default()
    });

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut ended_ui_error = None;
    let mut ended_recoverable = true;
    while Instant::now() < deadline {
        if let Some(SessionUpdate::Ended {
            recoverable,
            ui_error,
            ..
        }) = session.try_recv_update()
        {
            ended_recoverable = recoverable;
            ended_ui_error = ui_error;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        !ended_recoverable,
        "P2pOnly + Proxy conflict must be fatal (non-recoverable)"
    );
    let ui_err = ended_ui_error.expect("SessionUpdate::Ended must include UiError");
    assert_eq!(ui_err.code, crate::ui_error::codes::PROXY_CONFIG_CONFLICT);
}

#[test]
fn collect_lan_candidate_addrs_prunes_rfc1918_when_public_ips_differ() {
    let probe_targets = vec!["192.0.2.10:21116".parse().unwrap()];
    let local_ips = lan_discovery::detect_local_interface_ips_for_targets(&probe_targets);
    let local_v4s = local_ips.ipv4s;
    let peer_same_subnet = local_v4s
        .first()
        .map(|local_ip| {
            let o = local_ip.octets();
            let last = if o[3] == 200 { 201 } else { 200 };
            format!("{}.{}.{}.{}:50000", o[0], o[1], o[2], last)
        })
        .unwrap_or_else(|| "192.168.1.88:50000".to_string());

    // 1) 公网 IP 明确不同且无 lan_direct_addr -> 彻底剪枝 RFC 1918 `/24` LAN 候选，消除黑洞等待
    let cfg_no_direct = UiSessionConfig::default();
    let grant_diff_pub = ConnectGrant {
        session_id: "sess-diff-pub".to_string(),
        target_id: "111222333".to_string(),
        relay_addr: "192.0.2.10:21117".to_string(),
        relay_token: "tok".to_string(),
        self_public_addr: Some("198.51.100.10:50000".to_string()),
        peer_public_addr: Some("203.0.113.20:60000".to_string()),
        peer_lan_addrs: vec![peer_same_subnet.clone(), "192.168.1.99:50000".to_string()],
        ..ConnectGrant::default()
    };
    assert!(
        collect_lan_candidate_addrs(&cfg_no_direct, &grant_diff_pub).is_empty(),
        "different public IPs without lan_direct_addr must prune RFC1918 LAN candidates"
    );

    // 2) 若显式配置了同网段 mDNS 发现的 lan_direct_addr，仍保留该显式地址
    let explicit_lan: SocketAddr = "192.168.77.88:9901".parse().unwrap();
    let cfg_with_direct = UiSessionConfig {
        lan_direct_addr: Some(explicit_lan),
        ..UiSessionConfig::default()
    };
    assert_eq!(
        collect_lan_candidate_addrs(&cfg_with_direct, &grant_diff_pub)[0],
        explicit_lan
    );

    // 3) 若公网 IP 相同（同 NAT 发夹或同局域网出口），保留同子网 LAN 候选
    if let Some(local_ip) = local_v4s.first() {
        let o = local_ip.octets();
        let sibling_ip =
            std::net::Ipv4Addr::new(o[0], o[1], o[2], if o[3] == 200 { 201 } else { 200 });
        let grant_same_pub = ConnectGrant {
            self_public_addr: Some("198.51.100.10:50000".to_string()),
            peer_public_addr: Some("198.51.100.10:50001".to_string()),
            ..grant_diff_pub.clone()
        };
        let cands = collect_lan_candidate_addrs(&cfg_no_direct, &grant_same_pub);
        assert!(cands.contains(&SocketAddr::new(
            std::net::IpAddr::V4(sibling_ip),
            crate::host_bridge::DEFAULT_HOST_PORT,
        )));

        // 4) 跨地址族（本端 IPv6 公网 vs 对端 IPv4 公网）时同族不可比，绝不误杀同局域网直连
        let grant_cross_family = ConnectGrant {
            self_public_addr: Some("[2001:db8::10]:50000".to_string()),
            peer_public_addr: Some("203.0.113.20:60000".to_string()),
            peer_public_addrs: vec!["203.0.113.20:60000".to_string()],
            ..grant_diff_pub.clone()
        };
        let cands_cross = collect_lan_candidate_addrs(&cfg_no_direct, &grant_cross_family);
        assert!(
            cands_cross.contains(&SocketAddr::new(
                std::net::IpAddr::V4(sibling_ip),
                crate::host_bridge::DEFAULT_HOST_PORT,
            )),
            "cross-family (IPv6 vs IPv4) public addrs must not prune same-subnet LAN candidates"
        );
    }

    // 5) peer_public_addr 为空但 peer_public_addrs 含不同 IPv4 时仍准确剪枝
    let grant_via_list = ConnectGrant {
        self_public_addr: Some("198.51.100.10:50000".to_string()),
        peer_public_addr: None,
        peer_public_addrs: vec![
            "[2001:db8::20]:60000".to_string(),
            "203.0.113.20:60000".to_string(),
        ],
        ..grant_diff_pub
    };
    assert!(collect_lan_candidate_addrs(&cfg_no_direct, &grant_via_list).is_empty());
}

#[test]
fn build_client_p2p_candidates_filters_cross_site_rfc1918_only() {
    let grant = ConnectGrant {
        session_id: "sess-filter".to_string(),
        target_id: "111222333".to_string(),
        relay_addr: "192.0.2.10:21117".to_string(),
        relay_token: "tok".to_string(),
        self_public_addr: Some("198.51.100.10:50000".to_string()),
        peer_public_addr: Some("203.0.113.20:60000".to_string()),
        peer_public_addrs: vec!["203.0.113.20:60000".to_string()],
        peer_lan_addrs: vec![
            "192.168.1.20:9901".to_string(),
            "10.0.0.8:9901".to_string(),
            "203.0.113.21:45000".to_string(),
            "[2001:db8::20]:9901".to_string(),
        ],
        ..ConnectGrant::default()
    };
    let p2p_cands = build_client_p2p_candidates(&grant);
    assert_eq!(
        p2p_cands.peer_lan_addrs,
        vec![
            "203.0.113.21:45000".to_string(),
            "[2001:db8::20]:9901".to_string(),
            "192.168.1.20:9901".to_string(),
            "10.0.0.8:9901".to_string(),
        ]
    );
}

#[test]
fn race_lan_and_p2p_cancels_loser_prefers_first_ok_and_fails_closed_on_mtls() {
    struct DropTrackTransport {
        dropped: Arc<AtomicBool>,
    }
    impl Transport for DropTrackTransport {
        fn send_datagram(&mut self, _data: &[u8]) -> rc_types::Result<()> {
            Ok(())
        }
        fn send_reliable(&mut self, _data: &[u8]) -> rc_types::Result<()> {
            Ok(())
        }
        fn send_reliable_urgent(&mut self, _data: &[u8]) -> rc_types::Result<()> {
            Ok(())
        }
        fn poll(&mut self, _timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
            Ok(Vec::new())
        }
        fn stats(&self) -> NetStats {
            NetStats::default()
        }
        fn set_pacing_rate(&mut self, _bps: u64) {}
        fn tx_queued_bytes(&self) -> usize {
            0
        }
        fn tx_dropped_datagrams(&self) -> u64 {
            0
        }
    }
    impl Drop for DropTrackTransport {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    let no_disc = AtomicBool::new(false);
    let lan_addr: SocketAddr = "192.168.1.20:9901".parse().unwrap();

    // 1) LAN 先成功 -> 立即置位 p2p_cancel，P2P 快速中止，采用 LAN 且 p2p_already_failed=false
    let p2p_saw_cancel = Arc::new(AtomicBool::new(false));
    let p2p_saw_cancel_bg = Arc::clone(&p2p_saw_cancel);
    let t0 = Instant::now();
    let res1 = race_lan_and_p2p_with(
        false,
        &no_disc,
        |_lan_cancel| {
            Ok((
                Box::new(DropTrackTransport {
                    dropped: Arc::new(AtomicBool::new(false)),
                }),
                None,
                lan_addr,
            ))
        },
        move |p2p_cancel| {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if p2p_cancel.load(Ordering::Acquire) {
                    p2p_saw_cancel_bg.store(true, Ordering::Release);
                    return Err(("cancelled".to_string(), None));
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(("timed out".to_string(), None))
        },
    );
    assert!(t0.elapsed() < Duration::from_millis(300));
    assert!(p2p_saw_cancel.load(Ordering::Acquire));
    assert!(matches!(
        res1,
        Ok(DirectTierWinner::Lan {
            p2p_already_failed: false,
            ..
        })
    ));

    // 2) P2P 先成功而 LAN 黑洞等待 -> 立即置位 lan_cancel，LAN 快速中止，采用 P2P
    let lan_saw_cancel = Arc::new(AtomicBool::new(false));
    let lan_saw_cancel_bg = Arc::clone(&lan_saw_cancel);
    let t1 = Instant::now();
    let res2 = race_lan_and_p2p_with(
        false,
        &no_disc,
        move |lan_cancel| {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if lan_cancel.load(Ordering::Acquire) {
                    lan_saw_cancel_bg.store(true, Ordering::Release);
                    return Err((vec!["cancelled".to_string()], None));
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err((vec!["timed out".to_string()], None))
        },
        |_p2p_cancel| {
            Ok((
                Box::new(DropTrackTransport {
                    dropped: Arc::new(AtomicBool::new(false)),
                }),
                None,
            ))
        },
    );
    assert!(t1.elapsed() < Duration::from_millis(300));
    assert!(lan_saw_cancel.load(Ordering::Acquire));
    assert!(matches!(res2, Ok(DirectTierWinner::P2p { .. })));

    // 3) LanOk 先到、P2pOk 稍晚到 -> 保持 LAN 且立即释放迟到 P2P 传输
    let p2p_dropped = Arc::new(AtomicBool::new(false));
    let p2p_dropped_bg = Arc::clone(&p2p_dropped);
    let (lan_done_tx, lan_done_rx) = mpsc::channel();
    let res3 = race_lan_and_p2p_with(
        false,
        &no_disc,
        move |_lan_cancel| {
            let _ = lan_done_tx.send(());
            Ok((
                Box::new(DropTrackTransport {
                    dropped: Arc::new(AtomicBool::new(false)),
                }),
                None,
                lan_addr,
            ))
        },
        move |p2p_cancel| {
            let _ = lan_done_rx.recv();
            while !p2p_cancel.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            Ok((
                Box::new(DropTrackTransport {
                    dropped: p2p_dropped_bg,
                }),
                None,
            ))
        },
    );
    assert!(matches!(
        res3,
        Ok(DirectTierWinner::Lan {
            p2p_already_failed: false,
            ..
        })
    ));
    assert!(
        p2p_dropped.load(Ordering::Acquire),
        "late P2P transport must be dropped when LanOk arrived first"
    );

    // 4) P2pOk 先到、LanOk 稍晚到 -> 保持先胜者 P2P 并丢弃迟到 LAN（绝不制造 Host 孤儿 P2P 会话）
    let lan_dropped = Arc::new(AtomicBool::new(false));
    let lan_dropped_bg = Arc::clone(&lan_dropped);
    let p2p_kept_dropped = Arc::new(AtomicBool::new(false));
    let p2p_kept_dropped_bg = Arc::clone(&p2p_kept_dropped);
    let (p2p_done_tx, p2p_done_rx) = mpsc::channel();
    let res4 = race_lan_and_p2p_with(
        false,
        &no_disc,
        move |lan_cancel| {
            let _ = p2p_done_rx.recv();
            while !lan_cancel.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            Ok((
                Box::new(DropTrackTransport {
                    dropped: lan_dropped_bg,
                }),
                None,
                lan_addr,
            ))
        },
        move |_p2p_cancel| {
            let _ = p2p_done_tx.send(());
            Ok((
                Box::new(DropTrackTransport {
                    dropped: p2p_kept_dropped_bg,
                }),
                None,
            ))
        },
    );
    assert!(matches!(res4, Ok(DirectTierWinner::P2p { .. })));
    assert!(
        lan_dropped.load(Ordering::Acquire),
        "late LAN transport must be dropped when P2pOk arrived first"
    );
    assert!(
        !p2p_kept_dropped.load(Ordering::Acquire),
        "winning P2P transport must stay alive"
    );
    drop(res4);

    // 5) P2P 先明确失败、随后 LAN 成功 -> p2p_already_failed=true（握手回退时不重复补试）
    let (p2p_fail_tx, p2p_fail_rx) = mpsc::channel();
    let res5 = race_lan_and_p2p_with(
        false,
        &no_disc,
        move |_lan_cancel| {
            let _ = p2p_fail_rx.recv();
            thread::sleep(Duration::from_millis(25));
            Ok((
                Box::new(DropTrackTransport {
                    dropped: Arc::new(AtomicBool::new(false)),
                }),
                None,
                lan_addr,
            ))
        },
        move |_p2p_cancel| {
            let _ = p2p_fail_tx.send(());
            Err(("punch failed".to_string(), None))
        },
    );
    assert!(matches!(
        res5,
        Ok(DirectTierWinner::Lan {
            p2p_already_failed: true,
            ..
        })
    ));

    // 6) 开启 mTLS 时任一侧出现证书校验失败 -> 严格 fail-closed 并取消另一侧
    let lan_cancelled_on_mtls = Arc::new(AtomicBool::new(false));
    let lan_cancelled_on_mtls_bg = Arc::clone(&lan_cancelled_on_mtls);
    let res6 = race_lan_and_p2p_with(
        true,
        &no_disc,
        move |lan_cancel| {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if lan_cancel.load(Ordering::Acquire) {
                    lan_cancelled_on_mtls_bg.store(true, Ordering::Release);
                    return Err((vec!["cancelled".to_string()], None));
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err((vec!["timed out".to_string()], None))
        },
        |_p2p_cancel| {
            Err((
                "InvalidPeerCertificate".to_string(),
                Some("P2P mTLS 证书校验失败（严禁静默降级）".to_string()),
            ))
        },
    );
    assert!(lan_cancelled_on_mtls.load(Ordering::Acquire));
    assert!(matches!(res6, Err(DirectTierRaceError::FatalMtls(_))));
}

#[test]
fn dial_lan_addrs_happy_eyeballs_does_not_block_on_unreachable_candidate() {
    // 启动一个真实测试 QUIC 服务端监听在 127.0.0.1:0
    let identity = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).unwrap();
    let net = NetConfig {
        role: Role::Host,
        local_addr: "127.0.0.1:0".parse().unwrap(),
        peer_addr: None,
        mtu: rc_session::DEFAULT_SESSION_MTU,
    };
    let host_ep = QuicEndpoint::new(&net, &identity).unwrap();
    let ok_addr = host_ep.local_addr().unwrap();
    let accept_jh = std::thread::spawn(move || {
        let _ = host_ep.accept(Duration::from_secs(2));
    });

    // 第一个候选为不可达 TEST-NET-1（黑洞，普通顺序拨号会阻塞满 LAN_DIRECT_PROBE_TIMEOUT=1500ms），
    // 第二个候选为可达的本地回环端口；Happy Eyeballs 并发必须在 <500ms 内命中 ok_addr
    let dead_addr: SocketAddr = "192.0.2.250:9901".parse().unwrap();
    let cancel = AtomicBool::new(false);
    let t0 = Instant::now();
    let (_t, _fp, won_addr) =
        dial_lan_addrs_happy_eyeballs(&[dead_addr, ok_addr], None, false, &cancel)
            .expect("Happy Eyeballs must succeed via reachable second LAN addr");
    let elapsed = t0.elapsed();
    accept_jh.join().unwrap();
    assert_eq!(won_addr, ok_addr);
    assert!(
        elapsed < Duration::from_millis(600),
        "dead first LAN candidate must not block second candidate for 1500ms, took {elapsed:?}"
    );
}
