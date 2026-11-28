use super::mock::*;
use super::*;

#[test]
fn p2p_handshake_fallback_eligibility_matches_transport_errors_only() {
    assert!(is_p2p_handshake_fallback_eligible(
        &rc_types::Error::Timeout(Duration::from_secs(5))
    ));
    assert!(is_p2p_handshake_fallback_eligible(
        &rc_types::Error::Network("peer disconnected".to_string())
    ));
    assert!(is_p2p_handshake_fallback_eligible(&rc_types::Error::Io(
        std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset")
    )));
    assert!(!is_p2p_handshake_fallback_eligible(
        &rc_types::Error::Protocol {
            offset: 0,
            msg: "authentication rejected".to_string(),
        }
    ));
    assert!(!is_p2p_handshake_fallback_eligible(
        &rc_types::Error::InvalidConfig("bad cfg".to_string())
    ));
}

#[test]
fn relay_incoming_purge_before_keeps_new_switch_tokens_from_same_peer() {
    let queue = BoundedRelayIncomingQueue::new(8);
    let make_item = |peer_id: &str, token: &str| RelayIncoming {
        session_id: format!("sess-{token}"),
        peer_id: peer_id.to_string(),
        relay_addr: "127.0.0.1:21117".to_string(),
        relay_token: token.to_string(),
        peer_public_addr: None,
        peer_lan_addrs: Vec::new(),
        local_udp_port: None,
        owner_grant: None,
        is_owner_connection: true,
        is_relay_alloc: false,
        ..RelayIncoming::default()
    };

    queue.push(make_item("111222333", "old-token"));
    thread::sleep(Duration::from_millis(10));
    let session_started_at = Instant::now();
    thread::sleep(Duration::from_millis(10));
    queue.push(make_item("111222333", "new-relay-switch-token"));
    queue.push(make_item("444555666", "other-peer-token"));

    queue.purge_for_peer_before(
        Some("111222333"),
        session_started_at,
        Duration::from_secs(30),
    );

    let first = queue
        .pop_ready(Duration::from_secs(30), Duration::ZERO)
        .expect("new switch token must survive purge");
    assert_eq!(first.relay_token, "new-relay-switch-token");
    let second = queue
        .pop_ready(Duration::from_secs(30), Duration::ZERO)
        .expect("other peer token must survive purge");
    assert_eq!(second.relay_token, "other-peer-token");
    assert!(queue
        .pop_ready(Duration::from_secs(30), Duration::ZERO)
        .is_none());
}

#[test]
fn relay_incoming_queue_supersedes_older_entry_from_same_peer_preserving_others() {
    let q = BoundedRelayIncomingQueue::new(4);
    let mk = |peer: &str, token: &str, lan: Vec<&str>| RelayIncoming {
        session_id: format!("sid-{token}"),
        peer_id: peer.to_string(),
        relay_addr: "127.0.0.1:21117".to_string(),
        relay_token: token.to_string(),
        peer_public_addr: None,
        peer_lan_addrs: lan.into_iter().map(str::to_string).collect(),
        local_udp_port: None,
        owner_grant: None,
        is_owner_connection: true,
        is_relay_alloc: false,
        ..RelayIncoming::default()
    };

    q.push(mk("111222333", "stale-lan-token", vec!["192.168.1.5:9901"]));
    q.push(mk("444555666", "other-peer-token", vec![]));
    q.push(mk("111222333", "fresh-relay-token", vec![]));

    let first = q
        .pop_ready(Duration::from_secs(20), Duration::from_millis(180))
        .expect("other peer entry preserved");
    assert_eq!(first.peer_id, "444555666");
    assert_eq!(first.relay_token, "other-peer-token");

    let second = q
        .pop_ready(Duration::from_secs(20), Duration::from_millis(180))
        .expect("fresh relay entry for peer 111222333 must immediately pop without lan_grace");
    assert_eq!(second.peer_id, "111222333");
    assert_eq!(second.relay_token, "fresh-relay-token");

    assert!(q
        .pop_ready(Duration::from_secs(20), Duration::from_millis(180))
        .is_none());
}

#[test]
fn lan_stale_signal_cutoff_purges_late_wan_signal_while_protecting_recent_switch() {
    let started = Instant::now();
    let ended_6s = started + Duration::from_secs(6);
    let cutoff = lan_stale_signal_cutoff(started, ended_6s);
    let late_wan_signal = started + Duration::from_millis(200);
    let recent_switch_signal = ended_6s - Duration::from_millis(100);
    assert!(
        late_wan_signal < cutoff,
        "late WAN PunchCoord arriving 200ms after LAN start must be purged"
    );
    assert!(
        recent_switch_signal >= cutoff,
        "fresh switch signal arriving right before disconnect must be preserved"
    );
}

#[test]
fn relay_incoming_has_preempt_candidate_covers_same_peer_idle_and_active_third_party() {
    let mk = |peer_id: &str, is_owner: bool, lan: Vec<&str>, is_relay_alloc: bool| RelayIncoming {
        session_id: format!("sid-{peer_id}"),
        peer_id: peer_id.to_string(),
        relay_addr: "127.0.0.1:21117".to_string(),
        relay_token: format!("tok-{peer_id}"),
        peer_public_addr: None,
        peer_lan_addrs: lan.into_iter().map(str::to_string).collect(),
        local_udp_port: None,
        owner_grant: None,
        is_owner_connection: is_owner,
        is_relay_alloc,
        ..RelayIncoming::default()
    };

    let ttl = Duration::from_secs(20);
    let q = BoundedRelayIncomingQueue::new(8);
    assert!(!q.has_preempt_candidate(ttl, Some("peer-a"), 0, false));

    // 1) 同设备重连：即使旧会话活跃（idle=0, !detached）也立即允许抢占。
    q.push(mk("peer-a", false, vec![], false));
    assert!(q.has_preempt_candidate(ttl, Some("peer-a"), 0, false));
    // 空 active_peer_id 不得误匹配。
    assert!(!q.has_preempt_candidate(ttl, Some(""), 0, false));

    // 过期条目自动忽略。
    thread::sleep(Duration::from_millis(5));
    assert!(!q.has_preempt_candidate(Duration::ZERO, Some("peer-a"), 0, false));

    // 2) 不同设备的普通协助连接：旧会话活跃（< 4s 且未 Detached）时拒绝抢占；>= 4s 或 Detached 时放行。
    let q_guest = BoundedRelayIncomingQueue::new(8);
    q_guest.push(mk("peer-b", false, vec![], false));
    assert!(!q_guest.has_preempt_candidate(ttl, Some("peer-a"), 0, false));
    assert!(!q_guest.has_preempt_candidate(ttl, Some("peer-a"), 2_999_999, false));
    assert!(!q_guest.has_preempt_candidate(ttl, Some("peer-a"), 3_500_000, false));
    assert!(q_guest.has_preempt_candidate(ttl, Some("peer-a"), 4_000_000, false));
    assert!(q_guest.has_preempt_candidate(ttl, Some("peer-a"), 0, true));

    // 3) 不同设备的同账号自控连接：活跃（< 3s 且未 Detached）时保护当前用户；>= 3s 或 Detached 时抢占。
    let q_owner = BoundedRelayIncomingQueue::new(8);
    q_owner.push(mk("peer-owner-2", true, vec![], false));
    assert!(!q_owner.has_preempt_candidate(ttl, Some("peer-a"), 0, false));
    assert!(!q_owner.has_preempt_candidate(ttl, Some("peer-a"), 2_999_999, false));
    assert!(q_owner.has_preempt_candidate(ttl, Some("peer-a"), 3_000_000, false));
    assert!(q_owner.has_preempt_candidate(ttl, Some("peer-a"), 0, true));

    // 4) LAN 刚建连的 3s 宽限期内：无论 peer_lan_addrs 是否为空、无论 idle 是否 >= 3s/4s、
    //    无论 Streaming 还是 Detached，同对端普通 PunchCoord（is_relay_alloc=false）一律忽略；
    //    仅当显式切中继（is_relay_alloc=true）或晚于宽限期的新请求才触发抢占。
    let q_lan_guard = BoundedRelayIncomingQueue::new(8);
    let session_started = Instant::now();
    let cutoff = session_started + LAN_STALE_SIGNAL_GRACE;
    q_lan_guard.push(mk("peer-a", true, vec![], false));
    assert!(!q_lan_guard.has_preempt_candidate_filtered(
        ttl,
        Some("peer-a"),
        0,
        false,
        Some(cutoff),
    ));
    assert!(!q_lan_guard.has_preempt_candidate_filtered(
        ttl,
        Some("peer-a"),
        5_000_000,
        false,
        Some(cutoff),
    ));
    assert!(!q_lan_guard.has_preempt_candidate_filtered(
        ttl,
        Some("peer-a"),
        0,
        true,
        Some(cutoff),
    ));
    q_lan_guard.push(mk("peer-a", true, vec![], true));
    assert!(q_lan_guard.has_preempt_candidate_filtered(
        ttl,
        Some("peer-a"),
        0,
        false,
        Some(cutoff),
    ));
    assert!(q_lan_guard.has_preempt_candidate_filtered(ttl, Some("peer-a"), 0, true, Some(cutoff),));

    // 5) 端到端验证：drive_ui_host_session_inner 检测到同设备新入站连接时迅速抢占退出且不删队列凭据。
    let clock: SessionClock = Arc::new(|| 10_000);
    let (mut host, _in_tx, _out_rx, _out_dgrams) = build_streaming_channel_host(Arc::clone(&clock));
    let incoming_q = Arc::new(BoundedRelayIncomingQueue::new(8));
    incoming_q.push(mk("peer-a", true, vec![], true));
    let t_q = Arc::clone(&incoming_q);
    let t_clock = Arc::clone(&clock);
    let stop_flag = Arc::new(AtomicBool::new(false));
    let t_stop = Arc::clone(&stop_flag);
    let started = Instant::now();
    let outcome = drive_ui_host_session_inner(
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
        HostTransportKind::Relay,
        false,
        false,
        false,
        &AtomicU64::new(0),
        None,
        &mut PersistentOwnerTerminals::new(),
        Arc::new(Mutex::new(None)),
        Arc::new(RwLock::new(None)),
        &AtomicBool::new(true),
        Some(&t_q),
        Some("peer-a"),
        started,
    );
    assert!(
        outcome.preempted_by_incoming,
        "same-peer RelayIncoming must preempt active Relay session"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "preemption must complete promptly, took {:?}",
        started.elapsed()
    );
    let preserved = incoming_q
        .pop_ready(ttl, Duration::ZERO)
        .expect("preempting RelayIncoming token must remain intact in queue");
    assert_eq!(preserved.peer_id, "peer-a");
}

#[test]
fn lan_stale_punch_coord_empty_addrs_never_preempts_and_is_purged_while_relay_alloc_and_post_grace_preempt(
) {
    let mk = |peer_id: &str, token: &str, lan: Vec<&str>, is_relay_alloc: bool| RelayIncoming {
        session_id: format!("sid-{token}"),
        peer_id: peer_id.to_string(),
        relay_addr: "127.0.0.1:21117".to_string(),
        relay_token: token.to_string(),
        peer_public_addr: None,
        peer_lan_addrs: lan.into_iter().map(str::to_string).collect(),
        local_udp_port: None,
        owner_grant: None,
        is_owner_connection: true,
        is_relay_alloc,
        ..RelayIncoming::default()
    };

    let ttl = Duration::from_secs(20);
    let q = BoundedRelayIncomingQueue::new(8);
    let session_started = Instant::now();
    let lan_grace_cutoff = session_started + Duration::from_millis(80);

    // 1) 同对端迟到的普通 PunchCoord（is_relay_alloc=false）即使 peer_lan_addrs 为空，
    //    在 Streaming（含 idle>=3s/4s）和 Detached 两态均绝不抢占。
    q.push(mk("peer-a", "stale-empty-lan", vec![], false));
    assert!(!q.has_preempt_candidate_filtered(
        ttl,
        Some("peer-a"),
        0,
        false,
        Some(lan_grace_cutoff),
    ));
    assert!(!q.has_preempt_candidate_filtered(
        ttl,
        Some("peer-a"),
        3_500_000,
        false,
        Some(lan_grace_cutoff),
    ));
    assert!(!q.has_preempt_candidate_filtered(
        ttl,
        Some("peer-a"),
        5_000_000,
        false,
        Some(lan_grace_cutoff),
    ));
    assert!(!q.has_preempt_candidate_filtered(
        ttl,
        Some("peer-a"),
        0,
        true,
        Some(lan_grace_cutoff),
    ));

    // 2) purge_stale_lan_punch_for_peer 主动清掉同对端陈旧 PunchCoord，同时保留其他对端条目。
    q.push(mk("peer-other", "other-token", vec![], false));
    q.purge_stale_lan_punch_for_peer(Some("peer-a"), lan_grace_cutoff, ttl);
    let remaining = q
        .pop_ready(ttl, Duration::ZERO)
        .expect("other peer entry must survive stale LAN punch purge");
    assert_eq!(remaining.peer_id, "peer-other");
    assert!(q.pop_ready(ttl, Duration::ZERO).is_none());

    // 3) 显式切中继（is_relay_alloc=true）在宽限期内也不被清理，且在 Streaming 与 Detached 均立即抢占。
    q.push(mk("peer-a", "explicit-relay", vec![], true));
    q.purge_stale_lan_punch_for_peer(Some("peer-a"), lan_grace_cutoff, ttl);
    assert!(q.has_preempt_candidate_filtered(
        ttl,
        Some("peer-a"),
        0,
        false,
        Some(lan_grace_cutoff),
    ));
    assert!(q.has_preempt_candidate_filtered(ttl, Some("peer-a"), 0, true, Some(lan_grace_cutoff),));
    let preserved_relay = q
        .pop_ready(ttl, Duration::ZERO)
        .expect("explicit RelayReady must survive stale LAN purge");
    assert_eq!(preserved_relay.relay_token, "explicit-relay");

    // 4) 明确晚于宽限期的新 PunchCoord（enqueued_at > lan_grace_cutoff）不被清理，且立即抢占。
    let past_cutoff = Instant::now();
    thread::sleep(Duration::from_millis(5));
    q.push(mk("peer-a", "post-grace-punch", vec![], false));
    q.purge_stale_lan_punch_for_peer(Some("peer-a"), past_cutoff, ttl);
    assert!(q.has_preempt_candidate_filtered(ttl, Some("peer-a"), 0, false, Some(past_cutoff),));
    assert!(q.has_preempt_candidate_filtered(ttl, Some("peer-a"), 0, true, Some(past_cutoff),));

    // 5) 端到端验证：LAN 会话驱动循环收到 peer_lan_addrs 为空的同源旧 PunchCoord 时绝不误抢占，
    //    且在 Streaming 巡检后主动将其从队列中清理干净。
    let clock: SessionClock = Arc::new(|| 10_000);
    let (mut host, _in_tx, _out_rx, _out_dgrams) = build_streaming_channel_host(Arc::clone(&clock));
    let incoming_q = Arc::new(BoundedRelayIncomingQueue::new(8));
    let started = Instant::now();
    incoming_q.push(mk("peer-a", "late-same-origin", vec![], false));
    let t_q = Arc::clone(&incoming_q);
    let t_clock = Arc::clone(&clock);
    let stop_flag = Arc::new(AtomicBool::new(false));
    let t_stop = Arc::clone(&stop_flag);
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
            &AtomicBool::new(true),
            Some(&t_q),
            Some("peer-a"),
            started,
        )
    });

    // 超过 PREEMPT_CHECK_INTERVAL (100ms) 后，旧 PunchCoord 应已被清理且会话未被误抢占。
    thread::sleep(Duration::from_millis(220));
    assert!(
        !driver.is_finished(),
        "stale same-peer PunchCoord with empty peer_lan_addrs must not preempt LAN session"
    );
    assert!(
        incoming_q.pop_ready(ttl, Duration::ZERO).is_none(),
        "stale same-peer PunchCoord must be actively purged during LAN Streaming"
    );

    stop_flag.store(true, Ordering::Release);
    let outcome = driver.join().expect("join driver");
    assert!(!outcome.preempted_by_incoming);
}

#[test]
fn build_host_p2p_candidates_filters_cross_site_private_lan_addrs() {
    let cross_site = RelayIncoming {
        session_id: "host-cross".to_string(),
        relay_addr: "192.0.2.10:21117".to_string(),
        relay_token: "tok".to_string(),
        peer_id: "111222333".to_string(),
        self_public_addr: Some("198.51.100.10:50000".to_string()),
        peer_public_addr: Some("203.0.113.20:60000".to_string()),
        peer_public_addrs: vec!["203.0.113.20:60000".to_string()],
        peer_lan_addrs: vec![
            "192.168.1.10:9901".to_string(),
            "172.16.5.20:9901".to_string(),
            "203.0.113.21:45000".to_string(),
            "[2001:db8::99]:9901".to_string(),
        ],
        self_nat_type: crate::nat::NatType::ApdmRandom,
        peer_nat_type: crate::nat::NatType::ApdmRandom,
        ..RelayIncoming::default()
    };
    let cands = build_host_p2p_candidates(&cross_site);
    assert_eq!(
        cands.peer_lan_addrs,
        vec![
            "203.0.113.21:45000".to_string(),
            "[2001:db8::99]:9901".to_string(),
            "192.168.1.10:9901".to_string(),
            "172.16.5.20:9901".to_string(),
        ]
    );

    let cross_family = RelayIncoming {
        self_public_addr: Some("[2001:db8::10]:50000".to_string()),
        peer_public_addr: Some("203.0.113.20:60000".to_string()),
        peer_public_addrs: vec!["203.0.113.20:60000".to_string()],
        ..cross_site
    };
    let cands_cf = build_host_p2p_candidates(&cross_family);
    assert_eq!(cands_cf.peer_lan_addrs.len(), 4);
}

#[test]
fn dial_relay_for_incoming_extracts_real_mtls_peer_cert_fingerprint() {
    use crate::relay_transport::tests::mtls_test_certs::TestCa;
    use crate::relay_transport::tests::{
        build_mock_mtls_relay_server_config, spawn_mock_mtls_relay_server,
    };
    use crate::relay_transport::{E2eeRelayTransport, RelayE2eeMode, RelayRole};

    let mut ca = TestCa::new("HostSwitchRelayCA");
    let (srv_cert, srv_key) = ca.issue_server_for_loopback();
    let (host_cert, host_key) = ca.issue_device("u1", "200000011");
    let (client_cert, client_key) = ca.issue_device("u1", "100000011");

    let srv_cfg = build_mock_mtls_relay_server_config(&ca.ca_pem, &srv_cert, &srv_key);
    let (relay_addr, relay_jh) = spawn_mock_mtls_relay_server(srv_cfg);

    let host_bundle = SessionMtlsBundle {
        ca_cert_pem: ca.ca_pem.clone(),
        cert_pem: host_cert,
        key_pem: host_key,
        local_user_id: "u1".to_string(),
        expected_peer_device_id: None,
        expected_peer_user_id: None,
    };
    let client_bundle = SessionMtlsBundle {
        ca_cert_pem: ca.ca_pem.clone(),
        cert_pem: client_cert,
        key_pem: client_key,
        local_user_id: "u1".to_string(),
        expected_peer_device_id: Some("200000011".to_string()),
        expected_peer_user_id: Some("u1".to_string()),
    };

    let cancel_c = Arc::new(AtomicBool::new(false));
    let relay_str = relay_addr.to_string();
    let client_bundle_c = client_bundle.clone();
    let token = "real-fp-relay-token".to_string();
    let token_c = token.clone();
    let client_jh = thread::spawn(move || {
        let relay_mtls = client_bundle_c.to_relay_mtls_config(None);
        E2eeRelayTransport::connect_cancellable(
            &relay_str,
            RelayRole::Client,
            &token_c,
            Duration::from_secs(5),
            cancel_c,
            Some(&relay_mtls),
            RelayE2eeMode::ClientRequired(client_bundle_c),
        )
    });

    let incoming = RelayIncoming {
        session_id: "sess-real-fp".to_string(),
        relay_addr: relay_addr.to_string(),
        relay_token: token,
        peer_id: "100000011".to_string(),
        is_owner_connection: true,
        ..RelayIncoming::default()
    };
    let updates = BoundedHostUpdateQueue::new(16);
    let active_relay_interrupt = Mutex::new(None);
    let session_cancel = Arc::new(AtomicBool::new(false));
    let disconnect_flag = AtomicBool::new(false);
    let stop_flag = AtomicBool::new(false);

    let (_transport, kind, _label, fp) = dial_relay_for_incoming(
        &incoming,
        Some(&host_bundle),
        true,
        &updates,
        &active_relay_interrupt,
        &session_cancel,
        &disconnect_flag,
        &stop_flag,
    )
    .expect("host E2EE relay dial must succeed");
    assert_eq!(kind, HostTransportKind::Relay);

    let client_res = client_jh.join().unwrap().expect("client E2EE relay dial");
    let fp_str = fp.expect("dial_relay_for_incoming must extract real SHA-256 fingerprint");
    assert_ne!(fp_str, "relay-mtls-verified");
    assert_eq!(fp_str.len(), 64);
    assert!(fp_str.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(client_res.peer_mtls_identity().is_some());

    drop(_transport);
    drop(client_res);
    let _ = relay_jh.join();
}

#[test]
fn bounded_relay_incoming_takeover_preempts_active_and_protects_non_takeover() {
    let q = BoundedRelayIncomingQueue::new(4);

    // 1) 非接管请求：活跃期间（idle_us=0, !detached）不得抢占不同设备
    q.push(make_test_relay_incoming("s-normal", "peer-b", true, false));
    assert_eq!(
        q.check_preempt_candidate_with_switch(
            Duration::from_secs(20),
            Some("peer-a"),
            0,
            false,
            None,
            false,
        ),
        PreemptDecision::None
    );
    // 有 lan_addrs 且刚入队，非接管请求需等待 lan_grace
    assert!(q
        .pop_ready(Duration::from_secs(20), Duration::from_secs(5))
        .is_none());
    assert!(!q.has_pending_takeover_or_same_peer(Some("peer-other"), Duration::from_secs(20)));
    assert!(q.has_pending_takeover_or_same_peer(Some("peer-b"), Duration::from_secs(20)));

    // 2) 未经 Owner 身份校验的伪造 takeover=true（is_owner_connection=false）不得触发接管
    let q_unverified = BoundedRelayIncomingQueue::new(4);
    q_unverified.push(make_test_relay_incoming("s-spoof", "peer-c", false, true));
    assert_eq!(
        q_unverified.check_preempt_candidate_with_switch(
            Duration::from_secs(20),
            Some("peer-a"),
            0,
            false,
            None,
            false,
        ),
        PreemptDecision::None
    );
    assert!(!q_unverified
        .has_pending_takeover_or_same_peer(Some("peer-other"), Duration::from_secs(20)));

    // 3) 合法同账号 takeover=true && is_owner_connection=true：
    //    无视 0us 活跃期立即返回 TakeoverOwner，插队排在普通请求前且跳过 lan_grace
    q.push(make_test_relay_incoming(
        "s-takeover",
        "peer-owner-2",
        true,
        true,
    ));
    assert_eq!(
        q.check_preempt_candidate_with_switch(
            Duration::from_secs(20),
            Some("peer-a"),
            0,
            false,
            None,
            false,
        ),
        PreemptDecision::TakeoverOwner
    );
    assert!(q.has_pending_takeover_or_same_peer(Some("peer-other"), Duration::from_secs(20)));
    let popped = q
        .pop_ready(Duration::from_secs(20), Duration::from_secs(5))
        .expect("owner takeover must bypass lan_grace and jump to front");
    assert_eq!(popped.session_id, "s-takeover");
}
