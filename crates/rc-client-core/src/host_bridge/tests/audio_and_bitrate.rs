use super::mock::*;
use super::*;

#[test]
fn relay_bitrate_controller_backs_off_on_queue_or_drops_and_ramps_back_up() {
    let t0 = Instant::now();
    let mut ctrl = RelayBitrateController::new(14_000_000, t0);

    // 1) 持续高排队 200ms + 冷却 500ms 后触发回退（×0.75 = 10.5 Mbps）
    assert_eq!(
        ctrl.poll(t0 + Duration::from_millis(50), 260 * 1024, 0),
        None
    );
    assert_eq!(
        ctrl.poll(t0 + Duration::from_millis(520), 260 * 1024, 0),
        Some(10_500_000)
    );

    // 2) 孤立 1-3 包瞬态淘汰不立即误杀码率；连续两拍或整帧级 (>=12 包) 淘汰才回退：10.5M * 0.75 = 7.875M
    assert_eq!(
        ctrl.poll(t0 + Duration::from_millis(1_100), 16 * 1024, 3),
        None
    );
    assert_eq!(
        ctrl.poll(t0 + Duration::from_millis(1_200), 16 * 1024, 5),
        Some(7_875_000)
    );

    // 3) 排队清空并维持低水位 >= 1s 后对称逐步爬坡恢复（+1/4）
    assert_eq!(
        ctrl.poll(t0 + Duration::from_millis(2_000), 8 * 1024, 5),
        None
    );
    let ramped = ctrl.poll(t0 + Duration::from_millis(2_300), 8 * 1024, 5);
    assert_eq!(ramped, Some(9_875_000));

    // 4) 用户手动下调码率后，上限同步刷新且不再超过新上限
    assert_eq!(
        ctrl.sync_external_caps(
            Some((1, 8_000_000)),
            None,
            8_000_000,
            t0 + Duration::from_millis(2_400),
        ),
        None
    );
    assert_eq!(ctrl.poll(t0 + Duration::from_millis(5_000), 0, 5), None);

    // 5) 控制端 RTT 探针要求降至 4M，且本机排队清空时不得覆盖抬高；
    //    随后即使控制端试图用 Probe 拉高至 7.5M，但宿主自身突发整帧淘汰回退至 6M 时必须立刻钳制回 6M。
    assert_eq!(
        ctrl.sync_external_caps(
            Some((1, 8_000_000)),
            Some(4_000_000),
            4_000_000,
            t0 + Duration::from_millis(5_100),
        ),
        None
    );
    assert_eq!(ctrl.poll(t0 + Duration::from_millis(8_000), 0, 5), None);
    assert_eq!(
        ctrl.sync_external_caps(
            Some((1, 8_000_000)),
            Some(7_000_000),
            7_000_000,
            t0 + Duration::from_millis(8_100),
        ),
        None
    );
    assert_eq!(
        ctrl.poll(t0 + Duration::from_millis(8_600), 0, 17),
        Some(6_000_000)
    );
    assert_eq!(
        ctrl.sync_external_caps(
            Some((1, 8_000_000)),
            Some(7_500_000),
            7_500_000,
            t0 + Duration::from_millis(8_700),
        ),
        Some(6_000_000)
    );

    // 6) 用户再次显式手选同数值 8M（manual_gen 递增为 2）：必须识别为新手动指令，
    //    重置本机/远端拥塞上限，不得在下一拍把 8M 覆回 6M。
    assert_eq!(
        ctrl.sync_external_caps(
            Some((2, 8_000_000)),
            None,
            8_000_000,
            t0 + Duration::from_millis(8_800),
        ),
        None
    );
    assert_eq!(ctrl.effective_bps(), 8_000_000);
}

#[test]
fn sync_host_bitrate_on_path_switch_clears_probe_and_restores_bitrate_leaving_relay() {
    use rc_session::proto::{AuthMethod, BitrateReason, ControlMessage, Hello, PROTOCOL_VERSION};
    use rc_session::testkit::MockTransport;

    let initial_bps = 12_000_000;
    let requested = SessionParams {
        width: 320,
        height: 240,
        fps: 30,
        bitrate_bps: initial_bps,
    };
    let mut mock = MockTransport::new();
    mock.deliver_reliable(&ControlMessage::Hello(Hello {
        version: PROTOCOL_VERSION,
        session_id: 99,
        requested,
        auth_method: AuthMethod::None,
        auth_payload: Vec::new(),
    }));
    let mut handle = mock.clone();

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
        bitrate_bps: initial_bps,
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
            bitrate_bps: initial_bps,
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
    let clock: SessionClock = Arc::new(|| 1_000);
    let mut host = HostSession::with_parts(
        cfg,
        Box::new(mock),
        Box::new(capture),
        Box::new(encoder),
        clock,
    )
    .expect("with_parts");
    host.handshake().expect("handshake");

    // 1) Simulate Relay remote probe lowering bitrate to 4 Mbps.
    handle.deliver_reliable(&ControlMessage::SetBitrate {
        bps: 4_000_000,
        reason: BitrateReason::Probe,
    });
    host.tick(Duration::ZERO).expect("tick");
    assert_eq!(host.last_remote_probe_bitrate_bps(), Some(4_000_000));
    assert_eq!(host.current_bitrate_bps(), 4_000_000);

    // 2) Switch Relay -> P2p (without manual bitrate): clears probe & restores initial 12 Mbps.
    let t0 = Instant::now();
    let ctrl =
        sync_host_bitrate_on_path_switch(&mut host, true, HostTransportKind::P2p, initial_bps, t0);
    assert!(ctrl.is_none());
    assert_eq!(host.last_remote_probe_bitrate_bps(), None);
    assert_eq!(host.current_bitrate_bps(), initial_bps);

    // 2b) P2p runs BwProbe -> SetBitrate(4M, Probe), then degrades P2p -> Relay:
    //     must clear probe, restore initial 12 Mbps before constructing RelayBitrateController,
    //     and initialize RelayBitrateController::effective_bps() == initial_bps.
    handle.deliver_reliable(&ControlMessage::SetBitrate {
        bps: 4_000_000,
        reason: BitrateReason::Probe,
    });
    host.tick(Duration::ZERO).expect("tick");
    assert_eq!(host.last_remote_probe_bitrate_bps(), Some(4_000_000));
    assert_eq!(host.current_bitrate_bps(), 4_000_000);

    let degraded_relay_ctrl = sync_host_bitrate_on_path_switch(
        &mut host,
        false,
        HostTransportKind::Relay,
        initial_bps,
        t0,
    )
    .expect("P2p -> Relay must activate RelayBitrateController");
    assert_eq!(host.last_remote_probe_bitrate_bps(), None);
    assert_eq!(host.current_bitrate_bps(), initial_bps);
    assert_eq!(degraded_relay_ctrl.effective_bps(), initial_bps);

    // 3) On Relay, receive manual 8 Mbps + probe 3 Mbps, then Relay -> Lan:
    //    must clear probe & restore to manual 8 Mbps (not initial 12 Mbps).
    handle.deliver_reliable(&ControlMessage::SetBitrate {
        bps: 8_000_000,
        reason: BitrateReason::Manual,
    });
    handle.deliver_reliable(&ControlMessage::SetBitrate {
        bps: 3_000_000,
        reason: BitrateReason::Probe,
    });
    host.tick(Duration::ZERO).expect("tick");
    assert_eq!(host.last_manual_bitrate_bps(), Some(8_000_000));
    assert_eq!(host.last_remote_probe_bitrate_bps(), Some(3_000_000));
    assert_eq!(host.current_bitrate_bps(), 3_000_000);

    let lan_ctrl =
        sync_host_bitrate_on_path_switch(&mut host, true, HostTransportKind::Lan, initial_bps, t0);
    assert!(lan_ctrl.is_none());
    assert_eq!(host.last_remote_probe_bitrate_bps(), None);
    assert_eq!(host.current_bitrate_bps(), 8_000_000);

    host.close(rc_session::proto::ByeReason::Normal)
        .expect("close");
}

#[test]
fn audio_capture_is_stopped_triggers_automatic_self_healing_and_resumes_sending() {
    // Part A：端到端验证旧 AudioCapture::is_stopped() == true 后自动停止旧采集器、
    // 300ms 后异步创建新采集器并恢复向对端发送 AudioFrame。
    let clock: SessionClock = Arc::new(|| 10_000);
    let (mut host, _in_tx, out_rx, _out_dgrams) = build_streaming_channel_host(Arc::clone(&clock));

    let cap1_stopped = Arc::new(AtomicBool::new(false));
    let cap1_stop_calls = Arc::new(AtomicU64::new(0));
    let rebuilt_count = Arc::new(AtomicU64::new(0));

    let cap1: Box<dyn AudioCapture> = Box::new(ScriptedAudioCapture {
        inner: rc_audio::FakeAudioCapture::new(),
        stopped: Arc::clone(&cap1_stopped),
        stop_calls: Arc::clone(&cap1_stop_calls),
    });
    let t_rebuilt = Arc::clone(&rebuilt_count);
    let audio_mgr = HostAudioManager::with_creator(
        true,
        Some(cap1),
        Arc::new(move || {
            t_rebuilt.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(rc_audio::FakeAudioCapture::new()))
        }),
    );

    let stop_flag = Arc::new(AtomicBool::new(false));
    let t_stop = Arc::clone(&stop_flag);
    let t_clock = Arc::clone(&clock);
    let driver = thread::spawn(move || {
        drive_ui_host_session_with_audio(
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
            &AtomicU64::new(0),
            None,
            &mut PersistentOwnerTerminals::new(),
            Arc::new(Mutex::new(None)),
            Arc::new(RwLock::new(None)),
            &AtomicBool::new(true),
            None,
            None,
            Instant::now(),
            audio_mgr,
            None,
        )
    });

    let wait_audio_seq = |rx: &mpsc::Receiver<Vec<u8>>, min_seq: u32, timeout: Duration| {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let rem = deadline.saturating_duration_since(Instant::now());
            if let Ok(raw) = rx.recv_timeout(rem.min(Duration::from_millis(20))) {
                if let Ok(rc_session::proto::ControlMessage::AudioFrame { seq, .. }) =
                    rc_session::proto::ControlMessage::decode(&raw)
                {
                    if seq >= min_seq {
                        return Some(seq);
                    }
                }
            }
        }
        None
    };

    // 1) 旧采集器先正常送出音频帧。
    let before_seq =
        wait_audio_seq(&out_rx, 1, Duration::from_secs(2)).expect("initial audio frames");

    // 2) 模拟改分辨率/切屏导致底层 SCStream 中止：cap1.is_stopped() -> true。
    cap1_stopped.store(true, Ordering::Release);

    // 等待旧采集器被 stop() 释放并完成异步自愈重建（~300ms）。
    let heal_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < heal_deadline && rebuilt_count.load(Ordering::Acquire) == 0 {
        thread::sleep(Duration::from_millis(15));
    }
    assert!(
        cap1_stop_calls.load(Ordering::Acquire) >= 1,
        "stopped audio capture must be explicitly stopped and replaced"
    );
    assert!(
        rebuilt_count.load(Ordering::Acquire) >= 1,
        "audio manager must spawn a replacement AudioCapture after 300ms"
    );

    // 排空重建前可能已入队的旧帧，确认新采集器持续产出递增 seq 的 AudioFrame。
    let mut max_seen = before_seq;
    while let Ok(raw) = out_rx.try_recv() {
        if let Ok(rc_session::proto::ControlMessage::AudioFrame { seq, .. }) =
            rc_session::proto::ControlMessage::decode(&raw)
        {
            max_seen = max_seen.max(seq);
        }
    }
    let after_seq = wait_audio_seq(&out_rx, max_seen.saturating_add(2), Duration::from_secs(2))
        .expect("replacement audio capture must resume sending AudioFrame packets");
    assert!(after_seq > max_seen);

    stop_flag.store(true, Ordering::Release);
    let _ = driver.join().expect("join driver");

    // Part B：验证初始化失败时的有界退避序列（300ms -> 1s -> 2s -> 2s）及 media_paused 抑制。
    let attempts = Arc::new(AtomicU64::new(0));
    let t_attempts = Arc::clone(&attempts);
    let mut mgr = HostAudioManager::with_creator(
        true,
        None,
        Arc::new(move || {
            t_attempts.fetch_add(1, Ordering::AcqRel);
            Err("locked screen".to_string())
        }),
    );
    let mut gate = AudioSilenceGate::default();
    let t0 = Instant::now();
    // 等待首次异步失败线程退出并被 poll 消费 -> 预约 t0 + 300ms，下次退避升至 1s。
    let wait_init_fail = Instant::now() + Duration::from_secs(1);
    while Instant::now() < wait_init_fail && mgr.retry_at.is_none() {
        mgr.poll_and_recover(t0, false, &mut gate);
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(mgr.retry_at, Some(t0 + Duration::from_millis(300)));
    assert_eq!(mgr.retry_backoff, Duration::from_secs(1));

    // 推进虚拟时间至 +300ms 触发第 2 次失败 -> 预约 +1s，下次退避升至 2s。
    let t1 = t0 + Duration::from_millis(300);
    mgr.poll_and_recover(t1, false, &mut gate);
    let wait_fail2 = Instant::now() + Duration::from_secs(1);
    while Instant::now() < wait_fail2 && mgr.retry_at.is_none() {
        mgr.poll_and_recover(t1, false, &mut gate);
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(mgr.retry_at, Some(t1 + Duration::from_secs(1)));
    assert_eq!(mgr.retry_backoff, Duration::from_secs(2));

    // 推进虚拟时间至 +1s 触发第 3 次失败 -> 封顶 2s。
    let t2 = t1 + Duration::from_secs(1);
    mgr.poll_and_recover(t2, false, &mut gate);
    let wait_fail3 = Instant::now() + Duration::from_secs(1);
    while Instant::now() < wait_fail3 && mgr.retry_at.is_none() {
        mgr.poll_and_recover(t2, false, &mut gate);
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(mgr.retry_at, Some(t2 + Duration::from_secs(2)));
    assert_eq!(mgr.retry_backoff, Duration::from_secs(2));

    // 显示器切换后退避重置为 300ms，且 media_paused == true 时绝不拉起自愈。
    mgr.reset_backoff_for_display_change(t2);
    assert_eq!(mgr.retry_backoff, Duration::from_millis(300));
    assert_eq!(mgr.retry_at, Some(t2 + Duration::from_millis(300)));
    let attempts_before_paused = attempts.load(Ordering::Acquire);
    mgr.poll_and_recover(t2 + Duration::from_secs(10), true, &mut gate);
    assert_eq!(
        attempts.load(Ordering::Acquire),
        attempts_before_paused,
        "media_paused must suppress audio self-healing retries"
    );
}

#[test]
fn host_audio_manager_immediate_stop_escalates_backoff_and_resets_after_stable_window() {
    let should_start_stopped = Arc::new(AtomicBool::new(true));
    let t_stopped_flag = Arc::clone(&should_start_stopped);
    let created = Arc::new(AtomicU64::new(0));
    let t_created = Arc::clone(&created);

    let mut mgr = HostAudioManager::with_creator(
        true,
        None,
        Arc::new(move || {
            t_created.fetch_add(1, Ordering::AcqRel);
            let stopped = Arc::new(AtomicBool::new(t_stopped_flag.load(Ordering::Acquire)));
            Ok(Box::new(ScriptedAudioCapture {
                inner: rc_audio::FakeAudioCapture::new(),
                stopped,
                stop_calls: Arc::new(AtomicU64::new(0)),
            }))
        }),
    );
    let mut gate = AudioSilenceGate::default();
    let t0 = Instant::now();

    // 第 1 次创建成功但刚创建即 is_stopped() -> 预约 +300ms，下次退避升至 1s。
    let wait1 = Instant::now() + Duration::from_secs(1);
    while Instant::now() < wait1 && mgr.capture.is_none() {
        mgr.poll_and_recover(t0, false, &mut gate);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(mgr.capture.is_some());
    mgr.poll_and_recover(t0 + Duration::from_millis(10), false, &mut gate);
    assert!(mgr.capture.is_none());
    assert_eq!(
        mgr.retry_at,
        Some(t0 + Duration::from_millis(10) + Duration::from_millis(300))
    );
    assert_eq!(mgr.retry_backoff, Duration::from_secs(1));

    // 第 2 次刚创建即 is_stopped() -> 不回退到 300ms，预约 +1s，下次退避升至 2s。
    let t1 = t0 + Duration::from_millis(310);
    mgr.poll_and_recover(t1, false, &mut gate);
    let wait2 = Instant::now() + Duration::from_secs(1);
    while Instant::now() < wait2 && mgr.capture.is_none() {
        mgr.poll_and_recover(t1, false, &mut gate);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(mgr.capture.is_some());
    assert_eq!(
        mgr.retry_backoff,
        Duration::from_secs(1),
        "receiving Ok(cap) must not prematurely reset retry_backoff before stable window"
    );
    mgr.poll_and_recover(t1 + Duration::from_millis(10), false, &mut gate);
    assert!(mgr.capture.is_none());
    assert_eq!(
        mgr.retry_at,
        Some(t1 + Duration::from_millis(10) + Duration::from_secs(1))
    );
    assert_eq!(mgr.retry_backoff, Duration::from_secs(2));

    // 第 3 次刚创建即 is_stopped() -> 预约 +2s，封顶 2s。
    let t2 = t1 + Duration::from_millis(1010);
    mgr.poll_and_recover(t2, false, &mut gate);
    let wait3 = Instant::now() + Duration::from_secs(1);
    while Instant::now() < wait3 && mgr.capture.is_none() {
        mgr.poll_and_recover(t2, false, &mut gate);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(mgr.capture.is_some());
    mgr.poll_and_recover(t2 + Duration::from_millis(10), false, &mut gate);
    assert!(mgr.capture.is_none());
    assert_eq!(
        mgr.retry_at,
        Some(t2 + Duration::from_millis(10) + Duration::from_secs(2))
    );
    assert_eq!(mgr.retry_backoff, Duration::from_secs(2));

    // 第 4 次创建健康采集器并稳定存活 >= 5s -> 退避复位回 300ms。
    should_start_stopped.store(false, Ordering::Release);
    let t3 = t2 + Duration::from_millis(2010);
    mgr.poll_and_recover(t3, false, &mut gate);
    let wait4 = Instant::now() + Duration::from_secs(1);
    while Instant::now() < wait4 && mgr.capture.is_none() {
        mgr.poll_and_recover(t3, false, &mut gate);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(mgr.capture.is_some());
    mgr.poll_and_recover(t3 + Duration::from_secs(4), false, &mut gate);
    assert_eq!(
        mgr.retry_backoff,
        Duration::from_secs(2),
        "backoff must remain elevated before reaching 5s stable window"
    );
    mgr.poll_and_recover(t3 + AUDIO_RECOVERY_STABLE_WINDOW, false, &mut gate);
    assert_eq!(
        mgr.retry_backoff, AUDIO_RECOVERY_INITIAL_BACKOFF,
        "backoff must reset to 300ms once capture survives >= 5s"
    );
    assert_eq!(created.load(Ordering::Acquire), 4);
}

#[test]
fn pure_tool_epoch_refresh_stays_detached_reanchors_clock_and_preserves_watchdog() {
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

    // 将饱和刷新阈值缩短至 150ms，确定性离线触发 Bye(Refresh) 跨纪元重建。
    host.set_reconnect(ReconnectConfig {
        resume_ttl: Duration::from_secs(6),
        refresh_guard_us: 150_000,
        ..ReconnectConfig::default()
    })
    .expect("set_reconnect");
    let addr = host.local_addr().expect("local_addr");

    let connect_client = |sid: u64| {
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
        let cclock: SessionClock = Arc::new(|| 0);
        let mut client = ClientSession::new(
            ccfg,
            DEV_CERT_PEM,
            DEV_KEY_PEM,
            DEV_CERT_PEM,
            "rabbitcontrol",
            cclock,
        )
        .expect("client new");
        let welcome = client.connect_and_handshake().expect("client handshake");
        (client, welcome)
    };

    let stop_flag = Arc::new(AtomicBool::new(false));
    let t_stop = Arc::clone(&stop_flag);
    let t_updates = Arc::clone(&updates);
    let t_clock_anchor = clock_anchor.clone();
    let host_thread = thread::spawn(move || {
        t_clock_anchor.reset_pending();
        host.accept_and_handshake(Duration::from_secs(3))
            .expect("host accept_and_handshake");
        // 进入纯工具模式（media_paused == true）。
        host.pause_media();
        assert!(host.is_media_paused());

        let outcome = drive_ui_host_session_inner(
            &mut host,
            &clock,
            Some(&t_clock_anchor),
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
            &AtomicBool::new(true),
            None,
            None,
            Instant::now(),
        );
        (outcome, host.reconnect_stats(), clock())
    });

    // 1) 初始连接建立后记录首纪元 Fake(anchor1)，再等待被控端在纯工具态满 150ms 触发 Bye(Refresh)。
    let (mut client1, _w1) = connect_client(9101);
    let first_anchor = match &*clock_anchor
        .origin
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    {
        ClockOrigin::Fake(a) => *a,
        other => panic!("expected Fake clock origin after first handshake, got {other:?}"),
    };
    let refresh_deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_refresh = false;
    while Instant::now() < refresh_deadline {
        match client1.tick(Duration::from_millis(10), Instant::now()) {
            Ok(rep) => {
                if matches!(
                    rep.closed,
                    Some(StopReason::ByeReceived(ByeReason::Refresh))
                ) || client1.state() == SessionState::Reconnecting
                {
                    saw_refresh = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    assert!(
        saw_refresh,
        "client1 must observe Bye(Refresh) while host is in pure-tool mode"
    );
    // 丢弃旧连接，让被控端进入 Detached 等待新纪元 Hello（不得因 media_paused 误退出！）。
    drop(client1);
    thread::sleep(Duration::from_millis(60));
    assert!(
        !host_thread.is_finished(),
        "pure-tool host must stay in Detached during Bye(Refresh) instead of breaking"
    );

    // 发起新纪元连接，验证新会话落成后 clock_origin 已重锚为严格更新的 Fake(anchor2) 而非复用旧零点。
    let (client2, _w2) = connect_client(9102);
    let second_anchor = match &*clock_anchor
        .origin
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    {
        ClockOrigin::Fake(a) => *a,
        other => panic!("expected Fake clock origin after epoch rebuild, got {other:?}"),
    };
    assert!(
        second_anchor > first_anchor,
        "clock_origin must be strictly re-anchored after Bye(Refresh) rebuild (first={first_anchor:?}, second={second_anchor:?})"
    );
    let clock_after_reconnect = make_session_clock(Arc::clone(&clock_anchor.origin))();
    assert!(
        clock_after_reconnect < 500_000,
        "re-anchored session clock must restart near 0, got {clock_after_reconnect}us"
    );
    let _ = client2;

    stop_flag.store(true, Ordering::Release);
    let (outcome, rstats, _final_clock) = host_thread.join().expect("join host_thread");
    assert!(
        rstats.refreshes >= 1 && rstats.rebuilds >= 1,
        "must record both refresh and rebuild across pure-tool epoch refresh: {rstats:?}"
    );
    assert_ne!(
        outcome.reason, "纯工具连接已断开",
        "pure-tool epoch refresh must not abort Detached with ordinary tool disconnect"
    );

    // 额外验证：纯工具态普通断线（非 Bye(Refresh)）仍立刻退出 Detached。
    let clock_plain: SessionClock = Arc::new(|| 10_000);
    let (mut host_plain, in_tx, _out_rx, _out_dgrams) =
        build_streaming_channel_host(Arc::clone(&clock_plain));
    host_plain.pause_media();
    in_tx
        .send(NetEvent::Disconnected {
            reason: "ordinary drop".to_string(),
        })
        .expect("send disconnect");
    let plain_outcome = drive_ui_host_session_inner(
        &mut host_plain,
        &clock_plain,
        None,
        &BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP),
        &AtomicU64::new(0),
        0,
        &AtomicU64::new(0),
        0,
        &AtomicBool::new(false),
        &AtomicBool::new(false),
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
        None,
        None,
        Instant::now(),
    );
    assert_eq!(plain_outcome.reason, "纯工具连接已断开");
}
