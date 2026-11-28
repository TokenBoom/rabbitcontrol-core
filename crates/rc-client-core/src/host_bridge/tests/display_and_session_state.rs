use super::mock::*;
use super::*;

#[test]
fn hidpi_set_stream_nonzero_clamps_6k_and_toggles_auto_hidpi() {
    let clock: SessionClock = Arc::new(|| 10_000);
    let fail_hevc = Arc::new(AtomicBool::new(false));
    let (host, in_tx, out_rx) =
        build_hidpi_channel_host(Arc::clone(&clock), 3008, 1692, 60, 144, fail_hevc);
    let platform_mock = TestHostPlatformMock::new(
        Resolution::new(3008, 1692),
        Resolution::new(6016, 3384),
        Vec::new(),
    );
    // 仅 (2560, 1440) 支持真切系统逻辑分辨率，backing 为 6K (6016x3384)，用于验证 5120x2880 封顶与 auto_hidpi_active=true；
    // 其他尺寸如 (3200, 1800) 将命中 switch_to 失败回退分支，验证 auto_hidpi_active=false 与第 4 参数 session_max_res。
    platform_mock.with_mode_switch(
        (2560, 1440),
        Resolution::new(2560, 1440),
        Resolution::new(6016, 3384),
    );

    let (stop_flag, driver) = spawn_hidpi_channel_driver(
        host,
        clock,
        TestHostMediaOverride {
            native_res: Resolution::new(3008, 1692),
            max_res: Resolution::new(6016, 3384),
            auto_hidpi: true,
            hevc_available: true,
            encode_caps: rc_pipeline::default_codec_capabilities(true),
            platform: Some(platform_mock),
        },
    );

    let init_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(m, DisplayControlMsg::Capabilities { .. })
    });
    assert!(init_msgs.iter().any(|m| matches!(
        m,
        DisplayControlMsg::Capabilities {
            max_width: 5120,
            max_height: 2880,
            display_width: 3008,
            display_height: 1692,
            display_hidpi: true,
            ..
        }
    )));

    // 1) switch_to(2560, 1440) 成功：6K backing (6016x3384) 必须被 clamp_display_max_res 封顶到 5120x2880，
    //    且 auto_hidpi_active=true 使后续 fps 切换仍按 HiDPI 预算重算（且不被 host.caps 3008x1692 截断）。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::SetStream {
            width: 2560,
            height: 1440,
            fps: 60,
            codec: Some("hevc".to_string()),
        },
    );
    let expected_60 = compute_hidpi_stream_target(
        Resolution::new(2560, 1440),
        Some(Resolution::new(5120, 2880)),
        60,
        rc_encode::Codec::Hevc,
    );
    assert_eq!(expected_60, Resolution::new(3840, 2160));
    let switch_ok_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::Capabilities {
                display_width: 2560,
                display_height: 1440,
                ..
            }
        )
    });
    assert!(
        switch_ok_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_width,
                current_height,
                max_width: 5120,
                max_height: 2880,
                display_width: 2560,
                display_height: 1440,
                display_hidpi: true,
                current_codec: Some(c),
                ..
            } if c == "hevc"
                && (*current_width, *current_height) == (expected_60.width, expected_60.height)
        )),
        "SetStream switch_to success must clamp 6K max_res to 5120x2880 and use HiDPI target: {switch_ok_msgs:?}"
    );

    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::SetStream {
            width: 0,
            height: 0,
            fps: 120,
            codec: None,
        },
    );
    let expected_120 = compute_hidpi_stream_target(
        Resolution::new(2560, 1440),
        Some(Resolution::new(5120, 2880)),
        120,
        rc_encode::Codec::Hevc,
    );
    let fps120_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_fps: 120,
                ..
            }
        )
    });
    assert!(fps120_msgs.iter().any(|m| matches!(
        m,
        DisplayControlMsg::Capabilities {
            current_width,
            current_height,
            current_fps: 120,
            ..
        } if (*current_width, *current_height) == (expected_120.width, expected_120.height)
    )));

    // 2) switch_to(3200, 1800) 失败回退：auto_hidpi_active 置 false，仍以 Some(session_max_res)=5120x2880 作为第 4 参数
    //    从而允许 3200x1800（高于 host.caps 3008x1692），且后续 SetStream(0,0,120) 保持 3200x1800 不被覆盖。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::SetStream {
            width: 3200,
            height: 1800,
            fps: 60,
            codec: Some("hevc".to_string()),
        },
    );
    let fallback_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_width: 3200,
                current_height: 1800,
                current_fps: 60,
                ..
            }
        )
    });
    assert!(fallback_msgs.iter().any(|m| matches!(
        m,
        DisplayControlMsg::Capabilities {
            current_width: 3200,
            current_height: 1800,
            max_width: 5120,
            max_height: 2880,
            ..
        }
    )));

    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::SetStream {
            width: 0,
            height: 0,
            fps: 120,
            codec: None,
        },
    );
    let manual_120_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_fps: 120,
                ..
            }
        )
    });
    assert!(
        manual_120_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_width: 3200,
                current_height: 1800,
                current_fps: 120,
                ..
            }
        )),
        "switch_to fallback must keep auto_hidpi_active=false on subsequent fps changes: {manual_120_msgs:?}"
    );

    stop_flag.store(true, Ordering::Release);
    let _ = driver.join();
}

#[test]
fn switch_display_and_virtual_display_preserve_accurate_display_hidpi_and_auto_hidpi() {
    let clock: SessionClock = Arc::new(|| 10_000);
    let fail_hevc = Arc::new(AtomicBool::new(false));
    let (host, in_tx, out_rx) =
        build_hidpi_channel_host(Arc::clone(&clock), 1512, 982, 60, 144, fail_hevc);
    let platform_mock = TestHostPlatformMock::new(
        Resolution::new(1512, 982),
        Resolution::new(3024, 1964),
        vec![crate::platform::PlatformDisplayInfo {
            id: 2,
            name: "External 1080p".to_string(),
            width: 1920,
            height: 1080,
            origin_x: 1512.0,
            origin_y: 0.0,
            is_main: false,
            is_virtual: false,
        }],
    );
    let (stop_flag, driver) = spawn_hidpi_channel_driver(
        host,
        clock,
        TestHostMediaOverride {
            native_res: Resolution::new(1512, 982),
            max_res: Resolution::new(3024, 1964),
            auto_hidpi: true,
            hevc_available: true,
            encode_caps: rc_pipeline::default_codec_capabilities(true),
            platform: Some(platform_mock),
        },
    );

    let _init = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(m, DisplayControlMsg::Capabilities { .. })
    });
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::ClientMediaCaps {
            decode_caps: rc_pipeline::default_codec_capabilities(true),
            refinement_caps: None,
            pref: crate::codec_selector::CodecSelectionPref::OfficeClear,
            supports_ext_codec_flags: true,
        },
    );
    let _ = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_width: 3024,
                current_height: 1964,
                display_hidpi: true,
                ..
            }
        )
    });

    // 1) SwitchDisplay 到非 HiDPI 副屏 (1920x1080)：不得误报 display_hidpi=true，且 auto_hidpi_active=false。
    send_display_ctrl_event(&in_tx, &DisplayControlMsg::SwitchDisplay { display_id: 2 });
    let sec_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::DisplaysState {
                active_display_id: 2,
                ..
            }
        )
    });
    assert!(
        sec_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_width: 1920,
                current_height: 1080,
                display_width: 1920,
                display_height: 1080,
                display_hidpi: false,
                ..
            }
        )),
        "secondary non-HiDPI display must report display_hidpi=false: {sec_msgs:?}"
    );

    // 2) CreateVirtualDisplay(hidpi=false)：不得合成 2x max_res，也不得误报 display_hidpi=true。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::CreateVirtualDisplay {
            width: 1920,
            height: 1080,
            hidpi: false,
        },
    );
    let v_non_hidpi_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::DisplaysState {
                active_display_id,
                ..
            } if *active_display_id != 1 && *active_display_id != 2
        )
    });
    let v_non_hidpi_id = v_non_hidpi_msgs
        .iter()
        .rev()
        .find_map(|m| match m {
            DisplayControlMsg::DisplaysState {
                active_display_id, ..
            } => Some(*active_display_id),
            _ => None,
        })
        .expect("must receive virtual display id");
    assert!(
        v_non_hidpi_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_width: 1920,
                current_height: 1080,
                max_width: 1920,
                max_height: 1080,
                display_width: 1920,
                display_height: 1080,
                display_hidpi: false,
                ..
            }
        )),
        "CreateVirtualDisplay(hidpi=false) must report max=1920x1080 and display_hidpi=false: {v_non_hidpi_msgs:?}"
    );

    // 3) CreateVirtualDisplay(hidpi=true)：正确上报 2x max_res 与 display_hidpi=true。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::CreateVirtualDisplay {
            width: 1920,
            height: 1080,
            hidpi: true,
        },
    );
    let v_hidpi_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::DisplaysState {
                active_display_id,
                ..
            } if *active_display_id != v_non_hidpi_id && *active_display_id > 2
        )
    });
    let v_hidpi_id = v_hidpi_msgs
        .iter()
        .find_map(|m| match m {
            DisplayControlMsg::DisplaysState {
                active_display_id, ..
            } => Some(*active_display_id),
            _ => None,
        })
        .expect("must receive hidpi virtual display id");
    assert!(
        v_hidpi_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::Capabilities {
                max_width: 3840,
                max_height: 2160,
                display_width: 1920,
                display_height: 1080,
                display_hidpi: true,
                ..
            }
        )),
        "CreateVirtualDisplay(hidpi=true) must report display_hidpi=true: {v_hidpi_msgs:?}"
    );

    // 4) SwitchDisplay 切回非 HiDPI 虚拟屏再切回 HiDPI 虚拟屏，验证 virtual_display_hidpi 状态追踪准确。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::SwitchDisplay {
            display_id: v_non_hidpi_id,
        },
    );
    let back_non_hi = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::DisplaysState {
                active_display_id,
                ..
            } if *active_display_id == v_non_hidpi_id
        )
    });
    assert!(
        back_non_hi.iter().any(|m| matches!(
            m,
            DisplayControlMsg::Capabilities {
                max_width: 1920,
                max_height: 1080,
                display_hidpi: false,
                ..
            }
        )),
        "SwitchDisplay back to non-HiDPI virtual display must report max=1920x1080, display_hidpi=false: {back_non_hi:?}"
    );

    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::SwitchDisplay {
            display_id: v_hidpi_id,
        },
    );
    let back_hi = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::DisplaysState {
                active_display_id,
                ..
            } if *active_display_id == v_hidpi_id
        )
    });
    assert!(back_hi.iter().any(|m| matches!(
        m,
        DisplayControlMsg::Capabilities {
            max_width: 3840,
            max_height: 2160,
            display_hidpi: true,
            ..
        }
    )));

    // 5) RemoveVirtualDisplay 移除当前激活的虚拟屏：自动回退主屏并恢复 auto_hidpi_active=true 与 3024x1964 直出。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::RemoveVirtualDisplay {
            display_id: v_hidpi_id,
        },
    );
    let removed_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::DisplaysState {
                active_display_id: 1,
                ..
            }
        )
    });
    assert!(
        removed_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_width: 3024,
                current_height: 1964,
                display_width: 1512,
                display_height: 982,
                display_hidpi: true,
                ..
            }
        )),
        "RemoveVirtualDisplay must restore main display HiDPI state: {removed_msgs:?}"
    );

    stop_flag.store(true, Ordering::Release);
    let _ = driver.join();
}

#[test]
fn detach_outcome_replaced_resets_display_and_auto_hidpi_state() {
    use rc_session::{ClientSession, ClientSessionConfig};

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
    host.update_caps_resolution(1512, 982);
    let addr = host.local_addr().expect("local_addr");

    let platform_mock = TestHostPlatformMock::new(
        Resolution::new(1512, 982),
        Resolution::new(3024, 1964),
        vec![crate::platform::PlatformDisplayInfo {
            id: 2,
            name: "External 1080p".to_string(),
            width: 1920,
            height: 1080,
            origin_x: 1512.0,
            origin_y: 0.0,
            is_main: false,
            is_virtual: false,
        }],
    );
    let stop_flag = Arc::new(AtomicBool::new(false));
    let t_stop = Arc::clone(&stop_flag);
    let t_updates = Arc::clone(&updates);
    let t_anchor = clock_anchor.clone();
    let host_thread = thread::spawn(move || {
        t_anchor.reset_pending();
        host.accept_and_handshake(Duration::from_secs(5))
            .expect("accept_and_handshake");
        drive_ui_host_session_with_media_override(
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
            &AtomicU64::new(0),
            None,
            &mut PersistentOwnerTerminals::new(),
            Arc::new(Mutex::new(None)),
            Arc::new(RwLock::new(None)),
            &AtomicBool::new(true),
            None,
            None,
            Instant::now(),
            TestHostMediaOverride {
                native_res: Resolution::new(1512, 982),
                max_res: Resolution::new(3024, 1964),
                auto_hidpi: true,
                hevc_available: true,
                encode_caps: rc_pipeline::default_codec_capabilities(true),
                platform: Some(platform_mock),
            },
        )
    });

    let make_client = |sid: u64| {
        let mut ccfg = ClientSessionConfig::new(
            addr,
            SessionParams {
                width: 0,
                height: 0,
                fps: 60,
                bitrate_bps: 30_000_000,
            },
            sid,
            Box::new(EmptyInput),
        );
        ccfg.handshake_timeout = Duration::from_secs(3);
        ccfg.connect_timeout = Duration::from_secs(3);
        ccfg.auth = rc_session::auth::ClientAuthConfig::default();
        let cclock: SessionClock = Arc::new(|| 0);
        ClientSession::new(
            ccfg,
            DEV_CERT_PEM,
            DEV_KEY_PEM,
            DEV_CERT_PEM,
            "rabbitcontrol",
            cclock,
        )
        .expect("client new")
    };

    // 1) client1 连接并切换至非 HiDPI 副屏 (display_id=2)，随后直接 drop 进入 Detached
    let mut client1 = make_client(7791);
    client1.connect_and_handshake().expect("client1 handshake");
    client1
        .send_tool_message(
            TOOL_CHANNEL_DISPLAY_CTRL,
            display_ctrl::encode_display_ctrl(&DisplayControlMsg::SwitchDisplay { display_id: 2 })
                .unwrap(),
        )
        .expect("send SwitchDisplay");

    let mut saw_sec = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !saw_sec {
        let _ = client1.tick(Duration::from_millis(10), Instant::now());
        for (ch, payload) in client1.drain_tool_messages() {
            if ch == TOOL_CHANNEL_DISPLAY_CTRL {
                if let Some(DisplayControlMsg::Capabilities {
                    display_width: 1920,
                    display_height: 1080,
                    display_hidpi: false,
                    ..
                }) = display_ctrl::decode_display_ctrl(&payload)
                {
                    saw_sec = true;
                }
            }
        }
    }
    assert!(
        saw_sec,
        "client1 must switch to secondary display 1920x1080"
    );
    drop(client1);
    thread::sleep(Duration::from_millis(80));

    // 2) client2 以全新 session_id 连接命中 DetachOutcome::Replaced：
    //    必须重置回主屏 (display_width=1512, display_height=982, display_hidpi=true, active_display_id=1)，
    //    且恢复 auto_hidpi_active=true 使 ClientMediaCaps(HEVC) 自动升级为 3024x1964。
    let mut client2 = make_client(7792);
    client2
        .connect_and_handshake()
        .expect("client2 handshake (Replaced)");

    let mut saw_reset_caps = false;
    let mut saw_main_display_active = false;
    let deadline2 = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline2 && !(saw_reset_caps && saw_main_display_active) {
        let _ = client2.tick(Duration::from_millis(10), Instant::now());
        for (ch, payload) in client2.drain_tool_messages() {
            if ch == TOOL_CHANNEL_DISPLAY_CTRL {
                match display_ctrl::decode_display_ctrl(&payload) {
                    Some(DisplayControlMsg::Capabilities {
                        display_width: 1512,
                        display_height: 982,
                        display_hidpi: true,
                        ..
                    }) => saw_reset_caps = true,
                    Some(DisplayControlMsg::DisplaysState {
                        active_display_id: 1,
                        ..
                    }) => saw_main_display_active = true,
                    _ => {}
                }
            }
        }
    }
    assert!(
        saw_reset_caps && saw_main_display_active,
        "Replaced must reset to main HiDPI display (caps={saw_reset_caps}, displays={saw_main_display_active})"
    );

    client2
        .send_tool_message(
            TOOL_CHANNEL_DISPLAY_CTRL,
            display_ctrl::encode_display_ctrl(&DisplayControlMsg::ClientMediaCaps {
                decode_caps: rc_pipeline::default_codec_capabilities(true),
                refinement_caps: None,
                pref: crate::codec_selector::CodecSelectionPref::OfficeClear,
                supports_ext_codec_flags: true,
            })
            .unwrap(),
        )
        .expect("client2 send ClientMediaCaps");
    let mut saw_hidpi_reupgrade = false;
    let deadline3 = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline3 && !saw_hidpi_reupgrade {
        let _ = client2.tick(Duration::from_millis(10), Instant::now());
        for (ch, payload) in client2.drain_tool_messages() {
            if ch == TOOL_CHANNEL_DISPLAY_CTRL {
                if let Some(DisplayControlMsg::Capabilities {
                    current_width: 3024,
                    current_height: 1964,
                    current_codec: Some(c),
                    display_hidpi: true,
                    ..
                }) = display_ctrl::decode_display_ctrl(&payload)
                {
                    if c == "hevc" {
                        saw_hidpi_reupgrade = true;
                    }
                }
            }
        }
    }
    assert!(
        saw_hidpi_reupgrade,
        "Replaced must restore auto_hidpi_active=true so ClientMediaCaps(HEVC) upgrades to 3024x1964"
    );

    let _ = client2.close(ByeReason::Normal);
    stop_flag.store(true, Ordering::Release);
    let _ = host_thread.join();
}

#[test]
fn mid_session_wake_driver_is_nonblocking_replaces_guard_and_drops_on_session_exit() {
    struct DropCounter(Arc<AtomicU64>);
    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let drops = Arc::new(AtomicU64::new(0));
    let wake_guard: SharedWakeGuard =
        Arc::new(Mutex::new(Some(Box::new(DropCounter(Arc::clone(&drops))))));
    let mut driver = MidSessionWakeDriver::new();

    // 1) Spawning a slow wake must return immediately (non-blocking) and enforce single-in-flight
    let t0 = Instant::now();
    let drops_for_new = Arc::clone(&drops);
    let spawned = driver.maybe_spawn(t0, move || {
        thread::sleep(Duration::from_millis(60));
        (Ok(Some(Box::new(DropCounter(drops_for_new)))), true)
    });
    assert!(spawned);
    assert!(
        t0.elapsed() < Duration::from_millis(40),
        "maybe_spawn must not block caller thread"
    );
    // Second call while in flight is rejected
    assert!(!driver.maybe_spawn(Instant::now(), || (Ok(None), false)));

    // Wait for background thread to finish and poll_completed to swap guards
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && drops.load(Ordering::SeqCst) == 0 {
        driver.poll_completed(&wake_guard, Instant::now());
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "previous wake guard must be dropped upon swap"
    );
    // Because still_asleep == true, backoff is 15s -> immediate retry at +6s is suppressed
    assert!(
        !driver.maybe_spawn(Instant::now() + Duration::from_secs(6), || (
            Ok(None),
            false
        ))
    );

    // 2) If driver is dropped while a wake thread is in flight, the new guard is dropped immediately (zero leak)
    let mut driver2 = MidSessionWakeDriver::new();
    let drops_exit = Arc::clone(&drops);
    assert!(driver2.maybe_spawn(Instant::now(), move || {
        thread::sleep(Duration::from_millis(40));
        (Ok(Some(Box::new(DropCounter(drops_exit)))), false)
    }));
    drop(driver2);
    let leak_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < leak_deadline && drops.load(Ordering::SeqCst) < 2 {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        drops.load(Ordering::SeqCst),
        2,
        "in-flight guard must be dropped immediately when session drops MidSessionWakeDriver"
    );

    // 3) WakeGuardReleaser drops remaining stored guard cleanly
    {
        let _releaser = WakeGuardReleaser {
            slot: Arc::clone(&wake_guard),
        };
    }
    assert_eq!(drops.load(Ordering::SeqCst), 3);

    // 4) Unread completed rx must block maybe_spawn even after in_flight flips false,
    //    preserving the completed guard until poll_completed drains it and sets cooldown.
    let mut driver3 = MidSessionWakeDriver::new();
    let drops_unread = Arc::new(AtomicU64::new(0));
    let drops_unread_clone = Arc::clone(&drops_unread);
    assert!(driver3.maybe_spawn(Instant::now(), move || {
        (Ok(Some(Box::new(DropCounter(drops_unread_clone)))), false)
    }));
    let wait_done = Instant::now() + Duration::from_secs(2);
    while Instant::now() < wait_done && driver3.in_flight.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(2));
    }
    assert!(
        !driver3.in_flight.load(Ordering::Acquire),
        "background wake should have finished and cleared in_flight"
    );
    // rx is still unread: maybe_spawn must return false and not drop the completed guard
    assert!(!driver3.maybe_spawn(Instant::now(), || (Ok(None), false)));
    assert_eq!(
        drops_unread.load(Ordering::SeqCst),
        0,
        "unread completed wake guard must not be dropped by maybe_spawn"
    );
    // Draining via poll_completed installs the guard and arms the 5s cooldown
    let unread_slot: SharedWakeGuard = Arc::new(Mutex::new(None));
    let drain_at = Instant::now();
    driver3.poll_completed(&unread_slot, drain_at);
    assert!(unread_slot.lock().unwrap().is_some());
    assert_eq!(drops_unread.load(Ordering::SeqCst), 0);
    assert!(!driver3.maybe_spawn(drain_at + Duration::from_secs(2), || (Ok(None), false)));
    replace_wake_guard(&unread_slot, None);
    assert_eq!(drops_unread.load(Ordering::SeqCst), 1);
}

#[test]
fn set_media_paused_toggles_pipeline_without_exiting_and_emits_media_state() {
    assert_eq!(host_resume_ttl(HostTransportKind::Relay), Duration::ZERO);
    assert_eq!(host_resume_ttl(HostTransportKind::P2p), Duration::ZERO);
    assert_eq!(
        host_resume_ttl(HostTransportKind::Lan),
        Duration::from_secs(6)
    );
    assert_eq!(
        host_resume_ttl(HostTransportKind::MtlsLan),
        Duration::from_secs(6)
    );

    let clock: SessionClock = Arc::new(|| 10_000);
    let (mut host, in_tx, out_rx, out_dgrams) = build_streaming_channel_host(Arc::clone(&clock));

    let cap1_stopped = Arc::new(AtomicBool::new(false));
    let cap1_stop_calls = Arc::new(AtomicU64::new(0));
    let created_count = Arc::new(AtomicU64::new(0));
    let initial_cap: Box<dyn AudioCapture> = Box::new(ScriptedAudioCapture {
        inner: rc_audio::FakeAudioCapture::new(),
        stopped: Arc::clone(&cap1_stopped),
        stop_calls: Arc::clone(&cap1_stop_calls),
    });
    let creator_counter = Arc::clone(&created_count);
    let audio_mgr = HostAudioManager::with_creator(
        true,
        Some(initial_cap),
        Arc::new(move || {
            creator_counter.fetch_add(1, Ordering::AcqRel);
            Ok(Box::new(rc_audio::FakeAudioCapture::new()))
        }),
    );

    let stop_flag = Arc::new(AtomicBool::new(false));
    let t_stop = Arc::clone(&stop_flag);
    let t_clock = Arc::clone(&clock);
    let driver = thread::spawn(move || {
        let updates = BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP);
        let pw_ver = AtomicU64::new(0);
        let cfg_ver = AtomicU64::new(0);
        let disc = AtomicBool::new(false);
        let close_reason = AtomicU8::new(ByeReason::Normal as u8);
        let lock_cnt = AtomicU64::new(0);
        let mut owner_terms = PersistentOwnerTerminals::new();
        let wake_guard: SharedWakeGuard = Arc::new(Mutex::new(None));
        let ft_dir: SharedFileTransferDir = Arc::new(RwLock::new(None));
        let allow_assist_ft = AtomicBool::new(true);
        let outcome = drive_ui_host_session_with_audio(
            &mut host,
            &t_clock,
            None,
            &updates,
            &pw_ver,
            0,
            &cfg_ver,
            0,
            &disc,
            &t_stop,
            &close_reason,
            HostTransportKind::Lan,
            false,
            false,
            &lock_cnt,
            None,
            &mut owner_terms,
            wake_guard,
            ft_dir,
            &allow_assist_ft,
            None,
            None,
            Instant::now(),
            audio_mgr,
            None,
        );
        (outcome, host.client_idle_timeout_us())
    });

    // 1) 发送 SetMediaPaused { paused: true } -> 回执 MediaState { paused: true }，停管线与音频，不退出会话。
    send_display_ctrl_event(&in_tx, &DisplayControlMsg::SetMediaPaused { paused: true });
    let paused_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(m, DisplayControlMsg::MediaState { paused: true })
    });
    assert!(
        paused_msgs
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::MediaState { paused: true })),
        "must emit MediaState(paused=true), got: {paused_msgs:?}"
    );
    assert!(
        cap1_stopped.load(Ordering::Acquire) && cap1_stop_calls.load(Ordering::Acquire) >= 1,
        "pausing media must immediately stop and drop active audio capture"
    );

    // 暂停后继续空转一段时间：不应产出新视频数据报，也不应因 !has_pipeline() 异常退出。
    let dgrams_after_pause = out_dgrams.load(Ordering::Acquire);
    thread::sleep(Duration::from_millis(80));
    assert_eq!(
        out_dgrams.load(Ordering::Acquire),
        dgrams_after_pause,
        "media_paused must produce zero new video datagrams"
    );
    assert!(
        !driver.is_finished(),
        "host loop must stay alive in pure-tool paused state without pipeline"
    );

    // 2) 发送 SetMediaPaused { paused: false } -> 重建管线、补发 Capabilities/HostScreenState、拉起新音频、回执 MediaState { paused: false }。
    send_display_ctrl_event(&in_tx, &DisplayControlMsg::SetMediaPaused { paused: false });
    let resumed_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(m, DisplayControlMsg::MediaState { paused: false })
    });
    assert!(
        resumed_msgs
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::Capabilities { .. })),
        "resume must re-emit Capabilities, got: {resumed_msgs:?}"
    );
    assert!(
        resumed_msgs
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::HostScreenState { .. })),
        "resume must re-emit HostScreenState, got: {resumed_msgs:?}"
    );
    assert!(
        resumed_msgs
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::MediaState { paused: false })),
        "resume must emit MediaState(paused=false), got: {resumed_msgs:?}"
    );

    let resume_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < resume_deadline
        && (out_dgrams.load(Ordering::Acquire) <= dgrams_after_pause
            || created_count.load(Ordering::Acquire) == 0)
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        out_dgrams.load(Ordering::Acquire) > dgrams_after_pause,
        "resumed pipeline must produce video datagrams again"
    );
    assert!(
        created_count.load(Ordering::Acquire) >= 1,
        "resume must respawn audio capture"
    );

    stop_flag.store(true, Ordering::Release);
    let (outcome, idle_timeout) = driver.join().expect("join driver");
    assert_eq!(idle_timeout, HostSession::CLIENT_IDLE_TIMEOUT_US);
    assert!(!outcome.preempted_by_incoming);
    assert!(
        !outcome.reason.contains("热重建失败"),
        "clean stop must not report pipeline failure: {}",
        outcome.reason
    );
}

#[test]
fn host_display_ctrl_outbox_preserves_sticky_slots_under_burst_and_backpressure() {
    let mut outbox = HostDisplayCtrlOutbox::new();
    outbox.set_tool_perms(b"perms-v1".to_vec());
    outbox.set_tool_perms(b"perms-v2".to_vec());
    outbox.set_terminal_lock(b"lock-latest".to_vec());
    outbox.set_screen_state(b"screen-latest".to_vec());
    outbox.set_caps(b"caps-latest".to_vec());

    // 推入超过 64 条瞬态消息，绝不能挤掉 4 个粘性状态槽。
    for i in 0..100u32 {
        outbox.push_transient(format!("transient-{i}").into_bytes());
    }
    assert_eq!(outbox.queue.len(), DISPLAY_CTRL_QUEUE_CAP);

    // 模拟首次发送 screen-latest 时触发背压失败（保留全部粘性槽位与队列队首）。
    let mut fail_screen = true;
    let sent_first = outbox.flush(
        8,
        |frame| -> std::result::Result<(), &'static str> {
            if fail_screen && frame == b"screen-latest" {
                fail_screen = false;
                Err("backpressure")
            } else {
                Ok(())
            }
        },
        |_| false,
    );
    assert!(sent_first);
    // perms 与 lock 已发，screen 因背压保留在 sticky_screen_state，caps 也仍在。
    assert!(outbox.sticky_tool_perms.is_none());
    assert!(outbox.sticky_terminal_lock.is_none());
    assert_eq!(
        outbox.sticky_screen_state.as_deref(),
        Some(b"screen-latest".as_slice())
    );
    assert_eq!(
        outbox.sticky_caps.as_deref(),
        Some(b"caps-latest".as_slice())
    );

    // 第二轮背压恢复，应先发出保留的 screen-latest 与 caps-latest，再发队列中的 transient-36..。
    let mut flushed = Vec::new();
    assert!(outbox.flush(
        8,
        |frame| -> std::result::Result<(), &'static str> {
            flushed.push(frame);
            Ok(())
        },
        |_| false,
    ));
    assert_eq!(flushed[0], b"screen-latest");
    assert_eq!(flushed[1], b"caps-latest");
    assert_eq!(flushed[2], b"transient-36");
}
