use super::mock::*;
use super::*;

#[test]
fn compute_hidpi_stream_target_covers_retina_4k_5k_and_non_hidpi() {
    // 14" MBP (1512×982 logical / 3024×1964 backing)
    let mbp14_log = Resolution::new(1512, 982);
    let mbp14_back = Some(Resolution::new(3024, 1964));
    // @60fps & @90fps HEVC -> 1:1 物理像素直出（零缩放）
    assert_eq!(
        compute_hidpi_stream_target(mbp14_log, mbp14_back, 60, rc_encode::Codec::Hevc),
        Resolution::new(3024, 1964)
    );
    assert_eq!(
        compute_hidpi_stream_target(mbp14_log, mbp14_back, 90, rc_encode::Codec::Hevc),
        Resolution::new(3024, 1964)
    );
    // @120fps HEVC -> 收窄至 600M px/s 预算内（<= 5_000_000 px）且高于逻辑分辨率
    let mbp14_hevc_120 =
        compute_hidpi_stream_target(mbp14_log, mbp14_back, 120, rc_encode::Codec::Hevc);
    assert!(mbp14_hevc_120.width > 1512 && mbp14_hevc_120.height > 982);
    assert!(mbp14_hevc_120.width < 3024 && mbp14_hevc_120.height < 1964);
    assert!(
        u64::from(mbp14_hevc_120.width) * u64::from(mbp14_hevc_120.height) <= 600_000_000 / 120
    );
    // @60/90/120fps H.264 -> 按 280M px/s 预算适配
    for fps in [60u32, 90, 120] {
        let res = compute_hidpi_stream_target(mbp14_log, mbp14_back, fps, rc_encode::Codec::H264);
        assert_eq!(res.width % 2, 0);
        assert_eq!(res.height % 2, 0);
        assert!(res.width >= 1512 && res.height >= 982);
        assert!(
            u64::from(res.width) * u64::from(res.height) <= 280_000_000 / u64::from(fps),
            "H.264@{fps}fps 应满足 280M px/s 预算: {res:?}"
        );
    }

    // 16" MBP (1728×1117 logical / 3456×2234 backing) @60fps HEVC -> 1:1 物理像素直出
    assert_eq!(
        compute_hidpi_stream_target(
            Resolution::new(1728, 1117),
            Some(Resolution::new(3456, 2234)),
            60,
            rc_encode::Codec::Hevc,
        ),
        Resolution::new(3456, 2234)
    );

    // 4K HiDPI (1920×1080 logical / 3840×2160 backing) @60fps HEVC -> 1:1 物理像素直出
    assert_eq!(
        compute_hidpi_stream_target(
            Resolution::new(1920, 1080),
            Some(Resolution::new(3840, 2160)),
            60,
            rc_encode::Codec::Hevc,
        ),
        Resolution::new(3840, 2160)
    );

    // 5K Studio Display (2560×1440 logical / 5120×2880 backing) @60fps HEVC -> 封顶 3840×2400 -> 3840×2160
    let display_5k = compute_hidpi_stream_target(
        Resolution::new(2560, 1440),
        Some(Resolution::new(5120, 2880)),
        60,
        rc_encode::Codec::Hevc,
    );
    assert!(display_5k.width <= DEFAULT_HIDPI_STREAM_MAX_WIDTH);
    assert!(display_5k.height <= DEFAULT_HIDPI_STREAM_MAX_HEIGHT);
    assert_eq!(display_5k, Resolution::new(3840, 2160));

    // 非 HiDPI (1920×1080 / 1920×1080)、无 backing 与退化输入原样返回
    assert_eq!(
        compute_hidpi_stream_target(
            Resolution::new(1920, 1080),
            Some(Resolution::new(1920, 1080)),
            60,
            rc_encode::Codec::Hevc,
        ),
        Resolution::new(1920, 1080)
    );
    assert_eq!(
        compute_hidpi_stream_target(
            Resolution::new(1920, 1080),
            None,
            60,
            rc_encode::Codec::Hevc,
        ),
        Resolution::new(1920, 1080)
    );
    assert_eq!(
        compute_hidpi_stream_target(
            Resolution::new(0, 0),
            Some(Resolution::new(3024, 1964)),
            60,
            rc_encode::Codec::Hevc,
        ),
        Resolution::new(0, 0)
    );
}

#[test]
fn client_media_caps_and_fps_change_adapt_hidpi_physical_resolution_within_codec_budget() {
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
    // 模拟被控端系统当前逻辑分辨率 1512×982（如 14" MacBook Pro 默认缩放）
    host.update_caps_resolution(1512, 982);
    let addr = host.local_addr().expect("local_addr");

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
                platform: None,
            },
        )
    });

    let mut ccfg = ClientSessionConfig::new(
        addr,
        SessionParams {
            width: 0,
            height: 0,
            fps: 60,
            bitrate_bps: 30_000_000,
        },
        7789,
        Box::new(EmptyInput),
    );
    ccfg.handshake_timeout = Duration::from_secs(3);
    ccfg.connect_timeout = Duration::from_secs(3);
    ccfg.auth = rc_session::auth::ClientAuthConfig::default();
    let cclock: SessionClock = Arc::new(|| 0);
    let mut client = ClientSession::new(
        ccfg,
        DEV_CERT_PEM,
        DEV_KEY_PEM,
        DEV_CERT_PEM,
        "rabbitcontrol",
        Arc::clone(&cclock),
    )
    .expect("client new");
    let negotiated = client.connect_and_handshake().expect("client handshake");
    assert_eq!((negotiated.width, negotiated.height), (1512, 982));

    // 1) HiDPI 物理像素 3024×1964 + ClientMediaCaps(HEVC) -> 自动升级为 3024×1964（1:1 物理像素），
    //    同时 display_width=1512, display_height=982, display_hidpi=true。
    let caps_msg = display_ctrl::encode_display_ctrl(&DisplayControlMsg::ClientMediaCaps {
        decode_caps: rc_pipeline::default_codec_capabilities(true),
        refinement_caps: None,
        pref: crate::codec_selector::CodecSelectionPref::OfficeClear,
        supports_ext_codec_flags: true,
    })
    .expect("encode ClientMediaCaps");
    client
        .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, caps_msg)
        .expect("send ClientMediaCaps");

    let mut saw_hidpi_hevc_60 = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !saw_hidpi_hevc_60 {
        let _ = client.tick(Duration::from_millis(10), Instant::now());
        for (ch, payload) in client.drain_tool_messages() {
            if ch == TOOL_CHANNEL_DISPLAY_CTRL {
                if let Some(DisplayControlMsg::Capabilities {
                    current_width,
                    current_height,
                    current_codec,
                    native_width,
                    native_height,
                    display_width,
                    display_height,
                    display_hidpi,
                    ..
                }) = display_ctrl::decode_display_ctrl(&payload)
                {
                    assert_eq!((native_width, native_height), (1512, 982));
                    assert_eq!(
                        (display_width, display_height, display_hidpi),
                        (1512, 982, true)
                    );
                    if current_codec.as_deref() == Some("hevc")
                        && (current_width, current_height) == (3024, 1964)
                    {
                        saw_hidpi_hevc_60 = true;
                    }
                }
            }
        }
    }
    assert!(
        saw_hidpi_hevc_60,
        "HiDPI 3024×1964 + ClientMediaCaps(HEVC)@60fps 应自动升级为 3024×1964"
    );

    // 2) 切到 120fps 时收窄至 HEVC 600M px/s 预算内 (<= 600_000_000 / 120) 而不改系统逻辑分辨率。
    let set_fps = display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetStream {
        width: 0,
        height: 0,
        fps: 120,
        codec: None,
    })
    .expect("encode SetStream");
    client
        .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, set_fps)
        .expect("send SetStream");

    let expected_hevc_120 = compute_hidpi_stream_target(
        Resolution::new(1512, 982),
        Some(Resolution::new(3024, 1964)),
        120,
        rc_encode::Codec::Hevc,
    );
    let mut saw_hevc_120 = false;
    let deadline2 = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline2 && !saw_hevc_120 {
        let _ = client.tick(Duration::from_millis(10), Instant::now());
        for (ch, payload) in client.drain_tool_messages() {
            if ch == TOOL_CHANNEL_DISPLAY_CTRL {
                if let Some(DisplayControlMsg::Capabilities {
                    current_width,
                    current_height,
                    current_fps,
                    current_codec,
                    display_width,
                    display_height,
                    display_hidpi,
                    ..
                }) = display_ctrl::decode_display_ctrl(&payload)
                {
                    assert_eq!(
                        (display_width, display_height, display_hidpi),
                        (1512, 982, true)
                    );
                    if current_fps == 120 && current_codec.as_deref() == Some("hevc") {
                        assert_eq!(
                            (current_width, current_height),
                            (expected_hevc_120.width, expected_hevc_120.height)
                        );
                        assert!(
                            u64::from(current_width) * u64::from(current_height)
                                <= 600_000_000 / 120
                        );
                        saw_hevc_120 = true;
                    }
                }
            }
        }
    }
    assert!(
        saw_hevc_120,
        "切到 120fps 后应收窄至 HEVC 600M px/s 预算内并保持逻辑分辨率 1512×982"
    );

    // 3) 切到 H.264@120fps 时按 280M px/s 预算适配。
    let set_h264 = display_ctrl::encode_display_ctrl(&DisplayControlMsg::SetCodec {
        codec: "h264".to_string(),
    })
    .expect("encode SetCodec(h264)");
    client
        .send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, set_h264)
        .expect("send SetCodec(h264)");

    let expected_h264_120 = compute_hidpi_stream_target(
        Resolution::new(1512, 982),
        Some(Resolution::new(3024, 1964)),
        120,
        rc_encode::Codec::H264,
    );
    let mut saw_h264_120 = false;
    let deadline3 = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline3 && !saw_h264_120 {
        let _ = client.tick(Duration::from_millis(10), Instant::now());
        for (ch, payload) in client.drain_tool_messages() {
            if ch == TOOL_CHANNEL_DISPLAY_CTRL {
                if let Some(DisplayControlMsg::Capabilities {
                    current_width,
                    current_height,
                    current_fps,
                    current_codec,
                    display_width,
                    display_height,
                    display_hidpi,
                    ..
                }) = display_ctrl::decode_display_ctrl(&payload)
                {
                    assert_eq!(
                        (display_width, display_height, display_hidpi),
                        (1512, 982, true)
                    );
                    if current_fps == 120 && current_codec.as_deref() == Some("h264") {
                        assert_eq!(
                            (current_width, current_height),
                            (expected_h264_120.width, expected_h264_120.height)
                        );
                        assert!(
                            u64::from(current_width) * u64::from(current_height)
                                <= 280_000_000 / 120
                        );
                        saw_h264_120 = true;
                    }
                }
            }
        }
    }
    assert!(
        saw_h264_120,
        "H.264@120fps 应按 280M px/s 预算适配并保持逻辑分辨率 1512×982"
    );

    let _ = client.close(ByeReason::Normal);
    stop_flag.store(true, Ordering::Release);
    let _ = host_thread.join();
}

#[test]
fn hidpi_set_privacy_mode_mouse_mode_and_media_resume_rescale_on_hevc_fallback() {
    let expected_h264_60 = compute_hidpi_stream_target(
        Resolution::new(1512, 982),
        Some(Resolution::new(3024, 1964)),
        60,
        rc_encode::Codec::H264,
    );
    assert!(expected_h264_60.width < 3024 && expected_h264_60.height < 1964);
    assert!(
        u64::from(expected_h264_60.width) * u64::from(expected_h264_60.height) <= 280_000_000 / 60
    );

    let send_client_hevc_caps =
        |in_tx: &mpsc::Sender<NetEvent>, out_rx: &mpsc::Receiver<Vec<u8>>| -> u64 {
            let _init = recv_display_ctrl_until(out_rx, Duration::from_secs(2), |m| {
                matches!(m, DisplayControlMsg::Capabilities { .. })
            });
            send_display_ctrl_event(
                in_tx,
                &DisplayControlMsg::ClientMediaCaps {
                    decode_caps: rc_pipeline::default_codec_capabilities(true),
                    refinement_caps: None,
                    pref: crate::codec_selector::CodecSelectionPref::OfficeClear,
                    supports_ext_codec_flags: true,
                },
            );
            let msgs = recv_display_ctrl_until(out_rx, Duration::from_secs(2), |m| {
                matches!(
                    m,
                    DisplayControlMsg::Capabilities {
                        current_width: 3024,
                        current_height: 1964,
                        current_codec: Some(c),
                        ..
                    } if c == "hevc"
                )
            });
            msgs.into_iter()
                .rev()
                .find_map(|m| match m {
                    DisplayControlMsg::Capabilities {
                        codec_generation, ..
                    } => Some(codec_generation),
                    _ => None,
                })
                .expect("expected HEVC 3024x1964 Capabilities")
        };

    // 1) SetPrivacyMode (on + off) HEVC -> H.264 运行时回退必须按 280M px/s 预算缩流
    {
        let clock: SessionClock = Arc::new(|| 10_000);
        let fail_hevc = Arc::new(AtomicBool::new(false));
        let (host, in_tx, out_rx) = build_hidpi_channel_host(
            Arc::clone(&clock),
            1512,
            982,
            60,
            144,
            Arc::clone(&fail_hevc),
        );
        let platform_mock = TestHostPlatformMock::new(
            Resolution::new(1512, 982),
            Resolution::new(3024, 1964),
            Vec::new(),
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

        let gen_hevc = send_client_hevc_caps(&in_tx, &out_rx);

        // 开启防窥幕布时强制 HEVC 构码失败回退 H.264
        fail_hevc.store(true, Ordering::Release);
        send_display_ctrl_event(
            &in_tx,
            &DisplayControlMsg::SetPrivacyMode {
                mode: "privacy".to_string(),
                preset: "preset-1".to_string(),
                custom_image_base64: None,
            },
        );
        let msgs_on = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(m, DisplayControlMsg::PrivacyState { .. })
        });
        assert!(msgs_on.iter().any(|m| matches!(
            m,
            DisplayControlMsg::PrivacyState {
                mode,
                supported: true,
                ..
            } if mode == "privacy"
        )));
        assert!(
            msgs_on.iter().any(|m| matches!(
                m,
                DisplayControlMsg::Capabilities {
                    current_width,
                    current_height,
                    current_codec: Some(c),
                    supported_codecs,
                    codec_generation,
                    ..
                } if c == "h264"
                    && (*current_width, *current_height) == (expected_h264_60.width, expected_h264_60.height)
                    && !supported_codecs.iter().any(|s| s == "hevc")
                    && *codec_generation > gen_hevc
            )),
            "SetPrivacyMode(on) HEVC fallback must rescale into H.264 280M px/s budget: {msgs_on:?}"
        );

        // 恢复 HEVC 3024x1964 后再测试 SetPrivacyMode(off) 时触发 HEVC 回退
        fail_hevc.store(false, Ordering::Release);
        send_display_ctrl_event(
            &in_tx,
            &DisplayControlMsg::SetCodec {
                codec: "hevc".to_string(),
            },
        );
        let _ = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(
                m,
                DisplayControlMsg::Capabilities {
                    current_width: 3024,
                    current_height: 1964,
                    current_codec: Some(c),
                    ..
                } if c == "hevc"
            )
        });

        fail_hevc.store(true, Ordering::Release);
        send_display_ctrl_event(
            &in_tx,
            &DisplayControlMsg::SetPrivacyMode {
                mode: "off".to_string(),
                preset: "preset-1".to_string(),
                custom_image_base64: None,
            },
        );
        let msgs_off = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(
                m,
                DisplayControlMsg::Capabilities {
                    current_codec: Some(c),
                    ..
                } if c == "h264"
            )
        });
        assert!(
            msgs_off.iter().any(|m| matches!(
                m,
                DisplayControlMsg::Capabilities {
                    current_width,
                    current_height,
                    current_codec: Some(c),
                    ..
                } if c == "h264"
                    && (*current_width, *current_height) == (expected_h264_60.width, expected_h264_60.height)
            )),
            "SetPrivacyMode(off) HEVC fallback must rescale into H.264 280M px/s budget: {msgs_off:?}"
        );

        stop_flag.store(true, Ordering::Release);
        let _ = driver.join();
    }

    // 2) SetMouseMode HEVC -> H.264 运行时回退必须按 280M px/s 预算缩流
    {
        let clock: SessionClock = Arc::new(|| 10_000);
        let fail_hevc = Arc::new(AtomicBool::new(false));
        let (host, in_tx, out_rx) = build_hidpi_channel_host(
            Arc::clone(&clock),
            1512,
            982,
            60,
            144,
            Arc::clone(&fail_hevc),
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
                platform: None,
            },
        );

        let gen_hevc = send_client_hevc_caps(&in_tx, &out_rx);
        fail_hevc.store(true, Ordering::Release);
        send_display_ctrl_event(
            &in_tx,
            &DisplayControlMsg::SetMouseMode {
                mode: "remote".to_string(),
            },
        );
        let msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(m, DisplayControlMsg::MouseModeState { .. })
        });
        assert!(msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::MouseModeState { mode } if mode == "remote"
        )));
        assert!(
            msgs.iter().any(|m| matches!(
                m,
                DisplayControlMsg::Capabilities {
                    current_width,
                    current_height,
                    current_codec: Some(c),
                    codec_generation,
                    ..
                } if c == "h264"
                    && (*current_width, *current_height) == (expected_h264_60.width, expected_h264_60.height)
                    && *codec_generation > gen_hevc
            )),
            "SetMouseMode HEVC fallback must rescale into H.264 280M px/s budget: {msgs:?}"
        );

        stop_flag.store(true, Ordering::Release);
        let _ = driver.join();
    }

    // 3) SetMediaPaused(false) 恢复流时 HEVC -> H.264 运行时回退必须按 280M px/s 预算缩流
    {
        let clock: SessionClock = Arc::new(|| 10_000);
        let fail_hevc = Arc::new(AtomicBool::new(false));
        let (host, in_tx, out_rx) = build_hidpi_channel_host(
            Arc::clone(&clock),
            1512,
            982,
            60,
            144,
            Arc::clone(&fail_hevc),
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
                platform: None,
            },
        );

        let gen_hevc = send_client_hevc_caps(&in_tx, &out_rx);
        send_display_ctrl_event(&in_tx, &DisplayControlMsg::SetMediaPaused { paused: true });
        let paused_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(m, DisplayControlMsg::MediaState { paused: true })
        });
        assert!(paused_msgs
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::MediaState { paused: true })));

        fail_hevc.store(true, Ordering::Release);
        send_display_ctrl_event(&in_tx, &DisplayControlMsg::SetMediaPaused { paused: false });
        let resumed_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
            matches!(m, DisplayControlMsg::MediaState { paused: false })
        });
        assert!(
            resumed_msgs.iter().any(|m| matches!(
                m,
                DisplayControlMsg::Capabilities {
                    current_width,
                    current_height,
                    current_codec: Some(c),
                    supported_codecs,
                    codec_generation,
                    ..
                } if c == "h264"
                    && (*current_width, *current_height) == (expected_h264_60.width, expected_h264_60.height)
                    && !supported_codecs.iter().any(|s| s == "hevc")
                    && *codec_generation > gen_hevc
            )),
            "SetMediaPaused(false) HEVC fallback must rescale into H.264 280M px/s budget: {resumed_msgs:?}"
        );

        stop_flag.store(true, Ordering::Release);
        let _ = driver.join();
    }
}

#[test]
fn hidpi_codec_decode_failed_rescales_hevc_to_h264_budget() {
    let clock: SessionClock = Arc::new(|| 10_000);
    let fail_hevc = Arc::new(AtomicBool::new(false));
    let (host, in_tx, out_rx) =
        build_hidpi_channel_host(Arc::clone(&clock), 1512, 982, 90, 144, fail_hevc);
    let (stop_flag, driver) = spawn_hidpi_channel_driver(
        host,
        clock,
        TestHostMediaOverride {
            native_res: Resolution::new(1512, 982),
            max_res: Resolution::new(3024, 1964),
            auto_hidpi: true,
            hevc_available: true,
            encode_caps: rc_pipeline::default_codec_capabilities(true),
            platform: None,
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
    let hevc_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_width: 3024,
                current_height: 1964,
                current_fps: 90,
                current_codec: Some(c),
                ..
            } if c == "hevc"
        )
    });
    let hevc_gen = hevc_msgs
        .iter()
        .rev()
        .find_map(|m| match m {
            DisplayControlMsg::Capabilities {
                codec_generation, ..
            } => Some(*codec_generation),
            _ => None,
        })
        .expect("expected HEVC 3024x1964@90fps Capabilities");

    let expected_h264_90 = compute_hidpi_stream_target(
        Resolution::new(1512, 982),
        Some(Resolution::new(3024, 1964)),
        90,
        rc_encode::Codec::H264,
    );
    assert!(expected_h264_90.width < 3024 && expected_h264_90.height < 1964);
    assert!(
        u64::from(expected_h264_90.width) * u64::from(expected_h264_90.height) <= 280_000_000 / 90
    );

    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::CodecDecodeFailed {
            codec: "hevc".to_string(),
            generation: hevc_gen,
            reason: "decoder failed on 90fps hevc".to_string(),
        },
    );
    let fb_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_codec: Some(c),
                ..
            } if c == "h264"
        )
    });
    assert!(
        fb_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_width,
                current_height,
                current_fps: 90,
                current_codec: Some(c),
                supported_codecs,
                codec_generation,
                ..
            } if c == "h264"
                && (*current_width, *current_height) == (expected_h264_90.width, expected_h264_90.height)
                && !supported_codecs.iter().any(|s| s == "hevc")
                && *codec_generation == hevc_gen + 1
        )),
        "CodecDecodeFailed(hevc) must rescale HiDPI stream into H.264 280M px/s budget: {fb_msgs:?}"
    );

    stop_flag.store(true, Ordering::Release);
    let _ = driver.join();
}

#[test]
fn host_bridge_client_media_caps_and_codec_decode_failed_generation_handling() {
    let clock: SessionClock = Arc::new(|| 10_000);
    let (mut host, in_tx, out_rx, _out_dgrams) = build_streaming_channel_host(Arc::clone(&clock));
    let audio_mgr = HostAudioManager::with_creator(
        false,
        None,
        Arc::new(|| Ok(Box::new(rc_audio::FakeAudioCapture::new()))),
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
        drive_ui_host_session_with_audio(
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
        )
    });

    // 1) 初始 Capabilities 必须携带 supports_ext_codec_flags=true、codec_generation=1 及非空 encode_caps/decode_caps。
    let init_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(m, DisplayControlMsg::Capabilities { .. })
    });
    let init_gen = init_msgs
        .iter()
        .find_map(|m| match m {
            DisplayControlMsg::Capabilities {
                supports_ext_codec_flags,
                codec_generation,
                encode_caps,
                decode_caps,
                ..
            } => {
                assert!(
                    *supports_ext_codec_flags,
                    "新版被控端必须声明 supports_ext_codec_flags=true"
                );
                assert!(!encode_caps.is_empty());
                assert!(!decode_caps.is_empty());
                Some(*codec_generation)
            }
            _ => None,
        })
        .expect("must receive initial Capabilities");
    assert_eq!(init_gen, 1);

    // 2) 发送 supports_ext_codec_flags=false 的 ClientMediaCaps：不启用 AV1 且正常回传 Capabilities。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::ClientMediaCaps {
            decode_caps: rc_pipeline::default_codec_capabilities(true),
            refinement_caps: None,
            pref: crate::codec_selector::CodecSelectionPref::OfficeClear,
            supports_ext_codec_flags: false,
        },
    );
    let caps_after_client = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(m, DisplayControlMsg::Capabilities { .. })
    });
    let cur_gen = caps_after_client
        .iter()
        .find_map(|m| match m {
            DisplayControlMsg::Capabilities {
                current_codec,
                codec_generation,
                ..
            } => {
                assert_ne!(
                    current_codec.as_deref(),
                    Some("av1"),
                    "supports_ext_codec_flags=false 时绝不允许启用 AV1"
                );
                Some(*codec_generation)
            }
            _ => None,
        })
        .expect("must emit Capabilities after ClientMediaCaps");

    // 3) 发送过期 generation 的 CodecDecodeFailed：必须被忽略（不产生新 Capabilities 递增）。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::CodecDecodeFailed {
            codec: "av1".to_string(),
            generation: cur_gen + 99,
            reason: "stale generation".to_string(),
        },
    );
    let stale_msgs = recv_display_ctrl_until(&out_rx, Duration::from_millis(120), |m| {
        matches!(m, DisplayControlMsg::Capabilities { .. })
    });
    assert!(
        stale_msgs
            .iter()
            .all(|m| !matches!(m, DisplayControlMsg::Capabilities { .. })),
        "过期 generation 的 CodecDecodeFailed 不得触发降级重推: {stale_msgs:?}"
    );

    // 4) 发送不匹配 active_codec（当前 H.264）的 CodecDecodeFailed(hevc)：按严格回声拦截被忽略。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::CodecDecodeFailed {
            codec: "hevc".to_string(),
            generation: cur_gen,
            reason: "mismatched codec echo".to_string(),
        },
    );
    let mismatch_msgs = recv_display_ctrl_until(&out_rx, Duration::from_millis(120), |m| {
        matches!(m, DisplayControlMsg::Capabilities { .. })
    });
    assert!(
        mismatch_msgs
            .iter()
            .all(|m| !matches!(m, DisplayControlMsg::Capabilities { .. })),
        "与当前 active_codec 不符的 CodecDecodeFailed 必须忽略: {mismatch_msgs:?}"
    );

    // 5) 发送匹配当前 active_codec=h264 且匹配 generation 的 CodecDecodeFailed：
    //    保持 H.264（绝不反向升级至 HEVC）且因 active_codec 未变更不虚增 codec_generation，回推权威 Capabilities。
    send_display_ctrl_event(
        &in_tx,
        &DisplayControlMsg::CodecDecodeFailed {
            codec: "h264".to_string(),
            generation: cur_gen,
            reason: "simulated h264 decode failure".to_string(),
        },
    );
    let fb_msgs = recv_display_ctrl_until(&out_rx, Duration::from_secs(2), |m| {
        matches!(m, DisplayControlMsg::Capabilities { .. })
    });
    assert!(
        fb_msgs.iter().any(|m| matches!(
            m,
            DisplayControlMsg::Capabilities {
                current_codec: Some(c),
                codec_generation,
                ..
            } if c == "h264" && *codec_generation == cur_gen
        )),
        "H.264 兜底态收到匹配 CodecDecodeFailed 应保持 h264 且不虚增 generation: {fb_msgs:?}"
    );

    stop_flag.store(true, Ordering::Release);
    let _ = driver.join().expect("join host driver");
}
