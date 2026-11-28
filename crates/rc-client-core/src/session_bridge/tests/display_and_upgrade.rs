use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rc_input::InputEvent;
use rc_net::{NetEvent, NetStats, Transport};
use rc_pipeline::{ControllerPipeline, PipelineConfig};
use rc_render::Renderer;
use rc_session::dev_cert::{DEV_CERT_PEM, DEV_KEY_PEM};
use rc_session::proto::{ByeReason, ControlMessage, SessionParams};
use rc_session::{
    ClientSession, ClientSessionConfig, SessionClock, SessionState, TOOL_CHANNEL_DISPLAY_CTRL,
};
use rc_types::Resolution;

use crate::app_prefs::ConnectionMode;
use crate::codec_selector::CodecSelectionPref;
use crate::display_ctrl::{self, DisplayControlMsg, DisplayPreset, StreamCodec};

use super::super::adapters::{
    build_controller_pipeline, fake_controller_stack, BridgeInputCapture, BuiltPipeline,
    RendererHandle, SharedRenderer,
};
use super::super::connect::reanchorable_clock;
use super::super::display_ctrl::{
    build_client_media_caps_msg, handle_display_ctrl_msg, reconcile_decode_failure_on_capabilities,
    try_resume_or_upgrade_desktop, DesktopUpgradeCtx,
};
use super::super::handle::SessionHandle;
use super::super::queues::{BoundedInputQueue, BoundedUpdateQueue};
use super::super::types::{SessionCommand, SessionUpdate, UiSessionConfig, UPDATE_CHANNEL_CAP};

#[test]
fn handle_display_ctrl_msg_supports_custom_presets_and_wallpaper_validation() {
    let mut hud_w = 1280;
    let mut hud_h = 720;

    // 1) 非空 presets 直接沿用；为空时回退 build_resolution_presets。
    let custom_presets = vec![DisplayPreset {
        width: 2560,
        height: 1600,
        label: "2560 × 1600 (HiDPI)".to_string(),
        is_native: true,
        is_hidpi: true,
    }];
    let upd = handle_display_ctrl_msg(
        DisplayControlMsg::Capabilities {
            current_width: 2560,
            current_height: 1600,
            current_fps: 120,
            native_width: 2560,
            native_height: 1600,
            max_width: 2560,
            max_height: 1600,
            max_fps: 120,
            presets: custom_presets.clone(),
            current_codec: Some("h264".to_string()),
            supported_codecs: vec!["hevc".to_string(), "h264".to_string()],
            encode_caps: Vec::new(),
            decode_caps: Vec::new(),
            refinement_caps: None,
            supports_ext_codec_flags: false,
            codec_generation: 0,
            still_stream_epoch: 0,
            supports_pixel_scroll: false,
            supports_controller_meta: false,
            display_width: 1280,
            display_height: 800,
            display_hidpi: true,
        },
        &mut hud_w,
        &mut hud_h,
        true,
    )
    .expect("capabilities update");
    assert_eq!((hud_w, hud_h), (2560, 1600));
    match upd {
        SessionUpdate::DisplayConfig {
            presets,
            codec,
            supported_codecs,
            client_supports_hevc,
            advisory,
            display_width,
            display_height,
            display_hidpi,
            ..
        } => {
            assert_eq!(presets, custom_presets);
            assert_eq!(codec.as_deref(), Some("h264"));
            assert_eq!(supported_codecs, vec!["hevc", "h264"]);
            assert!(client_supports_hevc);
            assert_eq!(advisory.level, display_ctrl::HighRefreshLevel::SuggestHevc);
            assert!(advisory.can_enable_hevc);
            assert_eq!(
                (display_width, display_height, display_hidpi),
                (1280, 800, true)
            );
        }
        other => panic!("expected DisplayConfig, got {other:?}"),
    }

    let fallback_upd = handle_display_ctrl_msg(
        DisplayControlMsg::Capabilities {
            current_width: 1920,
            current_height: 1080,
            current_fps: 60,
            native_width: 1920,
            native_height: 1080,
            max_width: 1920,
            max_height: 1080,
            max_fps: 60,
            presets: Vec::new(),
            current_codec: None,
            supported_codecs: Vec::new(),
            encode_caps: Vec::new(),
            decode_caps: Vec::new(),
            refinement_caps: None,
            supports_ext_codec_flags: false,
            codec_generation: 0,
            still_stream_epoch: 0,
            supports_pixel_scroll: false,
            supports_controller_meta: false,
            display_width: 0,
            display_height: 0,
            display_hidpi: true,
        },
        &mut hud_w,
        &mut hud_h,
        false,
    )
    .expect("fallback capabilities update");
    match fallback_upd {
        SessionUpdate::DisplayConfig {
            presets,
            advisory,
            display_width,
            display_height,
            display_hidpi,
            ..
        } => {
            assert!(!presets.is_empty());
            assert!(presets.iter().any(|p| p.is_native && p.width == 1920));
            assert_eq!(advisory.level, display_ctrl::HighRefreshLevel::Optimal);
            assert_eq!(
                (display_width, display_height, display_hidpi),
                (0, 0, false)
            );
        }
        other => panic!("expected DisplayConfig, got {other:?}"),
    }

    // 2) Wallpaper 支持 image/jpeg 与 image/png，拒绝非法 mime、空/超长/非法 base64。
    let b64 = display_ctrl::base64_encode(b"\xff\xd8\xff\xe0");
    let wp = handle_display_ctrl_msg(
        DisplayControlMsg::Wallpaper {
            mime: "image/jpeg".to_string(),
            data_base64: b64.clone(),
        },
        &mut hud_w,
        &mut hud_h,
        false,
    );
    assert_eq!(
        wp,
        Some(SessionUpdate::Wallpaper {
            data_url: format!("data:image/jpeg;base64,{b64}"),
        })
    );
    assert_eq!(
        handle_display_ctrl_msg(
            DisplayControlMsg::Wallpaper {
                mime: "image/svg+xml".to_string(),
                data_base64: b64.clone(),
            },
            &mut hud_w,
            &mut hud_h,
            false,
        ),
        None
    );
    assert_eq!(
        handle_display_ctrl_msg(
            DisplayControlMsg::Wallpaper {
                mime: "image/png".to_string(),
                data_base64: "not!base64".to_string(),
            },
            &mut hud_w,
            &mut hud_h,
            false,
        ),
        None
    );
    assert_eq!(
        handle_display_ctrl_msg(
            DisplayControlMsg::Wallpaper {
                mime: "image/png".to_string(),
                data_base64: "AAAA".repeat(22_501),
            },
            &mut hud_w,
            &mut hud_h,
            false,
        ),
        None
    );

    // 3) SessionCommand::SetCodec JSON 往返且保持 Copy 语义。
    let cmd_hevc: SessionCommand =
        serde_json::from_str(r#"{"type":"set_codec","codec":"hevc"}"#).expect("parse hevc");
    let cmd_h264: SessionCommand =
        serde_json::from_str(r#"{"type":"set_codec","codec":"h264"}"#).expect("parse h264");
    assert_eq!(
        cmd_hevc,
        SessionCommand::SetCodec {
            codec: StreamCodec::Hevc
        }
    );
    assert_eq!(
        cmd_h264,
        SessionCommand::SetCodec {
            codec: StreamCodec::H264
        }
    );
}

#[test]
fn handle_display_ctrl_msg_emits_host_screen_state_update() {
    let mut hud_w = 1920u32;
    let mut hud_h = 1080u32;
    let upd = handle_display_ctrl_msg(
        DisplayControlMsg::HostScreenState {
            locked: true,
            capture_suspended: false,
        },
        &mut hud_w,
        &mut hud_h,
        true,
    );
    assert_eq!(
        upd,
        Some(SessionUpdate::HostScreenState {
            locked: true,
            capture_suspended: false,
        })
    );
    assert_eq!((hud_w, hud_h), (1920, 1080));

    assert_eq!(
        handle_display_ctrl_msg(
            DisplayControlMsg::MediaState { paused: true },
            &mut hud_w,
            &mut hud_h,
            true,
        ),
        Some(SessionUpdate::MediaState { paused: true })
    );
    assert_eq!(
        handle_display_ctrl_msg(
            DisplayControlMsg::MediaState { paused: false },
            &mut hud_w,
            &mut hud_h,
            true,
        ),
        Some(SessionUpdate::MediaState { paused: false })
    );
}

#[test]
fn tools_only_startup_pauses_media_and_upgrade_to_desktop_resumes_with_media_resumed() {
    struct NoopInjector;
    impl rc_input::InputInjector for NoopInjector {
        fn inject(&mut self, _events: &[InputEvent]) -> rc_types::Result<()> {
            Ok(())
        }
        fn set_screen_size(&mut self, _width: u32, _height: u32) {}
    }

    let host_origin = Instant::now();
    let (host_clock, _) = reanchorable_clock(host_origin);
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
    hcfg.pipeline.prefer_hardware = false;
    hcfg.pipeline.resolution = Resolution::new(640, 360);
    hcfg.pipeline.fps = 30;
    hcfg.pace_capture = true;

    let mut host = rc_session::HostSession::new(hcfg, DEV_CERT_PEM, DEV_KEY_PEM, host_clock)
        .expect("create host session");
    let host_addr = host.local_addr().expect("host local_addr");

    let received_ctrl: Arc<Mutex<Vec<DisplayControlMsg>>> = Arc::new(Mutex::new(Vec::new()));
    let host_stop = Arc::new(AtomicBool::new(false));
    let t_received = Arc::clone(&received_ctrl);
    let t_stop = Arc::clone(&host_stop);
    let host_thread =
        thread::spawn(move || {
            if host.accept_and_handshake(Duration::from_secs(5)).is_err() {
                return;
            }
            while !t_stop.load(Ordering::Acquire) && host.state() == SessionState::Streaming {
                if let Ok(rep) = host.tick(Duration::from_millis(5)) {
                    if rep.closed.is_some() {
                        break;
                    }
                } else {
                    break;
                }
                for (ch, payload) in host.drain_tool_messages() {
                    if ch == TOOL_CHANNEL_DISPLAY_CTRL {
                        if let Some(msg) = display_ctrl::decode_display_ctrl(&payload) {
                            if let DisplayControlMsg::SetMediaPaused { paused } = msg {
                                if paused {
                                    host.pause_media();
                                } else {
                                    let _ = host.resume_media();
                                }
                                if let Some(ack) = display_ctrl::encode_display_ctrl(
                                    &DisplayControlMsg::MediaState { paused },
                                ) {
                                    let _ = host.send_tool_message(TOOL_CHANNEL_DISPLAY_CTRL, ack);
                                }
                            }
                            t_received.lock().unwrap().push(msg);
                        }
                    }
                }
            }
            let _ = host.close(ByeReason::Normal);
        });

    let session = SessionHandle::spawn(UiSessionConfig {
        connect_addr: host_addr,
        connection_mode: ConnectionMode::Auto,
        tools_only: true,
        width: 640,
        height: 360,
        fps: 30,
        bitrate_bps: 2_000_000,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        ..UiSessionConfig::default()
    });

    // 1) 等待握手完成并确认 tools_only 启动不写 layer_lease、收到 Negotiated 且向被控端发出 SetMediaPaused(true)。
    let mut updates: Vec<SessionUpdate> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        while let Some(u) = session.try_recv_update() {
            updates.push(u);
        }
        let host_got_pause = received_ctrl
            .lock()
            .unwrap()
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::SetMediaPaused { paused: true }));
        let ui_got_media_paused = updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::MediaState { paused: true }));
        let ui_got_negotiated = updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::Negotiated { .. }));
        if host_got_pause && ui_got_media_paused && ui_got_negotiated {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        session.layer_lease().is_none(),
        "tools_only 启动期间不得写入 layer_lease"
    );
    assert!(
        updates.iter().any(|u| matches!(
            u,
            SessionUpdate::Negotiated { backend, .. } if backend == "tools-only"
        )),
        "tools_only 握手 Negotiated 后端标签应为 tools-only，实际：{updates:?}"
    );
    assert!(
        received_ctrl
            .lock()
            .unwrap()
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::SetMediaPaused { paused: true })),
        "tools_only 握手成功后必须发送 DisplayControlMsg::SetMediaPaused(true)"
    );
    assert!(
        updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::MediaState { paused: true })),
        "被控端回传 MediaState(true) 后必须转为 SessionUpdate::MediaState(true)"
    );

    // 2) 触发原地热升级桌面（upgrade_to_desktop）并顺带验证 ProbeNow 命令不破坏会话。
    updates.clear();
    session.upgrade_to_desktop(None);
    session.send(SessionCommand::ProbeNow);

    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        while let Some(u) = session.try_recv_update() {
            updates.push(u);
        }
        let host_got_resume = received_ctrl
            .lock()
            .unwrap()
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::SetMediaPaused { paused: false }));
        let ui_got_resumed = updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::MediaResumed { .. }));
        let ui_got_state_false = updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::MediaState { paused: false }));
        if host_got_resume && ui_got_resumed && ui_got_state_false {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        received_ctrl
            .lock()
            .unwrap()
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::SetMediaPaused { paused: false })),
        "upgrade_to_desktop 必须发送 DisplayControlMsg::SetMediaPaused(false)"
    );
    assert!(
        updates.iter().any(|u| matches!(
            u,
            SessionUpdate::MediaResumed {
                backend,
                width: 640,
                height: 360,
                fps: 30,
            } if backend == "fake"
        )),
        "upgrade_to_desktop 必须推送 MediaResumed，实际：{updates:?}"
    );
    assert!(
        updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::MediaState { paused: false })),
        "upgrade_to_desktop 必须推送 MediaState(false)"
    );

    // 3) 再次通过命令暂停媒体并验证 SessionUpdate::MediaState(true)。
    updates.clear();
    session.send(SessionCommand::SetMediaPaused { paused: true });
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        while let Some(u) = session.try_recv_update() {
            updates.push(u);
        }
        if updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::MediaState { paused: true }))
        {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::MediaState { paused: true })),
        "SetMediaPaused(true) 必须推送 MediaState(true)"
    );

    session.send(SessionCommand::Disconnect);
    session.join();
    host_stop.store(true, Ordering::Release);
    let _ = host_thread.join();
}

struct StubUpgradeTransport {
    inbound: VecDeque<NetEvent>,
}

impl Transport for StubUpgradeTransport {
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
        Ok(self.inbound.drain(..).collect())
    }
    fn stats(&self) -> NetStats {
        NetStats::default()
    }
}

struct RecordingStageRenderer {
    resizes: Arc<Mutex<Vec<(u32, u32)>>>,
}

impl Renderer for RecordingStageRenderer {
    fn present(
        &mut self,
        _frame: rc_decode::DecodedFrame,
    ) -> rc_types::Result<rc_types::Timestamp> {
        Ok(rc_types::Timestamp(0))
    }
    fn resize(&mut self, size: (u32, u32)) -> rc_types::Result<()> {
        self.resizes.lock().unwrap().push(size);
        Ok(())
    }
    fn set_vsync(&mut self, _on: bool) {}
    fn set_cursor(&mut self, _pos: (i32, i32), _visible: bool) {}
}

fn make_streaming_tools_only_client(params: SessionParams) -> ClientSession {
    let mut welcome_buf = Vec::new();
    ControlMessage::Welcome(rc_session::proto::Welcome {
        session_id: 99,
        granted: params,
        auth_status: rc_session::proto::AuthStatus::Ok,
        host_flags: rc_session::proto::HostFlags(0),
    })
    .encode(&mut welcome_buf);
    let transport = StubUpgradeTransport {
        inbound: VecDeque::from([NetEvent::Reliable(welcome_buf)]),
    };
    let capture = Box::new(BridgeInputCapture {
        queue: Arc::new(BoundedInputQueue::new(16)),
        watch_only: Arc::new(AtomicBool::new(false)),
    });
    let mut ccfg = ClientSessionConfig::new("127.0.0.1:9901".parse().unwrap(), params, 99, capture);
    ccfg.pipeline.prefer_hardware = false;
    let dec = rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
        resolution: Resolution::new(64, 64),
        ..rc_decode::FakeDecoderConfig::default()
    })
    .expect("fake decoder");
    let rend = rc_render::FakeRenderer::new(rc_render::FakeRendererConfig {
        size: (64, 64),
        ..rc_render::FakeRendererConfig::default()
    })
    .expect("fake renderer");
    let clock: SessionClock = Arc::new(|| 0);
    let mut client = ClientSession::with_parts(
        ccfg,
        Box::new(transport),
        Box::new(dec),
        Box::new(rend),
        clock,
    )
    .expect("with_parts");
    client.handshake().expect("handshake");
    client.set_media_paused(true);
    client
}

#[test]
fn desktop_upgrade_failure_keeps_media_paused_and_skips_media_resumed() {
    let params = SessionParams {
        width: 1280,
        height: 720,
        fps: 60,
        bitrate_bps: 8_000_000,
    };

    // 1) build_controller_pipeline 失败：必须保持 media_paused=true，不发 SetMediaPaused(false)，不发 MediaResumed/MediaState(false)。
    let mut client = make_streaming_tools_only_client(params);
    let real_pipeline_built = AtomicBool::new(false);
    let want_real_pipeline = AtomicBool::new(false);
    let is_hw_decoder_slot = AtomicBool::new(false);
    let mut backend = "tools-only".to_string();
    let backend_label = Mutex::new(backend.clone());
    let renderer_handle = Mutex::new(None);
    let renderer_pending_resize = Mutex::new(Arc::new(AtomicU64::new(0)));
    let layer_lease = Mutex::new(None);
    let mut is_hardware_decoder = false;
    let mut client_supports_hevc = false;
    let mut client_supports_av1 = false;
    let mut client_decode_caps = Vec::new();
    let mut stream_started_at = Instant::now();
    let mut first_frame_logged = false;
    let mut decode_error_logged = false;
    let mut pending_display_tx = VecDeque::new();
    let update_tx = BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP);

    let ok = try_resume_or_upgrade_desktop(
        DesktopUpgradeCtx {
            client: &mut client,
            real_pipeline_built: &real_pipeline_built,
            want_real_pipeline: &want_real_pipeline,
            is_hw_decoder_slot: &is_hw_decoder_slot,
            backend: &mut backend,
            backend_label: &backend_label,
            renderer_handle: &renderer_handle,
            renderer_pending_resize: &renderer_pending_resize,
            layer_lease: &layer_lease,
            active_backend_suffix: None,
            is_hardware_decoder: &mut is_hardware_decoder,
            client_supports_hevc: &mut client_supports_hevc,
            client_supports_av1: &mut client_supports_av1,
            client_decode_caps: &mut client_decode_caps,
            user_pinned_codec: None,
            still_refinement_enabled: true,
            prefer_hardware: false,
            hud_width: params.width,
            hud_height: params.height,
            current_fps: params.fps,
            negotiated: params,
            last_stage_rect: Some((1280, 720)),
            stream_started_at: &mut stream_started_at,
            first_frame_logged: &mut first_frame_logged,
            decode_error_logged: &mut decode_error_logged,
            pending_display_tx: &mut pending_display_tx,
            update_tx: &update_tx,
        },
        |_pcfg| {
            Err(rc_types::Error::InvalidConfig(
                "simulated hardware init error".into(),
            ))
        },
    );
    assert!(!ok, "构建管线失败时升级必须返回 false");
    assert!(
        client.is_media_paused(),
        "构建失败后必须保持 media_paused=true"
    );
    assert!(!real_pipeline_built.load(Ordering::Acquire));
    assert!(!want_real_pipeline.load(Ordering::Acquire));
    assert!(
        pending_display_tx.is_empty(),
        "构建失败时严禁通知被控端恢复推流"
    );
    assert!(
        update_tx.try_pop().is_none(),
        "构建失败时严禁向 UI 发射 MediaResumed 或 MediaState(false)"
    );

    // 2) client.replace_pipeline 失败（例如非 Streaming 态）：同样保持暂停、不发恢复通知。
    client.on_disconnected(1_000);
    assert_eq!(client.state(), SessionState::Reconnecting);
    let ok2 = try_resume_or_upgrade_desktop(
        DesktopUpgradeCtx {
            client: &mut client,
            real_pipeline_built: &real_pipeline_built,
            want_real_pipeline: &want_real_pipeline,
            is_hw_decoder_slot: &is_hw_decoder_slot,
            backend: &mut backend,
            backend_label: &backend_label,
            renderer_handle: &renderer_handle,
            renderer_pending_resize: &renderer_pending_resize,
            layer_lease: &layer_lease,
            active_backend_suffix: None,
            is_hardware_decoder: &mut is_hardware_decoder,
            client_supports_hevc: &mut client_supports_hevc,
            client_supports_av1: &mut client_supports_av1,
            client_decode_caps: &mut client_decode_caps,
            user_pinned_codec: None,
            still_refinement_enabled: true,
            prefer_hardware: false,
            hud_width: params.width,
            hud_height: params.height,
            current_fps: params.fps,
            negotiated: params,
            last_stage_rect: Some((1280, 720)),
            stream_started_at: &mut stream_started_at,
            first_frame_logged: &mut first_frame_logged,
            decode_error_logged: &mut decode_error_logged,
            pending_display_tx: &mut pending_display_tx,
            update_tx: &update_tx,
        },
        |pcfg| build_controller_pipeline(pcfg, false, Instant::now(), None),
    );
    assert!(!ok2, "replace_pipeline 失败时升级必须返回 false");
    assert!(
        client.is_media_paused(),
        "replace_pipeline 失败后必须保持暂停"
    );
    assert!(pending_display_tx.is_empty());
    assert!(update_tx.try_pop().is_none());
    let _ = client.close(ByeReason::Normal);
}

#[test]
fn desktop_upgrade_replays_cached_stage_rect_on_new_renderer() {
    let params = SessionParams {
        width: 1280,
        height: 720,
        fps: 60,
        bitrate_bps: 8_000_000,
    };
    let mut client = make_streaming_tools_only_client(params);
    let real_pipeline_built = AtomicBool::new(false);
    let want_real_pipeline = AtomicBool::new(false);
    let is_hw_decoder_slot = AtomicBool::new(false);
    let mut backend = "tools-only".to_string();
    let backend_label = Mutex::new(backend.clone());
    let renderer_handle = Mutex::new(None);
    let renderer_pending_resize = Mutex::new(Arc::new(AtomicU64::new(0)));
    let layer_lease = Mutex::new(None);
    let mut is_hardware_decoder = false;
    let mut client_supports_hevc = false;
    let mut client_supports_av1 = false;
    let mut client_decode_caps = Vec::new();
    let mut stream_started_at = Instant::now();
    let mut first_frame_logged = false;
    let mut decode_error_logged = false;
    let mut pending_display_tx = VecDeque::new();
    let update_tx = BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP);
    let resizes = Arc::new(Mutex::new(Vec::<(u32, u32)>::new()));
    let resizes_for_build = Arc::clone(&resizes);

    let ok = try_resume_or_upgrade_desktop(
        DesktopUpgradeCtx {
            client: &mut client,
            real_pipeline_built: &real_pipeline_built,
            want_real_pipeline: &want_real_pipeline,
            is_hw_decoder_slot: &is_hw_decoder_slot,
            backend: &mut backend,
            backend_label: &backend_label,
            renderer_handle: &renderer_handle,
            renderer_pending_resize: &renderer_pending_resize,
            layer_lease: &layer_lease,
            active_backend_suffix: None,
            is_hardware_decoder: &mut is_hardware_decoder,
            client_supports_hevc: &mut client_supports_hevc,
            client_supports_av1: &mut client_supports_av1,
            client_decode_caps: &mut client_decode_caps,
            user_pinned_codec: None,
            still_refinement_enabled: true,
            prefer_hardware: false,
            hud_width: params.width,
            hud_height: params.height,
            current_fps: params.fps,
            negotiated: params,
            last_stage_rect: Some((1440, 900)),
            stream_started_at: &mut stream_started_at,
            first_frame_logged: &mut first_frame_logged,
            decode_error_logged: &mut decode_error_logged,
            pending_display_tx: &mut pending_display_tx,
            update_tx: &update_tx,
        },
        move |pcfg| {
            let dec = rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
                resolution: pcfg.resolution,
                ..rc_decode::FakeDecoderConfig::default()
            })?;
            let shared: RendererHandle = Arc::new(Mutex::new(Box::new(RecordingStageRenderer {
                resizes: resizes_for_build,
            })));
            let pending_resize = Arc::new(AtomicU64::new(0));
            let wrapper = SharedRenderer::new(Arc::clone(&shared), Arc::clone(&pending_resize));
            let pipeline =
                ControllerPipeline::with_backends(pcfg.clone(), Box::new(dec), Box::new(wrapper))?;
            Ok(BuiltPipeline {
                pipeline,
                backend_label: "fake".to_string(),
                renderer: shared,
                pending_resize,
                layer_addr: 0,
                is_hardware: false,
            })
        },
    );
    assert!(ok, "正常升级必须成功");
    assert!(!client.is_media_paused());
    assert!(real_pipeline_built.load(Ordering::Acquire));
    assert!(want_real_pipeline.load(Ordering::Acquire));
    assert_eq!(
        *resizes.lock().unwrap(),
        vec![(1440, 900)],
        "升级创建新 renderer_handle 后必须立即回放缓存的 StageRect 尺寸"
    );
    let mut updates = Vec::new();
    while let Some(u) = update_tx.try_pop() {
        updates.push(u);
    }
    assert!(updates.iter().any(|u| matches!(
        u,
        SessionUpdate::MediaResumed {
            width: 1280,
            height: 720,
            ..
        }
    )));
    assert!(updates
        .iter()
        .any(|u| matches!(u, SessionUpdate::MediaState { paused: false })));
    let _ = client.close(ByeReason::Normal);
}

#[test]
fn client_media_caps_builder_and_av1_command_roundtrip() {
    let caps = rc_pipeline::default_codec_capabilities(true);
    let msg = build_client_media_caps_msg(&caps, true, CodecSelectionPref::OfficeClear);
    match msg {
        DisplayControlMsg::ClientMediaCaps {
            decode_caps,
            pref,
            supports_ext_codec_flags,
            ..
        } => {
            assert_eq!(decode_caps, caps);
            assert_eq!(pref, CodecSelectionPref::OfficeClear);
            assert!(supports_ext_codec_flags);
        }
        other => panic!("expected ClientMediaCaps, got {other:?}"),
    }

    let cmd = SessionCommand::SetCodec {
        codec: StreamCodec::Av1,
    };
    let copy_cmd = cmd;
    let json = serde_json::to_string(&copy_cmd).expect("serialize SetCodec(Av1)");
    let parsed: SessionCommand = serde_json::from_str(&json).expect("deserialize SetCodec");
    assert_eq!(parsed, cmd);

    // 晚到 Capabilities 补发 CodecDecodeFailed 及降级恢复后清除
    let mut pending = Some((
        rc_encode::Codec::Av1,
        1u64,
        "vt av1 unsupported".to_string(),
    ));
    // 同代不重复补发
    assert!(
        reconcile_decode_failure_on_capabilities(&mut pending, rc_encode::Codec::Av1, 1).is_none()
    );
    // 晚到的新代次 Capabilities 仍在 AV1 -> 补发带新 gen=2 的 CodecDecodeFailed
    assert_eq!(
        reconcile_decode_failure_on_capabilities(&mut pending, rc_encode::Codec::Av1, 2),
        Some(DisplayControlMsg::CodecDecodeFailed {
            codec: "av1".to_string(),
            generation: 2,
            reason: "vt av1 unsupported".to_string(),
        })
    );
    // 被控端切至 HEVC 后清除未恢复状态
    assert!(
        reconcile_decode_failure_on_capabilities(&mut pending, rc_encode::Codec::Hevc, 3).is_none()
    );
    assert!(pending.is_none());

    // fake_controller_stack 必须关闭内部 prefer_hardware 防止误调硬件热切
    let pcfg = PipelineConfig {
        resolution: Resolution::new(64, 64),
        prefer_hardware: true,
        ..PipelineConfig::default()
    };
    let (fake_pipe, _, _) = fake_controller_stack(&pcfg).expect("fake stack");
    assert!(!fake_pipe.config().prefer_hardware);
}

/// 对抗评审 Medium #4 回归：纯工具态升级桌面且 `still_refinement_enabled == false` 时，
/// 必须在发送 `ClientMediaCaps` 后同步补发 `DisplayControlMsg::StillRefineConfig { enabled: false }`。
#[test]
fn desktop_upgrade_emits_still_refine_disabled_config_when_off() {
    let params = SessionParams {
        width: 1280,
        height: 720,
        fps: 60,
        bitrate_bps: 8_000_000,
    };
    let mut client = make_streaming_tools_only_client(params);
    let real_pipeline_built = AtomicBool::new(false);
    let want_real_pipeline = AtomicBool::new(false);
    let is_hw_decoder_slot = AtomicBool::new(false);
    let mut backend = "tools-only".to_string();
    let backend_label = Mutex::new(backend.clone());
    let renderer_handle = Mutex::new(None);
    let renderer_pending_resize = Mutex::new(Arc::new(AtomicU64::new(0)));
    let layer_lease = Mutex::new(None);
    let mut is_hardware_decoder = false;
    let mut client_supports_hevc = false;
    let mut client_supports_av1 = false;
    let mut client_decode_caps = Vec::new();
    let mut stream_started_at = Instant::now();
    let mut first_frame_logged = false;
    let mut decode_error_logged = false;
    let mut pending_display_tx = VecDeque::new();
    let update_tx = BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP);

    let ok = try_resume_or_upgrade_desktop(
        DesktopUpgradeCtx {
            client: &mut client,
            real_pipeline_built: &real_pipeline_built,
            want_real_pipeline: &want_real_pipeline,
            is_hw_decoder_slot: &is_hw_decoder_slot,
            backend: &mut backend,
            backend_label: &backend_label,
            renderer_handle: &renderer_handle,
            renderer_pending_resize: &renderer_pending_resize,
            layer_lease: &layer_lease,
            active_backend_suffix: None,
            is_hardware_decoder: &mut is_hardware_decoder,
            client_supports_hevc: &mut client_supports_hevc,
            client_supports_av1: &mut client_supports_av1,
            client_decode_caps: &mut client_decode_caps,
            user_pinned_codec: None,
            still_refinement_enabled: false,
            prefer_hardware: false,
            hud_width: params.width,
            hud_height: params.height,
            current_fps: params.fps,
            negotiated: params,
            last_stage_rect: None,
            stream_started_at: &mut stream_started_at,
            first_frame_logged: &mut first_frame_logged,
            decode_error_logged: &mut decode_error_logged,
            pending_display_tx: &mut pending_display_tx,
            update_tx: &update_tx,
        },
        |pcfg| build_controller_pipeline(pcfg, false, Instant::now(), None),
    );
    assert!(ok);
    let msgs: Vec<DisplayControlMsg> = pending_display_tx
        .iter()
        .filter_map(|b| display_ctrl::decode_display_ctrl(b))
        .collect();
    let caps_idx = msgs
        .iter()
        .position(|m| matches!(m, DisplayControlMsg::ClientMediaCaps { .. }))
        .expect("must emit ClientMediaCaps on desktop upgrade");
    let cfg_idx = msgs
        .iter()
        .position(|m| matches!(m, DisplayControlMsg::StillRefineConfig { enabled: false }))
        .expect("must emit StillRefineConfig(false) when still refinement is disabled");
    assert!(
        cfg_idx > caps_idx,
        "StillRefineConfig(false) 必须紧跟在 ClientMediaCaps 之后发送: {msgs:?}"
    );
    let _ = client.close(ByeReason::Normal);
}
