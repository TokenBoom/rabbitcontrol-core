//! 进程内 `HostSession` + `session_bridge` 集成测试（T21 测试清单）。
//!
//! 全部 CI 用例使用临时端口 `127.0.0.1:0`（绝不触碰 19901）、假后端与
//! [`RecordingInjector`]，免 macOS 权限且不拉起 Tauri 窗口。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rc_client_core::session_bridge::{
    ConnectPhase, SessionCommand, SessionHandle, SessionUpdate, UiSessionConfig,
};
use rc_input::{InputEvent, MouseButton};
use rc_session::dev_cert::{DEV_CERT_PEM, DEV_KEY_PEM};
use rc_session::proto::SessionParams;
use rc_session::testkit::RecordingInjector;
use rc_session::{HostSession, HostSessionConfig, SessionClock};
use rc_types::Resolution;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

fn test_params() -> SessionParams {
    SessionParams {
        width: 64,
        height: 64,
        fps: 60,
        bitrate_bps: 8_000_000,
    }
}

fn test_pipeline_cfg() -> rc_pipeline::PipelineConfig {
    rc_pipeline::PipelineConfig {
        resolution: Resolution::new(64, 64),
        fps: 60,
        bitrate_bps: 8_000_000,
        prefer_hardware: false,
        target_latency_us: 22_000,
        trace_capacity: 4096,
        diff: rc_pipeline::DiffMode::TrustPlatform,
        clock_origin_us: None,
        max_packet_payload: rc_pipeline::MAX_PAYLOAD,
    }
}

type OriginSlot = Arc<Mutex<Option<Instant>>>;

fn origin_clock(origin: OriginSlot) -> SessionClock {
    Arc::new(move || match *origin.lock().expect("origin lock") {
        Some(o) => u32::try_from(o.elapsed().as_micros()).unwrap_or(u32::MAX),
        None => 0,
    })
}

struct HostRunResult {
    current_bitrate_bps: u32,
}

/// 在临时端口 `127.0.0.1:0` 上拉起进程内假后端 `HostSession`，返回监听地址与线程句柄。
fn spawn_inprocess_host(
    injector: RecordingInjector,
    max_duration: Duration,
) -> (SocketAddr, thread::JoinHandle<HostRunResult>) {
    let origin: OriginSlot = Arc::new(Mutex::new(None));
    let clock = origin_clock(Arc::clone(&origin));
    let mut host = HostSession::new(
        HostSessionConfig {
            listen_addr: "127.0.0.1:0".parse().expect("valid loopback addr"),
            mtu: rc_session::DEFAULT_SESSION_MTU,
            caps: test_params(),
            pipeline: test_pipeline_cfg(),
            handshake_timeout: Duration::from_secs(5),
            injector: Box::new(injector),
            pace_capture: true,
            auth: rc_session::HostAuthConfig::default(),
            approver: Box::new(rc_session::AutoApprover),
        },
        DEV_CERT_PEM,
        DEV_KEY_PEM,
        clock,
    )
    .expect("construct in-process host session");

    let factory_origin = Arc::clone(&origin);
    host.set_pipeline_factory_for(Box::new(move |pcfg| {
        *factory_origin.lock().expect("origin lock") = Some(Instant::now());
        let capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
            display: rc_capture::DisplayInfo {
                id: rc_types::DisplayId(0),
                resolution: pcfg.resolution,
                scale: 1.0,
                hdr: false,
            },
            fps: pcfg.fps,
            content: rc_capture::FakeContent::Dynamic,
            dirty_rect: None,
        })?;
        let encoder = rc_encode::FakeEncoder::with_tuning(
            rc_encode::EncoderConfig {
                resolution: pcfg.resolution,
                fps: pcfg.fps,
                bitrate_bps: pcfg.bitrate_bps,
                ..rc_encode::EncoderConfig::default()
            },
            500,
            512,
        )?;
        rc_pipeline::HostPipeline::with_backends_paced(
            pcfg.clone(),
            Box::new(capture),
            Box::new(encoder),
            true,
        )
    }));

    let addr = host.local_addr().expect("host local_addr");
    let handle = thread::spawn(move || {
        host.accept_and_handshake(CONNECT_TIMEOUT)
            .expect("host accept_and_handshake");
        let started = Instant::now();
        let _summary = host
            .run(&mut || started.elapsed() >= max_duration)
            .expect("host run");
        HostRunResult {
            current_bitrate_bps: host.current_bitrate_bps(),
        }
    });
    (addr, handle)
}

fn ui_cfg(addr: SocketAddr, watch_only: bool) -> UiSessionConfig {
    UiSessionConfig {
        connect_addr: addr,
        password: None,
        watch_only,
        width: 64,
        height: 64,
        fps: 60,
        bitrate_bps: 8_000_000,
        prefer_hardware: false,
        clipboard_enabled: false,
        audio_enabled: false,
        force_relay: false,
        relay_grant: None,
        ..UiSessionConfig::default()
    }
}

/// 轮询拉取 `SessionUpdate`，直到 `pred` 返回 `true` 或超时。
fn collect_until(
    session: &SessionHandle,
    timeout: Duration,
    mut pred: impl FnMut(&[SessionUpdate]) -> bool,
) -> Vec<SessionUpdate> {
    let mut updates = Vec::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        while let Some(u) = session.try_recv_update() {
            updates.push(u);
        }
        if pred(&updates) {
            return updates;
        }
        thread::sleep(Duration::from_millis(10));
    }
    while let Some(u) = session.try_recv_update() {
        updates.push(u);
    }
    updates
}

#[test]
fn bridge_connects_to_inprocess_host() {
    let injector = RecordingInjector::new();
    let (host_addr, host_thread) = spawn_inprocess_host(injector, Duration::from_secs(10));

    let session = SessionHandle::spawn(ui_cfg(host_addr, false));

    // 等待收到 Connecting → Negotiated → 至少一条 fps > 0 的 Hud 快照。
    let updates = collect_until(&session, Duration::from_secs(6), |list| {
        list.iter()
            .any(|u| matches!(u, SessionUpdate::Hud(h) if h.fps > 0.0))
    });

    assert!(
        updates.iter().any(|u| matches!(
            u,
            SessionUpdate::Connecting {
                phase: ConnectPhase::EndpointCreating,
                watch_only: false,
            }
        )),
        "应先上报 EndpointCreating，实际更新：{updates:?}"
    );
    assert!(
        updates.iter().any(|u| matches!(
            u,
            SessionUpdate::Negotiated {
                width: 64,
                height: 64,
                fps: 60,
                bitrate_bps: 8_000_000,
                backend,
                watch_only: false,
                ..
            } if backend == "fake"
        )),
        "应收到 Welcome 裁定参数 Negotiated，实际更新：{updates:?}"
    );
    assert!(
        updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::Hud(h) if h.fps > 0.0)),
        "应收到至少一条 fps > 0 的 HUD 快照，实际更新：{updates:?}"
    );

    // 主动发送 Disconnect，应收到 Ended 且线程干净退出。
    session.send(SessionCommand::Disconnect);
    let end_updates = collect_until(&session, Duration::from_secs(5), |list| {
        list.iter()
            .any(|u| matches!(u, SessionUpdate::Ended { .. }))
    });
    assert!(
        end_updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::Ended { .. })),
        "Disconnect 后应收到 Ended，实际：{end_updates:?}"
    );

    session.join();
    let _ = host_thread.join().expect("host thread join");
}

#[test]
fn watch_mode_sends_no_input() {
    // 场景 A：watch_only = true → 持续 send_input，host 侧 RecordingInjector 收到 0 条事件（U9）。
    {
        let injector = RecordingInjector::new();
        let observer = injector.clone();
        let (host_addr, host_thread) = spawn_inprocess_host(injector, Duration::from_secs(10));
        let session = SessionHandle::spawn(ui_cfg(host_addr, true));

        let updates = collect_until(&session, Duration::from_secs(5), |list| {
            list.iter()
                .any(|u| matches!(u, SessionUpdate::Negotiated { .. }))
        });
        assert!(
            updates
                .iter()
                .any(|u| matches!(u, SessionUpdate::Negotiated { .. })),
            "watch_only 会话应正常握手"
        );

        for _ in 0..10 {
            session.send_input(InputEvent::MouseMove { x: 1000, y: 2000 });
            session.send_input(InputEvent::MouseButton {
                button: MouseButton::Left,
                pressed: true,
            });
            session.send_input(InputEvent::MouseButton {
                button: MouseButton::Left,
                pressed: false,
            });
            thread::sleep(Duration::from_millis(20));
        }

        session.send(SessionCommand::Disconnect);
        session.join();
        let _ = host_thread.join().expect("host thread join");

        assert_eq!(
            observer.injected_count(),
            0,
            "watch_only=true 时 host RecordingInjector 必须收到 0 事件"
        );
    }

    // 场景 B：watch_only = false → 同场景必须有事件注入（U9 双向钉死）。
    {
        let injector = RecordingInjector::new();
        let observer = injector.clone();
        let (host_addr, host_thread) = spawn_inprocess_host(injector, Duration::from_secs(10));
        let session = SessionHandle::spawn(ui_cfg(host_addr, false));

        let updates = collect_until(&session, Duration::from_secs(5), |list| {
            list.iter()
                .any(|u| matches!(u, SessionUpdate::Negotiated { .. }))
        });
        assert!(updates
            .iter()
            .any(|u| matches!(u, SessionUpdate::Negotiated { .. })));

        for _ in 0..5 {
            session.send_input(InputEvent::MouseMove { x: 1000, y: 2000 });
            session.send_input(InputEvent::MouseButton {
                button: MouseButton::Left,
                pressed: true,
            });
            thread::sleep(Duration::from_millis(30));
        }

        session.send(SessionCommand::Disconnect);
        session.join();
        let _ = host_thread.join().expect("host thread join");

        assert!(
            observer.injected_count() > 0,
            "watch_only=false 时 host RecordingInjector 必须收到输入事件"
        );
    }
}

#[test]
fn set_bitrate_command_flows_to_host() {
    let injector = RecordingInjector::new();
    let (host_addr, host_thread) = spawn_inprocess_host(injector, Duration::from_secs(10));
    let session = SessionHandle::spawn(ui_cfg(host_addr, false));

    let updates = collect_until(&session, Duration::from_secs(5), |list| {
        list.iter()
            .any(|u| matches!(u, SessionUpdate::Negotiated { .. }))
    });
    assert!(updates
        .iter()
        .any(|u| matches!(u, SessionUpdate::Negotiated { .. })));

    // 稍等初次带宽粗测在回环上结算完毕，再下发手动 SetBitrate(reason=2)。
    thread::sleep(Duration::from_millis(300));
    let target_bps = 3_500_000;
    session.send(SessionCommand::SetBitrate { bps: target_bps });
    thread::sleep(Duration::from_millis(250));

    session.send(SessionCommand::Disconnect);
    session.join();
    let host_result = host_thread.join().expect("host thread join");

    assert_eq!(
        host_result.current_bitrate_bps, target_bps,
        "host 侧当前生效码率应更新为 UI 下发的手动码率"
    );
}

#[test]
fn input_events_reach_injector_normalized() {
    let injector = RecordingInjector::new();
    let mut observer = injector.clone();
    let (host_addr, host_thread) = spawn_inprocess_host(injector, Duration::from_secs(10));
    let session = SessionHandle::spawn(ui_cfg(host_addr, false));

    let updates = collect_until(&session, Duration::from_secs(5), |list| {
        list.iter()
            .any(|u| matches!(u, SessionUpdate::Negotiated { .. }))
    });
    assert!(updates
        .iter()
        .any(|u| matches!(u, SessionUpdate::Negotiated { .. })));

    session.send_input(InputEvent::MouseMove {
        x: 32_768,
        y: 32_768,
    });
    session.send_input(InputEvent::MouseButton {
        button: MouseButton::Left,
        pressed: true,
    });
    session.send_input(InputEvent::MouseButton {
        button: MouseButton::Left,
        pressed: false,
    });
    session.send_input(InputEvent::MouseWheel {
        delta: 3,
        horizontal: false,
    });

    thread::sleep(Duration::from_millis(250));
    session.send(SessionCommand::Disconnect);
    session.join();
    let _ = host_thread.join().expect("host thread join");

    let events = observer.take_events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            InputEvent::MouseMove {
                x: 32_768,
                y: 32_768
            }
        )),
        "应收到原样归一化坐标 MouseMove(32768, 32768)，实际：{events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            InputEvent::MouseButton {
                button: MouseButton::Left,
                pressed: true
            }
        )),
        "应收到 MouseButton(Left, pressed=true)，实际：{events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            InputEvent::MouseWheel {
                delta: 3,
                horizontal: false
            }
        )),
        "应收到 MouseWheel(delta=3, horizontal=false)，实际：{events:?}"
    );
}

#[test]
fn ended_session_commands_are_ignored() {
    let injector = RecordingInjector::new();
    let (host_addr, host_thread) = spawn_inprocess_host(injector, Duration::from_secs(10));
    let session = SessionHandle::spawn(ui_cfg(host_addr, false));

    let updates = collect_until(&session, Duration::from_secs(5), |list| {
        list.iter()
            .any(|u| matches!(u, SessionUpdate::Negotiated { .. }))
    });
    assert!(updates
        .iter()
        .any(|u| matches!(u, SessionUpdate::Negotiated { .. })));

    session.send(SessionCommand::Disconnect);
    let end_updates = collect_until(&session, Duration::from_secs(5), |list| {
        list.iter()
            .any(|u| matches!(u, SessionUpdate::Ended { .. }))
    });
    assert!(end_updates
        .iter()
        .any(|u| matches!(u, SessionUpdate::Ended { .. })));

    // 等待 running 标志置 false。
    let deadline = Instant::now() + Duration::from_secs(2);
    while session.is_running() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!session.is_running(), "Ended 后 is_running 必须为 false");

    // Ended 后重复发控制命令与输入必须静默幂等、不 panic、不阻塞（U10）。
    session.send(SessionCommand::SetBitrate { bps: 4_000_000 });
    session.send(SessionCommand::StageRect {
        width: 1280,
        height: 720,
    });
    session.send(SessionCommand::Disconnect);
    session.send_input(InputEvent::MouseMove { x: 100, y: 200 });
    assert!(!session.is_running());

    session.join();
    let _ = host_thread.join().expect("host thread join");
}

#[test]
fn live_display_reconfigure_updates_resolution_fps_and_keeps_streaming() {
    use rc_client_core::host_bridge::{HostHandle, UiHostConfig};

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        password: None,
        approval_timeout_us: 5_000_000,
        prefer_hardware: false,
        require_approval: false,
        auto_accept_with_password: true,
        auto_rotate_password: false,
        clipboard_enabled: false,
        audio_enabled: false,
        ..UiHostConfig::default()
    })
    .expect("spawn offline host handle");

    let mut cfg = ui_cfg(host.listen_addr(), false);
    cfg.width = 1920;
    cfg.height = 1080;
    cfg.fps = 60;
    cfg.bitrate_bps = 12_000_000;
    let session = SessionHandle::spawn(cfg);

    // 1) 握手入流后应立刻收到初始 DisplayConfig（含 144fps 上限与原生预设）及 fps > 0 的 HUD
    let initial = collect_until(&session, Duration::from_secs(6), |list| {
        let got_cfg = list
            .iter()
            .any(|u| matches!(u, SessionUpdate::DisplayConfig { .. }));
        let got_hud = list
            .iter()
            .any(|u| matches!(u, SessionUpdate::Hud(h) if h.fps > 0.0));
        got_cfg && got_hud
    });
    assert!(
        initial.iter().any(|u| matches!(
            u,
            SessionUpdate::DisplayConfig {
                width: 1920,
                height: 1080,
                fps: 60,
                native_width: 1920,
                native_height: 1080,
                max_fps: 144,
                presets,
            } if presets.iter().any(|p| p.is_native && p.width == 1920 && p.height == 1080)
                && presets.iter().any(|p| p.width == 1280 && p.height == 720)
        )),
        "入流后应收到 1920x1080@60 (max_fps=144) 初始 DisplayConfig，实际：{initial:?}"
    );

    // 2) 会话中热切换到 1280x720@120fps
    session.send(SessionCommand::SetStreamParams {
        width: 1280,
        height: 720,
        fps: 120,
    });

    // 3) 应收到更新后的 DisplayConfig(1280x720@120) 且后续 HUD 分辨率更新为 1280x720 并持续出帧
    let after_switch = collect_until(&session, Duration::from_secs(6), |list| {
        let got_new_cfg = list.iter().any(|u| {
            matches!(
                u,
                SessionUpdate::DisplayConfig {
                    width: 1280,
                    height: 720,
                    fps: 120,
                    ..
                }
            )
        });
        let got_new_hud = list.iter().any(|u| {
            matches!(
                u,
                SessionUpdate::Hud(h) if h.resolution == "1280x720" && h.fps > 0.0
            )
        });
        got_new_cfg && got_new_hud
    });
    assert!(
        after_switch.iter().any(|u| matches!(
            u,
            SessionUpdate::DisplayConfig {
                width: 1280,
                height: 720,
                fps: 120,
                native_width: 1920,
                native_height: 1080,
                max_fps: 144,
                ..
            }
        )),
        "热切换后应收到更新后的 DisplayConfig(1280x720@120)，实际：{after_switch:?}"
    );
    assert!(
        after_switch.iter().any(|u| matches!(
            u,
            SessionUpdate::Hud(h) if h.resolution == "1280x720" && h.fps > 0.0
        )),
        "热切换后 HUD 应更新为 1280x720 且持续产出新帧(fps > 0)，实际：{after_switch:?}"
    );

    session.send(SessionCommand::Disconnect);
    session.join();
    host.stop();
}

#[test]
fn lock_remote_screen_live_and_on_disconnect_reaches_host() {
    use rc_client_core::host_bridge::{HostHandle, UiHostConfig};

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        password: None,
        approval_timeout_us: 10_000_000,
        prefer_hardware: false,
        require_approval: false,
        auto_accept_with_password: true,
        auto_rotate_password: false,
        clipboard_enabled: false,
        audio_enabled: false,
        ..UiHostConfig::default()
    })
    .expect("spawn fake host");

    let mut cfg = ui_cfg(host.listen_addr(), false);
    cfg.prefer_hardware = false;
    let session = SessionHandle::spawn(cfg);

    let init = collect_until(&session, Duration::from_secs(10), |list| {
        list.iter()
            .any(|u| matches!(u, SessionUpdate::Negotiated { .. }))
    });
    assert!(
        init.iter()
            .any(|u| matches!(u, SessionUpdate::Negotiated { .. })),
        "应成功协商连接，实际：{init:?}"
    );
    assert_eq!(host.lock_screen_count(), 0);

    // 1) 在线立即锁屏
    session.send(SessionCommand::LockRemoteScreen);
    let wait_live = Instant::now() + Duration::from_secs(3);
    while Instant::now() < wait_live && host.lock_screen_count() < 1 {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        host.lock_screen_count(),
        1,
        "在线 LockRemoteScreen 应在 3s 内送达 Host"
    );

    // 2) 退出时自动锁屏（随 Disconnect 前刷新发出）
    session.request_lock_on_disconnect();
    session.send(SessionCommand::Disconnect);
    session.join();

    let wait_exit = Instant::now() + Duration::from_secs(3);
    while Instant::now() < wait_exit && host.lock_screen_count() < 2 {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        host.lock_screen_count(),
        2,
        "request_lock_on_disconnect + Disconnect 应在 3s 内送达 Host"
    );

    host.stop();
}

#[test]
fn host_stop_with_session_switching_notifies_client() {
    use rc_client_core::host_bridge::{HostHandle, UiHostConfig};
    use rc_client_core::session_bridge::SESSION_SWITCHING_REASON;
    use rc_session::proto::ByeReason;

    let mut host = HostHandle::spawn(UiHostConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        password: Some("SWITCH26".to_string()),
        approval_timeout_us: 10_000_000,
        prefer_hardware: false,
        require_approval: false,
        auto_accept_with_password: true,
        auto_rotate_password: false,
        clipboard_enabled: false,
        audio_enabled: false,
        ..UiHostConfig::default()
    })
    .expect("spawn fake host");

    let mut cfg = ui_cfg(host.listen_addr(), false);
    cfg.password = Some("SWITCH26".to_string());
    cfg.prefer_hardware = false;
    let session = SessionHandle::spawn(cfg);

    let init = collect_until(&session, Duration::from_secs(10), |list| {
        list.iter()
            .any(|u| matches!(u, SessionUpdate::Negotiated { .. }))
    });
    assert!(init
        .iter()
        .any(|u| matches!(u, SessionUpdate::Negotiated { .. })));

    host.stop_with_reason(ByeReason::SessionSwitching);

    let ended = collect_until(&session, Duration::from_secs(10), |list| {
        list.iter()
            .any(|u| matches!(u, SessionUpdate::Ended { .. }))
    });
    assert!(
        ended.iter().any(|u| matches!(
            u,
            SessionUpdate::SessionSwitching { reason } if reason == SESSION_SWITCHING_REASON
        )),
        "应推送 SessionUpdate::SessionSwitching 供前端触发重连，实际：{ended:?}"
    );
    assert!(
        ended.iter().any(|u| matches!(
            u,
            SessionUpdate::Ended { reason } if reason == SESSION_SWITCHING_REASON
        )),
        "应以 SESSION_SWITCHING_REASON 结束当前会话，实际：{ended:?}"
    );
    session.join();
}
