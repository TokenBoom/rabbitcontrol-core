use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rc_input::{InputEvent, MouseButton};
use rc_net::quic::{Identity, QuicEndpoint};
use rc_net::{NetEvent, NetStats, Transport};
use rc_session::proto::{ByeReason, ControlMessage, SessionParams};
use rc_session::{
    ClientSession, ClientSessionConfig, ReconnectOutcome, SessionClock, SessionState,
    ToolPermissions,
};
use rc_types::Resolution;

use super::super::adapters::{ActiveRelayInterrupt, BridgeInputCapture};
use super::super::classify::{
    classify_gave_up_end, classify_runtime_err_end, classify_stop_reason_end,
    is_non_recoverable_error_reason, signaling_disconnect_end,
};
use super::super::display_ctrl::refresh_after_reconnect_outcome;
use super::super::handle::{ScrollDispatchState, SessionHandle};
use super::super::queues::{BoundedInputQueue, BoundedQueue, BoundedUpdateQueue};
use super::super::tools::{FileClientWorker, ToolClientHub};
use super::super::types::{
    SessionCommand, SessionEnd, SessionUpdate, UiSessionConfig, COMMAND_CHANNEL_CAP,
    INPUT_CHANNEL_CAP, SESSION_SWITCHING_REASON, UPDATE_CHANNEL_CAP,
};

#[test]
fn detach_and_abort_returns_within_bounded_max_wait_for_stuck_thread() {
    let (unblock_tx, unblock_rx) = mpsc::channel::<()>();
    let cmd_tx = Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP));
    let file_event_rx = Arc::new(BoundedQueue::new(16));
    let (mut file_worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_event_rx));
    let disconnect_flag = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicBool::new(true));

    let stuck_thread = thread::spawn(move || {
        // 模拟卡在阻塞系统调用中、不响应 disconnect_flag 的僵尸会话线程。
        let _ = unblock_rx.recv_timeout(Duration::from_secs(5));
    });

    let handle = SessionHandle {
        cmd_tx: Arc::clone(&cmd_tx),
        display_ctrl_tx: Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP)),
        input_tx: Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP)),
        update_rx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
        file_event_rx,
        terminal_event_rx: Arc::new(BoundedQueue::new(16)),
        portmap_latest: Arc::new(Mutex::new(None)),
        tools_hub: Arc::new(Mutex::new(ToolClientHub::new())),
        file_handle,
        disconnect_flag: Arc::clone(&disconnect_flag),
        lock_on_disconnect: Arc::new(AtomicBool::new(false)),
        relay_interrupt: Arc::new(Mutex::new(None)),
        running: Arc::clone(&running),
        watch_only: Arc::new(AtomicBool::new(false)),
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        still_refine_metrics: Arc::new(Mutex::new(
            crate::still_refine::StillRefineMetrics::default(),
        )),
        scroll_state: Arc::new(ScrollDispatchState::new()),
        encrypt_connection: false,
        base_config: UiSessionConfig::default(),
        layer_lease: Arc::new(Mutex::new(None)),
        upgrade_surface: Arc::new(Mutex::new(None)),
        thread: Some(stuck_thread),
    };

    let start = Instant::now();
    handle.detach_and_abort(Duration::from_millis(50));
    let elapsed = start.elapsed();

    assert!(
        disconnect_flag.load(Ordering::Acquire),
        "detach_and_abort 必须立即置位 disconnect_flag"
    );
    assert_eq!(cmd_tx.drain_all(), vec![SessionCommand::Disconnect]);
    assert!(
        elapsed < Duration::from_millis(400),
        "detach_and_abort(50ms) 对卡住线程必须有界返回，实际耗时 {elapsed:?}"
    );

    // 释放阻塞线程以便后台回收线程干净退出。
    let _ = unblock_tx.send(());
    file_worker.shutdown();
}

#[test]
fn ended_recoverable_classification_covers_all_terminal_and_disconnect_cases() {
    // 1) 信令会话在 Reconnecting 退出时按 transport_label 精确文案 + recoverable = true。
    assert_eq!(
        signaling_disconnect_end("UDP LAN"),
        SessionEnd::recoverable("局域网连接已断开")
    );
    assert_eq!(
        signaling_disconnect_end("UDP P2P"),
        SessionEnd::recoverable("P2P 连接已断开")
    );
    assert_eq!(
        signaling_disconnect_end("TCP Relay"),
        SessionEnd::recoverable("中继连接已断开")
    );

    // 2) 纯 IP 直连 GaveUp：非 SessionSwitching → recoverable = true；SessionSwitching / ByeNormal → false。
    let gave_up = classify_gave_up_end(None);
    assert_eq!(gave_up.reason, "重连次数已耗尽");
    assert!(gave_up.recoverable);

    let gave_up_disc = classify_gave_up_end(Some(&rc_session::StopReason::Disconnected(
        "peer timeout".to_string(),
    )));
    assert!(gave_up_disc.recoverable);

    let gave_up_switch = classify_gave_up_end(Some(&rc_session::StopReason::ByeReceived(
        ByeReason::SessionSwitching,
    )));
    assert_eq!(gave_up_switch.reason, SESSION_SWITCHING_REASON);
    assert!(!gave_up_switch.recoverable);

    // 3) Streaming 期 StopReason 判定。
    assert!(
        !classify_stop_reason_end(&rc_session::StopReason::ByeReceived(ByeReason::Normal))
            .recoverable
    );
    assert!(
        !classify_stop_reason_end(&rc_session::StopReason::ByeReceived(
            ByeReason::SessionSwitching
        ))
        .recoverable
    );
    assert!(!classify_stop_reason_end(&rc_session::StopReason::Requested).recoverable);
    assert!(
        classify_stop_reason_end(&rc_session::StopReason::Disconnected(
            "connection lost".to_string()
        ))
        .recoverable
    );
    assert!(
        !classify_stop_reason_end(&rc_session::StopReason::Disconnected(
            "用户主动断开".to_string()
        ))
        .recoverable
    );
    assert!(
        !classify_stop_reason_end(&rc_session::StopReason::Disconnected(
            "InvalidPeerCertificate(UnknownIssuer)".to_string()
        ))
        .recoverable
    );
    assert!(
        !classify_stop_reason_end(&rc_session::StopReason::Disconnected(
            "密码错误，鉴权失败".to_string()
        ))
        .recoverable
    );

    // 4) 运行期驱动错误判定（断网可恢复 vs 用户断开/鉴权/mTLS 不可恢复）。
    assert!(
        classify_runtime_err_end(
            "重连驱动失败",
            &rc_types::Error::Network("transport poll failed".to_string()),
            false,
        )
        .recoverable
    );
    assert!(
        !classify_runtime_err_end(
            "重连驱动失败",
            &rc_types::Error::Network("auth rejected: wrong password".to_string()),
            false,
        )
        .recoverable
    );
    assert!(
        !classify_runtime_err_end(
            "会话运行失败",
            &rc_types::Error::Network("mTLS InvalidPeerCertificate(Revoked)".to_string()),
            false,
        )
        .recoverable
    );
    let user_end = classify_runtime_err_end(
        "会话运行失败",
        &rc_types::Error::Network("connection reset".to_string()),
        true,
    );
    assert_eq!(user_end.reason, "用户主动断开");
    assert!(!user_end.recoverable);

    // 5) 硬件解码持久失败 / P2pOnly 错误文案不可恢复。
    assert!(is_non_recoverable_error_reason(
        "远端画面解码失败（请确认被控端已授予屏幕录制权限）"
    ));
    assert!(is_non_recoverable_error_reason(
        "P2P 直连失败（当前为「仅 P2P」模式，未回退中继）：timeout"
    ));

    // 6) 新增 SessionCommand & SessionUpdate JSON 序列化形态校验。
    let cmd_pause: SessionCommand =
        serde_json::from_str(r#"{"type":"set_media_paused","paused":true}"#)
            .expect("parse set_media_paused");
    assert_eq!(cmd_pause, SessionCommand::SetMediaPaused { paused: true });
    let cmd_probe: SessionCommand =
        serde_json::from_str(r#"{"type":"probe_now"}"#).expect("parse probe_now");
    assert_eq!(cmd_probe, SessionCommand::ProbeNow);

    let ended_json = serde_json::to_value(SessionUpdate::Ended {
        reason: "局域网连接已断开".to_string(),
        recoverable: true,
        ui_error: None,
    })
    .expect("serialize Ended");
    assert_eq!(ended_json["kind"], "ended");
    assert_eq!(ended_json["data"]["recoverable"], true);

    let reconnecting_json = serde_json::to_value(SessionUpdate::Reconnecting {
        attempt: 2,
        max_attempts: 5,
        reason: "第 2/5 次重连尝试中…".to_string(),
    })
    .expect("serialize Reconnecting");
    assert_eq!(reconnecting_json["kind"], "reconnecting");
    assert_eq!(reconnecting_json["data"]["attempt"], 2);
    assert_eq!(reconnecting_json["data"]["max_attempts"], 5);

    let resumed_json = serde_json::to_value(SessionUpdate::MediaResumed {
        backend: "videotoolbox+metal".to_string(),
        width: 1920,
        height: 1080,
        fps: 60,
    })
    .expect("serialize MediaResumed");
    assert_eq!(resumed_json["kind"], "media_resumed");
    assert_eq!(resumed_json["data"]["backend"], "videotoolbox+metal");
}

#[test]
fn detach_and_abort_waits_graceful_window_before_triggering_force_disconnect() {
    // 场景 A：会话线程在优雅窗口内收到 Disconnect 并完成优雅发送后退出，
    // 期间 disconnect_flag 与 relay_interrupt 均不得提前置位。
    let cmd_tx = Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP));
    let file_event_rx = Arc::new(BoundedQueue::new(16));
    let (mut file_worker, file_handle) = FileClientWorker::spawn(Arc::clone(&file_event_rx));
    let disconnect_flag = Arc::new(AtomicBool::new(false));
    let relay_cancel = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicBool::new(true));
    let observed_clean_graceful = Arc::new(AtomicBool::new(false));
    let thread_ready = Arc::new(AtomicBool::new(false));

    let t_cmd = Arc::clone(&cmd_tx);
    let t_disc = Arc::clone(&disconnect_flag);
    let t_cancel = Arc::clone(&relay_cancel);
    let t_running = Arc::clone(&running);
    let t_clean = Arc::clone(&observed_clean_graceful);
    let t_ready = Arc::clone(&thread_ready);
    let graceful_thread = thread::spawn(move || {
        t_ready.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Some(SessionCommand::Disconnect) = t_cmd.try_pop() {
                // 模拟发完 LockScreen / Bye(Normal)（留足 CI 虚拟化调度抖动余量）
                thread::sleep(Duration::from_millis(5));
                if !t_disc.load(Ordering::Acquire) && !t_cancel.load(Ordering::Acquire) {
                    t_clean.store(true, Ordering::Release);
                }
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        t_running.store(false, Ordering::Release);
    });
    let ready_deadline = Instant::now() + Duration::from_secs(2);
    while !thread_ready.load(Ordering::Acquire) && Instant::now() < ready_deadline {
        thread::yield_now();
    }

    let handle = SessionHandle {
        cmd_tx: Arc::clone(&cmd_tx),
        display_ctrl_tx: Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP)),
        input_tx: Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP)),
        update_rx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
        file_event_rx,
        terminal_event_rx: Arc::new(BoundedQueue::new(16)),
        portmap_latest: Arc::new(Mutex::new(None)),
        tools_hub: Arc::new(Mutex::new(ToolClientHub::new())),
        file_handle,
        disconnect_flag: Arc::clone(&disconnect_flag),
        lock_on_disconnect: Arc::new(AtomicBool::new(false)),
        relay_interrupt: Arc::new(Mutex::new(Some(ActiveRelayInterrupt::Dialing(Arc::clone(
            &relay_cancel,
        ))))),
        running: Arc::clone(&running),
        watch_only: Arc::new(AtomicBool::new(false)),
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        still_refine_metrics: Arc::new(Mutex::new(
            crate::still_refine::StillRefineMetrics::default(),
        )),
        scroll_state: Arc::new(ScrollDispatchState::new()),
        encrypt_connection: false,
        base_config: UiSessionConfig::default(),
        layer_lease: Arc::new(Mutex::new(None)),
        upgrade_surface: Arc::new(Mutex::new(None)),
        thread: Some(graceful_thread),
    };

    handle.detach_and_abort(Duration::from_millis(600));
    assert!(
        observed_clean_graceful.load(Ordering::Acquire),
        "detach_and_abort 必须先给优雅窗口，让会话线程在 socket 切断前发完 LockScreen / Bye"
    );
    assert!(
        !disconnect_flag.load(Ordering::Acquire) && !relay_cancel.load(Ordering::Acquire),
        "优雅窗口内已干净退出的线程不得触发强断"
    );
    file_worker.shutdown();

    // 场景 B：线程忽略 Disconnect 卡住，超过 80ms 优雅窗口后必须触发 trigger_disconnect() 强断退出。
    let cmd_tx2 = Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP));
    let file_event_rx2 = Arc::new(BoundedQueue::new(16));
    let (mut file_worker2, file_handle2) = FileClientWorker::spawn(Arc::clone(&file_event_rx2));
    let disconnect_flag2 = Arc::new(AtomicBool::new(false));
    let relay_cancel2 = Arc::new(AtomicBool::new(false));
    let running2 = Arc::new(AtomicBool::new(true));
    let thread_ready2 = Arc::new(AtomicBool::new(false));

    let t_cancel2 = Arc::clone(&relay_cancel2);
    let t_running2 = Arc::clone(&running2);
    let t_ready2 = Arc::clone(&thread_ready2);
    let force_thread = thread::spawn(move || {
        t_ready2.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if t_cancel2.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        t_running2.store(false, Ordering::Release);
    });
    let ready_deadline2 = Instant::now() + Duration::from_secs(2);
    while !thread_ready2.load(Ordering::Acquire) && Instant::now() < ready_deadline2 {
        thread::yield_now();
    }

    let handle2 = SessionHandle {
        cmd_tx: cmd_tx2,
        display_ctrl_tx: Arc::new(BoundedQueue::new(COMMAND_CHANNEL_CAP)),
        input_tx: Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP)),
        update_rx: Arc::new(BoundedUpdateQueue::new(UPDATE_CHANNEL_CAP)),
        file_event_rx: file_event_rx2,
        terminal_event_rx: Arc::new(BoundedQueue::new(16)),
        portmap_latest: Arc::new(Mutex::new(None)),
        tools_hub: Arc::new(Mutex::new(ToolClientHub::new())),
        file_handle: file_handle2,
        disconnect_flag: Arc::clone(&disconnect_flag2),
        lock_on_disconnect: Arc::new(AtomicBool::new(false)),
        relay_interrupt: Arc::new(Mutex::new(Some(ActiveRelayInterrupt::Dialing(Arc::clone(
            &relay_cancel2,
        ))))),
        running: Arc::clone(&running2),
        watch_only: Arc::new(AtomicBool::new(false)),
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        still_refine_metrics: Arc::new(Mutex::new(
            crate::still_refine::StillRefineMetrics::default(),
        )),
        scroll_state: Arc::new(ScrollDispatchState::new()),
        encrypt_connection: false,
        base_config: UiSessionConfig::default(),
        layer_lease: Arc::new(Mutex::new(None)),
        upgrade_surface: Arc::new(Mutex::new(None)),
        thread: Some(force_thread),
    };

    let start = Instant::now();
    handle2.detach_and_abort(Duration::from_millis(800));
    let elapsed = start.elapsed();
    assert!(
        disconnect_flag2.load(Ordering::Acquire) && relay_cancel2.load(Ordering::Acquire),
        "优雅窗口超时后必须触发 trigger_disconnect() 强制中断底层 socket"
    );
    assert!(
        elapsed >= Duration::from_millis(60) && elapsed < Duration::from_millis(800),
        "强断应发生在 80ms 优雅窗口之后并在 max_wait 内返回，实际耗时 {elapsed:?}"
    );
    file_worker2.shutdown();
}

#[test]
fn reconnect_resumed_refreshes_input_queue_wake_handle() {
    use std::sync::atomic::AtomicUsize;

    struct WakeStubTransport {
        inbound: VecDeque<NetEvent>,
        wake_hits: Arc<AtomicUsize>,
    }

    impl Transport for WakeStubTransport {
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
        fn wake_handle(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
            let hits = Arc::clone(&self.wake_hits);
            Some(Arc::new(move || {
                hits.fetch_add(1, Ordering::Relaxed);
            }))
        }
    }

    let params = SessionParams {
        width: 1280,
        height: 720,
        fps: 60,
        bitrate_bps: 8_000_000,
    };
    let mut initial_welcome = Vec::new();
    ControlMessage::Welcome(rc_session::proto::Welcome {
        session_id: 42,
        granted: params,
        auth_status: rc_session::proto::AuthStatus::Ok,
        host_flags: rc_session::proto::HostFlags(0),
    })
    .encode(&mut initial_welcome);

    let old_wake_hits = Arc::new(AtomicUsize::new(0));
    let new_wake_hits = Arc::new(AtomicUsize::new(0));
    let input_rx = Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP));
    let scroll_state = ScrollDispatchState::new();

    let mut ccfg = ClientSessionConfig::new(
        "127.0.0.1:9901".parse().unwrap(),
        params,
        42,
        Box::new(BridgeInputCapture {
            queue: Arc::clone(&input_rx),
            watch_only: Arc::new(AtomicBool::new(false)),
        }),
    );
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
        Box::new(WakeStubTransport {
            inbound: VecDeque::from([NetEvent::Reliable(initial_welcome)]),
            wake_hits: Arc::clone(&old_wake_hits),
        }),
        Box::new(dec),
        Box::new(rend),
        clock,
    )
    .expect("with_parts");
    client.handshake().expect("initial handshake");
    input_rx.set_wake_handle(client.transport_wake_handle());

    // 空转非空入队触发旧传输的 wake_handle。
    input_rx.push(InputEvent::MouseButton {
        button: MouseButton::Left,
        pressed: true,
    });
    assert_eq!(old_wake_hits.load(Ordering::Relaxed), 1);
    assert_eq!(input_rx.drain_all().len(), 1);

    // 断线丢弃旧传输后，安装返回全新传输的 connect_factory 并走完快速 Resumed。
    let factory_wake_hits = Arc::clone(&new_wake_hits);
    client.set_connect_factory(Box::new(move || {
        let mut resumed_welcome = Vec::new();
        ControlMessage::Welcome(rc_session::proto::Welcome {
            session_id: 42,
            granted: params,
            auth_status: rc_session::proto::AuthStatus::Ok,
            host_flags: rc_session::proto::HostFlags(
                rc_session::proto::HostFlags::RESUME_ACCEPTED
                    | rc_session::proto::HostFlags::SUPPORTS_PIXEL_SCROLL,
            ),
        })
        .encode(&mut resumed_welcome);
        Ok(Box::new(WakeStubTransport {
            inbound: VecDeque::from([NetEvent::Reliable(resumed_welcome)]),
            wake_hits: Arc::clone(&factory_wake_hits),
        }))
    }));

    client.on_disconnected(0);
    assert_eq!(client.state(), SessionState::Reconnecting);
    let delay_us = client.reconnect_config().backoff_initial.as_micros() as u64;
    assert!(matches!(
        client.tick_reconnect(delay_us).expect("connect attempt"),
        ReconnectOutcome::Connecting
    ));
    assert!(matches!(
        client.tick_reconnect(delay_us).expect("resume welcome"),
        ReconnectOutcome::Resumed
    ));
    assert_eq!(client.state(), SessionState::Streaming);

    // run_session_thread 在 Resumed / Rebuilt 分支均调用此公共刷新入口。
    refresh_after_reconnect_outcome(&mut client, &input_rx, &scroll_state);
    assert!(scroll_state
        .peer_supports_pixel_scroll
        .load(Ordering::Acquire));

    // 恢复后空闲期入队必须唤醒新传输的 wake_handle，不得再打到已丢弃的旧句柄。
    input_rx.push(InputEvent::MouseButton {
        button: MouseButton::Left,
        pressed: false,
    });
    assert_eq!(old_wake_hits.load(Ordering::Relaxed), 1);
    assert_eq!(new_wake_hits.load(Ordering::Relaxed), 1);
}

#[test]
fn classify_preempted_and_busy_controlled_disable_auto_reconnect() {
    use crate::ui_error::ErrorPlatform;

    let preempted =
        classify_stop_reason_end(&rc_session::StopReason::ByeReceived(ByeReason::Preempted));
    assert!(preempted.preempted);
    assert!(!preempted.busy_controlled);
    assert!(!preempted.recoverable);
    assert_eq!(
        crate::ui_error::classify_session_reason(&preempted.reason, ErrorPlatform::Macos).code,
        "session.preempted"
    );

    let gave_up_preempted = classify_gave_up_end(Some(&rc_session::StopReason::ByeReceived(
        ByeReason::Preempted,
    )));
    assert!(gave_up_preempted.preempted);
    assert!(!gave_up_preempted.recoverable);

    let busy_sig = classify_runtime_err_end(
        "信令请求失败",
        &rc_types::Error::Network("signal error target_in_session: device busy".to_string()),
        false,
    );
    assert!(busy_sig.busy_controlled);
    assert!(!busy_sig.preempted);
    assert!(!busy_sig.recoverable);
    assert_eq!(
        crate::ui_error::classify_session_reason(&busy_sig.reason, ErrorPlatform::Macos).code,
        "signal.target_in_session"
    );

    let busy_lan = classify_stop_reason_end(&rc_session::StopReason::Disconnected(
        "HostBusyControlled: host already has an active controller".to_string(),
    ));
    assert!(busy_lan.busy_controlled);
    assert!(!busy_lan.preempted);
    assert!(!busy_lan.recoverable);
    assert_eq!(
        crate::ui_error::classify_session_reason(&busy_lan.reason, ErrorPlatform::Macos).code,
        "signal.target_in_session"
    );
}

#[test]
fn session_handle_lan_busy_controlled_and_preempted_emit_structured_disconnected() {
    use rc_net::{NetConfig, NetEvent, Role};
    use rc_session::dev_cert::{DEV_CERT_PEM, DEV_KEY_PEM};
    use rc_session::proto::{AuthStatus, ByeReason, ControlMessage, HostFlags, Welcome};

    fn drain_until_disconnected(t: &mut dyn rc_net::Transport, max_wait: Duration) {
        let deadline = Instant::now() + max_wait;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match t.poll(remaining.min(Duration::from_millis(50))) {
                Ok(events) => {
                    if events
                        .iter()
                        .any(|e| matches!(e, NetEvent::Disconnected { .. }))
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    let dev_id = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM).expect("dev id");

    // 1) 直连 LAN 握手返回 Welcome{Rejected, HostFlags::BUSY_CONTROLLED} -> 透出 busy_controlled=true 且禁自动重连
    {
        let ep = QuicEndpoint::new(
            &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
            &dev_id,
        )
        .expect("busy lan ep");
        let addr = ep.local_addr().expect("busy lan addr");
        let jh = thread::spawn(move || {
            let mut t = ep
                .accept_with_handshake_timeout(Duration::from_secs(5), Duration::from_secs(5), None)
                .expect("accept busy");
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
                                host_flags: HostFlags(HostFlags::BUSY_CONTROLLED),
                            })
                            .encode(&mut out);
                            let _ = t.send_reliable(&out);
                            drain_until_disconnected(&mut t, Duration::from_secs(2));
                            return;
                        }
                    }
                }
            }
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: addr,
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 1_000_000,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            ..UiSessionConfig::default()
        });

        let mut disc = None;
        let mut ended = None;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            while let Some(upd) = session.try_recv_update() {
                match upd {
                    SessionUpdate::Disconnected {
                        preempted,
                        busy_controlled,
                        auto_reconnect_eligible,
                        ui_error,
                        ..
                    } => {
                        disc = Some((
                            preempted,
                            busy_controlled,
                            auto_reconnect_eligible,
                            ui_error,
                        ));
                    }
                    SessionUpdate::Ended {
                        recoverable,
                        ui_error,
                        ..
                    } => {
                        ended = Some((recoverable, ui_error));
                    }
                    _ => {}
                }
            }
            if disc.is_some() && ended.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        session.join();
        jh.join().unwrap();

        let (preempted, busy, auto_reconn, disc_err) =
            disc.expect("must emit SessionUpdate::Disconnected");
        assert!(!preempted);
        assert!(busy);
        assert!(!auto_reconn);
        assert_eq!(
            disc_err.as_ref().map(|e| e.code.as_str()),
            Some("signal.target_in_session")
        );
        let (recoverable, end_err) = ended.expect("must emit SessionUpdate::Ended");
        assert!(!recoverable);
        assert_eq!(
            end_err.as_ref().map(|e| e.code.as_str()),
            Some("signal.target_in_session")
        );
    }

    // 2) 流式阶段收到被控端 ByeReason::Preempted -> 透出 preempted=true 且禁自动重连
    {
        let ep = QuicEndpoint::new(
            &NetConfig::new(Role::Host, "127.0.0.1:0".parse().unwrap()),
            &dev_id,
        )
        .expect("preempt ep");
        let addr = ep.local_addr().expect("preempt addr");
        let jh = thread::spawn(move || {
            let mut t = ep
                .accept_with_handshake_timeout(Duration::from_secs(5), Duration::from_secs(5), None)
                .expect("accept preempt");
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                for ev in t.poll(Duration::from_millis(20)).expect("poll") {
                    if let NetEvent::Reliable(bytes) = ev {
                        if let Ok(ControlMessage::Hello(h)) = ControlMessage::decode(&bytes) {
                            let mut w_out = Vec::new();
                            ControlMessage::Welcome(Welcome {
                                session_id: h.session_id,
                                granted: h.requested,
                                auth_status: AuthStatus::Ok,
                                host_flags: HostFlags(0),
                            })
                            .encode(&mut w_out);
                            let _ = t.send_reliable(&w_out);
                            // 等待客户端完成 Welcome 消费并进入 Streaming，避免单次 poll 被上行控制帧提前唤醒。
                            let settle_deadline = Instant::now() + Duration::from_millis(30);
                            while Instant::now() < settle_deadline {
                                let rem = settle_deadline.saturating_duration_since(Instant::now());
                                if rem.is_zero() {
                                    break;
                                }
                                match t.poll(rem) {
                                    Ok(evs)
                                        if evs.iter().any(|e| {
                                            matches!(e, NetEvent::Disconnected { .. })
                                        }) =>
                                    {
                                        return;
                                    }
                                    Ok(_) => {}
                                    Err(_) => return,
                                }
                            }

                            let mut bye_out = Vec::new();
                            ControlMessage::Bye {
                                reason: ByeReason::Preempted,
                            }
                            .encode(&mut bye_out);
                            let _ = t.send_reliable(&bye_out);
                            drain_until_disconnected(&mut t, Duration::from_secs(2));
                            return;
                        }
                    }
                }
            }
        });

        let session = SessionHandle::spawn(UiSessionConfig {
            connect_addr: addr,
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 1_000_000,
            prefer_hardware: false,
            clipboard_enabled: false,
            audio_enabled: false,
            ..UiSessionConfig::default()
        });

        let mut disc = None;
        let mut ended = None;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            while let Some(upd) = session.try_recv_update() {
                match upd {
                    SessionUpdate::Disconnected {
                        preempted,
                        busy_controlled,
                        auto_reconnect_eligible,
                        ui_error,
                        ..
                    } => {
                        disc = Some((
                            preempted,
                            busy_controlled,
                            auto_reconnect_eligible,
                            ui_error,
                        ));
                    }
                    SessionUpdate::Ended {
                        recoverable,
                        ui_error,
                        ..
                    } => {
                        ended = Some((recoverable, ui_error));
                    }
                    _ => {}
                }
            }
            if disc.is_some() && ended.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        session.join();
        jh.join().unwrap();

        let (preempted, busy, auto_reconn, disc_err) =
            disc.expect("must emit SessionUpdate::Disconnected on Preempted");
        assert!(preempted);
        assert!(!busy);
        assert!(!auto_reconn);
        assert_eq!(
            disc_err.as_ref().map(|e| e.code.as_str()),
            Some("session.preempted")
        );
        let (recoverable, end_err) = ended.expect("must emit SessionUpdate::Ended");
        assert!(!recoverable);
        assert_eq!(
            end_err.as_ref().map(|e| e.code.as_str()),
            Some("session.preempted")
        );
    }
}
