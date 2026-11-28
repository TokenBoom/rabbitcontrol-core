use super::*;

#[derive(Clone, Copy)]
pub(in crate::host_bridge) struct TestModeSwitchEntry {
    pub(in crate::host_bridge) req: (u32, u32),
    pub(in crate::host_bridge) logical: Resolution,
    pub(in crate::host_bridge) backing: Resolution,
}

#[derive(Clone)]
pub(in crate::host_bridge) struct TestHostPlatformMock {
    pub(in crate::host_bridge) enable_hardware_display_ops: bool,
    pub(in crate::host_bridge) displays: Arc<Mutex<Vec<crate::platform::PlatformDisplayInfo>>>,
    pub(in crate::host_bridge) next_virtual_id: Arc<std::sync::atomic::AtomicU32>,
    pub(in crate::host_bridge) mode_switches: Arc<Mutex<Vec<TestModeSwitchEntry>>>,
    pub(in crate::host_bridge) current_backing: Arc<Mutex<Option<Resolution>>>,
    pub(in crate::host_bridge) initial_backing: Option<Resolution>,
    pub(in crate::host_bridge) privacy_curtain_ok: bool,
}

impl TestHostPlatformMock {
    pub(in crate::host_bridge) fn new(
        main_logical: Resolution,
        main_backing: Resolution,
        extra_displays: Vec<crate::platform::PlatformDisplayInfo>,
    ) -> Self {
        let mut displays = vec![crate::platform::PlatformDisplayInfo {
            id: 1,
            name: "Main".to_string(),
            width: main_logical.width,
            height: main_logical.height,
            origin_x: 0.0,
            origin_y: 0.0,
            is_main: true,
            is_virtual: false,
        }];
        displays.extend(extra_displays);
        Self {
            enable_hardware_display_ops: true,
            displays: Arc::new(Mutex::new(displays)),
            next_virtual_id: Arc::new(std::sync::atomic::AtomicU32::new(100)),
            mode_switches: Arc::new(Mutex::new(Vec::new())),
            current_backing: Arc::new(Mutex::new(Some(main_backing))),
            initial_backing: Some(main_backing),
            privacy_curtain_ok: true,
        }
    }

    pub(in crate::host_bridge) fn with_mode_switch(
        &self,
        req: (u32, u32),
        logical: Resolution,
        backing: Resolution,
    ) {
        self.mode_switches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(TestModeSwitchEntry {
                req,
                logical,
                backing,
            });
    }

    pub(in crate::host_bridge) fn switch_mode(
        &self,
        target_w: u32,
        target_h: u32,
    ) -> Result<Resolution, String> {
        let switches = self.mode_switches.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = switches
            .iter()
            .find(|e| e.req.0 == target_w && e.req.1 == target_h)
            .copied()
        {
            *self
                .current_backing
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(entry.backing);
            Ok(entry.logical)
        } else {
            Err("mock switch_to unsupported".to_string())
        }
    }

    pub(in crate::host_bridge) fn restore_mode(&self) {
        *self
            .current_backing
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = self.initial_backing;
    }

    pub(in crate::host_bridge) fn backing_resolution(&self) -> Option<Resolution> {
        *self
            .current_backing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub(in crate::host_bridge) fn list_displays(
        &self,
    ) -> Vec<crate::platform::PlatformDisplayInfo> {
        self.displays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(in crate::host_bridge) fn create_virtual_display(
        &self,
        width: u32,
        height: u32,
        _hidpi: bool,
    ) -> Result<crate::platform::PlatformDisplayInfo, String> {
        let id = self.next_virtual_id.fetch_add(1, Ordering::AcqRel);
        let info = crate::platform::PlatformDisplayInfo {
            id,
            name: format!("Virtual {id}"),
            width,
            height,
            origin_x: 2000.0,
            origin_y: 0.0,
            is_main: false,
            is_virtual: true,
        };
        self.displays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(info.clone());
        Ok(info)
    }

    pub(in crate::host_bridge) fn destroy_virtual_display(&self, display_id: u32) -> bool {
        let mut guard = self.displays.lock().unwrap_or_else(|e| e.into_inner());
        let before = guard.len();
        guard.retain(|d| !(d.is_virtual && d.id == display_id));
        guard.len() < before
    }

    pub(in crate::host_bridge) fn destroy_all_virtual_displays(&self) {
        self.displays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|d| !d.is_virtual);
    }
}

#[derive(Clone)]
pub(in crate::host_bridge) struct TestHostMediaOverride {
    pub(in crate::host_bridge) native_res: Resolution,
    pub(in crate::host_bridge) max_res: Resolution,
    pub(in crate::host_bridge) auto_hidpi: bool,
    pub(in crate::host_bridge) hevc_available: bool,
    pub(in crate::host_bridge) encode_caps: Vec<rc_pipeline::CodecCapability>,
    pub(in crate::host_bridge) platform: Option<TestHostPlatformMock>,
}

/// U-H1：显式驱动已建立的 `HostSession`（`Streaming` 调 `tick`，`Detached` 调 `tick_detached`）。
///
/// 在以下任一条件满足时立即退出驱动循环并收尾，让外层 accept 循环回到监听态：
/// - `stop_flag` 或 `disconnect_flag` 置位；
/// - `Streaming` 期收到对端 `Bye`（`r.closed.is_some()`）；
/// - `Detached` 期重连窗口到期拆除管线（`DetachOutcome::TornDown`）；
/// - `Detached` 期密码版本（`password_version != observed_pw_ver`）或鉴权配置版本（`config_version != observed_cfg_ver`）发生变更，需重建以使新配置生效。
#[allow(clippy::too_many_arguments)]
pub(super) fn drive_ui_host_session(
    host: &mut HostSession,
    clock: &SessionClock,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
) -> String {
    let lock_screen_count = AtomicU64::new(0);
    let close_reason = AtomicU8::new(ByeReason::Normal as u8);
    let mut owner_terminals = PersistentOwnerTerminals::new();
    let wake_guard: SharedWakeGuard = Arc::new(Mutex::new(None));
    let file_transfer_dir: SharedFileTransferDir = Arc::new(RwLock::new(None));
    let allow_assist_file_transfer = AtomicBool::new(true);
    drive_ui_host_session_inner(
        host,
        clock,
        None,
        updates,
        password_version,
        observed_pw_ver,
        config_version,
        observed_cfg_ver,
        disconnect_flag,
        stop_flag,
        &close_reason,
        HostTransportKind::Lan,
        false,
        false,
        false,
        &lock_screen_count,
        None,
        &mut owner_terminals,
        wake_guard,
        file_transfer_dir,
        &allow_assist_file_transfer,
        None,
        None,
        Instant::now(),
    )
    .reason
}

#[allow(clippy::too_many_arguments)]
pub(super) fn drive_ui_host_session_inner(
    host: &mut HostSession,
    clock: &SessionClock,
    clock_anchor: Option<&HostClockAnchor>,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
    close_reason: &AtomicU8,
    transport_kind: HostTransportKind,
    prefer_hardware: bool,
    audio_enabled: bool,
    hardware_video_active: bool,
    lock_screen_count: &AtomicU64,
    auth_state: Option<&Mutex<AuthRuntimeState>>,
    owner_terminals: &mut PersistentOwnerTerminals,
    wake_guard: SharedWakeGuard,
    file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: &AtomicBool,
    incoming_relay: Option<&Arc<BoundedRelayIncomingQueue>>,
    active_peer_id: Option<&str>,
    session_started_at: Instant,
) -> DriveSessionOutcome {
    drive_ui_host_session_with_switch(
        host,
        clock,
        clock_anchor,
        updates,
        password_version,
        observed_pw_ver,
        config_version,
        observed_cfg_ver,
        disconnect_flag,
        stop_flag,
        close_reason,
        transport_kind,
        prefer_hardware,
        audio_enabled,
        hardware_video_active,
        lock_screen_count,
        auth_state,
        owner_terminals,
        wake_guard,
        file_transfer_dir,
        allow_assist_file_transfer,
        incoming_relay,
        active_peer_id,
        session_started_at,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn drive_ui_host_session_with_switch(
    host: &mut HostSession,
    clock: &SessionClock,
    clock_anchor: Option<&HostClockAnchor>,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
    close_reason: &AtomicU8,
    transport_kind: HostTransportKind,
    prefer_hardware: bool,
    audio_enabled: bool,
    hardware_video_active: bool,
    lock_screen_count: &AtomicU64,
    auth_state: Option<&Mutex<AuthRuntimeState>>,
    owner_terminals: &mut PersistentOwnerTerminals,
    wake_guard: SharedWakeGuard,
    file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: &AtomicBool,
    incoming_relay: Option<&Arc<BoundedRelayIncomingQueue>>,
    active_peer_id: Option<&str>,
    session_started_at: Instant,
    switch_rt: Option<HostSwitchRuntime>,
) -> DriveSessionOutcome {
    drive_ui_host_session_with_switch_and_tracking(
        host,
        clock,
        clock_anchor,
        updates,
        password_version,
        observed_pw_ver,
        config_version,
        observed_cfg_ver,
        disconnect_flag,
        stop_flag,
        close_reason,
        transport_kind,
        prefer_hardware,
        audio_enabled,
        hardware_video_active,
        lock_screen_count,
        auth_state,
        owner_terminals,
        wake_guard,
        file_transfer_dir,
        allow_assist_file_transfer,
        incoming_relay,
        active_peer_id,
        session_started_at,
        switch_rt,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn drive_ui_host_session_with_media_override(
    host: &mut HostSession,
    clock: &SessionClock,
    clock_anchor: Option<&HostClockAnchor>,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
    close_reason: &AtomicU8,
    transport_kind: HostTransportKind,
    prefer_hardware: bool,
    hardware_video_active: bool,
    lock_screen_count: &AtomicU64,
    auth_state: Option<&Mutex<AuthRuntimeState>>,
    owner_terminals: &mut PersistentOwnerTerminals,
    wake_guard: SharedWakeGuard,
    file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: &AtomicBool,
    incoming_relay: Option<&Arc<BoundedRelayIncomingQueue>>,
    active_peer_id: Option<&str>,
    session_started_at: Instant,
    media_override: TestHostMediaOverride,
) -> DriveSessionOutcome {
    let audio_mgr = HostAudioManager::new(false);
    drive_ui_host_session_core(
        host,
        clock,
        clock_anchor,
        updates,
        password_version,
        observed_pw_ver,
        config_version,
        observed_cfg_ver,
        disconnect_flag,
        stop_flag,
        close_reason,
        transport_kind,
        prefer_hardware,
        hardware_video_active,
        lock_screen_count,
        auth_state,
        owner_terminals,
        wake_guard,
        file_transfer_dir,
        allow_assist_file_transfer,
        incoming_relay,
        active_peer_id,
        session_started_at,
        audio_mgr,
        None,
        None,
        None,
        Some(media_override),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn drive_ui_host_session_with_audio(
    host: &mut HostSession,
    clock: &SessionClock,
    clock_anchor: Option<&HostClockAnchor>,
    updates: &BoundedHostUpdateQueue,
    password_version: &AtomicU64,
    observed_pw_ver: u64,
    config_version: &AtomicU64,
    observed_cfg_ver: u64,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
    close_reason: &AtomicU8,
    transport_kind: HostTransportKind,
    prefer_hardware: bool,
    hardware_video_active: bool,
    lock_screen_count: &AtomicU64,
    auth_state: Option<&Mutex<AuthRuntimeState>>,
    owner_terminals: &mut PersistentOwnerTerminals,
    wake_guard: SharedWakeGuard,
    file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: &AtomicBool,
    incoming_relay: Option<&Arc<BoundedRelayIncomingQueue>>,
    active_peer_id: Option<&str>,
    session_started_at: Instant,
    audio_mgr: HostAudioManager,
    switch_rt: Option<HostSwitchRuntime>,
) -> DriveSessionOutcome {
    drive_ui_host_session_core(
        host,
        clock,
        clock_anchor,
        updates,
        password_version,
        observed_pw_ver,
        config_version,
        observed_cfg_ver,
        disconnect_flag,
        stop_flag,
        close_reason,
        transport_kind,
        prefer_hardware,
        hardware_video_active,
        lock_screen_count,
        auth_state,
        owner_terminals,
        wake_guard,
        file_transfer_dir,
        allow_assist_file_transfer,
        incoming_relay,
        active_peer_id,
        session_started_at,
        audio_mgr,
        switch_rt,
        None,
        None,
        None,
    )
}

pub(super) fn build_hidpi_channel_host(
    clock: SessionClock,
    caps_w: u32,
    caps_h: u32,
    init_fps: u32,
    caps_fps: u32,
    fail_hevc: Arc<AtomicBool>,
) -> (HostSession, mpsc::Sender<NetEvent>, mpsc::Receiver<Vec<u8>>) {
    use rc_session::proto::{AuthMethod, ControlMessage, Hello, PROTOCOL_VERSION};

    let requested = SessionParams {
        width: caps_w,
        height: caps_h,
        fps: init_fps,
        bitrate_bps: 30_000_000,
    };
    let hello_msg = ControlMessage::Hello(Hello {
        version: PROTOCOL_VERSION,
        session_id: 142,
        requested,
        auth_method: AuthMethod::None,
        auth_payload: Vec::new(),
    });
    let mut hello_bytes = Vec::new();
    hello_msg.encode(&mut hello_bytes);

    let (in_tx, in_rx) = mpsc::channel::<NetEvent>();
    let (out_reliable_tx, out_reliable_rx) = mpsc::channel::<Vec<u8>>();
    let out_datagram_count = Arc::new(AtomicU64::new(0));
    in_tx
        .send(NetEvent::Reliable(hello_bytes))
        .expect("queue hello");

    let transport = ChannelTestTransport {
        in_rx,
        out_reliable_tx,
        out_datagram_count,
    };
    let capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
        display: rc_capture::DisplayInfo {
            id: rc_types::DisplayId(0),
            resolution: Resolution::new(caps_w, caps_h),
            scale: 1.0,
            hdr: false,
        },
        fps: init_fps,
        content: rc_capture::FakeContent::Dynamic,
        dirty_rect: None,
    })
    .expect("fake capture");
    let encoder = rc_encode::FakeEncoder::new(rc_encode::EncoderConfig {
        resolution: Resolution::new(caps_w, caps_h),
        fps: init_fps,
        bitrate_bps: 30_000_000,
        ..rc_encode::EncoderConfig::default()
    })
    .expect("fake encoder");

    let cfg = HostSessionConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        mtu: rc_session::DEFAULT_SESSION_MTU,
        caps: SessionParams {
            width: caps_w,
            height: caps_h,
            fps: caps_fps,
            bitrate_bps: 150_000_000,
        },
        pipeline: PipelineConfig {
            resolution: Resolution::new(caps_w, caps_h),
            fps: init_fps,
            bitrate_bps: 30_000_000,
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
        Box::new(transport),
        Box::new(capture),
        Box::new(encoder),
        clock,
    )
    .expect("with_parts");
    host.set_pipeline_factory_for(Box::new(move |pcfg| {
        if fail_hevc.load(Ordering::Acquire) && pcfg.codec == rc_encode::Codec::Hevc {
            return Err(rc_types::Error::Encoder(
                "simulated hevc runtime fallback".into(),
            ));
        }
        let (p, _) = fake_stack_anchored(pcfg, None)?;
        Ok(p)
    }));
    host.handshake().expect("handshake");
    assert_eq!(host.state(), SessionState::Streaming);
    (host, in_tx, out_reliable_rx)
}

pub(super) fn spawn_hidpi_channel_driver(
    mut host: HostSession,
    clock: SessionClock,
    media_override: TestHostMediaOverride,
) -> (Arc<AtomicBool>, thread::JoinHandle<DriveSessionOutcome>) {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let t_stop = Arc::clone(&stop_flag);
    let handle = thread::spawn(move || {
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
        drive_ui_host_session_with_media_override(
            &mut host,
            &clock,
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
            media_override,
        )
    });
    (stop_flag, handle)
}

pub(super) struct ChannelTestTransport {
    pub(super) in_rx: mpsc::Receiver<NetEvent>,
    pub(super) out_reliable_tx: mpsc::Sender<Vec<u8>>,
    pub(super) out_datagram_count: Arc<AtomicU64>,
}

impl Transport for ChannelTestTransport {
    fn send_datagram(&mut self, _data: &[u8]) -> rc_types::Result<()> {
        self.out_datagram_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
        let _ = self.out_reliable_tx.send(data.to_vec());
        Ok(())
    }

    fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
        let mut events = Vec::new();
        match self.in_rx.recv_timeout(timeout) {
            Ok(ev) => {
                events.push(ev);
                while let Ok(more) = self.in_rx.try_recv() {
                    events.push(more);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                events.push(NetEvent::Disconnected {
                    reason: "channel closed".to_string(),
                });
            }
        }
        Ok(events)
    }

    fn stats(&self) -> NetStats {
        NetStats::default()
    }
}

pub(super) struct ScriptedAudioCapture {
    pub(super) inner: rc_audio::FakeAudioCapture,
    pub(super) stopped: Arc<AtomicBool>,
    pub(super) stop_calls: Arc<AtomicU64>,
}

impl AudioCapture for ScriptedAudioCapture {
    fn try_recv_frame(&mut self) -> Option<rc_audio::PcmFrame> {
        if self.stopped.load(Ordering::Acquire) {
            return None;
        }
        self.inner.try_recv_frame()
    }

    fn sample_rate(&self) -> u32 {
        self.inner.sample_rate()
    }

    fn channels(&self) -> u8 {
        self.inner.channels()
    }

    fn stop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.stop_calls.fetch_add(1, Ordering::AcqRel);
        self.inner.stop();
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire) || self.inner.is_stopped()
    }
}

pub(super) fn build_streaming_channel_host(
    clock: SessionClock,
) -> (
    HostSession,
    mpsc::Sender<NetEvent>,
    mpsc::Receiver<Vec<u8>>,
    Arc<AtomicU64>,
) {
    use rc_session::proto::{AuthMethod, ControlMessage, Hello, PROTOCOL_VERSION};

    let requested = SessionParams {
        width: 320,
        height: 240,
        fps: 30,
        bitrate_bps: 2_000_000,
    };
    let hello_msg = ControlMessage::Hello(Hello {
        version: PROTOCOL_VERSION,
        session_id: 42,
        requested,
        auth_method: AuthMethod::None,
        auth_payload: Vec::new(),
    });
    let mut hello_bytes = Vec::new();
    hello_msg.encode(&mut hello_bytes);

    let (in_tx, in_rx) = mpsc::channel::<NetEvent>();
    let (out_reliable_tx, out_reliable_rx) = mpsc::channel::<Vec<u8>>();
    let out_datagram_count = Arc::new(AtomicU64::new(0));
    in_tx
        .send(NetEvent::Reliable(hello_bytes))
        .expect("queue hello");

    let transport = ChannelTestTransport {
        in_rx,
        out_reliable_tx,
        out_datagram_count: Arc::clone(&out_datagram_count),
    };
    let capture = rc_capture::FakeBackend::new(rc_capture::FakeBackendConfig {
        display: rc_capture::DisplayInfo {
            id: rc_types::DisplayId(0),
            resolution: Resolution::new(320, 240),
            scale: 1.0,
            hdr: false,
        },
        fps: 30,
        content: rc_capture::FakeContent::Dynamic,
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
        Box::new(transport),
        Box::new(capture),
        Box::new(encoder),
        clock,
    )
    .expect("with_parts");
    host.set_pipeline_factory_for(Box::new(|pcfg| {
        let (p, _) = fake_stack_anchored(pcfg, None)?;
        Ok(p)
    }));
    host.handshake().expect("handshake");
    assert_eq!(host.state(), SessionState::Streaming);
    (host, in_tx, out_reliable_rx, out_datagram_count)
}

pub(super) fn send_display_ctrl_event(tx: &mpsc::Sender<NetEvent>, msg: &DisplayControlMsg) {
    let payload = display_ctrl::encode_display_ctrl(msg).expect("encode display ctrl");
    let mut wire = Vec::new();
    rc_session::proto::ControlMessage::ToolChannel {
        channel: TOOL_CHANNEL_DISPLAY_CTRL,
        payload,
    }
    .encode(&mut wire);
    tx.send(NetEvent::Reliable(wire)).expect("send tool event");
}

pub(super) fn recv_display_ctrl_until(
    rx: &mpsc::Receiver<Vec<u8>>,
    timeout: Duration,
    mut pred: impl FnMut(&DisplayControlMsg) -> bool,
) -> Vec<DisplayControlMsg> {
    let deadline = Instant::now() + timeout;
    let mut collected = Vec::new();
    while Instant::now() < deadline {
        let rem = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(rem.min(Duration::from_millis(20))) {
            Ok(raw) => {
                if let Ok(rc_session::proto::ControlMessage::ToolChannel {
                    channel: TOOL_CHANNEL_DISPLAY_CTRL,
                    payload,
                }) = rc_session::proto::ControlMessage::decode(&raw)
                {
                    if let Some(msg) = display_ctrl::decode_display_ctrl(&payload) {
                        let matched = pred(&msg);
                        collected.push(msg);
                        if matched {
                            return collected;
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    collected
}

pub(super) fn make_test_relay_incoming(
    session_id: &str,
    peer_id: &str,
    is_owner_connection: bool,
    takeover: bool,
) -> RelayIncoming {
    RelayIncoming {
        session_id: session_id.to_string(),
        relay_addr: "127.0.0.1:21117".to_string(),
        relay_token: "tok-test".to_string(),
        peer_id: peer_id.to_string(),
        peer_name: Some(format!("Device {peer_id}")),
        peer_hostname: Some(format!("host-{peer_id}")),
        peer_os: Some("macos".to_string()),
        peer_public_addr: None,
        peer_public_addrs: Vec::new(),
        self_public_addr: None,
        self_nat_type: crate::nat::NatType::Unknown,
        self_nat_port_delta: None,
        self_nat_port_range: None,
        peer_nat_type: crate::nat::NatType::Unknown,
        peer_nat_port_delta: None,
        peer_nat_port_range: None,
        punch_secret: None,
        start_after_ms: None,
        relay_fallback_after_ms: None,
        peer_lan_addrs: vec!["127.0.0.1:21115".to_string()],
        local_udp_port: None,
        owner_grant: None,
        is_owner_connection,
        takeover,
        is_relay_alloc: false,
    }
}

pub(super) fn read_mock_signal_frame(stream: &mut std::net::TcpStream) -> serde_json::Value {
    use std::io::Read;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).expect("read frame len");
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("read frame body");
    serde_json::from_slice(&body).expect("parse signal json")
}

pub(super) fn write_mock_signal_frame(stream: &mut std::net::TcpStream, val: &serde_json::Value) {
    use std::io::Write;
    let body = serde_json::to_vec(val).unwrap();
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    stream.write_all(&frame).expect("write signal frame");
    stream.flush().expect("flush signal frame");
}
