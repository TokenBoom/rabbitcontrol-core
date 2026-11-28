use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rc_net::quic::QuicEndpoint;
use rc_session::auth::ConnectionApprover;
use rc_session::{AutoApprover, SessionState};

use super::approver::UiApprover;
use super::media_aux::replace_wake_guard;
use super::pipeline_factory::{
    bind_mtls_lan_endpoint, build_host_session, format_display_addr, host_hardware_display_caps,
    BuiltUiHost, HostListener,
};
use super::queues::{
    drain_matching_force_disconnect, emit_peer_connected, lan_stale_signal_cutoff,
    BoundedHostUpdateQueue, BoundedRelayIncomingQueue, PersistentOwnerTerminals,
};
use super::session_loop::drive_ui_host_session_with_switch_and_tracking;
use super::transport_dial::{
    build_and_handshake_transport, maybe_rotate_password_after_session, HandshakeTransportOutcome,
};
use super::transport_worker::serve_relay_incoming;
use super::types::{
    ActiveControllerPeerHints, ActiveRelayInterrupt, AuthRuntimeState, HostControllerTracking,
    HostTransportKind, HostUpdate, HostWorkerOptions, PasswordState, SharedActiveControllers,
    SharedFileTransferDir, DEFAULT_HOST_PORT, HOST_ACCEPT_SLICE, HOST_QUIC_HANDSHAKE_TIMEOUT,
    RELAY_INCOMING_TTL,
};

/// 可随时被 `stop_flag` 打断的有界短退避，防止恶意/故障客户端高频触发 accept 错误导致 tight-loop 烧 CPU。
pub(super) fn sleep_cancelable(duration: Duration, stop_flag: &AtomicBool) {
    let deadline = Instant::now() + duration;
    while !stop_flag.load(Ordering::Acquire) {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

/// 根据连续 accept 非超时错误次数计算有界退避时长（前 2 次零退避，第 3 次起 20ms→40ms→50ms）。
pub(super) fn accept_error_backoff(consecutive_errors: u32) -> Option<Duration> {
    if consecutive_errors < 3 {
        None
    } else {
        let ms = 20u64
            .saturating_mul(u64::from(consecutive_errors - 2))
            .min(50);
        Some(Duration::from_millis(ms))
    }
}

struct HostWorkerCtx {
    actual_addr: SocketAddr,
    display_addr: String,
    listen_addr_shared: Arc<Mutex<SocketAddr>>,
    opts: HostWorkerOptions,
    updates: Arc<BoundedHostUpdateQueue>,
    approver: UiApprover,
    password_state: Arc<Mutex<PasswordState>>,
    password_version: Arc<AtomicU64>,
    auth_state: Arc<Mutex<AuthRuntimeState>>,
    config_version: Arc<AtomicU64>,
    incoming_relay: Arc<BoundedRelayIncomingQueue>,
    active_relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    active_controllers: SharedActiveControllers,
    disconnect_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    close_reason: Arc<AtomicU8>,
    lock_screen_count: Arc<AtomicU64>,
    file_transfer_dir: SharedFileTransferDir,
    pending_listening_notify: bool,
    observed_pw_ver: u64,
    observed_cfg_ver: u64,
    owner_terminals: PersistentOwnerTerminals,
}

impl HostWorkerCtx {
    fn listener_backend_label(&self, listener: &HostListener) -> String {
        match listener {
            HostListener::Plain(b) => b
                .backend_label
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            HostListener::MtlsLan { .. } | HostListener::AwaitingMtlsCert => {
                if self.opts.prefer_hardware {
                    "auto".to_string()
                } else {
                    "fake".to_string()
                }
            }
        }
    }

    fn try_build_listener_at(
        &self,
        addr: SocketAddr,
        cur_pw: &Option<String>,
        cur_auth: &AuthRuntimeState,
    ) -> Result<HostListener, String> {
        if cur_auth.accept_mtls_lan {
            match cur_auth.mtls_config.as_ref() {
                Some(bundle) => bind_mtls_lan_endpoint(addr, bundle)
                    .map(|endpoint| HostListener::MtlsLan { endpoint }),
                None => Err("启用 accept_mtls_lan 时必须提供 mtls_config".to_string()),
            }
        } else {
            let box_approver: Box<dyn ConnectionApprover> = if self.opts.require_approval {
                Box::new(self.approver.clone())
            } else {
                Box::new(AutoApprover)
            };
            let effective_allow_remote = cur_auth.allow_owner_control
                && cur_auth.allow_remote_assist
                && (!self.opts.forbid_passwordless_auto_approve
                    || self.opts.require_approval
                    || cur_pw.is_some());
            build_host_session(
                addr,
                cur_pw.clone(),
                self.opts.approval_timeout_us,
                self.opts.prefer_hardware,
                self.opts.clipboard_enabled,
                cur_auth.allow_owner_control,
                effective_allow_remote,
                cur_auth.owner_verifier.clone(),
                Arc::clone(&cur_auth.owner_replay_cache),
                box_approver,
                Arc::clone(&self.updates),
            )
            .map(|b| HostListener::Plain(Box::new(b)))
        }
    }

    fn rebuild_listener(&mut self) -> Option<HostListener> {
        self.observed_pw_ver = self.password_version.load(Ordering::Acquire);
        self.observed_cfg_ver = self.config_version.load(Ordering::Acquire);
        let cur_pw = self
            .password_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .password
            .clone();
        let cur_auth = self
            .auth_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if cur_auth.accept_mtls_lan && cur_auth.mtls_config.is_none() {
            return Some(HostListener::AwaitingMtlsCert);
        }

        // 前一轮 `HostSession` / `QuicEndpoint` 在 tokio 后台异步释放 UDP 端口，
        // 立即重绑 `actual_addr` 可能短暂遇到 `AddrInUse`；短退避重试至多 25 次（~500ms）。
        let mut last_err = String::new();
        let mut rebuilt = None;
        let mut emitted_fallback_listening = false;
        for attempt in 0..25 {
            if self.stop_flag.load(Ordering::Acquire) {
                break;
            }
            match self.try_build_listener_at(self.actual_addr, &cur_pw, &cur_auth) {
                Ok(l) => {
                    rebuilt = Some(l);
                    break;
                }
                Err(e) => {
                    last_err = e;
                    if attempt < 24 {
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }
        if rebuilt.is_none()
            && (self.actual_addr.port() == DEFAULT_HOST_PORT || self.opts.ephemeral_listen_port)
            && !self.stop_flag.load(Ordering::Acquire)
        {
            let fallback_addr = SocketAddr::new(self.actual_addr.ip(), 0);
            let fallback_res = if cur_auth.accept_mtls_lan && cur_auth.mtls_config.is_none() {
                Err(last_err.clone())
            } else {
                self.try_build_listener_at(fallback_addr, &cur_pw, &cur_auth)
            };
            if let Ok(fb_listener) = fallback_res {
                let bound_addr = match &fb_listener {
                    HostListener::Plain(b) => b.host.local_addr().ok(),
                    HostListener::MtlsLan { endpoint } => endpoint.local_addr().ok(),
                    HostListener::AwaitingMtlsCert => None,
                };
                if let Some(new_addr) = bound_addr {
                    self.actual_addr = new_addr;
                    *self
                        .listen_addr_shared
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = new_addr;
                    self.display_addr = format_display_addr(new_addr);
                    let backend = self.listener_backend_label(&fb_listener);
                    self.updates.push(HostUpdate::Listening {
                        listen_addr: self.actual_addr.to_string(),
                        display_addr: self.display_addr.clone(),
                        backend,
                    });
                    emitted_fallback_listening = true;
                }
                rebuilt = Some(fb_listener);
            }
        }
        match rebuilt {
            Some(l) => {
                if self.pending_listening_notify
                    && !emitted_fallback_listening
                    && !self.stop_flag.load(Ordering::Acquire)
                {
                    let backend = self.listener_backend_label(&l);
                    self.updates.push(HostUpdate::Listening {
                        listen_addr: self.actual_addr.to_string(),
                        display_addr: self.display_addr.clone(),
                        backend,
                    });
                }
                self.pending_listening_notify = false;
                Some(l)
            }
            None => {
                if !self.stop_flag.load(Ordering::Acquire) {
                    self.updates.push(HostUpdate::error(last_err));
                }
                None
            }
        }
    }

    fn serve_plain_listener(&mut self, built: Box<BuiltUiHost>) {
        let BuiltUiHost {
            mut host,
            clock,
            clock_anchor,
            backend_label,
            hardware_video_active,
            wake_guard,
        } = *built;

        // 1) 分片 accept + 握手循环（同时轮询信令下发的入站中继/P2P 会话）。
        let mut consecutive_accept_errors: u32 = 0;
        let accepted = loop {
            if self.stop_flag.load(Ordering::Acquire) {
                break false;
            }
            self.owner_terminals
                .sync_auth_and_poll(Some(self.auth_state.as_ref()));
            let _ =
                drain_matching_force_disconnect(Some(&self.opts.signal_client), None, None, None);
            if let Some(incoming) = self
                .incoming_relay
                .pop_ready(RELAY_INCOMING_TTL, Duration::from_millis(180))
            {
                serve_relay_incoming(
                    incoming,
                    &self.incoming_relay,
                    self.actual_addr,
                    &self.display_addr,
                    &self.opts,
                    &self.updates,
                    &self.approver,
                    &self.password_state,
                    &self.password_version,
                    &self.auth_state,
                    &self.config_version,
                    &self.active_relay_interrupt,
                    &self.active_controllers,
                    &self.disconnect_flag,
                    &self.stop_flag,
                    &self.close_reason,
                    &self.lock_screen_count,
                    &mut self.owner_terminals,
                    &self.file_transfer_dir,
                    host.endpoint(),
                );
                // M6：中继会话结束后清理过期入站令牌，并重建空闲 LAN HostSession 清除期间积压的过期 QUIC 连接。
                self.incoming_relay.purge_expired(RELAY_INCOMING_TTL);
                break false;
            }
            if self.password_version.load(Ordering::Acquire) != self.observed_pw_ver
                || self.config_version.load(Ordering::Acquire) != self.observed_cfg_ver
            {
                // 密码或鉴权配置在等待期间被刷新：重建 HostSession 使新配置对下一次握手生效。
                self.pending_listening_notify = true;
                break false;
            }
            // 每轮 accept 分片前重锚 Pending 墙钟并刷新当前显示器分辨率能力，避免外接屏/分辨率切换后使用陈旧 caps。
            if self.opts.prefer_hardware && consecutive_accept_errors == 0 {
                if let Some(live_res) = host_hardware_display_caps(true) {
                    host.update_caps_resolution(live_res.width, live_res.height);
                }
            }
            clock_anchor.reset_pending();

            match host.accept_and_handshake_with_timeout_cancelable(
                HOST_ACCEPT_SLICE,
                HOST_QUIC_HANDSHAKE_TIMEOUT,
                &self.stop_flag,
            ) {
                Ok(_) => break true,
                Err(rc_types::Error::Timeout(_)) if host.state() == SessionState::Init => {
                    consecutive_accept_errors = 0;
                    continue;
                }
                Err(ref e)
                    if host.state() == SessionState::Init
                        && !self.stop_flag.load(Ordering::Acquire)
                        && !rc_net::quic::is_endpoint_stopped_error(e) =>
                {
                    // 单个非法/半开客户端在 QUIC 握手阶段失败，端点仍健康；
                    // 连续失败 >= 3 次时做有界短退避，防高频恶意连接空转烧 CPU。
                    consecutive_accept_errors = consecutive_accept_errors.saturating_add(1);
                    if let Some(backoff) = accept_error_backoff(consecutive_accept_errors) {
                        sleep_cancelable(backoff, &self.stop_flag);
                    }
                    continue;
                }
                Err(_) => {
                    // 端点已停止 / 鉴权失败 / 机主拒绝 / 握手超时 / 对端中途断开：本轮结束，回到监听。
                    break false;
                }
            }
        };

        if !accepted {
            replace_wake_guard(&wake_guard, None);
            drop(host);
            return;
        }

        // 2) 进入串流会话（U-H1：显式驱动循环，覆盖 Streaming 与 Detached 退出）。
        let session_started_at = Instant::now();
        self.disconnect_flag.store(false, Ordering::Release);
        let remote_addr = host.peer_addr().to_string();
        let initial_lan_peer_did = host
            .authenticated_owner()
            .map(|o| o.caller_device_id.clone());
        emit_peer_connected(&host, &remote_addr, &self.updates);

        let outcome = drive_ui_host_session_with_switch_and_tracking(
            &mut host,
            &clock,
            Some(&clock_anchor),
            &self.updates,
            &self.password_version,
            self.observed_pw_ver,
            &self.config_version,
            self.observed_cfg_ver,
            &self.disconnect_flag,
            &self.stop_flag,
            &self.close_reason,
            HostTransportKind::Lan,
            self.opts.prefer_hardware,
            self.opts.audio_enabled,
            hardware_video_active.load(Ordering::Acquire),
            &self.lock_screen_count,
            Some(self.auth_state.as_ref()),
            &mut self.owner_terminals,
            wake_guard,
            Arc::clone(&self.file_transfer_dir),
            &self.opts.allow_assist_file_transfer,
            Some(&self.incoming_relay),
            initial_lan_peer_did.as_deref(),
            session_started_at,
            None,
            Some(HostControllerTracking {
                active_controllers: Arc::clone(&self.active_controllers),
                peer_hints: ActiveControllerPeerHints {
                    session_id_hint: None,
                    relay_peer_id: initial_lan_peer_did.clone(),
                    relay_peer_name: None,
                    relay_peer_hostname: None,
                    relay_peer_os: None,
                    mtls_peer_did: None,
                    remote_addr: remote_addr.clone(),
                },
                signal_client: Arc::clone(&self.opts.signal_client),
            }),
            None,
        );
        let reason = outcome.reason;
        let lan_peer_did = host
            .authenticated_owner()
            .map(|o| o.caller_device_id.clone())
            .or(initial_lan_peer_did);
        let last_backend = backend_label
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.disconnect_flag.store(false, Ordering::Release);
        drop(host);

        // M7：LAN 会话结束后原子轮换临时密码，再通知 UI 并清理同对端残留及过期入站中继令牌（M6/M12）。
        maybe_rotate_password_after_session(
            &self.password_state,
            &self.password_version,
            &self.updates,
            &self.stop_flag,
        );
        let _ = last_backend;
        self.updates.push(HostUpdate::ClientDisconnected { reason });
        if !self.stop_flag.load(Ordering::Acquire) {
            // 等外层循环真正完成新 UDP/QUIC 监听重绑后再发出 `Listening`，
            // 避免对端在旧 quinn::Endpoint 异步释放窗口内重连撞上 CONNECTION_REFUSED。
            self.pending_listening_notify = true;
        }
        if outcome.preempted_by_incoming {
            // 被入站新连接抢占时绝不调用 purge_for_peer_before 误删刚到达的抢占凭据。
            self.incoming_relay.purge_expired(RELAY_INCOMING_TTL);
        } else {
            self.incoming_relay.purge_for_peer_before(
                lan_peer_did.as_deref(),
                lan_stale_signal_cutoff(session_started_at, Instant::now()),
                RELAY_INCOMING_TTL,
            );
        }
    }

    fn serve_awaiting_mtls_cert(&mut self) {
        while !self.stop_flag.load(Ordering::Acquire) {
            self.owner_terminals
                .sync_auth_and_poll(Some(self.auth_state.as_ref()));
            let _ =
                drain_matching_force_disconnect(Some(&self.opts.signal_client), None, None, None);
            if let Some(incoming) = self
                .incoming_relay
                .pop_ready(RELAY_INCOMING_TTL, Duration::from_millis(180))
            {
                self.updates.push(HostUpdate::error(format!(
                    "已开启加密连接但缺少 mTLS 设备证书，已拒绝入站会话 ({})",
                    incoming.peer_id
                )));
                self.incoming_relay.purge_expired(RELAY_INCOMING_TTL);
                continue;
            }
            if self.config_version.load(Ordering::Acquire) != self.observed_cfg_ver {
                self.pending_listening_notify = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// 返回 `true` 表示外层 worker 循环应立即 `break`。
    fn serve_mtls_lan_listener(&mut self, endpoint: QuicEndpoint) -> bool {
        // mTLS LAN 监听循环：保持 endpoint 复用，直到需要切回 Plain、config_version 变更或收到信令入站会话。
        let mut need_rebind = false;
        let mut consecutive_accept_errors: u32 = 0;
        while !self.stop_flag.load(Ordering::Acquire) {
            self.owner_terminals
                .sync_auth_and_poll(Some(self.auth_state.as_ref()));
            let _ =
                drain_matching_force_disconnect(Some(&self.opts.signal_client), None, None, None);
            if let Some(incoming) = self
                .incoming_relay
                .pop_ready(RELAY_INCOMING_TTL, Duration::from_millis(180))
            {
                serve_relay_incoming(
                    incoming,
                    &self.incoming_relay,
                    self.actual_addr,
                    &self.display_addr,
                    &self.opts,
                    &self.updates,
                    &self.approver,
                    &self.password_state,
                    &self.password_version,
                    &self.auth_state,
                    &self.config_version,
                    &self.active_relay_interrupt,
                    &self.active_controllers,
                    &self.disconnect_flag,
                    &self.stop_flag,
                    &self.close_reason,
                    &self.lock_screen_count,
                    &mut self.owner_terminals,
                    &self.file_transfer_dir,
                    Some(&endpoint),
                );
                self.incoming_relay.purge_expired(RELAY_INCOMING_TTL);
                continue;
            }
            if self.config_version.load(Ordering::Acquire) != self.observed_cfg_ver {
                need_rebind = true;
                self.pending_listening_notify = true;
                break;
            }
            self.observed_pw_ver = self.password_version.load(Ordering::Acquire);
            match endpoint.accept_with_handshake_timeout(
                HOST_ACCEPT_SLICE,
                HOST_QUIC_HANDSHAKE_TIMEOUT,
                Some(&self.stop_flag),
            ) {
                Ok(quic_transport) => {
                    consecutive_accept_errors = 0;
                    let session_started_at = Instant::now();
                    self.disconnect_flag.store(false, Ordering::Release);
                    let mtls_peer_did = quic_transport
                        .peer_mtls_identity()
                        .map(|id| id.device_id.clone());
                    let peer_label = match mtls_peer_did.as_deref() {
                        Some(did) => {
                            format!("设备 {} (LAN mTLS @ {})", did, quic_transport.remote_addr())
                        }
                        None => format!("{} (LAN mTLS)", quic_transport.remote_addr()),
                    };
                    match build_and_handshake_transport(
                        Box::new(quic_transport),
                        HostTransportKind::MtlsLan,
                        &peer_label,
                        self.actual_addr,
                        &self.opts,
                        &self.updates,
                        &self.approver,
                        &self.password_state,
                        &self.password_version,
                        &self.auth_state,
                        &self.config_version,
                        &self.disconnect_flag,
                        &self.stop_flag,
                    ) {
                        HandshakeTransportOutcome::Ready {
                            built,
                            streaming_started,
                            live_pw_ver,
                            live_cfg_ver,
                        } => {
                            let BuiltUiHost {
                                mut host,
                                clock,
                                clock_anchor,
                                backend_label,
                                hardware_video_active,
                                wake_guard,
                            } = *built;
                            streaming_started.store(true, Ordering::Release);
                            emit_peer_connected(&host, &peer_label, &self.updates);
                            let outcome = drive_ui_host_session_with_switch_and_tracking(
                                &mut host,
                                &clock,
                                Some(&clock_anchor),
                                &self.updates,
                                &self.password_version,
                                live_pw_ver,
                                &self.config_version,
                                live_cfg_ver,
                                &self.disconnect_flag,
                                &self.stop_flag,
                                &self.close_reason,
                                HostTransportKind::MtlsLan,
                                self.opts.prefer_hardware,
                                self.opts.audio_enabled,
                                hardware_video_active.load(Ordering::Acquire),
                                &self.lock_screen_count,
                                Some(self.auth_state.as_ref()),
                                &mut self.owner_terminals,
                                wake_guard,
                                Arc::clone(&self.file_transfer_dir),
                                &self.opts.allow_assist_file_transfer,
                                Some(&self.incoming_relay),
                                mtls_peer_did.as_deref(),
                                session_started_at,
                                None,
                                Some(HostControllerTracking {
                                    active_controllers: Arc::clone(&self.active_controllers),
                                    peer_hints: ActiveControllerPeerHints {
                                        session_id_hint: None,
                                        relay_peer_id: None,
                                        relay_peer_name: None,
                                        relay_peer_hostname: None,
                                        relay_peer_os: None,
                                        mtls_peer_did: mtls_peer_did.clone(),
                                        remote_addr: peer_label,
                                    },
                                    signal_client: Arc::clone(&self.opts.signal_client),
                                }),
                                Some(&endpoint),
                            );
                            let reason = outcome.reason;
                            let last_backend = backend_label
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone();
                            self.disconnect_flag.store(false, Ordering::Release);
                            drop(host);
                            maybe_rotate_password_after_session(
                                &self.password_state,
                                &self.password_version,
                                &self.updates,
                                &self.stop_flag,
                            );
                            self.updates.push(HostUpdate::ClientDisconnected { reason });
                            if !self.stop_flag.load(Ordering::Acquire) {
                                self.updates.push(HostUpdate::Listening {
                                    listen_addr: self.actual_addr.to_string(),
                                    display_addr: self.display_addr.clone(),
                                    backend: last_backend,
                                });
                            }
                            if outcome.preempted_by_incoming {
                                self.incoming_relay.purge_expired(RELAY_INCOMING_TTL);
                            } else {
                                self.incoming_relay.purge_for_peer_before(
                                    mtls_peer_did.as_deref(),
                                    lan_stale_signal_cutoff(session_started_at, Instant::now()),
                                    RELAY_INCOMING_TTL,
                                );
                            }
                        }
                        HandshakeTransportOutcome::Failed(_)
                        | HandshakeTransportOutcome::BuildError => {
                            self.disconnect_flag.store(false, Ordering::Release);
                        }
                    }
                }
                Err(rc_types::Error::Timeout(_)) => {
                    consecutive_accept_errors = 0;
                    continue;
                }
                Err(err) if rc_net::quic::is_endpoint_stopped_error(&err) => {
                    need_rebind = true;
                    self.pending_listening_notify = true;
                    break;
                }
                Err(_) => {
                    // 单个非法/半开客户端握手失败不得重建整个 UDP 端点；
                    // 连续失败 >= 3 次时做有界短退避，防高频恶意连接空转烧 CPU。
                    consecutive_accept_errors = consecutive_accept_errors.saturating_add(1);
                    if let Some(backoff) = accept_error_backoff(consecutive_accept_errors) {
                        sleep_cancelable(backoff, &self.stop_flag);
                    }
                    continue;
                }
            }
        }
        drop(endpoint);
        !need_rebind && self.stop_flag.load(Ordering::Acquire)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_host_worker(
    actual_addr: SocketAddr,
    listen_addr_shared: Arc<Mutex<SocketAddr>>,
    opts: HostWorkerOptions,
    first_listener: HostListener,
    updates: Arc<BoundedHostUpdateQueue>,
    approver: UiApprover,
    password_state: Arc<Mutex<PasswordState>>,
    password_version: Arc<AtomicU64>,
    auth_state: Arc<Mutex<AuthRuntimeState>>,
    config_version: Arc<AtomicU64>,
    incoming_relay: Arc<BoundedRelayIncomingQueue>,
    active_relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    active_controllers: SharedActiveControllers,
    disconnect_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    close_reason: Arc<AtomicU8>,
    lock_screen_count: Arc<AtomicU64>,
    file_transfer_dir: SharedFileTransferDir,
) {
    let display_addr = format_display_addr(actual_addr);
    let mut ctx = HostWorkerCtx {
        actual_addr,
        display_addr,
        listen_addr_shared,
        opts,
        updates,
        approver,
        password_state,
        password_version,
        auth_state,
        config_version,
        incoming_relay,
        active_relay_interrupt,
        active_controllers,
        disconnect_flag,
        stop_flag,
        close_reason,
        lock_screen_count,
        file_transfer_dir,
        pending_listening_notify: false,
        // U-M1：`first_listener` 在 `HostHandle::spawn` 时以初始版本 0 构造；
        // 若在工作线程进入此处前调用方已调用 `set_password` 或修改鉴权配置，必须立即可见并重建。
        observed_pw_ver: 0,
        observed_cfg_ver: 0,
        owner_terminals: PersistentOwnerTerminals::new(),
    };

    let initial_backend = ctx.listener_backend_label(&first_listener);
    ctx.updates.push(HostUpdate::Listening {
        listen_addr: ctx.actual_addr.to_string(),
        display_addr: ctx.display_addr.clone(),
        backend: initial_backend,
    });

    let mut next_listener = Some(first_listener);

    while !ctx.stop_flag.load(Ordering::Acquire) {
        ctx.owner_terminals
            .sync_auth_and_poll(Some(ctx.auth_state.as_ref()));
        let listener = match next_listener.take() {
            Some(l) => l,
            None => match ctx.rebuild_listener() {
                Some(l) => l,
                None => break,
            },
        };

        match listener {
            HostListener::Plain(built) => ctx.serve_plain_listener(built),
            HostListener::AwaitingMtlsCert => ctx.serve_awaiting_mtls_cert(),
            HostListener::MtlsLan { endpoint } => {
                if ctx.serve_mtls_lan_listener(endpoint) {
                    break;
                }
            }
        }
    }
}
