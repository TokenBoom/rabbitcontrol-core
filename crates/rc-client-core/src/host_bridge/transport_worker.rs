use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rc_net::quic::QuicEndpoint;
use rc_net::Transport;

use crate::p2p::{self, P2pCandidates};
use crate::relay_transport::SessionMtlsBundle;
use crate::signal_client::RelayIncoming;
use crate::switchable_transport::{
    CandidateTransport, SwitchHandle, SwitchableTransport, TransportPathKind,
};

use super::approver::UiApprover;
use super::pipeline_factory::BuiltUiHost;
use super::queues::{
    drain_matching_force_disconnect, emit_peer_connected, BoundedHostUpdateQueue,
    BoundedRelayIncomingQueue, PersistentOwnerTerminals,
};
use super::session_loop::drive_ui_host_session_with_switch_and_tracking;
use super::transport_dial::{
    build_and_handshake_transport, build_host_p2p_candidates, dial_relay_for_incoming,
    is_p2p_handshake_fallback_eligible, maybe_rotate_password_after_session, rebuild_host_p2p_mtls,
    EstablishedIncomingHost, HandshakeTransportOutcome,
};
use super::types::{
    ActiveControllerPeerHints, ActiveRelayInterrupt, AuthRuntimeState, HostControllerTracking,
    HostSwitchRuntime, HostTransportKind, HostUpdate, HostWorkerOptions, PasswordState,
    RelayInterruptSlotGuard, SharedActiveControllers, SharedFileTransferDir,
    BACKGROUND_P2P_UPGRADE_WINDOW, DEFAULT_RELAY_FIRST_AFTER_MS,
};

fn contains_non_cap_reliable(events: &[rc_net::NetEvent]) -> bool {
    events.iter().any(|ev| match ev {
        rc_net::NetEvent::Reliable(b) => {
            !(b.len() >= 6 && &b[0..4] == b"RCSW" && matches!(b[5], 0x01..=0x03))
        }
        _ => false,
    })
}

fn try_poll_for_first_hello(
    transport: &mut Box<dyn Transport>,
    prebuf: &mut Vec<rc_net::NetEvent>,
) -> std::result::Result<bool, ()> {
    match transport.poll(Duration::from_millis(2)) {
        Ok(events) => {
            for ev in events {
                if let rc_net::NetEvent::Disconnected { .. } = ev {
                    return Err(());
                }
                if let rc_net::NetEvent::Datagram(ref b) = ev {
                    if b.len() == 14 && &b[0..4] == b"RCSW" && b[4] == 1 && b[5] == 0x01 {
                        let mut ack = b.clone();
                        ack[5] = 0x02;
                        let _ = transport.send_datagram(&ack);
                    }
                }
                prebuf.push(ev);
            }
            Ok(contains_non_cap_reliable(prebuf))
        }
        Err(_) => Err(()),
    }
}

type PendingP2pTransport = (
    Box<dyn Transport>,
    HostTransportKind,
    String,
    Option<String>,
);
type RelayDialRx = mpsc::Receiver<Option<(Box<dyn Transport>, HostTransportKind, String)>>;

fn validate_incoming_p2p_mtls(
    auth_snapshot: &AuthRuntimeState,
    incoming: &RelayIncoming,
    updates: &BoundedHostUpdateQueue,
) -> Result<Option<rc_net::mtls::MtlsConfig>, ()> {
    if !auth_snapshot.accept_mtls_lan {
        return Ok(None);
    }
    match &auth_snapshot.mtls_config {
        Some(bundle) => {
            let expected_user = incoming
                .is_owner_connection
                .then(|| bundle.local_user_id.clone());
            match bundle
                .clone()
                .with_expected_peer(Some(incoming.peer_id.clone()), expected_user)
                .to_quic_mtls_config()
            {
                Ok(cfg) => Ok(Some(cfg)),
                Err(e) => {
                    updates.push(HostUpdate::error(format!(
                        "mTLS 配置无效 ({}): {e}",
                        incoming.peer_id
                    )));
                    Err(())
                }
            }
        }
        None => {
            updates.push(HostUpdate::error(format!(
                "已开启加密连接但缺少 mTLS 设备证书，已拒绝入站会话 ({})",
                incoming.peer_id
            )));
            Err(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_initial_p2p_dial(
    candidates: P2pCandidates,
    has_relay: bool,
    mtls_bundle: Option<&SessionMtlsBundle>,
    require_mtls: bool,
    peer_id: String,
    is_owner_connection: bool,
    session_cancel: Arc<AtomicBool>,
    bg_cancel: Arc<AtomicBool>,
) -> mpsc::Receiver<Option<PendingP2pTransport>> {
    let (tx, rx) = mpsc::channel();
    let punch_timeout = if has_relay {
        BACKGROUND_P2P_UPGRADE_WINDOW
    } else {
        p2p::P2P_ONLY_PUNCH_TIMEOUT
    };
    let p2p_mtls_c =
        rebuild_host_p2p_mtls(mtls_bundle, require_mtls, &peer_id, is_owner_connection);
    let _ = thread::Builder::new()
        .name("rc-host-p2p-dial".to_string())
        .spawn(move || {
            let port_hold =
                crate::signal_client::acquire_local_udp_port_for_p2p(candidates.local_udp_port);
            let combined_cancel = Arc::new(AtomicBool::new(false));
            let watch_stop = Arc::new(AtomicBool::new(false));
            let comb_w = Arc::clone(&combined_cancel);
            let sc_w = Arc::clone(&session_cancel);
            let bg_w = Arc::clone(&bg_cancel);
            let ws_w = Arc::clone(&watch_stop);
            let watcher = thread::spawn(move || {
                while !ws_w.load(Ordering::Acquire) {
                    if sc_w.load(Ordering::Acquire) || bg_w.load(Ordering::Acquire) {
                        comb_w.store(true, Ordering::Release);
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            });
            let dial_res = p2p::attempt_p2p_quic_host_mtls(
                &candidates,
                punch_timeout,
                p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                &combined_cancel,
                p2p_mtls_c.as_ref(),
            );
            watch_stop.store(true, Ordering::Release);
            let _ = watcher.join();

            let out = match dial_res {
                Ok(p2p_conn) => {
                    let fp = p2p_conn
                        .peer_mtls_identity()
                        .map(|id| id.cert_fingerprint_sha256);
                    let held_p2p = crate::signal_client::P2pHeldTransport::new(p2p_conn, port_hold);
                    Some((
                        Box::new(held_p2p) as Box<dyn Transport>,
                        HostTransportKind::P2p,
                        format!("设备 {peer_id} (P2P 直连)"),
                        fp,
                    ))
                }
                Err(_) => {
                    drop(port_hold);
                    None
                }
            };
            let _ = tx.send(out);
        });
    rx
}

#[allow(clippy::too_many_arguments)]
fn spawn_initial_relay_dial(
    incoming: &RelayIncoming,
    mtls_bundle: &Option<SessionMtlsBundle>,
    require_relay_e2ee: bool,
    updates: &Arc<BoundedHostUpdateQueue>,
    session_cancel: &Arc<AtomicBool>,
    relay_cancel: &Arc<AtomicBool>,
    disconnect_flag: &Arc<AtomicBool>,
    stop_flag: &Arc<AtomicBool>,
) -> RelayDialRx {
    let (tx, rx) = mpsc::channel();
    let inc_c = incoming.clone();
    let bundle_c = mtls_bundle.clone();
    let upd_c = Arc::clone(updates);
    let ari_c = Arc::new(Mutex::new(None));
    let sc_c = Arc::clone(session_cancel);
    let rc_c = Arc::clone(relay_cancel);
    let df_c = Arc::clone(disconnect_flag);
    let sf_c = Arc::clone(stop_flag);
    let _ = thread::Builder::new()
        .name("rc-host-relay-dial".to_string())
        .spawn(move || {
            let combined_cancel = Arc::new(AtomicBool::new(false));
            let watch_stop = Arc::new(AtomicBool::new(false));
            let comb_w = Arc::clone(&combined_cancel);
            let sc_w = Arc::clone(&sc_c);
            let rc_w = Arc::clone(&rc_c);
            let ws_w = Arc::clone(&watch_stop);
            let watcher = thread::spawn(move || {
                while !ws_w.load(Ordering::Acquire) {
                    if sc_w.load(Ordering::Acquire) || rc_w.load(Ordering::Acquire) {
                        comb_w.store(true, Ordering::Release);
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            });
            let res = dial_relay_for_incoming(
                &inc_c,
                bundle_c.as_ref(),
                require_relay_e2ee,
                &upd_c,
                &ari_c,
                &combined_cancel,
                &df_c,
                &sf_c,
            )
            .map(|(t, k, l, _fp)| (t, k, l));
            watch_stop.store(true, Ordering::Release);
            let _ = watcher.join();
            let _ = tx.send(res);
        });
    rx
}

fn spawn_bg_p2p_upgrade_bridge(
    bg_rx: mpsc::Receiver<Option<PendingP2pTransport>>,
    sw_handle: SwitchHandle,
    require_mtls: bool,
    bg_cancel: Arc<AtomicBool>,
    session_cancel: Arc<AtomicBool>,
    disconnect_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
) {
    let _ = thread::Builder::new()
        .name("rc-host-bg-p2p-upgrade".to_string())
        .spawn(move || {
            while !bg_cancel.load(Ordering::Acquire)
                && !session_cancel.load(Ordering::Acquire)
                && !disconnect_flag.load(Ordering::Acquire)
                && !stop_flag.load(Ordering::Acquire)
            {
                match bg_rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(Some((t, _k, _lbl, fp))) => {
                        let _ = sw_handle.accept_switch_candidate(CandidateTransport {
                            transport: t,
                            kind: TransportPathKind::P2p,
                            mtls_verified: !require_mtls || fp.is_some(),
                            peer_cert_fingerprint: fp,
                        });
                        break;
                    }
                    Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        });
}

#[allow(clippy::too_many_arguments)]
fn race_incoming_hello(
    incoming: &RelayIncoming,
    can_try_p2p: bool,
    has_relay: bool,
    relay_first_delay: Duration,
    mut p2p_rx_slot: Option<mpsc::Receiver<Option<PendingP2pTransport>>>,
    mtls_bundle: &Option<SessionMtlsBundle>,
    require_mtls: bool,
    actual_addr: SocketAddr,
    opts: &HostWorkerOptions,
    updates: &Arc<BoundedHostUpdateQueue>,
    approver: &UiApprover,
    password_state: &Mutex<PasswordState>,
    password_version: &AtomicU64,
    auth_state: &Mutex<AuthRuntimeState>,
    config_version: &AtomicU64,
    session_cancel: &Arc<AtomicBool>,
    relay_cancel: &Arc<AtomicBool>,
    bg_cancel: &Arc<AtomicBool>,
    disconnect_flag: &Arc<AtomicBool>,
    stop_flag: &Arc<AtomicBool>,
) -> Option<(EstablishedIncomingHost, Option<SwitchHandle>)> {
    let race_start = Instant::now();
    let mut relay_rx: Option<RelayDialRx> = if !can_try_p2p && has_relay {
        Some(spawn_initial_relay_dial(
            incoming,
            mtls_bundle,
            require_mtls,
            updates,
            session_cancel,
            relay_cancel,
            disconnect_flag,
            stop_flag,
        ))
    } else {
        None
    };

    let mut active_switch_handle: Option<SwitchHandle> = None;
    let mut established: Option<EstablishedIncomingHost> = None;
    let mut connected_p2p: Option<(Box<dyn Transport>, String, Option<String>)> = None;
    let mut p2p_prebuf: Vec<rc_net::NetEvent> = Vec::new();
    let mut p2p_done = p2p_rx_slot.is_none();
    let mut connected_relay: Option<(Box<dyn Transport>, String)> = None;
    let mut relay_prebuf: Vec<rc_net::NetEvent> = Vec::new();
    let mut relay_done = !has_relay;
    let race_deadline = Instant::now() + Duration::from_secs(16);

    while established.is_none()
        && Instant::now() < race_deadline
        && !stop_flag.load(Ordering::Acquire)
        && !disconnect_flag.load(Ordering::Acquire)
        && !session_cancel.load(Ordering::Acquire)
    {
        if drain_matching_force_disconnect(
            Some(&opts.signal_client),
            None,
            Some(incoming.peer_id.as_str()),
            Some(incoming.session_id.as_str()),
        ) {
            session_cancel.store(true, Ordering::Release);
            disconnect_flag.store(true, Ordering::Release);
            break;
        }
        if relay_rx.is_none()
            && has_relay
            && !relay_done
            && race_start.elapsed() >= relay_first_delay
        {
            relay_rx = Some(spawn_initial_relay_dial(
                incoming,
                mtls_bundle,
                require_mtls,
                updates,
                session_cancel,
                relay_cancel,
                disconnect_flag,
                stop_flag,
            ));
        }

        if let Some(ref rx) = p2p_rx_slot {
            match rx.try_recv() {
                Ok(Some((t, _kind, lbl, fp))) => {
                    connected_p2p = Some((t, lbl, fp));
                    p2p_rx_slot = None;
                }
                Ok(None) | Err(mpsc::TryRecvError::Disconnected) => {
                    p2p_done = true;
                    p2p_rx_slot = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(ref rx) = relay_rx {
            match rx.try_recv() {
                Ok(Some((t, _kind, lbl))) => {
                    connected_relay = Some((t, lbl));
                    relay_rx = None;
                }
                Ok(None) | Err(mpsc::TryRecvError::Disconnected) => {
                    relay_done = true;
                    relay_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }

        // 检查已连上的路径是否实际收到 ClientHello
        type ChosenHelloWinner = (
            Box<dyn Transport>,
            HostTransportKind,
            String,
            Vec<rc_net::NetEvent>,
        );
        let mut chosen: Option<ChosenHelloWinner> = None;
        if let Some((mut t, lbl, fp)) = connected_p2p.take() {
            match try_poll_for_first_hello(&mut t, &mut p2p_prebuf) {
                Ok(true) => {
                    let _ = fp;
                    chosen = Some((
                        t,
                        HostTransportKind::P2p,
                        lbl,
                        std::mem::take(&mut p2p_prebuf),
                    ));
                }
                Ok(false) => {
                    connected_p2p = Some((t, lbl, fp));
                }
                Err(()) => {
                    p2p_done = true;
                    p2p_prebuf.clear();
                }
            }
        }
        if chosen.is_none() {
            if let Some((mut t, lbl)) = connected_relay.take() {
                match try_poll_for_first_hello(&mut t, &mut relay_prebuf) {
                    Ok(true) => {
                        chosen = Some((
                            t,
                            HostTransportKind::Relay,
                            lbl,
                            std::mem::take(&mut relay_prebuf),
                        ));
                    }
                    Ok(false) => {
                        connected_relay = Some((t, lbl));
                    }
                    Err(()) => {
                        relay_done = true;
                        relay_prebuf.clear();
                    }
                }
            }
        }

        if let Some((raw_t, kind, peer_label, prebuf)) = chosen {
            let sw_kind = match kind {
                HostTransportKind::P2p => TransportPathKind::P2p,
                HostTransportKind::Relay => TransportPathKind::Relay,
                HostTransportKind::Lan => TransportPathKind::Lan,
                HostTransportKind::MtlsLan => TransportPathKind::MtlsLan,
            };
            let (mut sw_transport, sw_handle) =
                SwitchableTransport::new(raw_t, rc_net::Role::Host, sw_kind, require_mtls);
            sw_transport.push_prebuffered_events(prebuf);
            match build_and_handshake_transport(
                Box::new(sw_transport),
                kind,
                &peer_label,
                actual_addr,
                opts,
                updates,
                approver,
                password_state,
                password_version,
                auth_state,
                config_version,
                disconnect_flag,
                stop_flag,
            ) {
                HandshakeTransportOutcome::Ready {
                    built,
                    streaming_started,
                    live_pw_ver,
                    live_cfg_ver,
                } => {
                    active_switch_handle = Some(sw_handle.clone());
                    if kind == HostTransportKind::P2p {
                        // P2P 已完成握手胜出，立即取消任何尚未启动或在途的初始 Relay 拨号，保留服务端初始一次性 token 供 50s 内运行期降级复用
                        relay_cancel.store(true, Ordering::Release);
                        drop(relay_rx.take());
                        drop(connected_relay.take());
                    }
                    // 若初始走 Relay，且后台 P2P 已有就绪连接或仍在穿透窗口内，提交给 SwitchableTransport 无损升直连
                    if kind == HostTransportKind::Relay && can_try_p2p {
                        if let Some((t, _lbl, fp)) = connected_p2p.take() {
                            let _ = sw_handle.accept_switch_candidate(CandidateTransport {
                                transport: t,
                                kind: TransportPathKind::P2p,
                                mtls_verified: !require_mtls || fp.is_some(),
                                peer_cert_fingerprint: fp,
                            });
                        } else if let Some(bg_rx) = p2p_rx_slot.take() {
                            spawn_bg_p2p_upgrade_bridge(
                                bg_rx,
                                sw_handle,
                                require_mtls,
                                Arc::clone(bg_cancel),
                                Arc::clone(session_cancel),
                                Arc::clone(disconnect_flag),
                                Arc::clone(stop_flag),
                            );
                        }
                    }
                    established = Some(EstablishedIncomingHost {
                        built,
                        streaming_started,
                        live_pw_ver,
                        live_cfg_ver,
                        transport_kind: kind,
                        peer_label,
                    });
                    break;
                }
                HandshakeTransportOutcome::Failed(err) => {
                    let can_fallback_relay = kind == HostTransportKind::P2p
                        && is_p2p_handshake_fallback_eligible(&err)
                        && !stop_flag.load(Ordering::Acquire)
                        && !disconnect_flag.load(Ordering::Acquire)
                        && !session_cancel.load(Ordering::Acquire)
                        && has_relay;
                    if !can_fallback_relay {
                        bg_cancel.store(true, Ordering::Release);
                        disconnect_flag.store(false, Ordering::Release);
                        return None;
                    }
                    p2p_done = true;
                }
                HandshakeTransportOutcome::BuildError => {
                    bg_cancel.store(true, Ordering::Release);
                    disconnect_flag.store(false, Ordering::Release);
                    return None;
                }
            }
        }

        if p2p_done && connected_p2p.is_none() && relay_done && connected_relay.is_none() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    if stop_flag.load(Ordering::Acquire)
        || disconnect_flag.load(Ordering::Acquire)
        || session_cancel.load(Ordering::Acquire)
    {
        relay_cancel.store(true, Ordering::Release);
        bg_cancel.store(true, Ordering::Release);
        disconnect_flag.store(false, Ordering::Release);
        return None;
    }

    match established {
        Some(est) => Some((est, active_switch_handle)),
        None => {
            relay_cancel.store(true, Ordering::Release);
            bg_cancel.store(true, Ordering::Release);
            disconnect_flag.store(false, Ordering::Release);
            None
        }
    }
}

/// 处理一条入站信令会话请求：
/// 1) `Auto` 模式下实现双端同步 `Relay-first (400ms)` 与 **防分裂脑 `ClientHello` 并发守候**：
///    `0..400ms` 优先快速 P2P；`t = 400ms` 仍未完成 `ClientHello` 建连则并发拨号 `:21117/tcp` mTLS 中继，
///    以实际收到 `ClientHello` 并通过 `ServerHello` 握手的路径作为初始激活通道；
/// 2) 若初始由中继先起流且 `!is_relay_alloc && !skip_p2p_for_proxy`，保留/启动后台 `14s` P2P 穿透
///    （含 `ConeUnverified` Phase 2b 与两波次生日攻击），打通并过 mTLS 校验后经 [`SwitchableTransport`] 无损升直连；
/// 3) 运行期通过 `SwitchControlMsg` 响应 `P2P -> Relay` 降级与 `Relay -> P2P` 复探切换。
#[allow(clippy::too_many_arguments)]
pub(super) fn serve_relay_incoming(
    incoming: RelayIncoming,
    incoming_relay: &Arc<BoundedRelayIncomingQueue>,
    actual_addr: SocketAddr,
    display_addr: &str,
    opts: &HostWorkerOptions,
    updates: &Arc<BoundedHostUpdateQueue>,
    approver: &UiApprover,
    password_state: &Mutex<PasswordState>,
    password_version: &AtomicU64,
    auth_state: &Mutex<AuthRuntimeState>,
    config_version: &AtomicU64,
    active_relay_interrupt: &Mutex<Option<ActiveRelayInterrupt>>,
    active_controllers: &SharedActiveControllers,
    disconnect_flag: &Arc<AtomicBool>,
    stop_flag: &Arc<AtomicBool>,
    close_reason: &Arc<AtomicU8>,
    lock_screen_count: &AtomicU64,
    owner_terminals: &mut PersistentOwnerTerminals,
    file_transfer_dir: &SharedFileTransferDir,
    busy_lan_endpoint: Option<&QuicEndpoint>,
) {
    if stop_flag.load(Ordering::Acquire) {
        return;
    }
    // 清除此前空闲期残留的 disconnect 标记，确保本次新入站会话能正常建连；
    // 若建连/握手期间再次调用 disconnect_client() 则可即时中断。
    disconnect_flag.store(false, Ordering::Release);

    // 使用每会话独立的取消原子量（绝不直接传入 HostHandle::stop_flag，避免 TcpRelayTransport::drop
    // 置位 cancel 时误杀外层被控端工作线程）。
    let session_cancel = Arc::new(AtomicBool::new(false));
    *active_relay_interrupt
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        Some(ActiveRelayInterrupt::Dialing(Arc::clone(&session_cancel)));
    let _interrupt_guard = RelayInterruptSlotGuard {
        slot: active_relay_interrupt,
    };

    if stop_flag.load(Ordering::Acquire) || disconnect_flag.load(Ordering::Acquire) {
        disconnect_flag.store(false, Ordering::Release);
        return;
    }

    let auth_snapshot = auth_state.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mtls_bundle = auth_snapshot.mtls_config.clone();
    let Ok(p2p_mtls) = validate_incoming_p2p_mtls(&auth_snapshot, &incoming, updates) else {
        return;
    };

    // 1) 优先尝试 P2P UDP 打洞 + QUIC 直连；若当前启用了针对中继目标的有效出站代理则直接跳过 UDP P2P
    //    走 TCP 中继隧道；否则若 QUIC 建连成功但应用层握手前断连/超时（H4 分裂脑：控制端 P2P 刚好超时已切中继），
    //    释放死 P2P 会话并自动回退至 TCP 中继重试握手。
    let active_proxy = crate::proxy::active_proxy_config();
    let skip_p2p_for_proxy = match crate::proxy::split_host_port(&incoming.relay_addr) {
        Ok((relay_host, relay_port)) => {
            crate::proxy::is_proxy_active_for_target(&active_proxy, &relay_host, relay_port)
        }
        Err(_) => matches!(
            crate::proxy::resolve_effective_proxy(&active_proxy),
            Ok(Some(_))
        ),
    };
    let candidates = build_host_p2p_candidates(&incoming);
    let can_try_p2p = !skip_p2p_for_proxy
        && !incoming.is_relay_alloc
        && !p2p::parse_candidate_addrs(&candidates).is_empty();
    let has_relay = !incoming.relay_addr.is_empty() && !incoming.relay_token.is_empty();
    let relay_first_delay = Duration::from_millis(
        u64::from(
            incoming
                .relay_fallback_after_ms
                .unwrap_or(DEFAULT_RELAY_FIRST_AFTER_MS as u16),
        )
        .clamp(50, 5_000),
    );
    let bg_cancel = Arc::new(AtomicBool::new(false));
    let relay_cancel = Arc::new(AtomicBool::new(false));

    let p2p_rx = if can_try_p2p
        && !stop_flag.load(Ordering::Acquire)
        && !disconnect_flag.load(Ordering::Acquire)
    {
        Some(spawn_initial_p2p_dial(
            candidates,
            has_relay,
            mtls_bundle.as_ref(),
            auth_snapshot.accept_mtls_lan,
            incoming.peer_id.clone(),
            incoming.is_owner_connection,
            Arc::clone(&session_cancel),
            Arc::clone(&bg_cancel),
        ))
    } else {
        None
    };

    let Some((
        EstablishedIncomingHost {
            built,
            streaming_started,
            live_pw_ver,
            live_cfg_ver,
            transport_kind,
            peer_label,
        },
        active_switch_handle,
    )) = race_incoming_hello(
        &incoming,
        can_try_p2p,
        has_relay,
        relay_first_delay,
        p2p_rx,
        &mtls_bundle,
        auth_snapshot.accept_mtls_lan,
        actual_addr,
        opts,
        updates,
        approver,
        password_state,
        password_version,
        auth_state,
        config_version,
        &session_cancel,
        &relay_cancel,
        &bg_cancel,
        disconnect_flag,
        stop_flag,
    )
    else {
        return;
    };

    let BuiltUiHost {
        mut host,
        clock,
        clock_anchor,
        backend_label,
        hardware_video_active,
        wake_guard,
    } = *built;

    streaming_started.store(true, Ordering::Release);
    emit_peer_connected(&host, &peer_label, updates);

    let _ = &p2p_mtls;
    let switch_runtime = active_switch_handle.map(|handle| HostSwitchRuntime {
        handle,
        incoming: incoming.clone(),
        mtls_bundle: mtls_bundle.clone(),
        require_mtls: auth_snapshot.accept_mtls_lan,
        skip_p2p_for_proxy,
        updates: Arc::clone(updates),
        disconnect_flag: Arc::clone(disconnect_flag),
        stop_flag: Arc::clone(stop_flag),
        active_relay_interrupt: Arc::new(Mutex::new(None)),
        bg_cancel: Arc::clone(&bg_cancel),
        signal_client: Arc::clone(&opts.signal_client),
    });

    let outcome = drive_ui_host_session_with_switch_and_tracking(
        &mut host,
        &clock,
        Some(&clock_anchor),
        updates,
        password_version,
        live_pw_ver,
        config_version,
        live_cfg_ver,
        disconnect_flag,
        stop_flag,
        close_reason,
        transport_kind,
        opts.prefer_hardware,
        opts.audio_enabled,
        hardware_video_active.load(Ordering::Acquire),
        lock_screen_count,
        Some(auth_state),
        owner_terminals,
        wake_guard,
        Arc::clone(file_transfer_dir),
        &opts.allow_assist_file_transfer,
        Some(incoming_relay),
        Some(incoming.peer_id.as_str()),
        Instant::now(),
        switch_runtime,
        Some(HostControllerTracking {
            active_controllers: Arc::clone(active_controllers),
            peer_hints: ActiveControllerPeerHints {
                session_id_hint: (!incoming.session_id.trim().is_empty())
                    .then(|| incoming.session_id.clone()),
                relay_peer_id: (!incoming.peer_id.trim().is_empty())
                    .then(|| incoming.peer_id.clone()),
                relay_peer_name: incoming.peer_name.clone(),
                relay_peer_hostname: incoming.peer_hostname.clone(),
                relay_peer_os: incoming.peer_os.clone(),
                mtls_peer_did: None,
                remote_addr: peer_label,
            },
            signal_client: Arc::clone(&opts.signal_client),
        }),
        busy_lan_endpoint,
    );
    bg_cancel.store(true, Ordering::Release);
    let reason = outcome.reason;
    let last_backend = backend_label
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    disconnect_flag.store(false, Ordering::Release);
    drop(host);

    // M7：先于 ClientDisconnected 与下一次连接原子轮换临时密码。
    maybe_rotate_password_after_session(password_state, password_version, updates, stop_flag);
    updates.push(HostUpdate::ClientDisconnected { reason });
    if !stop_flag.load(Ordering::Acquire) {
        updates.push(HostUpdate::Listening {
            listen_addr: actual_addr.to_string(),
            display_addr: display_addr.to_string(),
            backend: last_backend,
        });
    }
}
