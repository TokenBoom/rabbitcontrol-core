use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use rc_net::Transport;

use crate::p2p::{self, P2pCandidates};
use crate::relay_transport::{RelayShutdownHandle, SessionMtlsBundle};
use crate::signal_client::ConnectGrant;

use super::super::adapters::ActiveRelayInterrupt;
use super::super::classify::is_mtls_cert_or_config_error;
use super::super::routing::{
    dial_lan_addrs_happy_eyeballs, race_lan_and_p2p_with, DirectTierRaceError, DirectTierWinner,
    LAN_DIRECT_HANDSHAKE_TIMEOUT, P2P_DIRECT_HANDSHAKE_TIMEOUT,
};
use super::super::types::SessionEnd;
use super::{
    dial_relay_transport, BgP2pUpgradeRx, ConnectEnv, ReadySignalingSession, SelectedRelayPath,
    TierHandshakeResult,
};

type PendingDirectTransport = (
    Box<dyn Transport>,
    &'static str,
    Option<&'static str>,
    Option<String>,
    SocketAddr,
    Duration,
);

/// `Auto` 模式下拥有中继且存在直连/P2P 候选时：先等待 `relay_first_delay` 优先直连，
/// 超时未成行则并发启动 Relay 与直连赛跑，若 Relay 先就绪则把后台直连交接给运行期无损升级通道。
#[allow(clippy::too_many_arguments)]
pub(super) fn connect_relay_first_race(
    env: &ConnectEnv<'_>,
    grant: &ConnectGrant,
    peer_bundle: Option<&SessionMtlsBundle>,
    lan_addrs: &[SocketAddr],
    p2p_candidates: &P2pCandidates,
    has_lan: bool,
    has_p2p: bool,
    bg_p2p_cancel: &Arc<AtomicBool>,
    ready: &mut Option<ReadySignalingSession>,
    direct_fail_reasons: &mut Vec<String>,
    initial_relay_token_consumed: &mut bool,
    bg_p2p_upgrade_rx: &mut Option<BgP2pUpgradeRx>,
) -> Result<(), Result<SessionEnd, SessionEnd>> {
    let cfg = env.cfg;
    let relay_first_delay = Duration::from_millis(
        u64::from(grant.relay_fallback_after_ms.unwrap_or(400)).clamp(50, 5_000),
    );
    let direct_rx = spawn_direct_race_thread(
        cfg.connect_addr,
        cfg.encrypt_connection,
        peer_bundle,
        lan_addrs,
        p2p_candidates,
        has_lan,
        has_p2p,
        &env.disconnect_flag,
        bg_p2p_cancel,
    );

    // t = 0..400ms 优先等待直连；超时未成行则于 t = 400ms 启动 Relay 同步起流
    let relay_start_at = Instant::now() + relay_first_delay;
    let mut direct_rx_slot = Some(direct_rx);
    let mut direct_finished_early = false;
    while Instant::now() < relay_start_at && !env.disconnect_flag.load(Ordering::Acquire) {
        if let Some(ref rx) = direct_rx_slot {
            match rx.try_recv() {
                Ok(Ok((t, lbl, suffix, fp, p_addr, hs_to))) => {
                    direct_rx_slot = None;
                    match env.attempt_tier_handshake(
                        SelectedRelayPath {
                            transport: t,
                            relay_shutdown: None,
                            transport_label: lbl,
                            backend_suffix: suffix,
                            mtls_active: cfg.encrypt_connection,
                            peer_cert_fingerprint: fp,
                        },
                        p_addr,
                        hs_to,
                        true,
                    ) {
                        TierHandshakeResult::Ready(sess) => {
                            *ready = Some(*sess);
                            bg_p2p_cancel.store(true, Ordering::Release);
                            break;
                        }
                        TierHandshakeResult::Fallback(reason) => {
                            direct_fail_reasons.push(reason);
                            direct_finished_early = true;
                            break;
                        }
                        TierHandshakeResult::Abort(res) => return Err(res),
                    }
                }
                Ok(Err(DirectTierRaceError::FatalMtls(msg))) => {
                    bg_p2p_cancel.store(true, Ordering::Release);
                    return Err(Err(SessionEnd::fatal(msg)));
                }
                Ok(Err(DirectTierRaceError::Cancelled)) => {
                    direct_rx_slot = None;
                    direct_finished_early = true;
                    break;
                }
                Ok(Err(DirectTierRaceError::NonFatal(reasons))) => {
                    direct_fail_reasons.extend(reasons);
                    direct_rx_slot = None;
                    direct_finished_early = true;
                    break;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    direct_rx_slot = None;
                    direct_finished_early = true;
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    thread::sleep(Duration::from_millis(5));
                }
            }
        } else {
            break;
        }
    }

    if ready.is_none() && !env.disconnect_flag.load(Ordering::Acquire) {
        let _ = direct_finished_early;
        race_relay_and_direct_handshakes(
            env,
            grant,
            peer_bundle,
            direct_rx_slot,
            bg_p2p_cancel,
            ready,
            direct_fail_reasons,
            initial_relay_token_consumed,
            bg_p2p_upgrade_rx,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_direct_race_thread(
    connect_addr: SocketAddr,
    encrypt_conn: bool,
    peer_bundle: Option<&SessionMtlsBundle>,
    lan_addrs: &[SocketAddr],
    p2p_candidates: &P2pCandidates,
    has_lan: bool,
    has_p2p: bool,
    disconnect_flag: &Arc<AtomicBool>,
    bg_p2p_cancel: &Arc<AtomicBool>,
) -> mpsc::Receiver<Result<PendingDirectTransport, DirectTierRaceError>> {
    let quic_mtls_c = if encrypt_conn {
        peer_bundle.and_then(|b| b.to_quic_mtls_config().ok())
    } else {
        None
    };
    let lan_addrs_c = lan_addrs.to_vec();
    let p2p_cands_c = p2p_candidates.clone();
    let disc_c = Arc::clone(disconnect_flag);
    let bg_c = Arc::clone(bg_p2p_cancel);
    let direct_cancel = Arc::new(AtomicBool::new(false));
    let dc_watch = Arc::clone(&direct_cancel);
    let (direct_tx, direct_rx) =
        mpsc::channel::<Result<PendingDirectTransport, DirectTierRaceError>>();

    let _ = thread::Builder::new()
        .name("rc-client-direct-race".to_string())
        .spawn(move || {
            let watch_stop = Arc::new(AtomicBool::new(false));
            let ws_c = Arc::clone(&watch_stop);
            let watcher = thread::spawn(move || {
                while !ws_c.load(Ordering::Acquire) {
                    if disc_c.load(Ordering::Acquire) || bg_c.load(Ordering::Acquire) {
                        dc_watch.store(true, Ordering::Release);
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            });

            const BG_P2P_PUNCH_TIMEOUT: Duration = Duration::from_secs(14);
            let res = if has_lan && has_p2p {
                match race_lan_and_p2p_with(
                    encrypt_conn,
                    &direct_cancel,
                    |lan_cancel| {
                        dial_lan_addrs_happy_eyeballs(
                            &lan_addrs_c,
                            quic_mtls_c.as_ref(),
                            encrypt_conn,
                            lan_cancel,
                        )
                    },
                    |p2p_cancel| {
                        let port_hold = crate::signal_client::acquire_local_udp_port_for_p2p(
                            p2p_cands_c.local_udp_port,
                        );
                        match p2p::attempt_p2p_quic_client_mtls(
                            &p2p_cands_c,
                            BG_P2P_PUNCH_TIMEOUT,
                            p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                            p2p_cancel,
                            quic_mtls_c.as_ref(),
                        ) {
                            Ok(p2p_conn) => {
                                let held = crate::signal_client::P2pHeldTransport::new(
                                    p2p_conn, port_hold,
                                );
                                let fp = held
                                    .peer_mtls_identity()
                                    .map(|id| id.cert_fingerprint_sha256);
                                Ok((Box::new(held) as Box<dyn Transport>, fp))
                            }
                            Err(e) => {
                                drop(port_hold);
                                Err((e, None))
                            }
                        }
                    },
                ) {
                    Ok(DirectTierWinner::Lan {
                        transport,
                        peer_cert_fingerprint,
                        lan_addr,
                        ..
                    }) => Ok((
                        transport,
                        "UDP LAN",
                        None,
                        peer_cert_fingerprint,
                        lan_addr,
                        LAN_DIRECT_HANDSHAKE_TIMEOUT,
                    )),
                    Ok(DirectTierWinner::P2p {
                        transport,
                        peer_cert_fingerprint,
                    }) => Ok((
                        transport,
                        "UDP P2P",
                        Some("(P2P 直连)"),
                        peer_cert_fingerprint,
                        connect_addr,
                        P2P_DIRECT_HANDSHAKE_TIMEOUT,
                    )),
                    Err(e) => Err(e),
                }
            } else if has_lan {
                dial_lan_addrs_happy_eyeballs(
                    &lan_addrs_c,
                    quic_mtls_c.as_ref(),
                    encrypt_conn,
                    &direct_cancel,
                )
                .map(|(t, fp, lan_addr)| {
                    (
                        t,
                        "UDP LAN",
                        None,
                        fp,
                        lan_addr,
                        LAN_DIRECT_HANDSHAKE_TIMEOUT,
                    )
                })
                .map_err(|(reasons, fatal)| match fatal {
                    Some(m) => DirectTierRaceError::FatalMtls(m),
                    None => DirectTierRaceError::NonFatal(reasons),
                })
            } else {
                let port_hold = crate::signal_client::acquire_local_udp_port_for_p2p(
                    p2p_cands_c.local_udp_port,
                );
                match p2p::attempt_p2p_quic_client_mtls(
                    &p2p_cands_c,
                    BG_P2P_PUNCH_TIMEOUT,
                    p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                    &direct_cancel,
                    quic_mtls_c.as_ref(),
                ) {
                    Ok(p2p_conn) => {
                        let held = crate::signal_client::P2pHeldTransport::new(p2p_conn, port_hold);
                        let fp = held
                            .peer_mtls_identity()
                            .map(|id| id.cert_fingerprint_sha256);
                        Ok((
                            Box::new(held) as Box<dyn Transport>,
                            "UDP P2P",
                            Some("(P2P 直连)"),
                            fp,
                            connect_addr,
                            P2P_DIRECT_HANDSHAKE_TIMEOUT,
                        ))
                    }
                    Err(e) => {
                        drop(port_hold);
                        if encrypt_conn && is_mtls_cert_or_config_error(&e) {
                            Err(DirectTierRaceError::FatalMtls(format!(
                                "P2P mTLS 证书校验失败（严禁静默降级）: {e}"
                            )))
                        } else {
                            Err(DirectTierRaceError::NonFatal(vec![e]))
                        }
                    }
                }
            };
            watch_stop.store(true, Ordering::Release);
            let _ = watcher.join();
            let _ = direct_tx.send(res);
        });

    direct_rx
}

#[allow(clippy::too_many_arguments)]
fn race_relay_and_direct_handshakes(
    env: &ConnectEnv<'_>,
    grant: &ConnectGrant,
    peer_bundle: Option<&SessionMtlsBundle>,
    mut direct_rx_slot: Option<mpsc::Receiver<Result<PendingDirectTransport, DirectTierRaceError>>>,
    bg_p2p_cancel: &Arc<AtomicBool>,
    ready: &mut Option<ReadySignalingSession>,
    direct_fail_reasons: &mut Vec<String>,
    initial_relay_token_consumed: &mut bool,
    bg_p2p_upgrade_rx: &mut Option<BgP2pUpgradeRx>,
) -> Result<(), Result<SessionEnd, SessionEnd>> {
    let cfg = env.cfg;
    let relay_addr_c = grant.relay_addr.clone();
    let relay_tok_c = grant.relay_token.clone();
    let peer_b_c = peer_bundle.cloned();
    let encrypt_c = cfg.encrypt_connection;
    let relay_cancel = Arc::new(AtomicBool::new(false));
    let rc_c = Arc::clone(&relay_cancel);
    let dc_c = Arc::clone(&env.disconnect_flag);
    let (relay_tx, relay_rx) = mpsc::channel();
    let _ = thread::Builder::new()
        .name("rc-client-relay-first".to_string())
        .spawn(move || {
            let peer_b_ref = peer_b_c.as_ref();
            let r = dial_relay_transport(
                &relay_addr_c,
                &relay_tok_c,
                peer_b_ref,
                encrypt_c,
                rc_c,
                &dc_c,
            );
            let _ = relay_tx.send(r);
        });

    let mut relay_done_err: Option<Result<SessionEnd, SessionEnd>> = None;
    let mut relay_rx_open = true;
    let mut pending_direct: Option<PendingDirectTransport> = None;
    let mut relay_hs_rx: Option<mpsc::Receiver<TierHandshakeResult>> = None;
    let mut relay_hs_shutdown: Option<RelayShutdownHandle> = None;

    let loop_outcome: Option<Result<SessionEnd, SessionEnd>> = std::thread::scope(|scope| {
        while ready.is_none() && !env.disconnect_flag.load(Ordering::Acquire) {
            if let Some(ref drx) = direct_rx_slot {
                match drx.try_recv() {
                    Ok(Ok((t, lbl, suffix, fp, p_addr, hs_to))) => {
                        direct_rx_slot = None;
                        if relay_hs_rx.is_some() {
                            // Relay 应用层握手已在途：保留已打通直连，若 Relay 失败立即回退直连，若 Relay 成功则立即交接无损升级
                            pending_direct = Some((t, lbl, suffix, fp, p_addr, hs_to));
                        } else {
                            relay_cancel.store(true, Ordering::Release);
                            match env.attempt_tier_handshake(
                                SelectedRelayPath {
                                    transport: t,
                                    relay_shutdown: None,
                                    transport_label: lbl,
                                    backend_suffix: suffix,
                                    mtls_active: cfg.encrypt_connection,
                                    peer_cert_fingerprint: fp,
                                },
                                p_addr,
                                hs_to,
                                relay_rx_open,
                            ) {
                                TierHandshakeResult::Ready(sess) => {
                                    *ready = Some(*sess);
                                    break;
                                }
                                TierHandshakeResult::Fallback(r) => {
                                    direct_fail_reasons.push(r);
                                }
                                TierHandshakeResult::Abort(res) => {
                                    return Some(res);
                                }
                            }
                        }
                    }
                    Ok(Err(DirectTierRaceError::FatalMtls(msg))) => {
                        relay_cancel.store(true, Ordering::Release);
                        bg_p2p_cancel.store(true, Ordering::Release);
                        if let Some(h) = relay_hs_shutdown.take() {
                            h.shutdown();
                        }
                        return Some(Err(SessionEnd::fatal(msg)));
                    }
                    Ok(Err(DirectTierRaceError::Cancelled)) => {
                        direct_rx_slot = None;
                    }
                    Ok(Err(DirectTierRaceError::NonFatal(reasons))) => {
                        direct_fail_reasons.extend(reasons);
                        direct_rx_slot = None;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        direct_rx_slot = None;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }

            if relay_rx_open && relay_hs_rx.is_none() {
                match relay_rx.try_recv() {
                    Ok(Ok(relay_path)) => {
                        *initial_relay_token_consumed = true;
                        relay_rx_open = false;
                        relay_hs_shutdown = relay_path.relay_shutdown.clone();
                        if let Some(ref handle) = relay_path.relay_shutdown {
                            *env.relay_interrupt
                                .lock()
                                .unwrap_or_else(|e| e.into_inner()) =
                                Some(ActiveRelayInterrupt::Connected(handle.clone()));
                        }
                        let (hs_tx, hs_rx) = mpsc::sync_channel(1);
                        let peer_c = cfg.connect_addr;
                        scope.spawn(move || {
                            let r = env.attempt_tier_handshake(
                                relay_path,
                                peer_c,
                                Duration::from_secs(10),
                                true,
                            );
                            let _ = hs_tx.send(r);
                        });
                        relay_hs_rx = Some(hs_rx);
                    }
                    Ok(Err(err_res)) => {
                        relay_done_err = Some(err_res);
                        relay_rx_open = false;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        relay_rx_open = false;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }

            if let Some(ref hs_rx) = relay_hs_rx {
                match hs_rx.try_recv() {
                    Ok(TierHandshakeResult::Ready(sess)) => {
                        relay_hs_rx = None;
                        relay_hs_shutdown = None;
                        *ready = Some(*sess);
                        if let Some((t, _l, _s, fp, _, _)) = pending_direct.take() {
                            let (up_tx, up_rx) = mpsc::channel();
                            let _ = up_tx.send(Ok((t, fp)));
                            *bg_p2p_upgrade_rx = Some(up_rx);
                        } else if let Some(bg_drx) = direct_rx_slot.take() {
                            *bg_p2p_upgrade_rx = Some(spawn_bg_p2p_upgrade_forwarder(
                                bg_drx,
                                Arc::clone(bg_p2p_cancel),
                                Arc::clone(&env.disconnect_flag),
                            ));
                        }
                        break;
                    }
                    Ok(TierHandshakeResult::Fallback(r)) => {
                        relay_hs_rx = None;
                        relay_hs_shutdown = None;
                        relay_done_err =
                            Some(Err(SessionEnd::fatal(format!("连接/握手失败: {r}"))));
                        if let Some((t, lbl, suffix, fp, p_addr, hs_to)) = pending_direct.take() {
                            match env.attempt_tier_handshake(
                                SelectedRelayPath {
                                    transport: t,
                                    relay_shutdown: None,
                                    transport_label: lbl,
                                    backend_suffix: suffix,
                                    mtls_active: cfg.encrypt_connection,
                                    peer_cert_fingerprint: fp,
                                },
                                p_addr,
                                hs_to,
                                direct_rx_slot.is_some(),
                            ) {
                                TierHandshakeResult::Ready(sess) => {
                                    *ready = Some(*sess);
                                    break;
                                }
                                TierHandshakeResult::Fallback(dr) => {
                                    direct_fail_reasons.push(dr);
                                }
                                TierHandshakeResult::Abort(res) => {
                                    return Some(res);
                                }
                            }
                        }
                    }
                    Ok(TierHandshakeResult::Abort(res)) => {
                        relay_hs_rx = None;
                        relay_hs_shutdown = None;
                        return Some(res);
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        relay_hs_rx = None;
                        relay_hs_shutdown = None;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }

            if direct_rx_slot.is_none()
                && pending_direct.is_none()
                && !relay_rx_open
                && relay_hs_rx.is_none()
            {
                if let Some(err_res) = relay_done_err {
                    return Some(err_res);
                }
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        if let Some(h) = relay_hs_shutdown.take() {
            h.shutdown();
        }
        None
    });

    if let Some(res) = loop_outcome {
        return Err(res);
    }
    Ok(())
}

fn spawn_bg_p2p_upgrade_forwarder(
    bg_drx: mpsc::Receiver<Result<PendingDirectTransport, DirectTierRaceError>>,
    bg_c2: Arc<AtomicBool>,
    disc_c2: Arc<AtomicBool>,
) -> BgP2pUpgradeRx {
    let (up_tx, up_rx) = mpsc::channel();
    let _ = thread::Builder::new()
        .name("rc-client-bg-p2p-wait".to_string())
        .spawn(move || {
            while !bg_c2.load(Ordering::Acquire) && !disc_c2.load(Ordering::Acquire) {
                match bg_drx.recv_timeout(Duration::from_millis(50)) {
                    Ok(Ok((t, _l, _s, fp, _, _))) => {
                        let _ = up_tx.send(Ok((t, fp)));
                        break;
                    }
                    Ok(Err(DirectTierRaceError::FatalMtls(e))) => {
                        let _ = up_tx.send(Err(e));
                        break;
                    }
                    Ok(Err(DirectTierRaceError::Cancelled)) => break,
                    Ok(Err(DirectTierRaceError::NonFatal(reasons))) => {
                        let _ = up_tx.send(Err(reasons.join("；")));
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        });
    up_rx
}
