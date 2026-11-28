use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::app_prefs::ConnectionMode;
use crate::p2p::{self, P2pCandidates};
use crate::signal_client::ConnectGrant;

use super::super::adapters::ActiveRelayInterrupt;
use super::super::routing::{
    build_client_p2p_candidates, collect_lan_candidate_addrs, dial_lan_addrs_happy_eyeballs,
    dial_p2p_held_transport, prepare_peer_mtls_bundle, punch_timeout_for_mode,
    race_lan_and_p2p_with, DirectTierRaceError, DirectTierWinner, LAN_DIRECT_HANDSHAKE_TIMEOUT,
    P2P_DIRECT_HANDSHAKE_TIMEOUT,
};
use super::super::types::{ConnectPhase, SessionEnd, SessionUpdate};
use super::relay_first::connect_relay_first_race;
use super::{
    dial_relay_transport, BgP2pUpgradeRx, ConnectEnv, EstablishedSession, ReadySignalingSession,
    SelectedRelayPath, TierHandshakeResult,
};

fn resolve_proxy_active_for_relay(relay_addr: &str) -> Result<bool, SessionEnd> {
    let active_proxy = crate::proxy::active_proxy_config();
    match crate::proxy::split_host_port(relay_addr) {
        Ok((relay_host, relay_port)) => {
            match crate::proxy::resolve_proxy_for_target(&active_proxy, &relay_host, relay_port) {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(err) => Err(SessionEnd::fatal(format!(
                    "proxy_config_conflict: 代理配置无效：{err}"
                ))),
            }
        }
        Err(_) => match crate::proxy::resolve_effective_proxy(&active_proxy) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(err) => Err(SessionEnd::fatal(format!(
                "proxy_config_conflict: 代理配置无效：{err}"
            ))),
        },
    }
}

/// 信令会话三阶建连：Tier 1（`UDP LAN`）→ Tier 2（`UDP P2P`）→ Tier 3（`TCP Relay`）。
///
/// 仅当尚未进入鉴权/审批交互且在 `Welcome` 前发生底层连接断开/重置时，才允许安全回退至下一级。
pub(super) fn connect_signaling_session(
    env: &ConnectEnv<'_>,
    grant: &ConnectGrant,
) -> Result<EstablishedSession, Result<SessionEnd, SessionEnd>> {
    let cfg = env.cfg;
    let effective_mode = env.effective_mode;

    env.update_tx.push(SessionUpdate::Connecting {
        phase: ConnectPhase::Connecting,
        watch_only: env.live_watch_only.load(Ordering::Acquire),
    });

    let dial_cancel = Arc::new(AtomicBool::new(false));
    *env.relay_interrupt
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        Some(ActiveRelayInterrupt::Dialing(Arc::clone(&dial_cancel)));
    if env.disconnect_flag.load(Ordering::Acquire) {
        return Err(Ok(SessionEnd::fatal("用户主动断开")));
    }

    let peer_bundle = prepare_peer_mtls_bundle(cfg, grant);
    let quic_mtls = if cfg.encrypt_connection {
        let bundle = peer_bundle.as_ref().ok_or_else(|| {
            Err(SessionEnd::fatal(
                "已开启「加密连接 (mTLS)」，但缺少设备证书配置",
            ))
        })?;
        Some(
            bundle
                .to_quic_mtls_config()
                .map_err(|e| Err(SessionEnd::fatal(e)))?,
        )
    } else {
        None
    };

    let mut ready: Option<ReadySignalingSession> = None;
    let mut direct_fail_reasons: Vec<String> = Vec::new();
    let proxy_active_for_relay = resolve_proxy_active_for_relay(&grant.relay_addr).map_err(Err)?;
    if proxy_active_for_relay && effective_mode == ConnectionMode::P2pOnly {
        return Err(Err(SessionEnd::fatal(
            "proxy_config_conflict: 当前已启用出站网络代理，与「仅 P2P 直连」模式冲突，请关闭代理或切换为自动/中继模式",
        )));
    }
    let grant_obtained_at = Instant::now();
    let mut initial_relay_token_consumed = false;
    let bg_p2p_cancel = Arc::new(AtomicBool::new(false));
    let mut bg_p2p_upgrade_rx: Option<BgP2pUpgradeRx> = None;

    let allow_lan_and_p2p = effective_mode != ConnectionMode::TcpRelay && !proxy_active_for_relay;
    if allow_lan_and_p2p && !env.disconnect_flag.load(Ordering::Acquire) {
        let lan_addrs = collect_lan_candidate_addrs(cfg, grant);
        let p2p_candidates = build_client_p2p_candidates(grant);
        let has_lan = !lan_addrs.is_empty();
        let has_p2p = !p2p::parse_candidate_addrs(&p2p_candidates).is_empty();
        let has_relay = !grant.relay_addr.is_empty() && !grant.relay_token.is_empty();
        let use_relay_first =
            effective_mode == ConnectionMode::Auto && has_relay && (has_lan || has_p2p);

        if use_relay_first {
            connect_relay_first_race(
                env,
                grant,
                peer_bundle.as_ref(),
                &lan_addrs,
                &p2p_candidates,
                has_lan,
                has_p2p,
                &bg_p2p_cancel,
                &mut ready,
                &mut direct_fail_reasons,
                &mut initial_relay_token_consumed,
                &mut bg_p2p_upgrade_rx,
            )?;
        } else {
            connect_direct_tier_blocking(
                env,
                quic_mtls.as_ref(),
                &lan_addrs,
                &p2p_candidates,
                has_lan,
                has_p2p,
                &mut ready,
                &mut direct_fail_reasons,
            )?;
        }
    }

    if ready.is_none() && env.disconnect_flag.load(Ordering::Acquire) {
        return Err(Ok(SessionEnd::fatal("用户主动断开")));
    }

    // `P2pOnly` 模式严禁回退至 Tier 3 TCP Relay，直接返回明确不可恢复错误。
    if ready.is_none() && effective_mode == ConnectionMode::P2pOnly {
        let detail = if direct_fail_reasons.is_empty() {
            "未命中局域网地址且对端无可用 P2P 候选地址".to_string()
        } else {
            direct_fail_reasons.join("；")
        };
        return Err(Err(SessionEnd::fatal(format!(
            "P2P 直连失败（当前为「仅 P2P」模式，未回退中继）：{detail}"
        ))));
    }

    // Tier 3：P2P 失败/未命中或强制中继 → 回退 `:21117` 中继（有 mtls_config 强制外层 mTLS；encrypt_connection 再叠加内层 E2EE mTLS）。
    let ReadySignalingSession {
        client,
        negotiated,
        transport_label: chosen_transport_label,
        backend_suffix,
        mtls_active,
        peer_cert_fingerprint: peer_fp,
        switch_handle,
    } = match ready {
        Some(session) => session,
        None => {
            initial_relay_token_consumed = true;
            let relay_path = dial_relay_transport(
                &grant.relay_addr,
                &grant.relay_token,
                peer_bundle.as_ref(),
                cfg.encrypt_connection,
                Arc::clone(&dial_cancel),
                &env.disconnect_flag,
            )
            .map_err(|end_res| match end_res {
                Ok(e) => Err(e),
                Err(e) => Err(e),
            });
            let relay_path = match relay_path {
                Ok(p) => p,
                Err(Ok(end)) | Err(Err(end)) => {
                    return Err(if end.recoverable { Ok(end) } else { Err(end) });
                }
            };
            if let Some(ref shutdown_handle) = relay_path.relay_shutdown {
                *env.relay_interrupt
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) =
                    Some(ActiveRelayInterrupt::Connected(shutdown_handle.clone()));
            }
            if env.disconnect_flag.load(Ordering::Acquire) {
                return Err(Ok(SessionEnd::fatal("用户主动断开")));
            }
            match env.attempt_tier_handshake(
                relay_path,
                cfg.connect_addr,
                Duration::from_secs(10),
                false,
            ) {
                TierHandshakeResult::Ready(session) => *session,
                TierHandshakeResult::Fallback(reason) => {
                    return Err(Err(SessionEnd::fatal(format!("连接/握手失败: {reason}"))));
                }
                TierHandshakeResult::Abort(res) => return Err(res),
            }
        }
    };

    Ok(EstablishedSession {
        client,
        negotiated,
        transport_label: chosen_transport_label,
        active_backend_suffix: backend_suffix,
        mtls_active,
        peer_cert_fingerprint: peer_fp,
        switch_handle: Some(switch_handle),
        bg_p2p_upgrade_rx,
        bg_p2p_cancel_slot: Some(bg_p2p_cancel),
        grant_obtained_at,
        initial_relay_token_consumed,
        proxy_active_runtime: proxy_active_for_relay,
        runtime_mode: effective_mode,
    })
}

#[allow(clippy::too_many_arguments)]
fn connect_direct_tier_blocking(
    env: &ConnectEnv<'_>,
    quic_mtls: Option<&rc_net::mtls::MtlsConfig>,
    lan_addrs: &[SocketAddr],
    p2p_candidates: &P2pCandidates,
    has_lan: bool,
    has_p2p: bool,
    ready: &mut Option<ReadySignalingSession>,
    direct_fail_reasons: &mut Vec<String>,
) -> Result<(), Result<SessionEnd, SessionEnd>> {
    let cfg = env.cfg;
    let effective_mode = env.effective_mode;
    let p2p_punch_timeout = punch_timeout_for_mode(effective_mode);

    let direct_winner: Option<DirectTierWinner> = if has_lan && has_p2p {
        let encrypt_conn = cfg.encrypt_connection;
        let disc_ref = &env.disconnect_flag;
        match race_lan_and_p2p_with(
            encrypt_conn,
            disc_ref,
            |lan_cancel| {
                dial_lan_addrs_happy_eyeballs(lan_addrs, quic_mtls, encrypt_conn, lan_cancel)
            },
            |p2p_cancel| {
                dial_p2p_held_transport(
                    p2p_candidates,
                    quic_mtls,
                    encrypt_conn,
                    p2p_cancel,
                    p2p_punch_timeout,
                )
            },
        ) {
            Ok(winner) => Some(winner),
            Err(DirectTierRaceError::FatalMtls(msg)) => {
                return Err(Err(SessionEnd::fatal(msg)));
            }
            Err(DirectTierRaceError::Cancelled) => {
                return Err(Ok(SessionEnd::fatal("用户主动断开")));
            }
            Err(DirectTierRaceError::NonFatal(reasons)) => {
                direct_fail_reasons.extend(reasons);
                None
            }
        }
    } else if has_lan {
        match dial_lan_addrs_happy_eyeballs(
            lan_addrs,
            quic_mtls,
            cfg.encrypt_connection,
            &env.disconnect_flag,
        ) {
            Ok((t, fp, lan_addr)) => Some(DirectTierWinner::Lan {
                transport: t,
                peer_cert_fingerprint: fp,
                lan_addr,
                p2p_already_failed: false,
            }),
            Err((_reasons, Some(fatal_msg))) => {
                return Err(Err(SessionEnd::fatal(fatal_msg)));
            }
            Err((reasons, None)) => {
                if env.disconnect_flag.load(Ordering::Acquire) {
                    return Err(Ok(SessionEnd::fatal("用户主动断开")));
                }
                direct_fail_reasons.extend(reasons);
                None
            }
        }
    } else if has_p2p {
        match dial_p2p_held_transport(
            p2p_candidates,
            quic_mtls,
            cfg.encrypt_connection,
            &env.disconnect_flag,
            p2p_punch_timeout,
        ) {
            Ok((transport, peer_cert_fingerprint)) => Some(DirectTierWinner::P2p {
                transport,
                peer_cert_fingerprint,
            }),
            Err((err, Some(fatal_mtls))) => {
                let _ = err;
                return Err(Err(SessionEnd::fatal(fatal_mtls)));
            }
            Err((err, None)) => {
                direct_fail_reasons.push(err);
                None
            }
        }
    } else {
        if effective_mode == ConnectionMode::P2pOnly {
            direct_fail_reasons.push("无可用直连或 P2P 候选地址".to_string());
        }
        None
    };

    if let Some(winner) = direct_winner {
        let mut retry_p2p_on_lan_fallback = false;
        let (path, peer_addr, handshake_timeout) = match winner {
            DirectTierWinner::Lan {
                transport,
                peer_cert_fingerprint,
                lan_addr,
                p2p_already_failed,
            } => {
                retry_p2p_on_lan_fallback = !p2p_already_failed;
                (
                    SelectedRelayPath {
                        transport,
                        relay_shutdown: None,
                        transport_label: "UDP LAN",
                        backend_suffix: None,
                        mtls_active: cfg.encrypt_connection,
                        peer_cert_fingerprint,
                    },
                    lan_addr,
                    LAN_DIRECT_HANDSHAKE_TIMEOUT,
                )
            }
            DirectTierWinner::P2p {
                transport,
                peer_cert_fingerprint,
            } => (
                SelectedRelayPath {
                    transport,
                    relay_shutdown: None,
                    transport_label: "UDP P2P",
                    backend_suffix: Some("(P2P 直连)"),
                    mtls_active: cfg.encrypt_connection,
                    peer_cert_fingerprint,
                },
                cfg.connect_addr,
                P2P_DIRECT_HANDSHAKE_TIMEOUT,
            ),
        };
        match env.attempt_tier_handshake(path, peer_addr, handshake_timeout, true) {
            TierHandshakeResult::Ready(session) => {
                *ready = Some(*session);
            }
            TierHandshakeResult::Fallback(reason) => {
                direct_fail_reasons.push(reason);
                env.update_tx.push(SessionUpdate::Connecting {
                    phase: ConnectPhase::Connecting,
                    watch_only: env.live_watch_only.load(Ordering::Acquire),
                });
                if retry_p2p_on_lan_fallback
                    && has_p2p
                    && !env.disconnect_flag.load(Ordering::Acquire)
                {
                    match dial_p2p_held_transport(
                        p2p_candidates,
                        quic_mtls,
                        cfg.encrypt_connection,
                        &env.disconnect_flag,
                        p2p_punch_timeout,
                    ) {
                        Ok((transport, peer_cert_fingerprint)) => {
                            let p2p_path = SelectedRelayPath {
                                transport,
                                relay_shutdown: None,
                                transport_label: "UDP P2P",
                                backend_suffix: Some("(P2P 直连)"),
                                mtls_active: cfg.encrypt_connection,
                                peer_cert_fingerprint,
                            };
                            match env.attempt_tier_handshake(
                                p2p_path,
                                cfg.connect_addr,
                                P2P_DIRECT_HANDSHAKE_TIMEOUT,
                                true,
                            ) {
                                TierHandshakeResult::Ready(session) => {
                                    *ready = Some(*session);
                                }
                                TierHandshakeResult::Fallback(p2p_reason) => {
                                    direct_fail_reasons.push(p2p_reason);
                                    env.update_tx.push(SessionUpdate::Connecting {
                                        phase: ConnectPhase::Connecting,
                                        watch_only: env.live_watch_only.load(Ordering::Acquire),
                                    });
                                }
                                TierHandshakeResult::Abort(res) => return Err(res),
                            }
                        }
                        Err((_, Some(fatal_mtls))) => {
                            return Err(Err(SessionEnd::fatal(fatal_mtls)));
                        }
                        Err((err, None)) => {
                            direct_fail_reasons.push(err);
                        }
                    }
                }
            }
            TierHandshakeResult::Abort(res) => return Err(res),
        }
    }

    Ok(())
}
