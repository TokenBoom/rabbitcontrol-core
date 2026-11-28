use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use rc_net::Transport;
use rc_session::auth::ConnectionApprover;
use rc_session::AutoApprover;

use crate::p2p::{self, P2pCandidates};
use crate::relay_transport::{
    E2eeRelayTransport, RelayE2eeMode, RelayRole, RelayShutdownHandle, SessionMtlsBundle,
    TcpRelayTransport,
};
use crate::signal_client::RelayIncoming;
use crate::switchable_transport::{
    CandidateTransport, SwitchControlMsg, SwitchHandle, TransportPathKind,
};

use super::approver::UiApprover;
use super::pipeline_factory::{
    build_transport_host_session, collect_host_lan_addrs, BuiltUiHost, CancellableHostTransport,
};
use super::queues::BoundedHostUpdateQueue;
use super::types::{
    generate_temp_code, ActiveRelayInterrupt, AuthRuntimeState, HostTransportKind, HostUpdate,
    HostWorkerOptions, PasswordState, SharedSignalClient, RELAY_CONNECT_TIMEOUT,
};

/// 会话结束后若启用临时验证码自动轮换（且未停机），在工作线程内原子生成新码并推进版本号，
/// 确保紧随其后的下一条入站请求不可能复用已过期的旧临时验证码（M7）。
pub(super) fn maybe_rotate_password_after_session(
    password_state: &Mutex<PasswordState>,
    password_version: &AtomicU64,
    updates: &BoundedHostUpdateQueue,
    stop_flag: &AtomicBool,
) {
    if stop_flag.load(Ordering::Acquire) {
        return;
    }
    let rotated = {
        let mut st = password_state.lock().unwrap_or_else(|e| e.into_inner());
        if !st.auto_rotate {
            None
        } else {
            let prev = st.password.clone();
            let mut next = generate_temp_code();
            if prev.as_deref() == Some(next.as_str()) {
                next = generate_temp_code();
            }
            st.password = Some(next.clone());
            password_version.fetch_add(1, Ordering::AcqRel);
            Some(next)
        }
    };
    if let Some(password) = rotated {
        updates.push(HostUpdate::PasswordRotated { password });
    }
}

/// 判定 P2P 握手失败错误是否属于「传输层超时/断连」导致的分裂脑场景（H4）：
/// 仅在 `Timeout` / `Network` / `Io` 错误时允许回退至 TCP 中继重试握手；
/// 鉴权拒绝 / 协议错误（`Protocol`）或非法配置（`InvalidConfig`）绝不回退重试。
pub(super) fn is_p2p_handshake_fallback_eligible(err: &rc_types::Error) -> bool {
    matches!(
        err,
        rc_types::Error::Timeout(_) | rc_types::Error::Network(_) | rc_types::Error::Io(_)
    )
}

pub(super) struct EstablishedIncomingHost {
    pub(super) built: Box<BuiltUiHost>,
    pub(super) streaming_started: Arc<AtomicBool>,
    pub(super) live_pw_ver: u64,
    pub(super) live_cfg_ver: u64,
    pub(super) transport_kind: HostTransportKind,
    pub(super) peer_label: String,
}

pub(super) enum HandshakeTransportOutcome {
    Ready {
        built: Box<BuiltUiHost>,
        streaming_started: Arc<AtomicBool>,
        live_pw_ver: u64,
        live_cfg_ver: u64,
    },
    Failed(rc_types::Error),
    BuildError,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_and_handshake_transport(
    raw_transport: Box<dyn Transport>,
    transport_kind: HostTransportKind,
    peer_label: &str,
    actual_addr: SocketAddr,
    opts: &HostWorkerOptions,
    updates: &Arc<BoundedHostUpdateQueue>,
    approver: &UiApprover,
    password_state: &Mutex<PasswordState>,
    password_version: &AtomicU64,
    auth_state: &Mutex<AuthRuntimeState>,
    config_version: &AtomicU64,
    disconnect_flag: &Arc<AtomicBool>,
    stop_flag: &Arc<AtomicBool>,
) -> HandshakeTransportOutcome {
    let streaming_started = Arc::new(AtomicBool::new(false));
    let transport: Box<dyn Transport> = Box::new(CancellableHostTransport {
        inner: raw_transport,
        stop_flag: Arc::clone(stop_flag),
        disconnect_flag: Arc::clone(disconnect_flag),
        streaming_started: Arc::clone(&streaming_started),
    });

    let live_pw_ver = password_version.load(Ordering::Acquire);
    let live_cfg_ver = config_version.load(Ordering::Acquire);
    let live_pw = password_state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .password
        .clone();
    let live_auth = auth_state.lock().unwrap_or_else(|e| e.into_inner()).clone();

    let box_approver: Box<dyn ConnectionApprover> = if opts.require_approval {
        approver.set_remote_addr_override(Some(peer_label.to_string()));
        Box::new(approver.clone())
    } else {
        Box::new(AutoApprover)
    };

    let effective_allow_remote = live_auth.allow_owner_control
        && live_auth.allow_remote_assist
        && (!opts.forbid_passwordless_auto_approve || opts.require_approval || live_pw.is_some());
    let mut built = match build_transport_host_session(
        actual_addr,
        transport,
        transport_kind,
        live_pw,
        opts.approval_timeout_us,
        opts.prefer_hardware,
        opts.clipboard_enabled,
        live_auth.allow_owner_control,
        effective_allow_remote,
        live_auth.owner_verifier,
        live_auth.owner_replay_cache,
        box_approver,
        Arc::clone(updates),
    ) {
        Ok(b) => b,
        Err(e) => {
            approver.set_remote_addr_override(None);
            if !stop_flag.load(Ordering::Acquire) {
                updates.push(HostUpdate::error(e));
            }
            return HandshakeTransportOutcome::BuildError;
        }
    };

    built.clock_anchor.reset_pending();
    let handshake_res = built.host.handshake();
    approver.set_remote_addr_override(None);

    match handshake_res {
        Ok(_) => HandshakeTransportOutcome::Ready {
            built: Box::new(built),
            streaming_started,
            live_pw_ver,
            live_cfg_ver,
        },
        Err(err) => {
            // 显式释放已失效的 HostSession（自动取消在途审批并关闭底层传输）。
            drop(built);
            HandshakeTransportOutcome::Failed(err)
        }
    }
}

pub(super) type DialedIncomingTransport = (
    Box<dyn Transport>,
    HostTransportKind,
    String,
    Option<String>,
);

#[allow(clippy::too_many_arguments)]
pub(super) fn dial_relay_for_incoming(
    incoming: &RelayIncoming,
    mtls_bundle: Option<&SessionMtlsBundle>,
    require_e2ee: bool,
    updates: &BoundedHostUpdateQueue,
    active_relay_interrupt: &Mutex<Option<ActiveRelayInterrupt>>,
    session_cancel: &Arc<AtomicBool>,
    disconnect_flag: &AtomicBool,
    stop_flag: &AtomicBool,
) -> Option<DialedIncomingTransport> {
    if incoming.relay_addr.is_empty() {
        return None;
    }
    let (transport, shutdown_handle, peer_fp): (
        Box<dyn Transport>,
        RelayShutdownHandle,
        Option<String>,
    ) = if let Some(bundle) = mtls_bundle {
        let expected_user = incoming
            .is_owner_connection
            .then(|| bundle.local_user_id.clone());
        let peer_bundle = bundle
            .clone()
            .with_expected_peer(Some(incoming.peer_id.clone()), expected_user);
        let relay_mtls = peer_bundle.to_relay_mtls_config(None);
        let e2ee_mode = if require_e2ee {
            RelayE2eeMode::HostRequired(peer_bundle)
        } else {
            RelayE2eeMode::HostAuto(peer_bundle)
        };
        let t = match E2eeRelayTransport::connect_cancellable(
            &incoming.relay_addr,
            RelayRole::Host,
            &incoming.relay_token,
            RELAY_CONNECT_TIMEOUT,
            Arc::clone(session_cancel),
            Some(&relay_mtls),
            e2ee_mode,
        ) {
            Ok(t) => t,
            Err(e) => {
                disconnect_flag.store(false, Ordering::Release);
                if !stop_flag.load(Ordering::Acquire) && !session_cancel.load(Ordering::Acquire) {
                    let friendly =
                        crate::bridge_shared::classify_relay_connect_error(&e, require_e2ee, true);
                    updates.push(HostUpdate::error(format!(
                        "{friendly} ({})",
                        incoming.peer_id
                    )));
                }
                return None;
            }
        };
        let h = t.shutdown_handle();
        let fp = t
            .peer_mtls_identity()
            .map(|id| id.cert_fingerprint_sha256.clone());
        (Box::new(t), h, fp)
    } else {
        let t = match TcpRelayTransport::connect_cancellable(
            &incoming.relay_addr,
            RelayRole::Host,
            &incoming.relay_token,
            RELAY_CONNECT_TIMEOUT,
            Arc::clone(session_cancel),
        ) {
            Ok(t) => t,
            Err(e) => {
                disconnect_flag.store(false, Ordering::Release);
                if !stop_flag.load(Ordering::Acquire) && !session_cancel.load(Ordering::Acquire) {
                    updates.push(HostUpdate::error(format!(
                        "中继通道连接失败 ({}): {e}",
                        incoming.peer_id
                    )));
                }
                return None;
            }
        };
        let h = t.shutdown_handle();
        (Box::new(t), h, None)
    };

    *active_relay_interrupt
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        Some(ActiveRelayInterrupt::Connected(shutdown_handle.clone()));

    // 注册中断句柄后立刻复核停机/断连标志，消除建连完成与 stop()/disconnect_client() 之间的竞态（H3）。
    if stop_flag.load(Ordering::Acquire) || disconnect_flag.load(Ordering::Acquire) {
        shutdown_handle.shutdown();
        disconnect_flag.store(false, Ordering::Release);
        return None;
    }

    Some((
        transport,
        HostTransportKind::Relay,
        format!("设备 {} (中继)", incoming.peer_id),
        peer_fp,
    ))
}

pub(super) fn rebuild_host_p2p_mtls(
    mtls_bundle: Option<&SessionMtlsBundle>,
    require_mtls: bool,
    peer_id: &str,
    is_owner_connection: bool,
) -> Option<rc_net::mtls::MtlsConfig> {
    if !require_mtls {
        return None;
    }
    let bundle = mtls_bundle?;
    let expected_user = is_owner_connection.then(|| bundle.local_user_id.clone());
    bundle
        .clone()
        .with_expected_peer(Some(peer_id.to_string()), expected_user)
        .to_quic_mtls_config()
        .ok()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_host_switch_relay_candidate(
    incoming: RelayIncoming,
    mtls_bundle: Option<SessionMtlsBundle>,
    require_mtls: bool,
    updates: Arc<BoundedHostUpdateQueue>,
    active_relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    bg_cancel: Arc<AtomicBool>,
    disconnect_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    handle: SwitchHandle,
) {
    let _ = thread::Builder::new()
        .name("rc-host-sw-relay".to_string())
        .spawn(move || {
            if bg_cancel.load(Ordering::Acquire)
                || stop_flag.load(Ordering::Acquire)
                || disconnect_flag.load(Ordering::Acquire)
            {
                return;
            }
            if let Some((transport, _kind, _lbl, fp)) = dial_relay_for_incoming(
                &incoming,
                mtls_bundle.as_ref(),
                require_mtls,
                &updates,
                &active_relay_interrupt,
                &bg_cancel,
                &disconnect_flag,
                &stop_flag,
            ) {
                let _ = handle.accept_switch_candidate(CandidateTransport {
                    transport,
                    kind: TransportPathKind::Relay,
                    mtls_verified: !require_mtls || fp.is_some(),
                    peer_cert_fingerprint: fp,
                });
            }
        });
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_host_reprobe_p2p_candidate(
    probe_id: String,
    _peer_port: u16,
    peer_addrs: Vec<String>,
    peer_nat_type: crate::nat::NatType,
    peer_nat_port_delta: Option<i16>,
    peer_nat_port_range: Option<crate::nat::PortRangeHint>,
    punch_secret: String,
    initial_nat_type: crate::nat::NatType,
    initial_nat_delta: Option<i16>,
    initial_nat_range: Option<crate::nat::PortRangeHint>,
    initial_local_udp_port: Option<u16>,
    initial_self_public_addr: Option<String>,
    initial_peer_public_addrs: Vec<String>,
    signal_client: SharedSignalClient,
    p2p_mtls: Option<rc_net::mtls::MtlsConfig>,
    require_mtls: bool,
    bg_cancel: Arc<AtomicBool>,
    handle: SwitchHandle,
) {
    let _ = thread::Builder::new()
        .name("rc-host-reprobe-p2p".to_string())
        .spawn(move || {
            if bg_cancel.load(Ordering::Acquire) {
                return;
            }
            let sc_snap = signal_client
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|sc| sc.snapshot_p2p_reprobe_info());
            let (sc_port, sc_addrs, sc_nat, sc_delta, sc_range) = match sc_snap {
                Some((p, addrs, nat, d, r)) => (p, addrs, Some(nat), d, r),
                None => (None, Vec::new(), None, None, None),
            };
            let local_port = sc_port
                .or(initial_local_udp_port)
                .filter(|&p| p != 0)
                .or_else(|| {
                    std::net::UdpSocket::bind("0.0.0.0:0")
                        .ok()
                        .and_then(|s| s.local_addr().ok())
                        .map(|a| a.port())
                        .filter(|&p| p != 0)
                })
                .unwrap_or(0);
            if local_port == 0 {
                return;
            }
            let mut self_addrs = sc_addrs;
            if let Some(ref pub_raw) = initial_self_public_addr {
                if let Ok(sock) = pub_raw.trim().parse::<SocketAddr>() {
                    if sock.port() != 0 {
                        let s = sock.to_string();
                        if !self_addrs.contains(&s) {
                            self_addrs.push(s);
                        }
                    }
                }
            }
            for lan in collect_host_lan_addrs(local_port) {
                if !self_addrs.contains(&lan) {
                    self_addrs.push(lan);
                }
            }
            let self_nat_type = sc_nat
                .filter(|n| *n != crate::nat::NatType::Unknown)
                .unwrap_or(initial_nat_type);
            let self_nat_port_delta = sc_delta.or(initial_nat_delta);
            let self_nat_port_range = sc_range.or(initial_nat_range);
            let _ = handle.send_control_msg(&SwitchControlMsg::P2pReprobeAnswer {
                probe_id: probe_id.clone(),
                local_udp_port: local_port,
                addrs: self_addrs,
                nat_type: self_nat_type,
                nat_port_delta: self_nat_port_delta,
                nat_port_range: self_nat_port_range,
            });
            let (peer_public_addrs, peer_lan_addrs) =
                crate::signal_client::split_public_and_lan_addrs(
                    &peer_addrs,
                    &initial_peer_public_addrs,
                );
            let cands = P2pCandidates {
                session_id: format!("reprobe-{probe_id}"),
                peer_public_addr: peer_public_addrs.first().cloned(),
                peer_public_addrs,
                peer_lan_addrs,
                local_udp_port: Some(local_port),
                self_nat_type,
                self_nat_port_delta,
                self_nat_port_range,
                peer_nat_type,
                peer_nat_port_delta,
                peer_nat_port_range,
                punch_secret: Some(punch_secret),
                start_after_ms: None,
                relay_fallback_after_ms: None,
            };
            let port_hold = crate::signal_client::acquire_local_udp_port_for_p2p(Some(local_port));
            if let Ok(p2p_conn) = p2p::attempt_p2p_quic_host_mtls(
                &cands,
                p2p::DEFAULT_PUNCH_TIMEOUT,
                p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                &bg_cancel,
                p2p_mtls.as_ref(),
            ) {
                let fp = p2p_conn
                    .peer_mtls_identity()
                    .map(|id| id.cert_fingerprint_sha256);
                let held = crate::signal_client::P2pHeldTransport::new(p2p_conn, port_hold);
                let _ = handle.accept_switch_candidate(CandidateTransport {
                    transport: Box::new(held),
                    kind: TransportPathKind::P2p,
                    mtls_verified: !require_mtls || fp.is_some(),
                    peer_cert_fingerprint: fp,
                });
            }
        });
}

pub(super) fn build_host_p2p_candidates(incoming: &RelayIncoming) -> P2pCandidates {
    let self_pubs: Vec<&str> = incoming.self_public_addr.as_deref().into_iter().collect();
    let peer_pubs: Vec<&str> = incoming
        .peer_public_addr
        .as_deref()
        .into_iter()
        .chain(incoming.peer_public_addrs.iter().map(String::as_str))
        .collect();
    let filtered_peer_lan_addrs =
        p2p::filter_cross_site_lan_addrs(&incoming.peer_lan_addrs, &self_pubs, &peer_pubs);
    P2pCandidates {
        session_id: incoming.session_id.clone(),
        peer_public_addr: incoming.peer_public_addr.clone(),
        peer_public_addrs: incoming.peer_public_addrs.clone(),
        peer_lan_addrs: filtered_peer_lan_addrs,
        local_udp_port: incoming.local_udp_port,
        self_nat_type: incoming.self_nat_type,
        self_nat_port_delta: incoming.self_nat_port_delta,
        self_nat_port_range: incoming.self_nat_port_range,
        peer_nat_type: incoming.peer_nat_type,
        peer_nat_port_delta: incoming.peer_nat_port_delta,
        peer_nat_port_range: incoming.peer_nat_port_range,
        punch_secret: incoming.punch_secret.clone(),
        start_after_ms: incoming.start_after_ms,
        relay_fallback_after_ms: incoming.relay_fallback_after_ms,
    }
}
