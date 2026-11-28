use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rc_net::quic::{Identity, QuicEndpoint};
use rc_net::{NetConfig, Role, Transport};
use rc_session::dev_cert::{dev_server_cert_pem, DEV_CERT_PEM, DEV_KEY_PEM, DEV_SERVER_NAME};

use crate::app_prefs::ConnectionMode;
use crate::lan_discovery;
use crate::p2p::{self, P2pCandidates};
use crate::relay_transport::SessionMtlsBundle;
use crate::signal_client::ConnectGrant;
use crate::switchable_transport::TransportPathKind;

use super::adapters::LanQuicTransport;
use super::classify::is_mtls_cert_or_config_error;
use super::types::UiSessionConfig;

pub(in crate::session_bridge) const LAN_DIRECT_PROBE_TIMEOUT: Duration = Duration::from_millis(300);
/// Tier 1（`UDP LAN`）发送 `Hello` 后等待首条响应的预算（3s，兼顾冷启硬件管线耗时与 `:21117` 15s 中继配对窗口；
/// 收到 `Welcome{ChallengeRequired}` 进入鉴权/审批后自动放宽至 45s）。
pub(in crate::session_bridge) const LAN_DIRECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// Tier 2（`UDP P2P`）发送 `Hello` 后等待首条响应的预算（4s，进入鉴权/审批后自动放宽至 45s）。
pub(in crate::session_bridge) const P2P_DIRECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

pub(in crate::session_bridge) const RELAY_RTT_MIN_BITRATE_BPS: u32 = 2_000_000;
const RELAY_RTT_INFLATE_ABS_US: u64 = 45_000;
const RELAY_RTT_BACKOFF_COOLDOWN: Duration = Duration::from_secs(2);
const RELAY_RTT_RAMP_COOLDOWN: Duration = Duration::from_secs(1);
const RELAY_RTT_MIN_WINDOW: Duration = Duration::from_secs(10);

/// 控制端 TCP Relay 基于 `ProbePong` RTT 膨胀的辅助调速器（捕获 Server→Client 段 TCP 队列膨胀）。
pub(in crate::session_bridge) struct RelayRttController {
    min_rtt_us: Option<u64>,
    min_rtt_updated_at: Option<Instant>,
    window_min_rtt_us: Option<u64>,
    pub(in crate::session_bridge) cap_bps: u32,
    pub(in crate::session_bridge) current_bps: u32,
    inflated_probes: u32,
    clean_probes: u32,
    last_pongs: u64,
    last_adjust: Instant,
}

impl RelayRttController {
    pub(in crate::session_bridge) fn new(initial_bps: u32, now: Instant) -> Self {
        let cap = initial_bps.max(1);
        Self {
            min_rtt_us: None,
            min_rtt_updated_at: None,
            window_min_rtt_us: None,
            cap_bps: cap,
            current_bps: cap,
            inflated_probes: 0,
            clean_probes: 0,
            last_pongs: 0,
            last_adjust: now,
        }
    }

    pub(in crate::session_bridge) fn on_manual_bitrate(&mut self, bps: u32, now: Instant) {
        let v = bps.max(1);
        self.cap_bps = v;
        self.current_bps = v;
        self.inflated_probes = 0;
        self.clean_probes = 0;
        self.last_adjust = now;
    }

    pub(in crate::session_bridge) fn on_probe(
        &mut self,
        now: Instant,
        pongs_received: u64,
        rtt_us: Option<u64>,
    ) -> Option<u32> {
        if pongs_received <= self.last_pongs {
            return None;
        }
        self.last_pongs = pongs_received;
        let rtt = rtt_us?;
        let min_rtt = match (self.min_rtt_us, self.min_rtt_updated_at) {
            (Some(m), Some(updated_at)) => {
                if rtt <= m {
                    self.min_rtt_us = Some(rtt);
                    self.min_rtt_updated_at = Some(now);
                    self.window_min_rtt_us = None;
                    rtt
                } else {
                    let candidate = self.window_min_rtt_us.map_or(rtt, |w| w.min(rtt));
                    if now.saturating_duration_since(updated_at) >= RELAY_RTT_MIN_WINDOW {
                        self.min_rtt_us = Some(candidate);
                        self.min_rtt_updated_at = Some(now);
                        self.window_min_rtt_us = None;
                        candidate
                    } else {
                        self.window_min_rtt_us = Some(candidate);
                        m
                    }
                }
            }
            _ => {
                self.min_rtt_us = Some(rtt);
                self.min_rtt_updated_at = Some(now);
                self.window_min_rtt_us = None;
                rtt
            }
        };

        if rtt > min_rtt.saturating_add(RELAY_RTT_INFLATE_ABS_US) && rtt > min_rtt.saturating_mul(2)
        {
            self.clean_probes = 0;
            self.inflated_probes = self.inflated_probes.saturating_add(1);
            if self.inflated_probes >= 2
                && now.saturating_duration_since(self.last_adjust) >= RELAY_RTT_BACKOFF_COOLDOWN
            {
                let floor = RELAY_RTT_MIN_BITRATE_BPS.min(self.cap_bps).max(1);
                let next = (((self.current_bps as f64) * 0.75) as u32).clamp(floor, self.cap_bps);
                self.last_adjust = now;
                self.inflated_probes = 0;
                if next != self.current_bps {
                    self.current_bps = next;
                    return Some(next);
                }
            }
            return None;
        }

        self.inflated_probes = 0;
        if rtt <= min_rtt.saturating_add(15_000) {
            self.clean_probes = self.clean_probes.saturating_add(1);
            if self.clean_probes >= 2
                && self.current_bps < self.cap_bps
                && now.saturating_duration_since(self.last_adjust) >= RELAY_RTT_RAMP_COOLDOWN
            {
                let step = (self.current_bps / 3).max(2_000_000);
                let next = self.current_bps.saturating_add(step).min(self.cap_bps);
                self.last_adjust = now;
                self.clean_probes = 0;
                if next != self.current_bps {
                    self.current_bps = next;
                    return Some(next);
                }
            }
        } else {
            self.clean_probes = 0;
        }

        None
    }
}

pub(in crate::session_bridge) fn path_kind_from_transport_label(label: &str) -> TransportPathKind {
    match label {
        "TCP Relay" => TransportPathKind::Relay,
        "UDP P2P" => TransportPathKind::P2p,
        "UDP LAN (mTLS)" => TransportPathKind::MtlsLan,
        _ => TransportPathKind::Lan,
    }
}

pub(in crate::session_bridge) fn should_run_initial_bw_probe(path_kind: TransportPathKind) -> bool {
    matches!(path_kind, TransportPathKind::P2p)
}

pub(in crate::session_bridge) fn sync_relay_rtt_ctrl_for_path(
    path_kind: TransportPathKind,
    target_bps: u32,
    now: Instant,
) -> Option<RelayRttController> {
    (path_kind == TransportPathKind::Relay).then(|| RelayRttController::new(target_bps.max(1), now))
}

/// 计算实际生效的连接模式（保留 `force_relay: true` 向后兼容强制映射至 `ConnectionMode::TcpRelay`）。
pub(in crate::session_bridge) fn effective_connection_mode(
    cfg: &UiSessionConfig,
) -> ConnectionMode {
    if cfg.force_relay {
        ConnectionMode::TcpRelay
    } else {
        cfg.connection_mode
    }
}

pub(in crate::session_bridge) fn prepare_peer_mtls_bundle(
    cfg: &UiSessionConfig,
    grant: &ConnectGrant,
) -> Option<SessionMtlsBundle> {
    let mut bundle = cfg.mtls_config.clone()?;
    if bundle.expected_peer_device_id.is_none() && !grant.target_id.is_empty() {
        bundle.expected_peer_device_id = Some(grant.target_id.clone());
    }
    if bundle.expected_peer_user_id.is_none() && grant.is_owner_connection {
        bundle.expected_peer_user_id = Some(bundle.local_user_id.clone());
    }
    Some(bundle)
}

pub(in crate::session_bridge) fn collect_lan_candidate_addrs(
    cfg: &UiSessionConfig,
    grant: &ConnectGrant,
) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut probe_targets = Vec::new();
    if let Some(addr) = cfg.lan_direct_addr {
        out.push(addr);
        probe_targets.push(addr);
    }
    // 当未配置同局域网显式直连地址且双方同族公网 IP 已确认不同时，直接跳过 RFC 1918 `/24` 猜测，
    // 消除跨网 `192.168.1.0/24` 地址重名造成的黑洞等待；跨地址族返回 `None` 时不误杀。
    let self_pubs: Vec<&str> = grant.self_public_addr.as_deref().into_iter().collect();
    let peer_pubs: Vec<&str> = grant
        .peer_public_addr
        .as_deref()
        .into_iter()
        .chain(grant.peer_public_addrs.iter().map(String::as_str))
        .collect();
    if cfg.lan_direct_addr.is_none()
        && crate::nat::same_public_ip_any(&self_pubs, &peer_pubs) == Some(false)
    {
        return out;
    }
    if let Ok(relay_addr) = grant.relay_addr.parse::<SocketAddr>() {
        if !probe_targets.contains(&relay_addr) {
            probe_targets.push(relay_addr);
        }
    }
    let local_ips = lan_discovery::detect_local_interface_ips_for_targets(&probe_targets);
    let local_v4s = local_ips.ipv4s;
    for raw in &grant.peer_lan_addrs {
        let Ok(addr) = raw.parse::<SocketAddr>() else {
            continue;
        };
        let std::net::IpAddr::V4(peer_ip) = addr.ip().to_canonical() else {
            continue;
        };
        if !lan_discovery::is_usable_lan_ipv4(peer_ip) {
            continue;
        }
        let same_subnet = local_v4s
            .iter()
            .any(|local_ip| peer_ip.octets()[..3] == local_ip.octets()[..3]);
        if same_subnet {
            let candidate = SocketAddr::new(
                std::net::IpAddr::V4(peer_ip),
                crate::bridge_shared::DEFAULT_HOST_PORT,
            );
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
    }
    out
}

pub(in crate::session_bridge) enum DirectTierWinner {
    Lan {
        transport: Box<dyn Transport>,
        peer_cert_fingerprint: Option<String>,
        lan_addr: SocketAddr,
        p2p_already_failed: bool,
    },
    P2p {
        transport: Box<dyn Transport>,
        peer_cert_fingerprint: Option<String>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum FirstOk {
    Lan,
    P2p,
}

pub(in crate::session_bridge) enum DirectTierRaceError {
    FatalMtls(String),
    NonFatal(Vec<String>),
    Cancelled,
}

pub(in crate::session_bridge) type LanDialResult =
    Result<(Box<dyn Transport>, Option<String>, SocketAddr), (Vec<String>, Option<String>)>;
pub(in crate::session_bridge) type P2pDialResult =
    Result<(Box<dyn Transport>, Option<String>), (String, Option<String>)>;

enum RaceBranchOutcome {
    LanOk {
        transport: Box<dyn Transport>,
        peer_cert_fingerprint: Option<String>,
        lan_addr: SocketAddr,
    },
    LanErr {
        reasons: Vec<String>,
        fatal_mtls: Option<String>,
    },
    P2pOk {
        transport: Box<dyn Transport>,
        peer_cert_fingerprint: Option<String>,
    },
    P2pErr {
        reason: String,
        fatal_mtls: Option<String>,
    },
}

/// Happy Eyeballs 并发 LAN 直连拨号（单目标零额外线程；多网卡候选以 ~50ms 错峰并发尝试，任一命中即中止其余拨号）。
pub(in crate::session_bridge) fn dial_lan_addrs_happy_eyeballs(
    lan_addrs: &[SocketAddr],
    mtls: Option<&rc_net::mtls::MtlsConfig>,
    encrypt_conn: bool,
    outer_cancel: &AtomicBool,
) -> LanDialResult {
    if lan_addrs.len() <= 1 {
        let mut reasons = Vec::new();
        for &lan_addr in lan_addrs {
            if outer_cancel.load(Ordering::Acquire) {
                break;
            }
            match dial_lan_direct_quic(lan_addr, mtls, outer_cancel) {
                Ok((t, fp)) => return Ok((t, fp, lan_addr)),
                Err(err) => {
                    if encrypt_conn && is_mtls_cert_or_config_error(&err) {
                        return Err((
                            reasons,
                            Some(format!("LAN mTLS 证书校验失败（严禁静默降级）: {err}")),
                        ));
                    }
                    reasons.push(err);
                }
            }
        }
        return Err((reasons, None));
    }

    let capped: Vec<SocketAddr> = lan_addrs.iter().copied().take(4).collect();
    let local_cancel = AtomicBool::new(false);
    let (tx, rx) = mpsc::channel::<(
        SocketAddr,
        Result<(Box<dyn Transport>, Option<String>), String>,
    )>();

    std::thread::scope(|scope| {
        let total = capped.len();
        for (idx, &addr) in capped.iter().enumerate() {
            let tx_c = tx.clone();
            let cancel_ref = &local_cancel;
            scope.spawn(move || {
                if idx > 0 {
                    let delay_end = Instant::now() + Duration::from_millis((idx as u64) * 50);
                    while Instant::now() < delay_end {
                        if cancel_ref.load(Ordering::Acquire)
                            || outer_cancel.load(Ordering::Acquire)
                        {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                if cancel_ref.load(Ordering::Acquire) || outer_cancel.load(Ordering::Acquire) {
                    return;
                }
                let res = dial_lan_direct_quic(addr, mtls, cancel_ref);
                let _ = tx_c.send((addr, res));
            });
        }
        drop(tx);

        let mut reasons = Vec::new();
        let mut fatal_mtls: Option<String> = None;
        let mut received = 0usize;
        while received < total {
            if outer_cancel.load(Ordering::Acquire) {
                local_cancel.store(true, Ordering::Release);
                break;
            }
            match rx.recv_timeout(Duration::from_millis(10)) {
                Ok((addr, Ok((t, fp)))) => {
                    local_cancel.store(true, Ordering::Release);
                    return Ok((t, fp, addr));
                }
                Ok((_addr, Err(err))) => {
                    received += 1;
                    if fatal_mtls.is_none() && encrypt_conn && is_mtls_cert_or_config_error(&err) {
                        fatal_mtls = Some(format!("LAN mTLS 证书校验失败（严禁静默降级）: {err}"));
                    }
                    reasons.push(err);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        Err((reasons, fatal_mtls))
    })
}

pub(in crate::session_bridge) fn race_lan_and_p2p_with<FLan, FP2p>(
    encrypt_connection: bool,
    disconnect_flag: &AtomicBool,
    dial_lan: FLan,
    dial_p2p: FP2p,
) -> Result<DirectTierWinner, DirectTierRaceError>
where
    FLan: FnOnce(&AtomicBool) -> LanDialResult + Send,
    FP2p: FnOnce(&AtomicBool) -> P2pDialResult + Send,
{
    let lan_cancel = AtomicBool::new(false);
    let p2p_cancel = AtomicBool::new(false);
    let (tx, rx) = mpsc::sync_channel::<RaceBranchOutcome>(2);

    std::thread::scope(|scope| {
        let tx_lan = tx.clone();
        let lan_cancel_ref = &lan_cancel;
        scope.spawn(move || {
            let msg = match dial_lan(lan_cancel_ref) {
                Ok((transport, peer_cert_fingerprint, lan_addr)) => RaceBranchOutcome::LanOk {
                    transport,
                    peer_cert_fingerprint,
                    lan_addr,
                },
                Err((reasons, fatal_mtls)) => RaceBranchOutcome::LanErr {
                    reasons,
                    fatal_mtls,
                },
            };
            let _ = tx_lan.send(msg);
        });

        let tx_p2p = tx;
        let p2p_cancel_ref = &p2p_cancel;
        scope.spawn(move || {
            let msg = match dial_p2p(p2p_cancel_ref) {
                Ok((transport, peer_cert_fingerprint)) => RaceBranchOutcome::P2pOk {
                    transport,
                    peer_cert_fingerprint,
                },
                Err((reason, fatal_mtls)) => RaceBranchOutcome::P2pErr { reason, fatal_mtls },
            };
            let _ = tx_p2p.send(msg);
        });

        let mut lan_res: Option<LanDialResult> = None;
        let mut p2p_res: Option<P2pDialResult> = None;
        let mut first_ok: Option<FirstOk> = None;
        let mut p2p_failed_before_lan_win = false;

        while lan_res.is_none() || p2p_res.is_none() {
            if disconnect_flag.load(Ordering::Acquire) {
                lan_cancel.store(true, Ordering::Release);
                p2p_cancel.store(true, Ordering::Release);
            }
            match rx.recv_timeout(Duration::from_millis(10)) {
                Ok(RaceBranchOutcome::LanOk {
                    transport,
                    peer_cert_fingerprint,
                    lan_addr,
                }) => {
                    if first_ok.is_none() {
                        first_ok = Some(FirstOk::Lan);
                    }
                    p2p_cancel.store(true, Ordering::Release);
                    lan_res = Some(Ok((transport, peer_cert_fingerprint, lan_addr)));
                }
                Ok(RaceBranchOutcome::LanErr {
                    reasons,
                    fatal_mtls,
                }) => {
                    if fatal_mtls.is_some() {
                        p2p_cancel.store(true, Ordering::Release);
                    }
                    lan_res = Some(Err((reasons, fatal_mtls)));
                }
                Ok(RaceBranchOutcome::P2pOk {
                    transport,
                    peer_cert_fingerprint,
                }) => {
                    if first_ok.is_none() {
                        first_ok = Some(FirstOk::P2p);
                    }
                    lan_cancel.store(true, Ordering::Release);
                    p2p_res = Some(Ok((transport, peer_cert_fingerprint)));
                }
                Ok(RaceBranchOutcome::P2pErr { reason, fatal_mtls }) => {
                    if lan_res.is_none() {
                        p2p_failed_before_lan_win = true;
                    }
                    if fatal_mtls.is_some() {
                        lan_cancel.store(true, Ordering::Release);
                    }
                    p2p_res = Some(Err((reason, fatal_mtls)));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        if disconnect_flag.load(Ordering::Acquire) {
            return Err(DirectTierRaceError::Cancelled);
        }

        if encrypt_connection {
            if let Some(Err((_, Some(mtls_err)))) = &lan_res {
                return Err(DirectTierRaceError::FatalMtls(mtls_err.clone()));
            }
            if let Some(Err((_, Some(mtls_err)))) = &p2p_res {
                return Err(DirectTierRaceError::FatalMtls(mtls_err.clone()));
            }
        }

        // 保持先到达的胜者，避免丢弃已与 Host 建好 QUIC 的 P2P 连接造成 Host 孤儿会话。
        if first_ok == Some(FirstOk::P2p) {
            if let Some(Ok((transport, peer_cert_fingerprint))) = p2p_res {
                drop(lan_res);
                return Ok(DirectTierWinner::P2p {
                    transport,
                    peer_cert_fingerprint,
                });
            }
        }

        if let Some(Ok((transport, peer_cert_fingerprint, lan_addr))) = lan_res {
            drop(p2p_res);
            return Ok(DirectTierWinner::Lan {
                transport,
                peer_cert_fingerprint,
                lan_addr,
                p2p_already_failed: p2p_failed_before_lan_win,
            });
        }

        if let Some(Ok((transport, peer_cert_fingerprint))) = p2p_res {
            return Ok(DirectTierWinner::P2p {
                transport,
                peer_cert_fingerprint,
            });
        }

        let mut all_reasons = Vec::new();
        if let Some(Err((reasons, _))) = lan_res {
            all_reasons.extend(reasons);
        }
        if let Some(Err((reason, _))) = p2p_res {
            all_reasons.push(reason);
        }
        Err(DirectTierRaceError::NonFatal(all_reasons))
    })
}

pub(in crate::session_bridge) fn build_client_p2p_candidates(
    grant: &ConnectGrant,
) -> P2pCandidates {
    let self_pubs: Vec<&str> = grant.self_public_addr.as_deref().into_iter().collect();
    let peer_pubs: Vec<&str> = grant
        .peer_public_addr
        .as_deref()
        .into_iter()
        .chain(grant.peer_public_addrs.iter().map(String::as_str))
        .collect();
    let filtered_peer_lan_addrs =
        p2p::filter_cross_site_lan_addrs(&grant.peer_lan_addrs, &self_pubs, &peer_pubs);
    P2pCandidates {
        session_id: grant.session_id.clone(),
        peer_public_addr: grant.peer_public_addr.clone(),
        peer_public_addrs: grant.peer_public_addrs.clone(),
        peer_lan_addrs: filtered_peer_lan_addrs,
        local_udp_port: grant.local_udp_port,
        self_nat_type: grant.self_nat_type,
        self_nat_port_delta: grant.self_nat_port_delta,
        self_nat_port_range: grant.self_nat_port_range,
        peer_nat_type: grant.peer_nat_type,
        peer_nat_port_delta: grant.peer_nat_port_delta,
        peer_nat_port_range: grant.peer_nat_port_range,
        punch_secret: grant.punch_secret.clone(),
        start_after_ms: grant.start_after_ms,
        relay_fallback_after_ms: grant.relay_fallback_after_ms,
    }
}

pub(in crate::session_bridge) fn punch_timeout_for_mode(mode: ConnectionMode) -> Duration {
    match mode {
        ConnectionMode::P2pOnly => p2p::P2P_ONLY_PUNCH_TIMEOUT,
        ConnectionMode::Auto | ConnectionMode::TcpRelay => p2p::DEFAULT_PUNCH_TIMEOUT,
    }
}

pub(in crate::session_bridge) fn dial_p2p_held_transport(
    candidates: &P2pCandidates,
    quic_mtls: Option<&rc_net::mtls::MtlsConfig>,
    encrypt_connection: bool,
    cancel: &AtomicBool,
    punch_timeout: Duration,
) -> P2pDialResult {
    let port_hold = crate::signal_client::acquire_local_udp_port_for_p2p(candidates.local_udp_port);
    match p2p::attempt_p2p_quic_client_mtls(
        candidates,
        punch_timeout,
        p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
        cancel,
        quic_mtls,
    ) {
        Ok(p2p_conn) => {
            let held = crate::signal_client::P2pHeldTransport::new(p2p_conn, port_hold);
            let fp = held
                .peer_mtls_identity()
                .map(|id| id.cert_fingerprint_sha256);
            Ok((Box::new(held) as Box<dyn Transport>, fp))
        }
        Err(err) => {
            drop(port_hold);
            let fatal_mtls = (encrypt_connection && is_mtls_cert_or_config_error(&err))
                .then(|| format!("P2P mTLS 证书校验失败（严禁静默降级）: {err}"));
            Err((err, fatal_mtls))
        }
    }
}

pub(in crate::session_bridge) fn dial_lan_direct_quic(
    lan_addr: SocketAddr,
    mtls: Option<&rc_net::mtls::MtlsConfig>,
    cancel: &AtomicBool,
) -> Result<(Box<dyn Transport>, Option<String>), String> {
    let identity = Identity::from_pem(DEV_CERT_PEM, DEV_KEY_PEM)
        .map_err(|e| format!("LAN QUIC 端点证书加载失败: {e}"))?;
    let local_addr: SocketAddr = if lan_addr.is_ipv6() {
        "[::]:0".parse().expect("[::]:0 is a valid socket addr")
    } else {
        "0.0.0.0:0"
            .parse()
            .expect("0.0.0.0:0 is a valid socket addr")
    };
    let net = NetConfig {
        role: Role::Controller,
        local_addr,
        peer_addr: Some(lan_addr),
        mtu: rc_session::DEFAULT_SESSION_MTU,
    };
    let endpoint =
        QuicEndpoint::new(&net, &identity).map_err(|e| format!("LAN QUIC 端点创建失败: {e}"))?;
    if let Some(mtls_cfg) = mtls {
        let transport = endpoint
            .connect_mtls_cancelable(lan_addr, mtls_cfg, "", LAN_DIRECT_PROBE_TIMEOUT, cancel)
            .map_err(|e| {
                let msg = e.to_string();
                if is_mtls_cert_or_config_error(&msg) {
                    format!("LAN mTLS 证书校验失败: {msg}")
                } else {
                    format!("LAN 直连失败: {msg}")
                }
            })?;
        let fp = transport
            .peer_mtls_identity()
            .map(|id| id.cert_fingerprint_sha256);
        Ok((
            Box::new(LanQuicTransport {
                transport,
                _endpoint: endpoint,
            }),
            fp,
        ))
    } else {
        let certs = Identity::certs_from_pem(dev_server_cert_pem())
            .map_err(|e| format!("LAN 受信任证书解析失败: {e}"))?;
        let transport = endpoint
            .connect_cancelable(
                lan_addr,
                &certs,
                DEV_SERVER_NAME,
                LAN_DIRECT_PROBE_TIMEOUT,
                cancel,
            )
            .map_err(|e| format!("LAN QUIC 直连失败: {e}"))?;
        Ok((
            Box::new(LanQuicTransport {
                transport,
                _endpoint: endpoint,
            }),
            None,
        ))
    }
}
