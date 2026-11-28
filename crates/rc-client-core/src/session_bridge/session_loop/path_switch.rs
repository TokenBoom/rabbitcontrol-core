use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use crate::app_prefs::ConnectionMode;
use crate::hud::HudSnapshot;
use crate::p2p::{self, P2pCandidates};
use crate::relay_transport::{E2eeRelayTransport, RelayE2eeMode, RelayRole, TcpRelayTransport};
use crate::signal_client::ConnectGrant;
use crate::switchable_transport::{
    CandidateTransport, HysteresisConfig, HysteresisDecision, SwitchControlMsg, SwitchHandle,
    TransportPathKind, DEFAULT_SWITCH_STAGE_TIMEOUT,
};

use super::super::display_ctrl::sample_hud;
use super::super::routing::{prepare_peer_mtls_bundle, sync_relay_rtt_ctrl_for_path};
use super::super::types::SessionUpdate;
use super::SessionLoopState;

impl SessionLoopState<'_> {
    /// 驱动运行期多路径无缝切换状态机（事件上报、后台升级/降级/重探回收、滞回评估）。
    pub(super) fn pump_runtime_path_switching(&mut self) {
        let Some(sw_h) = self.switch_handle.clone() else {
            return;
        };

        self.drain_switch_path_events(&sw_h);
        self.drain_switch_control_and_completions(&sw_h);
        self.poll_switch_background_workers(&sw_h);
        self.evaluate_path_hysteresis(&sw_h);
    }

    fn drain_switch_path_events(&mut self, sw_h: &SwitchHandle) {
        for ev in sw_h.drain_path_events() {
            self.transport_label = ev.label;
            self.active_backend_suffix = ev.backend_suffix;
            self.mtls_active = ev.mtls_active;
            self.peer_cert_fingerprint = ev.peer_cert_fingerprint.clone();
            self.active_path_kind = ev.kind;
            let mut cur_neg = self.client.negotiated().unwrap_or(self.negotiated);
            cur_neg.width = self.hud_width;
            cur_neg.height = self.hud_height;
            self.relay_rtt_ctrl = sync_relay_rtt_ctrl_for_path(
                self.active_path_kind,
                self.last_manual_bitrate_bps.unwrap_or(cur_neg.bitrate_bps),
                Instant::now(),
            );
            self.update_tx.push(SessionUpdate::Negotiated {
                width: cur_neg.width,
                height: cur_neg.height,
                fps: cur_neg.fps,
                bitrate_bps: cur_neg.bitrate_bps,
                backend: self.backend.clone(),
                watch_only: self.live_watch_only.load(Ordering::Acquire),
                transport: self.transport_label.to_string(),
                mtls_active: self.mtls_active,
                peer_cert_fingerprint: self.peer_cert_fingerprint.clone(),
            });
            let cur = sample_hud(&self.client, &self.clock_reader, cur_neg);
            let snap = HudSnapshot::derive_with_transport(
                Some(&self.prev_hud),
                &cur,
                self.transport_label,
            );
            self.update_tx.push(SessionUpdate::Hud(snap));
            self.prev_hud = cur;
        }
    }

    fn drain_switch_control_and_completions(&mut self, sw_h: &SwitchHandle) {
        for ctrl_msg in sw_h.drain_control_msgs() {
            if matches!(ctrl_msg, SwitchControlMsg::P2pReprobeAnswer { .. }) {
                if let Some(ref ans_tx) = self.reprobe_answer_tx {
                    let _ = ans_tx.send(ctrl_msg);
                }
            }
        }

        let cur_committed = sw_h.switches_committed();
        let cur_aborted = sw_h.switches_aborted();
        if cur_committed > self.last_seen_committed || cur_aborted > self.last_seen_aborted {
            let committed = cur_committed > self.last_seen_committed;
            self.last_seen_committed = cur_committed;
            self.last_seen_aborted = cur_aborted;
            match self.runtime_switch_inflight.take() {
                Some(1) => self
                    .path_monitor
                    .on_degrade_finished(committed, Instant::now()),
                Some(2) => self.path_monitor.on_reprobe_finished(Instant::now()),
                _ => {}
            }
        }
    }

    fn poll_switch_background_workers(&mut self, sw_h: &SwitchHandle) {
        if let Some(ref up_rx) = self.bg_p2p_upgrade_rx {
            match up_rx.try_recv() {
                Ok(Ok((t, fp))) => {
                    self.bg_p2p_upgrade_rx = None;
                    self.path_monitor.on_reprobe_finished(Instant::now());
                    let _ = sw_h.initiate_switch(CandidateTransport {
                        transport: t,
                        kind: TransportPathKind::P2p,
                        mtls_verified: !self.cfg.encrypt_connection || fp.is_some(),
                        peer_cert_fingerprint: fp,
                    });
                }
                Ok(Err(_)) | Err(mpsc::TryRecvError::Disconnected) => {
                    self.bg_p2p_upgrade_rx = None;
                    self.path_monitor.on_reprobe_finished(Instant::now());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }

        if let Some(ref drx) = self.degrade_rx {
            match drx.try_recv() {
                Ok(Ok(cand)) => {
                    self.degrade_rx = None;
                    if sw_h.initiate_switch(cand).is_err() {
                        self.runtime_switch_inflight = None;
                        self.path_monitor.on_degrade_finished(false, Instant::now());
                    }
                }
                Ok(Err(_)) | Err(mpsc::TryRecvError::Disconnected) => {
                    self.degrade_rx = None;
                    self.runtime_switch_inflight = None;
                    self.path_monitor.on_degrade_finished(false, Instant::now());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }

        if let Some(ref rrx) = self.reprobe_rx {
            match rrx.try_recv() {
                Ok(Ok(cand)) => {
                    self.reprobe_rx = None;
                    self.reprobe_answer_tx = None;
                    let max_rtt_us = self
                        .path_monitor
                        .relay_rtt_ms()
                        .map(|r| r.saturating_add(40).saturating_mul(1_000));
                    if sw_h
                        .submit_candidate_with_hold(
                            cand,
                            true,
                            DEFAULT_SWITCH_STAGE_TIMEOUT,
                            HysteresisConfig::default().recovery_hold_window,
                            max_rtt_us,
                            Some(HysteresisConfig::default().recovery_max_loss),
                        )
                        .is_err()
                    {
                        self.runtime_switch_inflight = None;
                        self.path_monitor.on_reprobe_finished(Instant::now());
                    }
                }
                Ok(Err(_)) | Err(mpsc::TryRecvError::Disconnected) => {
                    self.reprobe_rx = None;
                    self.reprobe_answer_tx = None;
                    self.runtime_switch_inflight = None;
                    self.path_monitor.on_reprobe_finished(Instant::now());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    fn evaluate_path_hysteresis(&mut self, sw_h: &SwitchHandle) {
        if !(self.is_signaling_session
            && self.runtime_mode == ConnectionMode::Auto
            && !self.proxy_active_runtime
            && self.bg_p2p_upgrade_rx.is_none()
            && sw_h.is_switch_capable()
            && !sw_h.is_switch_inflight()
            && self.runtime_switch_inflight.is_none()
            && self.last_path_sample_at.elapsed() >= Duration::from_millis(200))
        {
            return;
        }

        self.last_path_sample_at = Instant::now();
        let stats = self.client.net_stats();
        match self.path_monitor.evaluate(
            self.last_path_sample_at,
            sw_h.active_kind(),
            stats,
            sw_h.rx_silence(),
        ) {
            HysteresisDecision::Hold => {}
            HysteresisDecision::TriggerDegradeToRelay { .. } => {
                if let Some(grant) = self.cfg.relay_grant.clone() {
                    self.spawn_runtime_degrade_worker(sw_h, &grant);
                }
            }
            HysteresisDecision::TriggerP2pReprobe => {
                if let Some(grant) = self.cfg.relay_grant.clone() {
                    self.spawn_runtime_p2p_reprobe_worker(sw_h, &grant);
                }
            }
        }
    }

    fn spawn_runtime_degrade_worker(&mut self, sw_h: &SwitchHandle, grant: &ConnectGrant) {
        self.runtime_switch_inflight = Some(1);
        let (dtx, drx) = mpsc::channel();
        self.degrade_rx = Some(drx);
        let use_initial = !self.initial_relay_token_consumed
            && self.grant_obtained_at.elapsed() < Duration::from_secs(50)
            && !grant.relay_addr.is_empty()
            && !grant.relay_token.is_empty();
        let init_addr = grant.relay_addr.clone();
        let init_tok = grant.relay_token.clone();
        let peer_b = prepare_peer_mtls_bundle(&self.cfg, grant);
        let sig_opt = self.cfg.signal_client.clone();
        let target_id_opt = self
            .cfg
            .target_device_id
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| (!grant.target_id.is_empty()).then(|| grant.target_id.clone()));
        let encrypt_c = self.cfg.encrypt_connection;
        let sw_clone = sw_h.clone();
        let disc_c = Arc::clone(&self.disconnect_flag);
        if use_initial {
            self.initial_relay_token_consumed = true;
        }
        let _ = thread::Builder::new()
            .name("rc-runtime-degrade".to_string())
            .spawn(move || {
                let (relay_addr, relay_token) = if use_initial {
                    let _ = sw_clone.send_control_msg(&SwitchControlMsg::UseInitialRelay);
                    (init_addr, init_tok)
                } else if let (Some(sig), Some(tid)) = (sig_opt, target_id_opt) {
                    match sig.request_relay(&tid, Duration::from_secs(8)) {
                        Ok(fresh) => {
                            let _ = sw_clone.send_control_msg(&SwitchControlMsg::RelayAllocReady {
                                session_id: fresh.session_id,
                            });
                            (fresh.relay_addr, fresh.relay_token)
                        }
                        Err(e) => {
                            let _ = dtx.send(Err(e));
                            return;
                        }
                    }
                } else {
                    let _ = dtx.send(Err("缺少信令句柄，无法续签中继令牌".to_string()));
                    return;
                };

                let res = if encrypt_c {
                    let Some(bundle) = peer_b else {
                        let _ = dtx.send(Err("缺少 mTLS 证书".into()));
                        return;
                    };
                    let relay_mtls = bundle.to_relay_mtls_config(None);
                    E2eeRelayTransport::connect_cancellable(
                        &relay_addr,
                        RelayRole::Client,
                        &relay_token,
                        Duration::from_secs(10),
                        disc_c,
                        Some(&relay_mtls),
                        RelayE2eeMode::ClientRequired(bundle),
                    )
                    .map(|t| {
                        let fp = t
                            .peer_mtls_identity()
                            .map(|i| i.cert_fingerprint_sha256.clone());
                        CandidateTransport {
                            transport: Box::new(t),
                            kind: TransportPathKind::Relay,
                            mtls_verified: true,
                            peer_cert_fingerprint: fp,
                        }
                    })
                    .map_err(|e| format!("{e}"))
                } else if let Some(bundle) = peer_b {
                    let relay_mtls = bundle.to_relay_mtls_config(None);
                    TcpRelayTransport::connect_mtls_cancellable(
                        &relay_addr,
                        RelayRole::Client,
                        &relay_token,
                        Duration::from_secs(10),
                        disc_c,
                        &relay_mtls,
                    )
                    .map(|t| CandidateTransport {
                        transport: Box::new(t),
                        kind: TransportPathKind::Relay,
                        mtls_verified: false,
                        peer_cert_fingerprint: None,
                    })
                    .map_err(|e| format!("{e}"))
                } else {
                    TcpRelayTransport::connect_cancellable(
                        &relay_addr,
                        RelayRole::Client,
                        &relay_token,
                        Duration::from_secs(10),
                        disc_c,
                    )
                    .map(|t| CandidateTransport {
                        transport: Box::new(t),
                        kind: TransportPathKind::Relay,
                        mtls_verified: false,
                        peer_cert_fingerprint: None,
                    })
                    .map_err(|e| format!("{e}"))
                };
                let _ = dtx.send(res);
            });
    }

    fn spawn_runtime_p2p_reprobe_worker(&mut self, sw_h: &SwitchHandle, grant: &ConnectGrant) {
        self.runtime_switch_inflight = Some(2);
        let (rtx, rrx) = mpsc::channel();
        let (atx, arx) = mpsc::channel();
        self.reprobe_rx = Some(rrx);
        self.reprobe_answer_tx = Some(atx);
        let sw_clone = sw_h.clone();
        let initial_nat_type = grant.self_nat_type;
        let initial_nat_delta = grant.self_nat_port_delta;
        let initial_nat_range = grant.self_nat_port_range;
        let initial_local_port = grant.local_udp_port;
        let initial_self_pub = grant.self_public_addr.clone();
        let initial_peer_pubs = grant.peer_public_addrs.clone();
        let sc_opt = self.cfg.signal_client.clone();
        let encrypt_c = self.cfg.encrypt_connection;
        let q_mtls = if encrypt_c {
            prepare_peer_mtls_bundle(&self.cfg, grant).and_then(|b| b.to_quic_mtls_config().ok())
        } else {
            None
        };
        let disc_c = Arc::clone(&self.disconnect_flag);
        let _ = thread::Builder::new()
            .name("rc-runtime-p2p-reprobe".to_string())
            .spawn(move || {
                let sc_snap = sc_opt.as_ref().map(|sc| sc.snapshot_p2p_reprobe_info());
                let (sc_port, sc_addrs, sc_nat, sc_delta, sc_range) = match sc_snap {
                    Some((p, addrs, nat, d, r)) => (p, addrs, Some(nat), d, r),
                    None => (None, Vec::new(), None, None, None),
                };
                let local_port = sc_port
                    .or(initial_local_port)
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
                    let _ = rtx.send(Err("port 0".into()));
                    return;
                }
                let mut sec = [0u8; 16];
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut sec);
                let mut secret_hex = String::with_capacity(32);
                for b in sec {
                    use std::fmt::Write;
                    let _ = write!(&mut secret_hex, "{b:02x}");
                }
                let probe_id = format!("rp-{:08x}", rand::rngs::OsRng.next_u32());
                let mut self_addrs = sc_addrs;
                if let Some(ref pub_raw) = initial_self_pub {
                    if let Ok(sock) = pub_raw.trim().parse::<SocketAddr>() {
                        if sock.port() != 0 {
                            let s = sock.to_string();
                            if !self_addrs.contains(&s) {
                                self_addrs.push(s);
                            }
                        }
                    }
                }
                for lan in crate::bridge_shared::collect_host_lan_addrs(local_port) {
                    if !self_addrs.contains(&lan) {
                        self_addrs.push(lan);
                    }
                }
                let self_nat_type = sc_nat
                    .filter(|n| *n != crate::nat::NatType::Unknown)
                    .unwrap_or(initial_nat_type);
                let self_nat_delta = sc_delta.or(initial_nat_delta);
                let self_nat_range = sc_range.or(initial_nat_range);
                if sw_clone
                    .send_control_msg(&SwitchControlMsg::P2pReprobeOffer {
                        probe_id: probe_id.clone(),
                        local_udp_port: local_port,
                        addrs: self_addrs,
                        nat_type: self_nat_type,
                        nat_port_delta: self_nat_delta,
                        nat_port_range: self_nat_range,
                        punch_secret: secret_hex.clone(),
                    })
                    .is_err()
                {
                    let _ = rtx.send(Err("send offer fail".into()));
                    return;
                }
                let Ok(SwitchControlMsg::P2pReprobeAnswer {
                    local_udp_port: _,
                    addrs: peer_addrs,
                    nat_type: peer_nat,
                    nat_port_delta: peer_delta,
                    nat_port_range: peer_range,
                    ..
                }) = arx.recv_timeout(Duration::from_secs(5))
                else {
                    let _ = rtx.send(Err("answer timeout".into()));
                    return;
                };
                let (peer_public_addrs, peer_lan_addrs) =
                    crate::signal_client::split_public_and_lan_addrs(
                        &peer_addrs,
                        &initial_peer_pubs,
                    );
                let cands = P2pCandidates {
                    session_id: format!("reprobe-{probe_id}"),
                    peer_public_addr: peer_public_addrs.first().cloned(),
                    peer_public_addrs,
                    peer_lan_addrs,
                    local_udp_port: Some(local_port),
                    self_nat_type,
                    self_nat_port_delta: self_nat_delta,
                    self_nat_port_range: self_nat_range,
                    peer_nat_type: peer_nat,
                    peer_nat_port_delta: peer_delta,
                    peer_nat_port_range: peer_range,
                    punch_secret: Some(secret_hex),
                    start_after_ms: None,
                    relay_fallback_after_ms: None,
                };
                let port_hold =
                    crate::signal_client::acquire_local_udp_port_for_p2p(Some(local_port));
                match p2p::attempt_p2p_quic_client_mtls(
                    &cands,
                    p2p::DEFAULT_PUNCH_TIMEOUT,
                    p2p::DEFAULT_QUIC_HANDSHAKE_TIMEOUT,
                    &disc_c,
                    q_mtls.as_ref(),
                ) {
                    Ok(p2p_conn) => {
                        let fp = p2p_conn
                            .peer_mtls_identity()
                            .map(|i| i.cert_fingerprint_sha256);
                        let held = crate::signal_client::P2pHeldTransport::new(p2p_conn, port_hold);
                        let _ = rtx.send(Ok(CandidateTransport {
                            transport: Box::new(held),
                            kind: TransportPathKind::P2p,
                            mtls_verified: !encrypt_c || fp.is_some(),
                            peer_cert_fingerprint: fp,
                        }));
                    }
                    Err(e) => {
                        drop(port_hold);
                        let _ = rtx.send(Err(e));
                    }
                }
            });
    }
}
