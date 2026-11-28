use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rc_session::auth::{ConnectionApprover, OwnerTicketVerifier};
use rc_session::proto::ByeReason;
use rc_session::AutoApprover;

use crate::relay_transport::SessionMtlsBundle;
use crate::signal_client::{ActiveControllerSummary, RelayIncoming};

use super::approver::UiApprover;
use super::pipeline_factory::{
    bind_mtls_lan_endpoint, build_host_session, collect_host_lan_addrs, HostListener,
};
use super::queues::{clear_active_controllers, BoundedHostUpdateQueue, BoundedRelayIncomingQueue};
use super::types::{
    ActiveControllerSession, ActiveRelayInterrupt, AuthRuntimeState, HostCommand, HostUpdate,
    HostWorkerOptions, PasswordState, SharedActiveControllers, SharedFileTransferDir,
    SharedSignalClient, UiHostConfig, DEFAULT_HOST_PORT, HOST_UPDATE_CHANNEL_CAP,
    RELAY_INCOMING_QUEUE_CAP,
};
use super::worker::run_host_worker;

/// UI 侧被控端服务句柄：管理单会话循环工作线程、审批桥与优雅停机。
pub struct HostHandle {
    listen_addr: Arc<Mutex<SocketAddr>>,
    updates: Arc<BoundedHostUpdateQueue>,
    pub(super) approver: UiApprover,
    password_state: Arc<Mutex<PasswordState>>,
    password_version: Arc<AtomicU64>,
    pub(super) auth_state: Arc<Mutex<AuthRuntimeState>>,
    config_version: Arc<AtomicU64>,
    relay_incoming: Arc<BoundedRelayIncomingQueue>,
    active_relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>>,
    active_controllers: SharedActiveControllers,
    disconnect_flag: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    close_reason: Arc<AtomicU8>,
    running: Arc<AtomicBool>,
    lock_screen_count: Arc<AtomicU64>,
    pub(super) file_transfer_dir: SharedFileTransferDir,
    allow_assist_file_transfer: Arc<AtomicBool>,
    pub(super) signal_client: SharedSignalClient,
    thread: Option<JoinHandle<()>>,
}

fn bind_initial_listener(
    cfg: &UiHostConfig,
    shared_owner_replay: &Arc<Mutex<rc_session::OwnerReplayCache>>,
    approver: &UiApprover,
    updates: &Arc<BoundedHostUpdateQueue>,
) -> Result<(HostListener, SocketAddr), String> {
    let make_approver = |require: bool, ui: &UiApprover| -> Box<dyn ConnectionApprover> {
        if require {
            Box::new(ui.clone())
        } else {
            Box::new(AutoApprover)
        }
    };

    // 先在 spawn 内绑定首轮监听器（普通 QUIC HostSession 或 mTLS LAN QuicEndpoint），使 listen_addr() 同步立即可用。
    // 在系统后台服务切换会话（LoginWindow → Aqua）时，短轮询退避等待旧 Agent 释放 9901 端口，避免落入临时随机端口。
    let service_bind_retries = if cfg.listen_addr.port() == DEFAULT_HOST_PORT
        && crate::config_paths::is_service_managed()
    {
        8
    } else {
        0
    };
    if cfg.accept_mtls_lan {
        match cfg.mtls_config.as_ref() {
            Some(bundle) => {
                let mut ep_res = bind_mtls_lan_endpoint(cfg.listen_addr, bundle);
                for _ in 0..service_bind_retries {
                    if ep_res.is_ok() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(80));
                    ep_res = bind_mtls_lan_endpoint(cfg.listen_addr, bundle);
                }
                let ep = match ep_res {
                    Ok(ep) => ep,
                    Err(_) if cfg.listen_addr.port() == DEFAULT_HOST_PORT => {
                        let fallback_addr = SocketAddr::new(cfg.listen_addr.ip(), 0);
                        bind_mtls_lan_endpoint(fallback_addr, bundle)?
                    }
                    Err(e) => return Err(e),
                };
                let actual = ep
                    .local_addr()
                    .map_err(|e| format!("无法获取 mTLS LAN 实际监听地址: {e}"))?;
                Ok((HostListener::MtlsLan { endpoint: ep }, actual))
            }
            None => {
                let resolved_addr = if cfg.listen_addr.port() == 0 {
                    std::net::UdpSocket::bind(cfg.listen_addr)
                        .and_then(|s| s.local_addr())
                        .unwrap_or(cfg.listen_addr)
                } else {
                    cfg.listen_addr
                };
                Ok((HostListener::AwaitingMtlsCert, resolved_addr))
            }
        }
    } else {
        let initial_allow_remote = cfg.allow_owner_control
            && cfg.allow_remote_assist
            && (!cfg.forbid_passwordless_auto_approve
                || cfg.require_approval
                || cfg.password.is_some());
        let mut built_res = build_host_session(
            cfg.listen_addr,
            cfg.password.clone(),
            cfg.approval_timeout_us,
            cfg.prefer_hardware,
            cfg.clipboard_enabled,
            cfg.allow_owner_control,
            initial_allow_remote,
            cfg.owner_verifier.clone(),
            Arc::clone(shared_owner_replay),
            make_approver(cfg.require_approval, approver),
            Arc::clone(updates),
        );
        for _ in 0..service_bind_retries {
            if built_res.is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(80));
            built_res = build_host_session(
                cfg.listen_addr,
                cfg.password.clone(),
                cfg.approval_timeout_us,
                cfg.prefer_hardware,
                cfg.clipboard_enabled,
                cfg.allow_owner_control,
                initial_allow_remote,
                cfg.owner_verifier.clone(),
                Arc::clone(shared_owner_replay),
                make_approver(cfg.require_approval, approver),
                Arc::clone(updates),
            );
        }
        let first_built = match built_res {
            Ok(built) => built,
            Err(_) if cfg.listen_addr.port() == DEFAULT_HOST_PORT => {
                let fallback_addr = SocketAddr::new(cfg.listen_addr.ip(), 0);
                build_host_session(
                    fallback_addr,
                    cfg.password.clone(),
                    cfg.approval_timeout_us,
                    cfg.prefer_hardware,
                    cfg.clipboard_enabled,
                    cfg.allow_owner_control,
                    initial_allow_remote,
                    cfg.owner_verifier.clone(),
                    Arc::clone(shared_owner_replay),
                    make_approver(cfg.require_approval, approver),
                    Arc::clone(updates),
                )?
            }
            Err(e) => return Err(e),
        };
        let actual = first_built
            .host
            .local_addr()
            .map_err(|e| format!("无法获取实际监听地址: {e}"))?;
        Ok((HostListener::Plain(Box::new(first_built)), actual))
    }
}

impl HostHandle {
    /// 启动被控端服务：先同步绑定 QUIC 监听端口（默认 `9901` 冲突时自动回退临时端口），
    /// 随后派发后台单会话循环线程。
    pub fn spawn(cfg: UiHostConfig) -> Result<Self, String> {
        let updates = Arc::new(BoundedHostUpdateQueue::new(HOST_UPDATE_CHANNEL_CAP));
        let approver = UiApprover::new(
            Arc::clone(&updates),
            cfg.auto_accept_with_password,
            cfg.allow_owner_control && cfg.allow_remote_assist,
        );
        let password_state = Arc::new(Mutex::new(PasswordState {
            password: cfg.password.clone(),
            auto_rotate: cfg.auto_rotate_password,
        }));
        let password_version = Arc::new(AtomicU64::new(0));
        let shared_owner_replay = Arc::new(Mutex::new(rc_session::OwnerReplayCache::new()));
        let auth_state = Arc::new(Mutex::new(AuthRuntimeState {
            allow_owner_control: cfg.allow_owner_control,
            allow_remote_assist: cfg.allow_remote_assist,
            owner_verifier: cfg.owner_verifier.clone(),
            owner_replay_cache: Arc::clone(&shared_owner_replay),
            mtls_config: cfg.mtls_config.clone(),
            accept_mtls_lan: cfg.accept_mtls_lan,
        }));
        let config_version = Arc::new(AtomicU64::new(0));
        let relay_incoming = Arc::new(BoundedRelayIncomingQueue::new(RELAY_INCOMING_QUEUE_CAP));
        let active_relay_interrupt: Arc<Mutex<Option<ActiveRelayInterrupt>>> =
            Arc::new(Mutex::new(None));
        let active_controllers: SharedActiveControllers = Arc::new(Mutex::new(Vec::new()));
        let disconnect_flag = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let close_reason = Arc::new(AtomicU8::new(ByeReason::Normal as u8));
        let running = Arc::new(AtomicBool::new(true));
        let lock_screen_count = Arc::new(AtomicU64::new(0));
        let file_transfer_dir: SharedFileTransferDir =
            Arc::new(RwLock::new(cfg.file_transfer_dir.clone()));
        let allow_assist_file_transfer = Arc::new(AtomicBool::new(cfg.allow_assist_file_transfer));

        let (first_listener, actual_addr) =
            bind_initial_listener(&cfg, &shared_owner_replay, &approver, &updates)?;

        let shared_signal_client: SharedSignalClient =
            Arc::new(RwLock::new(cfg.signal_client.clone()));
        let worker_opts = HostWorkerOptions {
            approval_timeout_us: cfg.approval_timeout_us,
            prefer_hardware: cfg.prefer_hardware,
            require_approval: cfg.require_approval,
            clipboard_enabled: cfg.clipboard_enabled,
            audio_enabled: cfg.audio_enabled,
            forbid_passwordless_auto_approve: cfg.forbid_passwordless_auto_approve,
            ephemeral_listen_port: cfg.listen_addr.port() == 0,
            allow_assist_file_transfer: Arc::clone(&allow_assist_file_transfer),
            signal_client: Arc::clone(&shared_signal_client),
        };

        let t_updates = Arc::clone(&updates);
        let t_approver = approver.clone();
        let t_password_state = Arc::clone(&password_state);
        let t_pw_ver = Arc::clone(&password_version);
        let t_auth_state = Arc::clone(&auth_state);
        let t_cfg_ver = Arc::clone(&config_version);
        let t_relay_incoming = Arc::clone(&relay_incoming);
        let t_active_relay_interrupt = Arc::clone(&active_relay_interrupt);
        let t_active_controllers = Arc::clone(&active_controllers);
        let t_disconnect = Arc::clone(&disconnect_flag);
        let t_stop = Arc::clone(&stop_flag);
        let t_close_reason = Arc::clone(&close_reason);
        let t_running = Arc::clone(&running);
        let t_lock_screen_count = Arc::clone(&lock_screen_count);
        let t_file_transfer_dir = Arc::clone(&file_transfer_dir);
        let t_signal_client = Arc::clone(&shared_signal_client);

        let listen_addr_shared = Arc::new(Mutex::new(actual_addr));
        let t_listen_addr = Arc::clone(&listen_addr_shared);

        let handle = thread::Builder::new()
            .name("rc-ui-host".to_string())
            .spawn(move || {
                crate::platform::promote_current_thread_qos();

                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_host_worker(
                        actual_addr,
                        t_listen_addr,
                        worker_opts,
                        first_listener,
                        Arc::clone(&t_updates),
                        t_approver,
                        t_password_state,
                        t_pw_ver,
                        t_auth_state,
                        t_cfg_ver,
                        t_relay_incoming,
                        t_active_relay_interrupt,
                        Arc::clone(&t_active_controllers),
                        t_disconnect,
                        t_stop,
                        t_close_reason,
                        t_lock_screen_count,
                        t_file_transfer_dir,
                    )
                }));
                if res.is_err() {
                    t_updates.push(HostUpdate::error("被控端工作线程异常退出"));
                }
                clear_active_controllers(&t_active_controllers, &t_updates, Some(&t_signal_client));
                // M8：先清除 running 标记再推送 Stopped，消除轮询器读到 Stopped 时 is_running 仍为 true 的竞态。
                t_running.store(false, Ordering::Release);
                t_updates.push(HostUpdate::Stopped);
            })
            .expect("spawn rc-ui-host thread");

        Ok(Self {
            listen_addr: listen_addr_shared,
            updates,
            approver,
            password_state,
            password_version,
            auth_state,
            config_version,
            relay_incoming,
            active_relay_interrupt,
            active_controllers,
            disconnect_flag,
            stop_flag,
            close_reason,
            running,
            lock_screen_count,
            file_transfer_dir,
            allow_assist_file_transfer,
            signal_client: shared_signal_client,
            thread: Some(handle),
        })
    }

    /// 统计本 Host 实例收到并执行的远端锁屏请求次数（供集成测试与诊断验证）。
    pub fn lock_screen_count(&self) -> u64 {
        self.lock_screen_count.load(Ordering::Acquire)
    }

    /// 返回实际绑定的监听地址（已解析临时端口，并在端口回退后实时更新）。
    pub fn listen_addr(&self) -> SocketAddr {
        *self.listen_addr.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 收集当前被控端全网卡直连候选列表（多网卡/VPN IPv4 + 全球单播 IPv6，去重上限 16 条）。
    pub fn local_lan_addrs(&self) -> Vec<String> {
        collect_host_lan_addrs(self.listen_addr().port())
    }

    /// 工作线程是否仍在运行。
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// 非阻塞拉取一条被控端状态更新。
    pub fn try_recv_update(&self) -> Option<HostUpdate> {
        self.updates.try_pop()
    }

    /// 向被控端工作线程投递一条信令服务器下发的入站中继会话请求（有界非阻塞，容量 8，满载丢最旧）。
    pub fn offer_relay_incoming(&self, incoming: RelayIncoming) {
        self.relay_incoming.push(incoming);
    }

    /// 回写机主连接审批裁决（仅在途且代次匹配时生效）。
    pub fn respond_approval(&self, generation: u64, accepted: bool) -> bool {
        self.approver.resolve(generation, accepted)
    }

    /// 更新访问密码与会话结束自动轮换策略（对下一次新握手生效）。
    pub fn set_password_mode(&self, password: Option<String>, auto_rotate: bool) {
        {
            let mut st = self
                .password_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            st.password = password;
            st.auto_rotate = auto_rotate;
        }
        self.password_version.fetch_add(1, Ordering::AcqRel);
    }

    /// 更新访问密码（保留既有自动轮换策略，对下一次新握手生效）。
    pub fn set_password(&self, password: Option<String>) {
        {
            let mut st = self
                .password_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            st.password = password;
        }
        self.password_version.fetch_add(1, Ordering::AcqRel);
    }

    /// 运行时切换是否允许本机被远程控制（含同账号本人自控与他人远程协助总门控；对下一次新握手生效，关闭时同步拒收在途审批）。
    pub fn set_allow_owner_control(&self, allow: bool) {
        let effective_assist = {
            let mut st = self.auth_state.lock().unwrap_or_else(|e| e.into_inner());
            st.allow_owner_control = allow;
            st.allow_owner_control && st.allow_remote_assist
        };
        self.approver.set_remote_assist_enabled(effective_assist);
        self.config_version.fetch_add(1, Ordering::AcqRel);
        if !allow {
            self.approver.reject_in_flight();
        }
    }

    /// 运行时切换是否允许他人远程协助（对下一次新握手生效，关闭时同步拒收在途审批，本人同账号自控不受影响）。
    pub fn set_allow_remote_assist(&self, allow: bool) {
        let effective_assist = {
            let mut st = self.auth_state.lock().unwrap_or_else(|e| e.into_inner());
            st.allow_remote_assist = allow;
            st.allow_owner_control && st.allow_remote_assist
        };
        self.approver.set_remote_assist_enabled(effective_assist);
        self.config_version.fetch_add(1, Ordering::AcqRel);
        if !effective_assist {
            self.approver.reject_in_flight();
        }
    }

    /// 运行时注入或清除同账号 `OwnerTicket` 验签器（对下一次新握手生效，切换账号或置 `None` 时立即吊销旧账号的后台终端）。
    pub fn set_owner_verifier(&self, verifier: Option<Arc<dyn OwnerTicketVerifier>>) {
        {
            let mut st = self.auth_state.lock().unwrap_or_else(|e| e.into_inner());
            st.owner_verifier = verifier;
        }
        self.config_version.fetch_add(1, Ordering::AcqRel);
    }

    /// 运行时更新双向 mTLS 证书束与 LAN mTLS 监听开关（对下一次监听与入站会话生效）。
    pub fn set_mtls_config(&self, mtls_config: Option<SessionMtlsBundle>, accept_mtls_lan: bool) {
        {
            let mut st = self.auth_state.lock().unwrap_or_else(|e| e.into_inner());
            st.mtls_config = mtls_config;
            st.accept_mtls_lan = accept_mtls_lan;
        }
        self.config_version.fetch_add(1, Ordering::AcqRel);
    }

    /// 动态更新被控端 W2 文件传输默认接收目录（对当前及后续会话实时生效）。
    pub fn set_file_transfer_dir(&self, dir: Option<PathBuf>) {
        let mut guard = self
            .file_transfer_dir
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = dir;
    }

    /// 运行期动态更新或清除信令客户端句柄（使后启动或重连后的 `SignalClientHandle`
    /// 实时同步至 `P2pReprobe` 与 P2P 协调逻辑）。
    pub fn set_signal_client(
        &self,
        signal_client: Option<Arc<crate::signal_client::SignalClientHandle>>,
    ) {
        let sync_handle = signal_client.clone();
        {
            let mut guard = self
                .signal_client
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *guard = signal_client;
        }
        if let Some(sig) = sync_handle {
            let summaries: Vec<ActiveControllerSummary> = self
                .active_controllers()
                .iter()
                .map(ActiveControllerSummary::from)
                .collect();
            let _ = sig.report_control_state(summaries);
        }
    }

    /// 运行期热更新「他人远程协助时是否允许文件传输」（即时对当前活跃非 Owner 会话及后续会话生效，不中断会话）。
    ///
    /// 同账号本人通过 Ed25519 PoP `OwnerTicket` 建立的自控会话始终豁免保持全开。
    pub fn set_allow_assist_file_transfer(&self, allowed: bool) {
        self.allow_assist_file_transfer
            .store(allowed, Ordering::Release);
    }

    /// 查询当前「他人远程协助时是否允许文件传输」配置开关。
    pub fn allow_assist_file_transfer(&self) -> bool {
        self.allow_assist_file_transfer.load(Ordering::Acquire)
    }

    /// 查询当前正在接入本机的活跃控制端会话快照列表。
    pub fn active_controllers(&self) -> Vec<ActiveControllerSession> {
        self.active_controllers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 发送被控端控制命令（幂等）。
    pub fn send(&self, cmd: HostCommand) {
        match cmd {
            HostCommand::DisconnectController { session_id } => {
                let _ = self.disconnect_controller(session_id);
            }
        }
    }

    /// 主动断开指定或当前全部活跃控制端远控连接。
    ///
    /// - `None`：断开当前所有（活跃）远控连接；
    /// - `Some(sid)`：仅当与当前活跃控制端会话 `session_id` 匹配时断开。
    ///
    /// 返回 `true` 表示命中并已触发断开，`false` 表示无活跃连接或 `session_id` 不匹配。
    pub fn disconnect_controller(&self, session_id: Option<String>) -> bool {
        let should_disconnect = {
            let guard = self
                .active_controllers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match session_id.as_deref() {
                None => {
                    !guard.is_empty()
                        || self
                            .active_relay_interrupt
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .is_some()
                }
                Some(target) => guard.iter().any(|c| c.session_id == target),
            }
        };
        if should_disconnect {
            self.disconnect_client();
        }
        should_disconnect
    }

    /// 主动断开当前已连接的控制端会话（触发优雅 `Bye` / 中继即时断流，被控端继续等待新连接）。
    pub fn disconnect_client(&self) {
        self.disconnect_flag.store(true, Ordering::Release);
        let interrupt = self
            .active_relay_interrupt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(h) = interrupt {
            h.interrupt();
        }
    }

    /// 停止被控端服务并指定向在途控制端发送的 `ByeReason`（供 LoginWindow→Aqua 切换通知自动重连）。
    pub fn stop_with_reason(&mut self, reason: ByeReason) {
        self.close_reason.store(reason as u8, Ordering::Release);
        self.stop();
    }

    /// 停止被控端服务并等待工作线程回收（幂等；常规停机可立即中断在途中继拨号与会话）。
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Release);
        self.disconnect_flag.store(true, Ordering::Release);
        self.approver.mark_stopped();
        let preserve_connected_for_bye =
            self.close_reason.load(Ordering::Acquire) != ByeReason::Normal as u8;
        let interrupt = self
            .active_relay_interrupt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(h) = interrupt {
            match h {
                ActiveRelayInterrupt::Dialing(_) => h.interrupt(),
                ActiveRelayInterrupt::Connected(_) if !preserve_connected_for_bye => h.interrupt(),
                // 会话切换时先保留已建立的中继 TCP 流，`stop_flag` 会在 <=2ms 内驱动工作线程优雅发出 `Bye(SessionSwitching)`。
                ActiveRelayInterrupt::Connected(_) => {}
            }
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        self.stop();
    }
}
