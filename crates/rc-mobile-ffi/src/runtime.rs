//! 移动端运行时 FFI:认证会话管理 + 信令连接 + 一键设备连接。
//!
//! 分层:`auth.rs` 是无状态 HTTP 包装;本模块是有状态运行时——
//! 包装 core `AuthSessionManager`(令牌持久化/自动刷新/设备证书签发)
//! 与 `SignalClientHandle`(信令),把「输入 9 位设备码建立远控会话」
//! 的整条链(证书确保 → 信令请求 → 路由三阶 → mTLS/免密票据)
//! 压缩为一次 `rc_runtime_connect` 调用。
//!
//! 全部函数阻塞式,移动端必须在后台线程调用。

use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rc_client_core::auth_client::{AuthSessionManager, BindDeviceRequest};
use rc_client_core::cert_manager::CertManager;
use rc_client_core::relay_transport::SessionMtlsBundle;
use rc_client_core::server_config::ServerConfig;
use rc_client_core::session_bridge::{SessionHandle, UiSessionConfig};
use rc_client_core::signal_client::SignalClientHandle;
use serde::Deserialize;

use crate::{read_c_str, to_c_string};

struct Runtime {
    auth: AuthSessionManager,
    cert_manager: Arc<CertManager>,
    signal: Mutex<Option<Arc<SignalClientHandle>>>,
}

fn runtime() -> &'static Mutex<Option<Runtime>> {
    static RT: OnceLock<Mutex<Option<Runtime>>> = OnceLock::new();
    RT.get_or_init(|| Mutex::new(None))
}

fn lock_rt() -> std::sync::MutexGuard<'static, Option<Runtime>> {
    runtime().lock().unwrap_or_else(|e| e.into_inner())
}

fn err_json(e: impl std::fmt::Display) -> *mut c_char {
    to_c_string(serde_json::json!({ "error": e.to_string(), "kind": "other" }).to_string())
}

fn parse<'a, T: Deserialize<'a>>(ptr: *const c_char) -> Result<T, String> {
    let Some(s) = read_c_str(ptr) else {
        return Err("缺少 JSON 参数".to_string());
    };
    serde_json::from_str(s).map_err(|e| format!("JSON 参数解析失败: {e}"))
}

fn with_runtime(f: impl FnOnce(&Runtime) -> Result<serde_json::Value, String>) -> *mut c_char {
    let guard = lock_rt();
    let Some(rt) = guard.as_ref() else {
        return err_json("运行时尚未初始化,请先调用 rc_runtime_init");
    };
    match f(rt) {
        Ok(v) => to_c_string(v.to_string()),
        Err(e) => err_json(e),
    }
}

// ── 初始化 ──

#[derive(Deserialize)]
struct InitRequest {
    /// 服务端主机(IP 或域名)。
    server_host: String,
    #[serde(default)]
    use_https: bool,
    #[serde(default = "default_signal_port")]
    signal_port: u16,
    #[serde(default = "default_relay_port")]
    relay_port: u16,
    #[serde(default = "default_api_port")]
    api_port: u16,
    /// 数据目录(存放设备密钥/证书/会话持久化);iOS 传 App 容器内路径。
    data_dir: String,
    /// 服务端 CA PEM(HTTPS/mTLS 校验);可由 `rc_server_probe` 预取。
    #[serde(default)]
    ca_cert_pem: Option<String>,
    #[serde(default)]
    ca_fingerprint_sha256: Option<String>,
    #[serde(default)]
    server_auth_pubkey_hex: Option<String>,
}

fn default_signal_port() -> u16 {
    21116
}
fn default_relay_port() -> u16 {
    21117
}
fn default_api_port() -> u16 {
    21118
}

/// 初始化运行时(幂等:重复调用重建)。返回 `{"device_pubkey_hex": ...}`。
#[no_mangle]
pub extern "C" fn rc_runtime_init(json: *const c_char) -> *mut c_char {
    let result: Result<serde_json::Value, String> = (|| {
        let req: InitRequest = parse(json)?;
        let data_dir = PathBuf::from(&req.data_dir);
        let certs_dir = data_dir.join("certs");
        let auth_path = data_dir.join("auth_session.json");
        let cert_manager = Arc::new(
            CertManager::load_or_init(certs_dir).map_err(|e| format!("证书管理器初始化: {e}"))?,
        );
        let cfg = ServerConfig {
            enabled: true,
            server_host: req.server_host,
            signal_port: req.signal_port,
            relay_port: req.relay_port,
            api_port: req.api_port,
            use_https: req.use_https,
            ca_fingerprint_sha256: req.ca_fingerprint_sha256,
            ca_cert_pem: req.ca_cert_pem,
            server_auth_pubkey_hex: req.server_auth_pubkey_hex,
            ..ServerConfig::default()
        };
        let auth = AuthSessionManager::new(cfg, auth_path, Arc::clone(&cert_manager));
        // 启动时尝试从磁盘恢复会话
        let _ = auth.restore_on_startup();
        let pubkey = cert_manager.device_pubkey_hex();
        *lock_rt() = Some(Runtime {
            auth,
            cert_manager,
            signal: Mutex::new(None),
        });
        Ok(serde_json::json!({ "device_pubkey_hex": pubkey }))
    })();
    match result {
        Ok(v) => to_c_string(v.to_string()),
        Err(e) => err_json(e),
    }
}

// ── 登录 / 状态 / 登出 ──

#[derive(Deserialize)]
struct LoginReq {
    email: String,
    password: String,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    os: Option<String>,
}

fn session_json(rt: &Runtime) -> serde_json::Value {
    match rt.auth.current_session() {
        Some(s) => serde_json::json!({
            "logged_in": true,
            "user_id": s.user_id,
            "email": s.email,
            "display_name": s.display_name,
            "must_change_password": s.must_change_password,
        }),
        None => serde_json::json!({ "logged_in": false }),
    }
}

/// 登录(自动绑定本机设备)。输入 `{email, password, hostname?, os?}`。
#[no_mangle]
pub extern "C" fn rc_runtime_login(json: *const c_char) -> *mut c_char {
    let req: LoginReq = match parse(json) {
        Ok(r) => r,
        Err(e) => return err_json(e),
    };
    with_runtime(|rt| {
        rt.auth
            .login(
                &req.email,
                &req.password,
                req.hostname.as_deref(),
                req.os.as_deref(),
            )
            .map_err(|e| e.to_string())?;
        Ok(session_json(rt))
    })
}

/// 当前会话状态:`{logged_in, user_id?, email?, ...}`。
#[no_mangle]
pub extern "C" fn rc_runtime_status() -> *mut c_char {
    with_runtime(|rt| Ok(session_json(rt)))
}

/// 登出并清除本地凭据。
#[no_mangle]
pub extern "C" fn rc_runtime_logout() -> *mut c_char {
    with_runtime(|rt| {
        rt.auth.logout(None).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ok": true }))
    })
}

// ── 信令 ──

/// 启动信令连接:绑定/确认本机设备 → 确保设备证书 → 拉起信令客户端。
/// 输入 `{}`;返回 `{"device_id": "...", "cert_ready": bool}`。
#[no_mangle]
pub extern "C" fn rc_signal_start(json: *const c_char) -> *mut c_char {
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        hostname: Option<String>,
        #[serde(default)]
        os: Option<String>,
        #[serde(default)]
        lan_addrs: Option<Vec<String>>,
    }
    let req: Req = parse(json).unwrap_or(Req {
        hostname: None,
        os: None,
        lan_addrs: None,
    });
    with_runtime(|rt| {
        let token = rt
            .auth
            .ensure_valid_access_token()
            .map_err(|e| format!("登录状态: {e}"))?;
        let cfg = rt.auth.server_config();
        let client = rc_client_core::auth_client::AuthHttpClient::from_server_config(&cfg)
            .map_err(|e| e.to_string())?;
        // 绑定(幂等):同 device_key 重绑返回同一设备
        let bound = client
            .bind_device(
                &token,
                &BindDeviceRequest {
                    device_key: cfg.device_key.clone(),
                    hostname: req.hostname.clone(),
                    os: req.os.clone(),
                    alias: None,
                    device_pubkey: Some(rt.cert_manager.device_pubkey_hex()),
                    allow_remote_assist: None,
                },
            )
            .map_err(|e| format!("设备绑定: {e}"))?;
        let cert_ready = rt
            .auth
            .ensure_device_cert(&bound.device_id)
            .map_err(|e| format!("设备证书: {e}"))?;
        // 拉起信令(已运行则先停)
        {
            let mut slot = rt.signal.lock().unwrap_or_else(|e| e.into_inner());
            drop(slot.take());
            let hostname = req
                .hostname
                .clone()
                .unwrap_or_else(|| "ios-device".to_string());
            let handle = SignalClientHandle::spawn(
                cfg.clone(),
                hostname,
                req.lan_addrs.clone().unwrap_or_default(),
            );
            *slot = Some(Arc::new(handle));
        }
        Ok(serde_json::json!({
            "device_id": bound.device_id,
            "formatted_id": bound.formatted_id,
            "cert_ready": cert_ready,
        }))
    })
}

/// 停止信令连接。
#[no_mangle]
pub extern "C" fn rc_signal_stop() -> *mut c_char {
    with_runtime(|rt| {
        let mut slot = rt.signal.lock().unwrap_or_else(|e| e.into_inner());
        drop(slot.take());
        Ok(serde_json::json!({ "ok": true }))
    })
}

// ── 一键连接设备 ──

#[derive(Deserialize)]
struct ConnectReq {
    /// 目标 9 位设备码(允许带空格格式化)。
    target_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    watch_only: bool,
    #[serde(default = "default_width")]
    width: u32,
    #[serde(default = "default_height")]
    height: u32,
    #[serde(default = "default_fps")]
    fps: u32,
    #[serde(default = "default_bitrate")]
    bitrate_bps: u32,
    /// LAN 直连地址(调用方从局域网发现匹配得到,可选加速)。
    #[serde(default)]
    lan_direct_addr: Option<std::net::SocketAddr>,
    #[serde(default = "default_timeout")]
    timeout_sec: u64,
}

fn default_width() -> u32 {
    1920
}
fn default_height() -> u32 {
    1080
}
fn default_fps() -> u32 {
    30
}
fn default_bitrate() -> u32 {
    8_000_000
}
fn default_timeout() -> u64 {
    15
}

/// 一键连接设备:信令 request_connect → 组装路由/mTLS/免密票据 → 开会话。
/// 阻塞至拿到连接授权(默认 15s 超时)。返回 `{"session_id": N, "owner_connection": bool}`。
#[no_mangle]
pub extern "C" fn rc_runtime_connect(json: *const c_char) -> *mut c_char {
    let req: ConnectReq = match parse(json) {
        Ok(r) => r,
        Err(e) => return err_json(e),
    };
    let result: Result<(u64, bool), String> = (|| {
        let guard = lock_rt();
        let rt = guard.as_ref().ok_or("运行时未初始化")?;
        let signal = {
            let slot = rt.signal.lock().unwrap_or_else(|e| e.into_inner());
            slot.as_ref()
                .map(Arc::clone)
                .ok_or("信令未启动,请先 rc_signal_start")?
        };
        let grant = signal
            .request_connect(&req.target_id, Duration::from_secs(req.timeout_sec))
            .map_err(|e| format!("连接请求: {e}"))?;

        // mTLS 证书束(加密连接;无本地证书时降级为不加密)
        let mtls = build_mtls_bundle(rt, &grant.target_id);
        let encrypt = mtls.is_some();

        // 同账号免密票据签名器
        let owner_signer = grant.owner_grant.as_ref().and_then(|g| {
            rt.cert_manager
                .create_owner_ticket_signer(g.clone())
                .ok()
                .map(|s| Arc::new(s) as Arc<dyn rc_session::auth::OwnerTicketSigner>)
        });
        let is_owner = grant.is_owner_connection;

        let cfg = UiSessionConfig {
            connect_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 9901)), // grant 存在时被忽略
            password: req.password,
            watch_only: req.watch_only,
            width: req.width,
            height: req.height,
            fps: req.fps,
            bitrate_bps: req.bitrate_bps,
            prefer_hardware: true,
            clipboard_enabled: false,
            audio_enabled: false,
            relay_grant: Some(grant),
            encrypt_connection: encrypt,
            mtls_config: mtls,
            owner_signer,
            lan_direct_addr: req.lan_direct_addr,
            ..UiSessionConfig::default()
        };
        let handle = SessionHandle::spawn(cfg);
        let id = crate::session::register_session(handle);
        Ok((id, is_owner))
    })();
    match result {
        Ok((id, owner)) => to_c_string(
            serde_json::json!({ "session_id": id, "owner_connection": owner }).to_string(),
        ),
        Err(e) => err_json(e),
    }
}

/// 按桌面端同构逻辑组装 mTLS 证书束;任一前置缺失返回 None(降级不加密)。
fn build_mtls_bundle(rt: &Runtime, peer_device_id: &str) -> Option<SessionMtlsBundle> {
    let cfg = rt.auth.server_config();
    let ca_cert_pem = cfg.ca_cert_pem.clone()?;
    let sess = rt.auth.current_session()?;
    let (cert_pem, meta) = rt.cert_manager.load_device_cert()?;
    if !meta.user_id.eq_ignore_ascii_case(sess.user_id.trim()) {
        return None;
    }
    let key_pem = rt.cert_manager.tls_key_pem().ok()?;
    Some(SessionMtlsBundle {
        ca_cert_pem,
        cert_pem,
        key_pem,
        local_user_id: meta.user_id,
        expected_peer_device_id: Some(peer_device_id.to_string()),
        expected_peer_user_id: None,
    })
}
