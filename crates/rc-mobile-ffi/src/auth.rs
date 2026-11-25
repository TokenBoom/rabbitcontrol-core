//! 认证与账号设备 FFI:探测、注册、登录、刷新、设备列表。
//!
//! 全部函数阻塞式(core 认证客户端本身是同步 HTTP),
//! 移动端必须在后台线程调用,禁止在主线程直接调用。

use std::os::raw::c_char;

use rc_client_core::auth_client::{AuthClientError, AuthHttpClient, LoginRequest, RegisterRequest};
use serde::Deserialize;

use crate::{read_c_str, to_c_string};

/// FFI 输入:服务器连接参数(内嵌于每个请求)。
#[derive(Debug, Deserialize)]
struct ServerParams {
    server_host: String,
    #[serde(default = "default_api_port")]
    api_port: u16,
    #[serde(default)]
    use_https: bool,
    #[serde(default)]
    ca_cert_pem: Option<String>,
}

fn default_api_port() -> u16 {
    21118
}

/// `rc_auth_login` / `rc_auth_register` 输入。
#[derive(Debug, Deserialize)]
struct AuthRequest {
    #[serde(flatten)]
    server: ServerParams,
    email: String,
    password: String,
    #[serde(default)]
    device_key: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    device_pubkey: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
}

/// `rc_auth_list_devices` / `rc_auth_refresh` 输入。
#[derive(Debug, Deserialize)]
struct TokenRequest {
    #[serde(flatten)]
    server: ServerParams,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

fn parse_json<'a, T: Deserialize<'a>>(ptr: *const c_char) -> Result<T, String> {
    let Some(s) = read_c_str(ptr) else {
        return Err("缺少 JSON 参数".to_string());
    };
    serde_json::from_str(s).map_err(|e| format!("JSON 参数解析失败: {e}"))
}

fn error_json(err: &AuthClientError) -> String {
    let kind = if err.is_unauthorized() {
        "unauthorized"
    } else if err.is_token_reuse() {
        "token_reuse"
    } else if err.is_password_change_required() {
        "password_change_required"
    } else if err.is_registration_disabled() {
        "registration_disabled"
    } else {
        "other"
    };
    serde_json::json!({ "error": err.to_string(), "kind": kind }).to_string()
}

fn client(server: &ServerParams) -> Result<AuthHttpClient, String> {
    AuthHttpClient::new(
        server.server_host.clone(),
        server.api_port,
        server.use_https,
        server.ca_cert_pem.clone(),
    )
    .map_err(|e| e.to_string())
}

fn respond<T: serde::Serialize>(result: Result<T, AuthClientError>) -> *mut c_char {
    match result {
        Ok(v) => to_c_string(serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string())),
        Err(e) => to_c_string(error_json(&e)),
    }
}

/// 探测服务器:拉取 CA/health/注册开关,执行 TOFU 校验。
/// 输入 JSON:`{server_host, api_port?, use_https?, ca_cert_pem?, expected_ca_fingerprint_sha256?}`
#[no_mangle]
pub extern "C" fn rc_server_probe(json: *const c_char) -> *mut c_char {
    #[derive(Deserialize)]
    struct ProbeRequest {
        #[serde(flatten)]
        server: ServerParams,
        #[serde(default)]
        expected_ca_fingerprint_sha256: Option<String>,
    }
    let result: Result<Result<_, AuthClientError>, String> = parse_json::<ProbeRequest>(json)
        .map(|req| {
            client(&req.server)
                .map(|c| c.probe_server(req.expected_ca_fingerprint_sha256.as_deref()))
        })
        .and_then(|r| r);
    match result {
        Ok(Ok(r)) => {
            let out = serde_json::json!({
                "health": r.health,
                "ca_bundle": r.ca_bundle,
                "allow_registration": r.allow_registration,
                "tls_leaf_fingerprint_sha256": r.tls_leaf_fingerprint_sha256,
                "latency_ms": r.latency_ms,
            });
            to_c_string(out.to_string())
        }
        Ok(Err(e)) => to_c_string(error_json(&e)),
        Err(e) => to_c_string(serde_json::json!({ "error": e, "kind": "other" }).to_string()),
    }
}

/// 邮箱密码登录。输入见 `AuthRequest`;成功返回 `AuthTokenResponse` JSON。
#[no_mangle]
pub extern "C" fn rc_auth_login(json: *const c_char) -> *mut c_char {
    let result = parse_json::<AuthRequest>(json).and_then(|req| {
        client(&req.server).map(|c| {
            c.login(&LoginRequest {
                email: req.email,
                password: req.password,
                device_key: req.device_key,
                hostname: req.hostname,
                os: req.os,
                device_pubkey: req.device_pubkey,
            })
        })
    });
    match result {
        Ok(r) => respond(r),
        Err(e) => to_c_string(serde_json::json!({ "error": e, "kind": "other" }).to_string()),
    }
}

/// 邮箱注册。输入同 `rc_auth_login`,另含可选 `display_name`。
#[no_mangle]
pub extern "C" fn rc_auth_register(json: *const c_char) -> *mut c_char {
    let result = parse_json::<AuthRequest>(json).and_then(|req| {
        client(&req.server).map(|c| {
            c.register(&RegisterRequest {
                email: req.email,
                password: req.password,
                display_name: req.display_name,
                device_key: req.device_key,
                hostname: req.hostname,
                os: req.os,
                device_pubkey: req.device_pubkey,
            })
        })
    });
    match result {
        Ok(r) => respond(r),
        Err(e) => to_c_string(serde_json::json!({ "error": e, "kind": "other" }).to_string()),
    }
}

/// 原子轮换 Refresh Token。输入:`{server..., refresh_token}`。
#[no_mangle]
pub extern "C" fn rc_auth_refresh(json: *const c_char) -> *mut c_char {
    let result = parse_json::<TokenRequest>(json).and_then(|req| {
        let token = req
            .refresh_token
            .ok_or_else(|| "缺少 refresh_token".to_string())?;
        client(&req.server).map(|c| c.refresh(&token))
    });
    match result {
        Ok(r) => respond(r),
        Err(e) => to_c_string(serde_json::json!({ "error": e, "kind": "other" }).to_string()),
    }
}

/// 列出当前账号设备。输入:`{server..., access_token}`;成功返回 `MyDeviceInfo` 数组。
#[no_mangle]
pub extern "C" fn rc_auth_list_devices(json: *const c_char) -> *mut c_char {
    let result = parse_json::<TokenRequest>(json).and_then(|req| {
        let token = req
            .access_token
            .ok_or_else(|| "缺少 access_token".to_string())?;
        client(&req.server).map(|c| c.list_my_devices(&token))
    });
    match result {
        Ok(r) => respond(r),
        Err(e) => to_c_string(serde_json::json!({ "error": e, "kind": "other" }).to_string()),
    }
}

/// 修改密码。输入:`{server..., access_token, current_password, new_password}`;
/// 成功返回新的 `AuthTokenResponse`(服务端会吊销旧令牌)。
#[no_mangle]
pub extern "C" fn rc_auth_change_password(json: *const c_char) -> *mut c_char {
    #[derive(Deserialize)]
    struct Req {
        #[serde(flatten)]
        server: ServerParams,
        access_token: String,
        current_password: String,
        new_password: String,
    }
    let result = parse_json::<Req>(json).and_then(|req| {
        client(&req.server)
            .map(|c| c.change_password(&req.access_token, &req.current_password, &req.new_password))
    });
    match result {
        Ok(r) => respond(r),
        Err(e) => to_c_string(serde_json::json!({ "error": e, "kind": "other" }).to_string()),
    }
}

/// 设备重命名(设置别名)。输入:`{server..., access_token, device_id, alias}`。
#[no_mangle]
pub extern "C" fn rc_auth_rename_device(json: *const c_char) -> *mut c_char {
    device_op(json, false)
}

/// 设备解绑删除。输入:`{server..., access_token, device_id}`。
#[no_mangle]
pub extern "C" fn rc_auth_remove_device(json: *const c_char) -> *mut c_char {
    device_op(json, true)
}

fn device_op(json: *const c_char, is_remove: bool) -> *mut c_char {
    #[derive(Deserialize)]
    struct Req {
        #[serde(flatten)]
        server: ServerParams,
        access_token: String,
        device_id: String,
        #[serde(default)]
        alias: Option<String>,
    }
    let result = parse_json::<Req>(json).and_then(|req| {
        client(&req.server).map(|c| {
            if is_remove {
                c.remove_device(&req.access_token, &req.device_id)
                    .map(|_| serde_json::json!({ "ok": true }))
            } else {
                c.rename_device(
                    &req.access_token,
                    &req.device_id,
                    req.alias.as_deref().unwrap_or(""),
                )
                .map(|d| serde_json::json!({ "ok": true, "device": d }))
            }
        })
    });
    match result {
        Ok(Ok(v)) => to_c_string(v.to_string()),
        Ok(Err(e)) => to_c_string(error_json(&e)),
        Err(e) => to_c_string(serde_json::json!({ "error": e, "kind": "other" }).to_string()),
    }
}
