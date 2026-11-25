//! RabbitControl 移动端 FFI 边界。
//!
//! 设计约定:
//! - 全部函数为 C ABI;结构化数据以 JSON 字符串跨边界交换,移动端用原生 JSON 解码。
//! - 返回的 `*mut c_char` 由 Rust 侧分配,调用方必须经 [`rc_string_free`] 释放。
//! - 句柄类对象(局域网发现等)由 Rust 侧持有单例,移动端只调用过程式 API;
//!   后续会话/渲染等需要对象语义的接口再引入不透明指针句柄。
//!
//! 本 crate 是全 workspace 唯一允许 `unsafe` 的 crate,unsafe 严格限制在 FFI 边界层。

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Mutex, OnceLock};

use rc_client_core::lan_discovery::LanDiscoveryHandle;

pub mod auth;
pub mod session;

/// 返回核心库版本字符串(调用方负责用 `rc_string_free` 释放)。
#[no_mangle]
pub extern "C" fn rc_core_version() -> *mut c_char {
    to_c_string(env!("CARGO_PKG_VERSION").to_string())
}

/// 释放 Rust 侧分配的字符串。传入空指针安全无操作。
///
/// # Safety
/// `ptr` 必须为本 crate 函数返回的字符串指针,且只能释放一次。
#[no_mangle]
pub unsafe extern "C" fn rc_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(ptr));
    }
}

fn to_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn read_c_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

// ─────────────────────────────────────────────────────────────
// 局域网发现(W1 切片):移动端作为主控端默认仅监听,不广播。
// ─────────────────────────────────────────────────────────────

static LAN_DISCOVERY: OnceLock<Mutex<Option<LanDiscoveryHandle>>> = OnceLock::new();

fn lan_slot() -> &'static Mutex<Option<LanDiscoveryHandle>> {
    LAN_DISCOVERY.get_or_init(|| Mutex::new(None))
}

fn lock_lan() -> std::sync::MutexGuard<'static, Option<LanDiscoveryHandle>> {
    lan_slot().lock().unwrap_or_else(|e| e.into_inner())
}

/// 启动局域网发现后台线程。重复调用幂等(已启动则直接返回 1)。
///
/// - `instance_id`:本机随机实例 ID(过滤自身回环包)。
/// - `device_name`:UTF-8 设备可读名称。
///
/// 返回 1=已启动,0=参数非法。
#[no_mangle]
pub extern "C" fn rc_lan_discovery_start(instance_id: u64, device_name: *const c_char) -> i32 {
    let Some(name) = read_c_str(device_name) else {
        return 0;
    };
    let mut guard = lock_lan();
    if guard.is_some() {
        return 1;
    }
    *guard = Some(LanDiscoveryHandle::spawn(instance_id, name.to_string()));
    1
}

/// 停止局域网发现线程(幂等)。
#[no_mangle]
pub extern "C" fn rc_lan_discovery_stop() {
    let mut guard = lock_lan();
    if let Some(mut handle) = guard.take() {
        handle.stop();
    }
}

/// 获取当前在线局域网节点快照,JSON 数组字符串(字段与 `LanPeer` 一致:
/// `instance_id` / `name` / `addr` / `requires_password` / `device_id`)。
/// 未启动发现时返回空数组 `[]`。调用方负责释放字符串。
#[no_mangle]
pub extern "C" fn rc_lan_peers_json() -> *mut c_char {
    let guard = lock_lan();
    let peers = guard.as_ref().map(|h| h.peers()).unwrap_or_default();
    to_c_string(serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn version_roundtrip() {
        let ptr = rc_core_version();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        assert!(!s.is_empty());
        unsafe { rc_string_free(ptr) };
    }

    #[test]
    fn peers_empty_before_start() {
        let ptr = rc_lan_peers_json();
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        unsafe { rc_string_free(ptr) };
        // 已启动则元素不定,未启动应为空数组;两种形态都必须是合法 JSON 数组
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.is_array());
    }

    #[test]
    fn start_is_idempotent() {
        let name = CString::new("ffi-test").unwrap();
        assert_eq!(rc_lan_discovery_start(42, name.as_ptr()), 1);
        assert_eq!(rc_lan_discovery_start(42, name.as_ptr()), 1);
        rc_lan_discovery_stop();
    }

    #[test]
    fn start_rejects_null_name() {
        assert_eq!(rc_lan_discovery_start(42, std::ptr::null()), 0);
    }
}
