//! 运行时链路联调:init → login → signal_start(设备绑定+证书签发+信令拉起)。
//! 需要本机 rc-server 运行在 127.0.0.1:21118(plain http)。
use std::ffi::CString;

fn call(
    f: extern "C" fn(*const std::os::raw::c_char) -> *mut std::os::raw::c_char,
    json: &str,
) -> String {
    let cj = CString::new(json).unwrap();
    let ptr = f(cj.as_ptr());
    assert!(!ptr.is_null(), "FFI 返回空指针");
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { rc_mobile_ffi::rc_string_free(ptr) };
    s
}

fn main() {
    use rc_mobile_ffi::runtime::*;
    let dir = std::env::temp_dir().join("rc-ffi-runtime-test");
    std::fs::create_dir_all(&dir).unwrap();

    let init = call(
        rc_runtime_init,
        &format!(
            r#"{{"server_host":"127.0.0.1","use_https":false,"data_dir":"{}"}}"#,
            dir.display()
        ),
    );
    println!("init: {}", &init[..init.len().min(120)]);

    let login = call(
        rc_runtime_login,
        r#"{"email":"devin@example.com","password":"test-pass-123","hostname":"ffi-runtime-test","os":"ios"}"#,
    );
    println!("login: {}", &login[..login.len().min(200)]);
    if login.contains("\"error\"") {
        // 密码改过后试新密码;否则注册
        let reg = call(
            rc_mobile_ffi::auth::rc_auth_register,
            r#"{"server_host":"127.0.0.1","use_https":false,"email":"devin@example.com","password":"test-pass-123","hostname":"ffi-runtime-test","os":"ios"}"#,
        );
        println!("register: {}", &reg[..reg.len().min(150)]);
        let login2 = call(
            rc_runtime_login,
            r#"{"email":"devin@example.com","password":"test-pass-123","hostname":"ffi-runtime-test","os":"ios"}"#,
        );
        println!("login2: {}", &login2[..login2.len().min(200)]);
    }

    let status_ptr = rc_runtime_status();
    let status = unsafe { std::ffi::CStr::from_ptr(status_ptr) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { rc_mobile_ffi::rc_string_free(status_ptr) };
    println!("status: {}", &status[..status.len().min(200)]);

    let sig = call(
        rc_signal_start,
        r#"{"hostname":"ffi-runtime-test","os":"ios"}"#,
    );
    println!("signal_start: {}", &sig[..sig.len().min(300)]);

    // 等 3 秒看信令是否稳住,然后停
    std::thread::sleep(std::time::Duration::from_secs(3));
    let stop_ptr = rc_signal_stop();
    let stop = unsafe { std::ffi::CStr::from_ptr(stop_ptr) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { rc_mobile_ffi::rc_string_free(stop_ptr) };
    println!("signal_stop: {stop}");
    std::process::exit(if sig.contains("\"error\"") { 1 } else { 0 });
}
