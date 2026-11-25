//! 本地服务端联调验证:注册 → 登录 → 设备列表(rc-server 需运行在 127.0.0.1:21118,plain http)
use std::ffi::CString;

fn call(
    f: extern "C" fn(*const std::os::raw::c_char) -> *mut std::os::raw::c_char,
    json: &str,
) -> String {
    let cj = CString::new(json).unwrap();
    let ptr = f(cj.as_ptr());
    assert!(!ptr.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { rc_mobile_ffi::rc_string_free(ptr) };
    s
}

fn main() {
    let server = r#""server_host":"127.0.0.1","use_https":false"#;
    let probe = call(
        rc_mobile_ffi::auth::rc_server_probe,
        &format!("{{{server}}}"),
    );
    println!("probe: {}", &probe[..probe.len().min(200)]);

    let creds = format!(
        "{{{server},\"email\":\"devin@example.com\",\"password\":\"test-pass-123\",\"hostname\":\"ios-ffi-test\",\"os\":\"ios\"}}"
    );
    let reg = call(rc_mobile_ffi::auth::rc_auth_register, &creds);
    println!("register: {}", &reg[..reg.len().min(300)]);
    if reg.contains("\"error\"") {
        // 已注册过则登录
        let login = call(rc_mobile_ffi::auth::rc_auth_login, &creds);
        println!("login: {}", &login[..login.len().min(300)]);
    }
    std::process::exit(0);
}
