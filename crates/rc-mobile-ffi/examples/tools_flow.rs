//! 工具通道联调:直连会话 → 终端开/输入/输出收割 → 文件列目录。
//! 前置:rc-cli host 运行在 127.0.0.1:9901。
use std::ffi::CString;
use std::os::raw::c_char;

fn cstr_json(j: &str) -> CString {
    CString::new(j).unwrap()
}
fn take(ptr: *mut c_char) -> String {
    assert!(!ptr.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { rc_mobile_ffi::rc_string_free(ptr) };
    s
}

fn main() {
    use rc_mobile_ffi::{session::*, tools::*};
    let open = take(rc_session_open(
        cstr_json(r#"{"connect_addr":"127.0.0.1:9901","width":1280,"height":720}"#).as_ptr(),
    ));
    println!("open: {open}");
    let sid: u64 = serde_json::from_str::<serde_json::Value>(&open).unwrap()["session_id"]
        .as_u64()
        .expect("会话打开失败");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // 终端
    let t = take(rc_tools_call(
        sid,
        cstr_json(r#"{"op":"terminal_open","cols":80,"rows":24}"#).as_ptr(),
    ));
    println!("terminal_open: {t}");
    let term_id = serde_json::from_str::<serde_json::Value>(&t).unwrap()["term_id"]
        .as_u64()
        .unwrap_or(0) as u32;
    if term_id != 0 {
        let _ = take(rc_tools_call(
            sid,
            cstr_json(&format!(
                r#"{{"op":"terminal_input","term_id":{term_id},"text":"echo hello-rabbit\n"}}"#
            ))
            .as_ptr(),
        ));
        std::thread::sleep(std::time::Duration::from_secs(2));
        let poll = take(rc_tools_poll(sid));
        let got_output = poll.contains("hello-rabbit");
        println!("terminal output contains echo: {got_output}");
        let _ = take(rc_tools_call(
            sid,
            cstr_json(&format!(r#"{{"op":"terminal_close","term_id":{term_id}}}"#)).as_ptr(),
        ));
    }

    // 文件列目录
    let _ = take(rc_tools_call(
        sid,
        cstr_json(r#"{"op":"file_list_remote","path":null}"#).as_ptr(),
    ));
    std::thread::sleep(std::time::Duration::from_secs(2));
    let poll = take(rc_tools_poll(sid));
    let has_dir = poll.contains("remoteDir");
    println!("file remoteDir event: {has_dir}");

    // 端口映射
    let pm = take(rc_tools_call(sid, cstr_json(
        r#"{"op":"portmap_add","name":"test","local_port":18080,"remote_host":"127.0.0.1","remote_port":80}"#
    ).as_ptr()));
    println!("portmap_add: {}", &pm[..pm.len().min(120)]);

    let _ = take(rc_session_close(
        cstr_json(&format!(r#"{{"session_id":{sid}}}"#)).as_ptr(),
    ));
    let pass = term_id != 0 && has_dir;
    println!("RESULT: {}", if pass { "PASS" } else { "PARTIAL" });
    std::process::exit(if pass { 0 } else { 1 });
}
