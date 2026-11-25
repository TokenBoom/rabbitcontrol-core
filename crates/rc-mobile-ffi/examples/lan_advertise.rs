//! 局域网广播验证桩:模拟一台在线被控端,供 iOS 客户端发现链路端到端验证。
//! 用法: cargo run -p rc-mobile-ffi --example lan_advertise
use rc_client_core::lan_discovery::LanDiscoveryHandle;

fn main() {
    let handle = LanDiscoveryHandle::spawn(999_000_001, "FFI 验证机".to_string());
    // 广播:监听端口 21116、需要密码,并携带 9 位设备码
    handle.set_advertising(Some((21116, true)));
    handle.set_local_device_id(Some("183435140".to_string()));
    println!("advertising as 'FFI 验证机' on port 21116, ctrl-c to stop");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
