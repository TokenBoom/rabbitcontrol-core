//! 监听验证:打印 5s 内发现的局域网节点
use rc_client_core::lan_discovery::LanDiscoveryHandle;

fn main() {
    let handle = LanDiscoveryHandle::spawn(555_000_999, "listener".to_string());
    std::thread::sleep(std::time::Duration::from_secs(5));
    let peers = handle.peers();
    println!("peers: {:?}", peers);
    if peers.is_empty() {
        std::process::exit(1);
    }
}
