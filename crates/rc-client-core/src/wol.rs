//! Wake-on-LAN（远程开机）魔术包构造、MAC 校验与局域网 UDP 广播实现。
//!
//! 严格对齐 `rabbitcontrol-server/docs/02-protocol-and-api.md`：
//! - MAC 地址校验接受 `:` 或 `-` 分隔的 6 组十六进制字节（拒绝混用、全 `00`、全 `FF` 与多播
//!   `(b0 & 0x01) != 0`），统一规范化为小写 `aa:bb:cc:dd:ee:ff`；
//! - 102 字节标准魔术包：`6 × 0xFF` + `16 × MAC(6B)`；
//! - 定向广播目标提取 RFC 1918 私有 IPv4 `/24` 定向广播 `:9` + 兜底 `255.255.255.255:9`，
//!   严格过滤回环、链路本地与公网 IP；
//! - 全模块 `#![deny(unsafe_code)]` 与 `#![deny(missing_docs)]`。

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

/// 标准 Wake-on-LAN 魔术包固定长度（`6 + 16 * 6 = 102` 字节）。
pub const MAGIC_PACKET_LEN: usize = 102;

/// 标准 Wake-on-LAN UDP 目的端口（Discard 端口 9）。
pub const WOL_UDP_PORT: u16 = 9;

/// 每个目标地址重复发送魔术包的次数（缓解局域网 UDP 偶发丢包）。
pub const WOL_SEND_REPEATS: usize = 2;

/// 规范单播 MAC 地址文本长度（`"aa:bb:cc:dd:ee:ff"` = 17 字节）。
const MAC_ADDR_TEXT_LEN: usize = 17;

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 严格校验并解析单播 MAC 地址为 6 字节数组。
///
/// 规则与 `rabbitcontrol-server` 完全一致：
/// - 接受 `:` 或 `-` 分隔（禁止混用分隔符）；
/// - 拒绝控制字符/NUL、长度非 17、非十六进制字符；
/// - 拒绝全零（`00:00:00:00:00:00`）、广播（`ff:ff:ff:ff:ff:ff`）与多播（`(b0 & 0x01) != 0`）。
pub fn parse_mac_addr_bytes(raw: &str) -> Option<[u8; 6]> {
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        return None;
    }
    let trimmed = raw.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() != MAC_ADDR_TEXT_LEN {
        return None;
    }
    let sep = bytes[2];
    if sep != b':' && sep != b'-' {
        return None;
    }
    if bytes[5] != sep || bytes[8] != sep || bytes[11] != sep || bytes[14] != sep {
        return None;
    }
    let mut octets = [0u8; 6];
    for (i, slot) in octets.iter_mut().enumerate() {
        let base = i * 3;
        let hi = hex_nibble(bytes[base])?;
        let lo = hex_nibble(bytes[base + 1])?;
        *slot = (hi << 4) | lo;
    }
    if octets == [0u8; 6] || octets == [0xFFu8; 6] || (octets[0] & 0x01) != 0 {
        return None;
    }
    Some(octets)
}

/// 校验并规范化单播 MAC 地址为小写冒号分隔形式（`"aa:bb:cc:dd:ee:ff"`）。
pub fn normalize_mac_addr(raw: &str) -> Option<String> {
    let b = parse_mac_addr_bytes(raw)?;
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    ))
}

/// 构造标准 102 字节 Wake-on-LAN 魔术包（`6 × 0xFF` + `16 × mac`）。
pub fn build_magic_packet(mac: [u8; 6]) -> [u8; MAGIC_PACKET_LEN] {
    let mut pkt = [0u8; MAGIC_PACKET_LEN];
    pkt[..6].fill(0xFF);
    for chunk in pkt[6..].chunks_exact_mut(6) {
        chunk.copy_from_slice(&mac);
    }
    pkt
}

fn extract_private_ipv4(raw: &str) -> Option<Ipv4Addr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let ip: IpAddr = if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        sock.ip()
    } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
        ip
    } else {
        return None;
    };
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => v6.to_ipv4_mapped()?,
    };
    if !v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
    {
        return None;
    }
    Some(v4)
}

/// 从目标设备历史局域网地址列表推导 UDP `:9` 广播目标：
/// - 仅保留 RFC 1918 私有 IPv4，推导其 `/24` 定向广播地址（`a.b.c.255:9`），去重保序；
/// - 严格过滤回环（`127.0.0.0/8`）、链路本地（`169.254.0.0/16`）、IPv6 与公网 IP；
/// - 末尾始终追加兜底全局广播 `255.255.255.255:9`。
pub fn compute_broadcast_targets(target_lan_addrs: &[String]) -> Vec<SocketAddr> {
    let mut targets = Vec::with_capacity(target_lan_addrs.len() + 1);
    for raw in target_lan_addrs {
        let Some(v4) = extract_private_ipv4(raw) else {
            continue;
        };
        let o = v4.octets();
        let bcast = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(o[0], o[1], o[2], 255),
            WOL_UDP_PORT,
        ));
        if !targets.contains(&bcast) {
            targets.push(bcast);
        }
    }
    let fallback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, WOL_UDP_PORT));
    if !targets.contains(&fallback) {
        targets.push(fallback);
    }
    targets
}

/// 向指定 UDP 目标列表发送魔术包（开启 `SO_BROADCAST`，每目标发送 2 遍防丢包）。
///
/// 返回成功发出的数据报总数；若 `targets` 为空或全部发送失败则返回 `Err`。
pub fn send_magic_packet_to_addrs(mac: [u8; 6], targets: &[SocketAddr]) -> Result<usize, String> {
    if targets.is_empty() {
        return Err("Wake-on-LAN 目标地址列表为空".to_string());
    }
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("绑定 Wake-on-LAN UDP 套接字失败：{e}"))?;
    sock.set_broadcast(true)
        .map_err(|e| format!("开启 Wake-on-LAN SO_BROADCAST 失败：{e}"))?;
    let packet = build_magic_packet(mac);
    let mut sent = 0usize;
    let mut last_err: Option<String> = None;
    for &target in targets {
        for _ in 0..WOL_SEND_REPEATS {
            match sock.send_to(&packet, target) {
                Ok(n) if n == MAGIC_PACKET_LEN => sent += 1,
                Ok(n) => {
                    last_err = Some(format!(
                        "向 {target} 发送魔术包不完整（期望 {MAGIC_PACKET_LEN} 字节，实发 {n} 字节）"
                    ));
                }
                Err(err) => {
                    last_err = Some(format!("向 {target} 发送魔术包失败：{err}"));
                }
            }
        }
    }
    if sent > 0 {
        Ok(sent)
    } else {
        Err(last_err.unwrap_or_else(|| "发送 Wake-on-LAN 魔术包失败".to_string()))
    }
}

/// 校验 MAC 地址并向推导出的局域网广播目标发送 Wake-on-LAN 魔术包（每目标 2 遍）。
pub fn send_magic_packet(mac_str: &str, target_lan_addrs: &[String]) -> Result<usize, String> {
    let mac = parse_mac_addr_bytes(mac_str).ok_or_else(|| {
        "无效的单播 MAC 地址（需为冒号或短横线分隔的 6 字节十六进制）".to_string()
    })?;
    let targets = compute_broadcast_targets(target_lan_addrs);
    send_magic_packet_to_addrs(mac, &targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn mac_validation_matches_server_rules() {
        // 合法单播（冒号 / 短横线 / 大小写）
        assert_eq!(
            parse_mac_addr_bytes("AA:BB:CC:DD:EE:FF"),
            Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
        assert_eq!(
            normalize_mac_addr("  aa-bb-cc-dd-ee-ff  "),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac_addr("02:11:22:33:44:55"),
            Some("02:11:22:33:44:55".to_string())
        );

        // 混用分隔符
        assert_eq!(parse_mac_addr_bytes("aa:bb-cc:dd:ee:ff"), None);
        // 全 0
        assert_eq!(parse_mac_addr_bytes("00:00:00:00:00:00"), None);
        // 全 F 广播
        assert_eq!(parse_mac_addr_bytes("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(parse_mac_addr_bytes("FF-FF-FF-FF-FF-FF"), None);
        // 多播 (b0 & 0x01) != 0
        assert_eq!(parse_mac_addr_bytes("01:00:5e:00:00:01"), None);
        assert_eq!(parse_mac_addr_bytes("33:33:00:00:00:01"), None);
        // 非法长度 / 字符 / 控制字符
        assert_eq!(parse_mac_addr_bytes("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac_addr_bytes("gg:bb:cc:dd:ee:ff"), None);
        assert_eq!(parse_mac_addr_bytes("aa:bb:cc:dd:ee:ff\n"), None);
        assert_eq!(parse_mac_addr_bytes(""), None);
    }

    #[test]
    fn magic_packet_layout_is_102_bytes_exact() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let pkt = build_magic_packet(mac);
        assert_eq!(pkt.len(), 102);
        assert_eq!(&pkt[0..6], &[0xFF; 6]);
        for i in 0..16 {
            let start = 6 + i * 6;
            assert_eq!(&pkt[start..start + 6], &mac);
        }
    }

    #[test]
    fn compute_broadcast_targets_filters_non_private_and_appends_global_fallback() {
        let addrs = vec![
            "192.168.1.20:50000".to_string(),
            "192.168.1.55:50001".to_string(), // 同 /24 应去重
            "10.0.5.12".to_string(),
            "172.16.8.9:9901".to_string(),
            "127.0.0.1:9901".to_string(),   // 回环过滤
            "169.254.1.2:9901".to_string(), // 链路本地过滤
            "8.8.8.8:53".to_string(),       // 公网过滤
            "[fe80::1]:9901".to_string(),   // IPv6 过滤
            "not-an-ip".to_string(),
        ];
        let targets = compute_broadcast_targets(&addrs);
        assert_eq!(
            targets,
            vec![
                "192.168.1.255:9".parse::<SocketAddr>().unwrap(),
                "10.0.5.255:9".parse::<SocketAddr>().unwrap(),
                "172.16.8.255:9".parse::<SocketAddr>().unwrap(),
                "255.255.255.255:9".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn send_magic_packet_to_addrs_delivers_two_packets_over_loopback() {
        let rx = UdpSocket::bind("127.0.0.1:0").expect("bind loopback udp receiver");
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let rx_addr = rx.local_addr().unwrap();

        let mac = [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02];
        let expected = build_magic_packet(mac);
        let sent = send_magic_packet_to_addrs(mac, &[rx_addr]).expect("send magic packet");
        assert_eq!(sent, WOL_SEND_REPEATS);

        for _ in 0..WOL_SEND_REPEATS {
            let mut buf = [0u8; 256];
            let (n, _) = rx.recv_from(&mut buf).expect("recv magic packet");
            assert_eq!(n, MAGIC_PACKET_LEN);
            assert_eq!(&buf[..n], &expected);
        }
    }
}
