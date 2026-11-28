//! 平滑发送（pacing）。
//!
//! # 为什么必须有 pacing（N3）
//! 编码器输出一帧后立刻 for 循环把几十个包全部塞进 socket，会让：
//! - 本地与运营商队列瞬间堆积（bufferbloat），延迟出现秒级尖峰；
//! - 丢包集中在突发尾部，FEC 组内一次丢多个包、恢复失败。
//!
//! pacing 把「一次发完」摊成「按速率逐个放行」。它不限制吞吐，只限制
//! 瞬时突发——队列永远只有一两个包在途。
//!
//! # 时间注入（R7）
//! [`Pacer::poll`] 的时刻由调用方传入（`now: Instant`），因此所有测试
//! 精确、无 sleep、无 flaky。生产路径由 `quic.rs` 的发送线程传入真实时钟。
//!
//! # 放行模型
//! 队列从空闲转忙时，**第一个包立即放行**（交互延迟优先，不引入人为启动延迟）；
//! 之后第 k 个包的放行时刻 = 前一个包的放行时刻 + 该包的串行化时间
//! `ceil(len * 8 * 1e6 / rate)` 微秒。速率含义与线路上的一致：按**整包字节**
//! （含 `rc-proto` 包头）计。

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use rc_proto::MediaHeader;
use rc_types::FrameSeq;

/// 平滑发送队列。
///
/// # 并发
/// 本类型不内部加锁。`quic.rs` 把它放进 `Mutex` 由发送线程独占驱动；
/// 这里保持纯粹的可测逻辑。
#[derive(Debug)]
pub struct Pacer {
    /// 当前速率（bps）。0 表示不限速（测试/诊断用，生产路径不会设 0）。
    rate_bps: u64,
    /// 待发送队列（FIFO，保证同一帧内分片按序上线）
    queue: VecDeque<Vec<u8>>,
    /// 队列总字节数（增量维护，O(1) 查询）
    queued_bytes: usize,
    /// 下一个包的最早放行时刻。`None` 表示队列空闲过，下一个包可立即发。
    next_release: Option<Instant>,
    /// 单调递增入队序号（用于 `pacer_worker` 检测持锁外发送期间的并发入队，防止丢失唤醒）。
    enqueue_seq: u64,
    /// 因队列满而淘汰/丢弃的包计数（供 `Transport::tx_dropped_datagrams` 上报）。
    dropped_packets: u64,
    /// 最近在溢出淘汰中被整帧放弃的 `frame_seq`，用于拒收同一残帧的后续尾片。
    abandoned_frame_seq: Option<FrameSeq>,
}

/// pacer 排队包数上限，避免带宽骤降时排队延迟无界膨胀（按 MTU≈1200B 约 ≤2.4 MiB）。
pub const MAX_PACER_QUEUE_PACKETS: usize = 2048;

impl Pacer {
    /// 以初始速率构造。
    pub fn new(initial_rate_bps: u64) -> Self {
        Self {
            rate_bps: initial_rate_bps,
            queue: VecDeque::new(),
            queued_bytes: 0,
            next_release: None,
            enqueue_seq: 0,
            dropped_packets: 0,
            abandoned_frame_seq: None,
        }
    }

    /// 入队一个待发送的包。
    ///
    /// 入队不判速率——速率只影响 [`Self::poll`] 的放行节奏。
    /// 当队列达到 [`MAX_PACER_QUEUE_PACKETS`] 时优先按 `frame_seq` 整帧原子淘汰最旧非 IDR 帧，
    /// 保护在途 IDR 并避免只弹出单包留下必废残帧尾片。
    pub fn enqueue(&mut self, data: Vec<u8>) {
        let parsed = MediaHeader::parse(&data).ok();
        let incoming_seq = parsed.map(|h| h.frame_seq);
        let incoming_is_idr = parsed.is_some_and(|h| h.flags.is_idr());

        if incoming_seq.is_some() && self.abandoned_frame_seq == incoming_seq {
            self.dropped_packets = self.dropped_packets.saturating_add(1);
            return;
        }
        if incoming_seq.is_some() && self.abandoned_frame_seq != incoming_seq {
            self.abandoned_frame_seq = None;
        }

        while self.queue.len() >= MAX_PACER_QUEUE_PACKETS {
            let evict_idx = self
                .queue
                .iter()
                .position(|pkt| !MediaHeader::parse(pkt).is_ok_and(|h| h.flags.is_idr()));
            let idx = match evict_idx {
                Some(i) => i,
                None if !incoming_is_idr && incoming_seq.is_some() => {
                    // 队列中仅剩 IDR 分片时，直接放弃入站 P 帧并拒收后续尾片，保护在途 IDR。
                    self.abandoned_frame_seq = incoming_seq;
                    self.dropped_packets = self.dropped_packets.saturating_add(1);
                    return;
                }
                None => 0,
            };
            let Some(victim) = self.queue.remove(idx) else {
                break;
            };
            self.queued_bytes = self.queued_bytes.saturating_sub(victim.len());
            self.dropped_packets = self.dropped_packets.saturating_add(1);
            if let Ok(vh) = MediaHeader::parse(&victim) {
                let victim_seq = vh.frame_seq;
                let mut extra_bytes = 0usize;
                let mut extra_removed = 0u64;
                self.queue.retain(|pkt| {
                    if MediaHeader::parse(pkt).is_ok_and(|h| h.frame_seq == victim_seq) {
                        extra_bytes = extra_bytes.saturating_add(pkt.len());
                        extra_removed += 1;
                        false
                    } else {
                        true
                    }
                });
                self.queued_bytes = self.queued_bytes.saturating_sub(extra_bytes);
                self.dropped_packets = self.dropped_packets.saturating_add(extra_removed);
                if Some(victim_seq) == incoming_seq {
                    self.abandoned_frame_seq = Some(victim_seq);
                    self.dropped_packets = self.dropped_packets.saturating_add(1);
                    return;
                }
            }
        }
        self.queued_bytes += data.len();
        self.queue.push_back(data);
        self.enqueue_seq = self.enqueue_seq.wrapping_add(1);
    }

    /// 取出当前时刻允许发送的包（可能 0 个或多个）。
    ///
    /// `now` 由调用方注入：测试用受控时刻，生产用 `Instant::now()`。
    pub fn poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(front) = self.queue.front() {
            let release = match self.next_release {
                Some(t) => t,
                // 队列刚由空闲转忙：首包立即放行，不叠加人为启动延迟。
                None => now,
            };
            if release > now {
                break;
            }
            let interval = send_interval(self.rate_bps, front.len());
            // checked_add 防 Instant 溢出；溢出时退化为「立即放行」，
            // 比 panic 更符合传输层「尽力而为」的定位。
            self.next_release = release.checked_add(interval).or(Some(now));
            let pkt = self.queue.pop_front().expect("front checked above");
            self.queued_bytes -= pkt.len();
            out.push(pkt);
        }
        if self.queue.is_empty() {
            // 空闲复位：下一次突发仍从「首包立即放行」开始，
            // 否则短暂的发送间隙会把后续帧整体推迟。
            self.next_release = None;
        }
        out
    }

    /// 取出当前时刻及前瞻合并窗口 `[now, now + coalesce_horizon]` 内允许发送的包。
    ///
    /// 队列从空闲转忙时首包仍按 `now` 锚定（避免引入额外启动偏移），随后在
    /// `now + coalesce_horizon` 内的后续包同批放行，消除每包一次的线程唤醒与定时器合并抖动，
    /// 同时保持速率与包序完全精确。
    pub(crate) fn poll_coalesced(
        &mut self,
        now: Instant,
        coalesce_horizon: Duration,
    ) -> Vec<Vec<u8>> {
        if self.next_release.is_none() && !self.queue.is_empty() {
            let mut out = self.poll(now);
            if !coalesce_horizon.is_zero() {
                if let Some(horizon) = now.checked_add(coalesce_horizon) {
                    out.extend(self.poll(horizon));
                }
            }
            out
        } else {
            let horizon = now.checked_add(coalesce_horizon).unwrap_or(now);
            self.poll(horizon)
        }
    }

    /// 更新速率（由拥塞控制驱动；M3 之前保持初始值）。
    pub fn set_rate(&mut self, bps: u64) {
        self.rate_bps = bps;
    }

    /// 队列积压字节数。
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// 队列是否为空。
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// 累计因溢出被淘汰/丢弃的包数。
    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets
    }

    /// 单调入队序号。
    pub(crate) fn enqueue_seq(&self) -> u64 {
        self.enqueue_seq
    }

    /// 当前速率（bps）。
    pub fn rate_bps(&self) -> u64 {
        self.rate_bps
    }

    /// 下一个包的放行时刻（无积压时 `None`）。发送线程据此决定睡多久。
    pub(crate) fn next_release_at(&self) -> Option<Instant> {
        self.next_release
    }
}

/// 一个 `len` 字节的包在 `rate_bps` 速率下占用链路多久。
///
/// `ceil` 取整保证任何包至少占 1µs（速率为 0 视为不限速，返回 0）。
fn send_interval(rate_bps: u64, len: usize) -> Duration {
    if rate_bps == 0 {
        return Duration::ZERO;
    }
    let bits = (len as u64).saturating_mul(8).saturating_mul(1_000_000);
    let us = bits.div_ceil(rate_bps).max(1);
    Duration::from_micros(us)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1250 字节 @ 10 Mbps 恰好 1ms，取整不引入误差，断言可以做成精确值。
    const PKT: usize = 1250;
    const RATE_10M: u64 = 10_000_000;
    const ONE_MS: Duration = Duration::from_millis(1);

    #[test]
    fn pacer_smooths_burst_sends() {
        // N3：100 个包的突发不能一次发出；总耗时 ≥ 计算值的一半（确实在平滑）。
        let mut p = Pacer::new(RATE_10M);
        for _ in 0..100 {
            p.enqueue(vec![0u8; PKT]);
        }
        assert_eq!(p.queued_bytes(), 100 * PKT);

        let t0 = Instant::now();
        let first = p.poll(t0);
        // 首包立即放行，且只放行一个：poll 的语义是「当前时刻允许发送的」，
        // 第二个包的放行时刻是 t0 + 1ms。
        assert_eq!(first.len(), 1, "100 包突发不能一次发出（N3）");

        // 计算值：100 包 × 1ms = 100ms；验收线 = 一半。
        let expected_total = 100 * ONE_MS;
        let mut got = first.len();
        let mut t = t0;
        while got < 100 {
            t += Duration::from_millis(15);
            got += p.poll(t).len();
        }
        assert_eq!(got, 100, "最终必须全部放行");
        let span = t.duration_since(t0);
        assert!(
            span >= expected_total / 2,
            "100 包突发耗时 {span:?} < 计算值的一半 {:?}（没有在平滑）",
            expected_total / 2
        );
        // 上界也校验：不应比计算值多出一个数量级（那说明把间隔算错了）。
        assert!(
            span <= expected_total * 2,
            "耗时 {span:?} 明显超过计算值 {expected_total:?}，节奏算错"
        );
        assert_eq!(p.queued_bytes(), 0);
    }

    #[test]
    fn pacer_respects_rate_change() {
        let mut p = Pacer::new(RATE_10M);
        for _ in 0..100 {
            p.enqueue(vec![0u8; PKT]);
        }
        let t0 = Instant::now();
        assert_eq!(p.poll(t0).len(), 1);

        // 10 Mbps 下，[t0, t0+5ms] 内放行 5 个（release 1ms..5ms）。
        let w1 = p.poll(t0 + Duration::from_millis(5));
        assert_eq!(w1.len(), 5, "10Mbps → 1ms/包，5ms 窗口应放行 5 个");

        // 提速到 100 Mbps → 100µs/包。
        p.set_rate(100_000_000);
        assert_eq!(p.rate_bps(), 100_000_000);
        // 之后的 10ms 窗口应放行大部分剩余包。
        let w2 = p.poll(t0 + Duration::from_millis(15));
        assert!(
            w2.len() > w1.len() * 4,
            "提速后节奏必须明显变快：w1={} w2={}",
            w1.len(),
            w2.len()
        );
        let drained = 1 + w1.len() + w2.len() + p.poll(t0 + Duration::from_secs(1)).len();
        assert_eq!(drained, 100, "所有包最终都被放行且不重复");
    }

    #[test]
    fn pacer_queued_bytes_tracks_backlog() {
        let mut p = Pacer::new(RATE_10M);
        p.enqueue(vec![1u8; 500]);
        p.enqueue(vec![2u8; 300]);
        p.enqueue(vec![3u8; 200]);
        assert_eq!(p.queued_bytes(), 1000, "积压 = 全部队列字节");

        let t0 = Instant::now();
        let out = p.poll(t0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], vec![1u8; 500], "FIFO：先入先出");
        assert_eq!(p.queued_bytes(), 500, "放行一个 500B 包后剩 500");

        // 清空队列后积压归零，且空闲复位（下次首包立即放行）。
        let rest = p.poll(t0 + Duration::from_millis(50));
        assert_eq!(rest.len(), 2);
        assert_eq!(p.queued_bytes(), 0);
        assert_eq!(p.poll(t0 + Duration::from_millis(60)).len(), 0);
        p.enqueue(vec![9u8; 10]);
        assert_eq!(p.poll(t0 + Duration::from_millis(61)), vec![vec![9u8; 10]]);
    }

    #[test]
    fn send_interval_math() {
        // 1250B @10Mbps = 1ms 整
        assert_eq!(send_interval(RATE_10M, 1250), ONE_MS);
        // 1250B @100Mbps = 100µs 整
        assert_eq!(send_interval(100_000_000, 1250), Duration::from_micros(100));
        // 向上取整：1B @16Mbps = 0.5µs → 至少 1µs
        assert_eq!(send_interval(16_000_000, 1), Duration::from_micros(1));
        // 1B @8Mbps 恰好 1µs
        assert_eq!(send_interval(8_000_000, 1), Duration::from_micros(1));
        // 速率 0 = 不限速
        assert_eq!(send_interval(0, 9999), Duration::ZERO);
    }

    #[test]
    fn pacer_poll_coalesced_batches_within_horizon_and_preserves_rate() {
        // 200 Mbps 下 1150B 包串行化间隔 = 46µs；250µs 合并窗口应一次放行 6 包（0,46,92,138,184,230µs），
        // 且 next_release 精确停在 t0 + 276µs（无启动偏移）。
        let mut p = Pacer::new(200_000_000);
        for i in 0..20u8 {
            p.enqueue(vec![i; 1150]);
        }
        let t0 = Instant::now();
        let horizon = Duration::from_micros(250);
        let first_batch = p.poll_coalesced(t0, horizon);
        assert_eq!(first_batch.len(), 6);
        for (idx, pkt) in first_batch.iter().enumerate() {
            assert_eq!(pkt[0], idx as u8);
        }
        assert_eq!(p.next_release_at(), Some(t0 + Duration::from_micros(276)));

        // 按 276µs 后继续轮询直至排空，验证 FIFO 保序且不重复/不丢包。
        let mut drained: Vec<u8> = first_batch.iter().map(|b| b[0]).collect();
        let mut now = t0;
        while p.queued_bytes() > 0 {
            now += Duration::from_micros(250);
            for pkt in p.poll_coalesced(now, horizon) {
                drained.push(pkt[0]);
            }
        }
        assert_eq!(drained, (0..20u8).collect::<Vec<_>>());
        assert_eq!(p.next_release_at(), None);

        // 10 Mbps（1250B = 1ms/pkt > 250µs）时，poll_coalesced 仍每次只放行 1 包，保持 N3 平滑。
        let mut slow = Pacer::new(RATE_10M);
        slow.enqueue(vec![1; PKT]);
        slow.enqueue(vec![2; PKT]);
        let slow_batch = slow.poll_coalesced(t0, horizon);
        assert_eq!(slow_batch.len(), 1);
        assert_eq!(slow.next_release_at(), Some(t0 + ONE_MS));
    }

    fn make_media_pkt(seq: u64, pkt_idx: u16, pkt_count: u16, is_idr: bool) -> Vec<u8> {
        use rc_proto::{HeaderFlags, MediaHeader};
        use rc_types::Timestamp;

        let mut flags = HeaderFlags::empty();
        if is_idr {
            flags.set(HeaderFlags::IDR);
        }
        let h = MediaHeader {
            frame_seq: FrameSeq(seq),
            capture_ts: Timestamp(1_000),
            encode_done_ts: Timestamp(1_000),
            packet_idx: pkt_idx,
            packet_cnt: pkt_count,
            fec_group: 0,
            flags,
            layer_id: 0,
            payload_len: 16,
        };
        let mut buf = Vec::with_capacity(rc_proto::HEADER_LEN + 16);
        let mut hdr = [0u8; rc_proto::HEADER_LEN];
        h.write(&mut hdr);
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(&[0x5Au8; 16]);
        buf
    }

    #[test]
    fn pacer_overflow_evicts_oldest_p_frame_atomically_and_protects_idr() {
        let mut p = Pacer::new(10_000_000);
        // Enqueue 4-packet IDR (seq=1) + enough 4-packet P-frames to fill MAX_PACER_QUEUE_PACKETS (2048).
        for idx in 0..4u16 {
            p.enqueue(make_media_pkt(1, idx, 4, true));
        }
        // 511 P-frames * 4 packets = 2044 packets -> total 2048 packets.
        for seq in 2..=512u64 {
            for idx in 0..4u16 {
                p.enqueue(make_media_pkt(seq, idx, 4, false));
            }
        }
        assert_eq!(p.queue.len(), MAX_PACER_QUEUE_PACKETS);
        let before_seq = p.enqueue_seq();

        // Enqueue 1 packet of P-frame 513 -> must atomically evict all 4 packets of oldest P-frame 2,
        // keeping IDR (seq=1) intact and leaving zero orphan fragments of frame 2.
        p.enqueue(make_media_pkt(513, 0, 4, false));
        assert!(p.enqueue_seq() > before_seq);
        assert_eq!(p.dropped_packets(), 4);
        assert_eq!(p.queue.len(), MAX_PACER_QUEUE_PACKETS - 3);
        let has_idr1 = p
            .queue
            .iter()
            .filter(|pkt| MediaHeader::parse(pkt).is_ok_and(|h| h.frame_seq == FrameSeq(1)))
            .count();
        assert_eq!(has_idr1, 4, "in-flight IDR frame 1 must stay intact");
        let has_p2 = p
            .queue
            .iter()
            .any(|pkt| MediaHeader::parse(pkt).is_ok_and(|h| h.frame_seq == FrameSeq(2)));
        assert!(
            !has_p2,
            "evicted P-frame 2 must leave zero orphan fragments"
        );

        // When queue contains only IDR packets at capacity, incoming P-frame fragments are dropped whole.
        let mut idr_only = Pacer::new(10_000_000);
        for idx in 0..MAX_PACER_QUEUE_PACKETS as u16 {
            idr_only.enqueue(make_media_pkt(
                10,
                idx,
                MAX_PACER_QUEUE_PACKETS as u16,
                true,
            ));
        }
        idr_only.enqueue(make_media_pkt(11, 0, 2, false));
        idr_only.enqueue(make_media_pkt(11, 1, 2, false));
        assert_eq!(idr_only.dropped_packets(), 2);
        assert!(idr_only
            .queue
            .iter()
            .all(|pkt| MediaHeader::parse(pkt).is_ok_and(|h| h.frame_seq == FrameSeq(10))));
    }

    #[test]
    fn pacer_overflow_self_eviction_counts_incoming_packet_in_dropped_packets() {
        // Case 1: P-frame reaches MAX_PACER_QUEUE_PACKETS and self-evicts on its next fragment.
        let mut p = Pacer::new(10_000_000);
        for idx in 0..MAX_PACER_QUEUE_PACKETS as u16 {
            p.enqueue(make_media_pkt(
                42,
                idx,
                (MAX_PACER_QUEUE_PACKETS + 2) as u16,
                false,
            ));
        }
        assert_eq!(p.queue.len(), MAX_PACER_QUEUE_PACKETS);
        assert_eq!(p.dropped_packets(), 0);

        // Next fragment of frame 42 triggers self-eviction of all 2048 queued packets AND drops itself.
        p.enqueue(make_media_pkt(
            42,
            MAX_PACER_QUEUE_PACKETS as u16,
            (MAX_PACER_QUEUE_PACKETS + 2) as u16,
            false,
        ));
        assert!(p.is_empty());
        assert_eq!(p.queued_bytes(), 0);
        assert_eq!(
            p.dropped_packets(),
            (MAX_PACER_QUEUE_PACKETS + 1) as u64,
            "self-eviction must count all queued packets plus the dropped incoming packet"
        );

        // Subsequent fragment of the abandoned frame 42 is also dropped and counted.
        p.enqueue(make_media_pkt(
            42,
            (MAX_PACER_QUEUE_PACKETS + 1) as u16,
            (MAX_PACER_QUEUE_PACKETS + 2) as u16,
            false,
        ));
        assert!(p.is_empty());
        assert_eq!(p.dropped_packets(), (MAX_PACER_QUEUE_PACKETS + 2) as u64);

        // Case 2: IDR frame reaches MAX_PACER_QUEUE_PACKETS and self-evicts on its next fragment.
        let mut idr = Pacer::new(10_000_000);
        for idx in 0..MAX_PACER_QUEUE_PACKETS as u16 {
            idr.enqueue(make_media_pkt(
                99,
                idx,
                (MAX_PACER_QUEUE_PACKETS + 1) as u16,
                true,
            ));
        }
        idr.enqueue(make_media_pkt(
            99,
            MAX_PACER_QUEUE_PACKETS as u16,
            (MAX_PACER_QUEUE_PACKETS + 1) as u16,
            true,
        ));
        assert!(idr.is_empty());
        assert_eq!(idr.queued_bytes(), 0);
        assert_eq!(idr.dropped_packets(), (MAX_PACER_QUEUE_PACKETS + 1) as u64);
    }
}
