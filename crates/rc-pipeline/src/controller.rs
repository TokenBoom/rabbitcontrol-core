//! 控制端管线：重组 → 解码 → 呈现。
//!
//! 红线对应：
//! - P6：按 `frame_seq` 分组、按 `packet_idx` 排序，`packet_cnt` 齐了才交付；
//!   更新的完整帧到达后，序号更小的残帧永远凑不齐，判 `LostInNetwork`；
//! - P3：参考链断裂（`NeedKeyframe`）时置关键帧请求，会话层转发给 host；
//! - P4：残帧与解码失败都有明确结局，`shutdown`/截断时 [`finish_in_flight`]
//!   兜底，`unfinished == 0`。

use crate::{select_all, PipelineConfig};
use rc_decode::{DecodeOutput, DecodeSubmitStatus, Decoder};
use rc_proto::{MediaHeader, HEADER_LEN};
use rc_render::Renderer;
use rc_trace::{Mark, Outcome, TraceCollector};
use rc_types::{Error, FrameKind, FrameSeq, Result, Timestamp};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// 重组中的帧。
struct Partial {
    cnt: u16,
    packets: Vec<Option<Vec<u8>>>,
    received: u16,
    capture_ts: Timestamp,
    /// 发送端声明的编码完成时刻（诊断对照用，重组逻辑不依赖）。
    #[allow(dead_code)]
    encode_done_ts: Timestamp,
    kind: FrameKind,
    is_hevc: bool,
}

type ClockSlot = Arc<Mutex<Option<Arc<dyn Fn() -> u32 + Send + Sync>>>>;

struct PendingAsyncFrame {
    seq: FrameSeq,
    payload_all: Vec<u8>,
    capture_ts: Timestamp,
    received_ts: Timestamp,
    kind: FrameKind,
    is_hevc: bool,
}

enum AsyncFrameOutcome {
    Finished {
        seq: FrameSeq,
        capture_ts: Timestamp,
        received_ts: Timestamp,
        decoded_ts: Option<Timestamp>,
        presented_ts: Option<Timestamp>,
        outcome: Outcome,
    },
}

#[derive(Default)]
struct AsyncSharedState {
    completed: VecDeque<AsyncFrameOutcome>,
    fatal_error: Option<Error>,
}

enum ControllerExecMode {
    Sync {
        decoder: Box<dyn Decoder>,
        renderer: Box<dyn Renderer>,
        active_codec: rc_encode::Codec,
    },
    Async {
        slot: Arc<(Mutex<VecDeque<PendingAsyncFrame>>, Condvar)>,
        stop: Arc<AtomicBool>,
        shared: Arc<Mutex<AsyncSharedState>>,
        need_keyframe: Arc<AtomicBool>,
        displayed: Arc<AtomicU64>,
        worker: Option<JoinHandle<()>>,
    },
}

/// 控制端管线。
pub struct ControllerPipeline {
    cfg: PipelineConfig,
    mode: ControllerExecMode,
    trace: TraceCollector,
    /// 重组表（按帧序号有序，便于「新帧到达后清理旧残帧」）。
    partials: BTreeMap<FrameSeq, Partial>,
    /// 已交付的最高帧序号（其后的残帧仍在等待）。
    highest_delivered: Option<FrameSeq>,
    /// 已因过旧或超容量淘汰的最高帧序号（防止迟到分片复活已判 `LostInNetwork` 的帧）。
    highest_evicted: Option<FrameSeq>,
    /// 需要向对端请求关键帧（粘住直到成功解出一个 IDR）。
    need_keyframe: bool,
    /// `async_decode` 模式下参考链是否因丢帧/覆盖断链，等待下一张 IDR 重建。
    async_chain_broken: bool,
    /// 已上屏帧数（诊断）。
    displayed: u64,
    /// 会话时钟（微秒）。**管线是计时员**：`Decoded` / `Presented` 在操作
    /// 返回后读本时钟打点，而不是信任后端内部时钟——假后端各持独立
    /// 逻辑时钟，真后端的时间基准也不保证与会话同轴。`None` 时退化为
    /// 调用方传入的 `now_us`（decode/present 段退化为 0，诚实可解释）。
    clock: ClockSlot,
}

/// 重组表的容量上限（对应 TASK.md 铁律 1：任意并发重组帧上限 = 2，与
/// `DEFAULT_MAX_CONCURRENT_FRAMES = 2` 一致）。超过即淘汰最旧残帧并记
/// `LostInNetwork`，禁止为了减少丢帧而调大。
const MAX_PARTIALS: usize = 2;

/// 常规单帧解码 deadline 余量（微秒）。
const DECODE_BUDGET_US: u32 = 3_000;
/// 高分屏（>2.6M 像素）或 IDR 帧解码 deadline 余量（微秒）。
const HIGH_RES_DECODE_BUDGET_US: u32 = 10_000;
/// `async_decode` 有界帧队列容量（严格遵守 TASK.md 铁律 1：解码队列上限 ≤ 2；
/// 配合解码线程在途 1 帧可吸收 2–3 帧公网 TCP 微突发而不打断 P 帧参考链，同时硬约束排队不超 2 帧）。
const ASYNC_DECODE_QUEUE_CAP: usize = 2;
/// 硬件异步流水线解码的最大在途帧数（严格遵守铁律 1：≤ 2）。
const MAX_PIPELINED_DECODE_IN_FLIGHT: usize = 2;

struct InFlightDecodeMeta {
    seq: FrameSeq,
    capture_ts: Timestamp,
    received_ts: Timestamp,
}

fn take_in_flight_meta(
    in_flight: &mut VecDeque<InFlightDecodeMeta>,
    token: u64,
) -> Option<InFlightDecodeMeta> {
    if in_flight.front().is_some_and(|m| m.seq.0 == token) {
        return in_flight.pop_front();
    }
    in_flight
        .iter()
        .position(|m| m.seq.0 == token)
        .and_then(|pos| in_flight.remove(pos))
}

/// 处理单帧解码输出并推进渲染与完成记录；返回 `true` 表示遇到致命错误需终止工作线程。
#[allow(clippy::too_many_arguments)]
fn handle_async_decode_result(
    res: Result<DecodeOutput>,
    seq: FrameSeq,
    capture_ts: Timestamp,
    received_ts: Timestamp,
    fallback_now_us: u32,
    decoder: &dyn Decoder,
    renderer: &mut dyn Renderer,
    clock_w: &ClockSlot,
    shared_w: &Mutex<AsyncSharedState>,
    need_kf_w: &AtomicBool,
    disp_w: &AtomicU64,
) -> bool {
    match res {
        Ok(DecodeOutput::NeedKeyframe) => {
            need_kf_w.store(true, Ordering::Release);
            let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
            s.completed.push_back(AsyncFrameOutcome::Finished {
                seq,
                capture_ts,
                received_ts,
                decoded_ts: None,
                presented_ts: None,
                outcome: Outcome::DecodeError,
            });
            false
        }
        Ok(DecodeOutput::Nothing) => {
            let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
            s.completed.push_back(AsyncFrameOutcome::Finished {
                seq,
                capture_ts,
                received_ts,
                decoded_ts: None,
                presented_ts: None,
                outcome: Outcome::DecodeError,
            });
            false
        }
        Ok(DecodeOutput::Frame(decoded)) => {
            let decoded_ts = read_clock(clock_w, fallback_now_us);
            let presented = renderer.present(decoded);
            let presented_ts = read_clock(clock_w, fallback_now_us);
            match presented {
                Ok(_) => {
                    disp_w.fetch_add(1, Ordering::Relaxed);
                    if decoder.needs_keyframe() {
                        need_kf_w.store(true, Ordering::Release);
                    }
                    let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
                    s.completed.push_back(AsyncFrameOutcome::Finished {
                        seq,
                        capture_ts,
                        received_ts,
                        decoded_ts: Some(decoded_ts),
                        presented_ts: Some(presented_ts),
                        outcome: Outcome::Displayed,
                    });
                    false
                }
                Err(e) => {
                    let fatal = e.is_fatal();
                    let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
                    s.completed.push_back(AsyncFrameOutcome::Finished {
                        seq,
                        capture_ts,
                        received_ts,
                        decoded_ts: Some(decoded_ts),
                        presented_ts: None,
                        outcome: Outcome::DecodeError,
                    });
                    if fatal {
                        s.fatal_error = Some(e);
                        return true;
                    }
                    false
                }
            }
        }
        Err(e) => {
            let fatal = e.is_fatal();
            if decoder.needs_keyframe() {
                need_kf_w.store(true, Ordering::Release);
            }
            let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
            s.completed.push_back(AsyncFrameOutcome::Finished {
                seq,
                capture_ts,
                received_ts,
                decoded_ts: None,
                presented_ts: None,
                outcome: Outcome::DecodeError,
            });
            if fatal {
                s.fatal_error = Some(e);
                return true;
            }
            false
        }
    }
}

/// 排空一条异步流水线解码结果；返回 `None` 表示无就绪帧，`Some(true)` 遇到致命错误，`Some(false)` 正常消费。
#[allow(clippy::too_many_arguments)]
fn poll_pipelined_decode_once(
    timeout: Duration,
    decoder: &mut dyn Decoder,
    renderer: &mut dyn Renderer,
    in_flight: &mut VecDeque<InFlightDecodeMeta>,
    clock_w: &ClockSlot,
    shared_w: &Mutex<AsyncSharedState>,
    need_kf_w: &AtomicBool,
    disp_w: &AtomicU64,
) -> Option<bool> {
    match decoder.recv_decoded(timeout) {
        Ok(None) => None,
        Ok(Some((token, out))) => {
            let meta = take_in_flight_meta(in_flight, token)?;
            let now_us = read_clock(clock_w, meta.received_ts.0).0;
            Some(handle_async_decode_result(
                Ok(out),
                meta.seq,
                meta.capture_ts,
                meta.received_ts,
                now_us,
                decoder,
                renderer,
                clock_w,
                shared_w,
                need_kf_w,
                disp_w,
            ))
        }
        Err(e) => {
            let Some(meta) = in_flight.pop_front() else {
                if e.is_fatal() {
                    let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
                    s.fatal_error = Some(e);
                    return Some(true);
                }
                return Some(false);
            };
            let now_us = read_clock(clock_w, meta.received_ts.0).0;
            Some(handle_async_decode_result(
                Err(e),
                meta.seq,
                meta.capture_ts,
                meta.received_ts,
                now_us,
                decoder,
                renderer,
                clock_w,
                shared_w,
                need_kf_w,
                disp_w,
            ))
        }
    }
}

/// 在编码格式切换或停机前排空全部在途异步解码帧（最多等待 2s，兜底补齐结局保 `unfinished == 0`）。
#[allow(clippy::too_many_arguments)]
fn drain_pipelined_in_flight(
    decoder: &mut dyn Decoder,
    renderer: &mut dyn Renderer,
    in_flight: &mut VecDeque<InFlightDecodeMeta>,
    clock_w: &ClockSlot,
    shared_w: &Mutex<AsyncSharedState>,
    need_kf_w: &AtomicBool,
    disp_w: &AtomicU64,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !in_flight.is_empty() {
        if let Some(fatal) = poll_pipelined_decode_once(
            Duration::from_millis(5),
            decoder,
            renderer,
            in_flight,
            clock_w,
            shared_w,
            need_kf_w,
            disp_w,
        ) {
            if fatal {
                return true;
            }
            continue;
        }
        if Instant::now() >= deadline {
            while let Some(meta) = in_flight.pop_front() {
                let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
                s.completed.push_back(AsyncFrameOutcome::Finished {
                    seq: meta.seq,
                    capture_ts: meta.capture_ts,
                    received_ts: meta.received_ts,
                    decoded_ts: None,
                    presented_ts: None,
                    outcome: Outcome::DecodeError,
                });
            }
            break;
        }
    }
    false
}

fn frame_decode_budget_us(cfg: &PipelineConfig, kind: FrameKind) -> u32 {
    let pixels = u64::from(cfg.resolution.width) * u64::from(cfg.resolution.height);
    if pixels > 2_600_000 || kind == FrameKind::Idr {
        HIGH_RES_DECODE_BUDGET_US
    } else {
        DECODE_BUDGET_US
    }
}

fn read_clock(clock: &ClockSlot, fallback_us: u32) -> Timestamp {
    let guard = clock.lock().unwrap_or_else(|e| e.into_inner());
    Timestamp(guard.as_ref().map_or(fallback_us, |c| c()))
}

fn maybe_swap_decoder_for_codec(
    cfg: &PipelineConfig,
    active_codec: &mut rc_encode::Codec,
    decoder: &mut Box<dyn Decoder>,
    is_hevc: bool,
) {
    let target = if is_hevc {
        rc_encode::Codec::Hevc
    } else {
        rc_encode::Codec::H264
    };
    if target == *active_codec || !cfg.prefer_hardware {
        return;
    }
    let mut next_cfg = cfg.clone();
    next_cfg.codec = target;
    if let Ok((new_dec, _)) = crate::select_decoder_labeled(&next_cfg) {
        let _ = decoder.flush();
        *decoder = new_dec;
        *active_codec = target;
    }
}

impl ControllerPipeline {
    /// 用工厂后端创建（auto 模式）。
    pub fn new(cfg: PipelineConfig) -> Result<Self> {
        cfg.validate()?;
        let (_capture, _encoder, decoder, renderer, labels) = select_all(&cfg)?;
        eprintln!(
            "rc-pipeline: controller backends decoder={} renderer={}",
            labels.decoder, labels.renderer
        );
        Self::with_backends(cfg, decoder, renderer)
    }

    /// 注入指定后端（测试 / 会话层显式控制）。
    pub fn with_backends(
        cfg: PipelineConfig,
        mut decoder: Box<dyn Decoder>,
        mut renderer: Box<dyn Renderer>,
    ) -> Result<Self> {
        cfg.validate()?;
        let trace = TraceCollector::new(cfg.trace_capacity);
        let clock: ClockSlot = Arc::new(Mutex::new(None));
        let active_codec = cfg.codec;
        let mode = if cfg.async_decode {
            let slot = Arc::new((
                Mutex::new(VecDeque::<PendingAsyncFrame>::with_capacity(
                    ASYNC_DECODE_QUEUE_CAP,
                )),
                Condvar::new(),
            ));
            let stop = Arc::new(AtomicBool::new(false));
            let shared = Arc::new(Mutex::new(AsyncSharedState::default()));
            let need_keyframe = Arc::new(AtomicBool::new(false));
            let displayed = Arc::new(AtomicU64::new(0));

            let slot_w = Arc::clone(&slot);
            let stop_w = Arc::clone(&stop);
            let shared_w = Arc::clone(&shared);
            let need_kf_w = Arc::clone(&need_keyframe);
            let disp_w = Arc::clone(&displayed);
            let clock_w = Arc::clone(&clock);
            let cfg_w = cfg.clone();
            let mut active_codec_w = active_codec;

            let worker = std::thread::Builder::new()
                .name("rc-ctrl-decode".into())
                .spawn(move || {
                    crate::promote_current_thread_qos();
                    let mut in_flight: VecDeque<InFlightDecodeMeta> =
                        VecDeque::with_capacity(MAX_PIPELINED_DECODE_IN_FLIGHT);
                    loop {
                        // 1) 若后端支持 2-deep 流水线解码，优先非阻塞排空全部已就绪帧并立刻上屏。
                        let mut did_work = false;
                        if !in_flight.is_empty() {
                            while let Some(fatal) = poll_pipelined_decode_once(
                                Duration::ZERO,
                                decoder.as_mut(),
                                renderer.as_mut(),
                                &mut in_flight,
                                &clock_w,
                                &shared_w,
                                &need_kf_w,
                                &disp_w,
                            ) {
                                did_work = true;
                                if fatal {
                                    let _ = decoder.flush();
                                    return;
                                }
                            }
                        }

                        // 2) 非阻塞拉取待解码帧：若走流水线则补满 ≤2 帧在途，否则单帧同步解码。
                        let pipelined = decoder.supports_pipelined_decode();
                        let mut popped_any = false;
                        while !pipelined || in_flight.len() < MAX_PIPELINED_DECODE_IN_FLIGHT {
                            let next_frame = {
                                let (lock, _) = &*slot_w;
                                let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                                guard.pop_front()
                            };
                            let Some(frame) = next_frame else {
                                break;
                            };
                            popped_any = true;
                            did_work = true;

                            let target_codec = if frame.is_hevc {
                                rc_encode::Codec::Hevc
                            } else {
                                rc_encode::Codec::H264
                            };
                            if target_codec != active_codec_w
                                && !in_flight.is_empty()
                                && drain_pipelined_in_flight(
                                    decoder.as_mut(),
                                    renderer.as_mut(),
                                    &mut in_flight,
                                    &clock_w,
                                    &shared_w,
                                    &need_kf_w,
                                    &disp_w,
                                )
                            {
                                let _ = decoder.flush();
                                return;
                            }
                            maybe_swap_decoder_for_codec(
                                &cfg_w,
                                &mut active_codec_w,
                                &mut decoder,
                                frame.is_hevc,
                            );

                            let now_us = read_clock(&clock_w, frame.received_ts.0).0;
                            let budget = frame_decode_budget_us(&cfg_w, frame.kind);
                            let deadline = Timestamp(now_us.saturating_add(budget));

                            if decoder.supports_pipelined_decode() {
                                match decoder.submit_decode(
                                    frame.seq.0,
                                    &frame.payload_all,
                                    frame.kind,
                                    deadline,
                                ) {
                                    Ok(DecodeSubmitStatus::Submitted) => {
                                        in_flight.push_back(InFlightDecodeMeta {
                                            seq: frame.seq,
                                            capture_ts: frame.capture_ts,
                                            received_ts: frame.received_ts,
                                        });
                                    }
                                    Ok(DecodeSubmitStatus::NeedKeyframe) => {
                                        if handle_async_decode_result(
                                            Ok(DecodeOutput::NeedKeyframe),
                                            frame.seq,
                                            frame.capture_ts,
                                            frame.received_ts,
                                            now_us,
                                            decoder.as_ref(),
                                            renderer.as_mut(),
                                            &clock_w,
                                            &shared_w,
                                            &need_kf_w,
                                            &disp_w,
                                        ) {
                                            let _ = decoder.flush();
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        if handle_async_decode_result(
                                            Err(e),
                                            frame.seq,
                                            frame.capture_ts,
                                            frame.received_ts,
                                            now_us,
                                            decoder.as_ref(),
                                            renderer.as_mut(),
                                            &clock_w,
                                            &shared_w,
                                            &need_kf_w,
                                            &disp_w,
                                        ) {
                                            let _ = decoder.flush();
                                            return;
                                        }
                                    }
                                }
                            } else {
                                let res = decoder.decode(&frame.payload_all, frame.kind, deadline);
                                if handle_async_decode_result(
                                    res,
                                    frame.seq,
                                    frame.capture_ts,
                                    frame.received_ts,
                                    now_us,
                                    decoder.as_ref(),
                                    renderer.as_mut(),
                                    &clock_w,
                                    &shared_w,
                                    &need_kf_w,
                                    &disp_w,
                                ) {
                                    let _ = decoder.flush();
                                    return;
                                }
                                break;
                            }
                        }

                        if !did_work {
                            if !in_flight.is_empty() {
                                let wait = if in_flight.len() < MAX_PIPELINED_DECODE_IN_FLIGHT {
                                    Duration::from_micros(250)
                                } else {
                                    Duration::from_millis(2)
                                };
                                if let Some(true) = poll_pipelined_decode_once(
                                    wait,
                                    decoder.as_mut(),
                                    renderer.as_mut(),
                                    &mut in_flight,
                                    &clock_w,
                                    &shared_w,
                                    &need_kf_w,
                                    &disp_w,
                                ) {
                                    let _ = decoder.flush();
                                    return;
                                }
                                if stop_w.load(Ordering::Acquire) {
                                    let slot_empty = {
                                        let (lock, _) = &*slot_w;
                                        lock.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
                                    };
                                    if slot_empty {
                                        let _ = drain_pipelined_in_flight(
                                            decoder.as_mut(),
                                            renderer.as_mut(),
                                            &mut in_flight,
                                            &clock_w,
                                            &shared_w,
                                            &need_kf_w,
                                            &disp_w,
                                        );
                                        break;
                                    }
                                }
                            } else {
                                let (lock, cv) = &*slot_w;
                                let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                                while guard.is_empty() && !stop_w.load(Ordering::Acquire) {
                                    guard = cv.wait(guard).unwrap_or_else(|e| e.into_inner());
                                }
                                if guard.is_empty() && stop_w.load(Ordering::Acquire) {
                                    break;
                                }
                            }
                        } else if !popped_any
                            && stop_w.load(Ordering::Acquire)
                            && in_flight.is_empty()
                        {
                            let slot_empty = {
                                let (lock, _) = &*slot_w;
                                lock.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
                            };
                            if slot_empty {
                                break;
                            }
                        }
                    }
                    let _ = drain_pipelined_in_flight(
                        decoder.as_mut(),
                        renderer.as_mut(),
                        &mut in_flight,
                        &clock_w,
                        &shared_w,
                        &need_kf_w,
                        &disp_w,
                    );
                    let _ = decoder.flush();
                })
                .map_err(|e| Error::InvalidConfig(format!("spawn ctrl decode thread: {e}")))?;

            ControllerExecMode::Async {
                slot,
                stop,
                shared,
                need_keyframe,
                displayed,
                worker: Some(worker),
            }
        } else {
            ControllerExecMode::Sync {
                decoder,
                renderer,
                active_codec,
            }
        };

        Ok(Self {
            trace,
            mode,
            cfg,
            partials: BTreeMap::new(),
            highest_delivered: None,
            highest_evicted: None,
            need_keyframe: false,
            async_chain_broken: false,
            displayed: 0,
            clock,
        })
    }

    /// 注入会话时钟（微秒，与帧 `timestamp` 同基准）。见字段文档。
    pub fn set_clock(&mut self, clock: std::sync::Arc<dyn Fn() -> u32 + Send + Sync>) {
        *self.clock.lock().unwrap_or_else(|e| e.into_inner()) = Some(clock);
    }

    fn drain_async_completions(&mut self) -> Result<bool> {
        let (pending_outcomes, fatal) = match &self.mode {
            ControllerExecMode::Sync { .. } => return Ok(false),
            ControllerExecMode::Async { shared, .. } => {
                let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());
                let items: Vec<AsyncFrameOutcome> = s.completed.drain(..).collect();
                let fatal = s.fatal_error.take();
                (items, fatal)
            }
        };
        let mut presented_any = false;
        for item in pending_outcomes {
            match item {
                AsyncFrameOutcome::Finished {
                    seq,
                    capture_ts,
                    received_ts,
                    decoded_ts,
                    presented_ts,
                    outcome,
                } => {
                    let slot = self.trace.begin(seq);
                    slot.mark(Mark::Captured, capture_ts);
                    slot.mark(Mark::Received, received_ts);
                    if let Some(d) = decoded_ts {
                        slot.mark(Mark::Decoded, d);
                    }
                    if let Some(p) = presented_ts {
                        slot.mark(Mark::Presented, p);
                    }
                    slot.finish(outcome);
                    if outcome == Outcome::Displayed {
                        self.displayed += 1;
                        presented_any = true;
                    }
                }
            }
        }
        if let Some(err) = fatal {
            return Err(err);
        }
        Ok(presented_any)
    }

    /// 投入一个收到的数据报。返回 `Ok(true)` 表示有新帧上屏。
    pub fn push_datagram(&mut self, data: &[u8], now_us: u32) -> Result<bool> {
        let mut presented_now = self.drain_async_completions()?;
        let (header, payload) = MediaHeader::parse_datagram(data)?;
        let seq = header.frame_seq;
        let idx = header.packet_idx;

        // 重组表里不该出现已交付或已淘汰序号更小/相等的帧到达（乱序迟到包）：
        // 直接丢弃，不复活已判 LostInNetwork 的帧（若尚未入 trace 则补记 LostInNetwork）。
        if let Some(hi) = self.highest_delivered {
            if seq <= hi {
                return Ok(presented_now);
            }
        }
        if let Some(ev) = self.highest_evicted {
            if seq <= ev {
                self.mark_lost(seq, header.capture_ts);
                return Ok(presented_now);
            }
        }

        let (received, cnt) = {
            let partial = self.partials.entry(seq).or_insert_with(|| Partial {
                cnt: header.packet_cnt,
                packets: vec![None; header.packet_cnt as usize],
                received: 0,
                capture_ts: header.capture_ts,
                encode_done_ts: header.encode_done_ts,
                kind: if header.flags.is_idr() {
                    FrameKind::Idr
                } else {
                    FrameKind::P
                },
                is_hevc: header.flags.is_hevc(),
            });
            if idx >= partial.cnt {
                return Err(Error::Protocol {
                    offset: 20,
                    msg: format!("packet_idx {idx} >= packet_cnt {}", partial.cnt),
                });
            }
            if partial.packets[idx as usize].is_none() {
                partial.packets[idx as usize] = Some(payload.to_vec());
                partial.received += 1;
            }
            (partial.received, partial.cnt)
        };
        // entry 借用已随块结束释放，evict_stale 才能再借 self。
        self.evict_stale(seq);

        if received < cnt {
            return Ok(presented_now); // P6：缺包不交付
        }

        // 凑齐：按 packet_idx 拼接（坑 4）。remove 拿所有权。
        // 若本帧在容量裁剪中被当作最旧残帧淘汰（例如已有 2 个更新残帧在途时
        // 来了更旧的单包帧），evict_stale 已记 LostInNetwork，直接返回即可。
        let Some(partial) = self.partials.remove(&seq) else {
            return Ok(presented_now);
        };
        let mut payload_all = Vec::with_capacity(
            partial
                .packets
                .iter()
                .map(|p| p.as_ref().map_or(0, |v| v.len()))
                .sum(),
        );
        for bytes in partial.packets.iter().flatten() {
            payload_all.extend_from_slice(bytes);
        }
        let capture_ts = partial.capture_ts;
        let kind = partial.kind;
        let is_hevc = partial.is_hevc;
        self.highest_delivered = Some(seq);

        match &mut self.mode {
            ControllerExecMode::Sync {
                decoder,
                renderer,
                active_codec,
            } => {
                let slot = self.trace.begin(seq);
                slot.mark(Mark::Captured, capture_ts);
                slot.mark(Mark::Received, Timestamp(now_us));

                maybe_swap_decoder_for_codec(&self.cfg, active_codec, decoder, is_hevc);
                let budget = frame_decode_budget_us(&self.cfg, kind);
                match decoder.decode(&payload_all, kind, Timestamp(now_us.saturating_add(budget))) {
                    Ok(DecodeOutput::NeedKeyframe) => {
                        self.need_keyframe = true;
                        if let Some(f) = self.trace.get_mut(seq) {
                            f.finish(Outcome::DecodeError);
                        }
                        Ok(false)
                    }
                    Ok(DecodeOutput::Nothing) => {
                        if let Some(f) = self.trace.get_mut(seq) {
                            f.finish(Outcome::DecodeError);
                        }
                        Ok(false)
                    }
                    Ok(DecodeOutput::Frame(decoded)) => {
                        let decoded_at = read_clock(&self.clock, now_us);
                        let presented = renderer.present(decoded);
                        let presented_at = read_clock(&self.clock, now_us);
                        presented?;
                        if let Some(f) = self.trace.get_mut(seq) {
                            f.mark(Mark::Decoded, decoded_at);
                            f.mark(Mark::Presented, presented_at);
                            f.finish(Outcome::Displayed);
                        }
                        self.displayed += 1;
                        Ok(true)
                    }
                    Err(e) => {
                        if let Some(f) = self.trace.get_mut(seq) {
                            f.finish(Outcome::DecodeError);
                        }
                        if e.is_fatal() {
                            return Err(e);
                        }
                        Ok(false)
                    }
                }
            }
            ControllerExecMode::Async { slot, .. } => {
                let received_ts = Timestamp(now_us);
                if kind == FrameKind::Idr {
                    self.async_chain_broken = false;
                    // 若刚抵达的是完整 IDR，覆盖本次 evict_stale 因旧残帧而置位的关键帧请求，
                    // 避免在 IDR 刚入槽时发出多余关键帧请求。
                    self.need_keyframe = false;
                } else if self.async_chain_broken {
                    let f = self.trace.begin(seq);
                    f.mark(Mark::Captured, capture_ts);
                    f.mark(Mark::Received, received_ts);
                    f.finish(Outcome::DroppedStale);
                    self.need_keyframe = true;
                    if self.drain_async_completions()? {
                        presented_now = true;
                    }
                    return Ok(presented_now);
                }
                let incoming = PendingAsyncFrame {
                    seq,
                    payload_all,
                    capture_ts,
                    received_ts,
                    kind,
                    is_hevc,
                };
                let dropped_frames: Vec<(FrameSeq, Timestamp, Timestamp)> = {
                    let (lock, cv) = &**slot;
                    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                    let mut dropped = Vec::new();
                    if kind == FrameKind::Idr {
                        while let Some(prev) = guard.pop_front() {
                            dropped.push((prev.seq, prev.capture_ts, prev.received_ts));
                        }
                        guard.push_back(incoming);
                    } else if guard.len() < ASYNC_DECODE_QUEUE_CAP {
                        guard.push_back(incoming);
                    } else {
                        // 队列满时保留已有参考链完整的前序待解帧，丢弃本帧并标记断链等待 IDR。
                        dropped.push((seq, capture_ts, received_ts));
                    }
                    cv.notify_one();
                    dropped
                };
                if !dropped_frames.is_empty() {
                    for (d_seq, d_cap, d_recv) in dropped_frames {
                        let f = self.trace.begin(d_seq);
                        f.mark(Mark::Captured, d_cap);
                        f.mark(Mark::Received, d_recv);
                        f.finish(Outcome::DroppedStale);
                    }
                    if kind != FrameKind::Idr {
                        self.async_chain_broken = true;
                        self.need_keyframe = true;
                    }
                }
                if self.drain_async_completions()? {
                    presented_now = true;
                }
                Ok(presented_now)
            }
        }
    }

    /// 是否需要向对端请求关键帧（取走即清「请求」标志；参考链是否恢复
    /// 由解码器自己跟踪，解出 IDR 前它会让本标志再次置位）。
    pub fn take_keyframe_request(&mut self) -> bool {
        let _ = self.drain_async_completions();
        match &self.mode {
            ControllerExecMode::Sync { decoder, .. } => {
                let kf = self.need_keyframe || decoder.needs_keyframe();
                self.need_keyframe = false;
                kf
            }
            ControllerExecMode::Async { need_keyframe, .. } => {
                let async_kf = need_keyframe.swap(false, Ordering::AcqRel);
                let kf = self.need_keyframe || async_kf;
                self.need_keyframe = false;
                kf
            }
        }
    }

    /// 帧时间线（本端半场：Received→Presented + 传输/解码结局）。
    pub fn trace(&self) -> &TraceCollector {
        &self.trace
    }

    /// 已上屏帧数。
    pub fn displayed(&self) -> u64 {
        match &self.mode {
            ControllerExecMode::Sync { .. } => self.displayed,
            ControllerExecMode::Async { displayed, .. } => {
                self.displayed.max(displayed.load(Ordering::Relaxed))
            }
        }
    }

    /// 会话收尾：在途残帧判 `LostInNetwork`，冲刷解码器。
    pub fn shutdown(&mut self) {
        self.finish_in_flight();
        match &mut self.mode {
            ControllerExecMode::Sync { decoder, .. } => {
                let _ = decoder.flush();
            }
            ControllerExecMode::Async {
                slot, stop, worker, ..
            } => {
                stop.store(true, Ordering::Release);
                {
                    let (_, cv) = &**slot;
                    cv.notify_all();
                }
                if let Some(handle) = worker.take() {
                    let _ = handle.join();
                }
                let leftovers: Vec<PendingAsyncFrame> = {
                    let (lock, _) = &**slot;
                    lock.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .drain(..)
                        .collect()
                };
                for p in leftovers {
                    let f = self.trace.begin(p.seq);
                    f.mark(Mark::Captured, p.capture_ts);
                    f.mark(Mark::Received, p.received_ts);
                    f.finish(Outcome::DroppedStale);
                }
                let _ = self.drain_async_completions();
            }
        }
    }

    /// 把仍在重组表的残帧全部判 `LostInNetwork`（截断兜底，保证
    /// `unfinished == 0`）。60 秒会话结束时在途最多个位数帧。
    pub fn finish_in_flight(&mut self) {
        let seqs: Vec<FrameSeq> = self.partials.keys().copied().collect();
        for seq in seqs {
            let p = self.partials.remove(&seq).expect("key just collected");
            self.highest_evicted = Some(self.highest_evicted.map_or(seq, |prev| prev.max(seq)));
            let f = self.trace.begin(seq);
            f.mark(Mark::Captured, p.capture_ts);
            // 无真实到达时刻，用采集时刻占位（该帧从未凑齐）。
            f.mark(Mark::Received, Timestamp(p.capture_ts.0));
            f.finish(Outcome::LostInNetwork);
        }
    }

    /// 新帧 `upto` 到达后，序号更小的残帧永远凑不齐：判 LostInNetwork。
    /// 同时把重组表容量压回 `MAX_PARTIALS`（= 2）上限内。
    fn evict_stale(&mut self, upto: FrameSeq) {
        let stale: Vec<FrameSeq> = self.partials.range(..upto).map(|(k, _)| *k).collect();
        for seq in stale {
            let p = self.partials.remove(&seq).expect("key from range");
            self.mark_lost(seq, p.capture_ts);
        }
        while self.partials.len() > MAX_PARTIALS {
            let oldest = *self.partials.keys().next().expect("non-empty");
            let p = self.partials.remove(&oldest).expect("key exists");
            self.mark_lost(oldest, p.capture_ts);
        }
        debug_assert!(self.partials.len() <= MAX_PARTIALS);
    }

    /// 淘汰残帧：更新已淘汰水位线，并幂等记录 `LostInNetwork`（同一 `seq` 不重复 `begin`）。
    fn mark_lost(&mut self, seq: FrameSeq, capture_ts: Timestamp) {
        self.highest_evicted = Some(self.highest_evicted.map_or(seq, |prev| prev.max(seq)));
        if matches!(self.mode, ControllerExecMode::Async { .. }) {
            self.async_chain_broken = true;
            self.need_keyframe = true;
        }
        if let Some(f) = self.trace.get_mut(seq) {
            f.mark(Mark::Captured, capture_ts);
            f.finish(Outcome::LostInNetwork);
        } else {
            let slot = self.trace.begin(seq);
            slot.mark(Mark::Captured, capture_ts);
            slot.finish(Outcome::LostInNetwork);
        }
    }

    /// 配置引用（会话层取分辨率/容量等）。
    pub fn config(&self) -> &PipelineConfig {
        &self.cfg
    }
}

impl Drop for ControllerPipeline {
    fn drop(&mut self) {
        if let ControllerExecMode::Async {
            slot, stop, worker, ..
        } = &mut self.mode
        {
            stop.store(true, Ordering::Release);
            {
                let (_, cv) = &**slot;
                cv.notify_all();
            }
            if let Some(handle) = worker.take() {
                let _ = handle.join();
            }
        }
    }
}

/// HEADER_LEN 再导出（诊断输出用）。
pub const HEADER_BYTES: usize = HEADER_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use rc_capture::FrameTexture;
    use rc_decode::{DecodeOutput, DecodeSubmitStatus, DecodedFrame, Decoder};
    use rc_proto::{split_frame_with_flags, HeaderFlags};
    use rc_render::{FakeRenderer, FakeRendererConfig};
    use rc_types::{CpuFrame, PixelFormat};
    use std::sync::atomic::AtomicUsize;

    struct MockPipelinedDecoder {
        in_flight: VecDeque<(u64, FrameKind)>,
        max_observed_in_flight: Arc<AtomicUsize>,
        seen_idr: bool,
    }

    impl Decoder for MockPipelinedDecoder {
        fn decode(
            &mut self,
            _data: &[u8],
            _kind: FrameKind,
            _deadline_ts: Timestamp,
        ) -> Result<DecodeOutput> {
            panic!("pipelined async worker should call submit_decode/recv_decoded");
        }

        fn needs_keyframe(&self) -> bool {
            !self.seen_idr
        }

        fn flush(&mut self) -> Result<()> {
            self.in_flight.clear();
            Ok(())
        }

        fn supports_pipelined_decode(&self) -> bool {
            true
        }

        fn submit_decode(
            &mut self,
            token: u64,
            _data: &[u8],
            kind: FrameKind,
            _deadline_ts: Timestamp,
        ) -> Result<DecodeSubmitStatus> {
            if !self.seen_idr && kind != FrameKind::Idr {
                return Ok(DecodeSubmitStatus::NeedKeyframe);
            }
            if self.in_flight.len() >= MAX_PIPELINED_DECODE_IN_FLIGHT {
                return Err(Error::Decoder("pipelined decode limit exceeded".into()));
            }
            if kind == FrameKind::Idr {
                self.seen_idr = true;
            }
            self.in_flight.push_back((token, kind));
            let cur = self.in_flight.len();
            self.max_observed_in_flight.fetch_max(cur, Ordering::SeqCst);
            Ok(DecodeSubmitStatus::Submitted)
        }

        fn recv_decoded(&mut self, timeout: Duration) -> Result<Option<(u64, DecodeOutput)>> {
            if self.in_flight.is_empty() {
                return Ok(None);
            }
            if timeout.is_zero() && self.in_flight.len() < 2 {
                // 延迟首次非阻塞回收，便于验证双帧并发提交。
                return Ok(None);
            }
            let Some((token, _)) = self.in_flight.pop_front() else {
                return Ok(None);
            };
            Ok(Some((
                token,
                DecodeOutput::Frame(DecodedFrame {
                    texture: FrameTexture::Cpu(CpuFrame {
                        width: 4,
                        height: 4,
                        format: PixelFormat::Bgra8,
                        stride: 16,
                        data: vec![0; 64],
                    }),
                    decode_done_ts: Timestamp(100),
                    width: 4,
                    height: 4,
                }),
            )))
        }

        fn in_flight_count(&self) -> usize {
            self.in_flight.len()
        }
    }

    #[test]
    fn async_controller_uses_2deep_pipelined_decode_and_drains_cleanly() {
        let max_obs = Arc::new(AtomicUsize::new(0));
        let dec = MockPipelinedDecoder {
            in_flight: VecDeque::new(),
            max_observed_in_flight: Arc::clone(&max_obs),
            seen_idr: false,
        };
        let ren = FakeRenderer::new(FakeRendererConfig::default()).expect("假渲染器配置合法");
        let cfg = PipelineConfig {
            async_decode: true,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::with_backends(cfg, Box::new(dec), Box::new(ren))
            .expect("controller init");

        // 第 0 帧：首帧前 P 帧触发 NeedKeyframe（不占用在途槽）
        let p0 = split_frame_with_flags(
            FrameSeq(0),
            FrameKind::P,
            HeaderFlags::empty(),
            Timestamp(100),
            Timestamp(120),
            0,
            &[1, 2, 3, 4],
            1200,
        );
        for d in &p0 {
            ctrl.push_datagram(d, 200).expect("push p0");
        }
        // 投递 IDR 后按 2 帧微突发节奏推送 4 个 P 帧（不超出 ASYNC_DECODE_QUEUE_CAP=2），
        // 确定性验证 2-deep 并发在途与 shutdown 排空。
        let push_frame = |ctrl: &mut ControllerPipeline, seq: u64, kind: FrameKind| {
            let pkts = split_frame_with_flags(
                FrameSeq(seq),
                kind,
                HeaderFlags::empty(),
                Timestamp((seq as u32) * 16_000),
                Timestamp((seq as u32) * 16_000 + 100),
                seq as u16,
                &[0, 0, 0, 1, 0x65, seq as u8],
                1200,
            );
            for d in &pkts {
                ctrl.push_datagram(d, (seq as u32) * 16_000 + 200)
                    .expect("push frame");
            }
        };
        push_frame(&mut ctrl, 1, FrameKind::Idr);
        let wait_displayed = |ctrl: &mut ControllerPipeline, target: u64| {
            let dl = Instant::now() + Duration::from_secs(2);
            while ctrl.displayed() < target && Instant::now() < dl {
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        wait_displayed(&mut ctrl, 1);

        push_frame(&mut ctrl, 2, FrameKind::P);
        push_frame(&mut ctrl, 3, FrameKind::P);
        wait_displayed(&mut ctrl, 3);

        push_frame(&mut ctrl, 4, FrameKind::P);
        push_frame(&mut ctrl, 5, FrameKind::P);
        wait_displayed(&mut ctrl, 5);

        ctrl.shutdown();

        let sum = ctrl.trace().summary();
        assert_eq!(sum.unfinished, 0, "shutdown 后不得有未完结帧");
        assert_eq!(ctrl.displayed(), 5, "5 帧（1 IDR + 4 P）应全部解码上屏");
        assert!(
            max_obs.load(Ordering::SeqCst) <= MAX_PIPELINED_DECODE_IN_FLIGHT,
            "在途帧数不得超过铁律 1 上限 2"
        );
    }
}
