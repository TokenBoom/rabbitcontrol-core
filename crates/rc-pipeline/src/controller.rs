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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// 控制端热切解码器失败或收到无法解码的编解码器时向上层上报的结构化诊断事件。
///
/// 上层（如 `session_bridge`）通过 [`ControllerPipeline::take_decode_failure`] 消费后，
/// 立即向被控端发送 `DisplayControlMsg::CodecDecodeFailed` 触发熔断降级（如 `AV1 → HEVC → H.264`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecDecodeFailure {
    /// 失败的目标编解码器。
    pub codec: rc_encode::Codec,
    /// 人类可读的失败原因（来自硬件解码器构造错误或协议校验）。
    pub reason: String,
}

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
    codec: rc_encode::Codec,
}

type ClockSlot = Arc<Mutex<Option<Arc<dyn Fn() -> u32 + Send + Sync>>>>;
/// 控制端解码器热切工厂类型（输入目标 [`PipelineConfig`]，返回对应解码器实例或错误）。
pub type DecoderSwapFactory =
    Arc<dyn Fn(&PipelineConfig) -> Result<Box<dyn Decoder>> + Send + Sync>;
type DecoderSwapSlot = Arc<Mutex<Option<DecoderSwapFactory>>>;

struct PendingAsyncFrame {
    seq: FrameSeq,
    payload_all: Vec<u8>,
    capture_ts: Timestamp,
    received_ts: Timestamp,
    kind: FrameKind,
    codec: rc_encode::Codec,
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
    decode_failures: VecDeque<CodecDecodeFailure>,
    fatal_error: Option<Error>,
}

const fn encode_failed_codec_u8(codec: Option<rc_encode::Codec>) -> u8 {
    match codec {
        None => 0,
        Some(rc_encode::Codec::H264) => 1,
        Some(rc_encode::Codec::Hevc) => 2,
        Some(rc_encode::Codec::Av1) => 3,
    }
}

const fn decode_failed_codec_u8(code: u8) -> Option<rc_encode::Codec> {
    match code {
        1 => Some(rc_encode::Codec::H264),
        2 => Some(rc_encode::Codec::Hevc),
        3 => Some(rc_encode::Codec::Av1),
        _ => None,
    }
}

enum ControllerExecMode {
    Sync {
        decoder: Box<dyn Decoder>,
        renderer: Box<dyn Renderer>,
        active_codec: rc_encode::Codec,
        failed_codec: Option<rc_encode::Codec>,
    },
    Async {
        slot: Arc<(Mutex<VecDeque<PendingAsyncFrame>>, Condvar)>,
        stop: Arc<AtomicBool>,
        shared: Arc<Mutex<AsyncSharedState>>,
        need_keyframe: Arc<AtomicBool>,
        /// 当前被抑制的失败编解码器编码（`0=None, 1=H264, 2=Hevc, 3=Av1`）。
        /// 主线程收到任意 `codec != failed_codec` 的降级帧（含首 IDR 丢包后的 P 帧）时立即清零，
        /// 解除对 [`ControllerPipeline::take_keyframe_request`] 的抑制，杜绝断链死锁黑屏。
        failed_codec_code: Arc<AtomicU8>,
        displayed: Arc<AtomicU64>,
        in_flight_len: Arc<AtomicUsize>,
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
    /// 待上层通过 [`Self::take_decode_failure`] 消费的编解码切换失败事件队列。
    pending_decode_failures: VecDeque<CodecDecodeFailure>,
    /// 可选自定义解码器热切工厂（离线测试注入；生产路径默认为 `None`，走平台严格硬件解码器工厂）。
    swap_factory: DecoderSwapSlot,
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
/// 配合解码线程在途帧可吸收公网 TCP 微突发而不打断 P 帧参考链，同时硬约束排队不超 2 帧）。
const ASYNC_DECODE_QUEUE_CAP: usize = 2;
/// 硬件异步流水线解码的最大在途帧数（严格遵守铁律 1：≤ 2）。
const MAX_PIPELINED_DECODE_IN_FLIGHT: usize = 2;
/// 解码段总深度硬上限（`slot` 待解 + 硬件在途 ≤ 3，避免 2+2=4 帧堆积违背低延迟红线）。
const ASYNC_DECODE_TOTAL_CAP: usize = 3;
/// 停机 / 切码时排空异步在途帧的最长墙钟等待。
const PIPELINED_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

struct InFlightDecodeMeta {
    seq: FrameSeq,
    capture_ts: Timestamp,
    received_ts: Timestamp,
}

fn take_in_flight_meta(
    in_flight: &mut VecDeque<InFlightDecodeMeta>,
    in_flight_len_w: &AtomicUsize,
    held_frames: usize,
    token: u64,
) -> Option<InFlightDecodeMeta> {
    let item = if in_flight.front().is_some_and(|m| m.seq.0 == token) {
        in_flight.pop_front()
    } else {
        in_flight
            .iter()
            .position(|m| m.seq.0 == token)
            .and_then(|pos| in_flight.remove(pos))
    };
    if item.is_some() {
        in_flight_len_w.store(in_flight.len() + held_frames, Ordering::Release);
    }
    item
}

fn push_in_flight_meta(
    in_flight: &mut VecDeque<InFlightDecodeMeta>,
    in_flight_len_w: &AtomicUsize,
    meta: InFlightDecodeMeta,
) {
    in_flight.push_back(meta);
    in_flight_len_w.store(in_flight.len(), Ordering::Release);
}

/// 将 `in_flight` 中剩余全部帧以 `Outcome::DecodeError` 结案，确保 P4（`unfinished == 0`）。
fn fail_remaining_in_flight(
    in_flight: &mut VecDeque<InFlightDecodeMeta>,
    in_flight_len_w: &AtomicUsize,
    held_frames: usize,
    shared_w: &Mutex<AsyncSharedState>,
) {
    if in_flight.is_empty() {
        in_flight_len_w.store(held_frames, Ordering::Release);
        return;
    }
    let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
    while let Some(meta) = in_flight.pop_front() {
        s.completed.push_back(AsyncFrameOutcome::Finished {
            seq: meta.seq,
            capture_ts: meta.capture_ts,
            received_ts: meta.received_ts,
            decoded_ts: None,
            presented_ts: None,
            outcome: Outcome::DecodeError,
        });
    }
    in_flight_len_w.store(held_frames, Ordering::Release);
}

fn finish_aborted_frame(frame: &PendingAsyncFrame, shared_w: &Mutex<AsyncSharedState>) {
    let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
    s.completed.push_back(AsyncFrameOutcome::Finished {
        seq: frame.seq,
        capture_ts: frame.capture_ts,
        received_ts: frame.received_ts,
        decoded_ts: None,
        presented_ts: None,
        outcome: Outcome::DecodeError,
    });
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

/// 排空一条异步流水线解码结果；返回 `None` 表示无就绪帧，`Some(true)` 遇到致命错误，`Some(false)` 正常消费或已回收孤儿项。
#[allow(clippy::too_many_arguments)]
fn poll_pipelined_decode_once(
    timeout: Duration,
    decoder: &mut dyn Decoder,
    renderer: &mut dyn Renderer,
    in_flight: &mut VecDeque<InFlightDecodeMeta>,
    in_flight_len_w: &AtomicUsize,
    held_frames: usize,
    clock_w: &ClockSlot,
    shared_w: &Mutex<AsyncSharedState>,
    need_kf_w: &AtomicBool,
    disp_w: &AtomicU64,
) -> Option<bool> {
    match decoder.recv_decoded(timeout) {
        Ok(None) => {
            if !in_flight.is_empty() && decoder.in_flight_count() == 0 {
                // 底层解码器已无任何在途帧但上层仍记录在途：回收孤儿项防止 100% CPU 空转与永久死锁。
                fail_remaining_in_flight(in_flight, in_flight_len_w, held_frames, shared_w);
                need_kf_w.store(true, Ordering::Release);
                return Some(false);
            }
            None
        }
        Ok(Some((token, frame_res))) => {
            let Some(meta) = take_in_flight_meta(in_flight, in_flight_len_w, held_frames, token)
            else {
                // 忽略未知/过时 token，继续排空后续合法结果（不返回 None 误截断排空循环）。
                return Some(false);
            };
            let now_us = read_clock(clock_w, meta.received_ts.0).0;
            Some(handle_async_decode_result(
                frame_res,
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
            // 解码器级错误无法归属单一 token：先冲刷底层再结案全部剩余在途帧。
            let _ = decoder.flush();
            fail_remaining_in_flight(in_flight, in_flight_len_w, held_frames, shared_w);
            need_kf_w.store(true, Ordering::Release);
            if e.is_fatal() {
                let mut s = shared_w.lock().unwrap_or_else(|e| e.into_inner());
                s.fatal_error = Some(e);
                return Some(true);
            }
            Some(false)
        }
    }
}

/// 在编码格式切换或停机前排空全部在途异步解码帧（最多等待 `timeout`，超时冲刷解码器并兜底补齐结局保 `unfinished == 0`）。
#[allow(clippy::too_many_arguments)]
fn drain_pipelined_in_flight(
    timeout: Duration,
    decoder: &mut dyn Decoder,
    renderer: &mut dyn Renderer,
    in_flight: &mut VecDeque<InFlightDecodeMeta>,
    in_flight_len_w: &AtomicUsize,
    held_frames: usize,
    clock_w: &ClockSlot,
    shared_w: &Mutex<AsyncSharedState>,
    need_kf_w: &AtomicBool,
    disp_w: &AtomicU64,
) -> bool {
    let deadline = Instant::now() + timeout;
    while !in_flight.is_empty() {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            let _ = decoder.flush();
            fail_remaining_in_flight(in_flight, in_flight_len_w, held_frames, shared_w);
            need_kf_w.store(true, Ordering::Release);
            break;
        }
        if let Some(fatal) = poll_pipelined_decode_once(
            remain.min(Duration::from_millis(5)),
            decoder,
            renderer,
            in_flight,
            in_flight_len_w,
            held_frames,
            clock_w,
            shared_w,
            need_kf_w,
            disp_w,
        ) {
            if fatal {
                fail_remaining_in_flight(in_flight, in_flight_len_w, held_frames, shared_w);
                return true;
            }
            continue;
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

enum SwapStatus {
    /// 目标编解码器与当前解码器一致或已完成热切，可安全送入本帧。
    Ready,
    /// 首次热切至目标编解码器失败：必须拒喂旧解码器并立即向上层上报失败事件。
    FailedNow(CodecDecodeFailure),
    /// 目标编解码器已处于失败熔断等待态：继续拒喂旧解码器（防止 `NeedKeyframe` 风暴）。
    Blocked,
    /// 异步排空旧解码器在途帧期间遇到致命错误（仅异步路径返回）。
    Fatal,
}

fn create_swap_decoder(
    cfg: &PipelineConfig,
    target: rc_encode::Codec,
    swap_factory: &DecoderSwapSlot,
) -> Option<Result<Box<dyn Decoder>>> {
    let mut next_cfg = cfg.clone();
    next_cfg.codec = target;
    let custom = swap_factory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(factory) = custom {
        return Some(factory(&next_cfg));
    }
    if cfg.prefer_hardware {
        return Some(crate::select_hardware_decoder_labeled(&next_cfg).map(|(d, _)| d));
    }
    None
}

fn maybe_swap_decoder_for_codec(
    cfg: &PipelineConfig,
    active_codec: &mut rc_encode::Codec,
    failed_codec: &mut Option<rc_encode::Codec>,
    decoder: &mut Box<dyn Decoder>,
    swap_factory: &DecoderSwapSlot,
    target: rc_encode::Codec,
) -> SwapStatus {
    if target == *active_codec {
        *failed_codec = None;
        return SwapStatus::Ready;
    }
    if *failed_codec == Some(target) {
        return SwapStatus::Blocked;
    }
    match create_swap_decoder(cfg, target, swap_factory) {
        None => {
            *active_codec = target;
            *failed_codec = None;
            SwapStatus::Ready
        }
        Some(Ok(new_dec)) => {
            let _ = decoder.flush();
            *decoder = new_dec;
            *active_codec = target;
            *failed_codec = None;
            SwapStatus::Ready
        }
        Some(Err(err)) => {
            *failed_codec = Some(target);
            SwapStatus::FailedNow(CodecDecodeFailure {
                codec: target,
                reason: err.to_string(),
            })
        }
    }
}

/// 异步模式编解码切换：仅当确实需要切换且新解码器成功创建时才排空旧解码器在途帧；
/// 创建失败时严禁把新码流喂给旧解码器，而是标记 `failed_codec` 并立即产出 [`CodecDecodeFailure`]。
#[allow(clippy::too_many_arguments)]
fn maybe_swap_async_decoder_for_codec(
    cfg: &PipelineConfig,
    active_codec: &mut rc_encode::Codec,
    failed_codec: &mut Option<rc_encode::Codec>,
    failed_codec_code_w: &AtomicU8,
    decoder: &mut Box<dyn Decoder>,
    renderer: &mut dyn Renderer,
    swap_factory: &DecoderSwapSlot,
    in_flight: &mut VecDeque<InFlightDecodeMeta>,
    in_flight_len_w: &AtomicUsize,
    clock_w: &ClockSlot,
    shared_w: &Mutex<AsyncSharedState>,
    need_kf_w: &AtomicBool,
    disp_w: &AtomicU64,
    target: rc_encode::Codec,
) -> SwapStatus {
    if target == *active_codec {
        *failed_codec = None;
        failed_codec_code_w.store(0, Ordering::Release);
        return SwapStatus::Ready;
    }
    if *failed_codec == Some(target) {
        return SwapStatus::Blocked;
    }
    let new_dec = match create_swap_decoder(cfg, target, swap_factory) {
        None => {
            *active_codec = target;
            *failed_codec = None;
            failed_codec_code_w.store(0, Ordering::Release);
            return SwapStatus::Ready;
        }
        Some(Ok(d)) => d,
        Some(Err(err)) => {
            *failed_codec = Some(target);
            failed_codec_code_w.store(encode_failed_codec_u8(Some(target)), Ordering::Release);
            need_kf_w.store(false, Ordering::Release);
            return SwapStatus::FailedNow(CodecDecodeFailure {
                codec: target,
                reason: err.to_string(),
            });
        }
    };
    if !in_flight.is_empty()
        && drain_pipelined_in_flight(
            PIPELINED_DRAIN_TIMEOUT,
            decoder.as_mut(),
            renderer,
            in_flight,
            in_flight_len_w,
            1,
            clock_w,
            shared_w,
            need_kf_w,
            disp_w,
        )
    {
        return SwapStatus::Fatal;
    }
    let _ = decoder.flush();
    *decoder = new_dec;
    *active_codec = target;
    *failed_codec = None;
    failed_codec_code_w.store(0, Ordering::Release);
    SwapStatus::Ready
}

impl ControllerPipeline {
    /// 用工厂后端创建（auto 模式）。
    pub fn new(mut cfg: PipelineConfig) -> Result<Self> {
        cfg.validate()?;
        let (_capture, _encoder, decoder, renderer, labels) = select_all(&cfg)?;
        if labels.decoder == "fake" {
            // 降级到 FakeDecoder 后关闭内部硬件热切标志，防止热切不同 codec 时误调硬件工厂报错锁死。
            cfg.prefer_hardware = false;
        }
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
        let swap_factory: DecoderSwapSlot = Arc::new(Mutex::new(None));
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
            let failed_codec_code = Arc::new(AtomicU8::new(0));
            let displayed = Arc::new(AtomicU64::new(0));
            let in_flight_len = Arc::new(AtomicUsize::new(0));

            let slot_w = Arc::clone(&slot);
            let stop_w = Arc::clone(&stop);
            let shared_w = Arc::clone(&shared);
            let need_kf_w = Arc::clone(&need_keyframe);
            let failed_codec_code_w = Arc::clone(&failed_codec_code);
            let disp_w = Arc::clone(&displayed);
            let in_flight_len_w = Arc::clone(&in_flight_len);
            let clock_w = Arc::clone(&clock);
            let swap_factory_w = Arc::clone(&swap_factory);
            let cfg_w = cfg.clone();
            let mut active_codec_w = active_codec;
            let mut failed_codec_w: Option<rc_encode::Codec> = None;

            let worker = std::thread::Builder::new()
                .name("rc-ctrl-decode".into())
                .spawn(move || {
                    crate::promote_current_thread_qos();
                    let mut in_flight: VecDeque<InFlightDecodeMeta> =
                        VecDeque::with_capacity(MAX_PIPELINED_DECODE_IN_FLIGHT);
                    let mut stop_deadline: Option<Instant> = None;
                    'worker: loop {
                        if stop_w.load(Ordering::Acquire) {
                            let dl = *stop_deadline
                                .get_or_insert_with(|| Instant::now() + PIPELINED_DRAIN_TIMEOUT);
                            if Instant::now() >= dl {
                                break 'worker;
                            }
                        }

                        // 1) 若后端支持 2-deep 流水线解码，优先非阻塞排空全部已就绪帧并立刻上屏。
                        let mut did_work = false;
                        while !in_flight.is_empty() {
                            if stop_w.load(Ordering::Acquire) {
                                let dl = *stop_deadline.get_or_insert_with(|| {
                                    Instant::now() + PIPELINED_DRAIN_TIMEOUT
                                });
                                if Instant::now() >= dl {
                                    break 'worker;
                                }
                            }
                            let Some(fatal) = poll_pipelined_decode_once(
                                Duration::ZERO,
                                decoder.as_mut(),
                                renderer.as_mut(),
                                &mut in_flight,
                                &in_flight_len_w,
                                0,
                                &clock_w,
                                &shared_w,
                                &need_kf_w,
                                &disp_w,
                            ) else {
                                break;
                            };
                            did_work = true;
                            if fatal {
                                fail_remaining_in_flight(
                                    &mut in_flight,
                                    &in_flight_len_w,
                                    0,
                                    &shared_w,
                                );
                                let _ = decoder.flush();
                                return;
                            }
                        }

                        // 2) 非阻塞拉取待解码帧：若走流水线则补满 ≤2 帧在途，否则单帧同步解码。
                        let mut popped_any = false;
                        while !decoder.supports_pipelined_decode()
                            || in_flight.len() < MAX_PIPELINED_DECODE_IN_FLIGHT
                        {
                            let next_frame = {
                                let (lock, _) = &*slot_w;
                                let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                                let popped = guard.pop_front();
                                if popped.is_some() {
                                    // 在 slot 锁内即计入本帧在途占位，消除 pop_front 与 submit_decode 间的 TOCTOU 窗口，
                                    // 严格维持待解 + 在途 ≤ ASYNC_DECODE_TOTAL_CAP (3)。
                                    in_flight_len_w.store(in_flight.len() + 1, Ordering::Release);
                                }
                                popped
                            };
                            let Some(frame) = next_frame else {
                                break;
                            };
                            popped_any = true;
                            did_work = true;

                            match maybe_swap_async_decoder_for_codec(
                                &cfg_w,
                                &mut active_codec_w,
                                &mut failed_codec_w,
                                &failed_codec_code_w,
                                &mut decoder,
                                renderer.as_mut(),
                                &swap_factory_w,
                                &mut in_flight,
                                &in_flight_len_w,
                                &clock_w,
                                &shared_w,
                                &need_kf_w,
                                &disp_w,
                                frame.codec,
                            ) {
                                SwapStatus::Ready => {}
                                SwapStatus::FailedNow(failure) => {
                                    {
                                        let mut s =
                                            shared_w.lock().unwrap_or_else(|e| e.into_inner());
                                        if s.decode_failures.len() >= 8 {
                                            s.decode_failures.pop_front();
                                        }
                                        s.decode_failures.push_back(failure);
                                    }
                                    finish_aborted_frame(&frame, &shared_w);
                                    in_flight_len_w.store(in_flight.len(), Ordering::Release);
                                    continue;
                                }
                                SwapStatus::Blocked => {
                                    finish_aborted_frame(&frame, &shared_w);
                                    in_flight_len_w.store(in_flight.len(), Ordering::Release);
                                    continue;
                                }
                                SwapStatus::Fatal => {
                                    finish_aborted_frame(&frame, &shared_w);
                                    in_flight_len_w.store(in_flight.len(), Ordering::Release);
                                    let _ = decoder.flush();
                                    return;
                                }
                            }

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
                                        push_in_flight_meta(
                                            &mut in_flight,
                                            &in_flight_len_w,
                                            InFlightDecodeMeta {
                                                seq: frame.seq,
                                                capture_ts: frame.capture_ts,
                                                received_ts: frame.received_ts,
                                            },
                                        );
                                    }
                                    Ok(DecodeSubmitStatus::NeedKeyframe) => {
                                        in_flight_len_w.store(in_flight.len(), Ordering::Release);
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
                                            fail_remaining_in_flight(
                                                &mut in_flight,
                                                &in_flight_len_w,
                                                0,
                                                &shared_w,
                                            );
                                            let _ = decoder.flush();
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        in_flight_len_w.store(in_flight.len(), Ordering::Release);
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
                                            fail_remaining_in_flight(
                                                &mut in_flight,
                                                &in_flight_len_w,
                                                0,
                                                &shared_w,
                                            );
                                            let _ = decoder.flush();
                                            return;
                                        }
                                    }
                                }
                            } else {
                                let res = decoder.decode(&frame.payload_all, frame.kind, deadline);
                                in_flight_len_w.store(in_flight.len(), Ordering::Release);
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
                                    fail_remaining_in_flight(
                                        &mut in_flight,
                                        &in_flight_len_w,
                                        0,
                                        &shared_w,
                                    );
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
                                    &in_flight_len_w,
                                    0,
                                    &clock_w,
                                    &shared_w,
                                    &need_kf_w,
                                    &disp_w,
                                ) {
                                    fail_remaining_in_flight(
                                        &mut in_flight,
                                        &in_flight_len_w,
                                        0,
                                        &shared_w,
                                    );
                                    let _ = decoder.flush();
                                    return;
                                }
                                if stop_w.load(Ordering::Acquire) {
                                    let dl = *stop_deadline.get_or_insert_with(|| {
                                        Instant::now() + PIPELINED_DRAIN_TIMEOUT
                                    });
                                    let slot_empty = {
                                        let (lock, _) = &*slot_w;
                                        lock.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
                                    };
                                    if slot_empty || Instant::now() >= dl {
                                        break 'worker;
                                    }
                                }
                            } else {
                                let (lock, cv) = &*slot_w;
                                let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                                while guard.is_empty() && !stop_w.load(Ordering::Acquire) {
                                    guard = cv.wait(guard).unwrap_or_else(|e| e.into_inner());
                                }
                                if guard.is_empty() && stop_w.load(Ordering::Acquire) {
                                    break 'worker;
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
                                break 'worker;
                            }
                        }
                    }
                    let drain_budget = stop_deadline.map_or(PIPELINED_DRAIN_TIMEOUT, |dl| {
                        dl.saturating_duration_since(Instant::now())
                    });
                    let _ = drain_pipelined_in_flight(
                        drain_budget,
                        decoder.as_mut(),
                        renderer.as_mut(),
                        &mut in_flight,
                        &in_flight_len_w,
                        0,
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
                failed_codec_code,
                displayed,
                in_flight_len,
                worker: Some(worker),
            }
        } else {
            ControllerExecMode::Sync {
                decoder,
                renderer,
                active_codec,
                failed_codec: None,
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
            pending_decode_failures: VecDeque::new(),
            swap_factory,
        })
    }

    /// 注入会话时钟（微秒，与帧 `timestamp` 同基准）。见字段文档。
    pub fn set_clock(&mut self, clock: std::sync::Arc<dyn Fn() -> u32 + Send + Sync>) {
        *self.clock.lock().unwrap_or_else(|e| e.into_inner()) = Some(clock);
    }

    /// 注入自定义解码器热切工厂（用于确定性测试或自定义解码后端注入；不触碰全局注册表）。
    pub fn set_decoder_swap_factory(&mut self, factory: DecoderSwapFactory) {
        *self.swap_factory.lock().unwrap_or_else(|e| e.into_inner()) = Some(factory);
    }

    /// 取出最近一次待上报的编解码切换/解码失败事件（供上层发送 `CodecDecodeFailed` 触发被控端熔断降级）。
    pub fn take_decode_failure(&mut self) -> Option<CodecDecodeFailure> {
        let _ = self.drain_async_completions();
        self.pending_decode_failures.pop_front()
    }

    fn drain_async_completions(&mut self) -> Result<bool> {
        let (pending_outcomes, pending_failures, fatal) = match &self.mode {
            ControllerExecMode::Sync { .. } => return Ok(false),
            ControllerExecMode::Async { shared, .. } => {
                let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());
                let items: Vec<AsyncFrameOutcome> = s.completed.drain(..).collect();
                let failures: Vec<CodecDecodeFailure> = s.decode_failures.drain(..).collect();
                let fatal = s.fatal_error.take();
                (items, failures, fatal)
            }
        };
        for failure in pending_failures {
            if self.pending_decode_failures.len() >= 8 {
                self.pending_decode_failures.pop_front();
            }
            self.pending_decode_failures.push_back(failure);
        }
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
        let Some(frame_codec) = header.flags.codec() else {
            return Err(Error::Protocol {
                offset: 26,
                msg: format!(
                    "unsupported reserved codec flags (flags=0x{:02x})",
                    header.flags.0
                ),
            });
        };
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
                codec: frame_codec,
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
        let codec = partial.codec;
        self.highest_delivered = Some(seq);

        match &mut self.mode {
            ControllerExecMode::Sync {
                decoder,
                renderer,
                active_codec,
                failed_codec,
            } => {
                let slot = self.trace.begin(seq);
                slot.mark(Mark::Captured, capture_ts);
                slot.mark(Mark::Received, Timestamp(now_us));

                match maybe_swap_decoder_for_codec(
                    &self.cfg,
                    active_codec,
                    failed_codec,
                    decoder,
                    &self.swap_factory,
                    codec,
                ) {
                    SwapStatus::Ready => {}
                    SwapStatus::FailedNow(failure) => {
                        if self.pending_decode_failures.len() >= 8 {
                            self.pending_decode_failures.pop_front();
                        }
                        self.pending_decode_failures.push_back(failure);
                        self.need_keyframe = false;
                        if let Some(f) = self.trace.get_mut(seq) {
                            f.finish(Outcome::DecodeError);
                        }
                        return Ok(false);
                    }
                    SwapStatus::Blocked | SwapStatus::Fatal => {
                        self.need_keyframe = false;
                        if let Some(f) = self.trace.get_mut(seq) {
                            f.finish(Outcome::DecodeError);
                        }
                        return Ok(false);
                    }
                }
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
            ControllerExecMode::Async {
                slot,
                failed_codec_code,
                in_flight_len,
                ..
            } => {
                let received_ts = Timestamp(now_us);
                // 若此前在失败 codec（如 AV1）上抑制了关键帧请求，但此刻已收到对端降级后的其他 codec 帧
                //（即使首张降级 IDR 丢包、只收到后续 P 帧），立即解除抑制，使断链路径可立刻索取关键帧恢复出画。
                let cur_failed = decode_failed_codec_u8(failed_codec_code.load(Ordering::Acquire));
                if cur_failed.is_some_and(|fc| fc != codec) {
                    failed_codec_code.store(0, Ordering::Release);
                }
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
                    codec,
                };
                let dropped_frames: Vec<(FrameSeq, Timestamp, Timestamp)> = {
                    let (lock, cv) = &**slot;
                    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                    let cur_in_flight = in_flight_len.load(Ordering::Acquire);
                    let mut dropped = Vec::new();
                    if kind == FrameKind::Idr {
                        while let Some(prev) = guard.pop_front() {
                            dropped.push((prev.seq, prev.capture_ts, prev.received_ts));
                        }
                        guard.push_back(incoming);
                    } else if guard.len() < ASYNC_DECODE_QUEUE_CAP
                        && guard.len().saturating_add(cur_in_flight) < ASYNC_DECODE_TOTAL_CAP
                    {
                        guard.push_back(incoming);
                    } else {
                        // 队列满（或待解+硬件在途达到总深度上限）时保留已有参考链完整的前序帧，
                        // 丢弃本帧并标记断链等待 IDR。
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
    ///
    /// 当目标编解码器热切失败等待对端降级时返回 `false`，避免在旧解码器上制造 `NeedKeyframe` 风暴。
    pub fn take_keyframe_request(&mut self) -> bool {
        let _ = self.drain_async_completions();
        match &self.mode {
            ControllerExecMode::Sync {
                decoder,
                failed_codec,
                ..
            } => {
                if failed_codec.is_some() {
                    self.need_keyframe = false;
                    return false;
                }
                let kf = self.need_keyframe || decoder.needs_keyframe();
                self.need_keyframe = false;
                kf
            }
            ControllerExecMode::Async {
                need_keyframe,
                failed_codec_code,
                ..
            } => {
                if failed_codec_code.load(Ordering::Acquire) != 0 {
                    need_keyframe.store(false, Ordering::Release);
                    self.need_keyframe = false;
                    return false;
                }
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

    /// 已交付至解码/呈现路径的最高动态帧序号（用于静止无损补帧接收端防“画面倒退”校验）。
    pub fn highest_delivered_seq(&self) -> Option<FrameSeq> {
        self.highest_delivered
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
                {
                    let (lock, cv) = &**slot;
                    let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                    stop.store(true, Ordering::Release);
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
            {
                let (lock, cv) = &**slot;
                let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                stop.store(true, Ordering::Release);
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

        fn recv_decoded(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<(u64, Result<DecodeOutput>)>> {
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
                Ok(DecodeOutput::Frame(DecodedFrame {
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
                })),
            )))
        }

        fn in_flight_count(&self) -> usize {
            self.in_flight.len()
        }
    }

    /// 可配置行为的假流水线解码器：用于验证致命错误结案、失步回收与卡死停机超时。
    struct FaultyPipelinedDecoder {
        in_flight: VecDeque<u64>,
        fail_fatal_on_token: Option<u64>,
        fail_nonfatal_on_token: Option<u64>,
        drop_internally_on_submit: bool,
        stall_forever: bool,
        /// 在途帧数首次达到该阈值前暂不释放任何输出，确保双帧并发用例与调度无关。
        min_in_flight_to_release: usize,
        released: bool,
        flushed: Arc<AtomicUsize>,
    }

    impl FaultyPipelinedDecoder {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let flushed = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    in_flight: VecDeque::new(),
                    fail_fatal_on_token: None,
                    fail_nonfatal_on_token: None,
                    drop_internally_on_submit: false,
                    stall_forever: false,
                    min_in_flight_to_release: 1,
                    released: false,
                    flushed: Arc::clone(&flushed),
                },
                flushed,
            )
        }
    }

    impl Decoder for FaultyPipelinedDecoder {
        fn decode(
            &mut self,
            _data: &[u8],
            _kind: FrameKind,
            _deadline_ts: Timestamp,
        ) -> Result<DecodeOutput> {
            unreachable!()
        }

        fn needs_keyframe(&self) -> bool {
            false
        }

        fn flush(&mut self) -> Result<()> {
            self.in_flight.clear();
            self.flushed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn supports_pipelined_decode(&self) -> bool {
            true
        }

        fn submit_decode(
            &mut self,
            token: u64,
            _data: &[u8],
            _kind: FrameKind,
            _deadline_ts: Timestamp,
        ) -> Result<DecodeSubmitStatus> {
            if self.drop_internally_on_submit {
                // 模拟底层静默丢弃在途帧（制造上层/底层失步：上层以为在途，底层 in_flight_count == 0）
                self.in_flight.clear();
                return Ok(DecodeSubmitStatus::Submitted);
            }
            self.in_flight.push_back(token);
            Ok(DecodeSubmitStatus::Submitted)
        }

        fn recv_decoded(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<(u64, Result<DecodeOutput>)>> {
            if self.stall_forever {
                if !timeout.is_zero() {
                    std::thread::sleep(timeout.min(Duration::from_millis(5)));
                }
                return Ok(None);
            }
            if self.in_flight.is_empty() {
                return Ok(None);
            }
            if !self.released {
                if self.in_flight.len() < self.min_in_flight_to_release {
                    if !timeout.is_zero() {
                        std::thread::sleep(timeout.min(Duration::from_millis(2)));
                    }
                    return Ok(None);
                }
                self.released = true;
            }
            if timeout.is_zero() && self.in_flight.len() < 2 {
                return Ok(None);
            }
            let Some(token) = self.in_flight.pop_front() else {
                return Ok(None);
            };
            if self.fail_fatal_on_token == Some(token) {
                return Ok(Some((token, Err(Error::Decoder("fatal unit".into())))));
            }
            if self.fail_nonfatal_on_token == Some(token) {
                return Ok(Some((token, Err(Error::Timeout(Duration::from_millis(5))))));
            }
            Ok(Some((
                token,
                Ok(DecodeOutput::Frame(DecodedFrame {
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
                })),
            )))
        }

        fn in_flight_count(&self) -> usize {
            self.in_flight.len()
        }
    }

    fn push_test_frame(ctrl: &mut ControllerPipeline, seq: u64, kind: FrameKind) {
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
            let _ = ctrl.push_datagram(d, (seq as u32) * 16_000 + 200);
        }
    }

    #[test]
    fn pipelined_fatal_error_finishes_remaining_in_flight_frames_without_leak() {
        let (mut dec, _) = FaultyPipelinedDecoder::new();
        dec.fail_fatal_on_token = Some(1);
        dec.min_in_flight_to_release = 2;
        let ren = FakeRenderer::new(FakeRendererConfig::default()).expect("假渲染器");
        let cfg = PipelineConfig {
            async_decode: true,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::with_backends(cfg, Box::new(dec), Box::new(ren))
            .expect("controller init");

        push_test_frame(&mut ctrl, 1, FrameKind::Idr);
        push_test_frame(&mut ctrl, 2, FrameKind::P);
        std::thread::sleep(Duration::from_millis(50));
        ctrl.shutdown();

        let sum = ctrl.trace().summary();
        assert_eq!(sum.unfinished, 0, "致命错误后剩余在途帧也必须结案: {sum:?}");
        assert!(sum.decode_errors >= 2, "两帧均应记录 DecodeError: {sum:?}");
    }

    #[test]
    fn pipelined_desync_reaps_orphans_and_requests_keyframe() {
        let (mut dec, _) = FaultyPipelinedDecoder::new();
        dec.drop_internally_on_submit = true;
        let ren = FakeRenderer::new(FakeRendererConfig::default()).expect("假渲染器");
        let cfg = PipelineConfig {
            async_decode: true,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::with_backends(cfg, Box::new(dec), Box::new(ren))
            .expect("controller init");

        push_test_frame(&mut ctrl, 1, FrameKind::Idr);
        push_test_frame(&mut ctrl, 2, FrameKind::P);

        let dl = Instant::now() + Duration::from_secs(1);
        let mut saw_kf = false;
        while Instant::now() < dl {
            if ctrl.take_keyframe_request() {
                saw_kf = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(saw_kf, "底层在途失步后应回收孤儿并请求关键帧");
        ctrl.shutdown();
        let sum = ctrl.trace().summary();
        assert_eq!(sum.unfinished, 0, "失步回收后不得有未完结帧: {sum:?}");
    }

    #[test]
    fn pipelined_per_frame_nonfatal_error_preserves_sibling_frame() {
        let (mut dec, _) = FaultyPipelinedDecoder::new();
        dec.fail_nonfatal_on_token = Some(1);
        dec.min_in_flight_to_release = 2;
        let ren = FakeRenderer::new(FakeRendererConfig::default()).expect("假渲染器");
        let cfg = PipelineConfig {
            async_decode: true,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::with_backends(cfg, Box::new(dec), Box::new(ren))
            .expect("controller init");

        push_test_frame(&mut ctrl, 1, FrameKind::Idr);
        push_test_frame(&mut ctrl, 2, FrameKind::P);

        let dl = Instant::now() + Duration::from_secs(1);
        while ctrl.displayed() < 1 && Instant::now() < dl {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(ctrl.displayed(), 1, "帧 1 非致命失败后帧 2 仍应正常上屏");
        ctrl.shutdown();
        let sum = ctrl.trace().summary();
        assert_eq!(sum.unfinished, 0);
        assert_eq!(sum.decode_errors, 1);
    }

    #[test]
    fn pipelined_stalled_decoder_with_queued_slot_shuts_down_within_budget() {
        let (mut dec, flushed) = FaultyPipelinedDecoder::new();
        dec.stall_forever = true;
        let ren = FakeRenderer::new(FakeRendererConfig::default()).expect("假渲染器");
        let cfg = PipelineConfig {
            async_decode: true,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::with_backends(cfg, Box::new(dec), Box::new(ren))
            .expect("controller init");

        // 塞满 2 帧在途 + 1 帧排队（总深度受 ASYNC_DECODE_TOTAL_CAP=3 约束）+ 第 4 帧被拒
        push_test_frame(&mut ctrl, 1, FrameKind::Idr);
        push_test_frame(&mut ctrl, 2, FrameKind::P);
        std::thread::sleep(Duration::from_millis(20));
        push_test_frame(&mut ctrl, 3, FrameKind::P);
        push_test_frame(&mut ctrl, 4, FrameKind::P);

        let t0 = Instant::now();
        ctrl.shutdown();
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_secs(4),
            "卡死解码器停机不应永久阻塞，实际耗时 {elapsed:?}"
        );
        assert!(
            flushed.load(Ordering::SeqCst) >= 1,
            "超时停机应调用 decoder.flush()"
        );
        let sum = ctrl.trace().summary();
        assert_eq!(sum.unfinished, 0, "停机后全部在途与排队帧均须结案: {sum:?}");
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

    struct CountingDecoder {
        calls: Arc<AtomicUsize>,
        inner: rc_decode::FakeDecoder,
    }

    impl CountingDecoder {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self {
                calls,
                inner: rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
                    resolution: rc_types::Resolution::new(64, 64),
                    decode_cost_us: 100,
                    ..rc_decode::FakeDecoderConfig::default()
                })
                .expect("fake decoder"),
            }
        }
    }

    impl Decoder for CountingDecoder {
        fn decode(
            &mut self,
            data: &[u8],
            kind: FrameKind,
            deadline_ts: Timestamp,
        ) -> Result<DecodeOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.decode(data, kind, deadline_ts)
        }

        fn needs_keyframe(&self) -> bool {
            self.inner.needs_keyframe()
        }

        fn flush(&mut self) -> Result<()> {
            self.inner.flush()
        }
    }

    fn push_frame_with_flags(
        ctrl: &mut ControllerPipeline,
        seq: u64,
        kind: FrameKind,
        flags: HeaderFlags,
    ) -> Result<bool> {
        let pkts = split_frame_with_flags(
            FrameSeq(seq),
            kind,
            flags,
            Timestamp((seq as u32) * 16_000),
            Timestamp((seq as u32) * 16_000 + 100),
            seq as u16,
            &[0, 0, 0, 1, 0x65, seq as u8],
            1200,
        );
        let mut presented = false;
        for d in &pkts {
            if ctrl.push_datagram(d, (seq as u32) * 16_000 + 200)? {
                presented = true;
            }
        }
        Ok(presented)
    }

    #[test]
    fn reserved_codec_flags_11_rejected_without_feeding_decoder() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dec = CountingDecoder::new(Arc::clone(&calls));
        let ren = FakeRenderer::new(FakeRendererConfig::default()).expect("fake renderer");
        let cfg = PipelineConfig {
            resolution: rc_types::Resolution::new(64, 64),
            async_decode: false,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::with_backends(cfg, Box::new(dec), Box::new(ren))
            .expect("controller init");

        let reserved_flags = HeaderFlags(HeaderFlags::HEVC | HeaderFlags::CODEC_EXT);
        let err = push_frame_with_flags(&mut ctrl, 1, FrameKind::Idr, reserved_flags)
            .expect_err("预留 11 codec 标志位必须明确报协议错误");
        assert!(
            matches!(err, Error::Protocol { offset: 26, .. }),
            "应指向 flags 字节偏移 26，实际 {err:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0, "预留 11 绝不可喂入解码器");
    }

    #[test]
    fn sync_codec_swap_failure_blocks_old_decoder_and_reports_failure_until_fallback() {
        let old_calls = Arc::new(AtomicUsize::new(0));
        let dec = CountingDecoder::new(Arc::clone(&old_calls));
        let ren = FakeRenderer::new(FakeRendererConfig::default()).expect("fake renderer");
        let cfg = PipelineConfig {
            resolution: rc_types::Resolution::new(64, 64),
            prefer_hardware: true,
            async_decode: false,
            codec: rc_encode::Codec::H264,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::with_backends(cfg, Box::new(dec), Box::new(ren))
            .expect("controller init");
        let swap_attempts = Arc::new(AtomicUsize::new(0));
        let swap_attempts_c = Arc::clone(&swap_attempts);
        ctrl.set_decoder_swap_factory(Arc::new(move |next_cfg| {
            swap_attempts_c.fetch_add(1, Ordering::SeqCst);
            Err(Error::Decoder(format!(
                "codec {} unsupported on this GPU",
                next_cfg.codec.as_str()
            )))
        }));

        // 1) 首帧 H.264 正常上屏。
        let ok = push_frame_with_flags(
            &mut ctrl,
            1,
            FrameKind::Idr,
            HeaderFlags::empty().with_codec(rc_encode::Codec::H264),
        )
        .expect("h264 frame");
        assert!(ok);
        assert_eq!(old_calls.load(Ordering::SeqCst), 1);

        // 2) 对端切到 AV1 但本端创建 AV1 解码器失败：拒喂旧 H.264 解码器、不制造 NeedKeyframe 风暴、稳定上报 CodecDecodeFailure。
        let av1_flags = HeaderFlags::empty().with_codec(rc_encode::Codec::Av1);
        assert!(!push_frame_with_flags(&mut ctrl, 2, FrameKind::Idr, av1_flags).expect("av1 idr"));
        assert!(!push_frame_with_flags(&mut ctrl, 3, FrameKind::P, av1_flags).expect("av1 p"));
        assert_eq!(
            old_calls.load(Ordering::SeqCst),
            1,
            "热切失败后绝不能把 AV1 码流喂给旧 H.264 解码器"
        );
        assert_eq!(
            swap_attempts.load(Ordering::SeqCst),
            1,
            "同一失败 codec 不应每帧重复创建解码器"
        );
        assert!(
            !ctrl.take_keyframe_request(),
            "热切失败熔断期不得触发 NeedKeyframe 风暴"
        );

        let failure = ctrl
            .take_decode_failure()
            .expect("必须向上层产出 CodecDecodeFailure");
        assert_eq!(failure.codec, rc_encode::Codec::Av1);
        assert!(failure.reason.contains("av1"));
        assert!(ctrl.take_decode_failure().is_none(), "单次失败不重复刷屏");

        // 3) 对端降级回 H.264 后无缝恢复解码上屏。
        assert!(push_frame_with_flags(
            &mut ctrl,
            4,
            FrameKind::Idr,
            HeaderFlags::empty().with_codec(rc_encode::Codec::H264),
        )
        .expect("fallback h264 idr"));
        assert_eq!(old_calls.load(Ordering::SeqCst), 2);
        assert_eq!(ctrl.displayed(), 2);

        ctrl.shutdown();
        let sum = ctrl.trace().summary();
        assert_eq!(sum.unfinished, 0);
        assert_eq!(sum.decode_errors, 2);
    }

    #[test]
    fn async_codec_swap_failure_blocks_old_decoder_and_reports_failure() {
        let old_calls = Arc::new(AtomicUsize::new(0));
        let dec = CountingDecoder::new(Arc::clone(&old_calls));
        let ren = FakeRenderer::new(FakeRendererConfig::default()).expect("fake renderer");
        let cfg = PipelineConfig {
            resolution: rc_types::Resolution::new(64, 64),
            prefer_hardware: true,
            async_decode: true,
            codec: rc_encode::Codec::H264,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::with_backends(cfg, Box::new(dec), Box::new(ren))
            .expect("controller init");
        ctrl.set_decoder_swap_factory(Arc::new(|next_cfg| {
            Err(Error::Decoder(format!(
                "async decoder {} unavailable",
                next_cfg.codec.as_str()
            )))
        }));

        push_frame_with_flags(
            &mut ctrl,
            1,
            FrameKind::Idr,
            HeaderFlags::empty().with_codec(rc_encode::Codec::H264),
        )
        .expect("h264 idr");
        let dl = Instant::now() + Duration::from_secs(1);
        while ctrl.displayed() < 1 && Instant::now() < dl {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(ctrl.displayed(), 1);

        let av1_flags = HeaderFlags::empty().with_codec(rc_encode::Codec::Av1);
        push_frame_with_flags(&mut ctrl, 2, FrameKind::Idr, av1_flags).expect("av1 idr");
        push_frame_with_flags(&mut ctrl, 3, FrameKind::P, av1_flags).expect("av1 p");

        let dl2 = Instant::now() + Duration::from_secs(1);
        let mut got_failure = None;
        while Instant::now() < dl2 {
            if let Some(f) = ctrl.take_decode_failure() {
                got_failure = Some(f);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let failure = got_failure.expect("异步模式也必须稳定产出 CodecDecodeFailure");
        assert_eq!(failure.codec, rc_encode::Codec::Av1);
        assert!(!ctrl.take_keyframe_request());
        assert_eq!(
            old_calls.load(Ordering::SeqCst),
            1,
            "异步模式热切失败同样严禁将 AV1 码流喂给旧解码器"
        );

        ctrl.shutdown();
        let sum = ctrl.trace().summary();
        assert_eq!(sum.unfinished, 0);
    }

    #[test]
    fn async_codec_swap_failure_recovers_after_downgrade_idr_packet_loss() {
        let old_calls = Arc::new(AtomicUsize::new(0));
        let dec = CountingDecoder::new(Arc::clone(&old_calls));
        let ren = FakeRenderer::new(FakeRendererConfig::default()).expect("fake renderer");
        let cfg = PipelineConfig {
            resolution: rc_types::Resolution::new(64, 64),
            prefer_hardware: true,
            async_decode: true,
            codec: rc_encode::Codec::H264,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::with_backends(cfg, Box::new(dec), Box::new(ren))
            .expect("controller init");
        ctrl.set_decoder_swap_factory(Arc::new(|next_cfg| {
            Err(Error::Decoder(format!(
                "async decoder {} unsupported",
                next_cfg.codec.as_str()
            )))
        }));

        // 1) 首帧 H.264 正常上屏。
        let h264_flags = HeaderFlags::empty().with_codec(rc_encode::Codec::H264);
        push_frame_with_flags(&mut ctrl, 1, FrameKind::Idr, h264_flags).expect("h264 idr 1");
        let dl1 = Instant::now() + Duration::from_secs(1);
        while ctrl.displayed() < 1 && Instant::now() < dl1 {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(ctrl.displayed(), 1);

        // 2) 切入 AV1 失败，置位 failed_codec_code = AV1 并抑制关键帧请求。
        let av1_flags = HeaderFlags::empty().with_codec(rc_encode::Codec::Av1);
        push_frame_with_flags(&mut ctrl, 2, FrameKind::Idr, av1_flags).expect("av1 idr");
        let dl2 = Instant::now() + Duration::from_secs(1);
        let mut saw_fail = false;
        while Instant::now() < dl2 {
            if let Some(f) = ctrl.take_decode_failure() {
                assert_eq!(f.codec, rc_encode::Codec::Av1);
                saw_fail = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(saw_fail);
        assert!(!ctrl.take_keyframe_request());

        // 3) 对端降级回 H.264，但首张降级 IDR（2 片）丢失第 2 片，随后 H.264 P 帧到达淘汰残帧触发断链：
        //    主线程必须在收到 H.264 P 帧时立即解除 AV1 对 take_keyframe_request 的抑制，避免死锁黑屏！
        let big_idr_payload = vec![0x65u8; 1500];
        let lost_idr_pkts = split_frame_with_flags(
            FrameSeq(3),
            FrameKind::Idr,
            h264_flags,
            Timestamp(3 * 16_000),
            Timestamp(3 * 16_000 + 100),
            3,
            &big_idr_payload,
            1200,
        );
        assert_eq!(lost_idr_pkts.len(), 2);
        // 仅送达第 0 片，第 1 片模拟 UDP 丢包
        ctrl.push_datagram(&lost_idr_pkts[0], 3 * 16_000 + 200)
            .expect("partial lost idr pkt0");
        // 后续降级 H.264 P 帧抵达，淘汰残帧 seq=3 置 async_chain_broken=true
        push_frame_with_flags(&mut ctrl, 4, FrameKind::P, h264_flags).expect("downgraded h264 p");
        assert!(
            ctrl.take_keyframe_request(),
            "降级回 H.264 后即便首 IDR 丢包断链，也必须解除抑制并立刻触发关键帧请求"
        );

        // 4) 对端响应关键帧请求补发新 H.264 IDR -> 成功解码上屏。
        push_frame_with_flags(&mut ctrl, 5, FrameKind::Idr, h264_flags).expect("recovery h264 idr");
        let dl3 = Instant::now() + Duration::from_secs(1);
        while ctrl.displayed() < 2 && Instant::now() < dl3 {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(ctrl.displayed(), 2, "补发 H.264 IDR 后必须恢复出画");

        ctrl.shutdown();
        let sum = ctrl.trace().summary();
        assert_eq!(sum.unfinished, 0);
    }

    #[test]
    fn controller_new_fake_fallback_disables_strict_hw_swap_on_codec_change() {
        let cfg = PipelineConfig {
            resolution: rc_types::Resolution::new(64, 64),
            prefer_hardware: true,
            async_decode: false,
            codec: rc_encode::Codec::H264,
            ..PipelineConfig::default()
        };
        let mut ctrl = ControllerPipeline::new(cfg).expect("fake fallback init");
        assert!(
            !ctrl.config().prefer_hardware,
            "降级到 FakeDecoder 时必须关闭 prefer_hardware 防止热切误调硬件工厂"
        );
        assert!(push_frame_with_flags(
            &mut ctrl,
            1,
            FrameKind::Idr,
            HeaderFlags::empty().with_codec(rc_encode::Codec::Av1),
        )
        .expect("fake decoder accepts av1 synthetic frame"));
        assert!(ctrl.take_decode_failure().is_none());
        ctrl.shutdown();
    }
}
