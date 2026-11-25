//! M1 端到端管线编排：把采集→调度→编码→分片、重组→解码→呈现串成真实链路。
//!
//! 本 crate 只做**接线与测量**（T08）：不含新技术、不优化、不多线程、
//! 不引入网络——回环模式在进程内传递字节。所有延迟红线由各部件 crate
//! 自行保证，这里只负责按 T08 数据流图（docs/reference/tickets/T08-m1-pipeline.md）
//! 严格接线并打点。
//!
//! # 时间模型
//! `now_us` 一律由调用方注入（P5：与帧 `timestamp` 同一基准）。
//! 真实模式由会话层从 `session_start: Instant` 换算；测试用逻辑时钟。
//! 本 crate 自身**不读任何时钟**。
//!
//! # 帧结局的归属（P4）
//! host 侧丢弃的帧在 [`HostPipeline`] 内写结局；编码成功的帧结局由
//! [`ControllerPipeline`] 写（Displayed / LostInNetwork / DecodeError）。
//! 两端各持独立 [`rc_trace::TraceCollector`]，会话结束时用 [`merge_traces`]
//! 拼出完整时间线——每帧恰好一个 `Outcome`，`unfinished == 0`。

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod controller;
pub mod host;

pub use controller::ControllerPipeline;
pub use host::HostPipeline;

use rc_capture::{CaptureBackend, FakeBackend, FakeBackendConfig, FakeContent};
use rc_decode::{Decoder, FakeDecoder, FakeDecoderConfig};
use rc_encode::{Encoder, EncoderConfig, FakeEncoder};
use rc_render::{FakeRenderer, FakeRendererConfig, Renderer};
use rc_types::{Error, Resolution, Result};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// 单个媒体分片的最大负载（[`rc_proto::MAX_PAYLOAD`] 的再导出）。
///
/// 回环 / M1 语境下 [`PipelineConfig::max_packet_payload`] 的默认值；
/// 真 QUIC 会话应改用 `rc_net::quic::max_media_payload(mtu)`（见该字段文档）。
pub use rc_proto::MAX_PAYLOAD;

/// 分片预算下限（私有常量，注释写数学）。
///
/// [`rc_proto::split_frame`] 的 `packet_cnt` 是 u16：预算 B 下可安全分片
/// 的最大帧 = B × 65535 字节，超过即运行期 assert panic（修复卡D-1：
/// 预算 1 时 > 64KB 帧切出 > 65535 片，panic 落在生产路径）。取 16 时
/// 即便 65535B 的大帧也只切 ⌈65535/16⌉ = 4096 片，距 u16::MAX 余量
/// 充足（要 panic 需 > 16×65535 ≈ 1MiB 的单帧，现实码率下不会出现）；
/// 正常预算 1120（QUIC `max_media_payload`）/ 1200（[`MAX_PAYLOAD`]）
/// 远超下限。
const MIN_PACKET_PAYLOAD: usize = 16;

/// 重复帧判定策略。
///
/// M1 默认信任平台：ScreenCaptureKit 是回调驱动（有回调即有变化），
/// DXGI 用 `LastPresentTime` 判重，重复帧在平台层已过滤。
/// [`TileDiff`](rc_diff::TileDiff) 复核留给软件采集兜底路径（T03 GDI /
/// T06）——那条路上平台不提供任何变化信号。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    /// 信任 `CapturedFrame::is_repeat` / `dirty`（M1 默认）。
    ///
    /// 注：假后端的 `Dynamic` 内容像素恒为零（只声明「新内容」不真画），
    /// TileDiff 复核会把它误判为重复帧——所以回环与单测必须用本模式。
    TrustPlatform,
    /// CPU 帧走 [`rc_diff::TileDiff`] 软件复核（软件采集兜底路径用）。
    TileDiff,
}

/// M1 管线配置。
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// 编码分辨率（采集后已按需下采样到逻辑分辨率）。
    pub resolution: Resolution,
    /// 目标帧率。
    pub fps: u32,
    /// 目标码率（bps）。
    pub bitrate_bps: u32,
    /// 优先硬件后端：true 时先试真后端，构造失败才降级假后端（P8）；
    /// false 直接用假后端（CI / 回归模式）。
    pub prefer_hardware: bool,
    /// 端到端延迟预算（微秒），透传给 [`SchedulerConfig`](rc_sched::SchedulerConfig)。
    pub target_latency_us: u32,
    /// 帧时间线容量。
    pub trace_capacity: usize,
    /// 重复帧判定策略（见 [`DiffMode`]）。
    pub diff: DiffMode,
    /// 可选的平台单调时钟原点（微秒，来自 [`host_clock_us`]）。
    ///
    /// 设值后，平台采集后端（如 macOS SCK）的 `CapturedFrame::timestamp` 将以
    /// 同一原点换算，保证 `Captured` 与管线会话时钟零偏移同轴。
    pub clock_origin_us: Option<u64>,
    /// 视频编解码器（默认 `Codec::H264`；支持时可切换为 `Codec::Hevc`）。
    pub codec: rc_encode::Codec,
    /// 是否启用异步解码/上屏工作线程（解耦 QUIC 接收线程与解码/Metal 上屏耗时；默认 `false` 保持单测确定性）。
    pub async_decode: bool,
    /// 可选目标显示器 ID（`None` = 主显示器；`Some(id)` = 指定物理或虚拟显示器）。
    pub display_id: Option<u32>,
    /// 采集画面是否包含被控端系统鼠标光标（默认 `false`，主控端/智能光标合成；选择「使用被控端鼠标」时为 `true`）。
    pub shows_cursor: bool,
    /// 媒体分片预算（字节）：[`HostPipeline`](host::HostPipeline) 调
    /// [`split_frame`](rc_proto::split_frame) 时单片载荷的上限。
    ///
    /// 默认 [`MAX_PAYLOAD`]（1200）——回环 / M1 的既有行为，逐字节不变。
    /// 真 QUIC 会话的单个数据报（32 字节包头 + 媒体片）受 N2 约束
    /// （≤ `mtu - QUIC_OVERHEAD`），预算必须由会话层按
    /// `rc_net::quic::max_media_payload(mtu)`（默认 MTU 下 = 1120）覆盖，
    /// 否则多包大帧会被 `send_datagram` 整批拒收（T18 实测）。
    /// 合法范围 `[MIN_PACKET_PAYLOAD(16), MAX_PAYLOAD]`（下限的数学见
    /// [`MIN_PACKET_PAYLOAD`] 文档；修复卡D-1：预算 1 会放行到运行期，
    /// 大于 64KB 的帧在 `split_frame` 的 `packet_cnt` assert panic），由
    /// [`PipelineConfig::validate`] 在构造期拒绝非法值。
    pub max_packet_payload: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            resolution: Resolution::new(1920, 1080),
            fps: 60,
            bitrate_bps: 8_000_000,
            prefer_hardware: false,
            target_latency_us: 22_000,
            trace_capacity: 4096,
            diff: DiffMode::TrustPlatform,
            clock_origin_us: None,
            codec: rc_encode::Codec::H264,
            async_decode: false,
            display_id: None,
            shows_cursor: false,
            max_packet_payload: MAX_PAYLOAD,
        }
    }
}

/// 平台硬件媒体提供者（由平台实现 crate 在进程启动时通过 [`register_platform_provider`] 注册）。
///
/// 核心管线（`rc-pipeline`）保持 100% 平台无关；各系统适配器通过实现本 trait
/// 注入 ScreenCaptureKit / VideoToolbox / Metal / DXGI / VAAPI 等真实硬件后端。
pub trait PlatformMediaProvider: Send + Sync {
    /// 读取与平台硬件采集时间戳同域的单调主机时钟（微秒）。
    fn host_clock_us(&self) -> Option<u64> {
        None
    }

    /// 当前平台硬件编解码后端是否支持 HEVC（H.265）低延迟路径。
    fn supports_hevc(&self) -> bool {
        false
    }

    /// 提升当前工作线程（采集 / 编码）至平台低延迟实时 QoS。
    fn promote_current_thread_qos(&self) {}

    /// 按管线配置创建真实硬件采集后端及其诊断标签。
    fn create_capture(
        &self,
        _cfg: &PipelineConfig,
    ) -> Result<(Box<dyn CaptureBackend>, &'static str)> {
        Err(Error::InvalidConfig(
            "no hardware capture backend registered".into(),
        ))
    }

    /// 按管线配置创建真实硬件编码后端及其诊断标签。
    fn create_encoder(&self, _cfg: &PipelineConfig) -> Result<(Box<dyn Encoder>, &'static str)> {
        Err(Error::InvalidConfig(
            "no hardware encoder backend registered".into(),
        ))
    }

    /// 按管线配置创建真实硬件解码后端及其诊断标签。
    fn create_decoder(&self, _cfg: &PipelineConfig) -> Result<(Box<dyn Decoder>, &'static str)> {
        Err(Error::InvalidConfig(
            "no hardware decoder backend registered".into(),
        ))
    }

    /// 按管线配置创建真实硬件呈现后端及其诊断标签。
    fn create_renderer(&self, _cfg: &PipelineConfig) -> Result<(Box<dyn Renderer>, &'static str)> {
        Err(Error::InvalidConfig(
            "no hardware renderer backend registered".into(),
        ))
    }
}

static PLATFORM_MEDIA_PROVIDER: OnceLock<Arc<dyn PlatformMediaProvider>> = OnceLock::new();

/// 注册当前进程的平台硬件媒体提供者（仅首次调用生效）。
pub fn register_platform_provider(provider: Arc<dyn PlatformMediaProvider>) -> bool {
    PLATFORM_MEDIA_PROVIDER.set(provider).is_ok()
}

/// 若已注册平台硬件提供者，提升当前线程的调度服务质量。
pub fn promote_current_thread_qos() {
    if let Some(p) = PLATFORM_MEDIA_PROVIDER.get() {
        p.promote_current_thread_qos();
    }
}

/// 读取与当前平台硬件采集时间戳（如 macOS 为 `CMClockGetHostTimeClock()`）同域的
/// 单调主机时钟（微秒）；未注册平台提供者或不支持时返回 `None`。
pub fn host_clock_us() -> Option<u64> {
    PLATFORM_MEDIA_PROVIDER
        .get()
        .and_then(|p| p.host_clock_us())
}

impl PipelineConfig {
    /// 校验。非法项以 [`Error::InvalidConfig`] 返回。
    pub fn validate(&self) -> Result<()> {
        if self.resolution.width == 0 || self.resolution.height == 0 {
            return Err(Error::InvalidConfig(
                "pipeline: resolution must be non-zero".into(),
            ));
        }
        if self.fps == 0 {
            return Err(Error::InvalidConfig("pipeline: fps must be > 0".into()));
        }
        if self.bitrate_bps == 0 {
            return Err(Error::InvalidConfig(
                "pipeline: bitrate_bps must be > 0".into(),
            ));
        }
        // 分片预算的构造期校验（split_frame 内的 assert 在这里给出带字段名
        // 的错误，防止非法配置活到运行期才 panic）。下限 16 的数学见
        // MIN_PACKET_PAYLOAD 文档（修复卡D-1：预算 1 放行时，> 64KB 帧切出
        // > 65535 片，packet_cnt 的 assert 在生产路径 panic）。
        if self.max_packet_payload < MIN_PACKET_PAYLOAD || self.max_packet_payload > MAX_PAYLOAD {
            return Err(Error::InvalidConfig(format!(
                "pipeline: max_packet_payload must be in [{MIN_PACKET_PAYLOAD}, {MAX_PAYLOAD}] (got {})",
                self.max_packet_payload
            )));
        }
        Ok(())
    }

    /// 采集等待上限（契约 C10：16ms，既不空转也不漏帧间隔）。
    pub fn frame_timeout(&self) -> Duration {
        Duration::from_millis(16)
    }
}

/// 工厂实际选中的后端标签。诊断用：CLI 打到 stderr 让用户知道
/// 自己跑的是真后端还是降级假后端——静默降级是 P8 明令禁止的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendLabels {
    /// 采集后端（"sck" / "fake"）。
    pub capture: &'static str,
    /// 编码后端（"videotoolbox" / "fake"）。
    pub encoder: &'static str,
    /// 解码后端（"videotoolbox" / "fake"）。
    pub decoder: &'static str,
    /// 呈现后端（"metal" / "fake"）。
    pub renderer: &'static str,
}

/// 按 P8 选择采集后端：真后端构造失败（无权限 / 无显示器等）降级假后端；
/// `prefer_hardware == false` 直接选假后端。
pub fn select_capture(cfg: &PipelineConfig) -> Result<Box<dyn CaptureBackend>> {
    Ok(select_capture_labeled(cfg)?.0)
}

/// 同 [`select_capture`]，附带实际选中的标签。
pub fn select_capture_labeled(
    cfg: &PipelineConfig,
) -> Result<(Box<dyn CaptureBackend>, &'static str)> {
    if cfg.prefer_hardware {
        if let Some(provider) = PLATFORM_MEDIA_PROVIDER.get() {
            match provider.create_capture(cfg) {
                Ok(pair) => return Ok(pair),
                // 降级不静默：调用方（CLI / UI）负责把原因打到日志/stderr。
                Err(e) => {
                    eprintln!(
                        "rc-pipeline: hardware capture unavailable, falling back to fake: {e}"
                    )
                }
            }
        }
    }
    let fake = FakeBackend::new(FakeBackendConfig {
        display: rc_capture::DisplayInfo {
            id: rc_types::DisplayId(0),
            resolution: cfg.resolution,
            scale: 1.0,
            hdr: false,
        },
        fps: cfg.fps,
        content: FakeContent::Dynamic,
        dirty_rect: None,
    })?;
    Ok((Box::new(fake), "fake"))
}

/// 按 P8 选择编码后端。
pub fn select_encoder(cfg: &PipelineConfig) -> Result<Box<dyn Encoder>> {
    Ok(select_encoder_labeled(cfg)?.0)
}

/// 同 [`select_encoder`]，附带实际选中的标签。
pub fn select_encoder_labeled(cfg: &PipelineConfig) -> Result<(Box<dyn Encoder>, &'static str)> {
    if cfg.prefer_hardware {
        if let Some(provider) = PLATFORM_MEDIA_PROVIDER.get() {
            match provider.create_encoder(cfg) {
                Ok(pair) => return Ok(pair),
                Err(e) => {
                    eprintln!(
                        "rc-pipeline: hardware encoder unavailable, falling back to fake: {e}"
                    )
                }
            }
        }
    }
    Ok((
        Box::new(FakeEncoder::new(default_encoder_config(cfg))?),
        "fake",
    ))
}

/// 按 P8 选择解码后端。
pub fn select_decoder(cfg: &PipelineConfig) -> Result<Box<dyn Decoder>> {
    Ok(select_decoder_labeled(cfg)?.0)
}

/// 同 [`select_decoder`]，附带实际选中的标签。
pub fn select_decoder_labeled(cfg: &PipelineConfig) -> Result<(Box<dyn Decoder>, &'static str)> {
    if cfg.prefer_hardware {
        if let Some(provider) = PLATFORM_MEDIA_PROVIDER.get() {
            match provider.create_decoder(cfg) {
                Ok(pair) => return Ok(pair),
                Err(e) => {
                    eprintln!(
                        "rc-pipeline: hardware decoder unavailable, falling back to fake: {e}"
                    )
                }
            }
        }
    }
    let fake = FakeDecoder::new(FakeDecoderConfig {
        resolution: cfg.resolution,
        ..FakeDecoderConfig::default()
    })?;
    Ok((Box::new(fake), "fake"))
}

/// 按 P8 选择呈现后端。T08 契约只列了三个工厂；呈现是控制端管线的
/// 第四个必需部件，本函数是同一规则的延伸。
pub fn select_renderer(cfg: &PipelineConfig) -> Result<Box<dyn Renderer>> {
    Ok(select_renderer_labeled(cfg)?.0)
}

/// 同 [`select_renderer`]，附带实际选中的标签。
pub fn select_renderer_labeled(cfg: &PipelineConfig) -> Result<(Box<dyn Renderer>, &'static str)> {
    if cfg.prefer_hardware {
        if let Some(provider) = PLATFORM_MEDIA_PROVIDER.get() {
            match provider.create_renderer(cfg) {
                Ok(pair) => return Ok(pair),
                Err(e) => {
                    eprintln!(
                        "rc-pipeline: hardware renderer unavailable, falling back to fake: {e}"
                    )
                }
            }
        }
    }
    let fake = FakeRenderer::new(FakeRendererConfig {
        size: (cfg.resolution.width, cfg.resolution.height),
        ..FakeRendererConfig::default()
    })?;
    Ok((Box::new(fake), "fake"))
}

/// 一次选出全部后端（标签一并返回，CLI 诊断用）。
#[allow(clippy::type_complexity)]
pub fn select_all(
    cfg: &PipelineConfig,
) -> Result<(
    Box<dyn CaptureBackend>,
    Box<dyn Encoder>,
    Box<dyn Decoder>,
    Box<dyn Renderer>,
    BackendLabels,
)> {
    let (c, cl) = select_capture_labeled(cfg)?;
    let (e, el) = select_encoder_labeled(cfg)?;
    let (d, dl) = select_decoder_labeled(cfg)?;
    let (r, rl) = select_renderer_labeled(cfg)?;
    Ok((
        c,
        e,
        d,
        r,
        BackendLabels {
            capture: cl,
            encoder: el,
            decoder: dl,
            renderer: rl,
        },
    ))
}

/// 查询已注册平台后端是否支持 HEVC（H.265）硬件编解码。
pub fn platform_supports_hevc() -> bool {
    PLATFORM_MEDIA_PROVIDER
        .get()
        .is_some_and(|provider| provider.supports_hevc())
}

/// 由 [`PipelineConfig`] 构造低延迟编码器标准配置（零 B 帧、按需 IDR；
/// H.264 用 `Fastest` 压低编码尾延迟，HEVC 用 `Balanced` 兼顾更高画质密度与更低码率）。
pub fn default_encoder_config(cfg: &PipelineConfig) -> EncoderConfig {
    let preset = match cfg.codec {
        // Apple Silicon 真机实测：HEVC Balanced 较 Fastest 码率低 ~8% 且 4K@120 编码反而更快；
        // H.264 保持 Fastest（PrioritizeEncodingSpeedOverQuality=true）压低 P95/P99。
        rc_encode::Codec::Hevc => rc_encode::Preset::Balanced,
        _ => rc_encode::Preset::Fastest,
    };
    EncoderConfig {
        codec: cfg.codec,
        resolution: cfg.resolution,
        fps: cfg.fps,
        bitrate_bps: cfg.bitrate_bps,
        preset,
        low_latency: true, // E2
        gop_len: 0,        // 无限 GOP，按需 IDR
        b_frames: 0,       // E1
    }
}

/// 把 host 与 controller 两端的帧时间线拼成完整会话时间线（P4 的收口）。
///
/// 规则：
/// - 两端都有的帧：host 的前半段（Captured→Sent）+ controller 的后半段
///   （Received→Presented）+ controller 的结局（最终裁决）；
/// - 只在 host 里的帧（调度丢弃）：host 的标记与结局原样搬入；
/// - 会话截断时仍在途的帧（host 已发送、controller 未收齐）由调用方先经
///   [`ControllerPipeline::finish_in_flight`] 补 `LostInNetwork` 结局，
///   本函数只做拼接、不做裁决。
pub fn merge_traces(
    host: &rc_trace::TraceCollector,
    controller: &rc_trace::TraceCollector,
    capacity: usize,
) -> rc_trace::TraceCollector {
    use rc_trace::{FrameTrace, Mark, TraceCollector};

    fn copy_marks(src: &FrameTrace, slot: &mut FrameTrace) {
        for m in Mark::ALL {
            if let Some(ts) = src.at(m) {
                slot.mark(m, ts);
            }
        }
    }

    let mut out = TraceCollector::new(capacity);
    let mut seqs: Vec<rc_types::FrameSeq> = host
        .frames()
        .iter()
        .map(|f| f.seq())
        .chain(controller.frames().iter().map(|f| f.seq()))
        .collect();
    seqs.sort_unstable();
    seqs.dedup();

    for seq in seqs {
        let h = host.get(seq);
        let c = controller.get(seq);
        let slot = out.begin(seq);
        if let Some(hf) = h {
            copy_marks(hf, slot);
        }
        if let Some(cf) = c {
            copy_marks(cf, slot);
        }
        // 结局优先取 controller（Displayed/LostInNetwork/DecodeError 是
        // 最终裁决）；host-only 帧退回 host 的 Drop 结局。
        let outcome = c
            .and_then(|cf| cf.outcome())
            .or_else(|| h.and_then(|hf| hf.outcome()));
        if let Some(o) = outcome {
            slot.finish(o);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_zero_fields() {
        let bad_fps = PipelineConfig {
            fps: 0,
            ..PipelineConfig::default()
        };
        assert!(bad_fps.validate().is_err());
        let bad_res = PipelineConfig {
            resolution: Resolution::new(0, 100),
            ..PipelineConfig::default()
        };
        assert!(bad_res.validate().is_err());
        assert!(PipelineConfig::default().validate().is_ok());
    }

    /// 分片预算的构造期校验：小于 [`MIN_PACKET_PAYLOAD`]（含 0，修复
    /// 卡D-1：预算 1 会把 > 64KB 帧放行到 `split_frame` 的 `packet_cnt`
    /// assert panic）与超过 [`MAX_PAYLOAD`] 的值必须被
    /// [`PipelineConfig::validate`] 拒绝，错误信息带字段名。
    #[test]
    fn config_rejects_invalid_packet_budget() {
        let zero = PipelineConfig {
            max_packet_payload: 0,
            ..PipelineConfig::default()
        };
        let err = zero.validate().unwrap_err();
        assert!(
            matches!(&err, Error::InvalidConfig(msg) if msg.contains("max_packet_payload")),
            "0 预算应被拒绝且带字段名，实际 {err:?}"
        );

        // 修复卡D-1：预算 1（及其他 < 16 的值）同样被构造期拒绝。
        for too_small in [1usize, 8, 15] {
            let cfg = PipelineConfig {
                max_packet_payload: too_small,
                ..PipelineConfig::default()
            };
            assert!(
                matches!(
                    cfg.validate().unwrap_err(),
                    Error::InvalidConfig(ref msg) if msg.contains("max_packet_payload")
                ),
                "预算 {too_small} 应被拒绝（split_frame 的 packet_cnt 会溢出 u16）"
            );
        }

        let over = PipelineConfig {
            max_packet_payload: MAX_PAYLOAD + 1,
            ..PipelineConfig::default()
        };
        assert!(
            matches!(
                over.validate().unwrap_err(),
                Error::InvalidConfig(ref msg) if msg.contains("max_packet_payload")
            ),
            "超过 MAX_PAYLOAD 的预算应被拒绝"
        );

        // 边界值：下限 16 与 MAX_PAYLOAD 本身合法（默认值即 MAX_PAYLOAD）。
        PipelineConfig {
            max_packet_payload: MIN_PACKET_PAYLOAD,
            ..PipelineConfig::default()
        }
        .validate()
        .expect("下限 16 合法");
        PipelineConfig {
            max_packet_payload: MAX_PAYLOAD,
            ..PipelineConfig::default()
        }
        .validate()
        .expect("MAX_PAYLOAD 合法");
        assert_eq!(PipelineConfig::default().max_packet_payload, MAX_PAYLOAD);
    }

    #[test]
    fn default_encoder_config_uses_balanced_for_hevc_and_fastest_for_h264() {
        let h264_cfg = PipelineConfig {
            codec: rc_encode::Codec::H264,
            ..PipelineConfig::default()
        };
        assert_eq!(
            default_encoder_config(&h264_cfg).preset,
            rc_encode::Preset::Fastest
        );

        let hevc_cfg = PipelineConfig {
            codec: rc_encode::Codec::Hevc,
            ..PipelineConfig::default()
        };
        assert_eq!(
            default_encoder_config(&hevc_cfg).preset,
            rc_encode::Preset::Balanced
        );
    }
}
