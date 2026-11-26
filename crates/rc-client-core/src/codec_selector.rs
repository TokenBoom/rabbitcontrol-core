//! 跨平台编解码自动选型引擎、会话级熔断状态机与后台硬件能力缓存。
//!
//! # 架构职责
//! - **零阻塞热路径**：硬件能力探测经 [`HardwareCapsStore`] 在后台线程异步执行并原子落盘，
//!   建连热路径只读内存缓存，绝不阻塞首帧；
//! - **确定性纯函数选型**：[`select_codec_plan`] 基于非对称「被控端编码能力 × 控制端解码能力」
//!   交集、硬件优先硬过滤、熔断剔除、分辨率上限过滤与多目标优先级打分产出 [`CodecPlan`]；
//! - **会话级熔断防震荡**：[`CodecCircuitBreaker`] 按 `(Codec, ResolutionTier)` 记录运行时失败，
//!   严禁自动探测回升（防画面闪烁），仅在用户手动切换或变更分辨率时显式重置。

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rc_encode::Codec;
use rc_pipeline::{ChromaSubsampling, CodecCapability, LatencyTier, RefinementCapability};
use serde::{Deserialize, Serialize};

use crate::config_paths;
use crate::display_ctrl::HIGH_REFRESH_FPS_THRESHOLD;

/// 硬件能力磁盘缓存格式版本号（结构升级时递增自动失效旧缓存）。
pub const HARDWARE_CAPS_CACHE_SCHEMA_VERSION: u32 = 1;

/// 硬件能力磁盘缓存文件允许的最大字节数（256 KiB，防止异常超大文件或 DoS 拖慢启动）。
pub const MAX_HARDWARE_CAPS_CACHE_BYTES: u64 = 256 * 1024;

/// 弱网带宽阈值（8 Mbps）：低于该值或处于中继链路时偏向压缩率更高的 `AV1(SCC) > HEVC > H264`。
pub const WEAK_NETWORK_BITRATE_BPS: u32 = 8_000_000;

/// 硬件能力磁盘缓存键（OS + 架构 + GPU 标识 + 驱动版本 + Core 版本任一变化即失效重探）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HardwareCapsCacheKey {
    /// 操作系统标识（如 `"macos"` / `"windows"` / `"linux"`）。
    pub os: String,
    /// CPU 架构标识（如 `"arm64"` / `"x86_64"`）。
    pub arch: String,
    /// GPU 型号或设备标识（无专用探测钩子时使用平台默认标签）。
    pub gpu_id: String,
    /// 显卡驱动或系统图形栈版本。
    pub driver_version: String,
    /// Core 版本号（应用升级新增编解码能力时自动失效旧缓存并重探）。
    #[serde(default)]
    pub core_version: String,
}

impl HardwareCapsCacheKey {
    /// 基于当前编译目标、运行平台与 Core 版本构造默认缓存键。
    pub fn current_default() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: crate::platform::current_app_arch().to_string(),
            gpu_id: "default-gpu".to_string(),
            driver_version: "default-driver".to_string(),
            core_version: crate::version::core_version().to_string(),
        }
    }
}

/// 原子落盘的硬件编解码与静帧细化能力缓存条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareCapsCacheEntry {
    /// 缓存格式版本（必须等于 [`HARDWARE_CAPS_CACHE_SCHEMA_VERSION`]）。
    pub schema_version: u32,
    /// 硬件指纹缓存键。
    pub key: HardwareCapsCacheKey,
    /// 本机编码能力清单。
    #[serde(default)]
    pub encode_caps: Vec<CodecCapability>,
    /// 本机解码能力清单。
    #[serde(default)]
    pub decode_caps: Vec<CodecCapability>,
    /// 本机静帧细化能力。
    #[serde(default)]
    pub refinement_caps: RefinementCapability,
    /// 探测完成时间戳（Unix 秒）。
    #[serde(default)]
    pub probed_at_unix_secs: u64,
}

impl HardwareCapsCacheEntry {
    /// 构造带当前版本号与时间戳的缓存条目。
    pub fn new(
        key: HardwareCapsCacheKey,
        encode_caps: Vec<CodecCapability>,
        decode_caps: Vec<CodecCapability>,
        refinement_caps: RefinementCapability,
    ) -> Self {
        let probed_at_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            schema_version: HARDWARE_CAPS_CACHE_SCHEMA_VERSION,
            key,
            encode_caps,
            decode_caps,
            refinement_caps,
            probed_at_unix_secs,
        }
    }
}

/// 返回默认硬件能力缓存文件路径（位于配置根目录下 `hardware-caps-cache.json`）。
pub fn default_hardware_caps_cache_path() -> PathBuf {
    config_paths::config_dir().join("hardware-caps-cache.json")
}

/// 从磁盘读取并校验硬件能力缓存；symlink、非常规文件、超过 256 KiB、损坏、schema 版本不符或键不匹配均返回 `None`。
pub fn load_hardware_caps_cache(
    path: &Path,
    expected_key: &HardwareCapsCacheKey,
) -> Option<HardwareCapsCacheEntry> {
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.len() > MAX_HARDWARE_CAPS_CACHE_BYTES
    {
        return None;
    }
    let raw = fs::read(path).ok()?;
    if (raw.len() as u64) > MAX_HARDWARE_CAPS_CACHE_BYTES {
        return None;
    }
    let entry: HardwareCapsCacheEntry = serde_json::from_slice(&raw).ok()?;
    if entry.schema_version != HARDWARE_CAPS_CACHE_SCHEMA_VERSION || &entry.key != expected_key {
        return None;
    }
    Some(entry)
}

/// 将硬件能力缓存条目以原子临时文件 + `rename` 方式写入磁盘（零半写损坏窗口）。
pub fn save_hardware_caps_cache(path: &Path, entry: &HardwareCapsCacheEntry) -> Result<(), String> {
    let bytes =
        serde_json::to_vec_pretty(entry).map_err(|e| format!("序列化硬件能力缓存失败: {e}"))?;
    config_paths::write_private_file(path, &bytes)
}

/// 非阻塞后台硬件能力探测与内存/磁盘缓存管理器。
///
/// 建连热路径仅调用 [`Self::cached_snapshot`] 做 O(1) 内存读取，严禁在热路径执行同步硬件探测。
pub struct HardwareCapsStore {
    path: PathBuf,
    key: HardwareCapsCacheKey,
    cached: Arc<RwLock<Option<HardwareCapsCacheEntry>>>,
    probe_in_flight: Arc<AtomicBool>,
}

impl HardwareCapsStore {
    /// 启动时从磁盘加载匹配当前 `key` 的缓存条目（未命中时内存为空，不阻塞探测）。
    pub fn new_from_disk(path: PathBuf, key: HardwareCapsCacheKey) -> Self {
        let initial = load_hardware_caps_cache(&path, &key);
        Self {
            path,
            key,
            cached: Arc::new(RwLock::new(initial)),
            probe_in_flight: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 非阻塞读取当前内存缓存快照（建连热路径唯一入口，永不阻塞首帧）。
    pub fn cached_snapshot(&self) -> Option<HardwareCapsCacheEntry> {
        self.cached
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 判断当前是否已有后台探测线程在途。
    pub fn is_probe_in_flight(&self) -> bool {
        self.probe_in_flight.load(Ordering::Acquire)
    }

    /// 触发一次非阻塞后台硬件探测并在完成后更新内存缓存及原子落盘；
    /// 若已有探测在途则幂等返回 `false`。
    pub fn trigger_background_probe<F>(&self, probe_fn: F) -> bool
    where
        F: FnOnce() -> (
                Vec<CodecCapability>,
                Vec<CodecCapability>,
                RefinementCapability,
            ) + Send
            + 'static,
    {
        if self
            .probe_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let path = self.path.clone();
        let key = self.key.clone();
        let cached = Arc::clone(&self.cached);
        let in_flight = Arc::clone(&self.probe_in_flight);
        let spawn_res = thread::Builder::new()
            .name("rc-hw-caps-probe".to_string())
            .spawn(move || {
                struct InFlightResetGuard(Arc<AtomicBool>);
                impl Drop for InFlightResetGuard {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }
                let _reset_guard = InFlightResetGuard(in_flight);
                let (enc, dec, refinement) = probe_fn();
                let entry = HardwareCapsCacheEntry::new(key, enc, dec, refinement);
                *cached.write().unwrap_or_else(|e| e.into_inner()) = Some(entry.clone());
                let _ = save_hardware_caps_cache(&path, &entry);
            });
        if spawn_res.is_err() {
            self.probe_in_flight.store(false, Ordering::Release);
            return false;
        }
        true
    }
}

static PROCESS_HW_CAPS_STORE: OnceLock<HardwareCapsStore> = OnceLock::new();

fn process_hw_caps_store() -> &'static HardwareCapsStore {
    PROCESS_HW_CAPS_STORE.get_or_init(|| {
        HardwareCapsStore::new_from_disk(
            default_hardware_caps_cache_path(),
            HardwareCapsCacheKey::current_default(),
        )
    })
}

/// 触发进程级后台硬件能力探测（非阻塞，适合在应用启动或空闲时调用）。
pub fn trigger_default_hardware_caps_probe() -> bool {
    process_hw_caps_store().trigger_background_probe(|| {
        (
            rc_pipeline::platform_encode_capabilities(),
            rc_pipeline::platform_decode_capabilities(),
            rc_pipeline::platform_refinement_capability(),
        )
    })
}

/// 非阻塞读取本机编码能力（建连热路径只读缓存；未命中时返回零耗时默认能力并异步触发后台探测，绝不阻塞首帧）。
pub fn cached_or_platform_encode_caps(prefer_hardware: bool) -> Vec<CodecCapability> {
    if !prefer_hardware {
        return rc_pipeline::default_software_codec_capabilities();
    }
    if let Some(entry) = process_hw_caps_store().cached_snapshot() {
        if !entry.encode_caps.is_empty() {
            return entry.encode_caps;
        }
    }
    let _ = trigger_default_hardware_caps_probe();
    rc_pipeline::default_codec_capabilities(rc_pipeline::platform_supports_hevc())
}

/// 非阻塞读取本机解码能力（建连热路径只读缓存；未命中时返回零耗时默认能力并异步触发后台探测，绝不阻塞首帧）。
pub fn cached_or_platform_decode_caps(prefer_hardware: bool) -> Vec<CodecCapability> {
    if !prefer_hardware {
        return rc_pipeline::default_software_codec_capabilities();
    }
    if let Some(entry) = process_hw_caps_store().cached_snapshot() {
        if !entry.decode_caps.is_empty() {
            return entry.decode_caps;
        }
    }
    let _ = trigger_default_hardware_caps_probe();
    rc_pipeline::default_codec_capabilities(rc_pipeline::platform_supports_hevc())
}

/// 非阻塞读取本机静帧细化能力（建连热路径只读缓存；未命中时异步触发后台探测并返回默认不支持）。
pub fn cached_or_platform_refinement_caps(prefer_hardware: bool) -> RefinementCapability {
    if !prefer_hardware {
        return RefinementCapability::default();
    }
    if let Some(entry) = process_hw_caps_store().cached_snapshot() {
        return entry.refinement_caps;
    }
    let _ = trigger_default_hardware_caps_probe();
    RefinementCapability::default()
}

/// 用于会话级熔断隔离的分辨率档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionTier {
    /// 720p 及以下（`<= 1_000_000` 像素）。
    Hd720,
    /// 1080p 档（`<= 2_300_000` 像素，覆盖 1920×1080 / 1920×1200）。
    Fhd1080,
    /// 1440p / 2K 档（`<= 4_500_000` 像素，覆盖 2560×1440 / 2560×1664）。
    Qhd1440,
    /// 4K 档（`<= 9_000_000` 像素，覆盖 3024×1964 / 3840×2160）。
    Uhd4k,
    /// 5K 及以上超高分档（`> 9_000_000` 像素，覆盖 5120×2880）。
    Uhd5kPlus,
}

impl ResolutionTier {
    /// 按宽高像素总数映射到对应的分辨率档位。
    pub const fn from_dimensions(width: u32, height: u32) -> Self {
        let pixels = (width as u64).saturating_mul(height as u64);
        if pixels <= 1_000_000 {
            Self::Hd720
        } else if pixels <= 2_300_000 {
            Self::Fhd1080
        } else if pixels <= 4_500_000 {
            Self::Qhd1440
        } else if pixels <= 9_000_000 {
            Self::Uhd4k
        } else {
            Self::Uhd5kPlus
        }
    }
}

/// 待选型流的目标分辨率与帧率参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamTarget {
    /// 目标宽度（像素）。
    pub width: u32,
    /// 目标高度（像素）。
    pub height: u32,
    /// 目标帧率（fps）。
    pub fps: u32,
}

impl StreamTarget {
    /// 计算目标像素吞吐率（px/s）。
    pub const fn pixel_rate(self) -> u64 {
        (self.width as u64)
            .saturating_mul(self.height as u64)
            .saturating_mul(self.fps as u64)
    }

    /// 归类为对应的分辨率档位（供熔断器索引）。
    pub const fn resolution_tier(self) -> ResolutionTier {
        ResolutionTier::from_dimensions(self.width, self.height)
    }
}

/// 链路与带宽提示（用于自动选型时在压缩率与超低延迟间权衡）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkHint {
    /// 是否经由服务端中继转发（TCP Relay）。
    #[serde(default)]
    pub is_relay: bool,
    /// 是否为局域网直连（UDP LAN）。
    #[serde(default)]
    pub is_lan: bool,
    /// 估算可用码率（bps；`0` 表示未知）。
    #[serde(default)]
    pub estimated_bitrate_bps: u32,
    /// 估算往返时延（微秒；`0` 表示未知）。
    #[serde(default)]
    pub rtt_us: u32,
}

impl NetworkHint {
    /// 是否属于中继或弱网（`< 8 Mbps`）受限链路。
    pub const fn is_constrained(self) -> bool {
        self.is_relay
            || (self.estimated_bitrate_bps > 0
                && self.estimated_bitrate_bps < WEAK_NETWORK_BITRATE_BPS)
    }
}

/// 用户编解码选型偏好模式。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "mode", content = "codec", rename_all = "snake_case")]
pub enum CodecSelectionPref {
    /// 自动均衡模式（按刷新率、链路条件与双端硬件能力自动择优）。
    #[default]
    Auto,
    /// 办公文字清晰优先（偏向 AV1 / 屏幕内容编码工具与静帧细化）。
    OfficeClear,
    /// 极致跟手低延迟优先（偏向 `UltraLow` 延迟档与高刷满帧吞吐）。
    UltraLowLatency,
    /// 用户手动指定编解码器（若受限或已熔断则按梯队降级）。
    Manual(Codec),
}

/// 编解码自动选型的可观测诊断原因码。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodecSelectReason {
    /// 用户手动锁定命中目标编解码器。
    ManualPinned,
    /// 高刷甜点达标优先（满足 `>= 90fps` 满帧像素率预算）。
    HighRefreshSweetSpot,
    /// 办公文字清晰模式优先（高压缩比 / 屏幕内容编码工具）。
    OfficeClarityPreferred,
    /// 极致低延迟模式优先（最低硬件延迟档）。
    UltraLowLatencyPreferred,
    /// 中继或弱网（`< 8 Mbps`）压缩效率优先。
    ConstrainedNetworkEfficiency,
    /// 高带宽局域网低延迟满帧优先。
    LanHighBandwidthLowLatency,
    /// 更高优先级候选已熔断后的降级选择。
    CircuitBreakerFallback,
    /// 自动均衡模式在常规非高刷广域网下择优选择。
    AutoBalanced,
    /// 安全兜底选择 H.264。
    H264SafeFallback,
}

/// 自动选型引擎产出的编解码执行计划与熔断回退梯队。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodecPlan {
    /// 权威选中的首选编解码器。
    pub codec: Codec,
    /// 按优先级排列的熔断回退梯队（不含当前 `codec`）。
    pub fallback_ladder: Vec<Codec>,
    /// 是否建议开启静帧文字无损细化。
    pub refinement_recommended: bool,
    /// 可观测选型原因码。
    pub reason: CodecSelectReason,
}

/// 会话级通用编解码熔断降级状态机。
///
/// 按 `(Codec, ResolutionTier)` 记录运行时失败（编码失败/过载或控制端上报 `CodecDecodeFailed`），
/// 严格禁止会话内自动探测回升以防反复切换闪烁，仅在手动切换或分辨率变更时显式重置。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodecCircuitBreaker {
    tripped: BTreeSet<(Codec, ResolutionTier)>,
    reasons: BTreeMap<(Codec, ResolutionTier), String>,
}

impl CodecCircuitBreaker {
    /// 构造空白熔断状态机。
    pub fn new() -> Self {
        Self::default()
    }

    /// 熔断指定 `(codec, tier)` 并记录原因；返回 `true` 表示本次为新增熔断，`false` 表示此前已熔断。
    pub fn trip(&mut self, codec: Codec, tier: ResolutionTier, reason: impl Into<String>) -> bool {
        let newly_tripped = self.tripped.insert((codec, tier));
        self.reasons.insert((codec, tier), reason.into());
        newly_tripped
    }

    /// 查询指定 `(codec, tier)` 是否已被熔断。
    pub fn is_tripped(&self, codec: Codec, tier: ResolutionTier) -> bool {
        self.tripped.contains(&(codec, tier))
    }

    /// 查询指定 `(codec, tier)` 的熔断原因（未熔断返回 `None`）。
    pub fn trip_reason(&self, codec: Codec, tier: ResolutionTier) -> Option<&str> {
        self.reasons.get(&(codec, tier)).map(String::as_str)
    }

    /// 按候选回退梯队返回当前 `tier` 下第一个未熔断的下一档编解码器（不会自动回升至已熔断档）。
    pub fn next_fallback(
        &self,
        current: Codec,
        tier: ResolutionTier,
        ladder: &[Codec],
    ) -> Option<Codec> {
        if let Some(&next) = ladder
            .iter()
            .find(|&&c| c != current && !self.is_tripped(c, tier))
        {
            return Some(next);
        }
        if current != Codec::H264 && !self.is_tripped(Codec::H264, tier) {
            return Some(Codec::H264);
        }
        None
    }

    /// 仅在用户手动切换编解码器或变更流分辨率时显式重置全部熔断记录（严禁定时自动重置）。
    pub fn reset_on_manual_or_res_change(&mut self) {
        self.tripped.clear();
        self.reasons.clear();
    }

    /// 当前被熔断的条目数量（诊断与测试用）。
    pub fn tripped_count(&self) -> usize {
        self.tripped.len()
    }
}

#[derive(Debug, Clone)]
struct CandidatePair {
    codec: Codec,
    both_hardware: bool,
    max_width: u32,
    max_height: u32,
    max_pixel_rate: u64,
    screen_content_tools: bool,
    chroma: ChromaSubsampling,
    worst_latency: LatencyTier,
}

const fn latency_rank(tier: LatencyTier) -> u8 {
    match tier {
        LatencyTier::UltraLow => 3,
        LatencyTier::Low => 2,
        LatencyTier::Normal => 1,
    }
}

const fn worst_latency_tier(a: LatencyTier, b: LatencyTier) -> LatencyTier {
    if latency_rank(a) <= latency_rank(b) {
        a
    } else {
        b
    }
}

fn best_cap_for_codec(caps: &[CodecCapability], codec: Codec) -> Option<&CodecCapability> {
    caps.iter().filter(|c| c.codec == codec).max_by_key(|c| {
        (
            c.hardware,
            latency_rank(c.latency_tier),
            c.max_pixel_rate,
            u64::from(c.max_width).saturating_mul(u64::from(c.max_height)),
            c.screen_content_tools,
        )
    })
}

fn compression_rank(c: &CandidatePair) -> u8 {
    match c.codec {
        Codec::Av1 if c.screen_content_tools => 4,
        Codec::Av1 => 3,
        Codec::Hevc => 2,
        Codec::H264 => 1,
    }
}

fn codec_fallback_rank(codec: Codec) -> u8 {
    match codec {
        Codec::Hevc => 3,
        Codec::Av1 => 2,
        Codec::H264 => 1,
    }
}

fn score_candidate(
    c: &CandidatePair,
    target: StreamTarget,
    net: NetworkHint,
    pref: CodecSelectionPref,
) -> (u8, u8, u8, u8, u8, u64, u8) {
    let is_high_refresh = target.fps >= HIGH_REFRESH_FPS_THRESHOLD;
    let meets_sweet_spot = !is_high_refresh || target.pixel_rate() <= c.max_pixel_rate;
    let manual_hit = match pref {
        CodecSelectionPref::Manual(pinned) if pinned == c.codec => 1u8,
        _ => 0u8,
    };
    // ① 高刷甜点达标性（>= 90fps 时满足双端像素吞吐上限绝对优先）
    let high_refresh_score = if is_high_refresh {
        u8::from(meets_sweet_spot)
    } else {
        1u8
    };
    let lat = latency_rank(c.worst_latency);
    let comp = compression_rank(c);
    // ② 用户偏好模式得分
    let mode_score = match pref {
        CodecSelectionPref::OfficeClear => comp,
        CodecSelectionPref::UltraLowLatency => lat,
        CodecSelectionPref::Auto | CodecSelectionPref::Manual(_) => 0,
    };
    // ③ 链路与带宽倾向得分：中继/弱网偏向 AV1(SCC) > HEVC > H264；高带宽 LAN 偏向低延迟满帧
    let (net_primary, net_secondary) = if net.is_constrained() {
        (comp, lat)
    } else if net.is_lan || is_high_refresh {
        (lat, codec_fallback_rank(c.codec))
    } else {
        (lat, comp)
    };
    // ④ H.264 最后兜底（高像素吞吐与现代编码器优先）
    (
        manual_hit,
        high_refresh_score,
        mode_score,
        net_primary,
        net_secondary,
        c.max_pixel_rate,
        codec_fallback_rank(c.codec),
    )
}

/// 确定性跨平台编解码自动选型纯函数。
///
/// 过滤流水线：
/// 1. 双端交集（`host_enc ∩ client_dec`）；
/// 2. 硬件加速优先（存在双端 `hardware == true` 候选时剔除软编/软解）；
/// 3. 会话级熔断剔除（跳过当前分辨率档位已被 [`CodecCircuitBreaker`] 熔断的编解码器）；
/// 4. 分辨率上限过滤（剔除 `max_width < target.width || max_height < target.height` 的编解码器，例如 5K 自动排除 H.264）；
///
/// 优先级打分：① 高刷甜点达标性 → ② 用户偏好模式 → ③ 链路/带宽策略 → ④ `H.264` 兜底。
pub fn select_codec_plan(
    host_enc: &[CodecCapability],
    client_dec: &[CodecCapability],
    target: StreamTarget,
    net: NetworkHint,
    pref: CodecSelectionPref,
    breaker: &CodecCircuitBreaker,
) -> CodecPlan {
    let tier = target.resolution_tier();
    let is_high_refresh = target.fps >= HIGH_REFRESH_FPS_THRESHOLD;

    // 1) 双端交集（逐 codec 取各自最优能力项）
    let mut candidates = Vec::with_capacity(3);
    for codec in [Codec::Av1, Codec::Hevc, Codec::H264] {
        if let (Some(h), Some(c)) = (
            best_cap_for_codec(host_enc, codec),
            best_cap_for_codec(client_dec, codec),
        ) {
            candidates.push(CandidatePair {
                codec,
                both_hardware: h.hardware && c.hardware,
                max_width: h.max_width.min(c.max_width),
                max_height: h.max_height.min(c.max_height),
                max_pixel_rate: h.max_pixel_rate.min(c.max_pixel_rate),
                screen_content_tools: h.screen_content_tools,
                chroma: h.chroma,
                worst_latency: worst_latency_tier(h.latency_tier, c.latency_tier),
            });
        }
    }

    if candidates.is_empty() {
        return CodecPlan {
            codec: Codec::H264,
            fallback_ladder: Vec::new(),
            refinement_recommended: matches!(pref, CodecSelectionPref::OfficeClear),
            reason: CodecSelectReason::H264SafeFallback,
        };
    }

    // 记录熔断剔除前本应排名第一的候选（应用硬加优先后），用于准确生成 `CircuitBreakerFallback` 诊断原因
    let pre_breaker_has_hw = candidates.iter().any(|c| c.both_hardware);
    let pre_breaker_top = candidates
        .iter()
        .filter(|c| !pre_breaker_has_hw || c.both_hardware)
        .filter(|c| {
            (target.width == 0 || c.max_width >= target.width)
                && (target.height == 0 || c.max_height >= target.height)
        })
        .max_by_key(|c| score_candidate(c, target, net, pref))
        .map(|c| c.codec);

    // 2) 熔断剔除（先剔除已熔断项，再在未熔断候选中执行硬加优先，避免全硬加熔断时误删可用软编/软解）
    let tripped_any = candidates.iter().any(|c| breaker.is_tripped(c.codec, tier));
    candidates.retain(|c| !breaker.is_tripped(c.codec, tier));

    if candidates.is_empty() {
        return CodecPlan {
            codec: Codec::H264,
            fallback_ladder: Vec::new(),
            refinement_recommended: matches!(pref, CodecSelectionPref::OfficeClear),
            reason: if tripped_any {
                CodecSelectReason::CircuitBreakerFallback
            } else {
                CodecSelectReason::H264SafeFallback
            },
        };
    }

    // 3) 硬件加速优先：仅在未熔断候选中存在双端硬加时剔除软编/软解
    if candidates.iter().any(|c| c.both_hardware) {
        candidates.retain(|c| c.both_hardware);
    }

    // 4) 分辨率上限过滤（若全部被排除，严格保留最大分辨率容积降序兜底，不被普通打分覆盖）
    let mut res_filtered: Vec<CandidatePair> = candidates
        .iter()
        .filter(|c| {
            (target.width == 0 || c.max_width >= target.width)
                && (target.height == 0 || c.max_height >= target.height)
        })
        .cloned()
        .collect();
    let ranked = if !res_filtered.is_empty() {
        res_filtered.sort_by(|a, b| {
            score_candidate(b, target, net, pref).cmp(&score_candidate(a, target, net, pref))
        });
        res_filtered
    } else {
        candidates.sort_by_key(|c| {
            std::cmp::Reverse((
                u64::from(c.max_width).saturating_mul(u64::from(c.max_height)),
                score_candidate(c, target, net, pref),
            ))
        });
        candidates
    };

    let winner = &ranked[0];
    let fallback_ladder: Vec<Codec> = ranked[1..].iter().map(|c| c.codec).collect();
    let refinement_recommended = matches!(pref, CodecSelectionPref::OfficeClear)
        || (!is_high_refresh
            && !matches!(pref, CodecSelectionPref::UltraLowLatency)
            && winner.chroma == ChromaSubsampling::Yuv420);

    let reason = if matches!(pref, CodecSelectionPref::Manual(pinned) if pinned == winner.codec) {
        CodecSelectReason::ManualPinned
    } else if tripped_any
        && pre_breaker_top.is_some_and(|top| top != winner.codec && breaker.is_tripped(top, tier))
    {
        CodecSelectReason::CircuitBreakerFallback
    } else if is_high_refresh && target.pixel_rate() <= winner.max_pixel_rate {
        CodecSelectReason::HighRefreshSweetSpot
    } else if matches!(pref, CodecSelectionPref::OfficeClear) {
        CodecSelectReason::OfficeClarityPreferred
    } else if matches!(pref, CodecSelectionPref::UltraLowLatency) {
        CodecSelectReason::UltraLowLatencyPreferred
    } else if net.is_constrained() {
        CodecSelectReason::ConstrainedNetworkEfficiency
    } else if net.is_lan {
        CodecSelectReason::LanHighBandwidthLowLatency
    } else if winner.codec == Codec::H264 {
        CodecSelectReason::H264SafeFallback
    } else {
        CodecSelectReason::AutoBalanced
    };

    CodecPlan {
        codec: winner.codec,
        fallback_ladder,
        refinement_recommended,
        reason,
    }
}

/// 给定当前编解码器时仅向更低档位降级的静态安全梯队（旧端未发 `ClientMediaCaps` 时绝不从 H.264 反向升到 HEVC）。
const fn lower_fallback_ladder(current: Codec) -> &'static [Codec] {
    match current {
        Codec::Av1 => &[Codec::Hevc, Codec::H264],
        Codec::Hevc => &[Codec::H264],
        Codec::H264 => &[],
    }
}

/// 被控端会话级编解码协商与熔断控制器（封装 `codec_generation`、`prev_generation` 跨通道竞态宽限、`supports_ext_codec_flags` 门禁与熔断降级状态）。
#[derive(Debug, Clone)]
pub struct HostCodecNegotiator {
    codec_generation: u64,
    prev_generation: Option<u64>,
    breaker: CodecCircuitBreaker,
    host_encode_caps: Vec<CodecCapability>,
    client_decode_caps: Option<Vec<CodecCapability>>,
    client_refinement_caps: Option<RefinementCapability>,
    client_pref: CodecSelectionPref,
    client_supports_ext_codec_flags: bool,
    last_plan: Option<CodecPlan>,
}

impl HostCodecNegotiator {
    /// 以本机编码能力清单构造初始协商控制器（起始 `codec_generation = 1`）。
    pub fn new(host_encode_caps: Vec<CodecCapability>) -> Self {
        Self {
            codec_generation: 1,
            prev_generation: None,
            breaker: CodecCircuitBreaker::new(),
            host_encode_caps,
            client_decode_caps: None,
            client_refinement_caps: None,
            client_pref: CodecSelectionPref::Auto,
            client_supports_ext_codec_flags: false,
            last_plan: None,
        }
    }

    /// 当前权威编解码代次（每次发生实际编解码切换递增，用于过滤陈旧的 `CodecDecodeFailed` 回声）。
    pub fn codec_generation(&self) -> u64 {
        self.codec_generation
    }

    /// 上一次实际编解码切换前的代次（用于承接 UDP 媒体帧先于 Stream A `Capabilities` 抵达时的单代宽限）。
    pub fn prev_generation(&self) -> Option<u64> {
        self.prev_generation
    }

    /// 递增并返回新的编解码代次，同时记录切换前的 `prev_generation`。
    pub fn bump_generation(&mut self) -> u64 {
        self.prev_generation = Some(self.codec_generation);
        self.codec_generation = self.codec_generation.saturating_add(1);
        self.codec_generation
    }

    /// 用户手动指定编解码器时同步记录 `Manual(codec)` 偏好并重置会话级熔断器。
    pub fn set_manual_pref(&mut self, codec: Codec) {
        self.client_pref = CodecSelectionPref::Manual(codec);
        self.breaker.reset_on_manual_or_res_change();
    }

    /// 对端是否已确认支持 32B 媒体头扩展 codec 位（`HeaderFlags::CODEC_EXT` / `bit5`）。
    pub fn client_supports_ext_codec_flags(&self) -> bool {
        self.client_supports_ext_codec_flags
    }

    /// 返回被控端当前可用的非熔断编码能力清单（若对端不支持扩展标志位，自动排除 `AV1`）。
    pub fn effective_host_encode_caps(&self) -> Vec<CodecCapability> {
        self.host_encode_caps
            .iter()
            .filter(|c| self.client_supports_ext_codec_flags || c.codec != Codec::Av1)
            .cloned()
            .collect()
    }

    /// 返回完整被控端编码能力清单（供 `Capabilities` 上报）。
    pub fn host_encode_caps(&self) -> &[CodecCapability] {
        &self.host_encode_caps
    }

    /// 判断当前分辨率档位下指定编解码器是否可由本端编码（满足能力存在、未熔断、且 AV1 需双端确认扩展标志位）。
    pub fn is_codec_selectable(&self, codec: Codec, tier: ResolutionTier) -> bool {
        if codec == Codec::Av1 && !self.client_supports_ext_codec_flags {
            return false;
        }
        if self.breaker.is_tripped(codec, tier) {
            return false;
        }
        if codec == Codec::H264 {
            return true;
        }
        self.host_encode_caps.iter().any(|c| c.codec == codec)
    }

    /// 访问内部熔断状态机引用（诊断/测试用）。
    pub fn breaker(&self) -> &CodecCircuitBreaker {
        &self.breaker
    }

    /// 收到控制端 `ClientMediaCaps` 后执行权威 [`select_codec_plan`] 裁决。
    ///
    /// 仅当 `supports_ext_codec_flags == true` 时才允许选出 `Codec::Av1`。
    pub fn on_client_media_caps(
        &mut self,
        decode_caps: Vec<CodecCapability>,
        refinement_caps: Option<RefinementCapability>,
        pref: CodecSelectionPref,
        supports_ext_codec_flags: bool,
        target: StreamTarget,
        net: NetworkHint,
    ) -> CodecPlan {
        self.client_decode_caps = Some(decode_caps);
        self.client_refinement_caps = refinement_caps;
        self.client_pref = pref;
        self.client_supports_ext_codec_flags = supports_ext_codec_flags;
        self.recompute_plan(target, net)
    }

    /// 按当前记录的对端能力与熔断状态重新裁决编解码计划。
    pub fn recompute_plan(&mut self, target: StreamTarget, net: NetworkHint) -> CodecPlan {
        let host_caps = self.effective_host_encode_caps();
        let client_caps = self.client_decode_caps.as_deref().unwrap_or(&[]);
        let plan = select_codec_plan(
            &host_caps,
            client_caps,
            target,
            net,
            self.client_pref,
            &self.breaker,
        );
        self.last_plan = Some(plan.clone());
        plan
    }

    /// 收到控制端 `CodecDecodeFailed` 时按代次与当前生效 codec 校验并触发熔断降级：
    /// - 严格拦截 `failed_codec != active_codec`（旧 codec 的迟到回声）或过期代次（既不等于 `codec_generation`
    ///   也不等于 `prev_generation`）；
    /// - 允许 `generation == self.codec_generation || (failed_codec == active_codec && self.prev_generation == Some(generation))`
    ///   触发降级，彻底消除「UDP 新 codec 帧先于 Stream A `Capabilities` 抵达」导致的永久黑屏竞态。
    pub fn on_codec_decode_failed(
        &mut self,
        failed_codec: Codec,
        generation: u64,
        reason: impl Into<String>,
        active_codec: Codec,
        target: StreamTarget,
        net: NetworkHint,
    ) -> Option<CodecPlan> {
        let gen_matches = generation == self.codec_generation
            || (failed_codec == active_codec && self.prev_generation == Some(generation));
        if failed_codec != active_codec || !gen_matches {
            return None;
        }
        let tier = target.resolution_tier();
        self.breaker.trip(failed_codec, tier, reason);
        let plan = if self.client_decode_caps.is_some() {
            self.recompute_plan(target, net)
        } else {
            let next = self
                .breaker
                .next_fallback(active_codec, tier, lower_fallback_ladder(active_codec))
                .unwrap_or(Codec::H264);
            let remaining = if next == Codec::H264 {
                Vec::new()
            } else {
                vec![Codec::H264]
            };
            CodecPlan {
                codec: next,
                fallback_ladder: remaining,
                refinement_recommended: false,
                reason: CodecSelectReason::CircuitBreakerFallback,
            }
        };
        self.last_plan = Some(plan.clone());
        Some(plan)
    }

    /// 编码侧运行时构造失败或连续过载时触发熔断并返回下一档回退计划。
    pub fn on_encode_failure(
        &mut self,
        failed_codec: Codec,
        reason: impl Into<String>,
        active_codec: Codec,
        target: StreamTarget,
        net: NetworkHint,
    ) -> CodecPlan {
        let tier = target.resolution_tier();
        self.breaker.trip(failed_codec, tier, reason);
        if self.client_decode_caps.is_some() {
            self.recompute_plan(target, net)
        } else {
            let next = self
                .breaker
                .next_fallback(active_codec, tier, lower_fallback_ladder(active_codec))
                .unwrap_or(Codec::H264);
            let plan = CodecPlan {
                codec: next,
                fallback_ladder: if next == Codec::H264 {
                    Vec::new()
                } else {
                    vec![Codec::H264]
                },
                refinement_recommended: false,
                reason: CodecSelectReason::CircuitBreakerFallback,
            };
            self.last_plan = Some(plan.clone());
            plan
        }
    }

    /// 用户手动指定编解码器或变更分辨率时重置会话级熔断状态。
    pub fn reset_breaker_on_manual_or_res_change(&mut self) {
        self.breaker.reset_on_manual_or_res_change();
    }

    /// 返回对端最近一次上报的静帧细化能力（供后续 `7e-2` 细化管线读取）。
    pub fn client_refinement_caps(&self) -> Option<&RefinementCapability> {
        self.client_refinement_caps.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn cap(
        codec: Codec,
        hardware: bool,
        max_w: u32,
        max_h: u32,
        max_px_rate: u64,
        scc: bool,
        latency: LatencyTier,
    ) -> CodecCapability {
        CodecCapability {
            codec,
            hardware,
            max_width: max_w,
            max_height: max_h,
            max_pixel_rate: max_px_rate,
            screen_content_tools: scc,
            chroma: ChromaSubsampling::Yuv420,
            latency_tier: latency,
        }
    }

    /// Windows Host（NVENC AV1 SCC + HEVC + H264）与 macOS M3+ Client（AV1 硬解 + HEVC + H264）非对称能力组合。
    fn win_host_caps() -> Vec<CodecCapability> {
        vec![
            cap(
                Codec::Av1,
                true,
                7680,
                4320,
                400_000_000,
                true,
                LatencyTier::Low,
            ),
            cap(
                Codec::Hevc,
                true,
                7680,
                4320,
                650_000_000,
                false,
                LatencyTier::UltraLow,
            ),
            cap(
                Codec::H264,
                true,
                4096,
                2304,
                280_000_000,
                false,
                LatencyTier::UltraLow,
            ),
        ]
    }

    fn macos_m3_client_decode_caps() -> Vec<CodecCapability> {
        vec![
            cap(
                Codec::Av1,
                true,
                7680,
                4320,
                420_000_000,
                false,
                LatencyTier::Low,
            ),
            cap(
                Codec::Hevc,
                true,
                5120,
                2880,
                600_000_000,
                false,
                LatencyTier::UltraLow,
            ),
            cap(
                Codec::H264,
                true,
                4096,
                2304,
                280_000_000,
                false,
                LatencyTier::UltraLow,
            ),
        ]
    }

    #[test]
    fn asymmetric_m3_plus_selects_hevc_for_120fps_and_av1_for_60fps_office() {
        let host = win_host_caps();
        let client = macos_m3_client_decode_caps();
        let breaker = CodecCircuitBreaker::new();

        // 1) 2560x1600@120fps（491.5M px/s）：超过 AV1 400M 预算但落入 HEVC 600M 甜点 -> 选 HEVC
        let high_refresh = select_codec_plan(
            &host,
            &client,
            StreamTarget {
                width: 2560,
                height: 1600,
                fps: 120,
            },
            NetworkHint {
                is_lan: true,
                estimated_bitrate_bps: 30_000_000,
                ..NetworkHint::default()
            },
            CodecSelectionPref::Auto,
            &breaker,
        );
        assert_eq!(high_refresh.codec, Codec::Hevc);
        assert_eq!(high_refresh.reason, CodecSelectReason::HighRefreshSweetSpot);
        assert!(!high_refresh.fallback_ladder.is_empty());

        // 2) 2560x1440@60fps 办公文字清晰模式 -> 选 AV1(SCC) 并推荐静帧细化
        let office = select_codec_plan(
            &host,
            &client,
            StreamTarget {
                width: 2560,
                height: 1440,
                fps: 60,
            },
            NetworkHint {
                is_lan: false,
                estimated_bitrate_bps: 14_000_000,
                ..NetworkHint::default()
            },
            CodecSelectionPref::OfficeClear,
            &breaker,
        );
        assert_eq!(office.codec, Codec::Av1);
        assert_eq!(office.reason, CodecSelectReason::OfficeClarityPreferred);
        assert!(office.refinement_recommended);
        assert_eq!(office.fallback_ladder, vec![Codec::Hevc, Codec::H264]);
    }

    #[test]
    fn relay_and_weak_network_prefer_av1_scc_over_hevc_and_h264() {
        let host = win_host_caps();
        let client = macos_m3_client_decode_caps();
        let breaker = CodecCircuitBreaker::new();
        let target = StreamTarget {
            width: 1920,
            height: 1080,
            fps: 60,
        };

        // 中继链路（即便码率较高也按受限链路优先 AV1 SCC）
        let relay_plan = select_codec_plan(
            &host,
            &client,
            target,
            NetworkHint {
                is_relay: true,
                estimated_bitrate_bps: 10_000_000,
                ..NetworkHint::default()
            },
            CodecSelectionPref::Auto,
            &breaker,
        );
        assert_eq!(relay_plan.codec, Codec::Av1);
        assert_eq!(
            relay_plan.reason,
            CodecSelectReason::ConstrainedNetworkEfficiency
        );
        assert_eq!(relay_plan.fallback_ladder, vec![Codec::Hevc, Codec::H264]);

        // 弱网（< 8 Mbps）且不含 AV1 时优先 HEVC > H264
        let host_no_av1: Vec<_> = host.into_iter().filter(|c| c.codec != Codec::Av1).collect();
        let weak_plan = select_codec_plan(
            &host_no_av1,
            &client,
            target,
            NetworkHint {
                is_relay: false,
                estimated_bitrate_bps: 4_000_000,
                ..NetworkHint::default()
            },
            CodecSelectionPref::Auto,
            &breaker,
        );
        assert_eq!(weak_plan.codec, Codec::Hevc);
        assert_eq!(weak_plan.fallback_ladder, vec![Codec::H264]);
    }

    #[test]
    fn resolution_5k_excludes_h264_exceeding_max_dimensions() {
        let host = win_host_caps();
        let client = macos_m3_client_decode_caps();
        let breaker = CodecCircuitBreaker::new();
        let plan_5k = select_codec_plan(
            &host,
            &client,
            StreamTarget {
                width: 5120,
                height: 2880,
                fps: 60,
            },
            NetworkHint {
                is_lan: true,
                estimated_bitrate_bps: 50_000_000,
                ..NetworkHint::default()
            },
            CodecSelectionPref::Auto,
            &breaker,
        );
        assert_ne!(plan_5k.codec, Codec::H264);
        assert!(
            !plan_5k.fallback_ladder.contains(&Codec::H264),
            "5K 超出 H.264 4096×2304 上限，必须从候选与梯队中自动排除"
        );
        assert_eq!(plan_5k.codec, Codec::Hevc);
        assert_eq!(plan_5k.fallback_ladder, vec![Codec::Av1]);
    }

    #[test]
    fn hardware_preference_excludes_software_codecs_when_hardware_intersection_exists() {
        let host = vec![
            cap(
                Codec::Av1,
                false,
                7680,
                4320,
                600_000_000,
                true,
                LatencyTier::Normal,
            ),
            cap(
                Codec::Hevc,
                true,
                5120,
                2880,
                600_000_000,
                false,
                LatencyTier::UltraLow,
            ),
        ];
        let client = vec![
            cap(
                Codec::Av1,
                true,
                7680,
                4320,
                600_000_000,
                false,
                LatencyTier::Low,
            ),
            cap(
                Codec::Hevc,
                true,
                5120,
                2880,
                600_000_000,
                false,
                LatencyTier::UltraLow,
            ),
        ];
        let plan = select_codec_plan(
            &host,
            &client,
            StreamTarget {
                width: 1920,
                height: 1080,
                fps: 60,
            },
            NetworkHint {
                is_relay: true,
                estimated_bitrate_bps: 4_000_000,
                ..NetworkHint::default()
            },
            CodecSelectionPref::OfficeClear,
            &CodecCircuitBreaker::new(),
        );
        assert_eq!(
            plan.codec,
            Codec::Hevc,
            "Host AV1 为软编而双端 HEVC 为硬加，硬加优先必须剔除软编 AV1"
        );
        assert!(!plan.fallback_ladder.contains(&Codec::Av1));
    }

    #[test]
    fn circuit_breaker_degrades_without_oscillation_and_resets_only_explicitly() {
        let host = win_host_caps();
        let client = macos_m3_client_decode_caps();
        let target = StreamTarget {
            width: 1920,
            height: 1080,
            fps: 60,
        };
        let tier = target.resolution_tier();
        let net = NetworkHint {
            is_relay: true,
            estimated_bitrate_bps: 4_000_000,
            ..NetworkHint::default()
        };
        let mut breaker = CodecCircuitBreaker::new();

        // 初始选中 AV1
        let p0 = select_codec_plan(
            &host,
            &client,
            target,
            net,
            CodecSelectionPref::OfficeClear,
            &breaker,
        );
        assert_eq!(p0.codec, Codec::Av1);

        // AV1 熔断 -> 降级 HEVC，重复调用绝不回升 AV1
        assert!(breaker.trip(Codec::Av1, tier, "vt av1 decode error"));
        assert!(!breaker.trip(Codec::Av1, tier, "duplicate"));
        let p1 = select_codec_plan(
            &host,
            &client,
            target,
            net,
            CodecSelectionPref::OfficeClear,
            &breaker,
        );
        assert_eq!(p1.codec, Codec::Hevc);
        assert_eq!(p1.reason, CodecSelectReason::CircuitBreakerFallback);
        assert_eq!(
            breaker.next_fallback(Codec::Av1, tier, &p0.fallback_ladder),
            Some(Codec::Hevc)
        );

        // HEVC 再熔断 -> 降级 H264
        breaker.trip(Codec::Hevc, tier, "hevc overload");
        let p2 = select_codec_plan(
            &host,
            &client,
            target,
            net,
            CodecSelectionPref::OfficeClear,
            &breaker,
        );
        assert_eq!(p2.codec, Codec::H264);
        assert_eq!(p2.reason, CodecSelectReason::CircuitBreakerFallback);

        // 显式手动切换或切分辨率重置后才恢复 AV1
        breaker.reset_on_manual_or_res_change();
        assert_eq!(breaker.tripped_count(), 0);
        let p3 = select_codec_plan(
            &host,
            &client,
            target,
            net,
            CodecSelectionPref::OfficeClear,
            &breaker,
        );
        assert_eq!(p3.codec, Codec::Av1);
    }

    #[test]
    fn hardware_caps_cache_atomic_roundtrip_and_nonblocking_background_probe() {
        let tmp_dir =
            std::env::temp_dir().join(format!("rc-hw-caps-cache-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp_dir);
        let cache_path = tmp_dir.join("hardware-caps-cache.json");

        let key = HardwareCapsCacheKey {
            os: "macos".to_string(),
            arch: "arm64".to_string(),
            gpu_id: "apple-m3-pro".to_string(),
            driver_version: "15.2".to_string(),
            core_version: "0.2.0".to_string(),
        };
        let entry = HardwareCapsCacheEntry::new(
            key.clone(),
            win_host_caps(),
            macos_m3_client_decode_caps(),
            RefinementCapability {
                supported: true,
                true_rgb_capture: true,
                formats: vec!["webp_lossless".to_string()],
            },
        );
        save_hardware_caps_cache(&cache_path, &entry).expect("save cache");
        let loaded = load_hardware_caps_cache(&cache_path, &key).expect("load matching cache");
        assert_eq!(loaded, entry);

        // 驱动版本或 Core 版本变更时缓存自动失效
        let changed_key = HardwareCapsCacheKey {
            driver_version: "15.3".to_string(),
            ..key.clone()
        };
        assert!(load_hardware_caps_cache(&cache_path, &changed_key).is_none());
        let upgraded_core_key = HardwareCapsCacheKey {
            core_version: "0.2.1".to_string(),
            ..key.clone()
        };
        assert!(load_hardware_caps_cache(&cache_path, &upgraded_core_key).is_none());

        // 超大文件（> 256 KiB）必须拒绝加载
        let oversized_path = tmp_dir.join("oversized.json");
        fs::write(
            &oversized_path,
            vec![b' '; (MAX_HARDWARE_CAPS_CACHE_BYTES + 1) as usize],
        )
        .expect("write oversized");
        assert!(load_hardware_caps_cache(&oversized_path, &key).is_none());

        // 后台探测 panic 后 RAII 守卫必须复位 probe_in_flight，防止永久锁死
        let panic_store =
            HardwareCapsStore::new_from_disk(tmp_dir.join("panic-cache.json"), changed_key.clone());
        assert!(panic_store.trigger_background_probe(|| -> (
            Vec<CodecCapability>,
            Vec<CodecCapability>,
            RefinementCapability
        ) {
            panic!("simulated probe crash");
        }));
        let panic_dl = Instant::now() + Duration::from_secs(2);
        while panic_store.is_probe_in_flight() && Instant::now() < panic_dl {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !panic_store.is_probe_in_flight(),
            "probe_fn panic 后 probe_in_flight 必须通过 Drop 守卫归 false"
        );

        // 非阻塞后台探测包装：先命中 None，后台完成后立即可读并落盘
        let store = HardwareCapsStore::new_from_disk(cache_path.clone(), changed_key.clone());
        assert!(store.cached_snapshot().is_none());
        assert!(store.trigger_background_probe(move || {
            (
                win_host_caps(),
                macos_m3_client_decode_caps(),
                RefinementCapability::default(),
            )
        }));
        let deadline = Instant::now() + Duration::from_secs(5);
        while (store.cached_snapshot().is_none() || store.is_probe_in_flight())
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !store.is_probe_in_flight(),
            "background probe should finish disk flush within deadline"
        );
        let fresh = store
            .cached_snapshot()
            .expect("background probe populates cache");
        assert_eq!(fresh.key, changed_key);
        assert_eq!(
            load_hardware_caps_cache(&cache_path, &changed_key).as_ref(),
            Some(&fresh)
        );

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn host_codec_negotiator_gates_av1_on_ext_flags_and_filters_stale_decode_failed_generation() {
        let mut neg = HostCodecNegotiator::new(win_host_caps());
        let target = StreamTarget {
            width: 1920,
            height: 1080,
            fps: 60,
        };
        let net = NetworkHint {
            is_relay: true,
            estimated_bitrate_bps: 4_000_000,
            ..NetworkHint::default()
        };

        // 1) supports_ext_codec_flags = false 时严禁启用 AV1（即使控制端声明了 AV1 解码能力）
        let legacy_plan = neg.on_client_media_caps(
            macos_m3_client_decode_caps(),
            None,
            CodecSelectionPref::OfficeClear,
            false,
            target,
            net,
        );
        assert_eq!(legacy_plan.codec, Codec::Hevc);
        assert!(!neg.is_codec_selectable(Codec::Av1, target.resolution_tier()));

        // 2) supports_ext_codec_flags = true 后可选中 AV1（模拟 host 从 H264 gen=1 切到 AV1 gen=2）
        let ext_plan = neg.on_client_media_caps(
            macos_m3_client_decode_caps(),
            None,
            CodecSelectionPref::OfficeClear,
            true,
            target,
            net,
        );
        assert_eq!(ext_plan.codec, Codec::Av1);
        let gen_av1 = neg.bump_generation();
        assert_eq!(gen_av1, 2);
        assert_eq!(neg.prev_generation(), Some(1));

        // 3) 跨通道竞态回归：UDP AV1 帧先于 Stream A Capabilities(gen=2) 抵达控制端，
        //    控制端携旧 gen=1 (= prev_generation) 上报 CodecDecodeFailed(av1) -> 必须立即触发熔断降级至 HEVC！
        let fb_hevc_from_race = neg
            .on_codec_decode_failed(
                Codec::Av1,
                1,
                "udp av1 beat stream A capabilities",
                Codec::Av1,
                target,
                net,
            )
            .expect(
                "prev_generation matching active_codec must trigger fallback without black screen",
            );
        assert_eq!(fb_hevc_from_race.codec, Codec::Hevc);
        let gen_hevc = neg.bump_generation();
        assert_eq!(gen_hevc, 3);
        assert_eq!(neg.prev_generation(), Some(2));

        // 4) 迟到/错配回声拦截：此时 active_codec 已切为 HEVC，晚到的 AV1(gen=2) 或远古 HEVC(gen=1) 必须被忽略！
        assert!(neg
            .on_codec_decode_failed(Codec::Av1, 2, "late av1 echo", Codec::Hevc, target, net)
            .is_none());
        assert!(neg
            .on_codec_decode_failed(
                Codec::Hevc,
                1,
                "ancient gen < prev_gen",
                Codec::Hevc,
                target,
                net,
            )
            .is_none());
        assert!(!neg
            .breaker()
            .is_tripped(Codec::Hevc, target.resolution_tier()));

        // 5) 匹配 generation=3 的 CodecDecodeFailed(hevc) 熔断 HEVC 并顺延至 H.264
        let fb_h264 = neg
            .on_codec_decode_failed(
                Codec::Hevc,
                gen_hevc,
                "vt hevc failed",
                Codec::Hevc,
                target,
                net,
            )
            .expect("matching generation must trigger h264 fallback");
        assert_eq!(fb_h264.codec, Codec::H264);
    }

    #[test]
    fn select_codec_plan_edge_cases_sw_after_hw_trip_8k_area_fallback_and_legacy_no_upgrade() {
        // 1) 所有硬加均已熔断时，保留未熔断的软编/软解候选而不提前误删
        let host = vec![
            cap(
                Codec::Av1,
                true,
                7680,
                4320,
                400_000_000,
                true,
                LatencyTier::Low,
            ),
            cap(
                Codec::Hevc,
                false,
                5120,
                2880,
                300_000_000,
                false,
                LatencyTier::Normal,
            ),
        ];
        let client = vec![
            cap(
                Codec::Av1,
                true,
                7680,
                4320,
                400_000_000,
                false,
                LatencyTier::Low,
            ),
            cap(
                Codec::Hevc,
                false,
                5120,
                2880,
                300_000_000,
                false,
                LatencyTier::Normal,
            ),
        ];
        let target = StreamTarget {
            width: 1920,
            height: 1080,
            fps: 60,
        };
        let mut breaker = CodecCircuitBreaker::new();
        breaker.trip(Codec::Av1, target.resolution_tier(), "hw av1 failed");
        let plan = select_codec_plan(
            &host,
            &client,
            target,
            NetworkHint::default(),
            CodecSelectionPref::Auto,
            &breaker,
        );
        assert_eq!(
            plan.codec,
            Codec::Hevc,
            "全部硬加熔断后必须能回退到未熔断的软件 HEVC"
        );
        assert_eq!(plan.reason, CodecSelectReason::CircuitBreakerFallback);

        // 2) 全部候选超过分辨率上限（例如 10K）时，兜底严格按最大分辨率容积降序，不被 H.264 UltraLow 反超
        let host_all = win_host_caps();
        let client_all = macos_m3_client_decode_caps();
        let ultra_plan = select_codec_plan(
            &host_all,
            &client_all,
            StreamTarget {
                width: 10240,
                height: 4320,
                fps: 60,
            },
            NetworkHint {
                is_lan: true,
                estimated_bitrate_bps: 50_000_000,
                ..NetworkHint::default()
            },
            CodecSelectionPref::UltraLowLatency,
            &CodecCircuitBreaker::new(),
        );
        assert_eq!(
            ultra_plan.codec,
            Codec::Av1,
            "全员超分辨率上限时 AV1(7680×4320) 容积大于 HEVC(5120×2880) 与 H264(4096×2304)，绝不能被普通打分覆盖"
        );

        // 3) 60fps 常规 WAN（非高刷、非受限、非 LAN）使用 AutoBalanced 而非 HighRefreshSweetSpot
        let wan_60 = select_codec_plan(
            &host_all,
            &client_all,
            target,
            NetworkHint {
                is_lan: false,
                is_relay: false,
                estimated_bitrate_bps: 14_000_000,
                rtt_us: 20_000,
            },
            CodecSelectionPref::Auto,
            &CodecCircuitBreaker::new(),
        );
        assert_eq!(wan_60.reason, CodecSelectReason::AutoBalanced);

        // 4) 旧端不发 ClientMediaCaps 时，H.264 失败绝不反向“升”到未确认的 HEVC
        let mut legacy_neg = HostCodecNegotiator::new(host_all);
        let h264_fb = legacy_neg
            .on_codec_decode_failed(
                Codec::H264,
                1,
                "h264 error on legacy peer",
                Codec::H264,
                target,
                NetworkHint::default(),
            )
            .expect("matching gen on legacy peer");
        assert_eq!(h264_fb.codec, Codec::H264);

        // 5) set_manual_pref 同步更新偏好并重置熔断
        legacy_neg.set_manual_pref(Codec::Hevc);
        assert_eq!(legacy_neg.breaker().tripped_count(), 0);
    }
}
