//! 跨平台 Tile 级静止无损脏区补帧引擎（Wave 3B / `7e-2` 方案 B）。
//!
//! # 设计原则
//! - **零外部 C 依赖、零 `unsafe`**：内置完整纯 Rust QOI 无损编解码器（支持 `Bgra8` / `Rgba8`），
//!   解码端严格校验魔数、尺寸上限、截断与溢出，杜绝恶意载荷 OOM 或 panic；
//! - **Tile 级局部状态机（修正 #2）**：按 `128×128` 网格独立追踪每个 Tile 的脏区与静止时长，
//!   终端 500ms 闪烁光标仅失效相交的 1 个 Tile，周围 95% 静止代码区稳定保持无损锐利态；
//! - **输入优先毫秒级抢占与令牌桶限速（修正 #5）**：单片载荷上限 `<= 24 KiB`（超限自动细分子块或跳过），
//!   按估算带宽 20%–30%（带硬上限）限速发送，收到任意输入事件或新动态帧立刻清空队列并递增
//!   `cancel_generation`，弱网（丢包 `>= 1%` 或带宽 `< 2 Mbps`）或「极速低延迟」模式自动暂停；
//! - **接收端时序一致性守卫**：严格校验 `stream_epoch` 与单 Tile `tile_last_dynamic_seq`，
//!   拦截过期/乱序补丁防止画面倒退，并提供可观测 [`StillRefineMetrics`]。

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use rc_pipeline::RefinementCapability;
use rc_render::{Renderer, StillTilePatch};
use rc_types::{CpuFrame, PixelFormat, Rect};
use serde::{Deserialize, Serialize};

use crate::codec_selector::CodecSelectionPref;
use crate::display_ctrl::{base64_decode, base64_encode, DisplayControlMsg};

/// 默认 Tile 网格边长（像素：`128×128`）。
pub const DEFAULT_TILE_SIZE: u32 = 128;

/// 触发静止无损细化的默认静止等待时长（毫秒）。
pub const DEFAULT_STILL_DELAY_MS: u64 = 200;

/// 单个无损 Tile 压缩载荷的硬上限（24 KiB，保“起手第一帧”与控制面零拥塞）。
pub const MAX_STILL_TILE_PAYLOAD_BYTES: usize = 24 * 1024;

/// 单个无损 Tile 经 RFC 4648 Base64 编码后的最大合法字符数（`ceil(24 KiB / 3) * 4`）。
pub const MAX_STILL_TILE_BASE64_BYTES: usize = MAX_STILL_TILE_PAYLOAD_BYTES.div_ceil(3) * 4;

/// 自动切分子块时的最小边长下限（像素；`32×32×5 + 22 ≈ 5.1 KiB << 24 KiB`）。
pub const MIN_SUBTILE_DIM: u32 = 32;

/// 弱网门控：低于该可用带宽（2 Mbps）时自动暂停静止补帧。
pub const STILL_REFINE_MIN_BANDWIDTH_BPS: u32 = 2_000_000;

/// 弱网门控：丢包率达到或超过该阈值（1%）时自动暂停静止补帧。
pub const STILL_REFINE_MAX_LOSS_RATE: f32 = 0.01;

/// 令牌桶允许占用估算可用带宽的最小比例（20%）。
pub const MIN_BANDWIDTH_SHARE_PCT: u8 = 20;

/// 令牌桶允许占用估算可用带宽的默认比例（25%）。
pub const DEFAULT_BANDWIDTH_SHARE_PCT: u8 = 25;

/// 令牌桶允许占用估算可用带宽的最大比例（30%）。
pub const MAX_BANDWIDTH_SHARE_PCT: u8 = 30;

/// 令牌桶绝对发送速率硬上限（2 MiB/s，防止高带宽局域网突发挤占媒体流）。
pub const HARD_MAX_PACING_BYTES_PER_SEC: usize = 2 * 1024 * 1024;

/// 令牌桶最大突发深度硬上限（48 KiB = 2 片最大 Tile）。
pub const HARD_MAX_BURST_BYTES: usize = MAX_STILL_TILE_PAYLOAD_BYTES * 2;

/// 待发补帧队列有界容量上限（铁律 1：杜绝无界堆积）。
pub const MAX_PENDING_STILL_TILES: usize = 256;

/// QOI 编解码单边最大允许尺寸（像素，防恶意超大头导致 OOM）。
pub const MAX_QOI_DIM: u32 = 2048;

/// QOI 编解码最大允许总像素数（1M 像素 = 4 MiB 解码缓冲硬上限，防 OOM）。
pub const MAX_QOI_PIXELS: usize = 1024 * 1024;

/// QOI 规范 4 字节文件魔数。
const QOI_MAGIC: [u8; 4] = *b"qoif";

/// QOI 规范 14 字节头长度。
const QOI_HEADER_LEN: usize = 14;

/// QOI 规范 8 字节结束标记。
const QOI_END_MARKER: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

/// QOI 最小合法字节流长度（14B 头 + 8B 结束标记）。
const QOI_MIN_LEN: usize = QOI_HEADER_LEN + QOI_END_MARKER.len();

/// 协议中无损编解码器名称常量（`"qoi"`）。
pub const STILL_TILE_CODEC_QOI: &str = "qoi";

// ─────────────────────────────────────────────────────────────────
// 错误与像素格式辅助类型
// ─────────────────────────────────────────────────────────────────

/// 静止无损 Tile 编解码与切片提取错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StillRefineError {
    /// 宽高为 0 或非法。
    InvalidDimensions,
    /// 宽高或总像素数超过安全上限（防 OOM）。
    DimensionsTooLarge,
    /// 像素格式不受支持（仅支持 `Bgra8` / `Rgba8`）。
    UnsupportedFormat(PixelFormat),
    /// 输入像素缓冲长度与宽高/步幅不匹配或切片越界。
    InvalidPixelBuffer,
    /// 编码输出超出单 Tile 字节预算（触发上层子块切分或跳过）。
    PayloadBudgetExceeded {
        /// 当前预算上限（字节）。
        budget: usize,
    },
    /// QOI 数据流魔数非法。
    InvalidMagic,
    /// QOI 头中通道数非法（仅支持 3 或 4）。
    UnsupportedChannels(u8),
    /// QOI 头中色彩空间字段非法（仅支持 0 或 1）。
    InvalidColorspace(u8),
    /// QOI 结束标记缺失或损坏。
    InvalidEndMarker,
    /// QOI 码流被截断。
    Truncated,
    /// QOI 码流在像素写满后仍残留非法尾部字节或 RUN 越界。
    CorruptStream,
}

impl fmt::Display for StillRefineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDimensions => write!(f, "still tile dimensions must be non-zero"),
            Self::DimensionsTooLarge => write!(f, "still tile dimensions exceed safe OOM limit"),
            Self::UnsupportedFormat(fmt) => write!(f, "unsupported still tile format: {fmt:?}"),
            Self::InvalidPixelBuffer => write!(f, "invalid pixel buffer length or out-of-bounds"),
            Self::PayloadBudgetExceeded { budget } => {
                write!(f, "encoded still tile exceeded budget of {budget} bytes")
            }
            Self::InvalidMagic => write!(f, "invalid QOI magic header"),
            Self::UnsupportedChannels(ch) => write!(f, "unsupported QOI channels: {ch}"),
            Self::InvalidColorspace(cs) => write!(f, "invalid QOI colorspace: {cs}"),
            Self::InvalidEndMarker => write!(f, "invalid or missing QOI end marker"),
            Self::Truncated => write!(f, "truncated QOI stream"),
            Self::CorruptStream => write!(f, "corrupt QOI stream or run overflow"),
        }
    }
}

impl std::error::Error for StillRefineError {}

/// 将协议像素格式字符串（`"bgra8"` / `"rgba8"`）解析为 [`PixelFormat`]。
pub fn parse_still_pixel_format(raw: &str) -> Option<PixelFormat> {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("bgra8") || trimmed.eq_ignore_ascii_case("bgra") {
        Some(PixelFormat::Bgra8)
    } else if trimmed.eq_ignore_ascii_case("rgba8") || trimmed.eq_ignore_ascii_case("rgba") {
        Some(PixelFormat::Rgba8)
    } else {
        None
    }
}

/// 将 [`PixelFormat`] 转为协议标准小写格式名（`"bgra8"` / `"rgba8"`）。
pub const fn still_pixel_format_str(format: PixelFormat) -> Option<&'static str> {
    match format {
        PixelFormat::Bgra8 => Some("bgra8"),
        PixelFormat::Rgba8 => Some("rgba8"),
        PixelFormat::Nv12 | PixelFormat::I420 => None,
    }
}

// ─────────────────────────────────────────────────────────────────
// 1. 纯 Rust QOI 无损编解码器（零外部依赖、零 unsafe）
// ─────────────────────────────────────────────────────────────────

/// QOI 解码产出图像（4 字节紧致排列）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedQoiImage {
    /// 图像宽度（像素）。
    pub width: u32,
    /// 图像高度（像素）。
    pub height: u32,
    /// 输出像素格式（[`PixelFormat::Bgra8`] 或 [`PixelFormat::Rgba8`]）。
    pub format: PixelFormat,
    /// 紧密排列的未压缩像素字节（长度恒等于 `width * height * 4`）。
    pub pixels: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rgba {
    r: u8,
    g: u8,
    b: u8,
    a: u8,
}

impl Rgba {
    const ZERO: Self = Self {
        r: 0,
        g: 0,
        b: 0,
        a: 0,
    };

    const INIT_PREV: Self = Self {
        r: 0,
        g: 0,
        b: 0,
        a: 255,
    };

    #[inline]
    const fn qoi_hash(self) -> usize {
        ((self.r as usize) * 3
            + (self.g as usize) * 5
            + (self.b as usize) * 7
            + (self.a as usize) * 11)
            & 63
    }

    #[inline]
    const fn from_slice(px: &[u8], format: PixelFormat) -> Self {
        match format {
            PixelFormat::Bgra8 => Self {
                r: px[2],
                g: px[1],
                b: px[0],
                a: px[3],
            },
            PixelFormat::Rgba8 | PixelFormat::Nv12 | PixelFormat::I420 => Self {
                r: px[0],
                g: px[1],
                b: px[2],
                a: px[3],
            },
        }
    }

    #[inline]
    fn write_to(self, dst: &mut [u8], format: PixelFormat) {
        match format {
            PixelFormat::Bgra8 => {
                dst[0] = self.b;
                dst[1] = self.g;
                dst[2] = self.r;
                dst[3] = self.a;
            }
            PixelFormat::Rgba8 | PixelFormat::Nv12 | PixelFormat::I420 => {
                dst[0] = self.r;
                dst[1] = self.g;
                dst[2] = self.b;
                dst[3] = self.a;
            }
        }
    }
}

fn validate_qoi_dimensions(width: u32, height: u32) -> Result<usize, StillRefineError> {
    if width == 0 || height == 0 {
        return Err(StillRefineError::InvalidDimensions);
    }
    if width > MAX_QOI_DIM || height > MAX_QOI_DIM {
        return Err(StillRefineError::DimensionsTooLarge);
    }
    let total_pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or(StillRefineError::DimensionsTooLarge)?;
    if total_pixels > MAX_QOI_PIXELS {
        return Err(StillRefineError::DimensionsTooLarge);
    }
    Ok(total_pixels)
}

/// 将紧密排列的 `Bgra8` 或 `Rgba8` 像素缓冲编码为标准 QOI 无损字节流。
///
/// 若指定 `max_encoded_bytes`，编码过程中一旦输出长度（含 8 字节结束标记）超出预算即提前中止
/// 并返回 [`StillRefineError::PayloadBudgetExceeded`]，避免在不可压缩噪声块上浪费 CPU 与内存。
pub fn encode_qoi(
    pixels: &[u8],
    width: u32,
    height: u32,
    format: PixelFormat,
    max_encoded_bytes: Option<usize>,
) -> Result<Vec<u8>, StillRefineError> {
    if !matches!(format, PixelFormat::Bgra8 | PixelFormat::Rgba8) {
        return Err(StillRefineError::UnsupportedFormat(format));
    }
    let total_pixels = validate_qoi_dimensions(width, height)?;
    let expected_len = total_pixels
        .checked_mul(4)
        .ok_or(StillRefineError::DimensionsTooLarge)?;
    if pixels.len() != expected_len {
        return Err(StillRefineError::InvalidPixelBuffer);
    }

    if let Some(budget) = max_encoded_bytes {
        if budget < QOI_MIN_LEN {
            return Err(StillRefineError::PayloadBudgetExceeded { budget });
        }
    }

    // 预估容量（上限不超过预算或 64 KiB 初始预留，避免无谓大分配）。
    let est_cap = expected_len
        .min(64 * 1024)
        .saturating_add(QOI_MIN_LEN)
        .min(max_encoded_bytes.unwrap_or(usize::MAX));
    let mut out = Vec::with_capacity(est_cap);

    // 14B QOI 头：magic + BE width + BE height + channels(4) + colorspace(0 = sRGB + linear alpha)
    out.extend_from_slice(&QOI_MAGIC);
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.push(4);
    out.push(0);

    let max_body_end = max_encoded_bytes.map(|b| b.saturating_sub(QOI_END_MARKER.len()));
    let mut index = [Rgba::ZERO; 64];
    let mut prev = Rgba::INIT_PREV;
    let mut run: u8 = 0;

    for (idx, chunk) in pixels.chunks_exact(4).enumerate() {
        let px = Rgba::from_slice(chunk, format);
        let is_last = idx + 1 == total_pixels;

        if px == prev {
            run += 1;
            if run == 62 || is_last {
                out.push(0xC0 | (run - 1));
                run = 0;
            }
        } else {
            if run > 0 {
                out.push(0xC0 | (run - 1));
                run = 0;
            }
            let hash = px.qoi_hash();
            if index[hash] == px {
                out.push(hash as u8);
            } else {
                index[hash] = px;
                if px.a == prev.a {
                    let vr = px.r.wrapping_sub(prev.r) as i8;
                    let vg = px.g.wrapping_sub(prev.g) as i8;
                    let vb = px.b.wrapping_sub(prev.b) as i8;
                    let vg_r = vr.wrapping_sub(vg);
                    let vg_b = vb.wrapping_sub(vg);

                    if (-2..=1).contains(&vr) && (-2..=1).contains(&vg) && (-2..=1).contains(&vb) {
                        out.push(
                            0x40 | (((vr + 2) as u8) << 4)
                                | (((vg + 2) as u8) << 2)
                                | ((vb + 2) as u8),
                        );
                    } else if (-32..=31).contains(&vg)
                        && (-8..=7).contains(&vg_r)
                        && (-8..=7).contains(&vg_b)
                    {
                        out.push(0x80 | ((vg + 32) as u8));
                        out.push((((vg_r + 8) as u8) << 4) | ((vg_b + 8) as u8));
                    } else {
                        out.push(0xFE);
                        out.push(px.r);
                        out.push(px.g);
                        out.push(px.b);
                    }
                } else {
                    out.push(0xFF);
                    out.push(px.r);
                    out.push(px.g);
                    out.push(px.b);
                    out.push(px.a);
                }
            }
        }

        prev = px;

        if let Some(limit) = max_body_end {
            if out.len() > limit {
                return Err(StillRefineError::PayloadBudgetExceeded {
                    budget: max_encoded_bytes.unwrap_or(0),
                });
            }
        }
    }

    out.extend_from_slice(&QOI_END_MARKER);
    if let Some(budget) = max_encoded_bytes {
        if out.len() > budget {
            return Err(StillRefineError::PayloadBudgetExceeded { budget });
        }
    }
    Ok(out)
}

/// 将标准 QOI 字节流无损解码为 `Bgra8` 或 `Rgba8` 像素缓冲（严格防 OOM / 截断 / 越界，绝不 panic）。
pub fn decode_qoi(
    data: &[u8],
    output_format: PixelFormat,
) -> Result<DecodedQoiImage, StillRefineError> {
    if !matches!(output_format, PixelFormat::Bgra8 | PixelFormat::Rgba8) {
        return Err(StillRefineError::UnsupportedFormat(output_format));
    }
    if data.len() < QOI_MIN_LEN {
        return Err(StillRefineError::Truncated);
    }
    if data[0..4] != QOI_MAGIC {
        return Err(StillRefineError::InvalidMagic);
    }

    let width = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let height = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let channels = data[12];
    let colorspace = data[13];

    if channels != 3 && channels != 4 {
        return Err(StillRefineError::UnsupportedChannels(channels));
    }
    if colorspace > 1 {
        return Err(StillRefineError::InvalidColorspace(colorspace));
    }

    let total_pixels = validate_qoi_dimensions(width, height)?;
    let out_len = total_pixels
        .checked_mul(4)
        .ok_or(StillRefineError::DimensionsTooLarge)?;

    let body_end = data.len() - QOI_END_MARKER.len();
    if data[body_end..] != QOI_END_MARKER {
        return Err(StillRefineError::InvalidEndMarker);
    }
    let body = &data[QOI_HEADER_LEN..body_end];

    let mut pixels = vec![0u8; out_len];
    let mut index = [Rgba::ZERO; 64];
    let mut px = Rgba::INIT_PREV;
    let mut pos: usize = 0;
    let mut written_pixels: usize = 0;

    while written_pixels < total_pixels {
        let b1 = *body.get(pos).ok_or(StillRefineError::Truncated)?;
        pos += 1;

        if b1 == 0xFE {
            // QOI_OP_RGB
            if pos + 3 > body.len() {
                return Err(StillRefineError::Truncated);
            }
            px.r = body[pos];
            px.g = body[pos + 1];
            px.b = body[pos + 2];
            pos += 3;
            index[px.qoi_hash()] = px;
            let dst = &mut pixels[written_pixels * 4..written_pixels * 4 + 4];
            px.write_to(dst, output_format);
            written_pixels += 1;
        } else if b1 == 0xFF {
            // QOI_OP_RGBA
            if pos + 4 > body.len() {
                return Err(StillRefineError::Truncated);
            }
            px.r = body[pos];
            px.g = body[pos + 1];
            px.b = body[pos + 2];
            px.a = body[pos + 3];
            pos += 4;
            index[px.qoi_hash()] = px;
            let dst = &mut pixels[written_pixels * 4..written_pixels * 4 + 4];
            px.write_to(dst, output_format);
            written_pixels += 1;
        } else {
            match b1 & 0xC0 {
                0x00 => {
                    // QOI_OP_INDEX
                    px = index[(b1 & 0x3F) as usize];
                    let dst = &mut pixels[written_pixels * 4..written_pixels * 4 + 4];
                    px.write_to(dst, output_format);
                    written_pixels += 1;
                }
                0x40 => {
                    // QOI_OP_DIFF
                    let dr = (((b1 >> 4) & 0x03) as i8).wrapping_sub(2);
                    let dg = (((b1 >> 2) & 0x03) as i8).wrapping_sub(2);
                    let db = ((b1 & 0x03) as i8).wrapping_sub(2);
                    px.r = px.r.wrapping_add(dr as u8);
                    px.g = px.g.wrapping_add(dg as u8);
                    px.b = px.b.wrapping_add(db as u8);
                    index[px.qoi_hash()] = px;
                    let dst = &mut pixels[written_pixels * 4..written_pixels * 4 + 4];
                    px.write_to(dst, output_format);
                    written_pixels += 1;
                }
                0x80 => {
                    // QOI_OP_LUMA
                    let b2 = *body.get(pos).ok_or(StillRefineError::Truncated)?;
                    pos += 1;
                    let vg = ((b1 & 0x3F) as i8).wrapping_sub(32);
                    let dr_dg = (((b2 >> 4) & 0x0F) as i8).wrapping_sub(8);
                    let db_dg = ((b2 & 0x0F) as i8).wrapping_sub(8);
                    px.r = px.r.wrapping_add(vg.wrapping_add(dr_dg) as u8);
                    px.g = px.g.wrapping_add(vg as u8);
                    px.b = px.b.wrapping_add(vg.wrapping_add(db_dg) as u8);
                    index[px.qoi_hash()] = px;
                    let dst = &mut pixels[written_pixels * 4..written_pixels * 4 + 4];
                    px.write_to(dst, output_format);
                    written_pixels += 1;
                }
                _ => {
                    // QOI_OP_RUN (0xC0..=0xFD -> run length 1..=62)
                    // 对齐官方 qoi.h：解码每条 op 时同步刷新 index[hash(px)] = px，
                    // 确保首像素 (0,0,0,255) 经 RUN 编码后后续可被 QOI_OP_INDEX(53) 引用。
                    index[px.qoi_hash()] = px;
                    let run_len = usize::from(b1 & 0x3F) + 1;
                    let next_written = written_pixels
                        .checked_add(run_len)
                        .ok_or(StillRefineError::CorruptStream)?;
                    if next_written > total_pixels {
                        return Err(StillRefineError::CorruptStream);
                    }
                    for i in written_pixels..next_written {
                        let dst = &mut pixels[i * 4..i * 4 + 4];
                        px.write_to(dst, output_format);
                    }
                    written_pixels = next_written;
                }
            }
        }
    }

    if pos != body.len() {
        return Err(StillRefineError::CorruptStream);
    }

    Ok(DecodedQoiImage {
        width,
        height,
        format: output_format,
        pixels,
    })
}

/// 将紧密排列的 `Bgra8` 像素编码为 QOI 无损字节流（无字节上限限制）。
pub fn encode_qoi_bgra(bgra: &[u8], width: u32, height: u32) -> Result<Vec<u8>, StillRefineError> {
    encode_qoi(bgra, width, height, PixelFormat::Bgra8, None)
}

/// 将 QOI 字节流无损解码为 `Bgra8` 像素图像。
pub fn decode_qoi_bgra(data: &[u8]) -> Result<DecodedQoiImage, StillRefineError> {
    decode_qoi(data, PixelFormat::Bgra8)
}

/// 将紧密排列的 `Rgba8` 像素编码为 QOI 无损字节流（无字节上限限制）。
pub fn encode_qoi_rgba(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>, StillRefineError> {
    encode_qoi(rgba, width, height, PixelFormat::Rgba8, None)
}

/// 将 QOI 字节流无损解码为 `Rgba8` 像素图像。
pub fn decode_qoi_rgba(data: &[u8]) -> Result<DecodedQoiImage, StillRefineError> {
    decode_qoi(data, PixelFormat::Rgba8)
}

/// 从整帧 [`CpuFrame`] 中安全裁剪提取 `rect` 区域的紧密像素字节（支持任意对齐 `stride`）。
pub fn extract_tile_pixels(frame: &CpuFrame, rect: Rect) -> Result<Vec<u8>, StillRefineError> {
    if !matches!(frame.format, PixelFormat::Bgra8 | PixelFormat::Rgba8) {
        return Err(StillRefineError::UnsupportedFormat(frame.format));
    }
    if rect.is_empty() {
        return Err(StillRefineError::InvalidDimensions);
    }
    if rect.right() > frame.width || rect.bottom() > frame.height {
        return Err(StillRefineError::InvalidPixelBuffer);
    }
    frame
        .validate()
        .map_err(|_| StillRefineError::InvalidPixelBuffer)?;

    let row_bytes = (rect.width as usize)
        .checked_mul(4)
        .ok_or(StillRefineError::DimensionsTooLarge)?;
    let total_bytes = row_bytes
        .checked_mul(rect.height as usize)
        .ok_or(StillRefineError::DimensionsTooLarge)?;
    let stride = frame.stride as usize;
    let x_offset = (rect.x as usize)
        .checked_mul(4)
        .ok_or(StillRefineError::InvalidPixelBuffer)?;

    let mut out = Vec::with_capacity(total_bytes);
    for dy in 0..(rect.height as usize) {
        let src_row_start = (rect.y as usize + dy)
            .checked_mul(stride)
            .and_then(|v| v.checked_add(x_offset))
            .ok_or(StillRefineError::InvalidPixelBuffer)?;
        let src_row_end = src_row_start
            .checked_add(row_bytes)
            .ok_or(StillRefineError::InvalidPixelBuffer)?;
        let row = frame
            .data
            .get(src_row_start..src_row_end)
            .ok_or(StillRefineError::InvalidPixelBuffer)?;
        out.extend_from_slice(row);
    }
    Ok(out)
}

/// 编码完成的单个无损 Tile 载荷（已通过 `<= max_payload_bytes` 上限校验）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedStillTile {
    /// 所属视频流纪元号。
    pub stream_epoch: u64,
    /// 基于的动态帧序号。
    pub base_frame_seq: u64,
    /// Tile 覆盖的画面像素矩形。
    pub rect: Rect,
    /// 原始像素格式（`Bgra8` / `Rgba8`）。
    pub format: PixelFormat,
    /// QOI 压缩后的原始字节流（恒满足 `<= max_tile_payload_bytes`）。
    pub encoded_bytes: Vec<u8>,
}

impl EncodedStillTile {
    /// 转为可经 `TOOL_CHANNEL_DISPLAY_CTRL` 发送的 [`DisplayControlMsg::StillTileRefine`]。
    pub fn to_display_ctrl_msg(&self) -> Option<DisplayControlMsg> {
        let fmt = still_pixel_format_str(self.format)?;
        Some(DisplayControlMsg::StillTileRefine {
            stream_epoch: self.stream_epoch,
            base_frame_seq: self.base_frame_seq,
            x: self.rect.x,
            y: self.rect.y,
            width: self.rect.width,
            height: self.rect.height,
            format: fmt.to_string(),
            codec: STILL_TILE_CODEC_QOI.to_string(),
            data_base64: base64_encode(&self.encoded_bytes),
        })
    }
}

/// 对目标 `rect` 执行 QOI 编码；若超出 `max_payload_bytes`（默认 24 KiB），自动沿长边递归切分为更小
/// sub-tile（最小 `32×32`）；若仍超限则安全跳过，保证所有产出片严格满足 `<= max_payload_bytes`。
pub fn encode_tile_with_subdivision(
    frame: &CpuFrame,
    rect: Rect,
    stream_epoch: u64,
    base_frame_seq: u64,
    max_payload_bytes: usize,
) -> Result<Vec<EncodedStillTile>, StillRefineError> {
    let mut out = Vec::new();
    encode_tile_subdivide_recursive(
        frame,
        rect,
        stream_epoch,
        base_frame_seq,
        max_payload_bytes,
        0,
        &mut out,
    )?;
    Ok(out)
}

fn encode_tile_subdivide_recursive(
    frame: &CpuFrame,
    rect: Rect,
    stream_epoch: u64,
    base_frame_seq: u64,
    max_payload_bytes: usize,
    depth: u8,
    out: &mut Vec<EncodedStillTile>,
) -> Result<(), StillRefineError> {
    const MAX_DEPTH: u8 = 4;

    let raw = extract_tile_pixels(frame, rect)?;
    match encode_qoi(
        &raw,
        rect.width,
        rect.height,
        frame.format,
        Some(max_payload_bytes),
    ) {
        Ok(encoded_bytes) => {
            out.push(EncodedStillTile {
                stream_epoch,
                base_frame_seq,
                rect,
                format: frame.format,
                encoded_bytes,
            });
            Ok(())
        }
        Err(StillRefineError::PayloadBudgetExceeded { .. }) => {
            if depth >= MAX_DEPTH
                || (rect.width <= MIN_SUBTILE_DIM && rect.height <= MIN_SUBTILE_DIM)
            {
                // 极高熵噪声小块超过预算时安全跳过，不破坏带宽红线。
                return Ok(());
            }
            let (first, second) = if rect.width >= rect.height && rect.width > MIN_SUBTILE_DIM {
                let left_w = rect.width / 2;
                let right_w = rect.width - left_w;
                (
                    Rect::new(rect.x, rect.y, left_w, rect.height),
                    Rect::new(rect.x + left_w, rect.y, right_w, rect.height),
                )
            } else if rect.height > MIN_SUBTILE_DIM {
                let top_h = rect.height / 2;
                let bot_h = rect.height - top_h;
                (
                    Rect::new(rect.x, rect.y, rect.width, top_h),
                    Rect::new(rect.x, rect.y + top_h, rect.width, bot_h),
                )
            } else {
                return Ok(());
            };
            if !first.is_empty() {
                encode_tile_subdivide_recursive(
                    frame,
                    first,
                    stream_epoch,
                    base_frame_seq,
                    max_payload_bytes,
                    depth + 1,
                    out,
                )?;
            }
            if !second.is_empty() {
                encode_tile_subdivide_recursive(
                    frame,
                    second,
                    stream_epoch,
                    base_frame_seq,
                    max_payload_bytes,
                    depth + 1,
                    out,
                )?;
            }
            Ok(())
        }
        Err(other) => Err(other),
    }
}

// ─────────────────────────────────────────────────────────────────
// 2. Tile 级局部状态机 StillTileGrid（修正 #2）
// ─────────────────────────────────────────────────────────────────

/// 静止无损补帧策略配置。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StillRefineConfig {
    /// Tile 保持静止多久后进入无损细化候选（毫秒，默认 `200ms`）。
    pub still_delay_ms: u64,
    /// 单 Tile 压缩载荷上限（字节，默认 `24 KiB`）。
    pub max_tile_payload_bytes: usize,
    /// 令牌桶允许占用的估算可用带宽比例（`20..=30`，默认 `25%`）。
    pub bandwidth_share_pct: u8,
    /// 触发弱网暂停的最低带宽阈值（bps，默认 `2_000_000`）。
    pub min_bandwidth_bps: u32,
    /// 触发弱网暂停的最大容忍丢包率（`>= 0.01` 即 `1%` 时暂停）。
    pub max_loss_rate: f32,
    /// 令牌桶发送速率绝对硬上限（字节/秒，默认 `2 MiB/s`）。
    pub hard_max_bytes_per_sec: usize,
    /// 令牌桶突发上限（字节，默认 `48 KiB`）。
    pub hard_max_burst_bytes: usize,
}

impl Default for StillRefineConfig {
    fn default() -> Self {
        Self {
            still_delay_ms: DEFAULT_STILL_DELAY_MS,
            max_tile_payload_bytes: MAX_STILL_TILE_PAYLOAD_BYTES,
            bandwidth_share_pct: DEFAULT_BANDWIDTH_SHARE_PCT,
            min_bandwidth_bps: STILL_REFINE_MIN_BANDWIDTH_BPS,
            max_loss_rate: STILL_REFINE_MAX_LOSS_RATE,
            hard_max_bytes_per_sec: HARD_MAX_PACING_BYTES_PER_SEC,
            hard_max_burst_bytes: HARD_MAX_BURST_BYTES,
        }
    }
}

/// 网格中单个 `128×128`（边缘自适应裁剪）Tile 的局部状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StillTileState {
    /// 列索引（从 0 起）。
    pub col: u32,
    /// 行索引（从 0 起）。
    pub row: u32,
    /// 该 Tile 在视频帧坐标系中的精确像素矩形（边缘自动裁剪至分辨率边界）。
    pub rect: Rect,
    /// 是否处于脏态（已被动态帧修改且尚未完成当前帧序号的无损补帧）。
    pub dirty: bool,
    /// 最近一次被动态帧标脏的时间戳（毫秒）。
    pub last_change_ms: u64,
    /// 最近一次触及该 Tile 的动态帧序号（`None` 表示尚无动态帧内容）。
    pub last_dynamic_seq: Option<u64>,
    /// 已成功完成无损细化所对应的基准动态帧序号（`None` 表示尚未细化或已失效）。
    pub refined_base_seq: Option<u64>,
    /// 最近一次为该 Tile 发送补丁时的 `stream_epoch`。
    pub last_sent_epoch: u64,
}

/// 满足静止时长且按优先级排好序的待补帧 Tile 候选。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyStillTile {
    /// 列索引。
    pub col: u32,
    /// 行索引。
    pub row: u32,
    /// 像素矩形。
    pub rect: Rect,
    /// 所属视频流纪元号。
    pub stream_epoch: u64,
    /// 本次细化对应的基准动态帧序号。
    pub base_frame_seq: u64,
}

/// Tile 级局部状态机（按 `128×128` 网格追踪脏区与静止时长，彻底消除闪烁光标引起的整屏呼吸感）。
#[derive(Debug, Clone)]
pub struct StillTileGrid {
    stream_epoch: u64,
    width: u32,
    height: u32,
    tile_size: u32,
    cols: u32,
    rows: u32,
    tiles: Vec<StillTileState>,
}

impl StillTileGrid {
    /// 以指定 `stream_epoch` 与分辨率构建默认 `128×128` 网格。
    pub fn new(stream_epoch: u64, width: u32, height: u32) -> Self {
        Self::with_tile_size(stream_epoch, width, height, DEFAULT_TILE_SIZE)
    }

    /// 以指定 `stream_epoch`、分辨率与自定义 Tile 尺寸（最小 16）构建网格。
    pub fn with_tile_size(stream_epoch: u64, width: u32, height: u32, tile_size: u32) -> Self {
        let tile_size = tile_size.max(16);
        let mut grid = Self {
            stream_epoch,
            width: 0,
            height: 0,
            tile_size,
            cols: 0,
            rows: 0,
            tiles: Vec::new(),
        };
        grid.rebuild_tiles(width, height);
        grid
    }

    fn rebuild_tiles(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
        if width == 0 || height == 0 {
            self.cols = 0;
            self.rows = 0;
            self.tiles.clear();
            return;
        }
        self.cols = width.div_ceil(self.tile_size);
        self.rows = height.div_ceil(self.tile_size);
        let total = (self.cols as usize).saturating_mul(self.rows as usize);
        self.tiles = Vec::with_capacity(total);
        for row in 0..self.rows {
            let y = row.saturating_mul(self.tile_size);
            let h = self.tile_size.min(height.saturating_sub(y));
            for col in 0..self.cols {
                let x = col.saturating_mul(self.tile_size);
                let w = self.tile_size.min(width.saturating_sub(x));
                self.tiles.push(StillTileState {
                    col,
                    row,
                    rect: Rect::new(x, y, w, h),
                    dirty: false,
                    last_change_ms: 0,
                    last_dynamic_seq: None,
                    refined_base_seq: None,
                    last_sent_epoch: 0,
                });
            }
        }
    }

    /// 当前视频流纪元号。
    pub fn stream_epoch(&self) -> u64 {
        self.stream_epoch
    }

    /// 当前画布尺寸 `(width, height)`。
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// 网格单 Tile 边长（像素，默认 `128`）。
    pub fn tile_size(&self) -> u32 {
        self.tile_size
    }

    /// 网格行列数 `(cols, rows)`。
    pub fn grid_dims(&self) -> (u32, u32) {
        (self.cols, self.rows)
    }

    /// 网格总 Tile 数量。
    pub fn tile_count(&self) -> usize {
        self.tiles.len()
    }

    /// 按 `(col, row)` 查询单个 Tile 状态。
    pub fn tile_at(&self, col: u32, row: u32) -> Option<&StillTileState> {
        if col >= self.cols || row >= self.rows {
            return None;
        }
        let idx = (row as usize) * (self.cols as usize) + (col as usize);
        self.tiles.get(idx)
    }

    /// 统计当前处于已增强（无损锐利且未标脏）状态的 Tile 数量。
    pub fn refined_tile_count(&self) -> usize {
        self.tiles
            .iter()
            .filter(|t| !t.dirty && t.refined_base_seq.is_some())
            .count()
    }

    /// 统计当前处于脏态等待细化的 Tile 数量。
    pub fn dirty_tile_count(&self) -> usize {
        self.tiles.iter().filter(|t| t.dirty).count()
    }

    /// 动态视频帧到达时更新受影响 Tile 状态：
    /// - 若 `dirty_rects` 非空：仅将与任意有效矩形相交的 Tile 标脏并重置其静止计时，
    ///   未相交的静止代码区 Tile 保持已增强态不被破坏；
    /// - 若 `dirty_rects` 为空（平台未上报脏区）：标记全部 Tile 为脏态。
    pub fn on_dynamic_frame(&mut self, now_ms: u64, frame_seq: u64, dirty_rects: &[Rect]) {
        if self.tiles.is_empty() {
            return;
        }
        if dirty_rects.is_empty() {
            for tile in &mut self.tiles {
                tile.dirty = true;
                tile.last_change_ms = now_ms;
                tile.last_dynamic_seq = Some(
                    tile.last_dynamic_seq
                        .map_or(frame_seq, |prev| prev.max(frame_seq)),
                );
                tile.refined_base_seq = None;
            }
            return;
        }

        for raw_rect in dirty_rects {
            let clamped = raw_rect.clamp_to(self.width, self.height);
            if clamped.is_empty() {
                continue;
            }
            let min_col = (clamped.x / self.tile_size).min(self.cols.saturating_sub(1));
            let max_col = (clamped.right().saturating_sub(1) / self.tile_size).min(self.cols - 1);
            let min_row = (clamped.y / self.tile_size).min(self.rows.saturating_sub(1));
            let max_row = (clamped.bottom().saturating_sub(1) / self.tile_size).min(self.rows - 1);

            for row in min_row..=max_row {
                for col in min_col..=max_col {
                    let idx = (row as usize) * (self.cols as usize) + (col as usize);
                    if let Some(tile) = self.tiles.get_mut(idx) {
                        if tile.rect.intersects(&clamped) {
                            tile.dirty = true;
                            tile.last_change_ms = now_ms;
                            tile.last_dynamic_seq = Some(
                                tile.last_dynamic_seq
                                    .map_or(frame_seq, |prev| prev.max(frame_seq)),
                            );
                            tile.refined_base_seq = None;
                        }
                    }
                }
            }
        }
    }

    /// 收集当前静止时长 `>= config.still_delay_ms` 且尚未细化的候选 Tile，
    /// 按「距光标最近优先、其次屏幕中心优先、最后行列稳定序」排序返回。
    pub fn collect_ready_tiles(
        &self,
        now_ms: u64,
        cursor_xy: Option<(u32, u32)>,
        config: &StillRefineConfig,
    ) -> Vec<ReadyStillTile> {
        let mut ready: Vec<ReadyStillTile> = self
            .tiles
            .iter()
            .filter_map(|t| {
                if !t.dirty {
                    return None;
                }
                let base_frame_seq = t.last_dynamic_seq?;
                if now_ms.saturating_sub(t.last_change_ms) < config.still_delay_ms {
                    return None;
                }
                if t.last_sent_epoch == self.stream_epoch
                    && t.refined_base_seq == Some(base_frame_seq)
                {
                    return None;
                }
                Some(ReadyStillTile {
                    col: t.col,
                    row: t.row,
                    rect: t.rect,
                    stream_epoch: self.stream_epoch,
                    base_frame_seq,
                })
            })
            .collect();

        let center = (self.width / 2, self.height / 2);
        ready.sort_by_key(|t| {
            let tc = (t.rect.x + t.rect.width / 2, t.rect.y + t.rect.height / 2);
            let cursor_dist = cursor_xy.map_or(0u64, |c| dist_sq_u64(tc, c));
            let center_dist = dist_sq_u64(tc, center);
            (cursor_dist, center_dist, t.row, t.col)
        });
        ready
    }

    /// 标记指定 Tile 已在 `(epoch, base_frame_seq)` 完成无损发送；
    /// 若 `epoch` 已过期或该 Tile 在编码期间又被更新动态帧标脏，则忽略标记并返回 `false`。
    pub fn mark_tile_refined(
        &mut self,
        col: u32,
        row: u32,
        epoch: u64,
        base_frame_seq: u64,
    ) -> bool {
        if epoch != self.stream_epoch || col >= self.cols || row >= self.rows {
            return false;
        }
        let idx = (row as usize) * (self.cols as usize) + (col as usize);
        let Some(tile) = self.tiles.get_mut(idx) else {
            return false;
        };
        if tile
            .last_dynamic_seq
            .is_some_and(|latest| latest > base_frame_seq)
        {
            return false;
        }
        tile.dirty = false;
        tile.refined_base_seq = Some(base_frame_seq);
        tile.last_sent_epoch = epoch;
        true
    }

    /// 切分辨率、切显示器或重连时递增 `stream_epoch` 并重建全部网格状态。
    pub fn on_stream_reset(&mut self, new_epoch: u64, width: u32, height: u32) {
        self.stream_epoch = if new_epoch > self.stream_epoch {
            new_epoch
        } else {
            self.stream_epoch.saturating_add(1)
        };
        self.rebuild_tiles(width, height);
    }
}

#[inline]
fn dist_sq_u64(a: (u32, u32), b: (u32, u32)) -> u64 {
    let dx = u64::from(a.0.abs_diff(b.0));
    let dy = u64::from(a.1.abs_diff(b.1));
    dx.saturating_mul(dx).saturating_add(dy.saturating_mul(dy))
}

// ─────────────────────────────────────────────────────────────────
// 3. Pacing 限速与输入优先抢占控制器 StillRefinePacer（修正 #5）
// ─────────────────────────────────────────────────────────────────

/// 静止补帧暂停原因（用于诊断观测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StillRefinePauseReason {
    /// 运行期开关已关闭。
    Disabled,
    /// 对端或本端未声明支持静帧细化能力。
    UnsupportedByPeer,
    /// 用户选择了「极速低延迟」模式。
    UltraLowLatencyMode,
    /// 弱网门控：估算可用带宽低于 `min_bandwidth_bps`（默认 2 Mbps）。
    LowBandwidth,
    /// 弱网门控：丢包率达到或超过 `max_loss_rate`（默认 1%）。
    HighPacketLoss,
}

#[derive(Debug, Clone)]
struct QueuedStillTile {
    cancel_generation: u64,
    tile: EncodedStillTile,
}

/// 静止无损补帧令牌桶限速与输入优先抢占控制器（保“起手第一帧”零卡顿）。
#[derive(Debug, Clone)]
pub struct StillRefinePacer {
    config: StillRefineConfig,
    enabled: bool,
    peer_supported: bool,
    pref: CodecSelectionPref,
    estimated_bandwidth_bps: u32,
    loss_rate: f32,
    tokens: usize,
    last_refill_ms: Option<u64>,
    cancel_generation: u64,
    preempt_count: u64,
    pending: VecDeque<QueuedStillTile>,
}

impl StillRefinePacer {
    /// 以默认配置构造限速控制器。
    pub fn new(config: StillRefineConfig) -> Self {
        Self {
            config,
            enabled: true,
            peer_supported: true,
            pref: CodecSelectionPref::Auto,
            estimated_bandwidth_bps: 14_000_000,
            loss_rate: 0.0,
            tokens: 0,
            last_refill_ms: None,
            cancel_generation: 0,
            preempt_count: 0,
            pending: VecDeque::new(),
        }
    }

    /// 返回当前生效配置。
    pub fn config(&self) -> &StillRefineConfig {
        &self.config
    }

    /// 当前抢占取消代次（每次输入事件或运动检测立即递增）。
    pub fn cancel_generation(&self) -> u64 {
        self.cancel_generation
    }

    /// 累计抢占取消次数。
    pub fn preempt_count(&self) -> u64 {
        self.preempt_count
    }

    /// 当前待发队列中的 Tile 数量。
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// 待发队列当前剩余可入队容量。
    pub fn remaining_capacity(&self) -> usize {
        MAX_PENDING_STILL_TILES.saturating_sub(self.pending.len())
    }

    /// 当前可用令牌字节数（诊断/测试用）。
    pub fn available_tokens(&self) -> usize {
        self.tokens
    }

    /// 设置运行期启停开关；关闭时立即清空待发队列并递增 `cancel_generation`。
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.preempt_and_clear();
        }
    }

    /// 设置双端协商能力是否支持静帧细化；不支持时立即清空待发队列。
    pub fn set_peer_supported(&mut self, supported: bool) {
        self.peer_supported = supported;
        if !supported {
            self.preempt_and_clear();
        }
    }

    /// 更新用户编解码/画质偏好模式；切入「极速低延迟」时立即暂停并清空待发队列。
    pub fn set_codec_pref(&mut self, pref: CodecSelectionPref) {
        self.pref = pref;
        if matches!(pref, CodecSelectionPref::UltraLowLatency) {
            self.preempt_and_clear();
        }
    }

    /// 更新实时链路状态（估算带宽 bps 与丢包率 `0.0..=1.0`）；触发弱网门控时清空待发队列。
    pub fn update_network(&mut self, estimated_bandwidth_bps: u32, loss_rate: f32) {
        self.estimated_bandwidth_bps = estimated_bandwidth_bps;
        self.loss_rate = loss_rate;
        if self.pause_reason().is_some() {
            self.pending.clear();
            self.tokens = 0;
            self.last_refill_ms = None;
        }
    }

    /// 返回当前暂停原因；返回 `None` 表示允许按令牌桶速率发送静止无损补帧。
    pub fn pause_reason(&self) -> Option<StillRefinePauseReason> {
        if !self.enabled {
            return Some(StillRefinePauseReason::Disabled);
        }
        if !self.peer_supported {
            return Some(StillRefinePauseReason::UnsupportedByPeer);
        }
        if matches!(self.pref, CodecSelectionPref::UltraLowLatency) {
            return Some(StillRefinePauseReason::UltraLowLatencyMode);
        }
        if !self.loss_rate.is_finite() || self.loss_rate >= self.config.max_loss_rate {
            return Some(StillRefinePauseReason::HighPacketLoss);
        }
        if self.estimated_bandwidth_bps < self.config.min_bandwidth_bps {
            return Some(StillRefinePauseReason::LowBandwidth);
        }
        None
    }

    /// 当前是否允许发送补帧（无弱网/开关/模式暂停）。
    pub fn can_send(&self) -> bool {
        self.pause_reason().is_none()
    }

    /// 计算当前有效令牌填充速率（字节/秒）：估算可用带宽的 20%–30% 且不超过硬上限。
    pub fn effective_rate_bytes_per_sec(&self) -> usize {
        if !self.can_send() {
            return 0;
        }
        let share = u64::from(
            self.config
                .bandwidth_share_pct
                .clamp(MIN_BANDWIDTH_SHARE_PCT, MAX_BANDWIDTH_SHARE_PCT),
        );
        let bw_bytes_per_sec = u64::from(self.estimated_bandwidth_bps) / 8;
        let scaled = bw_bytes_per_sec.saturating_mul(share) / 100;
        usize::try_from(scaled)
            .unwrap_or(usize::MAX)
            .min(self.config.hard_max_bytes_per_sec)
    }

    fn burst_cap_bytes(&self) -> usize {
        let rate = self.effective_rate_bytes_per_sec();
        let min_one_tile = self.config.max_tile_payload_bytes;
        let dynamic_cap = (rate / 10).max(min_one_tile);
        dynamic_cap.min(self.config.hard_max_burst_bytes.max(min_one_tile))
    }

    fn refill(&mut self, now_ms: u64) {
        if !self.can_send() {
            self.tokens = 0;
            self.last_refill_ms = Some(now_ms);
            return;
        }
        let Some(prev_ms) = self.last_refill_ms else {
            self.last_refill_ms = Some(now_ms);
            return;
        };
        let elapsed_ms = now_ms.saturating_sub(prev_ms);
        if elapsed_ms == 0 {
            return;
        }
        self.last_refill_ms = Some(now_ms);
        let rate = self.effective_rate_bytes_per_sec() as u128;
        let added = rate.saturating_mul(u128::from(elapsed_ms)) / 1000;
        let cap = self.burst_cap_bytes();
        let next = (self.tokens as u128).saturating_add(added);
        self.tokens = usize::try_from(next).unwrap_or(cap).min(cap);
    }

    fn preempt_and_clear(&mut self) {
        self.pending.clear();
        self.cancel_generation = self.cancel_generation.wrapping_add(1);
        self.tokens = 0;
        self.last_refill_ms = None;
        self.preempt_count = self.preempt_count.saturating_add(1);
    }

    /// 收到任意用户输入事件：毫秒级立即清空全部待发补帧并递增 `cancel_generation`（修正 #5）。
    pub fn on_input_event(&mut self) {
        self.preempt_and_clear();
    }

    /// 检测到新动态视频帧/画面运动：立即清空全部待发补帧并递增 `cancel_generation`（修正 #5）。
    pub fn on_motion_detected(&mut self) {
        self.preempt_and_clear();
    }

    /// 将已编码 Tile 加入待发队列（强制校验单载荷 `<= max_tile_payload_bytes` 与队列有界上限）。
    ///
    /// 队列满载（`MAX_PENDING_STILL_TILES`）时拒绝尾部低优先级 Tile（返回 `false`），
    /// 绝不 `pop_front()` 淘汰队首的光标/屏幕中心最高优先级 Tile。
    pub fn enqueue(&mut self, tile: EncodedStillTile) -> bool {
        if !self.can_send() {
            return false;
        }
        if tile.encoded_bytes.is_empty()
            || tile.encoded_bytes.len() > self.config.max_tile_payload_bytes
        {
            return false;
        }
        if self.pending.len() >= MAX_PENDING_STILL_TILES {
            return false;
        }
        self.pending.push_back(QueuedStillTile {
            cancel_generation: self.cancel_generation,
            tile,
        });
        true
    }

    /// 在 `now_ms` 时刻按令牌桶预算取出最多 1 片允许立即发送的 Tile；预算不足或处于暂停态返回 `None`。
    pub fn poll_send(&mut self, now_ms: u64) -> Option<EncodedStillTile> {
        self.refill(now_ms);
        if !self.can_send() {
            return None;
        }
        while let Some(front) = self.pending.front() {
            if front.cancel_generation != self.cancel_generation
                || front.tile.encoded_bytes.len() > self.config.max_tile_payload_bytes
            {
                self.pending.pop_front();
                continue;
            }
            let cost = front.tile.encoded_bytes.len();
            if self.tokens < cost {
                return None;
            }
            self.tokens -= cost;
            return self.pending.pop_front().map(|q| q.tile);
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────
// 4. 接收端时序一致性守卫 StillRefineReceiver（防“画面倒退”）
// ─────────────────────────────────────────────────────────────────

/// 接收端拒绝应用某片静止无损 Tile 补丁的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StillPatchRejectReason {
    /// 非 `StillTileRefine` 消息。
    NotStillTileMsg,
    /// `stream_epoch` 与当前接收端视频流纪元不匹配（跨分辨率/切屏/重连过期补丁）。
    EpochMismatch,
    /// 目标 Tile 已被更新的动态视频帧覆盖（`tile_last_dynamic_seq > patch.base_frame_seq`）。
    SupersededByDynamicFrame,
    /// 矩形为空或超出当前视频帧边界。
    OutOfBounds,
    /// 不支持的编解码器或像素格式标识。
    UnsupportedCodecOrFormat,
    /// Base64 或原始压缩载荷超过安全上限或非法。
    InvalidPayload,
    /// QOI 解码失败或解码尺寸与声明宽高不符。
    DecodeFailed,
    /// 像素字节长度与矩形尺寸不匹配。
    InvalidPixels,
}

/// 接收端静止无损 Tile 补帧可观测诊断指标。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StillRefineMetrics {
    /// 成功通过一致性守卫并应用的无损 Tile 补丁累计数量。
    pub applied_count: u64,
    /// 因过期 `stream_epoch`、已被新动态帧覆盖或非法载荷而丢弃的补丁计数。
    pub drop_stale_count: u64,
    /// 成功应用补丁的平均压缩载荷字节数（无样本时为 0）。
    pub avg_tile_bytes: u64,
}

/// 控制端静止无损 Tile 接收与时序一致性守卫（防“画面倒退”与畸形载荷 DoS）。
#[derive(Debug, Clone)]
pub struct StillRefineReceiver {
    current_epoch: u64,
    width: u32,
    height: u32,
    tile_size: u32,
    cols: u32,
    rows: u32,
    tile_last_dynamic_seq: Vec<u64>,
    has_active_overlay: bool,
    applied_count: u64,
    drop_stale_count: u64,
    total_applied_bytes: u64,
}

impl StillRefineReceiver {
    /// 以初始 `stream_epoch` 与画布尺寸构造接收端守卫。
    pub fn new(initial_epoch: u64, width: u32, height: u32) -> Self {
        let mut r = Self {
            current_epoch: initial_epoch,
            width: 0,
            height: 0,
            tile_size: DEFAULT_TILE_SIZE,
            cols: 0,
            rows: 0,
            tile_last_dynamic_seq: Vec::new(),
            has_active_overlay: false,
            applied_count: 0,
            drop_stale_count: 0,
            total_applied_bytes: 0,
        };
        r.rebuild_seq_grid(width, height);
        r
    }

    fn rebuild_seq_grid(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
        if width == 0 || height == 0 {
            self.cols = 0;
            self.rows = 0;
            self.tile_last_dynamic_seq.clear();
            return;
        }
        self.cols = width.div_ceil(self.tile_size);
        self.rows = height.div_ceil(self.tile_size);
        let total = (self.cols as usize).saturating_mul(self.rows as usize);
        self.tile_last_dynamic_seq = vec![0; total];
    }

    /// 当前接收端期望的权威 `stream_epoch`。
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// 当前接收端画布尺寸 `(width, height)`。
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// 当前渲染器是否存在已叠加且尚未被动态帧或重置清除的静止无损层。
    pub fn has_active_overlay(&self) -> bool {
        self.has_active_overlay
    }

    /// 清除当前活跃叠加标记（在主动清空渲染器叠加层后调用）。
    pub fn clear_active_overlay(&mut self) {
        self.has_active_overlay = false;
    }

    /// 查询实时诊断指标快照。
    pub fn metrics(&self) -> StillRefineMetrics {
        let avg_tile_bytes = self
            .total_applied_bytes
            .checked_div(self.applied_count)
            .unwrap_or(0);
        StillRefineMetrics {
            applied_count: self.applied_count,
            drop_stale_count: self.drop_stale_count,
            avg_tile_bytes,
        }
    }

    /// 记录一次外部前置丢弃（例如功能已关闭或媒体已暂停时收到的补丁）。
    pub fn record_dropped(&mut self) {
        self.drop_stale_count = self.drop_stale_count.saturating_add(1);
    }

    /// 切分辨率、切显示器或重连时更新权威 `stream_epoch` 并重置逐 Tile 动态帧序追踪表。
    pub fn on_stream_reset(&mut self, new_epoch: u64, width: u32, height: u32) {
        self.current_epoch = new_epoch;
        self.has_active_overlay = false;
        self.rebuild_seq_grid(width, height);
    }

    /// 动态视频帧到达/呈现时更新受影响 Tile 的最高动态帧序号。
    ///
    /// - 若 `dirty_rects` 非空：仅推进相交 Tile 的 `tile_last_dynamic_seq`；
    /// - 若 `dirty_rects` 为空：推进全屏所有 Tile 的 `tile_last_dynamic_seq`。
    pub fn on_dynamic_frame(&mut self, frame_seq: u64, dirty_rects: &[Rect]) {
        if self.tile_last_dynamic_seq.is_empty() {
            return;
        }
        if dirty_rects.is_empty() {
            for seq in &mut self.tile_last_dynamic_seq {
                if frame_seq > *seq {
                    *seq = frame_seq;
                }
            }
            return;
        }
        for raw in dirty_rects {
            let clamped = raw.clamp_to(self.width, self.height);
            if clamped.is_empty() {
                continue;
            }
            let min_col = (clamped.x / self.tile_size).min(self.cols.saturating_sub(1));
            let max_col = (clamped.right().saturating_sub(1) / self.tile_size).min(self.cols - 1);
            let min_row = (clamped.y / self.tile_size).min(self.rows.saturating_sub(1));
            let max_row = (clamped.bottom().saturating_sub(1) / self.tile_size).min(self.rows - 1);
            for row in min_row..=max_row {
                for col in min_col..=max_col {
                    let idx = (row as usize) * (self.cols as usize) + (col as usize);
                    if let Some(slot) = self.tile_last_dynamic_seq.get_mut(idx) {
                        if frame_seq > *slot {
                            *slot = frame_seq;
                        }
                    }
                }
            }
        }
    }

    fn precheck_header(
        &self,
        stream_epoch: u64,
        base_frame_seq: u64,
        rect: Rect,
    ) -> Result<(), StillPatchRejectReason> {
        if stream_epoch != self.current_epoch {
            return Err(StillPatchRejectReason::EpochMismatch);
        }
        if rect.is_empty() || self.width == 0 || self.height == 0 {
            return Err(StillPatchRejectReason::OutOfBounds);
        }
        if rect.right() > self.width || rect.bottom() > self.height {
            return Err(StillPatchRejectReason::OutOfBounds);
        }
        let min_col = (rect.x / self.tile_size).min(self.cols.saturating_sub(1));
        let max_col = (rect.right().saturating_sub(1) / self.tile_size).min(self.cols - 1);
        let min_row = (rect.y / self.tile_size).min(self.rows.saturating_sub(1));
        let max_row = (rect.bottom().saturating_sub(1) / self.tile_size).min(self.rows - 1);
        for row in min_row..=max_row {
            for col in min_col..=max_col {
                let idx = (row as usize) * (self.cols as usize) + (col as usize);
                if let Some(&last_seq) = self.tile_last_dynamic_seq.get(idx) {
                    if last_seq > base_frame_seq {
                        return Err(StillPatchRejectReason::SupersededByDynamicFrame);
                    }
                }
            }
        }
        Ok(())
    }

    /// 校验一片已解码 [`StillTilePatch`] 的时序与边界一致性；通过后更新指标并返回 `Ok(())`，
    /// 否则累加 `drop_stale_count` 并返回拒绝原因。
    pub fn validate_and_accept(
        &mut self,
        patch: &StillTilePatch,
        encoded_bytes: usize,
    ) -> Result<(), StillPatchRejectReason> {
        if let Err(reason) =
            self.precheck_header(patch.stream_epoch, patch.base_frame_seq, patch.rect)
        {
            self.record_dropped();
            return Err(reason);
        }
        if !matches!(patch.format, PixelFormat::Bgra8 | PixelFormat::Rgba8) {
            self.record_dropped();
            return Err(StillPatchRejectReason::UnsupportedCodecOrFormat);
        }
        let expected_len = (patch.rect.width as usize)
            .checked_mul(patch.rect.height as usize)
            .and_then(|px| px.checked_mul(4));
        if expected_len != Some(patch.pixels.len()) {
            self.record_dropped();
            return Err(StillPatchRejectReason::InvalidPixels);
        }

        self.applied_count = self.applied_count.saturating_add(1);
        self.total_applied_bytes = self
            .total_applied_bytes
            .saturating_add(encoded_bytes as u64);
        self.has_active_overlay = true;
        Ok(())
    }

    /// 在不累加 `applied_count` 的前提下校验并解码 [`DisplayControlMsg::StillTileRefine`]
    /// （供调用方在渲染器锁外解码、再以 `try_lock` 实际叠加成功后调用 [`Self::commit_applied`]）。
    ///
    /// 任意校验或解码失败均累加 `drop_stale_count` 并返回具体拒绝原因。
    pub fn decode_msg_without_commit(
        &mut self,
        msg: &DisplayControlMsg,
    ) -> Result<(StillTilePatch, usize), StillPatchRejectReason> {
        let DisplayControlMsg::StillTileRefine {
            stream_epoch,
            base_frame_seq,
            x,
            y,
            width,
            height,
            format,
            codec,
            data_base64,
        } = msg
        else {
            return Err(StillPatchRejectReason::NotStillTileMsg);
        };

        let rect = Rect::new(*x, *y, *width, *height);
        // 1) 解码前快速拒绝过期 epoch / 已被新动态帧覆盖 / 越界载荷（零解码开销）。
        if let Err(reason) = self.precheck_header(*stream_epoch, *base_frame_seq, rect) {
            self.record_dropped();
            return Err(reason);
        }
        if !codec.eq_ignore_ascii_case(STILL_TILE_CODEC_QOI) {
            self.record_dropped();
            return Err(StillPatchRejectReason::UnsupportedCodecOrFormat);
        }
        let Some(pixel_format) = parse_still_pixel_format(format) else {
            self.record_dropped();
            return Err(StillPatchRejectReason::UnsupportedCodecOrFormat);
        };
        if data_base64.is_empty() || data_base64.len() > MAX_STILL_TILE_BASE64_BYTES {
            self.record_dropped();
            return Err(StillPatchRejectReason::InvalidPayload);
        }
        let Some(raw_bytes) = base64_decode(data_base64) else {
            self.record_dropped();
            return Err(StillPatchRejectReason::InvalidPayload);
        };
        if raw_bytes.is_empty() || raw_bytes.len() > MAX_STILL_TILE_PAYLOAD_BYTES {
            self.record_dropped();
            return Err(StillPatchRejectReason::InvalidPayload);
        }
        // 解码前直接核对 QOI 头魔数与宽高是否与消息声明一致，实现零放大拒绝（防 30B 畸形头触发 4 MiB 瞬时分配）。
        if raw_bytes.len() < QOI_MIN_LEN || raw_bytes[0..4] != QOI_MAGIC {
            self.record_dropped();
            return Err(StillPatchRejectReason::DecodeFailed);
        }
        let hdr_w = u32::from_be_bytes([raw_bytes[4], raw_bytes[5], raw_bytes[6], raw_bytes[7]]);
        let hdr_h = u32::from_be_bytes([raw_bytes[8], raw_bytes[9], raw_bytes[10], raw_bytes[11]]);
        if hdr_w != *width || hdr_h != *height {
            self.record_dropped();
            return Err(StillPatchRejectReason::DecodeFailed);
        }
        let Ok(decoded) = decode_qoi(&raw_bytes, pixel_format) else {
            self.record_dropped();
            return Err(StillPatchRejectReason::DecodeFailed);
        };
        if decoded.width != *width || decoded.height != *height {
            self.record_dropped();
            return Err(StillPatchRejectReason::DecodeFailed);
        }

        let expected_len = (rect.width as usize)
            .checked_mul(rect.height as usize)
            .and_then(|px| px.checked_mul(4));
        if expected_len != Some(decoded.pixels.len()) {
            self.record_dropped();
            return Err(StillPatchRejectReason::InvalidPixels);
        }

        let patch = StillTilePatch {
            stream_epoch: *stream_epoch,
            base_frame_seq: *base_frame_seq,
            rect,
            format: decoded.format,
            pixels: decoded.pixels,
        };
        Ok((patch, raw_bytes.len()))
    }

    /// 在实际将补丁叠加至渲染器成功后提交统计指标与活跃叠加层标记。
    pub fn commit_applied(&mut self, encoded_bytes: usize) {
        self.applied_count = self.applied_count.saturating_add(1);
        self.total_applied_bytes = self
            .total_applied_bytes
            .saturating_add(encoded_bytes as u64);
        self.has_active_overlay = true;
    }

    /// 校验并解码 [`DisplayControlMsg::StillTileRefine`]（在任何渲染器锁之外完成解码并记账），
    /// 返回 `(StillTilePatch, encoded_bytes)`；所有过期、越界或畸形载荷均在解码前/解码期安全拦截。
    pub fn decode_msg_if_valid(
        &mut self,
        msg: &DisplayControlMsg,
    ) -> Result<(StillTilePatch, usize), StillPatchRejectReason> {
        let (patch, raw_len) = self.decode_msg_without_commit(msg)?;
        self.commit_applied(raw_len);
        Ok((patch, raw_len))
    }

    /// 校验、解码并将 [`DisplayControlMsg::StillTileRefine`] 投递至可选 [`Renderer`] 实现。
    pub fn decode_and_apply_msg(
        &mut self,
        msg: &DisplayControlMsg,
        renderer: Option<&mut dyn Renderer>,
    ) -> Result<StillTilePatch, StillPatchRejectReason> {
        let (patch, _) = self.decode_msg_if_valid(msg)?;
        if let Some(r) = renderer {
            let _ = r.apply_still_tile(&patch);
        }
        Ok(patch)
    }
}

// ─────────────────────────────────────────────────────────────────
// 5. 被控端综合控制器 HostStillRefineController（供 host_bridge 接线）
// ─────────────────────────────────────────────────────────────────

/// 被控端静止无损补帧综合控制器：组合 [`StillTileGrid`] 与 [`StillRefinePacer`]，
/// 统一处理能力协商、运行期开关、输入/动态帧抢占、流重置与限速出队。
///
/// 网格 Tile 仅在其全部子片真正经 [`Self::poll_next_display_ctrl_msg`] 出队发送后才标记为已细化；
/// 若在途期间被输入抢占、弱网暂停或关闭开关清空队列，所有未发出的 Tile 自动保持 `dirty = true`，
/// 恢复静止后无损补全，绝不出现永久模糊区域。
#[derive(Debug, Clone)]
pub struct HostStillRefineController {
    grid: StillTileGrid,
    pacer: StillRefinePacer,
    host_supported: bool,
    peer_supported: bool,
    /// 已入队待发但尚未全部出队发送的网格 Tile 记账：`(col, row) -> (stream_epoch, base_frame_seq, remaining_subtiles)`。
    in_queue_tiles: BTreeMap<(u32, u32), (u64, u64, usize)>,
    last_synced_cancel_gen: u64,
}

impl HostStillRefineController {
    /// 构造被控端静止无损补帧控制器（初始 `peer_supported = false`，等待双端协商确认）。
    pub fn new(initial_epoch: u64, width: u32, height: u32, host_supported: bool) -> Self {
        let mut pacer = StillRefinePacer::new(StillRefineConfig::default());
        pacer.set_peer_supported(false);
        let cancel_gen = pacer.cancel_generation();
        Self {
            grid: StillTileGrid::new(initial_epoch, width, height),
            pacer,
            host_supported,
            peer_supported: false,
            in_queue_tiles: BTreeMap::new(),
            last_synced_cancel_gen: cancel_gen,
        }
    }

    fn sync_in_queue_with_pacer(&mut self) {
        let cur_gen = self.pacer.cancel_generation();
        if cur_gen != self.last_synced_cancel_gen || self.pacer.pending_len() == 0 {
            self.in_queue_tiles.clear();
            self.last_synced_cancel_gen = cur_gen;
        }
    }

    /// 当前权威 `stream_epoch`。
    pub fn stream_epoch(&self) -> u64 {
        self.grid.stream_epoch()
    }

    /// 访问内部网格状态机（观测/测试用）。
    pub fn grid(&self) -> &StillTileGrid {
        &self.grid
    }

    /// 访问内部限速抢占控制器（观测/测试用）。
    pub fn pacer(&self) -> &StillRefinePacer {
        &self.pacer
    }

    /// 当前是否满足双端支持、运行期开启与非弱网/非极速模式条件。
    pub fn is_active(&self) -> bool {
        self.host_supported && self.peer_supported && self.pacer.can_send()
    }

    /// 收到控制端 `ClientMediaCaps` 时同步对端静帧细化能力与编解码偏好模式。
    pub fn on_client_media_caps(
        &mut self,
        refinement_caps: Option<&RefinementCapability>,
        pref: CodecSelectionPref,
    ) {
        let peer_ok = refinement_caps.is_some_and(|c| c.supported);
        self.peer_supported = peer_ok;
        self.pacer
            .set_peer_supported(self.host_supported && peer_ok);
        self.pacer.set_codec_pref(pref);
        self.sync_in_queue_with_pacer();
    }

    /// 收到控制端 `StillRefineConfig` 时运行期动态启停静止无损补帧。
    pub fn on_still_refine_config(&mut self, enabled: bool) {
        self.pacer.set_enabled(enabled);
        self.sync_in_queue_with_pacer();
    }

    /// 更新当前估算可用带宽与丢包率。
    pub fn update_network(&mut self, estimated_bandwidth_bps: u32, loss_rate: f32) {
        self.pacer
            .update_network(estimated_bandwidth_bps, loss_rate);
        self.sync_in_queue_with_pacer();
    }

    /// 收到任意用户输入事件：毫秒级抢占清空待发补帧并递增 `cancel_generation`。
    pub fn on_input_event(&mut self) {
        self.pacer.on_input_event();
        self.sync_in_queue_with_pacer();
    }

    /// 检测到新动态视频帧：立即抢占清空待发补帧并更新网格局部脏区状态。
    pub fn on_dynamic_frame(&mut self, now_ms: u64, frame_seq: u64, dirty_rects: &[Rect]) {
        self.pacer.on_motion_detected();
        self.sync_in_queue_with_pacer();
        self.grid.on_dynamic_frame(now_ms, frame_seq, dirty_rects);
    }

    /// 切分辨率、切显示器、切编码器或会话重建时递增 `stream_epoch`、重置网格并清空待发队列。
    pub fn on_stream_reset(&mut self, width: u32, height: u32) -> u64 {
        let next = self.grid.stream_epoch().saturating_add(1);
        self.grid.on_stream_reset(next, width, height);
        self.pacer.on_motion_detected();
        self.sync_in_queue_with_pacer();
        self.grid.stream_epoch()
    }

    /// 在静止期从完整 CPU 帧中收集就绪 Tile、执行 QOI 编码（超 24 KiB 自动切分子块）并入队待发。
    ///
    /// - 队列满载时立即早停编码并保留队首光标/屏幕中心最高优先级 Tile；
    /// - 仅在后续 [`Self::poll_next_display_ctrl_msg`] 真正出队发完某 Tile 全部子块后才在网格中标记已细化，
    ///   保证抢占/弱网/开关切换后未发出的 Tile 仍保持脏态并在再次静止时自动补全。
    pub fn collect_and_enqueue_from_frame(
        &mut self,
        now_ms: u64,
        cursor_xy: Option<(u32, u32)>,
        frame: &CpuFrame,
    ) -> usize {
        self.sync_in_queue_with_pacer();
        if !self.is_active() || self.pacer.remaining_capacity() == 0 {
            return 0;
        }
        let cfg = self.pacer.config().clone();
        let ready = self.grid.collect_ready_tiles(now_ms, cursor_xy, &cfg);
        let mut enqueued = 0usize;
        for tile in ready {
            if self.pacer.remaining_capacity() == 0 {
                break;
            }
            if self
                .in_queue_tiles
                .get(&(tile.col, tile.row))
                .is_some_and(|&(ep, seq, _)| ep == tile.stream_epoch && seq == tile.base_frame_seq)
            {
                continue;
            }
            if let Ok(subtiles) = encode_tile_with_subdivision(
                frame,
                tile.rect,
                tile.stream_epoch,
                tile.base_frame_seq,
                cfg.max_tile_payload_bytes,
            ) {
                if subtiles.is_empty() {
                    // 极高熵噪声块跳过后直接结案，避免下一拍空转重复编码。
                    self.grid.mark_tile_refined(
                        tile.col,
                        tile.row,
                        tile.stream_epoch,
                        tile.base_frame_seq,
                    );
                    continue;
                }
                if subtiles.len() > self.pacer.remaining_capacity() {
                    // 剩余队列容量不足以容纳该 Tile 全部子片，立即早停留待下拍继续编码。
                    break;
                }
                let mut pushed = 0usize;
                for sub in subtiles {
                    if self.pacer.enqueue(sub) {
                        pushed += 1;
                        enqueued += 1;
                    }
                }
                if pushed > 0 {
                    self.in_queue_tiles.insert(
                        (tile.col, tile.row),
                        (tile.stream_epoch, tile.base_frame_seq, pushed),
                    );
                }
            }
        }
        enqueued
    }

    /// 按令牌桶限速出队至多 1 条 `DisplayControlMsg::StillTileRefine`，
    /// 当对应网格 Tile 的全部子片均已出队发送后立即在网格中标记为已细化。
    pub fn poll_next_display_ctrl_msg(&mut self, now_ms: u64) -> Option<DisplayControlMsg> {
        self.sync_in_queue_with_pacer();
        if !self.is_active() {
            return None;
        }
        let tile = self.pacer.poll_send(now_ms)?;
        let tile_sz = self.grid.tile_size();
        let key = (tile.rect.x / tile_sz, tile.rect.y / tile_sz);
        let completed = if let Some((ep, seq, remaining)) = self.in_queue_tiles.get_mut(&key) {
            if *ep == tile.stream_epoch && *seq == tile.base_frame_seq {
                *remaining = remaining.saturating_sub(1);
                *remaining == 0
            } else {
                false
            }
        } else {
            false
        };
        if completed {
            self.in_queue_tiles.remove(&key);
            self.grid
                .mark_tile_refined(key.0, key.1, tile.stream_epoch, tile.base_frame_seq);
        }
        tile.to_display_ctrl_msg()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_render::{FakeRenderer, FakeRendererConfig};

    fn make_solid_pixels(w: u32, h: u32, p: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::with_capacity((w * h * 4) as usize);
        for _ in 0..(w * h) {
            out.extend_from_slice(&p);
        }
        out
    }

    fn make_gradient_pixels(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                out.push(((x * 7 + y * 3) & 0xFF) as u8);
                out.push(((x * 3 + y * 11) & 0xFF) as u8);
                out.push(((x ^ y) & 0xFF) as u8);
                out.push(if (x + y) % 13 == 0 { 180 } else { 255 });
            }
        }
        out
    }

    fn make_text_edge_pixels(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                // 模拟深色 IDE 背景 + 锐利亮色字体笔画 + 亚像素抗锯齿边缘
                let is_glyph = (x % 9 == 2 && y % 14 >= 2 && y % 14 <= 11)
                    || (y % 14 == 6 && x % 9 >= 2 && x % 9 <= 6);
                let is_aa = !is_glyph && ((x + 1) % 9 == 2 && y % 14 >= 2 && y % 14 <= 11);
                let px = if is_glyph {
                    [0xF2, 0xEC, 0xE8, 0xFF]
                } else if is_aa {
                    [0x6A, 0x74, 0x82, 0xFF]
                } else {
                    [0x24, 0x1E, 0x1B, 0xFF]
                };
                out.extend_from_slice(&px);
            }
        }
        out
    }

    /// 单测 1a：QOI BGRA/RGBA 100% 无损像素往返（纯色、渐变、文字边缘、奇偶尺寸）。
    #[test]
    fn qoi_lossless_roundtrip_bgra_and_rgba_various_patterns_and_dims() {
        let cases: Vec<(&str, u32, u32, Vec<u8>)> = vec![
            ("solid_1x1", 1, 1, make_solid_pixels(1, 1, [0, 0, 0, 255])),
            (
                "solid_128x128",
                128,
                128,
                make_solid_pixels(128, 128, [30, 40, 50, 255]),
            ),
            (
                "solid_transparent_black",
                17,
                19,
                make_solid_pixels(17, 19, [0, 0, 0, 0]),
            ),
            ("gradient_odd_63x37", 63, 37, make_gradient_pixels(63, 37)),
            (
                "gradient_even_128x128",
                128,
                128,
                make_gradient_pixels(128, 128),
            ),
            (
                "text_edges_128x128",
                128,
                128,
                make_text_edge_pixels(128, 128),
            ),
            (
                "text_edges_odd_105x87",
                105,
                87,
                make_text_edge_pixels(105, 87),
            ),
        ];

        for (label, w, h, raw) in cases {
            let enc_bgra = encode_qoi_bgra(&raw, w, h).expect(label);
            let dec_bgra = decode_qoi_bgra(&enc_bgra).expect(label);
            assert_eq!(dec_bgra.width, w, "{label}");
            assert_eq!(dec_bgra.height, h, "{label}");
            assert_eq!(dec_bgra.format, PixelFormat::Bgra8, "{label}");
            assert_eq!(dec_bgra.pixels, raw, "{label} BGRA lossless mismatch");

            let enc_rgba = encode_qoi_rgba(&raw, w, h).expect(label);
            let dec_rgba = decode_qoi_rgba(&enc_rgba).expect(label);
            assert_eq!(dec_rgba.format, PixelFormat::Rgba8, "{label}");
            assert_eq!(dec_rgba.pixels, raw, "{label} RGBA lossless mismatch");

            // 跨格式解码验证：BGRA 编码再解回 RGBA 应恰好交换 R 与 B 通道。
            let cross = decode_qoi_rgba(&enc_bgra).expect(label);
            for (src, dst) in raw.chunks_exact(4).zip(cross.pixels.chunks_exact(4)) {
                assert_eq!(
                    [dst[0], dst[1], dst[2], dst[3]],
                    [src[2], src[1], src[0], src[3]]
                );
            }
        }

        // 文字边缘 128×128 Tile 应具备明显压缩率（远低于原始 64 KiB 与 24 KiB 上限）。
        let text_tile = make_text_edge_pixels(128, 128);
        let compressed = encode_qoi_bgra(&text_tile, 128, 128).expect("encode text tile");
        assert!(
            compressed.len() < MAX_STILL_TILE_PAYLOAD_BYTES,
            "128x128 text tile should compress well under 24 KiB, got {} bytes",
            compressed.len()
        );
    }

    /// 单测 1b：QOI 解码器对恶意超大宽高 OOM、截断、错误魔数、非法 RUN 溢出 100% 返回 Err 零 panic。
    #[test]
    fn qoi_decoder_rejects_malicious_truncated_and_oom_headers_without_panic() {
        // 1) 超大宽高（u32::MAX × u32::MAX）防乘法溢出与 OOM
        let mut oom_u32_max = Vec::new();
        oom_u32_max.extend_from_slice(&QOI_MAGIC);
        oom_u32_max.extend_from_slice(&u32::MAX.to_be_bytes());
        oom_u32_max.extend_from_slice(&u32::MAX.to_be_bytes());
        oom_u32_max.extend_from_slice(&[4, 0]);
        oom_u32_max.extend_from_slice(&QOI_END_MARKER);
        assert_eq!(
            decode_qoi_bgra(&oom_u32_max),
            Err(StillRefineError::DimensionsTooLarge)
        );

        // 2) 超过 MAX_QOI_DIM 的尺寸拒绝
        let mut oom_large = Vec::new();
        oom_large.extend_from_slice(&QOI_MAGIC);
        oom_large.extend_from_slice(&(MAX_QOI_DIM + 1).to_be_bytes());
        oom_large.extend_from_slice(&64u32.to_be_bytes());
        oom_large.extend_from_slice(&[4, 0]);
        oom_large.extend_from_slice(&QOI_END_MARKER);
        assert_eq!(
            decode_qoi_bgra(&oom_large),
            Err(StillRefineError::DimensionsTooLarge)
        );

        // 3) 单边合法但总像素超过 MAX_QOI_PIXELS（2048×2048 = 4M > 1M）拒绝
        let mut oom_pixels = Vec::new();
        oom_pixels.extend_from_slice(&QOI_MAGIC);
        oom_pixels.extend_from_slice(&2048u32.to_be_bytes());
        oom_pixels.extend_from_slice(&2048u32.to_be_bytes());
        oom_pixels.extend_from_slice(&[4, 0]);
        oom_pixels.extend_from_slice(&QOI_END_MARKER);
        assert_eq!(
            decode_qoi_bgra(&oom_pixels),
            Err(StillRefineError::DimensionsTooLarge)
        );

        // 4) 0 宽/0 高、非法魔数、非法通道数、非法色彩空间、缺失结束标记
        let mut zero_dim = oom_u32_max.clone();
        zero_dim[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            decode_qoi_bgra(&zero_dim),
            Err(StillRefineError::InvalidDimensions)
        );

        let mut bad_magic = oom_u32_max.clone();
        bad_magic[0..4].copy_from_slice(b"nope");
        assert_eq!(
            decode_qoi_bgra(&bad_magic),
            Err(StillRefineError::InvalidMagic)
        );

        let valid = encode_qoi_bgra(&make_gradient_pixels(16, 16), 16, 16).unwrap();
        // 截断所有前缀长度：全部必须返回 Err 绝不 panic
        for cut in 0..valid.len() {
            assert!(
                decode_qoi_bgra(&valid[..cut]).is_err(),
                "truncated length {cut} must fail"
            );
        }

        // RUN 越界溢出：声明 2×2=4 像素但写入 run=62
        let mut run_overflow = Vec::new();
        run_overflow.extend_from_slice(&QOI_MAGIC);
        run_overflow.extend_from_slice(&2u32.to_be_bytes());
        run_overflow.extend_from_slice(&2u32.to_be_bytes());
        run_overflow.extend_from_slice(&[4, 0]);
        run_overflow.push(0xC0 | 61);
        run_overflow.extend_from_slice(&QOI_END_MARKER);
        assert_eq!(
            decode_qoi_bgra(&run_overflow),
            Err(StillRefineError::CorruptStream)
        );

        // 多余尾字节拒绝
        let mut trailing = valid.clone();
        let insert_at = trailing.len() - QOI_END_MARKER.len();
        trailing.insert(insert_at, 0x00);
        assert_eq!(
            decode_qoi_bgra(&trailing),
            Err(StillRefineError::CorruptStream)
        );

        // 预算超限时 encode_tile_with_subdivision 自动切分为子块并全部 <= 预算
        let mut noisy = Vec::with_capacity(128 * 128 * 4);
        let mut state: u32 = 0x1234_5678;
        for _ in 0..(128 * 128) {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            noisy.extend_from_slice(&state.to_le_bytes());
        }
        let frame = CpuFrame {
            width: 128,
            height: 128,
            format: PixelFormat::Bgra8,
            stride: 128 * 4,
            data: noisy,
        };
        let subtiles =
            encode_tile_with_subdivision(&frame, Rect::new(0, 0, 128, 128), 1, 7, 24 * 1024)
                .expect("subdivide noisy tile");
        assert!(
            subtiles.len() > 1,
            "high-entropy 128x128 tile should subdivide under 24 KiB cap"
        );
        for st in &subtiles {
            assert!(st.encoded_bytes.len() <= 24 * 1024);
            let dec = decode_qoi_bgra(&st.encoded_bytes).expect("decode subtile");
            assert_eq!((dec.width, dec.height), (st.rect.width, st.rect.height));
        }
    }

    /// 单测 2：`StillTileGrid` 局部脏区失效（模拟终端 500ms 闪烁光标只失效 1 个 Tile，
    /// 周围 95% 静止代码区 Tile 稳定保持无损态且不被打断；并验证光标优先排序与流重置）。
    #[test]
    fn still_tile_grid_blinking_cursor_only_invalidates_intersecting_tile() {
        let cfg = StillRefineConfig::default();
        let mut grid = StillTileGrid::new(1, 1920, 1080);
        assert_eq!(grid.grid_dims(), (15, 9));
        assert_eq!(grid.tile_count(), 135);
        // 边缘 Tile 精确对齐到 1920×1080（最后一行高度 = 1080 - 8*128 = 56）。
        assert_eq!(
            grid.tile_at(14, 8).unwrap().rect,
            Rect::new(14 * 128, 8 * 128, 128, 56)
        );

        // t = 0ms：全屏首帧到达 -> 全部 135 个 Tile 标脏。
        grid.on_dynamic_frame(0, 1, &[]);
        assert_eq!(grid.dirty_tile_count(), 135);
        assert!(grid.collect_ready_tiles(150, None, &cfg).is_empty());

        // t = 200ms：全部 135 个 Tile 满足静止阈值，按距光标 (200, 200) 最近优先排序。
        let ready = grid.collect_ready_tiles(200, Some((200, 200)), &cfg);
        assert_eq!(ready.len(), 135);
        assert_eq!(
            (ready[0].col, ready[0].row),
            (1, 1),
            "tile containing cursor (200,200) must be prioritized first"
        );
        for t in &ready {
            assert!(grid.mark_tile_refined(t.col, t.row, t.stream_epoch, t.base_frame_seq));
        }
        assert_eq!(grid.refined_tile_count(), 135);
        assert_eq!(grid.dirty_tile_count(), 0);

        // 模拟终端 500ms 周期闪烁光标：仅落在 Tile (1, 1) 内部 (140, 140, 8, 18)。
        let cursor_rect = Rect::new(140, 140, 8, 18);
        for blink in 1..=5u64 {
            let blink_ms = blink * 500;
            let seq = 1 + blink;
            grid.on_dynamic_frame(blink_ms, seq, &[cursor_rect]);

            // 仅 Tile (1, 1) 被标脏，其余 134/135 (>99%) 静止代码区 Tile 保持已增强态！
            assert_eq!(grid.dirty_tile_count(), 1);
            assert_eq!(grid.refined_tile_count(), 134);
            assert!(grid.tile_at(1, 1).unwrap().dirty);
            assert!(!grid.tile_at(0, 0).unwrap().dirty);
            assert_eq!(grid.tile_at(0, 0).unwrap().refined_base_seq, Some(1));

            // 200ms 后仅收集到这 1 个光标 Tile。
            let ready_after = grid.collect_ready_tiles(blink_ms + 200, Some((144, 149)), &cfg);
            assert_eq!(ready_after.len(), 1);
            assert_eq!((ready_after[0].col, ready_after[0].row), (1, 1));
            assert_eq!(ready_after[0].base_frame_seq, seq);
            assert!(grid.mark_tile_refined(1, 1, 1, seq));
            assert_eq!(grid.refined_tile_count(), 135);
        }

        // 切分辨率/切屏触发流重置：递增 stream_epoch 并重建网格。
        grid.on_stream_reset(2, 1512, 982);
        assert_eq!(grid.stream_epoch(), 2);
        assert_eq!(grid.grid_dims(), (12, 8));
        assert_eq!(
            grid.tile_at(11, 7).unwrap().rect,
            Rect::new(11 * 128, 7 * 128, 104, 86)
        );
        assert_eq!(grid.refined_tile_count(), 0);
    }

    /// 单测 3：`StillRefinePacer` 令牌桶限速、弱网/极速模式暂停、输入事件毫秒级抢占清空。
    #[test]
    fn still_refine_pacer_enforces_rate_weak_net_gating_and_input_preemption() {
        let cfg = StillRefineConfig::default();
        let mut pacer = StillRefinePacer::new(cfg.clone());
        // 8 Mbps -> 1 MB/s，25% 份额 = 250_000 B/s（即 100ms 产生 25_000 B 令牌）。
        pacer.update_network(8_000_000, 0.0);
        assert_eq!(pacer.effective_rate_bytes_per_sec(), 250_000);

        let make_tile = |size: usize| EncodedStillTile {
            stream_epoch: 1,
            base_frame_seq: 10,
            rect: Rect::new(0, 0, 128, 128),
            format: PixelFormat::Bgra8,
            encoded_bytes: vec![0x55; size],
        };

        // 超过 24 KiB 硬上限的单 Tile 必须被拒绝入队。
        assert!(!pacer.enqueue(make_tile(MAX_STILL_TILE_PAYLOAD_BYTES + 1)));

        // 入队 3 片 10_000 B Tile。
        for _ in 0..3 {
            assert!(pacer.enqueue(make_tile(10_000)));
        }
        assert_eq!(pacer.pending_len(), 3);

        // t=1000ms 锚定初始时钟，令牌为 0，不能突发发射。
        assert!(pacer.poll_send(1000).is_none());
        // t=1020ms 仅积累 5_000 B < 10_000 B，继续等待。
        assert!(pacer.poll_send(1020).is_none());
        // t=1040ms 累计 10_000 B，恰好放出第 1 片，剩余 0 B 不放出第 2 片。
        assert!(pacer.poll_send(1040).is_some());
        assert!(pacer.poll_send(1040).is_none());
        assert_eq!(pacer.pending_len(), 2);

        // 收到用户输入事件：毫秒级立即清空待发队列、递增 cancel_generation 并清零令牌。
        let prev_gen = pacer.cancel_generation();
        pacer.on_input_event();
        assert_eq!(pacer.pending_len(), 0);
        assert_eq!(pacer.cancel_generation(), prev_gen + 1);
        assert_eq!(pacer.available_tokens(), 0);

        // 弱网门控 1：丢包 >= 1% 自动暂停。
        pacer.update_network(10_000_000, 0.01);
        assert_eq!(
            pacer.pause_reason(),
            Some(StillRefinePauseReason::HighPacketLoss)
        );
        assert!(!pacer.enqueue(make_tile(4_000)));

        // 弱网门控 2：带宽 < 2 Mbps 自动暂停。
        pacer.update_network(1_999_999, 0.0);
        assert_eq!(
            pacer.pause_reason(),
            Some(StillRefinePauseReason::LowBandwidth)
        );
        assert!(!pacer.enqueue(make_tile(4_000)));

        // 模式门控 3：「极速低延迟」模式自动暂停。
        pacer.update_network(20_000_000, 0.0);
        pacer.set_codec_pref(CodecSelectionPref::UltraLowLatency);
        assert_eq!(
            pacer.pause_reason(),
            Some(StillRefinePauseReason::UltraLowLatencyMode)
        );
        assert!(!pacer.enqueue(make_tile(4_000)));

        // 恢复自动模式后重新放行。
        pacer.set_codec_pref(CodecSelectionPref::Auto);
        assert!(pacer.can_send());
        assert!(pacer.enqueue(make_tile(4_000)));
    }

    /// 单测 4：`StillRefineReceiver` 拦截过期 `stream_epoch` 与已被新动态帧覆盖的迟到补丁。
    #[test]
    fn still_refine_receiver_blocks_stale_epoch_and_superseded_dynamic_frames() {
        let mut receiver = StillRefineReceiver::new(2, 1920, 1080);
        let mut renderer = FakeRenderer::new(FakeRendererConfig::default()).expect("fake renderer");

        let pixels = make_text_edge_pixels(128, 128);
        let qoi = encode_qoi_bgra(&pixels, 128, 128).expect("qoi encode");
        let b64 = base64_encode(&qoi);

        // 1) 过期 stream_epoch=1 被严格拦截并计入 drop_stale_count。
        let stale_epoch_msg = DisplayControlMsg::StillTileRefine {
            stream_epoch: 1,
            base_frame_seq: 10,
            x: 0,
            y: 0,
            width: 128,
            height: 128,
            format: "bgra8".to_string(),
            codec: "qoi".to_string(),
            data_base64: b64.clone(),
        };
        assert_eq!(
            receiver.decode_and_apply_msg(&stale_epoch_msg, Some(&mut renderer)),
            Err(StillPatchRejectReason::EpochMismatch)
        );
        assert_eq!(renderer.still_tiles_applied().len(), 0);
        assert_eq!(receiver.metrics().drop_stale_count, 1);

        // 2) 动态帧 10 到达，随后合法补丁 (epoch=2, base_frame_seq=10) 顺利应用。
        receiver.on_dynamic_frame(10, &[Rect::new(0, 0, 128, 128)]);
        let valid_msg = DisplayControlMsg::StillTileRefine {
            stream_epoch: 2,
            base_frame_seq: 10,
            x: 0,
            y: 0,
            width: 128,
            height: 128,
            format: "bgra8".to_string(),
            codec: "qoi".to_string(),
            data_base64: b64.clone(),
        };
        let applied = receiver
            .decode_and_apply_msg(&valid_msg, Some(&mut renderer))
            .expect("valid tile should apply");
        assert_eq!(applied.pixels, pixels);
        assert_eq!(renderer.still_tiles_applied().len(), 1);
        assert_eq!(receiver.metrics().applied_count, 1);
        assert_eq!(receiver.metrics().avg_tile_bytes, qoi.len() as u64);

        // 3) 动态帧 11 仅更新 Tile (0,0)：迟到的 base_frame_seq=10 补丁针对 (0,0) 被拦截，
        //    而未相交的 Tile (256, 256) 在 base_frame_seq=10 仍可正常应用！
        receiver.on_dynamic_frame(11, &[Rect::new(10, 10, 20, 20)]);
        assert_eq!(
            receiver.decode_and_apply_msg(&valid_msg, Some(&mut renderer)),
            Err(StillPatchRejectReason::SupersededByDynamicFrame)
        );
        assert_eq!(receiver.metrics().drop_stale_count, 2);

        let untouched_tile_msg = DisplayControlMsg::StillTileRefine {
            stream_epoch: 2,
            base_frame_seq: 10,
            x: 256,
            y: 256,
            width: 128,
            height: 128,
            format: "bgra8".to_string(),
            codec: "qoi".to_string(),
            data_base64: b64,
        };
        receiver
            .decode_and_apply_msg(&untouched_tile_msg, Some(&mut renderer))
            .expect("untouched static tile should still apply");
        assert_eq!(receiver.metrics().applied_count, 2);
        assert_eq!(renderer.still_tiles_applied().len(), 2);
    }

    /// 端到端控制器测试：`HostStillRefineController` 双端能力协商、运行期开关、静止补帧与输入抢占。
    #[test]
    fn host_still_refine_controller_end_to_end_lifecycle() {
        let mut ctrl = HostStillRefineController::new(1, 256, 128, true);
        // 协商前对端未声明支持，不得发送。
        assert!(!ctrl.is_active());

        // 对端上报支持静帧细化且为自动模式 -> 激活。
        ctrl.on_client_media_caps(
            Some(&RefinementCapability {
                supported: true,
                true_rgb_capture: true,
                formats: vec!["qoi".to_string()],
            }),
            CodecSelectionPref::Auto,
        );
        ctrl.update_network(14_000_000, 0.0);
        assert!(ctrl.is_active());

        let frame = CpuFrame {
            width: 256,
            height: 128,
            format: PixelFormat::Bgra8,
            stride: 256 * 4,
            data: make_text_edge_pixels(256, 128),
        };
        ctrl.on_dynamic_frame(0, 5, &[]);
        let enqueued = ctrl.collect_and_enqueue_from_frame(250, Some((10, 10)), &frame);
        assert_eq!(enqueued, 2);

        // 先锚定时间再推进 100ms，按限速放出消息并被 Receiver 无损应用。
        assert!(ctrl.poll_next_display_ctrl_msg(250).is_none());
        let msg = ctrl
            .poll_next_display_ctrl_msg(350)
            .expect("should emit first paced StillTileRefine");
        let mut receiver = StillRefineReceiver::new(1, 256, 128);
        receiver.on_dynamic_frame(5, &[]);
        receiver
            .decode_and_apply_msg(&msg, None)
            .expect("receiver should accept host tile");
        assert_eq!(receiver.metrics().applied_count, 1);

        // 关闭运行期开关后立即清空剩余队列并停发。
        ctrl.on_still_refine_config(false);
        assert!(!ctrl.is_active());
        assert_eq!(ctrl.pacer().pending_len(), 0);
        assert!(ctrl.poll_next_display_ctrl_msg(500).is_none());
    }

    /// 对抗评审 High #3 回归 1：入队后仅发出部分 Tile 即被输入事件抢占，未发出的 Tile 绝不提前标为 refined，
    /// 恢复静止后必须能够自动补全全部剩余未发 Tile（不留永久模糊区域）。
    #[test]
    fn host_still_refine_preemption_retains_unsent_tiles_dirty_for_next_still_window() {
        let mut ctrl = HostStillRefineController::new(1, 512, 128, true);
        ctrl.on_client_media_caps(
            Some(&RefinementCapability {
                supported: true,
                true_rgb_capture: true,
                formats: vec!["qoi".to_string()],
            }),
            CodecSelectionPref::Auto,
        );
        ctrl.update_network(14_000_000, 0.0);

        let frame = CpuFrame {
            width: 512,
            height: 128,
            format: PixelFormat::Bgra8,
            stride: 512 * 4,
            data: make_text_edge_pixels(512, 128),
        };
        // 4 个 128×128 Tile 全部标脏。
        ctrl.on_dynamic_frame(0, 1, &[]);
        let enqueued = ctrl.collect_and_enqueue_from_frame(250, Some((10, 10)), &frame);
        assert_eq!(enqueued, 4);
        // 入队但尚未实际出队发送前，grid 中 4 个 Tile 必须仍保持 dirty（不提前标 refined）。
        assert_eq!(ctrl.grid().refined_tile_count(), 0);
        assert_eq!(ctrl.grid().dirty_tile_count(), 4);

        // 仅发出第 1 片后立刻发生用户输入抢占！
        assert!(ctrl.poll_next_display_ctrl_msg(250).is_none());
        let first_msg = ctrl
            .poll_next_display_ctrl_msg(350)
            .expect("should emit tile 0");
        assert!(matches!(
            first_msg,
            DisplayControlMsg::StillTileRefine { x: 0, y: 0, .. }
        ));
        assert_eq!(ctrl.grid().refined_tile_count(), 1);
        assert_eq!(ctrl.grid().dirty_tile_count(), 3);

        ctrl.on_input_event();
        assert_eq!(ctrl.pacer().pending_len(), 0);
        // 未发出的 3 片必须仍处于 dirty，而不是永久丢失。
        assert_eq!(ctrl.grid().refined_tile_count(), 1);
        assert_eq!(ctrl.grid().dirty_tile_count(), 3);

        // 再次静止收集时自动补齐剩余 3 片。
        let reenqueued = ctrl.collect_and_enqueue_from_frame(600, Some((10, 10)), &frame);
        assert_eq!(reenqueued, 3);
        let mut sent = 0usize;
        let mut t = 600u64;
        assert!(ctrl.poll_next_display_ctrl_msg(t).is_none());
        while ctrl.pacer().pending_len() > 0 {
            t += 100;
            while ctrl.poll_next_display_ctrl_msg(t).is_some() {
                sent += 1;
            }
        }
        assert_eq!(sent, 3);
        assert_eq!(ctrl.grid().refined_tile_count(), 4);
        assert_eq!(ctrl.grid().dirty_tile_count(), 0);
    }

    /// 对抗评审 High #3 回归 2：4K（3840×2160 = 510 Tile > MAX_PENDING_STILL_TILES=256）场景下，
    /// 队满时必须拒绝尾部低优先级 Tile 并早停编码，严格保留队首光标/屏幕中心最高优先级 Tile，
    /// 并在首轮发完后于下一轮补全剩余 Tile。
    #[test]
    fn host_still_refine_4k_queue_cap_preserves_cursor_priority_and_finishes_second_pass() {
        let mut ctrl = HostStillRefineController::new(1, 3840, 2160, true);
        ctrl.on_client_media_caps(
            Some(&RefinementCapability {
                supported: true,
                true_rgb_capture: true,
                formats: vec!["qoi".to_string()],
            }),
            CodecSelectionPref::Auto,
        );
        ctrl.update_network(100_000_000, 0.0);

        let frame = CpuFrame {
            width: 3840,
            height: 2160,
            format: PixelFormat::Bgra8,
            stride: 3840 * 4,
            // 纯色 4K 帧（每个 128×128 Tile 仅 ~290 字节，1:1 入队）用于确定性验证 510 > 256 队列语义。
            data: make_solid_pixels(3840, 2160, [0x20, 0x24, 0x28, 0xFF]),
        };
        assert_eq!(ctrl.grid().tile_count(), 30 * 17);
        ctrl.on_dynamic_frame(0, 1, &[]);

        // 光标位于 (1920, 1080) -> Tile (15, 8) 必须排在队首首位！
        let cursor = (1920 + 64, 1080 + 64);
        let first_batch = ctrl.collect_and_enqueue_from_frame(250, Some(cursor), &frame);
        assert_eq!(first_batch, MAX_PENDING_STILL_TILES);
        assert_eq!(ctrl.pacer().pending_len(), MAX_PENDING_STILL_TILES);

        // 验证队首真正出队的是光标所在的 Tile (15, 8) 而非被 pop_front 顶掉！
        assert!(ctrl.poll_next_display_ctrl_msg(250).is_none());
        let head = ctrl
            .poll_next_display_ctrl_msg(350)
            .expect("first tile must be cursor tile");
        assert!(
            matches!(
                head,
                DisplayControlMsg::StillTileRefine { x, y, .. }
                if x == 15 * 128 && y == 8 * 128
            ),
            "队首光标高优 Tile 不得被队满淘汰，实际出队: {head:?}"
        );

        // 排空首轮全部 256 片。
        let mut total_sent = 1usize;
        let mut t = 350u64;
        while ctrl.pacer().pending_len() > 0 {
            t += 100;
            while ctrl.poll_next_display_ctrl_msg(t).is_some() {
                total_sent += 1;
            }
        }
        assert_eq!(total_sent, MAX_PENDING_STILL_TILES);
        assert_eq!(ctrl.grid().refined_tile_count(), MAX_PENDING_STILL_TILES);

        // 第二轮自动补全剩余 510 - 256 = 254 片。
        let second_batch = ctrl.collect_and_enqueue_from_frame(t, Some(cursor), &frame);
        assert_eq!(second_batch, 510 - MAX_PENDING_STILL_TILES);
        while ctrl.pacer().pending_len() > 0 {
            t += 100;
            while ctrl.poll_next_display_ctrl_msg(t).is_some() {
                total_sent += 1;
            }
        }
        assert_eq!(total_sent, 510);
        assert_eq!(ctrl.grid().refined_tile_count(), 510);
        assert_eq!(ctrl.grid().dirty_tile_count(), 0);
    }

    /// 对抗评审 Low #6 & #7：验证 QOI 解码 `QOI_OP_RUN` 刷新 index 与官方 `qoi.h` 对齐，
    /// 以及 `decode_msg_without_commit` 对畸形头尺寸不匹配的零放大前置拒绝。
    #[test]
    fn qoi_run_updates_index_like_reference_and_receiver_rejects_header_mismatch_zero_alloc() {
        // 构造 3×1 图像：像素 0 = (0,0,0,255) 用 QOI_OP_RUN(1) 编码，
        // 像素 1 = (1,2,3,255) 用 QOI_OP_RGB 编码，
        // 像素 2 = QOI_OP_INDEX(53)（(0*3+0*5+0*7+255*11) % 64 = 2805 % 64 = 53）引用像素 0。
        let mut stream = Vec::new();
        stream.extend_from_slice(&QOI_MAGIC);
        stream.extend_from_slice(&3u32.to_be_bytes());
        stream.extend_from_slice(&1u32.to_be_bytes());
        stream.extend_from_slice(&[4, 0]);
        stream.push(0xC0); // QOI_OP_RUN len=1 -> (0,0,0,255), 同步写入 index[53]
        stream.extend_from_slice(&[0xFE, 1, 2, 3]); // QOI_OP_RGB -> (1,2,3,255)
        stream.push(53); // QOI_OP_INDEX(53) -> 必须命中 (0,0,0,255) 而非全零 (0,0,0,0)
        stream.extend_from_slice(&QOI_END_MARKER);

        let dec = decode_qoi_rgba(&stream).expect("decode reference RUN+INDEX stream");
        assert_eq!(dec.pixels, vec![0, 0, 0, 255, 1, 2, 3, 255, 0, 0, 0, 255]);

        // 构造 30B 畸形 QOI（头声明 1024×1024）但消息头声明 1×1：必须在解码分配前即拒绝。
        let mut forged = Vec::new();
        forged.extend_from_slice(&QOI_MAGIC);
        forged.extend_from_slice(&1024u32.to_be_bytes());
        forged.extend_from_slice(&1024u32.to_be_bytes());
        forged.extend_from_slice(&[4, 0]);
        forged.extend_from_slice(&[0xC0 | 61; 8]);
        forged.extend_from_slice(&QOI_END_MARKER);

        let mut receiver = StillRefineReceiver::new(1, 1920, 1080);
        let msg = DisplayControlMsg::StillTileRefine {
            stream_epoch: 1,
            base_frame_seq: 0,
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            format: "bgra8".to_string(),
            codec: "qoi".to_string(),
            data_base64: base64_encode(&forged),
        };
        assert_eq!(
            receiver.decode_msg_without_commit(&msg),
            Err(StillPatchRejectReason::DecodeFailed)
        );
        assert_eq!(receiver.metrics().drop_stale_count, 1);
    }
}
