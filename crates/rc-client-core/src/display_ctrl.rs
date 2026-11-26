//! 显示控制协议与分辨率预设生成（`TOOL_CHANNEL_DISPLAY_CTRL = 5`）。
//!
//! 承载控制端与被控端之间的实时流参数能力通告（[`DisplayControlMsg::Capabilities`]）
//! 与热切换请求（[`DisplayControlMsg::SetStream`]），并按被控端主显示器宽高比生成
//! 严格等比、偶数对齐、由高到低排列的分辨率预设列表（[`build_resolution_presets`]）。
//!
//! 全模块纯安全 Rust（`#![deny(unsafe_code)]`），不依赖 Tauri 或平台 FFI，便于确定性单测。

#![deny(unsafe_code)]

/// `TOOL_CHANNEL_DISPLAY_CTRL` 单条 JSON 载荷的最大允许字节数（对齐 `rc_session::MAX_TOOL_PAYLOAD_BYTES` = 256 KiB，
/// 保证经 `encode_display_ctrl` 编码后的载荷绝不会超过会话层单帧上限而卡死通道）。
pub const MAX_DISPLAY_CTRL_BYTES: usize = rc_session::MAX_TOOL_PAYLOAD_BYTES;
const _: () = assert!(MAX_DISPLAY_CTRL_BYTES <= rc_session::MAX_TOOL_PAYLOAD_BYTES);

/// 热切换流分辨率允许的最大宽度上限（5K / 超宽屏）。
pub const MAX_STREAM_WIDTH: u32 = 5120;

/// 热切换流分辨率允许的最大高度上限（2880）。
pub const MAX_STREAM_HEIGHT: u32 = 2880;

/// 降采样预设保留的最小宽度（像素）。
const MIN_PRESET_WIDTH: u32 = 640;

/// 降采样预设保留的最小高度（像素）。
const MIN_PRESET_HEIGHT: u32 = 360;

/// 去重与「接近原生」判定的像素容差（避免出现高度几乎一致的重复档位）。
const PRESET_PROXIMITY_PX: u32 = 24;

/// 触发高刷甜点评估与提示的最低目标帧率（fps；60fps 及以下不打扰）。
pub const HIGH_REFRESH_FPS_THRESHOLD: u32 = 90;

/// HEVC（H.265）在低延迟双槽在途（`max_in_flight = 2`）下的推荐高刷满帧像素率上限（px/s）。
///
/// 对齐 Apple Silicon M1 Pro 实测：`2560×1664@120`（511M px/s → 118.7fps）、
/// `3440×1440@120`（594M px/s → 119.1fps）均可稳态满帧；`3024×1964@120`（713M px/s → ~83fps）
/// 与 `3840×2160@120`（995M px/s → ~84fps）超出满帧甜点。
pub const HEVC_HIGH_REFRESH_MAX_PIXEL_RATE: u64 = 600_000_000;

/// H.264 在低延迟双槽在途（`max_in_flight = 2`）下的推荐高刷满帧像素率上限（px/s）。
///
/// 对齐 Apple Silicon M1 Pro 实测：`1512×982@120`（178M px/s → 117.9fps）、
/// `1920×1200@120`（276M px/s → 118.3fps）均可稳态满帧；`2560×1600@120`（492M px/s → ~91fps）、
/// `3024×1964@120`（713M px/s → ~60fps）超出 H.264 满帧甜点。
pub const H264_HIGH_REFRESH_MAX_PIXEL_RATE: u64 = 280_000_000;

/// 视频流编解码器选择（纯值枚举，保持 `SessionCommand: Copy` 语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamCodec {
    /// H.264 / AVC。
    H264,
    /// H.265 / HEVC。
    Hevc,
}

impl StreamCodec {
    /// 转为协议标准小写名称（`"h264"` / `"hevc"`）。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::Hevc => "hevc",
        }
    }

    /// 大小写不敏感解析协议编码器名称（兼容 `"h265"` 别名）。
    pub fn parse_lossy(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("hevc") || trimmed.eq_ignore_ascii_case("h265") {
            Some(Self::Hevc)
        } else if trimmed.eq_ignore_ascii_case("h264") || trimmed.eq_ignore_ascii_case("avc") {
            Some(Self::H264)
        } else {
            None
        }
    }

    /// 当前编码器在高刷（`>= 90fps`）下的推荐满帧像素率上限（px/s）。
    pub const fn high_refresh_max_pixel_rate(self) -> u64 {
        match self {
            Self::Hevc => HEVC_HIGH_REFRESH_MAX_PIXEL_RATE,
            Self::H264 => H264_HIGH_REFRESH_MAX_PIXEL_RATE,
        }
    }
}

/// 高刷（`>= 90fps`）流参数与编码器甜点评估级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighRefreshLevel {
    /// 当前分辨率、帧率与编码器组合位于满帧甜点内（或帧率 `< 90fps`）。
    Optimal,
    /// 当前为 H.264 且超出 H.264 高刷甜点，切至 HEVC 后可落入满帧甜点。
    SuggestHevc,
    /// 当前组合超出硬件高刷满帧甜点（即便启用 HEVC 或客户端不支持 HEVC 仍受限）。
    AboveSweetSpot,
}

/// 高刷甜点评估的机器可读原因码（供各端本地化展示文案）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighRefreshReason {
    /// 处于高刷满帧甜点内或非高刷模式。
    Optimal,
    /// 当前 H.264 超甜点且双端均支持 HEVC，开启 HEVC 可显著提升帧率。
    H264SuggestHevc,
    /// 当前 H.264 超甜点且至少一端不支持 HEVC，建议降低分辨率。
    H264NoHevc,
    /// 当前已是 HEVC，但分辨率像素率仍高于高刷满帧甜点，建议切回甜点分辨率。
    HevcOverBudget,
}

/// 针对当前（或待切换）分辨率、帧率与编解码器的高刷预期管理评估结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HighRefreshAdvisory {
    /// 评估级别（`optimal` / `suggest_hevc` / `above_sweet_spot`）。
    pub level: HighRefreshLevel,
    /// 机器可读原因码。
    pub reason: HighRefreshReason,
    /// 是否可立即向被控端请求切换至 HEVC（当前为 H.264 且双端均支持 HEVC）。
    pub can_enable_hevc: bool,
    /// 推荐的高刷满帧分辨率宽度（像素，`Optimal` 时为 `None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_width: Option<u32>,
    /// 推荐的高刷满帧分辨率高度（像素，`Optimal` 时为 `None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_height: Option<u32>,
}

impl Default for HighRefreshAdvisory {
    fn default() -> Self {
        Self {
            level: HighRefreshLevel::Optimal,
            reason: HighRefreshReason::Optimal,
            can_enable_hevc: false,
            recommended_width: None,
            recommended_height: None,
        }
    }
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// 一条可供前端分辨率菜单展示的等比分辨率预设。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DisplayPreset {
    /// 预设画面宽度（像素，偶数对齐）。
    pub width: u32,
    /// 预设画面高度（像素，偶数对齐）。
    pub height: u32,
    /// 菜单展示标签（如 `"1512×982 (HiDPI)"` 或 `"1280×800"`）。
    pub label: String,
    /// 是否为被控端显示器原生逻辑分辨率。
    pub is_native: bool,
    /// 是否为 macOS HiDPI / Retina 缩放模式。
    #[serde(default)]
    pub is_hidpi: bool,
}

/// 一台被控端显示器（物理屏或虚拟屏）的摘要描述。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DisplayDescriptor {
    /// 平台显示器唯一标识（macOS `CGDirectDisplayID`）。
    pub id: u32,
    /// 可读展示名称（如 `"显示屏1 (Built-in Retina Display)"` 或 `"虚拟显示屏 2"`）。
    pub name: String,
    /// 当前逻辑宽度（像素/点）。
    pub width: u32,
    /// 当前逻辑高度（像素/点）。
    pub height: u32,
    /// 是否为主显示器。
    #[serde(default)]
    pub is_main: bool,
    /// 是否为本会话创建的虚拟显示器。
    #[serde(default)]
    pub is_virtual: bool,
}

/// 经 `TOOL_CHANNEL_DISPLAY_CTRL`（可靠 Stream A）双向传递的显示控制消息。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DisplayControlMsg {
    /// 被控端 → 控制端：通告当前生效分辨率/帧率以及原生/最高显示能力。
    Capabilities {
        /// 当前生效流宽度（像素）。
        current_width: u32,
        /// 当前生效流高度（像素）。
        current_height: u32,
        /// 当前生效帧率（fps）。
        current_fps: u32,
        /// 被控端主显示器原生逻辑宽度（像素）。
        native_width: u32,
        /// 被控端主显示器原生逻辑高度（像素）。
        native_height: u32,
        /// 被控端允许的最高输出宽度（Retina 物理像素或能力上界，封顶 3840）。
        max_width: u32,
        /// 被控端允许的最高输出高度（Retina 物理像素或能力上界，封顶 2160）。
        max_height: u32,
        /// 被控端支持的最高帧率（fps）。
        max_fps: u32,
        /// 被控端权威计算或上报的可选分辨率预设列表（为空时由控制端按原生宽高比回退生成）。
        #[serde(default)]
        presets: Vec<DisplayPreset>,
        /// 当前生效视频编码器（`"hevc"` 或 `"h264"`；旧版被控端未上报时为 `None`）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_codec: Option<String>,
        /// 被控端支持的硬件视频编码器列表（如 `["hevc", "h264"]`；旧版未上报时为空）。
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        supported_codecs: Vec<String>,
    },
    /// 控制端 → 被控端：请求热切换视频流的分辨率与帧率（可选附带目标编解码器实现单次原子重建）。
    SetStream {
        /// 目标视频宽度（像素；`0` 表示保持当前分辨率）。
        width: u32,
        /// 目标视频高度（像素；`0` 表示保持当前分辨率）。
        height: u32,
        /// 目标帧率（fps；`0` 表示保持当前帧率）。
        fps: u32,
        /// 可选目标编解码器（`"hevc"` / `"h264"`；旧版控制端不发送时保持当前编解码器）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codec: Option<String>,
    },
    /// 控制端 → 被控端：请求切换或协商视频编解码器（如 `"hevc"` / `"h264"`）。
    SetCodec {
        /// 目标编解码器名称（`"hevc"` 或 `"h264"`）。
        codec: String,
    },
    /// 被控端 → 控制端：推送当前桌面壁纸缩略图（JPEG/PNG Base64）。
    Wallpaper {
        /// MIME 类型（如 `"image/jpeg"` 或 `"image/png"`）。
        mime: String,
        /// Base64 编码的图片字节数据。
        data_base64: String,
    },
    /// 控制端 → 被控端：请求立即锁定被控端屏幕。
    LockScreen,
    /// 控制端 → 被控端：设置防窥模式（`"off"` / `"privacy"` / `"black"`）及屏保主题/自定义图片。
    SetPrivacyMode {
        /// 防窥模式（`"off"` | `"privacy"` | `"black"`）。
        mode: String,
        /// 内置预设 ID（如 `"preset-1"` .. `"preset-6"` 或 `"custom"`）。
        #[serde(default)]
        preset: String,
        /// 自定义屏保图片的 Base64 载荷（JPEG/PNG，仅 `preset == "custom"` 时传递）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        custom_image_base64: Option<String>,
    },
    /// 被控端 → 控制端：回传当前生效的防窥模式状态。
    PrivacyState {
        /// 当前生效防窥模式（`"off"` | `"privacy"` | `"black"`）。
        mode: String,
        /// 当前生效预设 ID。
        #[serde(default)]
        preset: String,
        /// 当前被控端是否支持物理隐私幕布。
        #[serde(default)]
        supported: bool,
    },
    /// 控制端 → 被控端：控制被控端本机扬声器静音与退出时是否恢复。
    SetHostMute {
        /// `true` = 静音被控端本机扬声器；`false` = 取消静音。
        muted: bool,
        /// 远控结束时是否自动恢复被控端原始声音状态。
        #[serde(default)]
        restore_on_exit: bool,
    },
    /// 被控端 → 控制端：回传被控端本机静音状态。
    HostMuteState {
        /// 当前被控端是否处于静音态。
        muted: bool,
        /// 当前被控端是否支持系统静音控制。
        #[serde(default)]
        supported: bool,
    },
    /// 控制端 → 被控端：设置鼠标模式（`"smart"` / `"remote"` / `"local"`）。
    SetMouseMode {
        /// 目标鼠标模式。
        mode: String,
    },
    /// 被控端 → 控制端：回传当前生效鼠标模式。
    MouseModeState {
        /// 生效鼠标模式。
        mode: String,
    },
    /// 控制端 → 被控端：请求刷新全部可用显示器（物理屏 + 虚拟屏）列表。
    ListDisplays,
    /// 被控端 → 控制端：推送全部可用显示器列表及当前正在采集的显示器 ID。
    DisplaysState {
        /// 可用显示器列表。
        #[serde(default)]
        displays: Vec<DisplayDescriptor>,
        /// 当前正在采集的显示器 ID。
        active_display_id: u32,
    },
    /// 控制端 → 被控端：切换当前采集与输入映射的目标显示器。
    SwitchDisplay {
        /// 目标显示器 ID。
        display_id: u32,
    },
    /// 控制端 → 被控端：创建一个新的虚拟显示器并可选切换至该屏。
    CreateVirtualDisplay {
        /// 期望逻辑宽度（像素）。
        width: u32,
        /// 期望逻辑高度（像素）。
        height: u32,
        /// 是否启用 HiDPI 2x 模式。
        #[serde(default)]
        hidpi: bool,
    },
    /// 控制端 → 被控端：销毁一个由本会话创建的虚拟显示器。
    RemoveVirtualDisplay {
        /// 待销毁的虚拟显示器 ID。
        display_id: u32,
    },
    /// 被控端 → 控制端：虚拟显示器创建或切换失败提示。
    VirtualDisplayError {
        /// 人类可读错误原因。
        message: String,
    },
    /// 被控端 → 控制端：上报当前应用版本、架构、更新能力与是否为同账号自控会话。
    HostVersionInfo {
        /// 当前应用版本号（如 `"0.1.9"`）。
        version: String,
        /// 当前 CPU 架构（如 `"arm64"` / `"x86_64"`）。
        arch: String,
        /// 当前操作系统（如 `"macos"`）。
        os: String,
        /// 是否具备自更新能力。
        #[serde(default)]
        update_capable: bool,
        /// 当前会话是否经 `OwnerTicket` 验证为同账号本人自控（仅 `true` 允许远程更新）。
        #[serde(default)]
        is_owner_session: bool,
        /// 是否已安装系统级后台服务（安装时支持免密替换与重启）。
        #[serde(default)]
        service_installed: bool,
    },
    /// 控制端 → 被控端：经控制端用户确认后，触发被控端执行远程更新（仅同账号本人自控放行）。
    UpdateTrigger {
        /// 目标版本号（如 `"0.1.10"`）。
        target_version: String,
        /// 原始 `https://` 安装包下载地址。
        download_url: String,
        /// 预期 64 位小写 SHA-256 摘要。
        expected_sha256: String,
        /// 安全文件名（如 `"RabbitControl-0.1.10-arm64.dmg"`）。
        asset_name: String,
        /// 可选镜像加速前缀。
        #[serde(default)]
        mirror_url: String,
        /// 被控端直连下载失败时是否允许回退至控制端中转推送安装包。
        #[serde(default)]
        relay_fallback_allowed: bool,
        /// 控制端单调递增的更新请求编号（`0` 表示兼容旧端未携带），用于隔离跨重试/跨 RTT 的陈旧状态回声。
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        request_id: u64,
    },
    /// 控制端 → 被控端：取消正在进行的远程更新下载或中转。
    UpdateCancel,
    /// 被控端 → 控制端：上报远程更新的实时阶段、进度或错误（以及是否请求控制端中转推送）。
    UpdateStatus {
        /// 当前更新阶段。
        stage: crate::updater::UpdateStage,
        /// 进度百分比（`0..=100`）。
        #[serde(default)]
        progress_pct: u8,
        /// 已下载/已接收字节数。
        #[serde(default)]
        downloaded_bytes: u64,
        /// 总字节数。
        #[serde(default)]
        total_bytes: u64,
        /// 目标版本号。
        #[serde(default)]
        target_version: String,
        /// 可读状态说明。
        #[serde(default)]
        message: String,
        /// 为 `true` 时表示被控端直连下载失败，请求控制端代为下载并推送 DMG 分块。
        #[serde(default)]
        need_controller_relay: bool,
        /// 失败时的错误原因。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// 回显对应 `UpdateTrigger.request_id`（`0` 表示旧端或无特定请求上下文）。
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        request_id: u64,
    },
    /// 控制端 → 被控端：开始中转推送校验后的安装包分块。
    UpdateChunkBegin {
        /// 目标版本号。
        target_version: String,
        /// 安全文件名。
        asset_name: String,
        /// 总字节大小（必须 `1..=MAX_UPDATE_PACKAGE_BYTES`）。
        total_bytes: u64,
        /// 预期 64 位小写 SHA-256 摘要。
        expected_sha256: String,
    },
    /// 控制端 → 被控端：中转推送单个安装包数据块（Base64，单块原始 ≤ 64 KiB）。
    UpdateChunkData {
        /// 当前分块在安装包中的字节偏移量（严格单调顺序写入）。
        offset: u64,
        /// Base64 编码的原始分块字节。
        data_base64: String,
    },
    /// 被控端 → 控制端：确认已落盘至 `next_offset`，驱动滑动窗口流控。
    UpdateChunkAck {
        /// 下一个期望接收的字节偏移量。
        next_offset: u64,
    },
    /// 控制端 → 被控端：安装包全部分块推送完成，请求校验 SHA-256 与签名并安装。
    UpdateChunkEnd,
    /// 控制端 → 被控端：中止中转推送并清理临时文件。
    UpdateChunkAbort {
        /// 中止原因说明。
        #[serde(default)]
        reason: String,
    },
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 将原始字节切片编码为标准 RFC 4648 Base64 字符串（含 `=` 填充）。
pub fn base64_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let out_len = input.len().div_ceil(3) * 4;
    let mut out = String::with_capacity(out_len);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(BASE64_ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// 将标准 RFC 4648 Base64 字符串解码为原始字节；长度、字符或填充非法时返回 `None`。
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return None;
    }
    let num_groups = bytes.len() / 4;
    let mut out = Vec::with_capacity(num_groups * 3);
    for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
        let is_last = idx + 1 == num_groups;
        let a = base64_decode_val(chunk[0])?;
        let b = base64_decode_val(chunk[1])?;
        match (chunk[2], chunk[3]) {
            (b'=', b'=') => {
                if !is_last || (b & 0x0F) != 0 {
                    return None;
                }
                out.push((a << 2) | (b >> 4));
            }
            (c_ch, b'=') => {
                if !is_last {
                    return None;
                }
                let c = base64_decode_val(c_ch)?;
                if (c & 0x03) != 0 {
                    return None;
                }
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
            }
            (c_ch, d_ch) => {
                let c = base64_decode_val(c_ch)?;
                let d = base64_decode_val(d_ch)?;
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
            }
        }
    }
    Some(out)
}

/// 将正浮点数按最接近的偶数对齐（不低于 2）。
fn round_to_even(v: f64) -> u32 {
    if !v.is_finite() || v < 2.0 {
        return 2;
    }
    (((v / 2.0).round() as u32).saturating_mul(2)).max(2)
}

/// 在最大包络 `(bound_w, bound_h)` 内按 `(aspect_w, aspect_h)` 等比缩放并偶数对齐。
pub fn fit_within_cap(bound_w: u32, bound_h: u32, aspect_w: u32, aspect_h: u32) -> (u32, u32) {
    let max_even_w = bound_w & !1;
    let max_even_h = bound_h & !1;
    if max_even_w < 2 || max_even_h < 2 || aspect_w == 0 || aspect_h == 0 {
        return (max_even_w.max(2), max_even_h.max(2));
    }
    if u64::from(max_even_w) * u64::from(aspect_h) <= u64::from(max_even_h) * u64::from(aspect_w) {
        let w = max_even_w;
        let h = round_to_even(f64::from(w) * f64::from(aspect_h) / f64::from(aspect_w))
            .clamp(2, max_even_h);
        (w, h)
    } else {
        let h = max_even_h;
        let w = round_to_even(f64::from(h) * f64::from(aspect_w) / f64::from(aspect_h))
            .clamp(2, max_even_w);
        (w, h)
    }
}

/// 将控制端请求的目标 `(target_w, target_h)` 限制在 `(max_w, max_h)`（并封顶 `3840×2160`）内，
/// 同时按 `(aspect_w, aspect_h)` 保持原生宽高比并偶数对齐。
pub fn fit_target_preserving_aspect(
    target_w: u32,
    target_h: u32,
    aspect_w: u32,
    aspect_h: u32,
    max_w: u32,
    max_h: u32,
) -> (u32, u32) {
    let cap_w = max_w.clamp(2, MAX_STREAM_WIDTH) & !1;
    let cap_h = max_h.clamp(2, MAX_STREAM_HEIGHT) & !1;
    let clamped_w = target_w.clamp(2, cap_w);
    let clamped_h = target_h.clamp(2, cap_h);
    fit_within_cap(clamped_w, clamped_h, aspect_w, aspect_h)
}

/// 根据显示器原生逻辑分辨率 `(native_w, native_h)` 与最大能力 `(max_w, max_h)` 生成
/// 去重、严格保持原生宽高比、偶数对齐且按由高到低排序的分辨率预设列表。
///
/// 规则：
/// 1. 若 `max_w > native_w`（如 Retina 2x 屏），加入封顶 `3840×2160` 且等比适配的高分上限，
///    并在中间存在明显档位时补充 `1440p` 等比过渡档；
/// 2. 始终包含原生逻辑分辨率，标记 `is_native: true`，文案为 `format!("原生 {nw}×{nh}")`；
/// 3. 按目标高度 `[1440, 1080, 900, 720, 540]` 生成等比降采样档位（跳过距原生或已有档位
///    24px 以内的条目，且仅保留 `width >= 640 && height >= 360`）。
pub fn build_resolution_presets(
    native_w: u32,
    native_h: u32,
    max_w: u32,
    max_h: u32,
) -> Vec<DisplayPreset> {
    let nw = native_w & !1;
    let nh = native_h & !1;
    if nw < 2 || nh < 2 {
        return Vec::new();
    }

    let eff_max_w = max_w.max(nw).min(MAX_STREAM_WIDTH);
    let eff_max_h = max_h.max(nh).min(MAX_STREAM_HEIGHT);
    let (hi_w, hi_h) = fit_within_cap(eff_max_w, eff_max_h, nw, nh);

    let mut presets: Vec<DisplayPreset> = Vec::new();
    let is_too_close_to = |w: u32, h: u32, list: &[DisplayPreset]| -> bool {
        list.iter().any(|p| {
            (p.width == w && p.height == h)
                || p.height.abs_diff(h) <= PRESET_PROXIMITY_PX
                || (p.width.abs_diff(w) <= PRESET_PROXIMITY_PX
                    && p.height.abs_diff(h) <= PRESET_PROXIMITY_PX)
        })
    };

    // 1) Retina / 高分档位（高于原生且差距 > 24px）
    if max_w > native_w && hi_w > nw + PRESET_PROXIMITY_PX && hi_h > nh + PRESET_PROXIMITY_PX {
        presets.push(DisplayPreset {
            width: hi_w,
            height: hi_h,
            label: format!("{hi_w}×{hi_h}"),
            is_native: false,
            is_hidpi: false,
        });

        // 中间过渡档（1440p 高度）：落在原生与高分上限之间且距两端均 > 24px
        let mid_h = 1440u32;
        if mid_h > nh + PRESET_PROXIMITY_PX && mid_h + PRESET_PROXIMITY_PX < hi_h {
            let mid_w = round_to_even(f64::from(mid_h) * f64::from(nw) / f64::from(nh));
            if mid_w >= MIN_PRESET_WIDTH
                && mid_w <= hi_w
                && !is_too_close_to(mid_w, mid_h, &presets)
            {
                presets.push(DisplayPreset {
                    width: mid_w,
                    height: mid_h,
                    label: format!("{mid_w}×{mid_h}"),
                    is_native: false,
                    is_hidpi: false,
                });
            }
        }
    }

    // 2) 原生逻辑分辨率（必选）
    presets.push(DisplayPreset {
        width: nw,
        height: nh,
        label: format!("原生 {nw}×{nh}"),
        is_native: true,
        is_hidpi: false,
    });

    // 3) 降采样等比档位：[1440, 1080, 900, 720, 540]
    for target_h in [1440u32, 1080, 900, 720, 540] {
        if target_h >= nh || nh.abs_diff(target_h) <= PRESET_PROXIMITY_PX {
            continue;
        }
        let h = target_h & !1;
        let w = round_to_even(f64::from(h) * f64::from(nw) / f64::from(nh));
        if w < MIN_PRESET_WIDTH || h < MIN_PRESET_HEIGHT || w > nw {
            continue;
        }
        if is_too_close_to(w, h, &presets) {
            continue;
        }
        presets.push(DisplayPreset {
            width: w,
            height: h,
            label: format!("{w}×{h}"),
            is_native: false,
            is_hidpi: false,
        });
    }

    // 按分辨率由高到低排序，并按 (width, height) 去重保底
    presets.sort_by_key(|a| std::cmp::Reverse((a.height, a.width)));
    presets.dedup_by(|a, b| a.width == b.width && a.height == b.height);
    presets
}

/// 判断给定 `(width, height, fps)` 是否落入指定编码器的高刷满帧甜点（非高刷 `< 90fps` 恒为 `true`）。
pub fn is_within_high_refresh_sweet_spot(
    width: u32,
    height: u32,
    fps: u32,
    codec: StreamCodec,
) -> bool {
    if fps < HIGH_REFRESH_FPS_THRESHOLD || width == 0 || height == 0 {
        return true;
    }
    let pixel_rate = u64::from(width)
        .saturating_mul(u64::from(height))
        .saturating_mul(u64::from(fps));
    pixel_rate <= codec.high_refresh_max_pixel_rate()
}

/// 从预设列表中挑选给定帧率与编码器下的推荐高刷满帧分辨率（甜点内像素最高者，平局偏好原生/HiDPI；无甜点匹配时回退最低像素预设）。
pub fn select_recommended_preset(
    presets: &[DisplayPreset],
    fps: u32,
    codec: StreamCodec,
) -> Option<(u32, u32)> {
    let best_in_budget = presets
        .iter()
        .filter(|p| is_within_high_refresh_sweet_spot(p.width, p.height, fps, codec))
        .max_by_key(|p| {
            let pixels = u64::from(p.width).saturating_mul(u64::from(p.height));
            (pixels, p.is_native, p.is_hidpi)
        });
    best_in_budget
        .or_else(|| {
            presets.iter().min_by_key(|p| {
                let pixels = u64::from(p.width).saturating_mul(u64::from(p.height));
                (pixels, !p.is_native, !p.is_hidpi)
            })
        })
        .map(|p| (p.width, p.height))
}

/// 评估当前（或目标）分辨率、帧率与编解码器组合的高刷预期与 HEVC 升级建议。
pub fn evaluate_high_refresh_advisory(
    width: u32,
    height: u32,
    fps: u32,
    current_codec: StreamCodec,
    host_supports_hevc: bool,
    client_supports_hevc: bool,
    presets: &[DisplayPreset],
) -> HighRefreshAdvisory {
    if fps < HIGH_REFRESH_FPS_THRESHOLD || width == 0 || height == 0 {
        return HighRefreshAdvisory::default();
    }
    let pixel_rate = u64::from(width)
        .saturating_mul(u64::from(height))
        .saturating_mul(u64::from(fps));

    match current_codec {
        StreamCodec::Hevc => {
            if pixel_rate <= HEVC_HIGH_REFRESH_MAX_PIXEL_RATE {
                HighRefreshAdvisory::default()
            } else {
                let rec = select_recommended_preset(presets, fps, StreamCodec::Hevc);
                HighRefreshAdvisory {
                    level: HighRefreshLevel::AboveSweetSpot,
                    reason: HighRefreshReason::HevcOverBudget,
                    can_enable_hevc: false,
                    recommended_width: rec.map(|(w, _)| w),
                    recommended_height: rec.map(|(_, h)| h),
                }
            }
        }
        StreamCodec::H264 => {
            if pixel_rate <= H264_HIGH_REFRESH_MAX_PIXEL_RATE {
                HighRefreshAdvisory::default()
            } else if host_supports_hevc && client_supports_hevc {
                let level = if pixel_rate <= HEVC_HIGH_REFRESH_MAX_PIXEL_RATE {
                    HighRefreshLevel::SuggestHevc
                } else {
                    HighRefreshLevel::AboveSweetSpot
                };
                let rec = select_recommended_preset(presets, fps, StreamCodec::Hevc);
                HighRefreshAdvisory {
                    level,
                    reason: HighRefreshReason::H264SuggestHevc,
                    can_enable_hevc: true,
                    recommended_width: rec.map(|(w, _)| w),
                    recommended_height: rec.map(|(_, h)| h),
                }
            } else {
                let rec = select_recommended_preset(presets, fps, StreamCodec::H264);
                HighRefreshAdvisory {
                    level: HighRefreshLevel::AboveSweetSpot,
                    reason: HighRefreshReason::H264NoHevc,
                    can_enable_hevc: false,
                    recommended_width: rec.map(|(w, _)| w),
                    recommended_height: rec.map(|(_, h)| h),
                }
            }
        }
    }
}

/// 将分辨率预设拆分为「一级主菜单（最多 `primary_limit` 项）」与「其他分辨率二级菜单」。
///
/// 避免按像素纯降序导致 14" MBP 的原生 HiDPI（`1512×982`）与高刷甜点档被挤进二级菜单：
/// - 若总数 `<= primary_limit + 1`，全部放一级菜单（不建只有 1 项的「其他分辨率」）；
/// - 否则一级菜单优先收录：① 原生逻辑分辨率；② 当前生效分辨率；③ 高刷满帧甜点内最高清晰度档；
///   ④ 最高超清物理档；⑤ 其余按 HiDPI 优先 + 分辨率降序补足至 `primary_limit`。
pub fn partition_presets_for_menu(
    presets: &[DisplayPreset],
    current_width: u32,
    current_height: u32,
    fps: u32,
    codec: StreamCodec,
    primary_limit: usize,
) -> (Vec<DisplayPreset>, Vec<DisplayPreset>) {
    let limit = primary_limit.max(1);
    if presets.len() <= limit.saturating_add(1) {
        let mut primary = presets.to_vec();
        primary.sort_by_key(|p| (!p.is_native, std::cmp::Reverse((p.height, p.width))));
        return (primary, Vec::new());
    }

    let mut chosen = vec![false; presets.len()];
    let mut primary = Vec::with_capacity(limit);

    let mut pick = |idx: usize| {
        if primary.len() < limit && idx < presets.len() && !chosen[idx] {
            chosen[idx] = true;
            primary.push(presets[idx].clone());
        }
    };

    // 1) 原生逻辑分辨率必在一级菜单
    if let Some(idx) = presets.iter().position(|p| p.is_native) {
        pick(idx);
    }

    // 2) 当前正在使用的分辨率（若已选中且不在原生上）
    if current_width > 0 && current_height > 0 {
        if let Some(idx) = presets.iter().position(|p| {
            p.width.abs_diff(current_width) <= 2 && p.height.abs_diff(current_height) <= 2
        }) {
            pick(idx);
        }
    }

    // 3) 高刷甜点内像素最高的清晰度档位（如 2560×1600 / 1920×1200）
    if let Some((rec_w, rec_h)) = select_recommended_preset(presets, fps, codec) {
        if let Some(idx) = presets
            .iter()
            .position(|p| p.width == rec_w && p.height == rec_h)
        {
            pick(idx);
        }
    }

    // 4) 最高物理分辨率档（如 3024×1964 / 3840×2160）保持直达入口
    if let Some((idx, _)) = presets
        .iter()
        .enumerate()
        .max_by_key(|(_, p)| (p.width, p.height))
    {
        pick(idx);
    }

    // 5) 先补常用 HiDPI 档，再按像素降序补齐至 limit
    for (idx, p) in presets.iter().enumerate() {
        if p.is_hidpi {
            pick(idx);
        }
    }
    for idx in 0..presets.len() {
        pick(idx);
    }

    // 一级菜单内按「原生置顶 → 其余按分辨率降序」排布，清晰稳定
    primary.sort_by_key(|p| (!p.is_native, std::cmp::Reverse((p.height, p.width))));

    let rest = presets
        .iter()
        .enumerate()
        .filter(|(idx, _)| !chosen[*idx])
        .map(|(_, p)| p.clone())
        .collect();
    (primary, rest)
}

/// 将 [`DisplayControlMsg`] 序列化为 JSON 字节；超限（`> MAX_DISPLAY_CTRL_BYTES`）或序列化失败返回 `None`。
pub fn encode_display_ctrl(msg: &DisplayControlMsg) -> Option<Vec<u8>> {
    let bytes = serde_json::to_vec(msg).ok()?;
    (bytes.len() <= MAX_DISPLAY_CTRL_BYTES).then_some(bytes)
}

/// 从 JSON 字节反序列化 [`DisplayControlMsg`]；空载荷、超限（`> MAX_DISPLAY_CTRL_BYTES`）或格式错误返回 `None`。
pub fn decode_display_ctrl(bytes: &[u8]) -> Option<DisplayControlMsg> {
    if bytes.is_empty() || bytes.len() > MAX_DISPLAY_CTRL_BYTES {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_presets_valid(presets: &[DisplayPreset], native_w: u32, native_h: u32) {
        assert!(!presets.is_empty(), "预设列表不能为空");
        let native_count = presets.iter().filter(|p| p.is_native).count();
        assert_eq!(native_count, 1, "必须且仅有一条原生预设: {presets:?}");

        let native_aspect = f64::from(native_w) / f64::from(native_h);
        for (i, p) in presets.iter().enumerate() {
            assert_eq!(p.width % 2, 0, "宽必须偶数对齐: {p:?}");
            assert_eq!(p.height % 2, 0, "高必须偶数对齐: {p:?}");
            assert!(p.width <= MAX_STREAM_WIDTH && p.height <= MAX_STREAM_HEIGHT);
            let aspect = f64::from(p.width) / f64::from(p.height);
            let rel_err = (aspect - native_aspect).abs() / native_aspect;
            assert!(
                rel_err < 0.005,
                "预设 {p:?} 宽高比({aspect:.4}) 偏离原生 {native_w}×{native_h}({native_aspect:.4})"
            );
            if p.is_native {
                assert_eq!(p.width, native_w & !1);
                assert_eq!(p.height, native_h & !1);
                assert_eq!(p.label, format!("原生 {}×{}", native_w & !1, native_h & !1));
            } else {
                assert!(p.width >= MIN_PRESET_WIDTH && p.height >= MIN_PRESET_HEIGHT);
            }
            if i > 0 {
                let prev = &presets[i - 1];
                assert!(
                    (prev.height, prev.width) > (p.height, p.width),
                    "预设必须严格由高到低去重排序: prev={prev:?}, cur={p:?}"
                );
            }
        }
    }

    #[test]
    fn presets_for_14inch_mbp_retina() {
        let presets = build_resolution_presets(1512, 982, 3024, 1964);
        assert_presets_valid(&presets, 1512, 982);

        let dims: Vec<(u32, u32, bool)> = presets
            .iter()
            .map(|p| (p.width, p.height, p.is_native))
            .collect();
        assert_eq!(
            dims,
            vec![
                (3024, 1964, false),
                (2218, 1440, false),
                (1512, 982, true),
                (1386, 900, false),
                (1108, 720, false),
                (832, 540, false),
            ]
        );
    }

    #[test]
    fn presets_for_16_9_1080p() {
        let presets = build_resolution_presets(1920, 1080, 1920, 1080);
        assert_presets_valid(&presets, 1920, 1080);

        let dims: Vec<(u32, u32, bool)> = presets
            .iter()
            .map(|p| (p.width, p.height, p.is_native))
            .collect();
        assert_eq!(
            dims,
            vec![
                (1920, 1080, true),
                (1600, 900, false),
                (1280, 720, false),
                (960, 540, false),
            ]
        );
    }

    #[test]
    fn presets_for_5k_imac_capped_at_4k() {
        // 3840x2160 上界封顶 4K；5120x2880 及更高上界放开至 5K 物理上界
        let presets_4k = build_resolution_presets(2560, 1440, 3840, 2160);
        assert_presets_valid(&presets_4k, 2560, 1440);
        let dims_4k: Vec<(u32, u32, bool)> = presets_4k
            .iter()
            .map(|p| (p.width, p.height, p.is_native))
            .collect();
        assert_eq!(
            dims_4k,
            vec![
                (3840, 2160, false),
                (2560, 1440, true),
                (1920, 1080, false),
                (1600, 900, false),
                (1280, 720, false),
                (960, 540, false),
            ]
        );

        let presets_5k = build_resolution_presets(2560, 1440, 7680, 4320);
        assert_presets_valid(&presets_5k, 2560, 1440);
        let dims_5k: Vec<(u32, u32, bool)> = presets_5k
            .iter()
            .map(|p| (p.width, p.height, p.is_native))
            .collect();
        assert_eq!(
            dims_5k,
            vec![
                (5120, 2880, false),
                (2560, 1440, true),
                (1920, 1080, false),
                (1600, 900, false),
                (1280, 720, false),
                (960, 540, false),
            ]
        );
    }

    #[test]
    fn encode_decode_roundtrip_and_size_limit() {
        assert_eq!(MAX_DISPLAY_CTRL_BYTES, rc_session::MAX_TOOL_PAYLOAD_BYTES);

        let caps = DisplayControlMsg::Capabilities {
            current_width: 1512,
            current_height: 982,
            current_fps: 120,
            native_width: 1512,
            native_height: 982,
            max_width: 3024,
            max_height: 1964,
            max_fps: 144,
            presets: build_resolution_presets(1512, 982, 3024, 1964),
            current_codec: Some("hevc".to_string()),
            supported_codecs: vec!["hevc".to_string(), "h264".to_string()],
        };
        let encoded_caps = encode_display_ctrl(&caps).expect("encode capabilities");
        assert_eq!(decode_display_ctrl(&encoded_caps), Some(caps));

        // 兼容旧版缺少 `presets` / `current_codec` / `supported_codecs` 字段的 JSON
        let legacy_json = serde_json::json!({
            "kind": "capabilities",
            "current_width": 1920,
            "current_height": 1080,
            "current_fps": 60,
            "native_width": 1920,
            "native_height": 1080,
            "max_width": 1920,
            "max_height": 1080,
            "max_fps": 144,
        });
        let decoded_legacy =
            decode_display_ctrl(&serde_json::to_vec(&legacy_json).unwrap()).expect("legacy caps");
        assert_eq!(
            decoded_legacy,
            DisplayControlMsg::Capabilities {
                current_width: 1920,
                current_height: 1080,
                current_fps: 60,
                native_width: 1920,
                native_height: 1080,
                max_width: 1920,
                max_height: 1080,
                max_fps: 144,
                presets: Vec::new(),
                current_codec: None,
                supported_codecs: Vec::new(),
            }
        );

        let set_stream = DisplayControlMsg::SetStream {
            width: 2218,
            height: 1440,
            fps: 144,
            codec: None,
        };
        let encoded_set = encode_display_ctrl(&set_stream).expect("encode set_stream");
        assert_eq!(decode_display_ctrl(&encoded_set), Some(set_stream));

        let set_stream_hevc = DisplayControlMsg::SetStream {
            width: 2560,
            height: 1600,
            fps: 120,
            codec: Some("hevc".to_string()),
        };
        let encoded_set_hevc =
            encode_display_ctrl(&set_stream_hevc).expect("encode set_stream_hevc");
        assert_eq!(
            decode_display_ctrl(&encoded_set_hevc),
            Some(set_stream_hevc)
        );

        let wallpaper = DisplayControlMsg::Wallpaper {
            mime: "image/jpeg".to_string(),
            data_base64: base64_encode(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]),
        };
        let encoded_wp = encode_display_ctrl(&wallpaper).expect("encode wallpaper");
        assert_eq!(decode_display_ctrl(&encoded_wp), Some(wallpaper));

        let encoded_lock =
            encode_display_ctrl(&DisplayControlMsg::LockScreen).expect("encode lock");
        assert_eq!(
            decode_display_ctrl(&encoded_lock),
            Some(DisplayControlMsg::LockScreen)
        );

        // 空载荷、非法 JSON、超过 96 KiB 均拒绝
        assert_eq!(decode_display_ctrl(&[]), None);
        assert_eq!(decode_display_ctrl(b"{not-json"), None);
        let oversized = vec![b' '; MAX_DISPLAY_CTRL_BYTES + 1];
        assert_eq!(decode_display_ctrl(&oversized), None);
    }

    #[test]
    fn base64_rfc4648_vectors_roundtrip_and_rejects_invalid() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, expected) in vectors {
            let enc = base64_encode(raw);
            assert_eq!(enc, *expected);
            assert_eq!(base64_decode(&enc).as_deref(), Some(*raw));
        }

        // 全字节值 0..=255 往返校验
        let all_bytes: Vec<u8> = (0..=255).collect();
        let enc_all = base64_encode(&all_bytes);
        assert_eq!(base64_decode(&enc_all), Some(all_bytes));

        // 非法长度、非法字符、错误填充位置、非规范末位比特均应拒绝
        for bad in [
            "A", "AB", "ABC", "ABCDE", "Zm9$", "Zm 9v", "====", "A=AA", "AA=A", "Zm9v====",
            "Zm8=Zm8=",
            // 非零未使用位：'Z','h' -> 0x66 + low bits 0x1 != 0 for "Zh=="
            "Zh==", "Zm9=",
        ] {
            assert_eq!(base64_decode(bad), None, "expected None for {bad:?}");
        }
    }

    #[test]
    fn fit_target_preserving_aspect_clamps_and_aligns() {
        assert_eq!(
            fit_target_preserving_aspect(1920, 1080, 1512, 982, 3024, 1964),
            (1662, 1080)
        );
        assert_eq!(
            fit_target_preserving_aspect(7680, 4320, 2560, 1440, 7680, 4320),
            (5120, 2880)
        );
        assert_eq!(
            fit_target_preserving_aspect(1280, 720, 1920, 1080, 3840, 2160),
            (1280, 720)
        );
    }

    #[test]
    fn high_refresh_advisory_matches_m1_pro_sweet_spots() {
        let mbp_modes = vec![
            DisplayPreset {
                width: 3024,
                height: 1964,
                label: "3024 × 1964".to_string(),
                is_native: false,
                is_hidpi: false,
            },
            DisplayPreset {
                width: 2560,
                height: 1600,
                label: "2560 × 1600".to_string(),
                is_native: false,
                is_hidpi: false,
            },
            DisplayPreset {
                width: 1920,
                height: 1200,
                label: "1920 × 1200".to_string(),
                is_native: false,
                is_hidpi: false,
            },
            DisplayPreset {
                width: 1512,
                height: 982,
                label: "1512 × 982 (HiDPI)".to_string(),
                is_native: true,
                is_hidpi: true,
            },
        ];

        // 60fps 下 3024×1964 H.264 不打扰
        let at_60 = evaluate_high_refresh_advisory(
            3024,
            1964,
            60,
            StreamCodec::H264,
            true,
            true,
            &mbp_modes,
        );
        assert_eq!(at_60.level, HighRefreshLevel::Optimal);
        assert!(!at_60.can_enable_hevc);

        // 120fps 下 1512×982 与 1920×1200 即使 H.264 也在甜点内
        for (w, h) in [(1512, 982), (1920, 1200)] {
            let adv = evaluate_high_refresh_advisory(
                w,
                h,
                120,
                StreamCodec::H264,
                true,
                true,
                &mbp_modes,
            );
            assert_eq!(adv.level, HighRefreshLevel::Optimal, "{w}x{h}@120 H.264");
        }

        // 2560×1600@120：H.264 建议切 HEVC（切完即可满帧），HEVC 直接 Optimal
        let mid_h264 = evaluate_high_refresh_advisory(
            2560,
            1600,
            120,
            StreamCodec::H264,
            true,
            true,
            &mbp_modes,
        );
        assert_eq!(mid_h264.level, HighRefreshLevel::SuggestHevc);
        assert_eq!(mid_h264.reason, HighRefreshReason::H264SuggestHevc);
        assert!(mid_h264.can_enable_hevc);
        assert_eq!(
            (mid_h264.recommended_width, mid_h264.recommended_height),
            (Some(2560), Some(1600))
        );

        let mid_hevc = evaluate_high_refresh_advisory(
            2560,
            1600,
            120,
            StreamCodec::Hevc,
            true,
            true,
            &mbp_modes,
        );
        assert_eq!(mid_hevc.level, HighRefreshLevel::Optimal);

        // 3024×1964@120：H.264 且双端支持 HEVC → AboveSweetSpot + can_enable_hevc=true + 推荐 2560×1600
        let retina_h264_can_hevc = evaluate_high_refresh_advisory(
            3024,
            1964,
            120,
            StreamCodec::H264,
            true,
            true,
            &mbp_modes,
        );
        assert_eq!(retina_h264_can_hevc.level, HighRefreshLevel::AboveSweetSpot);
        assert_eq!(
            retina_h264_can_hevc.reason,
            HighRefreshReason::H264SuggestHevc
        );
        assert!(retina_h264_can_hevc.can_enable_hevc);
        assert_eq!(
            (
                retina_h264_can_hevc.recommended_width,
                retina_h264_can_hevc.recommended_height
            ),
            (Some(2560), Some(1600))
        );

        // 3024×1964@120：H.264 且客户端不支持 HEVC → H264NoHevc + 推荐 1920×1200
        let retina_h264_no_hevc = evaluate_high_refresh_advisory(
            3024,
            1964,
            120,
            StreamCodec::H264,
            true,
            false,
            &mbp_modes,
        );
        assert_eq!(retina_h264_no_hevc.level, HighRefreshLevel::AboveSweetSpot);
        assert_eq!(retina_h264_no_hevc.reason, HighRefreshReason::H264NoHevc);
        assert!(!retina_h264_no_hevc.can_enable_hevc);
        assert_eq!(
            (
                retina_h264_no_hevc.recommended_width,
                retina_h264_no_hevc.recommended_height
            ),
            (Some(1920), Some(1200))
        );

        // 3024×1964@120：已是 HEVC → HevcOverBudget + 推荐 2560×1600
        let retina_hevc = evaluate_high_refresh_advisory(
            3024,
            1964,
            120,
            StreamCodec::Hevc,
            true,
            true,
            &mbp_modes,
        );
        assert_eq!(retina_hevc.level, HighRefreshLevel::AboveSweetSpot);
        assert_eq!(retina_hevc.reason, HighRefreshReason::HevcOverBudget);
        assert!(!retina_hevc.can_enable_hevc);
        assert_eq!(
            (
                retina_hevc.recommended_width,
                retina_hevc.recommended_height
            ),
            (Some(2560), Some(1600))
        );
    }

    #[test]
    fn partition_presets_for_menu_surfaces_native_hidpi_and_sweet_spot() {
        let mbp_all = vec![
            DisplayPreset {
                width: 3024,
                height: 1964,
                label: "3024 × 1964".into(),
                is_native: false,
                is_hidpi: false,
            },
            DisplayPreset {
                width: 3024,
                height: 1890,
                label: "3024 × 1890".into(),
                is_native: false,
                is_hidpi: false,
            },
            DisplayPreset {
                width: 2704,
                height: 1756,
                label: "2704 × 1756".into(),
                is_native: false,
                is_hidpi: false,
            },
            DisplayPreset {
                width: 2560,
                height: 1600,
                label: "2560 × 1600".into(),
                is_native: false,
                is_hidpi: false,
            },
            DisplayPreset {
                width: 1920,
                height: 1200,
                label: "1920 × 1200".into(),
                is_native: false,
                is_hidpi: false,
            },
            DisplayPreset {
                width: 1800,
                height: 1169,
                label: "1800 × 1169 (HiDPI)".into(),
                is_native: false,
                is_hidpi: true,
            },
            DisplayPreset {
                width: 1512,
                height: 982,
                label: "1512 × 982 (HiDPI)".into(),
                is_native: true,
                is_hidpi: true,
            },
            DisplayPreset {
                width: 1280,
                height: 800,
                label: "1280 × 800 (HiDPI)".into(),
                is_native: false,
                is_hidpi: true,
            },
        ];

        let (primary, rest) =
            partition_presets_for_menu(&mbp_all, 1512, 982, 120, StreamCodec::Hevc, 5);
        assert_eq!(primary.len(), 5);
        assert_eq!(rest.len(), 3);
        // 原生 HiDPI 必须置顶，HEVC 高刷甜点 2704×1756（4.75M px ≤ 5.0M px）与超清 3024×1964 均在一级菜单可见
        assert!(primary[0].is_native);
        assert_eq!((primary[0].width, primary[0].height), (1512, 982));
        assert!(primary.iter().any(|p| p.width == 2704 && p.height == 1756));
        assert!(primary.iter().any(|p| p.width == 3024 && p.height == 1964));

        // H.264 120fps 下甜点档为 1920×1200（2.30M px ≤ 2.33M px），同样必须进入一级菜单
        let (primary_h264, _) =
            partition_presets_for_menu(&mbp_all, 1512, 982, 120, StreamCodec::H264, 5);
        assert!(primary_h264[0].is_native);
        assert!(primary_h264
            .iter()
            .any(|p| p.width == 1920 && p.height == 1200));
        assert!(primary_h264
            .iter()
            .any(|p| p.width == 3024 && p.height == 1964));
    }
}
