//! WebView DOM 输入事件 → `rc_input::InputEvent` 纯映射（T21 API 契约 §3）。
//!
//! 全部纯函数、全部参数注入（铁律 4），不读时钟、不依赖 Tauri 或系统 API。

#![deny(unsafe_code)]

use rc_input::batch::modifier_bits as rc_mod;
use rc_input::{InputEvent, MouseButton};
use serde::Deserialize;

/// 在容器矩形 `(stage_w, stage_h)` 内按视频尺寸 `(video_w, video_h)` 等比居中缩放（aspect-fit），
/// 返回视频显示区相对容器左上角的 `(offset_x, offset_y, fit_w, fit_h)`。
///
/// - 保证渲染层（`CAMetalLayer` / `MetalRenderer`）与指针输入映射共用同一份纯几何计算，
///   消除任意窗口宽高比下的画面拉伸与鼠标位置偏移；
/// - 当 `video_w` 或 `video_h` 为 0 时退回填满整片容器 `(0.0, 0.0, stage_w, stage_h)`；
/// - 非正数或非有限容器尺寸返回全 0，绝不 panic 或产生 NaN。
pub fn fit_video_rect(
    stage_w: f64,
    stage_h: f64,
    video_w: u32,
    video_h: u32,
) -> (f64, f64, f64, f64) {
    if !stage_w.is_finite() || !stage_h.is_finite() || stage_w <= 0.0 || stage_h <= 0.0 {
        return (0.0, 0.0, 0.0, 0.0);
    }
    if video_w == 0 || video_h == 0 {
        return (0.0, 0.0, stage_w, stage_h);
    }
    let stage_aspect = stage_w / stage_h;
    let video_aspect = f64::from(video_w) / f64::from(video_h);
    if stage_aspect > video_aspect {
        // 容器更宽：高度撑满，左右留边（pillarbox）
        let fit_h = stage_h;
        let fit_w = (stage_h * video_aspect).min(stage_w);
        let offset_x = (stage_w - fit_w) * 0.5;
        (offset_x, 0.0, fit_w, fit_h)
    } else {
        // 容器更高：宽度撑满，上下留边（letterbox）
        let fit_w = stage_w;
        let fit_h = (stage_w / video_aspect).min(stage_h);
        let offset_y = (stage_h - fit_h) * 0.5;
        (0.0, offset_y, fit_w, fit_h)
    }
}

/// 指针坐标归一化到 `0..=65535`（`InputEvent::MouseMove` 语义）。
///
/// 坐标越界（stage 外的 DOM 事件）clamp 到边界；`stage_w`/`stage_h` 非正数或非有限值时
/// 返回 `0`，绝不 panic 或产生 NaN。
pub fn normalize_pointer(x: f64, y: f64, stage_w: f64, stage_h: f64) -> (u16, u16) {
    let norm = |v: f64, dim: f64| -> u16 {
        if !v.is_finite() || !dim.is_finite() || dim <= 0.0 {
            return 0;
        }
        let ratio = (v / dim).clamp(0.0, 1.0);
        (ratio * f64::from(u16::MAX)).round() as u16
    };
    (norm(x, stage_w), norm(y, stage_h))
}

/// 在等比居中的视频显示区内把相对 stage 左上角的指针坐标 `(x, y)` 归一化到 `0..=65535`。
///
/// - 当 `video_size` 为 `Some((vw, vh))`（且均 > 0）时，先通过 [`fit_video_rect`] 算出实际视频矩形，
///   再将 `(x - offset_x, y - offset_y)` 映射到 `(fit_w, fit_h)` 并钳制到 `0..=65535`；
/// - 当 `video_size` 为 `None`（尚未协商或无有效视频尺寸）时，退回整片 stage 归一化。
pub fn normalize_pointer_in_video(
    x: f64,
    y: f64,
    stage_w: f64,
    stage_h: f64,
    video_size: Option<(u32, u32)>,
) -> (u16, u16) {
    match video_size {
        Some((vw, vh)) if vw > 0 && vh > 0 => {
            let (ox, oy, fw, fh) = fit_video_rect(stage_w, stage_h, vw, vh);
            normalize_pointer(x - ox, y - oy, fw, fh)
        }
        _ => normalize_pointer(x, y, stage_w, stage_h),
    }
}

/// 每页滚动折算行数（DOM `WheelEvent.deltaMode == 2` / `DOM_DELTA_PAGE`）。
pub const WHEEL_LINES_PER_PAGE: f64 = 12.0;

/// UI / WebView DOM 输入事件负载（经 `input_bridge` 映射为 [`InputEvent`]）。
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UiInputEvent {
    /// 指针移动（坐标相对于 stage 左上角，CSS 像素）。
    MouseMove {
        /// 相对 stage 左上角的 X（CSS 像素）。
        x: f64,
        /// 相对 stage 左上角的 Y（CSS 像素）。
        y: f64,
        /// stage 宽度（CSS 像素）。
        stage_w: f64,
        /// stage 高度（CSS 像素）。
        stage_h: f64,
    },
    /// 鼠标按键按下/抬起（DOM `MouseEvent.button`：0=左 1=中 2=右 3=后退 4=前进）。
    MouseButton {
        /// DOM 按键编号。
        button: u8,
        /// `true` = 按下，`false` = 抬起。
        pressed: bool,
    },
    /// 鼠标滚轮（DOM `WheelEvent.deltaY` / `deltaX` / `deltaMode`）。
    MouseWheel {
        /// 垂直滚动量（向下为正；`delta_mode == 0` 时单位为 CSS 像素）。
        delta_y_px: f64,
        /// 前端实测行高（CSS 像素，注入参数）。
        line_height_px: f64,
        /// 可选水平滚动量（向右为正）。
        #[serde(default)]
        delta_x_px: f64,
        /// DOM `WheelEvent.deltaMode`：`0` = 像素，`1` = 行，`2` = 页。
        #[serde(default)]
        delta_mode: u8,
    },
    /// 键盘按键按下/抬起（DOM `KeyboardEvent.code` + 修饰键精确快照）。
    Key {
        /// DOM `KeyboardEvent.code`（如 `"KeyA"` / `"ArrowLeft"`）。
        code: String,
        /// `true` = 按下，`false` = 抬起。
        pressed: bool,
        /// Ctrl 是否处于按下态。
        #[serde(default)]
        ctrl: bool,
        /// Shift 是否处于按下态。
        #[serde(default)]
        shift: bool,
        /// Alt / Option 是否处于按下态。
        #[serde(default)]
        alt: bool,
        /// Meta / Command 是否处于按下态。
        #[serde(default)]
        meta: bool,
    },
}

/// 将 DOM `MouseEvent.button` 映射为 [`MouseButton`]。
pub fn map_dom_mouse_button(button: u8) -> Option<MouseButton> {
    match button {
        0 => Some(MouseButton::Left),
        1 => Some(MouseButton::Middle),
        2 => Some(MouseButton::Right),
        3 => Some(MouseButton::X2),
        4 => Some(MouseButton::X1),
        _ => None,
    }
}

/// 跨事件亚像素 / 亚行滚轮累加器（避免高刷触控板微滚动被逐条四舍五入归零丢弃）。
///
/// 按会话维护水平/垂直浮点余数 `(rem_x, rem_y)`：
/// - 若对端支持 `HostFlags::SUPPORTS_PIXEL_SCROLL` 且 `delta_mode == 0`，输出
///   [`InputEvent::MouseWheelPixel`]（`dy > 0` 向上、`dx > 0` 向左，与 macOS `CGEvent` 一致）；
/// - 否则（`delta_mode == 1/2` 或旧端不支持像素滚轮）累积小数行余数并输出
///   [`InputEvent::MouseWheel`]（行单位，零丢微增量）。
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct WheelAccumulator {
    rem_x: f64,
    rem_y: f64,
    last_pixel_mode: Option<bool>,
}

impl WheelAccumulator {
    /// 构造清零状态的累加器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 重置亚像素 / 亚行余数（断开重连或会话切换时调用）。
    pub fn reset(&mut self) {
        self.rem_x = 0.0;
        self.rem_y = 0.0;
    }

    /// 读取当前 `(rem_x, rem_y)` 余数（诊断 / 单测用）。
    pub fn remainder(&self) -> (f64, f64) {
        (self.rem_x, self.rem_y)
    }

    /// 累积一条滚轮事件并输出 0..=2 条待发送的 [`InputEvent`]。
    ///
    /// - `delta_x`：DOM `deltaX`（向右为正）；
    /// - `delta_y`：DOM `deltaY`（向下为正）；
    /// - `line_height_px`：CSS 行高（像素）；
    /// - `delta_mode`：`0` = 像素、`1` = 行、`2` = 页；
    /// - `peer_supports_pixel_scroll`：对端是否在 `Welcome` 中通告 `SUPPORTS_PIXEL_SCROLL`。
    pub fn push_wheel(
        &mut self,
        delta_x: f64,
        delta_y: f64,
        line_height_px: f64,
        delta_mode: u8,
        peer_supports_pixel_scroll: bool,
    ) -> Vec<InputEvent> {
        let use_pixel = peer_supports_pixel_scroll && delta_mode == 0;
        if self.last_pixel_mode != Some(use_pixel) {
            self.reset();
            self.last_pixel_mode = Some(use_pixel);
        }

        let needs_line_height = !use_pixel && (delta_mode == 0 || delta_mode > 2);
        if needs_line_height && (!line_height_px.is_finite() || line_height_px <= 0.0) {
            return Vec::new();
        }

        if use_pixel {
            // 与 macOS CGEventCreateScrollWheelEvent2 PIXEL 轴约定一致：
            // dy > 0 向上滚（DOM deltaY < 0），dx > 0 向左滚（DOM deltaX < 0）。
            let dx = Self::step_axis(&mut self.rem_x, -delta_x);
            let dy = Self::step_axis(&mut self.rem_y, -delta_y);
            if dx == 0 && dy == 0 {
                Vec::new()
            } else {
                vec![InputEvent::MouseWheelPixel { dx, dy }]
            }
        } else {
            let (lines_x, lines_y) = match delta_mode {
                1 => (delta_x, -delta_y),
                2 => (
                    delta_x * WHEEL_LINES_PER_PAGE,
                    -delta_y * WHEEL_LINES_PER_PAGE,
                ),
                _ => (delta_x / line_height_px, -delta_y / line_height_px),
            };
            let mut out = Vec::new();
            let dy = Self::step_axis(&mut self.rem_y, lines_y);
            if dy != 0 {
                out.push(InputEvent::MouseWheel {
                    delta: dy,
                    horizontal: false,
                });
            }
            let dx = Self::step_axis(&mut self.rem_x, lines_x);
            if dx != 0 {
                out.push(InputEvent::MouseWheel {
                    delta: dx,
                    horizontal: true,
                });
            }
            out
        }
    }

    fn step_axis(rem: &mut f64, delta: f64) -> i16 {
        if !rem.is_finite() {
            *rem = 0.0;
        }
        if !delta.is_finite() || delta == 0.0 {
            return 0;
        }
        if *rem != 0.0 && (delta < 0.0) != (*rem < 0.0) {
            *rem = 0.0;
        }
        let total = *rem + delta;
        if !total.is_finite() {
            *rem = 0.0;
            return if delta < 0.0 { i16::MIN } else { i16::MAX };
        }
        let rounded = total.round();
        let effective = if (total - rounded).abs() < 1e-9 {
            rounded
        } else {
            total
        };
        let truncated = effective.trunc();
        let clamped = truncated.clamp(f64::from(i16::MIN), f64::from(i16::MAX));
        if truncated != clamped {
            *rem = 0.0;
        } else {
            *rem = effective - clamped;
        }
        clamped as i16
    }
}

/// 将 [`UiInputEvent`] 映射为 0..=2 条 [`InputEvent`]（带会话级滚轮累加器与对端能力协商分发）。
///
/// 返回 `(events, unmapped_key)`；遇到未收录的 DOM `KeyboardEvent.code` 时 `unmapped_key == true`。
pub fn map_ui_input_event(
    ev: &UiInputEvent,
    video_size: Option<(u32, u32)>,
    wheel_acc: &mut WheelAccumulator,
    peer_supports_pixel_scroll: bool,
) -> (Vec<InputEvent>, bool) {
    match ev {
        UiInputEvent::MouseMove {
            x,
            y,
            stage_w,
            stage_h,
        } => {
            let (nx, ny) = normalize_pointer_in_video(*x, *y, *stage_w, *stage_h, video_size);
            (vec![InputEvent::MouseMove { x: nx, y: ny }], false)
        }
        UiInputEvent::MouseButton { button, pressed } => match map_dom_mouse_button(*button) {
            Some(btn) => (
                vec![InputEvent::MouseButton {
                    button: btn,
                    pressed: *pressed,
                }],
                false,
            ),
            None => (Vec::new(), false),
        },
        UiInputEvent::MouseWheel {
            delta_y_px,
            line_height_px,
            delta_x_px,
            delta_mode,
        } => (
            wheel_acc.push_wheel(
                *delta_x_px,
                *delta_y_px,
                *line_height_px,
                *delta_mode,
                peer_supports_pixel_scroll,
            ),
            false,
        ),
        UiInputEvent::Key {
            code,
            pressed,
            ctrl,
            shift,
            alt,
            meta,
        } => match scancode_for(code) {
            Some(scancode) => {
                let modifiers = modifier_bits(*ctrl, *shift, *alt, *meta);
                (
                    vec![InputEvent::Key {
                        scancode,
                        pressed: *pressed,
                        modifiers,
                    }],
                    false,
                )
            }
            None => (Vec::new(), true),
        },
    }
}

/// DOM wheel 的 `deltaY`（CSS 像素，向下为正）→ 行数（`InputEvent::MouseWheel` 规范单位 = 行）。
///
/// `deltaY > 0`（向下滚）⇒ 返回负值（`delta > 0` 表示向上滚）。
/// 行高由前端实测注入（不写死）；非法/非正行高或非有限值返回 `0`。
pub fn wheel_lines(delta_y_px: f64, line_height_px: f64) -> i16 {
    if !delta_y_px.is_finite() || !line_height_px.is_finite() || line_height_px <= 0.0 {
        return 0;
    }
    let lines = (-delta_y_px / line_height_px).round();
    lines.clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16
}

/// DOM `KeyboardEvent.code` → Windows Set 1 扫描码（I5：扫描码而非虚拟键码）。
///
/// E0 前缀键编码为 `0xE0 << 8 | code`（如 `ArrowLeft = 0xE04B`、`ControlRight = 0xE01D`），
/// 与 `rc_input::batch::modifier_scancodes` 及 `rc-input-macos/src/scancode.rs` 完全一致。
/// 未收录的 `code` 返回 `None`（由调用方静默丢弃并计数）。
pub fn scancode_for(code: &str) -> Option<u16> {
    let sc = match code {
        // ── 字母（Set 1 make code）────────────────────────────────────
        "KeyA" => 0x1E,
        "KeyB" => 0x30,
        "KeyC" => 0x2E,
        "KeyD" => 0x20,
        "KeyE" => 0x12,
        "KeyF" => 0x21,
        "KeyG" => 0x22,
        "KeyH" => 0x23,
        "KeyI" => 0x17,
        "KeyJ" => 0x24,
        "KeyK" => 0x25,
        "KeyL" => 0x26,
        "KeyM" => 0x32,
        "KeyN" => 0x31,
        "KeyO" => 0x18,
        "KeyP" => 0x19,
        "KeyQ" => 0x10,
        "KeyR" => 0x13,
        "KeyS" => 0x1F,
        "KeyT" => 0x14,
        "KeyU" => 0x16,
        "KeyV" => 0x2F,
        "KeyW" => 0x11,
        "KeyX" => 0x2D,
        "KeyY" => 0x15,
        "KeyZ" => 0x2C,

        // ── 主键盘数字 ────────────────────────────────────────────────
        "Digit1" => 0x02,
        "Digit2" => 0x03,
        "Digit3" => 0x04,
        "Digit4" => 0x05,
        "Digit5" => 0x06,
        "Digit6" => 0x07,
        "Digit7" => 0x08,
        "Digit8" => 0x09,
        "Digit9" => 0x0A,
        "Digit0" => 0x0B,

        // ── 符号 / 标点（ANSI）────────────────────────────────────────
        "Minus" => 0x0C,
        "Equal" => 0x0D,
        "BracketLeft" => 0x1A,
        "BracketRight" => 0x1B,
        "Backslash" => 0x2B,
        "Semicolon" => 0x27,
        "Quote" => 0x28,
        "Backquote" => 0x29,
        "Comma" => 0x33,
        "Period" => 0x34,
        "Slash" => 0x35,
        "IntlBackslash" => 0x56,

        // ── 控制键 ────────────────────────────────────────────────────
        "Escape" => 0x01,
        "Backspace" => 0x0E,
        "Tab" => 0x0F,
        "Enter" => 0x1C,
        "Space" => 0x39,
        "CapsLock" => 0x3A,
        "Delete" => 0xE053,
        "Insert" => 0xE052,
        "PrintScreen" => 0xE037,
        "ScrollLock" => 0x46,
        "NumLock" => 0x45,
        "ContextMenu" => 0xE05D,

        // ── 导航与方向键（E0 前缀）────────────────────────────────────
        "Home" => 0xE047,
        "End" => 0xE04F,
        "PageUp" => 0xE049,
        "PageDown" => 0xE051,
        "ArrowUp" => 0xE048,
        "ArrowDown" => 0xE050,
        "ArrowLeft" => 0xE04B,
        "ArrowRight" => 0xE04D,

        // ── 左右修饰键（与 rc_input::batch::modifier_scancodes 一致）──
        "ControlLeft" => 0x1D,
        "ShiftLeft" => 0x2A,
        "AltLeft" => 0x38,
        "MetaLeft" | "OSLeft" => 0xE05B,
        "ControlRight" => 0xE01D,
        "ShiftRight" => 0x36,
        "AltRight" => 0xE038,
        "MetaRight" | "OSRight" => 0xE05C,

        // ── 功能键 F1–F12 ─────────────────────────────────────────────
        "F1" => 0x3B,
        "F2" => 0x3C,
        "F3" => 0x3D,
        "F4" => 0x3E,
        "F5" => 0x3F,
        "F6" => 0x40,
        "F7" => 0x41,
        "F8" => 0x42,
        "F9" => 0x43,
        "F10" => 0x44,
        "F11" => 0x57,
        "F12" => 0x58,

        // ── 小键盘 ────────────────────────────────────────────────────
        "Numpad0" => 0x52,
        "Numpad1" => 0x4F,
        "Numpad2" => 0x50,
        "Numpad3" => 0x51,
        "Numpad4" => 0x4B,
        "Numpad5" => 0x4C,
        "Numpad6" => 0x4D,
        "Numpad7" => 0x47,
        "Numpad8" => 0x48,
        "Numpad9" => 0x49,
        "NumpadDecimal" => 0x53,
        "NumpadAdd" => 0x4E,
        "NumpadSubtract" => 0x4A,
        "NumpadMultiply" => 0x37,
        "NumpadDivide" => 0xE035,
        "NumpadEnter" => 0xE01C,

        _ => return None,
    };
    Some(sc)
}

/// 修饰键快照（I8：发送方在事件发生瞬间的精确状态，接收端不推断）。
///
/// 位定义逐位对齐 [`rc_input::batch::modifier_bits`]。
pub fn modifier_bits(ctrl: bool, shift: bool, alt: bool, meta: bool) -> u8 {
    let mut bits = 0u8;
    if ctrl {
        bits |= rc_mod::LEFT_CTRL;
    }
    if shift {
        bits |= rc_mod::LEFT_SHIFT;
    }
    if alt {
        bits |= rc_mod::LEFT_ALT;
    }
    if meta {
        bits |= rc_mod::LEFT_GUI;
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_input::batch::modifier_scancodes as rc_sc;

    #[test]
    fn normalize_pointer_clamps_to_stage() {
        assert_eq!(normalize_pointer(0.0, 0.0, 1920.0, 1080.0), (0, 0));
        assert_eq!(
            normalize_pointer(1920.0, 1080.0, 1920.0, 1080.0),
            (65535, 65535)
        );
        // 中点
        assert_eq!(
            normalize_pointer(960.0, 540.0, 1920.0, 1080.0),
            (32768, 32768)
        );
        // 越界 clamp
        assert_eq!(normalize_pointer(-50.0, 2000.0, 1920.0, 1080.0), (0, 65535));
        assert_eq!(normalize_pointer(5000.0, -10.0, 1920.0, 1080.0), (65535, 0));
        // 0 尺寸 / NaN 防御不 panic
        assert_eq!(normalize_pointer(100.0, 100.0, 0.0, 0.0), (0, 0));
        assert_eq!(
            normalize_pointer(f64::NAN, f64::INFINITY, 100.0, 100.0),
            (0, 0)
        );
    }

    #[test]
    fn fit_video_rect_and_pointer_mapping_align_pillarbox_and_letterbox() {
        // 1) 14" MBP (1512x982) 放进默认 1280x752 stage（左右留边 pillarbox）
        let (ox, oy, fw, fh) = fit_video_rect(1280.0, 752.0, 1512, 982);
        assert!((oy - 0.0).abs() < 1e-6);
        assert!((fh - 752.0).abs() < 1e-6);
        let expected_w = 752.0 * (1512.0 / 982.0);
        assert!((fw - expected_w).abs() < 1e-6);
        assert!((ox - (1280.0 - expected_w) * 0.5).abs() < 1e-6);

        // 视频区四角精确映射到 0 和 65535，留边区外平滑钳制到边缘
        assert_eq!(
            normalize_pointer_in_video(ox, 0.0, 1280.0, 752.0, Some((1512, 982))),
            (0, 0)
        );
        assert_eq!(
            normalize_pointer_in_video(ox + fw, 752.0, 1280.0, 752.0, Some((1512, 982))),
            (65535, 65535)
        );
        assert_eq!(
            normalize_pointer_in_video(0.0, 376.0, 1280.0, 752.0, Some((1512, 982))),
            (0, 32768)
        );
        assert_eq!(
            normalize_pointer_in_video(1280.0, 376.0, 1280.0, 752.0, Some((1512, 982))),
            (65535, 32768)
        );

        // 2) 16:9 (1920x1080) 放进 800x752 窄窗口（上下留边 letterbox）
        let (ox2, oy2, fw2, fh2) = fit_video_rect(800.0, 752.0, 1920, 1080);
        assert!((ox2 - 0.0).abs() < 1e-6);
        assert!((fw2 - 800.0).abs() < 1e-6);
        assert!((fh2 - 450.0).abs() < 1e-6);
        assert!((oy2 - 151.0).abs() < 1e-6);
        assert_eq!(
            normalize_pointer_in_video(400.0, oy2, 800.0, 752.0, Some((1920, 1080))),
            (32768, 0)
        );
        assert_eq!(
            normalize_pointer_in_video(400.0, oy2 + fh2, 800.0, 752.0, Some((1920, 1080))),
            (32768, 65535)
        );

        // 3) 未协商（None）时退回整片 stage
        assert_eq!(
            normalize_pointer_in_video(640.0, 376.0, 1280.0, 752.0, None),
            (32768, 32768)
        );
    }

    #[test]
    fn wheel_lines_sign_and_rounding() {
        // deltaY > 0（向下滚）→ 负行数
        assert_eq!(wheel_lines(16.0, 16.0), -1);
        assert_eq!(wheel_lines(48.0, 16.0), -3);
        // deltaY < 0（向上滚）→ 正行数
        assert_eq!(wheel_lines(-32.0, 16.0), 2);
        // |deltaY| < 半行 → 0
        assert_eq!(wheel_lines(7.9, 16.0), 0);
        assert_eq!(wheel_lines(-7.9, 16.0), 0);
        // 注入不同行高生效
        assert_eq!(wheel_lines(40.0, 20.0), -2);
        assert_eq!(wheel_lines(40.0, 10.0), -4);
        // 非法行高防御
        assert_eq!(wheel_lines(16.0, 0.0), 0);
        assert_eq!(wheel_lines(16.0, -16.0), 0);
        assert_eq!(wheel_lines(f64::NAN, 16.0), 0);
    }

    #[test]
    fn scancode_table_covers_common_keys() {
        let expected: &[(&str, u16)] = &[
            ("KeyA", 0x1E),
            ("KeyZ", 0x2C),
            ("Digit1", 0x02),
            ("Digit0", 0x0B),
            ("Minus", 0x0C),
            ("Equal", 0x0D),
            ("Space", 0x39),
            ("Enter", 0x1C),
            ("Escape", 0x01),
            ("Backspace", 0x0E),
            ("Tab", 0x0F),
            ("Delete", 0xE053),
            ("F1", 0x3B),
            ("F5", 0x3F),
            ("F11", 0x57),
            ("F12", 0x58),
            // 方向四键（E0 前缀）
            ("ArrowLeft", 0xE04B),
            ("ArrowRight", 0xE04D),
            ("ArrowUp", 0xE048),
            ("ArrowDown", 0xE050),
            // 导航键（E0 前缀）
            ("Home", 0xE047),
            ("End", 0xE04F),
            ("PageUp", 0xE049),
            ("PageDown", 0xE051),
            // 左右修饰键（与 rc-input 常量互锁）
            ("ControlLeft", rc_sc::LEFT_CTRL),
            ("ShiftLeft", rc_sc::LEFT_SHIFT),
            ("AltLeft", rc_sc::LEFT_ALT),
            ("MetaLeft", rc_sc::LEFT_GUI),
            ("ControlRight", rc_sc::RIGHT_CTRL),
            ("ShiftRight", rc_sc::RIGHT_SHIFT),
            ("AltRight", rc_sc::RIGHT_ALT),
            ("MetaRight", rc_sc::RIGHT_GUI),
        ];
        assert!(expected.len() >= 24);
        for &(code, want) in expected {
            assert_eq!(
                scancode_for(code),
                Some(want),
                "code={code} 应映射为 {want:#06X}"
            );
        }
        // 未知 code 返回 None
        assert_eq!(scancode_for("Unidentified"), None);
        assert_eq!(scancode_for(""), None);
        assert_eq!(scancode_for("NonExistentKey"), None);
    }

    #[test]
    fn modifier_bits_match_input_semantics() {
        assert_eq!(modifier_bits(false, false, false, false), 0);
        assert_eq!(modifier_bits(true, false, false, false), rc_mod::LEFT_CTRL);
        assert_eq!(modifier_bits(false, true, false, false), rc_mod::LEFT_SHIFT);
        assert_eq!(modifier_bits(false, false, true, false), rc_mod::LEFT_ALT);
        assert_eq!(modifier_bits(false, false, false, true), rc_mod::LEFT_GUI);
        assert_eq!(
            modifier_bits(true, true, true, true),
            rc_mod::LEFT_CTRL | rc_mod::LEFT_SHIFT | rc_mod::LEFT_ALT | rc_mod::LEFT_GUI
        );
    }

    #[test]
    fn ui_input_event_mouse_wheel_deserializes_delta_mode_with_default() {
        let legacy_json = r#"{"kind":"mouse_wheel","delta_y_px":12.5,"line_height_px":16.0}"#;
        let ev: UiInputEvent = serde_json::from_str(legacy_json).expect("legacy json");
        match ev {
            UiInputEvent::MouseWheel {
                delta_y_px,
                line_height_px,
                delta_x_px,
                delta_mode,
            } => {
                assert_eq!(delta_y_px, 12.5);
                assert_eq!(line_height_px, 16.0);
                assert_eq!(delta_x_px, 0.0);
                assert_eq!(delta_mode, 0);
            }
            other => panic!("unexpected {other:?}"),
        }

        let line_json = r#"{"kind":"mouse_wheel","delta_y_px":-3,"line_height_px":16,"delta_x_px":2,"delta_mode":1}"#;
        let ev2: UiInputEvent = serde_json::from_str(line_json).expect("delta_mode=1 json");
        assert!(matches!(
            ev2,
            UiInputEvent::MouseWheel { delta_mode: 1, .. }
        ));
    }

    #[test]
    fn wheel_accumulator_pixel_mode_axes_and_subpixel_accumulation() {
        let mut acc = WheelAccumulator::new();

        // deltaY > 0 向下滚 -> dy < 0；deltaX > 0 向右滚 -> dx < 0（与 macOS CGEvent PIXEL 轴一致）
        let evs = acc.push_wheel(5.0, 12.0, 16.0, 0, true);
        assert_eq!(evs, vec![InputEvent::MouseWheelPixel { dx: -5, dy: -12 }]);
        assert_eq!(acc.remainder(), (0.0, 0.0));

        // deltaY < 0 向上滚 -> dy > 0；deltaX < 0 向左滚 -> dx > 0
        let evs = acc.push_wheel(-3.0, -7.0, 16.0, 0, true);
        assert_eq!(evs, vec![InputEvent::MouseWheelPixel { dx: 3, dy: 7 }]);

        // 亚像素累积：0.4px 连续 3 次，前两次不丢弃、第三次输出 -1 并保留 -0.2 余数
        assert!(acc.push_wheel(0.0, 0.4, 16.0, 0, true).is_empty());
        assert!(acc.push_wheel(0.0, 0.4, 16.0, 0, true).is_empty());
        assert_eq!(
            acc.push_wheel(0.0, 0.4, 16.0, 0, true),
            vec![InputEvent::MouseWheelPixel { dx: 0, dy: -1 }]
        );
        assert!((acc.remainder().1 - (-0.2)).abs() < 1e-9);

        // 另一轴为 0.0 时保留既有亚像素余数不被误清零
        assert!(acc.push_wheel(0.5, 0.0, 16.0, 0, true).is_empty());
        assert!((acc.remainder().1 - (-0.2)).abs() < 1e-9);
        assert!((acc.remainder().0 - (-0.5)).abs() < 1e-9);
    }

    #[test]
    fn wheel_accumulator_line_fallback_and_delta_modes_preserve_micro_scrolls() {
        let mut acc = WheelAccumulator::new();

        // 旧端（peer_supports_pixel_scroll = false）：每次 2px / 16px = 0.125 行，连续 8 次无损凑出 -1 行
        for i in 0..7 {
            let out = acc.push_wheel(0.0, 2.0, 16.0, 0, false);
            assert!(out.is_empty(), "第 {i} 次不应提前输出");
        }
        assert_eq!(
            acc.push_wheel(0.0, 2.0, 16.0, 0, false),
            vec![InputEvent::MouseWheel {
                delta: -1,
                horizontal: false
            }]
        );
        assert_eq!(acc.remainder().1, 0.0);

        // 水平微滚动：4px / 16px = 0.25 行，连续 4 次向右凑出 delta=+1, horizontal=true
        for _ in 0..3 {
            assert!(acc.push_wheel(4.0, 0.0, 16.0, 0, false).is_empty());
        }
        assert_eq!(
            acc.push_wheel(4.0, 0.0, 16.0, 0, false),
            vec![InputEvent::MouseWheel {
                delta: 1,
                horizontal: true
            }]
        );

        // 即使对端支持像素滚轮，delta_mode == 1 (LINE) / 2 (PAGE) 也必须走 MouseWheel 行单位
        assert_eq!(
            acc.push_wheel(0.0, 3.0, 16.0, 1, true),
            vec![InputEvent::MouseWheel {
                delta: -3,
                horizontal: false
            }]
        );
        assert_eq!(
            acc.push_wheel(0.0, -1.0, 16.0, 2, true),
            vec![InputEvent::MouseWheel {
                delta: WHEEL_LINES_PER_PAGE as i16,
                horizontal: false
            }]
        );
    }

    #[test]
    fn wheel_accumulator_guards_reversal_nan_and_i16_clamping() {
        let mut acc = WheelAccumulator::new();

        // 方向反转时清空旧残差：先累积 -0.75px，再向上滚 1.0px -> 立即得 +1（不被旧 -0.75 吃掉）
        assert!(acc.push_wheel(0.0, 0.75, 16.0, 0, true).is_empty());
        assert_eq!(
            acc.push_wheel(0.0, -1.0, 16.0, 0, true),
            vec![InputEvent::MouseWheelPixel { dx: 0, dy: 1 }]
        );

        // 非有限值防御：不污染余数、不 panic
        assert!(acc.push_wheel(0.0, 0.5, 16.0, 0, true).is_empty());
        assert!(acc
            .push_wheel(f64::NAN, f64::INFINITY, 16.0, 0, true)
            .is_empty());
        assert!((acc.remainder().1 - (-0.5)).abs() < 1e-9);

        // 单次超出 i16 范围正确钳制，且余数归零防溢出
        assert_eq!(
            acc.push_wheel(-100_000.0, 100_000.0, 16.0, 0, true),
            vec![InputEvent::MouseWheelPixel {
                dx: i16::MAX,
                dy: i16::MIN,
            }]
        );
        assert_eq!(acc.remainder(), (0.0, 0.0));
    }
}
