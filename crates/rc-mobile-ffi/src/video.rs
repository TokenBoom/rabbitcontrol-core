//! iOS 视频通路:VT 解码器 + 帧泵渲染器 + 平台注册。
//!
//! 架构:
//! - `IosMediaProvider`(rc-pipeline `PlatformMediaProvider`)提供 VT 硬件解码器;
//! - `IosHooks`(rc-client-core `ClientPlatformHooks`)提供 `FramePumpRenderer`;
//! - `FramePumpRenderer` 实现 `Renderer`:每帧 CFRetain 后换入全局槽位,
//!   Swift 经 `rc_video_frame_take` 取走 CVPixelBuffer 指针(所有权转移),
//!   用 CoreImage/Metal 显示,用完必须调 `rc_video_frame_release`。
//!
//! 限制(v1):全局单帧槽,假定同一时刻只有一路会话。

use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rc_capture::FrameTexture;
use rc_decode::DecodedFrame;
use rc_pipeline::{PipelineConfig, PlatformMediaProvider};
use rc_render::Renderer;
use rc_types::{Error, Result, Timestamp};

use crate::to_c_string;

// ── CoreFoundation 引用计数(手工 FFI,避免额外依赖)──

type CFTypeRef = *const std::ffi::c_void;

extern "C" {
    fn CFRetain(cf: CFTypeRef) -> CFTypeRef;
    fn CFRelease(cf: CFTypeRef);
}

// ── 全局帧槽 ──

struct FrameSlot {
    /// 当前帧 CVPixelBuffer 指针(已 retain,槽位持有)。
    ptr: usize,
    width: u32,
    height: u32,
    /// 单调递增帧序号,Swift 据此避免重复取帧。
    seq: u64,
}

fn frame_slot() -> &'static Mutex<FrameSlot> {
    static SLOT: OnceLock<Mutex<FrameSlot>> = OnceLock::new();
    SLOT.get_or_init(|| {
        Mutex::new(FrameSlot {
            ptr: 0,
            width: 0,
            height: 0,
            seq: 0,
        })
    })
}

// ── 帧泵渲染器 ──

/// iOS 帧泵渲染器:不直接上屏,把每帧 CVPixelBuffer retain 进全局槽。
struct FramePumpRenderer {
    size: (u32, u32),
}

impl Renderer for FramePumpRenderer {
    fn present(&mut self, frame: DecodedFrame) -> Result<Timestamp> {
        match frame.texture {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            FrameTexture::CVPixelBuffer(ptr) => {
                if ptr.is_null() {
                    return Err(Error::InvalidConfig("null pixel buffer".to_string()));
                }
                #[allow(unsafe_code)]
                unsafe {
                    // 跨帧持有必须自行 retain(解码器只保活到下一次 decode)。
                    CFRetain(ptr as CFTypeRef);
                    let mut slot = frame_slot().lock().unwrap_or_else(|e| e.into_inner());
                    if slot.ptr != 0 {
                        CFRelease(slot.ptr as CFTypeRef);
                    }
                    slot.ptr = ptr as usize;
                    slot.width = frame.width;
                    slot.height = frame.height;
                    slot.seq = slot.seq.wrapping_add(1);
                }
                Ok(frame.decode_done_ts)
            }
            FrameTexture::Cpu(_) => {
                // CPU 帧(软件路径)暂不上屏,静默吞掉,保持管线存活。
                Ok(frame.decode_done_ts)
            }
            #[allow(unreachable_patterns)]
            _ => Ok(frame.decode_done_ts),
        }
    }

    fn resize(&mut self, size: (u32, u32)) -> Result<()> {
        if size.0 == 0 || size.1 == 0 {
            return Err(Error::InvalidConfig(
                "frame pump renderer: size must be non-zero".to_string(),
            ));
        }
        self.size = size;
        Ok(())
    }

    fn set_vsync(&mut self, _on: bool) {}

    fn set_cursor(&mut self, _pos: (i32, i32), _visible: bool) {}
}

// ── 平台注册 ──

struct IosMediaProvider;

impl PlatformMediaProvider for IosMediaProvider {
    fn create_decoder(
        &self,
        cfg: &PipelineConfig,
    ) -> Result<(Box<dyn rc_decode::Decoder>, &'static str)> {
        let decoder = rc_decode_vt::new_decoder(rc_decode_vt::VtDecoderConfig {
            max_resolution: rc_types::Resolution::new(
                cfg.resolution.width.max(4096),
                cfg.resolution.height.max(4096),
            ),
            ..rc_decode_vt::VtDecoderConfig::default()
        })
        .map_err(|e| Error::InvalidConfig(format!("vt decoder init: {e}")))?;
        Ok((Box::new(decoder), "videotoolbox"))
    }
}

struct IosHooks;

impl rc_client_core::platform::ClientPlatformHooks for IosHooks {
    fn create_hardware_renderer(
        &self,
        width: u32,
        height: u32,
        _session_start: std::time::Instant,
        _preallocated: Option<&rc_client_core::platform::PreallocatedRenderSurface>,
    ) -> std::result::Result<rc_client_core::platform::HardwareRendererOutput, String> {
        Ok(rc_client_core::platform::HardwareRendererOutput {
            renderer: Box::new(FramePumpRenderer {
                size: (width, height),
            }),
            layer_addr: 0,
            label: "frame-pump",
        })
    }
}

static REGISTERED: AtomicBool = AtomicBool::new(false);

/// 注册 iOS 媒体通路(幂等)。`rc_session_open` 前必须调用一次。
#[no_mangle]
pub extern "C" fn rc_video_init() -> i32 {
    if REGISTERED.swap(true, Ordering::SeqCst) {
        return 1;
    }
    let provider_ok = rc_pipeline::register_platform_provider(Arc::new(IosMediaProvider));
    let hooks_ok = rc_client_core::platform::register_platform_hooks(Arc::new(IosHooks));
    if provider_ok && hooks_ok {
        1
    } else {
        0
    }
}

// ── 帧取放 FFI ──

/// 取走当前最新帧(所有权转移)。返回:
/// `{"ptr": u64, "width": u32, "height": u32, "seq": u64}`,无帧时 `{}`。
///
/// Swift 侧:`ptr` 即 `CVPixelBufferRef`,可直接构造 `CIImage(cvPixelBuffer:)`;
/// 用毕必须调 `rc_video_frame_release(ptr)`。
/// 注意:take 之后槽位清空,同一帧不会被取两次。
#[no_mangle]
pub extern "C" fn rc_video_frame_take() -> *mut c_char {
    #[allow(unsafe_code)]
    let out = {
        let mut slot = frame_slot().lock().unwrap_or_else(|e| e.into_inner());
        if slot.ptr == 0 {
            serde_json::json!({})
        } else {
            let taken = serde_json::json!({
                "ptr": slot.ptr,
                "width": slot.width,
                "height": slot.height,
                "seq": slot.seq,
            });
            // 所有权转移给 Swift:槽位清零但不 release。
            slot.ptr = 0;
            taken
        }
    };
    to_c_string(out.to_string())
}

/// 释放一帧 CVPixelBuffer(`rc_video_frame_take` 取走的帧用毕必须调用)。
///
/// # Safety
///
/// `ptr` 必须为零或此前 `rc_video_frame_take` 返回且尚未释放的帧指针;
/// 重复释放或传入非帧指针属于未定义行为。
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn rc_video_frame_release(ptr: u64) {
    if ptr != 0 {
        unsafe {
            CFRelease(ptr as CFTypeRef);
        }
    }
}
