use std::collections::VecDeque;
use std::ffi::c_void;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rc_audio::{decode_ima_adpcm, AudioPlayer};
use rc_input::{InputCapture, InputEvent};
use rc_net::quic::QuicEndpoint;
use rc_net::{NetEvent, NetStats, Transport};
use rc_pipeline::{ControllerPipeline, PipelineConfig};
use rc_render::Renderer;
use rc_session::{AudioFramePacket, ClipboardBackend, AUDIO_CODEC_IMA_ADPCM, AUDIO_CODEC_PCM16};

use crate::platform::PreallocatedRenderSurface;
use crate::relay_transport::RelayShutdownHandle;

use super::queues::BoundedInputQueue;

/// 由有界输入队列喂给 `ClientSession` 的自定义 `InputCapture`。
pub(in crate::session_bridge) struct BridgeInputCapture {
    pub(in crate::session_bridge) queue: Arc<BoundedInputQueue>,
    pub(in crate::session_bridge) watch_only: Arc<AtomicBool>,
}

impl InputCapture for BridgeInputCapture {
    fn next_events(&mut self, _timeout: Duration) -> rc_types::Result<Vec<InputEvent>> {
        if self.watch_only.load(Ordering::Acquire) {
            let _ = self.queue.drain_all();
            return Ok(Vec::new());
        }
        Ok(self.queue.drain_all())
    }
}

// ─────────────────────────────────────────────────────────────────
// 渲染器与传输层桥接包装（零改动 rc-pipeline / rc-session）
// ─────────────────────────────────────────────────────────────────

/// 共享渲染器句柄（会话线程用于 `StageRect` resize，不改 `ControllerPipeline` API）。
pub(in crate::session_bridge) type RendererHandle = Arc<Mutex<Box<dyn Renderer>>>;

/// 保持离屏 `CAMetalLayer` 存活的渲染器租约（纯安全封装，零 `unsafe`）。
///
/// 内部持有底层 [`Renderer`] 的强引用：只要任意 `LayerLease` 存活，底层 `MetalRenderer`
/// 及其 `CAMetalLayer` 就绝不会被释放。跨线程派发到主线程的 `attach_layer` /
/// `sync_layer_frame` / `detach_layer` 闭包持有本租约的 clone，彻底消除主线程闭包与
/// 会话线程退出（含 `Ended` / 窗口销毁 / 并发重连）之间的 use-after-free 竞态。
#[derive(Clone)]
pub struct LayerLease {
    renderer: RendererHandle,
    layer_addr: usize,
}

impl LayerLease {
    /// 由共享渲染器句柄与借用 `CAMetalLayer` 地址构造保活租约；`layer_addr == 0` 返回 `None`。
    pub fn from_renderer(
        renderer: Arc<Mutex<Box<dyn Renderer>>>,
        layer_addr: usize,
    ) -> Option<Self> {
        if layer_addr == 0 {
            None
        } else {
            Some(Self {
                renderer,
                layer_addr,
            })
        }
    }

    /// 返回借用的 `CAMetalLayer` 原始指针（调用方须在持有本租约存活期间于主线程使用）。
    pub fn as_ptr(&self) -> *mut c_void {
        self.layer_addr as *mut c_void
    }

    /// 返回借用地址（仅用于日志/比较，不解引用）。
    pub fn addr(&self) -> usize {
        self.layer_addr
    }

    /// 判断两份租约是否指向同一渲染器实例的同一 `CAMetalLayer`（防地址复用 ABA）。
    pub fn same_layer(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.renderer, &other.renderer) && self.layer_addr == other.layer_addr
    }
}

impl fmt::Debug for LayerLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LayerLease")
            .field("layer_addr", &format_args!("{:#x}", self.layer_addr))
            .finish()
    }
}

/// 管线工厂构建产物。
pub(in crate::session_bridge) struct BuiltPipeline {
    pub(in crate::session_bridge) pipeline: ControllerPipeline,
    pub(in crate::session_bridge) backend_label: String,
    pub(in crate::session_bridge) renderer: RendererHandle,
    pub(in crate::session_bridge) pending_resize: Arc<AtomicU64>,
    pub(in crate::session_bridge) layer_addr: usize,
    pub(in crate::session_bridge) is_hardware: bool,
}

pub(in crate::session_bridge) fn pack_stage_rect(width: u32, height: u32) -> u64 {
    (u64::from(width) << 32) | u64::from(height)
}

fn unpack_stage_rect(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, (packed & 0xffff_ffff) as u32)
}

pub(in crate::session_bridge) fn apply_stage_rect_nonblocking(
    rend: &RendererHandle,
    pending_resize: &AtomicU64,
    width: u32,
    height: u32,
) -> bool {
    match rend.try_lock() {
        Ok(mut guard) => {
            pending_resize.store(0, Ordering::Release);
            let _ = guard.resize((width, height));
            true
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            pending_resize.store(pack_stage_rect(width, height), Ordering::Release);
            false
        }
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            let mut guard = poisoned.into_inner();
            pending_resize.store(0, Ordering::Release);
            let _ = guard.resize((width, height));
            true
        }
    }
}

pub(in crate::session_bridge) fn apply_stage_rect_to_slot(
    renderer_handle: &Mutex<Option<RendererHandle>>,
    renderer_pending_resize: &Mutex<Arc<AtomicU64>>,
    width: u32,
    height: u32,
) {
    let rend_opt = renderer_handle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let pending = Arc::clone(
        &renderer_pending_resize
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
    );
    if let Some(rend) = rend_opt {
        apply_stage_rect_nonblocking(&rend, &pending, width, height);
    }
}

/// 共享渲染器包装：让会话线程在不改 `ControllerPipeline` API 的前提下无阻塞响应 `StageRect` resize 与光标更新。
pub(in crate::session_bridge) struct SharedRenderer {
    inner: RendererHandle,
    pending_resize: Arc<AtomicU64>,
    pub(in crate::session_bridge) pending_cursor: Arc<Mutex<Option<(i32, i32, bool)>>>,
}

impl SharedRenderer {
    pub(in crate::session_bridge) fn new(
        inner: RendererHandle,
        pending_resize: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            pending_resize,
            pending_cursor: Arc::new(Mutex::new(None)),
        }
    }
}

impl Renderer for SharedRenderer {
    fn present(&mut self, frame: rc_decode::DecodedFrame) -> rc_types::Result<rc_types::Timestamp> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let packed = self.pending_resize.swap(0, Ordering::AcqRel);
        if packed != 0 {
            let (w, h) = unpack_stage_rect(packed);
            if w > 0 && h > 0 {
                let _ = guard.resize((w, h));
            }
        }
        if let Some((x, y, visible)) = self
            .pending_cursor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            guard.set_cursor((x, y), visible);
        }
        guard.present(frame)
    }

    fn resize(&mut self, size: (u32, u32)) -> rc_types::Result<()> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.pending_resize.store(0, Ordering::Release);
        guard.resize(size)
    }

    fn set_vsync(&mut self, on: bool) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_vsync(on);
    }

    fn set_cursor(&mut self, pos: (i32, i32), visible: bool) {
        match self.inner.try_lock() {
            Ok(mut guard) => {
                *self
                    .pending_cursor
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                guard.set_cursor(pos, visible);
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                // `present()` 正在等待 `CAMetalLayer::nextDrawable()` 回收时，绝不阻塞主会话循环，
                // 缓存最新光标等待 `present()` 在持锁区间原子补刷。
                *self
                    .pending_cursor
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some((pos.0, pos.1, visible));
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                *self
                    .pending_cursor
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                poisoned.into_inner().set_cursor(pos, visible);
            }
        }
    }

    fn apply_still_tile(&mut self, patch: &rc_render::StillTilePatch) -> rc_types::Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .apply_still_tile(patch)
    }

    fn invalidate_still_tiles(&mut self, dirty_rects: &[rc_types::Rect]) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .invalidate_still_tiles(dirty_rects);
    }

    fn clear_still_tiles(&mut self) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear_still_tiles();
    }
}

/// 按平台与硬件偏好构造剪贴板后端：仅 `prefer_hardware == true` 时挂接本机真实系统剪贴板，
/// 离线假后端测试绝不触碰开发者真实剪贴板。
pub(in crate::session_bridge) fn create_clipboard_backend(
    prefer_hardware: bool,
) -> Option<Box<dyn ClipboardBackend>> {
    if !prefer_hardware {
        return None;
    }
    rc_session::create_system_clipboard().ok()
}

/// 可动态开关的剪贴板后端包装（供 `SessionCommand::SetClipboardEnabled` 运行期切换）。
pub(in crate::session_bridge) struct ToggleableClipboardBackend {
    inner: Box<dyn ClipboardBackend>,
    enabled: Arc<AtomicBool>,
    last_count: u64,
}

impl ToggleableClipboardBackend {
    pub(in crate::session_bridge) fn new(
        inner: Box<dyn ClipboardBackend>,
        enabled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            enabled,
            last_count: 0,
        }
    }
}

impl ClipboardBackend for ToggleableClipboardBackend {
    fn change_count(&mut self) -> rc_types::Result<u64> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(self.last_count);
        }
        let c = self.inner.change_count()?;
        self.last_count = c;
        Ok(c)
    }

    fn read_text(&mut self) -> rc_types::Result<Option<String>> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(None);
        }
        self.inner.read_text()
    }

    fn write_text(&mut self, text: &str) -> rc_types::Result<()> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(());
        }
        self.inner.write_text(text)
    }
}

/// 包装底层 [`Transport`]（`QuicTransport`、`P2pQuicConnection` 或 `TcpRelayTransport`）：
/// - 在 `poll` 入口响应本地断连标记（H3：握手期即时中止 45s 等待并取消远端审批弹窗，中继态即时切断套接字）；
/// - 在 `poll` 入口排空上层排队的手动控制消息（如 `SetBitrate(Manual)`），
///   无需改动 `rc-session` 状态机或协议。
pub(in crate::session_bridge) struct BridgeTransport {
    pub(in crate::session_bridge) inner: Box<dyn Transport>,
    pub(in crate::session_bridge) pending_control: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub(in crate::session_bridge) disconnect_flag: Arc<AtomicBool>,
    pub(in crate::session_bridge) relay_shutdown: Option<RelayShutdownHandle>,
    pub(in crate::session_bridge) streaming_started: Arc<AtomicBool>,
}

impl BridgeTransport {
    fn flush_pending_control(&mut self) {
        let msgs: Vec<Vec<u8>> = {
            let mut q = self
                .pending_control
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            q.drain(..).collect()
        };
        for msg in msgs {
            let _ = self.inner.send_reliable(&msg);
        }
    }
}

impl Transport for BridgeTransport {
    fn send_datagram(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.inner.send_datagram(data)
    }

    fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.inner.send_reliable(data)
    }

    fn send_reliable_urgent(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.inner.send_reliable_urgent(data)
    }

    fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
        if self.disconnect_flag.load(Ordering::Acquire)
            && (self.relay_shutdown.is_some() || !self.streaming_started.load(Ordering::Acquire))
        {
            if let Some(ref handle) = self.relay_shutdown {
                handle.shutdown();
            }
            return Ok(vec![NetEvent::Disconnected {
                reason: "用户主动断开".to_string(),
            }]);
        }
        self.flush_pending_control();
        self.inner.poll(timeout)
    }

    fn stats(&self) -> NetStats {
        self.inner.stats()
    }

    fn set_pacing_rate(&mut self, bps: u64) {
        self.inner.set_pacing_rate(bps);
    }

    fn tx_queued_bytes(&self) -> usize {
        self.inner.tx_queued_bytes()
    }

    fn tx_dropped_datagrams(&self) -> u64 {
        self.inner.tx_dropped_datagrams()
    }

    fn reliable_tx_queued_len(&self) -> usize {
        self.inner.reliable_tx_queued_len()
    }

    fn has_live_rtt(&self) -> bool {
        self.inner.has_live_rtt()
    }

    fn wake_handle(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        self.inner.wake_handle()
    }
}

pub(in crate::session_bridge) struct LanQuicTransport {
    pub(in crate::session_bridge) transport: rc_net::quic::QuicTransport,
    pub(in crate::session_bridge) _endpoint: QuicEndpoint,
}

impl Transport for LanQuicTransport {
    fn send_datagram(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.transport.send_datagram(data)
    }

    fn send_reliable(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.transport.send_reliable(data)
    }

    fn send_reliable_urgent(&mut self, data: &[u8]) -> rc_types::Result<()> {
        self.transport.send_reliable_urgent(data)
    }

    fn poll(&mut self, timeout: Duration) -> rc_types::Result<Vec<NetEvent>> {
        self.transport.poll(timeout)
    }

    fn stats(&self) -> NetStats {
        self.transport.stats()
    }

    fn set_pacing_rate(&mut self, bps: u64) {
        self.transport.set_pacing_rate(bps);
    }

    fn tx_queued_bytes(&self) -> usize {
        self.transport.tx_queued_bytes()
    }

    fn tx_dropped_datagrams(&self) -> u64 {
        self.transport.tx_dropped_datagrams()
    }

    fn reliable_tx_queued_len(&self) -> usize {
        self.transport.reliable_tx_queued_len()
    }

    fn has_live_rtt(&self) -> bool {
        self.transport.has_live_rtt()
    }

    fn wake_handle(&self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        self.transport.wake_handle()
    }
}

/// 按收到音频包的 `(sample_rate, channels)` 校验/重建播放器（M9）：
/// 若格式与当前播放器不同，先调用旧播放器 `stop()` 再按新格式重建并同步静音态。
pub(in crate::session_bridge) fn ensure_audio_player_for_format(
    audio_player: &mut Option<Box<dyn AudioPlayer>>,
    audio_player_format: &mut Option<(u32, u8)>,
    sample_rate: u32,
    channels: u8,
    audio_muted: bool,
    make_player: impl FnOnce(u32, u8) -> Box<dyn AudioPlayer>,
) {
    let target_format = (sample_rate, channels);
    if *audio_player_format != Some(target_format) {
        if let Some(mut old_player) = audio_player.take() {
            old_player.stop();
        }
        let mut player = make_player(sample_rate, channels);
        player.set_muted(audio_muted);
        *audio_player = Some(player);
        *audio_player_format = Some(target_format);
    }
}

/// 将收到的音频帧包解码为线性 PCM16 采样；不支持的编码或非法包返回 `None`。
pub(in crate::session_bridge) fn decode_audio_packet_samples(
    pkt: &AudioFramePacket,
) -> Option<Vec<i16>> {
    match pkt.codec {
        AUDIO_CODEC_IMA_ADPCM => decode_ima_adpcm(&pkt.data, pkt.channels).ok(),
        AUDIO_CODEC_PCM16 => {
            if pkt.data.len() % 2 != 0 {
                return None;
            }
            let mut samples = Vec::with_capacity(pkt.data.len() / 2);
            for chunk in pkt.data.chunks_exact(2) {
                samples.push(i16::from_le_bytes([chunk[0], chunk[1]]));
            }
            Some(samples)
        }
        _ => None,
    }
}

/// 构造音频控制 JSON 载荷（`{"muted": bool}`）。
pub(in crate::session_bridge) fn encode_audio_ctrl_muted(muted: bool) -> Vec<u8> {
    serde_json::json!({ "muted": muted })
        .to_string()
        .into_bytes()
}

#[derive(Clone)]
pub(in crate::session_bridge) enum ActiveRelayInterrupt {
    Dialing(Arc<AtomicBool>),
    Connected(RelayShutdownHandle),
}

impl ActiveRelayInterrupt {
    pub(in crate::session_bridge) fn interrupt(&self) {
        match self {
            Self::Dialing(cancel) => cancel.store(true, Ordering::Release),
            Self::Connected(handle) => handle.shutdown(),
        }
    }
}

pub(in crate::session_bridge) struct RelayInterruptSlotGuard<'a> {
    pub(in crate::session_bridge) slot: &'a Mutex<Option<ActiveRelayInterrupt>>,
}

impl Drop for RelayInterruptSlotGuard<'_> {
    fn drop(&mut self) {
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// 构造控制端管线（硬件优先 + 假后端降级）。
pub(in crate::session_bridge) fn build_controller_pipeline(
    pcfg: &PipelineConfig,
    prefer_hardware: bool,
    session_start: Instant,
    preallocated_surface: Option<&PreallocatedRenderSurface>,
) -> rc_types::Result<BuiltPipeline> {
    if prefer_hardware {
        match try_hardware_controller_stack(pcfg, session_start, preallocated_surface) {
            Ok(hw) => return Ok(hw),
            Err(e) => {
                eprintln!(
                    "rc-ui: hardware controller stack unavailable, falling back to fake: {e}"
                );
            }
        }
        let (pipeline, renderer, pending_resize) = fake_controller_stack(pcfg)?;
        return Ok(BuiltPipeline {
            pipeline,
            backend_label: "fake(降级)".to_string(),
            renderer,
            pending_resize,
            layer_addr: 0,
            is_hardware: false,
        });
    }
    let _ = session_start;
    let (pipeline, renderer, pending_resize) = fake_controller_stack(pcfg)?;
    Ok(BuiltPipeline {
        pipeline,
        backend_label: "fake".to_string(),
        renderer,
        pending_resize,
        layer_addr: 0,
        is_hardware: false,
    })
}

/// 平台硬件解码 + 硬件渲染栈。
fn try_hardware_controller_stack(
    pcfg: &PipelineConfig,
    session_start: Instant,
    preallocated_surface: Option<&PreallocatedRenderSurface>,
) -> rc_types::Result<BuiltPipeline> {
    let mut hw_cfg = pcfg.clone();
    hw_cfg.prefer_hardware = true;
    let (decoder, dl) = rc_pipeline::select_decoder_labeled(&hw_cfg)?;
    if dl == "fake" {
        return Err(rc_types::Error::InvalidConfig(format!(
            "hardware decoder unavailable, got {dl}"
        )));
    }
    let hw_rend = crate::platform::create_hardware_renderer(
        pcfg.resolution.width,
        pcfg.resolution.height,
        session_start,
        preallocated_surface,
    )
    .map_err(rc_types::Error::InvalidConfig)?;
    let shared: RendererHandle = Arc::new(Mutex::new(hw_rend.renderer));
    let pending_resize = Arc::new(AtomicU64::new(0));
    let wrapper = SharedRenderer::new(Arc::clone(&shared), Arc::clone(&pending_resize));
    let pipeline = ControllerPipeline::with_backends(hw_cfg, decoder, Box::new(wrapper))?;
    Ok(BuiltPipeline {
        pipeline,
        backend_label: format!("{dl}+{}", hw_rend.label),
        renderer: shared,
        pending_resize,
        layer_addr: hw_rend.layer_addr,
        is_hardware: true,
    })
}

/// 假后端控制端栈：`FakeDecoder` + `FakeRenderer`。
pub(in crate::session_bridge) fn fake_controller_stack(
    pcfg: &PipelineConfig,
) -> rc_types::Result<(ControllerPipeline, RendererHandle, Arc<AtomicU64>)> {
    let decoder = rc_decode::FakeDecoder::new(rc_decode::FakeDecoderConfig {
        resolution: pcfg.resolution,
        ..rc_decode::FakeDecoderConfig::default()
    })?;
    let renderer = rc_render::FakeRenderer::new(rc_render::FakeRendererConfig {
        size: (pcfg.resolution.width, pcfg.resolution.height),
        ..rc_render::FakeRendererConfig::default()
    })?;
    let shared: RendererHandle = Arc::new(Mutex::new(Box::new(renderer)));
    let pending_resize = Arc::new(AtomicU64::new(0));
    let wrapper = SharedRenderer::new(Arc::clone(&shared), Arc::clone(&pending_resize));
    let mut fake_cfg = pcfg.clone();
    // 明确关闭假后端管线内部的 prefer_hardware，避免热切不同 codec 时误调硬件工厂报错锁死。
    fake_cfg.prefer_hardware = false;
    let pipeline =
        ControllerPipeline::with_backends(fake_cfg, Box::new(decoder), Box::new(wrapper))?;
    Ok((pipeline, shared, pending_resize))
}
