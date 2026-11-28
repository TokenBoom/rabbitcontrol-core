use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rc_audio::{AudioPlayer, NullAudioPlayer, PcmFrame};
use rc_input::{InputEvent, MouseButton};
use rc_render::Renderer;
use rc_session::{
    AudioFramePacket, ClipboardBackend, ToolPermissions, AUDIO_CODEC_IMA_ADPCM, AUDIO_CODEC_PCM16,
};

use super::super::adapters::{
    apply_stage_rect_nonblocking, decode_audio_packet_samples, ensure_audio_player_for_format,
    pack_stage_rect, LayerLease, RendererHandle, SharedRenderer, ToggleableClipboardBackend,
};
use super::super::display_ctrl::{is_persistent_decode_failure, try_clear_still_overlay};
use super::super::handle::{ScrollDispatchState, SessionHandle};
use super::super::queues::{
    flush_pending_tool_queue, BoundedInputQueue, BoundedQueue, BoundedUpdateQueue,
};
use super::super::tools::{FileClientWorker, ToolClientHub};
use super::super::types::{
    SessionCommand, UiSessionConfig, COMMAND_CHANNEL_CAP, CONSECUTIVE_DECODE_ERROR_LIMIT,
    INPUT_CHANNEL_CAP, PERSISTENT_DECODE_ERROR_MIN_ELAPSED,
};

#[test]
fn session_channels_are_bounded() {
    // 铁律 1 UI 侧延伸：常量钉死 64 / 256。
    assert_eq!(COMMAND_CHANNEL_CAP, 64);
    assert_eq!(INPUT_CHANNEL_CAP, 256);

    // 命令通道满载 64：再推不阻塞，丢最旧保留最新 64 条。
    let cmd_q: BoundedQueue<SessionCommand> = BoundedQueue::new(COMMAND_CHANNEL_CAP);
    for bps in 1..=100u32 {
        cmd_q.push_drop_oldest(SessionCommand::SetBitrate { bps });
    }
    assert_eq!(cmd_q.len(), COMMAND_CHANNEL_CAP);
    let drained = cmd_q.drain_all();
    assert_eq!(drained.len(), 64);
    assert_eq!(drained[0], SessionCommand::SetBitrate { bps: 37 });
    assert_eq!(drained[63], SessionCommand::SetBitrate { bps: 100 });

    // 输入通道满载 256：纯移动事件满载丢最旧、不阻塞。
    let input_q = BoundedInputQueue::new(INPUT_CHANNEL_CAP);
    for i in 0..300u16 {
        input_q.push(InputEvent::MouseMove { x: i, y: i });
    }
    assert_eq!(input_q.len(), INPUT_CHANNEL_CAP);
    let moves = input_q.drain_all();
    assert_eq!(moves.len(), 256);
    assert_eq!(moves[0], InputEvent::MouseMove { x: 44, y: 44 });
    assert_eq!(moves[255], InputEvent::MouseMove { x: 299, y: 299 });

    // 满载优先级：关键事件不被后续 MouseMove 挤掉。
    let key_ev = InputEvent::Key {
        scancode: 0x1E,
        pressed: true,
        modifiers: 0,
    };
    let click_ev = InputEvent::MouseButton {
        button: MouseButton::Left,
        pressed: true,
    };
    input_q.push(key_ev);
    input_q.push(click_ev);
    for i in 0..400u16 {
        input_q.push(InputEvent::MouseMove { x: i, y: 0 });
    }
    assert_eq!(input_q.len(), INPUT_CHANNEL_CAP);
    let mixed = input_q.drain_all();
    assert!(
        mixed.contains(&key_ev),
        "关键键盘事件不得被 MouseMove 挤占丢弃"
    );
    assert!(
        mixed.contains(&click_ev),
        "关键鼠标按键事件不得被 MouseMove 挤占丢弃"
    );
}

struct DropSpyRenderer {
    dropped: Arc<AtomicBool>,
}

impl Renderer for DropSpyRenderer {
    fn present(
        &mut self,
        _frame: rc_decode::DecodedFrame,
    ) -> rc_types::Result<rc_types::Timestamp> {
        Ok(rc_types::Timestamp(0))
    }

    fn resize(&mut self, _size: (u32, u32)) -> rc_types::Result<()> {
        Ok(())
    }

    fn set_vsync(&mut self, _on: bool) {}

    fn set_cursor(&mut self, _pos: (i32, i32), _visible: bool) {}
}

impl Drop for DropSpyRenderer {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn layer_lease_keeps_renderer_alive_until_last_clone_drops() {
    let dropped = Arc::new(AtomicBool::new(false));
    let renderer: RendererHandle = Arc::new(Mutex::new(Box::new(DropSpyRenderer {
        dropped: Arc::clone(&dropped),
    })));

    // 地址为 0 时不得构造租约（假后端路径）。
    assert!(LayerLease::from_renderer(Arc::clone(&renderer), 0).is_none());

    let lease = LayerLease::from_renderer(Arc::clone(&renderer), 0x1234_5678)
        .expect("non-zero layer addr should construct lease");
    assert_eq!(lease.addr(), 0x1234_5678);
    assert_eq!(lease.as_ptr() as usize, 0x1234_5678);

    // 模拟会话线程退出、释放管线与本地 RendererHandle。
    drop(renderer);
    assert!(
        !dropped.load(Ordering::SeqCst),
        "会话线程释放渲染器后，LayerLease 必须继续保活底层 MetalRenderer"
    );

    // 模拟主线程闭包 clone 租约后原持有者释放。
    let cloned = lease.clone();
    assert!(lease.same_layer(&cloned));
    drop(lease);
    assert!(
        !dropped.load(Ordering::SeqCst),
        "主线程闭包仍持有 clone 租约期间不得释放渲染器"
    );

    // 相同地址但不同渲染器实例必须判定为不同层（防 ABA）。
    let other_dropped = Arc::new(AtomicBool::new(false));
    let other_renderer: RendererHandle = Arc::new(Mutex::new(Box::new(DropSpyRenderer {
        dropped: Arc::clone(&other_dropped),
    })));
    let other_lease = LayerLease::from_renderer(other_renderer, 0x1234_5678).unwrap();
    assert!(!cloned.same_layer(&other_lease));

    drop(cloned);
    assert!(
        dropped.load(Ordering::SeqCst),
        "最后一份 LayerLease 释放后底层渲染器应立即析构"
    );
    drop(other_lease);
    assert!(other_dropped.load(Ordering::SeqCst));
}

#[test]
fn toggleable_clipboard_backend_respects_enabled_flag() {
    let fake = rc_session::testkit::SharedFakeClipboard::new();
    fake.simulate_local_copy(Some("initial"));
    let flag = Arc::new(AtomicBool::new(false));
    let mut backend = ToggleableClipboardBackend::new(Box::new(fake.clone()), Arc::clone(&flag));

    // 禁用态：不读取真实内容，也不写回本地剪贴板。
    assert_eq!(backend.read_text().unwrap(), None);
    backend.write_text("from-peer-while-disabled").unwrap();
    assert!(fake.writes().is_empty());
    let frozen_count = backend.change_count().unwrap();
    fake.simulate_local_copy(Some("changed-while-disabled"));
    assert_eq!(backend.change_count().unwrap(), frozen_count);

    // 启用态：正常读写并推进变更计数。
    flag.store(true, Ordering::Release);
    assert!(backend.change_count().unwrap() > frozen_count);
    assert_eq!(
        backend.read_text().unwrap(),
        Some("changed-while-disabled".to_string())
    );
    backend.write_text("from-peer-enabled").unwrap();
    assert_eq!(fake.writes(), vec!["from-peer-enabled".to_string()]);
}

#[test]
fn audio_packet_decoding_supports_ima_adpcm_and_pcm16() {
    use rc_audio::AudioCapture;

    let pcm = vec![1000i16, -1000, 2000, -2000, 3000, -3000];
    let mut pcm_bytes = Vec::with_capacity(pcm.len() * 2);
    for &s in &pcm {
        pcm_bytes.extend_from_slice(&s.to_le_bytes());
    }
    let pcm_pkt = AudioFramePacket {
        seq: 1,
        timestamp_us: 0,
        sample_rate: 48_000,
        channels: 2,
        codec: AUDIO_CODEC_PCM16,
        data: pcm_bytes,
    };
    assert_eq!(decode_audio_packet_samples(&pcm_pkt), Some(pcm));

    let mut cap = rc_audio::FakeAudioCapture::new();
    let frame = cap.try_recv_frame().expect("fake audio frame");
    let encoded = rc_audio::encode_ima_adpcm(&frame.samples, frame.channels);
    let adpcm_pkt = AudioFramePacket {
        seq: 2,
        timestamp_us: frame.timestamp_us,
        sample_rate: frame.sample_rate,
        channels: frame.channels,
        codec: AUDIO_CODEC_IMA_ADPCM,
        data: encoded,
    };
    let decoded = decode_audio_packet_samples(&adpcm_pkt).expect("decode IMA-ADPCM");
    assert_eq!(decoded.len(), frame.samples.len());

    let bad_pkt = AudioFramePacket {
        seq: 3,
        timestamp_us: 0,
        sample_rate: 48_000,
        channels: 2,
        codec: 99,
        data: vec![1, 2, 3, 4],
    };
    assert_eq!(decode_audio_packet_samples(&bad_pkt), None);
}

#[test]
fn ensure_audio_player_recreates_and_stops_old_player_on_format_change() {
    struct SpyAudioPlayer {
        stopped: Arc<AtomicBool>,
        muted: Arc<AtomicBool>,
    }

    impl AudioPlayer for SpyAudioPlayer {
        fn push_frame(&mut self, _frame: &PcmFrame) -> Result<(), String> {
            Ok(())
        }
        fn set_muted(&mut self, muted: bool) {
            self.muted.store(muted, Ordering::SeqCst);
        }
        fn is_muted(&self) -> bool {
            self.muted.load(Ordering::SeqCst)
        }
        fn stop(&mut self) {
            self.stopped.store(true, Ordering::SeqCst);
        }
    }

    let mut player: Option<Box<dyn AudioPlayer>> = None;
    let mut format: Option<(u32, u8)> = None;
    let stopped_1 = Arc::new(AtomicBool::new(false));
    let muted_1 = Arc::new(AtomicBool::new(false));
    let stopped_2 = Arc::new(AtomicBool::new(false));
    let muted_2 = Arc::new(AtomicBool::new(false));
    let mut created_formats: Vec<(u32, u8)> = Vec::new();

    ensure_audio_player_for_format(&mut player, &mut format, 48_000, 2, false, |sr, ch| {
        created_formats.push((sr, ch));
        Box::new(SpyAudioPlayer {
            stopped: Arc::clone(&stopped_1),
            muted: Arc::clone(&muted_1),
        })
    });
    assert_eq!(format, Some((48_000, 2)));
    assert_eq!(created_formats, vec![(48_000, 2)]);
    assert!(!stopped_1.load(Ordering::SeqCst));

    // 相同格式不重建播放器。
    ensure_audio_player_for_format(&mut player, &mut format, 48_000, 2, false, |sr, ch| {
        created_formats.push((sr, ch));
        Box::new(NullAudioPlayer::new())
    });
    assert_eq!(created_formats, vec![(48_000, 2)]);
    assert!(!stopped_1.load(Ordering::SeqCst));

    // 格式切换到 44.1kHz 单声道且静音态为 true：旧播放器必须被 stop()，新播放器继承 muted=true。
    ensure_audio_player_for_format(&mut player, &mut format, 44_100, 1, true, |sr, ch| {
        created_formats.push((sr, ch));
        Box::new(SpyAudioPlayer {
            stopped: Arc::clone(&stopped_2),
            muted: Arc::clone(&muted_2),
        })
    });
    assert!(
        stopped_1.load(Ordering::SeqCst),
        "格式变更时必须先 stop() 旧 AudioPlayer"
    );
    assert_eq!(format, Some((44_100, 1)));
    assert_eq!(created_formats, vec![(48_000, 2), (44_100, 1)]);
    assert!(muted_2.load(Ordering::SeqCst));
    assert!(!stopped_2.load(Ordering::SeqCst));
}

#[test]
fn flush_pending_tool_queue_retains_unsent_frames_on_backpressure() {
    let mut q: VecDeque<Vec<u8>> = vec![vec![1], vec![2], vec![3]].into();
    let mut delivered = Vec::new();
    let mut calls = 0usize;

    let sent_any = flush_pending_tool_queue(&mut q, |frame| {
        calls += 1;
        if calls == 2 {
            Err("full")
        } else {
            delivered.push(frame);
            Ok(())
        }
    });
    assert!(sent_any);
    assert_eq!(delivered, vec![vec![1]]);
    assert_eq!(q.len(), 2);

    let sent_rest = flush_pending_tool_queue(&mut q, |frame| {
        delivered.push(frame);
        Ok::<(), ()>(())
    });
    assert!(sent_rest);
    assert!(q.is_empty());
    assert_eq!(delivered, vec![vec![1], vec![2], vec![3]]);
}

#[test]
fn persistent_decode_failure_triggers_only_for_hw_zero_displayed_over_threshold() {
    let min = PERSISTENT_DECODE_ERROR_MIN_ELAPSED;
    let limit = CONSECUTIVE_DECODE_ERROR_LIMIT;

    // 达标场景：硬件解码器 + displayed==0 + 达到连续错误阈值与最小时长 → true。
    assert!(is_persistent_decode_failure(true, 0, limit, min));
    assert!(is_persistent_decode_failure(
        true,
        0,
        limit + 50,
        min + Duration::from_secs(2)
    ));

    // 假后端测试 / 非硬件解码器 → false。
    assert!(!is_persistent_decode_failure(false, 0, limit + 100, min));
    // 已有成功上屏帧（后续偶发解码错）→ false。
    assert!(!is_persistent_decode_failure(true, 1, limit + 100, min));
    // 静止屏幕（0 帧，0 错误）→ false。
    assert!(!is_persistent_decode_failure(
        true,
        0,
        0,
        Duration::from_secs(60)
    ));
    // 尚未达到错误次数或观察时长 → false。
    assert!(!is_persistent_decode_failure(true, 0, limit - 1, min));
    assert!(!is_persistent_decode_failure(
        true,
        0,
        limit,
        min - Duration::from_millis(1)
    ));
}

/// 对抗评审 High #2 回归：`rend.try_lock()` 争用期间保留 `pending_still_clear == true` 与
/// `has_active_overlay() == true`，锁释放后重试必须真正调用 `clear_still_tiles()` 清除叠加层。
#[test]
fn try_clear_still_overlay_retries_after_try_lock_contention() {
    let mut fake = rc_render::FakeRenderer::new(rc_render::FakeRendererConfig::default()).unwrap();
    let patch = rc_render::StillTilePatch {
        stream_epoch: 1,
        base_frame_seq: 1,
        rect: rc_types::Rect::new(0, 0, 4, 4),
        format: rc_types::PixelFormat::Bgra8,
        pixels: vec![0x77; 4 * 4 * 4],
    };
    fake.apply_still_tile(&patch).expect("apply initial tile");
    assert_eq!(fake.active_still_tiles().len(), 1);

    let rend_arc: RendererHandle = Arc::new(Mutex::new(Box::new(fake)));
    let rend_slot = Mutex::new(Some(Arc::clone(&rend_arc)));
    let mut receiver = crate::still_refine::StillRefineReceiver::new(1, 1920, 1080);
    receiver
        .validate_and_accept(&patch, 32)
        .expect("accept patch");
    assert!(receiver.has_active_overlay());
    let mut pending_still_clear = false;

    // 模拟异步解码线程在 present() 期间持有渲染器锁：try_clear 必须返回 false 且不提前清零标志。
    let guard = rend_arc.lock().unwrap();
    assert!(!try_clear_still_overlay(
        &rend_slot,
        &mut receiver,
        &mut pending_still_clear
    ));
    assert!(pending_still_clear);
    assert!(receiver.has_active_overlay());
    drop(guard);

    // 异步解码线程释放锁后，下一拍重试必须真正清空渲染器叠加层并复原标志。
    assert!(try_clear_still_overlay(
        &rend_slot,
        &mut receiver,
        &mut pending_still_clear
    ));
    assert!(!pending_still_clear);
    assert!(!receiver.has_active_overlay());

    // 确认底层 FakeRenderer 的活跃叠加层确实已被清空（借用 apply/clear 行为反向验证）。
    let next_patch = rc_render::StillTilePatch {
        stream_epoch: 1,
        base_frame_seq: 2,
        rect: rc_types::Rect::new(128, 128, 4, 4),
        format: rc_types::PixelFormat::Bgra8,
        pixels: vec![0x88; 4 * 4 * 4],
    };
    rend_arc
        .lock()
        .unwrap()
        .apply_still_tile(&next_patch)
        .expect("renderer remains healthy after clear");
}

#[test]
fn apply_stage_rect_nonblocking_defers_under_contention_and_applies_before_present() {
    #[derive(Debug, PartialEq, Eq)]
    enum Op {
        Resize(u32, u32),
        Present(u32),
    }

    struct RecordingOpsRenderer {
        ops: Arc<Mutex<Vec<Op>>>,
    }

    impl Renderer for RecordingOpsRenderer {
        fn present(
            &mut self,
            frame: rc_decode::DecodedFrame,
        ) -> rc_types::Result<rc_types::Timestamp> {
            self.ops
                .lock()
                .unwrap()
                .push(Op::Present(frame.decode_done_ts.0));
            Ok(frame.decode_done_ts)
        }

        fn resize(&mut self, size: (u32, u32)) -> rc_types::Result<()> {
            self.ops.lock().unwrap().push(Op::Resize(size.0, size.1));
            Ok(())
        }

        fn set_vsync(&mut self, _on: bool) {}
        fn set_cursor(&mut self, _pos: (i32, i32), _visible: bool) {}
    }

    let ops = Arc::new(Mutex::new(Vec::new()));
    let inner: RendererHandle = Arc::new(Mutex::new(Box::new(RecordingOpsRenderer {
        ops: Arc::clone(&ops),
    })));
    let pending_resize = Arc::new(AtomicU64::new(0));
    let mut shared_renderer = SharedRenderer::new(Arc::clone(&inner), Arc::clone(&pending_resize));

    // 1) While renderer mutex is held (simulating nextDrawable stall), apply_stage_rect_nonblocking
    //    must return immediately without blocking and store packed dimensions.
    let guard = inner.lock().unwrap();
    let applied_now = apply_stage_rect_nonblocking(&inner, &pending_resize, 1600, 900);
    assert!(!applied_now);
    assert_eq!(
        pending_resize.load(Ordering::Acquire),
        pack_stage_rect(1600, 900)
    );
    // Latest contended resize overwrites earlier pending dimensions.
    assert!(!apply_stage_rect_nonblocking(
        &inner,
        &pending_resize,
        1920,
        1080
    ));
    assert_eq!(
        pending_resize.load(Ordering::Acquire),
        pack_stage_rect(1920, 1080)
    );
    assert!(ops.lock().unwrap().is_empty());
    drop(guard);

    // 2) Next SharedRenderer::present() must apply pending resize(1920, 1080) BEFORE present(frame),
    //    and clear pending_resize to 0.
    let frame = rc_decode::DecodedFrame {
        decode_done_ts: rc_types::Timestamp(150),
        width: 64,
        height: 64,
        texture: rc_capture::FrameTexture::Cpu(rc_types::CpuFrame {
            width: 64,
            height: 64,
            format: rc_types::PixelFormat::Bgra8,
            stride: 64 * 4,
            data: vec![0u8; 64 * 64 * 4],
        }),
    };
    shared_renderer.present(frame).expect("present");
    assert_eq!(pending_resize.load(Ordering::Acquire), 0);
    assert_eq!(
        *ops.lock().unwrap(),
        vec![Op::Resize(1920, 1080), Op::Present(150)]
    );

    // 3) Uncontended apply_stage_rect_nonblocking applies immediately and clears any stale pending value.
    pending_resize.store(pack_stage_rect(800, 600), Ordering::Release);
    assert!(apply_stage_rect_nonblocking(
        &inner,
        &pending_resize,
        2560,
        1440
    ));
    assert_eq!(pending_resize.load(Ordering::Acquire), 0);
    assert_eq!(
        *ops.lock().unwrap(),
        vec![
            Op::Resize(1920, 1080),
            Op::Present(150),
            Op::Resize(2560, 1440)
        ]
    );
}

/// `SessionHandle::send_ui_input` 根据 `ScrollDispatchState`（对端是否支持 `SUPPORTS_PIXEL_SCROLL`）
/// 与 `WheelAccumulator` 分发 `MouseWheelPixel` 或回退 `MouseWheel`（行）。
#[test]
fn session_scroll_dispatch_routes_pixel_vs_legacy_line_mode() {
    let input_tx = Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP));
    let scroll_state = Arc::new(ScrollDispatchState::new());
    let running = Arc::new(AtomicBool::new(true));
    let watch_only = Arc::new(AtomicBool::new(false));
    let (fw, fh) = FileClientWorker::spawn(Arc::new(BoundedQueue::new(8)));
    let handle = SessionHandle {
        cmd_tx: Arc::new(BoundedQueue::new(8)),
        display_ctrl_tx: Arc::new(BoundedQueue::new(8)),
        input_tx: Arc::clone(&input_tx),
        update_rx: Arc::new(BoundedUpdateQueue::new(8)),
        file_event_rx: Arc::new(BoundedQueue::new(8)),
        terminal_event_rx: Arc::new(BoundedQueue::new(8)),
        portmap_latest: Arc::new(Mutex::new(None)),
        tools_hub: Arc::new(Mutex::new(ToolClientHub::new())),
        file_handle: fh,
        disconnect_flag: Arc::new(AtomicBool::new(false)),
        lock_on_disconnect: Arc::new(AtomicBool::new(false)),
        relay_interrupt: Arc::new(Mutex::new(None)),
        running,
        watch_only,
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        still_refine_metrics: Arc::new(Mutex::new(
            crate::still_refine::StillRefineMetrics::default(),
        )),
        scroll_state: Arc::clone(&scroll_state),
        encrypt_connection: false,
        base_config: UiSessionConfig::default(),
        layer_lease: Arc::new(Mutex::new(None)),
        upgrade_surface: Arc::new(Mutex::new(None)),
        thread: None,
    };

    // 1) 默认/旧端（supports_pixel_scroll = false）：8 次 2px 微滚动无损累积出 1 条 MouseWheel(-1)
    assert!(!handle.peer_supports_pixel_scroll());
    for _ in 0..8 {
        handle.send_wheel(0.0, 2.0, 16.0, 0);
    }
    assert_eq!(
        input_tx.drain_all(),
        vec![InputEvent::MouseWheel {
            delta: -1,
            horizontal: false
        }]
    );

    // 2) 新端（supports_pixel_scroll = true）：delta_mode=0 直接累积输出 MouseWheelPixel（轴向与 CGEvent 一致）
    scroll_state.update_peer_capability(true);
    assert!(handle.peer_supports_pixel_scroll());
    handle.send_wheel(3.0, 5.0, 16.0, 0);
    assert_eq!(
        input_tx.drain_all(),
        vec![InputEvent::MouseWheelPixel { dx: -3, dy: -5 }]
    );

    // 3) 新端收到 delta_mode=1（离散行滚轮）时仍走 MouseWheel 行单位
    handle.send_wheel(0.0, -2.0, 16.0, 1);
    assert_eq!(
        input_tx.drain_all(),
        vec![InputEvent::MouseWheel {
            delta: 2,
            horizontal: false
        }]
    );
    drop(fw);
}

#[test]
fn shared_renderer_set_cursor_defers_nonblocking_under_contention() {
    type RecordedCursors = Arc<Mutex<Vec<((i32, i32), bool)>>>;
    struct CursorStubRenderer {
        cursors: RecordedCursors,
        presented: usize,
    }
    impl Renderer for CursorStubRenderer {
        fn present(
            &mut self,
            _frame: rc_decode::DecodedFrame,
        ) -> rc_types::Result<rc_types::Timestamp> {
            self.presented += 1;
            Ok(rc_types::Timestamp(self.presented as u32))
        }
        fn resize(&mut self, _size: (u32, u32)) -> rc_types::Result<()> {
            Ok(())
        }
        fn set_vsync(&mut self, _on: bool) {}
        fn set_cursor(&mut self, pos: (i32, i32), visible: bool) {
            self.cursors.lock().unwrap().push((pos, visible));
        }
    }

    let recorded_cursors = Arc::new(Mutex::new(Vec::new()));
    let inner: RendererHandle = Arc::new(Mutex::new(Box::new(CursorStubRenderer {
        cursors: Arc::clone(&recorded_cursors),
        presented: 0,
    })));
    let pending_resize = Arc::new(AtomicU64::new(0));
    let mut shared = SharedRenderer::new(Arc::clone(&inner), Arc::clone(&pending_resize));

    // 模拟渲染线程正在持有 renderer mutex（等待 CAMetalLayer::nextDrawable）：
    // set_cursor 绝不能阻塞，必须写入 pending_cursor 并立即返回。
    let lock_guard = inner.lock().unwrap();
    shared.set_cursor((100, 200), true);
    shared.set_cursor((320, 480), false);
    assert_eq!(
        *shared.pending_cursor.lock().unwrap(),
        Some((320, 480, false))
    );
    assert!(recorded_cursors.lock().unwrap().is_empty());
    drop(lock_guard);

    // 下一次 present 在持锁区间原子补刷最后一次挂起光标。
    let dummy_frame = rc_decode::DecodedFrame {
        decode_done_ts: rc_types::Timestamp(1),
        width: 64,
        height: 64,
        texture: rc_capture::FrameTexture::Cpu(rc_types::CpuFrame {
            width: 64,
            height: 64,
            format: rc_types::PixelFormat::Bgra8,
            stride: 64 * 4,
            data: vec![0u8; 64 * 64 * 4],
        }),
    };
    shared.present(dummy_frame).unwrap();
    assert_eq!(*shared.pending_cursor.lock().unwrap(), None);
    assert_eq!(*recorded_cursors.lock().unwrap(), vec![((320, 480), false)]);

    // 无锁竞争时 set_cursor 直达底层渲染器。
    shared.set_cursor((10, 20), true);
    assert_eq!(*shared.pending_cursor.lock().unwrap(), None);
    assert_eq!(
        *recorded_cursors.lock().unwrap(),
        vec![((320, 480), false), ((10, 20), true)]
    );
}

#[test]
fn session_input_handle_and_wake_hook_notify_on_empty_to_nonempty_and_skip_wheel_lock() {
    let input_tx = Arc::new(BoundedInputQueue::new(INPUT_CHANNEL_CAP));
    let wake_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let wake_hits_cb = Arc::clone(&wake_hits);
    input_tx.set_wake_handle(Some(Arc::new(move || {
        wake_hits_cb.fetch_add(1, Ordering::Relaxed);
    })));

    let scroll_state = Arc::new(ScrollDispatchState::new());
    let running = Arc::new(AtomicBool::new(true));
    let watch_only = Arc::new(AtomicBool::new(false));
    let (fw, fh) = FileClientWorker::spawn(Arc::new(BoundedQueue::new(8)));
    let handle = SessionHandle {
        cmd_tx: Arc::new(BoundedQueue::new(8)),
        display_ctrl_tx: Arc::new(BoundedQueue::new(8)),
        input_tx: Arc::clone(&input_tx),
        update_rx: Arc::new(BoundedUpdateQueue::new(8)),
        file_event_rx: Arc::new(BoundedQueue::new(8)),
        terminal_event_rx: Arc::new(BoundedQueue::new(8)),
        portmap_latest: Arc::new(Mutex::new(None)),
        tools_hub: Arc::new(Mutex::new(ToolClientHub::new())),
        file_handle: fh,
        disconnect_flag: Arc::new(AtomicBool::new(false)),
        lock_on_disconnect: Arc::new(AtomicBool::new(false)),
        relay_interrupt: Arc::new(Mutex::new(None)),
        running,
        watch_only,
        tool_permissions: Arc::new(Mutex::new(ToolPermissions::all_allowed())),
        still_refine_metrics: Arc::new(Mutex::new(
            crate::still_refine::StillRefineMetrics::default(),
        )),
        scroll_state: Arc::clone(&scroll_state),
        encrypt_connection: false,
        base_config: UiSessionConfig::default(),
        layer_lease: Arc::new(Mutex::new(None)),
        upgrade_surface: Arc::new(Mutex::new(None)),
        thread: None,
    };

    let input_handle = handle.input_handle();
    // 即使 wheel_accumulator 被其他线程/事件占用，非滚轮鼠标移动仍无阻塞投递并唤醒发送端。
    let _wheel_guard = scroll_state.wheel_accumulator.lock().unwrap();
    let unmapped = input_handle.send_ui_input(
        &crate::input_bridge::UiInputEvent::MouseMove {
            x: 100.0,
            y: 100.0,
            stage_w: 200.0,
            stage_h: 200.0,
        },
        Some((1920, 1080)),
    );
    assert!(!unmapped);
    assert_eq!(wake_hits.load(Ordering::Relaxed), 1);

    // 队列非空时继续追加不会重复触发唤醒；排空后下一次由空转非空再次触发。
    input_handle.send_input(InputEvent::MouseButton {
        button: rc_input::MouseButton::Left,
        pressed: true,
    });
    assert_eq!(wake_hits.load(Ordering::Relaxed), 1);
    assert_eq!(input_tx.drain_all().len(), 2);

    input_handle.send_input(InputEvent::MouseButton {
        button: rc_input::MouseButton::Left,
        pressed: false,
    });
    assert_eq!(wake_hits.load(Ordering::Relaxed), 2);
    drop(fw);
}
