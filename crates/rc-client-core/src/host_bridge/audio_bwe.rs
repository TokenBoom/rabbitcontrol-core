use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use rc_audio::{encode_ima_adpcm, AudioCapture, AudioSilenceGate};
use rc_session::{AudioFramePacket, HostSession, AUDIO_CODEC_IMA_ADPCM};

use super::types::{
    HostTransportKind, AUDIO_RECOVERY_INITIAL_BACKOFF, AUDIO_RECOVERY_MAX_BACKOFF,
    AUDIO_RECOVERY_MID_BACKOFF, AUDIO_RECOVERY_STABLE_WINDOW, MAX_AUDIO_FRAMES_PER_TICK,
    RELAY_BACKOFF_COOLDOWN, RELAY_DROP_BURST_THRESHOLD, RELAY_HIGH_QUEUE_HOLD,
    RELAY_MIN_BITRATE_BPS, RELAY_QUEUE_HIGH_BYTES, RELAY_QUEUE_LOW_BYTES, RELAY_RAMP_INTERVAL,
};

fn next_audio_recovery_backoff(cur: Duration) -> Duration {
    if cur < AUDIO_RECOVERY_MID_BACKOFF {
        AUDIO_RECOVERY_MID_BACKOFF
    } else {
        AUDIO_RECOVERY_MAX_BACKOFF
    }
}

/// 在独立后台线程异步拉起系统音频采集器，绝不在 `Welcome` 后同步阻塞首帧出图（H13）。
/// 若会话在后台线程完成前退出并丢弃接收端，后台线程立即停止并释放刚创建的采集器。
fn spawn_audio_capture_init() -> mpsc::Receiver<Box<dyn AudioCapture>> {
    spawn_audio_capture_init_with(rc_audio::create_system_audio_capture)
}

fn spawn_audio_capture_init_with<F>(creator: F) -> mpsc::Receiver<Box<dyn AudioCapture>>
where
    F: FnOnce() -> Result<Box<dyn AudioCapture>, String> + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel::<Box<dyn AudioCapture>>(1);
    let _ = thread::Builder::new()
        .name("rc-audio-cap-init".to_string())
        .spawn(move || {
            if let Ok(cap) = creator() {
                if let Err(mpsc::SendError(mut cap)) = tx.send(cap) {
                    cap.stop();
                    drop(cap);
                }
            }
        });
    rx
}

pub(super) type AudioCaptureCreator =
    Arc<dyn Fn() -> Result<Box<dyn AudioCapture>, String> + Send + Sync>;

/// 被控端音频采集生命周期与有界退避自愈管理器（`300ms -> 1s -> 2s`）：
/// - 检测底层 `AudioCapture::is_stopped()`（如 macOS 改物理分辨率或切屏导致 SCStream 中止）时立即停止并重建；
/// - 异步初始化失败（如锁屏期无音频流）按有界退避重试；
/// - 纯工具态 `media_paused == true` 时主动停流且禁止拉起自愈。
pub(super) struct HostAudioManager {
    enabled: bool,
    pub(super) capture: Option<Box<dyn AudioCapture>>,
    started_at: Option<Instant>,
    init_rx: Option<mpsc::Receiver<Box<dyn AudioCapture>>>,
    pub(super) retry_at: Option<Instant>,
    pub(super) retry_backoff: Duration,
    creator: Option<AudioCaptureCreator>,
}

impl HostAudioManager {
    pub(super) fn new(enabled: bool) -> Self {
        let mut mgr = Self {
            enabled,
            capture: None,
            started_at: None,
            init_rx: None,
            retry_at: None,
            retry_backoff: AUDIO_RECOVERY_INITIAL_BACKOFF,
            creator: None,
        };
        if enabled {
            mgr.start_init();
        }
        mgr
    }

    #[cfg(test)]
    pub(super) fn with_creator(
        enabled: bool,
        initial_capture: Option<Box<dyn AudioCapture>>,
        creator: AudioCaptureCreator,
    ) -> Self {
        let started_at = initial_capture.as_ref().map(|_| Instant::now());
        let mut mgr = Self {
            enabled,
            capture: initial_capture,
            started_at,
            init_rx: None,
            retry_at: None,
            retry_backoff: AUDIO_RECOVERY_INITIAL_BACKOFF,
            creator: Some(creator),
        };
        if enabled && mgr.capture.is_none() {
            mgr.start_init();
        }
        mgr
    }

    fn start_init(&mut self) {
        if !self.enabled {
            return;
        }
        let rx = match &self.creator {
            Some(factory) => {
                let f = Arc::clone(factory);
                spawn_audio_capture_init_with(move || f())
            }
            None => spawn_audio_capture_init(),
        };
        self.init_rx = Some(rx);
    }

    pub(super) fn pause(&mut self, silence_gate: &mut AudioSilenceGate) {
        self.stop_all();
        silence_gate.reset();
        self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
    }

    pub(super) fn resume(&mut self, silence_gate: &mut AudioSilenceGate) {
        if !self.enabled {
            return;
        }
        silence_gate.reset();
        self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
        self.retry_at = None;
        if self.capture.is_none() && self.init_rx.is_none() {
            self.start_init();
        }
    }

    pub(super) fn reset_backoff_for_display_change(&mut self, now: Instant) {
        self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
        let fast_at = now + AUDIO_RECOVERY_INITIAL_BACKOFF;
        if self.retry_at.is_some_and(|at| at > fast_at) {
            self.retry_at = Some(fast_at);
        }
    }

    pub(super) fn poll_and_recover(
        &mut self,
        now: Instant,
        media_paused: bool,
        silence_gate: &mut AudioSilenceGate,
    ) {
        if !self.enabled || media_paused {
            return;
        }

        if let Some(cap) = self.capture.as_ref() {
            let stable = self.started_at.is_some_and(|at| {
                now.saturating_duration_since(at) >= AUDIO_RECOVERY_STABLE_WINDOW
            });
            if cap.is_stopped() {
                if stable {
                    self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
                }
                if let Some(mut old) = self.capture.take() {
                    old.stop();
                }
                self.started_at = None;
                silence_gate.reset();
                let delay = self.retry_backoff;
                self.retry_at = Some(now + delay);
                self.retry_backoff = next_audio_recovery_backoff(delay);
                eprintln!(
                    "[rc-ui-host] 检测到系统音频采集已中止，预约 {}ms 后自动重建",
                    delay.as_millis()
                );
            } else if stable {
                self.retry_backoff = AUDIO_RECOVERY_INITIAL_BACKOFF;
            }
        }

        if self.capture.is_none() {
            if let Some(ref rx) = self.init_rx {
                match rx.try_recv() {
                    Ok(cap) => {
                        self.capture = Some(cap);
                        self.started_at = Some(now);
                        self.init_rx = None;
                        self.retry_at = None;
                        // 不在刚创建时立即复位 retry_backoff：需稳定存活 >= 5s 后才复位回 300ms，
                        // 防止采集器刚创建即 is_stopped() 退化为固定 300ms 高频重建抖动。
                        silence_gate.reset();
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.init_rx = None;
                        let delay = self.retry_backoff;
                        self.retry_at = Some(now + delay);
                        self.retry_backoff = next_audio_recovery_backoff(delay);
                    }
                }
            }
        }

        if self.capture.is_none()
            && self.init_rx.is_none()
            && self.retry_at.is_some_and(|at| now >= at)
        {
            self.retry_at = None;
            self.start_init();
        }
    }

    pub(super) fn capture_mut(&mut self) -> Option<&mut Box<dyn AudioCapture>> {
        self.capture.as_mut()
    }

    pub(super) fn stop_all(&mut self) {
        // 先释放异步初始化接收端，确保尚未完成的 `rc-audio-cap-init` 线程立即感知并停止释放采集器（H13）。
        self.init_rx = None;
        if let Some(ref mut cap) = self.capture {
            cap.stop();
        }
        self.capture = None;
        self.started_at = None;
        self.retry_at = None;
    }
}

impl Drop for HostAudioManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}

/// 解析来自控制端 `TOOL_CHANNEL_AUDIO_CTRL` 的静音控制 JSON（`{"muted": bool}`）。
pub(super) fn parse_audio_ctrl_muted(payload: &[u8]) -> Option<bool> {
    let val: serde_json::Value = serde_json::from_slice(payload).ok()?;
    val.get("muted").and_then(serde_json::Value::as_bool)
}

/// 单拍泵送主机侧音频采集：`suppress_send == false` 且通过静音抑制门控（DTX）时编码 IMA-ADPCM 并发送；
/// 静音、Stream A 工具通道背压（`suppress_send == true`）或连续无声期仅排空陈旧缓冲不发送，
/// 消除空闲桌面持续 ~384–410 Kbps 的无效静音音频带宽占用（M9）。
pub(super) fn pump_host_audio(
    host: &mut HostSession,
    capture: &mut dyn AudioCapture,
    suppress_send: bool,
    silence_gate: &mut AudioSilenceGate,
    audio_seq: &mut u32,
) -> bool {
    let mut busy = false;
    for _ in 0..MAX_AUDIO_FRAMES_PER_TICK {
        let Some(frame) = capture.try_recv_frame() else {
            break;
        };
        busy = true;
        if suppress_send || frame.samples.is_empty() {
            continue;
        }
        if !silence_gate.should_transmit(&frame.samples) {
            continue;
        }
        let data = encode_ima_adpcm(&frame.samples, frame.channels);
        let seq = *audio_seq;
        *audio_seq = audio_seq.wrapping_add(1);
        let _ = host.send_audio_frame(AudioFramePacket {
            seq,
            timestamp_us: frame.timestamp_us,
            sample_rate: frame.sample_rate,
            channels: frame.channels,
            codec: AUDIO_CODEC_IMA_ADPCM,
            data,
        });
    }
    busy
}

/// 被控端 TCP Relay 连续码率控制器：将手动上限、`local_bps`（发送队列/淘汰 AIMD）与
/// 对端控制端 RTT 限速上限（`remote_probe_cap_bps`）解耦，恒取三者最小值以避免双端抢权互盖。
pub(super) struct RelayBitrateController {
    manual_cap_bps: u32,
    local_bps: u32,
    remote_probe_cap_bps: Option<u32>,
    last_dropped: u64,
    drop_streak: u32,
    high_queue_since: Option<Instant>,
    last_adjust: Instant,
    clean_since: Instant,
    last_manual_seen: Option<(u64, u32)>,
    last_remote_probe_seen: Option<u32>,
}

impl RelayBitrateController {
    pub(super) fn new(initial_bps: u32, now: Instant) -> Self {
        let cap = initial_bps.max(1);
        Self {
            manual_cap_bps: cap,
            local_bps: cap,
            remote_probe_cap_bps: None,
            last_dropped: 0,
            drop_streak: 0,
            high_queue_since: None,
            last_adjust: now,
            clean_since: now,
            last_manual_seen: None,
            last_remote_probe_seen: None,
        }
    }

    pub(super) fn effective_bps(&self) -> u32 {
        self.local_bps
            .min(self.remote_probe_cap_bps.unwrap_or(self.manual_cap_bps))
            .min(self.manual_cap_bps)
            .max(1)
    }

    pub(super) fn sync_external_caps(
        &mut self,
        manual: Option<(u64, u32)>,
        remote_probe_bps: Option<u32>,
        current_host_bps: u32,
        now: Instant,
    ) -> Option<u32> {
        if let Some((gen, m)) = manual {
            if self.last_manual_seen != Some((gen, m)) {
                self.last_manual_seen = Some((gen, m));
                self.manual_cap_bps = m.max(1);
                self.local_bps = self.manual_cap_bps;
                self.remote_probe_cap_bps = None;
                self.last_remote_probe_seen = remote_probe_bps;
                self.drop_streak = 0;
                self.high_queue_since = None;
                self.last_adjust = now;
                self.clean_since = now;
            }
        }
        if self.last_remote_probe_seen != remote_probe_bps {
            self.last_remote_probe_seen = remote_probe_bps;
            self.remote_probe_cap_bps = remote_probe_bps.map(|v| v.clamp(1, self.manual_cap_bps));
        }
        let target = self.effective_bps();
        (current_host_bps.max(1) != target).then_some(target)
    }

    pub(super) fn poll(
        &mut self,
        now: Instant,
        queued_bytes: usize,
        dropped_total: u64,
    ) -> Option<u32> {
        let prev_eff = self.effective_bps();
        let drop_delta = dropped_total.saturating_sub(self.last_dropped);
        self.last_dropped = dropped_total;
        if drop_delta > 0 {
            self.drop_streak = self.drop_streak.saturating_add(1);
        } else {
            self.drop_streak = 0;
        }
        let sustained_drops = drop_delta >= RELAY_DROP_BURST_THRESHOLD || self.drop_streak >= 2;

        if queued_bytes >= RELAY_QUEUE_HIGH_BYTES {
            self.high_queue_since.get_or_insert(now);
        } else {
            self.high_queue_since = None;
        }
        let sustained_high_queue = self
            .high_queue_since
            .is_some_and(|since| now.saturating_duration_since(since) >= RELAY_HIGH_QUEUE_HOLD);

        if sustained_drops || sustained_high_queue {
            self.clean_since = now;
            if now.saturating_duration_since(self.last_adjust) >= RELAY_BACKOFF_COOLDOWN {
                let floor = RELAY_MIN_BITRATE_BPS.min(self.manual_cap_bps).max(1);
                let next =
                    (((self.local_bps as f64) * 0.75) as u32).clamp(floor, self.manual_cap_bps);
                self.last_adjust = now;
                self.high_queue_since = None;
                self.drop_streak = 0;
                self.local_bps = next;
                let next_eff = self.effective_bps();
                if next_eff != prev_eff {
                    return Some(next_eff);
                }
            }
            return None;
        }

        if queued_bytes <= RELAY_QUEUE_LOW_BYTES {
            if self.local_bps < self.manual_cap_bps
                && now.saturating_duration_since(self.clean_since) >= RELAY_RAMP_INTERVAL
                && now.saturating_duration_since(self.last_adjust) >= RELAY_RAMP_INTERVAL
            {
                let step = (self.local_bps / 4).max(2_000_000);
                let next = self.local_bps.saturating_add(step).min(self.manual_cap_bps);
                self.last_adjust = now;
                self.clean_since = now;
                self.local_bps = next;
                let next_eff = self.effective_bps();
                if next_eff != prev_eff {
                    return Some(next_eff);
                }
            }
        } else {
            self.clean_since = now;
        }

        None
    }
}

pub(super) fn sync_host_bitrate_on_path_switch(
    host: &mut HostSession,
    was_relay: bool,
    new_kind: HostTransportKind,
    negotiated_initial_bitrate_bps: u32,
    now: Instant,
) -> Option<RelayBitrateController> {
    let had_remote_probe = host.last_remote_probe_bitrate_bps().is_some();
    host.clear_remote_probe_bitrate();
    if (was_relay && new_kind != HostTransportKind::Relay) || had_remote_probe {
        let restore_bps = host
            .last_manual_bitrate_bps()
            .unwrap_or(negotiated_initial_bitrate_bps)
            .max(1);
        let _ = host.on_set_bitrate(restore_bps, rc_session::proto::BitrateReason::Probe as u8);
    }
    (new_kind == HostTransportKind::Relay)
        .then(|| RelayBitrateController::new(host.current_bitrate_bps().max(1), now))
}
