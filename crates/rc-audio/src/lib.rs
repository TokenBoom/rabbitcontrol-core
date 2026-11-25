//! RabbitControl 音频子系统：纯 Rust IMA-ADPCM 编解码 + 低延迟采集与播放抽象。
//!
//! 跨平台核心接口（[`PcmFrame`]、[`AudioCapture`]、[`AudioPlayer`]、[`codec`]、
//! [`FakeAudioCapture`]、[`NullAudioPlayer`]）完全零 `unsafe`；
//! 平台相关后端由对应平台 crate 实现 [`AudioBackendProvider`] 后通过
//! [`register_audio_provider`] 注册并经 [`create_system_audio_capture`] /
//! [`create_audio_player`] 统一创建。

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod codec;

use std::f64::consts::TAU;
use std::sync::{Arc, OnceLock};

pub use codec::{
    apply_mute_or_gain, decode_ima_adpcm, encode_ima_adpcm, DEFAULT_CHANNELS, DEFAULT_SAMPLE_RATE,
    FRAME_DURATION_MS, SAMPLES_PER_CHANNEL_20MS,
};

/// 静音判定默认绝对采样幅值阈值（16-bit PCM；`<= 2` 过滤量化底噪而不吞任何可闻尾音）。
pub const DEFAULT_SILENCE_THRESHOLD: i16 = 2;

/// 静音抑制（DTX）默认拖尾保持帧数（10 帧 × 20 ms = 200 ms，保护混响与淡出尾音不被生硬截断）。
pub const DEFAULT_SILENCE_HANGOVER_FRAMES: u32 = 10;

/// 判断一帧线性 PCM16 采样是否全部处于静音阈值内（无溢出处理 `i16::MIN`）。
#[must_use]
pub fn is_pcm_silent(samples: &[i16], threshold: i16) -> bool {
    let limit = i32::from(threshold).abs();
    samples.iter().all(|&s| i32::from(s).abs() <= limit)
}

/// 发送侧音频静音抑制门控（DTX）：有声时立即放行，转入静音后保留若干拖尾帧再暂停发送，
/// 避免空闲桌面持续消耗 ~384–410 Kbps 传输纯零静音包。
#[derive(Debug, Clone)]
pub struct AudioSilenceGate {
    threshold: i16,
    hangover_frames: u32,
    remaining_hangover: u32,
}

impl Default for AudioSilenceGate {
    fn default() -> Self {
        Self::new(DEFAULT_SILENCE_THRESHOLD, DEFAULT_SILENCE_HANGOVER_FRAMES)
    }
}

impl AudioSilenceGate {
    /// 以指定幅值阈值与拖尾帧数构造静音门控。
    #[must_use]
    pub const fn new(threshold: i16, hangover_frames: u32) -> Self {
        Self {
            threshold,
            hangover_frames,
            remaining_hangover: 0,
        }
    }

    /// 重置门控状态（例如取消静音或重建音频采集时调用）。
    pub fn reset(&mut self) {
        self.remaining_hangover = 0;
    }

    /// 判断本帧是否需要编码发送：`false` 表示处于静音抑制期，可直接跳过编码与发送。
    pub fn should_transmit(&mut self, samples: &[i16]) -> bool {
        if samples.is_empty() {
            return false;
        }
        if !is_pcm_silent(samples, self.threshold) {
            self.remaining_hangover = self.hangover_frames;
            return true;
        }
        if self.remaining_hangover > 0 {
            self.remaining_hangover -= 1;
            return true;
        }
        false
    }
}

/// 单帧线性 PCM16 音频数据（单声道或交错立体声）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcmFrame {
    /// 采样率（Hz），默认 [`DEFAULT_SAMPLE_RATE`]（48 000）。
    pub sample_rate: u32,
    /// 声道数（1 = 单声道，2 = 交错立体声）。
    pub channels: u8,
    /// 帧时间戳（微秒，单调递增并允许自然回绕）。
    pub timestamp_us: u32,
    /// 16-bit 有符号线性 PCM 采样（立体声按 `[L0, R0, L1, R1, ...]` 交错排列）。
    pub samples: Vec<i16>,
}

/// 跨平台音频采集接口（非阻塞轮询式，适合音频发送线程消费）。
pub trait AudioCapture: Send {
    /// 非阻塞尝试取出一帧已就绪的 PCM 音频；暂无新帧或已停止时返回 `None`。
    fn try_recv_frame(&mut self) -> Option<PcmFrame>;

    /// 当前采集流的采样率（Hz）。
    fn sample_rate(&self) -> u32;

    /// 当前采集流的声道数。
    fn channels(&self) -> u8;

    /// 停止采集并释放底层资源（应支持幂等调用）。
    fn stop(&mut self);
}

/// 跨平台音频播放接口（低延迟非阻塞推送式）。
pub trait AudioPlayer: Send {
    /// 推送一帧线性 PCM 数据用于播放；底层缓冲满时可丢帧以控制延迟，绝不长时间阻塞。
    fn push_frame(&mut self, frame: &PcmFrame) -> Result<(), String>;

    /// 切换静音状态（静音期间应输出静音且保持推送路径不报错）。
    fn set_muted(&mut self, muted: bool);

    /// 查询当前是否处于静音状态。
    fn is_muted(&self) -> bool;

    /// 停止播放并释放底层资源（应支持幂等调用）。
    fn stop(&mut self);
}

/// 离线测试用确定性音频采集桩：按需生成连续相位的 440 Hz 正弦波 20 ms 帧。
#[derive(Debug, Clone)]
pub struct FakeAudioCapture {
    sample_rate: u32,
    channels: u8,
    frequency_hz: f64,
    amplitude: f64,
    frame_index: u64,
    stopped: bool,
}

impl Default for FakeAudioCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeAudioCapture {
    /// 创建默认参数（48 kHz、双声道立体声、440 Hz 正弦波）的确定性采集桩。
    #[must_use]
    pub fn new() -> Self {
        Self::with_params(DEFAULT_SAMPLE_RATE, DEFAULT_CHANNELS, 440.0)
    }

    /// 使用自定义采样率、声道数（1 或 2）与频率（Hz）创建确定性采集桩。
    #[must_use]
    pub fn with_params(sample_rate: u32, channels: u8, frequency_hz: f64) -> Self {
        let safe_rate = sample_rate.max(1);
        let safe_channels = if channels == 1 { 1 } else { 2 };
        Self {
            sample_rate: safe_rate,
            channels: safe_channels,
            frequency_hz,
            amplitude: 16_000.0,
            frame_index: 0,
            stopped: false,
        }
    }

    /// 已生成的帧数。
    #[must_use]
    pub fn frames_emitted(&self) -> u64 {
        self.frame_index
    }
}

impl AudioCapture for FakeAudioCapture {
    fn try_recv_frame(&mut self) -> Option<PcmFrame> {
        if self.stopped {
            return None;
        }
        let frames_per_chunk =
            ((u64::from(self.sample_rate) * u64::from(FRAME_DURATION_MS)) / 1000).max(1) as usize;
        let channels = usize::from(self.channels);
        let mut samples = Vec::with_capacity(frames_per_chunk * channels);

        let base_sample = self.frame_index * (frames_per_chunk as u64);
        let sr = f64::from(self.sample_rate);
        for i in 0..frames_per_chunk {
            let t = (base_sample + i as u64) as f64 / sr;
            let value = ((TAU * self.frequency_hz * t).sin() * self.amplitude).round() as i16;
            for _ in 0..channels {
                samples.push(value);
            }
        }

        let timestamp_us = self
            .frame_index
            .wrapping_mul(u64::from(FRAME_DURATION_MS) * 1_000) as u32;
        self.frame_index = self.frame_index.wrapping_add(1);

        Some(PcmFrame {
            sample_rate: self.sample_rate,
            channels: self.channels,
            timestamp_us,
            samples,
        })
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    fn channels(&self) -> u8 {
        self.channels
    }

    fn stop(&mut self) {
        self.stopped = true;
    }
}

/// 离线测试用空音频播放器：统计播放帧数/采样数并严格遵守静音与停止状态。
#[derive(Debug, Default, Clone)]
pub struct NullAudioPlayer {
    muted: bool,
    stopped: bool,
    played_frames: u64,
    played_samples: u64,
    muted_frames: u64,
    last_samples: Vec<i16>,
}

impl NullAudioPlayer {
    /// 创建处于未静音、未停止状态的空播放器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 非静音状态下实际播放的帧数。
    #[must_use]
    pub fn played_frames(&self) -> u64 {
        self.played_frames
    }

    /// 非静音状态下实际播放的 `i16` 采样总数。
    #[must_use]
    pub fn played_samples(&self) -> u64 {
        self.played_samples
    }

    /// 静音状态下收到并被静音的帧数。
    #[must_use]
    pub fn muted_frames(&self) -> u64 {
        self.muted_frames
    }

    /// 累计收到的全部帧数（含静音帧）。
    #[must_use]
    pub fn total_frames(&self) -> u64 {
        self.played_frames + self.muted_frames
    }

    /// 最近一帧经静音处理后的采样快照（静音时全为 0）。
    #[must_use]
    pub fn last_samples(&self) -> &[i16] {
        &self.last_samples
    }

    /// 是否已调用 [`AudioPlayer::stop`]。
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
}

impl AudioPlayer for NullAudioPlayer {
    fn push_frame(&mut self, frame: &PcmFrame) -> Result<(), String> {
        if self.stopped {
            return Err("null audio player has been stopped".to_string());
        }
        let mut buf = frame.samples.clone();
        apply_mute_or_gain(&mut buf, self.muted, 1.0);
        if self.muted {
            self.muted_frames = self.muted_frames.wrapping_add(1);
        } else {
            self.played_frames = self.played_frames.wrapping_add(1);
            self.played_samples = self.played_samples.wrapping_add(buf.len() as u64);
        }
        self.last_samples = buf;
        Ok(())
    }

    fn set_muted(&mut self, muted: bool) {
        self.muted = muted;
    }

    fn is_muted(&self) -> bool {
        self.muted
    }

    fn stop(&mut self) {
        self.stopped = true;
    }
}

/// 平台音频后端提供者（由平台实现 crate 在进程启动时通过 [`register_audio_provider`] 注册）。
pub trait AudioBackendProvider: Send + Sync {
    /// 创建系统环回音频采集器。
    fn create_system_audio_capture(&self) -> Result<Box<dyn AudioCapture>, String>;

    /// 创建指定采样率与声道数的低延迟音频播放器。
    fn create_audio_player(
        &self,
        sample_rate: u32,
        channels: u8,
    ) -> Result<Box<dyn AudioPlayer>, String>;
}

static AUDIO_BACKEND_PROVIDER: OnceLock<Arc<dyn AudioBackendProvider>> = OnceLock::new();

/// 注册当前进程的平台音频后端提供者（仅首次调用生效）。
pub fn register_audio_provider(provider: Arc<dyn AudioBackendProvider>) -> bool {
    AUDIO_BACKEND_PROVIDER.set(provider).is_ok()
}

/// 创建平台原生的系统音频采集器。
///
/// 未注册平台音频提供者或当前平台不支持时返回可读错误。
pub fn create_system_audio_capture() -> Result<Box<dyn AudioCapture>, String> {
    match AUDIO_BACKEND_PROVIDER.get() {
        Some(p) => p.create_system_audio_capture(),
        None => Err("no system audio capture backend registered on this platform".to_string()),
    }
}

/// 创建平台原生的低延迟音频播放器。
///
/// 未注册平台音频提供者或参数非法时返回可读错误。
pub fn create_audio_player(sample_rate: u32, channels: u8) -> Result<Box<dyn AudioPlayer>, String> {
    if !(8_000..=192_000).contains(&sample_rate) {
        return Err(format!("unsupported audio sample rate: {sample_rate}"));
    }
    if channels != 1 && channels != 2 {
        return Err(format!("unsupported audio channel count: {channels}"));
    }
    match AUDIO_BACKEND_PROVIDER.get() {
        Some(p) => p.create_audio_player(sample_rate, channels),
        None => Err("no native audio playback backend registered on this platform".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_audio_capture_produces_deterministic_20ms_stereo_frames() {
        let mut cap = FakeAudioCapture::new();
        assert_eq!(cap.sample_rate(), DEFAULT_SAMPLE_RATE);
        assert_eq!(cap.channels(), DEFAULT_CHANNELS);

        let f0 = cap.try_recv_frame().expect("frame 0");
        let f1 = cap.try_recv_frame().expect("frame 1");
        assert_eq!(f0.sample_rate, 48_000);
        assert_eq!(f0.channels, 2);
        assert_eq!(f0.timestamp_us, 0);
        assert_eq!(f0.samples.len(), SAMPLES_PER_CHANNEL_20MS * 2);

        assert_eq!(f1.timestamp_us, 20_000);
        assert_eq!(f1.samples.len(), SAMPLES_PER_CHANNEL_20MS * 2);
        assert_ne!(f0.samples, f1.samples);

        // Determinism check: a second instance produces bit-identical frame 0.
        let mut cap2 = FakeAudioCapture::new();
        assert_eq!(cap2.try_recv_frame().expect("frame 0 repeat"), f0);

        cap.stop();
        assert!(cap.try_recv_frame().is_none());
    }

    #[test]
    fn null_audio_player_counts_and_respects_mute_and_stop() {
        let mut player = NullAudioPlayer::new();
        assert!(!player.is_muted());
        assert!(!player.is_stopped());

        let frame = PcmFrame {
            sample_rate: DEFAULT_SAMPLE_RATE,
            channels: DEFAULT_CHANNELS,
            timestamp_us: 0,
            samples: vec![1000, -1000, 2000, -2000],
        };

        player.push_frame(&frame).expect("push audible");
        assert_eq!(player.played_frames(), 1);
        assert_eq!(player.played_samples(), 4);
        assert_eq!(player.muted_frames(), 0);
        assert_eq!(player.last_samples(), &[1000, -1000, 2000, -2000]);

        player.set_muted(true);
        assert!(player.is_muted());
        player.push_frame(&frame).expect("push muted");
        assert_eq!(player.played_frames(), 1);
        assert_eq!(player.played_samples(), 4);
        assert_eq!(player.muted_frames(), 1);
        assert_eq!(player.total_frames(), 2);
        assert_eq!(player.last_samples(), &[0, 0, 0, 0]);

        player.set_muted(false);
        assert!(!player.is_muted());
        player.push_frame(&frame).expect("push unmuted");
        assert_eq!(player.played_frames(), 2);
        assert_eq!(player.played_samples(), 8);

        player.stop();
        assert!(player.is_stopped());
        assert!(player.push_frame(&frame).is_err());
    }

    #[test]
    fn full_capture_encode_decode_play_round_trip() {
        let mut capture = FakeAudioCapture::new();
        let mut player = NullAudioPlayer::new();

        for idx in 0..5u64 {
            let captured = capture.try_recv_frame().expect("captured frame");
            let encoded = encode_ima_adpcm(&captured.samples, captured.channels);
            assert_eq!(encoded.len(), 968);

            let decoded_samples =
                decode_ima_adpcm(&encoded, captured.channels).expect("decode packet");
            assert_eq!(decoded_samples.len(), captured.samples.len());

            // Verify high audio fidelity per frame (SNR > 25 dB).
            let mut sig = 0.0_f64;
            let mut err = 0.0_f64;
            for (&orig, &dec) in captured.samples.iter().zip(decoded_samples.iter()) {
                let o = f64::from(orig);
                let d = o - f64::from(dec);
                sig += o * o;
                err += d * d;
            }
            let snr_db = 10.0 * (sig / err.max(1e-9)).log10();
            assert!(
                snr_db > 25.0,
                "round-trip frame {idx} SNR too low: {snr_db:.2} dB"
            );

            let decoded_frame = PcmFrame {
                sample_rate: captured.sample_rate,
                channels: captured.channels,
                timestamp_us: captured.timestamp_us,
                samples: decoded_samples,
            };
            player.push_frame(&decoded_frame).expect("play frame");
        }

        assert_eq!(player.played_frames(), 5);
        assert_eq!(
            player.played_samples(),
            5 * (SAMPLES_PER_CHANNEL_20MS * 2) as u64
        );
        capture.stop();
        player.stop();
    }

    #[test]
    fn audio_silence_gate_suppresses_idle_after_hangover_and_wakes_immediately() {
        assert!(is_pcm_silent(&[], DEFAULT_SILENCE_THRESHOLD));
        assert!(is_pcm_silent(&[0, 1, -2, 2, -1], DEFAULT_SILENCE_THRESHOLD));
        assert!(!is_pcm_silent(&[0, 3, 0], DEFAULT_SILENCE_THRESHOLD));
        assert!(!is_pcm_silent(&[i16::MIN], DEFAULT_SILENCE_THRESHOLD));

        let mut gate = AudioSilenceGate::new(2, 3);
        // 初始即为静音：立即抑制，不发送任何零静音包
        assert!(!gate.should_transmit(&[0, 0, 1, -1]));
        assert!(!gate.should_transmit(&[]));

        // 首帧有声信号：零延迟立即放行并装填 3 帧拖尾
        assert!(gate.should_transmit(&[0, 250, -180, 0]));
        // 随后 3 帧静音拖尾保护淡出
        assert!(gate.should_transmit(&[0, 0, 0, 0]));
        assert!(gate.should_transmit(&[1, -1, 0, 0]));
        assert!(gate.should_transmit(&[2, -2, 0, 0]));
        // 第 4 帧起进入 DTX 静音抑制
        assert!(!gate.should_transmit(&[0, 0, 0, 0]));
        assert!(!gate.should_transmit(&[0, 0, 0, 0]));

        // 再次出现声响立即唤醒；reset 立即清空拖尾
        assert!(gate.should_transmit(&[0, -100]));
        gate.reset();
        assert!(!gate.should_transmit(&[0, 0]));
    }
}
