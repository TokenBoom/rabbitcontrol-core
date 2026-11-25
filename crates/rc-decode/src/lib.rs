//! 解码抽象层：平台无关的 [`Decoder`] trait、解码输出类型与假解码器。
//!
//! # 职责边界
//! - 本 crate 只定义「解码侧的形状」：trait、输出枚举与解码帧载体。
//! - 真正的实现（DXVA2/D3D11VA / VideoToolbox）在各自的平台 crate 里
//!   实现 [`Decoder`]，本 crate **不含任何平台依赖**。
//! - [`fake::FakeDecoder`] 是可配置「丢前 N 帧 / 定点断参考链」的假解码器，
//!   把 D4/D5 契约固化成无 GPU 的 CI 可执行断言。
//!
//! # 延迟红线（任务卡 T05）
//! - **零拷贝（D1）**：解码输出直接携带 GPU 纹理（[`FrameTexture`]），
//!   解码与渲染共享同一 GPU 设备，禁止经 CPU 往返；
//! - **低延迟（D3）**：实现必须工作在低延迟模式（`AV_CODEC_FLAG_LOW_DELAY`
//!   或硬件等价），无重排缓冲；
//! - **缺参考帧不 panic（D4）**：参考链断裂时返回
//!   [`DecodeOutput::NeedKeyframe`] 并置位 [`Decoder::needs_keyframe`]，
//!   由上层向发送端请求关键帧；
//! - **进一出一（D5）**：编码端无 B 帧，解码器每输入一帧恰输出一帧
//!   （或明确的 NeedKeyframe / Nothing），输出顺序 == 输入顺序。
//!
//! # 时间注入
//! 实现内部**不读系统时钟**：`deadline_ts` 由调用方注入，预计完成时刻
//! 超过它时返回 [`Error::Timeout`]（不阻塞等待）；输出帧的
//! [`DecodedFrame::decode_done_ts`] 是解码器估算的完成时刻，是延迟测量
//! decode 段的终点。

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod fake;

pub use fake::{FakeDecoder, FakeDecoderConfig};
pub use rc_types::{Error, Result};

use std::time::Duration;

use rc_capture::FrameTexture;
use rc_types::{FrameKind, Timestamp};

/// 异步流水线解码提交结果（[`Decoder::submit_decode`] 返回值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeSubmitStatus {
    /// 帧已提交至异步硬件解码器，调用方需通过 [`Decoder::recv_decoded`] 回收输出。
    Submitted,
    /// 参考链断裂或首帧缺参数集，未提交硬件；调用方应向发送端请求关键帧。
    NeedKeyframe,
}

/// 视频解码器。实现必须满足 D1/D3/D4/D5（见 crate 文档）。
pub trait Decoder: Send {
    /// 输入一帧码流，返回解码出的纹理。
    ///
    /// - `kind`：发送端声明的帧语义（IDR / P），解码器据此维护参考链；
    /// - `deadline_ts`：截止时间戳（调用方注入）。预计完成时刻超过它时
    ///   返回 [`Error::Timeout`]，**不得阻塞等待**；
    /// - 码流不完整 / 缺参考帧时不 panic：缺参考帧返回
    ///   [`DecodeOutput::NeedKeyframe`]（同时 [`Decoder::needs_keyframe`]
    ///   置位，两者总是同时出现）；码流不完整返回 [`DecodeOutput::Nothing`]。
    fn decode(
        &mut self,
        data: &[u8],
        kind: FrameKind,
        deadline_ts: Timestamp,
    ) -> Result<DecodeOutput>;

    /// 是否需要调用方送入 / 请求关键帧。
    ///
    /// 参考链断裂（含「入会后从未解出过 IDR」）时为 `true`；直到成功
    /// 解码一个 IDR 帧才清除。上层据此向发送端回关键帧请求，而不是
    /// 继续盲送 P 帧。
    fn needs_keyframe(&self) -> bool;

    /// 冲刷内部缓冲。
    ///
    /// 进一出一（D5）的实现没有内部缓冲，恒返回 `Ok(())`；保留本方法是
    /// 为了契约稳定（硬件解码器在复位 / 分辨率切换时需要冲刷）。
    fn flush(&mut self) -> Result<()>;

    /// 是否支持 2-deep 异步流水线解码（[`Decoder::submit_decode`] /
    /// [`Decoder::recv_decoded`]）。默认返回 `false`。
    fn supports_pipelined_decode(&self) -> bool {
        false
    }

    /// 异步提交一帧待解码码流（仅当 [`Decoder::supports_pipelined_decode`] 为 `true` 时可用）。
    ///
    /// 调用方以 `token` 关联输入与输出，并需保证在途帧数不超过实现上限（铁律 1：≤ 2）。
    fn submit_decode(
        &mut self,
        _token: u64,
        _data: &[u8],
        _kind: FrameKind,
        _deadline_ts: Timestamp,
    ) -> Result<DecodeSubmitStatus> {
        Err(Error::InvalidConfig(
            "pipelined decode not supported".into(),
        ))
    }

    /// 按 FIFO 提交顺序接收下一帧已完成的异步解码输出；超时无就绪返回 `Ok(None)`。
    fn recv_decoded(&mut self, _timeout: Duration) -> Result<Option<(u64, DecodeOutput)>> {
        Ok(None)
    }

    /// 当前已提交但尚未被 [`Decoder::recv_decoded`] 回收的在途帧数。
    fn in_flight_count(&self) -> usize {
        0
    }
}

/// [`Decoder::decode`] 的输出。
#[derive(Debug, Clone)]
pub enum DecodeOutput {
    /// 解码成功，交出一帧（进一出一：与输入一一对应）。
    Frame(DecodedFrame),
    /// 参考链断裂，需要请求关键帧
    NeedKeyframe,
    /// 无输出（如码流不完整）
    Nothing,
}

/// 解码出的一帧。
#[derive(Debug, Clone)]
pub struct DecodedFrame {
    /// 帧内容载体：GPU 纹理句柄（零拷贝，D1）或 CPU 兜底缓冲。
    pub texture: FrameTexture,
    /// 解码完成时刻（时间戳，非墙钟）。延迟测量 decode 段的终点。
    pub decode_done_ts: Timestamp,
    /// 帧宽（像素）。
    pub width: u32,
    /// 帧高（像素）。
    pub height: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pipelined_decoder_methods_reject_submit_and_return_none() {
        let mut dec = FakeDecoder::new(FakeDecoderConfig::default()).expect("假解码器配置合法");
        assert!(!dec.supports_pipelined_decode());
        assert_eq!(dec.in_flight_count(), 0);
        assert!(dec
            .recv_decoded(Duration::from_millis(1))
            .expect("recv_decoded 默认返回 Ok(None)")
            .is_none());
        let err = dec
            .submit_decode(1, &[0, 0, 0, 1, 0x65], FrameKind::Idr, Timestamp(50_000))
            .expect_err("不支持流水线的解码器调用 submit_decode 应返回 Err");
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
