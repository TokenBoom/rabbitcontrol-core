# RabbitControl Core (`TokenBoom/rabbitcontrol-core`)

RabbitControl 跨平台核心引擎仓库：纯 Rust、零 GUI / OS 原生 SDK 依赖，包含全部共享协议、QUIC/mTLS 传输、帧调度与管线、会话状态机、工具引擎及客户端跨平台运行时。

## Crate 架构（18 crates）

| 分层 | Crate | 职责 |
|---|---|---|
| 基础类型与协议 | `rc-types`, `rc-proto`, `rc-diff`, `rc-fec`, `rc-trace` | 帧结构、UDP 媒体分片与重组、软件块差异、FEC 校验与时间线跟踪 |
| 低延迟调度与测试桩 | `rc-sched`, `rc-loopback` | Q1–Q6 严格有界帧调度与进程内回环评估框架 |
| 跨平台硬件抽象（Trait + Fake） | `rc-capture`, `rc-encode`, `rc-decode`, `rc-render`, `rc-input`, `rc-audio` | 平台无关采集/编解码/渲染/输入/音频接口（预留 `D3D11`/`CVPixelBuffer`/`DmaBuf`）与 IMA-ADPCM 编解码 |
| 传输与管线 | `rc-net`, `rc-pipeline` | QUIC + 双向 mTLS 传输、高优输入流与端到端媒体管线编排（经 `PlatformMediaProvider` 注入原生硬件） |
| 会话与工具引擎 | `rc-session`, `rc-tools` | 握手/PBKDF2/OwnerTicket 鉴权/重连/剪贴板协议、W2 文件传输/W3 远程终端/W4 端口转发引擎 |
| 客户端通用运行时 | `rc-client-core` | 认证/PKI 证书管理、信令客户端、P2P 打洞、mTLS 中继传输、LAN 路由缓存、主/被控会话桥接（经 `ClientPlatformHooks` 接入各 OS 客户端） |

## 平台客户端接入方式

平台仓（如 `TokenBoom/rabbitcontrol-macos` 或未来的 Windows/Linux 客户端）只需实现并注册：
1. `rc_pipeline::register_platform_provider(...)` — 注入采集/编解码/渲染硬件后端与主机单调时钟
2. `rc_audio::register_audio_provider(...)` — 注入系统音频采集与低延迟播放
3. `rc_session::register_clipboard_provider(...)` — 注入系统剪贴板后端
4. `rc_client_core::platform::register_platform_hooks(...)` — 注入显示器查询、分辨率切换、锁屏、输入注入与渲染表面挂接

## 本地验证

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```
