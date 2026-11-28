#![allow(unused_imports)]

pub(in crate::host_bridge) mod mock;

mod approver_and_handle;
mod audio_and_bitrate;
mod controller_tracking;
mod display_and_session_state;
mod hidpi_and_codec;
mod preempt_and_busy_lan_e2e;
mod relay_and_preempt;
mod tools_and_terminal;

pub(super) use std::collections::VecDeque;
pub(super) use std::net::{Ipv4Addr, SocketAddr};
pub(super) use std::path::PathBuf;
pub(super) use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
pub(super) use std::sync::{mpsc, Arc, Mutex, RwLock};
pub(super) use std::thread;
pub(super) use std::time::{Duration, Instant};

pub(super) use rc_audio::{AudioCapture, AudioSilenceGate};
pub(super) use rc_net::quic::QuicEndpoint;
pub(super) use rc_net::{NetConfig, NetEvent, NetStats, Role, Transport};
pub(super) use rc_pipeline::{DiffMode, PipelineConfig};
pub(super) use rc_session::auth::{
    ApprovalRequest, ApprovalVerdict, ConnectionApprover, OwnerTicketVerifier,
    DEFAULT_AUTH_ITERATIONS,
};
pub(super) use rc_session::dev_cert::{DEV_CERT_PEM, DEV_KEY_PEM};
pub(super) use rc_session::proto::{ByeReason, SessionParams};
pub(super) use rc_session::testkit::RecordingInjector;
pub(super) use rc_session::{
    AudioFramePacket, AutoApprover, ClipboardBackend, DetachOutcome, HostAuthConfig, HostSession,
    HostSessionConfig, SessionClock, SessionState, StopReason, AUDIO_CODEC_IMA_ADPCM,
    TOOL_CHANNEL_AUDIO_CTRL, TOOL_CHANNEL_DISPLAY_CTRL, TOOL_CHANNEL_FILE, TOOL_CHANNEL_PORTMAP,
    TOOL_CHANNEL_TERMINAL,
};
pub(super) use rc_tools::{FileHostEngine, PortMapHostEngine, TerminalHostEngine};
pub(super) use rc_types::Resolution;

pub(super) use crate::codec_selector::{
    self, HostCodecNegotiator, NetworkHint, ResolutionTier, StreamTarget,
};
pub(super) use crate::display_ctrl::{self, DisplayControlMsg, DisplayDescriptor, DisplayPreset};
pub(super) use crate::lan_discovery;
pub(super) use crate::p2p::{self, P2pCandidates};
pub(super) use crate::relay_transport::{
    E2eeRelayTransport, RelayE2eeMode, RelayRole, RelayShutdownHandle, SessionMtlsBundle,
    TcpRelayTransport,
};
pub(super) use crate::server_config::parse_device_id_input;
pub(super) use crate::signal_client::{
    ActiveControllerSummary, ForceDisconnectEvent, RelayIncoming,
};
pub(super) use crate::switchable_transport::{
    CandidateTransport, SwitchControlMsg, SwitchHandle, SwitchableTransport, TransportPathKind,
};

pub(super) use super::approver::UiApprover;
pub(super) use super::audio_bwe::{
    parse_audio_ctrl_muted, pump_host_audio, sync_host_bitrate_on_path_switch, AudioCaptureCreator,
    HostAudioManager, RelayBitrateController,
};
pub(super) use super::handle::HostHandle;
pub(super) use super::media_aux::{
    build_hardware_display_presets, build_session_display_caps_params, clamp_display_max_res,
    compute_host_display_bounds, encode_host_display_caps, encode_host_displays_state,
    encode_host_displays_state_from_list, handle_codec_fallback_hidpi,
    is_valid_privacy_image_bytes, replace_wake_guard, spawn_wallpaper_fetcher,
    trigger_host_lock_screen, HostDisplayModeSession, HostHardwareCleanupGuard,
    MidSessionWakeDriver, WakeGuardReleaser,
};
pub(super) use super::pipeline_factory::{
    bind_mtls_lan_endpoint, build_host_session, build_transport_host_session,
    collect_host_lan_addrs, compute_hidpi_stream_target, default_host_session_config,
    fake_stack_anchored, format_display_addr, format_host_lan_addrs_from_ips,
    host_hardware_display_backing, host_hardware_display_caps, make_host_pipeline_factory,
    make_session_clock, BuiltUiHost, CancellableHostTransport, ClockOrigin, HostClockAnchor,
    HostListener, HostPipelineFactory, DEFAULT_HIDPI_STREAM_MAX_HEIGHT,
    DEFAULT_HIDPI_STREAM_MAX_WIDTH,
};
pub(super) use super::queues::{
    build_active_controller_session, clear_active_controllers, drain_matching_force_disconnect,
    emit_peer_connected, force_disconnect_matches_controller, lan_stale_signal_cutoff,
    publish_active_controller, reject_busy_lan_endpoint_once_with_cancel,
    report_control_state_to_signal, unix_now_ms, BoundedHostUpdateQueue, BoundedRelayIncomingQueue,
    BusyLanRejectWorker, HostDisplayCtrlOutbox, PersistentOwnerTerminals,
};
pub(super) use super::session_loop::{
    drive_ui_host_session_core, drive_ui_host_session_with_switch_and_tracking,
};
pub(super) use super::tools_worker::{
    compute_effective_tool_permissions, encode_terminal_lock_state, encode_tool_permissions_state,
    flush_tool_channel_with_retry, flush_tool_channel_with_retry_checked,
    global_terminal_unlock_limiter, handle_terminal_unlock_request,
    handle_terminal_verify_completion, requested_username_matches_current, FileHostWorker,
    TerminalLockGate, TerminalUnlockRateLimiter, TerminalVerifyDriver,
};
pub(super) use super::transport_dial::{
    build_and_handshake_transport, build_host_p2p_candidates, dial_relay_for_incoming,
    is_p2p_handshake_fallback_eligible, maybe_rotate_password_after_session, rebuild_host_p2p_mtls,
    spawn_host_reprobe_p2p_candidate, spawn_host_switch_relay_candidate, DialedIncomingTransport,
    EstablishedIncomingHost, HandshakeTransportOutcome,
};
pub(super) use super::transport_worker::serve_relay_incoming;
pub(super) use super::types::{
    generate_temp_code, host_resume_ttl, ActiveControllerPeerHints, ActiveControllerSession,
    ActiveRelayInterrupt, AuthRuntimeState, DriveSessionOutcome, HostApprovalPrompt, HostCommand,
    HostControllerTracking, HostSwitchRuntime, HostTransportKind, HostUpdate, HostWorkerOptions,
    PasswordState, PreemptDecision, RelayInterruptSlotGuard, SharedActiveControllers,
    SharedFileTransferDir, SharedSignalClient, SharedWakeGuard, UiHostConfig,
    AUDIO_RECOVERY_INITIAL_BACKOFF, AUDIO_RECOVERY_MAX_BACKOFF, AUDIO_RECOVERY_MID_BACKOFF,
    AUDIO_RECOVERY_STABLE_WINDOW, BACKGROUND_P2P_UPGRADE_WINDOW, DEFAULT_HOST_PORT,
    DEFAULT_RELAY_FIRST_AFTER_MS, DISPLAY_CTRL_QUEUE_CAP, FAKE_ENCODE_COST_US,
    FILE_HOST_WORKER_CHAN_CAP, HOST_ACCEPT_SLICE, HOST_ENCODE_OVERLOAD_TRIP_LIMIT,
    HOST_LAN_RESUME_TTL, HOST_QUIC_HANDSHAKE_TIMEOUT, HOST_UPDATE_CHANNEL_CAP,
    LAN_STALE_SIGNAL_GRACE, MAX_AUDIO_FRAMES_PER_TICK, MAX_TOOL_FRAMES_PER_TICK,
    MAX_VIRTUAL_DISPLAYS_PER_SESSION, PREEMPT_ANY_IDLE_THRESHOLD_US, PREEMPT_CHECK_INTERVAL,
    PREEMPT_OWNER_IDLE_THRESHOLD_US, RELAY_BACKOFF_COOLDOWN, RELAY_CONNECT_TIMEOUT,
    RELAY_DROP_BURST_THRESHOLD, RELAY_HIGH_QUEUE_HOLD, RELAY_INCOMING_QUEUE_CAP,
    RELAY_INCOMING_TTL, RELAY_MIN_BITRATE_BPS, RELAY_QUEUE_HIGH_BYTES, RELAY_QUEUE_LOW_BYTES,
    RELAY_RAMP_INTERVAL, SWITCH_SIGNAL_PROTECT_WINDOW, TEMP_CODE_LEN,
    TOOL_PERMISSION_DENIED_THROTTLE,
};
pub(super) use super::worker::{accept_error_backoff, run_host_worker, sleep_cancelable};
