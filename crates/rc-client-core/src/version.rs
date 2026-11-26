//! 统一 Core 版本与协议元数据查询接口。
//!
//! 为桌面端、移动端及 FFI 适配层提供单一权威构建信息（版本号、Git 短提交哈希、
//! 构建时间戳、会话/打洞/局域网发现协议版本及 ABI 版本）。

use serde::{Deserialize, Serialize};

/// Core 跨平台运行时与 FFI 契约 ABI 版本号。
pub const CORE_ABI_VERSION: u32 = 1;

const CORE_VERSION_STR: &str = env!("RC_CORE_EFFECTIVE_VERSION");
const GIT_COMMIT_STR: &str = env!("RC_CORE_GIT_COMMIT");
const BUILD_TIMESTAMP_STR: &str = env!("RC_CORE_BUILD_TIMESTAMP");

/// RabbitControl Core 统一构建与协议版本元数据快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreBuildInfo {
    /// Core 语义化版本号（优先读取构建期 `RC_CORE_VERSION`，缺省为 `CARGO_PKG_VERSION`）。
    pub core_version: &'static str,
    /// 构建时仓库 Git 短提交哈希（无 `.git` 元数据时为 `"unknown"`）。
    pub git_commit: &'static str,
    /// 可复现构建时间戳（来自构建期 `SOURCE_DATE_EPOCH`，未设置时为 `"unknown"`）。
    pub build_timestamp: &'static str,
    /// 会话层控制协议版本号（[`rc_session::proto::PROTOCOL_VERSION`]）。
    pub session_protocol_version: u8,
    /// UDP P2P 打洞协议版本号（[`crate::p2p::PUNCH_VERSION`]）。
    pub punch_version: u8,
    /// 局域网发现信标协议版本号（[`crate::lan_discovery::BEACON_VERSION`]）。
    pub beacon_version: u8,
    /// Core 对外 ABI 版本号（[`CORE_ABI_VERSION`]）。
    pub abi_version: u32,
}

/// 返回当前构建的 [`CoreBuildInfo`] 完整版本与协议元数据。
pub fn core_build_info() -> CoreBuildInfo {
    CoreBuildInfo {
        core_version: CORE_VERSION_STR,
        git_commit: GIT_COMMIT_STR,
        build_timestamp: BUILD_TIMESTAMP_STR,
        session_protocol_version: rc_session::proto::PROTOCOL_VERSION,
        punch_version: crate::p2p::PUNCH_VERSION,
        beacon_version: crate::lan_discovery::BEACON_VERSION,
        abi_version: CORE_ABI_VERSION,
    }
}

/// 返回当前构建的 Core 版本字符串。
pub fn core_version() -> &'static str {
    CORE_VERSION_STR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_build_info_aggregates_versions_and_serializes_camel_case() {
        let info = core_build_info();
        assert_eq!(info.core_version, core_version());
        assert!(!info.core_version.is_empty());
        assert!(!info.git_commit.is_empty());
        assert!(!info.build_timestamp.is_empty());
        assert_eq!(
            info.session_protocol_version,
            rc_session::proto::PROTOCOL_VERSION
        );
        assert_eq!(info.punch_version, crate::p2p::PUNCH_VERSION);
        assert_eq!(info.beacon_version, crate::lan_discovery::BEACON_VERSION);
        assert_eq!(info.abi_version, CORE_ABI_VERSION);
        assert_eq!(CORE_ABI_VERSION, 1);

        let value = serde_json::to_value(&info).expect("serialize CoreBuildInfo");
        let obj = value.as_object().expect("CoreBuildInfo JSON object");
        assert_eq!(
            obj.get("coreVersion").and_then(|v| v.as_str()),
            Some(info.core_version)
        );
        assert_eq!(
            obj.get("gitCommit").and_then(|v| v.as_str()),
            Some(info.git_commit)
        );
        assert_eq!(
            obj.get("buildTimestamp").and_then(|v| v.as_str()),
            Some(info.build_timestamp)
        );
        assert_eq!(
            obj.get("sessionProtocolVersion").and_then(|v| v.as_u64()),
            Some(u64::from(rc_session::proto::PROTOCOL_VERSION))
        );
        assert_eq!(
            obj.get("punchVersion").and_then(|v| v.as_u64()),
            Some(u64::from(crate::p2p::PUNCH_VERSION))
        );
        assert_eq!(
            obj.get("beaconVersion").and_then(|v| v.as_u64()),
            Some(u64::from(crate::lan_discovery::BEACON_VERSION))
        );
        assert_eq!(
            obj.get("abiVersion").and_then(|v| v.as_u64()),
            Some(u64::from(CORE_ABI_VERSION))
        );

        // 验证与静态字符串反序列化往返一致（Deserialize 派生效验）。
        let static_json: &'static str = Box::leak(
            serde_json::to_string(&info)
                .expect("serialize json")
                .into_boxed_str(),
        );
        let parsed: CoreBuildInfo =
            serde_json::from_str(static_json).expect("deserialize CoreBuildInfo");
        assert_eq!(parsed, info);
    }

    #[test]
    fn default_core_version_matches_workspace_version_when_env_unset() {
        if std::env::var("RC_CORE_VERSION")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .is_none()
        {
            assert_eq!(core_version(), env!("CARGO_PKG_VERSION"));
            assert_eq!(core_version(), "0.1.27");
        }
    }
}
