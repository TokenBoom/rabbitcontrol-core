//! 跨平台应用更新检查、版本比较、镜像加速地址校验与远程更新状态模型。
//!
//! 本模块保持 100% 平台无关与 `#![deny(unsafe_code)]`，所有操作系统原生下载、
//! 签名验签与原子替换安装通过 [`crate::platform::ClientPlatformHooks`] 委托平台仓执行。

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::display_ctrl::{self, DisplayControlMsg};

/// 默认 macOS Release GitHub 仓库（`owner/repo`）。
pub const DEFAULT_GITHUB_REPO: &str = "TokenBoom/rabbitcontrol-macos";

/// 默认 GitHub Releases 最新版本查询 API 地址。
pub const DEFAULT_LATEST_RELEASE_API_URL: &str =
    "https://api.github.com/repos/TokenBoom/rabbitcontrol-macos/releases/latest";

/// 更新安装包体积硬上限（200 MiB，防止恶意超大载荷耗尽磁盘或内存）。
pub const MAX_UPDATE_PACKAGE_BYTES: u64 = 200 * 1024 * 1024;

/// 控制端中转推送 DMG 的单块原始字节大小（64 KiB，Base64 编码后约 87 KiB，远低于 256 KiB 单帧上限）。
pub const UPDATE_RELAY_CHUNK_BYTES: usize = 64 * 1024;

/// 控制端中转推送 DMG 的在途滑动窗口块数（4 块 = 256 KiB，防止拥塞控制流）。
pub const UPDATE_RELAY_WINDOW_CHUNKS: usize = 4;

/// 更新镜像前缀允许的最大字节长度。
pub const MAX_UPDATE_MIRROR_URL_LEN: usize = 256;

/// 更新下载地址允许的最大字节长度。
pub const MAX_UPDATE_DOWNLOAD_URL_LEN: usize = 1024;

/// 规范化语义版本号（`major.minor.patch[-pre]`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    /// 主版本号。
    pub major: u64,
    /// 次版本号。
    pub minor: u64,
    /// 修订号。
    pub patch: u64,
    /// 可选预发布标识（如 `"rc.1"`；正式版为 `None`）。
    pub pre: Option<String>,
}

impl SemVer {
    /// 解析版本号字符串（允许可选 `v`/`V` 前缀及 `+build` 元数据）。
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let no_prefix = trimmed
            .strip_prefix('v')
            .or_else(|| trimmed.strip_prefix('V'))
            .unwrap_or(trimmed);
        // 剥离 `+build` 元数据（按 SemVer 2.0 规则不参与版本大小比较）。
        let core_and_pre = no_prefix.split('+').next().unwrap_or("");
        let (core, pre) = match core_and_pre.split_once('-') {
            Some((c, p)) => {
                let p_trim = p.trim();
                let pre_opt = if p_trim.is_empty() {
                    None
                } else {
                    Some(p_trim.to_string())
                };
                (c, pre_opt)
            }
            None => (core_and_pre, None),
        };
        let mut parts = core.split('.');
        let major: u64 = parts.next()?.parse().ok()?;
        let minor: u64 = parts.next()?.parse().ok()?;
        let patch: u64 = match parts.next() {
            Some(p) => p.parse().ok()?,
            None => 0,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)) {
            Ordering::Equal => match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                // SemVer 2.0: 正式版 > 同版本号预发布版
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => compare_prerelease(a, b),
            },
            ord => ord,
        }
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let mut ia = a.split('.');
    let mut ib = b.split('.');
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(sa), Some(sb)) => {
                let ord = match (sa.parse::<u64>(), sb.parse::<u64>()) {
                    (Ok(na), Ok(nb)) => na.cmp(&nb),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => sa.cmp(sb),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// 判断候选版本 `candidate` 是否严格高于当前版本 `current`。
pub fn is_newer_version(candidate: &str, current: &str) -> bool {
    match (SemVer::parse(candidate), SemVer::parse(current)) {
        (Some(c), Some(cur)) => c > cur,
        _ => false,
    }
}

/// 规范化 CPU 架构名称（如 `aarch64` → `"arm64"`，`amd64` → `"x86_64"`）。
pub fn normalize_arch(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "aarch64" | "arm64" => "arm64".to_string(),
        "x86_64" | "amd64" | "x64" => "x86_64".to_string(),
        other => other.to_string(),
    }
}

/// 校验字符串是否为合法的 64 位十六进制 SHA-256 摘要。
pub fn is_valid_sha256_hex(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 常量时间比对两个十六进制摘要字符串（大小写不敏感）。
pub fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    let ba = a.trim().as_bytes();
    let bb = b.trim().as_bytes();
    if ba.len() != bb.len() || ba.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in ba.iter().zip(bb.iter()) {
        diff |= x.to_ascii_lowercase() ^ y.to_ascii_lowercase();
    }
    diff == 0
}

/// 校验安装包文件名安全（非空、无路径分隔符、无 `..`、无控制字符）。
pub fn is_safe_asset_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 160
        && !trimmed.contains('/')
        && !trimmed.contains('\\')
        && !trimmed.contains("..")
        && !trimmed.chars().any(|c| c.is_control())
}

fn parse_strict_port(port_str: &str) -> Result<u16, String> {
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err("更新地址端口号无效".to_string());
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| "更新地址端口号无效".to_string())?;
    if port == 0 {
        return Err("更新地址端口号不能为 0".to_string());
    }
    Ok(port)
}

fn validate_https_authority(authority: &str, allow_template: bool) -> Result<(), String> {
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains('\\')
        || authority.contains('{')
        || authority.contains('}')
    {
        return Err("更新地址缺少有效主机名".to_string());
    }
    let _ = allow_template;
    let host_only = if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err("更新地址 IPv6 主机名格式无效".to_string());
        };
        let ipv6_str = &rest[..end];
        if ipv6_str.parse::<std::net::Ipv6Addr>().is_err() {
            return Err("更新地址 IPv6 主机名无效".to_string());
        }
        let after = &rest[end + 1..];
        if !after.is_empty() {
            let Some(port_str) = after.strip_prefix(':') else {
                return Err("更新地址端口格式无效".to_string());
            };
            let _ = parse_strict_port(port_str)?;
        }
        return Ok(());
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return Err("更新地址主机名格式无效".to_string());
        }
        let _ = parse_strict_port(p)?;
        h
    } else {
        authority
    };

    if host_only.is_empty()
        || host_only.starts_with('.')
        || host_only.ends_with('.')
        || host_only.contains("..")
    {
        return Err("更新地址缺少有效主机名".to_string());
    }
    if !host_only
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err("更新地址主机名包含非法字符".to_string());
    }
    Ok(())
}

fn contains_unsafe_url_chars(s: &str, allow_braces: bool) -> bool {
    s.chars().any(|c| {
        c.is_control()
            || c.is_whitespace()
            || matches!(c, '\\' | '"' | '\'' | '<' | '>')
            || (!allow_braces && matches!(c, '{' | '}'))
    })
}

/// 校验并规范化用户可选配置的更新镜像前缀 URL（允许空串表示直连 GitHub；非空时必须为 `https://`）。
pub fn sanitize_update_mirror_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > MAX_UPDATE_MIRROR_URL_LEN {
        return Err(format!(
            "镜像地址长度不能超过 {MAX_UPDATE_MIRROR_URL_LEN} 字节"
        ));
    }
    if contains_unsafe_url_chars(trimmed, true) {
        return Err("镜像地址包含空白、控制字符或非法符号".to_string());
    }
    if trimmed.contains('#') {
        return Err("镜像加速地址不能包含片段标识 #".to_string());
    }
    let rest = trimmed
        .strip_prefix("https://")
        .ok_or_else(|| "镜像加速地址必须以 https:// 开头".to_string())?;
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    validate_https_authority(authority, true)?;
    let tail = &rest[auth_end..];
    // 若包含 `{` 或 `}`，仅允许合法的 `{url}` 模板占位符。
    let tail_without_placeholder = tail.replace("{url}", "");
    if tail_without_placeholder.contains('{') || tail_without_placeholder.contains('}') {
        return Err("镜像地址仅支持 {url} 占位符".to_string());
    }
    Ok(trimmed.to_string())
}

/// 校验目标下载或查询地址（必须为合法 `https://` URL）。
pub fn validate_update_https_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_UPDATE_DOWNLOAD_URL_LEN {
        return Err("更新下载地址无效或过长".to_string());
    }
    if contains_unsafe_url_chars(trimmed, false) {
        return Err("更新下载地址包含空白、控制字符或非法符号".to_string());
    }
    let rest = trimmed
        .strip_prefix("https://")
        .ok_or_else(|| "更新下载地址必须使用 https:// 协议".to_string())?;
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    validate_https_authority(authority, false)?;
    Ok(trimmed.to_string())
}

/// 将可选镜像前缀应用到目标 `https://` URL。
///
/// - `mirror_url` 为空：直接返回校验后的 `target_url`；
/// - `mirror_url` 包含 `{url}` 占位符：替换 `{url}` 为 `target_url`；
/// - 否则确保 `mirror_url` 以 `/` 结尾后直接拼接 `target_url`（适配主流 GitHub 加速前缀）。
pub fn apply_mirror_prefix(mirror_url: &str, target_url: &str) -> Result<String, String> {
    let clean_target = validate_update_https_url(target_url)?;
    let clean_mirror = sanitize_update_mirror_url(mirror_url)?;
    if clean_mirror.is_empty() {
        return Ok(clean_target);
    }
    let joined = if clean_mirror.contains("{url}") {
        clean_mirror.replace("{url}", &clean_target)
    } else if clean_mirror.ends_with('/') {
        format!("{clean_mirror}{clean_target}")
    } else {
        format!("{clean_mirror}/{clean_target}")
    };
    validate_update_https_url(&joined)
}

/// 为给定更新查询/下载 HTTPS URL 解析当前生效的出站代理（自动应用全局活跃代理、回环 Bypass 与 `NO_PROXY`）。
///
/// 供平台下载钩子（如 `curl` / `NSURLSession` / WinHTTP）在执行更新元数据拉取与安装包下载时统一复用代理策略。
pub fn resolve_updater_proxy(
    target_url: &str,
) -> Result<Option<crate::proxy::ResolvedProxy>, crate::proxy::ProxyError> {
    let active = crate::proxy::active_proxy_config();
    let trimmed = target_url.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let default_port = if trimmed.starts_with("http://") {
        80u16
    } else {
        443u16
    };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        match inner.find(']') {
            Some(end) => {
                let h = &inner[..end];
                let p = inner[end + 1..]
                    .strip_prefix(':')
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(default_port);
                (h, p)
            }
            None => (authority, default_port),
        }
    } else if let Some((h, p_str)) = authority.rsplit_once(':') {
        match p_str.parse::<u16>() {
            Ok(p) if !h.contains(':') => (h, p),
            _ => (authority, default_port),
        }
    } else {
        (authority, default_port)
    };
    if host.is_empty() {
        return crate::proxy::resolve_effective_proxy(&active);
    }
    crate::proxy::resolve_proxy_for_target(&active, host, port)
}

/// 单个 Release 发行资产描述。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseAsset {
    /// 文件名（例如 `RabbitControl-0.1.10-arm64.dmg`）。
    pub name: String,
    /// 原始 `https://` 下载地址。
    pub download_url: String,
    /// 文件字节大小。
    #[serde(default)]
    pub size: u64,
    /// 可选关联的 64 位小写 SHA-256 校验值（来自 `SHA256SUMS.txt` 或 `.sha256`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Release 版本元数据（来自 GitHub Releases API）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseInfo {
    /// 规范化版本号（不含前导 `v`，例如 `"0.1.10"`）。
    pub version: String,
    /// 原始 Git tag（例如 `"v0.1.10"`）。
    pub tag: String,
    /// 发布标题。
    #[serde(default)]
    pub title: String,
    /// Markdown 更新日志正文。
    #[serde(default)]
    pub notes: String,
    /// 发布时间（RFC 3339 字符串）。
    #[serde(default)]
    pub published_at: String,
    /// 发布页面网页链接。
    #[serde(default)]
    pub html_url: String,
    /// 附带资产列表。
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubReleaseRaw {
    tag_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    assets: Vec<GitHubAssetRaw>,
}

#[derive(Debug, Deserialize)]
struct GitHubAssetRaw {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

/// 解析 GitHub Releases `/releases/latest` JSON 响应体。
pub fn parse_github_release_json(json_str: &str) -> Result<ReleaseInfo, String> {
    let raw: GitHubReleaseRaw =
        serde_json::from_str(json_str).map_err(|e| format!("解析 Release JSON 失败: {e}"))?;
    let tag = raw.tag_name.trim().to_string();
    let version = tag
        .strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(&tag)
        .trim()
        .to_string();
    if SemVer::parse(&version).is_none() {
        return Err(format!("Release tag 版本号无效: {tag}"));
    }
    let mut assets = Vec::new();
    for a in raw.assets {
        if !is_safe_asset_name(&a.name) {
            continue;
        }
        if let Ok(url) = validate_update_https_url(&a.browser_download_url) {
            assets.push(ReleaseAsset {
                name: a.name.trim().to_string(),
                download_url: url,
                size: a.size,
                sha256: None,
            });
        }
    }
    Ok(ReleaseInfo {
        version,
        tag,
        title: raw.name.unwrap_or_default().trim().to_string(),
        notes: raw.body.unwrap_or_default(),
        published_at: raw.published_at.unwrap_or_default().trim().to_string(),
        html_url: raw
            .html_url
            .as_deref()
            .and_then(|u| validate_update_https_url(u).ok())
            .unwrap_or_default(),
        assets,
    })
}

/// 解析 `SHA256SUMS.txt` 或单文件 `.sha256` 文本为 `filename -> lowercase_hex` 映射。
pub fn parse_sha256sums(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let Some(hash_raw) = parts.next() else {
            continue;
        };
        let Some(name_raw) = parts.next() else {
            continue;
        };
        let hash = hash_raw.trim().to_ascii_lowercase();
        let name = name_raw.trim().trim_start_matches('*').trim();
        if is_valid_sha256_hex(&hash) && is_safe_asset_name(name) {
            map.insert(name.to_string(), hash);
        }
    }
    map
}

/// 将解析出的 `SHA256SUMS` 哈希映射关联回 [`ReleaseInfo::assets`]。
pub fn attach_sha256sums(release: &mut ReleaseInfo, sums_text: &str) {
    let map = parse_sha256sums(sums_text);
    for asset in &mut release.assets {
        if let Some(hash) = map.get(&asset.name) {
            asset.sha256 = Some(hash.clone());
        }
    }
}

/// 在 `release.assets` 中查找 `SHA256SUMS.txt` 资产。
pub fn find_sha256sums_asset(release: &ReleaseInfo) -> Option<&ReleaseAsset> {
    release
        .assets
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("SHA256SUMS.txt"))
}

/// 在 `release.assets` 中查找指定资产对应的单文件 `<asset>.sha256`。
pub fn find_sidecar_sha256_asset<'a>(
    release: &'a ReleaseInfo,
    asset_name: &str,
) -> Option<&'a ReleaseAsset> {
    let expected = format!("{asset_name}.sha256");
    release
        .assets
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(&expected))
}

/// 为指定目标平台（`os`、`arch`）选择最匹配的发行安装包资产。
pub fn select_asset_for_target(
    release: &ReleaseInfo,
    os: &str,
    arch: &str,
) -> Option<ReleaseAsset> {
    let norm_os = os.trim().to_ascii_lowercase();
    let norm_arch = normalize_arch(arch);
    if norm_os == "macos" || norm_os == "darwin" {
        let exact_name = format!("RabbitControl-{}-{}.dmg", release.version, norm_arch);
        if let Some(a) = release
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(&exact_name))
        {
            return Some(a.clone());
        }
        let suffix = format!("-{norm_arch}.dmg");
        return release
            .assets
            .iter()
            .find(|a| a.name.to_ascii_lowercase().ends_with(&suffix))
            .cloned();
    }
    None
}

/// 更新流程所处阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStage {
    /// 空闲。
    Idle,
    /// 正在检查更新。
    Checking,
    /// 正在从远端下载更新包。
    Downloading,
    /// 正在通过控制端中转推送更新包。
    Relaying,
    /// 正在校验 SHA-256 与代码签名。
    Verifying,
    /// 正在替换安装新版本应用。
    Installing,
    /// 已安装完成，正在重启并等待重新上线。
    Restarting,
    /// 更新完成。
    Succeeded,
    /// 更新失败或已取消。
    Failed,
}

/// 本地或远程更新的实时进度快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProgress {
    /// 当前阶段。
    pub stage: UpdateStage,
    /// 进度百分比（`0..=100`）。
    #[serde(default)]
    pub progress_pct: u8,
    /// 已下载或已传输字节数。
    #[serde(default)]
    pub downloaded_bytes: u64,
    /// 总字节数（未知时为 `0`）。
    #[serde(default)]
    pub total_bytes: u64,
    /// 目标版本号。
    #[serde(default)]
    pub target_version: String,
    /// 面向用户展示的阶段状态说明。
    #[serde(default)]
    pub message: String,
    /// 为 `true` 时表示被控端直连下载失败，正在请求控制端代为下载并经会话中转推送 DMG。
    #[serde(default)]
    pub need_controller_relay: bool,
    /// 失败时的错误详情。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for UpdateProgress {
    fn default() -> Self {
        Self {
            stage: UpdateStage::Idle,
            progress_pct: 0,
            downloaded_bytes: 0,
            total_bytes: 0,
            target_version: String::new(),
            message: String::new(),
            need_controller_relay: false,
            error: None,
        }
    }
}

/// 被控端在建立远控会话后上报给控制端的版本与更新能力快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteHostVersion {
    /// 被控端当前应用版本（如 `"0.1.9"`）。
    pub version: String,
    /// 被控端 CPU 架构（如 `"arm64"` / `"x86_64"`）。
    pub arch: String,
    /// 被控端操作系统（如 `"macos"`）。
    pub os: String,
    /// 被控端是否具备自更新能力。
    #[serde(default)]
    pub update_capable: bool,
    /// 当前会话是否为同账号本人自控（`OwnerTicket` 认证通过）；仅 `true` 允许远程更新。
    #[serde(default)]
    pub is_owner_session: bool,
    /// 被控端是否已安装系统级后台服务（安装时可免密更新与重启）。
    #[serde(default)]
    pub service_installed: bool,
}

/// 更新检查结果（供本机检查更新与远程更新对比复用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckResult {
    /// 当前运行版本号。
    pub current_version: String,
    /// 远端最新版本号。
    pub latest_version: String,
    /// 是否存在可更新的新版本。
    pub has_update: bool,
    /// 当前设备架构（如 `"arm64"`）。
    pub arch: String,
    /// 远端完整 Release 信息。
    pub release: ReleaseInfo,
    /// 匹配当前目标架构的发行安装包资产。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_asset: Option<ReleaseAsset>,
}

/// 已确认的远程更新触发参数（由控制端显式确认后保存并下发被控端）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteUpdateRequest {
    /// 目标版本号（如 `"0.1.10"`）。
    pub target_version: String,
    /// 原始 `https://` 安装包下载地址。
    pub download_url: String,
    /// 64 位小写 SHA-256 预期校验值。
    pub expected_sha256: String,
    /// 安装包文件名（如 `"RabbitControl-0.1.10-arm64.dmg"`）。
    pub asset_name: String,
    /// 可选镜像加速前缀。
    #[serde(default)]
    pub mirror_url: String,
    /// 被控端直连下载失败时是否允许控制端代下并中转推送 DMG。
    #[serde(default = "default_true")]
    pub relay_fallback_allowed: bool,
}

fn default_true() -> bool {
    true
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn make_temp_update_path(prefix: &str, asset_name: &str) -> PathBuf {
    let mut rnd = [0u8; 8];
    OsRng.fill_bytes(&mut rnd);
    let hex = encode_hex_lower(&rnd);
    let ext = Path::new(asset_name)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty() && e.len() <= 12 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("pkg");
    std::env::temp_dir().join(format!("rc-{prefix}-{}-{hex}.{ext}", std::process::id()))
}

fn progress_to_msg(p: UpdateProgress, request_id: u64) -> DisplayControlMsg {
    DisplayControlMsg::UpdateStatus {
        stage: p.stage,
        progress_pct: p.progress_pct.min(100),
        downloaded_bytes: p.downloaded_bytes,
        total_bytes: p.total_bytes,
        target_version: p.target_version,
        message: p.message,
        need_controller_relay: p.need_controller_relay,
        error: p.error,
        request_id,
    }
}

fn fail_status_msg(
    request_id: u64,
    target_version: &str,
    message: impl Into<String>,
    err: impl Into<String>,
) -> DisplayControlMsg {
    progress_to_msg(
        UpdateProgress {
            stage: UpdateStage::Failed,
            progress_pct: 0,
            downloaded_bytes: 0,
            total_bytes: 0,
            target_version: target_version.to_string(),
            message: message.into(),
            need_controller_relay: false,
            error: Some(err.into()),
        },
        request_id,
    )
}

fn scaled_pct(done: u64, total: u64, max_pct: u64) -> u8 {
    done.saturating_mul(max_pct)
        .checked_div(total)
        .unwrap_or(0)
        .min(max_pct) as u8
}

const MAX_HOST_UPDATE_PENDING_OUT: usize = 64;
const MAX_HOST_PENDING_UPDATE_TX: usize = 64;
const RELAY_RX_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone, Copy, PartialEq, Eq)]
enum UpdateTxClass {
    Ack,
    Progress,
    Critical,
}

fn classify_update_tx_msg(msg: &DisplayControlMsg) -> UpdateTxClass {
    match msg {
        DisplayControlMsg::UpdateChunkAck { .. } => UpdateTxClass::Ack,
        DisplayControlMsg::UpdateStatus {
            stage,
            need_controller_relay,
            ..
        } => {
            if *need_controller_relay
                || matches!(
                    stage,
                    UpdateStage::Installing
                        | UpdateStage::Restarting
                        | UpdateStage::Succeeded
                        | UpdateStage::Failed
                )
            {
                UpdateTxClass::Critical
            } else {
                UpdateTxClass::Progress
            }
        }
        _ => UpdateTxClass::Critical,
    }
}

enum PendingUpdateEntry {
    Ack {
        next_offset: u64,
        payload: Vec<u8>,
    },
    Progress(Vec<u8>),
    Critical {
        is_guest_reject: bool,
        payload: Vec<u8>,
    },
}

impl PendingUpdateEntry {
    fn payload(&self) -> &[u8] {
        match self {
            Self::Ack { payload, .. }
            | Self::Progress(payload)
            | Self::Critical { payload, .. } => payload,
        }
    }
}

/// 被控端出站更新控制消息的有界分级重试队列：
/// - 累计型 `UpdateChunkAck` 原地合并（队列内最多保留 1 条最大偏移 ACK），彻底杜绝 1 字节小块引发的无界队列膨胀；
/// - 非关键进度帧达到上限时原地覆盖最新进度或优先淘汰，永不静默丢弃关键状态（`HostVersionInfo` / `need_controller_relay` / `Installing` / `Restarting` / `Failed`）；
/// - 未授权 Guest 拒绝响应合并去重，防止背压放大内存。
pub struct PendingUpdateTxQueue {
    entries: VecDeque<PendingUpdateEntry>,
}

impl Default for PendingUpdateTxQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingUpdateTxQueue {
    /// 构造空的出站更新消息重试队列。
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    /// 队列是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 清空全部待发帧（用于会话替换或中转中止）。
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// 将一条更新控制消息编码并按优先级入队；返回是否成功入队或原地合并更新。
    pub fn enqueue(&mut self, msg: &DisplayControlMsg, is_owner_session: bool) -> bool {
        let class = classify_update_tx_msg(msg);
        let is_guest_reject = !is_owner_session
            && matches!(
                msg,
                DisplayControlMsg::UpdateStatus {
                    stage: UpdateStage::Failed,
                    ..
                }
            );
        if is_guest_reject
            && self.entries.iter().any(|e| {
                matches!(
                    e,
                    PendingUpdateEntry::Critical {
                        is_guest_reject: true,
                        ..
                    }
                )
            })
        {
            return false;
        }
        let Some(payload) = display_ctrl::encode_display_ctrl(msg) else {
            return false;
        };

        match (class, msg) {
            (UpdateTxClass::Ack, DisplayControlMsg::UpdateChunkAck { next_offset }) => {
                if let Some(PendingUpdateEntry::Ack {
                    next_offset: existing_offset,
                    payload: existing_payload,
                }) = self
                    .entries
                    .iter_mut()
                    .find(|e| matches!(e, PendingUpdateEntry::Ack { .. }))
                {
                    if *next_offset > *existing_offset {
                        *existing_offset = *next_offset;
                        *existing_payload = payload;
                    }
                    return true;
                }
                if self.entries.len() >= MAX_HOST_PENDING_UPDATE_TX {
                    if let Some(pos) = self
                        .entries
                        .iter()
                        .position(|e| matches!(e, PendingUpdateEntry::Progress(_)))
                    {
                        self.entries.remove(pos);
                    } else {
                        return false;
                    }
                }
                self.entries.push_back(PendingUpdateEntry::Ack {
                    next_offset: *next_offset,
                    payload,
                });
                true
            }
            (UpdateTxClass::Progress, _) => {
                if self.entries.len() >= MAX_HOST_PENDING_UPDATE_TX {
                    if let Some(PendingUpdateEntry::Progress(slot)) = self
                        .entries
                        .iter_mut()
                        .rev()
                        .find(|e| matches!(e, PendingUpdateEntry::Progress(_)))
                    {
                        *slot = payload;
                        return true;
                    }
                    return false;
                }
                self.entries
                    .push_back(PendingUpdateEntry::Progress(payload));
                true
            }
            _ => {
                if self.entries.len() >= MAX_HOST_PENDING_UPDATE_TX {
                    if let Some(pos) = self
                        .entries
                        .iter()
                        .position(|e| matches!(e, PendingUpdateEntry::Progress(_)))
                    {
                        self.entries.remove(pos);
                    } else if let Some(pos) = self
                        .entries
                        .iter()
                        .position(|e| !matches!(e, PendingUpdateEntry::Ack { .. }))
                    {
                        self.entries.remove(pos);
                    }
                }
                self.entries.push_back(PendingUpdateEntry::Critical {
                    is_guest_reject,
                    payload,
                });
                true
            }
        }
    }

    /// 每拍最多冲刷 `max_frames` 帧；遇暂时背压保留队首供下拍重试，遇致命编码/配置错误丢弃当前帧避免队头阻塞。
    pub fn flush<E, F, P>(&mut self, max_frames: usize, mut send: F, mut is_fatal: P) -> bool
    where
        F: FnMut(Vec<u8>) -> Result<(), E>,
        P: FnMut(&E) -> bool,
    {
        let mut sent_any = false;
        for _ in 0..max_frames {
            let Some(front) = self.entries.front() else {
                break;
            };
            match send(front.payload().to_vec()) {
                Ok(()) => {
                    self.entries.pop_front();
                    sent_any = true;
                }
                Err(err) => {
                    if is_fatal(&err) {
                        self.entries.pop_front();
                        continue;
                    }
                    break;
                }
            }
        }
        sent_any
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GlobalUpdatePhase {
    Idle,
    Running,
    Cancelled,
    Installing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CancelAttempt {
    Cancelled,
    AlreadyInstalling,
    NotOwnedOrIdle,
}

struct GlobalUpdateSlot {
    phase: GlobalUpdatePhase,
    active_gen: u64,
    next_gen: u64,
    active_cancel: Option<Arc<AtomicBool>>,
}

/// 进程级被控端更新互斥锁与统一阶段状态机：
/// 所有状态迁移（获取锁 / 取消 / 进入不可取消安装 / 释放锁）均在单一互斥锁下线性化，
/// 彻底消除跨会话重连双安装、安装/取消 TOCTOU 及重复释放问题。
struct HostUpdateGlobalLock {
    slot: Mutex<GlobalUpdateSlot>,
}

impl HostUpdateGlobalLock {
    fn new() -> Self {
        Self {
            slot: Mutex::new(GlobalUpdateSlot {
                phase: GlobalUpdatePhase::Idle,
                active_gen: 0,
                next_gen: 0,
                active_cancel: None,
            }),
        }
    }

    fn global() -> &'static Arc<Self> {
        static LOCK: OnceLock<Arc<HostUpdateGlobalLock>> = OnceLock::new();
        LOCK.get_or_init(|| Arc::new(HostUpdateGlobalLock::new()))
    }

    fn try_acquire(&self) -> Option<(u64, Arc<AtomicBool>)> {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot.phase != GlobalUpdatePhase::Idle {
            return None;
        }
        slot.next_gen = slot.next_gen.wrapping_add(1);
        if slot.next_gen == 0 {
            slot.next_gen = 1;
        }
        let task_gen = slot.next_gen;
        let cancel_flag = Arc::new(AtomicBool::new(false));
        slot.phase = GlobalUpdatePhase::Running;
        slot.active_gen = task_gen;
        slot.active_cancel = Some(Arc::clone(&cancel_flag));
        Some((task_gen, cancel_flag))
    }

    fn try_enter_installing(&self, task_gen: u64) -> bool {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot.active_gen == task_gen && slot.phase == GlobalUpdatePhase::Running {
            slot.phase = GlobalUpdatePhase::Installing;
            true
        } else {
            false
        }
    }

    fn try_cancel_for_gen(&self, task_gen: u64) -> CancelAttempt {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot.phase == GlobalUpdatePhase::Installing {
            return CancelAttempt::AlreadyInstalling;
        }
        if task_gen != 0
            && slot.active_gen == task_gen
            && matches!(
                slot.phase,
                GlobalUpdatePhase::Running | GlobalUpdatePhase::Cancelled
            )
        {
            slot.phase = GlobalUpdatePhase::Cancelled;
            if let Some(ref flag) = slot.active_cancel {
                flag.store(true, AtomicOrdering::Release);
            }
            CancelAttempt::Cancelled
        } else {
            CancelAttempt::NotOwnedOrIdle
        }
    }

    fn release(&self, task_gen: u64) {
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot.active_gen == task_gen {
            slot.phase = GlobalUpdatePhase::Idle;
            slot.active_gen = 0;
            slot.active_cancel = None;
        }
    }

    fn is_worker_alive(&self) -> bool {
        let slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        slot.phase != GlobalUpdatePhase::Idle
    }

    fn is_installing(&self) -> bool {
        let slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        slot.phase == GlobalUpdatePhase::Installing
    }

    fn is_cancelled(&self, task_gen: u64) -> bool {
        let slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        slot.active_gen != task_gen || slot.phase == GlobalUpdatePhase::Cancelled
    }
}

struct WorkerAliveGuard {
    lock: Arc<HostUpdateGlobalLock>,
    task_gen: u64,
    released: bool,
}

impl WorkerAliveGuard {
    fn new(lock: Arc<HostUpdateGlobalLock>, task_gen: u64) -> Self {
        Self {
            lock,
            task_gen,
            released: false,
        }
    }

    /// 显式释放进程级 worker 占用标记（须在向主循环发送终态/中转交接事件之前调用，避免紧随而来的重试或 `UpdateChunkBegin` 误触发 busy 拒绝）。
    fn release(&mut self) {
        if !self.released {
            self.released = true;
            self.lock.release(self.task_gen);
        }
    }
}

impl Drop for WorkerAliveGuard {
    fn drop(&mut self) {
        self.release();
    }
}

struct TempUpdateFileGuard {
    file: Option<File>,
    path: PathBuf,
}

impl TempUpdateFileGuard {
    fn close_file(&mut self) {
        self.file = None;
    }
}

impl Drop for TempUpdateFileGuard {
    fn drop(&mut self) {
        // 先显式释放文件句柄，再删除临时文件（兼容 Windows 及严格删除语义文件系统）。
        self.file = None;
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

enum RelayRxCmd {
    Data { offset: u64, data_base64: String },
    End,
    Abort,
}

struct AwaitingRelayMeta {
    target_version: String,
    asset_name: String,
    expected_sha256: String,
    request_id: u64,
}

enum HostWorkerEvent {
    Outbound(DisplayControlMsg),
    /// 原子推送 `need_controller_relay: true` 并置位 `awaiting_relay`，消除双事件竞态。
    DirectDownloadFailedForRelay {
        status: DisplayControlMsg,
        meta: AwaitingRelayMeta,
    },
    WorkerDone,
}

/// 被控端远程更新执行状态机（运行于 `host_bridge` 会话循环内，所有阻塞下载、分块落盘、SHA-256 与安装均在独立后台线程执行，零阻塞媒体热路径）。
///
/// 安全不变量：
/// - 仅 `is_owner_session == true`（同账号本人 `OwnerTicket` Ed25519 PoP 认证通过）放行；
/// - 无论直连下载还是控制端中转推送，均严格校验 64 位 SHA-256 与平台代码签名后才允许安装；
/// - 进程级全局互斥锁（`HostUpdateGlobalLock`）与原子阶段 CAS（`TaskPhaseState`）防止跨会话重连并发安装与取消/安装 TOCTOU；
/// - `Drop` 或会话切换自动置取消标记并清理受控临时文件。
pub struct HostUpdateWorker {
    busy: bool,
    global_lock: Arc<HostUpdateGlobalLock>,
    owned_gen: u64,
    active_request_id: u64,
    saw_terminal_or_install: bool,
    events_rx: Option<mpsc::Receiver<HostWorkerEvent>>,
    awaiting_relay: Option<AwaitingRelayMeta>,
    relay_cmd_tx: Option<mpsc::SyncSender<RelayRxCmd>>,
    relay_target_version: String,
    #[cfg(test)]
    last_relay_path: Option<PathBuf>,
    pending_out: VecDeque<DisplayControlMsg>,
}

impl Default for HostUpdateWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl HostUpdateWorker {
    /// 构造空闲态的被控端远程更新状态机（共享进程级互斥锁）。
    pub fn new() -> Self {
        Self::with_lock(Arc::clone(HostUpdateGlobalLock::global()))
    }

    fn with_lock(global_lock: Arc<HostUpdateGlobalLock>) -> Self {
        Self {
            busy: false,
            global_lock,
            owned_gen: 0,
            active_request_id: 0,
            saw_terminal_or_install: false,
            events_rx: None,
            awaiting_relay: None,
            relay_cmd_tx: None,
            relay_target_version: String::new(),
            #[cfg(test)]
            last_relay_path: None,
            pending_out: VecDeque::new(),
        }
    }

    fn is_task_running(&self) -> bool {
        self.busy || self.global_lock.is_worker_alive() || self.relay_cmd_tx.is_some()
    }

    /// 当前会话是否处于控制端中转接收或等待中转阶段。
    pub fn has_active_or_pending_relay(&self) -> bool {
        self.relay_cmd_tx.is_some() || self.awaiting_relay.is_some()
    }

    fn push_pending_out(&mut self, msg: DisplayControlMsg) {
        match classify_update_tx_msg(&msg) {
            UpdateTxClass::Ack => {
                if let DisplayControlMsg::UpdateChunkAck { next_offset } = msg {
                    if let Some(DisplayControlMsg::UpdateChunkAck {
                        next_offset: existing,
                    }) = self
                        .pending_out
                        .iter_mut()
                        .find(|m| matches!(m, DisplayControlMsg::UpdateChunkAck { .. }))
                    {
                        *existing = (*existing).max(next_offset);
                        return;
                    }
                }
                if self.pending_out.len() >= MAX_HOST_UPDATE_PENDING_OUT {
                    if let Some(pos) = self
                        .pending_out
                        .iter()
                        .position(|m| classify_update_tx_msg(m) == UpdateTxClass::Progress)
                    {
                        self.pending_out.remove(pos);
                    } else {
                        return;
                    }
                }
                self.pending_out.push_back(msg);
            }
            UpdateTxClass::Progress => {
                if self.pending_out.len() >= MAX_HOST_UPDATE_PENDING_OUT {
                    if let Some(slot) = self
                        .pending_out
                        .iter_mut()
                        .rev()
                        .find(|m| classify_update_tx_msg(m) == UpdateTxClass::Progress)
                    {
                        *slot = msg;
                    }
                    return;
                }
                self.pending_out.push_back(msg);
            }
            UpdateTxClass::Critical => {
                if self.pending_out.len() >= MAX_HOST_UPDATE_PENDING_OUT {
                    if let Some(pos) = self
                        .pending_out
                        .iter()
                        .position(|m| classify_update_tx_msg(m) == UpdateTxClass::Progress)
                    {
                        self.pending_out.remove(pos);
                    } else if let Some(pos) = self
                        .pending_out
                        .iter()
                        .position(|m| classify_update_tx_msg(m) != UpdateTxClass::Ack)
                    {
                        self.pending_out.remove(pos);
                    }
                }
                self.pending_out.push_back(msg);
            }
        }
    }

    fn drain_worker_events(&mut self) {
        let mut clear_rx = false;
        let mut buffered: Vec<HostWorkerEvent> = Vec::new();
        if let Some(ref rx) = self.events_rx {
            loop {
                match rx.try_recv() {
                    Ok(ev) => {
                        let is_terminal = matches!(
                            ev,
                            HostWorkerEvent::DirectDownloadFailedForRelay { .. }
                                | HostWorkerEvent::WorkerDone
                        );
                        buffered.push(ev);
                        if is_terminal {
                            clear_rx = true;
                            break;
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.busy = false;
                        self.owned_gen = 0;
                        self.relay_cmd_tx = None;
                        self.relay_target_version.clear();
                        clear_rx = true;
                        break;
                    }
                }
            }
        }
        if clear_rx {
            self.events_rx = None;
        }
        for ev in buffered {
            match ev {
                HostWorkerEvent::Outbound(msg) => {
                    if matches!(
                        msg,
                        DisplayControlMsg::UpdateStatus {
                            stage: UpdateStage::Installing
                                | UpdateStage::Restarting
                                | UpdateStage::Succeeded
                                | UpdateStage::Failed,
                            ..
                        }
                    ) {
                        self.saw_terminal_or_install = true;
                    }
                    self.push_pending_out(msg);
                }
                HostWorkerEvent::DirectDownloadFailedForRelay { status, meta } => {
                    self.awaiting_relay = Some(meta);
                    self.busy = false;
                    self.owned_gen = 0;
                    self.push_pending_out(status);
                }
                HostWorkerEvent::WorkerDone => {
                    self.busy = false;
                    self.owned_gen = 0;
                    self.active_request_id = 0;
                    self.relay_cmd_tx = None;
                    self.relay_target_version.clear();
                }
            }
        }
    }

    /// 构造本机当前版本与更新能力通告消息。
    pub fn build_version_info_msg(is_owner_session: bool) -> DisplayControlMsg {
        DisplayControlMsg::HostVersionInfo {
            version: crate::platform::current_app_version(),
            arch: crate::platform::current_app_arch().to_string(),
            os: std::env::consts::OS.to_string(),
            update_capable: crate::platform::can_self_update(),
            is_owner_session,
            service_installed: crate::platform::is_system_service_installed(),
        }
    }

    /// 取消当前会话正在进行的更新并复位会话级通道（例如会话结束或切换客户端时调用）。
    ///
    /// 注意：仅取消本会话持有的 `owned_gen`，不打断已进入 `Installing` 的安装阶段，也不强行清零全局锁。
    pub fn reset(&mut self) {
        if self.owned_gen != 0 {
            let _ = self.global_lock.try_cancel_for_gen(self.owned_gen);
            self.owned_gen = 0;
        }
        self.busy = false;
        self.active_request_id = 0;
        self.saw_terminal_or_install = false;
        self.events_rx = None;
        self.awaiting_relay = None;
        self.relay_cmd_tx = None;
        self.relay_target_version.clear();
        self.pending_out.clear();
    }

    /// 在传输层短暂断链并经 `Resumed` 恢复后中止正在进行或等待中的分块中转（保留未受影响的直连下载与安装阶段）。
    pub fn abort_relay_on_transport_resume(&mut self, reason: &str) {
        if !self.has_active_or_pending_relay() {
            return;
        }
        if self.global_lock.is_installing() {
            return;
        }
        if self.owned_gen != 0
            && matches!(
                self.global_lock.try_cancel_for_gen(self.owned_gen),
                CancelAttempt::AlreadyInstalling
            )
        {
            return;
        }
        let req_id = if self.active_request_id != 0 {
            self.active_request_id
        } else {
            self.awaiting_relay.as_ref().map_or(0, |m| m.request_id)
        };
        let ver = if !self.relay_target_version.is_empty() {
            self.relay_target_version.clone()
        } else {
            self.awaiting_relay
                .as_ref()
                .map(|m| m.target_version.clone())
                .unwrap_or_default()
        };
        if let Some(tx) = self.relay_cmd_tx.take() {
            let _ = tx.try_send(RelayRxCmd::Abort);
        }
        self.owned_gen = 0;
        self.active_request_id = 0;
        self.busy = false;
        self.events_rx = None;
        self.awaiting_relay = None;
        self.relay_target_version.clear();
        self.pending_out.clear();
        self.push_pending_out(fail_status_msg(req_id, &ver, reason, reason));
    }

    /// 处理一条来自控制端的远程更新相关 [`DisplayControlMsg`]。
    pub fn handle_message(&mut self, msg: DisplayControlMsg, is_owner_session: bool) {
        if !is_owner_session {
            // 防止未授权 Guest 高频灌帧放大出站队列（已有拒绝响应排队时合并去重）。
            let already_rejected = matches!(
                self.pending_out.back(),
                Some(DisplayControlMsg::UpdateStatus {
                    stage: UpdateStage::Failed,
                    ..
                })
            );
            if !already_rejected {
                let req_id = match &msg {
                    DisplayControlMsg::UpdateTrigger { request_id, .. } => *request_id,
                    _ => 0,
                };
                self.push_pending_out(fail_status_msg(
                    req_id,
                    "",
                    "仅同账号本人自控允许远程更新被控端",
                    "仅同账号本人自控允许远程更新被控端",
                ));
            }
            return;
        }

        match msg {
            DisplayControlMsg::UpdateTrigger {
                target_version,
                download_url,
                expected_sha256,
                asset_name,
                mirror_url,
                relay_fallback_allowed,
                request_id,
            } => {
                self.start_trigger(
                    target_version,
                    download_url,
                    expected_sha256,
                    asset_name,
                    mirror_url,
                    relay_fallback_allowed,
                    request_id,
                );
            }
            DisplayControlMsg::UpdateCancel => {
                let req_id = if self.active_request_id != 0 {
                    self.active_request_id
                } else {
                    self.awaiting_relay.as_ref().map_or(0, |m| m.request_id)
                };
                if self.global_lock.is_installing() {
                    let ver = self.relay_target_version.clone();
                    self.push_pending_out(progress_to_msg(
                        UpdateProgress {
                            stage: UpdateStage::Installing,
                            progress_pct: 95,
                            downloaded_bytes: 0,
                            total_bytes: 0,
                            target_version: ver,
                            message: "被控端正在原子替换应用，当前阶段暂不可取消".to_string(),
                            need_controller_relay: false,
                            error: None,
                        },
                        req_id,
                    ));
                    return;
                }
                if self.owned_gen != 0 {
                    match self.global_lock.try_cancel_for_gen(self.owned_gen) {
                        CancelAttempt::AlreadyInstalling => {
                            let ver = self.relay_target_version.clone();
                            self.push_pending_out(progress_to_msg(
                                UpdateProgress {
                                    stage: UpdateStage::Installing,
                                    progress_pct: 95,
                                    downloaded_bytes: 0,
                                    total_bytes: 0,
                                    target_version: ver,
                                    message: "被控端正在原子替换应用，当前阶段暂不可取消"
                                        .to_string(),
                                    need_controller_relay: false,
                                    error: None,
                                },
                                req_id,
                            ));
                            return;
                        }
                        CancelAttempt::Cancelled => {
                            let ver = self.relay_target_version.clone();
                            self.reset();
                            self.push_pending_out(fail_status_msg(
                                req_id,
                                &ver,
                                "远程更新已取消",
                                "远程更新已取消",
                            ));
                            return;
                        }
                        CancelAttempt::NotOwnedOrIdle => {
                            // 工作线程可能刚释放全局锁并把 `DirectDownloadFailedForRelay` 写入 `events_rx`，
                            // 或正停在 `alive_guard.release()` 与 `tx.send(DirectDownloadFailedForRelay)` 之间；
                            // 先排空事件：凡非中转终态（`Installing`/`Restarting`/`Failed`）均在释放全局锁前已写入并具备 happens-before，
                            // 故若排空后仍未见终态且 `events_rx` 仍存活，则必处于未送达的中转交接窗口，直接复位丢弃 `events_rx` 并回传已取消。
                            self.drain_worker_events();
                            if !self.saw_terminal_or_install && self.events_rx.is_some() {
                                let ver = self.relay_target_version.clone();
                                self.reset();
                                self.push_pending_out(fail_status_msg(
                                    req_id,
                                    &ver,
                                    "远程更新已取消",
                                    "远程更新已取消",
                                ));
                                return;
                            }
                        }
                    }
                } else if self.events_rx.is_some() {
                    self.drain_worker_events();
                }
                if let Some(meta) = self.awaiting_relay.as_ref() {
                    let ver = meta.target_version.clone();
                    let meta_req_id = meta.request_id;
                    self.reset();
                    self.push_pending_out(fail_status_msg(
                        meta_req_id,
                        &ver,
                        "远程更新已取消",
                        "远程更新已取消",
                    ));
                }
            }
            DisplayControlMsg::UpdateChunkBegin {
                target_version,
                asset_name,
                total_bytes,
                expected_sha256,
            } => {
                self.handle_chunk_begin(target_version, asset_name, total_bytes, expected_sha256);
            }
            DisplayControlMsg::UpdateChunkData {
                offset,
                data_base64,
            } => {
                self.handle_chunk_data(offset, data_base64);
            }
            DisplayControlMsg::UpdateChunkEnd => {
                self.handle_chunk_end();
            }
            DisplayControlMsg::UpdateChunkAbort { .. } => {
                // 先排空后台线程已写出的诊断/完成事件，避免覆盖主机自身的真实失败原因。
                self.drain_worker_events();
                if !self.has_active_or_pending_relay() {
                    return;
                }
                if self.global_lock.is_installing() {
                    return;
                }
                if self.owned_gen != 0
                    && matches!(
                        self.global_lock.try_cancel_for_gen(self.owned_gen),
                        CancelAttempt::AlreadyInstalling
                    )
                {
                    return;
                }
                if let Some(tx) = self.relay_cmd_tx.take() {
                    let _ = tx.try_send(RelayRxCmd::Abort);
                }
                // `UpdateChunkAbort` 仅由控制端发起且控制端已在本地上报 Failed，被控端静默清理即可，
                // 避免延迟回声的 `UpdateStatus(Failed)` 误杀控制端紧随其后的重试。
                self.reset();
            }
            _ => {}
        }
    }

    /// 非阻塞拉取所有待发往控制端的更新状态/流控确认消息。
    pub fn poll_outgoing(&mut self) -> Vec<DisplayControlMsg> {
        self.drain_worker_events();
        self.pending_out.drain(..).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn start_trigger(
        &mut self,
        target_version: String,
        download_url: String,
        expected_sha256: String,
        asset_name: String,
        mirror_url: String,
        relay_fallback_allowed: bool,
        request_id: u64,
    ) {
        self.drain_worker_events();
        if self.busy || self.relay_cmd_tx.is_some() {
            self.push_pending_out(fail_status_msg(
                request_id,
                &target_version,
                "被控端当前已有更新任务正在进行",
                "被控端当前已有更新任务正在进行",
            ));
            return;
        }
        let Some((task_gen, cancel_flag)) = self.global_lock.try_acquire() else {
            self.push_pending_out(fail_status_msg(
                request_id,
                &target_version,
                "被控端当前已有更新任务正在进行",
                "被控端当前已有更新任务正在进行",
            ));
            return;
        };
        let mut alive_guard = WorkerAliveGuard::new(Arc::clone(&self.global_lock), task_gen);
        if !crate::platform::can_self_update() {
            alive_guard.release();
            self.push_pending_out(fail_status_msg(
                request_id,
                &target_version,
                "当前被控端运行环境暂不支持远程自动更新",
                "当前被控端运行环境暂不支持远程自动更新",
            ));
            return;
        }
        if SemVer::parse(&target_version).is_none()
            || !is_safe_asset_name(&asset_name)
            || !is_valid_sha256_hex(&expected_sha256)
        {
            alive_guard.release();
            self.push_pending_out(fail_status_msg(
                request_id,
                &target_version,
                "更新请求参数无效（版本号、文件名或 SHA-256 校验失败）",
                "更新请求参数无效",
            ));
            return;
        }
        let effective_url = match apply_mirror_prefix(&mirror_url, &download_url) {
            Ok(u) => u,
            Err(err) => {
                alive_guard.release();
                self.push_pending_out(fail_status_msg(
                    request_id,
                    &target_version,
                    err.clone(),
                    err,
                ));
                return;
            }
        };

        self.awaiting_relay = None;
        self.busy = true;
        self.saw_terminal_or_install = false;
        self.owned_gen = task_gen;
        self.active_request_id = request_id;
        self.relay_target_version = target_version.clone();
        let global_lock = Arc::clone(&self.global_lock);
        let (tx, rx) = mpsc::channel::<HostWorkerEvent>();
        self.events_rx = Some(rx);

        let expected_lower = expected_sha256.trim().to_ascii_lowercase();
        let target_ver_for_err = target_version.clone();
        if let Err(err) = thread::Builder::new()
            .name("rc-host-update".to_string())
            .spawn(move || {
                let mut alive_guard = alive_guard;
                let _ = tx.send(HostWorkerEvent::Outbound(progress_to_msg(
                    UpdateProgress {
                        stage: UpdateStage::Downloading,
                        progress_pct: 0,
                        downloaded_bytes: 0,
                        total_bytes: 0,
                        target_version: target_version.clone(),
                        message: format!("被控端正在下载 v{target_version} 安装包…"),
                        need_controller_relay: false,
                        error: None,
                    },
                    request_id,
                )));

                let tmp_path = make_temp_update_path("host-upd", &asset_name);
                let mut last_emit: Option<Instant> = None;
                let mut last_pct: u8 = 0;
                let mut on_progress = |done: u64, total: u64| {
                    let pct = scaled_pct(done, total, 90).max(last_pct);
                    let due = last_emit.map_or(true, |t| t.elapsed() >= Duration::from_millis(250));
                    if due || pct >= last_pct.saturating_add(3) {
                        last_emit = Some(Instant::now());
                        last_pct = pct;
                        let _ = tx.send(HostWorkerEvent::Outbound(progress_to_msg(
                            UpdateProgress {
                                stage: UpdateStage::Downloading,
                                progress_pct: pct,
                                downloaded_bytes: done,
                                total_bytes: total,
                                target_version: target_version.clone(),
                                message: format!("被控端正在下载 v{target_version}…"),
                                need_controller_relay: false,
                                error: None,
                            },
                            request_id,
                        )));
                    }
                };

                let dl_res = crate::platform::download_update_package(
                    &effective_url,
                    &expected_lower,
                    &tmp_path,
                    &cancel_flag,
                    &mut on_progress,
                );

                match dl_res {
                    Ok(()) => {
                        if !global_lock.try_enter_installing(task_gen) {
                            let _ = fs::remove_file(&tmp_path);
                            alive_guard.release();
                            let _ = tx.send(HostWorkerEvent::WorkerDone);
                            return;
                        }
                        run_host_install_and_report(
                            &tx,
                            &tmp_path,
                            &expected_lower,
                            &target_version,
                            request_id,
                        );
                        alive_guard.release();
                        let _ = tx.send(HostWorkerEvent::WorkerDone);
                    }
                    Err(err) => {
                        let _ = fs::remove_file(&tmp_path);
                        if global_lock.is_cancelled(task_gen) {
                            alive_guard.release();
                            let _ = tx.send(HostWorkerEvent::WorkerDone);
                            return;
                        }
                        if relay_fallback_allowed {
                            let status = progress_to_msg(
                                UpdateProgress {
                                    stage: UpdateStage::Relaying,
                                    progress_pct: 0,
                                    downloaded_bytes: 0,
                                    total_bytes: 0,
                                    target_version: target_version.clone(),
                                    message: "被控端直连下载失败，正在由控制端下载并中转推送…"
                                        .to_string(),
                                    need_controller_relay: true,
                                    error: None,
                                },
                                request_id,
                            );
                            alive_guard.release();
                            let _ = tx.send(HostWorkerEvent::DirectDownloadFailedForRelay {
                                status,
                                meta: AwaitingRelayMeta {
                                    target_version,
                                    asset_name,
                                    expected_sha256: expected_lower,
                                    request_id,
                                },
                            });
                        } else {
                            let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                                request_id,
                                &target_version,
                                format!("被控端下载更新失败：{err}"),
                                err,
                            )));
                            alive_guard.release();
                            let _ = tx.send(HostWorkerEvent::WorkerDone);
                        }
                    }
                }
            })
        {
            // `alive_guard` 已随失败闭包 drop 并释放 `task_gen`，此处不再重复释放。
            self.busy = false;
            self.owned_gen = 0;
            self.active_request_id = 0;
            self.events_rx = None;
            self.relay_target_version.clear();
            self.push_pending_out(fail_status_msg(
                request_id,
                &target_ver_for_err,
                format!("启动被控端更新线程失败：{err}"),
                format!("{err}"),
            ));
        }
    }

    fn handle_chunk_begin(
        &mut self,
        target_version: String,
        asset_name: String,
        total_bytes: u64,
        expected_sha256: String,
    ) {
        self.drain_worker_events();
        if self.is_task_running() {
            self.push_pending_out(fail_status_msg(
                self.active_request_id,
                &target_version,
                "被控端当前已有更新任务正在进行",
                "被控端当前已有更新任务正在进行",
            ));
            return;
        }
        let Some(meta) = self.awaiting_relay.take() else {
            self.push_pending_out(fail_status_msg(
                0,
                &target_version,
                "被控端未处于等待安装包中转状态",
                "被控端未处于等待安装包中转状态",
            ));
            return;
        };
        let req_id = meta.request_id;
        if meta.target_version != target_version
            || meta.asset_name != asset_name
            || !constant_time_eq_hex(&meta.expected_sha256, &expected_sha256)
            || total_bytes == 0
            || total_bytes > MAX_UPDATE_PACKAGE_BYTES
        {
            self.push_pending_out(fail_status_msg(
                req_id,
                &target_version,
                "中转安装包元数据校验不匹配或体积超限",
                "中转安装包元数据校验不匹配或体积超限",
            ));
            return;
        }
        let Some((task_gen, _cancel_flag)) = self.global_lock.try_acquire() else {
            self.awaiting_relay = Some(meta);
            self.push_pending_out(fail_status_msg(
                req_id,
                &target_version,
                "被控端当前已有更新任务正在进行",
                "被控端当前已有更新任务正在进行",
            ));
            return;
        };
        let alive_guard = WorkerAliveGuard::new(Arc::clone(&self.global_lock), task_gen);

        let path = make_temp_update_path("host-relay", &asset_name);
        #[cfg(test)]
        {
            self.last_relay_path = Some(path.clone());
        }

        let (cmd_tx, cmd_rx) = mpsc::sync_channel::<RelayRxCmd>(16);
        let (ev_tx, ev_rx) = mpsc::channel::<HostWorkerEvent>();
        self.busy = true;
        self.saw_terminal_or_install = false;
        self.owned_gen = task_gen;
        self.active_request_id = req_id;
        self.relay_cmd_tx = Some(cmd_tx);
        self.relay_target_version = meta.target_version.clone();
        self.events_rx = Some(ev_rx);

        let global_lock = Arc::clone(&self.global_lock);
        let tv_for_err = meta.target_version.clone();

        if let Err(err) = thread::Builder::new()
            .name("rc-host-update-relay".to_string())
            .spawn(move || {
                run_host_relay_receiver_thread(
                    cmd_rx,
                    ev_tx,
                    path,
                    meta.target_version,
                    meta.expected_sha256,
                    total_bytes,
                    task_gen,
                    req_id,
                    global_lock,
                    alive_guard,
                );
            })
        {
            // `alive_guard` 已随失败闭包 drop 并释放 `task_gen`，此处不再重复释放。
            self.busy = false;
            self.owned_gen = 0;
            self.active_request_id = 0;
            self.relay_cmd_tx = None;
            self.events_rx = None;
            self.relay_target_version.clear();
            self.push_pending_out(fail_status_msg(
                req_id,
                &tv_for_err,
                format!("启动中转接收线程失败：{err}"),
                format!("{err}"),
            ));
        }
    }

    fn handle_chunk_data(&mut self, offset: u64, data_base64: String) {
        let Some(ref tx) = self.relay_cmd_tx else {
            return;
        };
        match tx.try_send(RelayRxCmd::Data {
            offset,
            data_base64,
        }) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                let ver = self.relay_target_version.clone();
                let req_id = self.active_request_id;
                self.reset();
                self.push_pending_out(fail_status_msg(
                    req_id,
                    &ver,
                    "被控端中转接收队列满载",
                    "被控端中转接收队列满载",
                ));
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                // 接收线程已退出（通常已写入真实诊断错误到 `events_rx`），仅停止继续喂入并保留 `events_rx` 供 `poll_outgoing` 完整吐出。
                self.relay_cmd_tx = None;
            }
        }
    }

    fn handle_chunk_end(&mut self) {
        let Some(tx) = self.relay_cmd_tx.take() else {
            return;
        };
        match tx.try_send(RelayRxCmd::End) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                let ver = self.relay_target_version.clone();
                let req_id = self.active_request_id;
                self.reset();
                self.push_pending_out(fail_status_msg(
                    req_id,
                    &ver,
                    "被控端中转接收队列满载，无法提交结束信号",
                    "被控端中转接收队列满载",
                ));
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                // 保留 `events_rx` 以便吐出接收线程先前写入的真实失败原因。
            }
        }
    }
}

impl Drop for HostUpdateWorker {
    fn drop(&mut self) {
        if self.owned_gen != 0 {
            let _ = self.global_lock.try_cancel_for_gen(self.owned_gen);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_host_relay_receiver_thread(
    cmd_rx: mpsc::Receiver<RelayRxCmd>,
    tx: mpsc::Sender<HostWorkerEvent>,
    path: PathBuf,
    target_version: String,
    expected_sha256: String,
    total_bytes: u64,
    task_gen: u64,
    request_id: u64,
    global_lock: Arc<HostUpdateGlobalLock>,
    mut alive_guard: WorkerAliveGuard,
) {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = match opts.open(&path) {
        Ok(f) => f,
        Err(err) => {
            let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                request_id,
                &target_version,
                format!("创建中转临时文件失败：{err}"),
                format!("{err}"),
            )));
            alive_guard.release();
            let _ = tx.send(HostWorkerEvent::WorkerDone);
            return;
        }
    };

    let mut guard = TempUpdateFileGuard {
        file: Some(file),
        path,
    };
    let _ = tx.send(HostWorkerEvent::Outbound(
        DisplayControlMsg::UpdateChunkAck { next_offset: 0 },
    ));

    let mut received_bytes: u64 = 0;
    let mut hasher = Sha256::new();
    let mut last_status_at: Option<Instant> = None;
    let mut last_status_pct: u8 = 0;
    let mut last_activity = Instant::now();

    loop {
        if global_lock.is_cancelled(task_gen) {
            break;
        }
        let cmd = match cmd_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(cmd) => {
                last_activity = Instant::now();
                cmd
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if last_activity.elapsed() >= RELAY_RX_IDLE_TIMEOUT {
                    let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                        request_id,
                        &target_version,
                        "等待控制端中转安装包分块超时，已中止更新",
                        "等待控制端中转安装包分块超时",
                    )));
                    drop(guard);
                    alive_guard.release();
                    let _ = tx.send(HostWorkerEvent::WorkerDone);
                    return;
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        match cmd {
            RelayRxCmd::Data {
                offset,
                data_base64,
            } => {
                if offset != received_bytes {
                    let msg = format!("中转分块偏移失序（期望 {received_bytes}，收到 {offset}）");
                    let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                        request_id,
                        &target_version,
                        msg.clone(),
                        msg,
                    )));
                    drop(guard);
                    alive_guard.release();
                    let _ = tx.send(HostWorkerEvent::WorkerDone);
                    return;
                }
                let Some(bytes) = display_ctrl::base64_decode(&data_base64) else {
                    let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                        request_id,
                        &target_version,
                        "中转分块 Base64 解码失败",
                        "中转分块 Base64 解码失败",
                    )));
                    drop(guard);
                    alive_guard.release();
                    let _ = tx.send(HostWorkerEvent::WorkerDone);
                    return;
                };
                if bytes.is_empty() || bytes.len() > UPDATE_RELAY_CHUNK_BYTES {
                    let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                        request_id,
                        &target_version,
                        "中转分块大小超出限制",
                        "中转分块大小超出限制",
                    )));
                    drop(guard);
                    alive_guard.release();
                    let _ = tx.send(HostWorkerEvent::WorkerDone);
                    return;
                }
                if received_bytes.saturating_add(bytes.len() as u64) > total_bytes {
                    let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                        request_id,
                        &target_version,
                        "中转分块总字节超出声明大小",
                        "中转分块总字节超出声明大小",
                    )));
                    drop(guard);
                    alive_guard.release();
                    let _ = tx.send(HostWorkerEvent::WorkerDone);
                    return;
                }
                if let Some(ref mut f) = guard.file {
                    if let Err(err) = f.write_all(&bytes) {
                        let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                            request_id,
                            &target_version,
                            format!("写入中转安装包失败：{err}"),
                            format!("{err}"),
                        )));
                        drop(guard);
                        alive_guard.release();
                        let _ = tx.send(HostWorkerEvent::WorkerDone);
                        return;
                    }
                }
                hasher.update(&bytes);
                received_bytes = received_bytes.saturating_add(bytes.len() as u64);

                let _ = tx.send(HostWorkerEvent::Outbound(
                    DisplayControlMsg::UpdateChunkAck {
                        next_offset: received_bytes,
                    },
                ));

                let pct = scaled_pct(received_bytes, total_bytes, 90).max(last_status_pct);
                let due =
                    last_status_at.map_or(true, |t| t.elapsed() >= Duration::from_millis(250));
                if due || pct >= last_status_pct.saturating_add(5) || received_bytes == total_bytes
                {
                    last_status_at = Some(Instant::now());
                    last_status_pct = pct;
                    let _ = tx.send(HostWorkerEvent::Outbound(progress_to_msg(
                        UpdateProgress {
                            stage: UpdateStage::Relaying,
                            progress_pct: pct,
                            downloaded_bytes: received_bytes,
                            total_bytes,
                            target_version: target_version.clone(),
                            message: format!("正在接收控制端中转安装包 v{target_version}…"),
                            need_controller_relay: false,
                            error: None,
                        },
                        request_id,
                    )));
                }
            }
            RelayRxCmd::End => {
                if received_bytes != total_bytes {
                    let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                        request_id,
                        &target_version,
                        format!("中转安装包接收不完整（{received_bytes}/{total_bytes} 字节）"),
                        "中转安装包接收不完整",
                    )));
                    drop(guard);
                    alive_guard.release();
                    let _ = tx.send(HostWorkerEvent::WorkerDone);
                    return;
                }
                if let Some(ref mut f) = guard.file {
                    if let Err(err) = f.sync_all() {
                        let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                            request_id,
                            &target_version,
                            format!("落盘中转安装包失败：{err}"),
                            format!("{err}"),
                        )));
                        drop(guard);
                        alive_guard.release();
                        let _ = tx.send(HostWorkerEvent::WorkerDone);
                        return;
                    }
                }
                // 先关闭文件句柄，再做最终哈希与安装（保证 Windows / APFS 安全打开和清理）。
                guard.close_file();
                let actual_hex = encode_hex_lower(&hasher.finalize());
                if !constant_time_eq_hex(&actual_hex, &expected_sha256) {
                    let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                        request_id,
                        &target_version,
                        "中转安装包 SHA-256 校验失败，已自动清理",
                        "中转安装包 SHA-256 校验失败",
                    )));
                    drop(guard);
                    alive_guard.release();
                    let _ = tx.send(HostWorkerEvent::WorkerDone);
                    return;
                }
                if !global_lock.try_enter_installing(task_gen) {
                    drop(guard);
                    alive_guard.release();
                    let _ = tx.send(HostWorkerEvent::WorkerDone);
                    return;
                }
                run_host_install_and_report(
                    &tx,
                    &guard.path,
                    &expected_sha256,
                    &target_version,
                    request_id,
                );
                drop(guard);
                alive_guard.release();
                let _ = tx.send(HostWorkerEvent::WorkerDone);
                return;
            }
            RelayRxCmd::Abort => {
                // 控制端主动中止中转且已在本地发出 Failed，此处静默清理临时文件并释放锁，不回声冗余 Failed。
                drop(guard);
                alive_guard.release();
                let _ = tx.send(HostWorkerEvent::WorkerDone);
                return;
            }
        }
    }
    drop(guard);
    alive_guard.release();
    let _ = tx.send(HostWorkerEvent::WorkerDone);
}

fn run_host_install_and_report(
    tx: &mpsc::Sender<HostWorkerEvent>,
    pkg_path: &Path,
    expected_sha256: &str,
    target_version: &str,
    request_id: u64,
) {
    let _ = tx.send(HostWorkerEvent::Outbound(progress_to_msg(
        UpdateProgress {
            stage: UpdateStage::Installing,
            progress_pct: 95,
            downloaded_bytes: 0,
            total_bytes: 0,
            target_version: target_version.to_string(),
            message: format!("SHA-256 与签名校验中，正在安装 v{target_version}…"),
            need_controller_relay: false,
            error: None,
        },
        request_id,
    )));
    let res = crate::platform::install_verified_update(pkg_path, expected_sha256, true, true);
    let _ = fs::remove_file(pkg_path);
    match res {
        Ok(()) => {
            let _ = tx.send(HostWorkerEvent::Outbound(progress_to_msg(
                UpdateProgress {
                    stage: UpdateStage::Restarting,
                    progress_pct: 100,
                    downloaded_bytes: 0,
                    total_bytes: 0,
                    target_version: target_version.to_string(),
                    message: format!("v{target_version} 安装完成，被控端正在重启并准备自动重连…"),
                    need_controller_relay: false,
                    error: None,
                },
                request_id,
            )));
        }
        Err(err) => {
            let _ = tx.send(HostWorkerEvent::Outbound(fail_status_msg(
                request_id,
                target_version,
                format!("被控端安装更新失败：{err}"),
                err,
            )));
        }
    }
}

struct RelayAckState {
    acked_offset: u64,
    sent_offset: u64,
}

struct RelayAckGate {
    state: Mutex<RelayAckState>,
    cv: Condvar,
}

impl RelayAckGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(RelayAckState {
                acked_offset: 0,
                sent_offset: 0,
            }),
            cv: Condvar::new(),
        }
    }

    fn note_sent(&self, end_offset: u64) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if end_offset > guard.sent_offset {
            guard.sent_offset = end_offset;
        }
    }

    fn set_acked(&self, offset: u64) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 严格拒绝超过已发送偏移的伪造未来 ACK（防止恶意对端发 `u64::MAX` 绕过 4 块滑动窗口流控）。
        if offset > guard.sent_offset {
            return;
        }
        if offset > guard.acked_offset {
            guard.acked_offset = offset;
            self.cv.notify_all();
        }
    }

    fn notify_cancel(&self) {
        let _guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.cv.notify_all();
    }

    fn wait_for_window(
        &self,
        next_send_offset: u64,
        window_bytes: u64,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while next_send_offset.saturating_sub(guard.acked_offset) >= window_bytes {
            if cancel.load(AtomicOrdering::Acquire) {
                return Err("已取消中转推送".to_string());
            }
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err("等待被控端确认中转分块超时".to_string());
            };
            let (next_guard, _) = self
                .cv
                .wait_timeout(guard, rem.min(Duration::from_millis(200)))
                .unwrap_or_else(|e| e.into_inner());
            guard = next_guard;
        }
        Ok(())
    }
}

enum ControllerRelayEvent {
    Outbound(DisplayControlMsg),
    LocalProgress(UpdateProgress),
    Done,
}

/// 控制端中转推送状态机（运行于 `session_bridge` 控制端会话线程）。
///
/// 安全不变量：仅当控制端用户在本会话中显式确认并下发 [`RemoteUpdateRequest`] 后，
/// 若被控端回传 `need_controller_relay == true`，才会使用**控制端自己保存的已确认参数**
/// （绝不采信被控端回传的任何 URL/哈希）下载校验并按滑动窗口分块推送。
pub struct ControllerUpdateRelay {
    confirmed: Option<RemoteUpdateRequest>,
    relay_active: bool,
    cancel: Arc<AtomicBool>,
    ack_gate: Arc<RelayAckGate>,
    events_rx: Option<mpsc::Receiver<ControllerRelayEvent>>,
}

impl Default for ControllerUpdateRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl ControllerUpdateRelay {
    /// 构造空闲态控制端中转推送器。
    pub fn new() -> Self {
        Self {
            confirmed: None,
            relay_active: false,
            cancel: Arc::new(AtomicBool::new(false)),
            ack_gate: Arc::new(RelayAckGate::new()),
            events_rx: None,
        }
    }

    /// 记录用户刚显式确认的远程更新请求，供被控端直连失败请求中转时使用。
    pub fn arm_confirmed_request(&mut self, req: RemoteUpdateRequest) {
        self.cancel_active_relay();
        self.confirmed = Some(req);
    }

    /// 取消当前正在进行的中转推送（不修改已发给被控端的 `UpdateCancel` 控制消息）。
    pub fn cancel_active_relay(&mut self) {
        self.cancel.store(true, AtomicOrdering::Release);
        self.ack_gate.notify_cancel();
        self.relay_active = false;
        self.events_rx = None;
        self.confirmed = None;
        self.cancel = Arc::new(AtomicBool::new(false));
        self.ack_gate = Arc::new(RelayAckGate::new());
    }

    /// 收到被控端 `UpdateChunkAck` 时推进滑动窗口。
    pub fn on_chunk_ack(&self, next_offset: u64) {
        self.ack_gate.set_acked(next_offset);
    }

    /// 当前是否处于活跃的控制端中转推送阶段。
    pub fn is_active(&self) -> bool {
        self.relay_active
    }

    /// 收到被控端 `UpdateStatus { stage: Relaying, need_controller_relay: true, .. }` 时，
    /// 若本会话存在用户已确认请求且尚未启动中转，则**一次性消耗**该确认请求并启动后台下载 + 分块推送线程。
    pub fn maybe_start_relay_for_host_request(&mut self) {
        if self.relay_active {
            return;
        }
        let Some(req) = self.confirmed.take() else {
            return;
        };
        if !req.relay_fallback_allowed {
            return;
        }
        let effective_url = match apply_mirror_prefix(&req.mirror_url, &req.download_url) {
            Ok(u) => u,
            Err(_) => return,
        };

        self.relay_active = true;
        self.cancel = Arc::new(AtomicBool::new(false));
        self.ack_gate = Arc::new(RelayAckGate::new());
        let cancel = Arc::clone(&self.cancel);
        let ack_gate = Arc::clone(&self.ack_gate);
        let (tx, rx) =
            mpsc::sync_channel::<ControllerRelayEvent>(UPDATE_RELAY_WINDOW_CHUNKS * 2 + 4);
        self.events_rx = Some(rx);

        let tx_fail = tx.clone();
        let req_ver = req.target_version.clone();
        if let Err(err) = thread::Builder::new()
            .name("rc-ctrl-update-relay".to_string())
            .spawn(move || {
                let tmp_path = make_temp_update_path("ctrl-relay", &req.asset_name);
                let _ = tx.try_send(ControllerRelayEvent::LocalProgress(UpdateProgress {
                    stage: UpdateStage::Relaying,
                    progress_pct: 1,
                    downloaded_bytes: 0,
                    total_bytes: 0,
                    target_version: req.target_version.clone(),
                    message: format!("控制端正在代为下载 v{} 安装包…", req.target_version),
                    need_controller_relay: false,
                    error: None,
                }));

                let mut last_emit: Option<Instant> = None;
                let mut last_pct: u8 = 1;
                let mut on_dl = |done: u64, total: u64| {
                    let pct = scaled_pct(done, total, 50).max(last_pct);
                    let due = last_emit.map_or(true, |t| t.elapsed() >= Duration::from_millis(250));
                    if due || pct >= last_pct.saturating_add(3) {
                        last_emit = Some(Instant::now());
                        last_pct = pct;
                        let _ = tx.try_send(ControllerRelayEvent::LocalProgress(UpdateProgress {
                            stage: UpdateStage::Relaying,
                            progress_pct: pct,
                            downloaded_bytes: done,
                            total_bytes: total,
                            target_version: req.target_version.clone(),
                            message: format!("控制端正在代为下载 v{} 安装包…", req.target_version),
                            need_controller_relay: false,
                            error: None,
                        }));
                    }
                };

                if let Err(err) = crate::platform::download_update_package(
                    &effective_url,
                    &req.expected_sha256,
                    &tmp_path,
                    &cancel,
                    &mut on_dl,
                ) {
                    let _ = fs::remove_file(&tmp_path);
                    let _ = tx.send(ControllerRelayEvent::Outbound(
                        DisplayControlMsg::UpdateChunkAbort {
                            reason: format!("控制端代下失败：{err}"),
                        },
                    ));
                    let _ = tx.send(ControllerRelayEvent::LocalProgress(UpdateProgress {
                        stage: UpdateStage::Failed,
                        progress_pct: 0,
                        downloaded_bytes: 0,
                        total_bytes: 0,
                        target_version: req.target_version.clone(),
                        message: format!("控制端代为下载安装包失败：{err}"),
                        need_controller_relay: false,
                        error: Some(err),
                    }));
                    let _ = tx.send(ControllerRelayEvent::Done);
                    return;
                }

                let stream_res =
                    stream_verified_file_to_host(&tmp_path, &req, &cancel, &ack_gate, &tx);
                let _ = fs::remove_file(&tmp_path);
                if let Err(err) = stream_res {
                    let _ = tx.send(ControllerRelayEvent::Outbound(
                        DisplayControlMsg::UpdateChunkAbort {
                            reason: err.clone(),
                        },
                    ));
                    let _ = tx.send(ControllerRelayEvent::LocalProgress(UpdateProgress {
                        stage: UpdateStage::Failed,
                        progress_pct: 0,
                        downloaded_bytes: 0,
                        total_bytes: 0,
                        target_version: req.target_version.clone(),
                        message: format!("中转推送失败：{err}"),
                        need_controller_relay: false,
                        error: Some(err),
                    }));
                }
                let _ = tx.send(ControllerRelayEvent::Done);
            })
        {
            self.relay_active = false;
            let _ = tx_fail.send(ControllerRelayEvent::Outbound(
                DisplayControlMsg::UpdateChunkAbort {
                    reason: format!("启动控制端中转线程失败：{err}"),
                },
            ));
            let _ = tx_fail.send(ControllerRelayEvent::LocalProgress(UpdateProgress {
                stage: UpdateStage::Failed,
                progress_pct: 0,
                downloaded_bytes: 0,
                total_bytes: 0,
                target_version: req_ver,
                message: format!("启动控制端中转线程失败：{err}"),
                need_controller_relay: false,
                error: Some(format!("{err}")),
            }));
            let _ = tx_fail.send(ControllerRelayEvent::Done);
        }
    }

    /// 非阻塞拉取全部待发往被控端的分块消息与控制端本地进度推送。
    pub fn poll(&mut self) -> (Vec<DisplayControlMsg>, Vec<UpdateProgress>) {
        self.poll_bounded(usize::MAX)
    }

    /// 非阻塞按上限 `max_outbound` 拉取待发往被控端的分块消息与控制端本地进度推送，防止背压下一次性排空撑爆出站队列。
    pub fn poll_bounded(
        &mut self,
        max_outbound: usize,
    ) -> (Vec<DisplayControlMsg>, Vec<UpdateProgress>) {
        let mut msgs = Vec::new();
        let mut progs = Vec::new();
        let mut done = false;
        if let Some(ref rx) = self.events_rx {
            while msgs.len() < max_outbound {
                match rx.try_recv() {
                    Ok(ControllerRelayEvent::Outbound(m)) => msgs.push(m),
                    Ok(ControllerRelayEvent::LocalProgress(p)) => progs.push(p),
                    Ok(ControllerRelayEvent::Done) => {
                        done = true;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        done = true;
                        break;
                    }
                }
            }
        }
        if done {
            self.relay_active = false;
            self.events_rx = None;
        }
        (msgs, progs)
    }
}

impl Drop for ControllerUpdateRelay {
    fn drop(&mut self) {
        self.cancel.store(true, AtomicOrdering::Release);
        self.ack_gate.notify_cancel();
    }
}

fn stream_verified_file_to_host(
    path: &Path,
    req: &RemoteUpdateRequest,
    cancel: &AtomicBool,
    ack_gate: &RelayAckGate,
    tx: &mpsc::SyncSender<ControllerRelayEvent>,
) -> Result<(), String> {
    let mut file = File::open(path).map_err(|e| format!("打开已下载安装包失败：{e}"))?;
    let total_bytes = file
        .metadata()
        .map_err(|e| format!("读取安装包大小失败：{e}"))?
        .len();
    if total_bytes == 0 || total_bytes > MAX_UPDATE_PACKAGE_BYTES {
        return Err("安装包大小无效或超出 200 MiB 上限".to_string());
    }

    tx.send(ControllerRelayEvent::Outbound(
        DisplayControlMsg::UpdateChunkBegin {
            target_version: req.target_version.clone(),
            asset_name: req.asset_name.clone(),
            total_bytes,
            expected_sha256: req.expected_sha256.clone(),
        },
    ))
    .map_err(|_| "控制端会话已关闭".to_string())?;

    let window_bytes = (UPDATE_RELAY_CHUNK_BYTES * UPDATE_RELAY_WINDOW_CHUNKS) as u64;
    let mut buf = vec![0u8; UPDATE_RELAY_CHUNK_BYTES];
    let mut offset: u64 = 0;
    let mut last_emit: Option<Instant> = None;
    let mut last_pct: u8 = 50;

    while offset < total_bytes {
        if cancel.load(AtomicOrdering::Acquire) {
            return Err("已取消中转推送".to_string());
        }
        ack_gate.wait_for_window(offset, window_bytes, cancel)?;
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("读取安装包分块失败：{e}"))?;
        if n == 0 {
            break;
        }
        let next_offset = offset.saturating_add(n as u64);
        ack_gate.note_sent(next_offset);
        let data_base64 = display_ctrl::base64_encode(&buf[..n]);
        tx.send(ControllerRelayEvent::Outbound(
            DisplayControlMsg::UpdateChunkData {
                offset,
                data_base64,
            },
        ))
        .map_err(|_| "控制端会话已关闭".to_string())?;
        offset = next_offset;

        let pct = 50u8
            .saturating_add(((offset.saturating_mul(42)) / total_bytes).min(42) as u8)
            .max(last_pct);
        let due = last_emit.map_or(true, |t| t.elapsed() >= Duration::from_millis(250));
        if due || pct >= last_pct.saturating_add(3) || offset == total_bytes {
            last_emit = Some(Instant::now());
            last_pct = pct;
            let _ = tx.try_send(ControllerRelayEvent::LocalProgress(UpdateProgress {
                stage: UpdateStage::Relaying,
                progress_pct: pct,
                downloaded_bytes: offset,
                total_bytes,
                target_version: req.target_version.clone(),
                message: format!("正在向被控端中转推送 v{} 安装包…", req.target_version),
                need_controller_relay: false,
                error: None,
            }));
        }
    }

    if offset != total_bytes {
        return Err("安装包读取不完整".to_string());
    }
    tx.send(ControllerRelayEvent::Outbound(
        DisplayControlMsg::UpdateChunkEnd,
    ))
    .map_err(|_| "控制端会话已关闭".to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_parsing_and_ordering() {
        assert!(is_newer_version("0.1.10", "0.1.9"));
        assert!(is_newer_version("v0.2.0", "0.1.99"));
        assert!(is_newer_version("1.0.0", "1.0.0-rc.1"));
        assert!(is_newer_version("1.0.0-rc.2", "1.0.0-rc.1"));
        assert!(!is_newer_version("0.1.9", "0.1.9"));
        assert!(!is_newer_version("0.1.8", "0.1.9"));
        assert!(!is_newer_version("invalid", "0.1.9"));
        assert_eq!(
            SemVer::parse("v0.1.10+abc123"),
            Some(SemVer {
                major: 0,
                minor: 1,
                patch: 10,
                pre: None,
            })
        );
    }

    #[test]
    fn mirror_url_validation_and_application() {
        assert_eq!(sanitize_update_mirror_url("").unwrap(), "");
        assert_eq!(
            sanitize_update_mirror_url("  https://ghproxy.example.com/  ").unwrap(),
            "https://ghproxy.example.com/"
        );
        assert!(sanitize_update_mirror_url("http://insecure.example.com").is_err());
        assert!(sanitize_update_mirror_url("https://bad host/").is_err());
        assert!(sanitize_update_mirror_url("https://user@evil.com/").is_err());
        assert!(sanitize_update_mirror_url("https://?foo=bar").is_err());
        assert!(sanitize_update_mirror_url("https://#frag").is_err());
        assert!(sanitize_update_mirror_url("https://:443/").is_err());
        assert!(sanitize_update_mirror_url("https://{url}").is_err());
        assert!(sanitize_update_mirror_url("https://evil.com\\target.com/").is_err());
        assert!(sanitize_update_mirror_url("https://mirror.example.com#frag").is_err());
        assert!(validate_update_https_url("https://example.com:+443/a.dmg").is_err());
        assert!(validate_update_https_url("https://[not-an-ipv6]/a.dmg").is_err());
        assert!(validate_update_https_url("https://[::1]:8443/a.dmg").is_ok());
        assert!(validate_update_https_url("https://github.com/{foo}").is_err());
        assert!(validate_update_https_url("https://https://github.com/a").is_err());

        let target = "https://github.com/TokenBoom/rabbitcontrol-macos/releases/download/v0.1.10/RabbitControl-0.1.10-arm64.dmg";
        assert_eq!(apply_mirror_prefix("", target).unwrap(), target);
        assert_eq!(
            apply_mirror_prefix("https://mirror.test", target).unwrap(),
            format!("https://mirror.test/{target}")
        );
        assert_eq!(
            apply_mirror_prefix("https://mirror.test/proxy?u={url}", target).unwrap(),
            format!("https://mirror.test/proxy?u={target}")
        );
    }

    #[test]
    fn parse_github_release_and_attach_sha256sums() {
        let json = r####"{
            "tag_name": "v0.1.10",
            "name": "RabbitControl v0.1.10",
            "body": "### 更新内容\n- 检查更新与远程更新",
            "published_at": "2026-11-26T08:00:00Z",
            "html_url": "https://github.com/TokenBoom/rabbitcontrol-macos/releases/tag/v0.1.10",
            "assets": [
                {
                    "name": "RabbitControl-0.1.10-arm64.dmg",
                    "browser_download_url": "https://github.com/TokenBoom/rabbitcontrol-macos/releases/download/v0.1.10/RabbitControl-0.1.10-arm64.dmg",
                    "size": 10485760
                },
                {
                    "name": "RabbitControl-0.1.10-x86_64.dmg",
                    "browser_download_url": "https://github.com/TokenBoom/rabbitcontrol-macos/releases/download/v0.1.10/RabbitControl-0.1.10-x86_64.dmg",
                    "size": 11534336
                },
                {
                    "name": "SHA256SUMS.txt",
                    "browser_download_url": "https://github.com/TokenBoom/rabbitcontrol-macos/releases/download/v0.1.10/SHA256SUMS.txt",
                    "size": 200
                },
                {
                    "name": "../evil.dmg",
                    "browser_download_url": "https://github.com/evil.dmg",
                    "size": 100
                }
            ]
        }"####;
        let mut rel = parse_github_release_json(json).unwrap();
        assert_eq!(rel.version, "0.1.10");
        assert_eq!(rel.assets.len(), 3); // ../evil.dmg stripped

        let h1 = "a".repeat(64);
        let h2 = "b".repeat(64);
        let sums = format!(
            "{h1}  RabbitControl-0.1.10-arm64.dmg\n{h2} *RabbitControl-0.1.10-x86_64.dmg\n"
        );
        attach_sha256sums(&mut rel, &sums);

        let arm = select_asset_for_target(&rel, "macos", "aarch64").unwrap();
        assert_eq!(arm.name, "RabbitControl-0.1.10-arm64.dmg");
        assert_eq!(arm.sha256.as_deref(), Some(h1.as_str()));

        let x64 = select_asset_for_target(&rel, "macos", "x86_64").unwrap();
        assert_eq!(x64.name, "RabbitControl-0.1.10-x86_64.dmg");
        assert_eq!(x64.sha256.as_deref(), Some(h2.as_str()));
        assert!(constant_time_eq_hex(&h1, &h1.to_ascii_uppercase()));
        assert!(!constant_time_eq_hex(&h1, &h2));
    }

    #[test]
    fn host_update_worker_rejects_guest_and_validates_relay_chunks() {
        let mut worker = HostUpdateWorker::new();
        // Guest session must always be rejected fail-closed.
        worker.handle_message(
            DisplayControlMsg::UpdateTrigger {
                target_version: "0.1.10".to_string(),
                download_url: "https://github.com/example.dmg".to_string(),
                expected_sha256: "a".repeat(64),
                asset_name: "RabbitControl-0.1.10-arm64.dmg".to_string(),
                mirror_url: String::new(),
                relay_fallback_allowed: true,
                request_id: 1,
            },
            false,
        );
        let out = worker.poll_outgoing();
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0],
            DisplayControlMsg::UpdateStatus {
                stage: UpdateStage::Failed,
                ..
            }
        ));

        // Relay receiver runs off the media loop, rejects mismatched SHA-256, and cleans up temp file.
        let payload = b"fake-dmg-content";
        let wrong_hash = "0".repeat(64);
        worker.awaiting_relay = Some(AwaitingRelayMeta {
            target_version: "0.1.10".to_string(),
            asset_name: "RabbitControl-0.1.10-arm64.dmg".to_string(),
            expected_sha256: wrong_hash.clone(),
            request_id: 7,
        });
        worker.handle_message(
            DisplayControlMsg::UpdateChunkBegin {
                target_version: "0.1.10".to_string(),
                asset_name: "RabbitControl-0.1.10-arm64.dmg".to_string(),
                total_bytes: payload.len() as u64,
                expected_sha256: wrong_hash,
            },
            true,
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut begin_out = Vec::new();
        while begin_out.is_empty() && Instant::now() < deadline {
            begin_out.extend(worker.poll_outgoing());
            if begin_out.is_empty() {
                thread::sleep(Duration::from_millis(5));
            }
        }
        assert!(matches!(
            begin_out.as_slice(),
            [DisplayControlMsg::UpdateChunkAck { next_offset: 0 }]
        ));
        let tmp_path = worker.last_relay_path.clone().unwrap();
        assert!(tmp_path.exists());

        worker.handle_message(
            DisplayControlMsg::UpdateChunkData {
                offset: 0,
                data_base64: display_ctrl::base64_encode(payload),
            },
            true,
        );
        worker.handle_message(DisplayControlMsg::UpdateChunkEnd, true);

        let end_deadline = Instant::now() + Duration::from_secs(2);
        let mut saw_failed = false;
        while Instant::now() < end_deadline {
            for msg in worker.poll_outgoing() {
                if matches!(
                    msg,
                    DisplayControlMsg::UpdateStatus {
                        stage: UpdateStage::Failed,
                        ..
                    }
                ) {
                    saw_failed = true;
                }
            }
            if saw_failed && !tmp_path.exists() && !worker.is_task_running() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(saw_failed, "corrupt SHA-256 relay must emit Failed");
        assert!(
            !tmp_path.exists(),
            "corrupt relay temp file must be cleaned up"
        );
        assert!(!worker.is_task_running());
    }

    #[test]
    fn parse_github_release_sanitizes_malicious_html_url() {
        let json = r#"{"tag_name":"v0.1.10","html_url":"javascript:alert(1)","assets":[]}"#;
        let rel = parse_github_release_json(json).unwrap();
        assert_eq!(rel.html_url, "");
    }

    #[test]
    fn controller_relay_ignores_unarmed_host_request() {
        let mut relay = ControllerUpdateRelay::new();
        relay.maybe_start_relay_for_host_request();
        let (msgs, progs) = relay.poll();
        assert!(msgs.is_empty());
        assert!(progs.is_empty());

        // Forged future ACK beyond sent_offset must be ignored so sliding window cannot be bypassed.
        let gate = RelayAckGate::new();
        gate.set_acked(u64::MAX);
        assert_eq!(gate.state.lock().unwrap().acked_offset, 0);
        gate.note_sent(65_536);
        gate.set_acked(131_072);
        assert_eq!(gate.state.lock().unwrap().acked_offset, 0);
        gate.set_acked(65_536);
        assert_eq!(gate.state.lock().unwrap().acked_offset, 65_536);
    }

    #[test]
    fn host_update_global_lock_and_phase_cas_prevent_concurrent_install() {
        let shared = Arc::new(HostUpdateGlobalLock::new());
        let (gen1, _cancel1) = shared.try_acquire().unwrap();
        assert!(shared.try_enter_installing(gen1));
        assert!(shared.is_installing());
        // Once installing, cancel from same or different generation must report AlreadyInstalling.
        assert!(matches!(
            shared.try_cancel_for_gen(gen1),
            CancelAttempt::AlreadyInstalling
        ));
        assert!(matches!(
            shared.try_cancel_for_gen(999),
            CancelAttempt::AlreadyInstalling
        ));
        shared.release(gen1);
        assert!(!shared.is_worker_alive());

        let (gen2, cancel2) = shared.try_acquire().unwrap();
        assert!(matches!(
            shared.try_cancel_for_gen(gen2),
            CancelAttempt::Cancelled
        ));
        assert!(cancel2.load(AtomicOrdering::Acquire));
        // Once cancelled, entering install must fail atomically.
        assert!(!shared.try_enter_installing(gen2));
        assert!(shared.is_cancelled(gen2));
        shared.release(gen2);

        // Cross-instance process lock: if another HostUpdateWorker instance holds the lock,
        // a newly constructed HostUpdateWorker must observe is_task_running() == true and reject triggers,
        // and calling UpdateCancel on w2 must NOT cancel w1's task or emit a bogus cancelled status.
        let (gen3, _cancel3) = shared.try_acquire().unwrap();
        let mut guard = WorkerAliveGuard::new(Arc::clone(&shared), gen3);
        let mut w2 = HostUpdateWorker::with_lock(Arc::clone(&shared));
        assert!(w2.is_task_running());
        w2.handle_message(DisplayControlMsg::UpdateCancel, true);
        assert!(w2.poll_outgoing().is_empty());
        assert!(!shared.is_cancelled(gen3));
        w2.handle_message(
            DisplayControlMsg::UpdateTrigger {
                target_version: "0.1.10".to_string(),
                download_url: "https://github.com/TokenBoom/rabbitcontrol-macos/releases/download/v0.1.10/RabbitControl-0.1.10-arm64.dmg".to_string(),
                expected_sha256: "a".repeat(64),
                asset_name: "RabbitControl-0.1.10-arm64.dmg".to_string(),
                mirror_url: String::new(),
                relay_fallback_allowed: true,
                request_id: 10,
            },
            true,
        );
        let out = w2.poll_outgoing();
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0],
            DisplayControlMsg::UpdateStatus {
                stage: UpdateStage::Failed,
                ..
            }
        ));
        // Idle UpdateChunkAbort must be ignored and not emit Failed.
        guard.release();
        assert!(!w2.is_task_running());
        w2.handle_message(
            DisplayControlMsg::UpdateChunkAbort {
                reason: "late".to_string(),
            },
            true,
        );
        assert!(w2.poll_outgoing().is_empty());

        // Guest spam coalescing: flooding guest requests produces at most 1 queued rejection.
        for _ in 0..100 {
            w2.handle_message(DisplayControlMsg::UpdateCancel, false);
        }
        assert_eq!(w2.poll_outgoing().len(), 1);

        // UpdateCancel racing with buffered DirectDownloadFailedForRelay must cancel cleanly instead of resurrecting Relaying.
        let (ev_tx, ev_rx) = mpsc::channel::<HostWorkerEvent>();
        w2.owned_gen = 42;
        w2.active_request_id = 42;
        w2.busy = true;
        w2.events_rx = Some(ev_rx);
        let relay_status = progress_to_msg(
            UpdateProgress {
                stage: UpdateStage::Relaying,
                progress_pct: 0,
                downloaded_bytes: 0,
                total_bytes: 0,
                target_version: "0.1.10".to_string(),
                message: "fallback".to_string(),
                need_controller_relay: true,
                error: None,
            },
            42,
        );
        ev_tx
            .send(HostWorkerEvent::DirectDownloadFailedForRelay {
                status: relay_status,
                meta: AwaitingRelayMeta {
                    target_version: "0.1.10".to_string(),
                    asset_name: "RabbitControl-0.1.10-arm64.dmg".to_string(),
                    expected_sha256: "a".repeat(64),
                    request_id: 42,
                },
            })
            .unwrap();
        w2.handle_message(DisplayControlMsg::UpdateCancel, true);
        let cancel_out = w2.poll_outgoing();
        assert!(!w2.has_active_or_pending_relay());
        assert_eq!(cancel_out.len(), 1);
        assert!(matches!(
            cancel_out[0],
            DisplayControlMsg::UpdateStatus {
                stage: UpdateStage::Failed,
                need_controller_relay: false,
                request_id: 42,
                ..
            }
        ));

        // Preemption case: worker released alive_guard BEFORE sending DirectDownloadFailedForRelay,
        // and UpdateCancel arrives while events_rx is still empty.
        let (ev_tx2, ev_rx2) = mpsc::channel::<HostWorkerEvent>();
        w2.owned_gen = 43;
        w2.active_request_id = 43;
        w2.busy = true;
        w2.saw_terminal_or_install = false;
        w2.relay_target_version = "0.1.10".to_string();
        w2.events_rx = Some(ev_rx2);
        w2.handle_message(DisplayControlMsg::UpdateCancel, true);
        // Late send from resumed worker must fail because events_rx was dropped on cancel.
        assert!(ev_tx2
            .send(HostWorkerEvent::DirectDownloadFailedForRelay {
                status: progress_to_msg(
                    UpdateProgress {
                        stage: UpdateStage::Relaying,
                        progress_pct: 0,
                        downloaded_bytes: 0,
                        total_bytes: 0,
                        target_version: "0.1.10".to_string(),
                        message: "late-fallback".to_string(),
                        need_controller_relay: true,
                        error: None,
                    },
                    43,
                ),
                meta: AwaitingRelayMeta {
                    target_version: "0.1.10".to_string(),
                    asset_name: "RabbitControl-0.1.10-arm64.dmg".to_string(),
                    expected_sha256: "a".repeat(64),
                    request_id: 43,
                },
            })
            .is_err());
        let cancel_out2 = w2.poll_outgoing();
        assert!(!w2.has_active_or_pending_relay());
        assert_eq!(cancel_out2.len(), 1);
        assert!(matches!(
            cancel_out2[0],
            DisplayControlMsg::UpdateStatus {
                stage: UpdateStage::Failed,
                need_controller_relay: false,
                request_id: 43,
                ..
            }
        ));

        // Buffered WorkerDone in events_rx must be drained before start_trigger so immediate retry is not rejected as busy.
        let (ev_tx3, ev_rx3) = mpsc::channel::<HostWorkerEvent>();
        w2.busy = true;
        w2.owned_gen = 44;
        w2.events_rx = Some(ev_rx3);
        ev_tx3.send(HostWorkerEvent::WorkerDone).unwrap();
        w2.handle_message(
            DisplayControlMsg::UpdateTrigger {
                target_version: "0.1.10".to_string(),
                download_url: "https://github.com/TokenBoom/rabbitcontrol-macos/releases/download/v0.1.10/RabbitControl-0.1.10-arm64.dmg".to_string(),
                expected_sha256: "a".repeat(64),
                asset_name: "RabbitControl-0.1.10-arm64.dmg".to_string(),
                mirror_url: String::new(),
                relay_fallback_allowed: true,
                request_id: 45,
            },
            true,
        );
        let retry_out = w2.poll_outgoing();
        // No platform update hooks in core unit tests, so it reaches can_self_update() rejection,
        // NOT the stale "被控端当前已有更新任务正在进行" busy error.
        assert_eq!(retry_out.len(), 1);
        match &retry_out[0] {
            DisplayControlMsg::UpdateStatus {
                stage: UpdateStage::Failed,
                message,
                request_id,
                ..
            } => {
                assert_eq!(*request_id, 45);
                assert!(
                    !message.contains("已有更新任务正在进行"),
                    "stale busy state must be drained before retry: {message}"
                );
            }
            other => panic!("unexpected retry status: {other:?}"),
        }

        // UpdateChunkAbort arriving after a buffered host relay Failed + WorkerDone must preserve the real host diagnostic.
        let (ev_tx4, ev_rx4) = mpsc::channel::<HostWorkerEvent>();
        let (cmd_tx4, _cmd_rx4) = mpsc::sync_channel::<RelayRxCmd>(4);
        w2.busy = true;
        w2.relay_cmd_tx = Some(cmd_tx4);
        w2.events_rx = Some(ev_rx4);
        ev_tx4
            .send(HostWorkerEvent::Outbound(fail_status_msg(
                46,
                "0.1.10",
                "real-disk-full-error",
                "real-disk-full-error",
            )))
            .unwrap();
        ev_tx4.send(HostWorkerEvent::WorkerDone).unwrap();
        w2.handle_message(
            DisplayControlMsg::UpdateChunkAbort {
                reason: "generic-abort".to_string(),
            },
            true,
        );
        let abort_out = w2.poll_outgoing();
        assert_eq!(abort_out.len(), 1);
        match &abort_out[0] {
            DisplayControlMsg::UpdateStatus {
                stage: UpdateStage::Failed,
                message,
                request_id,
                ..
            } => {
                assert_eq!(*request_id, 46);
                assert_eq!(message, "real-disk-full-error");
            }
            other => panic!("unexpected abort status: {other:?}"),
        }

        // PendingUpdateTxQueue coalesces cumulative ACKs and preserves critical terminal statuses under backpressure.
        let mut q = PendingUpdateTxQueue::new();
        for i in 1..=500u64 {
            q.enqueue(&DisplayControlMsg::UpdateChunkAck { next_offset: i }, true);
        }
        assert_eq!(q.entries.len(), 1);
        for i in 0..100u8 {
            q.enqueue(
                &progress_to_msg(
                    UpdateProgress {
                        stage: UpdateStage::Relaying,
                        progress_pct: i.min(90),
                        downloaded_bytes: u64::from(i),
                        total_bytes: 100,
                        target_version: "0.1.10".to_string(),
                        message: "progress".to_string(),
                        need_controller_relay: false,
                        error: None,
                    },
                    47,
                ),
                true,
            );
        }
        assert!(q.entries.len() <= MAX_HOST_PENDING_UPDATE_TX);
        // Critical status must still be enqueued even when queue is full of progress frames.
        assert!(q.enqueue(
            &fail_status_msg(47, "0.1.10", "critical-err", "critical-err"),
            true
        ));
        assert!(q.entries.len() <= MAX_HOST_PENDING_UPDATE_TX);
        let mut flushed = Vec::new();
        while !q.is_empty() {
            q.flush::<(), _, _>(
                8,
                |p| {
                    flushed.push(display_ctrl::decode_display_ctrl(&p).unwrap());
                    Ok(())
                },
                |_| false,
            );
        }
        assert!(flushed
            .iter()
            .any(|m| matches!(m, DisplayControlMsg::UpdateChunkAck { next_offset: 500 })));
        assert!(flushed.iter().any(|m| matches!(
            m,
            DisplayControlMsg::UpdateStatus {
                stage: UpdateStage::Failed,
                ..
            }
        )));
    }
}
