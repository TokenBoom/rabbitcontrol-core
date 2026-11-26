//! 跨平台终端字体扫描、SFNT/TTC 解析与安全二进制提取（仅限系统字体白名单目录）。
//!
//! 用于：
//! - 控制端离线枚举本机可渲染的终端字体；
//! - 被控端以只读白名单目录 + 不透明 `font_id` 方式向控制端安全传输远程字体文件，
//!   并在 `.ttc`/`.otc` 多面集合中提取单面独立 `.ttf`/`.otf`，供 `WKWebView` `FontFace` 直接加载。

#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 远程字体传输允许的单个字体文件大小上限（20 MiB，覆盖常见 Nerd Font 与 CJK 字体，防 OOM）。
pub const MAX_REMOTE_FONT_BYTES: u64 = 20 * 1024 * 1024;

/// 字体目录枚举返回的最大条目数。
pub const MAX_FONT_CATALOG_ENTRIES: usize = 512;

const MAX_SCAN_DEPTH: usize = 3;
const MAX_SCAN_FILES: usize = 2048;
const MAX_TTC_FACES_PER_FILE: usize = 32;
const MAX_NAME_TABLE_BYTES: usize = 256 * 1024;

/// 面向 UI 展示与远程字体选择的字体元数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalFontInfo {
    /// 不透明字体标识（基于规范路径与面索引哈希，客户端永不感知或传递主机文件路径）。
    pub id: String,
    /// 字体家族名称（可直接用于展示或作为 CSS fallback 提示）。
    pub family: String,
    /// 是否为等宽字体（推荐用于终端网格渲染）。
    pub monospace: bool,
    /// 原始字体文件大小（字节）。
    pub size_bytes: u64,
}

#[derive(Debug, Clone)]
struct FontCatalogEntry {
    info: TerminalFontInfo,
    canonical_path: PathBuf,
    extension: String,
    face_index: usize,
    regular_score: u8,
}

/// 进程内可复用的系统字体白名单目录与索引（禁止任意路径穿越与目录外符号链接）。
#[derive(Debug, Clone, Default)]
pub struct FontCatalog {
    entries: HashMap<String, FontCatalogEntry>,
    ordered: Vec<TerminalFontInfo>,
}

impl FontCatalog {
    /// 按默认系统字体目录扫描生成字体目录索引。
    pub fn scan_system() -> Self {
        let roots = default_font_roots();
        Self::scan_roots(&roots)
    }

    /// 仅在指定的白名单根目录内扫描字体文件（供单测与自定义沙箱使用）。
    pub fn scan_roots(roots: &[PathBuf]) -> Self {
        let mut canon_roots: Vec<PathBuf> = Vec::new();
        for root in roots {
            if let Ok(canon) = fs::canonicalize(root) {
                if canon.is_dir() && !canon_roots.contains(&canon) {
                    canon_roots.push(canon);
                }
            }
        }

        let mut scanned_files = 0usize;
        let mut by_family: HashMap<String, FontCatalogEntry> = HashMap::new();

        for root in &canon_roots {
            if scanned_files >= MAX_SCAN_FILES {
                break;
            }
            scan_dir_recursive(root, root, 0, &mut scanned_files, &mut by_family);
        }

        let mut list: Vec<FontCatalogEntry> = by_family.into_values().collect();
        list.sort_by(|a, b| {
            b.info
                .monospace
                .cmp(&a.info.monospace)
                .then_with(|| {
                    a.info
                        .family
                        .to_ascii_lowercase()
                        .cmp(&b.info.family.to_ascii_lowercase())
                })
                .then_with(|| a.info.family.cmp(&b.info.family))
                .then_with(|| a.info.id.cmp(&b.info.id))
        });
        if list.len() > MAX_FONT_CATALOG_ENTRIES {
            list.truncate(MAX_FONT_CATALOG_ENTRIES);
        }

        let mut entries = HashMap::with_capacity(list.len());
        let mut ordered = Vec::with_capacity(list.len());
        for entry in list {
            ordered.push(entry.info.clone());
            entries.insert(entry.info.id.clone(), entry);
        }
        Self { entries, ordered }
    }

    /// 返回按「等宽优先、家族名升序」排列的字体列表。
    pub fn list(&self) -> Vec<TerminalFontInfo> {
        self.ordered.clone()
    }

    /// 根据不透明 `font_id` 安全读取字体字节（`.ttc`/`.otc` 自动提取对应单面 `.ttf`/`.otf`）。
    pub fn load_font_bytes(
        &self,
        font_id: &str,
    ) -> Result<(TerminalFontInfo, String, Vec<u8>), String> {
        let entry = self
            .entries
            .get(font_id)
            .ok_or_else(|| format!("未找到字体索引：{font_id}"))?;

        let meta =
            fs::metadata(&entry.canonical_path).map_err(|e| format!("读取字体元数据失败：{e}"))?;
        if !meta.is_file() {
            return Err("目标字体不是常规文件".to_string());
        }
        let file_len = meta.len();
        if file_len == 0 || file_len > MAX_REMOTE_FONT_BYTES {
            return Err(format!(
                "字体文件大小超出限制（{file_len} 字节，上限 {MAX_REMOTE_FONT_BYTES} 字节）"
            ));
        }

        let raw = fs::read(&entry.canonical_path).map_err(|e| format!("读取字体文件失败：{e}"))?;
        if raw.len() as u64 > MAX_REMOTE_FONT_BYTES {
            return Err("字体文件实际读取大小超出限制".to_string());
        }

        if entry.extension == "ttc" || entry.extension == "otc" {
            let (fmt, extracted) = extract_ttc_face(&raw, entry.face_index)?;
            return Ok((entry.info.clone(), fmt, extracted));
        }

        let fmt = if entry.extension == "woff2" {
            "woff2".to_string()
        } else if raw.get(..4) == Some(b"OTTO") {
            "otf".to_string()
        } else {
            "ttf".to_string()
        };
        Ok((entry.info.clone(), fmt, raw))
    }
}

/// 枚举当前主机白名单目录内的所有可用系统字体。
pub fn list_local_fonts() -> Vec<TerminalFontInfo> {
    FontCatalog::scan_system().list()
}

/// 返回当前操作系统的默认系统字体白名单根目录列表。
pub fn default_font_roots() -> Vec<PathBuf> {
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux", target_os = "windows")),
        allow(unused_mut)
    )]
    let mut roots = Vec::new();
    #[cfg(target_os = "macos")]
    {
        roots.push(PathBuf::from("/System/Library/Fonts"));
        roots.push(PathBuf::from("/System/Library/Fonts/Supplemental"));
        roots.push(PathBuf::from("/Library/Fonts"));
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            roots.push(PathBuf::from(home).join("Library").join("Fonts"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        roots.push(PathBuf::from("/usr/share/fonts"));
        roots.push(PathBuf::from("/usr/local/share/fonts"));
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            roots.push(PathBuf::from(xdg).join("fonts"));
        } else if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            roots.push(
                PathBuf::from(&home)
                    .join(".local")
                    .join("share")
                    .join("fonts"),
            );
        }
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            roots.push(PathBuf::from(home).join(".fonts"));
        }
    }
    #[cfg(target_os = "windows")]
    {
        let windir = std::env::var_os("WINDIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        roots.push(windir.join("Fonts"));
        if let Some(local_app) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            roots.push(
                PathBuf::from(local_app)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Fonts"),
            );
        }
    }
    roots
}

fn scan_dir_recursive(
    root: &Path,
    dir: &Path,
    depth: usize,
    scanned_files: &mut usize,
    by_family: &mut HashMap<String, FontCatalogEntry>,
) {
    if depth > MAX_SCAN_DEPTH || *scanned_files >= MAX_SCAN_FILES {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|x| x.path())).collect();
    paths.sort();

    for path in paths {
        if *scanned_files >= MAX_SCAN_FILES {
            break;
        }
        let Ok(canon) = fs::canonicalize(&path) else {
            continue;
        };
        // 严禁符号链接逃逸到字体根目录之外。
        if !canon.starts_with(root) {
            continue;
        }
        let Ok(meta) = fs::metadata(&canon) else {
            continue;
        };
        if meta.is_dir() {
            if depth < MAX_SCAN_DEPTH {
                scan_dir_recursive(root, &canon, depth + 1, scanned_files, by_family);
            }
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let size_bytes = meta.len();
        if size_bytes == 0 || size_bytes > MAX_REMOTE_FONT_BYTES {
            continue;
        }
        let Some(ext) = canon
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
        else {
            continue;
        };
        if !matches!(ext.as_str(), "ttf" | "otf" | "ttc" | "otc" | "woff2") {
            continue;
        }

        *scanned_files += 1;
        let candidates = inspect_font_file(&canon, &ext, size_bytes);
        for candidate in candidates {
            let key = candidate.info.family.to_ascii_lowercase();
            match by_family.get(&key) {
                Some(existing) if existing.regular_score >= candidate.regular_score => {}
                _ => {
                    by_family.insert(key, candidate);
                }
            }
        }
    }
}

fn fnv1a_hex_id(path: &Path, face_index: usize) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash ^= b'#' as u64;
    hash = hash.wrapping_mul(0x0100_0000_01b3);
    for &b in face_index.to_string().as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn normalize_family_name(raw: &str, fallback_stem: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return fallback_stem.to_string();
    }
    if trimmed == ".SF NS Mono" || trimmed == ".SFNSMono" {
        return "SF Mono".to_string();
    }
    // 跳过如 `.Keyboard` 这类仅供 AppKit/CoreText 内部使用的隐藏字体。
    trimmed.to_string()
}

fn heuristic_monospace_name(family: &str) -> bool {
    let lower = family.to_ascii_lowercase();
    [
        "mono",
        "code",
        "console",
        "terminal",
        "courier",
        "menlo",
        "monaco",
        "consolas",
        "fixed",
        "inconsolata",
        "hack",
        "meslo",
        "fira",
        "iosevka",
        "cascadia",
        "proggy",
        "terminus",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
}

fn inspect_font_file(canon: &Path, ext: &str, size_bytes: u64) -> Vec<FontCatalogEntry> {
    let fallback_stem = canon
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown Font")
        .to_string();

    if ext == "woff2" {
        let family = fallback_stem;
        let monospace = heuristic_monospace_name(&family);
        let id = fnv1a_hex_id(canon, 0);
        return vec![FontCatalogEntry {
            info: TerminalFontInfo {
                id,
                family,
                monospace,
                size_bytes,
            },
            canonical_path: canon.to_path_buf(),
            extension: ext.to_string(),
            face_index: 0,
            regular_score: 2,
        }];
    }

    let Ok(mut file) = File::open(canon) else {
        return Vec::new();
    };
    let mut header = [0u8; 16];
    if file.read_exact(&mut header).is_err() {
        return Vec::new();
    }

    let face_offsets: Vec<u64> = if &header[..4] == b"ttcf" {
        let num_fonts = be_u32(&header, 8).unwrap_or(0) as usize;
        let count = num_fonts.min(MAX_TTC_FACES_PER_FILE);
        let mut off_buf = vec![0u8; count * 4];
        if file.seek(SeekFrom::Start(12)).is_err() || file.read_exact(&mut off_buf).is_err() {
            return Vec::new();
        }
        (0..count)
            .filter_map(|i| be_u32(&off_buf, i * 4).map(u64::from))
            .collect()
    } else if matches!(&header[..4], [0, 1, 0, 0] | b"OTTO" | b"true") {
        vec![0]
    } else {
        Vec::new()
    };

    let mut out = Vec::new();
    for (face_index, offset) in face_offsets.into_iter().enumerate() {
        let Some(meta) = parse_sfnt_face_from_file(&mut file, offset, size_bytes) else {
            continue;
        };
        let family = normalize_family_name(&meta.family, &fallback_stem);
        if family.starts_with('.') {
            continue;
        }
        let monospace = meta.monospace || heuristic_monospace_name(&family);
        let id = fnv1a_hex_id(canon, face_index);
        out.push(FontCatalogEntry {
            info: TerminalFontInfo {
                id,
                family,
                monospace,
                size_bytes,
            },
            canonical_path: canon.to_path_buf(),
            extension: ext.to_string(),
            face_index,
            regular_score: meta.regular_score,
        });
    }
    out
}

struct ParsedSfntMeta {
    family: String,
    monospace: bool,
    regular_score: u8,
}

fn parse_sfnt_face_from_file(
    file: &mut File,
    sfnt_offset: u64,
    file_size: u64,
) -> Option<ParsedSfntMeta> {
    if file.seek(SeekFrom::Start(sfnt_offset)).is_err() {
        return None;
    }
    let mut head12 = [0u8; 12];
    if file.read_exact(&mut head12).is_err() {
        return None;
    }
    if !matches!(&head12[..4], [0, 1, 0, 0] | b"OTTO" | b"true") {
        return None;
    }
    let num_tables = be_u16(&head12, 4)? as usize;
    if num_tables == 0 || num_tables > 128 {
        return None;
    }

    let mut dir_buf = vec![0u8; num_tables * 16];
    if file.read_exact(&mut dir_buf).is_err() {
        return None;
    }

    let mut name_loc: Option<(u64, usize)> = None;
    let mut post_loc: Option<(u64, usize)> = None;
    let mut os2_loc: Option<(u64, usize)> = None;

    for i in 0..num_tables {
        let rec = &dir_buf[i * 16..(i + 1) * 16];
        let tag = &rec[0..4];
        let offset = u64::from(be_u32(rec, 8)?);
        let length = be_u32(rec, 12)? as usize;
        if offset.saturating_add(length as u64) > file_size {
            continue;
        }
        if tag == b"name" {
            name_loc = Some((offset, length));
        } else if tag == b"post" {
            post_loc = Some((offset, length));
        } else if tag == b"OS/2" {
            os2_loc = Some((offset, length));
        }
    }

    let (name_off, name_len) = name_loc?;
    if name_len == 0 || name_len > MAX_NAME_TABLE_BYTES {
        return None;
    }
    let mut name_buf = vec![0u8; name_len];
    if file.seek(SeekFrom::Start(name_off)).is_err() || file.read_exact(&mut name_buf).is_err() {
        return None;
    }

    let (family, subfamily) = parse_name_table(&name_buf)?;

    let mut monospace = false;
    if let Some((post_off, post_len)) = post_loc {
        if post_len >= 16 && file.seek(SeekFrom::Start(post_off)).is_ok() {
            let mut post_buf = [0u8; 16];
            if file.read_exact(&mut post_buf).is_ok() && be_u32(&post_buf, 12).unwrap_or(0) != 0 {
                monospace = true;
            }
        }
    }

    let mut regular_score = 1u8;
    if let Some((os2_off, os2_len)) = os2_loc {
        if os2_len >= 64 && file.seek(SeekFrom::Start(os2_off)).is_ok() {
            let mut os2_buf = [0u8; 64];
            if file.read_exact(&mut os2_buf).is_ok() {
                // PANOSE[0]==2 (Latin Text) && PANOSE[3]==9 (Monospaced)
                if os2_buf[32] == 2 && os2_buf[35] == 9 {
                    monospace = true;
                }
                let weight = be_u16(&os2_buf, 4).unwrap_or(400);
                let fs_sel = be_u16(&os2_buf, 62).unwrap_or(0);
                let is_italic = (fs_sel & 0x0001) != 0;
                let is_bold = (fs_sel & 0x0020) != 0;
                let is_regular = (fs_sel & 0x0040) != 0;
                if is_regular || (!is_italic && !is_bold && (350..=450).contains(&weight)) {
                    regular_score = 4;
                } else if !is_italic && !is_bold {
                    regular_score = 2;
                } else {
                    regular_score = 0;
                }
            }
        }
    }

    let sub_lower = subfamily.to_ascii_lowercase();
    if sub_lower == "regular" || sub_lower == "normal" || sub_lower == "book" {
        regular_score = regular_score.max(5);
    } else if sub_lower.contains("italic")
        || sub_lower.contains("bold")
        || sub_lower.contains("oblique")
    {
        regular_score = 0;
    }

    Some(ParsedSfntMeta {
        family,
        monospace,
        regular_score,
    })
}

fn parse_name_table(data: &[u8]) -> Option<(String, String)> {
    let count = be_u16(data, 2)? as usize;
    let string_offset = be_u16(data, 4)? as usize;
    if string_offset > data.len() || 6usize.saturating_add(count * 12) > data.len() {
        return None;
    }

    let mut best_family: Option<(u8, String)> = None;
    let mut best_subfamily: Option<(u8, String)> = None;

    for i in 0..count {
        let rec = &data[6 + i * 12..6 + (i + 1) * 12];
        let platform = be_u16(rec, 0)?;
        let encoding = be_u16(rec, 2)?;
        let lang = be_u16(rec, 4)?;
        let name_id = be_u16(rec, 6)?;
        let len = be_u16(rec, 8)? as usize;
        let off = be_u16(rec, 10)? as usize;

        if !matches!(name_id, 1 | 2 | 16 | 17) || len == 0 {
            continue;
        }
        let start = string_offset.saturating_add(off);
        let end = start.saturating_add(len);
        if end > data.len() {
            continue;
        }
        let Some(decoded) = decode_name_string(platform, encoding, &data[start..end]) else {
            continue;
        };

        let is_preferred_id = name_id == 16 || name_id == 17;
        let is_en_us = (platform == 3 && lang == 0x0409) || (platform == 1 && lang == 0);
        let is_unicode = platform == 3 || platform == 0;
        let score =
            (u8::from(is_preferred_id) * 4) + (u8::from(is_en_us) * 2) + u8::from(is_unicode);

        let slot = if name_id == 1 || name_id == 16 {
            &mut best_family
        } else {
            &mut best_subfamily
        };
        if slot.as_ref().map_or(true, |(prev, _)| score > *prev) {
            *slot = Some((score, decoded));
        }
    }

    let (_, family) = best_family?;
    let subfamily = best_subfamily.map(|(_, s)| s).unwrap_or_default();
    Some((family, subfamily))
}

fn decode_name_string(platform: u16, encoding: u16, bytes: &[u8]) -> Option<String> {
    if platform == 3 || platform == 0 {
        if bytes.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16_lossy(&units).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    } else if platform == 1 && encoding == 0 {
        let s: String = bytes
            .iter()
            .filter(|b| b.is_ascii() && !b.is_ascii_control())
            .map(|&b| b as char)
            .collect();
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    } else {
        None
    }
}

/// 从 TrueType/OpenType Collection (`.ttc`/`.otc`) 提取指定 `face_index` 为独立的 `.ttf`/`.otf` 字节。
pub fn extract_ttc_face(ttc: &[u8], face_index: usize) -> Result<(String, Vec<u8>), String> {
    if ttc.len() < 16 || &ttc[..4] != b"ttcf" {
        return Err("不是有效的 TTC/OTC 字体集合".to_string());
    }
    let num_fonts = be_u32(ttc, 8).ok_or_else(|| "TTC 头部截断".to_string())? as usize;
    if face_index >= num_fonts || face_index >= MAX_TTC_FACES_PER_FILE {
        return Err(format!("TTC 字体面索引越界：{face_index} / {num_fonts}"));
    }
    let sfnt_offset =
        be_u32(ttc, 12 + face_index * 4).ok_or_else(|| "读取 TTC 面偏移失败".to_string())? as usize;
    let header_end = sfnt_offset
        .checked_add(12)
        .filter(|&end| end <= ttc.len())
        .ok_or_else(|| "TTC 子字体头部越界".to_string())?;
    let sfnt_header = &ttc[sfnt_offset..header_end];
    let sfnt_tag = &sfnt_header[0..4];
    if !matches!(sfnt_tag, [0, 1, 0, 0] | b"OTTO" | b"true") {
        return Err("TTC 子字体不是有效的 SFNT 表".to_string());
    }
    let fmt = if sfnt_tag == b"OTTO" {
        "otf".to_string()
    } else {
        "ttf".to_string()
    };

    let num_tables =
        be_u16(sfnt_header, 4).ok_or_else(|| "读取 SFNT 表数量失败".to_string())? as usize;
    if num_tables == 0 || num_tables > 128 {
        return Err(format!("非法的 SFNT 表数量：{num_tables}"));
    }
    let dir_end = header_end
        .checked_add(num_tables * 16)
        .filter(|&end| end <= ttc.len())
        .ok_or_else(|| "TTC 表目录越界".to_string())?;

    let new_dir_base = 12usize;
    let mut dst_cursor = new_dir_base + num_tables * 16;
    let mut total_estimated = dst_cursor;
    struct TableCopy<'a> {
        tag: &'a [u8],
        checksum: u32,
        src: &'a [u8],
        dst_offset: usize,
    }
    let mut tables = Vec::with_capacity(num_tables);
    for i in 0..num_tables {
        let rec = &ttc[header_end + i * 16..header_end + (i + 1) * 16];
        let checksum = be_u32(rec, 4).unwrap_or(0);
        let src_offset = be_u32(rec, 8).unwrap_or(0) as usize;
        let len = be_u32(rec, 12).unwrap_or(0) as usize;
        let src_end = src_offset
            .checked_add(len)
            .filter(|&end| end <= ttc.len())
            .ok_or_else(|| "TTC 表数据区越界".to_string())?;
        let aligned = (len + 3) & !3;
        if dst_cursor.saturating_add(aligned) > MAX_REMOTE_FONT_BYTES as usize {
            return Err("提取后的单面字体超出大小限制".to_string());
        }
        tables.push(TableCopy {
            tag: &rec[0..4],
            checksum,
            src: &ttc[src_offset..src_end],
            dst_offset: dst_cursor,
        });
        dst_cursor += aligned;
        total_estimated = dst_cursor;
    }

    let _ = dir_end;
    let mut out = Vec::with_capacity(total_estimated);
    out.extend_from_slice(sfnt_header);
    for t in &tables {
        out.extend_from_slice(t.tag);
        out.extend_from_slice(&t.checksum.to_be_bytes());
        out.extend_from_slice(&(t.dst_offset as u32).to_be_bytes());
        out.extend_from_slice(&(t.src.len() as u32).to_be_bytes());
    }
    for t in &tables {
        out.extend_from_slice(t.src);
        let pad = ((t.src.len() + 3) & !3) - t.src.len();
        out.resize(out.len() + pad, 0);
    }

    Ok((fmt, out))
}

fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_sfnt(family: &str, subfamily: &str, fixed_pitch: bool) -> Vec<u8> {
        let mut family_u16 = Vec::new();
        for u in family.encode_utf16() {
            family_u16.extend_from_slice(&u.to_be_bytes());
        }
        let mut sub_u16 = Vec::new();
        for u in subfamily.encode_utf16() {
            sub_u16.extend_from_slice(&u.to_be_bytes());
        }

        // `name` table: header(6) + 2*12(24) + strings
        let str_off = 30usize;
        let mut name_tbl = Vec::new();
        name_tbl.extend_from_slice(&0u16.to_be_bytes()); // format
        name_tbl.extend_from_slice(&2u16.to_be_bytes()); // count
        name_tbl.extend_from_slice(&(str_off as u16).to_be_bytes());
        // NameRecord 1 (Family)
        name_tbl.extend_from_slice(&3u16.to_be_bytes());
        name_tbl.extend_from_slice(&1u16.to_be_bytes());
        name_tbl.extend_from_slice(&0x0409u16.to_be_bytes());
        name_tbl.extend_from_slice(&1u16.to_be_bytes());
        name_tbl.extend_from_slice(&(family_u16.len() as u16).to_be_bytes());
        name_tbl.extend_from_slice(&0u16.to_be_bytes());
        // NameRecord 2 (Subfamily)
        name_tbl.extend_from_slice(&3u16.to_be_bytes());
        name_tbl.extend_from_slice(&1u16.to_be_bytes());
        name_tbl.extend_from_slice(&0x0409u16.to_be_bytes());
        name_tbl.extend_from_slice(&2u16.to_be_bytes());
        name_tbl.extend_from_slice(&(sub_u16.len() as u16).to_be_bytes());
        name_tbl.extend_from_slice(&(family_u16.len() as u16).to_be_bytes());
        name_tbl.extend_from_slice(&family_u16);
        name_tbl.extend_from_slice(&sub_u16);

        let mut post_tbl = vec![0u8; 32];
        post_tbl[12..16].copy_from_slice(&(u32::from(fixed_pitch)).to_be_bytes());

        let header_len = 12 + 2 * 16;
        let name_offset = header_len;
        let name_padded = (name_tbl.len() + 3) & !3;
        let post_offset = name_offset + name_padded;

        let mut sfnt = Vec::new();
        sfnt.extend_from_slice(&0x0001_0000u32.to_be_bytes());
        sfnt.extend_from_slice(&2u16.to_be_bytes());
        sfnt.extend_from_slice(&32u16.to_be_bytes());
        sfnt.extend_from_slice(&1u16.to_be_bytes());
        sfnt.extend_from_slice(&0u16.to_be_bytes());

        // Table directory: `name`, `post`
        sfnt.extend_from_slice(b"name");
        sfnt.extend_from_slice(&0u32.to_be_bytes());
        sfnt.extend_from_slice(&(name_offset as u32).to_be_bytes());
        sfnt.extend_from_slice(&(name_tbl.len() as u32).to_be_bytes());

        sfnt.extend_from_slice(b"post");
        sfnt.extend_from_slice(&0u32.to_be_bytes());
        sfnt.extend_from_slice(&(post_offset as u32).to_be_bytes());
        sfnt.extend_from_slice(&(post_tbl.len() as u32).to_be_bytes());

        sfnt.extend_from_slice(&name_tbl);
        sfnt.resize(post_offset, 0);
        sfnt.extend_from_slice(&post_tbl);
        sfnt
    }

    #[test]
    fn scan_roots_parses_sfnt_ttc_and_rejects_outside_symlink() {
        let base = std::env::temp_dir().join(format!("rc-fonts-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let font_root = base.join("fonts");
        let outside_dir = base.join("outside");
        fs::create_dir_all(&font_root).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();

        let mono_ttf = build_minimal_sfnt("TestMono", "Regular", true);
        let prop_ttf = build_minimal_sfnt("TestSans", "Regular", false);
        fs::write(font_root.join("TestMono.ttf"), &mono_ttf).unwrap();
        fs::write(outside_dir.join("SecretProp.ttf"), &prop_ttf).unwrap();

        let ttc_face_base = build_minimal_sfnt("CollMono", "Regular", true);
        // Build minimal 1-face TTC wrapper around `ttc_face_base` with adjusted table offsets.
        let ttc_face_offset = 16u32;
        let face_shifted = {
            let mut f = ttc_face_base;
            // Shift table offsets in directory (at bytes 12+8 and 28+8) by +16
            let off1 = be_u32(&f, 20).unwrap() + ttc_face_offset;
            let off2 = be_u32(&f, 36).unwrap() + ttc_face_offset;
            f[20..24].copy_from_slice(&off1.to_be_bytes());
            f[36..40].copy_from_slice(&off2.to_be_bytes());
            f
        };
        let mut ttc = Vec::new();
        ttc.extend_from_slice(b"ttcf");
        ttc.extend_from_slice(&0x0001_0000u32.to_be_bytes());
        ttc.extend_from_slice(&1u32.to_be_bytes());
        ttc.extend_from_slice(&ttc_face_offset.to_be_bytes());
        ttc.extend_from_slice(&face_shifted);
        let mono2 = ttc;
        fs::write(font_root.join("CollectionFont.ttc"), &mono2).unwrap();

        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(
                outside_dir.join("SecretProp.ttf"),
                font_root.join("Escape.ttf"),
            );
        }

        let catalog = FontCatalog::scan_roots(&[font_root]);
        let listed = catalog.list();
        assert_eq!(listed.len(), 2, "only in-root fonts allowed: {listed:?}");
        assert_eq!(listed[0].family, "CollMono");
        assert_eq!(listed[1].family, "TestMono");
        assert!(listed[0].monospace);

        // Verify TTC extraction via FontCatalog produces standalone SFNT with offset=44 for first table
        let (_, fmt, extracted) = catalog
            .load_font_bytes(&listed[0].id)
            .expect("load ttc face via catalog");
        assert_eq!(fmt, "ttf");
        assert_eq!(&extracted[..4], &[0, 1, 0, 0]);
        assert_eq!(be_u32(&extracted, 20), Some(44));

        let err = catalog.load_font_bytes("nonexistent").unwrap_err();
        assert!(err.contains("未找到字体索引"));

        let _ = fs::remove_dir_all(&base);
    }
}
