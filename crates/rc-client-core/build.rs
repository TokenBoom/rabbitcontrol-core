use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RC_CORE_VERSION");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let core_version = env::var("RC_CORE_VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string()));

    let build_timestamp = env::var("SOURCE_DATE_EPOCH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| is_valid_unix_epoch_seconds(s))
        .unwrap_or_else(|| "unknown".to_string());

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    emit_git_rerun_hints(&manifest_dir);
    let git_commit = read_git_short_commit(&manifest_dir).unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=RC_CORE_EFFECTIVE_VERSION={core_version}");
    println!("cargo:rustc-env=RC_CORE_GIT_COMMIT={git_commit}");
    println!("cargo:rustc-env=RC_CORE_BUILD_TIMESTAMP={build_timestamp}");
}

fn is_valid_unix_epoch_seconds(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u64>().is_ok()
}

fn read_git_short_commit(manifest_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(manifest_dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let trimmed = commit.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn emit_git_rerun_hints(manifest_dir: &Path) {
    let Some(git_dir) = find_git_dir(manifest_dir) else {
        return;
    };
    let common_dir = resolve_git_common_dir(&git_dir);
    let head_path = git_dir.join("HEAD");
    if !head_path.exists() {
        return;
    }
    println!("cargo:rerun-if-changed={}", head_path.display());

    if let Ok(head_contents) = std::fs::read_to_string(&head_path) {
        if let Some(ref_name) = head_contents.trim().strip_prefix("ref:") {
            let ref_rel = ref_name.trim();
            let direct_ref = git_dir.join(ref_rel);
            let common_ref = common_dir.join(ref_rel);
            if direct_ref.exists() {
                println!("cargo:rerun-if-changed={}", direct_ref.display());
            } else if common_ref.exists() {
                println!("cargo:rerun-if-changed={}", common_ref.display());
            } else {
                let packed_refs = common_dir.join("packed-refs");
                if packed_refs.exists() {
                    println!("cargo:rerun-if-changed={}", packed_refs.display());
                }
            }
        }
    }
}

fn resolve_git_common_dir(git_dir: &Path) -> PathBuf {
    let commondir_file = git_dir.join("commondir");
    if let Ok(contents) = std::fs::read_to_string(&commondir_file) {
        let rel = contents.trim();
        if !rel.is_empty() {
            let path = Path::new(rel);
            let candidate = if path.is_absolute() {
                path.to_path_buf()
            } else {
                git_dir.join(path)
            };
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    git_dir.to_path_buf()
}

fn find_git_dir(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        let dot_git = ancestor.join(".git");
        if dot_git.is_dir() {
            return Some(dot_git);
        }
        if dot_git.is_file() {
            let contents = std::fs::read_to_string(&dot_git).ok()?;
            let gitdir = contents.trim().strip_prefix("gitdir:")?.trim();
            let resolved = Path::new(gitdir);
            return Some(if resolved.is_absolute() {
                resolved.to_path_buf()
            } else {
                ancestor.join(resolved)
            });
        }
    }
    None
}
