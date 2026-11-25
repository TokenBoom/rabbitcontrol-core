//! RabbitControl 配置文件、运行时目录与 IPC 路径解析。
//!
//! 统一封装用户态目录（`$HOME/.config/rabbitcontrol`）与 macOS 系统服务模式目录
//! （`/Library/Application Support/RabbitControl`）之间的切换逻辑，避免各模块重复拼接路径。

#![deny(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// macOS 系统后台服务安装后的共享配置根目录。
pub const MACOS_SYSTEM_CONFIG_DIR: &str = "/Library/Application Support/RabbitControl";

/// 系统服务已安装标记文件名。
pub const SERVICE_MANAGED_MARKER: &str = "service-managed";

/// 测试与开发覆盖配置根目录的环境变量名。
pub const ENV_CONFIG_DIR: &str = "RC_CONFIG_DIR";

/// 标记当前进程处于后台系统服务（daemon / agent）模式。
pub const ENV_DAEMON_MODE: &str = "RC_DAEMON_MODE";

/// 覆盖 macOS 系统配置根目录的环境变量名（主要用于测试或打包验证）。
pub const ENV_SYSTEM_CONFIG_DIR: &str = "RC_SYSTEM_CONFIG_DIR";

/// 返回用户态默认配置根目录：`$HOME/.config/rabbitcontrol`。
pub fn user_config_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("rabbitcontrol")
}

/// 返回系统级配置根目录（macOS 默认为 `/Library/Application Support/RabbitControl`）。
pub fn system_config_dir() -> PathBuf {
    if let Some(val) = non_empty_env_path(ENV_SYSTEM_CONFIG_DIR) {
        return val;
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(MACOS_SYSTEM_CONFIG_DIR)
    }
    #[cfg(not(target_os = "macos"))]
    {
        user_config_dir()
    }
}

/// 返回系统服务标记文件在系统目录中的期望路径。
pub fn service_managed_marker_path() -> PathBuf {
    system_config_dir().join(SERVICE_MANAGED_MARKER)
}

/// 判断当前环境是否启用了系统后台服务托管模式。
pub fn is_service_managed() -> bool {
    let daemon_env =
        std::env::var_os(ENV_DAEMON_MODE).is_some_and(|v| !v.to_string_lossy().trim().is_empty());
    #[cfg(target_os = "macos")]
    {
        daemon_env || service_managed_marker_path().exists()
    }
    #[cfg(not(target_os = "macos"))]
    {
        daemon_env
    }
}

/// 解析当前生效的配置根目录。
///
/// 优先级：
/// 1. `RC_CONFIG_DIR` 环境变量（显式覆盖）；
/// 2. macOS 下若存在系统服务标记文件或 `RC_DAEMON_MODE` 已设置，返回 [`system_config_dir`]；
/// 3. 默认回退到 [`user_config_dir`]。
pub fn config_dir() -> PathBuf {
    if let Some(override_dir) = non_empty_env_path(ENV_CONFIG_DIR) {
        return override_dir;
    }
    if is_service_managed() {
        return system_config_dir();
    }
    user_config_dir()
}

/// 返回运行时目录（存放 Unix Socket、IPC 密钥与停止/启动标记）。
pub fn run_dir() -> PathBuf {
    config_dir().join("run")
}

/// 返回 `rc-host-agent` 暴露给控制端 GUI 的 IPC Unix Socket 路径。
pub fn agent_socket_path() -> PathBuf {
    run_dir().join("agent.sock")
}

/// 返回 `rc-daemon` 暴露给同机组件的 IPC Unix Socket 路径。
pub fn daemon_socket_path() -> PathBuf {
    run_dir().join("daemon.sock")
}

/// 返回前台控制端 GUI（`rc-ui`）暴露给后台状态栏唤醒用的 IPC Unix Socket 路径。
pub fn gui_socket_path() -> PathBuf {
    run_dir().join("gui.sock")
}

/// 返回「整体退出」防拉起标记文件路径（由 launchd `KeepAlive.PathState` 监控）。
pub fn manual_stop_path() -> PathBuf {
    run_dir().join("manual-stop")
}

/// 返回开机自检标记文件路径（每次开机后由 daemon 创建/刷新）。
pub fn boot_marker_path() -> PathBuf {
    run_dir().join("boot-marker")
}

/// 返回本地 IPC 共享鉴权密钥文件路径。
pub fn ipc_secret_path() -> PathBuf {
    run_dir().join("ipc.secret")
}

/// 判断路径是否处于系统托管目录之下（需要与登录用户共享 `0660`/`2770` 组权限）。
pub fn is_shared_system_path(path: &Path) -> bool {
    if !is_service_managed() {
        return false;
    }
    let sys_dir = system_config_dir();
    path.starts_with(&sys_dir)
}

/// 返回落盘私有文件应使用的 Unix 权限位（系统共享目录 `0660`，用户态目录 `0600`）。
pub fn file_mode_for(path: &Path) -> u32 {
    if is_shared_system_path(path) {
        0o660
    } else {
        0o600
    }
}

/// 返回私有目录应使用的 Unix 权限位（系统共享目录 `2770` 继承 `staff` 组，用户态目录 `0700`）。
pub fn dir_mode_for(path: &Path) -> u32 {
    if is_shared_system_path(path) {
        0o2770
    } else {
        0o700
    }
}

/// 原子创建并写入私有文件（使用 `create_new + 0o600/0o660` 权限，消除默认 umask 暴露窗口）。
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("创建目录失败 {}: {e}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(dir_mode_for(parent)));
        }
    }

    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let mut hex = String::with_capacity(suffix.len() * 2);
    for b in suffix {
        hex.push_str(&format!("{b:02x}"));
    }
    let tmp_path = path.with_extension(format!("tmp.{}.{hex}", std::process::id()));
    #[cfg(unix)]
    let mode = file_mode_for(path);

    let write_res = (|| -> std::io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut file = opts.open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode));
        }
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "写入临时私有文件失败 {}: {err}",
            tmp_path.display()
        ));
    }

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("原子落盘私有文件失败 {}: {err}", path.display()));
    }
    Ok(())
}

/// 跨进程文件互斥锁守卫（基于 `O_CREAT | O_EXCL` 锁文件，析构时校验 `(dev, ino)` 身份后释放，无需 `unsafe`）。
pub struct FileLockGuard {
    lock_path: PathBuf,
    #[cfg(unix)]
    lock_id: Option<(u64, u64)>,
}

impl FileLockGuard {
    fn from_open_file(lock_path: PathBuf, file: &fs::File) -> Self {
        #[cfg(unix)]
        let lock_id = {
            use std::os::unix::fs::MetadataExt;
            file.metadata().ok().map(|m| (m.dev(), m.ino()))
        };
        #[cfg(not(unix))]
        let _ = file;
        Self {
            lock_path,
            #[cfg(unix)]
            lock_id,
        }
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Some((exp_dev, exp_ino)) = self.lock_id {
                if let Ok(meta) = fs::symlink_metadata(&self.lock_path) {
                    if meta.dev() != exp_dev || meta.ino() != exp_ino {
                        return;
                    }
                } else {
                    return;
                }
            }
        }
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// 为目标配置文件获取跨进程互斥锁（锁文件路径为 `<target>.lock`）；超时（含过期陈旧锁清理）返回 `None`。
pub fn acquire_file_lock(target: &Path, timeout: std::time::Duration) -> Option<FileLockGuard> {
    let file_name = target.file_name()?.to_string_lossy();
    let lock_path = target.with_file_name(format!("{file_name}.lock"));
    let stale_breaker_path = target.with_file_name(format!("{file_name}.stale.lock"));
    if let Some(parent) = lock_path.parent() {
        let _ = fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(dir_mode_for(parent)));
        }
    }

    let deadline = std::time::Instant::now() + timeout;
    let stale_after = std::time::Duration::from_secs(60);
    let breaker_stale_after = std::time::Duration::from_secs(60);

    loop {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(file_mode_for(target));
        }
        match opts.open(&lock_path) {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", std::process::id());
                return Some(FileLockGuard::from_open_file(lock_path, &file));
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let needs_stale_check = match fs::symlink_metadata(&lock_path) {
                    Ok(meta) if meta.file_type().is_symlink() => true,
                    Ok(meta) => meta
                        .modified()
                        .ok()
                        .and_then(|m| std::time::SystemTime::now().duration_since(m).ok())
                        .map(|age| age >= stale_after)
                        .unwrap_or(false),
                    Err(_) => false,
                };
                if needs_stale_check {
                    // 使用独立 breaker 锁串行化陈旧锁清理并在持锁后复查，避免双等待者并发删掉刚新建的新锁。
                    let mut b_opts = OpenOptions::new();
                    b_opts.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        b_opts.mode(file_mode_for(target));
                    }
                    match b_opts.open(&stale_breaker_path) {
                        Ok(breaker_file) => {
                            let _breaker = FileLockGuard::from_open_file(
                                stale_breaker_path.clone(),
                                &breaker_file,
                            );
                            if let Ok(meta) = fs::symlink_metadata(&lock_path) {
                                let still_stale = meta.file_type().is_symlink()
                                    || meta
                                        .modified()
                                        .ok()
                                        .and_then(|m| {
                                            std::time::SystemTime::now().duration_since(m).ok()
                                        })
                                        .map(|age| age >= stale_after)
                                        .unwrap_or(false);
                                if still_stale && fs::remove_file(&lock_path).is_ok() {
                                    // 立刻尝试抢锁一次；若仍失败则走下方的超时与退避分支，防止移除失败时死循环空转。
                                    if let Ok(mut file) = opts.open(&lock_path) {
                                        let _ = writeln!(file, "{}", std::process::id());
                                        return Some(FileLockGuard::from_open_file(
                                            lock_path, &file,
                                        ));
                                    }
                                }
                            }
                        }
                        Err(be) if be.kind() == std::io::ErrorKind::AlreadyExists => {
                            if let Ok(meta) = fs::symlink_metadata(&stale_breaker_path) {
                                let breaker_old = meta
                                    .modified()
                                    .ok()
                                    .and_then(|m| {
                                        std::time::SystemTime::now().duration_since(m).ok()
                                    })
                                    .map(|age| age >= breaker_stale_after)
                                    .unwrap_or(false);
                                if meta.file_type().is_symlink() || breaker_old {
                                    let _ = fs::remove_file(&stale_breaker_path);
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
            Err(_) => return None,
        }
    }
}

fn non_empty_env_path(name: &str) -> Option<PathBuf> {
    let raw = std::env::var_os(name)?;
    let trimmed = raw.to_string_lossy().trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            use rand::rngs::OsRng;
            use rand::RngCore;
            let mut b = [0u8; 8];
            OsRng.fill_bytes(&mut b);
            let dir = std::env::temp_dir().join(format!(
                "rc-ui-paths-{tag}-{}",
                crate::app_prefs::encode_hex_lower(&b)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn resolves_override_before_service_and_user() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TestDir::new("override");
        let marker_root = dir.0.join("sys");
        std::fs::create_dir_all(&marker_root).unwrap();
        std::fs::write(marker_root.join(SERVICE_MANAGED_MARKER), b"1").unwrap();

        let custom_root = dir.0.join("custom");
        std::env::set_var(ENV_SYSTEM_CONFIG_DIR, &marker_root);
        std::env::set_var(ENV_CONFIG_DIR, &custom_root);

        assert_eq!(config_dir(), custom_root);
        assert_eq!(agent_socket_path(), custom_root.join("run/agent.sock"));
        assert_eq!(daemon_socket_path(), custom_root.join("run/daemon.sock"));
        assert_eq!(manual_stop_path(), custom_root.join("run/manual-stop"));
        assert_eq!(boot_marker_path(), custom_root.join("run/boot-marker"));
        assert_eq!(ipc_secret_path(), custom_root.join("run/ipc.secret"));

        std::env::remove_var(ENV_CONFIG_DIR);
        #[cfg(target_os = "macos")]
        {
            assert!(is_service_managed());
            assert_eq!(config_dir(), marker_root);
        }

        std::env::set_var(ENV_DAEMON_MODE, "1");
        assert!(is_service_managed());
        assert_eq!(config_dir(), marker_root);

        std::env::remove_var(ENV_DAEMON_MODE);
        std::env::remove_var(ENV_SYSTEM_CONFIG_DIR);
    }

    #[test]
    fn falls_back_to_user_config_dir_when_unmanaged() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TestDir::new("unmanaged");
        std::env::set_var(ENV_SYSTEM_CONFIG_DIR, dir.0.join("nonexistent"));
        std::env::remove_var(ENV_CONFIG_DIR);
        std::env::remove_var(ENV_DAEMON_MODE);

        assert!(!is_service_managed());
        assert_eq!(config_dir(), user_config_dir());

        std::env::remove_var(ENV_SYSTEM_CONFIG_DIR);
    }

    #[test]
    fn file_lock_guard_excludes_concurrent_acquire_until_dropped() {
        let dir = TestDir::new("filelock");
        let target = dir.0.join("prefs.json");
        let lock_file = dir.0.join("prefs.json.lock");

        let guard = acquire_file_lock(&target, std::time::Duration::from_millis(200))
            .expect("首次加锁应立即成功");
        assert!(lock_file.exists());
        assert!(
            acquire_file_lock(&target, std::time::Duration::from_millis(45)).is_none(),
            "持锁期间再次加锁应超时返回 None"
        );
        drop(guard);
        assert!(!lock_file.exists(), "Drop 后应自动释放锁文件");
        assert!(
            acquire_file_lock(&target, std::time::Duration::from_millis(100)).is_some(),
            "释放后应可重新获取锁"
        );
    }
}
