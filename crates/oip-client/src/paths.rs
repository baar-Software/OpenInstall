//! Shared location for OpenInstall's per-user data directory
//! (`%APPDATA%\OpenInstall\`), used by the pin store, blocklist, settings, and
//! installed-apps registry. Honors `OPENINSTALL_DATA_DIR` for tests.

use std::path::PathBuf;

pub(crate) const APP_DIR: &str = "OpenInstall";

/// The per-user data directory, or `None` if it can't be determined.
pub(crate) fn data_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("OPENINSTALL_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }
    dirs::data_dir().map(|d| d.join(APP_DIR))
}

/// Tests in `store`, `settings`, and `registry` all toggle the process-global
/// `OPENINSTALL_DATA_DIR`; this lock serializes them so they don't clobber each
/// other. Recovers from poisoning (a panicking test shouldn't wedge the rest).
#[cfg(test)]
pub(crate) fn test_env_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
