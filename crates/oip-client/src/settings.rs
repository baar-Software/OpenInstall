//! Persistent user settings (`%APPDATA%\OpenInstall\settings.json`).
//!
//! The only setting today is **Developer Mode**, an explicit, off-by-default
//! opt-in that allows resolving `openinstall://localhostâ€¦` links (mapped to
//! `http://` for loopback hosts) so packages can be served from a local dev
//! server. It does NOT relax any cryptographic verification or the consent gate â€”
//! signature, hash, TOFU, MotW, and verification behavior are unchanged.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths::data_dir;

const SETTINGS_FILE: &str = "settings.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// When true, loopback hosts (`localhost`, `127.0.0.1`, `::1`) are accepted
    /// and served over `http://`. Off by default.
    #[serde(default)]
    pub developer_mode: bool,
}

/// Load settings, defaulting to all-off if the file is missing or unreadable.
pub fn load() -> Settings {
    let Some(path) = data_dir().map(|d| d.join(SETTINGS_FILE)) else {
        return Settings::default();
    };
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Settings::default(),
    }
}

/// Persist settings.
pub fn save(settings: &Settings) -> Result<()> {
    let base = data_dir().ok_or_else(|| anyhow!("no data directory available"))?;
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    let path = base.join(SETTINGS_FILE);
    let json = serde_json::to_vec_pretty(settings).context("serializing settings")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip_default_off() {
        let _guard = crate::paths::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("OPENINSTALL_DATA_DIR", dir.path());

        // Default when nothing saved.
        assert!(!load().developer_mode);

        let s = Settings {
            developer_mode: true,
        };
        save(&s).unwrap();
        assert!(load().developer_mode);

        std::env::remove_var("OPENINSTALL_DATA_DIR");
    }
}
