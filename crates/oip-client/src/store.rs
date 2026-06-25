//! Persistent TOFU pin store and revocation blocklist under
//! `%APPDATA%\OpenInstall\` (brief §1.3, §3 step 8).
//!
//! * `pins.json`      — map of app id → pinned publisher key (TOFU).
//! * `blocklist.json` — local known-bad hashes, app ids, publisher names, and publisher keys.
//! * `remote-blocklist.txt` — cached GitHub-backed revocation feed.
//!
//! Missing files mean "no pins" / "nothing blocked" (not an error). Writes are
//! best-effort; a pin write failure must never silently weaken a future check, so
//! callers should surface failures.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use oip_core::PinnedKey;
use serde::{Deserialize, Serialize};

use crate::paths::data_dir as base_dir;

const PINS_FILE: &str = "pins.json";
const BLOCKLIST_FILE: &str = "blocklist.json";
const REMOTE_BLOCKLIST_FILE: &str = "remote-blocklist.txt";
const DEFAULT_REMOTE_BLOCKLIST_URL: &str =
    "https://raw.githubusercontent.com/baar-Software/OpenInstall/main/blocklist.txt";

#[derive(Default, Serialize, Deserialize)]
struct PinFile {
    /// id -> pinned key
    pins: HashMap<String, PinnedKey>,
}

#[derive(Default, Serialize, Deserialize)]
struct BlockFile {
    #[serde(default)]
    blocked_hashes: Vec<String>,
    #[serde(default)]
    blocked_app_ids: Vec<String>,
    #[serde(default)]
    blocked_publishers: Vec<String>,
    #[serde(default)]
    blocked_keys: Vec<String>,
}

#[derive(Debug, Default)]
pub struct BlockSubject<'a> {
    pub package_sha256: Option<&'a str>,
    pub payload_hash: Option<&'a str>,
    pub file_hashes: &'a [String],
    pub app_id: Option<&'a str>,
    pub publisher_name: Option<&'a str>,
    pub publisher_key: Option<&'a str>,
}

fn read_pins() -> PinFile {
    let Some(path) = base_dir().map(|d| d.join(PINS_FILE)) else {
        return PinFile::default();
    };
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => PinFile::default(),
    }
}

/// Load the pinned key for an app id, if any.
pub fn load_pin(id: &str) -> Option<PinnedKey> {
    read_pins().pins.get(id).cloned()
}

/// Pin (or update) the publisher key for an app id. Updating an existing pin is
/// only appropriate after an explicit user override of a `PublisherChanged`
/// warning — callers must enforce that policy before calling this.
pub fn save_pin(pin: &PinnedKey) -> Result<()> {
    let base = base_dir().ok_or_else(|| anyhow!("no data directory available"))?;
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    let path = base.join(PINS_FILE);

    let mut file = read_pins();
    file.pins.insert(pin.id.clone(), pin.clone());
    let json = serde_json::to_vec_pretty(&file).context("serializing pins")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn read_blocklist() -> BlockFile {
    let Some(path) = base_dir().map(|d| d.join(BLOCKLIST_FILE)) else {
        return BlockFile::default();
    };
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => BlockFile::default(),
    }
}

fn read_remote_blocklist() -> BlockFile {
    let Some(path) = base_dir().map(|d| d.join(REMOTE_BLOCKLIST_FILE)) else {
        return BlockFile::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_blocklist_txt(&text),
        Err(_) => BlockFile::default(),
    }
}

pub async fn refresh_remote_blocklist() -> Result<()> {
    let url = std::env::var("OPENINSTALL_BLOCKLIST_URL")
        .unwrap_or_else(|_| DEFAULT_REMOTE_BLOCKLIST_URL.to_string());
    let text = reqwest::get(&url)
        .await
        .with_context(|| format!("fetching remote blocklist {url}"))?
        .error_for_status()
        .with_context(|| format!("fetching remote blocklist {url}"))?
        .text()
        .await
        .context("reading remote blocklist")?;
    let _parsed = parse_blocklist_txt(&text);
    let base = base_dir().ok_or_else(|| anyhow!("no data directory available"))?;
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    let path = base.join(REMOTE_BLOCKLIST_FILE);
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Whether a package is revoked by the local blocklist or cached GitHub-backed
/// blocklist. Hash comparisons are case-insensitive.
pub fn is_blocked(subject: &BlockSubject<'_>) -> bool {
    let local = read_blocklist();
    let remote = read_remote_blocklist();
    blockfile_matches(&local, subject) || blockfile_matches(&remote, subject)
}

fn blockfile_matches(bl: &BlockFile, subject: &BlockSubject<'_>) -> bool {
    let hash_blocked = bl.blocked_hashes.iter().any(|blocked| {
        subject
            .package_sha256
            .is_some_and(|hash| blocked.eq_ignore_ascii_case(hash))
            || subject
                .payload_hash
                .is_some_and(|hash| blocked.eq_ignore_ascii_case(hash))
            || subject
                .file_hashes
                .iter()
                .any(|hash| blocked.eq_ignore_ascii_case(hash))
    });
    let app_blocked = match subject.app_id {
        Some(id) => bl.blocked_app_ids.iter().any(|blocked| blocked == id),
        None => false,
    };
    let publisher_blocked = match subject.publisher_name {
        Some(name) => bl
            .blocked_publishers
            .iter()
            .any(|blocked| blocked.eq_ignore_ascii_case(name)),
        None => false,
    };
    let key_blocked = match subject.publisher_key {
        Some(k) => bl.blocked_keys.iter().any(|blocked| blocked == k),
        None => false,
    };
    hash_blocked || app_blocked || publisher_blocked || key_blocked
}

fn parse_blocklist_txt(text: &str) -> BlockFile {
    let mut out = BlockFile::default();
    for raw_line in text.lines() {
        let line = raw_line
            .split_once('#')
            .map(|(value, _)| value)
            .unwrap_or(raw_line)
            .trim();
        if line.is_empty() {
            continue;
        }
        let Some((kind, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match kind.trim().to_ascii_lowercase().as_str() {
            "hash" | "sha256" | "blake3" | "package-sha256" | "file-sha256" => {
                out.blocked_hashes.push(value.to_string());
            }
            "app" | "app-id" | "bundle" | "bundle-id" => {
                out.blocked_app_ids.push(value.to_string());
            }
            "publisher" | "author" => {
                out.blocked_publishers.push(value.to_string());
            }
            "key" | "publisher-key" => {
                out.blocked_keys.push(value.to_string());
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: these tests set OPENINSTALL_DATA_DIR (process-global env), so they run
    // in one test fn to avoid cross-test interference.
    #[test]
    fn pin_roundtrip_and_blocklist() {
        let _guard = crate::paths::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("OPENINSTALL_DATA_DIR", dir.path());

        assert!(load_pin("com.example.app").is_none());

        let pin = PinnedKey {
            id: "com.example.app".to_string(),
            public_key: "RWQf6LRCGA9iAAAA".to_string(),
            first_seen: Some("1700000000".to_string()),
        };
        save_pin(&pin).unwrap();

        let loaded = load_pin("com.example.app").expect("pin present after save");
        assert_eq!(loaded.public_key, "RWQf6LRCGA9iAAAA");

        // Different id has no pin.
        assert!(load_pin("com.other.app").is_none());

        // Blocklist: write one and check.
        let bl = BlockFile {
            blocked_hashes: vec!["ABC123".to_string()],
            blocked_app_ids: vec!["com.bad.app".to_string()],
            blocked_publishers: vec!["Bad Publisher".to_string()],
            blocked_keys: vec!["RWbad".to_string()],
        };
        std::fs::write(
            dir.path().join(BLOCKLIST_FILE),
            serde_json::to_vec(&bl).unwrap(),
        )
        .unwrap();
        assert!(is_blocked(&BlockSubject {
            payload_hash: Some("abc123"),
            ..BlockSubject::default()
        })); // case-insensitive hash
        assert!(is_blocked(&BlockSubject {
            publisher_key: Some("RWbad"),
            ..BlockSubject::default()
        }));
        assert!(is_blocked(&BlockSubject {
            app_id: Some("com.bad.app"),
            ..BlockSubject::default()
        }));
        assert!(is_blocked(&BlockSubject {
            publisher_name: Some("bad publisher"),
            ..BlockSubject::default()
        }));
        assert!(!is_blocked(&BlockSubject {
            payload_hash: Some("nope"),
            publisher_key: Some("RWgood"),
            ..BlockSubject::default()
        }));

        std::env::remove_var("OPENINSTALL_DATA_DIR");
    }

    #[test]
    fn parses_remote_blocklist_txt() {
        let parsed = parse_blocklist_txt(
            r#"
            # comments are allowed
            hash: AABB
            app-id: com.evil.app
            publisher: Evil Corp
            publisher-key: RWbadkey
            ignored: nope
            "#,
        );
        assert_eq!(parsed.blocked_hashes, vec!["AABB"]);
        assert_eq!(parsed.blocked_app_ids, vec!["com.evil.app"]);
        assert_eq!(parsed.blocked_publishers, vec!["Evil Corp"]);
        assert_eq!(parsed.blocked_keys, vec!["RWbadkey"]);
    }
}
