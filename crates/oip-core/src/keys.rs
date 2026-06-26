//! Publisher-key primitives shared by the verification core: the pinned-key
//! record used for trust-on-first-use (TOFU) and a human-facing key fingerprint.

use serde::{Deserialize, Serialize};

/// A publisher key previously pinned for an app `id`, loaded from
/// `%APPDATA%\OpenInstall\` by the client. Compared against the key embedded in a
/// package to make the TOFU trust decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedKey {
    /// The app id this pin belongs to (reverse-DNS).
    pub id: String,
    /// The pinned minisign public key (`RW...` base64 form).
    pub public_key: String,
    /// RFC 3339 timestamp of when the key was first pinned (informational).
    #[serde(default)]
    pub first_seen: Option<String>,
}

/// A short, stable, human-facing fingerprint of a publisher public key, for the
/// consent dialog (e.g. rendered as `RWQf6L…`). Deterministic; no I/O.
///
/// The fingerprint is the first 10 characters of the key followed by an ellipsis.
/// It is purely a display aid for humans comparing keys; it is NEVER used to make
/// a trust decision (that compares the full key). Keys shorter than the prefix are
/// returned verbatim (still non-empty for any non-empty key).
pub fn key_fingerprint(public_key: &str) -> String {
    const PREFIX_CHARS: usize = 10;
    let key = public_key.trim();
    let mut chars = key.chars();
    let prefix: String = chars.by_ref().take(PREFIX_CHARS).collect();
    if chars.next().is_some() {
        // There were more characters beyond the prefix; indicate truncation.
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_truncates_long_keys() {
        let fp = key_fingerprint("RWQf6LRCGA9i53mlYecO4IzT51TGPo7wuoZtiAi4QrJX2vKt0o0bdaff");
        assert_eq!(fp, "RWQf6LRCGA…");
    }

    #[test]
    fn fingerprint_returns_short_keys_verbatim() {
        assert_eq!(key_fingerprint("RWshort"), "RWshort");
        assert_eq!(key_fingerprint(""), "");
    }
}
