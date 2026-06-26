//! The trust state of a package (brief §1.3, §4).

use serde::{Deserialize, Serialize};

/// The trust state of a package, as rendered in the consent dialog (brief §4).
///
/// Serializes to its bare variant name (`"Verified"`, `"VerifiedNewPublisher"`,
/// `"PublisherChanged"`, `"Unverified"`) so the Svelte frontend can switch on a
/// plain string. Do not add `#[serde(rename_all)]` — the frontend depends on
/// these exact spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Signed, signature valid, and the key matches the one already pinned for
    /// this id. Render green / "Verified".
    Verified,
    /// Signed, signature valid, and this is the first time we've seen this id —
    /// the key is being pinned now (TOFU). Render "Verified — NEW publisher".
    VerifiedNewPublisher,
    /// Signed, but the embedded key differs from the key already pinned for this
    /// id. Possible impersonation — render red, require explicit override, never
    /// install silently.
    PublisherChanged,
    /// No publisher key present (or signature absent). Render yellow,
    /// "UNVERIFIED — publisher unknown". Can never become `Verified`.
    Unverified,
}

impl TrustLevel {
    /// Whether this level represents a cryptographically trusted publisher
    /// (`Verified` or `VerifiedNewPublisher`).
    pub fn is_trusted(self) -> bool {
        matches!(
            self,
            TrustLevel::Verified | TrustLevel::VerifiedNewPublisher
        )
    }

    /// Whether proceeding from this level requires an explicit user override
    /// beyond the normal Install click (`PublisherChanged`).
    pub fn requires_override(self) -> bool {
        matches!(self, TrustLevel::PublisherChanged)
    }
}
