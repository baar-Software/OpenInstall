//! TOFU (trust-on-first-use) trust evaluation (brief §1.3).

use serde::{Deserialize, Serialize};

use crate::manifest::{Manifest, PinnedKey};

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

/// Decide the [`TrustLevel`] for a manifest given the currently pinned key (if
/// any) for its id.
///
/// **Contract:** the caller must already have verified the manifest signature
/// against `m.publisher_key` (via [`crate::verify_manifest_sig`]) BEFORE calling
/// this, or established that no key is present. This function only performs the
/// key-comparison / TOFU decision:
///
/// * no `publisher_key` in the manifest        → [`TrustLevel::Unverified`]
/// * key present, no pin yet for this id        → [`TrustLevel::VerifiedNewPublisher`]
/// * key present, equals the pinned key         → [`TrustLevel::Verified`]
/// * key present, differs from the pinned key   → [`TrustLevel::PublisherChanged`]
///
/// No I/O; deterministic.
pub fn evaluate_trust(m: &Manifest, pinned: Option<&PinnedKey>) -> TrustLevel {
    // Brief §1.8: a manifest with no publisher key can NEVER be "verified".
    let manifest_key = match &m.publisher_key {
        Some(key) => key.public_key.trim(),
        None => return TrustLevel::Unverified,
    };

    match pinned {
        // First time we've seen this id: TOFU pins this key now.
        None => TrustLevel::VerifiedNewPublisher,
        // Seen before: the embedded key must match the pinned key exactly.
        // A difference is a possible impersonation (brief §1.3) and must never
        // install silently.
        Some(pin) if pin.public_key.trim() == manifest_key => TrustLevel::Verified,
        Some(_) => TrustLevel::PublisherChanged,
    }
}
