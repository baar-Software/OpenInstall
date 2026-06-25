//! # `oip-core` — OpenInstall verification core
//!
//! This crate is the security kernel of OpenInstall. It is **pure** and
//! **side-effect-free**: it performs no I/O, no network access, no process
//! spawning, and no clock/random access. It only takes bytes in and returns
//! decisions. All I/O (download, disk, install) lives in `src-tauri`,
//! which is what makes the consent gate enforceable at the type level: this
//! crate *cannot* install anything.
//!
//! ## The §7 contract (FROZEN — do not change these signatures)
//!
//! ```ignore
//! pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, OipError>;
//! pub fn verify_manifest_sig(manifest_bytes: &[u8], sig: &[u8], pubkey: &str) -> Result<(), OipError>;
//! pub fn verify_payload(bytes: &[u8], m: &Manifest) -> Result<(), OipError>;
//! pub fn evaluate_trust(m: &Manifest, pinned: Option<&PinnedKey>) -> TrustLevel;
//! ```
//!
//! Phase B / subagent 1 fills in the bodies. New `OipError` variants and new
//! helper functions may be ADDED, but the four signatures above, the public
//! struct/enum field names, and the `TrustLevel` variants must not change — every
//! sibling crate (and the frontend's serialized view) is built against them.
//!
//! ## Invariants this crate is responsible for (brief §1)
//!
//! * **#2 Fail closed.** Every function returns `Err`/`Unverified` on anything
//!   missing, malformed, or mismatched. There is no "best effort" path.
//! * **#3 TOFU.** [`evaluate_trust`] decides `Verified` / `VerifiedNewPublisher`
//!   / `PublisherChanged` / `Unverified` from the manifest's embedded key and the
//!   currently pinned key. It performs the comparison only; the caller must have
//!   already verified the signature (or established its absence) before trusting
//!   the result for anything other than rendering.
//! * **#8 Unsigned is degraded, never "verified".** A manifest with no
//!   `[publisher_key]` parses fine but can only ever evaluate to `Unverified`.

#![forbid(unsafe_code)]

mod error;
mod manifest;
mod trust;
mod verify;

pub use error::OipError;
pub use manifest::{
    key_fingerprint, parse_manifest, Manifest, Payload, PayloadType, PinnedKey, PublisherKey,
};
pub use trust::{evaluate_trust, TrustLevel};
pub use verify::{verify_manifest_sig, verify_payload};

/// Length, in lowercase hex characters, of a BLAKE3-256 digest.
pub const BLAKE3_HEX_LEN: usize = 64;
/// Length, in lowercase hex characters, of a SHA-256 digest.
pub const SHA256_HEX_LEN: usize = 64;
