//! # `oip-core` — OpenInstall verification core
//!
//! This crate is the security kernel of OpenInstall. It is **pure** and
//! **side-effect-free**: it performs no I/O, no network access, no process
//! spawning, and no clock/random access. It only takes bytes in and returns
//! decisions. All I/O (download, disk, install) lives in `oip-client` /
//! `src-tauri`, which is what makes the consent gate enforceable at the type
//! level: this crate *cannot* install anything.
//!
//! ## Public surface
//!
//! ```ignore
//! pub fn verify_manifest_sig(manifest_bytes: &[u8], sig: &[u8], pubkey: &str) -> Result<(), OipError>;
//! pub fn key_fingerprint(public_key: &str) -> String;
//! pub struct PinnedKey { .. }   // TOFU pin record
//! pub enum TrustLevel { Verified, VerifiedNewPublisher, PublisherChanged, Unverified }
//! ```
//!
//! `TrustLevel` serializes to its bare variant name; the Svelte frontend depends
//! on those exact spellings.
//!
//! ## Invariants this crate is responsible for (brief §1)
//!
//! * **#2 Fail closed.** [`verify_manifest_sig`] returns `Err` on a malformed
//!   key, malformed signature, key-id mismatch, or any cryptographic failure —
//!   there is no "best effort" path.
//! * **#3 TOFU.** [`PinnedKey`] is the pinned-key record the client compares the
//!   package's embedded key against to decide a [`TrustLevel`].

#![forbid(unsafe_code)]

mod error;
mod keys;
mod trust;
mod verify;

pub use error::OipError;
pub use keys::{key_fingerprint, PinnedKey};
pub use trust::TrustLevel;
pub use verify::verify_manifest_sig;
