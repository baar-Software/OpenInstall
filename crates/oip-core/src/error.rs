//! Error type for the verification core.
//!
//! Consumers (`src-tauri`) surface these to the user via `Display`, so each
//! message is written to be safe and meaningful in a UI.

use thiserror::Error;

/// Anything that can go wrong while verifying a publisher signature.
///
/// Every variant represents a *fail-closed* condition: when the core returns
/// one of these, the caller must abort and install nothing (brief §1.2).
#[derive(Debug, Error)]
pub enum OipError {
    /// The publisher's minisign public key could not be decoded.
    #[error("publisher public key is malformed: {0}")]
    MalformedPublicKey(String),

    /// The detached signature could not be decoded.
    #[error("publisher signature is malformed: {0}")]
    MalformedSignature(String),

    /// The signature did not verify against the public key over the manifest
    /// bytes. (Tampered manifest, or signed with the wrong key.)
    #[error("publisher signature verification failed — manifest may be tampered or signed with the wrong key")]
    SignatureInvalid,
}
