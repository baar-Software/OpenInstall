//! Error type for the verification core.
//!
//! Consumers (`src-tauri`) surface these to the user via `Display`, so each
//! message is written to be safe and meaningful in a UI. Subagent 1 may ADD
//! variants (it's additive and backward-compatible because callers stringify),
//! but must not rename or remove the existing ones.

use thiserror::Error;

/// Anything that can go wrong while parsing or verifying an `.oip` package.
///
/// Every variant represents a *fail-closed* condition: when the core returns
/// one of these, the caller must abort and install nothing (brief §1.2).
#[derive(Debug, Error)]
pub enum OipError {
    /// `manifest.toml` was not valid UTF-8.
    #[error("manifest is not valid UTF-8: {0}")]
    ManifestEncoding(String),

    /// `manifest.toml` was not valid TOML, or did not match the expected shape.
    #[error("manifest is malformed: {0}")]
    ManifestParse(String),

    /// `schema` was present but is a version this build does not understand.
    #[error("unsupported manifest schema version {0} (this build supports schema 1)")]
    UnsupportedSchema(u32),

    /// A required manifest field was missing.
    #[error("manifest is missing required field: {0}")]
    MissingField(&'static str),

    /// A manifest field was present but invalid (bad reverse-DNS id, empty name,
    /// malformed hash hex, etc.).
    #[error("manifest field `{field}` is invalid: {reason}")]
    InvalidField { field: &'static str, reason: String },

    /// `[payload].type` was not one of the supported values.
    #[error("unsupported payload type `{0}` (expected `exe` or `msi`)")]
    UnsupportedPayloadType(String),

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

    /// The payload's BLAKE3 digest did not match the value pinned in the manifest.
    #[error("payload BLAKE3 hash mismatch — the binary does not match the signed manifest")]
    Blake3Mismatch,

    /// The payload's SHA-256 digest did not match the value pinned in the manifest.
    #[error("payload SHA-256 hash mismatch — the binary does not match the signed manifest")]
    Sha256Mismatch,
}
