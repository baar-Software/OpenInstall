//! The parsed, validated `manifest.toml` model (brief §2) plus the pinned-key
//! record used for TOFU.
//!
//! These structs derive `Serialize`/`Deserialize` so `src-tauri` can both parse
//! the TOML and ship the relevant fields to the frontend. The *validated* entry
//! point is [`parse_manifest`]; deserializing a `Manifest` directly bypasses the
//! extra checks and should not be used for untrusted input.

use serde::{Deserialize, Serialize};

use crate::error::OipError;

/// The kind of installer carried in the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadType {
    Exe,
    Msi,
}

/// The `[payload]` table: which file to run and the hashes that pin it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// Path of the installer inside the `.oip` zip, e.g. `payload/Setup.exe`.
    pub file: String,
    /// `exe` or `msi`.
    #[serde(rename = "type")]
    pub payload_type: PayloadType,
    /// Lowercase hex BLAKE3-256 of the payload bytes.
    pub hash_blake3: String,
    /// Lowercase hex SHA-256 of the payload bytes.
    pub hash_sha256: String,
    /// Arguments handed to the installer *only after the user consents* (e.g. `/S`).
    #[serde(default)]
    pub silent_args: String,
}

/// The `[publisher_key]` table embedded in the manifest. Absent ⇒ unsigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherKey {
    /// Signature scheme; `minisign` for schema 1.
    #[serde(rename = "type")]
    pub key_type: String,
    /// The minisign public key (the `RW...` base64 form) the signature must
    /// verify against; this is the value pinned on TOFU.
    pub public_key: String,
}

/// A publisher key previously pinned for an app `id`, loaded from
/// `%APPDATA%\OpenInstall\` by `src-tauri`. Passed to [`evaluate_trust`].
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

/// A fully parsed and validated `manifest.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest schema version. Must be `1` for this build.
    pub schema: u32,
    /// Globally unique, immutable reverse-DNS id, e.g. `com.example.coolapp`.
    pub id: String,
    /// Human-facing app name.
    pub name: String,
    /// Human-facing publisher name.
    pub publisher: String,
    /// App version string.
    pub version: String,
    /// Optional homepage URL.
    #[serde(default)]
    pub homepage: String,
    /// The `[payload]` table.
    pub payload: Payload,
    /// The `[publisher_key]` table; `None` ⇒ unsigned package (brief §1.8).
    #[serde(default)]
    pub publisher_key: Option<PublisherKey>,
}

impl Manifest {
    /// Whether this package carries a publisher key at all (i.e. is even a
    /// candidate for a "verified" state).
    pub fn is_signed(&self) -> bool {
        self.publisher_key.is_some()
    }
}

/// Parse and **validate** a `manifest.toml`.
///
/// Implementations (subagent 1) MUST, at minimum:
/// * decode UTF-8 → [`OipError::ManifestEncoding`] on failure;
/// * parse TOML → [`OipError::ManifestParse`] on failure;
/// * require `schema == 1`, else [`OipError::UnsupportedSchema`];
/// * require non-empty `id`, `name`, `publisher`, `version`, and `payload.file`,
///   else [`OipError::MissingField`];
/// * validate `id` looks like reverse-DNS, else [`OipError::InvalidField`];
/// * validate `hash_blake3` / `hash_sha256` are 64-char lowercase hex
///   ([`crate::BLAKE3_HEX_LEN`] / [`crate::SHA256_HEX_LEN`]), else
///   [`OipError::InvalidField`];
/// * if `[publisher_key]` is present, require `type == "minisign"` and a
///   non-empty `public_key`.
///
/// This function performs NO I/O and is the only sanctioned way to turn
/// untrusted bytes into a [`Manifest`].
///
/// Fail-closed (brief §1.2): any missing, malformed, or out-of-spec field is a
/// hard error; there is no best-effort path and no partially-trusted result.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, OipError> {
    // 1. Bytes must be valid UTF-8 before TOML can even be considered.
    let text = std::str::from_utf8(bytes).map_err(|e| OipError::ManifestEncoding(e.to_string()))?;

    // 2. Parse TOML into the strongly-typed model. serde rejects unknown shapes,
    //    wrong types, and missing *structurally required* fields (e.g. `payload`).
    let manifest: Manifest =
        toml::from_str(text).map_err(|e| OipError::ManifestParse(e.to_string()))?;

    // 3. Schema gate: only schema 1 is understood by this build.
    if manifest.schema != 1 {
        return Err(OipError::UnsupportedSchema(manifest.schema));
    }

    // 4. Required string fields must be present *and* non-empty. serde's
    //    `#[serde(default)]` is not used on these, so absence is already a parse
    //    error; here we additionally reject empty / whitespace-only values.
    require_non_empty("id", &manifest.id)?;
    require_non_empty("name", &manifest.name)?;
    require_non_empty("publisher", &manifest.publisher)?;
    require_non_empty("version", &manifest.version)?;
    require_non_empty("payload.file", &manifest.payload.file)?;

    // 5. The id must look like a reverse-DNS name (>= 2 labels, each label
    //    non-empty and drawn from [A-Za-z0-9-]).
    validate_reverse_dns(&manifest.id)?;

    // 6. Both payload hashes must be exactly 64 lowercase-hex characters.
    validate_hex_digest(
        "payload.hash_blake3",
        &manifest.payload.hash_blake3,
        crate::BLAKE3_HEX_LEN,
    )?;
    validate_hex_digest(
        "payload.hash_sha256",
        &manifest.payload.hash_sha256,
        crate::SHA256_HEX_LEN,
    )?;

    // 7. If a publisher key is present, it must be a non-empty minisign key.
    //    (Absence is allowed: that yields an UNVERIFIED package, brief §1.8.)
    if let Some(key) = &manifest.publisher_key {
        if key.key_type != "minisign" {
            return Err(OipError::InvalidField {
                field: "publisher_key.type",
                reason: format!(
                    "unsupported key type `{}` (expected `minisign`)",
                    key.key_type
                ),
            });
        }
        if key.public_key.trim().is_empty() {
            return Err(OipError::MissingField("publisher_key.public_key"));
        }
    }

    Ok(manifest)
}

/// Reject an empty or whitespace-only required string field.
fn require_non_empty(field: &'static str, value: &str) -> Result<(), OipError> {
    if value.trim().is_empty() {
        return Err(OipError::MissingField(field));
    }
    Ok(())
}

/// Validate that `id` looks like a reverse-DNS identifier: at least two
/// dot-separated labels, each label non-empty and composed only of ASCII
/// alphanumerics and `-`.
fn validate_reverse_dns(id: &str) -> Result<(), OipError> {
    let invalid = |reason: String| OipError::InvalidField {
        field: "id",
        reason,
    };

    let labels: Vec<&str> = id.split('.').collect();
    if labels.len() < 2 {
        return Err(invalid(
            "expected reverse-DNS form with at least two dot-separated labels".to_string(),
        ));
    }
    for label in labels {
        if label.is_empty() {
            return Err(invalid(
                "contains an empty label (consecutive or leading/trailing dots)".to_string(),
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid(format!(
                "label `{label}` contains characters outside [A-Za-z0-9-]"
            )));
        }
    }
    Ok(())
}

/// Validate that `value` is exactly `expected_len` lowercase hexadecimal
/// characters. Used for the BLAKE3 and SHA-256 pins.
fn validate_hex_digest(
    field: &'static str,
    value: &str,
    expected_len: usize,
) -> Result<(), OipError> {
    if value.len() != expected_len {
        return Err(OipError::InvalidField {
            field,
            reason: format!(
                "expected {expected_len} lowercase hex characters, got {}",
                value.len()
            ),
        });
    }
    if !value
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(OipError::InvalidField {
            field,
            reason: "expected only lowercase hex characters [0-9a-f]".to_string(),
        });
    }
    Ok(())
}

/// A short, stable, human-facing fingerprint of a publisher public key, for the
/// consent dialog (e.g. rendered as `RWQf6L…`). Deterministic; no I/O.
///
/// The fingerprint is the first 10 characters of the key followed by an ellipsis.
/// It is purely a display aid for humans comparing keys; it is NEVER used to make
/// a trust decision (that is [`crate::evaluate_trust`], which compares the full
/// key). Keys shorter than the prefix are returned verbatim (still non-empty for
/// any non-empty key).
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
