//! Signature and payload verification (brief §1.2, §3 steps 5–6).

use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};

use crate::error::OipError;
use crate::manifest::Manifest;

/// Verify a detached minisign signature over the exact bytes of `manifest.toml`.
///
/// * `manifest_bytes` — the byte-for-byte content that was signed (NOT the parsed
///   model; the signature covers raw bytes, brief §2).
/// * `sig` — the full contents of `manifest.minisig` (the detached signature file).
/// * `pubkey` — the publisher minisign public key (`RW...` base64 form), i.e.
///   `Manifest::publisher_key.public_key`.
///
/// Returns `Ok(())` only if the signature verifies. On a malformed key/signature
/// or a verification failure, returns the corresponding [`OipError`] — never a
/// partial success. Uses `minisign-verify` (no I/O).
///
/// Fail-closed (brief §1.2): a malformed key, malformed signature, key-id
/// mismatch, or cryptographic failure all abort with an error and trust nothing.
pub fn verify_manifest_sig(
    manifest_bytes: &[u8],
    sig: &[u8],
    pubkey: &str,
) -> Result<(), OipError> {
    // The public key in the manifest is the bare `RW...` base64 form. Accept that
    // primarily; tolerate a full two-line `minisign.pub` (comment + key) as a
    // fallback so a copy-pasted public-key file still works. Either way, a key we
    // cannot decode is MalformedPublicKey — never a silent pass.
    let public_key = parse_public_key(pubkey)?;

    // The signature file (`manifest.minisig`) must be valid UTF-8 minisign text.
    let sig_text = std::str::from_utf8(sig)
        .map_err(|e| OipError::MalformedSignature(format!("signature is not valid UTF-8: {e}")))?;
    let signature =
        Signature::decode(sig_text).map_err(|e| OipError::MalformedSignature(e.to_string()))?;

    // Only accept pre-hashed minisign signatures.
    // (the default produced by current minisign / the `minisign` crate). A
    // key-id mismatch or any cryptographic failure maps to SignatureInvalid.
    public_key
        .verify(manifest_bytes, &signature, false)
        .map_err(|_| OipError::SignatureInvalid)
}

/// Decode a minisign public key supplied as either the bare base64 (`RW...`)
/// form or a full two-line `minisign.pub` (untrusted-comment + key).
fn parse_public_key(pubkey: &str) -> Result<PublicKey, OipError> {
    let trimmed = pubkey.trim();
    if trimmed.is_empty() {
        return Err(OipError::MalformedPublicKey(
            "public key is empty".to_string(),
        ));
    }

    // Primary path: bare single-line base64 key.
    if let Ok(pk) = PublicKey::from_base64(trimmed) {
        return Ok(pk);
    }

    // Fallback: a full `minisign.pub` file (comment line + key line).
    PublicKey::decode(trimmed).map_err(|e| OipError::MalformedPublicKey(e.to_string()))
}

/// Verify the payload bytes against BOTH hashes pinned in the manifest.
///
/// Computes BLAKE3-256 and SHA-256 over `bytes` and compares (case-insensitive
/// hex) against `m.payload.hash_blake3` / `m.payload.hash_sha256`. Returns
/// [`OipError::Blake3Mismatch`] or [`OipError::Sha256Mismatch`] on the first
/// mismatch. BOTH must pass. No I/O.
///
/// Defense in depth: pinning two independent hash functions means a single
/// broken primitive cannot let a substituted payload through.
pub fn verify_payload(bytes: &[u8], m: &Manifest) -> Result<(), OipError> {
    // BLAKE3-256: `Hash::to_hex` yields lowercase hex.
    let blake3_hex = blake3::hash(bytes).to_hex();
    if !hex_eq_ascii_ci(blake3_hex.as_str(), &m.payload.hash_blake3) {
        return Err(OipError::Blake3Mismatch);
    }

    // SHA-256.
    let sha256_hex = hex::encode(Sha256::digest(bytes));
    if !hex_eq_ascii_ci(&sha256_hex, &m.payload.hash_sha256) {
        return Err(OipError::Sha256Mismatch);
    }

    Ok(())
}

/// Compare two hex strings for equality, ignoring ASCII case.
///
/// `parse_manifest` already constrains the manifest pins to 64 lowercase-hex
/// chars, but `verify_payload` may be called on a `Manifest` constructed by other
/// means, so we stay tolerant of uppercase on the manifest side while computing
/// our own digests in lowercase.
fn hex_eq_ascii_ci(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}
