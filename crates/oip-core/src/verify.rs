//! Publisher signature verification (brief §1.2, §3 step 5).

use minisign_verify::{PublicKey, Signature};

use crate::error::OipError;

/// Verify a detached minisign signature over the exact manifest bytes.
///
/// * `manifest_bytes` — the byte-for-byte content that was signed (NOT a parsed
///   model; the signature covers raw bytes).
/// * `sig` — the full contents of the detached signature file.
/// * `pubkey` — the publisher minisign public key (`RW...` base64 form).
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
