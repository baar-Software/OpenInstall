//! Public-API tests for the verification core: the publisher signature check
//! (`verify_manifest_sig`) and the display fingerprint. Every signature case is a
//! "fail closed" assertion — a bad input must be REFUSED, never partially trusted.

use minisign::KeyPair;
use std::io::Cursor;

use oip_core::{key_fingerprint, verify_manifest_sig, OipError};

const MANIFEST: &[u8] = br#"{"schema":1,"id":"com.example.coolapp","name":"CoolApp"}"#;

fn keypair() -> KeyPair {
    KeyPair::generate_unencrypted_keypair().expect("keygen")
}

/// Produce the detached `.minisig` signature text bytes for `bytes`.
fn sign(kp: &KeyPair, bytes: &[u8]) -> Vec<u8> {
    minisign::sign(Some(&kp.pk), &kp.sk, Cursor::new(bytes), None, None)
        .expect("sign")
        .to_string()
        .into_bytes()
}

#[test]
fn valid_signature_verifies() {
    let kp = keypair();
    let sig = sign(&kp, MANIFEST);
    verify_manifest_sig(MANIFEST, &sig, &kp.pk.to_base64()).expect("signature verifies");
}

#[test]
fn tampered_manifest_is_refused() {
    let kp = keypair();
    let sig = sign(&kp, MANIFEST);
    let mut tampered = MANIFEST.to_vec();
    tampered[10] ^= 0xFF;
    let err = verify_manifest_sig(&tampered, &sig, &kp.pk.to_base64())
        .expect_err("tampered manifest must fail");
    assert!(matches!(err, OipError::SignatureInvalid), "got {err:?}");
}

#[test]
fn wrong_key_is_refused() {
    let kp = keypair();
    let other = keypair();
    let sig = sign(&kp, MANIFEST);
    let err = verify_manifest_sig(MANIFEST, &sig, &other.pk.to_base64())
        .expect_err("wrong key must fail");
    assert!(matches!(err, OipError::SignatureInvalid), "got {err:?}");
}

#[test]
fn malformed_signature_and_key_are_refused() {
    let kp = keypair();
    assert!(verify_manifest_sig(MANIFEST, b"", &kp.pk.to_base64()).is_err());
    assert!(verify_manifest_sig(MANIFEST, b"not a minisig", &kp.pk.to_base64()).is_err());
    let sig = sign(&kp, MANIFEST);
    assert!(matches!(
        verify_manifest_sig(MANIFEST, &sig, ""),
        Err(OipError::MalformedPublicKey(_))
    ));
    assert!(matches!(
        verify_manifest_sig(MANIFEST, &sig, "not-a-key"),
        Err(OipError::MalformedPublicKey(_))
    ));
}

#[test]
fn full_pub_file_text_is_accepted_as_key() {
    let kp = keypair();
    let sig = sign(&kp, MANIFEST);
    let pub_file = kp.pk.to_box().unwrap().to_string(); // comment line + key line
    verify_manifest_sig(MANIFEST, &sig, &pub_file).expect("two-line .pub key is accepted");
}

#[test]
fn fingerprint_is_a_stable_display_prefix() {
    let key = "RWQf6LRCGA9i53mlYecO4IzT51TGPo7wuoZtiAi4QrJX2vKt0o0bdaff";
    assert_eq!(key_fingerprint(key), "RWQf6LRCGA…");
    assert_eq!(key_fingerprint("RWshort"), "RWshort");
}
