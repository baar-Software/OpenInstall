//! Cross-cutting adversarial integration suite (brief §10), exercising the real
//! native-package verifier (`oip_pack::verify_native_oip_bytes`) and the signature
//! kernel (`oip_core::verify_manifest_sig`) on real zipped `.oip` bytes that are
//! assembled BY HAND (independently of the package builder). Every case here is a
//! "fail closed" assertion: a bad package must be REFUSED, never partially trusted.

mod common;

use common::*;
use oip_core::{verify_manifest_sig, OipError, TrustLevel};
use oip_pack::verify_native_oip_bytes;

const ID: &str = "com.example.coolapp";
const PAYLOAD: &[u8] = b"MZ\x90\x00 fake but stable app payload bytes \x01\x02\x03";

#[test]
fn good_native_package_passes_the_whole_chain() {
    let (oip, signer_pub, _kp) = good_package(ID, PAYLOAD);
    let report = verify_native_oip_bytes(&oip).expect("good native package verifies");
    assert_eq!(report.id, ID);
    assert!(report.signed);
    assert_eq!(report.trust, TrustLevel::VerifiedNewPublisher);
    assert_eq!(
        report.key_fingerprint.unwrap(),
        oip_core::key_fingerprint(&signer_pub)
    );
}

#[test]
fn flipped_file_byte_is_refused() {
    // Manifest pins sha256(PAYLOAD) and is validly signed, but the archived file
    // bytes differ — the per-file hash check must refuse it.
    let kp = keypair();
    let pk = kp.pk.to_base64();
    let manifest = manifest_json(ID, PAYLOAD, &pk);
    let sig = sign_bytes(&kp, manifest.as_bytes());
    let mut tampered = PAYLOAD.to_vec();
    tampered[3] ^= 0xFF; // a single byte flip
    let oip = zip_native(manifest.as_bytes(), Some(&sig), &tampered);

    let err = verify_native_oip_bytes(&oip).expect_err("must refuse");
    assert!(err.to_string().contains("SHA-256"), "got: {err}");
}

#[test]
fn manifest_edited_after_signing_is_refused() {
    let kp = keypair();
    let pk = kp.pk.to_base64();
    let manifest = manifest_json(ID, PAYLOAD, &pk);
    let sig = sign_bytes(&kp, manifest.as_bytes());
    // Attacker edits the signed manifest (e.g. swaps the publisher name).
    let tampered = manifest.replace("Example Dev", "Evil Corp");
    assert_ne!(manifest, tampered);
    let oip = zip_native(tampered.as_bytes(), Some(&sig), PAYLOAD);

    assert!(
        verify_native_oip_bytes(&oip).is_err(),
        "an edited-after-signing manifest must fail verification"
    );
}

#[test]
fn wrong_signing_key_is_refused() {
    // Manifest embeds key A but is signed with key B — the signature must not
    // verify against the embedded key.
    let kp_a = keypair();
    let kp_b = keypair();
    let pk_a = kp_a.pk.to_base64();
    let manifest = manifest_json(ID, PAYLOAD, &pk_a);
    let sig = sign_bytes(&kp_b, manifest.as_bytes());
    let oip = zip_native(manifest.as_bytes(), Some(&sig), PAYLOAD);

    assert!(verify_native_oip_bytes(&oip).is_err());

    // The byte-level signature check agrees: B's signature does not verify under A.
    assert!(matches!(
        verify_manifest_sig(manifest.as_bytes(), &sig, &pk_a),
        Err(OipError::SignatureInvalid)
    ));
}

#[test]
fn missing_signature_is_refused() {
    let kp = keypair();
    let pk = kp.pk.to_base64();
    let manifest = manifest_json(ID, PAYLOAD, &pk);
    let oip = zip_native(manifest.as_bytes(), None, PAYLOAD); // no signature entry

    assert!(
        verify_native_oip_bytes(&oip).is_err(),
        "a package with no publisher signature must be refused"
    );
}

#[test]
fn malformed_manifest_json_is_refused() {
    let kp = keypair();
    let garbage = b"{ this is not valid manifest json";
    let sig = sign_bytes(&kp, garbage); // even a valid signature over garbage
    let oip = zip_native(garbage, Some(&sig), PAYLOAD);

    assert!(verify_native_oip_bytes(&oip).is_err());
}

#[test]
fn empty_and_garbage_signatures_do_not_verify() {
    let (_oip, signer_pub, _kp) = good_package(ID, PAYLOAD);
    let manifest = manifest_json(ID, PAYLOAD, &signer_pub);
    assert!(verify_manifest_sig(manifest.as_bytes(), b"", &signer_pub).is_err());
    assert!(verify_manifest_sig(manifest.as_bytes(), b"not a minisig", &signer_pub).is_err());
}
