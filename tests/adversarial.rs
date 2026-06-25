//! Cross-cutting adversarial integration suite (brief §10), exercising the real
//! `oip-core` public API on real zipped `.oip` bytes — the same bytes and code
//! path `src-tauri` uses. Every case here is a "fail closed" assertion: a bad
//! package must be REFUSED, never partially trusted.

mod common;

use common::*;
use oip_core::{evaluate_trust, parse_manifest, verify_manifest_sig, verify_payload};
use oip_core::{OipError, PinnedKey, TrustLevel};

const ID: &str = "com.example.coolapp";
const PAYLOAD: &[u8] = b"MZ\x90\x00 fake but stable installer payload bytes \x01\x02\x03";

fn pin(id: &str, key: &str) -> PinnedKey {
    PinnedKey {
        id: id.to_string(),
        public_key: key.to_string(),
        first_seen: None,
    }
}

#[test]
fn good_package_passes_the_whole_chain() {
    let (oip, signer_pub, _kp) = good_package(ID, PAYLOAD);
    let pkg = Extracted::open(&oip);

    let manifest = parse_manifest(pkg.manifest()).expect("manifest parses");
    let key = manifest.publisher_key.as_ref().expect("has key");
    assert_eq!(key.public_key, signer_pub);

    // Signature verifies over the exact manifest bytes.
    verify_manifest_sig(pkg.manifest(), pkg.sig().unwrap(), &key.public_key)
        .expect("signature verifies");

    // Payload hashes match.
    verify_payload(pkg.payload(&manifest.payload.file), &manifest).expect("payload verifies");

    // First use (no pin) => VerifiedNewPublisher; matching pin => Verified.
    assert_eq!(
        evaluate_trust(&manifest, None),
        TrustLevel::VerifiedNewPublisher
    );
    assert_eq!(
        evaluate_trust(&manifest, Some(&pin(ID, &signer_pub))),
        TrustLevel::Verified
    );
}

#[test]
fn flipped_payload_byte_is_refused() {
    let (oip, _pub, _kp) = good_package(ID, PAYLOAD);
    let pkg = Extracted::open(&oip);
    let manifest = parse_manifest(pkg.manifest()).unwrap();

    let mut payload = pkg.payload(&manifest.payload.file).to_vec();
    payload[3] ^= 0xFF; // a single bit/byte flip

    let err = verify_payload(&payload, &manifest).expect_err("must refuse");
    assert!(matches!(err, OipError::Blake3Mismatch), "got {err:?}");
}

#[test]
fn manifest_edited_after_signing_is_refused() {
    let (oip, signer_pub, _kp) = good_package(ID, PAYLOAD);
    let pkg = Extracted::open(&oip);

    // Tamper the signed bytes (e.g. attacker swaps the publisher name).
    let original = String::from_utf8(pkg.manifest().to_vec()).unwrap();
    let tampered = original.replace("Example Dev", "Evil Corp");
    assert_ne!(original, tampered);

    let err = verify_manifest_sig(tampered.as_bytes(), pkg.sig().unwrap(), &signer_pub)
        .expect_err("edited manifest must fail signature verification");
    assert!(matches!(err, OipError::SignatureInvalid), "got {err:?}");
}

#[test]
fn wrong_key_for_pinned_id_is_publisher_changed() {
    // Package is validly signed with key B and embeds key B...
    let (oip, key_b, _kp_b) = good_package(ID, PAYLOAD);
    let pkg = Extracted::open(&oip);
    let manifest = parse_manifest(pkg.manifest()).unwrap();

    // ...its own signature verifies against the embedded (B) key.
    verify_manifest_sig(pkg.manifest(), pkg.sig().unwrap(), &key_b).expect("B verifies");

    // But this id was previously pinned to a DIFFERENT key A.
    let key_a = keypair().pk.to_base64();
    assert_ne!(key_a, key_b);

    // TOFU must flag this as a publisher change — never a silent install (#3).
    assert_eq!(
        evaluate_trust(&manifest, Some(&pin(ID, &key_a))),
        TrustLevel::PublisherChanged
    );

    // And the signature does NOT verify against the pinned key A — proving the
    // mismatch is real, not a coincidence.
    let err = verify_manifest_sig(pkg.manifest(), pkg.sig().unwrap(), &key_a)
        .expect_err("must not verify against the wrong key");
    assert!(matches!(err, OipError::SignatureInvalid), "got {err:?}");
}

#[test]
fn unsigned_package_is_unverified_and_never_verified() {
    let oip = unsigned_package("com.example.unsigned", PAYLOAD);
    let pkg = Extracted::open(&oip);

    let manifest = parse_manifest(pkg.manifest()).expect("unsigned manifest still parses");
    assert!(manifest.publisher_key.is_none());
    assert!(pkg.sig().is_none(), "unsigned package has no signature");

    // Payload hashes still verify (integrity), but trust can NEVER be verified.
    verify_payload(pkg.payload(&manifest.payload.file), &manifest).expect("payload verifies");
    assert_eq!(evaluate_trust(&manifest, None), TrustLevel::Unverified);

    // Even if some (irrelevant) pin existed, an unsigned manifest stays Unverified.
    let bogus = pin("com.example.unsigned", "RWanything");
    assert_eq!(
        evaluate_trust(&manifest, Some(&bogus)),
        TrustLevel::Unverified
    );
}

#[test]
fn malformed_manifests_fail_closed() {
    let kp = keypair();
    let pk = kp.pk.to_base64();

    // schema != 1
    let m = manifest_for(ID, PAYLOAD, Some(&pk)).replace("schema = 1", "schema = 2");
    assert!(matches!(
        parse_manifest(m.as_bytes()),
        Err(OipError::UnsupportedSchema(2))
    ));

    // bad hash hex (truncated)
    let (b3, _sha) = hashes(PAYLOAD);
    let m = manifest_for(ID, PAYLOAD, Some(&pk)).replace(&b3, "deadbeef");
    assert!(matches!(
        parse_manifest(m.as_bytes()),
        Err(OipError::InvalidField { .. })
    ));

    // non reverse-DNS id
    let m = manifest_for("notreversedns", PAYLOAD, Some(&pk));
    assert!(matches!(
        parse_manifest(m.as_bytes()),
        Err(OipError::InvalidField { .. })
    ));

    // missing required field (drop the name line)
    let m = manifest_for(ID, PAYLOAD, Some(&pk)).replace("name = \"CoolApp\"\n", "");
    assert!(parse_manifest(m.as_bytes()).is_err());

    // not even valid TOML
    assert!(matches!(
        parse_manifest(b"this is not toml = = ="),
        Err(OipError::ManifestParse(_))
    ));
}

#[test]
fn signature_required_when_key_present_is_enforced_by_caller() {
    // A manifest that declares a key but ships no signature is a packaging error;
    // oip-core has no signature to check, and the caller (src-tauri) must treat a
    // missing manifest.minisig as fail-closed. Here we assert the building block:
    // an empty/garbage signature does not verify.
    let (oip, signer_pub, _kp) = good_package(ID, PAYLOAD);
    let pkg = Extracted::open(&oip);
    assert!(verify_manifest_sig(pkg.manifest(), b"", &signer_pub).is_err());
    assert!(verify_manifest_sig(pkg.manifest(), b"not a minisig", &signer_pub).is_err());
}
