//! End-to-end unit tests for the `oip-core` verification kernel.
//!
//! These exercise the four §7-contract functions plus `key_fingerprint`,
//! including the fail-closed (brief §1.2) and TOFU (brief §1.3) behaviour. Real
//! minisign keys and signatures are minted at test time with the `minisign`
//! dev-dependency and verified through the production `minisign-verify` path, so
//! the crypto round-trip is genuinely exercised (not mocked).

use std::io::Cursor;

use minisign::{KeyPair, SignatureBox};

use oip_core::{
    evaluate_trust, key_fingerprint, parse_manifest, verify_manifest_sig, verify_payload, Manifest,
    OipError, PinnedKey, PublisherKey, TrustLevel,
};

// ---------------------------------------------------------------------------
// Fixtures / helpers
// ---------------------------------------------------------------------------

/// A real payload whose hashes we pin in the test manifests.
const PAYLOAD: &[u8] = b"this is a fake Setup.exe payload for testing\x00\x01\x02";

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Build a syntactically valid signed manifest TOML for `PAYLOAD`, embedding the
/// given public key (the `RW...` base64 form).
fn signed_manifest_toml(public_key_b64: &str) -> String {
    format!(
        r#"schema = 1
id = "com.example.coolapp"
name = "Cool App"
publisher = "Example Inc"
version = "1.2.3"
homepage = "https://example.com"

[payload]
file = "payload/Setup.exe"
type = "exe"
hash_blake3 = "{b3}"
hash_sha256 = "{s256}"
silent_args = "/S"

[publisher_key]
type = "minisign"
public_key = "{pk}"
"#,
        b3 = blake3_hex(PAYLOAD),
        s256 = sha256_hex(PAYLOAD),
        pk = public_key_b64,
    )
}

/// An unsigned (no `[publisher_key]`) but otherwise valid manifest TOML.
fn unsigned_manifest_toml() -> String {
    format!(
        r#"schema = 1
id = "com.example.coolapp"
name = "Cool App"
publisher = "Example Inc"
version = "1.2.3"

[payload]
file = "payload/Setup.exe"
type = "msi"
hash_blake3 = "{b3}"
hash_sha256 = "{s256}"
"#,
        b3 = blake3_hex(PAYLOAD),
        s256 = sha256_hex(PAYLOAD),
    )
}

/// Generate a fresh unencrypted minisign keypair for tests.
fn keypair() -> KeyPair {
    KeyPair::generate_unencrypted_keypair().expect("keygen")
}

/// Sign `bytes` with `kp` and return the `.minisig` detached signature text bytes.
fn sign(kp: &KeyPair, bytes: &[u8]) -> Vec<u8> {
    let sig_box: SignatureBox =
        minisign::sign(Some(&kp.pk), &kp.sk, Cursor::new(bytes), None, None).expect("sign");
    sig_box.to_string().into_bytes()
}

// ---------------------------------------------------------------------------
// parse_manifest — happy paths
// ---------------------------------------------------------------------------

#[test]
fn parses_valid_signed_manifest() {
    let kp = keypair();
    let toml = signed_manifest_toml(&kp.pk.to_base64());
    let m = parse_manifest(toml.as_bytes()).expect("should parse");
    assert_eq!(m.schema, 1);
    assert_eq!(m.id, "com.example.coolapp");
    assert_eq!(m.name, "Cool App");
    assert_eq!(m.publisher, "Example Inc");
    assert_eq!(m.version, "1.2.3");
    assert_eq!(m.homepage, "https://example.com");
    assert_eq!(m.payload.file, "payload/Setup.exe");
    assert_eq!(m.payload.silent_args, "/S");
    assert!(m.is_signed());
    assert_eq!(
        m.publisher_key.as_ref().unwrap().public_key,
        kp.pk.to_base64()
    );
}

#[test]
fn parses_valid_unsigned_manifest() {
    let toml = unsigned_manifest_toml();
    let m = parse_manifest(toml.as_bytes()).expect("should parse");
    assert!(!m.is_signed());
    assert!(m.publisher_key.is_none());
    // Optional fields default sanely.
    assert_eq!(m.homepage, "");
    assert_eq!(m.payload.silent_args, "");
}

// ---------------------------------------------------------------------------
// parse_manifest — fail closed
// ---------------------------------------------------------------------------

#[test]
fn rejects_non_utf8() {
    let bytes = [0xff, 0xfe, 0x00, 0x80];
    match parse_manifest(&bytes) {
        Err(OipError::ManifestEncoding(_)) => {}
        other => panic!("expected ManifestEncoding, got {other:?}"),
    }
}

#[test]
fn rejects_malformed_toml() {
    let bytes = b"this is = = not valid toml [[[";
    match parse_manifest(bytes) {
        Err(OipError::ManifestParse(_)) => {}
        other => panic!("expected ManifestParse, got {other:?}"),
    }
}

#[test]
fn rejects_wrong_schema() {
    let toml = unsigned_manifest_toml().replace("schema = 1", "schema = 2");
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::UnsupportedSchema(2)) => {}
        other => panic!("expected UnsupportedSchema(2), got {other:?}"),
    }
}

#[test]
fn rejects_schema_zero() {
    let toml = unsigned_manifest_toml().replace("schema = 1", "schema = 0");
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::UnsupportedSchema(0)) => {}
        other => panic!("expected UnsupportedSchema(0), got {other:?}"),
    }
}

#[test]
fn rejects_missing_structural_field() {
    // Remove the entire [payload] table -> serde-level parse failure.
    let toml = r#"schema = 1
id = "com.example.app"
name = "App"
publisher = "Pub"
version = "1.0"
"#;
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::ManifestParse(_)) => {}
        other => panic!("expected ManifestParse (missing payload), got {other:?}"),
    }
}

#[test]
fn rejects_empty_id() {
    let toml = unsigned_manifest_toml().replace(r#"id = "com.example.coolapp""#, r#"id = """#);
    match parse_manifest(toml.as_bytes()) {
        // Empty id fails reverse-DNS check first; both are acceptable fail-closed
        // outcomes, but we expect the MissingField guard to fire on emptiness.
        Err(OipError::MissingField("id")) => {}
        other => panic!("expected MissingField(id), got {other:?}"),
    }
}

#[test]
fn rejects_whitespace_only_name() {
    let toml = unsigned_manifest_toml().replace(r#"name = "Cool App""#, r#"name = "   ""#);
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::MissingField("name")) => {}
        other => panic!("expected MissingField(name), got {other:?}"),
    }
}

#[test]
fn rejects_empty_publisher() {
    let toml =
        unsigned_manifest_toml().replace(r#"publisher = "Example Inc""#, r#"publisher = """#);
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::MissingField("publisher")) => {}
        other => panic!("expected MissingField(publisher), got {other:?}"),
    }
}

#[test]
fn rejects_empty_version() {
    let toml = unsigned_manifest_toml().replace(r#"version = "1.2.3""#, r#"version = """#);
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::MissingField("version")) => {}
        other => panic!("expected MissingField(version), got {other:?}"),
    }
}

#[test]
fn rejects_empty_payload_file() {
    let toml = unsigned_manifest_toml().replace(r#"file = "payload/Setup.exe""#, r#"file = """#);
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::MissingField("payload.file")) => {}
        other => panic!("expected MissingField(payload.file), got {other:?}"),
    }
}

#[test]
fn rejects_id_with_single_label() {
    let toml =
        unsigned_manifest_toml().replace(r#"id = "com.example.coolapp""#, r#"id = "coolapp""#);
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::InvalidField { field: "id", .. }) => {}
        other => panic!("expected InvalidField(id), got {other:?}"),
    }
}

#[test]
fn rejects_id_with_empty_label() {
    let toml =
        unsigned_manifest_toml().replace(r#"id = "com.example.coolapp""#, r#"id = "com..coolapp""#);
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::InvalidField { field: "id", .. }) => {}
        other => panic!("expected InvalidField(id), got {other:?}"),
    }
}

#[test]
fn rejects_id_with_illegal_chars() {
    let toml = unsigned_manifest_toml().replace(
        r#"id = "com.example.coolapp""#,
        r#"id = "com.exa mple.app!""#,
    );
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::InvalidField { field: "id", .. }) => {}
        other => panic!("expected InvalidField(id), got {other:?}"),
    }
}

#[test]
fn accepts_id_with_hyphen_and_digits() {
    let toml = unsigned_manifest_toml()
        .replace(r#"id = "com.example.coolapp""#, r#"id = "io.my-org.app2""#);
    let m = parse_manifest(toml.as_bytes()).expect("hyphen/digit id should parse");
    assert_eq!(m.id, "io.my-org.app2");
}

#[test]
fn rejects_short_blake3() {
    let toml = unsigned_manifest_toml().replace(&blake3_hex(PAYLOAD), "abc123");
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::InvalidField {
            field: "payload.hash_blake3",
            ..
        }) => {}
        other => panic!("expected InvalidField(payload.hash_blake3), got {other:?}"),
    }
}

#[test]
fn rejects_uppercase_blake3() {
    let upper = blake3_hex(PAYLOAD).to_uppercase();
    let toml = unsigned_manifest_toml().replace(&blake3_hex(PAYLOAD), &upper);
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::InvalidField {
            field: "payload.hash_blake3",
            ..
        }) => {}
        other => panic!("expected InvalidField(payload.hash_blake3) for uppercase, got {other:?}"),
    }
}

#[test]
fn rejects_non_hex_sha256() {
    // 64 chars but with non-hex characters (z, g).
    let bad = "z".repeat(64);
    let toml = unsigned_manifest_toml().replace(&sha256_hex(PAYLOAD), &bad);
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::InvalidField {
            field: "payload.hash_sha256",
            ..
        }) => {}
        other => panic!("expected InvalidField(payload.hash_sha256), got {other:?}"),
    }
}

#[test]
fn rejects_unknown_payload_type() {
    let toml = unsigned_manifest_toml().replace(r#"type = "msi""#, r#"type = "bat""#);
    // serde enum decode fails -> ManifestParse (fail closed either way).
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::ManifestParse(_)) => {}
        other => panic!("expected ManifestParse for bad payload type, got {other:?}"),
    }
}

#[test]
fn rejects_publisher_key_wrong_type() {
    let kp = keypair();
    let toml =
        signed_manifest_toml(&kp.pk.to_base64()).replace(r#"type = "minisign""#, r#"type = "pgp""#);
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::InvalidField {
            field: "publisher_key.type",
            ..
        }) => {}
        other => panic!("expected InvalidField(publisher_key.type), got {other:?}"),
    }
}

#[test]
fn rejects_publisher_key_empty_public_key() {
    let toml = signed_manifest_toml("");
    match parse_manifest(toml.as_bytes()) {
        Err(OipError::MissingField("publisher_key.public_key")) => {}
        other => panic!("expected MissingField(publisher_key.public_key), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// verify_manifest_sig
// ---------------------------------------------------------------------------

#[test]
fn good_signature_verifies() {
    let kp = keypair();
    let manifest_bytes = signed_manifest_toml(&kp.pk.to_base64());
    let sig = sign(&kp, manifest_bytes.as_bytes());
    verify_manifest_sig(manifest_bytes.as_bytes(), &sig, &kp.pk.to_base64())
        .expect("valid signature should verify");
}

#[test]
fn tampered_manifest_fails_signature() {
    let kp = keypair();
    let manifest_bytes = signed_manifest_toml(&kp.pk.to_base64());
    let sig = sign(&kp, manifest_bytes.as_bytes());

    // Flip one byte of the signed content.
    let mut tampered = manifest_bytes.clone().into_bytes();
    tampered[0] ^= 0x01;

    match verify_manifest_sig(&tampered, &sig, &kp.pk.to_base64()) {
        Err(OipError::SignatureInvalid) => {}
        other => panic!("expected SignatureInvalid for tampered manifest, got {other:?}"),
    }
}

#[test]
fn wrong_key_fails_signature() {
    let signer = keypair();
    let attacker = keypair();
    let manifest_bytes = signed_manifest_toml(&signer.pk.to_base64());
    let sig = sign(&signer, manifest_bytes.as_bytes());

    // Verify against a DIFFERENT public key than the one that signed it.
    match verify_manifest_sig(manifest_bytes.as_bytes(), &sig, &attacker.pk.to_base64()) {
        Err(OipError::SignatureInvalid) => {}
        other => panic!("expected SignatureInvalid for wrong key, got {other:?}"),
    }
}

#[test]
fn malformed_public_key_is_rejected() {
    let kp = keypair();
    let manifest_bytes = signed_manifest_toml(&kp.pk.to_base64());
    let sig = sign(&kp, manifest_bytes.as_bytes());
    match verify_manifest_sig(manifest_bytes.as_bytes(), &sig, "not-a-real-key") {
        Err(OipError::MalformedPublicKey(_)) => {}
        other => panic!("expected MalformedPublicKey, got {other:?}"),
    }
}

#[test]
fn empty_public_key_is_rejected() {
    match verify_manifest_sig(b"x", b"y", "   ") {
        Err(OipError::MalformedPublicKey(_)) => {}
        other => panic!("expected MalformedPublicKey for empty key, got {other:?}"),
    }
}

#[test]
fn malformed_signature_is_rejected() {
    let kp = keypair();
    let manifest_bytes = signed_manifest_toml(&kp.pk.to_base64());
    match verify_manifest_sig(
        manifest_bytes.as_bytes(),
        b"garbage not a minisig",
        &kp.pk.to_base64(),
    ) {
        Err(OipError::MalformedSignature(_)) => {}
        other => panic!("expected MalformedSignature, got {other:?}"),
    }
}

#[test]
fn non_utf8_signature_is_rejected() {
    let kp = keypair();
    let manifest_bytes = signed_manifest_toml(&kp.pk.to_base64());
    let bad_sig = [0xff, 0xff, 0xff];
    match verify_manifest_sig(manifest_bytes.as_bytes(), &bad_sig, &kp.pk.to_base64()) {
        Err(OipError::MalformedSignature(_)) => {}
        other => panic!("expected MalformedSignature for non-utf8 sig, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// verify_payload
// ---------------------------------------------------------------------------

fn manifest_for_payload(bytes: &[u8]) -> Manifest {
    let toml = format!(
        r#"schema = 1
id = "com.example.coolapp"
name = "Cool App"
publisher = "Example Inc"
version = "1.0"

[payload]
file = "payload/Setup.exe"
type = "exe"
hash_blake3 = "{b3}"
hash_sha256 = "{s256}"
"#,
        b3 = blake3_hex(bytes),
        s256 = sha256_hex(bytes),
    );
    parse_manifest(toml.as_bytes()).expect("manifest")
}

#[test]
fn correct_hashes_pass() {
    let m = manifest_for_payload(PAYLOAD);
    verify_payload(PAYLOAD, &m).expect("matching payload should verify");
}

#[test]
fn one_byte_flip_fails_blake3() {
    let m = manifest_for_payload(PAYLOAD);
    let mut flipped = PAYLOAD.to_vec();
    flipped[3] ^= 0x01;
    match verify_payload(&flipped, &m) {
        Err(OipError::Blake3Mismatch) => {}
        other => panic!("expected Blake3Mismatch for flipped byte, got {other:?}"),
    }
}

#[test]
fn empty_vs_nonempty_payload_fails_blake3() {
    let m = manifest_for_payload(PAYLOAD);
    match verify_payload(b"", &m) {
        Err(OipError::Blake3Mismatch) => {}
        other => panic!("expected Blake3Mismatch for empty payload, got {other:?}"),
    }
}

#[test]
fn sha256_mismatch_is_detected() {
    // Build a manifest whose BLAKE3 matches the payload but SHA-256 does not, so
    // the SHA-256 branch is exercised independently.
    let mut m = manifest_for_payload(PAYLOAD);
    m.payload.hash_sha256 = "0".repeat(64);
    match verify_payload(PAYLOAD, &m) {
        Err(OipError::Sha256Mismatch) => {}
        other => panic!("expected Sha256Mismatch, got {other:?}"),
    }
}

#[test]
fn payload_hash_compare_is_case_insensitive() {
    // verify_payload must accept an uppercase pin even though parse_manifest would
    // not have (verify_payload may be called on a Manifest built by other means).
    let mut m = manifest_for_payload(PAYLOAD);
    m.payload.hash_blake3 = m.payload.hash_blake3.to_uppercase();
    m.payload.hash_sha256 = m.payload.hash_sha256.to_uppercase();
    verify_payload(PAYLOAD, &m).expect("uppercase pins should still match");
}

// ---------------------------------------------------------------------------
// evaluate_trust — the full TOFU table
// ---------------------------------------------------------------------------

fn manifest_with_key(public_key: &str) -> Manifest {
    Manifest {
        schema: 1,
        id: "com.example.coolapp".to_string(),
        name: "Cool App".to_string(),
        publisher: "Example Inc".to_string(),
        version: "1.0".to_string(),
        homepage: String::new(),
        payload: oip_core::Payload {
            file: "payload/Setup.exe".to_string(),
            payload_type: oip_core::PayloadType::Exe,
            hash_blake3: blake3_hex(PAYLOAD),
            hash_sha256: sha256_hex(PAYLOAD),
            silent_args: String::new(),
        },
        publisher_key: Some(PublisherKey {
            key_type: "minisign".to_string(),
            public_key: public_key.to_string(),
        }),
    }
}

fn manifest_unsigned() -> Manifest {
    let mut m = manifest_with_key("ignored");
    m.publisher_key = None;
    m
}

fn pin(id: &str, public_key: &str) -> PinnedKey {
    PinnedKey {
        id: id.to_string(),
        public_key: public_key.to_string(),
        first_seen: None,
    }
}

#[test]
fn trust_unverified_when_unsigned() {
    let m = manifest_unsigned();
    assert_eq!(evaluate_trust(&m, None), TrustLevel::Unverified);
    // Even with a pin present, no key in the manifest can only be Unverified.
    assert_eq!(
        evaluate_trust(&m, Some(&pin("com.example.coolapp", "KEY"))),
        TrustLevel::Unverified
    );
}

#[test]
fn trust_new_publisher_when_no_pin() {
    let kp = keypair();
    let m = manifest_with_key(&kp.pk.to_base64());
    assert_eq!(evaluate_trust(&m, None), TrustLevel::VerifiedNewPublisher);
}

#[test]
fn trust_verified_when_key_matches_pin() {
    let kp = keypair();
    let key = kp.pk.to_base64();
    let m = manifest_with_key(&key);
    let pinned = pin("com.example.coolapp", &key);
    assert_eq!(evaluate_trust(&m, Some(&pinned)), TrustLevel::Verified);
}

#[test]
fn trust_publisher_changed_when_key_differs() {
    let signer = keypair();
    let attacker = keypair();
    let m = manifest_with_key(&signer.pk.to_base64());
    let pinned = pin("com.example.coolapp", &attacker.pk.to_base64());
    assert_eq!(
        evaluate_trust(&m, Some(&pinned)),
        TrustLevel::PublisherChanged
    );
}

#[test]
fn trust_levels_have_correct_semantics() {
    assert!(TrustLevel::Verified.is_trusted());
    assert!(TrustLevel::VerifiedNewPublisher.is_trusted());
    assert!(!TrustLevel::PublisherChanged.is_trusted());
    assert!(!TrustLevel::Unverified.is_trusted());

    assert!(TrustLevel::PublisherChanged.requires_override());
    assert!(!TrustLevel::Verified.requires_override());
    assert!(!TrustLevel::Unverified.requires_override());
}

// ---------------------------------------------------------------------------
// key_fingerprint
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_is_deterministic_and_nonempty() {
    let kp = keypair();
    let key = kp.pk.to_base64();
    let fp1 = key_fingerprint(&key);
    let fp2 = key_fingerprint(&key);
    assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    assert!(!fp1.is_empty());
    assert!(fp1.ends_with('…'), "long key should be truncated: {fp1}");
    assert!(key.starts_with(&fp1[..fp1.len() - '…'.len_utf8()]));
}

#[test]
fn fingerprint_differs_for_different_keys() {
    let a = keypair().pk.to_base64();
    let b = keypair().pk.to_base64();
    // Different keys overwhelmingly differ in their first 10 chars after the
    // shared "RW" algorithm prefix.
    assert_ne!(key_fingerprint(&a), key_fingerprint(&b));
}

#[test]
fn fingerprint_short_key_not_truncated() {
    let fp = key_fingerprint("RW");
    assert_eq!(fp, "RW");
}

// ---------------------------------------------------------------------------
// Full round trip: parse -> verify sig -> verify payload -> evaluate trust
// ---------------------------------------------------------------------------

#[test]
fn full_happy_path_round_trip() {
    let kp = keypair();
    let key = kp.pk.to_base64();
    let manifest_toml = signed_manifest_toml(&key);
    let sig = sign(&kp, manifest_toml.as_bytes());

    // 1. parse
    let m = parse_manifest(manifest_toml.as_bytes()).expect("parse");
    // 2. verify the detached signature over the EXACT manifest bytes
    verify_manifest_sig(manifest_toml.as_bytes(), &sig, &key).expect("sig");
    // 3. verify the payload hashes
    verify_payload(PAYLOAD, &m).expect("payload");
    // 4. TOFU: first install -> new publisher; second (pinned) -> verified
    assert_eq!(evaluate_trust(&m, None), TrustLevel::VerifiedNewPublisher);
    let pinned = pin(&m.id, &key);
    assert_eq!(evaluate_trust(&m, Some(&pinned)), TrustLevel::Verified);
}
