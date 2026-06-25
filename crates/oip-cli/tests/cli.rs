//! End-to-end tests for `oip-cli`: keygen → build → sign, then verify the
//! resulting `.oip` through the real `oip-core` client path. Also asserts the
//! adversarial cases (payload byte flip, manifest edit after signing) are
//! refused — fail closed (brief §1.2, §10).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_oip-cli")
}

fn run(args: &[&std::ffi::OsStr]) -> std::process::Output {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn oip-cli");
    if !out.status.success() {
        panic!(
            "oip-cli {:?} failed:\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out
}

fn read_entry(oip: &Path, name: &str) -> Option<Vec<u8>> {
    let bytes = std::fs::read(oip).unwrap();
    let mut a = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    for i in 0..a.len() {
        let mut f = a.by_index(i).unwrap();
        if f.name() == name {
            let mut v = Vec::new();
            f.read_to_end(&mut v).unwrap();
            return Some(v);
        }
    }
    None
}

/// Build a fully signed package in a temp dir and return (dir, oip_path).
fn make_signed_package() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let os = |s: &str| std::ffi::OsString::from(s);

    let key_prefix = dir.path().join("testkey");
    let pub_path = dir.path().join("testkey.pub");
    let payload = dir.path().join("Setup.exe");
    let oip = dir.path().join("app-1.0.0.oip");

    std::fs::write(&payload, b"MZ fake installer bytes \x00\x01\x02 hello").unwrap();

    // keygen (unencrypted for an unattended test)
    run(&[
        os("keygen").as_os_str(),
        os("--out").as_os_str(),
        key_prefix.as_os_str(),
    ]);
    assert!(pub_path.exists(), "keygen should write a .pub");

    // build (embeds the public key)
    run(&[
        os("build").as_os_str(),
        os("--payload").as_os_str(),
        payload.as_os_str(),
        os("--out").as_os_str(),
        oip.as_os_str(),
        os("--id").as_os_str(),
        os("com.example.coolapp").as_os_str(),
        os("--name").as_os_str(),
        os("CoolApp").as_os_str(),
        os("--publisher").as_os_str(),
        os("Example Dev").as_os_str(),
        os("--version").as_os_str(),
        os("1.0.0").as_os_str(),
        os("--silent-args").as_os_str(),
        os("/S").as_os_str(),
        os("--public-key").as_os_str(),
        pub_path.as_os_str(),
    ]);

    // sign
    run(&[
        os("sign").as_os_str(),
        os("--package").as_os_str(),
        oip.as_os_str(),
        os("--secret-key").as_os_str(),
        dir.path().join("testkey.key").as_os_str(),
    ]);

    (dir, oip)
}

#[test]
fn build_sign_roundtrips_through_oip_core() {
    let (_dir, oip) = make_signed_package();

    let manifest_bytes = read_entry(&oip, "manifest.toml").expect("manifest.toml present");
    let sig = read_entry(&oip, "manifest.minisig").expect("manifest.minisig present");

    let manifest = oip_core::parse_manifest(&manifest_bytes).expect("manifest parses");
    let key = manifest.publisher_key.as_ref().expect("has publisher key");

    // Signature verifies against the embedded key.
    oip_core::verify_manifest_sig(&manifest_bytes, &sig, &key.public_key)
        .expect("signature verifies");

    // Payload hashes match.
    let payload = read_entry(&oip, &manifest.payload.file).expect("payload present");
    oip_core::verify_payload(&payload, &manifest).expect("payload verifies");

    // First-use trust (no pin) is VerifiedNewPublisher.
    assert_eq!(
        oip_core::evaluate_trust(&manifest, None),
        oip_core::TrustLevel::VerifiedNewPublisher
    );
}

#[test]
fn flipped_payload_byte_is_refused() {
    let (_dir, oip) = make_signed_package();
    let manifest_bytes = read_entry(&oip, "manifest.toml").unwrap();
    let manifest = oip_core::parse_manifest(&manifest_bytes).unwrap();
    let mut payload = read_entry(&oip, &manifest.payload.file).unwrap();

    payload[0] ^= 0xFF; // flip a byte

    let err =
        oip_core::verify_payload(&payload, &manifest).expect_err("flipped payload must be refused");
    assert!(matches!(err, oip_core::OipError::Blake3Mismatch));
}

#[test]
fn manifest_edited_after_signing_is_refused() {
    let (_dir, oip) = make_signed_package();
    let manifest_bytes = read_entry(&oip, "manifest.toml").unwrap();
    let sig = read_entry(&oip, "manifest.minisig").unwrap();
    let manifest = oip_core::parse_manifest(&manifest_bytes).unwrap();
    let key = manifest.publisher_key.as_ref().unwrap();

    // Tamper the signed bytes.
    let mut tampered = manifest_bytes.clone();
    tampered.extend_from_slice(b"\n# sneaky trailing comment\n");

    let err = oip_core::verify_manifest_sig(&tampered, &sig, &key.public_key)
        .expect_err("edited manifest must fail signature verification");
    assert!(matches!(err, oip_core::OipError::SignatureInvalid));
}

#[test]
fn verify_subcommand_succeeds_on_good_package() {
    let (_dir, oip) = make_signed_package();
    // The `verify` subcommand must exit 0 for a good package.
    run(&[
        std::ffi::OsString::from("verify").as_os_str(),
        std::ffi::OsString::from("--package").as_os_str(),
        oip.as_os_str(),
    ]);
}

#[test]
fn unsigned_build_is_unverified() {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("Setup.exe");
    let oip = dir.path().join("unsigned.oip");
    std::fs::write(&payload, b"dummy payload").unwrap();

    let os = |s: &str| std::ffi::OsString::from(s);
    // build WITHOUT --public-key => unsigned, degraded.
    run(&[
        os("build").as_os_str(),
        os("--payload").as_os_str(),
        payload.as_os_str(),
        os("--out").as_os_str(),
        oip.as_os_str(),
        os("--id").as_os_str(),
        os("com.example.unsigned").as_os_str(),
        os("--name").as_os_str(),
        os("NoKey").as_os_str(),
        os("--publisher").as_os_str(),
        os("Anon").as_os_str(),
        os("--version").as_os_str(),
        os("0.1.0").as_os_str(),
    ]);

    let manifest_bytes = read_entry(&oip, "manifest.toml").unwrap();
    let manifest = oip_core::parse_manifest(&manifest_bytes).unwrap();
    assert!(manifest.publisher_key.is_none());
    assert!(read_entry(&oip, "manifest.minisig").is_none());
    assert_eq!(
        oip_core::evaluate_trust(&manifest, None),
        oip_core::TrustLevel::Unverified
    );
}
