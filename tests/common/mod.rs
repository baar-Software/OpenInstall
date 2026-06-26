//! Shared helpers for the adversarial integration suite: build real native `.oip`
//! (zip) bytes BY HAND — a minisign signature over `manifest.json` plus
//! sha256-pinned files — independently of `oip-pack`'s builder, so the verifier is
//! exercised against builder-independent inputs.
//!
//! Everything here is hermetic: keys and signatures are minted in-process, no
//! network, no `%APPDATA%`.

#![allow(dead_code)]

use std::io::{Cursor, Write};

use minisign::KeyPair;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

pub const ENTRY: &str = "CoolApp.exe";
pub const MANIFEST_NAME: &str = "manifest.json";
pub const SIG_NAME: &str = "signatures/publisher.ed25519.sig";

/// Generate a fresh unencrypted minisign keypair.
pub fn keypair() -> KeyPair {
    KeyPair::generate_unencrypted_keypair().expect("keygen")
}

/// Sign `bytes`, returning the detached `.minisig` signature text bytes — exactly
/// what would live in `signatures/publisher.ed25519.sig` (prehashed default).
pub fn sign_bytes(kp: &KeyPair, bytes: &[u8]) -> Vec<u8> {
    minisign::sign(Some(&kp.pk), &kp.sk, Cursor::new(bytes), None, None)
        .expect("sign")
        .to_string()
        .into_bytes()
}

/// Lowercase SHA-256 hex of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Build a native `manifest.json` string pinning the single entry file by sha256
/// and embedding `key_b64` as the publisher key (`minisign:<key>`).
pub fn manifest_json(id: &str, payload: &[u8], key_b64: &str) -> String {
    format!(
        "{{\n  \"schema\": 1,\n  \"id\": \"{id}\",\n  \"name\": \"CoolApp\",\n  \"version\": \"1.4.2\",\n  \"publisher\": {{ \"name\": \"Example Dev\", \"key\": \"minisign:{key}\", \"website\": \"https://coolapp.dev\" }},\n  \"entry\": \"{ENTRY}\",\n  \"installMode\": \"perUser\",\n  \"requiresAdmin\": false,\n  \"files\": [ {{ \"path\": \"{ENTRY}\", \"sha256\": \"{sha}\" }} ],\n  \"permissions\": {{ \"network\": false, \"autostart\": false, \"registry\": false, \"services\": false, \"drivers\": false, \"shellExtensions\": false }},\n  \"shortcuts\": [ {{ \"name\": \"CoolApp\", \"target\": \"{ENTRY}\" }} ]\n}}\n",
        key = key_b64,
        sha = sha256_hex(payload),
    )
}

/// Assemble a native `.oip` zip from parts. `sig = None` => omit the signature.
pub fn zip_native(manifest: &[u8], sig: Option<&[u8]>, entry_bytes: &[u8]) -> Vec<u8> {
    let mut zw = zip::ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zw.start_file(MANIFEST_NAME, opts).unwrap();
    zw.write_all(manifest).unwrap();
    if let Some(sig) = sig {
        zw.start_file(SIG_NAME, opts).unwrap();
        zw.write_all(sig).unwrap();
    }
    zw.start_file(format!("files/{ENTRY}"), opts).unwrap();
    zw.write_all(entry_bytes).unwrap();
    zw.finish().unwrap().into_inner()
}

/// A valid, signed native package. Returns (oip_bytes, signer_pubkey_b64, keypair).
pub fn good_package(id: &str, payload: &[u8]) -> (Vec<u8>, String, KeyPair) {
    let kp = keypair();
    let pk_b64 = kp.pk.to_base64();
    let manifest = manifest_json(id, payload, &pk_b64);
    let sig = sign_bytes(&kp, manifest.as_bytes());
    let oip = zip_native(manifest.as_bytes(), Some(&sig), payload);
    (oip, pk_b64, kp)
}
