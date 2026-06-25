//! Shared helpers for the adversarial integration suite: build real `.oip`
//! (zip) bytes with `minisign` + `zip`, then read them back the way `src-tauri`
//! does, and verify with the real `oip-core` API.
//!
//! Everything here is hermetic: keys and signatures are minted in-process, no
//! network, no `%APPDATA%`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use minisign::KeyPair;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

pub const PAYLOAD_PATH: &str = "payload/Setup.exe";

/// Generate a fresh unencrypted minisign keypair.
pub fn keypair() -> KeyPair {
    KeyPair::generate_unencrypted_keypair().expect("keygen")
}

/// Sign `bytes`, returning the `.minisig` detached-signature text bytes — exactly
/// what would live in `manifest.minisig` (prehashed, the modern default).
pub fn sign_bytes(kp: &KeyPair, bytes: &[u8]) -> Vec<u8> {
    minisign::sign(Some(&kp.pk), &kp.sk, Cursor::new(bytes), None, None)
        .expect("sign")
        .to_string()
        .into_bytes()
}

/// Compute (blake3_hex, sha256_hex) of the payload, lowercase.
pub fn hashes(payload: &[u8]) -> (String, String) {
    (
        blake3::hash(payload).to_hex().to_string(),
        hex::encode(Sha256::digest(payload)),
    )
}

/// Build a manifest.toml string with correct payload hashes. `pubkey` = Some =>
/// embed a `[publisher_key]`; None => unsigned manifest.
pub fn manifest_for(id: &str, payload: &[u8], pubkey: Option<&str>) -> String {
    let (b3, sha) = hashes(payload);
    let mut s = format!(
        "schema = 1\n\
         id = \"{id}\"\n\
         name = \"CoolApp\"\n\
         publisher = \"Example Dev\"\n\
         version = \"1.4.2\"\n\
         homepage = \"https://coolapp.dev\"\n\
         \n\
         [payload]\n\
         file = \"{PAYLOAD_PATH}\"\n\
         type = \"exe\"\n\
         hash_blake3 = \"{b3}\"\n\
         hash_sha256 = \"{sha}\"\n\
         silent_args = \"/S\"\n"
    );
    if let Some(pk) = pubkey {
        s.push_str(&format!(
            "\n[publisher_key]\ntype = \"minisign\"\npublic_key = \"{pk}\"\n"
        ));
    }
    s
}

/// Assemble a `.oip` zip from parts.
pub fn zip_oip(manifest: &[u8], sig: Option<&[u8]>, payload: &[u8]) -> Vec<u8> {
    let mut zw = zip::ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zw.start_file("manifest.toml", opts).unwrap();
    zw.write_all(manifest).unwrap();
    if let Some(sig) = sig {
        zw.start_file("manifest.minisig", opts).unwrap();
        zw.write_all(sig).unwrap();
    }
    zw.start_file(PAYLOAD_PATH, opts).unwrap();
    zw.write_all(payload).unwrap();
    zw.finish().unwrap().into_inner()
}

/// A `.oip` read back from its zip bytes, the way the client backend does.
pub struct Extracted {
    pub entries: HashMap<String, Vec<u8>>,
}

impl Extracted {
    pub fn open(oip_bytes: &[u8]) -> Self {
        let mut a = zip::ZipArchive::new(Cursor::new(oip_bytes.to_vec())).expect("open zip");
        let mut entries = HashMap::new();
        for i in 0..a.len() {
            let mut f = a.by_index(i).unwrap();
            if f.is_dir() {
                continue;
            }
            let name = f.name().to_string();
            let mut data = Vec::new();
            f.read_to_end(&mut data).unwrap();
            entries.insert(name, data);
        }
        Self { entries }
    }
    pub fn manifest(&self) -> &[u8] {
        self.entries
            .get("manifest.toml")
            .expect("manifest.toml")
            .as_slice()
    }
    pub fn sig(&self) -> Option<&[u8]> {
        self.entries.get("manifest.minisig").map(|v| v.as_slice())
    }
    pub fn payload(&self, name: &str) -> &[u8] {
        self.entries.get(name).expect("payload present").as_slice()
    }
}

// ---- convenience constructors for the variants -----------------------------

/// A valid, signed package. Returns (oip_bytes, signer_pubkey_b64).
pub fn good_package(id: &str, payload: &[u8]) -> (Vec<u8>, String, KeyPair) {
    let kp = keypair();
    let pk_b64 = kp.pk.to_base64();
    let manifest = manifest_for(id, payload, Some(&pk_b64));
    let sig = sign_bytes(&kp, manifest.as_bytes());
    let oip = zip_oip(manifest.as_bytes(), Some(&sig), payload);
    (oip, pk_b64, kp)
}

/// An unsigned package (no key, no signature).
pub fn unsigned_package(id: &str, payload: &[u8]) -> Vec<u8> {
    let manifest = manifest_for(id, payload, None);
    zip_oip(manifest.as_bytes(), None, payload)
}
