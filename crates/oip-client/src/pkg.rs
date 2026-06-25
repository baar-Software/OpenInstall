//! In-memory `.oip` (zip) reader.
//!
//! Reads the whole archive into a name→bytes map so the verification pipeline can
//! pull `manifest.toml`, `manifest.minisig`, and the payload without touching the
//! filesystem (the bytes are downloaded, never written to a runnable location at
//! resolve time — invariant #1).

use std::collections::HashMap;
use std::io::{Cursor, Read};

use anyhow::{anyhow, Context, Result};

pub const MANIFEST_NAME: &str = "manifest.toml";
pub const NATIVE_MANIFEST_NAME: &str = "manifest.json";
pub const SIG_NAME: &str = "manifest.minisig";
pub const NATIVE_SIG_NAME: &str = "signatures/publisher.ed25519.sig";

pub struct Package {
    entries: HashMap<String, Vec<u8>>,
}

impl Package {
    /// Parse zip bytes into a package.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut archive =
            zip::ZipArchive::new(Cursor::new(bytes)).context("opening .oip as a zip archive")?;
        let mut entries = HashMap::new();
        for i in 0..archive.len() {
            let mut f = archive.by_index(i)?;
            if f.is_dir() {
                continue;
            }
            let name = f.name().to_string();
            let mut data = Vec::new();
            f.read_to_end(&mut data)?;
            entries.insert(name, data);
        }
        Ok(Self { entries })
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries.get(name).map(|v| v.as_slice())
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }

    pub fn manifest_bytes(&self) -> Result<&[u8]> {
        self.get(MANIFEST_NAME)
            .ok_or_else(|| anyhow!("package has no {MANIFEST_NAME}"))
    }

    pub fn signature_bytes(&self) -> Option<&[u8]> {
        self.get(SIG_NAME)
    }

    pub fn native_manifest_bytes(&self) -> Option<&[u8]> {
        self.get(NATIVE_MANIFEST_NAME)
    }

    pub fn native_signature_bytes(&self) -> Option<&[u8]> {
        self.get(NATIVE_SIG_NAME).or_else(|| self.get(SIG_NAME))
    }
}
