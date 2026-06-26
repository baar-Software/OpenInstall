//! # `oip-pack` — OpenInstall package authoring
//!
//! Build and sign native `.oip` packages (`manifest.json` + `files/` +
//! `signatures/publisher.ed25519.sig`). Shared by `oip-cli` (developer CLI) and
//! the OpenInstall GUI's "Create package" feature, so the bytes a developer ships
//! are produced by exactly one code path.
//!
//! This crate is **byte-based and I/O-free** at its core: callers read app files /
//! keys and write outputs; we only transform bytes. Everything produced by
//! [`build_native_oip_bytes`] round-trips through `oip-core`: the signature is
//! self-checked against the embedded key before the archive is returned.
//!
//! It NEVER signs third-party payloads with the OpenInstall release cert and has no
//! "silent install" behavior — it only packages and signs (brief §11).

#![forbid(unsafe_code)]

use std::io::{Cursor, Read, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use minisign::{KeyPair, PublicKey, PublicKeyBox, SecretKey, SecretKeyBox};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::write::{SimpleFileOptions, ZipWriter};
use zip::{CompressionMethod, ZipArchive};

const NATIVE_MANIFEST_NAME: &str = "manifest.json";
const NATIVE_SIG_NAME: &str = "signatures/publisher.ed25519.sig";

/// A freshly generated minisign keypair, as the text you would store on disk.
#[derive(Debug, Clone)]
pub struct GeneratedKeypair {
    /// The bare `RW...` base64 public key embedded in the manifest's publisher key.
    pub public_key_b64: String,
    /// Full `.pub` file contents (comment line + key).
    pub public_key_box: String,
    /// Full `.key` file contents (encrypted iff `password` was supplied).
    pub secret_key_box: String,
    /// Whether the secret key is password-encrypted.
    pub encrypted: bool,
}

/// Metadata for a native OpenInstall v1 package (`manifest.json` + `files/`).
#[derive(Debug, Clone)]
pub struct NativeManifestMeta {
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher_name: String,
    pub publisher_website: String,
    pub entry: String,
    pub network: bool,
    pub shortcut_name: String,
}

/// A file to place under `files/<path>` in a native `.oip`.
#[derive(Debug, Clone)]
pub struct NativeFileInput {
    pub path: String,
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Serializable manifest document (controls the exact bytes we write & sign).
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeManifestDoc {
    schema: u32,
    id: String,
    name: String,
    version: String,
    publisher: NativePublisherDoc,
    entry: String,
    install_mode: String,
    requires_admin: bool,
    files: Vec<NativeFileDoc>,
    permissions: NativePermissionsDoc,
    shortcuts: Vec<NativeShortcutDoc>,
}

#[derive(Serialize)]
struct NativePublisherDoc {
    name: String,
    key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    website: String,
}

#[derive(Serialize)]
struct NativeFileDoc {
    path: String,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativePermissionsDoc {
    network: bool,
    autostart: bool,
    registry: bool,
    services: bool,
    drivers: bool,
    shell_extensions: bool,
}

#[derive(Serialize)]
struct NativeShortcutDoc {
    name: String,
    target: String,
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

/// Generate a minisign keypair. If `password` is `Some`, the secret key is
/// encrypted with it.
pub fn generate_keypair(password: Option<String>) -> Result<GeneratedKeypair> {
    let encrypted = password.is_some();
    let kp: KeyPair = match password {
        Some(pw) => KeyPair::generate_encrypted_keypair(Some(pw))
            .map_err(|e| anyhow!("keygen failed: {e}"))?,
        None => {
            KeyPair::generate_unencrypted_keypair().map_err(|e| anyhow!("keygen failed: {e}"))?
        }
    };
    let secret_key_box = kp
        .sk
        .to_box(Some("OpenInstall publisher secret key"))
        .map_err(|e| anyhow!("encoding secret key: {e}"))?
        .to_string();
    let public_key_box = kp
        .pk
        .to_box()
        .map_err(|e| anyhow!("encoding public key: {e}"))?
        .to_string();
    Ok(GeneratedKeypair {
        public_key_b64: kp.pk.to_base64(),
        public_key_box,
        secret_key_box,
        encrypted,
    })
}

/// Resolve a public key supplied as either the bare `RW...` base64 or the full
/// two-line `.pub` file contents, into the bare base64 form.
pub fn resolve_public_key(text: &str) -> Result<String> {
    let trimmed = text.trim();
    if let Ok(pk) = PublicKey::from_base64(trimmed) {
        return Ok(pk.to_base64());
    }
    let pk = PublicKeyBox::from_string(trimmed)
        .map_err(|e| anyhow!("parsing public key: {e}"))?
        .into_public_key()
        .map_err(|e| anyhow!("decoding public key: {e}"))?;
    Ok(pk.to_base64())
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

/// Build and sign a native OpenInstall v1 `.oip`.
///
/// The resulting archive contains:
///
/// ```text
/// manifest.json
/// files/<app files>
/// signatures/publisher.ed25519.sig
/// sbom.spdx.json
/// provenance.json
/// ```
pub fn build_native_oip_bytes(
    meta: &NativeManifestMeta,
    files: &[NativeFileInput],
    public_key: &str,
    secret_key_text: &str,
    password: Option<String>,
) -> Result<Vec<u8>> {
    validate_native_meta(meta)?;
    if files.is_empty() {
        bail!("native package must contain at least one file");
    }
    let public_key = resolve_public_key(public_key)?;
    let mut manifest_files = Vec::with_capacity(files.len());
    for file in files {
        validate_native_file_path(&file.path)?;
        if file.bytes.is_empty() {
            bail!("file `{}` is empty", file.path);
        }
        manifest_files.push(NativeFileDoc {
            path: file.path.clone(),
            sha256: hex::encode(Sha256::digest(&file.bytes)),
        });
    }
    if !files.iter().any(|file| file.path == meta.entry) {
        bail!(
            "entry `{}` is not present in the selected app folder",
            meta.entry
        );
    }

    let shortcut_name = if meta.shortcut_name.trim().is_empty() {
        meta.name.trim()
    } else {
        meta.shortcut_name.trim()
    };
    let doc = NativeManifestDoc {
        schema: 1,
        id: meta.id.trim().to_string(),
        name: meta.name.trim().to_string(),
        version: meta.version.trim().to_string(),
        publisher: NativePublisherDoc {
            name: meta.publisher_name.trim().to_string(),
            key: format!("minisign:{public_key}"),
            website: meta.publisher_website.trim().to_string(),
        },
        entry: meta.entry.trim().to_string(),
        install_mode: "perUser".to_string(),
        requires_admin: false,
        files: manifest_files,
        permissions: NativePermissionsDoc {
            network: meta.network,
            autostart: false,
            registry: false,
            services: false,
            drivers: false,
            shell_extensions: false,
        },
        shortcuts: vec![NativeShortcutDoc {
            name: shortcut_name.to_string(),
            target: meta.entry.trim().to_string(),
        }],
    };
    let manifest_bytes =
        serde_json::to_vec_pretty(&doc).context("serializing native manifest.json")?;
    let sk = load_secret_key_from_text(secret_key_text, password)?;
    let sig_bytes = minisign::sign(None, &sk, Cursor::new(&manifest_bytes), None, None)
        .map_err(|e| anyhow!("signing native manifest failed: {e}"))?
        .to_string()
        .into_bytes();
    oip_core::verify_manifest_sig(&manifest_bytes, &sig_bytes, &public_key).map_err(|e| {
        anyhow!("produced native signature does not verify against the embedded key ({e}); the secret key likely does not match the public key")
    })?;

    let mut zw = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    zw.start_file(NATIVE_MANIFEST_NAME, opts)?;
    zw.write_all(&manifest_bytes)?;
    for file in files {
        zw.start_file(format!("files/{}", file.path), opts)?;
        zw.write_all(&file.bytes)?;
    }
    zw.start_file(NATIVE_SIG_NAME, opts)?;
    zw.write_all(&sig_bytes)?;
    zw.start_file("sbom.spdx.json", opts)?;
    zw.write_all(b"{\n  \"spdxVersion\": \"SPDX-2.3\",\n  \"dataLicense\": \"CC0-1.0\",\n  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n  \"name\": \"OpenInstall generated package\"\n}\n")?;
    zw.start_file("provenance.json", opts)?;
    zw.write_all(
        b"{\n  \"builder\": \"OpenInstall Create\",\n  \"packageFormat\": \"oip-v1-native\"\n}\n",
    )?;
    Ok(zw.finish()?.into_inner())
}

/// Collect an app folder (or a single `.exe`) into native package files. Walks a
/// folder recursively, optionally excludes `exclude_output` (so the `.oip` is not
/// packaged into itself), and injects `icon` as `assets/icon.png`. Returns the
/// files (sorted by path) and an inferred entry (the first `.exe`). Shared by the
/// CLI and the GUI so both produce byte-identical native packages.
pub fn collect_app_files(
    app_source: &Path,
    exclude_output: Option<&Path>,
    icon: Option<&Path>,
) -> Result<(Vec<NativeFileInput>, String)> {
    if !app_source.exists() {
        bail!("{} does not exist", app_source.display());
    }
    let source = app_source
        .canonicalize()
        .with_context(|| format!("resolving app source {}", app_source.display()))?;
    let output = exclude_output.and_then(|p| p.canonicalize().ok());
    let mut files = Vec::new();

    let inferred_entry = if source.is_file() {
        let file_name = source
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("app executable has no file name"))?
            .to_string();
        let bytes =
            std::fs::read(&source).with_context(|| format!("reading {}", source.display()))?;
        files.push(NativeFileInput {
            path: file_name.clone(),
            bytes,
        });
        file_name
    } else if source.is_dir() {
        collect_dir(&source, &source, output.as_deref(), &mut files)?;
        files
            .iter()
            .find(|f| f.path.to_ascii_lowercase().ends_with(".exe"))
            .map(|f| f.path.clone())
            .unwrap_or_default()
    } else {
        bail!("{} is not a file or directory", source.display());
    };

    if let Some(icon) = icon {
        if !icon.as_os_str().is_empty() {
            let icon_bytes =
                std::fs::read(icon).with_context(|| format!("reading icon {}", icon.display()))?;
            files.retain(|f| f.path != "assets/icon.png");
            files.push(NativeFileInput {
                path: "assets/icon.png".to_string(),
                bytes: icon_bytes,
            });
        }
    }
    if files.is_empty() {
        bail!("app source contains no packageable files");
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((files, inferred_entry))
}

fn collect_dir(
    root: &Path,
    dir: &Path,
    output: Option<&Path>,
    files: &mut Vec<NativeFileInput>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            collect_dir(root, &path, output, files)?;
        } else if ty.is_file() {
            if output.is_some_and(|out| out == path) {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .with_context(|| format!("making relative path for {}", path.display()))?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let bytes =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            files.push(NativeFileInput { path: rel, bytes });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// Outcome of [`verify_native_oip_bytes`].
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub id: String,
    pub name: String,
    pub version: String,
    pub signed: bool,
    pub key_fingerprint: Option<String>,
    pub trust: oip_core::TrustLevel,
}

#[derive(Deserialize)]
struct NativeManifestRead {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    publisher: NativePublisherRead,
    #[serde(default)]
    files: Vec<NativeFileRead>,
}

#[derive(Deserialize)]
struct NativePublisherRead {
    key: String,
}

#[derive(Deserialize)]
struct NativeFileRead {
    path: String,
    sha256: String,
}

/// Verify a native (`manifest.json` + `files/`) `.oip` exactly as the client does:
/// the publisher signature over `manifest.json`, then every file's SHA-256. Trust
/// is first-use (no local pin on the dev side). Fails closed on any mismatch.
pub fn verify_native_oip_bytes(oip_bytes: &[u8]) -> Result<VerifyReport> {
    let entries = read_zip_entries(oip_bytes)?;
    let manifest_bytes = find_entry(&entries, NATIVE_MANIFEST_NAME)
        .ok_or_else(|| anyhow!("package has no {NATIVE_MANIFEST_NAME}"))?
        .to_vec();
    let manifest: NativeManifestRead =
        serde_json::from_slice(&manifest_bytes).context("parsing manifest.json")?;

    let raw_key = manifest.publisher.key.trim();
    let key = raw_key
        .strip_prefix("minisign:")
        .or_else(|| raw_key.strip_prefix("ed25519:"))
        .unwrap_or(raw_key);
    let public_key = resolve_public_key(key)?;

    let sig = find_entry(&entries, NATIVE_SIG_NAME)
        .ok_or_else(|| anyhow!("package has no {NATIVE_SIG_NAME}"))?;
    oip_core::verify_manifest_sig(&manifest_bytes, sig, &public_key)
        .context("publisher signature verification")?;

    if manifest.files.is_empty() {
        bail!("native package lists no files");
    }
    for file in &manifest.files {
        let data = find_entry(&entries, &format!("files/{}", file.path))
            .ok_or_else(|| anyhow!("file `{}` is missing from the package", file.path))?;
        if !hex::encode(Sha256::digest(data)).eq_ignore_ascii_case(&file.sha256) {
            bail!("file `{}` failed SHA-256 verification", file.path);
        }
    }

    Ok(VerifyReport {
        id: manifest.id,
        name: manifest.name,
        version: manifest.version,
        signed: true,
        key_fingerprint: Some(oip_core::key_fingerprint(&public_key)),
        trust: oip_core::TrustLevel::VerifiedNewPublisher,
    })
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn load_secret_key_from_text(text: &str, password: Option<String>) -> Result<SecretKey> {
    let sk_box = SecretKeyBox::from_string(text).map_err(|e| anyhow!("parsing secret key: {e}"))?;
    match password {
        Some(pw) => {
            SecretKey::from_box(sk_box, Some(pw)).map_err(|e| anyhow!("decrypting secret key: {e}"))
        }
        None => SecretKey::from_unencrypted_box(sk_box).map_err(|e| {
            anyhow!("loading secret key: {e}. If it is password-protected, supply the password")
        }),
    }
}

fn validate_native_meta(meta: &NativeManifestMeta) -> Result<()> {
    validate_reverse_dns(meta.id.trim())?;
    require_non_empty("name", &meta.name)?;
    require_non_empty("version", &meta.version)?;
    require_non_empty("publisher", &meta.publisher_name)?;
    validate_native_file_path(meta.entry.trim())?;
    Ok(())
}

fn validate_reverse_dns(id: &str) -> Result<()> {
    require_non_empty("id", id)?;
    let labels: Vec<_> = id.split('.').collect();
    if labels.len() < 2 {
        bail!("id must be reverse-DNS, for example com.example.app");
    }
    for label in labels {
        if label.is_empty()
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("id `{id}` is not a valid reverse-DNS identifier");
        }
    }
    Ok(())
}

fn validate_native_file_path(value: &str) -> Result<()> {
    require_non_empty("path", value)?;
    if value.contains('\\') || value.starts_with('/') || value.contains(':') {
        bail!("path `{value}` must be relative and slash-separated");
    }
    for part in value.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            bail!("path `{value}` contains unsupported components");
        }
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} is required");
    }
    Ok(())
}

fn read_zip_entries(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).context("opening .oip as a zip")?;
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i)?;
        if f.is_dir() {
            continue;
        }
        let name = f.name().to_string();
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        out.push((name, data));
    }
    Ok(out)
}

fn find_entry<'a>(entries: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    entries
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, d)| d.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_password_or_key_text_fails() {
        assert!(load_secret_key_from_text("not a key", None).is_err());
    }

    #[test]
    fn builds_signed_native_v1_package() {
        let kp = generate_keypair(None).unwrap();
        let meta = NativeManifestMeta {
            id: "com.example.native".into(),
            name: "Native App".into(),
            version: "1.0.0".into(),
            publisher_name: "Example Dev".into(),
            publisher_website: "https://example.com".into(),
            entry: "Native.exe".into(),
            network: true,
            shortcut_name: "Native App".into(),
        };
        let files = vec![NativeFileInput {
            path: "Native.exe".into(),
            bytes: b"MZ native app bytes".to_vec(),
        }];
        let oip =
            build_native_oip_bytes(&meta, &files, &kp.public_key_b64, &kp.secret_key_box, None)
                .unwrap();
        let entries = read_zip_entries(&oip).unwrap();
        assert!(find_entry(&entries, NATIVE_MANIFEST_NAME).is_some());
        assert!(find_entry(&entries, "files/Native.exe").is_some());
        assert!(find_entry(&entries, NATIVE_SIG_NAME).is_some());
    }

    #[test]
    fn native_build_then_verify_roundtrips() {
        let kp = generate_keypair(None).unwrap();
        let meta = NativeManifestMeta {
            id: "com.example.native".into(),
            name: "Native App".into(),
            version: "2.1.0".into(),
            publisher_name: "Example Dev".into(),
            publisher_website: "https://example.com".into(),
            entry: "Native.exe".into(),
            network: true,
            shortcut_name: String::new(),
        };
        let files = vec![NativeFileInput {
            path: "Native.exe".into(),
            bytes: b"MZ native app bytes".to_vec(),
        }];
        let oip =
            build_native_oip_bytes(&meta, &files, &kp.public_key_b64, &kp.secret_key_box, None)
                .unwrap();

        let report = verify_native_oip_bytes(&oip).unwrap();
        assert!(report.signed);
        assert_eq!(report.id, "com.example.native");
        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.trust, oip_core::TrustLevel::VerifiedNewPublisher);
    }

    #[test]
    fn tampered_native_file_is_refused() {
        let kp = generate_keypair(None).unwrap();
        let meta = NativeManifestMeta {
            id: "com.example.native".into(),
            name: "Native App".into(),
            version: "1.0.0".into(),
            publisher_name: "Example Dev".into(),
            publisher_website: String::new(),
            entry: "Native.exe".into(),
            network: false,
            shortcut_name: String::new(),
        };
        let files = vec![NativeFileInput {
            path: "Native.exe".into(),
            bytes: b"MZ original bytes".to_vec(),
        }];
        let oip =
            build_native_oip_bytes(&meta, &files, &kp.public_key_b64, &kp.secret_key_box, None)
                .unwrap();

        // Swap the file bytes inside the archive without re-signing the manifest.
        let mut entries = read_zip_entries(&oip).unwrap();
        for (name, data) in entries.iter_mut() {
            if name == "files/Native.exe" {
                *data = b"MZ tampered bytes".to_vec();
            }
        }
        let mut zw = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, data) in &entries {
            zw.start_file(name.as_str(), opts).unwrap();
            zw.write_all(data).unwrap();
        }
        let tampered = zw.finish().unwrap().into_inner();

        assert!(verify_native_oip_bytes(&tampered).is_err());
    }
}
