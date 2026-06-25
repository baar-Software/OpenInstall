//! # `oip-client` - the OpenInstall client engine
//!
//! All the verify-then-consent-then-install logic, with NO Tauri dependency.
//! `src-tauri` is a thin shell that wires these functions to `#[tauri::command]`s.
//! Keeping this crate Tauri-free also means its test binaries are named
//! `oip_client-*` (not `openinstall-*`), so they don't trip Windows'
//! installer-detection auto-elevation heuristic.
//!
//! Enforcement of the hard invariants lives here:
//!   * [`resolve`] downloads, verifies, inspects, then STOPS at minting a token.
//!     It never writes the payload to a runnable location and never executes
//!     anything (#1, #6); it is the only producer of `install_token`.
//!   * [`confirm`] acts only on a valid, unexpired, single-use token (#1), writes
//!     verified native package files into the per-user app directory.
//!   * Publisher key changes require a prior explicit [`acknowledge`].
//!
//! There is no silent-install path.

#![forbid(unsafe_code)]

pub mod appinfo;
pub mod icon;
pub mod installer;
pub mod motw;
pub mod native;
mod paths;
pub mod pkg;
pub mod registry;
pub mod repo;
pub mod resolver;
pub mod settings;
pub mod state;
pub mod store;

use oip_core::{Manifest, Payload, PayloadType, PublisherKey, TrustLevel};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub use settings::Settings;
pub use state::{AppState, PendingInstall, TokenError};

/// Everything the consent dialog needs. Serialized to the frontend in camelCase:
/// `id, name, publisher, version, homepage, sourceUrl, trust, keyFingerprint,
/// payloadSize, installToken`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveResult {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub homepage: String,
    pub source_url: String,
    pub trust: TrustLevel,
    pub key_fingerprint: String,
    pub payload_size: u64,
    pub install_token: String,
}

/// Result of an actual install.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub message: String,
}

/// Resolve an `openinstall://` URL: download, verify, inspect, and STOP.
/// Side-effect-free with respect to installation (never installs, never executes).
pub async fn resolve(url: &str, state: &AppState) -> Result<ResolveResult, String> {
    // 1. Deterministic openinstall:// mapping (#6/#7). A bare bundle id such as
    //    openinstall://com.example.app is first resolved through imported repos
    //    to that app's selected .oip. Loopback hosts are accepted (over http)
    //    ONLY when the user has opted into Developer Mode.
    let dev_mode = settings::load().developer_mode;
    let package_url = if repo::looks_like_bundle_reference(url) {
        repo::resolve_bundle_reference(url, dev_mode)
            .await
            .map_err(|e| e.to_string())?
    } else {
        url.to_string()
    };
    let source_url =
        resolver::resolve_url_with_policy(&package_url, dev_mode).map_err(|e| e.to_string())?;

    // 2. Download over TLS (mirror fallback list is just the primary for now).
    let bytes = resolver::download(std::slice::from_ref(&source_url), resolver::MAX_OIP_BYTES)
        .await
        .map_err(|e| format!("download failed: {e}"))?;
    let package_sha256 = hex::encode(Sha256::digest(&bytes));
    let _ = tokio::time::timeout(Duration::from_secs(3), store::refresh_remote_blocklist()).await;

    // 3. Open the zip in memory (nothing written to a runnable location, #1).
    let package = pkg::Package::from_bytes(&bytes).map_err(|e| e.to_string())?;

    if package.native_manifest_bytes().is_some() {
        return resolve_native(
            &package,
            bytes.len() as u64,
            package_sha256,
            source_url,
            state,
        )
        .await;
    }

    // 4. Parse + validate the manifest (fail closed, #2).
    let manifest_bytes = package
        .manifest_bytes()
        .map_err(|e| e.to_string())?
        .to_vec();
    let manifest = oip_core::parse_manifest(&manifest_bytes).map_err(|e| e.to_string())?;

    // 5. Locate the payload bytes named by the manifest.
    let payload = package
        .get(&manifest.payload.file)
        .ok_or_else(|| {
            format!(
                "payload `{}` is missing from the package",
                manifest.payload.file
            )
        })?
        .to_vec();

    // 6. Verify the payload against BOTH pinned hashes (fail closed, #2).
    oip_core::verify_payload(&payload, &manifest).map_err(|e| e.to_string())?;

    // 7. Signature + TOFU trust. Unsigned => Unverified, never "verified" (#8).
    let (trust, key_fingerprint) = match &manifest.publisher_key {
        Some(key) => {
            let sig = package.signature_bytes().ok_or_else(|| {
                "manifest declares a publisher key but manifest.minisig is missing".to_string()
            })?;
            // Signature must verify against the EMBEDDED key, else hard fail (#2).
            oip_core::verify_manifest_sig(&manifest_bytes, sig, &key.public_key)
                .map_err(|e| e.to_string())?;
            // TOFU: compare embedded key against the pinned key for this id (#3).
            let pinned = store::load_pin(&manifest.id);
            (
                oip_core::evaluate_trust(&manifest, pinned.as_ref()),
                oip_core::key_fingerprint(&key.public_key),
            )
        }
        None => (TrustLevel::Unverified, String::new()),
    };

    // 8. Local revocation blocklist (fail closed, #2).
    let pub_key = manifest
        .publisher_key
        .as_ref()
        .map(|k| k.public_key.as_str());
    if store::is_blocked(&store::BlockSubject {
        package_sha256: Some(&package_sha256),
        payload_hash: Some(&manifest.payload.hash_blake3),
        app_id: Some(&manifest.id),
        publisher_name: Some(&manifest.publisher),
        publisher_key: pub_key,
        ..store::BlockSubject::default()
    }) {
        return Err("this package is on the OpenInstall revocation blocklist".to_string());
    }

    let file_name = basename(&manifest.payload.file);

    // 9. Mint a single-use token bound to the verified bytes; STOP here (#1).
    let token = state::new_token();
    let payload_size = payload.len() as u64;
    state.insert(
        token.clone(),
        PendingInstall {
            native: None,
            payload,
            payload_type: manifest.payload.payload_type,
            file_name,
            silent_args: manifest.payload.silent_args.clone(),
            manifest: manifest.clone(),
            source_url: source_url.clone(),
            trust,
            created_at: std::time::Instant::now(),
            acknowledged: false,
        },
    );

    Ok(ResolveResult {
        id: manifest.id,
        name: manifest.name,
        publisher: manifest.publisher,
        version: manifest.version,
        homepage: manifest.homepage,
        source_url,
        trust,
        key_fingerprint,
        payload_size,
        install_token: token,
    })
}

async fn resolve_native(
    package: &pkg::Package,
    package_size: u64,
    package_sha256: String,
    source_url: String,
    state: &AppState,
) -> Result<ResolveResult, String> {
    let verified = native::verify_package(package, package_size)
        .await
        .map_err(|e| e.to_string())?;
    let file_hashes = verified
        .files
        .iter()
        .map(|file| hex::encode(Sha256::digest(&file.bytes)))
        .collect::<Vec<_>>();
    if store::is_blocked(&store::BlockSubject {
        package_sha256: Some(&package_sha256),
        file_hashes: &file_hashes,
        app_id: Some(&verified.manifest.id),
        publisher_name: Some(&verified.manifest.publisher.name),
        publisher_key: Some(&verified.public_key),
        ..store::BlockSubject::default()
    }) {
        return Err("this package is on the OpenInstall revocation blocklist".to_string());
    }

    let token = state::new_token();
    let synthetic = manifest_from_native(&verified);
    state.insert(
        token.clone(),
        PendingInstall {
            native: Some(verified.clone()),
            payload: Vec::new(),
            payload_type: PayloadType::Exe,
            file_name: verified.manifest.entry.clone(),
            silent_args: String::new(),
            manifest: synthetic,
            source_url: source_url.clone(),
            trust: verified.trust,
            created_at: std::time::Instant::now(),
            acknowledged: false,
        },
    );

    Ok(ResolveResult {
        id: verified.manifest.id,
        name: verified.manifest.name,
        publisher: verified.manifest.publisher.name,
        version: verified.manifest.version,
        homepage: verified.manifest.publisher.website,
        source_url,
        trust: verified.trust,
        key_fingerprint: verified.key_fingerprint,
        payload_size: verified.package_size,
        install_token: token,
    })
}

/// Record an explicit user acknowledgement for a publisher-key change. Keeps the
/// `confirm`/`confirm_install` signature unchanged.
pub fn acknowledge(install_token: &str, state: &AppState) -> Result<(), String> {
    state.acknowledge(install_token).map_err(|e| e.to_string())
}

/// Install ONLY with a valid, unexpired, single-use token minted by a prior
/// successful [`resolve`] (i.e. after the user clicked Install).
pub async fn confirm(install_token: &str, state: &AppState) -> Result<InstallResult, String> {
    // Validate + consume the token (rejects unknown/expired/reused, #1).
    let pending = state
        .consume(install_token, state::TOKEN_TTL)
        .map_err(|e| e.to_string())?;

    // Defense in depth: publisher-key changes must have been acknowledged (#3).
    if pending.trust == TrustLevel::PublisherChanged && !pending.acknowledged {
        return Err(
            "this package requires explicit acknowledgement of the risk before it can be installed"
                .to_string(),
        );
    }

    if let Some(native_package) = pending.native.as_ref() {
        let installed = native::install(native_package).map_err(|e| e.to_string())?;
        if matches!(
            native_package.trust,
            TrustLevel::Verified | TrustLevel::VerifiedNewPublisher | TrustLevel::PublisherChanged
        ) {
            let pin = oip_core::PinnedKey {
                id: native_package.manifest.id.clone(),
                public_key: native_package.public_key.clone(),
                first_seen: Some(unix_now_string()),
            };
            if let Err(e) = store::save_pin(&pin) {
                eprintln!("warning: failed to persist publisher key pin: {e}");
            }
        }

        let app = registry::InstalledApp {
            id: native_package.manifest.id.clone(),
            name: native_package.manifest.name.clone(),
            publisher: native_package.manifest.publisher.name.clone(),
            version: native_package.manifest.version.clone(),
            homepage: native_package.manifest.publisher.website.clone(),
            source_url: pending.source_url.clone(),
            trust: native_package.trust,
            key_fingerprint: native_package.key_fingerprint.clone(),
            installed_at: unix_now_string(),
            launch_target: installed.launch_target,
            entry_path: Some(installed.entry_path),
            icon: installed.icon,
        };
        if let Err(e) = registry::record(app) {
            eprintln!("warning: failed to record installed app: {e}");
        }

        return Ok(InstallResult {
            success: true,
            exit_code: None,
            message: format!(
                "Installed {} {} to {}",
                native_package.manifest.name,
                native_package.manifest.version,
                installed.install_dir
            ),
        });
    }

    Err("OpenInstall v1 installs native manifest.json + files/ packages".to_string())
}

fn manifest_from_native(package: &native::VerifiedNativePackage) -> Manifest {
    Manifest {
        schema: 1,
        id: package.manifest.id.clone(),
        name: package.manifest.name.clone(),
        publisher: package.manifest.publisher.name.clone(),
        version: package.manifest.version.clone(),
        homepage: package.manifest.publisher.website.clone(),
        payload: Payload {
            file: format!("files/{}", package.manifest.entry),
            payload_type: PayloadType::Exe,
            hash_blake3: "0".repeat(64),
            hash_sha256: "0".repeat(64),
            silent_args: String::new(),
        },
        publisher_key: Some(PublisherKey {
            key_type: "minisign".to_string(),
            public_key: package.public_key.clone(),
        }),
    }
}

/// Last path component of a manifest payload path (`payload/Setup.exe` -> `Setup.exe`).
fn basename(p: &str) -> String {
    p.rsplit(['/', '\\']).next().unwrap_or(p).to_string()
}

fn unix_now_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_handles_both_separators() {
        assert_eq!(basename("payload/Setup.exe"), "Setup.exe");
        assert_eq!(basename(r"payload\Setup.exe"), "Setup.exe");
        assert_eq!(basename("Setup.exe"), "Setup.exe");
    }
}
