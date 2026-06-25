//! Native OpenInstall app packages (`manifest.json` + `files/`).
//!
//! This is the package-manager path: OpenInstall verifies a package, stages files
//! for Authenticode inspection, then installs by copying files into a per-user
//! app directory. It never runs an external setup program.
//!
//! ## Installed files and SmartScreen
//!
//! Files written here come from a package OpenInstall has *cryptographically
//! verified* (publisher signature over the manifest + per-file SHA-256 + TOFU key
//! pinning + revocation blocklist) and that is forbidden from carrying installer
//! /script payloads. They are therefore treated as **installed software**, exactly
//! like apps from winget / MSIX / the Microsoft Store — they are NOT marked with
//! the Mark-of-the-Web, so launching them does not raise SmartScreen's
//! "unrecognized app" reputation prompt. This is not an evasion: OpenInstall never
//! disables SmartScreen, never adds antivirus exclusions, and never strips MotW
//! from a file Windows itself marked. Microsoft Defender's real-time antivirus
//! still scans these files on execution regardless. The trust basis is
//! OpenInstall's package verification, replacing browser-download reputation.

use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use oip_core::{PinnedKey, TrustLevel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{authenticode, paths::data_dir, pkg::Package};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeManifest {
    pub schema: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: NativePublisher,
    #[serde(default)]
    pub entry: String,
    #[serde(default = "default_install_mode")]
    pub install_mode: String,
    #[serde(default)]
    pub requires_admin: bool,
    #[serde(default)]
    pub files: Vec<NativeFile>,
    #[serde(default)]
    pub permissions: NativePermissions,
    #[serde(default)]
    pub shortcuts: Vec<NativeShortcut>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePublisher {
    pub name: String,
    pub key: String,
    #[serde(default)]
    pub website: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativePermissions {
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub registry: bool,
    #[serde(default)]
    pub services: bool,
    #[serde(default)]
    pub drivers: bool,
    #[serde(default)]
    pub shell_extensions: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeShortcut {
    pub name: String,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedNativePackage {
    pub manifest: NativeManifest,
    pub files: Vec<VerifiedFile>,
    pub trust: TrustLevel,
    pub public_key: String,
    pub key_fingerprint: String,
    pub authenticode: String,
    pub package_size: u64,
}

#[derive(Debug, Clone)]
pub struct VerifiedFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NativeInstallResult {
    pub install_dir: String,
    /// Full path to the installed entry-point file.
    pub entry_path: String,
    pub launch_target: Option<String>,
    /// The app's real icon as a `data:image/png;base64,…` URL, if extractable.
    pub icon: Option<String>,
}

fn default_install_mode() -> String {
    "perUser".to_string()
}

pub async fn verify_package(
    package: &Package,
    package_size: u64,
    source_url: &str,
) -> Result<VerifiedNativePackage> {
    let manifest_bytes = package
        .native_manifest_bytes()
        .ok_or_else(|| anyhow!("native package has no manifest.json"))?;
    let manifest: NativeManifest =
        serde_json::from_slice(manifest_bytes).context("parsing manifest.json")?;
    validate_manifest(&manifest)?;

    let public_key = package_key(&manifest.publisher.key)?;
    let sig = package
        .native_signature_bytes()
        .ok_or_else(|| anyhow!("native package has no publisher signature"))?;
    oip_core::verify_manifest_sig(manifest_bytes, sig, &public_key)
        .map_err(|e| anyhow!("publisher signature verification failed: {e}"))?;

    let mut files = Vec::with_capacity(manifest.files.len());
    for file in &manifest.files {
        let zip_path = format!("files/{}", file.path);
        let bytes = package
            .get(&zip_path)
            .ok_or_else(|| anyhow!("package file `{zip_path}` is missing"))?
            .to_vec();
        let digest = hex::encode(Sha256::digest(&bytes));
        if !digest.eq_ignore_ascii_case(&file.sha256) {
            bail!("file `{}` failed SHA-256 verification", file.path);
        }
        files.push(VerifiedFile {
            path: file.path.clone(),
            bytes,
        });
    }

    reject_unlisted_files(package, &manifest)?;
    reject_forbidden_files(&manifest.files)?;

    let pinned = crate::store::load_pin(&manifest.id);
    let trust = evaluate_native_trust(&manifest, pinned.as_ref(), &public_key);
    let key_fingerprint = oip_core::key_fingerprint(&public_key);
    let scan = inspect_verified_files(&files, source_url).await;

    Ok(VerifiedNativePackage {
        manifest,
        files,
        trust,
        public_key,
        key_fingerprint,
        authenticode: scan.authenticode,
        package_size,
    })
}

pub fn install(package: &VerifiedNativePackage) -> Result<NativeInstallResult> {
    if package.manifest.requires_admin {
        bail!("this package requires administrator rights and is blocked by default");
    }

    let install_dir = app_install_dir(&package.manifest)?;
    if install_dir.exists() {
        std::fs::remove_dir_all(&install_dir)
            .with_context(|| format!("removing {}", install_dir.display()))?;
    }
    std::fs::create_dir_all(&install_dir)
        .with_context(|| format!("creating {}", install_dir.display()))?;

    for file in &package.files {
        let dest = safe_join(&install_dir, &file.path)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        // No Mark-of-the-Web: these are files from a verified package, installed as
        // software, not browser-downloaded executables (see the module docs). We
        // never strip MotW from files Windows marked, disable SmartScreen, or add
        // AV exclusions; Defender real-time AV still scans these on execution.
        std::fs::write(&dest, &file.bytes)
            .with_context(|| format!("writing {}", dest.display()))?;
    }

    // The app's real icon, extracted from the verified entry-point file.
    let entry_path = safe_join(&install_dir, &package.manifest.entry)?;
    let icon = crate::icon::extract_icon_data_url(&entry_path);

    let launch_target = create_shortcuts(&package.manifest, &install_dir)?;
    write_uninstall_entry(&package.manifest, &install_dir)?;

    Ok(NativeInstallResult {
        install_dir: install_dir.to_string_lossy().into_owned(),
        entry_path: entry_path.to_string_lossy().into_owned(),
        launch_target,
        icon,
    })
}

pub fn app_install_dir(manifest: &NativeManifest) -> Result<PathBuf> {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|_| data_dir().ok_or(std::env::VarError::NotPresent))
        .map_err(|_| anyhow!("no per-user app data directory available"))?;
    Ok(base
        .join("OpenInstall")
        .join("Apps")
        .join(&manifest.id)
        .join(&manifest.version))
}

fn validate_manifest(manifest: &NativeManifest) -> Result<()> {
    if manifest.schema != 1 {
        bail!("unsupported native package schema {}", manifest.schema);
    }
    validate_reverse_dns(&manifest.id)?;
    require_non_empty("name", &manifest.name)?;
    require_non_empty("version", &manifest.version)?;
    require_non_empty("publisher.name", &manifest.publisher.name)?;
    require_non_empty("publisher.key", &manifest.publisher.key)?;
    require_non_empty("entry", &manifest.entry)?;
    validate_relative_path(&manifest.entry)?;
    if manifest.install_mode != "perUser" {
        bail!(
            "installMode `{}` is not allowed; expected perUser",
            manifest.install_mode
        );
    }
    if manifest.requires_admin {
        bail!("requiresAdmin packages are blocked by default");
    }
    if manifest.files.is_empty() {
        bail!("native package has no files");
    }
    validate_permissions(&manifest.permissions)?;
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        validate_sha256(&file.sha256)?;
    }
    if !manifest
        .files
        .iter()
        .any(|file| file.path == manifest.entry)
    {
        bail!("entry `{}` is not listed in files", manifest.entry);
    }
    for shortcut in &manifest.shortcuts {
        require_non_empty("shortcut.name", &shortcut.name)?;
        validate_relative_path(&shortcut.target)?;
        if !manifest
            .files
            .iter()
            .any(|file| file.path == shortcut.target)
        {
            bail!(
                "shortcut target `{}` is not listed in files",
                shortcut.target
            );
        }
    }
    Ok(())
}

fn validate_permissions(permissions: &NativePermissions) -> Result<()> {
    if permissions.autostart {
        bail!("autostart permission is blocked by default");
    }
    if permissions.registry {
        bail!("registry permission is blocked by default");
    }
    if permissions.services {
        bail!("service installation is blocked");
    }
    if permissions.drivers {
        bail!("driver installation is blocked");
    }
    if permissions.shell_extensions {
        bail!("shell extension installation is blocked");
    }
    Ok(())
}

fn reject_forbidden_files(files: &[NativeFile]) -> Result<()> {
    for file in files {
        let name = Path::new(&file.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_lowercase();
        let ext = Path::new(&file.path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_lowercase();
        if matches!(
            ext.as_str(),
            "ps1" | "bat" | "cmd" | "vbs" | "wsf" | "msi" | "reg"
        ) {
            bail!(
                "file `{}` has a blocked installer/script extension",
                file.path
            );
        }
        if name == "setup.exe" || name == "installer.exe" {
            bail!("unknown external setup executables are blocked");
        }
    }
    Ok(())
}

fn reject_unlisted_files(package: &Package, manifest: &NativeManifest) -> Result<()> {
    let allowed = manifest
        .files
        .iter()
        .map(|file| format!("files/{}", file.path))
        .collect::<std::collections::HashSet<_>>();
    for name in package.names() {
        if name.starts_with("files/") && !allowed.contains(name) {
            bail!("package contains unlisted file `{name}`");
        }
    }
    Ok(())
}

async fn inspect_verified_files(
    files: &[VerifiedFile],
    source_url: &str,
) -> crate::scan::ScanReport {
    let files = files.to_vec();
    let source_url = source_url.to_string();
    tokio::task::spawn_blocking(move || {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(_) => {
                return crate::scan::ScanReport {
                    authenticode: "unavailable".to_string(),
                }
            }
        };
        for file in &files {
            let Ok(path) = safe_join(dir.path(), &file.path) else {
                return crate::scan::ScanReport {
                    authenticode: "unavailable".to_string(),
                };
            };
            if let Some(parent) = path.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    return crate::scan::ScanReport {
                        authenticode: "unavailable".to_string(),
                    };
                }
            }
            if std::fs::write(&path, &file.bytes).is_err() {
                return crate::scan::ScanReport {
                    authenticode: "unavailable".to_string(),
                };
            }
            let _ = crate::motw::write_mark_of_the_web(&path, &source_url);
        }

        let authenticode = authenticode_summary(dir.path(), &files);
        crate::scan::ScanReport { authenticode }
    })
    .await
    .unwrap_or_else(|_| crate::scan::ScanReport {
        authenticode: "unavailable".to_string(),
    })
}

fn authenticode_summary(root: &Path, files: &[VerifiedFile]) -> String {
    let mut unsigned = 0usize;
    let mut unavailable = 0usize;
    for file in files {
        if !is_windows_binary(&file.path) {
            continue;
        }
        let Ok(path) = safe_join(root, &file.path) else {
            unavailable += 1;
            continue;
        };
        let status = authenticode::check_file(&path);
        if status.starts_with("invalid:") {
            return status;
        }
        if status == "unsigned" {
            unsigned += 1;
        } else if status == "unavailable" {
            unavailable += 1;
        }
    }
    if unsigned > 0 {
        "unsigned".to_string()
    } else if unavailable > 0 {
        "unavailable".to_string()
    } else {
        "signed:all Windows binaries".to_string()
    }
}

fn is_windows_binary(path: &str) -> bool {
    let ext = Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    matches!(ext.to_ascii_lowercase().as_str(), "exe" | "dll")
}

fn create_shortcuts(manifest: &NativeManifest, install_dir: &Path) -> Result<Option<String>> {
    let shortcuts = if manifest.shortcuts.is_empty() {
        vec![NativeShortcut {
            name: manifest.name.clone(),
            target: manifest.entry.clone(),
        }]
    } else {
        manifest.shortcuts.clone()
    };

    let Some(shortcut) = shortcuts.first() else {
        return Ok(None);
    };
    let target = safe_join(install_dir, &shortcut.target)?;
    let start_menu = user_start_menu_programs()?;
    std::fs::create_dir_all(&start_menu)
        .with_context(|| format!("creating {}", start_menu.display()))?;
    let link = start_menu.join(format!("{}.lnk", sanitize_shortcut_name(&shortcut.name)));
    create_shortcut(&link, &target, install_dir)?;
    Ok(Some(link.to_string_lossy().into_owned()))
}

fn create_shortcut(link: &Path, target: &Path, working_dir: &Path) -> Result<()> {
    let script = r#"$shell = New-Object -ComObject WScript.Shell
$s = $shell.CreateShortcut($env:OI_LINK)
$s.TargetPath = $env:OI_TARGET
$s.WorkingDirectory = $env:OI_WORKDIR
$s.Save()"#;
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("OI_LINK", link)
        .env("OI_TARGET", target)
        .env("OI_WORKDIR", working_dir)
        .status()
        .context("creating Start Menu shortcut")?;
    if !status.success() {
        bail!("creating Start Menu shortcut failed");
    }
    Ok(())
}

fn write_uninstall_entry(manifest: &NativeManifest, install_dir: &Path) -> Result<()> {
    let key = format!(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{}",
        manifest.id
    );
    reg_add(&key, "DisplayName", &manifest.name)?;
    reg_add(&key, "DisplayVersion", &manifest.version)?;
    reg_add(&key, "Publisher", &manifest.publisher.name)?;
    reg_add(&key, "InstallLocation", &install_dir.to_string_lossy())?;
    reg_add(&key, "NoModify", "1")?;
    reg_add(&key, "NoRepair", "1")?;
    Ok(())
}

fn reg_add(key: &str, name: &str, value: &str) -> Result<()> {
    let status = std::process::Command::new("reg")
        .args(["add", key, "/v", name, "/d", value, "/f"])
        .status()
        .with_context(|| format!("writing uninstall metadata {name}"))?;
    if !status.success() {
        bail!("writing uninstall metadata `{name}` failed");
    }
    Ok(())
}

fn user_start_menu_programs() -> Result<PathBuf> {
    let appdata = std::env::var("APPDATA").context("APPDATA is not set")?;
    Ok(PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs"))
}

fn sanitize_shortcut_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        "OpenInstall App".to_string()
    } else {
        trimmed.to_string()
    }
}

fn package_key(key: &str) -> Result<String> {
    let trimmed = key.trim();
    if let Some(rest) = trimmed.strip_prefix("ed25519:") {
        require_non_empty("publisher.key", rest)?;
        Ok(rest.to_string())
    } else if let Some(rest) = trimmed.strip_prefix("minisign:") {
        require_non_empty("publisher.key", rest)?;
        Ok(rest.to_string())
    } else {
        require_non_empty("publisher.key", trimmed)?;
        Ok(trimmed.to_string())
    }
}

fn evaluate_native_trust(
    manifest: &NativeManifest,
    pinned: Option<&PinnedKey>,
    public_key: &str,
) -> TrustLevel {
    match pinned {
        None => TrustLevel::VerifiedNewPublisher,
        Some(pin) if pin.public_key == public_key && pin.id == manifest.id => TrustLevel::Verified,
        Some(_) => TrustLevel::PublisherChanged,
    }
}

fn validate_relative_path(value: &str) -> Result<()> {
    require_non_empty("path", value)?;
    let path = Path::new(value);
    if path.is_absolute() || value.contains('\\') {
        bail!("path `{value}` must be a relative slash-separated path");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => bail!("path `{value}` contains unsupported components"),
        }
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    Ok(root.join(relative))
}

fn validate_reverse_dns(id: &str) -> Result<()> {
    require_non_empty("id", id)?;
    let labels: Vec<_> = id.split('.').collect();
    if labels.len() < 2 {
        bail!("id must be reverse-DNS");
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

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("sha256 must be 64 hex characters");
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} is required");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha() -> String {
        "0".repeat(64)
    }

    fn manifest() -> NativeManifest {
        NativeManifest {
            schema: 1,
            id: "com.example.app".to_string(),
            name: "Example App".to_string(),
            version: "1.0.0".to_string(),
            publisher: NativePublisher {
                name: "Example Publisher".to_string(),
                key: "minisign:RWQ00000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                website: "https://example.com".to_string(),
            },
            entry: "Example.exe".to_string(),
            install_mode: "perUser".to_string(),
            requires_admin: false,
            files: vec![NativeFile {
                path: "Example.exe".to_string(),
                sha256: sha(),
            }],
            permissions: NativePermissions::default(),
            shortcuts: vec![NativeShortcut {
                name: "Example App".to_string(),
                target: "Example.exe".to_string(),
            }],
        }
    }

    #[test]
    fn validates_minimal_native_manifest() {
        validate_manifest(&manifest()).unwrap();
    }

    #[test]
    fn rejects_admin_installs() {
        let mut m = manifest();
        m.requires_admin = true;
        assert!(validate_manifest(&m)
            .unwrap_err()
            .to_string()
            .contains("requiresAdmin"));
    }

    #[test]
    fn rejects_blocked_permissions() {
        for set_permission in [
            |p: &mut NativePermissions| p.autostart = true,
            |p: &mut NativePermissions| p.registry = true,
            |p: &mut NativePermissions| p.services = true,
            |p: &mut NativePermissions| p.drivers = true,
            |p: &mut NativePermissions| p.shell_extensions = true,
        ] {
            let mut m = manifest();
            set_permission(&mut m.permissions);
            assert!(validate_manifest(&m).is_err());
        }
    }

    #[test]
    fn rejects_forbidden_script_and_installer_files() {
        for path in [
            "install.ps1",
            "install.bat",
            "install.cmd",
            "payload.msi",
            "setup.exe",
            "nested/installer.exe",
        ] {
            let files = vec![NativeFile {
                path: path.to_string(),
                sha256: sha(),
            }];
            assert!(
                reject_forbidden_files(&files).is_err(),
                "{path} should be blocked"
            );
        }
    }

    #[test]
    fn rejects_path_traversal_and_backslashes() {
        assert!(validate_relative_path("../escape.exe").is_err());
        assert!(validate_relative_path("nested\\app.exe").is_err());
        assert!(validate_relative_path("nested/app.exe").is_ok());
    }
}
