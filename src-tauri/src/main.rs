// Prevent an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! OpenInstall — Tauri shell.
//!
//! Thin layer wiring commands to the Tauri runtime. ALL verification, consent,
//! install, packaging, and persistence logic lives in `oip-client` / `oip-pack` /
//! `oip-core`. There is no silent-install path here or there.
//!
//! Commands:
//!   resolve_oip / acknowledge_risk / confirm_install   — the verify→consent→install flow
//!   get_settings / set_developer_mode                  — opt-in localhost (dev mode)
//!   list_installed / launch_app / forget_app           — the launchpad
//!   generate_keypair / build_package                   — the GUI native package author

use oip_client::registry::InstalledApp;
use oip_client::repo::{RepoCatalog, RepoSource};
use oip_client::{AppState, InstallResult, ResolveResult, Settings};
use serde::{Deserialize, Serialize};
use tauri::State;

// ---------------------------------------------------------------------------
// Verify → consent → install (brief §7). Unchanged contract.
// ---------------------------------------------------------------------------

#[tauri::command]
async fn resolve_oip(url: String, state: State<'_, AppState>) -> Result<ResolveResult, String> {
    oip_client::resolve(&url, state.inner()).await
}

#[tauri::command]
async fn acknowledge_risk(install_token: String, state: State<'_, AppState>) -> Result<(), String> {
    oip_client::acknowledge(&install_token, state.inner())
}

#[tauri::command]
async fn confirm_install(
    install_token: String,
    state: State<'_, AppState>,
) -> Result<InstallResult, String> {
    oip_client::confirm(&install_token, state.inner()).await
}

// ---------------------------------------------------------------------------
// Settings / Developer Mode (opt-in localhost).
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_settings() -> Settings {
    oip_client::settings::load()
}

#[tauri::command]
fn set_developer_mode(enabled: bool) -> Result<Settings, String> {
    let mut s = oip_client::settings::load();
    s.developer_mode = enabled;
    oip_client::settings::save(&s).map_err(|e| e.to_string())?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// Launchpad.
// ---------------------------------------------------------------------------

#[tauri::command]
fn list_installed() -> Vec<InstalledApp> {
    oip_client::registry::list()
}

#[tauri::command]
fn launch_app(id: String) -> Result<(), String> {
    oip_client::registry::launch(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn forget_app(id: String) -> Result<(), String> {
    oip_client::registry::forget(&id).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// OpenInstall repositories.
// ---------------------------------------------------------------------------

#[tauri::command]
fn list_repo_sources() -> Vec<RepoSource> {
    oip_client::repo::list_sources()
}

#[tauri::command]
async fn add_repo_source(url: String) -> Result<Vec<RepoSource>, String> {
    let dev_mode = oip_client::settings::load().developer_mode;
    oip_client::repo::fetch_catalog(&url, dev_mode)
        .await
        .map_err(|e| e.to_string())?;
    oip_client::repo::add_source(&url, dev_mode).map_err(|e| e.to_string())
}

#[tauri::command]
fn remove_repo_source(url: String) -> Result<Vec<RepoSource>, String> {
    oip_client::repo::remove_source(&url).map_err(|e| e.to_string())
}

#[tauri::command]
async fn fetch_repo(url: String) -> Result<RepoCatalog, String> {
    let dev_mode = oip_client::settings::load().developer_mode;
    oip_client::repo::fetch_catalog(&url, dev_mode)
        .await
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// GUI native package author.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeygenResult {
    public_key: String,
    secret_key_path: String,
    public_key_path: String,
}

/// Generate a minisign keypair, writing `<out_prefix>.key` and `<out_prefix>.pub`.
#[tauri::command]
fn generate_keypair(out_prefix: String, password: Option<String>) -> Result<KeygenResult, String> {
    // Treat an empty password as "no password" (unencrypted).
    let password = password.filter(|p| !p.is_empty());
    let kp = oip_pack::generate_keypair(password).map_err(|e| e.to_string())?;
    let sk_path = format!("{out_prefix}.key");
    let pk_path = format!("{out_prefix}.pub");
    std::fs::write(&sk_path, &kp.secret_key_box).map_err(|e| format!("writing {sk_path}: {e}"))?;
    std::fs::write(&pk_path, &kp.public_key_box).map_err(|e| format!("writing {pk_path}: {e}"))?;
    Ok(KeygenResult {
        public_key: kp.public_key_b64,
        secret_key_path: sk_path,
        public_key_path: pk_path,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageSpec {
    app_dir: String,
    output_path: String,
    id: String,
    name: String,
    publisher: String,
    version: String,
    #[serde(default)]
    homepage: String,
    #[serde(default)]
    entry: String,
    #[serde(default)]
    shortcut_name: String,
    #[serde(default)]
    network: bool,
    #[serde(default)]
    icon_path: String,
    /// Public key to embed (path to a `.pub` file or a bare `RW...`).
    public_key: String,
    /// Secret key file path. Native v1 packages are always signed.
    secret_key_path: String,
    password: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuildPackageResult {
    output_path: String,
    signed: bool,
    size: u64,
}

/// Build and sign a native v1 `.oip` from an app directory and metadata.
#[tauri::command]
fn build_package(spec: PackageSpec) -> Result<BuildPackageResult, String> {
    if spec.public_key.trim().is_empty() || spec.secret_key_path.trim().is_empty() {
        return Err("native v1 packages must be signed with a publisher keypair".to_string());
    }

    let public_key_text = read_pubkey_arg(&spec.public_key).map_err(|e| e.to_string())?;
    let sk_text = std::fs::read_to_string(&spec.secret_key_path)
        .map_err(|e| format!("reading secret key {}: {e}", spec.secret_key_path))?;
    let (files, inferred_entry) =
        collect_native_files(&spec.app_dir, &spec.output_path, &spec.icon_path)?;
    let meta = oip_pack::NativeManifestMeta {
        id: spec.id,
        name: spec.name,
        version: spec.version,
        publisher_name: spec.publisher,
        publisher_website: spec.homepage,
        entry: if spec.entry.trim().is_empty() {
            inferred_entry
        } else {
            spec.entry
        },
        network: spec.network,
        shortcut_name: spec.shortcut_name,
    };
    let password = spec.password.filter(|p| !p.is_empty());
    let oip = oip_pack::build_native_oip_bytes(&meta, &files, &public_key_text, &sk_text, password)
        .map_err(|e| e.to_string())?;

    std::fs::write(&spec.output_path, &oip)
        .map_err(|e| format!("writing {}: {e}", spec.output_path))?;

    Ok(BuildPackageResult {
        output_path: spec.output_path,
        signed: true,
        size: oip.len() as u64,
    })
}

fn collect_native_files(
    app_path: &str,
    output_path: &str,
    icon_path: &str,
) -> Result<(Vec<oip_pack::NativeFileInput>, String), String> {
    let source = std::path::Path::new(app_path);
    if !source.exists() {
        return Err(format!("{app_path} does not exist"));
    }
    let source = source
        .canonicalize()
        .map_err(|e| format!("resolving app source {app_path}: {e}"))?;
    let output = std::path::Path::new(output_path).canonicalize().ok();
    let mut files = Vec::new();
    let inferred_entry = if source.is_file() {
        let file_name = source
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "app executable has no file name".to_string())?
            .to_string();
        let bytes =
            std::fs::read(&source).map_err(|e| format!("reading {}: {e}", source.display()))?;
        files.push(oip_pack::NativeFileInput {
            path: file_name.clone(),
            bytes,
        });
        file_name
    } else if source.is_dir() {
        collect_native_files_inner(&source, &source, output.as_deref(), &mut files)?;
        files
            .iter()
            .find(|file| file.path.to_ascii_lowercase().ends_with(".exe"))
            .map(|file| file.path.clone())
            .unwrap_or_default()
    } else {
        return Err(format!("{app_path} is not a file or directory"));
    };
    if !icon_path.trim().is_empty() {
        let icon = std::path::Path::new(icon_path);
        let icon_bytes =
            std::fs::read(icon).map_err(|e| format!("reading icon {}: {e}", icon.display()))?;
        files.retain(|file| file.path != "assets/icon.png");
        files.push(oip_pack::NativeFileInput {
            path: "assets/icon.png".to_string(),
            bytes: icon_bytes,
        });
    }
    if files.is_empty() {
        return Err("app directory contains no packageable files".to_string());
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((files, inferred_entry))
}

fn collect_native_files_inner(
    root: &std::path::Path,
    dir: &std::path::Path,
    output: Option<&std::path::Path>,
    files: &mut Vec<oip_pack::NativeFileInput>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading {}: {e}", dir.display()))?;
        let path = entry.path();
        let ty = entry
            .file_type()
            .map_err(|e| format!("reading file type {}: {e}", path.display()))?;
        if ty.is_dir() {
            collect_native_files_inner(root, &path, output, files)?;
        } else if ty.is_file() {
            if output.is_some_and(|out| out == path) {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("making relative path for {}: {e}", path.display()))?
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let bytes =
                std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            files.push(oip_pack::NativeFileInput { path: rel, bytes });
        }
    }
    Ok(())
}

/// Fill in real icons for installed apps that lack one (runs after the launchpad
/// has painted, so it never blocks the first render).
#[tauri::command]
fn backfill_icons() -> Vec<InstalledApp> {
    oip_client::registry::backfill_icons()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppSourceInfo {
    suggested_entry: String,
    file_count: u32,
    name: String,
    publisher: String,
    version: String,
}

/// Inspect an app folder (or a single `.exe`) the user picked in Create, so the
/// form can auto-fill the entry, name, publisher, and version from the app's own
/// version info. Best-effort; the user can edit anything.
#[tauri::command]
fn inspect_app_source(path: String) -> Result<AppSourceInfo, String> {
    let src = std::path::Path::new(&path);
    if !src.exists() {
        return Err(format!("{path} does not exist"));
    }
    let (entry_rel, entry_full, file_count) = if src.is_file() {
        let name = src
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "executable has no file name".to_string())?
            .to_string();
        (name, src.to_path_buf(), 1u32)
    } else {
        let mut count = 0u32;
        let mut exes: Vec<String> = Vec::new();
        scan_app_dir(src, src, &mut count, &mut exes)?;
        if count == 0 {
            return Err("folder contains no files".to_string());
        }
        let entry_rel = pick_entry(&exes, src)
            .ok_or_else(|| "no .exe found in the folder — pick an entry executable".to_string())?;
        let full = src.join(entry_rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        (entry_rel, full, count)
    };

    let info = oip_client::appinfo::read(&entry_full);
    let stem = std::path::Path::new(&entry_rel)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("App")
        .to_string();
    Ok(AppSourceInfo {
        suggested_entry: entry_rel,
        file_count,
        name: if info.product_name.is_empty() {
            stem
        } else {
            info.product_name
        },
        publisher: info.company,
        version: if info.version.is_empty() {
            "1.0.0".to_string()
        } else {
            info.version
        },
    })
}

fn scan_app_dir(
    root: &std::path::Path,
    dir: &std::path::Path,
    count: &mut u32,
    exes: &mut Vec<String>,
) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path();
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        if ty.is_dir() {
            scan_app_dir(root, &p, count, exes)?;
        } else if ty.is_file() {
            *count += 1;
            let is_exe = p
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("exe"))
                == Some(true);
            if is_exe {
                if let Ok(rel) = p.strip_prefix(root) {
                    exes.push(
                        rel.components()
                            .map(|c| c.as_os_str().to_string_lossy().into_owned())
                            .collect::<Vec<_>>()
                            .join("/"),
                    );
                }
            }
        }
    }
    Ok(())
}

/// Choose the most likely entry `.exe`: a top-level exe whose name matches the
/// folder, else a top-level exe that isn't an obvious helper, else any exe.
fn pick_entry(exes: &[String], dir: &std::path::Path) -> Option<String> {
    if exes.is_empty() {
        return None;
    }
    let dir_name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let stem = |e: &str| {
        std::path::Path::new(e)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase()
    };
    let is_helper = |e: &str| {
        let l = e.to_lowercase();
        [
            "unins",
            "vcredist",
            "vc_redist",
            "setup",
            "crashpad",
            "update",
            "helper",
        ]
        .iter()
        .any(|h| l.contains(h))
    };
    let top: Vec<&String> = exes.iter().filter(|e| !e.contains('/')).collect();
    if !dir_name.is_empty() {
        if let Some(m) = top.iter().find(|e| stem(e) == dir_name) {
            return Some((*m).clone());
        }
    }
    if let Some(m) = top.iter().find(|e| !is_helper(e)) {
        return Some((*m).clone());
    }
    if let Some(m) = top.first() {
        return Some((*m).clone());
    }
    if let Some(m) = exes.iter().find(|e| !is_helper(e)) {
        return Some(m.clone());
    }
    exes.first().cloned()
}

/// A public-key argument is a path to a `.pub` file or a bare RW key.
fn read_pubkey_arg(arg: &str) -> std::io::Result<String> {
    let p = std::path::Path::new(arg);
    if p.exists() {
        std::fs::read_to_string(p)
    } else {
        Ok(arg.to_string())
    }
}

fn main() {
    tauri::Builder::default()
        // single-instance MUST be registered first: a second launch (the OS
        // invoking us for a deep link) forwards its argv to the running window.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            use tauri::{Emitter, Manager};
            if let Some(url) = argv.iter().find(|a| a.starts_with("openinstall://")) {
                // Deliver the URL to the UI; the handler NEVER auto-installs (#6).
                let _ = app.emit("deep-link-url", url.clone());
            }
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .setup(|app| {
            use tauri::Manager;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_decorations(true);
                let _ = window.set_fullscreen(false);
                let _ = window.maximize();
            }
            #[cfg(desktop)]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                // Register the scheme at runtime (needed for dev; the MSI registers
                // it at install time in production).
                let _ = app.deep_link().register("openinstall");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            resolve_oip,
            confirm_install,
            acknowledge_risk,
            get_settings,
            set_developer_mode,
            list_installed,
            launch_app,
            forget_app,
            list_repo_sources,
            add_repo_source,
            remove_repo_source,
            fetch_repo,
            generate_keypair,
            build_package,
            inspect_app_source,
            backfill_icons
        ])
        .run(tauri::generate_context!())
        .expect("error while running OpenInstall");
}
