//! Registry of apps installed through OpenInstall
//! (`%APPDATA%\OpenInstall\installed.json`), powering the in-app launchpad.
//!
//! This is a *record* of what OpenInstall installed and from where — it does not
//! own the third-party app's files. For launching, we do a best-effort lookup of
//! the app's Start Menu shortcut (which the app's own installer created) and run
//! that, exactly as if the user clicked it in the Start Menu.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use oip_core::TrustLevel;
use serde::{Deserialize, Serialize};

use crate::paths::data_dir;

const INSTALLED_FILE: &str = "installed.json";

/// One installed app, as shown in the launchpad grid.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApp {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub version: String,
    #[serde(default)]
    pub homepage: String,
    /// The https/openinstall source the package came from (for "check updates").
    #[serde(default)]
    pub source_url: String,
    /// Trust level at install time.
    pub trust: TrustLevel,
    #[serde(default)]
    pub key_fingerprint: String,
    /// Unix-seconds timestamp of the (latest) install.
    #[serde(default)]
    pub installed_at: String,
    /// Best-effort path to a Start Menu `.lnk` for launching. `None` if not found.
    #[serde(default)]
    pub launch_target: Option<String>,
    /// Full path to the installed entry-point file (direct launch / icon source).
    #[serde(default)]
    pub entry_path: Option<String>,
    /// The app's real icon as a `data:image/png;base64,…` URL, captured at install.
    #[serde(default)]
    pub icon: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct InstalledFile {
    #[serde(default)]
    apps: Vec<InstalledApp>,
}

fn read_file() -> InstalledFile {
    let Some(path) = data_dir().map(|d| d.join(INSTALLED_FILE)) else {
        return InstalledFile::default();
    };
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => InstalledFile::default(),
    }
}

fn write_file(file: &InstalledFile) -> Result<()> {
    let base = data_dir().ok_or_else(|| anyhow!("no data directory available"))?;
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    let path = base.join(INSTALLED_FILE);
    let json = serde_json::to_vec_pretty(file).context("serializing installed.json")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// All installed apps, most recently installed first. Fast: never spawns icon
/// extraction, so the launchpad paints instantly. Icons captured at install time
/// are returned as-is; missing ones are filled by [`backfill_icons`].
pub fn list() -> Vec<InstalledApp> {
    let mut apps = read_file().apps;
    apps.sort_by(|a, b| b.installed_at.cmp(&a.installed_at));
    apps
}

/// Fill in a real icon for any app that doesn't have one yet (e.g. installed
/// before icon capture existed) by extracting it from the entry-point file or the
/// Start Menu shortcut, cache it, and return the updated list. This may spawn
/// PowerShell, so it runs as a background step AFTER the launchpad has painted.
pub fn backfill_icons() -> Vec<InstalledApp> {
    let mut file = read_file();
    let mut changed = false;
    for app in &mut file.apps {
        if app.icon.is_some() {
            continue;
        }
        let source = app
            .entry_path
            .as_deref()
            .filter(|p| Path::new(p).exists())
            .or_else(|| {
                app.launch_target
                    .as_deref()
                    .filter(|p| Path::new(p).exists())
            });
        if let Some(src) = source {
            if let Some(icon) = crate::icon::extract_icon_data_url(Path::new(src)) {
                app.icon = Some(icon);
                changed = true;
            }
        }
    }
    if changed {
        let _ = write_file(&file);
    }
    let mut apps = file.apps;
    apps.sort_by(|a, b| b.installed_at.cmp(&a.installed_at));
    apps
}

/// Record (upsert by id) an installed app.
pub fn record(app: InstalledApp) -> Result<()> {
    let mut file = read_file();
    if let Some(slot) = file.apps.iter_mut().find(|a| a.id == app.id) {
        *slot = app;
    } else {
        file.apps.push(app);
    }
    write_file(&file)
}

/// Remove an app from the launchpad list (does NOT uninstall the app).
pub fn forget(id: &str) -> Result<()> {
    let mut file = read_file();
    let before = file.apps.len();
    file.apps.retain(|a| a.id != id);
    if file.apps.len() == before {
        bail!("no installed app with id `{id}`");
    }
    write_file(&file)
}

/// Launch an installed app via its (re-)discovered Start Menu shortcut.
pub fn launch(id: &str) -> Result<()> {
    let mut file = read_file();
    let app = file
        .apps
        .iter_mut()
        .find(|a| a.id == id)
        .ok_or_else(|| anyhow!("no installed app with id `{id}`"))?;

    // Prefer the stored target if it still exists, else re-discover by name.
    let target = match &app.launch_target {
        Some(t) if Path::new(t).exists() => t.clone(),
        _ => {
            let found = find_launch_target(&app.name).ok_or_else(|| {
                anyhow!(
                    "couldn't find a Start Menu shortcut to launch `{}`",
                    app.name
                )
            })?;
            app.launch_target = Some(found.clone());
            let _ = write_file(&file); // best-effort cache update
            found
        }
    };

    launch_shortcut(&target)
}

/// ShellExecute-equivalent: open a `.lnk` (or any path) with its default handler,
/// detached. `cmd /C start "" "<target>"` runs the shortcut as the user would.
fn launch_shortcut(target: &str) -> Result<()> {
    std::process::Command::new("cmd")
        .args(["/C", "start", "", target])
        .spawn()
        .with_context(|| format!("launching {target}"))?;
    Ok(())
}

/// Best-effort search of the user and machine Start Menu for a `.lnk` whose name
/// matches `app_name`. Prefers an exact (case-insensitive) stem match, then a
/// contains-match. Bounded recursion.
pub fn find_launch_target(app_name: &str) -> Option<String> {
    let needle = app_name.trim().to_lowercase();
    if needle.is_empty() {
        return None;
    }

    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(pd) = std::env::var("ProgramData") {
        roots.push(PathBuf::from(pd).join("Microsoft/Windows/Start Menu/Programs"));
    }
    if let Ok(ad) = std::env::var("APPDATA") {
        roots.push(PathBuf::from(ad).join("Microsoft/Windows/Start Menu/Programs"));
    }

    let mut exact: Option<String> = None;
    let mut contains: Option<String> = None;
    for root in roots {
        collect_lnks(&root, 0, &needle, &mut exact, &mut contains);
        if exact.is_some() {
            break;
        }
    }
    exact.or(contains)
}

fn collect_lnks(
    dir: &Path,
    depth: usize,
    needle: &str,
    exact: &mut Option<String>,
    contains: &mut Option<String>,
) {
    if depth > 4 || exact.is_some() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_lnks(&path, depth + 1, needle, exact, contains);
            if exact.is_some() {
                return;
            }
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("lnk"))
            == Some(true)
        {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                let stem_l = stem.to_lowercase();
                if stem_l == *needle {
                    *exact = Some(path.to_string_lossy().into_owned());
                    return;
                }
                if contains.is_none() && (stem_l.contains(needle) || needle.contains(&stem_l)) {
                    *contains = Some(path.to_string_lossy().into_owned());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_list_forget_roundtrip() {
        let _guard = crate::paths::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("OPENINSTALL_DATA_DIR", dir.path());

        assert!(list().is_empty());
        record(InstalledApp {
            id: "com.example.app".into(),
            name: "App".into(),
            publisher: "Dev".into(),
            version: "1.0.0".into(),
            homepage: String::new(),
            source_url: "https://example.com/app.oip".into(),
            trust: TrustLevel::VerifiedNewPublisher,
            key_fingerprint: "RWabc…".into(),
            installed_at: "1700000000".into(),
            launch_target: None,
            entry_path: None,
            icon: None,
        })
        .unwrap();

        let apps = list();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, "com.example.app");
        assert_eq!(apps[0].trust, TrustLevel::VerifiedNewPublisher);

        // Upsert (same id) replaces, doesn't duplicate.
        record(InstalledApp {
            version: "2.0.0".into(),
            ..apps[0].clone()
        })
        .unwrap();
        let apps = list();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].version, "2.0.0");

        forget("com.example.app").unwrap();
        assert!(list().is_empty());
        assert!(forget("com.example.app").is_err());

        std::env::remove_var("OPENINSTALL_DATA_DIR");
    }
}
