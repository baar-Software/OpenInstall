//! OpenInstall repository catalogs.
//!
//! A repo is a user-imported HTTPS base URL with a `repo.json` catalog. Catalogs
//! are discovery metadata only: install URLs are derived from the repo base,
//! bundle identifier, and selected version, then resolved through the normal
//! verify -> consent pipeline.

use std::collections::HashSet;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::paths::data_dir;

const REPO_SOURCES_FILE: &str = "repo-sources.json";
const MAX_REPO_JSON_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoSource {
    pub url: String,
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoCatalog {
    pub source_url: String,
    pub manifest_url: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub apps: Vec<RepoApp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoApp {
    pub bundle_identifier: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub icon_url: String,
    #[serde(default)]
    pub screenshot_urls: Vec<String>,
    #[serde(default)]
    pub latest: String,
    #[serde(default)]
    pub versions: Vec<RepoVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoVersion {
    pub version: String,
    pub install_url: String,
    pub is_latest: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCatalog {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    apps: Vec<RawApp>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawApp {
    #[serde(alias = "bundle_identifier", alias = "id")]
    bundle_identifier: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(
        default,
        alias = "screenshots",
        alias = "screenshotUrls",
        alias = "screenshot_urls",
        alias = "screenshotFiles",
        alias = "screenshot_files"
    )]
    screenshot_files: Vec<String>,
    #[serde(default)]
    latest: String,
    #[serde(default)]
    versions: Vec<RawVersion>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawVersion {
    String(String),
    Object {
        version: String,
        #[serde(default)]
        latest: bool,
    },
}

pub fn list_sources() -> Vec<RepoSource> {
    let Some(path) = data_dir().map(|d| d.join(REPO_SOURCES_FILE)) else {
        return Vec::new();
    };
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn add_source(url: &str, allow_localhost: bool) -> Result<Vec<RepoSource>> {
    let normalized = normalize_base_url(url, allow_localhost)?;
    let mut sources = list_sources();
    if !sources.iter().any(|s| s.url == normalized) {
        sources.push(RepoSource {
            url: normalized,
            added_at: unix_now_string(),
        });
        save_sources(&sources)?;
    }
    Ok(sources)
}

pub fn remove_source(url: &str) -> Result<Vec<RepoSource>> {
    let mut sources = list_sources();
    sources.retain(|s| s.url != url);
    save_sources(&sources)?;
    Ok(sources)
}

pub async fn fetch_catalog(url: &str, allow_localhost: bool) -> Result<RepoCatalog> {
    let base = normalize_base_url(url, allow_localhost)?;
    let manifest_url = repo_manifest_url(&base)?;
    let bytes = crate::resolver::download(std::slice::from_ref(&manifest_url), MAX_REPO_JSON_BYTES)
        .await
        .map_err(|e| anyhow!("repo download failed: {e}"))?;
    parse_catalog(&base, &manifest_url, &bytes)
}

pub fn looks_like_bundle_reference(input: &str) -> bool {
    let trimmed = input.trim();
    let Some(rest) = trimmed.strip_prefix("openinstall://") else {
        return false;
    };
    !rest.contains('/') && rest.contains('.') && validate_bundle_identifier(rest).is_ok()
}

pub async fn resolve_bundle_reference(input: &str, allow_localhost: bool) -> Result<String> {
    let bundle_identifier = input
        .trim()
        .strip_prefix("openinstall://")
        .ok_or_else(|| anyhow!("URL must use the openinstall:// scheme"))?;
    validate_bundle_identifier(bundle_identifier)?;

    let sources = list_sources();
    if sources.is_empty() {
        bail!("no OpenInstall repos have been imported");
    }

    let mut matches = Vec::new();
    let mut failed_sources = 0usize;
    for source in sources {
        let catalog = match fetch_catalog(&source.url, allow_localhost).await {
            Ok(catalog) => catalog,
            Err(_) => {
                failed_sources += 1;
                continue;
            }
        };
        if let Some(app) = catalog
            .apps
            .iter()
            .find(|app| app.bundle_identifier == bundle_identifier)
        {
            if let Some(version) = app
                .versions
                .iter()
                .find(|version| version.is_latest)
                .or_else(|| app.versions.first())
            {
                matches.push((catalog.source_url.clone(), version.install_url.clone()));
            }
        }
    }

    match matches.len() {
        0 if failed_sources > 0 => bail!(
            "app `{bundle_identifier}` was not found; {failed_sources} imported repo(s) could not be refreshed"
        ),
        0 => bail!("app `{bundle_identifier}` was not found in imported OpenInstall repos"),
        1 => Ok(matches.remove(0).1),
        _ => {
            let sources = matches
                .into_iter()
                .map(|(source, _)| source)
                .collect::<Vec<_>>()
                .join(", ");
            bail!("app `{bundle_identifier}` exists in multiple imported repos: {sources}")
        }
    }
}

pub fn parse_catalog(base_url: &str, manifest_url: &str, bytes: &[u8]) -> Result<RepoCatalog> {
    let raw: RawCatalog = serde_json::from_slice(bytes).context("parsing repo.json")?;
    let base = base_dir_url(base_url)?;
    let name = if raw.name.trim().is_empty() {
        base.host_str().unwrap_or("OpenInstall repo").to_string()
    } else {
        raw.name.trim().to_string()
    };

    let mut apps = Vec::with_capacity(raw.apps.len());
    let mut app_ids = HashSet::new();
    for app in raw.apps {
        let bundle_identifier = app.bundle_identifier.trim().to_string();
        validate_bundle_identifier(&bundle_identifier)?;
        if !app_ids.insert(bundle_identifier.clone()) {
            bail!("repo contains duplicate app `{bundle_identifier}`");
        }
        let app_name = app.name.trim().to_string();
        if app_name.is_empty() {
            bail!("app `{bundle_identifier}` has an empty name");
        }
        let latest = selected_latest(&app)?;
        let mut versions = Vec::with_capacity(app.versions.len());
        let mut version_names = HashSet::new();
        for raw_version in app.versions {
            let (version, flagged_latest) = match raw_version {
                RawVersion::String(version) => (version, false),
                RawVersion::Object { version, latest } => (version, latest),
            };
            let version = version.trim().to_string();
            validate_version(&version)?;
            if !version_names.insert(version.clone()) {
                bail!("app `{bundle_identifier}` contains duplicate version `{version}`");
            }
            let is_latest = version == latest || flagged_latest;
            versions.push(RepoVersion {
                install_url: package_openinstall_url(&base, &bundle_identifier, &version)?,
                version,
                is_latest,
            });
        }
        if versions.iter().filter(|v| v.is_latest).count() != 1 {
            bail!("app `{bundle_identifier}` must identify exactly one latest version");
        }

        let icon_url = app_icon_url(&base, &bundle_identifier)?;
        let screenshot_urls = app
            .screenshot_files
            .iter()
            .map(|file| app_screenshot_url(&base, &bundle_identifier, file))
            .collect::<Result<Vec<_>>>()?;

        apps.push(RepoApp {
            bundle_identifier,
            name: app_name,
            description: app.description.trim().to_string(),
            icon_url,
            screenshot_urls,
            latest,
            versions,
        });
    }

    Ok(RepoCatalog {
        source_url: base_url.to_string(),
        manifest_url: manifest_url.to_string(),
        name,
        description: raw.description,
        apps,
    })
}

pub fn repo_manifest_url(base_url: &str) -> Result<String> {
    let mut url = base_dir_url(base_url)?;
    push_path_segment(&mut url, "repo.json")?;
    Ok(url.to_string())
}

fn save_sources(sources: &[RepoSource]) -> Result<()> {
    let base = data_dir().ok_or_else(|| anyhow!("no data directory available"))?;
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    let path = base.join(REPO_SOURCES_FILE);
    let json = serde_json::to_vec_pretty(sources).context("serializing repo sources")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn normalize_base_url(input: &str, allow_localhost: bool) -> Result<String> {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("repo URL is empty");
    }

    let resolved = if trimmed.starts_with("openinstall://") {
        crate::resolver::resolve_url_with_policy(trimmed, allow_localhost)?
    } else {
        let url = Url::parse(trimmed).map_err(|e| anyhow!("invalid repo URL: {e}"))?;
        let host = url
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| anyhow!("repo URL has no host"))?;
        if !url.username().is_empty() || url.password().is_some() {
            bail!("repo URL must not contain credentials");
        }
        if url.scheme() != "https"
            && !(allow_localhost && is_loopback(host) && url.scheme() == "http")
        {
            bail!("repo URL must be https");
        }
        if is_loopback(host) && !allow_localhost {
            bail!("localhost / loopback repo URLs require Developer Mode");
        }
        url.to_string()
    };

    Ok(resolved.trim_end_matches('/').to_string())
}

fn selected_latest(app: &RawApp) -> Result<String> {
    if !app.latest.trim().is_empty() {
        let latest = app.latest.trim().to_string();
        validate_version(&latest)?;
        return Ok(latest);
    }
    let mut flagged = app.versions.iter().filter_map(|v| match v {
        RawVersion::Object {
            version,
            latest: true,
        } => Some(version.clone()),
        _ => None,
    });
    if let Some(version) = flagged.next() {
        validate_version(&version)?;
        return Ok(version);
    }
    match app.versions.first() {
        Some(RawVersion::String(version)) => {
            validate_version(version)?;
            Ok(version.clone())
        }
        Some(RawVersion::Object { version, .. }) => {
            validate_version(version)?;
            Ok(version.clone())
        }
        None => bail!("app `{}` has no versions", app.bundle_identifier),
    }
}

fn package_openinstall_url(base: &Url, bundle_identifier: &str, version: &str) -> Result<String> {
    let mut url = base.clone();
    push_path_segment(&mut url, bundle_identifier)?;
    push_path_segment(&mut url, &format!("{version}.oip"))?;
    let package_url = url.to_string();
    let Some((_, rest)) = package_url.split_once("://") else {
        bail!("could not build package URL");
    };
    Ok(format!("openinstall://{rest}"))
}

fn app_icon_url(base: &Url, bundle_identifier: &str) -> Result<String> {
    let mut url = base.clone();
    push_path_segment(&mut url, bundle_identifier)?;
    push_path_segment(&mut url, "assets")?;
    push_path_segment(&mut url, "icon.png")?;
    Ok(url.to_string())
}

fn app_screenshot_url(base: &Url, bundle_identifier: &str, file_name: &str) -> Result<String> {
    let file_name = file_name.trim();
    validate_asset_file_name(file_name)?;
    let mut url = base.clone();
    push_path_segment(&mut url, bundle_identifier)?;
    push_path_segment(&mut url, "screenshots")?;
    push_path_segment(&mut url, file_name)?;
    Ok(url.to_string())
}

fn base_dir_url(base_url: &str) -> Result<Url> {
    let mut url = Url::parse(base_url).context("invalid repo base URL")?;
    if !url.path().ends_with('/') {
        let path = url.path().trim_end_matches('/');
        url.set_path(&format!("{path}/"));
    }
    Ok(url)
}

fn push_path_segment(url: &mut Url, segment: &str) -> Result<()> {
    url.path_segments_mut()
        .map_err(|_| anyhow!("URL cannot be a base path"))?
        .pop_if_empty()
        .push(segment);
    Ok(())
}

fn validate_bundle_identifier(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("bundle identifier is empty");
    }
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        bail!("bundle identifier `{value}` contains unsupported characters");
    }
}

fn validate_version(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("version is empty");
    }
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        bail!("version `{value}` contains unsupported characters");
    }
}

fn validate_asset_file_name(value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("screenshot file name is empty");
    }
    if value.contains('/') || value.contains('\\') || value == "." || value == ".." {
        bail!("screenshot file name `{value}` must be a bare file name");
    }
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        bail!("screenshot file name `{value}` contains unsupported characters");
    }
}

fn is_loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    matches!(h, "localhost" | "127.0.0.1" | "::1")
        || h.ends_with(".localhost")
        || h.starts_with("127.")
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
    fn parses_catalog_and_derives_install_urls() {
        let json = br#"{
          "name": "Example Repo",
          "apps": [{
            "bundleIdentifier": "com.example.coolapp",
            "name": "CoolApp",
            "description": "A useful app",
            "screenshots": ["one.png"],
            "latest": "latest",
            "versions": ["latest", "1.0.0"]
          }]
        }"#;

        let catalog = parse_catalog(
            "https://example.com/openinstall",
            "https://example.com/openinstall/repo.json",
            json,
        )
        .unwrap();
        let app = &catalog.apps[0];
        assert_eq!(
            app.icon_url,
            "https://example.com/openinstall/com.example.coolapp/assets/icon.png"
        );
        assert_eq!(
            app.screenshot_urls[0],
            "https://example.com/openinstall/com.example.coolapp/screenshots/one.png"
        );
        assert_eq!(app.latest, "latest");
        assert_eq!(
            app.versions[0].install_url,
            "openinstall://example.com/openinstall/com.example.coolapp/latest.oip"
        );
        assert!(app.versions[0].is_latest);
    }

    #[test]
    fn rejects_latest_that_is_not_a_version() {
        let json = br#"{
          "apps": [{
            "bundleIdentifier": "com.example.coolapp",
            "name": "CoolApp",
            "latest": "2.0.0",
            "versions": ["1.0.0"]
          }]
        }"#;

        let err = parse_catalog(
            "https://example.com/repo",
            "https://example.com/repo/repo.json",
            json,
        )
        .expect_err("latest must point at exactly one version");
        assert!(err.to_string().contains("latest"));
    }

    #[test]
    fn rejects_duplicate_apps_and_versions() {
        let dup_apps = br#"{
          "apps": [
            {"bundleIdentifier": "com.example.coolapp", "name": "A", "versions": ["latest"]},
            {"bundleIdentifier": "com.example.coolapp", "name": "B", "versions": ["latest"]}
          ]
        }"#;
        assert!(parse_catalog(
            "https://example.com/repo",
            "https://example.com/repo/repo.json",
            dup_apps
        )
        .expect_err("duplicate apps must fail")
        .to_string()
        .contains("duplicate app"));

        let dup_versions = br#"{
          "apps": [{
            "bundleIdentifier": "com.example.coolapp",
            "name": "CoolApp",
            "versions": ["1.0.0", "1.0.0"]
          }]
        }"#;
        assert!(parse_catalog(
            "https://example.com/repo",
            "https://example.com/repo/repo.json",
            dup_versions
        )
        .expect_err("duplicate versions must fail")
        .to_string()
        .contains("duplicate version"));
    }

    #[test]
    fn rejects_nested_screenshot_paths() {
        let json = br#"{
          "apps": [{
            "bundleIdentifier": "com.example.coolapp",
            "name": "CoolApp",
            "screenshots": ["nested/one.png"],
            "versions": ["latest"]
          }]
        }"#;

        assert!(parse_catalog(
            "https://example.com/repo",
            "https://example.com/repo/repo.json",
            json
        )
        .expect_err("screenshot paths must be bare file names")
        .to_string()
        .contains("bare file name"));
    }

    #[test]
    fn detects_bundle_references() {
        assert!(looks_like_bundle_reference(
            "openinstall://com.baar-verlag.baar-reader"
        ));
        assert!(!looks_like_bundle_reference(
            "openinstall://example.com/openinstall/app.oip"
        ));
    }

    #[test]
    fn persists_sources_without_duplicates() {
        let _guard = crate::paths::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("OPENINSTALL_DATA_DIR", dir.path());

        add_source("https://example.com/repo/", false).unwrap();
        add_source("https://example.com/repo", false).unwrap();
        assert_eq!(list_sources().len(), 1);

        remove_source("https://example.com/repo").unwrap();
        assert!(list_sources().is_empty());

        std::env::remove_var("OPENINSTALL_DATA_DIR");
    }
}
