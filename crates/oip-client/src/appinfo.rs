//! Read a Windows executable's version-resource metadata (ProductName,
//! CompanyName, version) so the package author can pre-fill name / publisher /
//! version automatically.
//!
//! This parses the PE file's version resource **in-process** with the pure-Rust
//! `pelite` crate — no PowerShell, no child processes. Best-effort: any missing
//! field (or a non-PE / unreadable file) comes back empty.

use std::path::Path;

use pelite::{FileMap, PeFile};

#[derive(Debug, Clone, Default)]
pub struct ExeInfo {
    pub product_name: String,
    pub company: String,
    pub version: String,
}

/// Read version info from a `.exe`/`.dll`. Returns empty fields on any failure.
pub fn read(path: &Path) -> ExeInfo {
    let mut info = ExeInfo::default();
    let Ok(map) = FileMap::open(path) else {
        return info;
    };
    let Ok(pe) = PeFile::from_bytes(map.as_ref()) else {
        return info;
    };
    let Ok(resources) = pe.resources() else {
        return info;
    };
    let Ok(version) = resources.version_info() else {
        return info;
    };

    // Use the first language/codepage the file declares (the common case).
    let Some(lang) = version.translation().first().copied() else {
        return info;
    };
    if let Some(v) = version.value(lang, "ProductName") {
        info.product_name = v.trim().to_string();
    }
    if let Some(v) = version.value(lang, "CompanyName") {
        info.company = v.trim().to_string();
    }
    let ver = version
        .value(lang, "ProductVersion")
        .filter(|s| !s.trim().is_empty())
        .or_else(|| version.value(lang, "FileVersion"));
    if let Some(v) = ver {
        info.version = clean_version(v.trim());
    }
    info
}

/// Normalize a version string to a leading dotted-number token (e.g.
/// "3.0.20.0 (built …)" -> "3.0.20.0"). Falls back to the trimmed input.
fn clean_version(s: &str) -> String {
    let token: String = s
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let token = token.trim_matches('.');
    if token.is_empty() {
        s.trim().to_string()
    } else {
        token.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_version_strings() {
        assert_eq!(clean_version("3.0.20.0"), "3.0.20.0");
        assert_eq!(clean_version("  1.2.3 (build 99) "), "1.2.3");
        assert_eq!(clean_version("v2"), "v2"); // no leading digits -> fallback
        assert_eq!(clean_version("..1.0.."), "1.0");
    }

    #[test]
    fn missing_or_non_pe_file_returns_empty() {
        let info = read(Path::new("this-file-does-not-exist.exe"));
        assert!(info.product_name.is_empty());
        assert!(info.company.is_empty());
        assert!(info.version.is_empty());
    }
}
