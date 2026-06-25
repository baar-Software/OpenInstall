//! Read a Windows executable's version-resource metadata (ProductName,
//! CompanyName, version) so the package author can pre-fill name / publisher /
//! version automatically. Best-effort via PowerShell; missing fields come back
//! empty.

use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct ExeInfo {
    pub product_name: String,
    pub company: String,
    pub version: String,
}

/// Read version info from a `.exe`/`.dll`. Returns empty fields on any failure.
pub fn read(path: &Path) -> ExeInfo {
    let script = r#"$ErrorActionPreference='SilentlyContinue'
$v = (Get-Item -LiteralPath $env:OI_EXE).VersionInfo
Write-Output ("NAME=" + $v.ProductName)
Write-Output ("PUB=" + $v.CompanyName)
$ver = $v.ProductVersion
if ([string]::IsNullOrWhiteSpace($ver)) { $ver = $v.FileVersion }
Write-Output ("VER=" + $ver)"#;

    let mut info = ExeInfo::default();
    let Ok(out) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("OI_EXE", path)
        .output()
    else {
        return info;
    };
    if !out.status.success() {
        return info;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("NAME=") {
            info.product_name = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("PUB=") {
            info.company = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("VER=") {
            info.version = clean_version(v.trim());
        }
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
}
