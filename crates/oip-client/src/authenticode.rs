//! Read-only inspection of a payload's **Authenticode** (Windows code-signing)
//! status, surfaced in the consent dialog.
//!
//! This is purely informative. It does NOT change anything about how Windows
//! treats the file — OpenInstall never strips the Mark-of-the-Web and never
//! suppresses SmartScreen (invariants #4/#5). It just tells the user (and the
//! publisher) whether Windows SmartScreen is likely to warn on first run, and if
//! the installer is signed, by whom. The honest fix for a SmartScreen warning is
//! for the publisher to Authenticode-sign their installer (see docs/smartscreen.md).
//!
//! We shell out to PowerShell's `Get-AuthenticodeSignature` rather than add a
//! Win32 crypto dependency; if PowerShell can't run, the status is `unavailable`.

use std::path::Path;

/// Map a `Get-AuthenticodeSignature` `Status` + signer subject to the value shown
/// to the user. Forms:
///   `signed:<signer>`     valid Authenticode signature (SmartScreen-friendly once
///                         the cert has reputation)
///   `unsigned`            no signature (SmartScreen will warn on first run)
///   `invalid:<status>`    present but not valid/trusted (e.g. HashMismatch)
///   `unavailable`         couldn't determine
pub fn interpret(status: &str, subject: &str) -> String {
    match status.trim() {
        "Valid" => {
            let who = signer_name(subject);
            if who.is_empty() {
                "signed:unknown signer".to_string()
            } else {
                format!("signed:{who}")
            }
        }
        "NotSigned" => "unsigned".to_string(),
        "" => "unavailable".to_string(),
        other => format!("invalid:{other}"),
    }
}

/// Pull a human name out of an X.500 subject like `CN=Example Dev, O=Example, C=US`.
fn signer_name(subject: &str) -> String {
    for part in subject.split(',') {
        let p = part.trim();
        if let Some(cn) = p.strip_prefix("CN=") {
            return cn.trim().trim_matches('"').to_string();
        }
    }
    subject.trim().to_string()
}

/// Inspect a file on disk. Blocking (spawns PowerShell).
pub fn check_file(path: &Path) -> String {
    let script = r#"$ErrorActionPreference='SilentlyContinue'
$s = Get-AuthenticodeSignature -LiteralPath $env:OI_SCAN_FILE
$subj = ''
if ($s.SignerCertificate) { $subj = $s.SignerCertificate.Subject }
Write-Output ("STATUS=" + $s.Status)
Write-Output ("SUBJECT=" + $subj)"#;

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("OI_SCAN_FILE", path)
        .output();

    match output {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            let mut status = String::new();
            let mut subject = String::new();
            for line in text.lines() {
                if let Some(v) = line.strip_prefix("STATUS=") {
                    status = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("SUBJECT=") {
                    subject = v.trim().to_string();
                }
            }
            if status.is_empty() {
                "unavailable".to_string()
            } else {
                interpret(&status, &subject)
            }
        }
        Err(_) => "unavailable".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_extracts_cn() {
        assert_eq!(
            interpret("Valid", "CN=Example Dev, O=Example LLC, C=US"),
            "signed:Example Dev"
        );
    }

    #[test]
    fn not_signed_is_unsigned() {
        assert_eq!(interpret("NotSigned", ""), "unsigned");
    }

    #[test]
    fn hash_mismatch_is_invalid() {
        assert_eq!(interpret("HashMismatch", ""), "invalid:HashMismatch");
    }

    #[test]
    fn empty_status_is_unavailable() {
        assert_eq!(interpret("", ""), "unavailable");
    }

    #[test]
    fn valid_without_cn_uses_subject() {
        assert_eq!(interpret("Valid", "O=Example"), "signed:O=Example");
    }
}
