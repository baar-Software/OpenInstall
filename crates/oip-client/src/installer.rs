//! Launching the verified installer (brief Â§3 step 10).
//!
//! Only ever called from `confirm_install`, i.e. after the user clicked Install
//! on a fully verified package. The payload has already been written to disk WITH
//! Mark-of-the-Web. We let it run (Windows security apply normally) and
//! report the outcome.

use std::path::Path;

use anyhow::{Context, Result};
use oip_core::PayloadType;

/// Result of running an installer.
pub struct InstallOutcome {
    pub success: bool,
    pub exit_code: Option<i32>,
}

/// Run the installer and wait for it to finish.
///
/// * `exe` payloads are run directly with their `silent_args`.
/// * `msi` payloads are run via `msiexec /i <path>` plus `silent_args`.
pub async fn run(
    path: &Path,
    payload_type: PayloadType,
    silent_args: &str,
) -> Result<InstallOutcome> {
    let mut cmd = match payload_type {
        PayloadType::Exe => tokio::process::Command::new(path),
        PayloadType::Msi => {
            let mut c = tokio::process::Command::new("msiexec");
            c.arg("/i").arg(path);
            c
        }
    };

    for arg in split_args(silent_args) {
        cmd.arg(arg);
    }

    let status = cmd
        .status()
        .await
        .with_context(|| format!("failed to launch installer {}", path.display()))?;

    Ok(InstallOutcome {
        success: status.success(),
        exit_code: status.code(),
    })
}

/// Split an argument string on whitespace, honoring simple double-quoted spans.
/// Sufficient for typical installer switches (e.g. `/S`, `/qn /norestart`).
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_simple_args() {
        assert_eq!(split_args("/S"), vec!["/S"]);
        assert_eq!(split_args("/qn /norestart"), vec!["/qn", "/norestart"]);
        assert!(split_args("").is_empty());
        assert!(split_args("   ").is_empty());
    }

    #[test]
    fn honors_quotes() {
        assert_eq!(
            split_args(r#"/DIR="C:\Program Files\App" /S"#),
            vec![r"/DIR=C:\Program Files\App", "/S"]
        );
    }
}
