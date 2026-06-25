//! One-shot payload inspection: write the payload to a private temp file once,
//! run a read-only Authenticode check, and delete the temp file. The temp file is
//! never executed.

use crate::authenticode;

pub struct ScanReport {
    /// `"signed:<signer>" | "unsigned" | "invalid:<status>" | "unavailable"`.
    pub authenticode: String,
}

impl ScanReport {
    fn unavailable() -> Self {
        ScanReport {
            authenticode: "unavailable".to_string(),
        }
    }
}

/// Inspect payload bytes off the async runtime.
pub async fn inspect_payload(file_name: &str, bytes: &[u8]) -> ScanReport {
    let bytes = bytes.to_vec();
    let file_name = file_name.to_string();
    tokio::task::spawn_blocking(move || {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(_) => return ScanReport::unavailable(),
        };
        let name = if file_name.is_empty() {
            "payload.bin"
        } else {
            file_name.as_str()
        };
        let path = dir.path().join(name);
        if std::fs::write(&path, &bytes).is_err() {
            return ScanReport::unavailable();
        }
        ScanReport {
            authenticode: authenticode::check_file(&path),
        }
        // `dir` drops here, deleting the temp file.
    })
    .await
    .unwrap_or_else(|_| ScanReport::unavailable())
}
