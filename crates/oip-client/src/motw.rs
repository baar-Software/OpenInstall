//! Mark-of-the-Web writer (brief Â§1.4, Â§3 step 10).
//!
//! Every payload written to disk before launch gets the NTFS `Zone.Identifier`
//! alternate data stream with `ZoneId=3` (Internet). This is what makes Windows
//! Windows treat the file as downloaded-from-the-internet. We
//! NEVER strip it. We also record the source URL as `HostUrl` for transparency.

use std::io;
use std::path::Path;

/// Write the `Zone.Identifier` ADS marking `path` as Internet-zone (`ZoneId=3`).
///
/// Implemented by opening the NTFS alternate data stream `"<path>:Zone.Identifier"`
/// as an ordinary file â€” no extra crates required.
pub fn write_mark_of_the_web(path: &Path, source_url: &str) -> io::Result<()> {
    let mut ads = path.as_os_str().to_os_string();
    ads.push(":Zone.Identifier");

    // Sanitize the URL onto a single line (defensive; URLs shouldn't contain
    // newlines, but never let one break the ADS format).
    let host_url: String = source_url
        .chars()
        .filter(|c| *c != '\r' && *c != '\n')
        .collect();

    let content = format!("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={host_url}\r\n");
    std::fs::write(&ads, content)
}

/// Read back the `Zone.Identifier` stream (used by tests / diagnostics).
#[cfg(test)]
pub fn read_zone_identifier(path: &Path) -> io::Result<String> {
    let mut ads = path.as_os_str().to_os_string();
    ads.push(":Zone.Identifier");
    std::fs::read_to_string(&ads)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_zone_id_3() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Setup.exe");
        std::fs::write(&file, b"installer bytes").unwrap();

        write_mark_of_the_web(&file, "https://coolapp.dev/download/coolapp-1.4.2.oip").unwrap();

        let zone = read_zone_identifier(&file).unwrap();
        assert!(zone.contains("[ZoneTransfer]"), "got: {zone}");
        assert!(zone.contains("ZoneId=3"), "got: {zone}");
        assert!(zone.contains("HostUrl=https://coolapp.dev/"), "got: {zone}");
    }

    #[test]
    fn motw_survives_independently_of_payload_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.msi");
        std::fs::write(&file, vec![0u8; 1024]).unwrap();
        write_mark_of_the_web(&file, "https://example.com/a.oip").unwrap();
        assert!(read_zone_identifier(&file).unwrap().contains("ZoneId=3"));
        // The primary stream is unchanged.
        assert_eq!(std::fs::read(&file).unwrap().len(), 1024);
    }
}
