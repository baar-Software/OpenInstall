//! Extract an app's real Windows icon for display in the launchpad.
//!
//! Uses the shell's *associated* icon for the entry-point file, so it works for
//! any file type (an `.exe`'s embedded icon, or whatever icon Explorer shows for
//! the file). The icon is rendered to a PNG and returned as a `data:` URL the
//! frontend can drop straight into an `<img>`. Best-effort: returns `None` if the
//! icon can't be extracted, and the launchpad falls back to a lettermark.

use std::path::Path;

/// Extract the icon for `path` as a `data:image/png;base64,…` URL.
pub fn extract_icon_data_url(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let script = r#"$ErrorActionPreference = 'Stop'
try {
  $src = $env:OI_ICON_SRC
  # If given a shortcut, extract the icon from its target so we get the clean app
  # icon (not the .lnk with a shortcut-overlay arrow).
  if ($src.ToLower().EndsWith('.lnk')) {
    $target = (New-Object -ComObject WScript.Shell).CreateShortcut($src).TargetPath
    if ($target -and (Test-Path -LiteralPath $target)) { $src = $target }
  }
  Add-Type -AssemblyName System.Drawing
  $ico = [System.Drawing.Icon]::ExtractAssociatedIcon($src)
  if ($null -eq $ico) { exit 2 }
  $bmp = $ico.ToBitmap()
  $ms = New-Object System.IO.MemoryStream
  $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
  [Console]::Out.Write([Convert]::ToBase64String($ms.ToArray()))
} catch { exit 3 }"#;

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("OI_ICON_SRC", path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    let b64 = String::from_utf8_lossy(&output.stdout);
    let b64 = b64.trim();
    if b64.is_empty() {
        return None;
    }
    Some(format!("data:image/png;base64,{b64}"))
}
