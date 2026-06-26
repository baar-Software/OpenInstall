//! Extract an app's embedded Windows icon for display in the launchpad.
//!
//! Reads the entry executable's icon resource group **in-process** with the
//! pure-Rust `pelite` crate, reassembles a complete `.ico`, and returns it as a
//! `data:` URL the frontend drops straight into an `<img>` (WebView2 renders ICO).
//! No PowerShell, no child processes. Best-effort: returns `None` if the icon
//! can't be extracted, and the launchpad falls back to a lettermark.

use std::path::Path;

use base64::Engine;
use pelite::{FileMap, PeFile};

/// Extract the entry executable's icon as a `data:image/x-icon;base64,…` URL.
pub fn extract_icon_data_url(path: &Path) -> Option<String> {
    let ico = extract_ico_bytes(path)?;
    if ico.is_empty() {
        return None;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&ico);
    Some(format!("data:image/x-icon;base64,{b64}"))
}

/// Read the first icon group from the PE and write it out as a complete `.ico`.
fn extract_ico_bytes(path: &Path) -> Option<Vec<u8>> {
    let map = FileMap::open(path).ok()?;
    let pe = PeFile::from_bytes(map.as_ref()).ok()?;
    let resources = pe.resources().ok()?;
    // The first icon group is the executable's primary application icon.
    let (_, group) = resources.icons().filter_map(Result::ok).next()?;
    let mut ico = Vec::new();
    group.write(&mut ico).ok()?;
    Some(ico)
}
