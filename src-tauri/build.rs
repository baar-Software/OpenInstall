fn main() {
    // Embed a Windows application manifest that runs OpenInstall as the invoking
    // user (asInvoker). Besides being correct (we install per-user and never need
    // admin), this stops Windows' installer-detection heuristic from auto-elevating
    // the executable just because its name contains "install" — so OpenInstall
    // never raises a UAC prompt on launch.
    let windows = tauri_build::WindowsAttributes::new()
        .app_manifest(include_str!("windows-app-manifest.xml"));
    let attributes = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}
