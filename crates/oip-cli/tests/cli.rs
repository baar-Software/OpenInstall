//! End-to-end tests for `oip-cli`: keygen → build a NATIVE package from an app
//! folder (or a single .exe) → verify. Asserts the CLI emits the same native
//! `manifest.json` + `files/` + `signatures/` layout the GUI produces.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_oip-cli")
}

fn os(s: &str) -> std::ffi::OsString {
    std::ffi::OsString::from(s)
}

fn run(args: &[&std::ffi::OsStr]) -> std::process::Output {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn oip-cli");
    if !out.status.success() {
        panic!(
            "oip-cli {:?} failed:\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out
}

fn read_entry(oip: &Path, name: &str) -> Option<Vec<u8>> {
    let bytes = std::fs::read(oip).unwrap();
    let mut a = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    for i in 0..a.len() {
        let mut f = a.by_index(i).unwrap();
        if f.name() == name {
            let mut v = Vec::new();
            f.read_to_end(&mut v).unwrap();
            return Some(v);
        }
    }
    None
}

fn has_entry(oip: &Path, name: &str) -> bool {
    read_entry(oip, name).is_some()
}

/// keygen + build a signed native package from a small app folder.
fn make_native_package() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let key_prefix = dir.path().join("testkey");
    let pub_path = dir.path().join("testkey.pub");
    let key_path = dir.path().join("testkey.key");

    // A tiny app folder: an entry exe plus a nested asset.
    let app = dir.path().join("app");
    std::fs::create_dir_all(app.join("data")).unwrap();
    std::fs::write(app.join("CoolApp.exe"), b"MZ cool app bytes \x00\x01\x02").unwrap();
    std::fs::write(app.join("data").join("readme.txt"), b"hello").unwrap();
    let oip = dir.path().join("coolapp-1.0.0.oip");

    run(&[
        os("keygen").as_os_str(),
        os("--out").as_os_str(),
        key_prefix.as_os_str(),
    ]);
    assert!(pub_path.exists(), "keygen should write a .pub");

    run(&[
        os("build").as_os_str(),
        os("--app").as_os_str(),
        app.as_os_str(),
        os("--out").as_os_str(),
        oip.as_os_str(),
        os("--id").as_os_str(),
        os("com.example.coolapp").as_os_str(),
        os("--name").as_os_str(),
        os("CoolApp").as_os_str(),
        os("--publisher").as_os_str(),
        os("Example Dev").as_os_str(),
        os("--version").as_os_str(),
        os("1.0.0").as_os_str(),
        os("--secret-key").as_os_str(),
        key_path.as_os_str(),
        os("--public-key").as_os_str(),
        pub_path.as_os_str(),
    ]);

    (dir, oip)
}

#[test]
fn build_produces_native_package_layout() {
    let (_dir, oip) = make_native_package();
    assert!(
        has_entry(&oip, "manifest.json"),
        "native manifest.json present"
    );
    assert!(
        has_entry(&oip, "files/CoolApp.exe"),
        "entry exe under files/"
    );
    assert!(
        has_entry(&oip, "files/data/readme.txt"),
        "nested file under files/"
    );
    assert!(
        has_entry(&oip, "signatures/publisher.ed25519.sig"),
        "publisher signature present"
    );
    // It must NOT be the legacy format.
    assert!(!has_entry(&oip, "manifest.toml"), "no legacy manifest.toml");

    let manifest = String::from_utf8(read_entry(&oip, "manifest.json").unwrap()).unwrap();
    assert!(manifest.contains("com.example.coolapp"), "id in manifest");
    assert!(manifest.contains("CoolApp.exe"), "entry in manifest");
    assert!(manifest.contains("\"minisign:"), "publisher key embedded");
}

#[test]
fn verify_subcommand_reports_signed() {
    let (_dir, oip) = make_native_package();
    let out = run(&[
        os("verify").as_os_str(),
        os("--package").as_os_str(),
        oip.as_os_str(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("signature: OK"), "verify output: {stdout}");
}

#[test]
fn build_from_single_exe_works() {
    let dir = tempfile::tempdir().unwrap();
    let key_prefix = dir.path().join("k");
    run(&[
        os("keygen").as_os_str(),
        os("--out").as_os_str(),
        key_prefix.as_os_str(),
    ]);

    let exe = dir.path().join("Solo.exe");
    std::fs::write(&exe, b"MZ solo app").unwrap();
    let oip = dir.path().join("solo.oip");

    run(&[
        os("build").as_os_str(),
        os("--app").as_os_str(),
        exe.as_os_str(),
        os("--out").as_os_str(),
        oip.as_os_str(),
        os("--id").as_os_str(),
        os("com.example.solo").as_os_str(),
        os("--name").as_os_str(),
        os("Solo").as_os_str(),
        os("--publisher").as_os_str(),
        os("Me").as_os_str(),
        os("--version").as_os_str(),
        os("2.0.0").as_os_str(),
        os("--secret-key").as_os_str(),
        dir.path().join("k.key").as_os_str(),
        os("--public-key").as_os_str(),
        dir.path().join("k.pub").as_os_str(),
    ]);

    assert!(has_entry(&oip, "manifest.json"));
    assert!(has_entry(&oip, "files/Solo.exe"));
    assert!(has_entry(&oip, "signatures/publisher.ed25519.sig"));
}
