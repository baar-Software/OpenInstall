//! End-to-end: build a signed native `.oip` in-process, serve it over a real
//! localhost socket, then run the client's download + native verification
//! pipeline on the downloaded bytes. Exercises `resolver::download`, the native
//! package verifier, and the full `resolve()` path together — hermetically (keys
//! and packages are minted in-process; no network, no committed secrets).

use std::io::{Read, Write};
use std::net::TcpListener;

/// Serve `body` exactly once over HTTP/1.1 on an ephemeral localhost port.
fn serve_once(body: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut scratch = [0u8; 2048];
            let _ = stream.read(&mut scratch); // consume the request line/headers
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    port
}

/// Build a signed native package (`manifest.json` + `files/` + signature).
fn native_package(id: &str) -> Vec<u8> {
    let kp = oip_pack::generate_keypair(None).expect("keygen");
    let meta = oip_pack::NativeManifestMeta {
        id: id.to_string(),
        name: "CoolApp".to_string(),
        version: "1.4.2".to_string(),
        publisher_name: "Example Dev".to_string(),
        publisher_website: "https://coolapp.dev".to_string(),
        entry: "CoolApp.exe".to_string(),
        network: false,
        shortcut_name: String::new(),
    };
    let files = vec![oip_pack::NativeFileInput {
        path: "CoolApp.exe".to_string(),
        bytes: b"MZ\x90\x00 fake but stable app bytes \x01\x02\x03".to_vec(),
    }];
    oip_pack::build_native_oip_bytes(&meta, &files, &kp.public_key_b64, &kp.secret_key_box, None)
        .expect("build native package")
}

#[tokio::test]
async fn download_then_verify_native() {
    let oip = native_package("com.example.coolapp");
    let port = serve_once(oip.clone());
    let url = format!("http://127.0.0.1:{port}/app.oip");

    // Real network download via the client's download path (mirror list of 1).
    let bytes = oip_client::resolver::download(&[url], oip_client::resolver::MAX_OIP_BYTES)
        .await
        .expect("download");
    assert_eq!(bytes, oip, "downloaded bytes must match what we served");

    // The downloaded bytes are a valid, signed native package (fail-closed verify).
    let report = oip_pack::verify_native_oip_bytes(&bytes).expect("native package verifies");
    assert_eq!(report.id, "com.example.coolapp");
    assert!(report.signed);
    assert_eq!(report.trust, oip_core::TrustLevel::VerifiedNewPublisher);
}

/// Developer Mode end-to-end: with the setting enabled, the full `resolve()` path
/// accepts an `openinstall://localhost…` link, maps it to http, downloads from a
/// real local server, verifies the native package, and mints an install token —
/// without weakening any verification.
#[tokio::test]
async fn dev_mode_resolves_localhost_end_to_end() {
    // Isolate persistent state to a temp dir and enable Developer Mode.
    let data = tempfile::tempdir().unwrap();
    std::env::set_var("OPENINSTALL_DATA_DIR", data.path());
    oip_client::settings::save(&oip_client::Settings {
        developer_mode: true,
    })
    .expect("save settings");

    let port = serve_once(native_package("com.example.coolapp"));
    let url = format!("openinstall://127.0.0.1:{port}/app.oip");

    let state = oip_client::AppState::default();
    let result = oip_client::resolve(&url, &state).await.expect("resolve");

    assert_eq!(result.id, "com.example.coolapp");
    assert_eq!(result.trust, oip_core::TrustLevel::VerifiedNewPublisher);
    assert!(
        result.source_url.starts_with("http://127.0.0.1:"),
        "loopback should resolve to http in dev mode: {}",
        result.source_url
    );
    assert!(!result.install_token.is_empty(), "a token must be minted");

    std::env::remove_var("OPENINSTALL_DATA_DIR");
}
