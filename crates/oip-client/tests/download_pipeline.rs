//! End-to-end: download the committed `sample.oip` fixture over a real localhost
//! socket, then run the full client verification pipeline on the downloaded bytes
//! and write Mark-of-the-Web. This exercises `resolver::download` + the
//! `oip-core` verify chain + the MotW writer together on a real signed package.

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

fn fixture_bytes() -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/sample.oip");
    std::fs::read(path).expect("read fixtures/sample.oip")
}

#[tokio::test]
async fn download_then_verify_then_motw() {
    let oip = fixture_bytes();
    let port = serve_once(oip.clone());
    let url = format!("http://127.0.0.1:{port}/sample.oip");

    // 1. Real network download via the client's download path (mirror list of 1).
    let bytes = oip_client::resolver::download(&[url], oip_client::resolver::MAX_OIP_BYTES)
        .await
        .expect("download");
    assert_eq!(bytes, oip, "downloaded bytes must match the fixture");

    // 2. Open + verify the package exactly as resolve() does internally.
    let pkg = oip_client::pkg::Package::from_bytes(&bytes).expect("open zip");
    let manifest_bytes = pkg.manifest_bytes().expect("manifest").to_vec();
    let manifest = oip_core::parse_manifest(&manifest_bytes).expect("parse");
    let key = manifest.publisher_key.as_ref().expect("signed fixture");
    let sig = pkg.signature_bytes().expect("signature present");
    oip_core::verify_manifest_sig(&manifest_bytes, sig, &key.public_key).expect("sig verifies");
    let payload = pkg.get(&manifest.payload.file).expect("payload");
    oip_core::verify_payload(payload, &manifest).expect("payload verifies");
    assert_eq!(
        oip_core::evaluate_trust(&manifest, None),
        oip_core::TrustLevel::VerifiedNewPublisher
    );

    // 3. Write the payload WITH Mark-of-the-Web, as confirm_install would, and
    //    confirm the Zone.Identifier stream marks it Internet-zone.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(manifest.payload.file.replace('/', "_"));
    std::fs::write(&path, payload).unwrap();
    oip_client::motw::write_mark_of_the_web(&path, &manifest.homepage).unwrap();

    let mut ads = path.as_os_str().to_os_string();
    ads.push(":Zone.Identifier");
    let zone = std::fs::read_to_string(&ads).expect("read Zone.Identifier");
    assert!(
        zone.contains("ZoneId=3"),
        "MotW must mark Internet zone: {zone}"
    );
}

/// Developer Mode end-to-end: with the setting enabled, the full `resolve()` path
/// accepts an `openinstall://localhost…` link, maps it to http, downloads from a
/// real local server, verifies, and mints an install token — without weakening
/// any verification. (This is the headline localhost/dev feature.)
#[tokio::test]
async fn dev_mode_resolves_localhost_end_to_end() {
    // Isolate persistent state to a temp dir and enable Developer Mode.
    let data = tempfile::tempdir().unwrap();
    std::env::set_var("OPENINSTALL_DATA_DIR", data.path());
    oip_client::settings::save(&oip_client::Settings {
        developer_mode: true,
    })
    .expect("save settings");

    let port = serve_once(fixture_bytes());
    let url = format!("openinstall://127.0.0.1:{port}/sample.oip");

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
