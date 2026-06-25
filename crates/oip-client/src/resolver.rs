//! URL resolution (openinstall:// → https://) and download (brief §3 steps 2–3).
//!
//! Resolution is deterministic and conservative: only a clean https mapping is
//! accepted. Alternate schemes, credentials, and (in release) localhost are
//! rejected. This upholds host transparency (#7) and the "no surprises" posture
//! of the protocol handler (#6).

use anyhow::{anyhow, bail, Result};
use url::Url;

/// Max size we will download for a `.oip` (defense against resource exhaustion).
pub const MAX_OIP_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// Resolve an `openinstall://` URL with the safe default policy (loopback hosts
/// rejected). Callers that honor Developer Mode use
/// [`resolve_url_with_policy`] with `allow_localhost = settings.developer_mode`.
pub fn resolve_url(input: &str) -> Result<String> {
    resolve_url_with_policy(input, false)
}

/// Resolve `openinstall://HOST/PATH` → `https://HOST/PATH` (or `http://` for a
/// loopback host when `allow_localhost` is set — Developer Mode).
///
/// * Rejects any input that does not start with `openinstall://`.
/// * Requires a host; rejects embedded credentials (`user:pass@`).
/// * Rejects localhost/loopback unless `allow_localhost` is set.
/// * Non-loopback hosts are ALWAYS https. Only loopback may be http (local dev).
/// * Preserves host, port, path, and query; drops any fragment.
pub fn resolve_url_with_policy(input: &str, allow_localhost: bool) -> Result<String> {
    let trimmed = input.trim();
    let rest = trimmed
        .strip_prefix("openinstall://")
        .ok_or_else(|| anyhow!("URL must use the openinstall:// scheme"))?;
    if rest.is_empty() {
        bail!("URL has no host");
    }

    // The authority is everything up to the first '/', '?', or '#'. Require it to
    // be non-empty BEFORE handing to the (lenient) URL parser, so inputs like
    // `openinstall:///path` (no host) are rejected deterministically.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if rest[..authority_end].is_empty() {
        bail!("URL has no host");
    }

    // Re-parse as https to validate the authority/path structure deterministically.
    let candidate = format!("https://{rest}");
    let u = Url::parse(&candidate).map_err(|e| anyhow!("invalid URL: {e}"))?;

    let host = u
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("URL has no host"))?;

    if !u.username().is_empty() || u.password().is_some() {
        bail!("URL must not contain credentials");
    }
    if u.scheme() != "https" {
        // Should be impossible given we prefixed https://, but fail closed.
        bail!("resolved URL is not https");
    }
    if is_loopback(host) && !allow_localhost {
        bail!("localhost / loopback hosts are not allowed");
    }

    // Rebuild a clean URL (no fragment). Loopback (only reachable when
    // allow_localhost is set) is served over http for local dev convenience;
    // every real host is always https.
    let scheme = if is_loopback(host) { "http" } else { "https" };
    let mut out = format!("{scheme}://");
    out.push_str(host);
    if let Some(port) = u.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(u.path());
    if let Some(q) = u.query() {
        out.push('?');
        out.push_str(q);
    }
    Ok(out)
}

fn is_loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    matches!(h, "localhost" | "127.0.0.1" | "::1")
        || h.ends_with(".localhost")
        || h.starts_with("127.")
}

/// Download a `.oip` from the first URL that succeeds (mirror fallback). The hash
/// gate downstream is identical regardless of which mirror served the bytes.
pub async fn download(urls: &[String], max_bytes: u64) -> Result<Vec<u8>> {
    if urls.is_empty() {
        bail!("no download URLs");
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("OpenInstall/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let mut last_err: Option<anyhow::Error> = None;
    for url in urls {
        match download_one(&client, url, max_bytes).await {
            Ok(bytes) => return Ok(bytes),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("download failed")))
}

async fn download_one(client: &reqwest::Client, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await?.error_for_status()?;
    if let Some(len) = resp.content_length() {
        if len > max_bytes {
            bail!("package is too large ({len} bytes > {max_bytes} limit)");
        }
    }
    let bytes = resp.bytes().await?;
    if bytes.len() as u64 > max_bytes {
        bail!("package exceeds the size limit");
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_clean_https() {
        assert_eq!(
            resolve_url_with_policy("openinstall://example.com/download/app.oip", false).unwrap(),
            "https://example.com/download/app.oip"
        );
    }

    #[test]
    fn preserves_port_and_query() {
        assert_eq!(
            resolve_url_with_policy("openinstall://example.com:8443/a/b.oip?v=2", false).unwrap(),
            "https://example.com:8443/a/b.oip?v=2"
        );
    }

    #[test]
    fn drops_fragment() {
        assert_eq!(
            resolve_url_with_policy("openinstall://example.com/x.oip#frag", false).unwrap(),
            "https://example.com/x.oip"
        );
    }

    #[test]
    fn rejects_http_scheme() {
        assert!(resolve_url_with_policy("http://example.com/x.oip", false).is_err());
    }

    #[test]
    fn rejects_file_scheme() {
        assert!(resolve_url_with_policy("file:///c:/windows/system32/x.oip", false).is_err());
    }

    #[test]
    fn rejects_no_host() {
        assert!(resolve_url_with_policy("openinstall:///nohost.oip", false).is_err());
    }

    #[test]
    fn rejects_credentials() {
        assert!(
            resolve_url_with_policy("openinstall://user:pass@example.com/x.oip", false).is_err()
        );
    }

    #[test]
    fn rejects_localhost_in_release() {
        assert!(resolve_url_with_policy("openinstall://localhost/x.oip", false).is_err());
        assert!(resolve_url_with_policy("openinstall://127.0.0.1/x.oip", false).is_err());
        assert!(resolve_url_with_policy("openinstall://[::1]/x.oip", false).is_err());
    }

    #[test]
    fn dev_mode_maps_loopback_to_http() {
        // In Developer Mode loopback is allowed and served over http (local dev).
        assert_eq!(
            resolve_url_with_policy("openinstall://localhost:8000/x.oip", true).unwrap(),
            "http://localhost:8000/x.oip"
        );
        assert_eq!(
            resolve_url_with_policy("openinstall://127.0.0.1/x.oip", true).unwrap(),
            "http://127.0.0.1/x.oip"
        );
    }

    #[test]
    fn dev_mode_keeps_real_hosts_https() {
        // Even in Developer Mode, a non-loopback host is still https.
        assert_eq!(
            resolve_url_with_policy("openinstall://example.com/x.oip", true).unwrap(),
            "https://example.com/x.oip"
        );
    }
}
