//! Backend state: the single-use, time-limited install-token store.
//!
//! This is the mechanism that makes "install without consent" unrepresentable:
//! `resolve_oip` mints a token bound to an already-verified package;
//! `confirm_install` can only act on a valid token. Tokens are single-use and
//! expire, so they cannot be replayed or forged.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use oip_core::TrustLevel;

use crate::native::VerifiedNativePackage;

/// How long a minted token remains valid.
pub const TOKEN_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// A verified-but-not-yet-installed native package, held in memory behind a token
/// until the user consents (invariant #1). The package bytes live here, never on a
/// runnable disk location, until `confirm` copies them into the per-user app dir.
#[derive(Debug)]
pub struct PendingInstall {
    pub package: VerifiedNativePackage,
    pub source_url: String,
    pub trust: TrustLevel,
    pub created_at: Instant,
    /// Set via `acknowledge_risk` when the user explicitly acknowledges a publisher-key change.
    pub acknowledged: bool,
}

/// Why a token was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    Unknown,
    Expired,
    Reused,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            TokenError::Unknown => "unknown or invalid install token",
            TokenError::Expired => "install token has expired - please resolve the link again",
            TokenError::Reused => "install token has already been used",
        };
        f.write_str(msg)
    }
}

#[derive(Default)]
pub struct AppState {
    pending: Mutex<HashMap<String, PendingInstall>>,
    consumed: Mutex<HashSet<String>>,
}

impl AppState {
    pub fn insert(&self, token: String, pending: PendingInstall) {
        self.pending.lock().unwrap().insert(token, pending);
    }

    /// Record an explicit risk acknowledgement for a pending token.
    pub fn acknowledge(&self, token: &str) -> Result<(), TokenError> {
        let mut map = self.pending.lock().unwrap();
        match map.get_mut(token) {
            Some(p) => {
                p.acknowledged = true;
                Ok(())
            }
            None => Err(TokenError::Unknown),
        }
    }

    /// Validate and CONSUME a token. On success the pending install is removed and
    /// the token marked consumed (single-use). Rejects unknown, expired, and
    /// already-consumed tokens.
    pub fn consume(&self, token: &str, ttl: Duration) -> Result<PendingInstall, TokenError> {
        if self.consumed.lock().unwrap().contains(token) {
            return Err(TokenError::Reused);
        }
        let mut map = self.pending.lock().unwrap();
        match map.get(token) {
            None => Err(TokenError::Unknown),
            Some(entry) => {
                if entry.created_at.elapsed() > ttl {
                    map.remove(token);
                    Err(TokenError::Expired)
                } else {
                    let pending = map.remove(token).expect("just checked present");
                    drop(map);
                    self.consumed.lock().unwrap().insert(token.to_string());
                    Ok(pending)
                }
            }
        }
    }
}

/// Mint a fresh random token (128 bits of entropy, hex-encoded).
pub fn new_token() -> String {
    let mut buf = [0u8; 16];
    rand::fill(&mut buf[..]);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{NativeManifest, NativePermissions, NativePublisher};

    fn dummy_package() -> VerifiedNativePackage {
        VerifiedNativePackage {
            manifest: NativeManifest {
                schema: 1,
                id: "com.example.app".to_string(),
                name: "App".to_string(),
                version: "1.0.0".to_string(),
                publisher: NativePublisher {
                    name: "Dev".to_string(),
                    key: "minisign:RWtest".to_string(),
                    website: String::new(),
                },
                entry: "App.exe".to_string(),
                install_mode: "perUser".to_string(),
                requires_admin: false,
                files: Vec::new(),
                permissions: NativePermissions::default(),
                shortcuts: Vec::new(),
            },
            files: Vec::new(),
            trust: TrustLevel::Verified,
            public_key: "RWtest".to_string(),
            key_fingerprint: "RWtest".to_string(),
            package_size: 0,
        }
    }

    fn dummy_pending(trust: TrustLevel) -> PendingInstall {
        PendingInstall {
            package: dummy_package(),
            source_url: "https://example.com/app.oip".to_string(),
            trust,
            created_at: Instant::now(),
            acknowledged: false,
        }
    }

    #[test]
    fn unknown_token_is_rejected() {
        let s = AppState::default();
        assert_eq!(
            s.consume("nope", TOKEN_TTL).unwrap_err(),
            TokenError::Unknown
        );
    }

    #[test]
    fn fresh_token_is_accepted_once() {
        let s = AppState::default();
        let token = new_token();
        s.insert(token.clone(), dummy_pending(TrustLevel::Verified));
        assert!(s.consume(&token, TOKEN_TTL).is_ok());
    }

    #[test]
    fn reused_token_is_rejected() {
        let s = AppState::default();
        let token = new_token();
        s.insert(token.clone(), dummy_pending(TrustLevel::Verified));
        assert!(s.consume(&token, TOKEN_TTL).is_ok());
        assert_eq!(
            s.consume(&token, TOKEN_TTL).unwrap_err(),
            TokenError::Reused
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let s = AppState::default();
        let token = new_token();
        s.insert(token.clone(), dummy_pending(TrustLevel::Verified));
        // A zero TTL means anything already minted is expired.
        assert_eq!(
            s.consume(&token, Duration::ZERO).unwrap_err(),
            TokenError::Expired
        );
        // And after an expiry rejection, the entry is gone (treated as unknown).
        assert_eq!(
            s.consume(&token, TOKEN_TTL).unwrap_err(),
            TokenError::Unknown
        );
    }

    #[test]
    fn tokens_are_unique_and_nonempty() {
        let a = new_token();
        let b = new_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32); // 16 bytes hex
    }

    #[test]
    fn acknowledge_sets_flag_then_consume_sees_it() {
        let s = AppState::default();
        let token = new_token();
        s.insert(token.clone(), dummy_pending(TrustLevel::PublisherChanged));
        s.acknowledge(&token).unwrap();
        let p = s.consume(&token, TOKEN_TTL).unwrap();
        assert!(p.acknowledged);
    }

    #[test]
    fn acknowledge_unknown_token_errors() {
        let s = AppState::default();
        assert_eq!(s.acknowledge("nope").unwrap_err(), TokenError::Unknown);
    }
}
