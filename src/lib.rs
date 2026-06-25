//! Root crate for the `openinstall-tests` package.
//!
//! This crate intentionally has no runtime logic. It exists so the workspace
//! root is a package, which lets the top-level `tests/` directory host the
//! cross-cutting adversarial integration suite (see the project brief §10).
//!
//! Real logic lives in:
//!   - `crates/oip-core`  — pure verification + trust types
//!   - `crates/oip-cli`   — developer tool to build & sign `.oip` packages
//!   - `src-tauri`        — the Tauri app (handler, download, consent, install)
//!
//! Integration tests should depend on `oip-core` (a dev-dependency) and build
//! `.oip` fixtures on the fly with `minisign` + `zip`. They reference the crate
//! directly as `oip_core::...`.
