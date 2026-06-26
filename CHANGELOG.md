# Changelog

All notable changes to OpenInstall will be documented here.

This project follows a pre-1.0 release process. Breaking changes may happen while
the native `.oip` package format and authoring tools stabilize.

## 0.3.0 — 2026-06-26

### Removed

* The legacy installer-style `.oip` format (`manifest.toml` + `manifest.minisig`
  + `payload/`) and **all** code that produced, parsed, or installed it.
  OpenInstall now builds, ships, and installs only native packages
  (`manifest.json` + `files/` + `signatures/publisher.ed25519.sig`).
* The unused Authenticode / Windows-code-signing inspection (and the orange
  "not code-signed" disclosure it fed). Package resolution no longer spawns
  PowerShell per binary.

### Changed

* `oip-core` is reduced to a focused signature/trust kernel: publisher-signature
  verification, publisher-key fingerprints, and the TOFU trust model. Legacy
  manifest parsing and payload hashing were removed with the legacy format.
* Test fixtures are generated in-process; the committed legacy `sample.oip` /
  `testkey` fixtures were removed.

## 0.2.0 — 2026-06-25

### Added

* Native `.oip` package verification and per-user install model.
* OpenInstall repo browsing through `/repo.json`.
* Consented repo-add links.
* Direct `.oip` package links that do not require repo membership.
* User-controlled install flow after OpenInstall package verification.
* GitHub community docs and issue/PR templates.
* Privacy, governance, roadmap, download, and code-signing documentation.
* Dependency review workflow for pull requests.

### Changed

* `oip-cli build` produces byte-identical native packages to the GUI's Create
  view (both go through `oip-pack`).
* README, security docs, package format docs, and signing docs now describe the
  native package-manager model.
* Release documentation now labels unsigned preview MSI artifacts clearly until
  Windows code signing is enabled.

### Security

* OpenInstall package verification remains the install gate.
* The documented security model explicitly rejects Windows security bypasses.
