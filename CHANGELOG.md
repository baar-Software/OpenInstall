# Changelog

All notable changes to OpenInstall will be documented here.

This project follows a pre-1.0 release process. Breaking changes may happen while
the native `.oip` package format and authoring tools stabilize.

## 0.5.0 — 2026-06-26

### Added

* Uninstall apps from the launchpad. The × on an app tile now **fully uninstalls**
  it after a confirmation prompt: it deletes the app's files (all installed
  versions), removes its Start Menu shortcut, and removes its Add/Remove Programs
  entry — instead of only dropping it from the list. The app stays listed if the
  files can't be removed (e.g. it is still running), with a clear error.

## 0.4.0 — 2026-06-26

### Security

* Removed **all** child-process / shell invocations from the app. OpenInstall no
  longer spawns PowerShell, `cmd.exe`, or `reg.exe` for any operation — every
  Windows integration is now done in-process via pure-Rust / safe-wrapper crates.
  This shrinks the attack surface (no shell/interpreter spawning, no argument-
  string parsing) and removes the per-operation interpreter startup cost.

### Changed

* Start Menu shortcuts are written with the pure-Rust `mslnk` crate instead of a
  PowerShell `WScript.Shell` script.
* The Add/Remove Programs (uninstall) entry is written with the `winreg` safe
  wrapper over the Win32 registry API instead of `reg.exe`.
* App version metadata (Create form auto-fill) is read from the PE version
  resource with `pelite` instead of PowerShell.
* App icons are extracted from the executable's icon resource with `pelite`
  (returned as a `data:image/x-icon` URL) instead of PowerShell + System.Drawing.
* Installed apps launch by running their verified entry executable directly,
  instead of `cmd /C start` on a discovered Start Menu shortcut.

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
