# Architecture

OpenInstall is a Rust + Tauri 2 + Svelte app. Its design goal is a clean
package-manager flow: resolve and verify first, stop for consent, then install
native `.oip` app files directly without launching unknown downloaded installers.

## Components

```text
+-------------------+        pure decisions
|  crates/oip-core  |  manifest/signature/hash verification and TOFU
+-------------------+
          ^
          | uses
          |
+-------------------+        client engine, all package-manager I/O
| crates/oip-client |  repo/direct URL resolver, native .oip verification,
|                   |  download, Authenticode status, MotW,
|                   |  pin store, blocklist, install-token gate, per-user
|                   |  file copy, shortcut creation, HKCU uninstall metadata
+-------------------+
          ^
          | uses
          |
+-------------------+        thin Tauri shell
|    src-tauri      |  commands, deep-link handling, package-authoring bridge
+-------------------+
          ^
          | IPC
          |
+-------------------+
|        ui         |  Launchpad, Store, repo-add consent, package consent,
|                   |  native v1 Create view
+-------------------+

+-------------------+        native package authoring
| crates/oip-pack   |  build / keygen / sign for v1 .oip
+-------------------+
          ^
          | uses
+-------------------+
|  crates/oip-cli   |  developer CLI over oip-pack
+-------------------+
```

## Native Install Flow

1. A user opens `openinstall://install/<bundle-id>` or a direct `.oip` link.
2. `oip-client` resolves repository metadata when needed, downloads the `.oip`,
   and parses `manifest.json`.
3. The native verifier validates id, version, `perUser` install mode, declared
   permissions, file paths, shortcuts, package signature, publisher key pin, and
   every file's SHA-256 hash.
4. The client refreshes the GitHub-backed `blocklist.txt` feed on a short
   timeout, uses the cached copy when available, and blocks known-bad package
   hashes, file hashes, app ids, publisher names, or publisher keys.
5. Forbidden installer/script/admin patterns are rejected before installation:
   PowerShell, batch, `.msi`, registry scripts, `setup.exe`, `installer.exe`,
   services, drivers, shell extensions, kernel components, autostart, and admin
   installs.
6. The verified files are staged in a temp dir and inspected for Authenticode
   status where possible. The files that get installed are written as per-user
   software and are NOT marked with the Mark-of-the-Web (see invariant 6), so
   launching them does not raise SmartScreen's first-run prompt.
7. The UI shows the package, trust state, Authenticode status,
   and source URL. It stops until the user clicks Install.
8. `confirm_install` redeems the single-use install token, copies files under
   `%LOCALAPPDATA%\OpenInstall\Apps\<id>\<version>\`, creates current-user Start
   Menu shortcuts, writes HKCU uninstall metadata, and records the app in the
   OpenInstall database.

## Frontend Contract

`resolve_oip(url) -> ResolveResult` downloads, verifies, inspects, and stops. It
mints a single-use install token but does not install.

`confirm_install(installToken) -> InstallResult` installs only when given a
valid, unexpired token from a successful resolve. Native packages are installed
by copying verified files.

The UI can only restrict installation further. It never creates a bypass:

* `PublisherChanged` requires explicit acknowledgement.
* `Unverified` is displayed as degraded and can never look verified.
* Unsigned or invalid Authenticode app binaries are shown honestly.

## Repositories And Direct Links

Apps do not need to be in a repo to install: direct `.oip` links are accepted and
verified through the same pipeline. Repos add app-store browsing:

* `/repo.json` lists apps and versions.
* `/<bundle-id>/<version>.oip` stores packages.
* `/<bundle-id>/assets/icon.png` stores the icon.
* `/<bundle-id>/screenshots/` stores screenshots.

Repo-add links such as `openinstall://repo?url=https://example.com/openinstall`
show a separate Add Source consent dialog and only add the catalog source. Apps
still require package verification and an Install click.

## Invariants

| # | Invariant | Enforced by |
| --- | --- | --- |
| 1 | No silent install path | `resolve_oip` only mints a token; `confirm_install` requires that token; UI calls it only from Install. |
| 2 | No unknown external installer execution | Native verifier rejects installer/script payloads and install scripts. |
| 3 | Fail closed | Signature, manifest, hash, path, permission, blocklist, and policy failures abort. |
| 4 | Publisher keys are pinned | Pin store compares package key to app id; UI gates `PublisherChanged`. |
| 5 | No OS security bypass | OpenInstall does not disable Windows security, add exclusions, or alter OS security settings. |
| 6 | SmartScreen is not bypassed | Never disables SmartScreen/AV, adds exclusions, or strips MotW from OS-marked files. Verified package files install as per-user software (no MotW), like winget/MSIX — Defender real-time AV still scans them. No reputation-transfer claims. |
| 7 | Normal apps avoid UAC | v1 installs per-user and writes HKCU/current-user shortcuts. |
| 8 | Host transparency | Resolved source URL is shown before Install. |

## Build And CI

* Local run: `cargo tauri dev`
* Local MSI: `cargo tauri build`
* CI: formatting, Rust tests, clippy, and UI build on Windows.
* Release: tag-triggered MSI build and GitHub release upload. Windows code
  signing is planned, but not yet enabled for public releases.

## See Also

* [oip-format.md](oip-format.md) - native `.oip` format and verification flow.
* [openinstall-repos.md](openinstall-repos.md) - repo catalog format.
* [signing-keys.md](signing-keys.md) - publisher key custody.
* [smartscreen.md](smartscreen.md) - Windows reputation behavior.
