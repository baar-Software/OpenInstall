# OpenInstall

[![CI](https://github.com/baar-Software/OpenInstall/actions/workflows/ci.yml/badge.svg)](https://github.com/baar-Software/OpenInstall/actions/workflows/ci.yml)
[![Release](https://github.com/baar-Software/OpenInstall/actions/workflows/release.yml/badge.svg)](https://github.com/baar-Software/OpenInstall/actions/workflows/release.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](#license)

OpenInstall is an open source Windows package manager, mini app store, and
installer for signed `.oip` app packages.

Users install OpenInstall once. After that, `openinstall://` links and imported
OpenInstall repositories install apps through a verify-then-consent flow:
OpenInstall resolves the package, verifies signatures and file hashes, checks
publisher identity and permissions, inspects Authenticode status, shows a
consent dialog, and only then installs the verified files itself.

OpenInstall does **not** bypass Windows security policy, and it does **not**
download and run random `Setup.exe` installers.

> Free code signing for OpenInstall releases is provided by
> [SignPath.io](https://signpath.io), certificate by
> [SignPath Foundation](https://signpath.org).

## Why OpenInstall Exists

Windows app installation is often noisy: browser download warnings, unknown
installer prompts, UAC prompts, self-updaters, unsigned scripts, and hard-to-audit
setup flows. OpenInstall aims for the cleaner package-manager model:

```text
User opens openinstall://install/com.example.app
OpenInstall downloads a .oip package
OpenInstall verifies signatures, hashes, permissions, publisher key, and Authenticode status
User reviews the consent dialog
OpenInstall copies verified files into a per-user app directory
OpenInstall creates shortcuts, uninstall metadata, and future update state
```

Normal apps install per-user, without UAC, under:

```text
%LOCALAPPDATA%\OpenInstall\Apps\<bundle-id>\<version>\
```

## Security Model

OpenInstall's promise is "no avoidable scary installer flow", not "turn off
Windows security".

OpenInstall avoids:

* Browser downloads of random app installers.
* UAC prompts for normal per-user apps.
* Unknown `setup.exe` / `installer.exe` launches.
* Arbitrary PowerShell, batch, VBScript, registry, MSI, service, or driver
  install payloads.
* Admin installs when per-user install is sufficient.

OpenInstall respects:

* Windows security policy may still act independently at the OS level.
* SmartScreen reputation warnings for low-reputation or unsigned app binaries.
* Enterprise/local Windows security policy.

See [SECURITY.md](SECURITY.md) for the full security policy.

## User Flow

1. Import an OpenInstall repo or open a direct `.oip` link.
2. Browse apps in the Store or open a bundle link such as
   `openinstall://install/com.baar-verlag.baar-reader`.
3. OpenInstall resolves the package and verifies it.
4. The consent dialog shows package trust, publisher key, Windows code-signing
   status, source URL, and install mode.
5. The user clicks **Install**.
6. OpenInstall copies files, creates Start Menu shortcuts, writes HKCU uninstall
   metadata, and records the app for launch/update management.

Apps can also be installed from direct package links such as:

```text
openinstall://example.com/download/app.oip
```

Direct package installs do not require the app to be listed in a repo. Repo-add
links use:

```text
openinstall://repo?url=https%3A%2F%2Fexample.com%2Fopeninstall
```

Repo-add links only add a catalog source after user consent; they never install
an app.

## Package Format

OpenInstall v1 installs native `.oip` packages:

```text
baar-reader-1.0.0.oip
|-- manifest.json
|-- files/
|   |-- BaarReader.exe
|   |-- BaarReader.dll
|   `-- assets/
|-- signatures/
|   |-- publisher.ed25519.sig
|   `-- openinstall.review.sig
|-- sbom.spdx.json
`-- provenance.json
```

The manifest declares identity, publisher key, version, entry point, permissions,
shortcuts, and SHA-256 hashes for every installed file. OpenInstall refuses
unlisted files under `files/`.

See [docs/oip-format.md](docs/oip-format.md).

## OpenInstall Repositories

An OpenInstall repo is a static HTTPS directory with a `/repo.json` catalog:

```text
https://example.com/openinstall/
  repo.json
  com.example.coolapp/
    assets/icon.png
    screenshots/one.png
    screenshots/two.png
    latest.oip
    1.0.0.oip
```

Repo catalogs are discovery metadata only. Every selected `.oip` still goes
through the same verification and consent pipeline.

See [docs/openinstall-repos.md](docs/openinstall-repos.md).

## Project Status

OpenInstall is pre-1.0. The security model and native `.oip` direction are the
core design, but APIs and package-authoring tools may still change.

Current highlights:

* Native `.oip` verification and per-user install path.
* Store/repo browsing with consented repo-add links.
* Direct `.oip` link installs.
* User-controlled install flow after OpenInstall package verification.
* GitHub-backed revocation blocklist for known-bad package hashes, file hashes,
  app ids, publisher names, and publisher keys.
* Authenticode status disclosure.
* Native v1 package creator for signed app-folder packages.
* SignPath-backed release signing workflow.

## Building From Source

OpenInstall is Windows-only.

Prerequisites:

* Windows 10/11.
* Stable Rust toolchain.
* Node.js 20 or newer.
* Tauri CLI v2:

```sh
cargo install tauri-cli --version "^2" --locked
```

Install dependencies and run:

```sh
npm --prefix ui ci
cargo tauri dev
```

Build an MSI:

```sh
cargo tauri build --bundles msi
```

The MSI is written under:

```text
target/release/bundle/msi/
```

Official release MSIs are signed by the SignPath Foundation through
[.github/workflows/release.yml](.github/workflows/release.yml). The private code
signing key never exists in GitHub Actions.

## Testing

Run the same checks CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix ui ci
npm --prefix ui test
npm --prefix ui run build
```

## Documentation

* [docs/oip-format.md](docs/oip-format.md) - native `.oip` package format.
* [docs/openinstall-repos.md](docs/openinstall-repos.md) - repo catalog format.
* [docs/signing-keys.md](docs/signing-keys.md) - publisher keys and TOFU.
* [docs/smartscreen.md](docs/smartscreen.md) - Windows reputation behavior.
* [docs/architecture.md](docs/architecture.md) - crate and app architecture.
* [docs/releasing.md](docs/releasing.md) - maintainer release checklist.
* [SECURITY.md](SECURITY.md) - security policy and vulnerability reporting.
* [CONTRIBUTING.md](CONTRIBUTING.md) - contributor guide.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `crates/oip-core` | Pure verification kernel for manifest/signature/hash logic and trust evaluation. |
| `crates/oip-client` | Client engine: repo/direct URL resolver, native `.oip` validation, download, Authenticode inspection, MotW, pin store, blocklist, install tokens, per-user install. |
| `crates/oip-pack` | Native `.oip` package authoring, publisher key generation, and manifest signing. |
| `crates/oip-cli` | Developer CLI for package tooling. |
| `src-tauri` | Tauri shell, commands, deep-link handling, MSI packaging. |
| `ui` | Svelte/Vite frontend: Launchpad, Store, consent dialogs, Create view. |
| `docs` | Package, repo, signing, security, and architecture documentation. |
| `.github` | CI, release, issue, and PR automation. |

## Contributing

Contributions are welcome, especially in native package authoring, repo tooling,
security review, documentation, and Windows integration testing.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before opening a pull request.

For security-sensitive reports, do not open a public issue. Follow
[SECURITY.md](SECURITY.md).

## License

OpenInstall is licensed under the [GNU Affero General Public License v3.0](LICENSE).
