# The `.oip` Package Format

An `.oip` file is the unit OpenInstall downloads, verifies, inspects, and installs.
It is a ZIP archive, but it is **not** a wrapped `Setup.exe`. OpenInstall v1's
native format contains app files plus metadata, and OpenInstall installs those
files itself.

OpenInstall fails closed: if metadata, signatures, hashes, policy checks, or the
verification checks fail, nothing is installed.

## 1. Archive Layout

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

Only paths under `files/` are installed. Every installed file must be listed in
`manifest.json` with a SHA-256 hash. Unlisted files under `files/` are rejected.

OpenInstall v1 packages use `manifest.json`; installed app content lives under
`files/` and is copied by OpenInstall after verification and consent.

## 2. `manifest.json`

```json
{
  "schema": 1,
  "id": "com.baar-verlag.baar-reader",
  "name": "Baar Reader",
  "version": "1.0.0",
  "publisher": {
    "name": "Baar Verlag",
    "key": "ed25519:PUBLIC_KEY_HERE",
    "website": "https://example.com"
  },
  "entry": "BaarReader.exe",
  "installMode": "perUser",
  "requiresAdmin": false,
  "files": [
    {
      "path": "BaarReader.exe",
      "sha256": "64 lowercase hex chars"
    }
  ],
  "permissions": {
    "network": true,
    "autostart": false,
    "registry": false,
    "services": false,
    "drivers": false,
    "shellExtensions": false
  },
  "shortcuts": [
    {
      "name": "Baar Reader",
      "target": "BaarReader.exe"
    }
  ]
}
```

## 3. Field Rules

| Field | Rule |
| --- | --- |
| `schema` | Must be `1`. |
| `id` | Reverse-DNS bundle identifier; immutable across versions. |
| `name`, `version` | Required and non-empty. |
| `publisher.name` | Required and non-empty. |
| `publisher.key` | Required package-signing public key. |
| `publisher.website` | Optional HTTPS publisher site. |
| `entry` | Required path inside `files/`; must be listed in `files`. |
| `installMode` | Must be `perUser` for v1. |
| `requiresAdmin` | Must be `false` for normal packages. |
| `files[].path` | Relative path under `files/`; no absolute paths, drive prefixes, `..`, or backslashes. |
| `files[].sha256` | SHA-256 of `files/<path>`, lowercase hex. |
| `permissions` | Services, drivers, shell extensions, registry writes, and autostart are blocked by default. |
| `shortcuts[].target` | Relative target under the installed app directory. |

## 4. Install Locations

Native packages install per-user by default:

```text
%LOCALAPPDATA%\OpenInstall\Apps\<bundle-id>\<version>\
```

Start Menu shortcuts are created by OpenInstall:

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\<App Name>.lnk
```

Uninstall metadata is registered for the current user:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\<bundle-id>
```

This avoids UAC for normal apps because OpenInstall does not write to Program
Files or machine-wide registry locations.

## 5. Verification Flow

1. Resolve `openinstall://install/<bundle-id>` from imported repos, or resolve a
   direct `.oip` link such as `openinstall://example.com/download/app.oip`.
2. Download the `.oip` over HTTPS and verify the repository metadata when a repo
   was used.
3. Open the ZIP and parse `manifest.json`.
4. Validate id, version, install mode, permissions, file paths, and shortcut
   targets.
5. Verify the publisher package signature over `manifest.json`.
6. Apply publisher-key pinning for the app id.
7. Verify every listed file's SHA-256 and reject unlisted installed files.
8. Check the local and GitHub-backed OpenInstall revocation blocklists.
9. Reject forbidden installer/script/service/driver patterns.
10. Stage the package and preserve internet-origin metadata.
11. Verify Authenticode status for Windows executables and libraries when
    possible, and show unsigned/invalid status honestly.
12. Show the consent dialog and stop. No install happens until the user clicks
    Install.
13. Copy files to the per-user app directory, create shortcuts, write HKCU
    uninstall metadata, and record the install in OpenInstall's database.

## 6. Hard Blocks

OpenInstall blocks these by default:

* Invalid package signatures or file hashes.
* Revoked package hashes, file hashes, app ids, publisher names, or publisher
  keys from OpenInstall's local blocklist or cached GitHub-backed blocklist.
* Driver installation.
* Service installation.
* Kernel components.
* Browser extension injection.
* Shell extension installation.
* Arbitrary PowerShell, batch, VBScript, or registry scripts.
* Unknown external `setup.exe` / `installer.exe` launchers.
* Admin elevation unless a future reviewed package type explicitly allows it.

OpenInstall does not add a separate external-scanner approval gate. The install
gate is OpenInstall package verification, publisher identity, hashes,
permissions, and user consent.

## 7. Trust Levels

| Level | Meaning | UI |
| --- | --- | --- |
| `Verified` | Package signature valid and publisher key matches the existing pin. | Green |
| `VerifiedNewPublisher` | Signature valid and this app id has no previous pin. | Green/blue, first-seen publisher |
| `PublisherChanged` | Signature valid but the key differs from the existing pin. | Red; explicit override required |
| `Unverified` | Package is unsigned or lacks a usable publisher key. | Yellow; never shown as verified |

An unsigned package can never become `Verified`.

## See Also

* [openinstall-repos.md](openinstall-repos.md) - distributor repo catalogs.
* [signing-keys.md](signing-keys.md) - publisher keys and custody.
* [smartscreen.md](smartscreen.md) - why Windows reputation warnings may still appear.
