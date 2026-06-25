# Windows SmartScreen And OpenInstall

SmartScreen is Microsoft's app and download reputation system. It is separate
from OpenInstall package verification, and OpenInstall does not bypass it.

## What OpenInstall Avoids

OpenInstall avoids the avoidable scary flow:

* The browser does not download a random app `Setup.exe`.
* The user does not launch unknown external installers from Downloads.
* Normal apps install per-user without UAC.
* OpenInstall does not run PowerShell, batch, `.msi`, `setup.exe`, or
  `installer.exe` app-install payloads.

Instead, OpenInstall downloads a `.oip`, verifies its package signature, checks
file hashes and permissions, inspects Authenticode status, then copies files
into the per-user app directory itself.

## Why Installed Apps Launch Cleanly

OpenInstall is a package manager. The files it installs come from a package it
has cryptographically verified (publisher signature + per-file SHA-256 + pinned
publisher key + revocation blocklist) and that is forbidden from carrying
installer or script payloads. Those files are written as **installed software**
in the per-user app directory — exactly like apps from winget, MSIX, or the
Microsoft Store. They are not browser-download artifacts, so they do not carry
the **Mark-of-the-Web**, and launching them does not raise SmartScreen's
"unrecognized app" first-run prompt.

This is not an evasion. OpenInstall never marks these files as downloaded and
then strips that mark; it simply installs them as software, the way every package
manager does. Microsoft Defender's real-time antivirus still scans these files on
execution and can block a genuinely malicious binary regardless. The trust basis
is OpenInstall's package verification, which replaces browser-download reputation.

## What OpenInstall Cannot Promise

OpenInstall cannot promise mathematically zero Windows security UI:

* Microsoft Defender real-time antivirus still scans installed files and can
  block genuinely malicious binaries.
* Local or enterprise Windows security policy is respected and may act
  independently.
* Installing OpenInstall itself, or running a raw `.exe` you downloaded in a
  browser *outside* OpenInstall, can still show SmartScreen.

OpenInstall will not, in any case:

* Disable Windows security features (SmartScreen, Defender).
* Add antivirus or SmartScreen exclusions.
* Strip the Mark-of-the-Web from a file the OS marked.
* Hide or alter OS security prompts.
* Modify OS security settings.

## Two Different Signatures

OpenInstall verifies a package signature over `.oip` metadata. Windows
SmartScreen evaluates the reputation of the executable Windows is asked to run.
These are different trust systems:

* Package signature: proves who published the package and that the package
  metadata was not tampered with.
* File hashes: prove each installed file matches the manifest.
* Authenticode signature: tells Windows who signed an `.exe` or `.dll`, and lets
  that binary build Windows reputation.

A package can be verified by OpenInstall and still have unsigned app binaries.
In that case, OpenInstall shows the unsigned status honestly because Windows may
still warn at first launch.

## Publisher Guidance

For the best Windows experience:

1. Sign OpenInstall itself through the official release pipeline.
2. Sign every app `.exe` and `.dll` with Authenticode when possible.
3. Timestamp signatures.
4. Build the native `.oip` from the signed files.
5. Sign the `.oip` package manifest with the publisher package key.
6. Publish through an OpenInstall repo or a direct `.oip` link.

Microsoft SignTool is the standard Windows tool for signing, verifying, and
timestamping binaries. Tauri's Windows distribution guidance also recommends
code signing to reduce SmartScreen friction.
