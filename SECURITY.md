# Security Policy

OpenInstall is a trusted package manager / mini app store for Windows. Users
install OpenInstall once; after that, apps are installed from verified `.oip`
packages that OpenInstall unpacks and installs itself. It is not a SmartScreen or
Windows security bypass, and it is not a silent executor for downloaded installers.

## Trust Model

```text
Windows trusts OpenInstall.msi / OpenInstall.exe
        |
        v
user clicks openinstall://install/com.baar-verlag.baar-reader
        |
        v
OpenInstall resolves repo metadata or a direct .oip link
        |
        v
download https://repo.example/com.baar-verlag.baar-reader/latest.oip
        |
        v
.oip is a ZIP: manifest.json + files/ + signatures/ + SBOM/provenance
        |
        v
verify package signature, publisher identity, file hashes, permissions, policy,
and Authenticode status where possible
        |
        v
show consent dialog
        |
        v
copy files per-user, create Start Menu shortcut, write HKCU uninstall entry
```

Trust comes from the publisher's package signature, the pinned publisher key for
the app id, the manifest's SHA-256 file hashes, and repository metadata when
used. A package signature proves identity and integrity; it does not prove that
an app is benign.

## Invariants We Guarantee

1. **No downloaded setup flow.** OpenInstall v1 does not download
   `installer.exe`, `setup.exe`, `.msi`, PowerShell, or batch files and run them
   as an app install mechanism.
2. **Consent is mandatory.** Resolving `openinstall://` links is side-effect-free
   with respect to installation. Installing requires an explicit Install click
   and a single-use install token minted by a successful resolve.
3. **Fail closed.** Bad signatures, hash mismatches, malformed manifests,
   revoked publishers/packages, forbidden files, denied permissions, and failed
   policy checks abort the install.
4. **Publisher keys are pinned.** The first verified install of an app id pins
   its publisher key. A later package signed by another key is shown as
   `PublisherChanged` and requires explicit user acknowledgement.
5. **OpenInstall does not bypass the OS.** OpenInstall does not disable Windows
   security, add exclusions, suppress OS prompts, or alter operating-system
   security settings.
6. **SmartScreen is not bypassed.** OpenInstall never turns off SmartScreen,
   never adds antivirus exclusions, and never strips the Mark-of-the-Web from a
   file the OS marked (e.g. something a browser downloaded). Files it installs
   from a verified package are written as installed software in the per-user app
   directory — like winget / MSIX / Microsoft Store installs, they are not
   browser-download artifacts, so they do not carry the Mark-of-the-Web and do
   not raise SmartScreen's "unrecognized app" first-run prompt. Microsoft
   Defender's real-time antivirus still scans them on execution, and OpenInstall
   never claims that package verification transfers reputation to unsigned
   binaries.
7. **Normal installs are per-user.** Apps install under
   `%LOCALAPPDATA%\OpenInstall\Apps\<id>\<version>\`, create Start Menu shortcuts
   under the current user profile, and register uninstall metadata under HKCU.
8. **Admin is exceptional.** Normal apps do not request UAC. Services, drivers,
   shell extensions, kernel components, and admin installs are blocked by v1
   policy unless a future reviewed package type explicitly supports them.
9. **Unsigned/invalid app binaries are disclosed.** OpenInstall verifies
   Authenticode status where possible and tells the user when Windows reputation
   warnings may still occur.

## What "No Avoidable Warnings" Means

OpenInstall avoids the scary, avoidable installer path:

* Browser download warnings for random app installers.
* UAC prompts for normal apps.
* Unknown setup executables launched from the browser.
* Unsigned external installer launchers.
* PowerShell or batch installer scripts.
* Admin installs when per-user install is enough.

Because OpenInstall installs verified package files as software (no
Mark-of-the-Web), launching an installed app does not raise SmartScreen's
first-run reputation prompt — the same as any other package manager. The trust
basis is OpenInstall's package verification, not browser-download reputation.

OpenInstall still does not and cannot promise zero Windows security UI:

* Microsoft Defender's real-time antivirus still scans installed files on
  execution and can block genuinely malicious binaries regardless.
* Enterprise / local Windows security policy is respected.
* Installing OpenInstall itself, or running a raw `.exe` you downloaded in a
  browser outside OpenInstall, can still show SmartScreen.

## Reporting a Vulnerability in OpenInstall

If you find a flaw in OpenInstall itself, such as a way to bypass consent, defeat
signature/hash verification, evade Authenticode disclosure, install a forbidden
package type, or make a tampered package appear trusted, please report it
privately:

* Preferred: open a private security advisory via GitHub.
* Do not open a public issue for an exploitable verification or consent bypass
  until a fix is available.

Please include the affected version, a reproduction `.oip` or URL if possible,
and which invariant you believe is violated.

## Reporting a Malicious Package

OpenInstall does not host third-party packages, but it can revoke known-bad
packages and publisher keys for users:

* Report the malicious `.oip` URL, package hash, app id, version, and publisher
  key fingerprint.
* Confirmed malicious package hashes, file hashes, app ids, publisher names, and
  publisher keys can be added to the GitHub-backed `blocklist.txt` revocation
  feed.
* OpenInstall refreshes that feed during resolve, caches it locally as
  `remote-blocklist.txt`, and also honors the local `blocklist.json` file.
* A blocklist match fails closed before the Install consent step.
* For hosting takedown, contact the publisher's host, CDN, registrar, or abuse
  contact. The package file is outside OpenInstall's infrastructure.

## Supported Versions

OpenInstall is pre-1.0. Security fixes are made against the latest release and
`main`. Pin to a released, SignPath-signed `.msi`; do not trust unsigned builds
for production use.

---

Free code signing provided by [SignPath.io](https://signpath.io), certificate by
[SignPath Foundation](https://signpath.org).
