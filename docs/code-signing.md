# Code Signing

OpenInstall is applying for the SignPath Foundation program so official Windows
release binaries can be Authenticode-signed through the SignPath Foundation.

Until that application is approved and signing is enabled, release workflow
artifacts are clearly labeled as unsigned preview builds.

## Planned Official Download Location

Official releases are published on GitHub Releases:

https://github.com/baar-Software/OpenInstall/releases

After SignPath Foundation approval, this page will be the canonical download
location for SignPath Foundation-signed OpenInstall release binaries.

## What The Signature Covers

The Windows code signature covers OpenInstall's own MSI and executable files. It
does not sign third-party app binaries and does not replace OpenInstall's `.oip`
package-signature verification.

OpenInstall packages still use publisher package signatures, file hashes,
publisher-key pinning, policy checks, and explicit user consent before install.

## Security Reports

Do not report vulnerabilities in public issues. Use GitHub Security Advisories:

https://github.com/baar-Software/OpenInstall/security/advisories/new
