# Downloads

Official OpenInstall downloads are published on GitHub Releases:

https://github.com/baar-Software/OpenInstall/releases

OpenInstall is applying for the SignPath Foundation program so official Windows
release binaries can be Authenticode-signed through the SignPath Foundation.

Until the SignPath Foundation application is approved and signing is enabled,
release workflow artifacts are labeled as unsigned preview builds.

## Verification

After SignPath Foundation signing is enabled, release notes will identify signed
MSI assets and users will be able to inspect the Authenticode signature in
Windows file properties or with PowerShell:

```powershell
Get-AuthenticodeSignature .\OpenInstall*.msi
```

## Source Code

Source code is available in the main repository:

https://github.com/baar-Software/OpenInstall
