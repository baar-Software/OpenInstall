# Changelog

All notable changes to OpenInstall will be documented here.

This project follows a pre-1.0 release process. Breaking changes may happen while
the native `.oip` package format and authoring tools stabilize.

## Unreleased

### Added

* Native `.oip` package verification and per-user install model.
* OpenInstall repo browsing through `/repo.json`.
* Consented repo-add links.
* Direct `.oip` package links that do not require repo membership.
* User-controlled install flow after OpenInstall package verification.
* Authenticode status disclosure in the consent dialog.
* GitHub community docs and issue/PR templates.
* Privacy, governance, roadmap, download, and code-signing documentation.
* Dependency review workflow for pull requests.

### Changed

* OpenInstall v1 refuses legacy installer-style `.oip` packages at install time.
* README, security docs, package format docs, and signing docs now describe the
  native package-manager model.
* Release documentation now labels unsigned preview MSI artifacts clearly until
  Windows code signing is enabled.

### Security

* OpenInstall package verification remains the install gate.
* The documented security model explicitly rejects Windows security bypasses.
