# Roadmap

OpenInstall is pre-1.0. The current focus is making the native `.oip` model
boring, auditable, and pleasant to use before expanding the ecosystem.

## Near Term

* Stabilize the native `.oip` package format.
* Improve package-authoring validation and error messages.
* Add stronger repository catalog validation tooling.
* Enable official Windows code signing for OpenInstall release binaries.
* Expand Windows integration tests around install, uninstall, shortcuts, and
  update state.

## Medium Term

* Add publisher-facing package/repo lint commands.
* Improve the Store browsing experience for larger repositories.
* Document practical publisher key rotation and revocation workflows.
* Add release provenance and reproducibility notes.
* Improve accessibility and keyboard navigation in the UI.

## Not Planned For v1

* Silent installs.
* Arbitrary installer script execution.
* Driver, service, or system-wide admin package types.
* Disabling or bypassing Windows security controls.
* Running downloaded `setup.exe` or `.msi` payloads as the install mechanism.

## Feedback

Use GitHub issues for public feature discussions and GitHub Security Advisories
for private vulnerability reports.
