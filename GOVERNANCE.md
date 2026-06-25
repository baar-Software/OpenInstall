# Governance

OpenInstall is maintained by the Baar-Verlag Software Team with help from
community contributors.

## Maintainer Responsibilities

Maintainers are responsible for:

* reviewing pull requests,
* keeping CI and release automation healthy,
* triaging issues and security reports,
* preserving the package verification and consent model,
* documenting changes that affect users, publishers, or repository operators.

## Decision Making

OpenInstall is pre-1.0 and security-sensitive. Maintainers make final decisions
by rough consensus, with extra caution for changes that affect verification,
publisher identity, install policy, update behavior, or user consent.

Changes that weaken an invariant in `SECURITY.md` are out of scope unless they
come with a documented replacement model and explicit maintainer approval.

## Contributions

Contributions are welcome. Small, focused pull requests are easiest to review.
Please read `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md` before
opening a pull request.

## Security Reports

Do not report vulnerabilities publicly. Use GitHub Security Advisories:

https://github.com/baar-Software/OpenInstall/security/advisories/new
