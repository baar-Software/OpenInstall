# Contributing to OpenInstall

Thanks for helping make Windows app installation cleaner and safer.

OpenInstall is security-sensitive software. Please keep changes small, explicit,
and easy to review.

## Ground Rules

* Do not implement SmartScreen or Windows security bypasses.
* Do not disable Windows security or add exclusions, strip/fake
  download-origin metadata, or silently run arbitrary downloaded installers.
* Normal app installs should remain per-user and should not require UAC.
* Favor fail-closed behavior for malformed, unsigned, tampered, or policy-denied
  packages.
* Keep user consent explicit. Resolving a link must not install anything.

## Development Setup

OpenInstall is Windows-only.

Prerequisites:

* Windows 10/11.
* Stable Rust.
* Node.js 20 or newer.
* Tauri CLI v2:

```sh
cargo install tauri-cli --version "^2" --locked
```

Install UI dependencies:

```sh
npm --prefix ui ci
```

Run the app:

```sh
cargo tauri dev
```

## Checks Before Opening a PR

Run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix ui test
npm --prefix ui run build
```

If a check cannot run locally, mention it in the PR.

## Pull Request Style

Good PRs usually:

* Solve one problem.
* Include tests for security or behavior changes.
* Update docs when user-facing behavior, package format, or repo format changes.
* Avoid unrelated formatting/refactors.
* Explain security impact clearly.

## Commit Messages

Use short, conventional prefixes where they help reviewers scan history:

* `core:` verification kernel and trust logic.
* `client:` resolver, install pipeline, registry, state, and blocklist code.
* `pack:` package authoring.
* `ui:` Svelte/Tauri frontend changes.
* `docs:` documentation-only changes.
* `ci:` GitHub Actions and automation.
* `chore:` repository maintenance.

Keep the subject line imperative and specific, for example
`client: reject forbidden package paths`.

## Review Expectations

Security-sensitive changes need tests or a clear explanation of why tests are
not practical. Maintainers may ask for a narrower patch if a PR combines
behavior changes with broad formatting or refactoring.

## Areas That Need Help

* Native `.oip` authoring tools.
* Package signing UX and documentation.
* Repo publishing tools and validation.
* Windows integration tests.
* Accessibility and UI polish.
* Security review of package validation and install policy.

## Reporting Security Issues

Please do not open public issues for vulnerabilities. Use GitHub private security
advisories as described in [SECURITY.md](SECURITY.md).
