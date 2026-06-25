## Summary

<!-- What changed and why? -->

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Security hardening
- [ ] Documentation
- [ ] Refactor / maintenance

## Safety Checklist

- [ ] This does not bypass SmartScreen, Windows security policy, or user consent.
- [ ] This does not silently run arbitrary downloaded installers or scripts.
- [ ] Package verification still fails closed.
- [ ] User-facing behavior is documented.

## Tests

<!-- Paste the commands you ran, or explain why a check was not run. -->

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `npm --prefix ui test`
- [ ] `npm --prefix ui run build`

## Screenshots

<!-- For UI changes, include before/after screenshots when possible. -->
