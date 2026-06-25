# Test fixtures

The adversarial integration suite (`tests/adversarial.rs`) builds `.oip` packages
**hermetically in-process** using `tests/common/mod.rs` (minisign keys + `zip`),
so the canonical fixtures are generated fresh on every `cargo test` run — no
network, no committed secrets, fully reproducible.

The variants exercised (brief §10):

| Variant            | What it is                                              | Expected result |
|--------------------|--------------------------------------------------------|-----------------|
| `good`             | valid, signed, hashes correct                          | parses, signature verifies, payload verifies; trust = `VerifiedNewPublisher` (no pin) / `Verified` (matching pin) |
| `tampered-payload` | good package with one payload byte flipped             | `verify_payload` → `Blake3Mismatch` → refused |
| `tampered-manifest`| manifest edited **after** signing                      | `verify_manifest_sig` → `SignatureInvalid` → refused |
| `wrong-key`        | validly signed with key **B**, but id pinned to key **A** | `evaluate_trust` → `PublisherChanged`; never a silent install |
| `unsigned`         | no `[publisher_key]`, no `manifest.minisig`            | parses; trust = `Unverified`; can never become `Verified` |
| `malformed`        | bad hash hex / `schema != 1` / non-reverse-DNS id / missing field / non-TOML | `parse_manifest` → `Err` (fail closed) |

## Generating a real sample package for manual inspection

A throwaway, **TEST-ONLY** keypair is committed here (`testkey.pub` / `testkey.key`)
— it is NOT a real publisher key, do not trust it. Use it with `oip-cli` to build a
real signed `.oip` you can open in the app or inspect with a zip tool:

```sh
# from the repo root
cargo run -p oip-cli -- build \
  --payload path/to/Setup.exe --out fixtures/sample.oip \
  --id com.example.coolapp --name CoolApp --publisher "Example Dev" \
  --version 1.4.2 --silent-args "/S" --public-key fixtures/testkey.pub
cargo run -p oip-cli -- sign --package fixtures/sample.oip --secret-key fixtures/testkey.key
cargo run -p oip-cli -- verify --package fixtures/sample.oip
```
