# Test fixtures

The adversarial integration suite (`tests/adversarial.rs`) builds native `.oip`
packages **hermetically in-process** using `tests/common/mod.rs` (minisign keys +
`zip`), so the fixtures are generated fresh on every `cargo test` run — no network,
no committed secrets, fully reproducible.

A native `.oip` is a zip containing:

```text
manifest.json                          # app metadata + per-file sha256 pins + publisher key
files/<app files>                      # the verified application files
signatures/publisher.ed25519.sig       # detached minisign signature over manifest.json
```

The fail-closed variants exercised (brief §10):

| Variant             | What it is                                            | Expected result |
|---------------------|-------------------------------------------------------|-----------------|
| `good`              | valid, signed, file hashes correct                    | verifies; trust = `VerifiedNewPublisher` (no pin) |
| `flipped-file`      | good package, one file byte flipped                   | per-file SHA-256 mismatch → refused |
| `edited-manifest`   | `manifest.json` edited **after** signing              | signature invalid → refused |
| `wrong-key`         | manifest embeds key **A** but is signed with key **B** | signature does not verify under **A** → refused |
| `missing-signature` | no `signatures/publisher.ed25519.sig`                 | refused |
| `malformed`         | `manifest.json` is not valid JSON                     | refused |

## Building a real sample package for manual inspection

Use `oip-cli` with a throwaway keypair to produce a real signed native `.oip` you
can open in the app or inspect with a zip tool:

```sh
# from the repo root
cargo run -p oip-cli -- keygen --out mykey
cargo run -p oip-cli -- build \
  --app path/to/AppFolder --out sample.oip \
  --id com.example.coolapp --name CoolApp --publisher "Example Dev" \
  --version 1.4.2 --secret-key mykey.key --public-key mykey.pub
cargo run -p oip-cli -- verify --package sample.oip
```
