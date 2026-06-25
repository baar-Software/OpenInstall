# Signing Keys For Publishers

This guide is for app developers who publish native `.oip` packages. It covers
package-signing keys, where the public key appears in `manifest.json`, and the
trust-on-first-use (TOFU) rules OpenInstall applies.

OpenInstall package signing uses an Ed25519-style publisher key. The current
implementation accepts `ed25519:...`, `minisign:...`, or a bare minisign public
key string while the tooling migrates fully to the native format.

## 1. Create A Package Key

Keep the secret key private and publish only the public key:

```sh
minisign -G -p baar-reader.pub -s baar-reader.key
```

The secret key never goes into the `.oip`, repo, source repository, or CI logs.
The public key goes in `manifest.json`.

## 2. Put The Public Key In `manifest.json`

```json
{
  "publisher": {
    "name": "Baar Verlag",
    "key": "minisign:RWQ...",
    "website": "https://example.com"
  }
}
```

Use the same key for every release of the same app id. OpenInstall pins the key
to the bundle identifier, for example `com.baar-verlag.baar-reader`.

## 3. Sign The Package Manifest

The package signature covers the exact bytes of `manifest.json` as it appears in
the `.oip`:

```text
signatures/publisher.ed25519.sig
```

If you edit `manifest.json` after signing, even whitespace, sign it again. A
signature mismatch fails closed and the package will not install.

## 4. Sign Windows App Binaries Too

Package signing and Windows code signing solve different problems:

* Package signature: lets OpenInstall verify publisher identity and package
  integrity.
* File hashes: let OpenInstall verify every installed file.
* Authenticode signatures: let Windows identify `.exe` and `.dll` publishers and
  build SmartScreen reputation.

Sign and timestamp every app `.exe` and `.dll` when possible before building the
`.oip`.

## 5. Key Custody And TOFU

The first verified install of an app id pins the publisher key. Later packages
for the same app id are checked against that pin:

| Situation | Client behavior |
| --- | --- |
| Same id, same key | `Verified`; normal install. |
| New id | `VerifiedNewPublisher`; key is pinned. |
| Same id, different key | `PublisherChanged`; possible impersonation, explicit acknowledgement required. |

This has consequences:

* Reusing an id across unrelated apps or publishers is forbidden.
* Losing the secret key means all existing users will see a publisher-change
  warning when you rotate.
* A stolen secret key lets an attacker publish packages that existing users may
  see as the same publisher until the key is revoked.
* Store signing keys in a password manager, hardware token, or dedicated signing
  service. Never commit `*.key`.

## OpenInstall's Own Signing

OpenInstall release binaries are expected to be Authenticode-signed before
stable public distribution. That certificate signs OpenInstall itself, not
third-party apps and not third-party `.oip` packages.

## See Also

* [oip-format.md](oip-format.md) - native `.oip` format and verification flow.
* [smartscreen.md](smartscreen.md) - Windows reputation and Authenticode.
* [openinstall-repos.md](openinstall-repos.md) - distributor catalog format.
