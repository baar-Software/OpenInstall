# OpenInstall repos

An OpenInstall repo is a static HTTPS directory that exposes a catalog at
`/repo.json`. Users can import the repo URL in OpenInstall, browse its apps, and
then install a selected `.oip` through the normal verify-and-consent flow.
After a repo is imported, a bundle link like
`openinstall://com.baar-verlag.baar-reader` resolves to that app's selected
version from the repo.

Importing a repo does not trust the distributor. The catalog is only discovery
metadata; each `.oip` is still downloaded, hash-checked, signature-checked,
verified, and shown in the consent dialog before installation.

Apps do not have to be listed in an imported repo to install. A direct package
link such as `openinstall://example.com/download/coolapp.oip` still resolves and
installs through the same consent flow.

## Add-source links

Publishers can offer a link that asks OpenInstall to add their repo:

```text
openinstall://repo?url=https%3A%2F%2Fexample.com%2Fopeninstall
```

OpenInstall validates `/repo.json` and shows an Add Source dialog first. The repo
is saved only after the user accepts. A repo-add link never installs an app.

## Layout

```text
https://example.com/openinstall/
  repo.json
  com.example.coolapp/
    assets/icon.png
    screenshots/one.png
    screenshots/two.png
    latest.oip
    1.0.0.oip
    1.1.0.oip
```

The app package URL is derived from the repo base, bundle identifier, and version:

```text
openinstall://example.com/openinstall/com.example.coolapp/latest.oip
openinstall://example.com/openinstall/com.example.coolapp/1.1.0.oip
```

`latest` is allowed as a real version name. If you publish it, keep
`latest.oip` signed and internally versioned like any other package.

## `repo.json`

```json
{
  "name": "Example Apps",
  "description": "Apps distributed by Example.",
  "apps": [
    {
      "bundleIdentifier": "com.example.coolapp",
      "name": "CoolApp",
      "description": "A small useful app.",
      "screenshots": ["one.png", "two.png"],
      "latest": "latest",
      "versions": ["latest", "1.1.0", "1.0.0"]
    }
  ]
}
```

Supported app fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `bundleIdentifier` | yes | Stable app id. Used as the package directory name. |
| `name` | yes | Human-readable app name. |
| `description` | no | Short catalog description. |
| `screenshots` / `screenshotFiles` | no | Screenshot file names under `[bundleIdentifier]/screenshots/`. |
| `latest` | no | Version to mark as latest. |
| `versions` | yes | Version names. Each maps to `[bundleIdentifier]/[version].oip`. |

The icon is always loaded from `[bundleIdentifier]/assets/icon.png`. Screenshot
entries must be bare file names, not paths or URLs.

`versions` may also use objects:

```json
{
  "versions": [
    { "version": "1.1.0", "latest": true },
    { "version": "1.0.0" }
  ]
}
```

Bundle identifiers and versions may contain ASCII letters, digits, `.`, `-`, and
`_`. Repo URLs must be HTTPS, except loopback HTTP URLs while Developer Mode is
enabled.
