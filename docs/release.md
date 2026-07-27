# Release Checklist

This repo does not use GitHub Actions. Release manually unless that policy changes.

## Before Publish

Run:

```sh
npm ci
npm run check
npm run bench
npm audit --omit=dev
npm pack --dry-run
```

Check the dry-run contents. It should include:

```text
dist
docs
examples
bench
README.md
SECURITY.md
LICENSE
package.json
```

It should not include:

```text
local instruction files
private notes
node_modules
coverage
```

## First Publish

Log in:

```sh
npm login
```

Confirm the package name:

```sh
npm view keybound
```

If the name is available or owned by you, publish:

```sh
npm publish --access public
```

## Git Tag

After npm publish succeeds:

```sh
git tag -s v0.1.0 -m "keybound v0.1.0"
git push origin v0.1.0
```

Use the `2D45` signing key:

```text
6A0DC11D3231AF40DCDC75712D4500072620C9BA
```

## GitHub Release

Create a GitHub release from `v0.1.0`.

Keep release notes short:

```text
Initial public release.

- Device-key proof core
- Purpose-bound challenges
- HTTP cookie helpers
- Browser key helper
- Login demo
- Storage and framework docs
```

## Provenance

npm provenance normally uses a trusted publisher flow through CI. Since this repo currently avoids GitHub Actions, manual publish is the simpler path. Add a workflow only if the project policy changes.
