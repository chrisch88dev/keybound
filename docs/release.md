# Release Checklist

This repo has a manual GitHub Actions release workflow and can also be released from a local machine.

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

## GitHub Actions

Add an `NPM_TOKEN` repository secret before using the workflow.

Then run the `Release` workflow manually from GitHub and set:

```text
confirm = publish
```

The workflow runs install, checks, benchmarks, a pack dry-run, then publishes.

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

npm provenance normally uses a trusted publisher flow through CI. The current workflow uses an npm token secret. Move to trusted publishing later if you want provenance without long-lived npm tokens.
