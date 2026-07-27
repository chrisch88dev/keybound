# Contributing

Keybound is security-sensitive software. Keep changes focused, reviewable, and supported by tests.

## Development

Use Node.js 20 or newer, then run:

```sh
npm ci
npm run check
```

The package is written in strict TypeScript and currently has no runtime dependencies. Keep the core independent of frameworks, databases, and application-specific session stores.

## Changes

- Include tests for behavior changes.
- Explain changes to security behavior, defaults, and public types.
- Keep request-path work bounded and avoid unnecessary allocations or blocking I/O.
- Do not include secrets, cookies, tokens, private logs, or production request data.
- Keep documentation precise and avoid claims that cannot be tested.

## Security-Sensitive Changes

Changes involving cookie handling, session binding, cryptography, comparisons, parsing, or revocation need focused tests and careful review. Explain relevant failure behavior and compatibility impact in the pull request.

Public API changes should be typed, explicit, and difficult to misuse. Avoid implicit global state and framework-specific behavior in the core package.
