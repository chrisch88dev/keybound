# Contributing

Keybound is small by design. Keep changes focused, typed, and covered by tests.

## Local Checks

Use Node.js 20 or newer:

```sh
npm ci
npm run check
npm run build
node examples/node-proof.mjs
```

The package uses strict TypeScript, Node.js crypto primitives, and no runtime dependencies. Keep the core independent of a specific framework, database, or session library.

## Pull Requests

- Describe the behavior change and its effect on the public API.
- Include tests for successful and failing paths.
- Keep documentation aligned with the actual API.
- Do not include secrets, cookies, tokens, session IDs, production logs, or user data.
- Use a public issue for ordinary defects and [SECURITY.md](SECURITY.md) for vulnerabilities.

## Security Changes

Changes to challenge encoding, HMAC input, public key parsing, signature verification, expiry, cookie defaults, or the store contract need focused tests. Include the expected behavior under malformed input, concurrent consumption, and upgrade compatibility.

Do not add implicit global state, blocking I/O, or framework-specific policy to the core. Public APIs should be explicit and difficult to misuse.
