# keybound

Session replay resistance for Node.js.

Keybound is a TypeScript package for applications that want additional protection around authenticated sessions. Its purpose is to make copied session cookies harder to reuse from a different environment without making ordinary changes in a user's network or browser session cause avoidable sign-outs.

The package is in early development. The current release contains immutable security presets and the type definitions that will support the session protection API.

## Install

```sh
npm install keybound
```

## Current API

```ts
import { DEFAULT_PRESET } from "keybound";

const sessionSecurity = {
  ...DEFAULT_PRESET,
  // Add application-specific settings when the session API is enabled.
};
```

The exported presets are the starting point for the public configuration model. The session middleware, storage contract, and framework adapters are not part of this release yet.

## Design Boundary

- Designed to work with existing authentication, session, and database systems.
- Core security decisions will remain independent of a specific framework or database.
- Session state and application policy remain under the host application's control.
- The package will complement secure cookies, session rotation, CSRF protection, XSS defenses, MFA, and incident response.
- No security package can protect a session from a compromised server or code running inside the active browser session.

Keybound is focused on session replay. It is not an HTTP security-header package and is not intended to replace Helmet.

## Project Status

The API is being developed in small, reviewable steps. Do not use this package as the only protection for production sessions until the session implementation has been released and reviewed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development and review expectations.

## Security

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

MIT
