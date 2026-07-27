# Security Policy

## Current State

Keybound is not stable yet. Do not rely on this repo for production protection until a stable release and security review exist.

## Reporting Vulnerabilities

Use GitHub private vulnerability reporting if it is enabled for the repository.

If private reporting is not enabled, open a minimal public issue asking for a private contact path. Do not include exploit details, secrets, logs, cookies, tokens, or identifying user data in a public issue.

## Security Scope

In scope:

- Session binding logic.
- Token and cookie handling.
- Adapter request parsing.
- Timing-sensitive comparisons.
- Storage contract behavior.
- Config profiles that can weaken security unexpectedly.

Out of scope:

- Vulnerabilities in user applications.
- Weak session secrets controlled by the application.
- Compromised servers.
- Malware running inside the user's active browser session.
- Browser or operating system vulnerabilities.

## Logging Rules

Do not log raw cookies, session IDs, binding tokens, IP addresses, user agent strings, language headers, TLS fingerprints, or custom binding signals. Logs should use coarse event names and request IDs supplied by the host application.
