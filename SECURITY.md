# Security

Keybound verifies a one-time device proof for a session. It is designed for the case where a session cookie has been copied but the attacker does not have access to the enrolled device key.

## Required Deployment Rules

- Use a server secret with at least 32 random bytes. Keep it in your secret manager, not source control.
- Generate device private keys as nonextractable Web Crypto keys and keep them outside cookies.
- Store the enrolled public key server-side with the device ID. Do not accept a proof request's public key as the enrolled key.
- Require an existing device proof or step-up authentication to enroll or replace a device key. Never allow a cookie-only session to register a new key.
- Pass that stored public key to both `issueChallenge` and `verifyAndConsumeProof`.
- Pass a server-defined `purpose` for sensitive actions. Do not let the request body choose it.
- Implement `consume` as an atomic operation. A read followed by an unconditional write is replayable under concurrent requests.
- Rate-limit challenge issuance and remove expired challenge records through normal storage cleanup.
- Serve the enrollment and proof endpoints over HTTPS. Set the device ID with `keybound.config.cookie` or equivalent secure settings.
- Treat a denied proof as an application security event. Decide whether the action is denial, step-up authentication, session rotation, or session termination.

The stored challenge record contains an ID, an HMAC digest, and an expiry. It does not need to contain the raw challenge, session ID, cookie value, proof purpose, or device public key.

## Security Scope

In scope:

- Challenge generation, expiry, and binding.
- Server purpose binding for challenges.
- HMAC verification and constant-time digest comparison.
- P-256 public key validation and ECDSA signature verification.
- Configuration that could weaken the device cookie or challenge lifetime.
- The contract required for one-time challenge consumption.

Out of scope:

- A compromised application server or server secret.
- XSS, browser extensions, or malware using the active browser session.
- Phishing that obtains a fresh proof from the user for the same server purpose.
- Weak application authentication, session handling, or authorization rules.
- Incorrect database or cache implementations of the atomic store contract.

## Reporting A Vulnerability

Use GitHub private vulnerability reporting for this repository. Do not include exploit details, cookies, tokens, session IDs, logs, or user data in a public issue.

If private reporting is unavailable, open a minimal public issue requesting a private contact path. Include no sensitive detail.

## Release Checks

Before a security-sensitive release, run `npm run check`, test the target Node.js versions, verify browser Web Crypto interoperability, test the production challenge store under concurrent requests, and review changes that affect challenge formats, purpose binding, signature handling, key parsing, or cookie defaults.
