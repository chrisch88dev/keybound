# Configuration

Create one Keybound instance in server-only code and reuse it.

```ts
// src/security/keybound.ts
import { createKeybound } from "keybound";

export const keybound = createKeybound({
  secret: process.env.KEYBOUND_SECRET!,
  preset: "default"
});
```

Do not create it in browser code. Do not ship `KEYBOUND_SECRET` to the client.

`KEYBOUND_SECRET` signs challenge records with HMAC. Generate it once:

```sh
openssl rand -base64 32
```

Use `.env` or `.env.local` for development. Use a real secret manager in production. Every server instance that issues or verifies challenges needs the same value.

Do not use `randomBytes(32)` as a fallback in production startup code. A fresh value on every restart invalidates active challenge records and makes multi-server deployments inconsistent.

## Local Development

Keybound does not provide an insecure cookie mode. `Secure`, `HttpOnly`, and `Path=/` stay enabled.

For local work, use `http://localhost` or local HTTPS. If a browser, proxy, or framework refuses secure cookies on local HTTP, run the dev server with HTTPS. Do not weaken production code to make local setup easier.

## Presets

| Preset | Challenge lifetime | Device cookie |
| --- | ---: | --- |
| `relaxed` | 120 seconds | `SameSite=Lax`, 365 days |
| `default` | 60 seconds | `SameSite=Lax`, 180 days |
| `strict` | 30 seconds | `SameSite=Strict`, 90 days |

`default` is the normal starting point. `strict` is better for admin panels, account recovery, API keys, payouts, crypto, finance, and internal tools.

`relaxed` exists for low-risk apps that want a longer device memory window. Do not use it for sensitive actions without a separate policy reason.

## Cookie Lifetime

The device cookie lifetime is not the login session lifetime.

```text
login session cookie -> controls whether the user is logged in
Keybound device cookie -> selects the enrolled device record
```

If the Keybound device cookie expires, the user may need step-up authentication and device re-enrollment. Your normal session can still expire in 15 minutes, 8 hours, 7 days, or whatever your auth system uses.

## SameSite Lax And Strict

Assume your app is `app.example.com`.

With `SameSite=Lax`, a normal link from another site to your app usually includes the Keybound cookie:

```text
mail.example -> user clicks link -> app.example.com
Keybound cookie is usually sent
```

This avoids annoying first-request gaps when users enter from email, search, chat, docs, support tools, or an OAuth redirect.

With `SameSite=Strict`, the first request from another site usually does not include the Keybound cookie:

```text
mail.example -> user clicks link -> app.example.com
Keybound cookie may be missing on that first request
```

After the user is already inside your app, same-site requests normally include the cookie again.

Use `Lax` when smooth entry matters. Use `Strict` where missing the device cookie should force a stronger check.

## Safe Overrides

You can tune safe fields:

```ts
export const keybound = createKeybound({
  secret: process.env.KEYBOUND_SECRET!,
  preset: "strict",
  challengeTtlMs: 30_000,
  cookie: {
    name: "__Host-keybound",
    sameSite: "strict",
    maxAgeSeconds: 60 * 60 * 24 * 30,
    partitioned: false
  }
});
```

Keybound always forces:

```text
HttpOnly
Secure
Path=/
```

It does not expose `Domain`, `secure: false`, `httpOnly: false`, or custom cookie paths.

## Purpose Binding

Use a stable server-defined purpose for sensitive actions:

```ts
const issued = keybound.issueChallenge({
  sessionId,
  deviceId,
  publicKey: enrolledDevice.publicKey,
  purpose: "payment:create"
});
```

The same purpose must be used during verification:

```ts
await keybound.verifyAndConsumeProof({
  store,
  sessionId,
  deviceId,
  publicKey: enrolledDevice.publicKey,
  purpose: "payment:create",
  challengeId,
  challenge,
  signature
});
```

Do not let the request body decide the purpose. The route handler should set it.
