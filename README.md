# keybound

Device-key session proof for Node.js.

Keybound helps protect high-risk server actions when session cookies are copied from a browser profile, malware dump, leaked disk backup, or stolen cookie jar. It does not replace your login system. It adds a proof step that copied cookies alone cannot complete.

Read more at [chrisch88.dev/projects/keybound](https://chrisch88.dev/projects/keybound).

```text
session cookie          says who is logged in
Keybound device cookie  says which enrolled device record to load
browser private key     proves the browser has the enrolled key
purpose                 says what server action the proof is for
```

The core is TypeScript, ESM, framework-neutral, database-neutral, and has no runtime dependencies.

## What It Solves

Normal cookie replay:

```text
1. User logs in
2. Browser stores session cookie
3. Attacker copies cookie from a file dump
4. Attacker sends the cookie from another machine
5. Server sees a valid session token
```

With Keybound:

```text
1. User logs in
2. Browser creates a nonextractable P-256 private key
3. Server stores the matching public key for that device
4. Attacker copies the cookies
5. Server asks for a fresh signed challenge
6. Attacker has cookies, but not the browser private key
```

This raises the cost of replaying stolen cookies. It does not protect against a compromised server, XSS running inside the real browser, malware controlling the live browser, or phishing that obtains a fresh proof for the same action.

## Install

```sh
npm install keybound
```

Requires Node.js 20 or newer.

## Server Setup

Create one Keybound instance in server-only code.

```ts
// src/security/keybound.ts
import { createKeybound } from "keybound";

export const keybound = createKeybound({
  secret: process.env.KEYBOUND_SECRET!,
  preset: "default"
});
```

`KEYBOUND_SECRET` is a server secret used for HMAC records. It must be the same on every server instance that issues or verifies challenges.

Generate it once:

```sh
openssl rand -base64 32
```

Put it in your local `.env` file for development. Put it in your secret manager for production. Do not generate a new random secret on every process start, or old challenges will stop verifying after a restart.

For local development, keep the same safe config and use `localhost` or local HTTPS. See [configuration](docs/configuration.md) for details.

## Demo

Run the browser login demo:

```sh
npm run demo:login
```

Open:

```text
http://localhost:4173
```

## The Flow

```text
Login or step-up
  |
  | browser creates P-256 key pair
  | private key stays in IndexedDB
  | public key goes to server
  v
Server stores device record
  |
  | user_id, session_id, device_id, public_key
  v
Protected action
  |
  | server issues challenge for purpose
  | browser signs challenge
  v
Server verifies and consumes once
```

The backend must link the normal session and Keybound device record:

```text
user_id
session_id or session family id
device_id
public_key
created_at
last_seen_at
revoked_at
```

Never verify against a public key from the request body. Load the enrolled public key from your database or session store.

## Server Example

Issue a challenge:

```ts
const issued = keybound.issueChallenge({
  sessionId: session.id,
  deviceId: enrolledDevice.id,
  publicKey: enrolledDevice.publicKey,
  purpose: "session:renew"
});

await challengeStore.insert(issued.record);

return {
  challengeId: issued.id,
  challenge: issued.challenge,
  expiresAt: issued.expiresAt
};
```

Verify the browser proof:

```ts
const result = await keybound.verifyAndConsumeProof({
  store: challengeStore,
  sessionId: session.id,
  deviceId: enrolledDevice.id,
  publicKey: enrolledDevice.publicKey,
  purpose: "session:renew",
  challengeId: request.body.challengeId,
  challenge: request.body.challenge,
  signature: request.body.signature
});

if (!result.ok) {
  // Deny, step up, rotate the session, or end the session.
}
```

The store has two operations:

```ts
interface KeyboundChallengeStore {
  get(challengeId: string): Promise<KeyboundChallengeRecord | null>;
  consume(challengeId: string, expectedDigest: string): Promise<boolean>;
}
```

`consume` must be atomic. It returns `true` once for the matching challenge ID and digest. Later calls return `false`. Use a conditional delete or update in SQL. Use one atomic command or script in Redis.

## Browser Key

Use `keybound/browser` in browser code:

```js
import {
  describeKeyboundBrowserError,
  getOrCreateKeyboundBrowserKey
} from "keybound/browser";

try {
  const deviceKey = await getOrCreateKeyboundBrowserKey();

  await fetch("/keybound/enroll", {
    method: "POST",
    body: JSON.stringify({ publicKey: deviceKey.publicKey })
  });

  const issued = await fetch("/keybound/challenge").then((res) => res.json());
  const signature = await deviceKey.signChallenge(issued.challenge);
} catch (error) {
  console.log(describeKeyboundBrowserError(error));
}
```

The helper creates a nonextractable P-256 key and stores it as a `CryptoKey` in IndexedDB. Browser JavaScript can ask the key to sign, but cannot export the private key bytes through Web Crypto.

## Configuration

Most apps should start with:

```ts
createKeybound({
  secret: process.env.KEYBOUND_SECRET!,
  preset: "default"
});
```

Main presets:

| Preset | Challenge lifetime | Device cookie |
| --- | ---: | --- |
| `default` | 60 seconds | `SameSite=Lax`, 180 days |
| `strict` | 30 seconds | `SameSite=Strict`, 90 days |

The device cookie lifetime is not the login lifetime. Your auth system still controls whether a user session lasts 15 minutes, 8 hours, 7 days, or any other period. The Keybound cookie only selects the enrolled device record.

Safe overrides:

```ts
createKeybound({
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

Keybound always keeps:

```text
Secure
HttpOnly
Path=/
```

## Lax And Strict Cookies

Assume your app is `app.example.com`.

`SameSite=Lax`:

```text
user clicks link in email -> app.example.com
Keybound cookie is usually sent
```

This is the practical default. It works better with email links, support links, OAuth redirects, docs, search, chat, and payment redirects.

`SameSite=Strict`:

```text
user clicks link from another site -> app.example.com
Keybound cookie may be missing on the first request
```

After the user is already inside your app, same-site requests normally include the cookie again.

Use `default` for normal apps. Use `strict` for admin panels, account recovery, API keys, payouts, security settings, and other high-risk areas.

## HTTP Helpers

Use `keybound/http` when your framework needs raw cookie headers:

```ts
import {
  readKeyboundCookie,
  serializeKeyboundCookie,
  clearKeyboundCookie
} from "keybound/http";
```

These helpers work with plain Node, Express, Fastify, Next.js route handlers, Hono, and other Node HTTP frameworks.

Use `keybound/browser` for browser key creation, IndexedDB storage, signing, and browser exception mapping.

## Performance

The hot path is small:

```text
issue challenge: random bytes + HMAC-SHA-256
verify proof: HMAC-SHA-256 + P-256 signature verification
storage: your database or cache
```

The core does no network I/O, database I/O, request parsing, or logging. Use it for session renewal and sensitive actions, not every image, script, or static page request.

Run `npm run bench` from the repo to measure the core proof paths on your machine.

## Docs

- [How it works](docs/how-it-works.md)
- [Configuration](docs/configuration.md)
- [Browser key and exceptions](docs/browser-key.md)
- [Storage examples](docs/storage.md)
- [Framework wiring](docs/frameworks.md)
- [Release checklist](docs/release.md)
- [Login demo](docs/demo.md)

## Testing

```sh
npm run check
```

The test suite covers valid proofs, session, device, and purpose mismatches, tampered challenges, key substitution, expiry, malformed input, cookie helpers, and atomic replay handling.

Security issues belong in [SECURITY.md](SECURITY.md).

## License

MIT
