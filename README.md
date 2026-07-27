# keybound

Device-key session proof for Node.js. Keybound makes copied session cookies harder to replay by requiring a browser-held private key for sensitive server actions.

Keybound started from a practical problem: cookie dumps make normal session cookies portable. The goal is a small Node.js security primitive that a solo developer can understand, test, and wire into real apps without buying into a framework or platform.

Keybound adds a proof step to an authenticated session. A browser-held P-256 key signs a fresh server challenge that is bound to one session, one device, one server purpose, and the enrolled public key. A copied cookie does not contain that private key.

Keybound is framework-neutral. It does not replace your authentication library, session store, or database. It provides the small server-side core that those systems can call.

## Install

```sh
npm install keybound
```

Requires Node.js 20 or newer.

## Setup

Use a random server secret. Keep it out of source control and rotate it through your normal secret-management process.

```ts
import { randomBytes } from "node:crypto";
import { createKeybound } from "keybound";

const keybound = createKeybound({
  secret: process.env.KEYBOUND_SECRET ?? randomBytes(32),
  preset: "default"
});
```

`keybound.config.cookie` is the hardened configuration for the device identifier cookie. The default is an `__Host-` cookie with `Secure`, `HttpOnly`, and `Path=/` set. The device identifier is not a secret. The browser private key is the proof material and must not be stored in a cookie.

The Keybound device cookie is separate from your login cookie:

```text
session cookie -> who is logged in
Keybound device cookie -> which enrolled device record to load
browser private key -> proof that copied cookies are not enough
```

## Flow

1. The browser creates an ECDSA P-256 key pair with Web Crypto. Create the private key as nonextractable and persist it outside cookies, for example in IndexedDB.
2. During device enrollment, send the public JWK to the server. Store it against a server-generated device ID.
3. Set the device ID as the configured secure cookie. Store the public key server-side.
4. When proof is required, issue a short-lived challenge for a server purpose and return its ID and value to the browser.
5. The browser signs the base64url-decoded challenge with ECDSA SHA-256, then sends the signature back.
6. Load the enrolled public key from the server, verify the proof, and atomically consume the challenge.

The public key passed to Keybound must come from the enrolled device record, not from the proof request body. Keybound also binds that key into the challenge record, so a swapped key cannot verify a previously issued challenge.

Use `purpose` to bind a challenge to the server action that requested it. Examples: `session:renew`, `device:replace`, `mfa:step-up`, `payment:create`. A proof issued for `session:renew` will not verify as `payment:create`, even inside the same session and device.

Device enrollment and replacement are security boundaries. Require an existing device proof or step-up authentication before adding or replacing a key. A cookie-only enrollment endpoint lets a cookie thief register their own device.

## Server Example

```ts
const issued = keybound.issueChallenge({
  sessionId,
  deviceId,
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

```ts
const result = await keybound.verifyAndConsumeProof({
  store: challengeStore,
  sessionId,
  deviceId,
  challengeId: request.body.challengeId,
  challenge: request.body.challenge,
  signature: request.body.signature,
  publicKey: enrolledDevice.publicKey,
  purpose: "session:renew"
});

if (!result.ok) {
  // Deny, require step-up, or end the session according to your application policy.
}
```

`challengeStore` has two operations:

```ts
interface KeyboundChallengeStore {
  get(challengeId: string): Promise<KeyboundChallengeRecord | null>;
  consume(challengeId: string, expectedDigest: string): Promise<boolean>;
}
```

`consume` must be atomic. It must return `true` once for the matching challenge ID and digest, then return `false` for every later call. A SQL implementation can use a conditional update or delete. A Redis implementation should use one atomic command or script.

The included runnable flow is available after building:

```sh
npm run build
node examples/node-proof.mjs
```

The browser login demo shows the full session and device flow:

```sh
npm run demo:login
```

Open `http://localhost:4173`.

## Configuration

| Preset | Challenge lifetime | Device cookie |
| --- | ---: | --- |
| `relaxed` | 120 seconds | `SameSite=Lax`, 365 days |
| `default` | 60 seconds | `SameSite=Lax`, 180 days |
| `strict` | 30 seconds | `SameSite=Strict`, 90 days |

All presets keep `Secure`, `HttpOnly`, and `Path=/` enabled. You can choose a preset and override the safe cookie fields:

```ts
const keybound = createKeybound({
  secret: process.env.KEYBOUND_SECRET!,
  preset: "strict",
  cookie: {
    name: "__Host-keybound-device",
    maxAgeSeconds: 60 * 60 * 24 * 30,
    partitioned: true
  }
});
```

Challenge lifetime is deliberately bounded from 5 seconds to 5 minutes. Shorter lifetimes reduce the replay window. The device cookie is host-only because Keybound does not expose a `Domain` option.

`purpose` is optional and defaults to `session`. For sensitive routes, pass an explicit stable value from server code. Do not trust the request body to choose the purpose.

For cookie helpers:

```ts
import {
  readKeyboundCookie,
  serializeKeyboundCookie,
  clearKeyboundCookie
} from "keybound/http";
```

## Browser Key

The browser side should use Web Crypto:

```js
const keyPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign", "verify"]
);

const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
```

The `false` value makes the private key nonextractable. Browser JavaScript can still ask the key to sign, but it cannot export the private key bytes through Web Crypto. Store the private key in IndexedDB as a `CryptoKey`, not in cookies or localStorage.

When signing a challenge, decode the base64url challenge first:

```js
const signature = await crypto.subtle.sign(
  { name: "ECDSA", hash: "SHA-256" },
  privateKey,
  decodedChallenge
);
```

Web Crypto returns the raw P-256 signature format. Keybound verifies that format directly, so the browser does not need DER conversion.

Expect browser exceptions during enrollment or proof:

- `NotAllowedError`: the key cannot be used for the requested operation.
- `InvalidAccessError`: the key type, curve, or usages do not match.
- `DataError`: imported key data is malformed.
- `OperationError`: the browser could not complete the crypto operation.

Treat those as proof failure, then use your application policy: retry once, require step-up authentication, replace the device after step-up, or end the session.

## Technology And Performance

- Strict TypeScript and ESM.
- Node.js built-ins only, with no runtime dependencies.
- `randomBytes` for challenge and device IDs.
- HMAC-SHA-256 to bind the challenge, session, device, purpose, public key, and expiry into the stored record.
- ECDSA P-256 with SHA-256 for browser proof verification.

Issuing a challenge performs one random generation step and one HMAC. Verifying a proof performs one HMAC and one P-256 signature verification. The core does no network or database I/O. Storage latency and the browser round trip remain the application’s responsibility, so use proof on session continuation, session renewal, and high-risk actions rather than static asset requests.

## Security Boundary

Keybound helps when an attacker has copied cookies but cannot use the enrolled browser key. It also limits where a fresh proof can be used when you bind challenges to server purposes. It does not protect a compromised server, XSS or malware operating inside the active browser, phishing that obtains a fresh proof for the same purpose, or an application that accepts an attacker-controlled public key as enrolled state.

It complements secure session cookies, session rotation, CSRF protection, XSS defenses, MFA, and incident response. It is not an HTTP security-header package and does not replace Helmet.

## Docs

- [How it works](docs/how-it-works.md)
- [Configuration](docs/configuration.md)
- [Browser key and exceptions](docs/browser-key.md)
- [Framework wiring](docs/frameworks.md)
- [Login demo](docs/demo.md)

## Testing

```sh
npm run check
```

The test suite covers valid proofs, session, device, and purpose mismatches, tampered challenges, key substitution, expiry, malformed input, and atomic replay handling.

Security issues belong in [SECURITY.md](SECURITY.md). Contribution and review expectations are in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
