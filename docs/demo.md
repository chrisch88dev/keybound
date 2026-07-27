# Login Demo

The repo includes a local browser demo:

```sh
npm run demo:login
```

Open:

```text
http://localhost:4173
```

The demo uses:

```text
node:http server
in-memory sessions
in-memory devices
in-memory one-time challenges
browser Web Crypto
browser IndexedDB
```

No database or framework is required.

## What To Click

1. Click `Login and enroll browser`.
2. Click `Run protected action`.
3. Click `Simulate copied cookies`.
4. Click `Logout`.

The page shows:

```text
logged-in state
whether the session is linked to an enrolled device
whether a session cookie exists
whether a Keybound device cookie exists
challenge and proof results
copied-cookie failure
```

## What It Demonstrates

During login, the browser creates a nonextractable P-256 key. The public key goes to the server. The private key stays in IndexedDB.

The server creates:

```text
normal session cookie
Keybound device cookie
server-side session record
server-side device record with public key
```

For a protected action, the server issues a challenge for a purpose such as:

```text
settings:view-secret
```

The browser signs the challenge. The server verifies the signature against the stored public key, then consumes the challenge once.

The copied-cookie simulation shows the core point: copied cookies can name a session and device, but cannot sign a fresh challenge without the browser private key.
