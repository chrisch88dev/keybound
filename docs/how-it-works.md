# How Keybound Works

Keybound is for applications where copied session cookies are a real risk. A normal session cookie proves that a request knows the session token. It does not prove that the request came from the browser where the session was created.

Keybound adds a second check:

```text
normal session cookie -> who is logged in
Keybound device cookie -> which enrolled device record to load
browser private key -> proof that copied cookies are not enough
purpose -> the exact server action this proof is for
```

The server remains the source of truth. The device cookie is only a lookup value.

## Server State

Store a device record next to your user or session state:

```text
user_id
session_id or session_family_id
device_id
public_key
created_at
last_seen_at
revoked_at
```

On a protected action, the backend should:

1. Read the normal session cookie.
2. Load the authenticated session from your session store.
3. Read the Keybound device cookie.
4. Load the enrolled device record for that user or session.
5. Pass the stored public key to Keybound.
6. Verify and consume a fresh challenge.

Never trust a public key from the proof request body as enrolled state. That lets an attacker bring their own key.

## Challenge Record

When the server issues a challenge, Keybound returns:

```text
challengeId
challenge
expiresAt
record
```

Store `record`. Return `challengeId`, `challenge`, and `expiresAt` to the browser.

The record contains only:

```text
id
digest
expiresAt
```

The digest is HMAC-SHA-256 over:

```text
protocol label
sessionId
deviceId
purpose
challengeId
raw challenge
public key x coordinate
public key y coordinate
expiresAt
```

Length prefixes are used before each field, so values cannot be rearranged into another valid message.

## Verification

The browser signs the raw challenge bytes with ECDSA P-256 and SHA-256. Keybound verifies:

```text
challenge record exists
challenge is not expired
record id matches challenge id
session id matches the issued challenge
device id matches the issued challenge
purpose matches the issued challenge
public key matches the issued challenge
signature matches the stored public key
challenge is consumed once
```

If any part does not line up, the protected action should not run.

## What Happens On Mismatch

Missing device cookie:

```text
do not run high-risk action
require step-up authentication
re-enroll only after step-up
```

Device ID belongs to another user:

```text
deny
clear the device cookie
rotate or end the session if your risk policy requires it
```

Challenge replayed:

```text
deny
keep the action blocked
review concurrent request behavior in your challenge store
```

Invalid signature:

```text
deny
do not auto-enroll
consider step-up or session rotation
```

## Security Limits

Keybound helps when cookies are copied but the browser private key is not copied. It does not protect against a compromised server, stolen server secret, XSS that can run inside the active browser, malware controlling the browser, or phishing that obtains a fresh proof for the same purpose.

Use it with secure session cookies, CSRF protection, XSS defenses, MFA, session rotation, rate limits, and clear device revocation.

## Why Not CPU Timing Checks

Keybound does not try to prove that a request came from the same CPU by measuring browser calculation time, WebAssembly speed, rendering timing, or similar signals.

Those checks are fragile:

```text
battery mode changes timing
thermal throttling changes timing
browser updates change timing
JIT warmup changes timing
mobile devices vary heavily
virtual machines and remote desktops distort results
attackers can replay or shape timing
privacy tools may reduce timer precision
```

They also create fingerprinting concerns. Keybound uses cryptographic possession instead: the browser either has the enrolled private key and can sign the challenge, or it cannot.
