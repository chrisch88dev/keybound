# Browser Key

The browser private key is what makes copied cookies less useful. Keep it outside cookies.

## Generate

```js
const keyPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign", "verify"]
);

const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
```

The `false` argument makes the key nonextractable. Browser JavaScript can ask the private key to sign, but cannot export the private key bytes through Web Crypto.

Store the `CryptoKey` in IndexedDB:

```js
const tx = db.transaction("keys", "readwrite");
tx.objectStore("keys").put(keyPair, "device");
```

Do not store the private key in cookies, localStorage, JSON, logs, or analytics.

## Sign

Keybound challenges are base64url strings. Decode the challenge before signing:

```js
const signature = await crypto.subtle.sign(
  { name: "ECDSA", hash: "SHA-256" },
  privateKey,
  decodedChallenge
);
```

Web Crypto returns a raw 64-byte P-256 signature. Keybound verifies that format directly.

## Exceptions

Handle browser crypto errors as proof failure, not as app crashes.

| Exception | Common meaning | Useful response |
| --- | --- | --- |
| `NotAllowedError` | Browser refused the key operation | Retry once or require step-up |
| `InvalidAccessError` | Wrong key type, curve, or key usage | Re-enroll after step-up |
| `DataError` | Malformed key or challenge data | Clear local device state after step-up |
| `OperationError` | Browser crypto operation failed | Retry once, then step-up |

Example:

```js
try {
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    decodedChallenge
  );
} catch (error) {
  return {
    ok: false,
    reason: error.name || "browser-proof-failed"
  };
}
```

Do not silently create a new device after a proof error. Device replacement is a security boundary. Require step-up authentication first.

## Browser Support

Modern Chrome, Edge, Firefox, Safari, and mobile browsers support Web Crypto, IndexedDB, and P-256 ECDSA. Expect edge cases:

```text
private browsing
cleared site data
enterprise browser policy
old browser versions
blocked storage
browser profile migration
```

Those cases should fall back to step-up authentication and device re-enrollment.
