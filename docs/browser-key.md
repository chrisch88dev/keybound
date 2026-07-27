# Browser Key

Use `keybound/browser` in browser code. The server package verifies proofs, but the browser helper handles the private key.

```js
import {
  describeKeyboundBrowserError,
  getOrCreateKeyboundBrowserKey
} from "keybound/browser";

const deviceKey = await getOrCreateKeyboundBrowserKey();

await fetch("/keybound/enroll", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ publicKey: deviceKey.publicKey })
});
```

Later, after the server returns a challenge:

```js
const signature = await deviceKey.signChallenge(challenge);
```

Send `challengeId`, `challenge`, and `signature` to your server.

## What The Helper Does

`getOrCreateKeyboundBrowserKey`:

```text
checks for Web Crypto and IndexedDB
opens an IndexedDB database
loads the existing device key if present
otherwise creates a new P-256 ECDSA key pair
stores the key pair as CryptoKey objects
returns the public JWK and a signChallenge function
```

The private key is created as nonextractable. Browser JavaScript can ask the key to sign a challenge, but cannot export the private key bytes through Web Crypto.

Do not store the private key in cookies, localStorage, JSON, logs, or analytics.

## Options

```js
const deviceKey = await getOrCreateKeyboundBrowserKey({
  dbName: "my-app-keybound",
  storeName: "device-keys",
  keyName: "default"
});
```

Most apps can use the defaults.

Use a different `keyName` if your app supports multiple independent device keys in the same browser profile.

## Exceptions

Handle browser crypto and storage failures as proof failure, not as crashes.

```js
try {
  const deviceKey = await getOrCreateKeyboundBrowserKey();
  const signature = await deviceKey.signChallenge(challenge);
} catch (error) {
  const reason = describeKeyboundBrowserError(error);
  // Retry once, require step-up, or ask the user to re-enroll the device.
}
```

| Reason | Common cause | Useful response |
| --- | --- | --- |
| `not-supported` | Web Crypto or IndexedDB is unavailable | Fall back to normal login or step-up |
| `not-allowed` | Browser refused the key operation | Retry once, then step-up |
| `invalid-access` | Wrong key type, curve, or usage | Re-enroll after step-up |
| `data-error` | Malformed key or challenge data | Clear local key after step-up |
| `operation-error` | Browser crypto or IndexedDB operation failed | Retry once, then step-up |

Do not silently enroll a new device after a proof error. Device replacement is a security boundary. Require step-up authentication first.

## Raw Web Crypto

The helper uses the same browser primitives you would write by hand:

```js
const keyPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign", "verify"]
);
```

The `false` argument makes the private key nonextractable.

Web Crypto returns a raw 64-byte P-256 signature for ECDSA. Keybound verifies that format directly, so the browser does not need DER conversion.

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
