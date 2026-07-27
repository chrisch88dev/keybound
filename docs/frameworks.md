# Framework Wiring

Keybound core is framework-neutral. The backend rules stay the same in every framework:

```text
read session cookie
load session from server store
read Keybound device cookie
load enrolled device for that user or session
use the stored public key
issue or verify proof for a server-defined purpose
```

The `keybound/http` export helps with cookie handling:

```ts
import {
  readKeyboundCookie,
  serializeKeyboundCookie,
  clearKeyboundCookie
} from "keybound/http";
```

## Shared Setup

```ts
// src/security/keybound.ts
import { createKeybound } from "keybound";

export const keybound = createKeybound({
  secret: process.env.KEYBOUND_SECRET!,
  preset: "default"
});
```

## Plain Node

```ts
import { createServer } from "node:http";
import { readKeyboundCookie, serializeKeyboundCookie } from "keybound/http";
import { keybound } from "./security/keybound.js";

createServer(async (req, res) => {
  const deviceId = readKeyboundCookie(req.headers.cookie, keybound.config);

  if (req.url === "/login" && req.method === "POST") {
    const newDeviceId = keybound.createDeviceId();
    res.setHeader("Set-Cookie", serializeKeyboundCookie(keybound.config, newDeviceId));
    res.end("ok");
    return;
  }

  res.end(deviceId ?? "no device");
});
```

## Express

```ts
app.post("/keybound/challenge", async (req, res) => {
  const session = await sessions.require(req);
  const deviceId = readKeyboundCookie(req.headers.cookie, keybound.config);
  const device = await devices.requireForSession(session, deviceId);

  const issued = keybound.issueChallenge({
    sessionId: session.id,
    deviceId: device.id,
    publicKey: device.publicKey,
    purpose: "settings:view-secret"
  });

  await challengeStore.insert(issued.record);
  res.json({
    challengeId: issued.id,
    challenge: issued.challenge,
    expiresAt: issued.expiresAt
  });
});
```

## Fastify

```ts
fastify.post("/keybound/proof", async (request, reply) => {
  const session = await sessions.require(request);
  const deviceId = readKeyboundCookie(request.headers.cookie, keybound.config);
  const device = await devices.requireForSession(session, deviceId);

  const result = await keybound.verifyAndConsumeProof({
    store: challengeStore,
    sessionId: session.id,
    deviceId: device.id,
    publicKey: device.publicKey,
    purpose: "settings:view-secret",
    challengeId: request.body.challengeId,
    challenge: request.body.challenge,
    signature: request.body.signature
  });

  return reply.code(result.ok ? 200 : 403).send(result);
});
```

## Next.js Route Handler

```ts
import { cookies, headers } from "next/headers";
import { readKeyboundCookie, serializeKeyboundCookie } from "keybound/http";
import { keybound } from "@/security/keybound";

export async function POST() {
  const session = await requireSession();
  const deviceId = keybound.createDeviceId();

  await devices.insert({
    userId: session.userId,
    deviceId,
    publicKey: await readPublicKeyFromRequest()
  });

  cookies().set(keybound.config.cookie.name, deviceId, {
    httpOnly: true,
    secure: true,
    sameSite: keybound.config.cookie.sameSite,
    path: "/",
    maxAge: keybound.config.cookie.maxAgeSeconds
  });

  return Response.json({ ok: true });
}

export async function GET() {
  const deviceId = readKeyboundCookie(headers().get("cookie"), keybound.config);
  return Response.json({ deviceId });
}
```

## Hono

```ts
app.post("/keybound/proof", async (c) => {
  const session = await sessions.require(c);
  const deviceId = readKeyboundCookie(c.req.header("cookie"), keybound.config);
  const device = await devices.requireForSession(session, deviceId);
  const body = await c.req.json();

  const result = await keybound.verifyAndConsumeProof({
    store: challengeStore,
    sessionId: session.id,
    deviceId: device.id,
    publicKey: device.publicKey,
    purpose: "settings:view-secret",
    challengeId: body.challengeId,
    challenge: body.challenge,
    signature: body.signature
  });

  return c.json(result, result.ok ? 200 : 403);
});
```

## Production Notes

Use your framework's normal secure cookie API when it has one. Use `serializeKeyboundCookie` when you need a raw `Set-Cookie` header.

Do not put Keybound verification in front of every static asset or simple page load. Use it for session continuation, session renewal, device changes, credential changes, API key access, payouts, admin actions, and other routes where stolen cookies matter.
