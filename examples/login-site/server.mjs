import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  clearKeyboundCookie,
  createKeybound,
  readKeyboundCookie,
  serializeKeyboundCookie
} from "../../dist/index.js";

const PORT = Number.parseInt(process.env.PORT ?? "4173", 10);
const SESSION_COOKIE = "kb_demo_session";
const PURPOSES = new Set(["session:renew", "settings:view-secret"]);
const ROOT = dirname(fileURLToPath(import.meta.url));

const keybound = createKeybound({
  secret: process.env.KEYBOUND_SECRET ?? randomBytes(32),
  preset: "default"
});

const sessions = new Map();
const devices = new Map();
const challenges = new Map();

const challengeStore = {
  async get(challengeId) {
    return challenges.get(challengeId) ?? null;
  },
  async consume(challengeId, expectedDigest) {
    const record = challenges.get(challengeId);
    if (!record || record.digest !== expectedDigest) {
      return false;
    }

    challenges.delete(challengeId);
    return true;
  }
};

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/") {
      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      response.end(await readFile(join(ROOT, "index.html"), "utf8"));
      return;
    }

    if (request.method === "GET" && request.url === "/keybound-browser.js") {
      response.writeHead(200, {
        "Content-Type": "text/javascript; charset=utf-8",
        "Cache-Control": "no-store"
      });
      response.end(await readFile(join(ROOT, "../../dist/browser.js"), "utf8"));
      return;
    }

    if (request.method === "GET" && request.url === "/api/status") {
      sendJson(response, 200, getStatus(request));
      return;
    }

    if (request.method === "POST" && request.url === "/api/login") {
      const body = await readJson(request);
      const username = readUsername(body.username);
      const publicKey = body.publicKey;
      const sessionId = randomBytes(32).toString("base64url");
      const deviceId = keybound.createDeviceId();
      const userId = `demo:${username.toLowerCase()}`;

      keybound.issueChallenge({
        sessionId,
        deviceId,
        publicKey,
        purpose: "session:renew"
      });

      sessions.set(sessionId, {
        id: sessionId,
        userId,
        username,
        deviceId,
        createdAt: Date.now()
      });
      devices.set(deviceKey(userId, deviceId), {
        userId,
        deviceId,
        publicKey,
        createdAt: Date.now()
      });

      response.setHeader("Set-Cookie", [
        serializeSessionCookie(sessionId),
        serializeKeyboundCookie(keybound.config, deviceId)
      ]);
      sendJson(response, 200, {
        ok: true,
        message: "Logged in and enrolled this browser.",
        status: getStatus(request, { sessionId, deviceId })
      });
      return;
    }

    if (request.method === "POST" && request.url === "/api/challenge") {
      const body = await readJson(request);
      const context = readContext(request);
      const purpose = readPurpose(body.purpose);

      if (!context.ok) {
        sendJson(response, 401, context);
        return;
      }

      const issued = keybound.issueChallenge({
        sessionId: context.session.id,
        deviceId: context.device.deviceId,
        publicKey: context.device.publicKey,
        purpose
      });
      challenges.set(issued.id, issued.record);

      sendJson(response, 200, {
        ok: true,
        purpose,
        challengeId: issued.id,
        challenge: issued.challenge,
        expiresAt: issued.expiresAt
      });
      return;
    }

    if (request.method === "POST" && request.url === "/api/proof") {
      const body = await readJson(request);
      const context = readContext(request);
      const purpose = readPurpose(body.purpose);

      if (!context.ok) {
        sendJson(response, 401, context);
        return;
      }

      const result = await keybound.verifyAndConsumeProof({
        store: challengeStore,
        sessionId: context.session.id,
        deviceId: context.device.deviceId,
        publicKey: context.device.publicKey,
        purpose,
        challengeId: body.challengeId,
        challenge: body.challenge,
        signature: body.signature
      });

      sendJson(response, result.ok ? 200 : 403, {
        ...result,
        message: result.ok
          ? "Proof accepted. The protected action can run."
          : "Proof denied. The protected action stays blocked."
      });
      return;
    }

    if (request.method === "POST" && request.url === "/api/fraud/cookie-dump") {
      const status = getStatus(request);
      sendJson(response, 200, {
        ok: false,
        action: "deny",
        reason: "missing-private-key",
        message:
          "A copied cookie dump can name a session and device, but it cannot sign a fresh Keybound challenge without the browser private key.",
        copiedSessionCookie: status.hasSessionCookie,
        copiedDeviceCookie: status.hasDeviceCookie
      });
      return;
    }

    if (request.method === "POST" && request.url === "/api/logout") {
      const sessionId = readCookie(request.headers.cookie, SESSION_COOKIE);
      if (sessionId) {
        sessions.delete(sessionId);
      }

      response.setHeader("Set-Cookie", [
        clearSessionCookie(),
        clearKeyboundCookie(keybound.config)
      ]);
      sendJson(response, 200, { ok: true, message: "Logged out." });
      return;
    }

    sendJson(response, 404, { ok: false, message: "Not found." });
  } catch (error) {
    sendJson(response, 400, {
      ok: false,
      message: error instanceof Error ? error.message : "Request failed."
    });
  }
});

server.listen(PORT, () => {
  console.log(`Keybound login demo: http://localhost:${PORT}`);
});

function getStatus(request, override = {}) {
  const cookieHeader = request.headers.cookie;
  const sessionId =
    override.sessionId ?? readCookie(cookieHeader, SESSION_COOKIE) ?? null;
  const deviceId =
    override.deviceId ?? readKeyboundCookie(cookieHeader, keybound.config) ?? null;
  const session = sessionId ? sessions.get(sessionId) ?? null : null;
  const device =
    session && deviceId ? devices.get(deviceKey(session.userId, deviceId)) ?? null : null;

  return {
    ok: true,
    loggedIn: Boolean(session),
    username: session?.username ?? null,
    sessionLinkedToDevice: Boolean(
      session && device && session.deviceId === device.deviceId
    ),
    hasSessionCookie: Boolean(sessionId),
    hasDeviceCookie: Boolean(deviceId),
    sessionId: sessionId ? mask(sessionId) : null,
    deviceId: deviceId ? mask(deviceId) : null,
    config: {
      preset: keybound.config.preset,
      challengeTtlMs: keybound.config.challengeTtlMs,
      cookie: keybound.config.cookie
    }
  };
}

function readContext(request) {
  const cookieHeader = request.headers.cookie;
  const sessionId = readCookie(cookieHeader, SESSION_COOKIE);
  const deviceId = readKeyboundCookie(cookieHeader, keybound.config);

  if (!sessionId || !deviceId) {
    return {
      ok: false,
      action: "deny",
      reason: "missing-session-or-device-cookie"
    };
  }

  const session = sessions.get(sessionId);
  if (!session) {
    return { ok: false, action: "deny", reason: "session-not-found" };
  }

  if (session.deviceId !== deviceId) {
    return { ok: false, action: "deny", reason: "device-session-mismatch" };
  }

  const device = devices.get(deviceKey(session.userId, deviceId));
  if (!device) {
    return { ok: false, action: "deny", reason: "device-not-enrolled" };
  }

  return { ok: true, session, device };
}

function readCookie(cookieHeader, name) {
  if (!cookieHeader) {
    return null;
  }

  for (const field of cookieHeader.split(";")) {
    const index = field.indexOf("=");
    if (index === -1) {
      continue;
    }

    if (field.slice(0, index).trim() === name) {
      return field.slice(index + 1).trim() || null;
    }
  }

  return null;
}

function readPurpose(value) {
  if (typeof value !== "string" || !PURPOSES.has(value)) {
    throw new TypeError("Unknown proof purpose.");
  }

  return value;
}

function readUsername(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{2,32}$/.test(value)) {
    throw new TypeError("Username must be 2 to 32 letters, numbers, hyphens, or underscores.");
  }

  return value;
}

async function readJson(request) {
  let body = "";

  for await (const chunk of request) {
    body += chunk;
    if (body.length > 32_768) {
      throw new TypeError("Request body is too large.");
    }
  }

  return body ? JSON.parse(body) : {};
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  response.end(JSON.stringify(body));
}

function serializeSessionCookie(sessionId) {
  return [
    `${SESSION_COOKIE}=${sessionId}`,
    "Max-Age=3600",
    "Path=/",
    "HttpOnly",
    "SameSite=Lax"
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${SESSION_COOKIE}=`,
    "Max-Age=0",
    "Path=/",
    "HttpOnly",
    "SameSite=Lax"
  ].join("; ");
}

function deviceKey(userId, deviceId) {
  return `${userId}:${deviceId}`;
}

function mask(value) {
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}
