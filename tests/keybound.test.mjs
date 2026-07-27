import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  randomBytes,
  sign
} from "node:crypto";
import { webcrypto } from "node:crypto";
import { describe, it } from "node:test";

import {
  createKeybound,
  defineConfig,
  DEFAULT_PRESET,
  RELAXED_PRESET,
  STRICT_PRESET
} from "../dist/index.js";

const NOW = 1_700_000_000_000;

class MemoryChallengeStore {
  #records = new Map();
  #consumed = new Set();

  put(record) {
    this.#records.set(record.id, record);
  }

  async get(challengeId) {
    return this.#records.get(challengeId) ?? null;
  }

  async consume(challengeId, expectedDigest) {
    const record = this.#records.get(challengeId);
    if (!record || record.digest !== expectedDigest || this.#consumed.has(challengeId)) {
      return false;
    }

    this.#consumed.add(challengeId);
    return true;
  }
}

function createDeviceKey() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ format: "jwk" });

  return {
    publicKey,
    signChallenge(challenge) {
      return sign(
        "sha256",
        Buffer.from(challenge, "base64url"),
        { key: pair.privateKey, dsaEncoding: "ieee-p1363" }
      ).toString("base64url");
    }
  };
}

function createFixture() {
  const keybound = createKeybound({ secret: randomBytes(32) });
  const device = createDeviceKey();
  const deviceId = keybound.createDeviceId();
  const sessionId = "session_41b6a0b7a7a0";
  const issued = keybound.issueChallenge({
    sessionId,
    deviceId,
    publicKey: device.publicKey,
    now: NOW
  });
  const signature = device.signChallenge(issued.challenge);

  return { keybound, device, deviceId, sessionId, issued, signature };
}

function proofInput(fixture, overrides = {}) {
  return {
    sessionId: fixture.sessionId,
    deviceId: fixture.deviceId,
    challengeId: fixture.issued.id,
    challenge: fixture.issued.challenge,
    signature: fixture.signature,
    publicKey: fixture.device.publicKey,
    record: fixture.issued.record,
    now: NOW,
    ...overrides
  };
}

function alterBase64url(value) {
  const replacement = value[0] === "A" ? "B" : "A";
  return `${replacement}${value.slice(1)}`;
}

describe("configuration", () => {
  it("uses immutable secure defaults", () => {
    const config = defineConfig();

    assert.equal(config.preset, "default");
    assert.equal(config.challengeTtlMs, 60_000);
    assert.deepEqual(config.cookie, DEFAULT_PRESET.cookie);
    assert.equal(Object.isFrozen(config), true);
    assert.equal(Object.isFrozen(config.cookie), true);
  });

  it("offers bounded relaxed and strict presets", () => {
    assert.equal(RELAXED_PRESET.challengeTtlMs > DEFAULT_PRESET.challengeTtlMs, true);
    assert.equal(STRICT_PRESET.challengeTtlMs < DEFAULT_PRESET.challengeTtlMs, true);
    assert.equal(STRICT_PRESET.cookie.sameSite, "strict");
  });

  it("keeps device cookie transport protections enabled", () => {
    const config = defineConfig({
      cookie: {
        name: "keybound_device",
        sameSite: "none",
        partitioned: true,
        maxAgeSeconds: 3_600
      }
    });

    assert.equal(config.cookie.httpOnly, true);
    assert.equal(config.cookie.secure, true);
    assert.equal(config.cookie.path, "/");
    assert.equal(config.cookie.sameSite, "none");
    assert.equal(config.cookie.partitioned, true);
  });

  it("does not allow runtime overrides to weaken cookie transport settings", () => {
    const config = defineConfig({
      cookie: {
        httpOnly: false,
        secure: false,
        path: "/another-path"
      }
    });

    assert.equal(config.cookie.httpOnly, true);
    assert.equal(config.cookie.secure, true);
    assert.equal(config.cookie.path, "/");
  });

  it("rejects short secrets and unsafe lifetime values", () => {
    assert.throws(() => createKeybound({ secret: "too-short" }), TypeError);
    assert.throws(() => defineConfig({ challengeTtlMs: 4_999 }), RangeError);
    assert.throws(() => defineConfig({ challengeTtlMs: 300_001 }), RangeError);
    assert.throws(
      () => defineConfig({ cookie: { name: "invalid;cookie" } }),
      TypeError
    );
  });
});

describe("device proof", () => {
  it("accepts a valid proof for its original session and device", () => {
    const fixture = createFixture();

    assert.deepEqual(fixture.keybound.verifyProof(proofInput(fixture)), {
      ok: true,
      action: "allow"
    });
  });

  it("accepts the raw P-256 signature format emitted by Web Crypto", async () => {
    const keybound = createKeybound({ secret: randomBytes(32) });
    const keyPair = await webcrypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    );
    const publicKey = await webcrypto.subtle.exportKey("jwk", keyPair.publicKey);
    const deviceId = keybound.createDeviceId();
    const sessionId = "session_webcrypto";
    const issued = keybound.issueChallenge({
      sessionId,
      deviceId,
      publicKey,
      now: NOW
    });
    const signature = Buffer.from(
      await webcrypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.privateKey,
        Buffer.from(issued.challenge, "base64url")
      )
    ).toString("base64url");

    assert.deepEqual(
      keybound.verifyProof({
        sessionId,
        deviceId,
        challengeId: issued.id,
        challenge: issued.challenge,
        signature,
        publicKey,
        record: issued.record,
        now: NOW
      }),
      { ok: true, action: "allow" }
    );
  });

  it("rejects a proof moved to another session or device", () => {
    const fixture = createFixture();

    assert.equal(
      fixture.keybound.verifyProof(
        proofInput(fixture, { sessionId: "session_other" })
      ).reason,
      "challenge-mismatch"
    );
    assert.equal(
      fixture.keybound.verifyProof(
        proofInput(fixture, { deviceId: fixture.keybound.createDeviceId() })
      ).reason,
      "challenge-mismatch"
    );
  });

  it("rejects an altered challenge before signature verification", () => {
    const fixture = createFixture();

    assert.equal(
      fixture.keybound.verifyProof(
        proofInput(fixture, { challenge: alterBase64url(fixture.issued.challenge) })
      ).reason,
      "challenge-mismatch"
    );
  });

  it("rejects a signature made by another device key", () => {
    const fixture = createFixture();
    const otherDevice = createDeviceKey();

    assert.equal(
      fixture.keybound.verifyProof(
        proofInput(fixture, {
          signature: otherDevice.signChallenge(fixture.issued.challenge)
        })
      ).reason,
      "invalid-signature"
    );
  });

  it("rejects a substituted public key even when it signs the challenge", () => {
    const fixture = createFixture();
    const otherDevice = createDeviceKey();

    assert.equal(
      fixture.keybound.verifyProof(
        proofInput(fixture, {
          publicKey: otherDevice.publicKey,
          signature: otherDevice.signChallenge(fixture.issued.challenge)
        })
      ).reason,
      "challenge-mismatch"
    );
  });

  it("rejects expired and malformed proofs", () => {
    const fixture = createFixture();

    assert.equal(
      fixture.keybound.verifyProof(
        proofInput(fixture, { now: fixture.issued.expiresAt })
      ).reason,
      "challenge-expired"
    );
    assert.equal(
      fixture.keybound.verifyProof(proofInput(fixture, { signature: "not-a-signature" }))
        .reason,
      "invalid-proof"
    );
  });

  it("consumes a valid challenge once and preserves it after a bad proof", async () => {
    const fixture = createFixture();
    const store = new MemoryChallengeStore();
    store.put(fixture.issued.record);

    const bad = await fixture.keybound.verifyAndConsumeProof({
      ...proofInput(fixture, { signature: alterBase64url(fixture.signature) }),
      store
    });
    assert.equal(bad.reason, "invalid-signature");

    const first = await fixture.keybound.verifyAndConsumeProof({
      ...proofInput(fixture),
      store
    });
    assert.deepEqual(first, { ok: true, action: "allow" });

    const replay = await fixture.keybound.verifyAndConsumeProof({
      ...proofInput(fixture),
      store
    });
    assert.equal(replay.reason, "challenge-replayed");
  });

  it("does not query storage with malformed challenge identifiers", async () => {
    const fixture = createFixture();
    let queried = false;
    const store = {
      async get() {
        queried = true;
        return null;
      },
      async consume() {
        return false;
      }
    };

    const result = await fixture.keybound.verifyAndConsumeProof({
      ...proofInput(fixture, { challengeId: "bad-id" }),
      store
    });

    assert.equal(result.reason, "invalid-proof");
    assert.equal(queried, false);
  });
});
