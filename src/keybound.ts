import {
  createHmac,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify
} from "node:crypto";
import type { webcrypto } from "node:crypto";

import { presets } from "./presets.js";
import type {
  Keybound,
  KeyboundChallenge,
  KeyboundChallengeInput,
  KeyboundChallengeRecord,
  KeyboundConfig,
  KeyboundConfigOptions,
  KeyboundCookieOptions,
  KeyboundOptions,
  KeyboundP256PublicKey,
  KeyboundPresetName,
  KeyboundProofInput,
  KeyboundStoredProofInput,
  KeyboundVerificationReason,
  KeyboundVerificationResult
} from "./types.js";

const CHALLENGE_BYTES = 32;
const DEVICE_ID_BYTES = 32;
const DIGEST_BYTES = 32;
const P256_SIGNATURE_BYTES = 64;
const MIN_SECRET_BYTES = 32;
const MIN_CHALLENGE_TTL_MS = 5_000;
const MAX_CHALLENGE_TTL_MS = 5 * 60_000;
const MAX_COOKIE_AGE_SECONDS = 60 * 60 * 24 * 365;
const MAX_SESSION_ID_BYTES = 512;
const MAX_PURPOSE_BYTES = 128;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const COOKIE_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/;
const PURPOSE = /^[A-Za-z0-9._:/@+ -]+$/;
const DEFAULT_PURPOSE = "session";
const PROTOCOL_LABEL = Buffer.from("keybound/device-proof/v1", "utf8");

const ALLOW = Object.freeze({ ok: true, action: "allow" } as const);
const DENIALS = Object.freeze({
  "challenge-not-found": Object.freeze({
    ok: false,
    action: "deny",
    reason: "challenge-not-found"
  } as const),
  "challenge-expired": Object.freeze({
    ok: false,
    action: "deny",
    reason: "challenge-expired"
  } as const),
  "challenge-mismatch": Object.freeze({
    ok: false,
    action: "deny",
    reason: "challenge-mismatch"
  } as const),
  "invalid-proof": Object.freeze({
    ok: false,
    action: "deny",
    reason: "invalid-proof"
  } as const),
  "invalid-signature": Object.freeze({
    ok: false,
    action: "deny",
    reason: "invalid-signature"
  } as const),
  "challenge-replayed": Object.freeze({
    ok: false,
    action: "deny",
    reason: "challenge-replayed"
  } as const)
});

export function defineConfig(options: KeyboundConfigOptions = {}): KeyboundConfig {
  const presetName = options.preset ?? "default";
  const preset = presets[presetName];

  if (!preset) {
    throw new TypeError("Keybound preset must be relaxed, default, or strict.");
  }

  const challengeTtlMs = options.challengeTtlMs ?? preset.challengeTtlMs;
  assertChallengeTtl(challengeTtlMs);

  const cookie: KeyboundCookieOptions = {
    ...preset.cookie,
    ...options.cookie,
    httpOnly: true as const,
    secure: true as const,
    path: "/" as const
  };

  assertCookieOptions(cookie);

  return Object.freeze({
    preset: presetName,
    challengeTtlMs,
    cookie: Object.freeze(cookie)
  });
}

export function createKeybound(options: KeyboundOptions): Keybound {
  const secret = normalizeSecret(options?.secret);
  const config = defineConfig(options);

  return Object.freeze({
    config,
    createDeviceId,
    issueChallenge(input: KeyboundChallengeInput): KeyboundChallenge {
      const now = readTimestamp(input.now);
      const sessionId = readSessionId(input.sessionId);
      const purpose = readPurpose(input.purpose);
      const deviceId = readRandomValue(input.deviceId, DEVICE_ID_BYTES, "deviceId");
      const publicKey = readPublicKey(input.publicKey);
      const idBytes = randomBytes(CHALLENGE_BYTES);
      const challengeBytes = randomBytes(CHALLENGE_BYTES);
      const id = idBytes.toString("base64url");
      const challenge = challengeBytes.toString("base64url");
      const expiresAt = now + config.challengeTtlMs;
      const digest = createChallengeDigest(
        secret,
        sessionId,
        purpose,
        deviceId,
        idBytes,
        challengeBytes,
        publicKey.x,
        publicKey.y,
        expiresAt
      ).toString("base64url");
      const record = Object.freeze({ id, digest, expiresAt });

      return Object.freeze({ id, challenge, expiresAt, record });
    },
    verifyProof(input: KeyboundProofInput): KeyboundVerificationResult {
      return verifyProof(secret, input);
    },
    async verifyAndConsumeProof(
      input: KeyboundStoredProofInput
    ): Promise<KeyboundVerificationResult> {
      const challengeId = readChallengeIdForStore(input);
      if (!challengeId) {
        return deny("invalid-proof");
      }

      const store = input.store;
      if (!store || typeof store.get !== "function" || typeof store.consume !== "function") {
        throw new TypeError("Keybound store must implement get and consume.");
      }

      const record = await store.get(challengeId);
      if (!record) {
        return deny("challenge-not-found");
      }

      const result = verifyProof(secret, { ...input, record });
      if (!result.ok) {
        return result;
      }

      const consumed = await store.consume(challengeId, record.digest);
      return consumed ? ALLOW : deny("challenge-replayed");
    }
  });
}

export function createDeviceId(): string {
  return createRandomValue(DEVICE_ID_BYTES);
}

function verifyProof(
  secret: Buffer,
  input: KeyboundProofInput
): KeyboundVerificationResult {
  try {
    const now = readTimestamp(input.now);
    const sessionId = readSessionId(input.sessionId);
    const purpose = readPurpose(input.purpose);
    const deviceId = readRandomValue(input.deviceId, DEVICE_ID_BYTES, "deviceId");
    const challengeId = readRandomValue(
      input.challengeId,
      CHALLENGE_BYTES,
      "challengeId"
    );
    const challenge = readRandomValue(
      input.challenge,
      CHALLENGE_BYTES,
      "challenge"
    );
    const signature = readRandomValue(
      input.signature,
      P256_SIGNATURE_BYTES,
      "signature"
    );
    const record = readRecord(input.record);

    if (record.id !== input.challengeId) {
      return deny("challenge-mismatch");
    }

    if (now >= record.expiresAt) {
      return deny("challenge-expired");
    }

    const publicKey = readPublicKey(input.publicKey);
    const expectedDigest = createChallengeDigest(
      secret,
      sessionId,
      purpose,
      deviceId,
      challengeId,
      challenge,
      publicKey.x,
      publicKey.y,
      record.expiresAt
    );
    const actualDigest = readRandomValue(record.digest, DIGEST_BYTES, "digest");

    if (!timingSafeEqual(expectedDigest, actualDigest)) {
      return deny("challenge-mismatch");
    }

    const validSignature = verify(
      "sha256",
      challenge,
      { key: publicKey.key, dsaEncoding: "ieee-p1363" },
      signature
    );

    return validSignature ? ALLOW : deny("invalid-signature");
  } catch {
    return deny("invalid-proof");
  }
}

function createChallengeDigest(
  secret: Buffer,
  sessionId: string,
  purpose: string,
  deviceId: Buffer,
  challengeId: Buffer,
  challenge: Buffer,
  publicKeyX: Buffer,
  publicKeyY: Buffer,
  expiresAt: number
): Buffer {
  const hmac = createHmac("sha256", secret);
  hmac.update(PROTOCOL_LABEL);
  updateField(hmac, Buffer.from(sessionId, "utf8"));
  updateField(hmac, Buffer.from(purpose, "utf8"));
  updateField(hmac, deviceId);
  updateField(hmac, challengeId);
  updateField(hmac, challenge);
  updateField(hmac, publicKeyX);
  updateField(hmac, publicKeyY);

  const timestamp = Buffer.allocUnsafe(8);
  timestamp.writeBigUInt64BE(BigInt(expiresAt));
  updateField(hmac, timestamp);

  return hmac.digest();
}

function updateField(
  hmac: ReturnType<typeof createHmac>,
  value: Buffer
): void {
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(value.length);
  hmac.update(length);
  hmac.update(value);
}

function readPublicKey(value: KeyboundP256PublicKey) {
  if (!value || value.kty !== "EC" || value.crv !== "P-256") {
    throw new TypeError("Keybound public key must be an EC P-256 JWK.");
  }

  const x = readRandomValue(value.x, CHALLENGE_BYTES, "publicKey.x");
  const y = readRandomValue(value.y, CHALLENGE_BYTES, "publicKey.y");

  const key: webcrypto.JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: value.x,
    y: value.y
  };

  return { key: createPublicKey({ key, format: "jwk" }), x, y };
}

function normalizeSecret(value: string | Uint8Array | undefined): Buffer {
  const secret =
    typeof value === "string"
      ? Buffer.from(value, "utf8")
      : value instanceof Uint8Array
        ? Buffer.from(value)
        : undefined;

  if (!secret || secret.length < MIN_SECRET_BYTES) {
    throw new TypeError("Keybound secret must contain at least 32 bytes.");
  }

  return secret;
}

function assertChallengeTtl(value: number): void {
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_CHALLENGE_TTL_MS ||
    value > MAX_CHALLENGE_TTL_MS
  ) {
    throw new RangeError("Keybound challengeTtlMs must be between 5000 and 300000.");
  }
}

function assertCookieOptions(value: KeyboundCookieOptions): void {
  if (!COOKIE_NAME.test(value.name)) {
    throw new TypeError("Keybound cookie name is invalid.");
  }

  if (
    value.sameSite !== "lax" &&
    value.sameSite !== "strict" &&
    value.sameSite !== "none"
  ) {
    throw new TypeError("Keybound cookie sameSite is invalid.");
  }

  if (typeof value.partitioned !== "boolean") {
    throw new TypeError("Keybound cookie partitioned must be a boolean.");
  }

  if (
    !Number.isSafeInteger(value.maxAgeSeconds) ||
    value.maxAgeSeconds < 60 ||
    value.maxAgeSeconds > MAX_COOKIE_AGE_SECONDS
  ) {
    throw new RangeError("Keybound cookie maxAgeSeconds must be between 60 and 31536000.");
  }
}

function readRecord(value: KeyboundChallengeRecord): KeyboundChallengeRecord {
  if (!value || typeof value !== "object") {
    throw new TypeError("Keybound challenge record is invalid.");
  }

  const id = readRandomValue(value.id, CHALLENGE_BYTES, "record.id");
  const digest = readRandomValue(value.digest, DIGEST_BYTES, "record.digest");
  const expiresAt = readTimestamp(value.expiresAt);

  return { id: id.toString("base64url"), digest: digest.toString("base64url"), expiresAt };
}

function readTimestamp(value: number | undefined): number {
  const timestamp = value ?? Date.now();
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new TypeError("Keybound timestamp must be a safe integer.");
  }

  return timestamp;
}

function readSessionId(value: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError("Keybound sessionId must be a non-empty string.");
  }

  if (Buffer.byteLength(value, "utf8") > MAX_SESSION_ID_BYTES) {
    throw new RangeError("Keybound sessionId exceeds 512 bytes.");
  }

  return value;
}

function readPurpose(value: string | undefined): string {
  const purpose = value ?? DEFAULT_PURPOSE;
  if (
    typeof purpose !== "string" ||
    purpose.length === 0 ||
    Buffer.byteLength(purpose, "utf8") > MAX_PURPOSE_BYTES ||
    !PURPOSE.test(purpose)
  ) {
    throw new TypeError(
      "Keybound purpose must be a non-empty visible ASCII string up to 128 bytes."
    );
  }

  return purpose;
}

function readRandomValue(value: string, size: number, name: string): Buffer {
  if (typeof value !== "string" || !BASE64URL.test(value)) {
    throw new TypeError(`Keybound ${name} must be base64url.`);
  }

  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== size || decoded.toString("base64url") !== value) {
    throw new TypeError(`Keybound ${name} has an invalid length or encoding.`);
  }

  return decoded;
}

function createRandomValue(size: number): string {
  return randomBytes(size).toString("base64url");
}

function readChallengeIdForStore(input: KeyboundStoredProofInput): string | null {
  try {
    return readRandomValue(input?.challengeId, CHALLENGE_BYTES, "challengeId").toString(
      "base64url"
    );
  } catch {
    return null;
  }
}

function deny(reason: KeyboundVerificationReason): KeyboundVerificationResult {
  return DENIALS[reason];
}
