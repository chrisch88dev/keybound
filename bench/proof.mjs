import { performance } from "node:perf_hooks";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";

import { createKeybound } from "../dist/index.js";

const ITERATIONS = Number.parseInt(process.env.ITERATIONS ?? "5000", 10);
const WARMUP = Math.min(1000, Math.max(100, Math.floor(ITERATIONS / 5)));

const keybound = createKeybound({ secret: randomBytes(32) });
const device = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const publicKey = device.publicKey.export({ format: "jwk" });
const sessionId = "bench_session";
const deviceId = keybound.createDeviceId();

for (let index = 0; index < WARMUP; index += 1) {
  const issued = keybound.issueChallenge({ sessionId, deviceId, publicKey });
  const signature = signChallenge(issued.challenge);
  keybound.verifyProof({
    sessionId,
    deviceId,
    publicKey,
    challengeId: issued.id,
    challenge: issued.challenge,
    signature,
    record: issued.record
  });
}

const issueMs = measure(() => {
  keybound.issueChallenge({ sessionId, deviceId, publicKey });
});

const issued = keybound.issueChallenge({ sessionId, deviceId, publicKey });
const signature = signChallenge(issued.challenge);
const verifyMs = measure(() => {
  keybound.verifyProof({
    sessionId,
    deviceId,
    publicKey,
    challengeId: issued.id,
    challenge: issued.challenge,
    signature,
    record: issued.record
  });
});

console.log({
  iterations: ITERATIONS,
  issueChallenge: summary(issueMs),
  verifyProof: summary(verifyMs)
});

function measure(fn) {
  const start = performance.now();
  for (let index = 0; index < ITERATIONS; index += 1) {
    fn();
  }

  return performance.now() - start;
}

function summary(ms) {
  return {
    totalMs: Number(ms.toFixed(2)),
    avgMicroseconds: Number(((ms * 1000) / ITERATIONS).toFixed(2)),
    opsPerSecond: Math.round(ITERATIONS / (ms / 1000))
  };
}

function signChallenge(challenge) {
  return sign(
    "sha256",
    Buffer.from(challenge, "base64url"),
    { key: device.privateKey, dsaEncoding: "ieee-p1363" }
  ).toString("base64url");
}
