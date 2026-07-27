import { generateKeyPairSync, randomBytes, sign } from "node:crypto";

import { createKeybound } from "../dist/index.js";

const keybound = createKeybound({ secret: randomBytes(32) });
const deviceId = keybound.createDeviceId();
const sessionId = "session_example";

const deviceKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const publicKey = deviceKey.publicKey.export({ format: "jwk" });
const issued = keybound.issueChallenge({ sessionId, deviceId, publicKey });

const signature = sign(
  "sha256",
  Buffer.from(issued.challenge, "base64url"),
  { key: deviceKey.privateKey, dsaEncoding: "ieee-p1363" }
).toString("base64url");

const result = keybound.verifyProof({
  sessionId,
  deviceId,
  challengeId: issued.id,
  challenge: issued.challenge,
  signature,
  publicKey,
  record: issued.record
});

console.log(result);
