export type KeyboundPresetName = "relaxed" | "default" | "strict";

export type KeyboundSameSite = "lax" | "strict" | "none";

export interface KeyboundCookieOptions {
  readonly name: string;
  readonly httpOnly: true;
  readonly secure: true;
  readonly sameSite: KeyboundSameSite;
  readonly path: "/";
  readonly maxAgeSeconds: number;
  readonly partitioned: boolean;
}

export interface KeyboundCookieOverrides {
  readonly name?: string;
  readonly sameSite?: KeyboundSameSite;
  readonly maxAgeSeconds?: number;
  readonly partitioned?: boolean;
}

export interface KeyboundPreset {
  readonly name: KeyboundPresetName;
  readonly challengeTtlMs: number;
  readonly cookie: KeyboundCookieOptions;
}

export interface KeyboundConfigOptions {
  readonly preset?: KeyboundPresetName;
  readonly challengeTtlMs?: number;
  readonly cookie?: KeyboundCookieOverrides;
}

export interface KeyboundOptions extends KeyboundConfigOptions {
  readonly secret: string | Uint8Array;
}

export interface KeyboundConfig {
  readonly preset: KeyboundPresetName;
  readonly challengeTtlMs: number;
  readonly cookie: KeyboundCookieOptions;
}

export interface KeyboundP256PublicKey {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
}

export interface KeyboundChallengeRecord {
  readonly id: string;
  readonly digest: string;
  readonly expiresAt: number;
}

export interface KeyboundChallenge {
  readonly id: string;
  readonly challenge: string;
  readonly expiresAt: number;
  readonly record: KeyboundChallengeRecord;
}

export interface KeyboundChallengeInput {
  readonly sessionId: string;
  readonly deviceId: string;
  readonly publicKey: KeyboundP256PublicKey;
  readonly purpose?: string;
  readonly now?: number;
}

export interface KeyboundProofInput {
  readonly sessionId: string;
  readonly deviceId: string;
  readonly purpose?: string;
  readonly challengeId: string;
  readonly challenge: string;
  readonly signature: string;
  readonly publicKey: KeyboundP256PublicKey;
  readonly record: KeyboundChallengeRecord;
  readonly now?: number;
}

/**
 * The consume operation must be atomic. It returns true only once for the
 * matching id and digest, then returns false for every later attempt.
 */
export interface KeyboundChallengeStore {
  get(challengeId: string): Promise<KeyboundChallengeRecord | null>;
  consume(challengeId: string, expectedDigest: string): Promise<boolean>;
}

export interface KeyboundStoredProofInput
  extends Omit<KeyboundProofInput, "record"> {
  readonly store: KeyboundChallengeStore;
}

export type KeyboundVerificationReason =
  | "challenge-not-found"
  | "challenge-expired"
  | "challenge-mismatch"
  | "invalid-proof"
  | "invalid-signature"
  | "challenge-replayed";

export type KeyboundVerificationResult =
  | {
      readonly ok: true;
      readonly action: "allow";
    }
  | {
      readonly ok: false;
      readonly action: "deny";
      readonly reason: KeyboundVerificationReason;
    };

export interface Keybound {
  readonly config: KeyboundConfig;
  createDeviceId(): string;
  issueChallenge(input: KeyboundChallengeInput): KeyboundChallenge;
  verifyProof(input: KeyboundProofInput): KeyboundVerificationResult;
  verifyAndConsumeProof(
    input: KeyboundStoredProofInput
  ): Promise<KeyboundVerificationResult>;
}
