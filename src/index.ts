export { createDeviceId, createKeybound, defineConfig } from "./keybound.js";
export {
  clearKeyboundCookie,
  readKeyboundCookie,
  serializeKeyboundCookie
} from "./http.js";
export {
  DEFAULT_PRESET,
  RELAXED_PRESET,
  STRICT_PRESET,
  presets
} from "./presets.js";

export type {
  Keybound,
  KeyboundChallenge,
  KeyboundChallengeInput,
  KeyboundChallengeRecord,
  KeyboundChallengeStore,
  KeyboundConfig,
  KeyboundConfigOptions,
  KeyboundCookieOptions,
  KeyboundCookieOverrides,
  KeyboundOptions,
  KeyboundP256PublicKey,
  KeyboundPreset,
  KeyboundPresetName,
  KeyboundProofInput,
  KeyboundSameSite,
  KeyboundStoredProofInput,
  KeyboundVerificationReason,
  KeyboundVerificationResult
} from "./types.js";

export const KEYBOUND_VERSION = "0.1.0";
