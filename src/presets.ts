import type { KeyboundPreset } from "./types.js";

const freezePreset = <T extends KeyboundPreset>(preset: T): T => {
  Object.freeze(preset.cookie);
  Object.freeze(preset.signals.ipPrefix || {});
  Object.freeze(preset.signals.custom);
  Object.freeze(preset.signals);
  Object.freeze(preset.risk);
  return Object.freeze(preset);
};

export const RELAXED_PRESET = freezePreset({
  name: "relaxed",
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAgeSeconds: 60 * 60 * 24 * 30,
    partitioned: false
  },
  signals: {
    userAgent: true,
    acceptLanguage: false,
    ipPrefix: false,
    custom: []
  },
  risk: {
    maxDriftScore: 70,
    allowMissingBinding: true,
    rotateOnSoftDrift: true,
    revokeOnHardDrift: false
  }
} as const);

export const DEFAULT_PRESET = freezePreset({
  name: "default",
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAgeSeconds: 60 * 60 * 24 * 14,
    partitioned: false
  },
  signals: {
    userAgent: true,
    acceptLanguage: true,
    ipPrefix: {
      ipv4Bits: 24,
      ipv6Bits: 56
    },
    custom: []
  },
  risk: {
    maxDriftScore: 40,
    allowMissingBinding: false,
    rotateOnSoftDrift: true,
    revokeOnHardDrift: true
  }
} as const);

export const STRICT_PRESET = freezePreset({
  name: "strict",
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAgeSeconds: 60 * 60 * 8,
    partitioned: true
  },
  signals: {
    userAgent: true,
    acceptLanguage: true,
    ipPrefix: {
      ipv4Bits: 28,
      ipv6Bits: 64
    },
    custom: []
  },
  risk: {
    maxDriftScore: 20,
    allowMissingBinding: false,
    rotateOnSoftDrift: true,
    revokeOnHardDrift: true
  }
} as const);

export const COOKIE_ONLY_PRESET = freezePreset({
  name: "cookie-only",
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAgeSeconds: 60 * 60 * 24 * 7,
    partitioned: false
  },
  signals: {
    userAgent: false,
    acceptLanguage: false,
    ipPrefix: false,
    custom: []
  },
  risk: {
    maxDriftScore: 100,
    allowMissingBinding: false,
    rotateOnSoftDrift: false,
    revokeOnHardDrift: false
  }
} as const);

export const presets = freezePresetMap({
  relaxed: RELAXED_PRESET,
  default: DEFAULT_PRESET,
  strict: STRICT_PRESET,
  "cookie-only": COOKIE_ONLY_PRESET
});

function freezePresetMap<T extends Record<string, KeyboundPreset>>(value: T): Readonly<T> {
  return Object.freeze(value);
}
