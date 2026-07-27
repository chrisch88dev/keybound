import type { KeyboundPreset } from "./types.js";

const freezePreset = <T extends KeyboundPreset>(preset: T): T => {
  Object.freeze(preset.cookie);
  return Object.freeze(preset);
};

export const RELAXED_PRESET = freezePreset({
  name: "relaxed",
  challengeTtlMs: 120_000,
  cookie: {
    name: "__Host-keybound",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAgeSeconds: 60 * 60 * 24 * 365,
    partitioned: false
  }
} as const);

export const DEFAULT_PRESET = freezePreset({
  name: "default",
  challengeTtlMs: 60_000,
  cookie: {
    name: "__Host-keybound",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAgeSeconds: 60 * 60 * 24 * 180,
    partitioned: false
  }
} as const);

export const STRICT_PRESET = freezePreset({
  name: "strict",
  challengeTtlMs: 30_000,
  cookie: {
    name: "__Host-keybound",
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAgeSeconds: 60 * 60 * 24 * 90,
    partitioned: false
  }
} as const);

export const presets = Object.freeze({
  relaxed: RELAXED_PRESET,
  default: DEFAULT_PRESET,
  strict: STRICT_PRESET
});
