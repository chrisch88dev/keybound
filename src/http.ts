import type { KeyboundConfig } from "./types.js";

const DEVICE_ID = /^[A-Za-z0-9_-]{43}$/;

export function serializeKeyboundCookie(
  config: KeyboundConfig,
  deviceId: string
): string {
  assertDeviceId(deviceId);

  const parts = [
    `${config.cookie.name}=${deviceId}`,
    `Max-Age=${config.cookie.maxAgeSeconds}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    `SameSite=${formatSameSite(config.cookie.sameSite)}`
  ];

  if (config.cookie.partitioned) {
    parts.push("Partitioned");
  }

  return parts.join("; ");
}

export function clearKeyboundCookie(config: KeyboundConfig): string {
  return [
    `${config.cookie.name}=`,
    "Max-Age=0",
    "Path=/",
    "HttpOnly",
    "Secure",
    `SameSite=${formatSameSite(config.cookie.sameSite)}`
  ].join("; ");
}

export function readKeyboundCookie(
  cookieHeader: string | readonly string[] | null | undefined,
  config: KeyboundConfig
): string | null {
  const header =
    typeof cookieHeader === "string"
      ? cookieHeader
      : Array.isArray(cookieHeader)
        ? cookieHeader.join("; ")
        : null;

  if (!header) {
    return null;
  }

  for (const field of header.split(";")) {
    const index = field.indexOf("=");
    if (index === -1) {
      continue;
    }

    const name = field.slice(0, index).trim();
    if (name !== config.cookie.name) {
      continue;
    }

    const value = field.slice(index + 1).trim();
    return DEVICE_ID.test(value) ? value : null;
  }

  return null;
}

function formatSameSite(value: KeyboundConfig["cookie"]["sameSite"]): string {
  if (value === "strict") {
    return "Strict";
  }

  if (value === "none") {
    return "None";
  }

  return "Lax";
}

function assertDeviceId(value: string): void {
  if (typeof value !== "string" || !DEVICE_ID.test(value)) {
    throw new TypeError("Keybound device ID must be a 32-byte base64url value.");
  }
}
