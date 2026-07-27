export type KeyboundPresetName = "relaxed" | "default" | "strict" | "cookie-only";

export type KeyboundAction = "allow" | "deny" | "step-up" | "rotate" | "revoke";

export interface KeyboundCookieOptions {
  readonly httpOnly: boolean;
  readonly secure: boolean;
  readonly sameSite: "lax" | "strict" | "none";
  readonly path: string;
  readonly maxAgeSeconds: number;
  readonly partitioned: boolean;
}

export interface KeyboundSignalPolicy {
  readonly userAgent: boolean;
  readonly acceptLanguage: boolean;
  readonly ipPrefix:
    | false
    | {
        readonly ipv4Bits: number;
        readonly ipv6Bits: number;
      };
  readonly custom: readonly string[];
}

export interface KeyboundRiskPolicy {
  readonly maxDriftScore: number;
  readonly allowMissingBinding: boolean;
  readonly rotateOnSoftDrift: boolean;
  readonly revokeOnHardDrift: boolean;
}

export interface KeyboundPreset {
  readonly name: KeyboundPresetName;
  readonly cookie: KeyboundCookieOptions;
  readonly signals: KeyboundSignalPolicy;
  readonly risk: KeyboundRiskPolicy;
}

export interface KeyboundSignals {
  readonly userAgent?: string;
  readonly acceptLanguage?: string;
  readonly ipAddress?: string;
  readonly custom?: Readonly<Record<string, string | number | boolean | null>>;
}
