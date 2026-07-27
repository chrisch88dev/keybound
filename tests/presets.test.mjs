import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  COOKIE_ONLY_PRESET,
  DEFAULT_PRESET,
  RELAXED_PRESET,
  STRICT_PRESET,
  presets
} from "../dist/index.js";

describe("presets", () => {
  it("exports the expected preset names", () => {
    assert.deepEqual(Object.keys(presets), ["relaxed", "default", "strict", "cookie-only"]);
  });

  it("keeps default stricter than relaxed", () => {
    assert.equal(DEFAULT_PRESET.risk.maxDriftScore < RELAXED_PRESET.risk.maxDriftScore, true);
    assert.equal(DEFAULT_PRESET.risk.allowMissingBinding, false);
  });

  it("keeps strict stricter than default", () => {
    assert.equal(STRICT_PRESET.risk.maxDriftScore < DEFAULT_PRESET.risk.maxDriftScore, true);
    assert.equal(STRICT_PRESET.cookie.sameSite, "strict");
  });

  it("keeps cookie-only free of request signal binding", () => {
    assert.equal(COOKIE_ONLY_PRESET.signals.userAgent, false);
    assert.equal(COOKIE_ONLY_PRESET.signals.acceptLanguage, false);
    assert.equal(COOKIE_ONLY_PRESET.signals.ipPrefix, false);
  });

  it("freezes exported presets", () => {
    assert.equal(Object.isFrozen(DEFAULT_PRESET), true);
    assert.equal(Object.isFrozen(DEFAULT_PRESET.cookie), true);
    assert.equal(Object.isFrozen(DEFAULT_PRESET.signals), true);
    assert.equal(Object.isFrozen(DEFAULT_PRESET.risk), true);
  });
});
