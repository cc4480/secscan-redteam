/**
 * Safety module barrel (v0.13.0) — the production safety case.
 *
 * Mechanical, runner-enforced protections a buyer's security team can verify:
 * per-target rate limiting, PII redaction, staging→production graduation,
 * per-target auto-halt, the machine-readable safety manifest, and the
 * zero-disruption record derived from the audit log.
 */

export {
  TargetRateLimiter,
  resolveEffectiveRps,
  DEFAULT_STAGING_RPS,
  DEFAULT_PRODUCTION_RPS,
  PRODUCTION_RPS_CAP,
} from "./ratelimit.js";
export type { RateLimitConfig } from "./ratelimit.js";

export { redactPii, piiPatternLabels, likelyContainsPii } from "./pii.js";

export {
  parseEnvironment,
  productionConfirmed,
  requireGraduation,
  describeEnvironment,
  PROD_CONFIRM_ENV,
  ENV_SELECT_ENV,
} from "./graduation.js";
export type { TestEnvironment } from "./graduation.js";

export {
  TargetAutoHalt,
  isTargetDistress,
  DEFAULT_AUTOHALT_CONFIG,
} from "./autohalt.js";
export type { AutoHaltConfig } from "./autohalt.js";

export {
  buildZeroDisruptionRecord,
  disruptionVerdict,
} from "./disruption.js";
export type { ZeroDisruptionRecord } from "./disruption.js";

export {
  buildSafetyManifest,
  renderSafetyManifestMarkdown,
  PROTECTIONS_IN_FORCE,
  RESIDUAL_RISKS,
  SAFETY_MANIFEST_VERSION,
} from "./manifest.js";
export type { SafetyManifest, ManifestInputs } from "./manifest.js";
