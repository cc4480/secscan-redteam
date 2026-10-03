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

export {
  ABORT_FILE_NAME,
  readAbortFile,
  writeAbortFile,
  consumeAbortFile,
} from "./abortfile.js";
export type { AbortSignal } from "./abortfile.js";

export {
  LOG_ROTATION_VERSION,
  DEFAULT_LOG_MAX_BYTES,
  DEFAULT_LOG_MAX_ARCHIVES,
  LOG_MAX_BYTES_ENV,
  LOG_MAX_ARCHIVES_ENV,
  resolveLogRotationConfig,
  maybeRotateLog,
} from "./rotation.js";
export type { LogRotationConfig, RotationOutcome, SeqRange } from "./rotation.js";
