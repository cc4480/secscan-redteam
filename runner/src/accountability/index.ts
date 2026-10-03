/**
 * Accountability module barrel (v0.17.0) — autonomy tiers + named human
 * accountability, the last enterprise buying gate.
 *
 * Graduated, mechanically-enforced autonomy (tiers.ts): Tier 0 observe,
 * Tier 1 validate (single-step), Tier 2 chain. Named operator accountability
 * and the append-only approval log (accountability.ts).
 */

export {
  parseTier,
  defaultTier,
  tier2ProductionConfirmed,
  requireTier2ProductionApproval,
  toolMinTier,
  isExploitStepTool,
  checkTierAllows,
  recordExploitStep,
  describeTier,
  TIER_NAMES,
  TIER_DESCRIPTIONS,
  TIER1_CHAIN_BUDGET_PER_TARGET,
  TIER_ENV,
  TIER2_PROD_CONFIRM_ENV,
} from "./tiers.js";
export type { AutonomyTier, TierState } from "./tiers.js";

export {
  ApprovalLog,
  escalateTier,
  requireNamedOperator,
  resolveOperatorName,
  OPERATOR_ENV,
} from "./accountability.js";
export type { ApprovalEntry, ApprovalKind, EscalationApproval } from "./accountability.js";

export { readTierFile, writeTierFile, TIER_FILE_NAME } from "./tierfile.js";
export type { TierFile } from "./tierfile.js";

export {
  escalateEngagement,
  describeEscalation,
  resolveEngagementsDir,
  isSafeEngagementId,
} from "./escalate.js";
export type { EscalateRequest, EscalateResult } from "./escalate.js";
