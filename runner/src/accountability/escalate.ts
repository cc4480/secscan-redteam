/**
 * Mid-run tier escalation entry point (v0.24.0) — shared by the CLI
 * (`redteam-runner escalate`) and the UI (POST /api/engagements/:id/escalate).
 * One implementation, two surfaces: the rules cannot drift between them.
 *
 * Rules (mechanical, same as the dispatcher enforces):
 *  - UP (toTier > current) requires a named operator AND a recorded reason.
 *  - DOWN (toTier < current) is allowed freely — lowering autonomy mid-run
 *    is harmless — but it is still logged with the operator's name.
 *  - Tier 2 on PRODUCTION additionally requires explicit production
 *    confirmation (--confirm-tier2-production / REDTEAM_TIER2_PROD_CONFIRM).
 *  - The approval is recorded in approvals.jsonl BEFORE tier.json is
 *    rewritten; a running dispatcher picks the new tier up on its next
 *    tool call. Agents can never call this — there is no agent tool for it.
 */

import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { ApprovalLog, escalateTier, resolveOperatorName, type ApprovalEntry } from "./accountability.js";
import {
  parseTier,
  requireTier2ProductionApproval,
  TIER_NAMES,
  type AutonomyTier,
} from "./tiers.js";
import { readTierFile, writeTierFile } from "./tierfile.js";
import { readState } from "../events.js";

/** Same convention as the runner config and the UI store: REDTEAM_HOME or cwd. */
export function resolveEngagementsDir(env: NodeJS.ProcessEnv = process.env, override?: string): string {
  if (override && override.trim()) return resolve(override);
  const home = env["REDTEAM_HOME"];
  return home ? join(home, "engagements", "live") : join(process.cwd(), "engagements", "live");
}

/** Engagement IDs are runner-generated — accept only the safe shape (no traversal). */
export function isSafeEngagementId(id: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]{0,120}$/.test(id);
}

export interface EscalateRequest {
  engagementsDir?: string;
  engagementId: string;
  /** 0|1|2 (or observe|validate|chain) — parsed loudly, never guessed. */
  toTier: string;
  operator?: string;
  reason?: string;
  /** Explicit Tier-2-on-production confirmation (flag or env). */
  tier2ProdConfirmed?: boolean;
  env?: NodeJS.ProcessEnv;
}

export interface EscalateResult {
  engagementId: string;
  fromTier: AutonomyTier;
  toTier: AutonomyTier;
  operator: string;
  /** Engagement status from state.json — tells the caller whether a live dispatcher will pick this up. */
  engagementStatus: string;
  approvalSeq: number;
}

export function escalateEngagement(req: EscalateRequest): EscalateResult {
  const env = req.env ?? process.env;
  const id = (req.engagementId ?? "").trim();
  if (!isSafeEngagementId(id)) {
    throw new Error("[escalate] bad engagement id — refusing (path traversal guard).");
  }
  const toTier = parseTier(req.toTier);
  if (toTier === undefined) {
    throw new Error("[escalate] --tier is required: 0|1|2 (observe|validate|chain).");
  }
  const dir = resolveEngagementsDir(env, req.engagementsDir);
  const engDir = join(dir, id);
  if (!existsSync(join(engDir, "state.json"))) {
    throw new Error(`[escalate] unknown engagement ${JSON.stringify(id)} (no state.json under ${dir}).`);
  }
  const tf = readTierFile(engDir);
  if (!tf) {
    throw new Error(
      `[escalate] engagement ${JSON.stringify(id)} has no tier.json — it predates v0.24.0 or never declared a tier. ` +
        `Re-run it on this version to enable mid-run escalation.`,
    );
  }
  const operator = resolveOperatorName(req.operator, env);
  if (!operator) {
    throw new Error("[escalate] a named operator is required — pass --operator \"<name>\" (or set REDTEAM_OPERATOR). Someone must own the tier change.");
  }
  const up = toTier > tf.tier;
  const reason = (req.reason ?? "").trim();
  if (up && !reason) {
    throw new Error("[escalate] raising the tier requires --reason \"<text>\" — unexplained escalation is refused.");
  }
  if (toTier === 2 && tf.environment === "production") {
    const confirmed = req.tier2ProdConfirmed ?? false;
    requireTier2ProductionApproval(2, "production", confirmed);
  }
  const log = new ApprovalLog(engDir, id);
  const state = { current: tf.tier };
  const entry: ApprovalEntry = escalateTier(state, toTier, log, { operator, reason });
  writeTierFile(engDir, {
    tier: toTier,
    declared: tf.declared,
    environment: tf.environment,
    updatedAt: new Date().toISOString(),
    by: operator,
    ...(reason ? { reason } : {}),
  });
  const st = readState(engDir);
  const engagementStatus = st?.status ?? "unknown";
  return {
    engagementId: id,
    fromTier: tf.tier,
    toTier,
    operator,
    engagementStatus,
    approvalSeq: entry.seq,
  };
}

/** Human-readable one-liner for CLI output. */
export function describeEscalation(r: EscalateResult): string {
  const live = r.engagementStatus === "running" || r.engagementStatus === "authorizing";
  const signal = live
    ? "the running dispatcher picks it up on its next tool call (no restart needed)"
    : `engagement is ${r.engagementStatus} — approval recorded; nothing left to signal`;
  return (
    `[escalate] ${r.engagementId}: Tier ${r.fromTier} (${TIER_NAMES[r.fromTier]}) → Tier ${r.toTier} (${TIER_NAMES[r.toTier]}) ` +
    `by ${r.operator} (approval #${r.approvalSeq}). ${signal}.`
  );
}
