/**
 * Named accountability + approval log (v0.17.0) — the human side of the
 * autonomy tiers.
 *
 * Buyers reject AI-only testing without a named human accountable per
 * finding. This module provides:
 *
 *  - `requireNamedOperator`: production engagements refuse to start without
 *    a named human operator (fail fast, before any packet). Staging warns
 *    via the existing "(operator name not supplied)" fallback.
 *  - `ApprovalLog`: every approval (tier declared, tier escalation,
 *    production confirmation, scope renewal) appended to an
 *    append-only-per-engagement log (approvals.jsonl), with who/what/when.
 *    The log is embedded in the compliance pack and the safety manifest.
 *  - `escalateTier`: the ONLY path to raise the tier mid-engagement. It
 *    requires an operator name + reason, records the approval FIRST, then
 *    moves the tier. There is no agent tool that calls this — escalation is
 *    an operator act, never a silent agent decision.
 *
 * Honesty: tiers describe what the agents MAY do, never imply the human did
 * the work. The accountability record adds who supervised and approved.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AutonomyTier } from "./tiers.js";
import { TIER_NAMES } from "./tiers.js";

export type ApprovalKind = "tier-declared" | "tier-escalation" | "production-confirm" | "scope-renewal";

export interface ApprovalEntry {
  seq: number;
  ts: string; // ISO
  engagementId: string;
  operator: string;
  kind: ApprovalKind;
  detail: string;
  fromTier?: AutonomyTier;
  toTier?: AutonomyTier;
}

export const OPERATOR_ENV = "REDTEAM_OPERATOR";

/** Resolve the named human operator: explicit input wins, then env. */
export function resolveOperatorName(inputName: string | undefined, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const v = (inputName ?? "").trim() || (env[OPERATOR_ENV] ?? "").trim();
  return v || undefined;
}

/**
 * Mechanical: production engagements refuse to start without a named human
 * operator. Someone must be accountable. Staging keeps the existing
 * fallback labeling (honest "(not supplied)" marker downstream).
 */
export function requireNamedOperator(environment: "staging" | "production", operator: string | undefined): void {
  if (environment === "production" && !operator) {
    throw new Error(
      `[accountability] PRODUCTION engagements require a named human operator accountable for the run. ` +
        `Pass --operator "<name>" (or set ${OPERATOR_ENV}=<name>). Someone must own the findings, the tier, and the scope.`,
    );
  }
}

export interface EscalationApproval {
  operator: string;
  reason: string;
}

/**
 * Append-only approval log, one file per engagement (approvals.jsonl).
 * Entries are never edited or deleted — the log is the record.
 */
export class ApprovalLog {
  private seq = 0;
  private readonly file: string;
  private readonly engagementId: string;

  constructor(dir: string, engagementId: string) {
    mkdirSync(dir, { recursive: true });
    this.file = join(dir, "approvals.jsonl");
    this.engagementId = engagementId;
    // Resume sequence if the file already exists (re-entrant runs).
    if (existsSync(this.file)) {
      for (const line of readFileSync(this.file, "utf8").split("\n")) {
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line) as ApprovalEntry;
          if (typeof e.seq === "number" && e.seq >= this.seq) this.seq = e.seq + 1;
        } catch {
          /* corrupt line: skip, keep counting */
        }
      }
    }
  }

  append(kind: ApprovalKind, operator: string, detail: string, fromTier?: AutonomyTier, toTier?: AutonomyTier): ApprovalEntry {
    const entry: ApprovalEntry = {
      seq: this.seq++,
      ts: new Date().toISOString(),
      engagementId: this.engagementId,
      operator,
      kind,
      detail,
      ...(fromTier !== undefined ? { fromTier } : {}),
      ...(toTier !== undefined ? { toTier } : {}),
    };
    appendFileSync(this.file, JSON.stringify(entry) + "\n");
    return entry;
  }

  list(): ApprovalEntry[] {
    if (!existsSync(this.file)) return [];
    const out: ApprovalEntry[] = [];
    for (const line of readFileSync(this.file, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        out.push(JSON.parse(line) as ApprovalEntry);
      } catch {
        /* skip corrupt lines */
      }
    }
    return out;
  }

  get path(): string {
    return this.file;
  }
}

/**
 * The ONLY path to raise the tier mid-engagement. Requires a named operator
 * and a reason; records the approval BEFORE moving the tier. There is no
 * agent tool that calls this — escalation is an operator act.
 *
 * Returns the recorded approval entry. Refuses no-op or downward moves
 * (lowering the tier mid-run is a fresh engagement decision, not an
 * escalation).
 */
export function escalateTier(
  state: { current: AutonomyTier },
  toTier: AutonomyTier,
  log: ApprovalLog,
  approval: EscalationApproval,
): ApprovalEntry {
  const operator = (approval.operator ?? "").trim();
  if (!operator) {
    throw new Error("[accountability] tier escalation requires a named operator — refusing anonymous escalation.");
  }
  const reason = (approval.reason ?? "").trim();
  if (!reason) {
    throw new Error("[accountability] tier escalation requires a recorded reason — refusing unexplained escalation.");
  }
  if (toTier <= state.current) {
    throw new Error(
      `[accountability] escalation moves UP only (current Tier ${state.current}, requested Tier ${toTier}). ` +
        `Lowering the tier mid-run is a new engagement decision, not an escalation.`,
    );
  }
  const fromTier = state.current;
  const entry = log.append(
    "tier-escalation",
    operator,
    `Tier escalated ${fromTier} (${TIER_NAMES[fromTier]}) → ${toTier} (${TIER_NAMES[toTier]}): ${reason}`,
    fromTier,
    toTier,
  );
  state.current = toTier;
  return entry;
}
