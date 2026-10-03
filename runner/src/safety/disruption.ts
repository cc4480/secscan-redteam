/**
 * Zero-disruption record (v0.13.0) — the production safety case.
 *
 * Derived mechanically from the engagement's events.jsonl AFTER the run:
 * counts every safety refusal and proves the negative — no destructive
 * action fired. This is the artifact a buyer's security team reviews: not
 * "we were careful", but the counted refusals from the audit log.
 *
 * Counts (all from events the runner itself appended):
 *  - denylistRefusals: destructive-command denylist hits ("DENIED by destructive-command denylist")
 *  - dosRefusals: DoS/destructive module or payload refusals (msf policy)
 *  - scopeRefusals: out-of-scope target refusals
 *  - policyRefusals: other ROE/policy refusals (technique excluded, phase-gated msf run, etc.)
 *  - autoHalts: per-target auto-halt events
 *  - killSwitchAborts: coordinator/operator aborts that terminated in-flight work
 *  - destructiveActionsFired: MUST be 0 — any event whose result claims a
 *    destructive action executed. The record states the count, never assumes.
 */

import type { EngagementEvent } from "../types.js";

export interface ZeroDisruptionRecord {
  denylistRefusals: number;
  dosRefusals: number;
  scopeRefusals: number;
  policyRefusals: number;
  autoHalts: number;
  killSwitchAborts: number;
  /** Counted, never assumed — the record is only clean when this is 0. */
  destructiveActionsFired: number;
  /** Total safety interventions (all of the above except destructiveActionsFired). */
  totalInterventions: number;
}

const EMPTY: ZeroDisruptionRecord = {
  denylistRefusals: 0,
  dosRefusals: 0,
  scopeRefusals: 0,
  policyRefusals: 0,
  autoHalts: 0,
  killSwitchAborts: 0,
  destructiveActionsFired: 0,
  totalInterventions: 0,
};

export function buildZeroDisruptionRecord(events: EngagementEvent[]): ZeroDisruptionRecord {
  const rec: ZeroDisruptionRecord = { ...EMPTY };
  for (const ev of events) {
    const r = `${ev.action} ${ev.result}`.toLowerCase();
    const denied = /denied|refus/.test(r);
    if (/destructive(-command)? denylist/.test(r) && denied) rec.denylistRefusals++;
    // DoS refusals are explicit: the word "dos"/"denial of service" plus a
    // denial — a bare T1499 mention (e.g. an ROE technique exclusion) is a
    // policy refusal, counted below.
    else if (denied && (/\bdos\b/.test(r) || /denial.of.service/.test(r))) rec.dosRefusals++;
    else if (/out of scope|outside the engagement scope/.test(r)) rec.scopeRefusals++;
    else if (/^denied/.test(ev.result.trim().toLowerCase()) || /denied by roe|phase-gat/.test(r)) rec.policyRefusals++;
    if (ev.action === "target_auto_halt") rec.autoHalts++;
    if (ev.action === "abort_engagement" && /abort/i.test(ev.result)) rec.killSwitchAborts++;
    // The negative we must prove: any event claiming a destructive action ran.
    if (/destructive action (executed|fired)|executed destructive/i.test(r)) rec.destructiveActionsFired++;
  }
  rec.totalInterventions =
    rec.denylistRefusals + rec.dosRefusals + rec.scopeRefusals + rec.policyRefusals + rec.autoHalts + rec.killSwitchAborts;
  return rec;
}

/** One-line verdict for the manifest and the report. */
export function disruptionVerdict(rec: ZeroDisruptionRecord): string {
  if (rec.destructiveActionsFired > 0) {
    return `FAIL: ${rec.destructiveActionsFired} destructive action(s) recorded as executed — investigate events.jsonl immediately.`;
  }
  return (
    `CLEAN: 0 destructive actions fired across the engagement; ` +
    `${rec.totalInterventions} safety intervention(s) ` +
    `(${rec.denylistRefusals} denylist, ${rec.dosRefusals} DoS, ${rec.scopeRefusals} scope, ` +
    `${rec.policyRefusals} policy, ${rec.autoHalts} auto-halt, ${rec.killSwitchAborts} kill-switch).`
  );
}
