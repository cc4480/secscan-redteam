/**
 * Negative proof (killed hypotheses with decisive audit evidence) and the
 * one-line bundle summary for the report.
 */

import { redactSecrets } from "../../host-exec/common.js";
import { PROOF_TOOL_ACTIONS } from "./steps.js";
import type { PocBundle } from "./bundle.js";
import type { EngagementEvent } from "../../types.js";

export interface NegativeProof {
  hypothesis: string;
  killingObservation: string;
  attackId?: string;
  vulnClass?: string;
  /** The audit events constituting the decisive observation (what was tried, what was seen). */
  decisiveEvents: Array<{ seq: number; ts: string; tool: string; result: string }>;
}

/**
 * Negative proof: for each killed hypothesis, attach the decisive audit
 * events. Buyers value knowing what was tried and ruled out — and the
 * registry already records the killing observation; this grounds it in
 * the actual probe sequence.
 */
export function buildNegativeProof(
  killed: Array<{ hypothesis: string; killingObservation: string; attackId?: string; vulnClass?: string }>,
  events: EngagementEvent[],
  secrets: string[],
): NegativeProof[] {
  const redact = (s: string) => redactSecrets(s, secrets);
  return killed.map((k) => {
    const attack = (k.attackId ?? "").toUpperCase();
    const decisiveEvents = events
      .filter((ev) => {
        if (ev.phase !== "exploit" && ev.phase !== "recon") return false;
        if (!PROOF_TOOL_ACTIONS.has(ev.action)) return false;
        if (attack && (ev.attackId ?? "").toUpperCase() !== attack) return false;
        return true;
      })
      .slice(-5)
      .map((ev) => ({ seq: ev.seq, ts: ev.ts, tool: ev.action, result: redact(ev.result.slice(0, 300)) }));
    return {
      hypothesis: redact(k.hypothesis),
      killingObservation: redact(k.killingObservation),
      attackId: k.attackId,
      vulnClass: k.vulnClass,
      decisiveEvents,
    };
  });
}

/** One-line bundle summary for the report's Proof of exploitation section. */
export function bundleSummary(b: PocBundle): string {
  const steps = b.steps.map((s) => `seq ${s.seq} ${s.tool}${s.marker ? ` (marker ${s.marker})` : ""}`).join("; ");
  return (
    `**${b.findingId}** — ${b.title} [${b.severity}] (${b.validationTier} proof). ` +
    `${b.proves} Steps (${b.steps.length}): ${steps}. ` +
    `Bundle: poc/${b.findingId}.json. Re-verify: \`${b.reverifyCommand}\``
  );
}
