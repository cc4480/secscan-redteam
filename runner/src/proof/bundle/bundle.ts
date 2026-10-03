/**
 * PoC bundle builder: derives a structured, re-verifiable proof bundle
 * from the audit log for one confirmed finding. Returns null (with
 * reason) when the validation bar is not met — never fabricated.
 */

import type { EngagementEvent, Finding } from "../../types.js";
import { redactSecrets } from "../../host-exec/common.js";
import {
  CVE_RE,
  PROOF_TOOL_ACTIONS,
  extractCommand,
  extractReplay,
  isFailure,
  stepValidation,
} from "./steps.js";
import type { PocStep, StepValidation } from "./steps.js";

export type ValidationTier = "execution" | "observation";

export interface PocBundle {
  version: 1;
  bundleId: string;
  engagementId: string;
  findingId: string;
  batteryItemId?: string;
  attackIds: string[];
  cve?: string;
  severity: string;
  title: string;
  target: string;
  operator: string;
  generatedAt: string;
  steps: PocStep[];
  markerSent?: string;
  markerObserved?: string;
  validationTier: ValidationTier;
  /** Exactly what the bundle proves — the specific executed/observed action. */
  proves: string;
  /** What it does NOT prove — no impact overclaim, stated explicitly. */
  doesNotProve: string;
  reverifyCommand: string;
}

export interface BundleBuildInput {
  finding: Finding;
  batteryItemId?: string;
  cve?: string;
  events: EngagementEvent[];
  engagement: { engagementId: string; target: string; operator: string };
  secrets: string[];
}

export interface BundleBuildResult {
  bundle: PocBundle | null;
  /** Why no bundle was built (honest absence). */
  reason?: string;
}

export function buildPocBundle(input: BundleBuildInput): BundleBuildResult {
  const { finding, events, engagement, secrets } = input;
  const redact = (s: string) => redactSecrets(s, secrets);

  if (finding.status !== "confirmed") {
    return { bundle: null, reason: `finding ${finding.id} is not confirmed (status=${finding.status}) — no bundle` };
  }

  const attackIds = finding.attackIds.map((a) => a.toUpperCase());
  const correlated = events.filter((ev) => {
    if (ev.phase !== "exploit" && ev.phase !== "recon") return false;
    if (!PROOF_TOOL_ACTIONS.has(ev.action)) return false;
    if (attackIds.length > 0) {
      const evAttack = (ev.attackId ?? "").toUpperCase();
      if (!attackIds.includes(evAttack)) return false;
    } else if (ev.target !== engagement.target) {
      return false;
    }
    return true;
  });

  if (correlated.length === 0) {
    return { bundle: null, reason: `finding ${finding.id}: no correlated tool execution in the audit log — no bundle` };
  }

  const steps: PocStep[] = correlated.map((ev) => {
    const { validation, marker } = stepValidation(ev.action, ev.result);
    const command = redact(extractCommand(ev.action, ev.result));
    const cveM = ev.result.match(CVE_RE);
    return {
      seq: ev.seq,
      ts: ev.ts,
      tool: ev.action,
      target: ev.target,
      attackId: ev.attackId,
      command,
      result: redact(ev.result.slice(0, 500)),
      validation: isFailure(ev.result) ? "none" : validation,
      marker,
      cve: cveM ? cveM[1]!.toUpperCase() : undefined,
      replay: extractReplay(ev.action, ev, command),
    };
  });

  const validating = steps.filter((s) => s.validation !== "none");
  if (validating.length === 0) {
    return {
      bundle: null,
      reason:
        `finding ${finding.id}: ${steps.length} correlated step(s) but no validation signal ` +
        `(no marker echo observed, no read-only evidence output) — no bundle`,
    };
  }

  const markerStep = steps.find((s) => s.validation === "marker-echo");
  const tier: ValidationTier = markerStep ? "execution" : "observation";
  const stepCves = steps.map((s) => s.cve).filter(Boolean) as string[];
  const cve = input.cve ?? stepCves[0];

  const proves =
    tier === "execution"
      ? `${markerStep!.tool} executed the runner-built canary on ${markerStep!.target ?? engagement.target} ` +
        `(${markerStep!.attackId ?? attackIds[0] ?? "technique"}); marker REDTEAM-MARKER-${markerStep!.marker ?? "?"} ` +
        `echoed back at ${markerStep!.ts}. This proves the specific executed action and nothing more.`
      : `Read-only ${validating[0]!.tool} output on ${validating[0]!.target ?? engagement.target} ` +
        `(${validating[0]!.attackId ?? attackIds[0] ?? "technique"}) directly demonstrates "${finding.title}". ` +
        `This proves the observed misconfiguration/exposure and nothing more.`;

  const bundle: PocBundle = {
    version: 1,
    bundleId: `POC-${engagement.engagementId}-${finding.id}`,
    engagementId: engagement.engagementId,
    findingId: finding.id,
    batteryItemId: input.batteryItemId,
    attackIds,
    cve,
    severity: finding.severity,
    title: redact(finding.title),
    target: engagement.target,
    operator: engagement.operator,
    generatedAt: new Date().toISOString(),
    steps,
    markerSent: markerStep?.marker ? `REDTEAM-MARKER-${markerStep.marker}` : undefined,
    markerObserved: markerStep?.marker ? `REDTEAM-MARKER-${markerStep.marker}` : undefined,
    validationTier: tier,
    proves: redact(proves),
    doesNotProve:
      "Full impact beyond the executed/observed action — lateral movement, persistence, " +
      "privilege beyond what the steps show, data access or exfiltration — was not attempted " +
      "and is NOT proven by this bundle. Re-running the steps should reproduce the same " +
      "observation; any deviation means the target changed.",
    reverifyCommand: `redteam-runner reverify --bundle poc/${finding.id}.json --scope ${engagement.target} --execute`,
  };
  return { bundle };
}

/** A killed hypothesis with its decisive audit evidence attached (negative proof). */
