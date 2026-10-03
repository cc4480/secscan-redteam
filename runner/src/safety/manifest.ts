/**
 * Safety manifest (v0.13.0) — the production safety case, machine-readable.
 *
 * One engagement → one manifest, written next to report.md and embedded in
 * the compliance pack's safety section. It states every protection that was
 * mechanically active, the configuration it ran with, what it did during
 * the engagement, and the residual risks — honestly. We never claim "zero
 * risk"; we claim specific protections and what they mechanically enforce.
 */

import { destructiveDenyList } from "../host-exec/common.js";
import { piiPatternLabels } from "./pii.js";
import type { TestEnvironment } from "./graduation.js";
import type { ZeroDisruptionRecord } from "./disruption.js";
import type { ApprovalEntry, AutonomyTier } from "../accountability/index.js";
import { TIER_NAMES, TIER_DESCRIPTIONS } from "../accountability/index.js";

export const SAFETY_MANIFEST_VERSION = "v0.17.0";

/** The mechanical protections — stated as what the RUNNER enforces, not what the agents were told. */
export const PROTECTIONS_IN_FORCE: string[] = [
  "exact-hostname ROE scope enforcement (out-of-scope targets refused before any packet)",
  "destructive-command denylist (fail closed; refused commands are DENIED events the coordinator re-plans around)",
  "DoS/resource-exhaustion exclusion (T1499) in every mode — DoS modules and destructive payloads refused mechanically",
  "canary-only payload policy (validated exploits execute a runner-built benign marker, nothing else)",
  "per-target rate limiting (token bucket, stated rps/host, mechanically enforced)",
  "per-target auto-halt (distress threshold → target halted, never hammered)",
  "kill switch (coordinator/operator abort terminates in-flight executions across all parallel tasks; new work refused)",
  "credential hygiene (env/Secure Vault only; redacted from logs, errors, events, reports)",
  "PII redaction (tool outputs scrubbed before the audit log, agent context, evidence, and reports)",
  "full audit log (every action → events.jsonl with ATT&CK ID; the zero-disruption record is derived from it)",
  "phase sign-off gates (coordinator approves plan→recon→exploit→report; exploit-phase gating for msf_exec run)",
  "staging→production graduation (production requires explicit operator confirmation + tighter rate limits)",
  "autonomy tiers (Tier 0 observe / Tier 1 validate / Tier 2 chain — tools above the tier refused mechanically in the dispatcher; Tier 1 limited to one validated exploit step per target; escalation needs a recorded operator approval, never silent)",
];

/**
 * Residual risks — stated plainly in the manifest and docs/safety.md.
 * A safety case that lists no residual risks is marketing, not engineering.
 */
export const RESIDUAL_RISKS: string[] = [
  "A validated exploit still executes a benign command on the target host — the canary marker is harmless by construction, but it IS code execution on the client's infrastructure.",
  "Rate limits bound request volume, not request cleverness — a single well-formed request can still trigger an expensive code path on the target (e.g. a heavy report query).",
  "Auto-halt reacts to distress signals; a target that degrades silently (slow responses, no errors) may not trip it before the engagement's own caps do.",
  "PII redaction is pattern-based (email, phone, SSN-like, card-like with Luhn) — novel PII shapes, or PII inside binary/encoded blobs, may pass through.",
  "The destructive denylist is a backstop over command TEXT — novel destructive formulations the patterns don't match are refused only if the agent prompts hold.",
  "Credential material lives in the operator's environment/Secure Vault — the runner redacts it everywhere it can see, but cannot protect the operator's own handling of it.",
];

export interface SafetyManifest {
  manifestVersion: string;
  engagementId: string;
  generatedAt: string;
  environment: TestEnvironment;
  productionConfirmed: boolean;
  scopeAllowlist: string[];
  rateLimit: {
    rpsPerHost: number;
    burst: number;
    productionCapApplied: boolean;
    throttledMs: number;
    acquires: number;
  };
  killSwitch: { armed: boolean; aborts: number };
  destructiveDenylist: { version: string; patternCount: number; patterns: string[] };
  payloadPolicy: "canary-only";
  dosPolicy: "excluded-always";
  humanOverride: {
    operator: string;
    abortPath: string;
    responseExpectation: string;
  };
  piiRedaction: { enabled: boolean; patterns: string[] };
  autoHalt: {
    consecutiveThreshold: number;
    windowSize: number;
    windowFailureRate: number;
    haltedTargets: string[];
    haltCount: number;
  };
  protectionsInForce: string[];
  zeroDisruption: ZeroDisruptionRecord;
  disruptionVerdict: string;
  residualRisks: string[];
  /**
   * v0.17.0 accountability: the autonomy tier in force and its approval
   * trail. A control boundary, stated plainly — never a safety guarantee.
   */
  autonomy: {
    tier: AutonomyTier;
    tierName: string;
    tierDescription: string;
    declaredTier: AutonomyTier;
    approvals: ApprovalEntry[];
  };
}

export interface ManifestInputs {
  engagementId: string;
  environment: TestEnvironment;
  productionConfirmed: boolean;
  scopeAllowlist: string[];
  rpsPerHost: number;
  burst: number;
  productionCapApplied: boolean;
  throttledMs: number;
  acquires: number;
  killSwitchAborts: number;
  operator: string;
  autoHalt: { consecutiveThreshold: number; windowSize: number; windowFailureRate: number; haltedTargets: string[]; haltCount: number };
  zeroDisruption: ZeroDisruptionRecord;
  disruptionVerdict: string;
  generatedAt?: string;
  /**
   * v0.17.0 accountability: tier in force + approval trail. Optional for
   * backward compatibility — defaults to Tier 2 (chain) declared, no
   * approvals (the pre-tier manifest shape).
   */
  autonomy?: {
    tier: AutonomyTier;
    declaredTier: AutonomyTier;
    approvals: ApprovalEntry[];
  };
}

export function buildSafetyManifest(input: ManifestInputs): SafetyManifest {
  return {
    manifestVersion: SAFETY_MANIFEST_VERSION,
    engagementId: input.engagementId,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    environment: input.environment,
    productionConfirmed: input.productionConfirmed,
    scopeAllowlist: [...input.scopeAllowlist],
    rateLimit: {
      rpsPerHost: input.rpsPerHost,
      burst: input.burst,
      productionCapApplied: input.productionCapApplied,
      throttledMs: input.throttledMs,
      acquires: input.acquires,
    },
    killSwitch: { armed: true, aborts: input.killSwitchAborts },
    destructiveDenylist: {
      version: SAFETY_MANIFEST_VERSION,
      patternCount: destructiveDenyList().length,
      patterns: destructiveDenyList(),
    },
    payloadPolicy: "canary-only",
    dosPolicy: "excluded-always",
    humanOverride: {
      operator: input.operator,
      abortPath: "abort_engagement tool (coordinator) → kill switch aborts every registered execution controller; in-flight host/msf work terminates, new work is refused. The console operator can trigger it at any time.",
      responseExpectation:
        "The operator who launched the engagement is expected to be reachable for its duration (24/7 override for scheduled multi-day runs — see docs/safety.md). Abort takes effect on the next dispatch boundary, typically seconds.",
    },
    piiRedaction: { enabled: true, patterns: piiPatternLabels() },
    autoHalt: input.autoHalt,
    protectionsInForce: [...PROTECTIONS_IN_FORCE],
    zeroDisruption: input.zeroDisruption,
    disruptionVerdict: input.disruptionVerdict,
    residualRisks: [...RESIDUAL_RISKS],
    autonomy: {
      tier: input.autonomy?.tier ?? 2,
      tierName: TIER_NAMES[input.autonomy?.tier ?? 2],
      tierDescription: TIER_DESCRIPTIONS[input.autonomy?.tier ?? 2],
      declaredTier: input.autonomy?.declaredTier ?? 2,
      approvals: (input.autonomy?.approvals ?? []).map((a) => ({ ...a })),
    },
  };
}

/** Markdown rendering for safety-manifest.md (human-readable twin of the JSON). */
export function renderSafetyManifestMarkdown(m: SafetyManifest): string {
  const L: string[] = [];
  L.push(`# Safety manifest — engagement ${m.engagementId}`);
  L.push(``);
  L.push(`Generated ${m.generatedAt} · manifest ${m.manifestVersion} · environment **${m.environment}**${m.environment === "production" ? ` (operator-confirmed: ${m.productionConfirmed})` : ""}.`);
  L.push(``);
  L.push(`## Protections in force (mechanical, runner-enforced)`);
  for (const p of m.protectionsInForce) L.push(`- ${p}`);
  L.push(``);
  L.push(`## Configuration this engagement`);
  L.push(`- Scope allowlist: ${m.scopeAllowlist.join(", ") || "(empty)"}`);
  L.push(`- Rate limit: ${m.rateLimit.rpsPerHost} rps/host (burst ${m.rateLimit.burst})${m.rateLimit.productionCapApplied ? " — production cap applied" : ""}; throttled ${m.rateLimit.throttledMs}ms total across ${m.rateLimit.acquires} acquires`);
  L.push(`- Kill switch: armed; aborts this engagement: ${m.killSwitch.aborts}`);
  L.push(`- Destructive denylist: ${m.destructiveDenylist.patternCount} patterns (${m.destructiveDenylist.version})`);
  L.push(`- Payload policy: ${m.payloadPolicy} · DoS policy: ${m.dosPolicy}`);
  L.push(`- PII redaction: enabled (${m.piiRedaction.patterns.join(", ")})`);
  L.push(`- Auto-halt: ${m.autoHalt.consecutiveThreshold} consecutive distress or ${Math.round(m.autoHalt.windowFailureRate * 100)}% over last ${m.autoHalt.windowSize} → target halted; halted: ${m.autoHalt.haltedTargets.join(", ") || "(none)"}`);
  L.push(`- Human override: ${m.humanOverride.operator} — ${m.humanOverride.abortPath}`);
  L.push(`- Autonomy tier: Tier ${m.autonomy.tier} (${m.autonomy.tierName}) — ${m.autonomy.tierDescription}`);
  if (m.autonomy.declaredTier !== m.autonomy.tier) {
    L.push(`  (declared Tier ${m.autonomy.declaredTier} at start; escalated mid-engagement — see approval log)`);
  }
  L.push(`- Approvals recorded: ${m.autonomy.approvals.length} (see compliance pack §7 for the full log)`);
  L.push(``);
  L.push(`## Zero-disruption record (derived from events.jsonl)`);
  L.push(``);
  L.push(m.disruptionVerdict);
  const z = m.zeroDisruption;
  L.push(``);
  L.push(`| Intervention | Count |`);
  L.push(`|---|---|`);
  L.push(`| Destructive-denylist refusals | ${z.denylistRefusals} |`);
  L.push(`| DoS refusals | ${z.dosRefusals} |`);
  L.push(`| Out-of-scope refusals | ${z.scopeRefusals} |`);
  L.push(`| Other policy refusals | ${z.policyRefusals} |`);
  L.push(`| Per-target auto-halts | ${z.autoHalts} |`);
  L.push(`| Kill-switch aborts | ${z.killSwitchAborts} |`);
  L.push(`| **Destructive actions fired** | **${z.destructiveActionsFired}** |`);
  L.push(``);
  L.push(`## Residual risks (stated honestly — a safety case with none is marketing)`);
  for (const r of m.residualRisks) L.push(`- ${r}`);
  L.push(``);
  return L.join("\n");
}
