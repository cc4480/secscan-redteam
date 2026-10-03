/**
 * Human-readable markdown rendering of the compliance pack (written next
 * to report.md).
 */

import { TIER_DESCRIPTIONS } from "../../accountability/index.js";
import { lookupControl } from "../controls.js";
import type { CompliancePack } from "./meta.js";

export function renderCompliancePackMarkdown(pack: CompliancePack): string {
  const L: string[] = [];
  L.push(`# Compliance evidence pack — engagement ${pack.engagementId}`);
  L.push(``);
  L.push(`Generated: ${pack.generatedAt} · Operator: ${pack.operator}${pack.client ? ` · Client: ${pack.client}` : ""}`);
  L.push(``);
  L.push(`> This pack is EVIDENCE supporting the listed compliance requirements. It does not declare the client compliant or certified — that judgment belongs to the client's QSA/auditor.`);
  L.push(``);
  L.push(`## 1. Engagement metadata`);
  L.push(``);
  L.push(`- Target: ${pack.metadata.target}`);
  L.push(`- Mode: ${pack.metadata.mode.toUpperCase()} · Objective: ${pack.metadata.objective}`);
  L.push(`- Scope: ${pack.metadata.scope.join(", ") || "(none recorded)"}`);
  L.push(`- Test window: ${pack.metadata.testWindow.start} → ${pack.metadata.testWindow.end}`);
  L.push(`- Authorization proof: ${pack.metadata.authorizationProof}`);
  L.push(``);
  L.push(`## 2. Documented methodology`);
  L.push(``);
  L.push(pack.methodology.approach);
  L.push(``);
  for (const p of pack.methodology.phases) L.push(`- ${p}`);
  L.push(``);
  L.push(`### Tools used`);
  L.push(``);
  for (const t of pack.methodology.toolsUsed) L.push(`- ${t}`);
  L.push(``);
  L.push(`### Validation standard`);
  L.push(``);
  L.push(pack.methodology.validationStandard);
  L.push(``);
  L.push(`### Explicit exclusions`);
  L.push(``);
  for (const e of pack.methodology.exclusions) L.push(`- ${e}`);
  L.push(``);
  L.push(`### Authorization`);
  L.push(``);
  L.push(pack.methodology.authorization);
  L.push(``);
  if (pack.safety) {
    const s = pack.safety;
    L.push(`## 3. Safety case (mechanical protections, runner-enforced)`);
    L.push(``);
    L.push(`Environment: **${s.environment}**${s.environment === "production" ? ` (operator-confirmed: ${s.productionConfirmed})` : ""} · Manifest ${s.manifestVersion} · Generated ${s.generatedAt}`);
    L.push(``);
    L.push(`### Protections in force`);
    L.push(``);
    for (const p of s.protectionsInForce) L.push(`- ${p}`);
    L.push(``);
    L.push(`### Configuration this engagement`);
    L.push(``);
    L.push(`- Scope allowlist: ${s.scopeAllowlist.join(", ") || "(empty)"}`);
    L.push(`- Rate limit: ${s.rateLimit.rpsPerHost} requests/sec per host (burst ${s.rateLimit.burst})${s.rateLimit.productionCapApplied ? " — production cap applied mechanically" : ""}`);
    L.push(`- Kill switch: armed; aborts this engagement: ${s.killSwitch.aborts}`);
    L.push(`- Destructive denylist: ${s.destructiveDenylist.patternCount} patterns (${s.destructiveDenylist.version})`);
    L.push(`- Payload policy: ${s.payloadPolicy} · DoS policy: ${s.dosPolicy}`);
    L.push(`- PII redaction: enabled (${s.piiRedaction.patterns.join(", ")})`);
    L.push(`- Auto-halt: ${s.autoHalt.consecutiveThreshold} consecutive distress outcomes or ${Math.round(s.autoHalt.windowFailureRate * 100)}% distress over last ${s.autoHalt.windowSize} → target halted; halted targets: ${s.autoHalt.haltedTargets.join(", ") || "(none)"}`);
    L.push(`- Human override: ${s.humanOverride.operator}. ${s.humanOverride.abortPath}`);
    L.push(``);
    L.push(`### Zero-disruption record (derived from events.jsonl)`);
    L.push(``);
    L.push(s.disruptionVerdict);
    L.push(``);
    L.push(`### Residual risks`);
    L.push(``);
    for (const r of s.residualRisks) L.push(`- ${r}`);
    L.push(``);
  } else {
    L.push(`## 3. Safety case`);
    L.push(``);
    L.push(`(safety manifest not recorded for this engagement — engagements before v0.13.0 predate the machine-readable safety case)`);
    L.push(``);
  }
  L.push(`## 4. Findings → controls`);
  L.push(``);
  L.push(`Controls exercised: ${pack.coverage.controlsExercised}/${pack.coverage.controlsTotal}`);
  L.push(``);
  if (pack.findings.length === 0) {
    L.push(`(no findings recorded this engagement)`);
  } else {
    L.push(`| ID | Severity | Title | ATT&CK | Controls | Status |`);
    L.push(`|---|---|---|---|---|---|`);
    for (const f of pack.findings) {
      const ctrls = f.controls.length > 0 ? f.controls.join(", ") : "(no ATT&CK mapping)";
      L.push(`| ${f.id} | ${f.severity} | ${f.title} | ${f.attackIds.join(", ") || "—"} | ${ctrls} | ${f.status} |`);
    }
    for (const f of pack.findings) {
      L.push(``);
      L.push(`### ${f.id} — ${f.title} [${f.severity}]`);
      L.push(``);
      L.push(`- ATT&CK: ${f.attackIds.join(", ") || "—"}`);
      L.push(`- Controls: ${f.controls.length > 0 ? f.controls.map((c) => `${c} (${lookupControl(c)?.title ?? ""})`).join("; ") : "(none — no ATT&CK mapping)"}`);
      L.push(`- Accountable operator: ${f.accountableOperator}`);
      L.push(`- Evidence: ${f.evidence}`);
      L.push(`- Remediation: ${f.fix}`);
      L.push(`- Retest: ${f.retest}`);
    }
  }
  L.push(``);
  L.push(`## 5. Retest evidence (before/after per vulnerability class)`);
  L.push(``);
  if (pack.retestEvidence.length === 0) {
    L.push(`(no registry history yet)`);
  } else {
    for (const r of pack.retestEvidence) {
      L.push(`- **${r.vulnClass}** — ${r.observationCount} observation(s): first ${r.firstSeen.engagementId} (${r.firstSeen.date}, ${r.firstSeen.severity}, ref: ${r.firstSeen.evidenceRef}) → latest ${r.latest.engagementId} (${r.latest.date}, ${r.latest.severity}, ref: ${r.latest.evidenceRef})`);
    }
  }
  L.push(``);
  L.push(`## 6. Honest limits`);
  L.push(``);
  for (const h of pack.honestLimits) L.push(`- ${h}`);
  L.push(``);
  L.push(`## 7. Autonomy tier & approval log`);
  L.push(``);
  L.push(
    `Autonomy in force: **Tier ${pack.autonomyTier} (${pack.autonomyTierName})** — ${TIER_DESCRIPTIONS[pack.autonomyTier]} ` +
      `Tiers are a control boundary describing what the agents were allowed to do; they are not a safety guarantee and never imply the human did the work.`,
  );
  L.push(``);
  if (pack.approvals.length === 0) {
    L.push(`(no approvals recorded)`);
  } else {
    L.push(`| Seq | Time | Operator | Kind | Detail |`);
    L.push(`|---|---|---|---|---|`);
    for (const a of pack.approvals) {
      const tierMove = a.fromTier !== undefined || a.toTier !== undefined ? ` [${a.fromTier ?? "?"}→${a.toTier ?? "?"}]` : "";
      L.push(`| ${a.seq} | ${a.ts} | ${a.operator} | ${a.kind}${tierMove} | ${a.detail} |`);
    }
  }
  L.push(``);
  return L.join("\n");
}
