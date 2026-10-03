/**
 * Compliance evidence-pack artifacts (v0.19.0 refactor — extracted from reportPhase).
 *
 * Mechanical, runner-computed evidence for the client's auditors — never a
 * claim of compliance or certification. Writes compliance-pack.json/.md and
 * the attestation letter. Its own try/catch: a pack failure never breaks the report.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { METHODOLOGY_EXCLUSIONS, buildCompliancePack, renderAttestationLetter, renderCompliancePackMarkdown } from "../compliance/index.js";
import { buildSafetyManifest } from "../safety/index.js";
import { type Ctx } from "../context.js";
import { type Finding } from "../types.js";

export function writeComplianceArtifacts(
  ctx: Ctx,
  findings: Finding[],
  batteryLine: string,
  safetyManifest: ReturnType<typeof buildSafetyManifest> | undefined,
): void {
  try {
    const pack = buildCompliancePack({
      engagementId: ctx.events.engagementId,
      client: ctx.input.client,
      operator: ctx.input.operatorName ?? process.env["REDTEAM_OPERATOR"],
      target: ctx.input.target,
      mode: ctx.input.mode,
      objective: ctx.input.objective,
      scope: ctx.input.roe.scope,
      verificationProof: ctx.verificationProof,
      roe: ctx.input.roe,
      testStart: new Date(ctx.startedAt).toISOString(),
      testEnd: new Date().toISOString(),
      plan: ctx.plan,
      findings,
      batteryCoverageNote: batteryLine,
      registry: ctx.registry,
      safety: safetyManifest,
      // v0.17.0 accountability: the approval log and autonomy tier are part
      // of the evidence pack — auditors see who approved what, when.
      approvals: ctx.approvals.list(),
      autonomyTier: ctx.tier.current,
    });
    writeFileSync(join(ctx.events.dir, "compliance-pack.json"), JSON.stringify(pack, null, 2));
    writeFileSync(join(ctx.events.dir, "compliance-pack.md"), renderCompliancePackMarkdown(pack));
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      if (f.severity in counts) counts[f.severity as keyof typeof counts]++;
    }
    writeFileSync(
      join(ctx.events.dir, "attestation.md"),
      renderAttestationLetter({
        engagementId: ctx.events.engagementId,
        client: ctx.input.client,
        operator: ctx.input.operatorName ?? process.env["REDTEAM_OPERATOR"],
        // v0.17.0 accountability: the letter names the tier the operator approved.
        tier: ctx.tier.current,
        target: ctx.input.target,
        mode: ctx.input.mode,
        objective: ctx.input.objective,
        scope: ctx.input.roe.scope,
        testStart: new Date(ctx.startedAt).toISOString(),
        testEnd: new Date().toISOString(),
        findingCounts: counts,
        exclusions: METHODOLOGY_EXCLUSIONS,
      }),
    );
    ctx.events.append({
      phase: "report",
      actor: "runner",
      action: "compliance_pack",
      result: `Compliance evidence pack written (${pack.findings.length} findings, ${pack.coverage.controlsExercised}/${pack.coverage.controlsTotal} controls exercised).`,
    });
  } catch (err) {
    ctx.events.append({
      phase: "report",
      actor: "runner",
      action: "compliance_pack_failed",
      result: `Compliance pack generation failed (report.md unaffected): ${(err as Error).message}`,
    });
  }
}
