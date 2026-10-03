/**
 * Safety-manifest artifacts (v0.19.0 refactor — extracted from reportPhase).
 *
 * The machine-readable safety manifest — every protection that was
 * mechanically active, what it did, and the zero-disruption record derived
 * from the audit log. Written next to report.md.
 * Its own try/catch: a manifest failure must never break the report.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { readEvents } from "../events.js";
import { buildSafetyManifest, buildZeroDisruptionRecord, disruptionVerdict, renderSafetyManifestMarkdown } from "../safety/index.js";
import { type Ctx } from "../context.js";

export function writeSafetyArtifacts(ctx: Ctx): ReturnType<typeof buildSafetyManifest> | undefined {
  let safetyManifest: ReturnType<typeof buildSafetyManifest> | undefined;
  try {
    const events = readEvents(ctx.events.dir);
    const zeroDisruption = buildZeroDisruptionRecord(events);
    const ah = ctx.safety.autoHalt;
    safetyManifest = buildSafetyManifest({
      engagementId: ctx.events.engagementId,
      environment: ctx.safety.environment,
      productionConfirmed: ctx.safety.productionConfirmed,
      scopeAllowlist: ctx.hosts,
      rpsPerHost: ctx.safety.rpsPerHost,
      burst: ctx.safety.rpsPerHost,
      productionCapApplied: ctx.safety.productionCapApplied,
      throttledMs: Math.round(ctx.safety.limiter.throttledMs),
      acquires: ctx.safety.limiter.acquires,
      killSwitchAborts: ctx.safety.killSwitchAborts,
      operator: ctx.input.operatorName ?? process.env["REDTEAM_OPERATOR"] ?? "(operator name not supplied — set REDTEAM_OPERATOR)",
      autoHalt: {
        consecutiveThreshold: ah.config.consecutiveThreshold,
        windowSize: ah.config.windowSize,
        windowFailureRate: ah.config.windowFailureRate,
        haltedTargets: ah.haltedHosts(),
        haltCount: ah.halts,
      },
      zeroDisruption,
      disruptionVerdict: disruptionVerdict(zeroDisruption),
      // v0.17.0 accountability: the autonomy tier and its approval trail are
      // part of the safety manifest — buyers see the control boundary.
      autonomy: {
        tier: ctx.tier.current,
        declaredTier: ctx.tier.declared,
        approvals: ctx.approvals.list(),
      },
    });
    writeFileSync(join(ctx.events.dir, "safety-manifest.json"), JSON.stringify(safetyManifest, null, 2));
    writeFileSync(join(ctx.events.dir, "safety-manifest.md"), renderSafetyManifestMarkdown(safetyManifest));
    ctx.events.append({
      phase: "report",
      actor: "runner",
      action: "safety_manifest",
      result: `Safety manifest written (env=${safetyManifest.environment}, ${safetyManifest.rateLimit.rpsPerHost}rps/host, ${safetyManifest.disruptionVerdict.split(";")[0]}).`,
    });
  } catch (err) {
    ctx.events.append({
      phase: "report",
      actor: "runner",
      action: "safety_manifest_failed",
      result: `Safety manifest generation failed (report.md unaffected): ${(err as Error).message}`,
    });
  }
  return safetyManifest;
}
