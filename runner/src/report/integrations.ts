/**
 * Buyer-integrations section (v0.19.0 refactor — extracted from reportPhase).
 *
 * Confirmed findings sync to configured ticketing sinks (Jira/ServiceNow),
 * SIEM-ready JSONL export, and Slack completion + critical-finding
 * notifications. Returns the markdown section to append.
 * Its own try/catch: integrations must never break the report.
 */
import { type Ctx } from "../context.js";
import { type Finding } from "../types.js";
import { PocBundle } from "../proof/index.js";
import { buildSiemEvents, syncFindingsToTickets, writeSiemEvents } from "../integrations/index.js";
import { fireSlack } from "./notify.js";

export async function buildIntegrationsSection(
  ctx: Ctx,
  findings: Finding[],
  pocBundleMap: Map<string, PocBundle>,
): Promise<string> {
  let section = "";
  // v0.15.0 buyer integrations: confirmed findings sync to configured
  // ticketing sinks (Jira/ServiceNow), SIEM-ready JSONL export, and Slack
  // completion + critical-finding notifications. Its own try/catch:
  // integrations must never break the report.
  try {
    const { attempts } = await syncFindingsToTickets(
      {
        engagementId: ctx.events.engagementId,
        target: ctx.input.target,
        findings,
        bundles: pocBundleMap,
      },
      ctx.events.dir,
    );
    const severityCounts: Record<string, number> = {};
    for (const f of findings) {
      if (f.status === "confirmed") severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
    }
    const siemEvents = buildSiemEvents({
      engagementId: ctx.events.engagementId,
      target: ctx.input.target,
      operator: ctx.input.operatorName ?? process.env["REDTEAM_OPERATOR"] ?? "(operator name not supplied)",
      findings,
      bundles: pocBundleMap,
      safetySummary: `engagement ${ctx.events.engagementId}: ${findings.length} findings parsed; zero-disruption record in safety-manifest.json`,
      severityCounts,
    });
    writeSiemEvents(ctx.events.dir, siemEvents);
    const ok = attempts.filter((a) => a.status === "ok").length;
    const skipped = attempts.filter((a) => a.status === "skipped").length;
    const failed = attempts.filter((a) => a.status === "failed").length;
    ctx.events.append({
      phase: "report",
      actor: "reporter",
      action: "integrations",
      result: `Ticket sync + SIEM export: ${ok} ok, ${skipped} skipped, ${failed} failed. ${siemEvents.length} SIEM events written.`,
    });
    section += `\n\n---\n\n## Integrations (runner-computed)\n\n`;
    section += `Ticket sync: ${attempts.map((a) => `${a.sink}=${a.status}`).join(", ") || "(no ticketing sinks attempted)"}\n\n`;
    for (const a of attempts) {
      if (a.status !== "ok") section += `- ${a.sink}: ${a.status} — ${a.detail}\n`;
    }
    section += `\nSIEM export: ${siemEvents.length} events → \`siem-events.jsonl\` (schema v1, see docs/integrations.md).\n`;
    section += `Ticket linkage: \`integrations.json\` (findingId → ticket refs; used by \`reverify\` for the retest loop).\n`;
    // Slack: completion summary + one alert per critical finding (best-effort).
    await fireSlack(ctx, { kind: "completed", severityCounts });
    for (const f of findings) {
      if (f.status === "confirmed" && f.severity === "critical") {
        await fireSlack(ctx, { kind: "critical_finding", findingId: f.id, findingTitle: f.title });
      }
    }
  } catch (err) {
    ctx.events.append({
      phase: "report",
      actor: "reporter",
      action: "integrations_failed",
      result: `Integrations failed (report.md unaffected): ${(err as Error).message}`,
    });
    section += `\n\n---\n\n## Integrations (runner-computed)\n\nIntegrations failed: ${(err as Error).message}\n`;
  }
  return section;
}
