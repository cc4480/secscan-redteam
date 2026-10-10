/**
 * Report phase orchestrator (v0.19.0 refactor — extracted from report.ts).
 *
 * reportPhase drives the reporter agent, reconciles battery coverage
 * (cells + per-item ledger), and assembles report.md from runner-computed
 * sections (proof bundles, item reconciliation, integrations). Artifact
 * writers live in ./safety.ts, ./compliance.ts, ./proof.ts, ./integrations.ts.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { reporterPrompt } from "../prompts.js";
import { type Finding } from "../types.js";
import { BATTERY_CATEGORIES } from "../battery.js";
import { TARGET_PROFILES, activeTargets, targetCellStatus } from "../targets.js";
import { ledgerSummary, serializeLedger } from "../coverage/items.js";
import { type Ctx, type LiveFinding } from "../context.js";
import { agentLoop, promptCtx } from "../agents.js";
import { extractJsonBlock } from "../util.js";
import { coerceSeverity } from "../severity.js";
import { READ_TOOLS } from "../tools.js";
import { batteryStatusLine } from "../coverage/cells.js";
import { PocBundle } from "../proof/index.js";
import { resolveOperatorName } from "../accountability/index.js";
import { countVariants, variantCountLine, variantProgressSuffix } from "../variants/index.js";
import { nucleiCountLine } from "../nuclei/index.js";
import { buildProofSection } from "./proof.js";
import { buildIntegrationsSection } from "./integrations.js";
import { writeSafetyArtifacts } from "./safety.js";
import { writeComplianceArtifacts } from "./compliance.js";
import { extractNarrative } from "./narrative.js";

// ---------------------------------------------------------------------------
// Verdict integrity (audit correctness H1): the engagement's findings are
// derived from the verdicts recorded mechanically during the run —
// ctx.liveFindings, written by record_finding / the VERDICTS-block merge —
// never from the reporter LLM's closing JSON. That JSON is untrusted
// formatting: it may only enrich a recorded verdict with remediation text
// (fix/retest). It can never add a finding no verdict supports, drop one a
// verdict recorded, or rewrite a verdict's severity/title/evidence — where
// the two disagree, the recorded verdict wins. A reporter that omits or
// mangles its JSON block therefore changes nothing about the findings of
// record, and downstream consumers (state.json, drift watching) never see
// a confirmed finding vanish because a model slipped.
// ---------------------------------------------------------------------------



/**
 * Find the reporter entry that speaks for a recorded verdict: exact title
 * first (the reporter echoes the verdict list it was shown), else the
 * F-<n> id slot when its attackIds still name the verdict's technique.
 * Matching only ever borrows fix/retest — never verdict facts.
 */
function reporterEntryFor(lf: LiveFinding, index: number, reporter: Finding[]): number {
  const byTitle = reporter.findIndex((r) => typeof r.title === "string" && r.title === lf.title);
  if (byTitle >= 0) return byTitle;
  return reporter.findIndex(
    (r) => r.id === `F-${index + 1}` && Array.isArray(r.attackIds) && r.attackIds.includes(lf.attackId),
  );
}

interface ReconciledFindings {
  findings: Finding[];
  /** Reporter-JSON entries matching no recorded verdict — dropped. */
  reporterOnly: number;
  /** Recorded verdicts the reporter's JSON never mentioned. */
  reporterOmitted: number;
}

function findingsFromRecordedVerdicts(recorded: LiveFinding[], reporterRaw: unknown): ReconciledFindings {
  const reporter: Finding[] = Array.isArray(reporterRaw)
    ? (reporterRaw as unknown[]).filter(
        (f): f is Finding => typeof f === "object" && f !== null && !Array.isArray(f),
      )
    : [];
  const used = new Set<number>();
  let covered = 0;
  const findings = recorded.map((lf, i) => {
    const matchIdx = reporterEntryFor(lf, i, reporter);
    const match = matchIdx >= 0 ? reporter[matchIdx] : undefined;
    if (match) {
      used.add(matchIdx);
      covered++;
    }
    const fix =
      typeof match?.fix === "string" && match.fix.trim() ? match.fix : "(pending — the reporter writes the fix)";
    const retest = typeof match?.retest === "string" && match.retest.trim() ? match.retest : "(pending)";
    return {
      id: `F-${i + 1}`,
      severity: coerceSeverity(lf.severity),
      title: lf.title,
      attackIds: [lf.attackId],
      evidence: lf.evidence,
      fix,
      retest,
      status: "confirmed" as const,
    };
  });
  return {
    findings,
    reporterOnly: reporter.length - used.size,
    reporterOmitted: recorded.length - covered,
  };
}

export async function reportPhase(ctx: Ctx, reconBrief: string, exploitSummary: string): Promise<Finding[]> {
  const selected = ctx.input.fullBattery ? activeTargets(ctx.input) : [];
  const fbCells = selected.flatMap((t) => BATTERY_CATEGORIES.map((c) => ({ t, c })));
  const fbStatus = fbCells.map(({ t, c }) => ({ t, c, s: targetCellStatus(TARGET_PROFILES[t], c, ctx.targetCoverage.get(t)) }));
  const fbDone = fbStatus.filter((x) => x.s === "done");
  const fbBlocked = fbStatus.filter((x) => x.s === "blocked");
  const fbMissing = fbStatus.filter((x) => x.s === "missing");
  // Individual battery items carrying a `needs` prerequisite (v0.10.0: the
  // only ones left are WS-064 [kerberos ticket material], WS-065 [human
  // operator], LX-041 [privileged test client]). They execute when the
  // prerequisite is met; the report names the prerequisite so the operator
  // knows exactly what to supply. Nothing is plan-only anymore.
  const fbPlanOnly = selected.flatMap((t) =>
    TARGET_PROFILES[t].battery.filter((b) => !!b.needs).map((b) => `${t}:${b.id} [needs: ${b.needs}]`),
  );
  // v0.18.0 per-item verdicts: the battery may not report complete while any
  // selected item lacks a defensible disposition. Blocked/na items never
  // force extra rounds — they are reported honestly, exactly like cells.
  const lsum = ledgerSummary(ctx.itemLedger);
  const pendingKeys = [...ctx.itemLedger.values()]
    .filter((v) => v.disposition === "pending")
    .map((v) => v.key);
  const nonCleanItems = [...ctx.itemLedger.values()].filter(
    (v) => v.disposition !== "executed-clean" && v.disposition !== "pending",
  );
  try {
    writeFileSync(
      join(ctx.events.dir, "item-verdicts.json"),
      JSON.stringify(serializeLedger(ctx.itemLedger), null, 2),
    );
  } catch {
    /* the ledger lives in memory too — a write failure must never break the report */
  }
  ctx.events.append({
    phase: "report",
    actor: "runner",
    action: pendingKeys.length > 0 ? "battery_incomplete_items" : "battery_complete_items",
    result:
      `Item reconciliation: ${lsum.total} items — ${lsum.confirmed} confirmed, ${lsum.executedClean} executed-clean, ` +
      `${lsum.killed} killed, ${lsum.blocked} blocked, ${lsum.na} na, ${lsum.pending} pending.` +
      (pendingKeys.length > 0 ? ` NOT COMPLETE: ${pendingKeys.length} items still pending a verdict.` : ""),
  });
  const covered = BATTERY_CATEGORIES.filter((c) => ctx.coverage.has(c));
  const batteryLine = ctx.input.fullBattery
    ? `Battery coverage (FULL BATTERY — 3 categories × ${selected.length} targets): ${fbDone.length}/${fbCells.length} cells probed ` +
      `(${batteryStatusLine(ctx)}, ${ctx.probesUsed} probes total). ` +
      (fbBlocked.length > 0
        ? `BLOCKED (prerequisite not met — planned, not probed; see Honest limits): ${fbBlocked.map(({ t, c }) => `${t}:${c}`).join(", ")}. `
        : "") +
      (fbPlanOnly.length > 0
        ? `Items with prerequisites (execute when met — see Honest limits): ${fbPlanOnly.join(", ")}. `
        : "") +
      (fbMissing.length > 0 || pendingKeys.length > 0
        ? `NOT COVERED: ${[
            ...fbMissing.map(({ t, c }) => `${t}:${c}`),
            ...(pendingKeys.length > 0
              ? [
                  `${pendingKeys.length} battery items pending a verdict ` +
                    `(${pendingKeys.slice(0, 25).join(", ")}${pendingKeys.length > 25 ? "…" : ""})`,
                ]
              : []),
          ].join("; ")} — list these under Honest limits.`
        : `Full battery complete: all ${fbCells.length} cells probed or honestly blocked; all ${lsum.total} battery items carry a verdict.`)
    : `Battery coverage: ${covered.length}/3 categories probed ` +
      `(${covered.map((c) => `${c}:${ctx.coverage.has(c) ? "yes" : "no"}`).join(", ")}, ${ctx.probesUsed} probes total). ` +
      (covered.length < 3 ? `NOT COVERED: ${BATTERY_CATEGORIES.filter((c) => !ctx.coverage.has(c)).join(", ")} — list these under Honest limits.` : "Full battery complete.");
  let reportMd: string;
  if (ctx.config.dryRunAgents) {
    reportMd = `# Engagement report (dry-run)\n\nTarget: ${ctx.input.target}\nMode: ${ctx.input.mode}\n`;
  } else {
    reportMd = await agentLoop(
      ctx,
      "reporter",
      "report",
      reporterPrompt(promptCtx(ctx)),
      `Write the client report now.\n\nAuthorization: ${ctx.verificationProof}\n\nOperation plan: ${JSON.stringify(ctx.plan)}\n\nShared verdicts this engagement — confirmed (${ctx.liveFindings.length}):\n${ctx.liveFindings.map((f) => `- [${f.severity}] ${f.title} (${f.attackId}${f.vulnClass ? `, ${f.vulnClass}` : ""}): ${f.evidence}`).join("\n") || "(none)"}\nKilled hypotheses (${ctx.killedLive.length}):\n${ctx.killedLive.map((k) => `- ${k.hypothesis} → ${k.killingObservation}`).join("\n") || "(none)"}\nRegistry hits consulted: ${ctx.registryHits.length}. Target fingerprint: ${JSON.stringify(ctx.fingerprint)}.\n\n${batteryLine}\n\nRecon brief:\n${reconBrief.slice(0, 4000)}\n\nExploitation summary:\n${exploitSummary.slice(0, 4000)}\n\nProof of exploitation is appended mechanically by the runner from the audit log — do not invent PoC details, marker values, or reproduction steps in your narrative; describe findings only from the evidence given.\n\nEnd the report with a JSON block: \`\`\`json {"findings": [{"id":"F-1","severity":"low","title":"...","attackIds":["T1190"],"evidence":"...","fix":"...","retest":"...","status":"confirmed"}]} \`\`\``,
      READ_TOOLS,
      4,
    );
  }
  const parsed = extractJsonBlock(reportMd) as { findings?: unknown } | null;
  // Findings of record come from the recorded verdicts (see the verdict-
  // integrity note above); the reporter's JSON only lends fix/retest text.
  const { findings, reporterOnly, reporterOmitted } = findingsFromRecordedVerdicts(
    ctx.liveFindings,
    parsed?.findings,
  );
  if (reporterOnly > 0 || reporterOmitted > 0) {
    ctx.events.append({
      phase: "report",
      actor: "runner",
      action: "findings_reconciled",
      result:
        `Reporter JSON disagreed with the recorded verdicts and was overridden: ` +
        `${findings.length} recorded finding(s) stand` +
        (reporterOnly > 0 ? `; ${reporterOnly} reporter-only entr${reporterOnly === 1 ? "y" : "ies"} dropped (no recorded verdict)` : "") +
        (reporterOmitted > 0 ? `; ${reporterOmitted} recorded verdict(s) the reporter omitted restored` : "") +
        `.`,
    });
  }
  // v0.17.0 accountability: every finding records the named human
  // accountable for it. Stamped mechanically by the runner at report time —
  // the reporter agent cannot set or change it.
  {
    const accountable = resolveOperatorName(ctx.input.operatorName, process.env) ?? "(operator name not supplied — set REDTEAM_OPERATOR)";
    for (const f of findings) f.accountableOperator = accountable;
  }
  // The unified operation narrative ("Megazord"): the reporter writes it first
  // as plain paragraphs; the runner extracts it for the console header.
  const narrative = extractNarrative(reportMd);
  if (narrative) {
    ctx.operationNarrative = narrative;
    ctx.events.updateState({ operationNarrative: narrative });
  }
  // Runner-computed facts are appended deterministically — never trusted to the model.
  reportMd += `\n\n---\n\n## Battery coverage (runner-computed)\n\n${batteryLine}\n`;
  // v0.21.0 nuclei: honest counting — template executions are variant-level
  // checks, printed whenever nuclei ran (not only full-battery), reported
  // separately from intents, never merged.
  const ncAny = nucleiCountLine(ctx.nuclei);
  if (ncAny) reportMd += `\n${ncAny}\n`;
  const pocBundleMap = new Map<string, PocBundle>();
  reportMd += buildProofSection(ctx, findings, pocBundleMap);
  // v0.18.0 per-item verdicts: the item reconciliation section — every
  // battery item's disposition, derived from the ledger (audit log +
  // verdict tools), never hand-waved. Full ledger: item-verdicts.json.
  if (ctx.input.fullBattery && ctx.itemLedger.size > 0) {
    reportMd += `\n---\n\n## Item reconciliation (runner-computed)\n\n`;
    reportMd +=
      `Every battery item carries exactly one verdict this engagement. ` +
      `The battery counts complete only when no item is pending.\n\n`;
    reportMd +=
      `**${lsum.total} items:** ${lsum.confirmed} confirmed · ${lsum.executedClean} executed-clean · ` +
      `${lsum.killed} killed · ${lsum.blocked} blocked · ${lsum.na} not-applicable · ${lsum.pending} pending.\n\n`;
    // v0.20.0 variants: honest counting — intents vs executions, two
    // numbers, never merged into one inflated figure.
    const vc = countVariants(ctx.itemLedger);
    if (vc.itemsWithVariants > 0) {
      reportMd += `${variantCountLine(vc)}\n\n`;
    }
    if (nonCleanItems.length > 0) {
      reportMd += `Non-clean items (with reason):\n\n`;
      for (const v of nonCleanItems) {
        reportMd += `- **${v.key}** [${v.disposition}]${variantProgressSuffix(v)} ${v.name}${v.reason ? ` — ${v.reason}` : ""}\n`;
      }
      reportMd += `\n`;
    }
    if (pendingKeys.length > 0) {
      reportMd +=
        `**Battery NOT complete:** ${pendingKeys.length} items still pending a verdict ` +
        `(${pendingKeys.slice(0, 50).join(", ")}${pendingKeys.length > 50 ? "…" : ""}). ` +
        `See Honest limits.\n`;
    }
  }
  reportMd += await buildIntegrationsSection(ctx, findings, pocBundleMap);
  writeFileSync(join(ctx.events.dir, "report.md"), reportMd);
  ctx.events.append({ phase: "report", actor: "reporter", action: "report_written", result: `Report written (${findings.length} findings from recorded verdicts).` });
  const safetyManifest = writeSafetyArtifacts(ctx);
  writeComplianceArtifacts(ctx, findings, batteryLine, safetyManifest);
  ctx.events.updateState({ findings });
  return findings;
}
