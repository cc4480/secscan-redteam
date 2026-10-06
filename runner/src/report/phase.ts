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
import { type Ctx } from "../context.js";
import { agentLoop, promptCtx } from "../agents.js";
import { extractJsonBlock } from "../util.js";
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

export async function reportPhase(
  ctx: Ctx,
  reconBrief: string,
  exploitSummary: string,
  opts: { haltedReason?: string } = {},
): Promise<Finding[]> {
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
  let findings: Finding[];
  if (opts.haltedReason) {
    // Halt path (action/duration cap, 5xx auto-halt, kill switch, aborted
    // sign-off, unexpected error): NEVER run the reporter LLM here — it could
    // re-hit the same cap and we would lose the accountability record exactly
    // when it matters most. Build the report mechanically from the audit-log
    // state so the safety manifest, proof bundles, and item verdicts still
    // ship. Findings are the live-confirmed set recorded during the run.
    reportMd =
      `# Engagement report (HALTED)\n\n` +
      `Target: ${ctx.input.target}\nMode: ${ctx.input.mode}\n` +
      `Status: HALTED — ${opts.haltedReason}\n` +
      `Authorization: ${ctx.verificationProof}\n\n` +
      `This engagement halted before the reporter phase. The findings, coverage, ` +
      `proof bundles, and safety manifest below are the runner-computed record of ` +
      `work completed up to the halt — no reporter-agent narrative was generated.\n`;
    findings = ctx.liveFindings.map((lf, i) => ({
      id: `F-${i + 1}`,
      severity: (["critical", "high", "medium", "low", "info"].includes(lf.severity)
        ? lf.severity
        : "info") as Finding["severity"],
      title: lf.title,
      attackIds: lf.attackId ? [lf.attackId] : [],
      evidence: lf.evidence,
      fix: "(engagement halted before remediation guidance was written)",
      retest: "(engagement halted before a retest plan was written)",
      status: "confirmed",
    }));
  } else if (ctx.config.dryRunAgents) {
    reportMd = `# Engagement report (dry-run)\n\nTarget: ${ctx.input.target}\nMode: ${ctx.input.mode}\n`;
    findings = [];
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
    const parsed = extractJsonBlock(reportMd) as { findings?: Finding[] } | null;
    findings = Array.isArray(parsed?.findings) ? parsed.findings : [];
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
  ctx.events.append({ phase: "report", actor: "reporter", action: "report_written", result: `Report written (${findings.length} findings parsed).` });
  const safetyManifest = writeSafetyArtifacts(ctx);
  writeComplianceArtifacts(ctx, findings, batteryLine, safetyManifest);
  ctx.events.updateState({ findings });
  return findings;
}
