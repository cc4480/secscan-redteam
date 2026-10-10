/**
 * Nuclei bridge tool handler: nuclei_exec (v0.21.0).
 *
 * Mirrors the msf_exec dispatcher shape: ROE technique check, explicit
 * targetProfile pinning (windows|linux, never inferred), exploit-phase
 * gating for `run`, kill-switch controller registration, DENIED/ABORTED
 * mapping, coverage counting, per-item attempt recording.
 */
import { BATTERY_CATEGORIES, type BatteryCategory } from "../battery.js";
import { type TargetId, isTargetId } from "../targets.js";
import { techniqueAllowed } from "../gate.js";
import { sleep } from "../util.js";
import { type Ctx } from "../context.js";
import { type ActorRole, type EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { type DispatchResult } from "./types.js";
import { mapTemplateToBattery, overlapHint } from "../nuclei/index.js";

function strArg(args: Record<string, unknown>, key: string): string | undefined {
  const v = args[key];
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

function strListArg(args: Record<string, unknown>, key: string): string[] | undefined {
  const v = args[key];
  if (!Array.isArray(v)) return undefined;
  const out = v.filter((x): x is string => typeof x === "string" && x.trim().length > 0).map((x) => x.trim());
  return out.length ? out : undefined;
}

/**
 * Record battery coverage for a probe that actually EXECUTED (audit
 * 2026-10-09 H2). Coverage used to be marked at dispatch, so refused,
 * denied, and failed probes counted as covered. Callers invoke this
 * only once an execution produced an outcome; denials and transport
 * failures never reach it. ctx.probesUsed stays the attempt counter —
 * coverage is outcome-only.
 */
function markCoverage(ctx: Ctx, category: BatteryCategory, tp: TargetId): void {
  ctx.coverage.add(category);
  if (ctx.input.fullBattery) {
    let set = ctx.targetCoverage.get(tp);
    if (!set) {
      set = new Set();
      ctx.targetCoverage.set(tp, set);
    }
    set.add(category);
  }
  ctx.events.updateState({
    batteryCoverage: {
      logic: ctx.coverage.has("logic") ? 1 : 0,
      functionality: ctx.coverage.has("functionality") ? 1 : 0,
      validation: ctx.coverage.has("validation") ? 1 : 0,
    },
  });
}

export async function handleNucleiTools(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest, args: Record<string, unknown>): Promise<DispatchResult | null> {
  if (call.name !== "nuclei_exec") return null;
  const attackId = strArg(args, "attackId")?.toUpperCase();
  const rawCat = (strArg(args, "category") ?? "").toLowerCase();
  const category = (BATTERY_CATEGORIES as string[]).includes(rawCat) ? (rawCat as BatteryCategory) : undefined;
  if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
    return { result: `DENIED by ROE: technique ${attackId} is excluded for this engagement.`, attackId, target: String(args["host"] ?? "") };
  }
  const rawTp = (strArg(args, "targetProfile") ?? "").toLowerCase();
  if (!isTargetId(rawTp) || (rawTp !== "windows" && rawTp !== "linux")) {
    return {
      result: `DENIED: nuclei_exec requires targetProfile "windows"|"linux" (host targets are never inferred) — got ${JSON.stringify(args["targetProfile"] ?? null)}.`,
      attackId,
      target: String(args["host"] ?? ""),
    };
  }
  const action = args["action"] === "run" ? "run" : "templates";
  if (action === "run" && phase !== "exploit") {
    return {
      result: `DENIED: nuclei_exec run executes templates against a target — allowed in the exploit phase only, after the recon→exploit coordinator sign-off. Current phase: ${phase}.`,
      attackId,
      target: String(args["host"] ?? ""),
    };
  }
  const host = String(args["host"] ?? "");
  // Counts attempts only — coverage is marked after the executor
  // returns, and only when the call actually executed (audit
  // 2026-10-09 H2).
  ctx.probesUsed++;
  const ctrl = new AbortController();
  ctx.hostKill.controllers.add(ctrl);
  try {
    if (ctx.input.mode === "black") await sleep(Math.random() * 2500); // jitter
    const exec = ctx.nucleiExecutor;
    exec.killSwitch = ctx.hostKill;
    const filter = {
      ids: strListArg(args, "ids"),
      tags: strListArg(args, "tags"),
      severities: strListArg(args, "severities"),
      cve: strArg(args, "cve"),
    };
    if (action === "templates") {
      const res = await exec.templates({ filter });
      if (res.refused) return { result: `DENIED by nuclei safety policy: ${res.refused}`, attackId, target: host };
      // The listing executed — coverage counts it (audit 2026-10-09 H2).
      if (category) markCoverage(ctx, category, rawTp as TargetId);
      return { result: `${res.summary}\n${res.output}`, attackId, target: host };
    }
    const res = await exec.run({
      host,
      scopeHosts: ctx.hosts,
      scheme: args["scheme"] === "http" ? "http" : "https",
      filter,
      severity: strListArg(args, "severities"),
      rateLimit: ctx.safety.rpsPerHost,
      signal: ctrl.signal,
    });
    if (res.refused) return { result: `DENIED by nuclei safety policy: ${res.refused}`, attackId, target: host };
    // Coverage counts EXECUTED probes only (audit 2026-10-09 H2):
    // policy refusals returned just above (scope, tags, kill switch,
    // missing binary) mark nothing; a run that reached the target —
    // including one that later timed out with partial output — counts.
    if (category) markCoverage(ctx, category, rawTp as TargetId);
    if (res.timedOut) {
      return { result: `ABORTED: nuclei run timed out at the runner timeout — target ${host}. Partial results below.\n${res.output}`, attackId, target: host };
    }
    // Honest counting: template executions are variant-level checks, tracked
    // separately from the 418 intents (see nuclei/reporting.ts).
    ctx.nuclei.templateExecutions++;
    ctx.nuclei.templatesRun += res.templatesExecuted && res.templatesExecuted > 0 ? res.templatesExecuted : 0;
    ctx.nuclei.findings += res.findings.length;
    const tp = rawTp as "windows" | "linux";
    const hints = res.findings.slice(0, 10).map((f) => {
      const o = mapTemplateToBattery(f, tp);
      return `${f.templateId}: ${overlapHint(o)}`;
    });
    const hintBlock = hints.length ? `\nDedupe guidance:\n${hints.join("\n")}` : "";
    return { result: `${res.summary}\n${res.output}${hintBlock}`, attackId, target: host };
  } finally {
    ctx.hostKill.controllers.delete(ctrl);
  }
}
