/**
 * Metasploit bridge tool handler: msf_exec (v0.19.0 refactor — extracted from dispatch.ts).
 */
import { BATTERY_CATEGORIES, type BatteryCategory } from "../battery.js";
import { type TargetId, isTargetId } from "../targets.js";
import { scopeHosts, techniqueAllowed } from "../gate.js";
import { sleep } from "../util.js";
import { type Ctx } from "../context.js";
import { type ActorRole, type EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { type DispatchResult } from "./types.js";
import { numArg, optStr } from "./prelude.js";
import { MSF_OPERATOR_GRANT_ENV, msfRunOperatorGranted } from "../accountability/tiers.js";
import { OPERATOR_ENV, resolveOperatorName } from "../accountability/accountability.js";

// ---------------------------------------------------------------------------
// Human operator gate for msf_exec run. The recon→exploit coordinator
// sign-off is an LLM approval; firing live exploit modules additionally
// needs an explicit human grant, in either of two forms:
//   1. REDTEAM_OPERATOR_MSF_APPROVED=1 in the runner environment, or
//   2. an 'msf-run' entry in this engagement's approvals.jsonl (the log is
//      re-read on each dispatch, so an operator can grant mid-run the same
//      way tier.json carries mid-run tier changes).
// With neither, run is DENIED on every tier and in every environment; the
// grant decision (present or denied) is written to approvals.jsonl once
// per engagement so the record shows a person was — or was not — asked.
// ---------------------------------------------------------------------------

const msfDecisionRecorded = new WeakSet<object>();

function hasRecordedMsfGrant(ctx: Ctx): boolean {
  try {
    return (ctx.approvals?.list() ?? []).some((e) => e.kind === "msf-run");
  } catch {
    return false;
  }
}

function recordMsfDecision(ctx: Ctx, granted: boolean): void {
  if (msfDecisionRecorded.has(ctx)) return;
  msfDecisionRecorded.add(ctx);
  try {
    const operator = resolveOperatorName(ctx.input.operatorName) ?? `(operator name not supplied — set ${OPERATOR_ENV})`;
    ctx.approvals?.append(
      granted ? "msf-run" : "msf-run-denied",
      operator,
      granted
        ? `Operator grant for msf_exec run present (${MSF_OPERATOR_GRANT_ENV}=1), recorded at first run attempt — firing live modules is human-approved for this engagement.`
        : `msf_exec run attempted without an operator grant — DENIED. Grant with ${MSF_OPERATOR_GRANT_ENV}=1 in the runner environment or an 'msf-run' entry in approvals.jsonl.`,
    );
  } catch {
    /* the audit log must never crash dispatch */
  }
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

/**
 * Did this msf call actually execute? The executor reports pre-flight
 * refusals via `refused`, aborts via the summary, and transport failures
 * (msfrpcd down, auth down) as ok:false with a failure summary
 * ("msf search failed: …", "msfrpcd unreachable …"). A run whose module
 * fired but missed the canary marker is ok:false with a verdict summary
 * — that DID execute against the target and counts.
 */
function msfProbeExecuted(res: { ok: boolean; refused?: string; summary: string }): boolean {
  if (res.refused) return false;
  if (/kill switch/i.test(res.summary)) return false;
  if (!res.ok && /failed|unreachable/i.test(res.summary)) return false;
  return true;
}

export async function handleMsfTools(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest, args: Record<string, unknown>): Promise<DispatchResult | null> {
  if (call.name !== "msf_exec") return null;
if (call.name === "msf_exec") {
  const attackId = typeof args["attackId"] === "string" ? (args["attackId"] as string).toUpperCase() : undefined;
  const rawCat = typeof args["category"] === "string" ? (args["category"] as string).toLowerCase() : "";
  const category = (BATTERY_CATEGORIES as string[]).includes(rawCat) ? (rawCat as BatteryCategory) : undefined;
  if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
    return { result: `DENIED by ROE: technique ${attackId} is excluded for this engagement.`, attackId, target: String(args["host"] ?? "") };
  }
  const rawTp = typeof args["targetProfile"] === "string" ? (args["targetProfile"] as string).toLowerCase() : "";
  if (!isTargetId(rawTp) || (rawTp !== "windows" && rawTp !== "linux")) {
    return {
      result: `DENIED: msf_exec requires targetProfile "windows"|"linux" (host targets are never inferred) — got ${JSON.stringify(args["targetProfile"] ?? null)}.`,
      attackId,
      target: String(args["host"] ?? ""),
    };
  }
  const action = args["action"] === "run" ? "run" : args["action"] === "suggest" ? "suggest" : "search";
  if (action === "run" && phase !== "exploit") {
    return {
      result: `DENIED: msf_exec run fires exploits — allowed in the exploit phase only, after the recon→exploit coordinator sign-off (candidate modules from 'suggest' go to the coordinator for approval first). Current phase: ${phase}.`,
      attackId,
      target: String(args["host"] ?? ""),
    };
  }
  if (action === "run") {
    // Human gate: phase + coordinator sign-off are necessary, not
    // sufficient. An explicit operator grant must exist (env var, or an
    // 'msf-run' entry already in this engagement's approval log).
    const viaLog = hasRecordedMsfGrant(ctx);
    const granted = viaLog || msfRunOperatorGranted();
    if (!granted) {
      recordMsfDecision(ctx, false);
      return {
        result:
          `DENIED by operator gate: msf_exec run fires live exploits and requires an explicit human operator grant — ` +
          `the coordinator sign-off is an LLM approval, not a human one. Missing grant: set ${MSF_OPERATOR_GRANT_ENV}=1 ` +
          `in the runner environment (the named operator's decision), or record an 'msf-run' approval entry in this ` +
          `engagement's approvals.jsonl, then re-run. The denial is recorded in approvals.jsonl. msf_exec search/suggest need no grant.`,
        attackId,
        target: String(args["host"] ?? ""),
      };
    }
    // A grant supplied via the approval log is already recorded by the
    // operator; an env-var grant is recorded here, once per engagement.
    if (!viaLog) recordMsfDecision(ctx, true);
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
    const exec = ctx.msfExecutor;
    exec.killSwitch = ctx.hostKill;
    const t = { host, scopeHosts: ctx.hosts, signal: ctrl.signal };
    const platform = args["platform"] === "linux" ? "linux" : args["platform"] === "windows" ? "windows" : rawTp === "linux" ? "linux" : "windows";
    const res =
      action === "search"
        ? await exec.search({ ...t, query: optStr(args["query"]), cve: optStr(args["cve"]), service: optStr(args["service"]), platform })
        : action === "suggest"
          ? await exec.suggest({
              ...t,
              service: optStr(args["service"]),
              version: optStr(args["version"]),
              cve: optStr(args["cve"]),
              platform,
            })
          : await exec.run({
              ...t,
              moduleType: args["moduleType"] === "auxiliary" ? "auxiliary" : "exploit",
              module: String(args["module"] ?? ""),
              options:
                args["options"] && typeof args["options"] === "object"
                  ? Object.fromEntries(
                      Object.entries(args["options"] as Record<string, unknown>)
                        .filter(([, v]) => typeof v === "string")
                        .map(([k, v]) => [k, v as string]),
                    )
                  : undefined,
              payload: optStr(args["payload"]),
              // Runner-generated canary — the agent never chooses the marker.
              marker: `${Date.now().toString(36)}${Math.floor(Math.random() * 0xffffff).toString(16)}`,
            });
    if (/kill switch/i.test(res.summary)) {
      return { result: `ABORTED by coordinator kill switch — engagement halting. ${res.summary}`, attackId, target: host };
    }
    if (res.refused) {
      return { result: `DENIED by msf safety policy: ${res.refused}`, attackId, target: host };
    }
    // Coverage counts EXECUTED probes only (audit 2026-10-09 H2):
    // operator-gate/phase/ROE denials returned above, policy refusals
    // just returned, kill-switch aborts just returned, and transport
    // failures (msfrpcd unreachable) mark nothing.
    if (category && msfProbeExecuted(res)) {
      markCoverage(ctx, category, rawTp as TargetId);
    }
    const cveTag = /^CVE-\d{4}-\d{4,7}$/i.test(String(args["cve"] ?? "")) ? ` [${String(args["cve"]).toUpperCase()}]` : "";
    const out = res.output ? ` Output: ${res.output.slice(0, 600)}` : "";
    return { result: `${res.summary}.${cveTag}${out}`, attackId, target: host };
  } finally {
    ctx.hostKill.controllers.delete(ctrl);
  }
}

// MCP tools.
const readOnly = new Set(["get_scan_status", "get_report", "list_recent_scans", "get_account"]);
  return null;
}
