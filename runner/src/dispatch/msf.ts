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
  const host = String(args["host"] ?? "");
  ctx.probesUsed++;
  if (category) {
    ctx.coverage.add(category);
    if (ctx.input.fullBattery) {
      let set = ctx.targetCoverage.get(rawTp as TargetId);
      if (!set) {
        set = new Set();
        ctx.targetCoverage.set(rawTp as TargetId, set);
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
