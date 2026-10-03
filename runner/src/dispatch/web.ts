/**
 * Web prober tool handlers: http_probe, burst_probe (v0.19.0 refactor — extracted from dispatch.ts).
 */
import { BATTERY_CATEGORIES, type BatteryCategory } from "../battery.js";
import { type TargetId, inferTargetProfile, isTargetId } from "../targets.js";
import { sleep } from "../util.js";
import { techniqueAllowed } from "../gate.js";
import { recheckVerified } from "./prelude.js";
import { type Ctx } from "../context.js";
import { type ActorRole, type EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { type DispatchResult } from "./types.js";

export async function handleWebTools(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest, args: Record<string, unknown>): Promise<DispatchResult | null> {
  if (call.name !== "http_probe" && call.name !== "burst_probe") return null;
if (call.name === "http_probe") {
  const attackId = typeof args["attackId"] === "string" ? (args["attackId"] as string).toUpperCase() : undefined;
  const rawCat = typeof args["category"] === "string" ? (args["category"] as string).toLowerCase() : "";
  const category = (BATTERY_CATEGORIES as string[]).includes(rawCat) ? (rawCat as BatteryCategory) : undefined;
  if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
    return { result: `DENIED by ROE: technique ${attackId} is excluded for this engagement.`, attackId, target: String(args["url"] ?? "") };
  }
  const url = String(args["url"] ?? "");
  const method = String(args["method"] ?? "GET").toUpperCase();
  let path = "";
  try {
    path = new URL(url).pathname;
  } catch {
    return { result: `DENIED: unparseable URL ${url}`, attackId, target: url };
  }
  const cooldownKey = `${method} ${path}`;
  if (ctx.opsecCooldown.has(cooldownKey)) {
    return {
      result: `DENIED by OPSEC cooldown: ${cooldownKey} was abandoned after a detection signal. Pivot to a quieter vector.`,
      attackId,
      target: url,
      opsec: "cooldown",
    };
  }
  // The probe is really going out: count it toward the battery.
  ctx.probesUsed++;
  if (category) {
    ctx.coverage.add(category);
    if (ctx.input.fullBattery) {
      // Per-target cell: explicit tag wins, otherwise infer from the URL
      // path (/api/mcp → seclayer, everything else → secscan). Host targets
      // (windows/linux) are never inferred — they need an explicit tag.
      const rawTp = typeof args["targetProfile"] === "string" ? (args["targetProfile"] as string).toLowerCase() : "";
      const tp: TargetId = isTargetId(rawTp) ? rawTp : inferTargetProfile(url);
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
  try {
    if (ctx.input.mode === "black") await sleep(Math.random() * 2500); // jitter
    const res = await ctx.prober.probe({
      method,
      url,
      headers: (args["headers"] as Record<string, string>) ?? {},
      body: typeof args["body"] === "string" ? (args["body"] as string) : undefined,
    });
    if (res.status >= 500) {
      ctx.consecutive5xx++;
    } else {
      ctx.consecutive5xx = 0;
    }
    if (res.opsecSignal) {
      ctx.opsecCooldown.add(cooldownKey);
      return {
        result: `HTTP ${res.status} in ${res.ms}ms — OPSEC SIGNAL: ${res.opsecSignal}. Vector abandoned; pivot quieter. Snippet: ${res.bodySnippet.slice(0, 400)}`,
        attackId,
        target: url,
        opsec: res.opsecSignal,
      };
    }
    return {
      result: `HTTP ${res.status} in ${res.ms}ms. Snippet: ${res.bodySnippet.slice(0, 600)}`,
      attackId,
      target: url,
    };
  } catch (err) {
    return { result: `probe failed: ${(err as Error).message}`, attackId, target: url };
  }
}

if (call.name === "burst_probe") {
  const attackId = typeof args["attackId"] === "string" ? (args["attackId"] as string).toUpperCase() : undefined;
  if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
    return { result: `DENIED by ROE: technique ${attackId} is excluded for this engagement.`, attackId, target: String(args["url"] ?? "") };
  }
  const url = String(args["url"] ?? "");
  let path = "";
  try {
    path = new URL(url).pathname;
  } catch {
    return { result: `DENIED: unparseable URL ${url}`, attackId, target: url };
  }
  const burstKey = `BURST ${path}`;
  if (ctx.opsecCooldown.has(burstKey)) {
    return {
      result: `DENIED: burst_probe already ran against ${path} this engagement — one-shot per endpoint, not a repeatable flood primitive.`,
      attackId,
      target: url,
    };
  }
  ctx.opsecCooldown.add(burstKey); // one-shot regardless of outcome, including failure
  ctx.probesUsed++;
  if (!ctx.prober.probeBurst) {
    return { result: `burst_probe unavailable: this harness's prober does not implement it.`, attackId, target: url };
  }
  try {
    const res = await ctx.prober.probeBurst({ method: String(args["method"] ?? "GET"), url });
    return {
      result: `Burst probe (${res.count} concurrent requests, fixed size): ${res.note} Latency range ${res.minMs}-${res.maxMs}ms.`,
      attackId,
      target: url,
    };
  } catch (err) {
    return { result: `burst probe failed/refused: ${(err as Error).message}`, attackId, target: url };
  }
}

// -- Host execution tools (v0.9.0): ssh/smb/winrm via the safety core ----
// Host targets are NEVER inferred — targetProfile is required and must be
// windows|linux. Every refusal (scope, denylist, kill switch, credentials)
// is a DENIED event, never silent. Coverage counts like http_probe.
  return null;
}
