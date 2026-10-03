/**
 * Shared-state tool handlers: registry, target map, findings, verdicts, abort (v0.19.0 refactor — extracted from dispatch.ts).
 */
import { type Finding } from "../types.js";
import { HaltError, type KilledLive, type LiveFinding } from "../context.js";
import { join, resolve } from "node:path";
import { queryRegistry } from "../registry.js";
import { redactPii } from "../safety/index.js";
import { resolveItemKey, setDisposition } from "../coverage/items.js";
import { type Ctx } from "../context.js";
import { type ActorRole, type EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { type DispatchResult } from "./types.js";
import { syncLiveFindingsToState, writeFindingToRegistry, writeKilledToRegistry } from "./verdicts.js";
import { optStr } from "./prelude.js";

export async function handleBookkeepingTools(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest, args: Record<string, unknown>): Promise<DispatchResult | null> {
  if (!["query_registry","update_target_map","record_finding","record_killed","record_item_verdict","abort_engagement"].includes(call.name)) return null;
if (call.name === "query_registry") {
  const limit = Math.min(Math.max(Number(args["limit"] ?? 5) || 5, 1), 10);
  const hits = queryRegistry(ctx.registry, {
    vulnClass: optStr(args["vulnClass"]),
    stack: optStr(args["stack"]) ?? ctx.fingerprint.stack.join(","),
    appType: optStr(args["appType"]) ?? ctx.fingerprint.appType,
    attackId: optStr(args["attackId"]),
    limit,
  });
  for (const h of hits) {
    if (!ctx.registryHits.some((e) => e.id === h.id)) ctx.registryHits.push(h);
  }
  if (hits.length === 0) {
    return {
      result: "Registry: no relevant entries for this target profile — uncharted territory. Proceed from first principles and write back everything you learn.",
      target: "registry",
    };
  }
  const lines = hits.map((h) =>
    h.kind === "confirmed"
      ? `[CONFIRMED] ${h.vulnClass} (${h.attackId ?? "?"} ${h.technique}) — payload: ${h.payloadPattern} — ${h.engagementId} ${h.date}`
      : `[KILLED — exact attempt dead; class still in play with a different angle] ${h.hypothesis} — killing observation: ${h.killingObservation} — ${h.engagementId} ${h.date}`,
  );
  return { result: `Registry hits (${hits.length}):\n${lines.join("\n")}`, target: "registry" };
}

if (call.name === "update_target_map") {
  const entries = Array.isArray(args["entries"]) ? (args["entries"] as Record<string, unknown>[]) : [];
  let added = 0;
  for (const e of entries) {
    const area = String(e["area"] ?? "").slice(0, 200);
    const method = (optStr(e["method"]) ?? "GET").toUpperCase().slice(0, 12);
    if (!area) continue;
    if (ctx.targetMap.some((t) => t.method === method && t.area === area)) continue;
    ctx.targetMap.push({
      area,
      method,
      params: optStr(e["params"])?.slice(0, 200),
      authState: optStr(e["authState"])?.slice(0, 60),
      attackId: optStr(e["attackId"])?.toUpperCase(),
      notes: optStr(e["notes"])?.slice(0, 200),
    });
    added++;
  }
  return {
    result: `Target map updated: ${added} new entries (${ctx.targetMap.length} total) — the whole team sees this shared state.`,
    target: "target-map",
  };
}

if (call.name === "record_finding") {
  const attackId = (optStr(args["attackId"]) ?? "T1190").toUpperCase();
  // v0.13.0 safety case: PII redaction applies to finding evidence too —
  // agents paste tool output into evidence, and it lands in reports.
  const lf: LiveFinding = {
    severity: optStr(args["severity"]) ?? "low",
    title: redactPii(String(args["title"] ?? "untitled").slice(0, 200)),
    vulnClass: optStr(args["vulnClass"]),
    attackId,
    evidence: redactPii(String(args["evidence"] ?? "").slice(0, 800)),
    payload: optStr(args["payload"])?.slice(0, 300),
  };
  ctx.liveFindings.push(lf);
  syncLiveFindingsToState(ctx);
  writeFindingToRegistry(ctx, lf);
  // v0.18.0 per-item verdicts: tie the confirmed finding to its battery item.
  const fItem = optStr(args["batteryItem"]);
  if (fItem && ctx.input.fullBattery && ctx.itemLedger.size > 0) {
    const fKey = resolveItemKey(fItem, optStr(args["targetProfile"]));
    if (fKey && ctx.itemLedger.has(fKey)) {
      try {
        setDisposition(ctx.itemLedger, fKey, "confirmed", {
          reason: `[${lf.severity}] ${lf.title}`.slice(0, 300),
        });
      } catch (e) {
        ctx.events.append({
          phase,
          actor: "runner",
          action: "item_verdict_refused",
          result: `record_finding for "${fItem}": ${(e as Error).message}`,
        });
      }
    } else {
      ctx.events.append({
        phase,
        actor: "runner",
        action: "item_tag_unresolved",
        result: `record_finding batteryItem "${fItem}" did not resolve to a selected battery item — finding recorded, ledger untouched.`,
      });
    }
  }
  return {
    result: `Finding recorded to shared state + registry: [${lf.severity}] ${lf.title} (${attackId}). The reporter and all future engagements see it.`,
    attackId,
    target: ctx.domain,
  };
}

if (call.name === "record_killed") {
  const kl: KilledLive = {
    hypothesis: String(args["hypothesis"] ?? "").slice(0, 300),
    killingObservation: String(args["killingObservation"] ?? "").slice(0, 500),
    attackId: optStr(args["attackId"])?.toUpperCase(),
    vulnClass: optStr(args["vulnClass"]),
    payload: optStr(args["payload"])?.slice(0, 300),
  };
  ctx.killedLive.push(kl);
  writeKilledToRegistry(ctx, kl);
  // v0.18.0 per-item verdicts: tie the killed hypothesis to its battery
  // item (negative intelligence — the class stays in play per the registry rule).
  const kItem = optStr(args["batteryItem"]);
  if (kItem && ctx.input.fullBattery && ctx.itemLedger.size > 0) {
    const kKey = resolveItemKey(kItem, optStr(args["targetProfile"]));
    if (kKey && ctx.itemLedger.has(kKey)) {
      try {
        setDisposition(ctx.itemLedger, kKey, "killed", { reason: kl.killingObservation.slice(0, 500) });
      } catch (e) {
        ctx.events.append({
          phase,
          actor: "runner",
          action: "item_verdict_refused",
          result: `record_killed for "${kItem}": ${(e as Error).message}`,
        });
      }
    } else {
      ctx.events.append({
        phase,
        actor: "runner",
        action: "item_tag_unresolved",
        result: `record_killed batteryItem "${kItem}" did not resolve to a selected battery item — hypothesis recorded, ledger untouched.`,
      });
    }
  }
  return {
    result: "Killed hypothesis recorded to shared state + registry as negative intelligence — future engagements keep the full spectrum; the exact attempt is dead, the class stays in play.",
    attackId: kl.attackId,
    target: ctx.domain,
  };
}

// v0.18.0 per-item verdicts: explicit not-applicable declarations. The
// battery cannot report complete while any item is pending, so items with
// no applicable surface must be declared here — with evidence, never a
// bare flag. "na" without evidence is refused mechanically.
if (call.name === "record_item_verdict") {
  const rawItem = optStr(args["batteryItem"]) ?? "";
  const verdict = (optStr(args["verdict"]) ?? "").toLowerCase();
  const evidence = optStr(args["evidence"]) ?? "";
  if (!ctx.input.fullBattery || ctx.itemLedger.size === 0) {
    return {
      result: "Item verdicts are tracked on full-battery engagements only — verdict not recorded.",
      target: ctx.domain,
    };
  }
  const key = resolveItemKey(rawItem, optStr(args["targetProfile"]));
  if (!key || !ctx.itemLedger.has(key)) {
    return {
      result: `REFUSED: batteryItem "${rawItem}" did not resolve to a selected battery item.`,
      target: ctx.domain,
    };
  }
  if (verdict !== "na") {
    return {
      result: `REFUSED: record_item_verdict only records "na" (with evidence). Other verdicts land via record_finding / record_killed; attempts are recorded automatically from tagged actions.`,
      target: ctx.domain,
    };
  }
  try {
    setDisposition(ctx.itemLedger, key, "na", { reason: evidence });
  } catch (e) {
    return { result: `REFUSED: ${(e as Error).message}`, target: ctx.domain };
  }
  ctx.events.append({
    phase,
    actor: role,
    action: "item_verdict_na",
    target: key,
    result: `${key} marked not-applicable: ${evidence.slice(0, 200)}`,
  });
  return { result: `Item ${key} recorded as not-applicable with evidence.`, target: key };
}

if (call.name === "abort_engagement") {
  const reason = String(args["reason"] ?? "coordinator abort").slice(0, 500);
  // KILL SWITCH: terminate every in-flight host execution across all
  // parallel tasks (shared ctx), then refuse any new host work.
  ctx.hostKill.aborted = true;
  for (const c of ctx.hostKill.controllers) {
    try {
      c.abort();
    } catch {
      /* best effort */
    }
  }
  ctx.hostKill.controllers.clear();
  // v0.13.0 safety case: count the kill-switch use for the manifest —
  // the zero-disruption record is derived from these events.
  ctx.safety.killSwitchAborts++;
  ctx.events.append({ phase, actor: "coordinator", action: "abort_engagement", result: `ABORTED by coordinator: ${reason}` });
  throw new HaltError(`aborted by coordinator: ${reason}`);
}

  return null;
}
