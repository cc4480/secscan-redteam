/**
 * Nmap bridge tool handler: nmap_exec (v0.31.0).
 *
 * Mirrors the nuclei_exec dispatcher shape: ROE technique check, explicit
 * targetProfile pinning (windows|linux, never inferred), kill-switch controller
 * registration, coverage counting.
 *
 * Two deliberate differences from nuclei_exec:
 *
 *  - `scan` is allowed in RECON, not gated to exploit. Port and service
 *    discovery IS recon; gating it the way nuclei templates are gated would
 *    leave recon with no way to learn what is listening, which is the hole this
 *    tool exists to fill.
 *  - The profile's own minTier is enforced here. The dispatcher's tier ladder
 *    works on tool NAMES, and all six profiles share one name, so a 65535-port
 *    sweep and a top-100 sweep would otherwise be equally reachable at Tier 0.
 *    The check is mechanical and the denial names the tier that would allow it.
 */
import { BATTERY_CATEGORIES, type BatteryCategory } from "../battery.js";
import { type TargetId, isTargetId } from "../targets.js";
import { techniqueAllowed } from "../gate.js";
import { sleep } from "../util.js";
import { type Ctx } from "../context.js";
import { type ActorRole, type EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { type DispatchResult } from "./types.js";
import { findProfile, NMAP_PROFILES } from "../nmap/index.js";
import { validateHostTarget } from "../host-exec/common.js";

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

export async function handleNmapTools(
  ctx: Ctx,
  _role: ActorRole,
  _phase: EngagementPhase,
  call: ToolCallRequest,
  args: Record<string, unknown>,
): Promise<DispatchResult | null> {
  if (call.name !== "nmap_exec") return null;
  const attackId = strArg(args, "attackId")?.toUpperCase();
  const rawCat = (strArg(args, "category") ?? "").toLowerCase();
  const category = (BATTERY_CATEGORIES as string[]).includes(rawCat) ? (rawCat as BatteryCategory) : undefined;
  const host = String(args["host"] ?? "");

  if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
    return { result: `DENIED by ROE: technique ${attackId} is excluded for this engagement.`, attackId, target: host };
  }
  const rawTp = (strArg(args, "targetProfile") ?? "").toLowerCase();
  if (!isTargetId(rawTp) || (rawTp !== "windows" && rawTp !== "linux")) {
    return {
      result: `DENIED: nmap_exec requires targetProfile "windows"|"linux" (host targets are never inferred) — got ${JSON.stringify(args["targetProfile"] ?? null)}.`,
      attackId,
      target: host,
    };
  }
  if (!host) return { result: "DENIED: nmap_exec requires a host.", attackId, target: "" };

  const action = args["action"] === "scan" ? "scan" : "profiles";
  const profileId = strArg(args, "profile") ?? "quick";
  const profile = findProfile(profileId);
  if (action === "scan" && !profile) {
    return {
      result: `DENIED: unknown profile ${JSON.stringify(profileId)} — available: ${NMAP_PROFILES.map((p) => p.id).join(", ")}.`,
      attackId,
      target: host,
    };
  }
  // Profile tier gate — see the header. A profile above the declared tier is
  // refused before any packet, and the refusal names the tier that would allow it.
  if (action === "scan" && profile && profile.minTier > ctx.tier.current) {
    return {
      result: `DENIED by autonomy tier: profile ${JSON.stringify(profile.id)} needs Tier ${profile.minTier}, this engagement is Tier ${ctx.tier.current}. Escalate with an operator approval to run it, or use a lighter profile: ${NMAP_PROFILES.filter((p) => p.minTier <= ctx.tier.current).map((p) => p.id).join(", ") || "(none)"}.`,
      attackId,
      target: host,
    };
  }
  // Scope gate — fail closed BEFORE any packet. The executor deliberately does
  // NOT re-check (its contract says the dispatch layer owns the ROE host check),
  // so this is the one and only place it happens. Every other host-touching
  // tool (prober, scan_url, host-exec, nuclei, msf) validates here; nmap must
  // not be the exception, or an agent can point a port sweep at any host/CIDR.
  if (action === "scan") {
    const scope = validateHostTarget(host, ctx.hosts);
    if (!scope.ok) {
      return { result: `DENIED by scope: ${scope.reason}`, attackId, target: host };
    }
  }

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
    const exec = ctx.nmapExecutor;
    if (action === "profiles") {
      const res = await exec.profiles();
      return { result: res.message, attackId, target: "(no target — profile listing)" };
    }
    const res = await exec.scan({
      target: host,
      profile: profileId,
      scriptCategories: strListArg(args, "scriptCategories"),
      rateLimit: ctx.safety.rpsPerHost,
      skipPing: args["skipPing"] === true,
      signal: ctrl.signal,
    });
    if (!res.ok) return { result: `FAILED: ${res.message}`, attackId, target: host };
    // Evidence, not impressions: ports as structured lines an agent can cite.
    const lines: string[] = [];
    for (const h of res.run?.hosts ?? []) {
      const label = h.hostnames.length ? `${h.address} (${h.hostnames.join(", ")})` : h.address;
      lines.push(`${label} — ${h.ports.filter((p) => p.state === "open").length} open`);
      for (const p of h.ports.filter((x) => x.state === "open")) {
        const svc = [p.service, p.product, p.version].filter(Boolean).join(" ");
        lines.push(`  ${p.port}/${p.protocol} open  ${svc}`);
        for (const [id, out] of Object.entries(p.scripts)) lines.push(`    [${id}] ${out.slice(0, 200)}`);
      }
      for (const os of h.osMatches) lines.push(`  os-match: ${os}`);
    }
    return { result: `${res.message}\n${lines.join("\n")}`, attackId, target: host };
  } finally {
    ctx.hostKill.controllers.delete(ctrl);
  }
}
