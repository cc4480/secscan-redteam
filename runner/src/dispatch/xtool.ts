/**
 * External-tool dispatch handler (v0.32.0): john_exec, sqlmap_exec, ffuf_exec,
 * gobuster_exec, nikto_exec.
 *
 * Same shape as the nuclei/nmap handlers: ROE technique check, explicit
 * targetProfile pinning, profile tier gate, kill-switch controller registration,
 * coverage counting.
 *
 * One difference that matters: `john_exec` is an OFFLINE tool. Its `host` is a
 * path to a hash file, NOT a network target, so it skips the scope check and the
 * rate limiter entirely — rate-limiting a local CPU-bound crack would be
 * meaningless, and scope-checking a filesystem path would be wrong. Everything
 * else routes through the same checks as every other tool that touches a host.
 */
import { BATTERY_CATEGORIES, type BatteryCategory } from "../battery.js";
import { type TargetId, isTargetId } from "../targets.js";
import { techniqueAllowed, urlInScope } from "../gate.js";
import { type Ctx } from "../context.js";
import { type ActorRole, type EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { type DispatchResult } from "./types.js";
import { findXTool, checkXToolFlags, runXTool, binPresent, type XToolSpec } from "../xtool/index.js";
import { validateHostTarget } from "../host-exec/common.js";
import { noteCategoryCoverage } from "./prelude.js";

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

/** Resolve which tool a call names, by the `<id>_exec` naming convention. */
function specForTool(name: string): XToolSpec | undefined {
  if (!name.endsWith("_exec")) return undefined;
  return findXTool(name.slice(0, -"_exec".length));
}

export async function handleXTool(
  ctx: Ctx,
  _role: ActorRole,
  _phase: EngagementPhase,
  call: ToolCallRequest,
  args: Record<string, unknown>,
): Promise<DispatchResult | null> {
  const spec = specForTool(call.name);
  if (!spec) return null;

  const offline = spec.id === "john";
  const attackId = strArg(args, "attackId")?.toUpperCase();
  const rawCat = (strArg(args, "category") ?? "").toLowerCase();
  const category = (BATTERY_CATEGORIES as string[]).includes(rawCat) ? (rawCat as BatteryCategory) : undefined;
  const host = String(args["host"] ?? "");

  if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
    return { result: `DENIED by ROE: technique ${attackId} is excluded for this engagement.`, attackId, target: host };
  }
  // Refuse agent-supplied flags before anything else — this is the control that
  // stops a "scanner" from being argued into a shell.
  const flagDenial = checkXToolFlags(strListArg(args, "flags") ?? strListArg(args, "extraFlags"));
  if (flagDenial) return { result: `DENIED: ${flagDenial}`, attackId, target: host };

  const action = args["action"] === "run" ? "run" : "probe";
  const profileId = strArg(args, "profile") ?? spec.profiles[0]!.id;

  if (action === "run" && !host) {
    return { result: `DENIED: ${spec.id}_exec run requires 'host'${offline ? " — the path to a hash file" : ""}.`, attackId, target: "" };
  }
  const profile = spec.profiles.find((p) => p.id === profileId);
  if (action === "run" && !profile) {
    return {
      result: `DENIED: unknown profile ${JSON.stringify(profileId)} — available: ${spec.profiles.map((p) => p.id).join(", ")}.`,
      attackId,
      target: host,
    };
  }
  if (action === "run" && profile && profile.minTier > ctx.tier.current) {
    return {
      result: `DENIED by autonomy tier: profile ${JSON.stringify(profile.id)} needs Tier ${profile.minTier}, this engagement is Tier ${ctx.tier.current}. Escalate with an operator approval, or use a lighter profile: ${spec.profiles.filter((p) => p.minTier <= ctx.tier.current).map((p) => p.id).join(", ") || "(none)"}.`,
      attackId,
      target: host,
    };
  }

  // Network tools must declare which host battery they belong to; john does not.
  let rawTp = "";
  if (!offline) {
    rawTp = (strArg(args, "targetProfile") ?? "").toLowerCase();
    if (!isTargetId(rawTp) || (rawTp !== "windows" && rawTp !== "linux")) {
      return {
        result: `DENIED: ${spec.id}_exec requires targetProfile "windows"|"linux" (host targets are never inferred) — got ${JSON.stringify(args["targetProfile"] ?? null)}.`,
        attackId,
        target: host,
      };
    }
    // Scope gate — fail closed BEFORE any packet, for the four network tools.
    // The target may be a full URL (sqlmap/ffuf/gobuster/nikto) or a bare host;
    // accept it only when its hostname is an exact in-scope host. john is offline
    // (host is a hash-file path) and correctly skips this.
    if (action === "run") {
      const inScope = urlInScope(host, ctx.hosts) || validateHostTarget(host, ctx.hosts).ok;
      if (!inScope) {
        return {
          result: `DENIED by scope: ${host} is not an in-scope host (scope: ${ctx.hosts.join(", ") || "(empty)"}).`,
          attackId,
          target: host,
        };
      }
    }
  }

  if (action === "probe" && !binPresent(spec, process.env)) {
    return { result: `UNAVAILABLE: ${spec.setup.join("\n")}`, attackId, target: "(no target — probe)" };
  }

  if (!offline) ctx.probesUsed++;
  noteCategoryCoverage(ctx, category, rawTp ? (rawTp as TargetId) : undefined);

  const ctrl = new AbortController();
  ctx.hostKill.controllers.add(ctrl);
  try {
    if (ctx.hostKill.aborted) {
      return { result: "ABORTED by operator (kill switch) — no process started.", attackId, target: host };
    }
    const wordlist =
      strArg(args, "wordlist") ??
      process.env["REDTEAM_WORDLIST"] ??
      "C:\\Users\\Cho-zen\\tools\\wordlists\\common.txt";
    const res = await runXTool(spec, {
      action,
      target: host,
      profileId,
      wordlist,
      // john is offline and its rate is bounded by the CPU, not a network.
      rateLimit: offline ? 0 : ctx.safety.rpsPerHost,
      timeoutS: offline
        ? Number(process.env["REDTEAM_JOHN_TIMEOUT_S"] ?? 600)
        : Math.max(60, Math.min(900, ctx.safety.rpsPerHost > 0 ? 300 : 300)),
      signal: ctrl.signal,
    });
    const lines: string[] = [];
    for (const f of res.findings ?? []) lines.push(`  [${f.kind}] ${f.target} — ${f.detail}`);
    return {
      result: `${res.ok ? "" : "PARTIAL/FAILED: "}${res.message}${lines.length ? "\nFindings:\n" + lines.join("\n") : ""}`,
      attackId,
      target: host,
    };
  } finally {
    ctx.hostKill.controllers.delete(ctrl);
  }
}
