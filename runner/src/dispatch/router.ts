/**
 * Tool dispatcher: router + safety wrapper (v0.19.0 refactor — extracted from dispatch.ts).
 *
 * dispatchToolInner routes each tool call to its handler module (web, host,
 * msf, mcp, bookkeeping) in the original order. dispatchTool wraps it with
 * the v0.13.0 safety wrapper: rate limiting + per-target auto-halt +
 * autonomy-tier enforcement, all mechanical.
 */
import { type ActorRole, type EngagementPhase } from "../types.js";
import { type Ctx } from "../context.js";
import { type ToolCallRequest } from "@secscan/redteam-llm-router";
import { checkTierAllows, recordExploitStep } from "../accountability/index.js";
import { isTargetDistress } from "../safety/index.js";
import { resolve } from "node:path";
import { type DispatchResult } from "./types.js";
import { recordItemAttempt } from "./verdicts.js";
import { handleWebTools } from "./web.js";
import { handleHostTools } from "./host.js";
import { handleMsfTools } from "./msf.js";
import { handleMcpTools } from "./mcp.js";
import { handleBookkeepingTools } from "./bookkeeping.js";
async function dispatchToolInner(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest): Promise<DispatchResult> {
  const args = call.arguments ?? {};
  ctx.actions++;

  const handlers = [handleWebTools, handleHostTools, handleMsfTools, handleMcpTools, handleBookkeepingTools];
  for (const h of handlers) {
    const r = await h(ctx, role, phase, call, args);
    if (r) return r;
  }
  return { result: `DENIED: unknown tool ${call.name}` };
}

// the outcome is recorded against the auto-halt tracker. Tools without a
// resolvable target host (shared-state tools, MCP read-only tools) skip
// the limiter — they generate no target traffic.
// ---------------------------------------------------------------------------

/** Tools whose calls generate traffic against a target host. */
const RATE_LIMITED_TOOLS = new Set([
  "http_probe",
  "burst_probe",
  "scan_url",
  "ssh_exec",
  "smb_exec",
  "winrm_exec",
  "winrm_probe",
  "rdp_auth",
  "rdp_shadow_prep",
  "smb_pth",
  "ad_enum",
  "krb_ptt",
  "ssh_agent_audit",
  "nfs_enum",
  "msf_exec",
]);

/** Best-effort target host for a tool call — undefined when the tool has no target traffic. */
function toolTargetHost(call: ToolCallRequest): string | undefined {
  if (!RATE_LIMITED_TOOLS.has(call.name)) return undefined;
  const args = call.arguments as Record<string, unknown> | undefined ?? {};
  const direct = typeof args["host"] === "string" ? (args["host"] as string).trim().toLowerCase() : "";
  if (direct) return direct;
  const url = typeof args["url"] === "string" ? (args["url"] as string) : "";
  if (url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export async function dispatchTool(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest): Promise<DispatchResult> {
  const host = toolTargetHost(call);
  const args = call.arguments ?? {};
  if (host) {
    // Auto-halt first: a halted target is refused before any packet AND
    // before waiting on the rate limiter — never hammer, never queue.
    if (ctx.safety.autoHalt.isHalted(host)) {
      const reason = ctx.safety.autoHalt.haltReason(host) ?? "auto-halted";
      return {
        result: `HALTED: target ${host} was auto-halted (${reason}). No further traffic to this host this engagement — pivot to another in-scope target or report the halt.`,
        target: host,
      };
    }
    await ctx.safety.limiter.acquire(host);
  }
  // v0.17.0 accountability: autonomy tiers are MECHANICAL. A tool above the
  // current tier is refused before any packet, before the rate limiter, and
  // before the executor — the denial is an event, never silent. There is no
  // agent path to raise the tier; escalation needs a recorded operator
  // approval via escalateTier().
  const tierDenial = checkTierAllows(ctx.tier, call.name, args, host);
  if (tierDenial) {
    return { result: tierDenial, target: host };
  }
  const d = await dispatchToolInner(ctx, role, phase, call);
  if (host) {
    const haltReason = ctx.safety.autoHalt.recordOutcome(host, isTargetDistress(d.result));
    if (haltReason) {
      ctx.events.append({
        phase,
        actor: "runner",
        action: "target_auto_halt",
        target: host,
        result: `AUTO-HALT: ${host} — ${haltReason}. Further traffic to this host refused this engagement.`,
      });
    }
    // v0.17.0 accountability: a successful validated exploit step consumes
    // the Tier 1 per-target chain budget. Denials, halts, and failures don't.
    const clean = !/^(DENIED|HALTED)/i.test(d.result) && !d.result.startsWith("probe failed");
    if (clean) recordExploitStep(ctx.tier, call.name, args, host);
  }
  // v0.18.0 per-item verdicts: a clean execution tagged with batteryItem
  // marks that item attempted (pending/blocked → executed-clean). Denials,
  // halts, aborts, refusals, and failed probes never mark anything. The
  // verdict tools (record_finding / record_killed / record_item_verdict)
  // set terminal dispositions in their own handlers — skipped here.
  if (
    call.name !== "record_finding" &&
    call.name !== "record_killed" &&
    call.name !== "record_item_verdict" &&
    !/^(DENIED|HALTED|ABORTED|REFUSED)/i.test(d.result) &&
    !d.result.startsWith("probe failed")
  ) {
    recordItemAttempt(ctx, args, phase);
  }
  return d;
}

/**
 * v0.18.0: resolve a tagged batteryItem (and any CVE) from tool args
 * against the item ledger. Unresolvable tags are surfaced as events —
 * never silently dropped.
 */
