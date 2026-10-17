/**
 * Tool dispatcher: router + safety wrapper (v0.19.0 refactor — extracted from dispatch.ts).
 *
 * dispatchToolInner routes each tool call to its handler module (web, host,
 * msf, mcp, bookkeeping) in the original order. dispatchTool wraps it with
 * the v0.13.0 safety wrapper: rate limiting + per-target auto-halt +
 * autonomy-tier enforcement, all mechanical.
 */
import { type ActorRole, type EngagementPhase } from "../types.js";
import { type Ctx, HaltError } from "../context.js";
import { type ToolCallRequest } from "@secscan/redteam-llm-router";
import { checkTierAllows, recordExploitStep, readTierFile, TIER_NAMES } from "../accountability/index.js";
import { isTargetDistress, readAbortFile, consumeAbortFile } from "../safety/index.js";
import { type DispatchResult } from "./types.js";
import { recordItemAttempt } from "./verdicts.js";
import { checkVariantCap, recordVariantExecution } from "../variants/index.js";
import { postDispatchHooks, preDispatchGate } from "./policy-gate.js";
import { handleWebTools } from "./web.js";
import { handleHostTools } from "./host.js";
import { handleMsfTools } from "./msf.js";
import { handleNucleiTools } from "./nuclei.js";
import { handleNmapTools } from "./nmap.js";
import { handleXTool } from "./xtool.js";
import { XTOOLS } from "../xtool/registry.js";
import { handleMcpTools } from "./mcp.js";
import { handleBookkeepingTools } from "./bookkeeping.js";
async function dispatchToolInner(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest): Promise<DispatchResult> {
  const args = call.arguments ?? {};
  ctx.actions++;

  const handlers = [handleWebTools, handleHostTools, handleMsfTools, handleNucleiTools, handleNmapTools, handleXTool, handleMcpTools, handleBookkeepingTools];
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
/**
 * Tool names owned by the external-tool bridge. Kept as an explicit set because
 * an `_exec` suffix is NOT a safe discriminator — it also matches the host-exec
 * family (ssh_exec, smb_exec, winrm_exec, …), which has no `action` argument.
 */
const XTOOL_TOOL_NAMES = new Set(XTOOLS.map((t) => `${t.id}_exec`));

/**
 * Tools whose calls generate traffic against a target host. Tools without a
 * resolvable target host (shared-state tools, MCP read-only tools) skip the
 * limiter — they generate no target traffic.
 *
 * Exported so test/tool-family-consistency.test.ts can assert that every host
 * tool the runner exposes is actually rate-limited and auto-halt tracked. A
 * tool missing from this set fires real traffic with no limiter at all, which
 * is exactly the class of gap the nmap scope check fell into.
 */
export const RATE_LIMITED_TOOLS = new Set([
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
  "nuclei_exec",
  "nmap_exec",
  "sqlmap_exec",
  "ffuf_exec",
  "gobuster_exec",
  "nikto_exec",
]);

/** Best-effort target host for a tool call — undefined when the tool has no target traffic. */
function toolTargetHost(call: ToolCallRequest): string | undefined {
  if (!RATE_LIMITED_TOOLS.has(call.name)) return undefined;
  const args = call.arguments as Record<string, unknown> | undefined ?? {};
  // v0.21.0: nuclei_exec templates is local-only (reads the operator's
  // template checkout) — no target traffic, so no limiter/halt applies.
  if (call.name === "nuclei_exec" && args["action"] !== "run") return undefined;
  // v0.31.0: nmap_exec profiles runs `nmap --version` locally — no target
  // traffic, so no limiter and no auto-halt applies.
  if (call.name === "nmap_exec" && args["action"] !== "scan") return undefined;
  // v0.32.0: an xtool probe runs nothing; john_exec is offline entirely.
  //
  // The xtool names are listed EXPLICITLY rather than matched with an `_exec`
  // suffix test. A suffix test also matches ssh_exec, smb_exec, winrm_exec and
  // the rest of the host-exec family — none of which take an `action`
  // argument — so it returned undefined for every one of them and silently
  // removed them from the rate limiter and the auto-halt tracker. The chaining
  // test caught it: a second ssh_exec against the same target fired instead of
  // being refused.
  if (XTOOL_TOOL_NAMES.has(call.name) && args["action"] !== "run") return undefined;
  if (call.name === "john_exec") return undefined;
  const direct = typeof args["host"] === "string" ? (args["host"] as string).trim().toLowerCase() : "";
  if (direct) {
    // URL-taking tools (sqlmap/ffuf/gobuster/nikto) take the target in `host`
    // as a full URL. Key on the hostname so varying the path/query/scheme cannot
    // mint a fresh rate-limit bucket (and defeat auto-halt) for the same host.
    try {
      return new URL(direct).hostname.toLowerCase();
    } catch {
      return direct;
    }
  }
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

/**
 * v0.24.0: mid-run tier changes. The operator may raise/lower the tier via
 * `redteam-runner escalate` or the UI; both rewrite tier.json in the
 * engagement dir (atomically). The dispatcher re-reads it before every tier
 * check so the new tier takes effect without restarting the engagement.
 * The change lands in the audit log — never silent. A missing or corrupt
 * file means "no change". Exported for tests; dispatchTool calls it.
 */
export function refreshTierFromDisk(ctx: Ctx, phase: EngagementPhase): void {
  const tf = readTierFile(ctx.events.dir);
  if (!tf || tf.tier === ctx.tier.current) return;
  const from = ctx.tier.current;
  ctx.tier.current = tf.tier;
  ctx.events.append({
    phase,
    actor: "runner",
    action: "tier_changed",
    result:
      `Autonomy tier changed mid-run: Tier ${from} (${TIER_NAMES[from]}) → Tier ${tf.tier} (${TIER_NAMES[tf.tier]})` +
      `${tf.by ? ` by ${tf.by}` : ""}${tf.reason ? ` — ${tf.reason}` : ""}. ` +
      `Picked up from tier.json; see approvals.jsonl for the operator approval record. No restart needed.`,
  });
}

/**
 * v0.25.0: cross-process kill switch. The UI cannot reach into a
 * CLI-launched engagement's process, so it writes abort.json into the
 * engagement dir; the dispatcher checks for it here on every dispatch
 * cycle. When the marker is found, the abort sequence is identical to the
 * in-process kill switch: set the flag, terminate every in-flight
 * execution via the registered controllers (shared ctx — covers parallel
 * tasks), count it for the safety manifest, log abort_engagement, consume
 * the marker (the audit event is the durable record), and throw HaltError
 * so the run unwinds to "halted". Exported for tests; dispatchTool calls
 * it. A missing or corrupt file means "no abort requested" — never a
 * crash, never a spurious abort.
 */
export function checkAbortSignal(ctx: Ctx, phase: EngagementPhase): void {
  if (ctx.hostKill.aborted) return;
  const sig = readAbortFile(ctx.events.dir);
  if (!sig) return;
  ctx.hostKill.aborted = true;
  for (const c of ctx.hostKill.controllers) {
    try {
      c.abort();
    } catch {
      /* best effort */
    }
  }
  ctx.hostKill.controllers.clear();
  ctx.safety.killSwitchAborts++;
  ctx.events.append({
    phase,
    actor: "coordinator",
    action: "abort_engagement",
    result:
      `ABORTED by operator: ${sig.reason ?? "operator abort"} ` +
      `(cross-process kill switch; requested ${sig.requestedAt}${sig.by ? ` by ${sig.by}` : ""})`,
  });
  consumeAbortFile(ctx.events.dir);
  throw new HaltError("aborted by operator (kill switch)");
}

export async function dispatchTool(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest): Promise<DispatchResult> {
  // v0.22.0 UI kill switch: the operator abort is mechanically identical to
  // the coordinator's abort_engagement. In-flight work is already dead
  // (controllers aborted when the flag was set); the next tool call throws
  // HaltError so the engagement unwinds to "halted" instead of spinning on
  // preflight refusals. Nothing sets hostKill.aborted and continues — the
  // coordinator's own abort sets it and throws immediately after.
  if (ctx.hostKill.aborted) {
    throw new HaltError("aborted by operator (kill switch)");
  }
  // v0.25.0 cross-process kill switch: a CLI-launched engagement has no
  // abort handle inside the UI server process, so the UI writes abort.json
  // into the engagement dir instead. Check for it on every dispatch — the
  // abort sequence below is identical to the in-process kill switch
  // (flag, controllers, audit event), then HaltError unwinds to "halted".
  // Checked before the rate limiter: an aborted run acquires nothing.
  checkAbortSignal(ctx, phase);
  const host = toolTargetHost(call);
  const args = call.arguments ?? {};
  // v0.17.0 accountability: autonomy tiers are MECHANICAL. A tool above the
  // current tier is refused before any packet and before the rate limiter —
  // v0.28.0: the tier check was moved ahead of limiter.acquire so a refused
  // call consumes no rate token and waits on nothing. The denial is an
  // event, never silent. There is no agent path to raise the tier; mid-run
  // changes arrive only via tier.json, written by `redteam-runner escalate`
  // or the UI with a recorded operator approval (escalateTier()).
  // v0.24.0: pick up operator tier changes without restarting the engagement.
  refreshTierFromDisk(ctx, phase);
  const tierDenial = checkTierAllows(ctx.tier, call.name, args, host);
  if (tierDenial) {
    return { result: tierDenial, target: host };
  }
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
  // v0.20.0 variants: the per-item variant cap is MECHANICAL. A
  // variant-tagged call past the cap is denied before any packet — one
  // item can't spray the target.
  const variantDenial = checkVariantCap(ctx.itemLedger, args);
  if (variantDenial) {
    return { result: variantDenial, target: host };
  }
  // v0.34.0 operator controls: policy (deny-wins) and pre-execute hooks, then
  // post-hooks — all audited individually. A denial sends nothing.
  const gate = await preDispatchGate(ctx, phase, call, host);
  if (gate.denial) return gate.denial;
  let d = await dispatchToolInner(ctx, role, phase, gate.call);
  d = await postDispatchHooks(ctx, phase, gate.call, d, host);
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
    // A failed host-exec or msf call (connection refused, non-zero exit, marker
    // not echoed) carries ok:false and must not consume the budget — the old
    // string heuristic treated "ssh host failed: …" as clean and permanently
    // wedged the target after one failed attempt.
    const clean = d.ok === undefined
      ? !/^(DENIED|HALTED)/i.test(d.result) && !d.result.startsWith("probe failed")
      : d.ok;
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
    call.name !== "variant_list" &&
    // v0.21.0: nuclei template listing is recon for the methodology item —
    // only `run` executions mark the item attempted.
    !(call.name === "nuclei_exec" && (call.arguments as Record<string, unknown> | undefined)?.["action"] !== "run") &&
    !/^(DENIED|HALTED|ABORTED|REFUSED)/i.test(d.result) &&
    !d.result.startsWith("probe failed")
  ) {
    recordItemAttempt(ctx, args, phase);
    // v0.20.0 variants: variant-tagged clean executions advance the item's
    // expansion; exhaustion settles it to executed-clean with honest counts.
    recordVariantExecution(ctx, args, phase);
  }
  return d;
}

/**
 * v0.18.0: resolve a tagged batteryItem (and any CVE) from tool args
 * against the item ledger. Unresolvable tags are surfaced as events —
 * never silently dropped.
 */
