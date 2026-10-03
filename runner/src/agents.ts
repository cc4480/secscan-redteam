/**
 * The agent driver (v0.19.0 refactor — extracted from phases.ts).
 *
 * agentLoop is the thin REASON → ACT → OBSERVE loop over the model router:
 * promptCtx builds each role's context, extractJsonBlock parses structured
 * model output, and commanderRedirect / blackout / halt plumbing keeps the
 * loop bounded and safe. HaltError is the loop's stop signal.
 */
import { join, resolve, dirname } from "node:path";
import { completeForRole as routerCompleteForRole, type AgentRole, type ChatMessage, type ChatResult, type JsonSchemaTool } from "@secscan/redteam-llm-router";
import { GateVerdict, checkAuthorization, inBlackout, scopeHosts } from "./gate.js";
import { isPrivateOrLoopbackHost } from "./prober.js";
import { reconPrompt } from "./prompts.js";
import { redactPii } from "./safety/index.js";
import { type EngagementMode, type EngagementPhase, type RulesOfEngagement } from "./types.js";
import { type TargetId } from "./targets.js";
import { HaltError, type Ctx } from "./context.js";
import { extractJsonBlock, sleep } from "./util.js";
import { dispatchTool } from "./dispatch.js";
import { sharedStateDigest } from "./coverage/cells.js";
import { RECON_TOOLS } from "./tools.js";

// ---------------------------------------------------------------------------
// Stop-condition plumbing
// ---------------------------------------------------------------------------

async function respectBlackout(ctx: Ctx, phase: EngagementPhase): Promise<void> {
  const w = inBlackout(new Date(), ctx.input.roe.blackoutWindows);
  if (!w) return;
  ctx.events.append({
    phase,
    actor: "runner",
    action: "blackout_pause",
    result: `Entering blackout window ${w.start}–${w.end}${w.tz ? ` ${w.tz}` : ""}. No traffic until it ends.`,
  });
  for (;;) {
    await sleep(30_000);
    if (!inBlackout(new Date(), ctx.input.roe.blackoutWindows)) break;
  }
  ctx.events.append({ phase, actor: "runner", action: "blackout_resume", result: "Blackout window ended. Resuming." });
}

function haltedByCaps(ctx: Ctx): string | null {
  if (ctx.actions >= ctx.config.maxActions) return `action cap reached (${ctx.config.maxActions})`;
  if (Date.now() - ctx.startedAt >= ctx.config.maxDurationMs) return `duration cap reached`;
  if (ctx.consecutive5xx >= 3) return `three consecutive 5xx responses — possible production impact, halting`;
  return null;
}

// ---------------------------------------------------------------------------
// The agent loop: REASON → ACT → OBSERVE, bounded
// ---------------------------------------------------------------------------

export async function agentLoop(
  ctx: Ctx,
  role: AgentRole,
  phase: EngagementPhase,
  system: string,
  user: string,
  tools: JsonSchemaTool[],
  maxTurns: number,
  opts: {
    /** Called when the model stops calling tools. Return a follow-up prompt to
     *  keep the phase going, or null to finish the phase. */
    onIdle?: () => string | null;
  } = {},
): Promise<string> {
  const complete = ctx.deps.completeForRole ?? routerCompleteForRole;
  const messages: ChatMessage[] = [
    { role: "system", content: system },
    { role: "user", content: user },
  ];
  const notes: string[] = [];
  for (let turn = 0; turn < maxTurns; turn++) {
    await respectBlackout(ctx, phase);
    const cap = haltedByCaps(ctx);
    if (cap) {
      ctx.events.append({ phase, actor: "runner", action: "halt", result: `Halted: ${cap}.` });
      throw new HaltError(cap);
    }
    let res: ChatResult;
    try {
      res = await complete(role, messages, { tools });
    } catch (err) {
      ctx.events.append({ phase, actor: "runner", action: "llm_error", result: `LLM call failed: ${(err as Error).message}` });
      throw err;
    }
    if (res.text || res.reasoning) {
      if (res.text) notes.push(res.text);
      // The thinking trace is first-class observability: it lands in the
      // event feed (and the console) alongside the visible reply.
      // v0.28.0: redact before the audit log — reasoning may echo secrets or
      // PII the upstream input redaction missed.
      const thought = res.reasoning ? `\n[thinking] ${res.reasoning.slice(0, 600)}` : "";
      const reasoningText = redactPii(`${res.text.slice(0, 500)}${thought}`.slice(0, 1200));
      ctx.events.append({ phase, actor: role, action: "reasoning", result: reasoningText });
    }
    if (!res.toolCalls || res.toolCalls.length === 0) {
      const followUp = opts.onIdle?.();
      if (!followUp) {
        messages.push({ role: "assistant", content: res.text });
        break;
      }
      messages.push({ role: "assistant", content: res.text || "(pausing)" });
      messages.push({ role: "user", content: followUp });
      ctx.events.append({ phase, actor: "runner", action: "phase_nudge", result: followUp.slice(0, 300) });
      continue;
    }
    messages.push({ role: "assistant", content: res.text || "(tool calls)" });
    for (const call of res.toolCalls) {
      const d = await dispatchTool(ctx, role, phase, call);
      // v0.13.0 safety case: PII is redacted from tool outputs BEFORE they
      // reach the audit log or the agent context. The agents reason about
      // vulnerability shapes, not other people's personal data.
      const safeResult = redactPii(d.result);
      ctx.events.append({
        phase,
        actor: role,
        action: call.name,
        attackId: d.attackId,
        target: d.target,
        result: safeResult.slice(0, 800),
        opsec: d.opsec,
      });
      messages.push({
        role: "tool",
        toolCallId: call.id,
        // Every observation carries the current shared state — no agent ever
        // works from a stale or private picture (Megazord protocol).
        content: safeResult.slice(0, 4000) + "\n" + sharedStateDigest(ctx, phase),
      });
      // Wall detection: consecutive blocked/cooled-down/OPSEC-signaled probes
      // with no successful observation. The coordinator redirects to re-recon.
      const blocked = /^(DENIED|probe failed)/i.test(d.result) || /OPSEC SIGNAL|cooling down/i.test(d.result);
      ctx.deniedStreak = blocked ? ctx.deniedStreak + 1 : 0;
      const capAfter = haltedByCaps(ctx);
      if (capAfter) {
        ctx.events.append({ phase, actor: "runner", action: "halt", result: `Halted: ${capAfter}.` });
        throw new HaltError(capAfter);
      }
    }
    if (phase === "exploit" && ctx.deniedStreak >= 4 && ctx.redirects < 2) {
      ctx.deniedStreak = 0;
      ctx.redirects++;
      const intel = await commanderRedirect(
        ctx,
        "The exploiter hit a wall: 4+ consecutive probes denied, cooled-down, or OPSEC-signaled with no successful observation.",
      );
      messages.push({ role: "user", content: intel });
    }
  }
  return notes.join("\n\n");
}

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

export function promptCtx(ctx: Ctx): {
  mode: EngagementMode;
  objective: string;
  target: string;
  scopeHosts: string[];
  roe: RulesOfEngagement;
  fullBattery?: boolean;
  targets?: TargetId[];
  localSandbox?: boolean;
} {
  return {
    mode: ctx.input.mode,
    objective: ctx.input.objective,
    target: ctx.input.target,
    scopeHosts: ctx.hosts,
    roe: ctx.input.roe,
    fullBattery: ctx.input.fullBattery,
    targets: ctx.input.targets,
    // Only actually relax discipline when the target is genuinely
    // loopback/private — matches the gate's invariant exactly. Leaving
    // --local-sandbox on does nothing against a real domain.
    localSandbox: ctx.config.localSandbox && ctx.hosts.every((h) => isPrivateOrLoopbackHost(h)),
  };
}



export /**
 * Commander-ordered focused re-recon. Used when the exploiter hits a wall
 * (mechanical wall detection) or when the coordinator redirects the
 * recon→exploit handoff. Writes to the shared target map as it goes.
 */
async function commanderRedirect(ctx: Ctx, reason: string): Promise<string> {
  ctx.events.append({
    phase: "exploit",
    actor: "coordinator",
    action: "redirect_rerecon",
    result: `Commander redirect (${ctx.redirects}/2): ${reason}`,
  });
  const mapLines = ctx.targetMap.map((t) => `${t.method} ${t.area}${t.authState ? ` [${t.authState}]` : ""}`).join("; ");
  const intel = await agentLoop(
    ctx,
    "recon",
    "recon",
    reconPrompt(promptCtx(ctx)),
    `COMMANDER REDIRECT — focused re-recon, not a full re-scan. ${reason}\n` +
      `Current shared target map (${ctx.targetMap.length} entries): ${mapLines || "(empty)"}.\n` +
      `Find NEW angles the exploiter has not tried: untested endpoints, parameters, methods, auth flows. ` +
      `Write every discovery to the shared target map with update_target_map as you go. ` +
      `End with a 5-line brief of the new angles.`,
    RECON_TOOLS,
    6,
  );
  ctx.events.append({ phase: "recon", actor: "recon", action: "rerecon_brief", result: intel.slice(0, 800) });
  return (
    `COMMANDER REDIRECT — re-recon complete (redirect ${ctx.redirects}/2 used). New angles:\n${intel.slice(0, 1200)}\n` +
    `The shared target map now has ${ctx.targetMap.length} entries (see [SHARED STATE]). Form fresh hypotheses from the new angles — do not re-probe cooled-down vectors.`
  );
}
