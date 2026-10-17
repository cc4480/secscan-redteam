/**
 * Dispatch policy gate (v0.34.0) — the operator controls that sit between the
 * mechanical safety core and the tool handlers.
 *
 * Extracted from dispatch/router.ts so the dispatcher stays readable and under
 * the 300-line file budget, and so the gate can be tested on its own.
 *
 * Order per call:
 *   1. operator policy (allow/deny rules, deny-wins) — a denied call sends nothing
 *   2. PreToolUse hooks (allow / deny / modify)
 *   3. handler
 *   4. PostToolUse hooks (may replace the result)
 *
 * Every evaluation is appended as an individual audit event — a policy decision
 * is never silent.
 */

import type { Ctx } from "../context.js";
import type { EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import type { DispatchResult } from "./types.js";
import { checkToolPolicy } from "../policy/rules.js";

export interface DispatchGate {
  /** Set when the call must not reach the handler. */
  denial?: DispatchResult;
  /** The call to execute (may carry hook-modified arguments). */
  call: ToolCallRequest;
}

/** Policy + pre-hooks. Never sends anything; returns a denial or the call to run. */
export async function preDispatchGate(
  ctx: Ctx,
  phase: EngagementPhase,
  call: ToolCallRequest,
  host: string | undefined,
): Promise<DispatchGate> {
  const args = (call.arguments ?? {}) as Record<string, unknown>;

  if (ctx.policy) {
    const pol = checkToolPolicy(ctx.policy, call.name, host, args);
    if (!pol.allowed) {
      ctx.events.append({
        phase,
        actor: "runner",
        action: "policy_denied",
        target: host,
        result: `DENIED by policy: ${pol.reason}`,
      });
      return { denial: { result: `DENIED by policy: ${pol.reason}`, target: host }, call };
    }
  }

  if (!ctx.hooks) return { call };

  const pre = await ctx.hooks.runPre(call.name, args, host);
  for (const ev of pre.evaluations) {
    ctx.events.append({
      phase,
      actor: "runner",
      action: "hook_evaluated",
      target: host,
      result:
        `${ev.phase}:${ev.name} ${ev.decision} ${ev.latencyMs}ms` +
        `${ev.timedOut ? " (timeout)" : ""}${ev.reason ? ` — ${ev.reason}` : ""}`,
    });
  }
  if (!pre.allowed) {
    return { denial: { result: `DENIED by hook: ${pre.reason ?? "denied"}`, target: host }, call };
  }
  if (pre.args !== args) return { call: { ...call, arguments: pre.args } };
  return { call };
}

/** Post-hooks. May replace the handler's result (e.g. scrub a secret). */
export async function postDispatchHooks(
  ctx: Ctx,
  phase: EngagementPhase,
  call: ToolCallRequest,
  result: DispatchResult,
  host: string | undefined,
): Promise<DispatchResult> {
  if (!ctx.hooks) return result;
  const post = await ctx.hooks.runPost(call.name, (call.arguments ?? {}) as Record<string, unknown>, result.result, host);
  for (const ev of post.evaluations) {
    ctx.events.append({
      phase,
      actor: "runner",
      action: "hook_evaluated",
      target: host,
      result: `${ev.phase}:${ev.name} ${ev.decision} ${ev.latencyMs}ms${ev.timedOut ? " (timeout)" : ""}`,
    });
  }
  return post.result === result.result ? result : { ...result, result: post.result };
}
