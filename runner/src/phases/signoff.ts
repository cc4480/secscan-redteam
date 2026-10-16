/**
 * Coordinator sign-off gate (v0.19.0 refactor — extracted from phases.ts).
 */
import { COMMAND_TOOLS } from "../tools.js";
import { type Ctx, HaltError } from "../context.js";
import { type SignOffTransition, focusedExploit } from "./exploit-one.js";
import { planPhase } from "./plan.js";
import { agentLoop, commanderRedirect, promptCtx } from "../agents.js";
import { coordinatorPrompt } from "../prompts.js";
import { ledgerSummary } from "../coverage/items.js";
import { batteryGate } from "./batterygate.js";

/**
 * How many extra exploit rounds the battery gate may force before it stops.
 * Bounded so a genuinely unreachable item cannot spin the engagement forever;
 * the report records the battery as NOT COMPLETE when the bound is hit.
 */
const MAX_INCOMPLETE_ROUNDS = 3;

export async function coordinatorSignOff(
  ctx: Ctx,
  transition: SignOffTransition,
  payload: string,
  incompleteRounds = 0,
): Promise<void> {
  if (ctx.config.dryRunAgents) {
    ctx.events.append({ phase: "plan", actor: "coordinator", action: "signoff", result: `${transition} auto-approved (dry-run).` });
    return;
  }
  const text = await agentLoop(
    ctx,
    "coordinator",
    "plan",
    coordinatorPrompt(promptCtx(ctx)) +
      `\n\n## SIGN-OFF DUTY — current task\nYou are signing off the phase transition: ${transition}.\n` +
      `Review the material below. Your reply must start with EXACTLY one of:\n` +
      `- \`SIGN-OFF: <one-line summary of what is approved>\` — the operation proceeds.\n` +
      `- \`REDIRECT: <what must change and which specialist does it>\` — at most 2 redirects per engagement (used: ${ctx.redirects}).\n` +
      `You may also call abort_engagement on any stop condition, ROE violation, or gate-bypass attempt.\n` +
      `Confirm role discipline in one line per specialist, or correct them.`,
    `Transition awaiting sign-off: ${transition}\n\n${payload}`,
    COMMAND_TOOLS,
    3,
  );
  ctx.events.append({ phase: "plan", actor: "coordinator", action: "signoff_review", result: `${transition}: ${text.slice(0, 400)}` });
  if (/^\s*REDIRECT\s*:/im.test(text)) {
    if (ctx.redirects >= 2) {
      throw new HaltError(`coordinator withheld sign-off for ${transition} after 2 redirects — engagement halted`);
    }
    const reason = (text.match(/^\s*REDIRECT\s*:\s*([\s\S]*)/im)?.[1] ?? "commander ordered redirect").trim().slice(0, 500);
    ctx.redirects++;
    ctx.events.append({ phase: "plan", actor: "coordinator", action: "signoff_redirect", result: `${transition}: ${reason}` });
    if (transition === "recon→exploit") {
      await commanderRedirect(ctx, `Sign-off redirect for ${transition}: ${reason}`);
    } else if (transition === "exploit→report") {
      await focusedExploit(ctx, reason);
    } else {
      await planPhase(ctx, reason);
    }
    return coordinatorSignOff(ctx, transition, payload, incompleteRounds);
  }
  if (!/^\s*SIGN-OFF\s*:/im.test(text)) {
    throw new HaltError(`coordinator did not issue a clear sign-off for ${transition} — engagement halted (fail closed)`);
  }

  // The battery gate: a coordinator's approval is not sufficient while in-scope
  // work is still pending and there is budget left to do it. The decision itself
  // lives in batterygate.ts so it is tested directly rather than through a
  // mocked agent loop — see that file for why prompt wording was not enough.
  if (transition === "exploit→report" && ctx.input.fullBattery) {
    const decision = batteryGate({
      transition,
      fullBattery: ctx.input.fullBattery,
      pending: ledgerSummary(ctx.itemLedger).pending,
      actions: ctx.actions,
      maxActions: ctx.config.maxActions,
      rounds: incompleteRounds,
      maxRounds: MAX_INCOMPLETE_ROUNDS,
    });
    if (decision.action === "refuse-incomplete") {
      ctx.events.append({
        phase: "plan",
        actor: "runner",
        action: "signoff_refused_incomplete",
        result:
          `Sign-off refused: ${decision.pending} in-scope battery item(s) still pending a verdict and the action budget ` +
          `is not exhausted (${ctx.actions}/${ctx.config.maxActions}). Round ${incompleteRounds + 1} of ` +
          `${MAX_INCOMPLETE_ROUNDS}: sending the exploiter back to work them.`,
      });
      await focusedExploit(
        ctx,
        `Battery incomplete — ${decision.pending} in-scope items carry no verdict. Probe them, or record why not.`,
      );
      return coordinatorSignOff(ctx, transition, payload, incompleteRounds + 1);
    }
    if (decision.action === "approve-incomplete") {
      ctx.events.append({
        phase: "plan",
        actor: "runner",
        action: "signoff_allowed_incomplete",
        result:
          `${decision.pending} in-scope item(s) still pending, but ${decision.why}. ` +
          `Sign-off allowed; the report records the battery as NOT COMPLETE.`,
      });
    }
  }
  ctx.events.append({ phase: "plan", actor: "coordinator", action: "signoff", result: `${transition} approved.` });
}

