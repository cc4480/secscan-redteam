/**
 * Planning phase (v0.19.0 refactor — extracted from phases.ts).
 */
import { ABORT_TOOL, READ_TOOLS } from "../tools.js";
import { type Ctx } from "../context.js";
import { type PlanStep } from "../types.js";
import { agentLoop, promptCtx } from "../agents.js";
import { coordinatorPrompt } from "../prompts.js";
import { extractJsonBlock } from "../util.js";
import { lookupTechnique } from "../attack.js";
import { techniqueAllowed } from "../gate.js";

export async function planPhase(ctx: Ctx, critique?: string): Promise<void> {
  if (ctx.config.dryRunAgents) {
    ctx.plan = { mode: ctx.input.mode, objective: ctx.input.objective, adversaryProfile: "dry-run", steps: [] };
    ctx.events.updateState({ plan: ctx.plan });
    ctx.events.append({ phase: "plan", actor: "coordinator", action: "plan", result: "dry-run: planning skipped." });
    return;
  }
  const text = await agentLoop(
    ctx,
    "coordinator",
    "plan",
    coordinatorPrompt(promptCtx(ctx)),
    `Authorization is proven for ${ctx.domain} (${ctx.verificationProof}). Produce the operation plan as JSON now: { "adversaryProfile": "...", "steps": [{ "phase": "recon|exploit", "attackId": "Txxxx", "description": "...", "stealthNote": "..." }] }.` +
      (critique ? `\n\nCOMMANDER REDIRECT on the previous plan: ${critique}. Revise the plan accordingly.` : ""),
    [...READ_TOOLS, ABORT_TOOL],
    4,
  );
  const parsed = extractJsonBlock(text) as { adversaryProfile?: string; steps?: PlanStep[] } | null;
  const steps: PlanStep[] = [];
  if (parsed && Array.isArray(parsed.steps)) {
    for (const s of parsed.steps) {
      const attackId = typeof s.attackId === "string" ? s.attackId.toUpperCase() : undefined;
      if (attackId && !lookupTechnique(attackId)) {
        ctx.events.append({ phase: "plan", actor: "runner", action: "plan_step_rejected", attackId, result: `Unknown ATT&CK ID ${attackId} — step rejected.` });
        continue;
      }
      if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
        ctx.events.append({ phase: "plan", actor: "runner", action: "plan_step_rejected", attackId, result: `Technique ${attackId} excluded by ROE/mode — step rejected.` });
        continue;
      }
      const step: PlanStep = {
        phase: s.phase === "exploit" ? "exploit" : "recon",
        attackId,
        description: String(s.description ?? "").slice(0, 500),
        stealthNote: typeof s.stealthNote === "string" ? s.stealthNote.slice(0, 300) : undefined,
      };
      steps.push(step);
      ctx.events.append({ phase: "plan", actor: "coordinator", action: "plan_step", attackId, result: step.description });
    }
  }
  ctx.plan = {
    mode: ctx.input.mode,
    objective: ctx.input.objective,
    adversaryProfile: typeof parsed?.adversaryProfile === "string" ? parsed.adversaryProfile : "unspecified",
    steps,
  };
  ctx.events.updateState({ plan: ctx.plan });
}

// ---------------------------------------------------------------------------
// Coordinator command authority: sign-offs, redirects, abort (Megazord protocol)
// ---------------------------------------------------------------------------

/**
 * Commander-ordered focused re-recon. Used when the exploiter hits a wall
 * (mechanical wall detection) or when the coordinator redirects the
 * recon→exploit handoff. Writes to the shared target map as it goes.
 */

/** Commander-ordered focused exploitation (redirect on the exploit→report handoff). */
