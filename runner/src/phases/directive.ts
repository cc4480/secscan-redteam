/**
 * Coordinator directive synthesis (v0.19.0 refactor — extracted from phases.ts).
 */
import { COMMAND_TOOLS } from "../tools.js";
import { type Ctx } from "../context.js";
import { agentLoop, promptCtx } from "../agents.js";
import { coordinatorPrompt } from "../prompts.js";
import { extractJsonBlock } from "../util.js";
import { validateTasks } from "./tasks.js";
import { type CoordinatorDirective } from "./tasks.js";

export async function coordinatorDirective(
  ctx: Ctx,
  kind: "decompose" | "replan",
  context: string,
): Promise<CoordinatorDirective> {
  const cap = ctx.input.mode === "black" ? 1 : 3;
  const head =
    kind === "decompose"
      ? `DECOMPOSE — break the operation into small discrete tasks (one task, one specialist, one objective). ` +
        `Fan out independent hypotheses${ctx.input.mode === "black" ? " ONE AT A TIME (black mode: stealth, strictly sequential)" : " in parallel (red mode: up to 3 per round)"}. ` +
        `Put promising leads in their own dedicated tasks. Include registry-informed tasks (fuse what worked before). ` +
        `Tasks must span all three battery categories (logic | functionality | validation) before finish.`
      : `RE-PLAN — the last batch completed. Re-evaluate from the fresh observations: PIVOT to new angles, ESCALATE a promising lead with a dedicated deeper task, ` +
        `GO STEALTHY on detection signals, BACK OFF cooled-down vectors, SPAWN MORE HELP across independent surface. Never coast on the earlier plan.`;
  const text = await agentLoop(
    ctx,
    "coordinator",
    "exploit",
    coordinatorPrompt(promptCtx(ctx)),
    `${head}\n\nReturn ONLY a JSON block: {"tasks": [<at most ${cap} task(s) this round>, {"kind": "probe|recon", "brief": "<1-2 sentences>", "attackId": "<ATT&CK, optional>", "category": "<logic|functionality|validation — probe tasks only>", "batteryItem": "<battery item ID this task covers, e.g. SS-042 — pick from the pending list>", "maxTurns": 6}], "finish": <true only when the objective is met AND (battery complete — every battery item verdict-recorded, none pending — OR probe budget exhausted OR no applicable surface declared with reasons)>, "note": "<what changed and why, one line>"}\n\n${context}`,
    COMMAND_TOOLS,
    3,
  );
  const parsed = extractJsonBlock(text) as {
    tasks?: Array<Record<string, unknown>>;
    finish?: boolean;
    note?: string;
  } | null;
  const tasks = validateTasks(ctx, Array.isArray(parsed?.tasks) ? parsed!.tasks! : [], cap);
  const finish = parsed?.finish === true;
  const note = typeof parsed?.note === "string" ? parsed.note.slice(0, 300) : text.slice(0, 300);
  ctx.events.append({
    phase: "exploit",
    actor: "coordinator",
    action: kind === "decompose" ? "decompose" : "replan",
    result: `${note} → ${tasks.length} task(s)${finish ? ", FINISH requested" : ""}`,
  });
  return { tasks, finish, note };
}

