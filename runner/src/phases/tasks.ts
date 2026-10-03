/**
 * Coordinator task model: TaskDef/TaskResult, runTask, runBatch, validateTasks (v0.19.0 refactor — extracted from phases.ts).
 */
import { BATTERY_CATEGORIES, type BatteryCategory } from "../battery.js";
import { type Ctx, HaltError } from "../context.js";
import { EXPLOIT_TOOLS, RECON_TOOLS } from "../tools.js";
import { agentLoop, promptCtx } from "../agents.js";
import { lookupTechnique } from "../attack.js";
import { mergeVerdictBlock } from "../dispatch.js";
import { taskPrompt } from "../prompts.js";
import { techniqueAllowed } from "../gate.js";

export interface TaskDef {
  id: string;
  kind: "probe" | "recon";
  brief: string;
  attackId?: string;
  category?: BatteryCategory;
  /** Battery item ID this task covers (v0.18.0) — surfaced to the specialist via taskPrompt. */
  batteryItem?: string;
  maxTurns: number;
}

export interface TaskResult {
  task: TaskDef;
  summary: string;
  probesBefore: number;
  probesAfter: number;
  findingsBefore: number;
  findingsAfter: number;
  killedBefore: number;
  killedAfter: number;
}

/**
 * "Spawn a subagent": execute one discrete task as a bounded foundation loop
 * with a task-scoped specialist prompt. Fresh context, cyber task definition.
 */
export async function runTask(ctx: Ctx, task: TaskDef): Promise<TaskResult> {
  const role = task.kind === "recon" ? "recon" : "exploiter";
  const tools = task.kind === "recon" ? RECON_TOOLS : EXPLOIT_TOOLS;
  const probesBefore = ctx.probesUsed;
  const findingsBefore = ctx.liveFindings.length;
  const killedBefore = ctx.killedLive.length;
  ctx.events.append({
    phase: "exploit",
    actor: "coordinator",
    action: "task_spawn",
    target: task.id,
    attackId: task.attackId,
    result: `[${task.kind}] ${task.brief.slice(0, 200)}${task.category ? ` (${task.category})` : ""}`,
  });
  const summary = await agentLoop(
    ctx,
    role,
    "exploit",
    taskPrompt(promptCtx(ctx), task),
    "Execute the task now.",
    tools,
    task.maxTurns,
  );
  mergeVerdictBlock(ctx, summary);
  const verdictNote =
    `probes +${ctx.probesUsed - probesBefore}, ` +
    `confirmed +${ctx.liveFindings.length - findingsBefore}, killed +${ctx.killedLive.length - killedBefore}`;
  ctx.events.append({
    phase: "exploit",
    actor: role,
    action: "task_complete",
    target: task.id,
    attackId: task.attackId,
    result: `${verdictNote}. ${summary.slice(0, 600)}`,
  });
  return {
    task,
    summary,
    probesBefore,
    probesAfter: ctx.probesUsed,
    findingsBefore,
    findingsAfter: ctx.liveFindings.length,
    killedBefore,
    killedAfter: ctx.killedLive.length,
  };
}

/**
 * Fan-out with a concurrency cap: red fans out independent tasks in parallel,
 * black runs strictly one at a time (stealth). HaltError always propagates.
 */
export async function runBatch(ctx: Ctx, tasks: TaskDef[], cap: number): Promise<TaskResult[]> {
  const results: TaskResult[] = [];
  for (let i = 0; i < tasks.length; i += cap) {
    const chunk = tasks.slice(i, i + cap);
    const settled = await Promise.allSettled(chunk.map((t) => runTask(ctx, t)));
    for (let j = 0; j < settled.length; j++) {
      const s = settled[j]!;
      if (s.status === "fulfilled") {
        results.push(s.value);
      } else {
        if (s.reason instanceof HaltError) throw s.reason;
        ctx.events.append({
          phase: "exploit",
          actor: "runner",
          action: "task_failed",
          target: chunk[j]!.id,
          result: `Task failed: ${String(s.reason).slice(0, 300)}`,
        });
      }
    }
  }
  return results;
}

let taskCounter = 0;

/**
 * Cyber-layer task validation: the coordinator proposes, the runner disposes.
 * Unknown/excluded ATT&CK IDs and invalid categories are rejected (with an
 * event) — the coordinator re-plans without them.
 */
export function validateTasks(ctx: Ctx, raw: Array<Record<string, unknown>>, cap: number): TaskDef[] {
  const tasks: TaskDef[] = [];
  const overCap = raw.slice(cap);
  for (const r of overCap) {
    ctx.events.append({
      phase: "exploit",
      actor: "runner",
      action: "task_rejected",
      result: `Task over concurrency cap (${cap}/round): re-plan it next round. Brief was: ${String(r["brief"] ?? "").slice(0, 120)}`,
    });
  }
  for (const r of raw.slice(0, cap)) {
    const kind = r["kind"] === "recon" ? "recon" : "probe";
    const brief = String(r["brief"] ?? "").trim().slice(0, 800);
    if (!brief) continue;
    let attackId = typeof r["attackId"] === "string" ? r["attackId"].toUpperCase() : undefined;
    if (attackId && (!lookupTechnique(attackId) || !techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe))) {
      ctx.events.append({
        phase: "exploit",
        actor: "runner",
        action: "task_rejected",
        attackId,
        result: `Task rejected: attackId ${attackId} unknown or ROE-excluded. Brief was: ${brief.slice(0, 120)}`,
      });
      continue;
    }
    let category: BatteryCategory | undefined;
    if (kind === "probe") {
      const c = String(r["category"] ?? "").toLowerCase();
      if (!(BATTERY_CATEGORIES as string[]).includes(c)) {
        ctx.events.append({
          phase: "exploit",
          actor: "runner",
          action: "task_rejected",
          result: `Task rejected: probe task needs a battery category (logic|functionality|validation). Brief was: ${brief.slice(0, 120)}`,
        });
        continue;
      }
      category = c as BatteryCategory;
    }
    const maxTurns = Math.min(Math.max(Number(r["maxTurns"]) || 6, 2), 8);
    const batteryItem = typeof r["batteryItem"] === "string" && r["batteryItem"].trim() ? r["batteryItem"].trim().slice(0, 40) : undefined;
    tasks.push({ id: `task-${++taskCounter}`, kind, brief, attackId, category, batteryItem, maxTurns });
  }
  return tasks;
}

export interface CoordinatorDirective {
  tasks: TaskDef[];
  finish: boolean;
  note: string;
}

/**
 * One coordinator command turn: DECOMPOSE (initial) or RE-PLAN (after every
 * observation round). Returns validated tasks or a finish decision.
 */
