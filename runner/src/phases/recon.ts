/**
 * Reconnaissance phase (v0.19.0 refactor — extracted from phases.ts).
 */
import { type Ctx } from "../context.js";
import { RECON_TOOLS } from "../tools.js";
import { agentLoop, promptCtx } from "../agents.js";
import { join } from "node:path";
import { reconPrompt } from "../prompts.js";

export async function reconPhase(ctx: Ctx): Promise<string> {
  if (ctx.config.dryRunAgents) {
    ctx.events.append({ phase: "recon", actor: "recon", action: "recon_brief", result: "dry-run: recon skipped." });
    return "dry-run brief";
  }
  const brief = await agentLoop(
    ctx,
    "recon",
    "recon",
    reconPrompt(promptCtx(ctx)),
    `Begin reconnaissance of ${ctx.input.target}. In-scope hosts: ${ctx.hosts.join(", ")}. ` +
      (ctx.input.mode === "red"
        ? "Use scan_url with aggressive=true for the active tier."
        : "Start with the passive tier (scan_url without aggressive). Escalate only if the plan calls for it.") +
      ` Deliver the attack-surface brief when done.`,
    RECON_TOOLS,
    ctx.config.maxReconTurns,
  );
  ctx.events.append({ phase: "recon", actor: "recon", action: "recon_brief", result: brief.slice(0, 1200) });
  // Target fingerprint: the runner parses the FINGERPRINT: line from the brief
  // (format: FINGERPRINT: stack=<csv>; appType=<...>; notes=<one line>).
  const fp = brief.match(/FINGERPRINT:\s*stack=([^;]*);\s*appType=([^;]*);\s*notes=([^\n]*)/i);
  if (fp) {
    const stack = fp[1]!.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
    const appType = fp[2]!.trim() || "unknown";
    ctx.fingerprint = { host: ctx.domain, stack, appType, notes: fp[3]!.trim().slice(0, 200) || undefined };
    ctx.events.append({ phase: "recon", actor: "runner", action: "fingerprint", result: JSON.stringify(ctx.fingerprint) });
  }
  return brief;
}

// ---------------------------------------------------------------------------
// Dynamic orchestration: decompose → delegate → observe → re-plan.
//
// The coordinator never runs a long static plan. It breaks the operation into
// small discrete tasks; the runner validates each task against the cyber
// constraints (ROE, ATT&CK catalog, battery) and executes it by feeding it to
// the foundation (a bounded completeForRole loop = one specialist subagent).
// After every observation round the coordinator re-evaluates: pivot,
// escalate, go stealthy, back off, or spawn more help.
// ---------------------------------------------------------------------------

/** A discrete unit of work: one task, one specialist, one objective. */
