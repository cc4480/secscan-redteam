/**
 * Operator-facing agent docs (agents/*.md) rendered from the executing
 * prompt code — the single source of truth for role behavior.
 *
 * The markdown files are NOT hand-maintained: scripts/gen-agent-prompts.mjs
 * writes them from renderAgentMarkdown() below, and
 * runner/test/prompts-drift.test.ts fails loudly if a committed file drifts
 * from what the code renders. Edit behavior in the sibling prompt modules
 * (coordinator.ts, recon.ts, exploiter.ts, reporter.ts, shared.ts), then
 * regenerate; never edit agents/*.md directly, and never use this renderer
 * as a back door to change behavior.
 *
 * The docs render with a canonical, engagement-independent context (RED
 * mode, placeholder objective/target/scope, default ROE posture) so they
 * describe the roles, not any engagement. Live runs substitute the real
 * context — BLACK mode briefs, ROE, target batteries, the sandbox posture —
 * through the same functions.
 */

import { coordinatorPrompt } from "./coordinator.js";
import { exploiterPrompt } from "./exploiter.js";
import { reconPrompt } from "./recon.js";
import { reporterPrompt } from "./reporter.js";
import type { PromptContext } from "./shared.js";

export const AGENT_DOC_ROLES = ["coordinator", "recon", "exploiter", "reporter"] as const;
export type AgentDocRole = (typeof AGENT_DOC_ROLES)[number];

const PROMPT_BY_ROLE: Record<AgentDocRole, (ctx: PromptContext) => string> = {
  coordinator: coordinatorPrompt,
  recon: reconPrompt,
  exploiter: exploiterPrompt,
  reporter: reporterPrompt,
};

/**
 * Canonical context used ONLY to render the operator-facing docs: RED mode,
 * placeholder objective/target/scope, default rule-of-engagement posture
 * (mode-default exclusions, no blackout windows, non-sandbox discipline).
 */
export function canonicalAgentDocContext(): PromptContext {
  return {
    mode: "red",
    objective: "<engagement objective>",
    target: "<TARGET>",
    scopeHosts: ["<in-scope hosts>"],
    roe: { scope: ["<in-scope hosts>"] },
  };
}

/** Banner stamped at the top of every generated agents/*.md file. */
export const AGENT_DOC_BANNER = `<!--
  GENERATED FILE — do not edit by hand.
  Single source of truth: runner/src/prompts/ (the code the runner executes).
  Regenerate: npm run build && node scripts/gen-agent-prompts.mjs
  Drift guard: runner/test/prompts-drift.test.ts fails if this file disagrees
  with what the code renders.
-->`;

/** The exact bytes agents/<role>.md must contain. */
export function renderAgentMarkdown(role: AgentDocRole): string {
  return `${AGENT_DOC_BANNER}\n\n${PROMPT_BY_ROLE[role](canonicalAgentDocContext())}\n`;
}
