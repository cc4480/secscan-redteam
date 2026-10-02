/**
 * Per-role model policy — the cost/latency brain of the router.
 *
 * v0.5 (DeepSeek + Qwen; model IDs verified against the live APIs):
 *   coordinator → deepseek / deepseek-flash   (fast orchestration, tool use)
 *   recon       → deepseek / deepseek-flash   (cheap recon loops)
 *   exploiter   → qwen / qwen3.8-max          (strongest reasoning: hypotheses,
 *                                              exploit chains, pivot decisions)
 *   reporter    → deepseek / deepseek-flash   (fast write-up)
 *
 * Rationale: recon burns the most tokens on the least thinking (listing
 * endpoints, reading headers, paging scan history) — flash keeps engagements
 * cheap. The exploiter is where the product's differentiator lives (dynamic
 * hypothesis-driven testing), so it gets the strongest reasoner. The
 * coordinator and reporter need speed and reliable tool use, not deep thought.
 */

import type { AgentRole, RoleRoute } from "./types.js";
import { DEEPSEEK_MODELS } from "./providers/deepseek.js";
import { QWEN_MODELS } from "./providers/qwen.js";

export const ROLE_MODEL_POLICY: Record<AgentRole, RoleRoute> = {
  coordinator: { provider: "deepseek", model: DEEPSEEK_MODELS.flash },
  recon: { provider: "deepseek", model: DEEPSEEK_MODELS.flash, reasoningEffort: "low" },
  exploiter: { provider: "qwen", model: QWEN_MODELS.reasoning, reasoningEffort: "high" },
  reporter: { provider: "deepseek", model: DEEPSEEK_MODELS.flash },
};

/** Roles in a fixed, dependency-safe order for policy display. */
export const ROLE_ORDER: AgentRole[] = ["coordinator", "recon", "exploiter", "reporter"];
