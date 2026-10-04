/**
 * Per-role model policy — the cost/latency brain of the router.
 *
 * v0.6 (DeepSeek only for now; Qwen stays registered for later reinstatement):
 *   coordinator → deepseek / deepseek-flash   (fast orchestration, tool use)
 *   recon       → deepseek / deepseek-flash   (cheap recon loops)
 *   exploiter   → deepseek / deepseek-v4-pro  (strongest reasoning: hypotheses,
 *                                              exploit chains, pivot decisions)
 *   reporter    → deepseek / deepseek-flash   (fast write-up)
 *
 * Rationale: recon burns the most tokens on the least thinking (listing
 * endpoints, reading headers, paging scan history) — flash keeps engagements
 * cheap. The exploiter is where the product's differentiator lives (dynamic
 * hypothesis-driven testing), so it gets the strongest reasoner. The
 * coordinator and reporter need speed and reliable tool use, not deep thought.
 *
 * Qwen (qwen3.8-max) was the exploiter's reasoner through v0.5; the operator
 * has asked to run DeepSeek-only for now and bring Qwen back later. The
 * provider stays registered in router.ts so switching back is a one-line
 * change here, not a re-integration.
 */

import type { AgentRole, RoleRoute } from "./types.js";
import { DEEPSEEK_MODELS } from "./providers/deepseek.js";

export const ROLE_MODEL_POLICY: Record<AgentRole, RoleRoute> = {
  coordinator: { provider: "deepseek", model: DEEPSEEK_MODELS.flash },
  recon: { provider: "deepseek", model: DEEPSEEK_MODELS.flash, reasoningEffort: "low" },
  exploiter: { provider: "deepseek", model: DEEPSEEK_MODELS.pro, reasoningEffort: "high" },
  reporter: { provider: "deepseek", model: DEEPSEEK_MODELS.flash },
};

/** Roles in a fixed, dependency-safe order for policy display. */
export const ROLE_ORDER: AgentRole[] = ["coordinator", "recon", "exploiter", "reporter"];
