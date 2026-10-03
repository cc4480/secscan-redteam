/**
 * variant_list agent tool definition (v0.20.0).
 *
 * Tier 0 bookkeeping: returns curated payload variants for a battery
 * item's attack class — never fires anything itself. The agent executes
 * variants through the normal tools with batteryItem + variantIndex tagged;
 * the per-item cap is enforced mechanically in dispatch.
 */
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";

export const VARIANT_LIST_TOOL: JsonSchemaTool = {
  name: "variant_list",
  description:
    "List curated payload variants for a battery item's attack class (SQLi/XSS/command injection/SSTI/XXE/traversal/SSRF/redirect/auth-param/header matrices). Mechanical, Tier 0 — returns payloads, never fires. Each variant carries variantIndex: execute it via the normal tools with batteryItem + variantIndex tagged. Per-item variant cap enforced mechanically (default 25 staging / 10 production; --max-variants / REDTEAM_MAX_VARIANTS). Args: batteryItem (e.g. \"SS-042\"); closeExpansion (true = done expanding: record executed-clean with honest variant counts).",
  parameters: {
    type: "object",
    properties: {
      batteryItem: {
        type: "string",
        description: 'Battery item ID to expand (e.g. "SS-042").',
      },
      closeExpansion: {
        type: "boolean",
        description: "true = close variant expansion early; the report shows exactly what ran.",
      },
    },
    required: ["batteryItem"],
  },
};
