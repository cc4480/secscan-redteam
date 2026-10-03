/**
 * Honest variant counting for reports (v0.20.0).
 *
 * The anti-AI-washing posture: "418 attack intents" and "N variant
 * executions" are reported as TWO numbers, never merged into one
 * inflated "attacks" figure. A competitor-style single number is
 * exactly what we refuse to print.
 */
import type { ItemVerdict } from "../coverage/items.js";
import type { VariantCounts } from "./types.js";

export function countVariants(ledger: Map<string, ItemVerdict>): VariantCounts {
  let variantExecutions = 0;
  let variantConfirmed = 0;
  let itemsWithVariants = 0;
  let itemsCapped = 0;
  for (const v of ledger.values()) {
    const vp = v.variants;
    if (!vp) continue;
    itemsWithVariants++;
    variantExecutions += vp.executed;
    variantConfirmed += vp.confirmed;
    // The cap cut the library short: executed hit the cap below library size.
    if (vp.executed >= vp.cap && vp.cap < vp.librarySize) itemsCapped++;
  }
  return {
    intents: ledger.size,
    variantExecutions,
    variantConfirmed,
    itemsWithVariants,
    itemsCapped,
  };
}

/** One-line honest summary for the battery coverage line. */
export function variantCountLine(c: VariantCounts): string {
  return (
    `Variant executions: ${c.variantExecutions} across ${c.itemsWithVariants} items ` +
    `(${c.variantConfirmed} confirmed via variants${c.itemsCapped > 0 ? `, ${c.itemsCapped} items hit the per-item cap` : ""}). ` +
    `Intents (${c.intents}) and executions are counted separately — never merged.`
  );
}

/** Per-item variant progress suffix for the reconciliation list. */
export function variantProgressSuffix(v: ItemVerdict): string {
  const vp = v.variants;
  if (!vp) return "";
  return ` [variants ${vp.executed}/${vp.planned} executed, ${vp.confirmed} confirmed]`;
}
