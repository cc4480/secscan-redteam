/**
 * Payload-variant expansion types (v0.20.0).
 *
 * The 416 battery items are distinct attacker INTENTS. Competitors reach
 * "tens of thousands of attacks" by executing variants of each intent.
 * This module gives us honest variant depth: curated, reviewed payload
 * libraries — mechanical, never LLM-invented at runtime — each variant a
 * genuine execution through the same tools, rate limiter, denylists, and
 * proof bundles as its parent item.
 *
 * Counting honesty (the anti-AI-washing posture): reports distinguish
 * "N attack intents" from "M variant executions" — never merged into one
 * inflated number.
 */

/** Variant classes with curated payload libraries. */
export type VariantClass =
  | "sqli"
  | "xss"
  | "cmdi"
  | "ssti"
  | "xxe"
  | "traversal"
  | "ssrf"
  | "redirect"
  | "auth"
  | "headers";

export const VARIANT_CLASSES: VariantClass[] = [
  "sqli",
  "xss",
  "cmdi",
  "ssti",
  "xxe",
  "traversal",
  "ssrf",
  "redirect",
  "auth",
  "headers",
];

/** One curated payload. Libraries are static data — reviewed lists in code. */
export interface VariantPayload {
  /** Which library this came from. */
  kind: VariantClass;
  /** The payload. `{{CANARY}}` = operator canary host placeholder (agent substitutes). */
  payload: string;
  /** What evasion/shape this variant tests — the honest label. */
  whatItTests: string;
}

/** A payload offered to an agent for a specific battery item. */
export interface Variant extends VariantPayload {
  /** The battery item this variant was offered for (e.g. "SS-042"). */
  parentItemId: string;
  /** Stable index within the offered (capped) list — tag executions with it. */
  variantIndex: number;
}

/**
 * Per-item variant expansion progress, stored on the item's ledger verdict.
 * Set when variant_list opens expansion; the tracker owns the item's
 * disposition until exhausted, capped, or closed.
 */
export interface VariantProgress {
  /** Variant classes applicable to this item. */
  classes: VariantClass[];
  /** Total variants in the libraries (before cap). */
  librarySize: number;
  /** Effective per-item cap this engagement. */
  cap: number;
  /** Variants offered = min(librarySize, cap). */
  planned: number;
  /** Variant-tagged clean executions so far. */
  executed: number;
  /** Variants that confirmed a finding. */
  confirmed: number;
}

/** Aggregate counts for honest reporting. */
export interface VariantCounts {
  /** Distinct battery items (intents) in the ledger. */
  intents: number;
  /** Total variant-tagged executions. */
  variantExecutions: number;
  /** Variant executions that confirmed a finding. */
  variantConfirmed: number;
  /** Items with variant expansion opened. */
  itemsWithVariants: number;
  /** Items where the cap cut the library short. */
  itemsCapped: number;
}
