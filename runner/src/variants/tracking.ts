/**
 * Variant execution tracking (v0.20.0) — per-engagement, mechanical.
 *
 * The flow:
 *  1. Agent calls variant_list(batteryItem) → startVariantExpansion opens
 *     expansion on the item's ledger verdict (reopening executed-clean →
 *     pending for deeper testing; executed-clean is not a final
 *     disposition, so the move is allowed).
 *  2. Agent executes variants via the normal tools with batteryItem +
 *     variantIndex tagged. checkVariantCap denies past the cap BEFORE any
 *     packet — one item can't spray.
 *  3. Each clean variant execution → recordVariantExecution increments;
 *     when executed >= planned (min(librarySize, cap)) the item settles to
 *     executed-clean with the honest counts.
 *  4. Agent may close early via variant_list(closeExpansion: true) — the
 *     report shows exactly what ran.
 *  5. record_finding with a variant-tagged batteryItem → confirmed (and
 *     variants.confirmed++).
 *
 * While expansion is open, recordItemAttempt's plain executed-clean flip
 * is skipped (see dispatch/verdicts.ts) — the tracker owns the disposition.
 */
import type { Ctx } from "../context.js";
import type { EngagementPhase } from "../types.js";
import { TARGET_PROFILES, type TargetId } from "../targets/index.js";
import type { TargetBatteryItem } from "../targets/types.js";
import { resolveItemKey, setDisposition, type ItemVerdict } from "../coverage/items.js";
import type { Variant, VariantClass, VariantPayload, VariantProgress } from "./types.js";
import { buildVariantsForClasses, classifyItem } from "./classify.js";

/** Defaults: 25 variants/item staging, 10 production (lower blast radius). */
export const DEFAULT_VARIANT_CAP_STAGING = 25;
export const DEFAULT_VARIANT_CAP_PRODUCTION = 10;

export function resolveVariantCap(
  environment: "staging" | "production",
  configured?: number,
): number {
  if (configured !== undefined && Number.isFinite(configured) && configured > 0) {
    return Math.floor(configured);
  }
  return environment === "production" ? DEFAULT_VARIANT_CAP_PRODUCTION : DEFAULT_VARIANT_CAP_STAGING;
}

/** Find the battery item for a ledger key ("secscan:SS-042"). */
export function findBatteryItem(key: string): TargetBatteryItem | undefined {
  const m = key.match(/^([a-z]+):([A-Z]{2}-\d{3})$/);
  if (!m) return undefined;
  const profile = TARGET_PROFILES[m[1] as TargetId];
  if (!profile) return undefined;
  return profile.battery.find((b) => b.id === m[2]);
}

/** True while an item's variant expansion is open and unexhausted. */
export function hasActiveVariantExpansion(
  ledger: Map<string, ItemVerdict>,
  key: string,
): boolean {
  const vp = ledger.get(key)?.variants;
  return !!vp && vp.executed < vp.planned;
}

export interface ExpansionOpened {
  variants: Variant[];
  classes: VariantClass[];
  librarySize: number;
  cap: number;
  reopened: boolean;
}

/**
 * Open variant expansion for an item. Idempotent: calling twice returns
 * the same capped list — progress is NEVER reset.
 */
export function startVariantExpansion(ctx: Ctx, key: string, phase: EngagementPhase): ExpansionOpened {
  const v = ctx.itemLedger.get(key);
  if (!v) throw new Error(`unknown battery item key "${key}"`);
  const item = findBatteryItem(key);
  if (!item) throw new Error(`no battery item for key "${key}"`);
  if (v.variants) {
    const again = buildVariantsForClasses(v.variants.classes)
      .slice(0, v.variants.cap)
      .map((p, i) => toVariant(p, item.id, i));
    return { variants: again, classes: v.variants.classes, librarySize: v.variants.librarySize, cap: v.variants.cap, reopened: false };
  }
  const classes = classifyItem(item);
  const cap = ctx.variantCap;
  const all = buildVariantsForClasses(classes);
  if (all.length === 0) {
    // No curated library for this item's attack class — the item
    // reconciles normally; the ledger is untouched.
    return { variants: [], classes, librarySize: 0, cap, reopened: false };
  }
  const planned = all.slice(0, cap).map((p, i) => toVariant(p, item.id, i));
  let reopened = false;
  if (v.disposition === "executed-clean") {
    // Deeper testing reopens the item — executed-clean is not final.
    setDisposition(ctx.itemLedger, key, "pending", { reason: "Variant expansion opened — deeper testing in progress" });
    reopened = true;
  }
  v.variants = {
    classes,
    librarySize: all.length,
    cap,
    planned: planned.length,
    executed: 0,
    confirmed: 0,
  };
  ctx.events.append({
    phase,
    actor: "runner",
    action: "variant_expansion_opened",
    target: key,
    result: `${planned.length} variants offered (library ${all.length}, cap ${cap}, classes: ${classes.join(",") || "none"})${reopened ? " — item reopened from executed-clean" : ""}`,
  });
  return { variants: planned, classes, librarySize: all.length, cap, reopened };
}

function toVariant(p: VariantPayload, parentItemId: string, variantIndex: number): Variant {
  return { ...p, parentItemId, variantIndex };
}

/**
 * Cap check — call BEFORE dispatch. Returns a DENIED message when a
 * variant-tagged call would exceed the item's cap, else undefined.
 */
export function checkVariantCap(
  ledger: Map<string, ItemVerdict>,
  args: Record<string, unknown>,
): string | undefined {
  const vIdx = args["variantIndex"];
  const rawItem = typeof args["batteryItem"] === "string" ? args["batteryItem"].trim() : "";
  if (typeof vIdx !== "number" || !rawItem) return undefined;
  const key = resolveItemKey(rawItem, typeof args["targetProfile"] === "string" ? args["targetProfile"] : undefined);
  if (!key) return undefined;
  const vp = ledger.get(key)?.variants;
  if (!vp) return undefined;
  if (vp.executed >= vp.cap) {
    return (
      `DENIED: variant cap reached for ${key} (${vp.executed}/${vp.cap} variants executed). ` +
      `Record your verdict for this item — the battery counts it as variant-capped, reported honestly. ` +
      `Further variant-tagged executions are refused mechanically.`
    );
  }
  return undefined;
}

/**
 * Record a clean variant-tagged execution. Settles the item to
 * executed-clean when its variants are exhausted (or the cap cut the
 * library short) — with the honest counts in the reason.
 */
export function recordVariantExecution(
  ctx: Ctx,
  args: Record<string, unknown>,
  phase: EngagementPhase,
): void {
  const vIdx = args["variantIndex"];
  const rawItem = typeof args["batteryItem"] === "string" ? args["batteryItem"].trim() : "";
  if (typeof vIdx !== "number" || !rawItem) return;
  const key = resolveItemKey(rawItem, typeof args["targetProfile"] === "string" ? args["targetProfile"] : undefined);
  if (!key) return;
  const v = ctx.itemLedger.get(key);
  const vp = v?.variants;
  if (!v || !vp) return;
  vp.executed++;
  ctx.events.append({
    phase,
    actor: "runner",
    action: "variant_executed",
    target: key,
    result: `variant ${vIdx} executed (${vp.executed}/${vp.planned} of offered; library ${vp.librarySize}, cap ${vp.cap})`,
  });
  if (vp.executed >= vp.planned) {
    settleExpansion(ctx, v, `Variant expansion complete: ${vp.executed}/${vp.planned} variants executed (library ${vp.librarySize}, cap ${vp.cap})`);
  }
}

/** Settle an expansion to executed-clean — never overwrites a final disposition. */
function settleExpansion(ctx: Ctx, v: ItemVerdict, reason: string): void {
  if (v.disposition === "pending" || v.disposition === "blocked" || v.disposition === "executed-clean") {
    try {
      setDisposition(ctx.itemLedger, v.key, "executed-clean", { reason });
    } catch {
      /* already final via a racing verdict — variant progress stays as info */
    }
  }
}

/**
 * Agent-declared early close: "I've run enough variants." The report shows
 * exactly what ran — executed/planned — so closing early is transparent,
 * not a bypass.
 */
export function closeVariantExpansion(ctx: Ctx, key: string, phase: EngagementPhase): string {
  const v = ctx.itemLedger.get(key);
  if (!v) return `REFUSED: unknown battery item key "${key}"`;
  const vp = v.variants;
  if (!vp) return `${key}: no variant expansion open — nothing to close.`;
  const summary = `${vp.executed}/${vp.planned} variants executed (library ${vp.librarySize}, cap ${vp.cap})`;
  settleExpansion(ctx, v, `Variant expansion closed by agent: ${summary}`);
  ctx.events.append({ phase, actor: "runner", action: "variant_expansion_closed", target: key, result: summary });
  return `${key}: variant expansion closed — ${summary}. Reported honestly.`;
}
