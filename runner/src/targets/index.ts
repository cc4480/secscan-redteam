/**
 * Target profiles + target-specific attack batteries — the culmination (v0.7.0).
 *
 * Generic batteries test "a webapp". These batteries test THESE targets:
 * SecScan (the scanner webapp, 120 items) and SecLayer (the MCP/API layer,
 * 80 items), against their REAL surfaces — the DNS ownership gate, the scan
 * lifecycle, the share-link flow, the JSON-RPC message flow — as observed
 * across our own engagements.
 *
 * Target-specific beats generic because the same flaw class lands
 * differently on each surface: IDOR on a scan report is not IDOR on a
 * shopping cart. Every item names the actual endpoint, flow, or parameter.
 *
 * FULL_BATTERY unified engagement: one operation, both targets, one report —
 *   1. recon BOTH surfaces (webapp + MCP API)
 *   2. exploit SecScan battery (SS-*)
 *   3. exploit SecLayer battery (SL-*)
 *   4. cross-cutting chains (MCP → webapp paths)
 *   5. unified report
 * Coverage counts complete only at 3 categories × 2 targets (6 cells).
 *
 * Non-destructive always: never trigger emails to real users, never delete
 * scans/reports, benign canary content only, races are single paired
 * requests. Items that need prerequisites say so in `needs` — honestly,
 * never pretending a test ran when its setup was missing.
 */

import type { BatteryCategory } from "../battery.js";
import { BATTERY_CATEGORIES, CATEGORY_LABELS } from "../battery.js";
import type { TargetBatteryItem, TargetId, TargetKind, TargetProfile } from "./types.js";
import { FULL_BATTERY_TARGETS } from "./types.js";
import { SECSCAN_PROFILE } from "./secscan.js";
import { SECLAYER_PROFILE } from "./seclayer.js";

export type { TargetBatteryItem, TargetId, TargetKind, TargetProfile };
export { FULL_BATTERY_TARGETS };

export const TARGET_PROFILES: Record<TargetId, TargetProfile> = {
  secscan: SECSCAN_PROFILE,
  seclayer: SECLAYER_PROFILE,
};

export function lookupTargetProfile(id: string): TargetProfile | undefined {
  const key = id.toLowerCase() as TargetId;
  return key === "secscan" || key === "seclayer" ? TARGET_PROFILES[key] : undefined;
}

export function targetItemsFor(profile: TargetProfile, category: BatteryCategory): TargetBatteryItem[] {
  return profile.battery.filter((b) => b.category === category);
}

/** Infer which target a probe URL belongs to: the MCP path is SecLayer, everything else is the webapp. */
export function inferTargetProfile(url: string): TargetId {
  try {
    const path = new URL(url).pathname.toLowerCase();
    if (path.startsWith("/api/mcp")) return "seclayer";
  } catch {
    /* unparseable — default to the webapp */
  }
  return "secscan";
}

/**
 * Compact checklist for one target's battery, for prompt injection.
 * 200 items can't ship with full detail — every item appears as
 * ID + name + one-line brief, grouped by category. The full `what`
 * stays in-module; agents expand per item as they work it.
 */
export function targetBatteryChecklistText(profile: TargetProfile, mode: "red" | "black"): string {
  const lines: string[] = [`## ${profile.name} (${profile.baseUrl}) — ${profile.battery.length} items`, `Auth model: ${profile.authModel}`];
  for (const cat of BATTERY_CATEGORIES) {
    lines.push(`### ${CATEGORY_LABELS[cat]}`);
    for (const item of targetItemsFor(profile, cat)) {
      const stealth = mode === "black" && item.blackNote ? ` [black: ${item.blackNote}]` : "";
      const needs = item.needs ? ` [needs: ${item.needs}]` : "";
      const deferred = item.deferredReason ? ` [DEFERRED: ${item.deferredReason}]` : "";
      lines.push(`- ${item.id} ${item.name}: ${item.brief}${stealth}${needs}${deferred}`);
    }
  }
  return lines.join("\n");
}

/** Both batteries, for the full-battery plan skeleton. */
export function fullBatteryChecklistText(mode: "red" | "black"): string {
  return FULL_BATTERY_TARGETS.map((t) => targetBatteryChecklistText(TARGET_PROFILES[t], mode)).join("\n\n");
}

/**
 * The unified engagement plan skeleton — one operation, both targets, one report.
 * The coordinator expands this into the operation plan; the runner enforces
 * the coverage rule (3 categories × 2 targets) mechanically.
 */
export function fullBatteryPlanSkeleton(): string {
  return `## FULL-BATTERY unified engagement — SecScan + SecLayer, ONE operation
Phase order (do not reorder):
1. RECON both surfaces — webapp (https://secscan.us) AND MCP API (https://secscan.us/api/mcp): entry points, auth models, fingerprints, WAF signals.
2. EXPLOIT SecScan battery (SS-001…SS-120) — the scanner webapp: intake, SSRF guard, DNS gate, lifecycle, reports, shares, opt-out, rate limits, auth, API, efficacy canaries.
3. EXPLOIT SecLayer battery (SL-001…SL-080) — the MCP/API layer: handshake, tools/list, per-tool per-param attacks, JSON-RPC layer, HTTP layer, auth layer, notifications, quotas, oracles.
4. CROSS-CUTTING CHAINS — MCP → webapp paths: does an API-layer primitive become a webapp impact (or vice versa)? State each chain as one line.
5. UNIFIED REPORT — one Megazord narrative, both batteries, honest limits per target.
Coverage rule (runner-enforced): the battery counts complete only when ALL THREE categories are probed on BOTH targets (3 × 2 = 6 cells). Tag every http_probe with targetProfile ("secscan" | "seclayer") — the runner also infers it from the URL path (/api/mcp → seclayer).`;
}
