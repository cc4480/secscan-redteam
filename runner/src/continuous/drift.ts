/**
 * CONTINUOUS TESTING — drift detection (v0.16.0).
 *
 * Two phases, kept deliberately separate:
 *
 *   Phase 1 (pure, no traffic) — classifyDrift(): match this run's
 *   confirmed findings against the baseline by stable key →
 *   new / unchanged / missing.
 *
 *   Phase 2 (mechanical reverify, traffic) — resolveMissingDrift(): for
 *   each missing entry, re-execute its PoC bundle via the injected
 *   reverify function:
 *     reproduced     → "reopened"   (still there; this run just missed it)
 *     not-reproduced → "remediated" (verified fix — the ONLY way an entry
 *                                    becomes remediated; never assumed)
 *     target-changed → "needs-review"
 *     no bundle / reverify error → "needs-review"
 *
 * A finding that merely didn't reproduce due to a moved target is
 * "needs-review," never "fixed." Honesty is structural: the remediated
 * verdict is unreachable without a confirming reverify.
 */

import { existsSync } from "node:fs";
import type { Finding } from "../types.js";
import type { ReverifyVerdict } from "../proof/index.js";
import { bundlePathFor, findingKey, type BaselineEntry, type WatchBaseline } from "./baseline.js";

export type DriftDisposition = "reopened" | "remediated" | "needs-review";

export interface DriftMissing {
  entry: BaselineEntry;
  disposition: DriftDisposition;
  reverifyVerdict?: ReverifyVerdict;
  note: string;
}

export interface DriftClassification {
  /** Confirmed findings with no baseline match. */
  newFindings: Finding[];
  /** Confirmed findings matched to an open baseline entry. */
  unchanged: Array<{ finding: Finding; entry: BaselineEntry }>;
  /** Baseline entries (open or needs-review) absent from this run. */
  missing: BaselineEntry[];
}

/**
 * Phase 1 — pure key matching, no traffic. Only confirmed findings count;
 * killed/deferred findings are not findings. Duplicate keys within one run
 * (same technique twice on one target) get a "#2" suffix so nothing is
 * silently merged.
 */
export function classifyDrift(baseline: WatchBaseline, current: Finding[], target: string): DriftClassification {
  const confirmed = current.filter((f) => f.status === "confirmed");
  const seen = new Map<string, number>();
  const keyed = confirmed.map((finding) => {
    let key = findingKey(target, finding);
    const n = (seen.get(key) ?? 0) + 1;
    seen.set(key, n);
    if (n > 1) key = `${key}#${n}`;
    return { finding, key };
  });
  const openEntries = new Map<string, BaselineEntry>();
  for (const e of baseline.entries) {
    if (e.status === "open" || e.needsReview) openEntries.set(e.key, e);
  }
  const newFindings: Finding[] = [];
  const unchanged: Array<{ finding: Finding; entry: BaselineEntry }> = [];
  const matched = new Set<string>();
  for (const { finding, key } of keyed) {
    const entry = openEntries.get(key);
    if (entry) {
      unchanged.push({ finding, entry });
      matched.add(key);
    } else {
      newFindings.push(finding);
    }
  }
  const missing = [...openEntries.values()].filter((e) => !matched.has(e.key));
  return { newFindings, unchanged, missing };
}

/** Injected reverify — tests fake it; the watcher wires the real replayer. */
export type ReverifyFn = (bundlePath: string) => Promise<{ verdict: ReverifyVerdict; note: string }>;

/**
 * Phase 2 — resolve every missing entry. Never throws: a failed reverify
 * is "needs-review," never a silent drop.
 */
export async function resolveMissingDrift(
  missing: BaselineEntry[],
  runsDir: string,
  reverify: ReverifyFn,
): Promise<DriftMissing[]> {
  const out: DriftMissing[] = [];
  for (const entry of missing) {
    const bundlePath = bundlePathFor(runsDir, entry);
    if (!existsSync(bundlePath)) {
      out.push({
        entry,
        disposition: "needs-review",
        note: `no PoC bundle at ${bundlePath} — cannot mechanically re-verify; manual review required. Not marked remediated.`,
      });
      continue;
    }
    let verdict: ReverifyVerdict;
    let note: string;
    try {
      const r = await reverify(bundlePath);
      verdict = r.verdict;
      note = r.note;
    } catch (err) {
      out.push({
        entry,
        disposition: "needs-review",
        note: `reverify failed (${(err as Error).message}) — manual review required. Not marked remediated.`,
      });
      continue;
    }
    if (verdict === "reproduced") {
      out.push({ entry, disposition: "reopened", reverifyVerdict: verdict, note: `reverify REPRODUCED: ${note}` });
    } else if (verdict === "not-reproduced") {
      out.push({ entry, disposition: "remediated", reverifyVerdict: verdict, note: `reverify NOT-REPRODUCED: ${note}` });
    } else {
      out.push({
        entry,
        disposition: "needs-review",
        reverifyVerdict: verdict,
        note: `reverify target-changed: the environment moved, not the vulnerability — retest when reachable. Not marked remediated.`,
      });
    }
  }
  return out;
}

export interface DriftReport {
  version: 1;
  profileName: string;
  engagementId: string;
  /** CI/CD change reference for trigger runs, e.g. "deploy abc123". */
  changeRef?: string;
  generatedAt: string;
  newFindings: Finding[];
  unchangedCount: number;
  reopened: DriftMissing[];
  remediated: DriftMissing[];
  needsReview: DriftMissing[];
}

export function buildDriftReport(args: {
  profileName: string;
  engagementId: string;
  changeRef?: string;
  classification: DriftClassification;
  resolved: DriftMissing[];
}): DriftReport {
  return {
    version: 1,
    profileName: args.profileName,
    engagementId: args.engagementId,
    ...(args.changeRef ? { changeRef: args.changeRef } : {}),
    generatedAt: new Date().toISOString(),
    newFindings: args.classification.newFindings,
    unchangedCount: args.classification.unchanged.length,
    reopened: args.resolved.filter((r) => r.disposition === "reopened"),
    remediated: args.resolved.filter((r) => r.disposition === "remediated"),
    needsReview: args.resolved.filter((r) => r.disposition === "needs-review"),
  };
}

/**
 * Fold the drift report back into the baseline. Entries are never deleted —
 * remediated ones stay as history (firstSeen → lastSeen spans the finding's
 * lifetime). New findings become open entries pointing at this run's PoC
 * bundles for future reverify.
 */
export function applyDriftToBaseline(
  baseline: WatchBaseline,
  report: DriftReport,
  target: string,
  engagementId: string,
  nowIso: string,
): WatchBaseline {
  const byKey = new Map(baseline.entries.map((e) => [e.key, e]));
  const seen = new Map<string, number>();
  for (const f of report.newFindings) {
    let key = findingKey(target, f);
    const n = (seen.get(key) ?? 0) + 1;
    seen.set(key, n);
    if (n > 1) key = `${key}#${n}`;
    if (byKey.has(key)) continue; // already folded (defensive)
    byKey.set(key, {
      key,
      target,
      severity: f.severity,
      title: f.title,
      attackIds: f.attackIds,
      firstSeen: nowIso,
      lastSeen: nowIso,
      firstSeenEngagement: engagementId,
      lastSeenEngagement: engagementId,
      status: "open",
      engagementId,
      findingId: f.id,
    });
  }
  // Unchanged / reopened / remediated / needs-review transitions are applied
  // by touchBaselineEntries / remediateBaselineEntries / flagBaselineNeedsReview
  // so each state change stays explicit and testable.
  return { ...baseline, entries: [...byKey.values()], updatedAt: nowIso };
}

/** Keys the caller wants refreshed (unchanged this run + reopened). */
export function touchBaselineEntries(
  baseline: WatchBaseline,
  keys: string[],
  engagementId: string,
  nowIso: string,
): WatchBaseline {
  const set = new Set(keys);
  return {
    ...baseline,
    updatedAt: nowIso,
    entries: baseline.entries.map((e) => {
      if (!set.has(e.key)) return e;
      const touched: BaselineEntry = {
        ...e,
        lastSeen: nowIso,
        lastSeenEngagement: engagementId,
        engagementId,
        status: "open",
      };
      delete touched.needsReview;
      return touched;
    }),
  };
}

/** Mark remediated entries (reverify-confirmed only — enforced by the caller). */
export function remediateBaselineEntries(
  baseline: WatchBaseline,
  keys: string[],
  nowIso: string,
): WatchBaseline {
  const set = new Set(keys);
  return {
    ...baseline,
    updatedAt: nowIso,
    entries: baseline.entries.map((e) =>
      set.has(e.key) ? { ...e, status: "remediated" as const, lastSeen: nowIso, needsReview: false } : e,
    ),
  };
}

/** Flag entries that need human review. */
export function flagBaselineNeedsReview(baseline: WatchBaseline, keys: string[], note: string): WatchBaseline {
  const set = new Set(keys);
  return {
    ...baseline,
    entries: baseline.entries.map((e) => (set.has(e.key) ? { ...e, needsReview: true, note } : e)),
  };
}

export function renderDriftMarkdown(report: DriftReport): string {
  const L: string[] = [];
  L.push(`## Continuous drift — watch profile "${report.profileName}"`);
  L.push(``);
  L.push(`Engagement: ${report.engagementId}${report.changeRef ? ` · change ref: ${report.changeRef}` : ""} · ${report.generatedAt}`);
  L.push(``);
  L.push(
    `- **New:** ${report.newFindings.length} · **Unchanged:** ${report.unchangedCount} · ` +
      `**Reopened:** ${report.reopened.length} · **Remediated (reverify-confirmed):** ${report.remediated.length} · ` +
      `**Needs review:** ${report.needsReview.length}`,
  );
  L.push(``);
  if (report.newFindings.length > 0) {
    L.push(`### New findings`);
    for (const f of report.newFindings) L.push(`- **[${f.severity}] ${f.id}** — ${f.title} (${f.attackIds.join(", ") || "no technique"})`);
    L.push(``);
  }
  const section = (title: string, items: DriftMissing[]) => {
    if (items.length === 0) return;
    L.push(`### ${title}`);
    for (const m of items) {
      L.push(`- **[${m.entry.severity}]** ${m.entry.title} (${m.entry.attackIds.join(", ") || "no technique"}) — ${m.note}`);
    }
    L.push(``);
  };
  section("Reopened (reverify reproduced — still present)", report.reopened);
  section("Remediated (reverify confirmed the fix)", report.remediated);
  section("Needs review (could not be mechanically resolved — NOT marked remediated)", report.needsReview);
  L.push(`> Remediated verdicts require a confirming reverify run. "Needs review" entries stay open.`);
  L.push(``);
  return L.join("\n");
}
