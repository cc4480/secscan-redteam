/**
 * CONTINUOUS TESTING — rolling baseline (v0.16.0).
 *
 * The baseline is the watch profile's memory: every confirmed finding ever
 * seen, keyed stably so it can be matched across runs. Finding IDs (F-1…)
 * are per-run and useless for this; the key is target + sorted ATT&CK IDs,
 * which is what actually identifies "the same vulnerability."
 *
 * The baseline is per-profile and explicit — baselines are never silently
 * merged across different scopes. One profile, one baseline.json, in the
 * profile home directory.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Finding } from "../types.js";

export const BASELINE_VERSION = 1;

export type BaselineEntryStatus = "open" | "remediated";

export interface BaselineEntry {
  /** Stable key: "<target>::<sorted ATT&CK ids>" (see findingKey). */
  key: string;
  target: string;
  severity: string;
  title: string;
  attackIds: string[];
  firstSeen: string; // ISO
  lastSeen: string; // ISO
  firstSeenEngagement: string;
  lastSeenEngagement: string;
  status: BaselineEntryStatus;
  /** Engagement + finding that last confirmed it — locates the PoC bundle for reverify. */
  engagementId: string;
  findingId: string;
  /** Set when the last drift pass couldn't mechanically resolve the entry. */
  needsReview?: boolean;
  note?: string;
}

export interface WatchBaseline {
  version: 1;
  profileName: string;
  updatedAt: string; // ISO
  entries: BaselineEntry[];
}

function normalizeTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

/**
 * Stable cross-run finding key. ATT&CK IDs are the identity of "the same
 * vulnerability" — titles are LLM-written and drift between runs. When a
 * finding carries no technique IDs, fall back to a normalized title slug
 * (documented limitation: title drift may split or merge these).
 */
export function findingKey(target: string, f: Pick<Finding, "attackIds" | "title">): string {
  const t = target.trim().toLowerCase();
  const ids = [...new Set((f.attackIds ?? []).map((a) => a.trim().toUpperCase()).filter(Boolean))].sort();
  if (ids.length > 0) return `${t}::${ids.join("+")}`;
  return `${t}::title-${normalizeTitle(f.title ?? "") || "untitled"}`;
}

export function emptyBaseline(profileName: string): WatchBaseline {
  return { version: 1, profileName, updatedAt: new Date().toISOString(), entries: [] };
}

/** Load the baseline, or null when this profile has never run (first cycle). */
export function loadBaseline(path: string): WatchBaseline | null {
  if (!existsSync(path)) return null;
  const raw = JSON.parse(readFileSync(path, "utf8")) as WatchBaseline;
  if (raw.version !== BASELINE_VERSION || !Array.isArray(raw.entries)) {
    throw new Error(`[watch] bad baseline ${path}: version must be ${BASELINE_VERSION} with an entries array`);
  }
  return raw;
}

export function saveBaseline(path: string, baseline: WatchBaseline): void {
  mkdirSync(dirname(path), { recursive: true });
  baseline.updatedAt = new Date().toISOString();
  writeFileSync(path, JSON.stringify(baseline, null, 2));
}

/** Where a baseline entry's PoC bundle lives (for reverify of missing findings). */
export function bundlePathFor(runsDir: string, entry: Pick<BaselineEntry, "engagementId" | "findingId">): string {
  return join(runsDir, entry.engagementId, "poc", `${entry.findingId}.json`);
}
