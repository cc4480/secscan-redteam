/**
 * Shared types for the target-specific attack batteries (v0.7.0).
 *
 * The batteries are exhaustive: every distinct attacker intent against each
 * target's real surface is one item. Prompts inject a COMPACT checklist
 * (id + name + one-line brief); the full `what` stays in-module as the
 * execution detail the agents expand per item.
 */

import type { BatteryCategory } from "../battery.js";

export type TargetId = "secscan" | "seclayer";
export const FULL_BATTERY_TARGETS: TargetId[] = ["secscan", "seclayer"];

export interface TargetBatteryItem {
  /** SS-001… / SL-001… — unique per target, zero-padded, ordered by surface. */
  id: string;
  category: BatteryCategory;
  name: string;
  /** One-line summary — this is what the coordinator sees in the prompt checklist. */
  brief: string;
  owasp: string;
  /** ATT&CK technique ID where one honestly fits; otherwise undefined. */
  attackId?: string;
  /** What to test — concrete: the actual endpoint/flow/param and the exact abuse. */
  what: string;
  /** Stealth-weighted variant for black-team mode. */
  blackNote?: string;
  /** Prerequisites, stated honestly (e.g. "Second test account", "Canary/OAST infra"). */
  needs?: string;
  /** Why this item is deferred rather than tested (set instead of pretending). */
  deferredReason?: string;
}

export type TargetKind = "webapp" | "mcp-api";

export interface TargetProfile {
  id: TargetId;
  name: string;
  baseUrl: string;
  kind: TargetKind;
  /** How the target authenticates callers — the trust boundary under test. */
  authModel: string;
  scopeNotes: string;
  battery: TargetBatteryItem[];
}
