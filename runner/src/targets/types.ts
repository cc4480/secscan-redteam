/**
 * Shared types for the target-specific attack batteries (v0.7.0).
 *
 * The batteries are exhaustive: every distinct attacker intent against each
 * target's real surface is one item. Prompts inject a COMPACT checklist
 * (id + name + one-line brief); the full `what` stays in-module as the
 * execution detail the agents expand per item.
 */

import type { BatteryCategory } from "../battery.js";

export type TargetId = "secscan" | "seclayer" | "windows" | "linux";
export const FULL_BATTERY_TARGETS: TargetId[] = ["secscan", "seclayer", "windows", "linux"];

/** Guard for user-supplied target ids (--targets, probe args). */
export function isTargetId(s: string): s is TargetId {
  return (FULL_BATTERY_TARGETS as string[]).includes(s.toLowerCase());
}

/** Battery id prefixes per target: SS-*, SL-*, WS-*, LX-*. */
export const TARGET_PREFIXES: Record<TargetId, string> = {
  secscan: "SS",
  seclayer: "SL",
  windows: "WS",
  linux: "LX",
};

/**
 * Marker for battery items the runner cannot execute even WITH the host-exec
 * tools (v0.9.0): anything needing interactive sessions (RDP GUI), active
 * network attacks (relay/spoofing), Kerberos protocol operations, binary
 * tooling deployment (BloodHound collectors), or AD CS/RDS role tooling.
 * Such items are PLAN-ONLY — the agents plan the hypothesis and expected
 * evidence, and the coverage cell reports BLOCKED (under Honest limits)
 * instead of covered or failed.
 */
export const HOST_EXEC_TOOLING = "host-exec tooling";

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

export type TargetKind = "webapp" | "mcp-api" | "host-windows" | "host-linux";

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
