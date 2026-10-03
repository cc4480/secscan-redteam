/**
 * tier.json — the mid-run tier signal (v0.24.0).
 *
 * The autonomy tier is declared at engagement start, but the operator may
 * raise or lower it mid-run (`redteam-runner escalate`, or the UI's
 * Escalate-tier action). There is deliberately no new network surface for
 * this: the escalation writes tier.json into the engagement dir, and the
 * tool dispatcher re-reads it before every tier check, adopting the new
 * tier without restarting the engagement.
 *
 * The approval itself lives in approvals.jsonl (via escalateTier) — tier.json
 * is only the signal the dispatcher watches. Reads are tolerant: a missing
 * or corrupt file means "no change", never a crash.
 */

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AutonomyTier } from "./tiers.js";

export const TIER_FILE_NAME = "tier.json";

export interface TierFile {
  /** The tier currently in force (what the dispatcher enforces). */
  tier: AutonomyTier;
  /** The tier declared at engagement start (never changes). */
  declared: AutonomyTier;
  environment: "staging" | "production";
  updatedAt: string; // ISO
  /** Operator who last changed the tier (absent on the initial write). */
  by?: string;
  /** Recorded reason for the last change (absent on the initial write). */
  reason?: string;
}

function isTier(v: unknown): v is AutonomyTier {
  return v === 0 || v === 1 || v === 2;
}

function isEnvironment(v: unknown): v is "staging" | "production" {
  return v === "staging" || v === "production";
}

/**
 * Tolerant read: undefined when the file is absent or fails validation.
 * The dispatcher treats undefined as "no change" — a half-written or
 * foreign file can never crash or silently alter a running engagement.
 */
export function readTierFile(dir: string): TierFile | undefined {
  const p = join(dir, TIER_FILE_NAME);
  if (!existsSync(p)) return undefined;
  try {
    const raw = JSON.parse(readFileSync(p, "utf8")) as Partial<TierFile>;
    if (!isTier(raw.tier) || !isTier(raw.declared) || !isEnvironment(raw.environment)) return undefined;
    const tf: TierFile = {
      tier: raw.tier,
      declared: raw.declared,
      environment: raw.environment,
      updatedAt: typeof raw.updatedAt === "string" ? raw.updatedAt : "",
    };
    if (typeof raw.by === "string" && raw.by.trim()) tf.by = raw.by;
    if (typeof raw.reason === "string" && raw.reason.trim()) tf.reason = raw.reason;
    return tf;
  } catch {
    return undefined;
  }
}

/**
 * Atomic write (tmp file + rename) so a dispatcher re-reading mid-write
 * never observes a partial file. The reader is tolerant anyway — this is
 * defense in depth, not the only guard.
 */
export function writeTierFile(dir: string, tf: TierFile): void {
  const p = join(dir, TIER_FILE_NAME);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(tf, null, 2) + "\n");
  renameSync(tmp, p);
}
