/**
 * Per-item verdict tracking for the full battery (v0.18.0).
 *
 * The coverage contract used to be cell-level (3 categories × selected
 * targets = 12 cells): a cell could report "done" while individual battery
 * items inside it had never been attempted. This module closes that gap
 * mechanically: every selected battery item (418 static items across the
 * four target profiles, plus dynamic per-CVE runtime instances from
 * msf_exec) carries exactly one disposition per engagement, and the battery
 * may not report complete while any item is still `pending`.
 *
 * Dispositions: pending (not attempted) · confirmed (validated finding) ·
 * executed-clean (executed, no finding) · killed (ruled out — negative
 * intelligence, class stays in play) · blocked (prerequisite unmet, named) ·
 * na (not applicable WITH evidence).
 *
 * Transition rules (mechanical, enforced here — not by prompt):
 * pending/blocked → any non-final; executed-clean → confirmed/killed/na;
 * confirmed/killed/na are FINAL except via reverify (remediated → pending);
 * "na" requires evidence text. The ledger is append-only: dispositions move
 * toward terminal, never backwards, except the reverify reopen path.
 */

import type { BatteryCategory } from "../battery.js";
import { FULL_BATTERY_TARGETS, TARGET_PREFIXES, TARGET_PROFILES } from "../targets/index.js";
import type { TargetId } from "../targets/index.js";
import type { VariantProgress } from "../variants/types.js";
import { nucleiBinaryPresent } from "../nuclei/prereq.js";

export type ItemDisposition =
  | "pending"
  | "confirmed"
  | "executed-clean"
  | "killed"
  | "blocked"
  | "na";

export interface ItemVerdict {
  /** "secscan:SS-001" for static items, "cve:CVE-2021-44228" for dynamic CVE instances. */
  key: string;
  /** TargetId for static items, "cve" for dynamic instances. */
  target: string;
  /** "SS-001" or "CVE-2021-44228". */
  itemId: string;
  category: BatteryCategory;
  name: string;
  disposition: ItemDisposition;
  /** Required for na/killed/blocked — the evidence or prerequisite. */
  reason?: string;
  decidedAt?: string;
  /** Audit-log seq of the event that decided it (when known). */
  auditSeq?: number;
  /**
   * v0.20.0 variant expansion progress (set by variant_list). While open
   * and unexhausted, the variant tracker owns this item's disposition.
   */
  variants?: VariantProgress;
}

/** Dispositions that are final: no overwrite except via the reverify reopen path. */
const FINAL_DISPOSITIONS: ItemDisposition[] = ["confirmed", "killed", "na"];

const PREFIX_TO_TARGET: Record<string, TargetId> = {
  SS: "secscan",
  SL: "seclayer",
  WS: "windows",
  LX: "linux",
};

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;
const ITEM_RE = /^([A-Z]{2})-(\d{1,4})$/;

/**
 * Resolve an agent-supplied battery item reference to a ledger key.
 * Accepts "SS-042" (+ optional targetProfile), "secscan:SS-042",
 * "cve:CVE-2021-44228". Returns undefined when the reference does not
 * identify a real battery item — the caller must surface that, never
 * silently drop it.
 */
export function resolveItemKey(raw: string, targetProfile?: string): string | undefined {
  const s = raw.trim();
  if (!s) return undefined;
  // Qualified form: "secscan:SS-001" / "cve:CVE-2021-44228"
  const qual = s.match(/^([A-Za-z]+):(.+)$/);
  if (qual) {
    const [, t, item] = qual as [string, string, string];
    const tl = t.toLowerCase();
    if (tl === "cve") {
      const cu = item.trim().toUpperCase();
      return CVE_RE.test(cu) ? `cve:${cu}` : undefined;
    }
    if (!(FULL_BATTERY_TARGETS as string[]).includes(tl)) return undefined;
    const m = item.trim().toUpperCase().match(ITEM_RE);
    if (!m) return undefined;
    const [, prefix, num] = m as [string, string, string];
    if (TARGET_PREFIXES[tl as TargetId] !== prefix) return undefined;
    return `${tl}:${prefix}-${num.padStart(3, "0")}`;
  }
  // CVE form without qualifier
  const cu = s.toUpperCase();
  if (CVE_RE.test(cu)) return `cve:${cu}`;
  // Bare item form: "SS-042" — prefix determines (or confirms) the target
  const m = cu.match(ITEM_RE);
  if (!m) return undefined;
  const [, prefix, num] = m as [string, string, string];
  const inferred = PREFIX_TO_TARGET[prefix];
  if (!inferred) return undefined;
  if (targetProfile) {
    const tl = targetProfile.toLowerCase();
    if (!(FULL_BATTERY_TARGETS as string[]).includes(tl)) return undefined;
    if (TARGET_PREFIXES[tl as TargetId] !== prefix) return undefined;
    return `${tl}:${prefix}-${num.padStart(3, "0")}`;
  }
  return `${inferred}:${prefix}-${num.padStart(3, "0")}`;
}

/**
 * Whether a battery item's `needs` prerequisite is satisfied right now.
 * Checked from the environment — the honest, mechanical reading. Unknown
 * prerequisites (free text like "Second test account") and the human
 * operator are never auto-met: those items start blocked.
 */
export function prerequisiteMet(needs: string): boolean {
  const n = needs.toLowerCase();
  if (n.includes("msfrpcd")) {
    return !!(process.env.REDTEAM_MSFRPC_USER && process.env.REDTEAM_MSFRPC_PASS);
  }
  if (n.includes("kerberos ticket")) {
    return !!(
      process.env.REDTEAM_KRB_CCACHE_B64 ||
      process.env.REDTEAM_KRB_CCACHE_PATH ||
      process.env.REDTEAM_KRB_KIRBI_B64
    );
  }
  if (n.includes("privileged test client")) {
    return !!process.env.REDTEAM_NFS_TEST_CLIENT;
  }
  if (n.includes("nuclei")) {
    return nucleiBinaryPresent();
  }
  return false;
}

/** Build the opening ledger: every selected item pending, except items whose prerequisites are unmet (blocked, with the prerequisite named). */
export function buildItemLedger(targets: TargetId[]): Map<string, ItemVerdict> {
  const ledger = new Map<string, ItemVerdict>();
  for (const t of targets) {
    const profile = TARGET_PROFILES[t];
    for (const item of profile.battery) {
      const key = `${t}:${item.id}`;
      const prereq = item.needs ?? item.deferredReason;
      const blocked = !!prereq && !prerequisiteMet(prereq);
      ledger.set(key, {
        key,
        target: t,
        itemId: item.id,
        category: item.category,
        name: item.name,
        disposition: blocked ? "blocked" : "pending",
        reason: blocked ? `Prerequisite not met: ${prereq}` : undefined,
        decidedAt: blocked ? new Date().toISOString() : undefined,
      });
    }
  }
  return ledger;
}

/**
 * Record that an item was genuinely attempted (a clean tool execution
 * tagged with its ID). pending/blocked → executed-clean. Already
 * decided items are untouched. Returns false when the key is unknown.
 */
export function markAttempted(
  ledger: Map<string, ItemVerdict>,
  key: string,
  auditSeq?: number,
): boolean {
  const v = ledger.get(key);
  if (!v) return false;
  if (v.disposition === "pending" || v.disposition === "blocked") {
    v.disposition = "executed-clean";
    v.reason = undefined;
    v.decidedAt = new Date().toISOString();
    if (auditSeq !== undefined) v.auditSeq = auditSeq;
  }
  return true;
}

/**
 * Set a terminal disposition. Enforces the transition rules mechanically:
 * final dispositions (confirmed/killed/na) cannot be overwritten except
 * via the reverify reopen path (which may only move back to pending);
 * "na" requires evidence text.
 */
export function setDisposition(
  ledger: Map<string, ItemVerdict>,
  key: string,
  disposition: ItemDisposition,
  opts?: { reason?: string; auditSeq?: number; viaReverify?: boolean },
): void {
  const v = ledger.get(key);
  if (!v) throw new Error(`unknown battery item key "${key}"`);
  const reason = opts?.reason?.trim() || undefined;
  if (disposition === "na" && !reason) {
    throw new Error(`"na" requires evidence — refusing to mark ${key} not-applicable without it`);
  }
  const isFinal = FINAL_DISPOSITIONS.includes(v.disposition);
  if (isFinal && !opts?.viaReverify) {
    throw new Error(
      `${key} already has final disposition "${v.disposition}" — refusing to overwrite (reverify may reopen it to pending)`,
    );
  }
  if (isFinal && opts?.viaReverify && disposition !== "pending") {
    throw new Error(`reverify reopen may only move ${key} back to pending`);
  }
  v.disposition = disposition;
  v.reason = reason;
  v.decidedAt = new Date().toISOString();
  if (opts?.auditSeq !== undefined) v.auditSeq = opts.auditSeq;
}

/** Ensure a dynamic per-CVE runtime instance has a ledger entry (created pending on first sight). Returns its key. */
export function ensureCveEntry(ledger: Map<string, ItemVerdict>, cve: string): string {
  const upper = cve.trim().toUpperCase();
  if (!CVE_RE.test(upper)) throw new Error(`not a CVE id: "${cve}"`);
  const key = `cve:${upper}`;
  if (!ledger.has(key)) {
    ledger.set(key, {
      key,
      target: "cve",
      itemId: upper,
      category: "functionality",
      name: `CVE exploit validation ${upper}`,
      disposition: "pending",
    });
  }
  return key;
}

export interface LedgerSummary {
  total: number;
  pending: number;
  confirmed: number;
  executedClean: number;
  killed: number;
  blocked: number;
  na: number;
}

export function ledgerSummary(ledger: Map<string, ItemVerdict>): LedgerSummary {
  const s: LedgerSummary = {
    total: ledger.size,
    pending: 0,
    confirmed: 0,
    executedClean: 0,
    killed: 0,
    blocked: 0,
    na: 0,
  };
  for (const v of ledger.values()) {
    if (v.disposition === "pending") s.pending++;
    else if (v.disposition === "confirmed") s.confirmed++;
    else if (v.disposition === "executed-clean") s.executedClean++;
    else if (v.disposition === "killed") s.killed++;
    else if (v.disposition === "blocked") s.blocked++;
    else if (v.disposition === "na") s.na++;
  }
  return s;
}

/** Pending item IDs grouped by target+category — the coordinator reads this to aim re-planning at real gaps. */
export function pendingByCell(
  ledger: Map<string, ItemVerdict>,
): Array<{ target: string; category: BatteryCategory; ids: string[] }> {
  const groups = new Map<string, { target: string; category: BatteryCategory; ids: string[] }>();
  for (const v of ledger.values()) {
    if (v.disposition !== "pending") continue;
    const gk = `${v.target}:${v.category}`;
    let g = groups.get(gk);
    if (!g) {
      g = { target: v.target, category: v.category, ids: [] };
      groups.set(gk, g);
    }
    g.ids.push(v.itemId);
  }
  return [...groups.values()].sort((a, b) =>
    a.target === b.target ? a.category.localeCompare(b.category) : a.target.localeCompare(b.target),
  );
}

export function serializeLedger(ledger: Map<string, ItemVerdict>): ItemVerdict[] {
  return [...ledger.values()];
}
