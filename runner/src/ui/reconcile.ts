/**
 * Orphaned-engagement reconciliation.
 *
 * A run whose driving process is gone leaves a state.json still saying
 * "running" with nobody behind it — a console restart, a killed CLI run, or a
 * crash. Reporting the stored status verbatim makes abandoned work look active,
 * which is worse than reporting nothing: an operator scanning the list sees
 * progress that is not happening and may wait on it.
 *
 * The check is mechanical where it can be. The state records the PID of the
 * process that owns the run, and a dead PID means the run is over whatever the
 * file says. Records written before that field existed fall back to age.
 *
 * Kept out of store.ts deliberately: that file is already at its size budget,
 * and this is a distinct concern from storing and reading engagement records.
 */

import type { LiveState } from "../events.js";

/**
 * How long a pre-ownerPid record may claim to be running before it is treated
 * as orphaned. Thirty minutes is far longer than any single tool call this
 * runner makes (the longest profile carries a 300s host timeout), so a record
 * this quiet is not being driven by anything.
 */
export const LEGACY_STALE_MS = 30 * 60 * 1000;

/**
 * Whether the process that owned a run is still alive.
 *
 * signal 0 performs the permission and existence checks without delivering a
 * signal, which is the standard liveness probe. EPERM means the process exists
 * but belongs to another user — still alive for our purposes.
 */
export function ownerAlive(pid: number | undefined): boolean {
  if (pid === undefined || !Number.isFinite(pid)) return true;
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** A run's reported status, and whether it was found to be orphaned. */
export interface ReconciledStatus {
  status: string;
  orphaned: boolean;
}

/**
 * Reported status for an ON-DISK engagement.
 *
 * Only "running" and "authorizing" are ever revised — a terminal status is the
 * run's own final word and is never second-guessed.
 */
export function reconcileStatus(state: LiveState): ReconciledStatus {
  if (state.status !== "running" && state.status !== "authorizing") {
    return { status: state.status, orphaned: false };
  }
  if (state.ownerPid !== undefined) {
    return ownerAlive(state.ownerPid)
      ? { status: state.status, orphaned: false }
      : { status: "halted", orphaned: true };
  }
  // No ownerPid to check, so fall back to age. The threshold is deliberately
  // generous: a live run must never be called dead, and leaving a dead one
  // listed is the lesser error of the two.
  const ageMs = Date.now() - Date.parse(state.updatedAt);
  if (Number.isFinite(ageMs) && ageMs > LEGACY_STALE_MS) return { status: "halted", orphaned: true };
  return { status: state.status, orphaned: false };
}

/** Why a record was revised, for the operator reading the list. */
export const ORPHAN_REASON =
  "orphaned: the process driving this run is gone (console restart, killed CLI run or crash), so its status was never updated to a terminal one";
