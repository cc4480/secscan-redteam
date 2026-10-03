/**
 * abort.json — the cross-process kill-switch signal (v0.25.0).
 *
 * An engagement launched from the CLI has no abort handle inside the UI
 * server process, so the dashboard could not stop it (409 "not live in
 * this UI process"). The fix follows the v0.24.0 tier.json precedent:
 * the UI writes abort.json into the engagement dir (atomically), and the
 * tool dispatcher checks for it on every dispatch cycle. When the marker
 * is found, the dispatcher runs the exact same abort sequence as the
 * in-process kill switch (flag, controllers, audit event) and throws
 * HaltError so the run unwinds to "halted".
 *
 * The marker only ever means "abort" — it carries no commands, no targets,
 * no tier changes. Reads are tolerant: a missing or corrupt file means "no
 * abort requested", never a crash. After acting on the marker, the
 * dispatcher consumes (deletes) it; the audit event is the durable record,
 * so a stale marker can never abort a future run.
 */

import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const ABORT_FILE_NAME = "abort.json";

export interface AbortSignal {
  /** ISO timestamp of when the abort was requested. */
  requestedAt: string;
  /**
   * Who requested it. The UI has one shared token and no per-user
   * identity, so this is the surface that wrote the file
   * ("ui-operator"), never a person. Recorded in the audit event.
   */
  by?: string;
  /** Operator-supplied reason, truncated at write time. */
  reason?: string;
}

/**
 * Tolerant read: undefined when the file is absent or fails validation.
 * The dispatcher treats undefined as "no abort requested" — a half-written
 * or foreign file can never crash or spuriously abort a running engagement.
 */
export function readAbortFile(dir: string): AbortSignal | undefined {
  const p = join(dir, ABORT_FILE_NAME);
  if (!existsSync(p)) return undefined;
  try {
    const raw = JSON.parse(readFileSync(p, "utf8")) as Partial<AbortSignal>;
    if (typeof raw.requestedAt !== "string" || !raw.requestedAt) return undefined;
    const sig: AbortSignal = { requestedAt: raw.requestedAt };
    if (typeof raw.by === "string" && raw.by.trim()) sig.by = raw.by.slice(0, 120);
    if (typeof raw.reason === "string" && raw.reason.trim()) sig.reason = raw.reason.slice(0, 500);
    return sig;
  } catch {
    return undefined;
  }
}

/**
 * Atomic write (tmp file + rename) so a dispatcher re-reading mid-write
 * never observes a partial file. The reader is tolerant anyway — this is
 * defense in depth, not the only guard.
 */
export function writeAbortFile(dir: string, sig: AbortSignal): void {
  const p = join(dir, ABORT_FILE_NAME);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(sig, null, 2) + "\n");
  renameSync(tmp, p);
}

/**
 * Best-effort consume: remove the marker after the dispatcher has acted
 * on it. The abort_engagement audit event is the durable record; the file
 * itself must not linger to abort anything else.
 */
export function consumeAbortFile(dir: string): void {
  try {
    unlinkSync(join(dir, ABORT_FILE_NAME));
  } catch {
    /* already gone or unwritable — the audit event stands on its own */
  }
}
