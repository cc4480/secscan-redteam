/**
 * Orphaned-engagement reconciliation (v0.33.0).
 *
 * A run whose driving process is gone leaves a state.json still saying
 * "running" with nobody behind it. Two different failures produced that in one
 * session: a console restart, and a run that died before writing a terminal
 * state. Reporting the stored status verbatim makes abandoned work look active,
 * which is worse than reporting nothing — an operator scanning the list sees
 * progress that is not happening and may wait on it.
 *
 * The check is mechanical where it can be: the state records the PID of the
 * process that owns the run, and a dead PID means the run is over. Records
 * written before that field existed fall back to age, with a threshold far
 * longer than any single tool call so a live run is never called dead.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { UiStore } from "../src/ui/store.js";

let dir: string;

function writeEngagement(id: string, state: Record<string, unknown>): void {
  const d = join(dir, id);
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, "state.json"), JSON.stringify(state, null, 2));
}

const base = (over: Record<string, unknown>): Record<string, unknown> => ({
  engagementId: "x",
  target: "example.test",
  mode: "red",
  objective: "o",
  status: "running",
  phase: "recon",
  verified: true,
  plan: null,
  findings: [],
  eventCount: 1,
  startedAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  ...over,
});

function find(id: string) {
  return new UiStore(dir).list().find((r) => r.id === id);
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "ui-orphan-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("orphaned engagement reconciliation", () => {
  it("reports a run whose owner process is gone as halted, not running", () => {
    // PID 1 is not running on Windows, and is not this process on POSIX.
    const dead = 0x7ffffff0;
    writeEngagement("eng-dead", base({ engagementId: "eng-dead", ownerPid: dead, updatedAt: new Date().toISOString() }));
    const row = find("eng-dead");
    assert.ok(row, "listed");
    assert.equal(row.status, "halted", "a dead owner cannot still be running");
    assert.match(String(row.error), /orphaned/i, "and says why");
  });

  it("leaves a live run alone even when its timestamp is old", () => {
    // Its own PID: this test process is definitionally alive. The timestamp is
    // deliberately ancient to prove the PID check wins over any age heuristic.
    writeEngagement("eng-live", base({
      engagementId: "eng-live",
      ownerPid: process.pid,
      updatedAt: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
    }));
    const row = find("eng-live");
    assert.ok(row);
    assert.equal(row.status, "running", "a live owner keeps its status regardless of age");
    assert.equal(row.error, undefined, "and is not flagged");
  });

  it("treats a pre-ownerPid record as orphaned once it is long stale", () => {
    writeEngagement("eng-legacy-stale", base({
      engagementId: "eng-legacy-stale",
      updatedAt: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
    }));
    const row = find("eng-legacy-stale");
    assert.ok(row);
    assert.equal(row.status, "halted");
    assert.match(String(row.error), /orphaned/i);
  });

  it("trusts a pre-ownerPid record that is still recent", () => {
    // No ownerPid and a fresh timestamp: could be a CLI run in another process.
    // Guessing it is dead would hide a perfectly live engagement.
    writeEngagement("eng-legacy-fresh", base({ engagementId: "eng-legacy-fresh", updatedAt: new Date().toISOString() }));
    const row = find("eng-legacy-fresh");
    assert.ok(row);
    assert.equal(row.status, "running");
    assert.equal(row.error, undefined);
  });

  it("never rewrites a terminal status", () => {
    for (const status of ["complete", "halted", "blocked"]) {
      const id = `eng-${status}`;
      writeEngagement(id, base({ engagementId: id, status, ownerPid: 0x7ffffff0 }));
      const row = find(id);
      assert.equal(row?.status, status, `${status} stays ${status}`);
    }
  });
});
