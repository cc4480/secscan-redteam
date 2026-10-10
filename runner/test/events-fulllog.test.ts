/**
 * Full event-log reads (audit H4 regression). No network, no API keys.
 *
 * readEvents() is a paging TAIL over the current events.jsonl (default:
 * first 200 events) — right for the live console feed, wrong for verdicts.
 * Report-time consumers (PoC bundles, zero-disruption record) must read
 * the FULL log via iterateEvents/readAllEvents: rotation archives first,
 * then the current file, no 200-event truncation. These tests pin that:
 *  - every event comes back, in seq order, far past event 200;
 *  - a finding validated after seq 200 still gets its PoC bundle — and
 *    still gets it when rotation has archived the validating event;
 *  - a destructive-action-executed event after seq 200 makes the
 *    zero-disruption verdict FAIL, where the old prefix read said CLEAN.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventLog, iterateEvents, readAllEvents, readEvents, readState } from "../src/events.js";
import { buildPocBundle } from "../src/proof/bundle.js";
import { buildZeroDisruptionRecord, disruptionVerdict } from "../src/safety/index.js";
import type { Finding } from "../src/types.js";

const MARKER_RESULT =
  "msf exploit/windows/smb/ms17_010_eternalblue vs target.example: MARKER ECHOED — command execution validated. Output: REDTEAM-MARKER-late42";

const FINDING: Finding = {
  id: "F-late",
  severity: "critical",
  title: "Late-run RCE",
  attackIds: ["T1190"],
  evidence: "marker echoed",
  fix: "patch",
  retest: "re-run",
  status: "confirmed",
};

const META = { engagementId: "eng-full", target: "target.example", operator: "op" };

describe("iterateEvents / readAllEvents — no 200-event truncation", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rt-fulllog-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function appendFiller(log: EventLog, n: number, pad = ""): void {
    for (let i = 0; i < n; i++) {
      log.append({ phase: "recon", actor: "recon", action: "reasoning", result: `note ${i}${pad}` });
    }
  }

  it("returns every event in seq order, far past the tail reader's 200-event page", () => {
    const log = new EventLog(dir, "eng-250", { target: "t", mode: "red", objective: "o" });
    appendFiller(log, 250);

    // The tail reader's contract is unchanged: one 200-event page.
    assert.equal(readEvents(dir).length, 200);

    const all = readAllEvents(dir);
    assert.equal(all.length, 250);
    assert.deepEqual(
      all.map((e) => e.seq),
      Array.from({ length: 250 }, (_, i) => i + 1),
    );
    // The streaming iterator agrees with the materialized read.
    assert.deepEqual([...iterateEvents(dir)], all);
  });

  it("honors afterSeq and skips corrupt lines", () => {
    const log = new EventLog(dir, "eng-corrupt", { target: "t", mode: "red", objective: "o" });
    appendFiller(log, 5);
    appendFileSync(join(dir, "events.jsonl"), "this is not json\n");
    appendFiller(log, 1);

    assert.equal(readAllEvents(dir).length, 6);
    assert.deepEqual(
      [...iterateEvents(dir, 3)].map((e) => e.seq),
      [4, 5, 6],
    );
  });

  it("empty for a dir with no event log", () => {
    assert.deepEqual(readAllEvents(join(dir, "nope")), []);
    assert.deepEqual([...iterateEvents(join(dir, "nope"))], []);
  });

  it("safety: destructive-executed after seq 200 fails the verdict (prefix read said CLEAN)", () => {
    const log = new EventLog(dir, "eng-safety", { target: "t", mode: "red", objective: "o" });
    appendFiller(log, 249);
    log.append({
      phase: "exploit", actor: "exploiter", action: "ssh_exec", target: "t",
      result: "ssh t: destructive action executed: rm -rf /var/www (fired despite policy)",
    });

    // The old consumer read (tail page from seq 0) never reaches seq 250.
    const prefixRecord = buildZeroDisruptionRecord(readEvents(dir));
    assert.equal(prefixRecord.destructiveActionsFired, 0);
    assert.match(disruptionVerdict(prefixRecord), /^CLEAN/);

    const fullRecord = buildZeroDisruptionRecord(readAllEvents(dir));
    assert.equal(fullRecord.destructiveActionsFired, 1);
    assert.match(disruptionVerdict(fullRecord), /^FAIL/);
  });

  it("proof: bundle is built for a finding validated after seq 200", () => {
    const log = new EventLog(dir, "eng-proof", { target: "t", mode: "red", objective: "o" });
    appendFiller(log, 240);
    log.append({
      phase: "exploit", actor: "exploiter", action: "msf_exec", attackId: "T1190",
      target: "target.example", result: MARKER_RESULT,
    });

    // Old read: the validating event is past the 200-event page — no bundle.
    const old = buildPocBundle({ finding: FINDING, events: readEvents(dir), engagement: META, secrets: [] });
    assert.equal(old.bundle, null);
    assert.match(old.reason!, /no correlated tool execution/);

    const { bundle, reason } = buildPocBundle({ finding: FINDING, events: readAllEvents(dir), engagement: META, secrets: [] });
    assert.ok(bundle, `expected bundle from full log, got: ${reason}`);
    assert.equal(bundle!.validationTier, "execution");
    assert.equal(bundle!.steps.length, 1);
    assert.equal(bundle!.steps[0]!.seq, 241);
  });

  it("rotated log: archives are read — archived validation still proves, seqs stay continuous", () => {
    const rdir = join(dir, "eng-rot");
    const log = new EventLog(
      rdir, "eng-rot",
      { target: "t", mode: "red", objective: "o" },
      { maxBytes: 1024, maxArchives: 100 },
    );
    // The validating event goes FIRST so rotations push it into an archive.
    log.append({
      phase: "exploit", actor: "exploiter", action: "msf_exec", attackId: "T1190",
      target: "target.example", result: MARKER_RESULT,
    });
    appendFiller(log, 250, "x".repeat(60));
    // A late disruptive event, deep past seq 200 in the current file.
    log.append({
      phase: "exploit", actor: "exploiter", action: "ssh_exec", target: "t",
      result: "ssh t: destructive action executed: rm -rf /var/www (fired despite policy)",
    });

    const archives = readdirSync(rdir).filter((n) => n.startsWith("events.jsonl."));
    assert.ok(archives.length >= 1, "expected rotation archives");

    // The validating event survives ONLY in an archive: even an unbounded
    // read of the current file cannot see it.
    const currentOnly = readEvents(rdir, 0, Number.MAX_SAFE_INTEGER);
    assert.ok(!currentOnly.some((e) => e.action === "msf_exec"), "marker event must live only in an archive");
    assert.equal(buildPocBundle({ finding: FINDING, events: currentOnly, engagement: META, secrets: [] }).bundle, null);

    // Full read: unbroken seq trail across archives + current file.
    const total = readState(rdir)!.eventCount;
    const all = readAllEvents(rdir);
    assert.equal(all.length, total);
    assert.deepEqual(
      all.map((e) => e.seq).sort((a, b) => a - b),
      Array.from({ length: total }, (_, i) => i + 1),
    );
    assert.ok(all.some((e) => e.action === "log_rotated"), "rotation audit events are part of the trail");

    const { bundle, reason } = buildPocBundle({ finding: FINDING, events: all, engagement: META, secrets: [] });
    assert.ok(bundle, `expected bundle from archived validation, got: ${reason}`);
    assert.equal(bundle!.validationTier, "execution");

    const record = buildZeroDisruptionRecord(all);
    assert.equal(record.destructiveActionsFired, 1);
    assert.match(disruptionVerdict(record), /^FAIL/);

    // Raw-file sanity: events.jsonl really is far past 200 total lines.
    const rawLines = readFileSync(join(rdir, "events.jsonl"), "utf8").split("\n").filter(Boolean).length;
    assert.ok(total > 200 && rawLines < total, "current file is only the tail of the log");
  });
});
