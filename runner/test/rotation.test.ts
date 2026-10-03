/**
 * Log rotation tests (v0.26.0): append-only stores (events.jsonl,
 * engagement.md, watch history.jsonl) rotate at a size cap with immutable
 * archives, pruning, and an audit-logged rotation record.
 * No live engagement, no network — tmp dirs only.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  DEFAULT_LOG_MAX_ARCHIVES,
  DEFAULT_LOG_MAX_BYTES,
  maybeRotateLog,
  resolveLogRotationConfig,
  type LogRotationConfig,
} from "../src/safety/rotation.js";
import { EventLog, readEvents } from "../src/events.js";
import { appendHistory } from "../src/continuous/watch/helpers.js";
import { loadWatchProfile } from "../src/continuous/profile.js";

let tmp = "";

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "rotation-test-"));
});
afterEach(() => {
  chmodSync(tmp, 0o755); // in case a test locked it down
  rmSync(tmp, { recursive: true, force: true });
});

const small: LogRotationConfig = { maxBytes: 200, maxArchives: 5 };

describe("resolveLogRotationConfig", () => {
  it("defaults to 50 MiB and 5 archives", () => {
    const c = resolveLogRotationConfig({});
    assert.equal(c.maxBytes, DEFAULT_LOG_MAX_BYTES);
    assert.equal(c.maxArchives, DEFAULT_LOG_MAX_ARCHIVES);
  });
  it("env overrides, opts override env", () => {
    const env = { REDTEAM_LOG_MAX_BYTES: "1048576", REDTEAM_LOG_MAX_ARCHIVES: "3" };
    assert.equal(resolveLogRotationConfig(env).maxBytes, 1048576);
    assert.equal(resolveLogRotationConfig(env, { maxLogBytes: 7 }).maxBytes, 7);
    assert.equal(resolveLogRotationConfig(env, { maxLogArchives: 9 }).maxArchives, 9);
  });
  it("bad env values fail fast naming the variable", () => {
    assert.throws(() => resolveLogRotationConfig({ REDTEAM_LOG_MAX_BYTES: "abc" }), /REDTEAM_LOG_MAX_BYTES/);
    assert.throws(() => resolveLogRotationConfig({ REDTEAM_LOG_MAX_ARCHIVES: "-2" }), /REDTEAM_LOG_MAX_ARCHIVES/);
    assert.throws(() => resolveLogRotationConfig({ REDTEAM_LOG_MAX_BYTES: "1.5" }), /REDTEAM_LOG_MAX_BYTES/);
  });
});

describe("maybeRotateLog", () => {
  it("does nothing under the cap", () => {
    const p = join(tmp, "events.jsonl");
    writeFileSync(p, "small\n");
    const out = maybeRotateLog(p, small);
    assert.equal(out.rotated, false);
    assert.equal(readFileSync(p, "utf8"), "small\n");
  });
  it("missing file is not an error", () => {
    assert.equal(maybeRotateLog(join(tmp, "nope.jsonl"), small).rotated, false);
  });
  it("rotates at/over the cap: immutable archive, seq range returned", () => {
    const p = join(tmp, "events.jsonl");
    writeFileSync(p, "x".repeat(300));
    const out = maybeRotateLog(p, small, { firstSeq: 1, lastSeq: 42 });
    assert.equal(out.rotated, true);
    assert.ok(out.archivePath);
    assert.ok(existsSync(out.archivePath));
    assert.equal(out.firstSeq, 1);
    assert.equal(out.lastSeq, 42);
    assert.equal(readFileSync(out.archivePath, "utf8"), "x".repeat(300));
    // archive is immutable (read-only)
    assert.equal(statSync(out.archivePath).mode & 0o777, 0o444);
    // fresh file does not exist yet — the caller writes it
    assert.equal(existsSync(p), false);
  });
  it("prunes oldest archives beyond the cap", () => {
    const p = join(tmp, "events.jsonl");
    const cfg: LogRotationConfig = { maxBytes: 10, maxArchives: 2 };
    const archives: string[] = [];
    for (let i = 0; i < 3; i++) {
      writeFileSync(p, "x".repeat(20));
      archives.push(maybeRotateLog(p, cfg).archivePath!);
    }
    const remaining = readdirSync(tmp).filter((n) => n.startsWith("events.jsonl."));
    assert.equal(remaining.length, 2);
    assert.equal(existsSync(archives[0]!), false); // oldest pruned
    assert.ok(existsSync(archives[1]!));
    assert.ok(existsSync(archives[2]!));
  });
  it("fails closed with a clear error when the archive cannot be written", () => {
    // Archive name = base + "." + 24-char stamp. A 240-char base pushes the
    // archive name past NAME_MAX (255) so renameSync fails ENAMETOOLONG —
    // deterministic even when tests run as root (chmod tricks don't stop root).
    const p = join(tmp, `${"e".repeat(240)}.jsonl`);
    writeFileSync(p, "x".repeat(300));
    assert.throws(() => maybeRotateLog(p, small), /\[runner\] log rotation: failed to archive/);
  });
});

describe("EventLog rotation", () => {
  it("rotates events.jsonl + engagement.md with a continuous, resolvable audit trail", () => {
    const dir = join(tmp, "eng1");
    // high archive cap so nothing is pruned — full 1..N continuity is checkable
    const log = new EventLog(
      dir, "eng1",
      { target: "t", mode: "red", objective: "o" },
      { maxBytes: 200, maxArchives: 100 },
    );
    for (let i = 0; i < 30; i++) {
      log.append({ phase: "recon", actor: "recon", action: `probe_${i}`, result: "x".repeat(120) });
    }
    const archives = readdirSync(dir).filter((n) => n.startsWith("events.jsonl."));
    assert.ok(archives.length >= 1, "expected at least one rotation");
    const mdArchives = readdirSync(dir).filter((n) => n.startsWith("engagement.md."));
    assert.ok(mdArchives.length >= 1, "engagement.md rotates alongside");
    // md archive is immutable and the fresh md carries a rotation note
    assert.equal(statSync(join(dir, mdArchives[0]!)).mode & 0o777, 0o444);
    assert.match(readFileSync(join(dir, "engagement.md"), "utf8"), /log rotated/);

    // seq continuity: archive seqs + fresh seqs = 1..N with no gaps or dupes
    const seqs: number[] = [];
    const archiveNames = new Set(readdirSync(dir).filter((n) => n.startsWith("events.jsonl.")));
    for (const a of archiveNames) {
      for (const line of readFileSync(join(dir, a), "utf8").split("\n").filter(Boolean)) {
        seqs.push((JSON.parse(line) as { seq: number }).seq);
      }
    }
    let rotations = 0;
    for (const ev of readEvents(dir, 0, 100000)) {
      seqs.push(ev.seq);
      if (ev.action === "log_rotated") {
        rotations++;
        const name = ev.result.match(/rotated to (\S+)/)?.[1];
        const range = ev.result.match(/\(seq (\d+)-(\d+)\)/);
        assert.ok(name && archiveNames.has(name), `log_rotated names a real archive: ${ev.result}`);
        assert.ok(range, `log_rotated names the archived seq range: ${ev.result}`);
      }
    }
    seqs.sort((a, b) => a - b);
    for (let i = 0; i < seqs.length; i++) assert.equal(seqs[i], i + 1, "seq continuous across rotations");
    assert.ok(rotations >= 1, "log_rotated audit events present in the fresh file");
  });
  it("no rotation configured: behavior unchanged", () => {
    const dir = join(tmp, "eng2");
    const log = new EventLog(dir, "eng2", { target: "t", mode: "red", objective: "o" });
    for (let i = 0; i < 10; i++) log.append({ phase: "recon", actor: "recon", action: "a", result: "r" });
    assert.deepEqual(readdirSync(dir).filter((n) => n.startsWith("events.jsonl.")), []);
    assert.equal(readEvents(dir, 0, 100).length, 10);
  });
});

describe("appendHistory rotation", () => {
  it("rotates history.jsonl and records the rotation", () => {
    const home = join(tmp, "watchhome");
    mkdirSync(home, { recursive: true });
    for (let i = 0; i < 40; i++) {
      appendHistory(home, { ts: "t", status: "complete", n: i, pad: "x".repeat(80) }, small);
    }
    const archives = readdirSync(home).filter((n) => n.startsWith("history.jsonl."));
    assert.ok(archives.length >= 1, "history rotated");
    const lines = readFileSync(join(home, "history.jsonl"), "utf8").split("\n").filter(Boolean);
    assert.ok(
      lines.some((l) => (JSON.parse(l) as { status?: string }).status === "log_rotated"),
      "rotation recorded in the fresh history file",
    );
  });
});

describe("watch profile logRetention", () => {
  function profileWith(lr: unknown): string {
    const p = join(tmp, `prof-${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(
      p,
      JSON.stringify({
        version: 1,
        name: "ret-test",
        engagement: { target: "t", mode: "red", objective: "o", roe: { scope: ["t"] } },
        cadence: { intervalHours: 24 },
        scopeValidUntil: "2030-01-01T00:00:00Z",
        logRetention: lr,
      }),
    );
    return p;
  }
  it("accepts valid logRetention", () => {
    const p = loadWatchProfile(profileWith({ maxBytes: 1024, maxArchives: 3 }));
    assert.deepEqual(p.logRetention, { maxBytes: 1024, maxArchives: 3 });
  });
  it("rejects bad logRetention", () => {
    assert.throws(() => loadWatchProfile(profileWith({ maxBytes: -1 })), /logRetention/);
    assert.throws(() => loadWatchProfile(profileWith({ maxArchives: 1.5 })), /logRetention/);
    assert.throws(() => loadWatchProfile(profileWith("big")), /logRetention/);
  });
  it("absent logRetention stays undefined", () => {
    const p = loadWatchProfile(profileWith(undefined));
    assert.equal(p.logRetention, undefined);
  });
});
