/**
 * Concurrency tests (v0.23.0): two engagements live in one process.
 *
 * Regression coverage for the audit-log corruption class:
 *  - EventLog sequence counters are per-instance (was module-global; two
 *    interleaved engagements corrupted each other's seq numbering).
 *  - Registry verdict writes are atomic read-modify-write transactions
 *    (was load-at-start / blind-save-at-verdict; the second writer silently
 *    lost the first writer's entries).
 * No live engagement, no network — tmp dirs only.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EventLog, readEvents } from "../src/events.js";
import {
  emptyRegistry,
  loadRegistryFile,
  transactRegistryFile,
  type VulnerabilityRegistry,
} from "../src/registry.js";
import { writeFindingToRegistry, writeKilledToRegistry } from "../src/dispatch/verdicts.js";
import type { Ctx, KilledLive, LiveFinding } from "../src/context.js";

let tmp = "";

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "concurrency-test-"));
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function makeLog(id: string): EventLog {
  return new EventLog(join(tmp, id), id, { target: "t", mode: "red", objective: "o" });
}

/** Minimal Ctx for the verdict writers: real EventLog, in-memory registry. */
function makeCtx(id: string, registryPath: string): Ctx {
  return {
    events: makeLog(id),
    registry: emptyRegistry(),
    registryPath,
    fingerprint: { host: "h", stack: [], appType: "t" },
  } as unknown as Ctx;
}

function finding(vulnClass: string, n: number): LiveFinding {
  return {
    severity: "high",
    title: `${vulnClass} ${n}`,
    vulnClass,
    attackId: "T1190",
    evidence: "e",
    payload: `p${n}`,
  };
}

describe("EventLog per-instance sequencing", () => {
  it("two interleaved logs keep independent 1..N sequences", () => {
    const a = makeLog("eng-a");
    const b = makeLog("eng-b");
    for (let i = 0; i < 5; i++) {
      a.append({ phase: "recon", actor: "recon", action: `a${i}`, result: "ok" });
      b.append({ phase: "recon", actor: "recon", action: `b${i}`, result: "ok" });
    }
    const ea = readEvents(a.dir);
    const eb = readEvents(b.dir);
    assert.deepEqual(ea.map((e) => e.seq), [1, 2, 3, 4, 5]);
    assert.deepEqual(eb.map((e) => e.seq), [1, 2, 3, 4, 5]);
    assert.ok(ea.every((e) => e.engagementId === "eng-a"));
    assert.ok(eb.every((e) => e.engagementId === "eng-b"));
    assert.equal(a.snapshot.eventCount, 5);
    assert.equal(b.snapshot.eventCount, 5);
  });

  it("EventLog.open resumes the counter from the file's own eventCount", () => {
    const dir = join(tmp, "eng-c");
    const log = new EventLog(dir, "eng-c", { target: "t", mode: "red", objective: "o" });
    log.append({ phase: "recon", actor: "recon", action: "x", result: "ok" });
    log.append({ phase: "recon", actor: "recon", action: "y", result: "ok" });
    const reopened = EventLog.open(dir);
    const ev = reopened.append({ phase: "recon", actor: "recon", action: "z", result: "ok" });
    assert.equal(ev.seq, 3);
    // Opening one log must not disturb another live log's counter.
    const other = makeLog("eng-d");
    const ev2 = other.append({ phase: "recon", actor: "recon", action: "w", result: "ok" });
    assert.equal(ev2.seq, 1);
  });
});

describe("registry atomic transactions", () => {
  it("two concurrent engagements lose no verdicts (lost-update regression)", () => {
    const path = join(tmp, "registry.json");
    const ctxA = makeCtx("eng-a", path);
    const ctxB = makeCtx("eng-b", path);
    // Interleaved verdict writes, as two live engagements would produce.
    writeFindingToRegistry(ctxA, finding("sqli", 1));
    writeFindingToRegistry(ctxB, finding("xss", 1));
    writeKilledToRegistry(ctxA, { hypothesis: "h-a", killingObservation: "dead-a" } as KilledLive);
    writeFindingToRegistry(ctxB, finding("ssrf", 2));
    writeKilledToRegistry(ctxB, { hypothesis: "h-b", killingObservation: "dead-b" } as KilledLive);
    const file = loadRegistryFile(path)!;
    assert.equal(file.confirmed.length, 3);
    assert.equal(file.killed.length, 2);
    // IDs are unique across both writers.
    const ids = file.confirmed.map((e) => e.id);
    assert.equal(new Set(ids).size, ids.length);
    // In-memory mirrors stay accurate for in-engagement queries.
    assert.equal(ctxA.registry.confirmed.length, 1);
    assert.equal(ctxB.registry.confirmed.length, 2);
  });

  it("dedupe still works inside a transaction", () => {
    const path = join(tmp, "registry.json");
    const ctx = makeCtx("eng-a", path);
    const f = finding("sqli", 1);
    writeFindingToRegistry(ctx, f);
    writeFindingToRegistry(ctx, { ...f });
    assert.equal(loadRegistryFile(path)!.confirmed.length, 1);
  });

  it("transactRegistryFile runs read-modify-write atomically", () => {
    const path = join(tmp, "registry.json");
    const seen: number[] = [];
    transactRegistryFile(path, (reg: VulnerabilityRegistry) => {
      seen.push(reg.confirmed.length);
      reg.confirmed.push({
        id: "vuln-x",
        kind: "confirmed",
        date: "d",
        engagementId: "e",
        target: { host: "h", stack: [], appType: "t" },
        vulnClass: "c",
        technique: "t",
        payloadPattern: "p",
        evidenceRef: "r",
        severity: "low",
      });
    });
    transactRegistryFile(path, (reg: VulnerabilityRegistry) => {
      seen.push(reg.confirmed.length);
    });
    assert.deepEqual(seen, [0, 1]);
  });
});
