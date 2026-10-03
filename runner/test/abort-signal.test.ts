/**
 * Cross-process kill switch tests (v0.25.0).
 *
 * The UI cannot reach into a CLI-launched engagement's process, so it
 * writes abort.json into the engagement dir; the dispatcher checks for it
 * on every dispatch cycle. No live engagement, no network: the
 * "two-process" flow is simulated with a real engagement dir on disk —
 * one side writes the marker (what the UI endpoint does), the other side
 * runs checkAbortSignal against a minimal ctx (what dispatchTool does).
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  ABORT_FILE_NAME,
  readAbortFile,
  writeAbortFile,
  consumeAbortFile,
} from "../src/safety/index.js";
import { checkAbortSignal } from "../src/dispatch/router.js";
import { HaltError, type Ctx } from "../src/context.js";
import type { EngagementPhase } from "../src/types.js";

let tmp = "";
beforeEach(() => {
  tmp = join(tmpdir(), `abort-signal-test-${process.pid}-${Date.now()}`);
  mkdirSync(tmp, { recursive: true });
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** Minimal ctx: checkAbortSignal only touches hostKill, safety, events. */
function fakeCtx(dir: string) {
  const appended: Array<{ action: string; result: string }> = [];
  const ctx = {
    hostKill: { aborted: false, controllers: new Set<AbortController>() },
    safety: { killSwitchAborts: 0 },
    events: {
      dir,
      append: (e: { action: string; result: string }) => {
        appended.push({ action: e.action, result: e.result });
      },
    },
  } as unknown as Ctx;
  return { ctx, appended };
}

const PHASE = "exploit" as EngagementPhase;

describe("abort.json file signal", () => {
  it("round-trips through write/read", () => {
    writeAbortFile(tmp, { requestedAt: "2026-10-03T10:00:00Z", by: "ui-operator", reason: "test" });
    const sig = readAbortFile(tmp);
    assert.deepEqual(sig, { requestedAt: "2026-10-03T10:00:00Z", by: "ui-operator", reason: "test" });
  });

  it("missing file reads as no abort requested", () => {
    assert.equal(readAbortFile(tmp), undefined);
  });

  it("corrupt file reads as no abort requested (never a spurious abort)", () => {
    writeFileSync(join(tmp, ABORT_FILE_NAME), "not json{{{");
    assert.equal(readAbortFile(tmp), undefined);
  });

  it("wrong shape reads as no abort requested", () => {
    writeFileSync(join(tmp, ABORT_FILE_NAME), JSON.stringify({ nope: 1 }));
    assert.equal(readAbortFile(tmp), undefined);
  });

  it("consume removes the marker; missing file does not throw", () => {
    writeAbortFile(tmp, { requestedAt: "2026-10-03T10:00:00Z" });
    consumeAbortFile(tmp);
    assert.equal(existsSync(join(tmp, ABORT_FILE_NAME)), false);
    consumeAbortFile(tmp); // no-op, no throw
  });
});

describe("checkAbortSignal (dispatcher side)", () => {
  it("is a no-op with no marker", () => {
    const { ctx } = fakeCtx(tmp);
    checkAbortSignal(ctx, PHASE);
    assert.equal(ctx.hostKill.aborted, false);
    assert.equal(ctx.safety.killSwitchAborts, 0);
  });

  it("performs the full abort sequence on a marker and throws HaltError", () => {
    const { ctx, appended } = fakeCtx(tmp);
    const ctrl = new AbortController();
    ctx.hostKill.controllers.add(ctrl);
    writeAbortFile(tmp, { requestedAt: "2026-10-03T10:00:00Z", by: "ui-operator", reason: "operator stop" });

    assert.throws(() => checkAbortSignal(ctx, PHASE), HaltError);
    assert.equal(ctx.hostKill.aborted, true);
    assert.equal(ctrl.signal.aborted, true, "in-flight controller terminated");
    assert.equal(ctx.hostKill.controllers.size, 0);
    assert.equal(ctx.safety.killSwitchAborts, 1);
    const evt = appended.find((e) => e.action === "abort_engagement");
    assert.ok(evt, "abort_engagement audit event logged");
    assert.match(evt!.result, /ui-operator/);
    assert.match(evt!.result, /operator stop/);
    assert.equal(existsSync(join(tmp, ABORT_FILE_NAME)), false, "marker consumed");
  });

  it("is safe when already aborted (no double count, no throw from itself)", () => {
    const { ctx } = fakeCtx(tmp);
    ctx.hostKill.aborted = true;
    writeAbortFile(tmp, { requestedAt: "2026-10-03T10:00:00Z" });
    checkAbortSignal(ctx, PHASE); // returns; dispatchTool's own check throws first
    assert.equal(ctx.safety.killSwitchAborts, 0);
  });

  it("ignores a corrupt marker", () => {
    const { ctx } = fakeCtx(tmp);
    writeFileSync(join(tmp, ABORT_FILE_NAME), "garbage");
    checkAbortSignal(ctx, PHASE);
    assert.equal(ctx.hostKill.aborted, false);
  });
});

describe("two-process flow (UI writes, CLI dispatcher acts)", () => {
  it("a marker written 'by the UI' aborts the 'CLI' dispatcher with full audit", () => {
    // Side A — the CLI-launched engagement's dispatch loop.
    const { ctx, appended } = fakeCtx(tmp);
    // Side B — what POST /api/engagements/:id/abort does for a non-live id.
    writeAbortFile(tmp, {
      requestedAt: "2026-10-03T10:00:00Z",
      by: "ui-operator",
      reason: "operator abort from UI",
    });
    assert.equal(existsSync(join(tmp, ABORT_FILE_NAME)), true);
    // Side A — next dispatch cycle.
    assert.throws(() => checkAbortSignal(ctx, PHASE), (e: unknown) => e instanceof HaltError);
    assert.equal(ctx.hostKill.aborted, true);
    assert.ok(appended.some((e) => e.action === "abort_engagement"));
    assert.equal(existsSync(join(tmp, ABORT_FILE_NAME)), false);
  });
});
