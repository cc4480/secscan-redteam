/**
 * Task validation: a batteryItem belongs to a probe, never to a recon task.
 *
 * The coordinator picks battery items for probe tasks from the pending list.
 * The directive prompt used to show `batteryItem` on every task shape, so on
 * recon tasks the coordinator filled it with a plausible-looking invention —
 * "seclayer:functionality" — and the runner dutifully tagged every recon tool
 * call with it. Nothing resolved, so every call produced
 *
 *   batteryItem "seclayer:functionality" did not resolve to a selected battery
 *   item — action executed but not reconciled to the ledger.
 *
 * Nineteen of those in one run. The action HAD executed; the reader is invited
 * to think something failed. A recon task has no battery item, so one attached
 * to it is noise and is dropped.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateTasks } from "../src/phases/tasks.js";
import type { Ctx } from "../src/context.js";

/** validateTasks only touches ctx.events for rejections; the recon path needs none. */
function stubCtx(): Ctx {
  const appended: unknown[] = [];
  return { events: { append: (e: unknown) => appended.push(e) } } as unknown as Ctx;
}

describe("task validation — batteryItem belongs to probes only", () => {
  it("drops an invented batteryItem from a recon task", () => {
    const tasks = validateTasks(
      stubCtx(),
      [{ kind: "recon", brief: "map the surface", batteryItem: "seclayer:functionality", maxTurns: 6 }],
      4,
    );
    assert.equal(tasks.length, 1, "the recon task survives");
    assert.equal(tasks[0]!.kind, "recon");
    assert.equal(tasks[0]!.batteryItem, undefined, "its meaningless tag is dropped");
  });

  it("keeps a real batteryItem on a probe task", () => {
    const tasks = validateTasks(
      stubCtx(),
      [{ kind: "probe", brief: "test for SQLi", category: "validation", batteryItem: "SS-042", maxTurns: 6 }],
      4,
    );
    assert.equal(tasks.length, 1);
    assert.equal(tasks[0]!.batteryItem, "SS-042", "probe tags are the point of the field");
  });

  it("still rejects a probe with no category", () => {
    const tasks = validateTasks(stubCtx(), [{ kind: "probe", brief: "vague" }], 4);
    assert.equal(tasks.length, 0, "a category-less probe cannot be tracked, so it never runs");
  });
});
