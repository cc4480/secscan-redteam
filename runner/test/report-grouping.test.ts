/**
 * The report must not bury its findings under the enumeration.
 *
 * A scoped engagement marks every item in each unreachable battery family
 * not-applicable, and they share one family-level reason. Rendered one per line
 * that was 338 of a 392-line report, all saying the same sentence with a
 * different id, with the actual findings somewhere in the middle.
 *
 * Grouping keeps the information and drops the repetition. The ids are not lost
 * — item-verdicts.json is the machine-readable record and still carries every
 * one — but the report is for a human, and a human needs the shape.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { groupNotApplicable, renderNotApplicable, type VerdictRow } from "../src/report/grouping.js";

const row = (key: string, disposition: string, reason?: string): VerdictRow => ({
  key,
  disposition,
  name: "item",
  reason,
});

function family(prefix: string, target: string, n: number, reason: string): VerdictRow[] {
  return Array.from({ length: n }, (_, i) => row(`${target}:${prefix}-${String(i + 1).padStart(3, "0")}`, "na", reason));
}

describe("grouping the not-applicable verdicts", () => {
  it("collapses one family with one reason into a single group", () => {
    const g = groupNotApplicable(family("SS", "secscan", 120, "secscan.us is not in scope"));
    assert.equal(g.length, 1);
    assert.equal(g[0]!.target, "secscan");
    assert.equal(g[0]!.ids.length, 120);
  });

  it("keeps families with different reasons apart", () => {
    const g = groupNotApplicable([
      ...family("SS", "secscan", 120, "secscan.us is not in scope"),
      ...family("WS", "windows", 108, "no Windows host in scope"),
      ...family("LX", "linux", 110, "no Linux host in scope"),
    ]);
    assert.equal(g.length, 3, "three families, three lines");
  });

  it("splits one family that was declared for two different reasons", () => {
    // A family is not the unit of meaning - the reason is. Two declarations that
    // say different things must not be merged into one line that says one of them.
    const g = groupNotApplicable([
      ...family("SS", "secscan", 10, "secscan.us is not in scope"),
      ...family("SS", "secscan", 5, "duplicate declaration"),
    ]);
    assert.equal(g.length, 2);
    assert.deepEqual(g.map((x) => x.ids.length).sort((a, b) => b - a), [10, 5]);
  });

  it("puts the largest group first", () => {
    const g = groupNotApplicable([
      ...family("WS", "windows", 2, "small"),
      ...family("SS", "secscan", 50, "large"),
    ]);
    assert.equal(g[0]!.ids.length, 50, "the family that dominated the ledger reads first");
  });

  it("ignores everything that is not not-applicable", () => {
    const g = groupNotApplicable([
      row("seclayer:SL-001", "executed-clean"),
      row("seclayer:SL-002", "killed"),
      row("seclayer:SL-003", "blocked", "needs a second account"),
      row("seclayer:SL-004", "na", "not in scope"),
    ]);
    assert.equal(g.length, 1);
    assert.equal(g[0]!.ids.length, 1);
  });

  it("does not lose a verdict that has no reason recorded", () => {
    const g = groupNotApplicable([row("secscan:SS-001", "na")]);
    assert.equal(g[0]!.reason, "(no reason recorded)", "silence is surfaced, not dropped");
  });
});

describe("rendering the groups", () => {
  it("is a handful of lines, not one per item", () => {
    const g = groupNotApplicable([
      ...family("SS", "secscan", 120, "secscan.us is not in scope"),
      ...family("WS", "windows", 108, "no Windows host in scope"),
      ...family("LX", "linux", 110, "no Linux host in scope"),
    ]);
    const lines = renderNotApplicable(g).split("\n").filter((l) => l.startsWith("- "));
    assert.equal(lines.length, 3, "338 items render as 3 lines");
  });

  it("states the count and the id span so the reader can see the shape", () => {
    const g = groupNotApplicable(family("SS", "secscan", 120, "secscan.us is not in scope"));
    const out = renderNotApplicable(g);
    assert.match(out, /\*\*secscan:\*\* 120 items/);
    assert.match(out, /secscan:SS-001 … secscan:SS-120/, "the span, not the enumeration");
    assert.match(out, /secscan\.us is not in scope/, "the reason survives");
  });

  it("points at the machine-readable record for the ids", () => {
    const g = groupNotApplicable(family("SS", "secscan", 3, "r"));
    assert.match(renderNotApplicable(g), /item-verdicts\.json/);
  });

  it("handles a single item without an awkward range", () => {
    const out = renderNotApplicable(groupNotApplicable([row("secscan:SS-042", "na", "r")]));
    assert.match(out, /1 item \(secscan:SS-042\)/);
    assert.ok(!out.includes("…"), "no range for one id");
  });

  it("renders nothing for an empty list", () => {
    assert.equal(renderNotApplicable([]), "");
  });
});
