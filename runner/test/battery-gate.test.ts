/**
 * The battery gate: an approval is not sufficient while work is pending.
 *
 * Prompt wording was tried three times on this problem. The objective said
 * plainly that a pending item is unfinished work; the budget went from 900
 * actions to 2500; the run used 575 of them and signed off with 62 in-scope
 * items unprobed, down from 70. Six percent. A coordinator that judges the work
 * "good enough" keeps judging it good enough, so the rule is mechanical now —
 * the same as every other gate in this runner.
 *
 * The tests below pin the part that is easy to get wrong: what does NOT block.
 * A gate that refuses on items nobody could reach would make a scoped
 * engagement impossible to finish, and it would look like diligence while doing
 * it.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { batteryGate, type BatteryGateInput } from "../src/phases/batterygate.js";

const base: BatteryGateInput = {
  transition: "exploit→report",
  fullBattery: true,
  pending: 62,
  actions: 575,
  maxActions: 2500,
  rounds: 0,
  maxRounds: 3,
};

const gate = (over: Partial<BatteryGateInput> = {}) => batteryGate({ ...base, ...over });

describe("battery gate — refuses while there is work and budget", () => {
  it("refuses a sign-off with in-scope items pending and budget left", () => {
    // The exact shape of the run that motivated this: 62 pending, 575 of 2500 used.
    const d = gate();
    assert.equal(d.action, "refuse-incomplete");
    assert.equal(d.pending, 62);
  });

  it("approves once the pending count reaches zero", () => {
    assert.equal(gate({ pending: 0 }).action, "approve");
  });

  it("approves when the budget is spent, and says so", () => {
    const d = gate({ actions: 2500 });
    assert.equal(d.action, "approve-incomplete");
    assert.match(d.action === "approve-incomplete" ? d.why : "", /budget is exhausted/);
  });

  it("approves when the forced-round limit is reached, and says so", () => {
    const d = gate({ rounds: 3 });
    assert.equal(d.action, "approve-incomplete");
    assert.match(d.action === "approve-incomplete" ? d.why : "", /round limit/);
  });

  it("stops forcing rounds eventually — a bounded loop, not a livelock", () => {
    // With budget always available, round 0..2 refuse and round 3 approves.
    const seq = [0, 1, 2, 3].map((rounds) => gate({ rounds }).action);
    assert.deepEqual(seq, ["refuse-incomplete", "refuse-incomplete", "refuse-incomplete", "approve-incomplete"]);
  });
});

describe("battery gate — what must NOT block", () => {
  it("ignores the battery on transitions other than exploit→report", () => {
    // plan→recon and recon→exploit are not about battery coverage.
    assert.equal(gate({ transition: "plan→recon" }).action, "approve");
    assert.equal(gate({ transition: "recon→exploit" }).action, "approve");
  });

  it("ignores the battery when the engagement is not a full-battery run", () => {
    // A narrow engagement has no battery to complete, so pending is meaningless.
    assert.equal(gate({ fullBattery: false }).action, "approve");
  });

  it("is not fooled into refusing by a pending count of zero", () => {
    assert.equal(gate({ pending: 0, actions: 0 }).action, "approve");
  });

  it("refuses even at zero actions used, because nothing has been tried", () => {
    const d = gate({ actions: 0 });
    assert.equal(d.action, "refuse-incomplete", "budget untouched means the work is available");
  });
});

describe("battery gate — the decision is total", () => {
  it("always returns one of the three actions", () => {
    const seen = new Set<string>();
    for (const pending of [0, 1, 62, 400]) {
      for (const actions of [0, 100, 2500]) {
        for (const rounds of [0, 3]) {
          for (const fullBattery of [true, false]) {
            const d = gate({ pending, actions, rounds, fullBattery });
            seen.add(d.action);
            assert.ok(["approve", "refuse-incomplete", "approve-incomplete"].includes(d.action));
          }
        }
      }
    }
    assert.ok(seen.has("approve") && seen.has("refuse-incomplete") && seen.has("approve-incomplete"));
  });
});
