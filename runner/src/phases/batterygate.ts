/**
 * The battery gate, as a pure decision.
 *
 * Kept separate from the sign-off orchestration so the rule can be tested
 * directly rather than through a mocked agent loop. The rule is the thing worth
 * pinning: everything around it is plumbing.
 *
 * Why this gate exists at all: prompt wording was tried three times and moved
 * the needle from 70 pending items to 62. The objective said plainly that a
 * pending item is unfinished work; the budget went from 900 actions to 2500; the
 * run used 575 of them and signed off anyway. A coordinator that judges the work
 * "good enough" keeps judging it good enough. Every other gate in this runner is
 * mechanical for that reason, so this one is too.
 *
 * What it deliberately does NOT block on:
 *   - `blocked` — a prerequisite is unmet (no second operator account, no canary
 *     DNS infrastructure). The item is out of reach, and refusing would make the
 *     engagement impossible to finish.
 *   - `na` — the item has no applicable surface in this engagement's scope.
 * Only `pending` blocks: the item was reachable and simply was not reached.
 */

export type BatteryGateDecision =
  | { action: "approve" }
  | { action: "refuse-incomplete"; pending: number }
  | { action: "approve-incomplete"; pending: number; why: string };

export interface BatteryGateInput {
  /** The transition being signed off, e.g. "exploit→report". */
  transition: string;
  /** Battery tracking is only meaningful on a full-battery engagement. */
  fullBattery: boolean;
  /** In-scope items carrying no verdict. */
  pending: number;
  actions: number;
  maxActions: number;
  /** How many forced rounds have already run. */
  rounds: number;
  maxRounds: number;
}

export function batteryGate(i: BatteryGateInput): BatteryGateDecision {
  if (i.transition !== "exploit→report" || !i.fullBattery) return { action: "approve" };
  if (i.pending <= 0) return { action: "approve" };

  if (i.rounds >= i.maxRounds) {
    return {
      action: "approve-incomplete",
      pending: i.pending,
      why: `the forced-round limit (${i.maxRounds}) is reached`,
    };
  }
  if (i.actions >= i.maxActions) {
    return {
      action: "approve-incomplete",
      pending: i.pending,
      why: `the action budget is exhausted (${i.actions}/${i.maxActions})`,
    };
  }
  return { action: "refuse-incomplete", pending: i.pending };
}
