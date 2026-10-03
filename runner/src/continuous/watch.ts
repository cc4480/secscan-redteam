/**
 * CONTINUOUS TESTING — watch cycles (v0.16.0).
 *
 * One watch cycle = one engagement run + drift detection against the
 * rolling baseline + alerts. The safety contract:
 *
 *   - Every cycle re-checks scopeValidUntil (fail closed past expiry).
 *   - Every cycle runs the full engagement pipeline — authorization,
 *     ownership verification, ROE, rate limits, kill switch, production
 *     graduation — nothing is weakened because the run is scheduled.
 *   - "Remediated" requires a confirming reverify; anything else that
 *     can't be mechanically resolved stays open as needs-review.
 *   - Drift alerts and ticket sync are best-effort and never break the
 *     cycle; the baseline update is the source of truth and always lands.
 */

export type { WatchCycleOptions, WatchCycleResult, WatchCycleStatus } from "./watch/types.js";
export { runWatchCycle } from "./watch/cycle.js";
export { watchLoop } from "./watch/loop.js";
