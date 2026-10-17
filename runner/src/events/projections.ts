/**
 * Pure event projections (v0.33.0).
 *
 * The engagement record is a flat JSONL stream; the console, the report and the
 * compliance pack all need derived views of it. These functions are the single
 * place those views are computed — no filesystem, no state, each takes the
 * already-read event array and returns a plain result. Keeping them pure means
 * they are unit-testable and reusable by the report, the proof layer and any
 * future query tool (the analogue of AlterEgo's `projections.py`).
 */

import type { EngagementEvent, EngagementPhase } from "../types.js";

/** Per-action activity summary, oldest first preserved. */
export interface ToolStats {
  action: string;
  count: number;
  attackIds: string[];
  firstSeq: number;
  lastSeq: number;
  firstTs?: string;
  lastTs?: string;
}

/** Per-phase actor breakdown. */
export interface PhaseActorStats {
  phase: EngagementPhase;
  actors: Record<string, number>;
  total: number;
}

/** A single event with its resolved cause chain (oldest → newest). */
export interface CausalChain {
  seq: number;
  chain: EngagementEvent[];
}

/** Count events per action, preserving first-seen order. */
export function projectToolStats(events: EngagementEvent[]): ToolStats[] {
  const order: string[] = [];
  const map = new Map<string, ToolStats>();
  for (const ev of events) {
    let stats = map.get(ev.action);
    if (!stats) {
      stats = { action: ev.action, count: 0, attackIds: [], firstSeq: ev.seq, lastSeq: ev.seq, firstTs: ev.ts, lastTs: ev.ts };
      map.set(ev.action, stats);
      order.push(ev.action);
    }
    stats.count += 1;
    stats.lastSeq = ev.seq;
    stats.lastTs = ev.ts;
    if (ev.attackId && !stats.attackIds.includes(ev.attackId)) stats.attackIds.push(ev.attackId);
  }
  return order.map((action) => map.get(action)!);
}

/** Per-phase counts of which actor did what. */
export function projectActorTimeline(events: EngagementEvent[]): PhaseActorStats[] {
  const order: EngagementPhase[] = [];
  const map = new Map<EngagementPhase, PhaseActorStats>();
  for (const ev of events) {
    let stats = map.get(ev.phase);
    if (!stats) {
      stats = { phase: ev.phase, actors: {}, total: 0 };
      map.set(ev.phase, stats);
      order.push(ev.phase);
    }
    stats.actors[ev.actor] = (stats.actors[ev.actor] ?? 0) + 1;
    stats.total += 1;
  }
  return order.map((phase) => map.get(phase)!);
}

/** Actions that record an operator decision (sign-off, escalation, abort, approval). */
const DECISION_ACTION = /signoff|abort|escalat|approve|confirm|tier/i;

/** The operator-decision events, in stream order — the approval timeline. */
export function projectApprovals(events: EngagementEvent[]): EngagementEvent[] {
  return events.filter((ev) => DECISION_ACTION.test(ev.action));
}

/** Events that produced a finding. */
export function projectFindings(events: EngagementEvent[]): EngagementEvent[] {
  return events.filter((ev) => ev.action === "record_finding");
}

/**
 * Resolve the causal chain ending at `seq`, walking `causedBy` links backward.
 * Returns oldest-first, including the event at `seq` itself. An event with no
 * `causedBy` yields a one-element chain. An unresolvable `causedBy` link stops
 * the walk rather than looping.
 */
export function projectCausalChain(events: EngagementEvent[], seq: number): CausalChain {
  const bySeq = new Map<number, EngagementEvent>();
  for (const ev of events) bySeq.set(ev.seq, ev);
  const chain: EngagementEvent[] = [];
  const seen = new Set<number>();
  let cursor: EngagementEvent | undefined = bySeq.get(seq);
  while (cursor && !seen.has(cursor.seq)) {
    seen.add(cursor.seq);
    chain.unshift(cursor);
    cursor = cursor.causedBy !== undefined ? bySeq.get(cursor.causedBy) : undefined;
  }
  return { seq, chain };
}

/** Every event id that is referenced as a cause but never appears — an integrity check. */
export function projectDanglingCauses(events: EngagementEvent[]): number[] {
  const present = new Set(events.map((ev) => ev.seq));
  const dangling: number[] = [];
  for (const ev of events) {
    if (ev.causedBy !== undefined && !present.has(ev.causedBy)) dangling.push(ev.seq);
  }
  return dangling;
}
