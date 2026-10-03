/**
 * Streaming engagement records.
 *
 * Three views of the same truth, all under engagements/live/<id>/:
 *  - events.jsonl — one JSON object per line, appended synchronously as each
 *    action happens. This is the LIVE feed: the console tails it.
 *  - state.json  — rewritten on every event: current phase/status, verification
 *    proof, plan, findings so far. One read gives the console everything.
 *  - engagement.md — the human paper trail (Time | Phase | Actor | Action | Result).
 */

import { appendFileSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { basename, join } from "node:path";
import type { EngagementEvent, EngagementMode, EngagementPhase, EngagementStatus, Finding, OperationPlan } from "./types.js";
import type { BatteryCategory } from "./battery.js";
import { maybeRotateLog, type LogRotationConfig } from "./safety/rotation.js";

export interface LiveState {
  engagementId: string;
  target: string;
  mode: EngagementMode;
  objective: string;
  status: EngagementStatus;
  phase: EngagementPhase;
  verified: boolean;
  verificationTs?: string;
  verificationProof?: string;
  plan: OperationPlan | null;
  findings: Finding[];
  batteryCoverage?: Record<BatteryCategory, number>;
  /** The reporter's unified operation narrative (Megazord header for the console). */
  operationNarrative?: string;
  eventCount: number;
  startedAt: string;
  updatedAt: string;
  blockedReason?: string;
}

export class EventLog {
  readonly dir: string;
  readonly engagementId: string;
  private state: LiveState;
  /**
   * v0.23.0: per-instance sequence counter. Previously module-global, which
   * corrupted seq numbering when two engagements ran concurrently in one
   * process (e.g. two UI-launched runs interleaving appends). Each log owns
   * its counter, seeded from its own file state on open.
   */
  private seq = 0;
  /**
   * v0.26.0: log rotation. The first seq number living in the CURRENT
   * events.jsonl (1 for a fresh log, N+1 after a rotation archived seqs
   * 1..N). Lets the `log_rotated` audit event name the archived range.
   */
  private rotationBase = 1;
  private readonly rotation?: LogRotationConfig;

  constructor(
    dir: string,
    engagementId: string,
    init: { target: string; mode: EngagementMode; objective: string },
    rotation?: LogRotationConfig,
  ) {
    this.dir = dir;
    this.engagementId = engagementId;
    this.rotation = rotation;
    mkdirSync(dir, { recursive: true });
    const now = new Date().toISOString();
    this.state = {
      engagementId,
      target: init.target,
      mode: init.mode,
      objective: init.objective,
      status: "authorizing",
      phase: "authorize",
      verified: false,
      plan: null,
      findings: [],
      eventCount: 0,
      startedAt: now,
      updatedAt: now,
    };
    writeFileSync(join(dir, "engagement.md"), `# Engagement ${engagementId}\n\n| Time | Phase | Actor | Action | Result |\n|------|-------|-------|--------|--------|\n`);
    this.persistState();
  }

  /** Reopen an existing engagement dir (for resume / inspection). */
  static open(dir: string): EventLog {
    const statePath = join(dir, "state.json");
    if (!existsSync(statePath)) throw new Error(`[events] no state.json in ${dir}`);
    const raw = JSON.parse(readFileSync(statePath, "utf8")) as LiveState;
    const log = Object.create(EventLog.prototype) as unknown as {
      dir: string;
      engagementId: string;
      state: LiveState;
      seq: number;
    };
    log.dir = dir;
    log.engagementId = raw.engagementId;
    log.state = raw;
    log.seq = raw.eventCount;
    return log as unknown as EventLog;
  }

  append(
    partial: Omit<EngagementEvent, "ts" | "seq" | "engagementId">,
  ): EngagementEvent {
    this.rotateIfNeeded();
    return this.writeEvent(partial);
  }

  /**
   * v0.26.0: rotate events.jsonl (and engagement.md alongside it) when the
   * log exceeds the rotation cap. The fresh file leads with a `log_rotated`
   * audit event naming the archive and its seq range, so PoC bundles'
   * `auditSeq` references stay resolvable. Seq numbers stay continuous
   * across rotations — the audit trail is unbroken.
   */
  private rotateIfNeeded(): void {
    if (!this.rotation) return;
    const outcome = maybeRotateLog(join(this.dir, "events.jsonl"), this.rotation, {
      firstSeq: this.rotationBase,
      lastSeq: this.seq,
    });
    if (!outcome.rotated) return;
    const mdOutcome = maybeRotateLog(join(this.dir, "engagement.md"), this.rotation);
    if (mdOutcome.rotated) {
      writeFileSync(
        join(this.dir, "engagement.md"),
        `# Engagement ${this.engagementId}\n\n| Time | Phase | Actor | Action | Result |\n|------|-------|-------|--------|--------|\n` +
          `| ${new Date().toISOString()} | ${this.state.phase} | runner | log rotated | prior rows archived to ${basename(mdOutcome.archivePath!)} |\n`,
      );
    }
    this.rotationBase = this.seq + 1;
    this.writeEvent({
      phase: this.state.phase,
      actor: "runner",
      action: "log_rotated",
      result: `events.jsonl rotated to ${basename(outcome.archivePath!)} (seq ${outcome.firstSeq}-${outcome.lastSeq}); engagement.md rotated alongside`,
    });
  }

  private writeEvent(
    partial: Omit<EngagementEvent, "ts" | "seq" | "engagementId">,
  ): EngagementEvent {
    const ev: EngagementEvent = {
      ts: new Date().toISOString(),
      seq: ++this.seq,
      engagementId: this.engagementId,
      ...partial,
    };
    appendFileSync(join(this.dir, "events.jsonl"), JSON.stringify(ev) + "\n");
    const mdLine = `| ${ev.ts} | ${ev.phase} | ${ev.actor} | ${ev.action}${ev.attackId ? ` (${ev.attackId})` : ""} | ${oneLine(ev.result)} |\n`;
    appendFileSync(join(this.dir, "engagement.md"), mdLine);
    this.state.eventCount = ev.seq;
    this.state.phase = ev.phase;
    this.state.updatedAt = ev.ts;
    this.persistState();
    return ev;
  }

  /** Merge fields into state.json (status transitions, plan, findings, proof). */
  updateState(patch: Partial<LiveState>): void {
    Object.assign(this.state, patch, { updatedAt: new Date().toISOString() });
    this.persistState();
  }

  get snapshot(): LiveState {
    return { ...this.state, findings: [...this.state.findings] };
  }

  private persistState(): void {
    writeFileSync(join(this.dir, "state.json"), JSON.stringify(this.state, null, 2));
  }
}

function oneLine(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim().slice(0, 300);
}

/** Read-only tail for the console: events after `afterSeq`. */
export function readEvents(dir: string, afterSeq = 0, limit = 200): EngagementEvent[] {
  const path = join(dir, "events.jsonl");
  if (!existsSync(path)) return [];
  const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
  const out: EngagementEvent[] = [];
  for (const line of lines) {
    try {
      const ev = JSON.parse(line) as EngagementEvent;
      if (ev.seq > afterSeq) {
        out.push(ev);
        if (out.length >= limit) break;
      }
    } catch {
      // skip corrupt lines, keep tailing
    }
  }
  return out;
}

/** Read-only state snapshot for the console. */
export function readState(dir: string): LiveState | null {
  const path = join(dir, "state.json");
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as LiveState;
  } catch {
    return null;
  }
}
