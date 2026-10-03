/**
 * Auto-halt (v0.13.0) — the production safety case.
 *
 * If a target starts erroring, refusing connections, or throwing 5xxs, the
 * runner must NOT keep hammering it — that is how "testing" becomes "outage".
 * The existing global guard halts the whole engagement on three consecutive
 * 5xxs; this module is the per-target version buyers ask for:
 *
 *  - N consecutive target-distress outcomes (default 5), OR
 *  - a failure rate >= 50% over the last 20 outcomes (default window),
 *  → the target is HALTED: further tool calls to it are refused before any
 *    packet, a `target_auto_halt` event is appended, and the halt is named
 *    in the safety manifest + report. Other in-scope targets continue.
 *
 * "Target distress" is classified by the caller (dispatch passes an explicit
 * boolean), not regex-guessed here — the classifier lives next to the tools.
 */

export interface AutoHaltConfig {
  /** Consecutive distress outcomes that halt a target. */
  consecutiveThreshold: number;
  /** Sliding window size for the rate check. */
  windowSize: number;
  /** Failure rate within the window that halts a target (0–1). */
  windowFailureRate: number;
}

export const DEFAULT_AUTOHALT_CONFIG: AutoHaltConfig = {
  consecutiveThreshold: 5,
  windowSize: 20,
  windowFailureRate: 0.5,
};

interface TargetTrack {
  consecutive: number;
  window: boolean[]; // true = distress
  halted: boolean;
  haltReason?: string;
}

export class TargetAutoHalt {
  private tracks = new Map<string, TargetTrack>();
  private cfg: AutoHaltConfig;
  /** Total auto-halts this engagement (manifest). */
  halts = 0;

  constructor(cfg: Partial<AutoHaltConfig> = {}) {
    this.cfg = { ...DEFAULT_AUTOHALT_CONFIG, ...cfg };
  }

  private track(host: string): TargetTrack {
    let t = this.tracks.get(host);
    if (!t) {
      t = { consecutive: 0, window: [], halted: false };
      this.tracks.set(host, t);
    }
    return t;
  }

  /**
   * Record one tool outcome for a host. `distress` = the target errored,
   * refused, timed out, or threw 5xx — i.e. the TARGET may be in trouble,
   * as opposed to a clean negative (404, auth denied, vuln absent).
   */
  recordOutcome(host: string, distress: boolean): string | null {
    const t = this.track(host);
    if (t.halted) return t.haltReason ?? "already halted";
    if (distress) {
      t.consecutive++;
    } else {
      t.consecutive = 0;
    }
    t.window.push(distress);
    if (t.window.length > this.cfg.windowSize) t.window.shift();
    const rate = t.window.filter(Boolean).length / t.window.length;
    let reason: string | null = null;
    if (t.consecutive >= this.cfg.consecutiveThreshold) {
      reason = `${t.consecutive} consecutive target-distress outcomes (possible WAF block, service degradation, or outage)`;
    } else if (t.window.length >= this.cfg.windowSize && rate >= this.cfg.windowFailureRate) {
      reason = `${Math.round(rate * 100)}% distress rate over the last ${t.window.length} outcomes`;
    }
    if (reason) {
      t.halted = true;
      t.haltReason = reason;
      this.halts++;
      return reason;
    }
    return null;
  }

  isHalted(host: string): boolean {
    return this.tracks.get(host)?.halted ?? false;
  }

  haltReason(host: string): string | undefined {
    return this.tracks.get(host)?.haltReason;
  }

  haltedHosts(): string[] {
    return [...this.tracks.entries()].filter(([, t]) => t.halted).map(([h]) => h);
  }

  /** Operator-initiated reset (e.g. after confirming the target recovered). */
  reset(host: string): void {
    this.tracks.delete(host);
  }

  get config(): AutoHaltConfig {
    return { ...this.cfg };
  }
}

/**
 * Classify a dispatch result as target distress (true) or a clean outcome
 * (false). Distress = the target may be hurt: transport errors, timeouts,
 * connection refusals, 5xx. Clean = 404s, auth denials, vuln-absent, scope
 * denials, policy refusals — the target answered fine.
 */
export function isTargetDistress(result: string): boolean {
  const r = result.toLowerCase();
  if (/^halted\b/.test(r)) return false; // our own halt, not target distress
  return (
    /probe failed|connection refused|timed out|timeout|econnreset|econnrefused|enotfound|socket hang up/.test(r) ||
    /http 5\d\d/.test(r) ||
    /\b5\d\d\b.*(error|from target)/.test(r)
  );
}
