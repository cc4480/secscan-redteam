/**
 * Per-target rate limiting (v0.13.0) — the production safety case.
 *
 * Buyers demand stated, mechanical rate limits — not "the agents are told to
 * be gentle". This is a per-host token bucket the RUNNER enforces: every
 * probe/exec tool acquires a slot before any packet leaves. Black-mode
 * jitter already exists; this is the hard ceiling underneath it.
 *
 * Defaults: 5 requests/sec per host in staging, 2 in production (the
 * production cap is applied mechanically even if the operator configures
 * higher). Overridable via REDTEAM_MAX_RPS / resolveConfig maxRpsPerHost.
 */

export interface RateLimitConfig {
  /** Max sustained requests per second, per host. */
  rpsPerHost: number;
  /** Burst allowance (tokens available immediately). Defaults to rpsPerHost. */
  burst?: number;
}

export const DEFAULT_STAGING_RPS = 5;
export const DEFAULT_PRODUCTION_RPS = 2;
export const PRODUCTION_RPS_CAP = 2;

interface Bucket {
  tokens: number;
  lastRefillMs: number;
}

/**
 * Per-host token bucket. `acquire(host)` resolves once a token is available
 * (sleeping as needed); `tryAcquire` is the non-blocking check for tests.
 * Time source is injectable so tests don't sleep.
 */
export class TargetRateLimiter {
  readonly rpsPerHost: number;
  readonly burst: number;
  private buckets = new Map<string, Bucket>();
  private now: () => number;
  /** Total ms agents spent waiting on the limiter this engagement (manifest). */
  throttledMs = 0;
  /** Total acquires granted (manifest). */
  acquires = 0;

  constructor(cfg: RateLimitConfig, now: () => number = Date.now) {
    if (!Number.isFinite(cfg.rpsPerHost) || cfg.rpsPerHost <= 0) {
      throw new Error(`[safety] rpsPerHost must be a positive number, got ${cfg.rpsPerHost}`);
    }
    this.rpsPerHost = cfg.rpsPerHost;
    this.burst = cfg.burst && cfg.burst > 0 ? cfg.burst : cfg.rpsPerHost;
    this.now = now;
  }

  private bucket(host: string): Bucket {
    let b = this.buckets.get(host);
    if (!b) {
      b = { tokens: this.burst, lastRefillMs: this.now() };
      this.buckets.set(host, b);
    }
    return b;
  }

  private refill(b: Bucket, nowMs: number): void {
    const elapsed = Math.max(0, nowMs - b.lastRefillMs);
    b.tokens = Math.min(this.burst, b.tokens + (elapsed / 1000) * this.rpsPerHost);
    b.lastRefillMs = nowMs;
  }

  /** Non-blocking: true when a token is available right now. */
  tryAcquire(host: string): boolean {
    const b = this.bucket(host);
    this.refill(b, this.now());
    if (b.tokens >= 1) {
      b.tokens -= 1;
      this.acquires++;
      return true;
    }
    return false;
  }

  /** Blocking: waits until a token is available, then takes it. */
  async acquire(host: string): Promise<number> {
    const started = this.now();
    for (;;) {
      if (this.tryAcquire(host)) {
        this.throttledMs += this.now() - started;
        return this.now() - started;
      }
      // Time until the next token, plus a small margin. Never busy-waits.
      const waitMs = Math.min(1000, Math.ceil(1000 / this.rpsPerHost) + 5);
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }

  /** For the manifest: hosts currently tracked. */
  trackedHosts(): string[] {
    return [...this.buckets.keys()];
  }
}

/**
 * Resolve the effective per-host RPS: operator config, with the production
 * cap applied mechanically (production never exceeds PRODUCTION_RPS_CAP,
 * even if configured higher — the manifest records when the cap bites).
 */
export function resolveEffectiveRps(
  environment: "staging" | "production",
  configuredRps?: number,
): { rps: number; productionCapApplied: boolean } {
  const configured =
    configuredRps && Number.isFinite(configuredRps) && configuredRps > 0
      ? configuredRps
      : environment === "production"
        ? DEFAULT_PRODUCTION_RPS
        : DEFAULT_STAGING_RPS;
  if (environment === "production" && configured > PRODUCTION_RPS_CAP) {
    return { rps: PRODUCTION_RPS_CAP, productionCapApplied: true };
  }
  return { rps: configured, productionCapApplied: false };
}
