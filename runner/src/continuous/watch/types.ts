/**
 * Watch-cycle option/result types.
 */

import type { EngagementInput, EngagementResult, EngagementStatus } from "../../types.js";
import type { RunOptions } from "../../phases.js";
import type { HttpFn } from "../../integrations/index.js";
import type { DriftReport, ReverifyFn } from "../drift.js";

export interface WatchCycleOptions {
  profilePath: string;
  /** Single cycle (also implied by --trigger). The loop calls this per cycle. */
  once?: boolean;
  /** CI/CD change reference, e.g. "deploy abc123" — tags the drift report. */
  trigger?: string;
  env?: NodeJS.ProcessEnv;
  /** Injected HTTP for integrations (tests). */
  http?: HttpFn;
  /** Injected clock (tests). */
  now?: () => Date;
  /** Injected engagement runner (tests). Defaults to runEngagement. */
  runFn?: (input: EngagementInput, opts: RunOptions) => Promise<EngagementResult>;
  /** Injected reverify (tests). Defaults to the real replayer. */
  reverifyFn?: ReverifyFn;
  /** Per-host rate limit override, passed through to runEngagement. */
  maxRpsPerHost?: number;
  /**
   * v0.26.0: log-rotation overrides (CLI --log-max-bytes / --log-max-archives),
   * passed through to runEngagement. Env REDTEAM_LOG_* and the profile's
   * logRetention fill in below these.
   */
  maxLogBytes?: number;
  maxLogArchives?: number;
}

export type WatchCycleStatus = "complete" | "refused" | "error";

export interface WatchCycleResult {
  status: WatchCycleStatus;
  engagementId?: string;
  engagementStatus?: EngagementStatus;
  drift?: DriftReport;
  /** Machine-readable reason for refused/error. */
  reason?: string;
}
