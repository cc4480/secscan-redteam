/**
 * Web UI types (v0.22.0) — the dashboard wired directly to the CLI's code
 * paths. Every API endpoint calls the same functions the CLI calls.
 */

import type { EngagementStatus } from "../types.js";

/** Validated launch request body for POST /api/engagements. */
export interface UiLaunchRequest {
  target: string;
  mode: "red" | "black";
  objective: string;
  scope: string[];
  client?: string;
  operatorName?: string;
  fullBattery?: boolean;
  targets?: string[];
  environment?: "staging" | "production";
  confirmProduction?: boolean;
  tier?: 0 | 1 | 2;
  confirmTier2Production?: boolean;
  excludedTechniques?: string[];
  dryRun?: boolean;
  localSandbox?: boolean;
}

/** One tracked engagement, live or historical. */
export interface StoredEngagement {
  id: string;
  dir: string;
  status: "starting" | "running" | EngagementStatus;
  startedAt: string;
  /** Set while the engagement is live in this process (kill-switch handle). */
  abort?: (reason: string) => void;
  error?: string;
}

/** Background job (reverify-execute, watch trigger). */
export interface UiJob {
  id: string;
  kind: "reverify" | "watch-trigger";
  status: "running" | "done" | "failed";
  startedAt: string;
  finishedAt?: string;
  result?: unknown;
  error?: string;
}

export interface UiServerOptions {
  port?: number;
  /** Default 127.0.0.1. Any other value requires explicit operator intent. */
  listen?: string;
  engagementsDir?: string;
}
