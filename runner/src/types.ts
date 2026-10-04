/**
 * Core types for the live engagement runner.
 *
 * An engagement is a scoped, authorized red-team or black-team operation
 * against web targets. Red = overt, aggressive, full breadth. Black = the
 * covert-ops tier: black-box (zero prior knowledge), stealth-prioritized,
 * OPSEC-strict, undeclared to the target's blue team. BOTH modes require
 * server-authoritative domain-ownership proof before any active testing —
 * covert means covert vs the blue team, NEVER vs the authorization gate.
 */

/** Red = overt/aggressive. Black = covert-ops tier (stealth-prioritized). */
export type EngagementMode = "red" | "black";

import type { TargetId } from "./targets/types.js";
import type { AutonomyTier } from "./accountability/tiers.js";

export type EngagementPhase =
  | "authorize"
  | "plan"
  | "recon"
  | "exploit"
  | "report"
  | "done"
  | "blocked"
  | "halted";

export type EngagementStatus =
  | "queued"
  | "authorizing"
  | "running"
  | "complete"
  | "blocked"
  | "halted";

export type ActorRole = "coordinator" | "recon" | "exploiter" | "reporter" | "runner";

/** Daily blackout window, 24h "HH:MM" strings. May cross midnight. */
export interface BlackoutWindow {
  start: string; // "02:00"
  end: string; // "04:30"
  /** IANA timezone, e.g. "America/Chicago". Defaults to the runner's local tz. */
  tz?: string;
}

/**
 * Rules of Engagement — the contract that bounds every action the runner takes.
 * Mirrors engagements/engagement-template.md §1–§3.
 */
export interface RulesOfEngagement {
  /** Exact in-scope hosts or URLs. Nothing else is ever touched. */
  scope: string[];
  /** ATT&CK technique IDs the engagement must not use, e.g. ["T1110"]. null/omitted = none beyond the mode defaults. */
  excludedTechniques?: string[] | null;
  /** Daily windows during which the runner pauses (no traffic). */
  blackoutWindows?: BlackoutWindow[];
  /** Stop conditions, e.g. ["production outage", "WAF hard-block", "scope crossing"]. */
  stopConditions?: string[];
  /** Who to contact on the client side if something goes wrong. */
  deconflictionContact?: string;
  /** ISO timestamps bounding the test. The runner refuses to run outside it. */
  testWindow?: { start: string; end: string };
  /** Free-text notes (provided creds reference, out-of-scope remarks…). Never paste secrets. */
  notes?: string;
}

export interface EngagementInput {
  /** Target domain or URL, e.g. "secscan.us" or "https://secscan.us". */
  target: string;
  mode: EngagementMode;
  /** What the client wants proven, e.g. "assess external attack surface". */
  objective: string;
  roe: RulesOfEngagement;
  client?: string;
  /** Named human operator accountable for the engagement (attestation + evidence pack). */
  operatorName?: string;
  /**
   * Full-battery unified engagement (target-specific batteries as ONE
   * operation). The coordinator prompt carries the selected target batteries
   * as the plan skeleton; coverage requires all 3 categories × every
   * selected target (or the cell honestly BLOCKED).
   * Set via --full-battery or --target secscan+seclayer.
   */
  fullBattery?: boolean;
  /**
   * Subset of full-battery targets, set via --targets (comma-separated).
   * Defaults to all four (secscan, seclayer, windows, linux).
   */
  targets?: TargetId[];
  /**
   * Test environment for staging→production graduation (v0.13.0 safety case).
   * "staging" (default): full battery, configured rate limits. "production":
   * requires explicit operator confirmation (confirmProduction or
   * REDTEAM_PROD_CONFIRM=1) and caps the per-host rate limit mechanically.
   * Set via --env staging|production.
   */
  environment?: "staging" | "production";
  /**
   * Explicit operator confirmation for a production run. The runner refuses
   * to start a production engagement without it — fail fast, before any
   * packet. Set via --confirm-production.
   */
  confirmProduction?: boolean;
  /**
   * Autonomy tier (v0.17.0 accountability): 0 = observe (read-only recon),
   * 1 = validate (single-step validated exploitation, one step per target),
   * 2 = chain (multi-step attack chains, still non-destructive, no-DoS).
   * Enforced mechanically in the tool dispatcher — not by prompt.
   * Unset → environment default (staging: 2, production: 1).
   * Set via --tier 0|1|2 (or REDTEAM_TIER).
   */
  tier?: AutonomyTier;
  /**
   * Explicit operator approval for Tier 2 on production. The runner refuses
   * to start a Tier 2 production engagement without it — fail fast, before
   * any packet. Set via --confirm-tier2-production (or
   * REDTEAM_TIER2_PROD_CONFIRM=1).
   */
  confirmTier2Production?: boolean;
}

/** One streamed event. Written to events.jsonl as it happens. */
export interface EngagementEvent {
  ts: string; // ISO
  seq: number;
  engagementId: string;
  phase: EngagementPhase;
  actor: ActorRole;
  /** Short machine-readable action, e.g. "scan_url", "http_probe", "plan_step". */
  action: string;
  /** MITRE ATT&CK technique ID when the action maps to one. */
  attackId?: string;
  target?: string;
  /** Human-readable outcome. */
  result: string;
  /** Black-mode OPSEC notes (detection signals, backoff decisions…). */
  opsec?: string;
}

export interface PlanStep {
  phase: EngagementPhase;
  attackId?: string;
  description: string;
  stealthNote?: string;
}

export interface OperationPlan {
  mode: EngagementMode;
  objective: string;
  adversaryProfile: string;
  steps: PlanStep[];
}

export interface Finding {
  id: string; // F-1, F-2…
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  attackIds: string[];
  evidence: string;
  fix: string;
  retest: string;
  status: "confirmed" | "killed" | "deferred";
  /** Named human operator accountable for this finding (v0.17.0). Stamped by the runner at report time. */
  accountableOperator?: string;
}

export interface EngagementResult {
  engagementId: string;
  status: EngagementStatus;
  /** Present when the run was blocked/halted before completion. */
  blockedReason?: string;
  reportPath?: string;
  findings: Finding[];
}

/** Knobs for the runner. All have safe defaults. */
export interface RunnerOptions {
  /** Max LLM turns per phase. Default 10 (recon), 14 (exploit) — see constants. */
  maxReconTurns?: number;
  maxExploitProbes?: number;
  /** Global caps. Defaults: 60 actions, 45 minutes. */
  maxActions?: number;
  maxDurationMs?: number;
  /** Base delay between web probes; black mode adds jitter on top. Default 800ms. */
  probeDelayMs?: number;
  /** Where engagement dirs live. Default: <repo>/engagements/live. */
  engagementsDir?: string;
  /** Skip the LLM entirely (plan/recon/exploit/report become no-ops) — for gate tests. */
  dryRunAgents?: boolean;
}

export interface ResolvedRunnerConfig {
  mcpEndpoint: string;
  mcpToken: string;
  deepseekApiKey: string;
  /** Alibaba Model Studio key — optional since v0.6 (DeepSeek-only policy); the provider still reads it from env when configured. */
  qwenApiKey: string;
  maxReconTurns: number;
  maxExploitProbes: number;
  maxActions: number;
  maxDurationMs: number;
  probeDelayMs: number;
  engagementsDir: string;
  /** Persistent vulnerability registry path. Seeded on first run. */
  registryPath: string;
  dryRunAgents: boolean;
  /**
   * LOCAL SANDBOX MODE ONLY — explicit opt-in (CLI --local-sandbox or
   * REDTEAM_LOCAL_SANDBOX=1). Skips ownership verification and the
   * prober's private-host rejection, but ONLY for targets that already
   * resolve to a private/loopback address. Has no effect on a real
   * domain. Default false. See gate.ts / prober.ts for the invariant.
   */
  localSandbox: boolean;
  /**
   * Operator-configured per-host rate limit (requests/sec) for the v0.13.0
   * safety rate limiter. Env REDTEAM_MAX_RPS. Production caps it at 2
   * mechanically regardless. Undefined = environment default (5 staging,
   * 2 production).
   */
  maxRpsPerHost?: number;
  /**
   * v0.20.0 payload-variant expansion: max variant executions per battery
   * item. Env REDTEAM_MAX_VARIANTS. Undefined = environment default
   * (25 staging, 10 production). Enforced mechanically in dispatch.
   */
  maxVariantsPerItem?: number;
}
