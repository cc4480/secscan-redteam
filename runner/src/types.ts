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
  /**
   * Full-battery unified engagement (SecScan webapp + SecLayer MCP API as
   * ONE operation). The coordinator prompt carries both target batteries as
   * the plan skeleton; coverage requires all 3 categories × both targets.
   * Set via --full-battery or --target secscan+seclayer.
   */
  fullBattery?: boolean;
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
  /** Alibaba Model Studio key — the exploiter (Qwen) reads it from env. */
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
}
