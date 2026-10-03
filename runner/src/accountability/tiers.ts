/**
 * Autonomy tiers (v0.17.0) — graduated, MECHANICALLY enforced agent autonomy.
 *
 * Buyers demand OWASP-style autonomy tiers per environment: agents own
 * frequency/retest, humans own critical assets and accountability. These
 * tiers are enforced in the tool dispatcher (phases.ts), never by prompt:
 *
 *  - Tier 0 (observe): read-only recon/enumeration only. No exploitation
 *    tool fires — the dispatcher refuses them before any packet.
 *  - Tier 1 (validate): Tier 0 + single-step validated exploitation with
 *    canary markers only. One validated exploit step per target per
 *    engagement; a second step against the same target is refused as
 *    chaining — it needs Tier 2 (operator-approved).
 *  - Tier 2 (chain): Tier 1 + multi-step attack chains toward critical
 *    assets (msf_exec run), still non-destructive, still no-DoS.
 *
 * Tiers describe what the agents MAY do. They are a control boundary, never
 * a safety guarantee, and never imply the human did the work — the
 * methodology doc states the agent-driven approach truthfully; the
 * accountability record adds who supervised and approved.
 */

export type AutonomyTier = 0 | 1 | 2;

export const TIER_NAMES: Record<AutonomyTier, string> = {
  0: "observe",
  1: "validate",
  2: "chain",
};

export const TIER_DESCRIPTIONS: Record<AutonomyTier, string> = {
  0: "Read-only recon/enumeration. No exploitation tool fires.",
  1: "Single-step validated exploitation with canary markers only — one validated step per target; chaining needs Tier 2.",
  2: "Multi-step attack chains toward critical assets (still non-destructive, still no-DoS).",
};

/** Default tier per environment: staging runs the full battery, production validates carefully. */
export function defaultTier(environment: "staging" | "production"): AutonomyTier {
  return environment === "production" ? 1 : 2;
}

export const TIER_ENV = "REDTEAM_TIER";
export const TIER2_PROD_CONFIRM_ENV = "REDTEAM_TIER2_PROD_CONFIRM";

/**
 * Parse a tier from CLI/env. undefined/empty → undefined (caller applies the
 * environment default). Anything else unrecognized fails LOUD — refusing to
 * guess about autonomy.
 */
export function parseTier(raw: string | undefined): AutonomyTier | undefined {
  const v = (raw ?? "").trim();
  if (!v) return undefined;
  if (v === "0" || v.toLowerCase() === "observe") return 0;
  if (v === "1" || v.toLowerCase() === "validate") return 1;
  if (v === "2" || v.toLowerCase() === "chain") return 2;
  throw new Error(`[accountability] bad autonomy tier ${JSON.stringify(raw)} — want 0|1|2 (observe|validate|chain). Refusing to guess.`);
}

/** True when the operator explicitly approved Tier 2 on production. */
export function tier2ProductionConfirmed(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env[TIER2_PROD_CONFIRM_ENV] ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

/**
 * Mechanical gate for Tier 2 on production. Tier 2 chains toward critical
 * assets — on production that needs an explicit operator decision, exactly
 * like the staging→production graduation itself. Fail fast, before the
 * engagement directory is even created.
 */
export function requireTier2ProductionApproval(tier: AutonomyTier, environment: "staging" | "production", confirmed: boolean): void {
  if (tier === 2 && environment === "production" && !confirmed) {
    throw new Error(
      `[accountability] Tier 2 (chain) on PRODUCTION requires explicit operator approval. ` +
        `Set ${TIER2_PROD_CONFIRM_ENV}=1 (or pass --confirm-tier2-production) to approve multi-step attack chains against production infrastructure. ` +
        `Without it the runner refuses to start.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Tool classification — the minimum tier that may fire each tool.
// Evaluated in dispatchTool (phases.ts) BEFORE any packet, rate-limiter
// slot, or executor involvement. Unknown tools fail closed to Tier 2.
// ---------------------------------------------------------------------------

/** Tool names that never touch a target: pure bookkeeping / control. */
const TIER0_TOOLS = new Set([
  "get_scan_status",
  "get_report",
  "list_recent_scans",
  "get_account",
  "query_registry",
  "update_target_map",
  "record_finding",
  "record_killed",
  "http_probe",
  "burst_probe",
  // abort_engagement is always allowed — the kill switch must work at every tier.
  "abort_engagement",
]);

/** Single validated exploit steps (one command, canary marker). Never chains by itself. */
const TIER1_TOOLS = new Set([
  "ssh_exec",
  "smb_exec",
  "winrm_exec",
  "winrm_probe",
  "rdp_auth",
  "rdp_shadow_prep",
  "smb_pth",
  "ad_enum",
  "krb_ptt",
  "ssh_agent_audit",
  "nfs_enum",
]);

/**
 * Minimum tier for a tool call. Two tools are argument-sensitive:
 *  - scan_url: passive scan is Tier 0; aggressive=true runs the active test
 *    tier (injection, XSS, SSRF) → Tier 1.
 *  - msf_exec: search/suggest never fire → Tier 1; run fires exploits → Tier 2.
 */
export function toolMinTier(toolName: string, args: Record<string, unknown> = {}): AutonomyTier {
  if (toolName === "scan_url") {
    return args["aggressive"] === true ? 1 : 0;
  }
  if (toolName === "msf_exec") {
    return args["action"] === "run" ? 2 : 1;
  }
  if (TIER0_TOOLS.has(toolName)) return 0;
  if (TIER1_TOOLS.has(toolName)) return 1;
  // Unknown tool: fail closed to the highest tier — a tool the classifier
  // doesn't know is never fired at a low tier.
  return 2;
}

/**
 * Tools whose successful execution counts as a "validated exploit step" for
 * the Tier 1 chain budget. Enumeration-flavored Tier 1 tools (winrm_probe,
 * ad_enum, nfs_enum, ssh_agent_audit, rdp_shadow_prep) observe; they don't
 * execute against the target, so they don't consume the budget.
 */
const EXPLOIT_STEP_TOOLS = new Set(["ssh_exec", "smb_exec", "winrm_exec", "smb_pth", "krb_ptt", "rdp_auth"]);

export function isExploitStepTool(toolName: string, args: Record<string, unknown> = {}): boolean {
  if (toolName === "scan_url") return args["aggressive"] === true;
  return EXPLOIT_STEP_TOOLS.has(toolName);
}

/** Tier 1 chain budget: validated exploit steps allowed per target per engagement. */
export const TIER1_CHAIN_BUDGET_PER_TARGET = 1;

export interface TierState {
  /** The tier currently in force (may rise via recorded escalation). */
  current: AutonomyTier;
  /** The tier declared at engagement start. */
  declared: AutonomyTier;
  /** Target → validated exploit steps used (Tier 1 chain budget). */
  chainSteps: Map<string, number>;
}

/**
 * Pure tier check, called by the dispatcher before any packet. Returns the
 * denial text, or undefined when the call is allowed. Chain-budget denials
 * name the re-approval path (Tier 2, operator-approved) — never silent.
 */
export function checkTierAllows(state: TierState, toolName: string, args: Record<string, unknown>, host?: string): string | undefined {
  const need = toolMinTier(toolName, args);
  if (state.current < need) {
    return (
      `DENIED by autonomy tier: ${toolName} requires Tier ${need} (${TIER_NAMES[need]}), ` +
      `engagement is Tier ${state.current} (${TIER_NAMES[state.current]}). ` +
      `Tier 0 allows read-only recon only; Tier 1 adds single-step validated exploitation; ` +
      `Tier 2 allows multi-step chains. Escalation needs recorded operator approval — no silent escalation.`
    );
  }
  if (state.current === 1 && isExploitStepTool(toolName, args) && host) {
    const used = state.chainSteps.get(host) ?? 0;
    if (used >= TIER1_CHAIN_BUDGET_PER_TARGET) {
      return (
        `DENIED by autonomy tier: Tier 1 (validate) permits a single validated exploit step per target ` +
        `(${used} already used on ${host}). Chaining beyond one step needs Tier 2 — declare --tier 2 at ` +
        `engagement start with operator approval (plus --confirm-tier2-production for production). ` +
        `No chaining without re-approval.`
      );
    }
  }
  return undefined;
}

/** Record a successful validated exploit step against the chain budget. */
export function recordExploitStep(state: TierState, toolName: string, args: Record<string, unknown>, host: string): void {
  if (state.current === 1 && isExploitStepTool(toolName, args)) {
    state.chainSteps.set(host, (state.chainSteps.get(host) ?? 0) + 1);
  }
}

export function describeTier(tier: AutonomyTier): string {
  return `Tier ${tier} (${TIER_NAMES[tier]}) — ${TIER_DESCRIPTIONS[tier]}`;
}
