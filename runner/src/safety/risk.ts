/**
 * Tool risk profiles + trajectory arbitration (v0.34.0).
 *
 * The tier system (0/1/2) answers "how much autonomy does the operator grant the
 * agent". It does not answer "how dangerous is THIS call" — a read-only
 * `nmap_exec profiles` and a `msf_exec run` are both just tool names at tier 1.
 * This module supplies the missing per-tool risk vocabulary and an interpretable
 * scorer, ported from AlterEgo's verified arbitration layer.
 *
 * Two fixes over the source design, both found by its own verification run:
 *   1. COVERAGE — every tool resolves. Unknown tools get a fail-closed profile
 *      (system blast, recoverability 0) instead of making the scorer throw.
 *   2. NO THROWING — `scoreTrajectory` never raises on an unknown name; it
 *      scores with the conservative default and says so in the rationale.
 *
 * score = w1*(1−blast) + w2*recoverability + w3*(1−sideEffects) + w4*optionality − w5*humanCost
 * tier  = auto (>0.8) | confirm (>=0.5) | explicit_intent (<0.5)
 */

export type BlastRadius = "none" | "session" | "external" | "user_data" | "system";

export interface RiskProfile {
  blastRadius: BlastRadius;
  /** 0-10; 10 = no-op / fully reversible. */
  recoverability: number;
  sideEffects: string[];
  compensatingAction?: string;
  sensitivityTags: string[];
  /** True when this profile came from the fail-closed default, not a curated entry. */
  unknown?: boolean;
}

const BLAST_NORM: Record<BlastRadius, number> = {
  none: 0,
  session: 0.25,
  external: 0.35,
  user_data: 0.6,
  system: 1,
};

const W1 = 0.25;
const W2 = 0.35;
const W3 = 0.15;
const W4 = 0.25;
const W5 = 0.1;

function p(
  blastRadius: BlastRadius,
  recoverability: number,
  sideEffects: string[] = [],
  compensatingAction?: string,
  sensitivityTags: string[] = [],
): RiskProfile {
  return { blastRadius, recoverability, sideEffects, compensatingAction, sensitivityTags };
}

/** Curated profiles for the tools whose risk is not obvious from the name. */
export const RISK_PROFILES: Record<string, RiskProfile> = {
  // Read-only bookkeeping and reporting: no blast.
  record_finding: p("none", 10, ["ledger entry appended"]),
  record_killed: p("none", 10, ["ledger entry appended"]),
  record_item_verdict: p("none", 10, ["ledger entry appended"]),
  update_target_map: p("none", 10, ["map entry updated"]),
  task_create: p("none", 10, ["task record created"]),
  task_checkpoint: p("none", 10, ["checkpoint appended"]),
  task_status: p("none", 10),
  task_complete: p("none", 10, ["task closed"]),
  query_registry: p("none", 10),
  get_report: p("none", 10, ["read of a stored report"]),
  get_scan_status: p("none", 10),
  list_recent_scans: p("none", 10),
  get_account: p("none", 10),
  list_verified_domains: p("none", 10),
  variant_list: p("none", 10),
  watch_profiles: p("none", 10),
  get_engagement: p("none", 10),
  get_feed: p("none", 10),
  get_findings: p("none", 10),
  get_coverage: p("none", 10),
  get_proof: p("none", 10),
  get_compliance: p("none", 10),

  // Network probes: external blast, no target change, fully reversible.
  http_probe: p("external", 10, ["HTTP request to target"], "no rollback needed", ["network"]),
  scan_url: p("external", 10, ["scan of target issued"], "stop the scan", ["network"]),
  send_message: p("none", 10, ["message queued"]),
  spawn_teammate: p("session", 10, ["teammate created"]),
  team_task_create: p("none", 10, ["task created"]),
  team_task_update: p("none", 10, ["task mutated"]),

  // Host execution: real side effects on a real machine.
  ssh_exec: p("system", 3, ["command runs on the target"], "revert the command's effect manually", ["host", "rce"]),
  winrm_exec: p("system", 3, ["command runs on the target"], "revert the command's effect manually", ["host", "rce"]),
  smb_exec: p("external", 8, ["SMB session opened", "share listing read"], "close the session", ["host"]),
  rdp_auth: p("external", 9, ["authentication attempt"], "no rollback needed", ["host", "auth"]),
  ad_enum: p("external", 9, ["LDAP queries issued"], "no rollback needed", ["host", "directory"]),
  nfs_enum: p("external", 9, ["RPC/MOUNT queries issued"], "no rollback needed", ["host"]),
  krb_ptt: p("session", 5, ["ticket cache written"], "clear the ticket cache", ["host", "auth"]),
  msf_exec: p("system", 2, ["exploit module may fire"], "stop the session; revert target state manually", ["host", "exploit"]),
  nmap_exec: p("external", 10, ["port probes sent"], "no rollback needed", ["network"]),
  nuclei_exec: p("external", 9, ["template requests sent"], "no rollback needed", ["network"]),
  ffuf_exec: p("external", 9, ["fuzz requests sent"], "no rollback needed", ["network"]),
  gobuster_exec: p("external", 9, ["discovery requests sent"], "no rollback needed", ["network"]),
  nikto_exec: p("external", 9, ["scanner requests sent"], "no rollback needed", ["network"]),
  sqlmap_exec: p("user_data", 5, ["injection probes; possible data read"], "stop the injection; review extracted data", ["web", "injection"]),
  john_exec: p("none", 10, ["CPU-bound local cracking"], "no rollback needed", ["offline"]),
  escalate: p("session", 6, ["autonomy tier raised"], "lower the tier with a recorded approval", ["accountability"]),
  revert: p("session", 8, ["state reverted"]),
};

/** Names that are read-only by construction, whatever the family. */
const READ_ONLY_PATTERN = /^(get_|list_|query_|read_|check_|probe_|search_|find_|variant_list|task_|team_task_|doctor|readiness|describe_)/i;

/** Tools that execute something on/against a target. */
const EXECUTING_PATTERN = /(_exec$|^exec_|^run_|^fire_|^replay_|^reverify$)/i;

/**
 * Resolve the risk profile for any tool name. Never throws: an unknown name gets
 * the fail-closed default (system blast, recoverability 0) with `unknown: true`.
 */
export function profileFor(tool: string): RiskProfile {
  const name = (tool ?? "").trim();
  const curated = RISK_PROFILES[name];
  if (curated) return curated;
  if (READ_ONLY_PATTERN.test(name)) return p("none", 10, ["read-only"], undefined, ["read-only"]);
  if (EXECUTING_PATTERN.test(name)) {
    return p("system", 3, ["tool executes against the target"], "revert the tool's effect manually", ["executing"]);
  }
  // Fail closed: an unclassified tool is treated as the most dangerous kind.
  return { ...p("system", 0, ["unknown tool — blast radius unverified"], "manual review required", ["unknown", "destructive"]), unknown: true };
}

/** Approval posture implied by a profile (mirrors the AlterEgo tier names). */
export function approvalTierFor(profile: RiskProfile): "silent" | "routine" | "always_ask" {
  if (profile.blastRadius === "none" && profile.recoverability >= 9) return "silent";
  if (profile.blastRadius === "system" || profile.recoverability <= 2 || profile.unknown) return "always_ask";
  return "routine";
}

export interface TrajectoryScore {
  tools: string[];
  score: number;
  tier: "auto" | "confirm" | "explicit_intent";
  rationale: string;
  metrics: { blastRadius: number; recoverability: number; sideEffects: number; optionality: number; humanCost: number };
  profiles: RiskProfile[];
}

/** Score a candidate tool sequence. Unknown tools are scored conservatively, never thrown on. */
export function scoreTrajectory(tools: string[]): TrajectoryScore {
  const names = Array.isArray(tools) && tools.length > 0 ? tools : ["(empty)"];
  const profiles = names.map((t) => profileFor(t));
  const blast = Math.max(...profiles.map((x) => BLAST_NORM[x.blastRadius]));
  const rec = Math.min(...profiles.map((x) => x.recoverability / 10));
  const sideEffects = Math.min(1, profiles.reduce((sum, x) => sum + x.sideEffects.length, 0) / 8);
  const optionality = profiles.filter((x) => x.recoverability >= 7).length / profiles.length;
  const humanCost = Math.min(1, profiles.filter((x) => approvalTierFor(x) !== "silent").length / 8);
  const raw = W1 * (1 - blast) + W2 * rec + W3 * (1 - sideEffects) + W4 * optionality - W5 * humanCost;
  const score = Math.round(Math.max(0, Math.min(1, raw)) * 1000) / 1000;
  const tier: TrajectoryScore["tier"] = score > 0.8 ? "auto" : score >= 0.5 ? "confirm" : "explicit_intent";
  const bits: string[] = [];
  const unknown = profiles.filter((x) => x.unknown).length;
  if (unknown > 0) bits.push(`${unknown} unclassified tool(s) scored fail-closed`);
  if (blast >= 0.6) bits.push(`high blast radius (${profiles.find((x) => BLAST_NORM[x.blastRadius] === blast)?.blastRadius ?? "system"})`);
  else if (blast <= 0.25) bits.push("low blast radius");
  if (rec >= 0.8) bits.push("high recoverability");
  else if (rec < 0.5) bits.push("low recoverability");
  const approvals = profiles.filter((x) => approvalTierFor(x) !== "silent").length;
  bits.push(`${approvals} approval${approvals === 1 ? "" : "s"} implied`);
  return {
    tools: names,
    score,
    tier,
    rationale: `score ${score}: ${bits.join("; ")} -> ${tier}`,
    metrics: {
      blastRadius: Math.round(blast * 1000) / 1000,
      recoverability: Math.round(rec * 1000) / 1000,
      sideEffects: Math.round(sideEffects * 1000) / 1000,
      optionality: Math.round(optionality * 1000) / 1000,
      humanCost: Math.round(humanCost * 1000) / 1000,
    },
    profiles,
  };
}

/** Plan-style explanation: per-step risk plus a rollback plan. */
export function explainTrajectory(tools: string[]): {
  score: number;
  tier: TrajectoryScore["tier"];
  rationale: string;
  steps: Array<{ tool: string; approval: string; blastRadius: BlastRadius; recoverability: number; sideEffects: string[]; compensatingAction?: string }>;
  rollbackPlan: string[];
  maxBlastRadius: BlastRadius | undefined;
} {
  const s = scoreTrajectory(tools);
  const steps = s.tools.map((tool, i) => {
    const profile = s.profiles[i]!;
    return {
      tool,
      approval: approvalTierFor(profile),
      blastRadius: profile.blastRadius,
      recoverability: profile.recoverability,
      sideEffects: profile.sideEffects,
      compensatingAction: profile.compensatingAction,
    };
  });
  const order: BlastRadius[] = ["none", "session", "external", "user_data", "system"];
  const maxBlastRadius = steps.reduce<BlastRadius | undefined>((max, step) => {
    if (!max) return step.blastRadius;
    return order.indexOf(step.blastRadius) > order.indexOf(max) ? step.blastRadius : max;
  }, undefined);
  return {
    score: s.score,
    tier: s.tier,
    rationale: s.rationale,
    steps,
    rollbackPlan: steps
      .filter((step) => step.compensatingAction)
      .map((step) => `${step.tool}: ${step.compensatingAction}`),
    maxBlastRadius,
  };
}

/** Rank candidate trajectories, safest first. */
export function rankTrajectories(candidates: string[][]): { ranked: TrajectoryScore[]; recommended?: TrajectoryScore } {
  const ranked = candidates.map((c) => scoreTrajectory(c)).sort((a, b) => b.score - a.score);
  return { ranked, recommended: ranked[0] };
}
