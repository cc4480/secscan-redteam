/**
 * Compliance evidence pack builder (v0.12.0): metadata, methodology,
 * findings table, coverage, honest limits, safety + approval sections.
 */

import type { Finding, OperationPlan, RulesOfEngagement } from "../../types.js";
import type { VulnerabilityRegistry } from "../../registry.js";
import type { SafetyManifest } from "../../safety/index.js";
import type { ApprovalEntry, AutonomyTier } from "../../accountability/index.js";
import { TIER_NAMES } from "../../accountability/index.js";
import { COMPLIANCE_CONTROLS } from "../controls.js";
import { controlsForTechnique } from "../mapping.js";
import { buildRetestEvidence } from "./findings.js";
import type { PackFinding, RetestEntry } from "./findings.js";

export interface CompliancePackInput {
  engagementId: string;
  client?: string;
  /** Named human operator accountable for the engagement. */
  operator?: string;
  target: string;
  mode: "red" | "black";
  objective: string;
  scope: string[];
  /** Server-authoritative ownership proof (DNS TXT verification). */
  verificationProof?: string;
  roe: RulesOfEngagement;
  testStart: string; // ISO
  testEnd: string; // ISO
  plan?: OperationPlan | null;
  findings: Finding[];
  /** Runner-computed battery coverage line, for the methodology appendix. */
  batteryCoverageNote?: string;
  registry: VulnerabilityRegistry;
  generatedAt?: string;
  /**
   * v0.13.0 safety case: the engagement's machine-readable safety manifest
   * (built by the runner at report time). Embedded as the pack's safety
   * section — the artifact a buyer's security team reviews.
   */
  safety?: SafetyManifest;
  /**
   * v0.17.0 accountability: the append-only approval log and the autonomy
   * tier in force. Defaults: empty log, Tier 2 (chain).
   */
  approvals?: ApprovalEntry[];
  autonomyTier?: AutonomyTier;
}

export interface CompliancePack {
  engagementId: string;
  client?: string;
  operator: string;
  generatedAt: string;
  metadata: {
    target: string;
    mode: string;
    objective: string;
    scope: string[];
    testWindow: { start: string; end: string };
    authorizationProof: string;
    rulesOfEngagement: RulesOfEngagement;
  };
  methodology: {
    approach: string;
    phases: string[];
    toolsUsed: string[];
    validationStandard: string;
    exclusions: string[];
    authorization: string;
  };
  findings: PackFinding[];
  retestEvidence: RetestEntry[];
  coverage: {
    controlsExercised: number;
    controlsTotal: number;
    /** Control id → finding ids exercising it. */
    controlFindings: Record<string, string[]>;
  };
  /**
   * v0.13.0 safety case: the engagement's safety manifest (mechanical
   * protections, configuration, zero-disruption record, residual risks).
   * Present when the runner built it at report time.
   */
  safety?: SafetyManifest;
  /**
   * v0.17.0 accountability: the append-only approval log (tier declared,
   * tier escalations, production confirmation…) and the autonomy tier in
   * force. Auditors see who approved what, when.
   */
  approvals: ApprovalEntry[];
  autonomyTier: AutonomyTier;
  autonomyTierName: string;
  honestLimits: string[];
}

/** The tools the runner can put in play — named exactly as the agents know them. */
export const METHODOLOGY_TOOLS: string[] = [
  "http_probe (web/API reconnaissance)",
  "scan_url (SecScan assessment via MCP)",
  "ssh_exec (Linux command execution)",
  "smb_exec (SMB share/directory enumeration)",
  "winrm_exec (Windows command execution)",
  "rdp_auth (RDP credential validation via NLA)",
  "smb_pth (pass-the-hash, test account's own hash)",
  "ad_enum (read-only LDAP: users/groups/trusts/GPOs, offline attack paths, AD CS template audit)",
  "krb_ptt (pass-the-ticket, test account's own tickets)",
  "ssh_agent_audit (SSH agent-forwarding exposure analysis)",
  "nfs_enum (userland NFS export enumeration)",
  "winrm_probe (unauthenticated WinRM listener probe)",
  "rdp_shadow_prep (RDP session enumeration for human handoff)",
  "msf_exec (Metasploit module suggest/search/run — coordinator-approved, canary payloads only)",
];

/** What the runner never does — stated in the methodology so a QSA sees the boundary. */
export const METHODOLOGY_EXCLUSIONS: string[] = [
  "Denial of service / resource exhaustion (ATT&CK T1499 excluded in every mode — the runner refuses DoS modules and destructive payloads mechanically)",
  "Destructive payloads: disk wipers, ransomware patterns, firmware/boot destruction (refused by the module/payload policy)",
  "Destructive host commands (rm -rf /, mkfs, shutdown/reboot, shadow-copy deletion — refused by the destructive-command denylist)",
  "Phishing, social engineering, and physical access (outside the automated runner by design)",
  "Any host, network, or account outside the declared ROE scope (exact-hostname enforcement, fail closed)",
  "Interactive RDP session shadowing (WS-065) — prepared for, but performed by, a human operator",
];

const OPERATOR_UNSET = "(operator name not supplied — set REDTEAM_OPERATOR or engagement operatorName before delivery)";

export function buildCompliancePack(input: CompliancePackInput): CompliancePack {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const operator = input.operator?.trim() || OPERATOR_UNSET;

  const findings: PackFinding[] = input.findings.map((f) => {
    const controls = [...new Set(f.attackIds.flatMap((a) => controlsForTechnique(a)))].sort();
    return {
      id: f.id,
      severity: f.severity,
      title: f.title,
      attackIds: f.attackIds,
      controls,
      evidence: f.evidence,
      fix: f.fix,
      retest: f.retest,
      status: f.status,
      accountableOperator: f.accountableOperator ?? operator,
    };
  });

  const controlFindings: Record<string, string[]> = {};
  for (const f of findings) {
    for (const c of f.controls) {
      (controlFindings[c] ??= []).push(f.id);
    }
  }

  return {
    engagementId: input.engagementId,
    client: input.client,
    operator,
    generatedAt,
    metadata: {
      target: input.target,
      mode: input.mode,
      objective: input.objective,
      scope: input.scope,
      testWindow: { start: input.testStart, end: input.testEnd },
      authorizationProof: input.verificationProof ?? "(authorization proof not recorded)",
      rulesOfEngagement: input.roe,
    },
    methodology: {
      approach:
        "Testing was performed by an autonomous AI agent team operating under mechanical safety rails. " +
        "Four roles collaborate on shared operation state: the coordinator (plans the operation, owns phase sign-off gates and the kill switch), " +
        "recon (maps the attack surface), the exploiter (forms hypotheses and executes probes — each probe is one reasoning step, never a blind scan), " +
        "and the reporter (writes the client report; runner-computed facts are appended deterministically, never trusted to the model). " +
        "Coordinator sign-off is required at every phase transition (plan→recon→exploit→report). " +
        "Every action is audit-logged to a JSONL event stream with its ATT&CK technique ID; credentials come from the Secure Vault only and are redacted from all output. " +
        "This is an agent-driven penetration test, not a human-led one — the methodology, tooling, and validation standard below describe exactly what the agents did, so an assessor knows precisely what they are reading.",
      phases: [
        "1. Authorize — server-authoritative domain-ownership proof (DNS TXT challenge) plus ROE scope, test window, and stop conditions. The runner refuses to proceed without proof.",
        "2. Plan — the coordinator writes the operation plan (adversary profile + phased steps with ATT&CK IDs) against the target-specific battery; coordinator sign-off required.",
        "3. Recon — surface mapping: entry points, auth models, fingerprints, WAF/EDR signals. Findings feed the shared target map every agent reads.",
        "4. Exploit — hypothesis-driven probing: each hypothesis is executed, observed, and recorded as confirmed (with evidence) or killed (with the killing observation — negative intelligence the registry keeps). Coverage is enforced mechanically: 3 categories × every selected target, or the cell is honestly BLOCKED.",
        "5. Report — the reporter writes the client narrative; the runner appends battery coverage, then this compliance pack is generated from engagement state.",
        "6. Registry write-back — every verdict persists to the vulnerability registry, compounding the product's attack intelligence across engagements.",
      ],
      toolsUsed: METHODOLOGY_TOOLS,
      validationStandard:
        "Proof of execution, not assertion: every claimed exploitation is validated by a runner-built benign canary marker " +
        "(e.g. echo REDTEAM-MARKER-<id>) whose echo back IS the validation. No destructive payloads, no real data exfiltration, " +
        "no persistent changes to the target. Killed hypotheses are recorded with their killing observations as negative evidence.",
      exclusions: METHODOLOGY_EXCLUSIONS,
      authorization:
        "Authorization was proven before any active testing via server-authoritative domain-ownership verification " +
        `(proof reference: ${input.verificationProof ?? "not recorded"}). Testing stayed inside the declared ROE scope at all times ` +
        "(exact-hostname enforcement — out-of-scope targets are refused before any packet is sent). " +
        "A named human operator is accountable for the engagement: " +
        operator +
        ".",
    },
    findings,
    retestEvidence: buildRetestEvidence(input.registry),
    coverage: {
      controlsExercised: Object.keys(controlFindings).length,
      controlsTotal: COMPLIANCE_CONTROLS.length,
      controlFindings,
    },
    honestLimits: [
      "This pack is EVIDENCE supporting the listed requirements — it does not declare the client compliant or certified. That judgment belongs to the client's QSA/auditor.",
      "Controls with no exercised findings in this engagement (see coverage.controlFindings) have no evidence from this test — the pack does not pretend otherwise.",
      "Findings without ATT&CK IDs carry no control mapping (the mapping is technique-keyed, honestly).",
      "The tester is an AI agent team under mechanical safety rails, not a human penetration tester. Assessors evaluating tester qualification (e.g. PCI DSS 11.4.1's 'qualified' language) should weigh this methodology description directly.",
      "Retest evidence is observational (before/after across engagements), not a certification of remediation.",
      "The safety section states mechanical protections and residual risks honestly — it is not a claim of zero risk.",
      "Autonomy tiers are a control boundary, not a safety guarantee — they state what the agents were allowed to do, never that the human did the work.",
    ],
    safety: input.safety,
    approvals: input.approvals ?? [],
    autonomyTier: input.autonomyTier ?? 2,
    autonomyTierName: TIER_NAMES[input.autonomyTier ?? 2],
  };
}

/**
 * Before/after per vulnerability class across the whole registry history.
 * Honest and mechanical: earliest observation vs latest observation, with
 * engagement ids and evidence refs. Remediation status itself comes from
 * each finding's retest field — the pack does not infer it.
 */
