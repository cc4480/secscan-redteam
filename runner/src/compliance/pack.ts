/**
 * Compliance evidence pack (v0.12.0) — the per-engagement artifact a
 * client's auditors actually use.
 *
 * One engagement → one pack, written next to report.md:
 *  - engagement metadata (scope, authorization proof, ROE, dates, tester identity)
 *  - documented methodology (what QSAs demand under PCI DSS 11.4.1):
 *    agent-driven approach described truthfully, phases, tools, validation
 *    standard, explicit exclusions
 *  - findings table: finding → severity → mapped controls → evidence →
 *    remediation → retest status (registry wired in)
 *  - retest evidence: before/after observations per vulnerability class
 *
 * Everything here is runner-computed from engagement state — the pack is
 * evidence, not marketing. Wording never claims the client is "compliant"
 * or "certified"; it says "evidence supporting requirement X".
 */

import type { Finding, OperationPlan, RulesOfEngagement } from "../types.js";
import type { VulnerabilityRegistry, ConfirmedFinding } from "../registry.js";
import type { SafetyManifest } from "../safety/index.js";
import type { ApprovalEntry, AutonomyTier } from "../accountability/index.js";
import { TIER_NAMES, TIER_DESCRIPTIONS } from "../accountability/index.js";
import { COMPLIANCE_CONTROLS, lookupControl } from "./controls.js";
import { controlsForTechnique } from "./mapping.js";

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

export interface PackFinding {
  id: string;
  severity: string;
  title: string;
  attackIds: string[];
  /** Compliance control ids exercised by this finding. */
  controls: string[];
  evidence: string;
  fix: string;
  retest: string;
  status: string;
  /** Named human operator accountable for this finding (v0.17.0). */
  accountableOperator: string;
}

export interface RetestObservation {
  engagementId: string;
  date: string;
  severity: string;
  evidenceRef: string;
}

export interface RetestEntry {
  vulnClass: string;
  /** Earliest observation across all engagements (the "before"). */
  firstSeen: RetestObservation;
  /** Latest observation (the "after" — possibly this engagement). */
  latest: RetestObservation;
  observationCount: number;
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
export function buildRetestEvidence(registry: VulnerabilityRegistry): RetestEntry[] {
  const byClass = new Map<string, ConfirmedFinding[]>();
  for (const c of registry.confirmed) {
    const list = byClass.get(c.vulnClass) ?? [];
    list.push(c);
    byClass.set(c.vulnClass, list);
  }
  const entries: RetestEntry[] = [];
  for (const [vulnClass, list] of byClass) {
    const sorted = [...list].sort((a, b) => a.date.localeCompare(b.date));
    const first = sorted[0]!;
    const last = sorted[sorted.length - 1]!;
    const obs = (c: ConfirmedFinding): RetestObservation => ({
      engagementId: c.engagementId,
      date: c.date,
      severity: c.severity,
      evidenceRef: c.evidenceRef,
    });
    entries.push({ vulnClass, firstSeen: obs(first), latest: obs(last), observationCount: sorted.length });
  }
  return entries.sort((a, b) => a.vulnClass.localeCompare(b.vulnClass));
}

/** Human-readable markdown rendering of the pack (written next to report.md). */
export function renderCompliancePackMarkdown(pack: CompliancePack): string {
  const L: string[] = [];
  L.push(`# Compliance evidence pack — engagement ${pack.engagementId}`);
  L.push(``);
  L.push(`Generated: ${pack.generatedAt} · Operator: ${pack.operator}${pack.client ? ` · Client: ${pack.client}` : ""}`);
  L.push(``);
  L.push(`> This pack is EVIDENCE supporting the listed compliance requirements. It does not declare the client compliant or certified — that judgment belongs to the client's QSA/auditor.`);
  L.push(``);
  L.push(`## 1. Engagement metadata`);
  L.push(``);
  L.push(`- Target: ${pack.metadata.target}`);
  L.push(`- Mode: ${pack.metadata.mode.toUpperCase()} · Objective: ${pack.metadata.objective}`);
  L.push(`- Scope: ${pack.metadata.scope.join(", ") || "(none recorded)"}`);
  L.push(`- Test window: ${pack.metadata.testWindow.start} → ${pack.metadata.testWindow.end}`);
  L.push(`- Authorization proof: ${pack.metadata.authorizationProof}`);
  L.push(``);
  L.push(`## 2. Documented methodology`);
  L.push(``);
  L.push(pack.methodology.approach);
  L.push(``);
  for (const p of pack.methodology.phases) L.push(`- ${p}`);
  L.push(``);
  L.push(`### Tools used`);
  L.push(``);
  for (const t of pack.methodology.toolsUsed) L.push(`- ${t}`);
  L.push(``);
  L.push(`### Validation standard`);
  L.push(``);
  L.push(pack.methodology.validationStandard);
  L.push(``);
  L.push(`### Explicit exclusions`);
  L.push(``);
  for (const e of pack.methodology.exclusions) L.push(`- ${e}`);
  L.push(``);
  L.push(`### Authorization`);
  L.push(``);
  L.push(pack.methodology.authorization);
  L.push(``);
  if (pack.safety) {
    const s = pack.safety;
    L.push(`## 3. Safety case (mechanical protections, runner-enforced)`);
    L.push(``);
    L.push(`Environment: **${s.environment}**${s.environment === "production" ? ` (operator-confirmed: ${s.productionConfirmed})` : ""} · Manifest ${s.manifestVersion} · Generated ${s.generatedAt}`);
    L.push(``);
    L.push(`### Protections in force`);
    L.push(``);
    for (const p of s.protectionsInForce) L.push(`- ${p}`);
    L.push(``);
    L.push(`### Configuration this engagement`);
    L.push(``);
    L.push(`- Scope allowlist: ${s.scopeAllowlist.join(", ") || "(empty)"}`);
    L.push(`- Rate limit: ${s.rateLimit.rpsPerHost} requests/sec per host (burst ${s.rateLimit.burst})${s.rateLimit.productionCapApplied ? " — production cap applied mechanically" : ""}`);
    L.push(`- Kill switch: armed; aborts this engagement: ${s.killSwitch.aborts}`);
    L.push(`- Destructive denylist: ${s.destructiveDenylist.patternCount} patterns (${s.destructiveDenylist.version})`);
    L.push(`- Payload policy: ${s.payloadPolicy} · DoS policy: ${s.dosPolicy}`);
    L.push(`- PII redaction: enabled (${s.piiRedaction.patterns.join(", ")})`);
    L.push(`- Auto-halt: ${s.autoHalt.consecutiveThreshold} consecutive distress outcomes or ${Math.round(s.autoHalt.windowFailureRate * 100)}% distress over last ${s.autoHalt.windowSize} → target halted; halted targets: ${s.autoHalt.haltedTargets.join(", ") || "(none)"}`);
    L.push(`- Human override: ${s.humanOverride.operator}. ${s.humanOverride.abortPath}`);
    L.push(``);
    L.push(`### Zero-disruption record (derived from events.jsonl)`);
    L.push(``);
    L.push(s.disruptionVerdict);
    L.push(``);
    L.push(`### Residual risks`);
    L.push(``);
    for (const r of s.residualRisks) L.push(`- ${r}`);
    L.push(``);
  } else {
    L.push(`## 3. Safety case`);
    L.push(``);
    L.push(`(safety manifest not recorded for this engagement — engagements before v0.13.0 predate the machine-readable safety case)`);
    L.push(``);
  }
  L.push(`## 4. Findings → controls`);
  L.push(``);
  L.push(`Controls exercised: ${pack.coverage.controlsExercised}/${pack.coverage.controlsTotal}`);
  L.push(``);
  if (pack.findings.length === 0) {
    L.push(`(no findings recorded this engagement)`);
  } else {
    L.push(`| ID | Severity | Title | ATT&CK | Controls | Status |`);
    L.push(`|---|---|---|---|---|---|`);
    for (const f of pack.findings) {
      const ctrls = f.controls.length > 0 ? f.controls.join(", ") : "(no ATT&CK mapping)";
      L.push(`| ${f.id} | ${f.severity} | ${f.title} | ${f.attackIds.join(", ") || "—"} | ${ctrls} | ${f.status} |`);
    }
    for (const f of pack.findings) {
      L.push(``);
      L.push(`### ${f.id} — ${f.title} [${f.severity}]`);
      L.push(``);
      L.push(`- ATT&CK: ${f.attackIds.join(", ") || "—"}`);
      L.push(`- Controls: ${f.controls.length > 0 ? f.controls.map((c) => `${c} (${lookupControl(c)?.title ?? ""})`).join("; ") : "(none — no ATT&CK mapping)"}`);
      L.push(`- Accountable operator: ${f.accountableOperator}`);
      L.push(`- Evidence: ${f.evidence}`);
      L.push(`- Remediation: ${f.fix}`);
      L.push(`- Retest: ${f.retest}`);
    }
  }
  L.push(``);
  L.push(`## 5. Retest evidence (before/after per vulnerability class)`);
  L.push(``);
  if (pack.retestEvidence.length === 0) {
    L.push(`(no registry history yet)`);
  } else {
    for (const r of pack.retestEvidence) {
      L.push(`- **${r.vulnClass}** — ${r.observationCount} observation(s): first ${r.firstSeen.engagementId} (${r.firstSeen.date}, ${r.firstSeen.severity}, ref: ${r.firstSeen.evidenceRef}) → latest ${r.latest.engagementId} (${r.latest.date}, ${r.latest.severity}, ref: ${r.latest.evidenceRef})`);
    }
  }
  L.push(``);
  L.push(`## 6. Honest limits`);
  L.push(``);
  for (const h of pack.honestLimits) L.push(`- ${h}`);
  L.push(``);
  L.push(`## 7. Autonomy tier & approval log`);
  L.push(``);
  L.push(
    `Autonomy in force: **Tier ${pack.autonomyTier} (${pack.autonomyTierName})** — ${TIER_DESCRIPTIONS[pack.autonomyTier]} ` +
      `Tiers are a control boundary describing what the agents were allowed to do; they are not a safety guarantee and never imply the human did the work.`,
  );
  L.push(``);
  if (pack.approvals.length === 0) {
    L.push(`(no approvals recorded)`);
  } else {
    L.push(`| Seq | Time | Operator | Kind | Detail |`);
    L.push(`|---|---|---|---|---|`);
    for (const a of pack.approvals) {
      const tierMove = a.fromTier !== undefined || a.toTier !== undefined ? ` [${a.fromTier ?? "?"}→${a.toTier ?? "?"}]` : "";
      L.push(`| ${a.seq} | ${a.ts} | ${a.operator} | ${a.kind}${tierMove} | ${a.detail} |`);
    }
  }
  L.push(``);
  return L.join("\n");
}
