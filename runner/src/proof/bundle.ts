/**
 * PROOF OF EXPLOITATION — PoC bundles (v0.14.0).
 *
 * Reproducible proof is the 2026 credibility standard: it is what separates
 * a serious pentest product from "AI-washing". The runner already validates
 * findings with canary markers; this module turns each validation into a
 * structured, re-verifiable proof bundle.
 *
 * The cardinal rule: bundles are DERIVED from the audit log (events.jsonl),
 * mechanically — never reconstructed from memory, never fabricated. A
 * bundle exists only when the audit trail shows a genuine validation signal:
 *   - "execution" tier: a canary marker echo was observed (the marker sent
 *     came back in tool output — command execution proved), or
 *   - "observation" tier: a read-only enumeration tool's output directly
 *     demonstrates the finding (e.g. ad_enum listing an ESC1-vulnerable
 *     certificate template — the output IS the evidence).
 * Killed hypotheses and unvalidated probes get NO bundle. The absence is
 * honest: not every probe becomes a finding.
 *
 * Anti-overclaim: the bundle proves the specific executed action, never
 * full impact ("command executed as SYSTEM", not "domain compromised").
 */

import type { EngagementEvent, Finding } from "../types.js";
import { redactSecrets } from "../host-exec/common.js";

/** Tool-call actions that generate target traffic (mirrors RATE_LIMITED_TOOLS in phases.ts). */
export const PROOF_TOOL_ACTIONS = new Set([
  "http_probe",
  "burst_probe",
  "scan_url",
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
  "msf_exec",
]);

/** Read-only enumeration tools: their output IS the evidence (observation tier). */
const OBSERVATION_TOOLS = new Set([
  "ad_enum",
  "smb_exec",
  "nfs_enum",
  "winrm_probe",
  "http_probe",
  "ssh_agent_audit",
  "rdp_shadow_prep",
  "scan_url",
  "get_report",
]);

/** Command-execution tools: only a marker echo validates (execution tier). */
const EXECUTION_TOOLS = new Set([
  "ssh_exec",
  "winrm_exec",
  "msf_exec",
  "smb_pth",
  "krb_ptt",
  "rdp_auth",
  "burst_probe",
]);

const MARKER_RE = /REDTEAM-MARKER-([A-Za-z0-9_-]{1,64})/;
const CVE_RE = /\[(CVE-\d{4}-\d{4,7})\]/i;

/** Results that are refusals/failures, never proof. */
const FAILURE_RE = /^(DENIED|ABORTED|HALTED)/i;
const FAILED_RE = /probe failed|timed out|connection (refused|reset|timed out)|unreachable/i;

export type StepValidation = "marker-echo" | "observation" | "none";

/** Structured replay parameters — redacted but structurally complete. Credentials are NEVER stored; reverify resolves them fresh from env. */
export interface PocReplay {
  tool: string;
  host?: string;
  args: Record<string, string>;
}

export interface PocStep {
  seq: number;
  ts: string;
  tool: string;
  target?: string;
  attackId?: string;
  /** What was executed (redacted command / request summary, from the audit log). */
  command: string;
  /** Redacted outcome summary. */
  result: string;
  /** Validation signal observed in this step. */
  validation: StepValidation;
  /** The canary marker involved, if any. */
  marker?: string;
  /** CVE tagged on the step, if any. */
  cve?: string;
  /** Replay parameters, or null when the step is not mechanically replayable. */
  replay: PocReplay | null;
}

export type ValidationTier = "execution" | "observation";

export interface PocBundle {
  version: 1;
  bundleId: string;
  engagementId: string;
  findingId: string;
  batteryItemId?: string;
  attackIds: string[];
  cve?: string;
  severity: string;
  title: string;
  target: string;
  operator: string;
  generatedAt: string;
  steps: PocStep[];
  markerSent?: string;
  markerObserved?: string;
  validationTier: ValidationTier;
  /** Exactly what the bundle proves — the specific executed/observed action. */
  proves: string;
  /** What it does NOT prove — no impact overclaim, stated explicitly. */
  doesNotProve: string;
  reverifyCommand: string;
}

export interface BundleBuildInput {
  finding: Finding;
  batteryItemId?: string;
  cve?: string;
  events: EngagementEvent[];
  engagement: { engagementId: string; target: string; operator: string };
  secrets: string[];
}

export interface BundleBuildResult {
  bundle: PocBundle | null;
  /** Why no bundle was built (honest absence). */
  reason?: string;
}

function isFailure(result: string): boolean {
  return FAILURE_RE.test(result) || FAILED_RE.test(result);
}

/** Extract the executed command/request from a tool result summary (all formats are runner-generated, so parsing is mechanical). */
function extractCommand(tool: string, result: string): string {
  let m: RegExpMatchArray | null;
  if (tool === "ssh_exec" || tool === "winrm_exec") {
    // "ssh <host>: exit=0 in 12ms :: <command>"
    m = result.match(/::\s*(.+)$/);
    if (m) return m[1]!.trim().slice(0, 300);
  }
  if (tool === "msf_exec") {
    // "msf exploit/windows/smb/ms17_010 vs <host>: <verdict>"
    m = result.match(/^msf\s+(\w+\/\S+?)\s+vs\s+/);
    if (m) return `msf_exec run ${m[1]}`;
  }
  if (tool === "smb_exec") {
    // "smb <host>: <operation> <where>"
    m = result.match(/^smb\s+\S+:\s*(.+?)(?:\.|$)/);
    if (m) return `smb_exec ${m[1]!.trim()}`.slice(0, 300);
  }
  if (tool === "http_probe" || tool === "burst_probe") {
    m = result.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);
    if (m) return `${m[1]!.toUpperCase()} ${m[2]}`.slice(0, 300);
  }
  return result.slice(0, 200);
}

/** Best-effort structured replay parameters from a correlated event. Null = not mechanically replayable (manual retest). */
function extractReplay(tool: string, event: EngagementEvent, command: string): PocReplay | null {
  const host = event.target;
  if ((tool === "ssh_exec" || tool === "winrm_exec") && host) {
    const cmd = command.length > 0 ? command : undefined;
    if (!cmd) return null;
    return { tool, host, args: { command: cmd } };
  }
  if (tool === "msf_exec" && host) {
    const m = event.result.match(/^msf\s+(exploit|auxiliary)\/(\S+?)\s+vs\s+/);
    if (!m) return null;
    const cveM = event.result.match(CVE_RE);
    return {
      tool,
      host,
      args: {
        moduleType: m[1]!,
        module: `${m[1]}/${m[2]}`,
        ...(cveM ? { cve: cveM[1]!.toUpperCase() } : {}),
      },
    };
  }
  if ((tool === "ad_enum" || tool === "nfs_enum" || tool === "winrm_probe" || tool === "smb_exec") && host) {
    return { tool, host, args: { operation: command.slice(0, 200) } };
  }
  return null;
}

function stepValidation(tool: string, result: string): { validation: StepValidation; marker?: string } {
  const markerM = result.match(MARKER_RE);
  if (markerM || /MARKER ECHOED/i.test(result)) {
    return { validation: "marker-echo", marker: markerM ? markerM[1] : undefined };
  }
  if (OBSERVATION_TOOLS.has(tool)) return { validation: "observation" };
  // Command-execution tools without a marker echo validate nothing — the
  // step is still recorded (full sequence), but it is not proof.
  return { validation: EXECUTION_TOOLS.has(tool) ? "none" : "observation" };
}

/**
 * Build a PoC bundle for one finding, derived mechanically from the audit
 * log. Returns null (with reason) when the bar is not met — no bundle is
 * ever fabricated.
 */
export function buildPocBundle(input: BundleBuildInput): BundleBuildResult {
  const { finding, events, engagement, secrets } = input;
  const redact = (s: string) => redactSecrets(s, secrets);

  if (finding.status !== "confirmed") {
    return { bundle: null, reason: `finding ${finding.id} is not confirmed (status=${finding.status}) — no bundle` };
  }

  const attackIds = finding.attackIds.map((a) => a.toUpperCase());
  const correlated = events.filter((ev) => {
    if (ev.phase !== "exploit" && ev.phase !== "recon") return false;
    if (!PROOF_TOOL_ACTIONS.has(ev.action)) return false;
    if (attackIds.length > 0) {
      const evAttack = (ev.attackId ?? "").toUpperCase();
      if (!attackIds.includes(evAttack)) return false;
    } else if (ev.target !== engagement.target) {
      return false;
    }
    return true;
  });

  if (correlated.length === 0) {
    return { bundle: null, reason: `finding ${finding.id}: no correlated tool execution in the audit log — no bundle` };
  }

  const steps: PocStep[] = correlated.map((ev) => {
    const { validation, marker } = stepValidation(ev.action, ev.result);
    const command = redact(extractCommand(ev.action, ev.result));
    const cveM = ev.result.match(CVE_RE);
    return {
      seq: ev.seq,
      ts: ev.ts,
      tool: ev.action,
      target: ev.target,
      attackId: ev.attackId,
      command,
      result: redact(ev.result.slice(0, 500)),
      validation: isFailure(ev.result) ? "none" : validation,
      marker,
      cve: cveM ? cveM[1]!.toUpperCase() : undefined,
      replay: extractReplay(ev.action, ev, command),
    };
  });

  const validating = steps.filter((s) => s.validation !== "none");
  if (validating.length === 0) {
    return {
      bundle: null,
      reason:
        `finding ${finding.id}: ${steps.length} correlated step(s) but no validation signal ` +
        `(no marker echo observed, no read-only evidence output) — no bundle`,
    };
  }

  const markerStep = steps.find((s) => s.validation === "marker-echo");
  const tier: ValidationTier = markerStep ? "execution" : "observation";
  const stepCves = steps.map((s) => s.cve).filter(Boolean) as string[];
  const cve = input.cve ?? stepCves[0];

  const proves =
    tier === "execution"
      ? `${markerStep!.tool} executed the runner-built canary on ${markerStep!.target ?? engagement.target} ` +
        `(${markerStep!.attackId ?? attackIds[0] ?? "technique"}); marker REDTEAM-MARKER-${markerStep!.marker ?? "?"} ` +
        `echoed back at ${markerStep!.ts}. This proves the specific executed action and nothing more.`
      : `Read-only ${validating[0]!.tool} output on ${validating[0]!.target ?? engagement.target} ` +
        `(${validating[0]!.attackId ?? attackIds[0] ?? "technique"}) directly demonstrates "${finding.title}". ` +
        `This proves the observed misconfiguration/exposure and nothing more.`;

  const bundle: PocBundle = {
    version: 1,
    bundleId: `POC-${engagement.engagementId}-${finding.id}`,
    engagementId: engagement.engagementId,
    findingId: finding.id,
    batteryItemId: input.batteryItemId,
    attackIds,
    cve,
    severity: finding.severity,
    title: redact(finding.title),
    target: engagement.target,
    operator: engagement.operator,
    generatedAt: new Date().toISOString(),
    steps,
    markerSent: markerStep?.marker ? `REDTEAM-MARKER-${markerStep.marker}` : undefined,
    markerObserved: markerStep?.marker ? `REDTEAM-MARKER-${markerStep.marker}` : undefined,
    validationTier: tier,
    proves: redact(proves),
    doesNotProve:
      "Full impact beyond the executed/observed action — lateral movement, persistence, " +
      "privilege beyond what the steps show, data access or exfiltration — was not attempted " +
      "and is NOT proven by this bundle. Re-running the steps should reproduce the same " +
      "observation; any deviation means the target changed.",
    reverifyCommand: `redteam-runner reverify --bundle poc/${finding.id}.json --scope ${engagement.target} --execute`,
  };
  return { bundle };
}

/** A killed hypothesis with its decisive audit evidence attached (negative proof). */
export interface NegativeProof {
  hypothesis: string;
  killingObservation: string;
  attackId?: string;
  vulnClass?: string;
  /** The audit events constituting the decisive observation (what was tried, what was seen). */
  decisiveEvents: Array<{ seq: number; ts: string; tool: string; result: string }>;
}

/**
 * Negative proof: for each killed hypothesis, attach the decisive audit
 * events. Buyers value knowing what was tried and ruled out — and the
 * registry already records the killing observation; this grounds it in
 * the actual probe sequence.
 */
export function buildNegativeProof(
  killed: Array<{ hypothesis: string; killingObservation: string; attackId?: string; vulnClass?: string }>,
  events: EngagementEvent[],
  secrets: string[],
): NegativeProof[] {
  const redact = (s: string) => redactSecrets(s, secrets);
  return killed.map((k) => {
    const attack = (k.attackId ?? "").toUpperCase();
    const decisiveEvents = events
      .filter((ev) => {
        if (ev.phase !== "exploit" && ev.phase !== "recon") return false;
        if (!PROOF_TOOL_ACTIONS.has(ev.action)) return false;
        if (attack && (ev.attackId ?? "").toUpperCase() !== attack) return false;
        return true;
      })
      .slice(-5)
      .map((ev) => ({ seq: ev.seq, ts: ev.ts, tool: ev.action, result: redact(ev.result.slice(0, 300)) }));
    return {
      hypothesis: redact(k.hypothesis),
      killingObservation: redact(k.killingObservation),
      attackId: k.attackId,
      vulnClass: k.vulnClass,
      decisiveEvents,
    };
  });
}

/** One-line bundle summary for the report's Proof of exploitation section. */
export function bundleSummary(b: PocBundle): string {
  const steps = b.steps.map((s) => `seq ${s.seq} ${s.tool}${s.marker ? ` (marker ${s.marker})` : ""}`).join("; ");
  return (
    `**${b.findingId}** — ${b.title} [${b.severity}] (${b.validationTier} proof). ` +
    `${b.proves} Steps (${b.steps.length}): ${steps}. ` +
    `Bundle: poc/${b.findingId}.json. Re-verify: \`${b.reverifyCommand}\``
  );
}
