/**
 * PoC bundle step primitives: tool tiers, marker/CVE/failure patterns,
 * and the mechanical command/replay/validation extractors.
 */

import type { EngagementEvent } from "../../types.js";

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
export const CVE_RE = /\[(CVE-\d{4}-\d{4,7})\]/i;

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

export function isFailure(result: string): boolean {
  return FAILURE_RE.test(result) || FAILED_RE.test(result);
}

/** Extract the executed command/request from a tool result summary (all formats are runner-generated, so parsing is mechanical). */
export function extractCommand(tool: string, result: string): string {
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
export function extractReplay(tool: string, event: EngagementEvent, command: string): PocReplay | null {
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

export function stepValidation(tool: string, result: string): { validation: StepValidation; marker?: string } {
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
