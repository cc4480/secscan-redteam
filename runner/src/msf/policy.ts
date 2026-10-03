/**
 * Metasploit module/payload policy — the mechanical backstop for msf_exec.
 *
 * What MAY run through the bridge:
 *  - exploit and auxiliary modules (NOT dos/* — denial of service stays
 *    excluded per standing ROE, no exceptions)
 *  - payloads matching ^cmd/<platform>/generic$ — single benign command
 *    execution, no session, no Meterpreter, no post-exploitation agent
 *  - the command is ALWAYS exactly `echo <canary marker>` (built by the
 *    executor, never agent-supplied) and additionally passes the
 *    host-exec destructive-command denylist
 *
 * What may NEVER run: dos modules, destructive modules (disk wipers,
 * ransomware patterns, formatters), and any non-generic payload.
 * All pure functions — tested directly, no network.
 */

import { checkDestructive } from "../host-exec/common.js";

export const MSF_ENV_HOST = "REDTEAM_MSFRPC_HOST";
export const MSF_ENV_PORT = "REDTEAM_MSFRPC_PORT";
export const MSF_ENV_USER = "REDTEAM_MSFRPC_USER";
export const MSF_ENV_PASS = "REDTEAM_MSFRPC_PASS";
export const MSF_ENV_TLS = "REDTEAM_MSFRPC_TLS";

export const MSFRPC_SETUP_INSTRUCTIONS = [
  "msfrpcd is unreachable. The Metasploit bridge needs Metasploit's RPC daemon:",
  "  1. Install Metasploit Framework (https://www.metasploit.com/download or your distro package).",
  "  2. Start the daemon: msfrpcd -P <rpc-password> -U msf -a 127.0.0.1 -p 55553 -S",
  "     (-S = SSL; keep it on loopback unless you know what you're doing.)",
  "  3. Set REDTEAM_MSFRPC_USER / REDTEAM_MSFRPC_PASS (and optionally",
  "     REDTEAM_MSFRPC_HOST / REDTEAM_MSFRPC_PORT / REDTEAM_MSFRPC_TLS) in the",
  "     environment or Secure Vault, then re-run.",
].join("\n");

export interface MsfCredentials {
  host: string;
  port: number;
  useTls: boolean;
  user: string;
  pass: string;
}

/** msfrpcd connection credentials — fail fast with setup instructions. */
export function resolveMsfCredentials(env: NodeJS.ProcessEnv = process.env): MsfCredentials {
  const host = env[MSF_ENV_HOST]?.trim() || "127.0.0.1";
  const portRaw = env[MSF_ENV_PORT]?.trim();
  const port = portRaw ? Number(portRaw) : 55553;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`[msf] ${MSF_ENV_PORT} must be a TCP port number, got ${JSON.stringify(portRaw)}.`);
  }
  const useTls = (env[MSF_ENV_TLS]?.trim() ?? "1") !== "0";
  const user = env[MSF_ENV_USER]?.trim();
  const pass = env[MSF_ENV_PASS];
  if (!user || !pass) {
    throw new Error(
      `[msf] missing msfrpcd credentials: set ${MSF_ENV_USER} and ${MSF_ENV_PASS} in the environment or Secure Vault.\n${MSFRPC_SETUP_INSTRUCTIONS}`,
    );
  }
  return { host, port, useTls, user, pass };
}

/** Values that must never appear in logs, errors, or events. */
export function msfSecrets(creds: MsfCredentials): string[] {
  return creds.pass && creds.pass.length >= 4 ? [creds.pass] : [];
}

/**
 * Generic command-execution payloads only: they run ONE command and open
 * NO session. Everything else (meterpreter, shell bind/reverse, etc.) is
 * refused — the bridge validates, it does not take over hosts.
 */
const GENERIC_PAYLOAD_RE = /^cmd\/[^/]+\/generic$/;

export function checkMsfPayload(payload: string): string | null {
  const p = (payload ?? "").trim();
  if (!p) return "empty payload";
  if (GENERIC_PAYLOAD_RE.test(p)) return null;
  return `payload not allowed — only generic single-command payloads (cmd/<platform>/generic) may run; got ${JSON.stringify(p)}`;
}

interface ModuleDenyPattern {
  label: string;
  re: RegExp;
}

const MODULE_DENY: ModuleDenyPattern[] = [
  // Denial of service is excluded in every mode, every target — standing ROE.
  { label: "denial-of-service module (T1499 excluded by ROE)", re: /(^|\/)dos(\/|$|_)/i },
  { label: "disk/volume destruction", re: /format|disk_?wipe|wiper|shredder/i },
  { label: "ransomware/cryptolocker pattern", re: /ransom|cryptolocker|cryptowall|locker/i },
  { label: "firmware/boot destruction", re: /firmware|bootkit|mbr_?overwrite/i },
];

/** Refuses dos/destructive modules. Returns the label, or null when allowed. */
export function checkMsfModule(fullname: string, moduleType?: string): string | null {
  const name = (fullname ?? "").trim();
  if (!name) return "empty module name";
  const t = (moduleType ?? "").trim().toLowerCase();
  if (t && t !== "exploit" && t !== "auxiliary") {
    return `module type not allowed — only exploit/auxiliary modules may run; got ${JSON.stringify(moduleType)}`;
  }
  for (const d of MODULE_DENY) {
    if (d.re.test(name)) return `module denylist: ${d.label}`;
  }
  return null;
}

/** Exported for tests and docs — the mechanical backstop, stated plainly. */
export function msfModuleDenyList(): string[] {
  return MODULE_DENY.map((d) => d.label);
}

/**
 * The marker command the bridge runs — built by the RUNNER, never by the
 * agent. Validation is "the module achieved command execution", proven by
 * the canary token echoing back. Also passes the destructive denylist as a
 * second mechanical check (defense in depth on a fixed string).
 */
export function buildMarkerCommand(marker: string): { command: string; refused: string | null } {
  const clean = marker.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64) || "REDACTED-MARKER";
  const command = `echo REDTEAM-MARKER-${clean}`;
  return { command, refused: checkDestructive(command) };
}

/** Rank labels msfrpcd reports → numeric weight for sorting. */
const RANK_WEIGHTS: Record<string, number> = {
  excellent: 600,
  great: 500,
  good: 400,
  normal: 300,
  average: 200,
  low: 100,
  manual: 0,
};

export function msfRankWeight(rank: string | undefined): number {
  return RANK_WEIGHTS[(rank ?? "").toLowerCase()] ?? 0;
}
