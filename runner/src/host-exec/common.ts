/**
 * host-exec safety core — every host tool (ssh/smb/winrm) goes through this.
 *
 * The runner — not the model — enforces the hard boundaries. The model's
 * prompts already forbid destructive behavior; this module is the MECHANICAL
 * backstop: scope checks, a destructive-command denylist, credential hygiene,
 * timeouts, and output caps. All of it fails closed.
 *
 * Scope model (deliberate, differs from the web prober on purpose): the web
 * prober rejects private/loopback hosts because its URLs are derived from
 * scan targets (SSRF-pivot risk). Host-exec targets come from the
 * operator-DECLARED ROE scope — the operator explicitly listed these hosts,
 * and internal pentests legitimately target RFC1918 space. So the check is:
 * the host must EXACTLY match a declared scope host (case-insensitive).
 * Anything else is rejected before any packet is sent.
 */

export const HOST_EXEC_TIMEOUT_MS = 30_000;
export const HOST_OUTPUT_CAP = 8 * 1024;
export const HOST_COMMAND_CAP = 4_000;

/** Scope check: exact match against the engagement's declared scope hosts. */
export function validateHostTarget(
  host: string,
  scopeHosts: string[],
): { ok: true } | { ok: false; reason: string } {
  const h = (host ?? "").trim().toLowerCase();
  if (!h) return { ok: false, reason: "empty host" };
  if (h.length > 253) return { ok: false, reason: "host too long" };
  const scope = scopeHosts.map((s) => s.toLowerCase());
  if (!scope.includes(h)) {
    return { ok: false, reason: `out of scope: ${h} (scope: ${scope.join(", ") || "(empty)"})` };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Destructive-command denylist (fail closed).
//
// This is a backstop, not a sandbox: the agent prompts already forbid
// destructive behavior, and the engagement is non-destructive by ROE. These
// patterns catch the catastrophic cases even if a prompt is bypassed.
// Matching is case-insensitive against the normalized command (whitespace
// collapsed). When in doubt we refuse — a refused benign command is a
// DENIED event the coordinator can re-plan around; a fired destructive one
// is not recoverable.
// ---------------------------------------------------------------------------

interface DenyPattern {
  label: string;
  re: RegExp;
}

const DENY: DenyPattern[] = [
  { label: "recursive delete of filesystem root", re: /\brm\s+(-[a-z]*r[a-z]*\s+|--recursive\s+)(["']?)(\/|\/\*|\$HOME|\~|\%SystemDrive\%|\%windir\%|C:\\?)(["']?)/i },
  { label: "recursive delete of filesystem root", re: /\brm\s+.*\s\/\s*$/i },
  { label: "Windows recursive delete of system drive", re: /\b(rmdir|rd)\s+\/s(\s+\/q)?\s+["']?(C:\\?|%SystemDrive%)/i },
  { label: "PowerShell recursive remove of system drive", re: /\bRemove-Item\s+.*(-Recurse).*(C:\\?|C:\\)/i },
  { label: "filesystem format", re: /\bmkfs(\.\w+)?\b/i },
  { label: "Windows volume format", re: /\bFormat-Volume\b/i },
  { label: "raw disk write", re: /\bdd\b[^|]*\bof=\s*\/dev\/(sd|hd|nvme|vd|xvd|mmcblk)/i },
  { label: "disk wipe", re: /\b(shred|wipefs|blkdiscard)\b.*\/dev\//i },
  { label: "diskpart destructive script", re: /\bdiskpart\b/i },
  { label: "partition table destruction", re: /\b(gdisk|fdisk|parted)\b.*\/(dev)\//i },
  { label: "fork bomb", re: /:\(\)\s*\{\s*:\|\:&\s*\}\s*;/ },
  { label: "host shutdown/poweroff", re: /\b(shutdown|poweroff|halt)(\.exe)?\b/i },
  { label: "host reboot", re: /\b(reboot|Restart-Computer)\b/i },
  { label: "init runlevel change", re: /\binit\s+[06]\b/ },
  { label: "volume shadow copy deletion (ransomware precursor)", re: /\bvssadmin\b.*delete\s+shadows/i },
  { label: "backup catalog deletion", re: /\bwbadmin\b.*delete\s+(catalog|backup)/i },
  { label: "boot config tampering", re: /\bbcdedit\b/i },
  { label: "Windows cipher wipe", re: /\bcipher\b.*\/w/i },
  { label: "mass file encryption loop (ransomware pattern)", re: /\b(openssl\s+enc|gpg\s+--?(encrypt|symmetric)|7z\s+a\s+.*-p)\b.*(\$\(|\`|\*\.\*)/i },
  { label: "kernel module force-load of unsigned code", re: /\binsmod\b/i },
  { label: "firmware flash", re: /\bflashrom\b/i },
];

/**
 * Returns the matched denylist label, or null when the command is allowed.
 * Pure function — tested directly, no network.
 */
export function checkDestructive(command: string): string | null {
  const norm = ` ${command.replace(/\s+/g, " ")} `;
  for (const d of DENY) {
    if (d.re.test(norm)) return d.label;
  }
  return null;
}

/** Exported for tests and docs — the mechanical backstop, stated plainly. */
export function destructiveDenyList(): string[] {
  return DENY.map((d) => d.label);
}

// ---------------------------------------------------------------------------
// Credential hygiene
// ---------------------------------------------------------------------------

export interface HostCredentials {
  username: string;
  password?: string;
  privateKey?: string;
  domain?: string;
  /**
   * NT hash (32 hex chars) for pass-the-hash — the test account's OWN hash,
   * provided by the client. Handled with the same secrecy as a password.
   */
  ntHash?: string;
}

function need(name: string, value: string | undefined, hint: string): string {
  if (value && value.trim()) return value;
  throw new Error(
    `[host-exec] missing credential ${name}: ${hint} ` +
      `Set it in the environment or Secure Vault — host-exec refuses to run without operator-provided test-account credentials.`,
  );
}

/** SSH credentials: REDTEAM_SSH_USER + one of PASSWORD / KEY / KEY_PATH. */
export function resolveSshCredentials(env: NodeJS.ProcessEnv = process.env): HostCredentials {
  const username = need("REDTEAM_SSH_USER", env["REDTEAM_SSH_USER"], "the authorized test-account login name.");
  let password = env["REDTEAM_SSH_PASSWORD"];
  let privateKey = env["REDTEAM_SSH_KEY"];
  const keyPath = env["REDTEAM_SSH_KEY_PATH"];
  if (!password && !privateKey && !keyPath) {
    throw new Error(
      "[host-exec] missing SSH credential: set one of REDTEAM_SSH_PASSWORD, REDTEAM_SSH_KEY, or REDTEAM_SSH_KEY_PATH. " +
        "Host-exec refuses to run without operator-provided test-account credentials.",
    );
  }
  if (keyPath && !privateKey) {
    // Read lazily at use time so a missing file is a clear error, not a silent skip.
    privateKey = `__KEY_PATH__:${keyPath}`;
  }
  return { username, password, privateKey };
}

/** SMB credentials: REDTEAM_SMB_USER + REDTEAM_SMB_PASSWORD (+ optional DOMAIN). */
export function resolveSmbCredentials(env: NodeJS.ProcessEnv = process.env): HostCredentials {
  const username = need("REDTEAM_SMB_USER", env["REDTEAM_SMB_USER"], "the authorized test-account login name.");
  const password = need("REDTEAM_SMB_PASSWORD", env["REDTEAM_SMB_PASSWORD"], "the test account's password.");
  return { username, password, domain: env["REDTEAM_SMB_DOMAIN"] };
}

/** WinRM credentials: REDTEAM_WINRM_USER + REDTEAM_WINRM_PASSWORD. */
export function resolveWinrmCredentials(env: NodeJS.ProcessEnv = process.env): HostCredentials {
  const username = need("REDTEAM_WINRM_USER", env["REDTEAM_WINRM_USER"], "the authorized test-account login name.");
  const password = need("REDTEAM_WINRM_PASSWORD", env["REDTEAM_WINRM_PASSWORD"], "the test account's password.");
  return { username, password };
}

/**
 * SMB pass-the-hash credentials: REDTEAM_SMB_USER + REDTEAM_SMB_NTHASH.
 * The hash is the test account's OWN NTLM hash, provided by the client —
 * never dumped, never another principal's material. Strict 32-hex validation.
 */
export function resolveSmbHashCredentials(env: NodeJS.ProcessEnv = process.env): HostCredentials {
  const username = need("REDTEAM_SMB_USER", env["REDTEAM_SMB_USER"], "the authorized test-account login name.");
  const ntHash = need(
    "REDTEAM_SMB_NTHASH",
    env["REDTEAM_SMB_NTHASH"],
    "the test account's own NTLM hash as 32 hex chars (client-provided; used for the WS-023 pass-the-hash exposure test only).",
  ).toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(ntHash)) {
    throw new Error("[host-exec] REDTEAM_SMB_NTHASH must be exactly 32 hex characters (the NT hash, not a password).");
  }
  return { username, ntHash, domain: env["REDTEAM_SMB_DOMAIN"] };
}

/**
 * AD/LDAP credentials: dedicated REDTEAM_AD_* when set, otherwise the SMB
 * test-account credentials (same authorized test account, documented fallback).
 */
export function resolveAdCredentials(env: NodeJS.ProcessEnv = process.env): HostCredentials {
  const username = env["REDTEAM_AD_USER"] ?? env["REDTEAM_SMB_USER"];
  const password = env["REDTEAM_AD_PASSWORD"] ?? env["REDTEAM_SMB_PASSWORD"];
  const domain = env["REDTEAM_AD_DOMAIN"] ?? env["REDTEAM_SMB_DOMAIN"];
  if (!username || !password) {
    throw new Error(
      "[host-exec] missing AD credential: set REDTEAM_AD_USER + REDTEAM_AD_PASSWORD (or REDTEAM_SMB_USER + REDTEAM_SMB_PASSWORD as fallback). " +
        "Host-exec refuses to run without operator-provided test-account credentials.",
    );
  }
  return { username, password, domain };
}

/** Values that must never appear in logs, errors, or events. */
export function collectSecrets(creds: HostCredentials): string[] {
  const out: string[] = [];
  for (const v of [creds.password, creds.privateKey, creds.ntHash]) {
    if (v && v.length >= 4 && !v.startsWith("__KEY_PATH__:")) out.push(v);
  }
  return out;
}

/** Redact every secret occurrence. Applied to ALL strings leaving this module. */
export function redactSecrets(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) {
    if (!s) continue;
    out = out.split(s).join("[REDACTED]");
  }
  return out;
}

/** Truncate to the output cap (no bulk exfiltration through the tool). */
export function capOutput(text: string, cap = HOST_OUTPUT_CAP): string {
  if (text.length <= cap) return text;
  return text.slice(0, cap) + `\n…[truncated at ${cap} bytes — refine the command instead of dumping bulk output]`;
}

/** One-line audit summary of a command (redacted, capped). */
export function summarizeCommand(command: string, secrets: string[]): string {
  return redactSecrets(command.replace(/\s+/g, " ").trim().slice(0, 200), secrets);
}
