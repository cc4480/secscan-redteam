/**
 * MITRE ATT&CK technique catalog used by the runner.
 *
 * Started as a web-focused subset; v0.8.0 adds host techniques (Windows /
 * Linux) for the host batteries. The coordinator maps every operation-plan
 * step to one of these IDs; every streamed event carries the ID of the
 * technique it exercises. This is what makes the engagement legible to a
 * client's SOC: they can see exactly which adversary behaviors were emulated
 * and where their detections did or didn't fire.
 *
 * Honest scope note (also stated in the client report): ATT&CK is built for
 * endpoint/network intrusions, and web vulnerability classes (SQLi, XSS, IDOR…)
 * map imperfectly onto it. In this runner, successful exploitation of a
 * public-facing web flaw is recorded as T1190 (Exploit Public-Facing
 * Application); the specific flaw class is named in the event text and the
 * finding. The mapping is a lens, not a claim that ATT&CK natively models
 * every web bug.
 */

import type { EngagementMode, EngagementPhase } from "./types.js";

export type NoiseLevel = "low" | "medium" | "high";

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  /** Which runner phases may use it. */
  phases: EngagementPhase[];
  /** Relative likelihood of tripping a defender. Drives black-mode choices. */
  noise: NoiseLevel;
  description: string;
  /** OWASP reference where the technique covers a web flaw class. */
  owasp?: string;
}

export const TECHNIQUES: AttackTechnique[] = [
  {
    id: "T1595.002",
    name: "Vulnerability Scanning",
    tactic: "Reconnaissance",
    phases: ["recon"],
    noise: "medium",
    description: "Active scanning of the target for weaknesses (the SecScan aggressive tier).",
  },
  {
    id: "T1595.003",
    name: "Wordlist Scanning",
    tactic: "Reconnaissance",
    phases: ["recon", "exploit"],
    noise: "medium",
    description: "Enumerating hidden paths/files with wordlists. Low request rate in black mode.",
  },
  {
    id: "T1592.002",
    name: "Gather Victim Host Information: Software",
    tactic: "Reconnaissance",
    phases: ["recon"],
    noise: "low",
    description: "Fingerprinting stack, frameworks, and versions from banners, headers, bundles.",
  },
  {
    id: "T1590.002",
    name: "Gather Victim Network Information: DNS",
    tactic: "Reconnaissance",
    phases: ["recon"],
    noise: "low",
    description: "DNS posture review (DNSSEC, records) — passive, via the scanner's DNS checks.",
  },
  {
    id: "T1593.002",
    name: "Search Engines",
    tactic: "Reconnaissance",
    phases: ["recon"],
    noise: "low",
    description: "OSINT: what the target exposes in indexed pages, robots/sitemaps.",
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    phases: ["exploit"],
    noise: "high",
    description:
      "Testing a public web flaw for real (injection, auth bypass, IDOR, SSRF…). " +
      "The specific flaw class is named per-event; T1190 is the ATT&CK bucket.",
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Persistence",
    phases: ["exploit"],
    noise: "low",
    description:
      "Using client-PROVIDED credentials only (never guessed or stuffed) to test " +
      "authorization boundaries. Requires credentials referenced in the ROE notes.",
  },
  {
    id: "T1552.001",
    name: "Unsecured Credentials: Credentials In Files",
    tactic: "Credential Access",
    phases: ["recon", "exploit"],
    noise: "low",
    description: "Hunting hardcoded secrets, keys, and tokens in client-side code and responses.",
  },
  {
    id: "T1027",
    name: "Obfuscated Files or Information",
    tactic: "Defense Evasion",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Payload encoding/mutation to test input handling (black mode: also used to " +
      "reduce signature footprint). Never used to hide activity from the CLIENT.",
  },
  {
    id: "T1087",
    name: "Account Discovery",
    tactic: "Discovery",
    phases: ["recon", "exploit"],
    noise: "low",
    description:
      "User/identifier existence oracles via response differentials. Handful of probes — an oracle check, not a harvest.",
    owasp: "WSTG-ATHN",
  },
  {
    id: "T1556",
    name: "Modify Authentication Process",
    tactic: "Defense Evasion",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Auth-flow logic flaws: password-reset token reuse, skipped verification steps, change-email without re-auth. Test accounts only.",
    owasp: "WSTG-ATHN-04",
  },
  {
    id: "T1505.003",
    name: "Server Software Component: Web Shell",
    tactic: "Persistence",
    phases: ["exploit"],
    noise: "high",
    description:
      "File-upload abuse testing: hostile packaging around BENIGN canary content only (double extensions, magic-byte mismatch). Never executable or exfiltrating content.",
    owasp: "WSTG-BUSL-08/09",
  },
  {
    id: "T1552.005",
    name: "Unsecured Credentials: Cloud Instance Metadata API",
    tactic: "Credential Access",
    phases: ["exploit"],
    noise: "medium",
    description:
      "SSRF-to-metadata testing: coax the server into fetching the cloud metadata " +
      "endpoint (169.254.169.254 etc.) via a server-side fetch/webhook/import feature. " +
      "Stop at retrieving the metadata response; never use any credential it returns.",
    owasp: "WSTG-INPV-19 / OWASP API7:2023",
  },
  {
    id: "T1606",
    name: "Forge Web Credentials",
    tactic: "Credential Access",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Session/JWT forgery testing: alg=none, alg confusion (RS256→HS256), kid-path " +
      "injection, signature stripping, expiry/claim tampering. Test tokens only — never " +
      "used to access another real user's account beyond the oracle confirmation.",
    owasp: "WSTG-SESS / OWASP API2:2023",
  },
  {
    id: "T1539",
    name: "Steal Web Session Cookie",
    tactic: "Credential Access",
    phases: ["exploit"],
    noise: "low",
    description:
      "Session/cookie security posture: missing Secure/HttpOnly/SameSite flags, " +
      "session-ID predictability, session fixation (pre-login ID survives post-login), " +
      "session non-invalidation on logout/password-change. Observational — no live session theft.",
    owasp: "WSTG-SESS-02",
  },
  {
    id: "T1098",
    name: "Account Manipulation",
    tactic: "Persistence",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Self-service privilege/role escalation: profile or account-settings endpoints that " +
      "accept a role/permission/tier field the UI doesn't expose. Test accounts only.",
    owasp: "WSTG-ATHZ-02",
  },
  {
    id: "T1110",
    name: "Brute Force",
    tactic: "Credential Access",
    phases: ["exploit"],
    noise: "high",
    description:
      "Password guessing / credential stuffing. EXCLUDED by default in black mode " +
      "and forbidden by the ROE template unless the client explicitly allows it.",
  },
  {
    id: "T1018",
    name: "Remote System Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "Host and service discovery against in-scope hosts — port scans, banner " +
      "grabs, fingerprinting. Read-only; no exploitation.",
  },
  {
    id: "T1083",
    name: "File and Directory Discovery",
    tactic: "Discovery",
    phases: ["recon", "exploit"],
    noise: "low",
    description:
      "Enumerating files and directories on reachable hosts and shares " +
      "(SMB/NFS listings, readable paths). Read-only enumeration.",
  },
  {
    id: "T1135",
    name: "Network Share Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "SMB/NFS share enumeration on in-scope hosts — share names and " +
      "permissions mapping. No data exfiltration.",
  },
  {
    id: "T1033",
    name: "System Owner/User Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "Enumerating users, groups, and sessions on in-scope hosts via " +
      "authorized channels. Read-only.",
  },
  {
    id: "T1082",
    name: "System Information Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "OS version, hostname, domain membership, and patch-level discovery " +
      "on in-scope hosts. Read-only.",
  },
  {
    id: "T1518",
    name: "Software Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "Installed-software and service-version discovery on in-scope hosts " +
      "for CVE correlation. Read-only.",
  },
  {
    id: "T1021",
    name: "Remote Services",
    tactic: "Lateral Movement",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Using RDP/SMB/WinRM/SSH sessions with client-PROVIDED test-account " +
      "credentials only (never guessed). Authorized scope, fully logged.",
  },
  {
    id: "T1021.004",
    name: "Remote Services: SSH",
    tactic: "Lateral Movement",
    phases: ["exploit"],
    noise: "medium",
    description:
      "SSH sessions with authorized test-account credentials or provided " +
      "keys only. Agent-forwarding and config abuse tested, never pivoted " +
      "beyond scope.",
  },
  {
    id: "T1047",
    name: "Windows Management Instrumentation",
    tactic: "Execution",
    phases: ["exploit"],
    noise: "medium",
    description:
      "WMI for authorized enumeration and execution on Windows hosts in " +
      "scope. Non-destructive queries and test-account execution only.",
  },
  {
    id: "T1053",
    name: "Scheduled Task/Job",
    tactic: "Execution",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Scheduled-task abuse paths (schtasks, cron, at, systemd timers): " +
      "audited read-only; execution only against tasks owned by authorized " +
      "test accounts. Findings reported, never planted.",
  },
  {
    id: "T1547",
    name: "Boot or Logon Autostart Execution",
    tactic: "Persistence",
    phases: ["exploit"],
    noise: "low",
    description:
      "Persistence MECHANISMS audited as findings (run keys, systemd units, " +
      "services, authorized_keys) — reported, never planted by the runner.",
  },
  {
    id: "T1003",
    name: "OS Credential Dumping",
    tactic: "Credential Access",
    phases: ["exploit"],
    noise: "high",
    description:
      "Credential-dumping EXPOSURE audited (LSASS protections, hive " +
      "permissions, credential files) — authorized scope only. Findings " +
      "reported; nothing exfiltrated beyond evidence needs.",
  },
  {
    id: "T1210",
    name: "Exploitation of Remote Services",
    tactic: "Lateral Movement",
    phases: ["exploit"],
    noise: "high",
    description:
      "Testing remotely exploitable services (EternalBlue-class, RCE in " +
      "exposed services) against authorized test hosts only. Non-destructive " +
      "proof — never weaponized beyond a safe check.",
  },
  {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    tactic: "Privilege Escalation",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Kernel and local privilege-escalation CVEs tested against authorized " +
      "test hosts only, with safe non-destructive checks.",
  },
  {
    id: "T1548",
    name: "Abuse Elevation Control Mechanism",
    tactic: "Privilege Escalation",
    phases: ["exploit"],
    noise: "medium",
    description:
      "sudo/sudo-caching, setuid/setgid binaries, and Windows " +
      "AlwaysInstallElevated tested with authorized test accounts. " +
      "Non-destructive proof only.",
  },
  {
    id: "T1574",
    name: "Hijack Execution Flow",
    tactic: "Privilege Escalation",
    phases: ["exploit"],
    noise: "medium",
    description:
      "DLL hijacking, PATH interception, and unquoted service paths — " +
      "writable-location proof with benign canary files, never real payloads.",
  },
  {
    id: "T1499",
    name: "Endpoint Denial of Service",
    tactic: "Impact",
    phases: [],
    noise: "high",
    description:
      "ALWAYS excluded. The runner never performs DoS or resource exhaustion. " +
      "Listed so plans that mention it are rejected loudly.",
  },
];

const byId = new Map(TECHNIQUES.map((t) => [t.id, t]));

export function lookupTechnique(id: string): AttackTechnique | undefined {
  return byId.get(id.toUpperCase());
}

/** Technique IDs excluded in every engagement, regardless of ROE. */
export const ALWAYS_EXCLUDED = ["T1499"];

/**
 * Technique IDs excluded by default in black (covert) mode. The operator can
 * narrow this list in the ROE, but cannot remove ALWAYS_EXCLUDED.
 */
export function defaultExcludedForMode(mode: EngagementMode): string[] {
  const base = [...ALWAYS_EXCLUDED];
  if (mode === "black") base.push("T1110");
  return base;
}

/** Full exclusion set: always-excluded + mode defaults + ROE exclusions (deduped, uppercased). */
export function resolveExcludedTechniques(
  mode: EngagementMode,
  roeExcluded: string[] | null | undefined,
): string[] {
  const set = new Set<string>([
    ...defaultExcludedForMode(mode),
    ...(roeExcluded ?? []).map((t) => t.toUpperCase()),
  ]);
  return [...set];
}
