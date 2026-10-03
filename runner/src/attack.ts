/**
 * MITRE ATT&CK technique catalog (web-focused subset) used by the runner.
 *
 * The coordinator maps every operation-plan step to one of these IDs; every
 * streamed event carries the ID of the technique it exercises. This is what
 * makes the engagement legible to a client's SOC: they can see exactly which
 * adversary behaviors were emulated and where their detections did or didn't fire.
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
