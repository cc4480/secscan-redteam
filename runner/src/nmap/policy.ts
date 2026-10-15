/**
 * Nmap bridge policy — the mechanical backstop for nmap_exec (v0.31.0).
 *
 * Cloned from the nuclei policy on purpose: same shape, same guarantees. The
 * agent picks a PROFILE and a HOST; it never supplies flags. The argv builder
 * emits only flags it knows, so an unknown field is dropped rather than
 * forwarded, and there is no path from agent input to shell text.
 *
 * What MAY run:
 *  - PROFILE LISTING — reads the built-in profile table, touches no target
 *  - a SCAN of one scope-checked host using a named profile
 *
 * What may NEVER run:
 *  - NSE script categories that are intrusive, exploitative, denial-of-service,
 *    brute-force, fuzzing or external. `--script` is emitted ONLY with the safe
 *    category set, so requesting `exploit` gets refused rather than filtered
 *    silently — an operator should be told no, not handed a quieter scan.
 *  - timing above -T4. -T5 is "insane" and reliably saturates a link; the
 *    rate limiter in the safety core cannot throttle a raw SYN flood, so the
 *    cap lives here where nothing can route around it.
 *  - decoy, spoof, and fragmentation flags: they obscure the source of traffic
 *    the ROE says must be attributable.
 *  - any flag the builder does not know.
 *
 * All pure functions — tested directly, no subprocess.
 */

export const NMAP_ENV_BIN = "REDTEAM_NMAP_BIN";
export const NMAP_ENV_TIMEOUT = "REDTEAM_NMAP_TIMEOUT_S";

export const NMAP_SETUP_INSTRUCTIONS = [
  "nmap binary not found. The Nmap bridge needs nmap:",
  "  1. Install nmap (https://nmap.org/download, or it ships inside the",
  "     Metasploit installer at <msf>/nmap/nmap.exe on Windows).",
  "  2. Optionally set REDTEAM_NMAP_BIN to the binary path, then re-run.",
  "  3. Nmap needs raw-socket privileges for SYN and OS detection scans;",
  "     without them it falls back to a TCP connect scan, which is fine.",
].join("\n");

/** NSE categories that may be selected. Anything else is refused. */
export const NMAP_ALLOWED_SCRIPT_CATEGORIES = ["default", "safe", "discovery", "version", "auth"];

/**
 * NSE categories that are refused by name with a reason, so the refusal is
 * legible rather than a generic "unknown category".
 */
export const NMAP_DENIED_SCRIPT_CATEGORIES = [
  "intrusive",
  "exploit",
  "dos",
  "brute",
  "malware",
  "fuzzer",
  "external",
];

/** Flags the argv builder will never emit, even if requested by name. */
const FORBIDDEN_FLAGS = new Set([
  "-D", // decoys — traffic must stay attributable
  "-S", // spoofed source address
  "-f", "--mtu", // fragmentation
  "--data-length", "--data-string",
  "--script-args-file",
  "--datadir",
]);

export interface NmapProfile {
  /** Operator-facing name. */
  id: string;
  /** What it does, in one line, for the tool description and a refusal message. */
  description: string;
  /** Fixed flags for this profile. Never agent-supplied. */
  args: string[];
  /**
   * Minimum autonomy tier. Port discovery and version detection are recon
   * (Tier 0/1); a full 65535-port sweep and UDP are noisier and slower, so
   * they need the operator to have declared at least Tier 1.
   */
  minTier: number;
}

/**
 * The profile table — this IS the "point and shoot" surface. An operator picks
 * a name, not a flag set, which is what keeps the tool safe to hand to an agent.
 */
export const NMAP_PROFILES: readonly NmapProfile[] = [
  {
    id: "quick",
    description: "Top 100 TCP ports, -T4. The fastest useful sweep.",
    args: ["-sS", "-T4", "--top-ports", "100"],
    minTier: 0,
  },
  {
    id: "service",
    description: "Version detection on the top 200 TCP ports.",
    args: ["-sS", "-sV", "-T4", "--version-intensity", "5", "--top-ports", "200"],
    minTier: 0,
  },
  {
    id: "default",
    description: "Nmap's default script set on the top 100 ports — the safe NSE categories only.",
    args: ["-sS", "-sV", "-sC", "-T4", "--top-ports", "100"],
    minTier: 0,
  },
  {
    id: "full",
    description: "All 65535 TCP ports with version detection. Slow and loud.",
    args: ["-sS", "-sV", "-T4", "-p-"],
    minTier: 1,
  },
  {
    id: "udp",
    description: "Top 50 UDP ports. Slow — UDP scans wait on timeouts by nature.",
    args: ["-sU", "-T4", "--top-ports", "50"],
    minTier: 1,
  },
  {
    id: "os",
    description: "OS detection (-O) on the top 100 ports. Needs raw sockets.",
    args: ["-sS", "-O", "--osscan-guess", "-T4", "--top-ports", "100"],
    minTier: 1,
  },
];

export const NMAP_PROFILE_IDS = NMAP_PROFILES.map((p) => p.id);

export function findProfile(id: string): NmapProfile | undefined {
  return NMAP_PROFILES.find((p) => p.id === id.trim().toLowerCase());
}

/** Resolve the nmap binary — explicit env wins, else PATH lookup. */
export function resolveNmapBinary(env: NodeJS.ProcessEnv = process.env): string {
  const explicit = env[NMAP_ENV_BIN]?.trim();
  if (explicit) return explicit;
  return "nmap";
}

/** Run timeout in seconds — env override, sane default. */
export function resolveNmapTimeoutS(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env[NMAP_ENV_TIMEOUT]?.trim();
  const n = raw ? Number(raw) : NaN;
  if (Number.isInteger(n) && n >= 10 && n <= 3600) return n;
  return 300;
}

/**
 * Refuses a script category that is not on the safe list.
 *
 * Refusal, not filtering: silently dropping `exploit` would hand back a scan
 * that looks like it ran what was asked. An operator who asked for an
 * intrusive category must be told it is refused and why.
 */
export function checkNmapScriptCategories(categories: string[] | undefined): string | null {
  for (const c of categories ?? []) {
    const cat = c.trim().toLowerCase();
    if (NMAP_DENIED_SCRIPT_CATEGORIES.includes(cat)) {
      return `NSE category denied — ${JSON.stringify(c)} is refused by policy (intrusive/exploit/dos categories are not run through the bridge); allowed: ${NMAP_ALLOWED_SCRIPT_CATEGORIES.join(", ")}`;
    }
    if (!NMAP_ALLOWED_SCRIPT_CATEGORIES.includes(cat)) {
      return `unknown NSE category ${JSON.stringify(c)} — allowed: ${NMAP_ALLOWED_SCRIPT_CATEGORIES.join(", ")}`;
    }
  }
  return null;
}

/** Refuses timing above -T4 and any flag on the forbidden list. */
export function checkNmapFlags(flags: string[] | undefined): string | null {
  for (const f of flags ?? []) {
    const flag = f.trim();
    if (FORBIDDEN_FLAGS.has(flag)) {
      return `flag denied — ${JSON.stringify(flag)} may never run through the bridge (it would defeat source attribution required by the ROE)`;
    }
    const t = /^-T(\d)$/.exec(flag);
    if (t && Number(t[1]) > 4) {
      return `timing denied — ${JSON.stringify(flag)} is above -T4; a -T5 sweep outruns the per-host rate limiter, which is the protection the engagement depends on`;
    }
  }
  return null;
}

export interface NmapRunOptions {
  /** Scope-checked host or CIDR. Never a URL — nmap takes hosts. */
  target: string;
  profile: NmapProfile;
  /** NSE categories, already validated by checkNmapScriptCategories. */
  scriptCategories?: string[];
  /** Requests per second cap, inherited from the engagement safety config. */
  rateLimit: number;
  timeoutS: number;
  /** Restrict the host-discovery step for a single known-up host. */
  skipPing?: boolean;
}

/**
 * Build the nmap argv from structured options — no shell, no interpolation.
 *
 * `--max-rate` carries the engagement's per-host rate limit into nmap itself.
 * The safety core's limiter gates how OFTEN the bridge is invoked; it cannot
 * throttle packets inside a single scan, so the cap has to be handed down.
 */
export function buildNmapRunArgv(binary: string, opts: NmapRunOptions): string[] {
  const argv = [binary, ...opts.profile.args];
  // -oX - streams XML to stdout: one parser, no temp files to clean up, and no
  // half-written file if the run is killed by the kill switch mid-scan.
  argv.push("-oX", "-");
  argv.push("--max-rate", String(Math.max(1, Math.floor(opts.rateLimit))));
  argv.push("--host-timeout", `${Math.max(10, Math.floor(opts.timeoutS))}s`);
  // -Pn when the operator knows the host is up: a single known-up target should
  // not be skipped because it drops ICMP.
  if (opts.skipPing) argv.push("-Pn");
  // --script is emitted ONLY with the safe category set. No category means no
  // --script at all; the profile's own -sC (if any) still applies.
  if (opts.scriptCategories?.length) {
    argv.push("--script", opts.scriptCategories.join(","));
  }
  // The target goes LAST so a value beginning with "-" cannot be read as a flag.
  argv.push("--", opts.target);
  return argv;
}

/** argv for the profile listing — touches no target. */
export function buildNmapProfileListArgv(binary: string): string[] {
  return [binary, "--version"];
}

/** Values that must never appear in logs, errors, or events. */
export function nmapSecrets(): string[] {
  return [];
}
