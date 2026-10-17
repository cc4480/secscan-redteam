/**
 * External-tool bridge registry (v0.32.0).
 *
 * john, sqlmap, ffuf, gobuster and nikto are all the same shape: a binary, a
 * fixed set of named profiles, and refusals that must happen BEFORE the process
 * starts. Cloning the nuclei/nmap module five times would be five copies of the
 * same policy logic and five places for it to drift, so the per-tool differences
 * live here as data and one executor drives all of them.
 *
 * The contract is the one the earlier bridges established:
 *   - the agent picks a PROFILE and a TARGET, never a flag
 *   - the argv is built runner-side, so nothing from the model reaches a shell
 *   - a refusal names the reason and is returned as a result, not swallowed
 *   - destructive and denial-of-service behaviour is refused by construction
 *
 * All pure functions — tested directly, no subprocess.
 */

export type XToolId = "john" | "sqlmap" | "ffuf" | "gobuster" | "nikto";

export interface XProfile {
  id: string;
  description: string;
  /** Minimum autonomy tier. Anything that can break or lock something is >= 1. */
  minTier: number;
  /** Extra argv appended after the tool's base flags. Never agent-supplied. */
  args: string[];
  /**
   * Where the target goes FOR THIS PROFILE. It is per-profile, not per-tool,
   * because one tool's modes disagree: john's --list=formats reads no file at
   * all while its cracking modes need the hash file. A tool-level flag made
   * identify fail on a path it should never have received.
   */
  target?: "flag" | "positional" | "none";
  /** This profile needs the configured wordlist. Per-profile for the same reason. */
  wordlist?: boolean;
  /** Pass the wordlist as --wordlist=<path> rather than -w <path>. */
  wordlistEq?: boolean;
}

export interface XToolSpec {
  id: XToolId;
  /** Env var that overrides the binary path. */
  envBin: string;
  envDir?: string;
  /** What the tool is for, in one line, for the tool description. */
  purpose: string;
  /** Command prefix: argv[0] plus any interpreter. */
  command: (bin: string) => string[];
  /** Named profiles. The first is the default. */
  profiles: XProfile[];
  /** Where the target goes: appended, or substituted into a profile arg. */
  targetFlag?: string;
  /** Output is JSON that the executor should parse. */
  jsonOutput?: boolean;
  setup: string[];
}

/**
 * Every tool here can be pointed at a host the operator does not own, so the
 * scope check in the dispatch layer is the load-bearing control — not anything
 * in this file. What this file adds is that the COMMAND cannot be bent: no
 * `--os-shell`, no rules file that writes back, no wordlist the agent supplied
 * as a path traversal.
 */
export const XTOOLS: readonly XToolSpec[] = [
  {
    id: "john",
    envBin: "REDTEAM_JOHN_BIN",
    envDir: "REDTEAM_JOHN_HOME",
    purpose: "offline password-hash cracking against a hash file the operator supplies",
    // John has no single john.exe on Windows — the jumbo build ships
    // CPU-specific binaries and picks one at runtime. The dispatch layer
    // prefers an explicit REDTEAM_JOHN_BIN, then the most capable variant
    // present, so a machine without AVX2 does not silently fail.
    command: (bin) => [bin],
    profiles: [
      { id: "identify", description: "Report the hash type and formats available. Cracks nothing.", minTier: 0, args: ["--list=formats"], target: "none" },
      { id: "wordlist", description: "Dictionary attack with the configured wordlist.", minTier: 1, args: [], target: "positional", wordlist: true, wordlistEq: true },
      { id: "incremental", description: "Brute force. Slow and unbounded — cap it with runS.", minTier: 2, args: ["--incremental"], target: "positional" },
      { id: "show", description: "Show already-cracked results from the pot file. Runs nothing.", minTier: 0, args: ["--show"], target: "positional" },
    ],
    setup: [
      "john not found. The Metasploit installer bundles John the Ripper jumbo:",
      "  <msf>\\john\\bin\\john-avx2-non-omp.exe  (or john-avx / john-sse2)",
      "Set REDTEAM_JOHN_BIN to the variant your CPU supports (check with",
      "`john --list=build-info`), and REDTEAM_JOHN_HOME to the john directory.",
    ],
  },
  {
    id: "sqlmap",
    envBin: "REDTEAM_SQLMAP_BIN",
    envDir: "REDTEAM_SQLMAP_DIR",
    purpose: "detect and confirm SQL injection against ONE scope-checked URL",
    command: () => ["python", "sqlmap.py"],
    profiles: [
      { id: "detect", description: "Non-destructive detection only — no data extraction.", minTier: 1, args: ["--batch", "--smart", "--level", "1", "--risk", "1"], target: "flag" },
      { id: "enumerate", description: "Detection plus DBMS banner and current user/db. Still read-only.", minTier: 1, args: ["--batch", "--level", "2", "--risk", "1", "--banner", "--current-user", "--current-db"], target: "flag" },
      { id: "tables", description: "List tables in the current database. Read-only, but reads schema.", minTier: 1, args: ["--batch", "--level", "3", "--risk", "1", "--tables"], target: "flag" },
    ],
    targetFlag: "-u",
    jsonOutput: false,
    setup: [
      "sqlmap not found. Clone it (it is pure Python):",
      "  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git C:\\tools\\sqlmap",
      "Then set REDTEAM_SQLMAP_DIR to that checkout.",
    ],
  },
  {
    id: "ffuf",
    envBin: "REDTEAM_FFUF_BIN",
    purpose: "content and directory discovery against ONE scope-checked host",
    command: (bin) => [bin],
    profiles: [
      { id: "dirs", description: "Directory/file discovery using the configured wordlist.", minTier: 0, args: ["-json", "-s", "-mc", "200,204,301,302,307,401,403", "-t", "20"], target: "flag", wordlist: true },
      { id: "vhosts", description: "Virtual-host discovery by Host header fuzzing.", minTier: 1, args: ["-json", "-s", "-mc", "200,204,301,302,307,401,403", "-t", "20"], target: "flag", wordlist: true },
      { id: "extensions", description: "Discovery with common script extensions appended.", minTier: 0, args: ["-json", "-s", "-mc", "200,204,301,302,307,401,403", "-t", "20", "-e", ".php,.asp,.aspx,.jsp,.html,.txt"], target: "flag", wordlist: true },
    ],
    targetFlag: "-u",
    jsonOutput: true,
    setup: [
      "ffuf not found. Download a release binary:",
      "  https://github.com/ffuf/ffuf/releases  (ffuf_<ver>_windows_amd64.zip)",
      "Set REDTEAM_FFUF_BIN to ffuf.exe.",
    ],
  },
  {
    id: "gobuster",
    envBin: "REDTEAM_GOBUSTER_BIN",
    purpose: "directory, DNS and vhost discovery against ONE scope-checked host",
    command: (bin) => [bin],
    profiles: [
      { id: "dir", description: "Directory/file brute force with the configured wordlist.", minTier: 0, args: ["dir", "-q", "-t", "20", "--no-error"], target: "flag", wordlist: true },
      { id: "vhost", description: "Virtual-host discovery via Host header.", minTier: 1, args: ["vhost", "-q", "-t", "20", "--no-error"], target: "flag", wordlist: true },
      { id: "dns", description: "Subdomain discovery. Needs a domain, not an IP.", minTier: 1, args: ["dns", "-q", "--no-error"], target: "flag", wordlist: true },
    ],
    targetFlag: "-u",
    setup: [
      "gobuster not found. Download a release binary:",
      "  https://github.com/OJ/gobuster/releases  (gobuster_Windows_x86_64.zip)",
      "Set REDTEAM_GOBUSTER_BIN to gobuster.exe.",
    ],
  },
  {
    id: "nikto",
    envBin: "REDTEAM_NIKTO_BIN",
    envDir: "REDTEAM_NIKTO_DIR",
    purpose: "web server misconfiguration scanning against ONE scope-checked host",
    command: () => ["perl", "nikto.pl"],
    profiles: [
      { id: "scan", description: "Standard scan against the target port.", minTier: 1, args: ["-nointeractive", "-ask", "no"], target: "flag" },
      { id: "tuning", description: "Standard scan limited to interesting files and misconfigurations.", minTier: 1, args: ["-nointeractive", "-ask", "no", "-Tuning", "123b"], target: "flag" },
    ],
    targetFlag: "-h",
    setup: [
      "nikto not found. It is a Perl script:",
      "  git clone --depth 1 https://github.com/sullo/nikto.git C:\\tools\\nikto",
      "  perl is required (Strawberry Perl on Windows).",
      "Set REDTEAM_NIKTO_DIR to the repo's program/ directory.",
      "NOTE: Windows Defender flags nikto.pl as potentially unwanted software.",
      "Exclude the checkout or the file will be removed and the tool will fail",
      "with 'Invalid argument' rather than a clear error.",
    ],
  },
];

export const XTOOLS_BY_ID = new Map(XTOOLS.map((t) => [t.id, t]));

export function findXTool(id: string): XToolSpec | undefined {
  return XTOOLS_BY_ID.get(id.trim().toLowerCase() as XToolId);
}

/** The default profile for a tool — its first entry. */
export function defaultProfile(spec: XToolSpec): XProfile {
  return spec.profiles[0]!;
}

export function findProfile(spec: XToolSpec, id: string): XProfile | undefined {
  return spec.profiles.find((p) => p.id === id.trim().toLowerCase());
}

/**
 * Flags no profile may ever emit, whatever the agent asks for.
 *
 * These are the ones that turn a scanner into something that changes the target
 * or hides the attacker. `--os-shell` and `--os-cmd` hand over a shell; `--file-write`
 * writes to the target's filesystem; the rest obscure or exfiltrate. A bridge
 * that can be argued into emitting one of these is not a scanner.
 */
export const XTOOL_DENIED_FLAGS = [
  "--os-shell",
  "--os-cmd",
  "--os-pwn",
  "--file-write",
  "--file-read",
  "--sql-shell",
  "--sql-query",
  "--dump",
  "--dump-all",
  "--passwords",
  "--eval",
  "--proxy",
  "--tor",
  "--random-agent",
  "--flush-session",
  "-x",
  "--forms",
  "--crawl",
];

/** Refuses any denied flag in an agent-supplied list. Returns the reason or null. */
export function checkXToolFlags(flags: string[] | undefined): string | null {
  for (const raw of flags ?? []) {
    const f = raw.trim();
    for (const denied of XTOOL_DENIED_FLAGS) {
      // Match the flag itself, not a prefix of a longer word: --dump matches
      // --dump but not --dumpsomething, so a refusal is never spurious.
      if (f === denied) {
        return `flag denied — ${JSON.stringify(f)} may never run through the bridge: it changes the target or conceals the tester, and the ROE requires non-destructive, attributable testing.`;
      }
    }
    if (f.startsWith("-")) {
      return `flag denied — the bridge does not accept agent-supplied flags (${JSON.stringify(f)}); pick a profile instead.`;
    }
  }
  return null;
}

export interface XRunOptions {
  bin: string;
  dir?: string;
  target: string;
  profile: XProfile;
  wordlist?: string;
  /** Per-run ceiling in seconds, inherited from the safety config. */
  timeoutS: number;
}

/**
 * Build the argv. No shell, no interpolation, and the target goes LAST so a
 * value beginning with "-" cannot be read as a flag.
 */
export function buildXToolArgv(spec: XToolSpec, opts: XRunOptions): string[] {
  const argv = [...spec.command(opts.bin), ...opts.profile.args];
  // Per-profile: john's identify takes no target at all, and its cracking modes
  // need `--wordlist=<path>` rather than a separate -w argument.
  if (opts.profile.wordlist && opts.wordlist) {
    if (opts.profile.wordlistEq) argv.push(`--wordlist=${opts.wordlist}`);
    else argv.push("-w", opts.wordlist);
  }
  const style = opts.profile.target ?? (spec.targetFlag ? "flag" : "positional");
  if (style === "none") return argv;
  // ffuf requires the FUZZ keyword somewhere in the request. The agent supplies a
  // target, not a template, so add the placeholder here: path profiles get /FUZZ
  // appended, vhost discovery fuzzes the Host header. Only a real URL target is
  // rewritten; a flag-like value passes through verbatim (the security contract is
  // that a target value can never be reinterpreted as a flag).
  let target = opts.target;
  const urlTarget = /^https?:\/\//i.test(target);
  if (spec.id === "ffuf" && style === "flag" && opts.profile.wordlist && urlTarget) {
    if (opts.profile.id === "vhosts") {
      if (!argv.includes("-H")) argv.push("-H", "Host: FUZZ");
    } else if (!target.includes("FUZZ")) {
      target = `${target.replace(/\/+$/, "")}/FUZZ`;
    }
  }
  if (style === "flag" && spec.targetFlag) argv.push(spec.targetFlag, target);
  else argv.push(target);
  return argv;
}
