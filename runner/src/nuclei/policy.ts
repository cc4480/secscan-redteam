/**
 * Nuclei bridge policy — the mechanical backstop for nuclei_exec (v0.21.0).
 *
 * What MAY run through the bridge:
 *  - template SELECTION (list/select by id, tag, severity, CVE) — recon-safe,
 *    touches no target, only reads the operator's local template checkout
 *  - template EXECUTION against a single scope-checked host, with the
 *    runner-built argv (never agent-supplied shell text), JSONL output,
 *    rate limit inherited from the safety config
 *
 * What may NEVER run:
 *  - dos-tagged templates (denial of service stays excluded per standing
 *    ROE, no exceptions) — refused if requested, always passed as
 *    -exclude-tags dos on every run
 *  - template updates mid-engagement (`-update-templates` is never passed;
 *    updating templates is an operator act, done before the engagement)
 *  - any flag the argv builder doesn't know (unknown options are dropped,
 *    never forwarded)
 *
 * All pure functions — tested directly, no subprocess.
 */

import { resolveExternalBinary } from "../toolchain.js";

export const NUCLEI_ENV_BIN = "REDTEAM_NUCLEI_BIN";
export const NUCLEI_ENV_TEMPLATES = "REDTEAM_NUCLEI_TEMPLATES";
export const NUCLEI_ENV_TIMEOUT = "REDTEAM_NUCLEI_TIMEOUT_S";

export const NUCLEI_SETUP_INSTRUCTIONS = [
  "nuclei binary not found. The Nuclei bridge needs ProjectDiscovery's nuclei:",
  "  1. Install nuclei (https://github.com/projectdiscovery/nuclei/releases",
  "     or: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest).",
  "  2. As the OPERATOR (never mid-engagement): nuclei -update-templates",
  "  3. Optionally set REDTEAM_NUCLEI_BIN (binary path) and/or",
  "     REDTEAM_NUCLEI_TEMPLATES (template directory) in the environment",
  "     or Secure Vault, then re-run.",
].join("\n");

/** Template tags that are always excluded — DoS stays excluded in every mode. */
export const NUCLEI_DENIED_TAGS = ["dos"];

/**
 * Flags an AGENT may never request. This governs agent-supplied flags only:
 * the argv builder emits -disable-update-check itself, because omitting it lets
 * nuclei block on a network update check and the run dies on its timeout with
 * empty output. What stays forbidden is an agent asking for a template UPDATE
 * or an uncover run - updating templates remains an operator act.
 */
const FORBIDDEN_FLAGS = new Set(["-update-templates", "-ut", "-uncover", "-duc"]);

/**
 * Resolve the nuclei binary through the shared toolchain resolver: explicit env
 * wins, then the payload bundled at REDTEAM_TOOLS_DIR, then PATH. The operator's
 * explicit value is authoritative even when it is missing (readiness reports
 * that honestly); only when none is set does the bundled copy get a turn.
 */
export function resolveNucleiBinary(env: NodeJS.ProcessEnv = process.env): string {
  return resolveExternalBinary("nuclei", { env }).path;
}

/** Run timeout in seconds — env override, sane default. */
export function resolveNucleiTimeoutS(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env[NUCLEI_ENV_TIMEOUT]?.trim();
  const n = raw ? Number(raw) : NaN;
  if (Number.isInteger(n) && n >= 10 && n <= 1800) return n;
  return 120;
}

/** Optional operator template directory override. */
export function resolveNucleiTemplateDir(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const d = env[NUCLEI_ENV_TEMPLATES]?.trim();
  return d || undefined;
}

export interface NucleiTemplateFilter {
  ids?: string[];
  tags?: string[];
  severities?: string[];
  cve?: string;
}

/**
 * Refuses denied tags (dos). Returns the refusal label, or null when allowed.
 * The dos exclusion is ALSO enforced on every run argv via -exclude-tags.
 */
export function checkNucleiTags(tags: string[] | undefined): string | null {
  for (const t of tags ?? []) {
    if (NUCLEI_DENIED_TAGS.includes(t.trim().toLowerCase())) {
      return `template tag denied — dos templates are excluded per standing ROE (T1499), no exceptions; got ${JSON.stringify(t)}`;
    }
  }
  return null;
}

/** Refuses unknown/unsafe extra flags — the builder only emits known flags. */
export function checkNucleiExtraFlags(flags: string[] | undefined): string | null {
  for (const f of flags ?? []) {
    if (FORBIDDEN_FLAGS.has(f.trim())) {
      return `flag denied — ${JSON.stringify(f)} may never run through the bridge (template updates are operator-initiated only)`;
    }
  }
  return null;
}

export interface NucleiRunOptions {
  /** Fully-formed target URL, already scope-checked (e.g. https://host). */
  target: string;
  filter: NucleiTemplateFilter;
  /** Requests per second — inherited from the engagement safety config. */
  rateLimit: number;
  timeoutS: number;
  templateDir?: string;
  /** Max templates to execute in one run (operator sanity bound). */
  maxTemplates?: number;
}

/**
 * Build the nuclei argv from structured options — no shell, no interpolation.
 * The agent never supplies raw flags; unknown fields are dropped, not passed.
 */
export function buildNucleiRunArgv(binary: string, opts: NucleiRunOptions): string[] {
  const argv = [binary, "-u", opts.target, "-jsonl", "-silent", "-nc", "-retries", "1"];
  // Always skip the update check. It is a NETWORK call nuclei makes before it
  // does anything else, and when it stalls the whole run stalls with it — the
  // spawn then hits its timeout with empty output, which is indistinguishable
  // from "no templates matched". Found by watching -tl return 0 templates while
  // the same command run by hand listed 13,866.
  //
  // This is not a template UPDATE: -update-templates is still refused, and
  // checkNucleiExtraFlags refuses it if an agent asks. Updating templates stays
  // an operator act done outside the engagement; this only stops the engine
  // from phoning home mid-flight.
  argv.push("-disable-update-check");
  argv.push("-rate-limit", String(Math.max(1, Math.floor(opts.rateLimit))));
  argv.push("-timeout", String(Math.max(10, Math.floor(opts.timeoutS))));
  argv.push("-stats-interval", "0");
  // DoS templates are excluded on EVERY run, mechanically — even if the
  // agent somehow requested them (checkNucleiTags refuses first).
  argv.push("-exclude-tags", NUCLEI_DENIED_TAGS.join(","));
  const f = opts.filter;
  if (f.ids?.length) argv.push("-id", f.ids.join(","));
  if (f.tags?.length) argv.push("-tags", f.tags.join(","));
  if (f.severities?.length) argv.push("-severity", f.severities.join(","));
  if (opts.templateDir) argv.push("-t", opts.templateDir);
  // NOTE: no max-template-count flag exists in nuclei; when explicit ids are
  // given the executor truncates the id list runner-side (see executor.ts).
  // Filter-broad runs are bounded by the timeout + rate limit instead.
  return argv;
}

/** argv for the recon-safe template listing (no target touched). */
export function buildNucleiListArgv(binary: string, templateDir?: string): string[] {
  // -disable-update-check is load-bearing. Without it nuclei makes a BLOCKING
  // network call before printing anything; the spawn then hits its 60s timeout
  // with empty stdout, and the listing reports 0 templates from the 13,866 that
  // are installed. Found exactly that way: the tool said zero while the same
  // binary run by hand listed all of them.
  const argv = [binary, "-tl", "-silent", "-nc", "-disable-update-check"];
  if (templateDir) argv.push("-t", templateDir);
  return argv;
}

/** Values that must never appear in logs, errors, or events. */
export function nucleiSecrets(): string[] {
  return [];
}
