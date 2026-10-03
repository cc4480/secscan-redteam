/**
 * NucleiExecutor — the Nuclei template bridge (v0.21.0).
 *
 * Two actions:
 *  - templates: recon-safe template listing/selection from the operator's
 *    local template checkout. Touches no target — only reads local files
 *    via the nuclei binary. Never fires.
 *  - run: execute selected templates against ONE scope-checked host with
 *    the runner-built argv. Exploit-phase-gated by the dispatcher (like
 *    msf_exec run), Tier 2.
 *
 * Preflight order (mirrors the msf bridge): kill switch → exact-hostname
 * ROE scope check (before any packet) → template/tag policy. Injectable
 * spawn + binary probe make everything testable with a fake binary.
 */
import { basename } from "node:path";
import { validateHostTarget, redactSecrets } from "../host-exec/common.js";
import {
  resolveNucleiBinary,
  resolveNucleiTimeoutS,
  resolveNucleiTemplateDir,
  buildNucleiRunArgv,
  buildNucleiListArgv,
  checkNucleiTags,
  NUCLEI_SETUP_INSTRUCTIONS,
  type NucleiTemplateFilter,
} from "./policy.js";
import { realNucleiSpawn, parseNucleiJsonl, type SpawnFn, type NucleiFinding } from "./runner.js";

export interface NucleiDeps {
  env?: NodeJS.ProcessEnv;
  spawn?: SpawnFn;
  /** Injectable binary probe for tests (default: run `<bin> -version`). */
  probeBinary?: (bin: string) => Promise<boolean>;
}

export interface NucleiTemplateInfo {
  id: string;
  path: string;
}

export interface NucleiExecResult {
  summary: string;
  output: string;
  ms: number;
  refused?: string;
  findings: NucleiFinding[];
  templatesListed?: NucleiTemplateInfo[];
  templatesExecuted?: number;
  timedOut?: boolean;
}

/** Max templates returned by the recon-safe listing (operator sanity bound). */
export const NUCLEI_LIST_CAP = 200;

export class NucleiExecutor {
  killSwitch: { aborted: boolean } = { aborted: false };
  private deps: NucleiDeps;

  constructor(deps: NucleiDeps = {}) {
    this.deps = deps;
  }

  private get env(): NodeJS.ProcessEnv {
    return this.deps.env ?? process.env;
  }

  private get spawn(): SpawnFn {
    return this.deps.spawn ?? realNucleiSpawn();
  }

  private async binaryAvailable(bin: string): Promise<boolean> {
    if (this.deps.probeBinary) return this.deps.probeBinary(bin);
    try {
      const r = await this.spawn([bin, "-version"], { timeoutMs: 15000 });
      return r.exitCode === 0 || r.stdout.includes("Nuclei");
    } catch {
      return false;
    }
  }

  private preflight(host: string, scopeHosts: string[]): { refused: string } | null {
    if (this.killSwitch.aborted) {
      return { refused: "kill switch active — coordinator aborted; no new nuclei executions" };
    }
    const v = validateHostTarget(host, scopeHosts);
    if (!v.ok) return { refused: v.reason };
    return null;
  }

  /**
   * Recon-safe template selection. Lists the operator's local templates and
   * filters by id/tag/CVE substring — no target touched, no packet sent.
   */
  async templates(args: { filter?: NucleiTemplateFilter }): Promise<NucleiExecResult> {
    const started = Date.now();
    if (this.killSwitch.aborted) {
      return this.refused("kill switch active — coordinator aborted; no new nuclei executions", started);
    }
    const bin = resolveNucleiBinary(this.env);
    if (!(await this.binaryAvailable(bin))) {
      return this.refused(`nuclei binary not available.\n${NUCLEI_SETUP_INSTRUCTIONS}`, started);
    }
    const argv = buildNucleiListArgv(bin, resolveNucleiTemplateDir(this.env));
    const r = await this.spawn(argv, { timeoutMs: 60000 });
    const listed = parseTemplateList(r.stdout).slice(0, NUCLEI_LIST_CAP);
    const filtered = filterTemplates(listed, args.filter);
    const lines = filtered.map((t) => `- ${t.id} (${t.path})`).join("\n");
    return {
      summary: `Nuclei template selection: ${filtered.length} templates match (from ${listed.length} listed, cap ${NUCLEI_LIST_CAP}). Recon-safe — nothing fired.`,
      output: lines.slice(0, 4000),
      ms: Date.now() - started,
      findings: [],
      templatesListed: filtered,
    };
  }

  /**
   * Execute templates against ONE scope-checked host. The target URL is
   * runner-built from the scope-checked host — never agent-supplied raw.
   */
  async run(args: {
    host: string;
    scopeHosts: string[];
    scheme?: string;
    filter?: NucleiTemplateFilter;
    severity?: string[];
    rateLimit: number;
    signal?: AbortSignal;
  }): Promise<NucleiExecResult> {
    const started = Date.now();
    const pre = this.preflight(args.host, args.scopeHosts);
    if (pre) return this.refused(pre.refused, started);
    const tagRefused = checkNucleiTags(args.filter?.tags);
    if (tagRefused) return this.refused(`DENIED by nuclei safety policy: ${tagRefused}`, started);
    const bin = resolveNucleiBinary(this.env);
    if (!(await this.binaryAvailable(bin))) {
      return this.refused(`nuclei binary not available.\n${NUCLEI_SETUP_INSTRUCTIONS}`, started);
    }
    const scheme = args.scheme === "http" ? "http" : "https";
    const target = `${scheme}://${args.host}`;
    const timeoutS = resolveNucleiTimeoutS(this.env);
    const ids = truncateIds(args.filter?.ids, 100);
    const argv = buildNucleiRunArgv(bin, {
      target,
      filter: { ...args.filter, ids },
      rateLimit: args.rateLimit,
      timeoutS,
      templateDir: resolveNucleiTemplateDir(this.env),
    });
    const r = await this.spawn(argv, { timeoutMs: timeoutS * 1000 + 15000, signal: args.signal });
    const parsed = parseNucleiJsonl(r.stdout);
    const sev = (parsed.findings[0]?.severity ?? "none");
    return {
      summary:
        `Nuclei run against ${target}: ${parsed.findings.length} findings ` +
        `(top severity: ${sev}; ${parsed.rawLines} output lines, ${parsed.parseErrors} parse errors)` +
        (r.timedOut ? " — TIMED OUT at the runner timeout" : "") +
        (r.killed && !r.timedOut ? " — KILLED by kill switch" : ""),
      output: parsed.findings
        .slice(0, 25)
        .map((f) => `[${f.severity}] ${f.templateId} — ${f.name} @ ${f.matchedAt}${f.cve ? ` [${f.cve}]` : ""}`)
        .join("\n")
        .slice(0, 4000),
      ms: Date.now() - started,
      findings: parsed.findings,
      templatesExecuted: ids?.length ?? -1,
      timedOut: r.timedOut,
    };
  }

  private refused(refused: string, started: number): NucleiExecResult {
    const msg = redactSecrets(`REFUSED: ${refused}`, []);
    return { summary: msg, output: "", ms: Date.now() - started, refused: msg, findings: [] };
  }
}

/** Parse `nuclei -tl` output — one template path per line, lenient. */
export function parseTemplateList(stdout: string): NucleiTemplateInfo[] {
  const out: NucleiTemplateInfo[] = [];
  for (const line of stdout.split("\n")) {
    const p = line.trim();
    if (!p || p.startsWith("[")) continue;
    // basename handles Windows separators too (nuclei -tl output may carry
    // backslash paths when the binary runs on Windows).
    const id = basename(p.replace(/\\/g, "/")).replace(/\.ya?ml$/, "") || p;
    out.push({ id, path: p });
  }
  return out;
}

/** Filter templates by id/tag/CVE substring — mechanical, case-insensitive. */
export function filterTemplates(list: NucleiTemplateInfo[], filter?: NucleiTemplateFilter): NucleiTemplateInfo[] {
  if (!filter) return list;
  const q = (s: string) => s.toLowerCase();
  return list.filter((t) => {
    if (filter.ids?.length && !filter.ids.some((id) => q(t.id).includes(q(id)))) return false;
    if (filter.cve && !q(`${t.id} ${t.path}`).includes(q(filter.cve))) return false;
    if (filter.tags?.length && !filter.tags.some((tag) => q(t.path).includes(q(tag)))) return false;
    return true;
  });
}

/** Runner-side bound on explicit template id lists (no silent mega-runs). */
export function truncateIds(ids: string[] | undefined, cap: number): string[] | undefined {
  if (!ids) return undefined;
  return ids.slice(0, cap);
}
