/**
 * Nmap executor (v0.31.0) — the bridge the nmap_exec tool calls.
 *
 * Two actions, mirroring the nuclei bridge:
 *   profiles() — read the built-in profile table and confirm the binary runs.
 *                Touches no target, so it is safe in any phase.
 *   scan()     — run ONE profile against ONE scope-checked host.
 *
 * Policy decisions live in policy.ts and are pure; this class owns the spawn
 * and the honest reading of its result. It never builds a flag itself — it asks
 * policy for an argv and runs it.
 */

import { realNmapSpawn, parseNmapXml, type SpawnFn, type NmapRunResult } from "./runner.js";
import {
  NMAP_PROFILES,
  buildNmapRunArgv,
  buildNmapProfileListArgv,
  checkNmapFlags,
  checkNmapScriptCategories,
  findProfile,
  resolveNmapBinary,
  resolveNmapTimeoutS,
  type NmapProfile,
} from "./policy.js";

export interface NmapDeps {
  spawn?: SpawnFn;
  env?: NodeJS.ProcessEnv;
}

export interface NmapProfileInfo {
  id: string;
  description: string;
  minTier: number;
  args: string;
}

export interface NmapExecResult {
  ok: boolean;
  action: string;
  /** Human-readable result for the agent — the refusal reason when !ok. */
  message: string;
  profiles?: NmapProfileInfo[];
  binary?: string;
  version?: string;
  run?: NmapRunResult;
}

export class NmapExecutor {
  /**
   * Kill switch, same contract as NucleiExecutor: the dispatcher hands the
   * engagement's hostKill here, and a scan refuses to start once aborted. The
   * scan already receives the controller's AbortSignal, so an IN-FLIGHT nmap is
   * killed too — this flag is what stops the next one from starting.
   */
  killSwitch: { aborted: boolean } = { aborted: false };

  private readonly spawn: SpawnFn;
  private readonly env: NodeJS.ProcessEnv;

  constructor(deps: NmapDeps = {}) {
    this.spawn = deps.spawn ?? realNmapSpawn;
    this.env = deps.env ?? process.env;
  }

  /** The catalogue. Recon-safe: runs `nmap --version`, never touches a target. */
  async profiles(): Promise<NmapExecResult> {
    const binary = resolveNmapBinary(this.env);
    const table: NmapProfileInfo[] = NMAP_PROFILES.map((p: NmapProfile) => ({
      id: p.id,
      description: p.description,
      minTier: p.minTier,
      args: p.args.join(" "),
    }));
    let version = "";
    try {
      const r = await this.spawn({
        file: binary,
        args: buildNmapProfileListArgv(binary).slice(1),
        timeoutMs: 15000,
      });
      if (r.timedOut) version = "(nmap did not answer --version within 15s)";
      else version = (r.stdout || r.stderr).split("\n")[0]?.trim() ?? "";
    } catch (err) {
      version = `nmap not runnable: ${(err as Error).message}`;
    }
    return {
      ok: true,
      action: "profiles",
      binary,
      version,
      profiles: table,
      message:
        `nmap ${version}\n\nProfiles (pass one as \`profile\`):\n` +
        table.map((p) => `  ${p.id.padEnd(9)} tier${p.minTier}+  ${p.description}`).join("\n"),
    };
  }

  /**
   * Run one profile against one host.
   *
   * `target` is expected to have been scope-checked by the caller (the dispatch
   * layer owns the ROE host check) — this method builds an argv, runs it, and
   * reports what happened, including a refusal from policy.
   */
  async scan(args: {
    target: string;
    profile: string;
    scriptCategories?: string[];
    extraFlags?: string[];
    rateLimit: number;
    timeoutS?: number;
    skipPing?: boolean;
    signal?: AbortSignal;
  }): Promise<NmapExecResult> {
    if (this.killSwitch.aborted) {
      return { ok: false, action: "scan", message: "ABORTED by operator (kill switch) — no scan started." };
    }
    const profile = findProfile(args.profile);
    if (!profile) {
      return {
        ok: false,
        action: "scan",
        message: `unknown profile ${JSON.stringify(args.profile)} — available: ${NMAP_PROFILES.map((p) => p.id).join(", ")}`,
      };
    }
    const scriptDenial = checkNmapScriptCategories(args.scriptCategories);
    if (scriptDenial) return { ok: false, action: "scan", message: scriptDenial };
    const flagDenial = checkNmapFlags(args.extraFlags);
    if (flagDenial) return { ok: false, action: "scan", message: flagDenial };

    const binary = resolveNmapBinary(this.env);
    const timeoutS = args.timeoutS ?? resolveNmapTimeoutS(this.env);
    const argv = buildNmapRunArgv(binary, {
      target: args.target,
      profile,
      scriptCategories: args.scriptCategories,
      rateLimit: args.rateLimit,
      timeoutS,
      skipPing: args.skipPing,
    });

    const r = await this.spawn({
      file: argv[0]!,
      args: argv.slice(1),
      timeoutMs: timeoutS * 1000,
      signal: args.signal,
    });

    if (r.timedOut) {
      // A partial scan is still evidence; report it as partial rather than
      // discarding it, but never as complete.
      const partial = parseNmapXml(r.stdout);
      return {
        ok: false,
        action: "scan",
        run: partial,
        message: `nmap exceeded the ${timeoutS}s host timeout and was killed. Partial result: ${partial.summary}. Re-run with a narrower profile or a longer REDTEAM_NMAP_TIMEOUT_S.`,
      };
    }
    if (r.code !== 0) {
      // nmap exits 1 when some hosts are down — a completed answer, not a
      // failure. Parse the XML regardless; only when nothing parses is it an
      // error. Discarding the XML on any non-zero exit lost a normal
      // "host down / partial" result and reported it as a hard failure.
      const run = parseNmapXml(r.stdout);
      if (run.hosts.length > 0) {
        return {
          ok: true,
          action: "scan",
          run,
          message: `${run.summary} (profile ${profile.id}, ${run.elapsedS.toFixed(1)}s, ${run.upHostCount} host(s) up, exit ${r.code} = some hosts down/partial). Command: nmap ${argv.slice(1).join(" ")}`,
        };
      }
      return {
        ok: false,
        action: "scan",
        message: `nmap exited ${r.code} with no parseable output. ${r.stderr.trim().split("\n").slice(0, 3).join(" / ") || "(no stderr)"}`,
      };
    }
    const run = parseNmapXml(r.stdout);
    return {
      ok: true,
      action: "scan",
      run,
      message:
        `${run.summary} (profile ${profile.id}, ${run.elapsedS.toFixed(1)}s, ${run.upHostCount} host(s) up). ` +
        `Command: nmap ${argv.slice(1).join(" ")}`,
    };
  }
}
