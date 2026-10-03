/**
 * MsfExecutor — the runner's Metasploit bridge, behind the safety core.
 *
 * Preflight order (mirrors host-exec/executor.ts):
 *   1. kill-switch check (refuse new work when the coordinator aborted)
 *   2. ROE scope check (exact hostname match, fail closed, before any packet)
 *   3. module/payload policy (dos + destructive modules refused; only
 *      generic single-command payloads; the command is always the runner-built
 *      canary marker and additionally passes the destructive denylist)
 *   4. credential resolution (REDTEAM_MSFRPC_* env/Secure Vault only, fail
 *      fast with setup instructions)
 *   5. execution with timeout + abort signal; the console is destroyed on
 *      abort (that IS the kill switch for a running module)
 *   6. session hygiene: a validation run must not leave sessions behind —
 *      any session that wasn't there before is stopped immediately
 *   7. redaction of every secret from every string that leaves
 *
 * The request function is injectable so tests run against a fake msfrpcd.
 */

import { HOST_EXEC_TIMEOUT_MS, capOutput, checkDestructive, redactSecrets, validateHostTarget } from "../host-exec/common.js";
import { createHttpMsfRequest, MsfTransportError, type MsfRequestFn } from "./protocol.js";
import { MsfAuthError, MsfClient } from "./client.js";
import {
  buildMarkerCommand,
  checkMsfModule,
  checkMsfPayload,
  msfSecrets,
  resolveMsfCredentials,
} from "./policy.js";
import { filterAndRank, suggestModules, type SuggestInput } from "./suggest.js";

export interface MsfDeps {
  /** Injectable transport (default: HTTPS to the operator's msfrpcd). */
  request?: MsfRequestFn;
  env?: NodeJS.ProcessEnv;
  /** Override msfrpcd endpoint (tests). */
  endpoint?: { host: string; port: number; useTls: boolean };
}

export interface MsfResult {
  ok: boolean;
  transport: "msf";
  host: string;
  /** Redacted one-line summary for audit logs and events. */
  summary: string;
  /** Redacted, capped output. */
  output: string;
  ms: number;
  /** Set when the safety core refused before contacting msfrpcd. */
  refused?: string;
}

export const MSF_TIMEOUT_MS = 120_000; // exploits get longer than 30s host-exec

export class MsfExecutor {
  private readonly deps: { request?: MsfRequestFn; env: NodeJS.ProcessEnv; endpoint?: { host: string; port: number; useTls: boolean } };
  /** Kill-switch state, shared with the engagement context (phases.ts owns it). */
  killSwitch: { aborted: boolean } = { aborted: false };

  constructor(deps: MsfDeps = {}) {
    this.deps = { request: deps.request, env: deps.env ?? process.env, endpoint: deps.endpoint };
  }

  private refusedResult(host: string, refused: string, secrets: string[] = []): MsfResult {
    return {
      ok: false,
      transport: "msf",
      host,
      summary: redactSecrets(`REFUSED: ${refused}`, secrets),
      output: "",
      ms: 0,
      refused: redactSecrets(refused, secrets),
    };
  }

  /**
   * Authenticated client. Credential resolution is fail-fast: missing
   * REDTEAM_MSFRPC_USER/PASS throws with setup instructions (never a
   * silent unauthenticated attempt).
   */
  private async authedClient(signal?: AbortSignal): Promise<{ client: MsfClient; secrets: string[] }> {
    const creds = resolveMsfCredentials(this.deps.env);
    const secrets = msfSecrets(creds);
    const ep = this.deps.endpoint ?? { host: creds.host, port: creds.port, useTls: creds.useTls };
    const request =
      this.deps.request ??
      createHttpMsfRequest({ host: ep.host, port: ep.port, useTls: ep.useTls, timeoutMs: MSF_TIMEOUT_MS, signal });
    const client = new MsfClient(request);
    try {
      await client.login(creds.user, creds.pass);
    } catch (err) {
      if (err instanceof MsfAuthError) throw err;
      throw new MsfTransportError(redactSecrets(`msfrpcd unreachable at ${ep.host}:${ep.port}: ${(err as Error).message}`, secrets));
    }
    return { client, secrets };
  }

  private preflight(host: string, scopeHosts: string[]): { secrets: string[] } | { refused: string } {
    if (this.killSwitch.aborted) {
      return { refused: "kill switch active — coordinator aborted; no new msf executions" };
    }
    const v = validateHostTarget(host, scopeHosts);
    if (!v.ok) return { refused: v.reason };
    return { secrets: [] };
  }

  /**
   * Search the module database (recon-safe: no module runs).
   * `query` uses msf search syntax; when omitted, `cve`/`service` build it.
   */
  async search(args: {
    host: string;
    scopeHosts: string[];
    query?: string;
    cve?: string;
    service?: string;
    platform?: string;
    signal?: AbortSignal;
  }): Promise<MsfResult> {
    const started = Date.now();
    const pre = this.preflight(args.host, args.scopeHosts);
    if ("refused" in pre) return this.refusedResult(args.host, pre.refused);
    const input: SuggestInput = { service: args.service, cve: args.cve, platform: args.platform };
    try {
      const { client, secrets } = await this.authedClient(args.signal);
      const modules = args.query
        ? filterAndRank(await client.searchModules(args.query))
        : await suggestModules(client, input);
      const runnable = modules.filter((m) => !m.dropped);
      const lines = runnable
        .slice(0, 15)
        .map((m) => `${m.fullname} [rank:${m.rank || "n/a"}] — ${(m.description || "").slice(0, 140)}`);
      const dropped = modules.filter((m) => m.dropped).length;
      return {
        ok: true,
        transport: "msf",
        host: args.host,
        summary: redactSecrets(
          `msf search vs ${args.host}: ${runnable.length} runnable module(s)` +
            (dropped > 0 ? `, ${dropped} refused by policy` : ""),
          secrets,
        ),
        output: redactSecrets(capOutput(lines.join("\n") || "(no modules matched)"), secrets),
        ms: Date.now() - started,
      };
    } catch (err) {
      return {
        ok: false,
        transport: "msf",
        host: args.host,
        summary: `msf search failed: ${(err as Error).message}`,
        output: "",
        ms: Date.now() - started,
      };
    }
  }

  /**
   * Recon → module mapping: detected service/version → ranked candidate
   * modules. The candidates go to the COORDINATOR for approval — this tool
   * never fires an exploit. That approval is the recon→exploit sign-off
   * the coordinator already owns.
   */
  async suggest(args: {
    host: string;
    scopeHosts: string[];
    service?: string;
    version?: string;
    cve?: string;
    platform?: string;
    signal?: AbortSignal;
  }): Promise<MsfResult> {
    const started = Date.now();
    const pre = this.preflight(args.host, args.scopeHosts);
    if ("refused" in pre) return this.refusedResult(args.host, pre.refused);
    try {
      const { client, secrets } = await this.authedClient(args.signal);
      const ranked = await suggestModules(client, {
        service: args.service,
        version: args.version,
        cve: args.cve,
        platform: args.platform,
      });
      const runnable = ranked.filter((m) => !m.dropped);
      const lines = runnable.map(
        (m) => `${m.fullname} [rank:${m.rank || "n/a"}] — ${(m.description || "").slice(0, 140)}`,
      );
      const dropped = ranked.filter((m) => m.dropped);
      const droppedLines = dropped.map((m) => `${m.fullname} — REFUSED: ${m.dropped}`);
      return {
        ok: true,
        transport: "msf",
        host: args.host,
        summary: redactSecrets(
          `msf suggest vs ${args.host} (service=${args.service ?? "?"}, version=${args.version ?? "?"}): ` +
            `${runnable.length} candidate(s) for coordinator approval` +
            (dropped.length > 0 ? `, ${dropped.length} refused by policy` : ""),
          secrets,
        ),
        output: redactSecrets(
          capOutput(
            [...lines, ...(droppedLines.length > 0 ? ["", "--- refused by policy ---", ...droppedLines] : [])].join("\n") ||
              "(no candidate modules)",
          ),
          secrets,
        ),
        ms: Date.now() - started,
      };
    } catch (err) {
      return {
        ok: false,
        transport: "msf",
        host: args.host,
        summary: `msf suggest failed: ${(err as Error).message}`,
        output: "",
        ms: Date.now() - started,
      };
    }
  }

  /**
   * Run ONE module with a benign canary marker as the only payload action.
   * Exploits use a generic cmd payload running `echo REDTEAM-MARKER-<id>` —
   * the marker echoing back IS the validation ("command execution
   * achieved"). No sessions, no post-exploitation, no destructive modules.
   */
  async run(args: {
    host: string;
    scopeHosts: string[];
    moduleType: "exploit" | "auxiliary";
    module: string;
    /** Module datastore options (RHOSTS etc. derived from host — secrets never in here). */
    options?: Record<string, string>;
    payload?: string;
    /** Canary id echoed by the marker command (runner-generated upstream). */
    marker: string;
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<MsfResult> {
    const started = Date.now();
    const pre = this.preflight(args.host, args.scopeHosts);
    if ("refused" in pre) return this.refusedResult(args.host, pre.refused);
    // Policy first — before credentials, before any packet to msfrpcd.
    const deniedModule = checkMsfModule(args.module, args.moduleType);
    if (deniedModule) return this.refusedResult(args.host, deniedModule);
    const payload = args.payload ?? (args.moduleType === "exploit" ? "cmd/unix/generic" : undefined);
    if (payload) {
      const deniedPayload = checkMsfPayload(payload);
      if (deniedPayload) return this.refusedResult(args.host, deniedPayload);
    }
    const { command: markerCmd, refused: deniedCmd } = buildMarkerCommand(args.marker);
    if (deniedCmd) return this.refusedResult(args.host, `marker command refused: ${deniedCmd}`);
    // The marker is fixed, but run it through the destructive denylist
    // anyway — defense in depth on the one command we ever fire.
    const denied = checkDestructive(markerCmd);
    if (denied) return this.refusedResult(args.host, `destructive-command denylist: ${denied}`);
    try {
      const { client, secrets } = await this.authedClient(args.signal);
      const before = new Set(Object.keys(await client.sessionList()));
      const timeoutMs = args.timeoutMs ?? MSF_TIMEOUT_MS;
      const options: Record<string, string> = { ...(args.options ?? {}) };
      // RHOSTS always comes from the scope-checked host — never agent-supplied.
      if (args.moduleType === "exploit" && !options["RHOSTS"]) options["RHOSTS"] = args.host;
      const res = await client.runModuleConsole({
        moduleType: args.moduleType,
        fullname: args.module,
        options,
        payload,
        cmd: payload ? markerCmd : undefined,
        timeoutMs,
        signal: args.signal,
      });
      // Session hygiene: validation must not leave sessions behind.
      const after = await client.sessionList().catch(() => ({}));
      const strays = Object.keys(after).filter((id) => !before.has(id));
      for (const id of strays) {
        await client.sessionStop(id).catch(() => undefined);
      }
      const markerHit = res.output.includes(`REDTEAM-MARKER-`);
      const verdict = res.aborted
        ? "ABORTED by kill switch (console destroyed)"
        : res.timedOut
          ? "timed out (console destroyed)"
          : markerHit
            ? "MARKER ECHOED — command execution validated"
            : "completed without marker echo";
      return {
        ok: !res.aborted && !res.timedOut && markerHit,
        transport: "msf",
        host: args.host,
        summary: redactSecrets(
          `msf ${args.moduleType}/${args.module} vs ${args.host}: ${verdict}` +
            (strays.length > 0 ? ` — ${strays.length} stray session(s) stopped (hygiene)` : ""),
          secrets,
        ),
        output: redactSecrets(capOutput(res.output), secrets),
        ms: Date.now() - started,
      };
    } catch (err) {
      const msg = (err as Error).message;
      const refused =
        err instanceof MsfAuthError || msg.includes("unreachable") ? msg : `msf run failed: ${msg}`;
      return {
        ok: false,
        transport: "msf",
        host: args.host,
        summary: refused.slice(0, 300),
        output: "",
        ms: Date.now() - started,
        refused: err instanceof MsfAuthError ? refused : undefined,
      };
    }
  }
}
