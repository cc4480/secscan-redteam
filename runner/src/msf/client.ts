/**
 * MsfClient — thin typed wrapper over msfrpc (msfCall).
 *
 * Covers what the bridge needs: auth, module search, console-based module
 * execution WITH output capture (the evidence for "command execution
 * achieved"), and session hygiene (a validation payload must never leave a
 * session behind — any unexpected session is stopped immediately).
 *
 * All methods throw MsfTransportError / MsfAuthError on failure; callers
 * translate those into DENIED/failed results with redacted messages.
 */

import { msfCall, type MsfRequestFn } from "./protocol.js";
import { MSFRPC_SETUP_INSTRUCTIONS } from "./policy.js";

export class MsfAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MsfAuthError";
  }
}

export interface MsfModule {
  type: string;
  name: string;
  fullname: string;
  rank: string;
  description: string;
  disclosureDate?: string;
}

export interface ConsoleRunResult {
  /** Full captured console output (capped by caller). */
  output: string;
  /** True when the console went idle (module finished) before the deadline. */
  completed: boolean;
  /** True when we gave up waiting and destroyed the console. */
  timedOut: boolean;
  /** True when the abort signal fired and we destroyed the console. */
  aborted: boolean;
}

const CONSOLE_POLL_MS = 750;

// ---------------------------------------------------------------------------
// Console input hardening.
//
// Everything written to an msf console is a single line of `use …` /
// `set K V` / `run` text. Any string that can end that line or re-tokenize
// it lets the caller inject whole console commands (`irb`, a second
// `set RHOSTS …`), escaping the canary-only design of the bridge. So every
// agent- or target-influenced string is checked here and REFUSED — never
// escaped-and-continued: input that needs a metacharacter is not
// expressible through the bridge, loudly.
//
// Metasploit's datastore is case-insensitive, so target selection
// (RHOSTS / RHOST / RHOSTS_FILE in any casing) is runner-owned: agent
// values are dropped and the scope-checked host forced for every module
// type (auxiliary scanners take RHOSTS too, not just exploits).
// ---------------------------------------------------------------------------

/** Slash-separated module/payload path: word chars, dots, dashes per segment. */
const MODULE_PATH_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*(?:\/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$/;
/** Datastore keys are plain identifiers (dots/colons for namespaced keys). */
const OPTION_KEY_RE = /^[A-Za-z][A-Za-z0-9_.:]*$/;
/** Values: no whitespace/control (kills \n, \r, \t, ESC) and no console metacharacters. */
const OPTION_VALUE_FORBIDDEN_RE = /[\s\x00-\x1F\x7F"'`$;|&<>(){}\[\]\\!]/;
/** CMD is one `set CMD <rest of line>` value: spaces ok, no control chars or shell/console punctuation. */
const CMD_FORBIDDEN_RE = /[\x00-\x1F\x7F;`"'$|&<>]/;
/** Datastore keys (any case) that choose the module's target — runner-owned. */
export const MSF_TARGET_OPTION_RE = /^rhosts?(_file)?$/i;

/**
 * Force the scope-checked host as the module's target. Any agent-supplied
 * target option (RHOSTS/RHOST/RHOSTS_FILE, any casing) is dropped first —
 * the datastore is case-insensitive, so `rhosts` would retarget just as
 * surely as `RHOSTS`. Does not mutate the caller's object.
 */
export function forceMsfTargetOptions(
  options: Record<string, string> | undefined,
  host: string,
): Record<string, string> {
  const out: Record<string, string> = { ...(options ?? {}) };
  for (const k of Object.keys(out)) {
    if (MSF_TARGET_OPTION_RE.test(k)) delete out[k];
  }
  out["RHOSTS"] = host;
  return out;
}

/**
 * Refusal reason when any console-bound string is unsafe to write, or null
 * when the whole input may be written line-by-line. Pure — the executor
 * runs this as preflight policy (before credentials, before any packet)
 * and the client re-checks before creating a console, so no caller of
 * runModuleConsole can bypass it.
 */
export function checkMsfConsoleInputs(args: {
  moduleType: string;
  fullname: string;
  options: Record<string, string>;
  payload?: string;
  cmd?: string;
}): string | null {
  if (args.moduleType !== "exploit" && args.moduleType !== "auxiliary") {
    return `msf console refused: module type must be exploit|auxiliary, got ${JSON.stringify(args.moduleType)}`;
  }
  if (!MODULE_PATH_RE.test(args.fullname)) {
    return `msf console refused: unsafe module name ${JSON.stringify(args.fullname)} — only plain module paths are expressible through the bridge`;
  }
  if (args.payload !== undefined && !MODULE_PATH_RE.test(args.payload)) {
    return `msf console refused: unsafe payload name ${JSON.stringify(args.payload)} — only plain payload paths are expressible through the bridge`;
  }
  if (args.cmd !== undefined && CMD_FORBIDDEN_RE.test(args.cmd)) {
    return `msf console refused: unsafe CMD string ${JSON.stringify(args.cmd)} — control characters and console/shell punctuation are not expressible through the bridge`;
  }
  for (const [k, v] of Object.entries(args.options)) {
    if (!OPTION_KEY_RE.test(k)) {
      return `msf console refused: unsafe option key ${JSON.stringify(k)} — datastore keys are plain identifiers`;
    }
    if (OPTION_VALUE_FORBIDDEN_RE.test(v)) {
      return `msf console refused: unsafe value for option ${k}: ${JSON.stringify(v)} — whitespace, control characters and console metacharacters are not expressible through the bridge`;
    }
  }
  return null;
}

function asRecord(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function asString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

export class MsfClient {
  private token: string | null = null;

  constructor(private readonly request: MsfRequestFn) {}

  /** Authenticate. Throws MsfAuthError (with setup instructions) on failure. */
  async login(user: string, pass: string): Promise<void> {
    const res = await msfCall(this.request, "auth.login", null, [user, pass]);
    if (res["result"] === "success" && typeof res["token"] === "string") {
      this.token = res["token"] as string;
      return;
    }
    throw new MsfAuthError(
      `[msf] msfrpcd authentication failed for user ${JSON.stringify(user)} — check ${"REDTEAM_MSFRPC_USER"}/${"REDTEAM_MSFRPC_PASS"}.\n${MSFRPC_SETUP_INSTRUCTIONS}`,
    );
  }

  private async call(method: string, args: unknown[]): Promise<Record<string, unknown>> {
    if (!this.token) throw new MsfAuthError("[msf] not authenticated — call login() first");
    return msfCall(this.request, method, this.token, args);
  }

  /** Search the module database. Query uses msf search syntax (cve:, type:, platform:, name:…). */
  async searchModules(query: string): Promise<MsfModule[]> {
    const res = await this.call("module.search", [query]);
    const list = res["modules"];
    if (!Array.isArray(list)) return [];
    return list.map((m) => {
      const r = asRecord(m);
      return {
        type: asString(r["type"]),
        name: asString(r["name"]),
        fullname: asString(r["fullname"]) || asString(r["name"]),
        rank: asString(r["rank"]),
        description: asString(r["description"]),
        disclosureDate: typeof r["disclosure_date"] === "string" ? r["disclosure_date"] : undefined,
      };
    });
  }

  /** Current sessions (id → info). Used for hygiene: validation runs must not leave sessions. */
  async sessionList(): Promise<Record<string, Record<string, unknown>>> {
    const res = await this.call("session.list", []);
    const out: Record<string, Record<string, unknown>> = {};
    for (const [k, v] of Object.entries(res)) out[k] = asRecord(v);
    return out;
  }

  async sessionStop(id: string): Promise<void> {
    await this.call("session.stop", [id]);
  }

  /**
   * Run a module in a throwaway console and capture its output.
   *
   * Flow: console.create → `use <type>/<fullname>` → `set` each option →
   * `set PAYLOAD`/`set CMD` (for exploits with generic payloads) → `run`
   * (foreground, so output streams to the console) → poll console.read
   * until idle/timeout/abort → console.destroy (always).
   *
   * The console is destroyed on abort — that is the kill switch for a
   * running module: destroying the console kills whatever it was doing.
   *
   * Every console-bound string is validated first (see
   * checkMsfConsoleInputs): an unsafe module/option/payload/CMD string
   * throws before any console is created.
   */
  async runModuleConsole(args: {
    moduleType: "exploit" | "auxiliary";
    fullname: string;
    options: Record<string, string>;
    payload?: string;
    cmd?: string;
    timeoutMs: number;
    signal?: AbortSignal;
  }): Promise<ConsoleRunResult> {
    const refusal = checkMsfConsoleInputs(args);
    if (refusal) throw new Error(`[msf] ${refusal}`);
    const created = await this.call("console.create", []);
    const cid = asString(created["id"]);
    if (!cid) throw new Error("[msf] console.create returned no console id");
    let output = "";
    let aborted = false;
    const write = async (data: string) => {
      await this.call("console.write", [cid, data]);
    };
    const destroy = async () => {
      try {
        await this.call("console.destroy", [cid]);
      } catch {
        /* best effort — the console may already be gone */
      }
    };
    try {
      if (args.signal?.aborted) aborted = true;
      const onAbort = () => {
        aborted = true;
      };
      args.signal?.addEventListener("abort", onAbort, { once: true });
      try {
        await write(`use ${args.moduleType}/${args.fullname}\n`);
        for (const [k, v] of Object.entries(args.options)) {
          await write(`set ${k} ${v}\n`);
        }
        if (args.payload) await write(`set PAYLOAD ${args.payload}\n`);
        if (args.cmd) await write(`set CMD ${args.cmd}\n`);
        await write(`run\n`);
        const deadline = Date.now() + args.timeoutMs;
        // Race each poll against the abort signal: a hanging console.read
        // must not delay the kill switch. The dangling read promise is
        // harmless — we break out and destroy the console.
        const abortedPromise = new Promise<null>((resolve) => {
          if (args.signal?.aborted) resolve(null);
          else args.signal?.addEventListener("abort", () => resolve(null), { once: true });
        });
        for (;;) {
          const raced = await Promise.race([
            this.call("console.read", [cid]).then((r) => ({ read: r }) as const),
            abortedPromise.then(() => ({ read: null }) as const),
          ]);
          if (raced.read === null) {
            aborted = true;
            break;
          }
          const read = raced.read;
          output += asString(read["data"]);
          const busy = read["busy"] === true;
          if (!busy) break;
          if (Date.now() >= deadline) break;
          await new Promise((r) => setTimeout(r, CONSOLE_POLL_MS));
        }
        const completed = !aborted && Date.now() < deadline;
        return { output, completed, timedOut: !completed && !aborted, aborted };
      } finally {
        args.signal?.removeEventListener("abort", onAbort);
      }
    } finally {
      await destroy();
    }
  }
}
