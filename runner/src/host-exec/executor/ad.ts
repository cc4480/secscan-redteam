/**
 * AD enumeration implementation (v0.19.0 refactor — extracted from executor.ts).
 */
import { HOST_EXEC_TIMEOUT_MS, type HostCredentials, capOutput, collectSecrets, redactSecrets, resolveAdCredentials, validateHostTarget } from "../common.js";
import { type AdOperation, adEnumerate } from "../ad.js";
import { ExecutorCore } from "./core.js";
import { type HostExecResult } from "./types.js";

export async function adEnumImpl(core: ExecutorCore, args: {
  host: string;
  port?: number;
  useTls?: boolean;
  baseDn?: string;
  operations: string[];
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  const validOps: AdOperation[] = ["users", "groups", "computers", "trusts", "ous", "gpos", "acls", "attack_paths", "adcs"];
  const operations = args.operations.filter((o): o is AdOperation => (validOps as string[]).includes(o));
  if (operations.length === 0) {
    return core.refusedResult("winrm", args.host, "ad_enum requires at least one valid operation");
  }
  if (core.killSwitch.aborted) {
    return core.refusedResult("winrm", args.host, "kill switch active — coordinator aborted; no new host executions");
  }
  const v = validateHostTarget(args.host, args.scopeHosts);
  if (!v.ok) return core.refusedResult("winrm", args.host, v.reason);
  let creds: HostCredentials;
  let secrets: string[];
  try {
    creds = resolveAdCredentials(core.deps.env);
    secrets = collectSecrets(creds);
  } catch (err) {
    return core.refusedResult("winrm", args.host, (err as Error).message);
  }
  const t = core.deps.ad();
  try {
    const r = await core.bounded(
      adEnumerate(t, {
        host: args.host,
        port: args.port,
        useTls: args.useTls,
        baseDn: args.baseDn,
        creds,
        operations,
        timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
        signal: args.signal,
      }),
      (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 60_000,
      "ad_enum",
      t,
    );
    const lines = r.sections.map((s) => `[${s.operation}] findings=${s.findingCount}\n${s.summary}`).join("\n\n");
    return {
      ok: r.ok,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(
        `ad enum ${args.host}: ${r.sections.length} operations, ${r.sections.reduce((n, s) => n + s.findingCount, 0)} findings (${operations.join(",")})`,
        secrets,
      ),
      output: redactSecrets(capOutput(lines), secrets),
      ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(`ad enum ${args.host} failed: ${(err as Error).message}`, secrets),
      output: "",
      ms: Date.now() - started,
    };
  } finally {
    await t.close().catch(() => undefined);
  }
}

/**
 * Pass-the-ticket (battery WS-064). Ticket material via env (ccache/kirbi)
 * or kinit as the test account; replayed ccache-only with kvno proof.
 * The SPN's hostname is scope-checked in addition to the host.
 */
