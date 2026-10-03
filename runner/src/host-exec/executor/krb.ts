/**
 * Kerberos PTT implementation (v0.19.0 refactor — extracted from executor.ts).
 */
import { HOST_EXEC_TIMEOUT_MS, capOutput, validateHostTarget } from "../common.js";
import { spnHostname } from "../krb.js";
import { ExecutorCore } from "./core.js";
import { type HostExecResult } from "./types.js";

export async function krbPttImpl(core: ExecutorCore, args: {
  host: string;
  spn?: string;
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  if (core.killSwitch.aborted) {
    return core.refusedResult("winrm", args.host, "kill switch active — coordinator aborted; no new host executions");
  }
  const v = validateHostTarget(args.host, args.scopeHosts);
  if (!v.ok) return core.refusedResult("winrm", args.host, v.reason);
  if (args.spn) {
    const spnHost = spnHostname(args.spn);
    if (!spnHost) return core.refusedResult("winrm", args.host, `malformed SPN: ${args.spn}`);
    const sv = validateHostTarget(spnHost, args.scopeHosts);
    if (!sv.ok) return core.refusedResult("winrm", args.host, `SPN host out of scope: ${sv.reason}`);
  }
  // Ticket material (ccache/kirbi/kinit) is resolved inside the transport;
  // any password it touches is redacted from all output there. The factory
  // receives the executor's env so tests stay hermetic.
  const t = core.deps.krb(core.deps.env);
  try {
    const r = await core.bounded(
      t.ptt({
        host: args.host,
        spn: args.spn,
        timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
        signal: args.signal,
      }),
      (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 30_000,
      "krb_ptt",
      t,
    );
    return {
      ok: r.ok,
      transport: "winrm",
      host: args.host,
      summary: `krb pass-the-ticket ${args.host}: source=${r.ticketSource} principal=${r.principal ?? "?"} kdcAccepted=${r.kdcAccepted ?? "n/a"}`,
      output: capOutput(r.note),
      ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "winrm",
      host: args.host,
      summary: `krb pass-the-ticket ${args.host} failed: ${(err as Error).message}`,
      output: "",
      ms: Date.now() - started,
    };
  } finally {
    await t.close().catch(() => undefined);
  }
}
