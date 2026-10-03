/**
 * NFS enumeration implementation (v0.19.0 refactor — extracted from executor.ts).
 */
import { HOST_EXEC_TIMEOUT_MS, capOutput, redactSecrets } from "../common.js";
import { ExecutorCore } from "./core.js";
import { type HostExecResult } from "./types.js";

export async function nfsEnumImpl(core: ExecutorCore, args: {
  host: string;
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  const pre = core.preflightNoCreds("nfs", args.host, args.scopeHosts);
  if ("refused" in pre) return core.refusedResult("nfs", args.host, pre.refused);
  const t = core.deps.nfs();
  try {
    const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
    const exports = await core.bounded(
      t.enumerateExports({ host: args.host, timeoutMs, signal: args.signal }),
      timeoutMs + 5_000,
      "nfs_enum",
      t,
    );
    const lines = exports.map((e) => `${e.export}  [${e.groups.length > 0 ? e.groups.join(", ") : "no group restriction listed"}]`);
    return {
      ok: true,
      transport: "nfs",
      host: args.host,
      summary: redactSecrets(`nfs ${args.host}: ${exports.length} export(s) enumerated (no mount performed)`, pre.secrets),
      output: redactSecrets(capOutput(lines.join("\n") || "(no exports)"), pre.secrets),
      ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "nfs",
      host: args.host,
      summary: redactSecrets(`nfs ${args.host} enumeration failed: ${(err as Error).message}`, pre.secrets),
      output: "",
      ms: Date.now() - started,
    };
  } finally {
    await t.close().catch(() => undefined);
  }
}

/**
 * SSH agent-forwarding audit (batteries LX-018/LX-019).
 *
 * Preflight order: kill-switch → scope → SSH credential resolution →
 * denylist on the FIXED audit command (mechanical backstop even though
 * the command is not agent-supplied) → local agent socket resolution
 * (fails fast when no agent is available).
 *
 * The SAME ssh transport runs with `agentForward: true` and the
 * operator's local agent socket — then executes ONE fixed read-only
 * command. The forwarded socket is OBSERVED ONLY (ANALYSIS ONLY): it is
 * never used for onward authentication. That is the whole point of the
 * battery — detecting the exposure, not exploiting it.
 */
