/**
 * SSH transport implementation (v0.19.0 refactor — extracted from executor.ts).
 */
import { HOST_EXEC_TIMEOUT_MS, capOutput, redactSecrets, summarizeCommand } from "../common.js";
import { ExecutorCore } from "./core.js";
import { type HostExecResult } from "./types.js";

export async function sshExecImpl(core: ExecutorCore, args: {
  host: string;
  port?: number;
  command: string;
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  const pre = core.preflight("ssh", args.host, args.scopeHosts, args.command);
  if ("refused" in pre) return core.refusedResult("ssh", args.host, pre.refused);
  const t = core.deps.ssh();
  try {
    const r = await core.bounded(
      t.exec({
        host: args.host,
        port: args.port,
        creds: pre.creds,
        command: args.command.slice(0, 4000),
        timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
        signal: args.signal,
      }),
      (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 5_000,
      "ssh_exec",
      t,
    );
    return {
      ok: r.code === 0,
      transport: "ssh",
      host: args.host,
      summary: redactSecrets(
        `ssh ${args.host}: exit=${r.code} in ${r.ms}ms :: ${summarizeCommand(args.command, pre.secrets)}`,
        pre.secrets,
      ),
      output: redactSecrets(capOutput(`${r.stdout}${r.stderr ? `\n[stderr]\n${r.stderr}` : ""}`), pre.secrets),
      ms: Date.now() - started,
      exitCode: r.code,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "ssh",
      host: args.host,
      summary: redactSecrets(`ssh ${args.host} failed: ${(err as Error).message}`, pre.secrets),
      output: "",
      ms: Date.now() - started,
    };
  } finally {
    await t.close().catch(() => undefined);
  }
}

