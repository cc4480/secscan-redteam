/**
 * WinRM transport implementations: winrmExec, winrmProbe (v0.19.0 refactor — extracted from executor.ts).
 */
import { HOST_EXEC_TIMEOUT_MS, capOutput, redactSecrets, summarizeCommand } from "../common.js";
import { type WinrmProbeRequestImpl, type WinrmProbeResult, probeWinrmListener } from "../winrm.js";
import { ExecutorCore } from "./core.js";
import { type HostExecResult } from "./types.js";

export async function winrmExecImpl(core: ExecutorCore, args: {
  host: string;
  port?: number;
  command: string;
  powershell?: boolean;
  useTls?: boolean;
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  const pre = core.preflight("winrm", args.host, args.scopeHosts, args.command);
  if ("refused" in pre) return core.refusedResult("winrm", args.host, pre.refused);
  const t = core.deps.winrm();
  try {
    const r = await core.bounded(
      t.exec({
        host: args.host,
        port: args.port,
        creds: pre.creds,
        command: args.command.slice(0, 4000),
        powershell: args.powershell,
        useTls: args.useTls,
        timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
        signal: args.signal,
      }),
      (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 5_000,
      "winrm_exec",
      t,
    );
    return {
      ok: r.code === 0,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(
        `winrm ${args.host}: exit=${r.code} in ${r.ms}ms :: ${summarizeCommand(args.command, pre.secrets)}`,
        pre.secrets,
      ),
      output: redactSecrets(capOutput(`${r.stdout}${r.stderr ? `\n[stderr]\n${r.stderr}` : ""}`), pre.secrets),
      ms: Date.now() - started,
      exitCode: r.code,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(`winrm ${args.host} failed: ${(err as Error).message}`, pre.secrets),
      output: "",
      ms: Date.now() - started,
    };
  } finally {
    await t.close().catch(() => undefined);
  }
}

/**
 * WinRM listener probe (battery WS-010). Unauthenticated reconnaissance:
 * one POST /wsman per port, reads the 401 challenge. Preflight is
 * kill-switch + scope only — no credentials are resolved or sent.
 * `ok` means the probe completed (per-port answers in `output`);
 * a port with no listener is a finding, not a failure.
 */

export async function winrmProbeImpl(core: ExecutorCore, args: {
  host: string;
  ports?: number[];
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Test seam — production callers leave this unset. */
  requestImpl?: WinrmProbeRequestImpl;
}): Promise<HostExecResult> {
  const started = Date.now();
  const pre = core.preflightNoCreds("winrm", args.host, args.scopeHosts);
  if ("refused" in pre) return core.refusedResult("winrm", args.host, pre.refused);
  const ports = args.ports ?? [5985, 5986];
  if (ports.length === 0) return core.refusedResult("winrm", args.host, "no ports to probe");
  if (ports.length > 16) return core.refusedResult("winrm", args.host, "refusing to probe more than 16 ports");
  const perPortMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
  try {
    const results: WinrmProbeResult[] = await core.bounded(
      probeWinrmListener({
        host: args.host,
        ports,
        timeoutMs: perPortMs,
        signal: args.signal,
        requestImpl: args.requestImpl,
      }),
      perPortMs * ports.length + 5_000,
      "winrm_probe",
      { close: async () => undefined },
    );
    const reachable = results.filter((r) => r.reachable);
    const schemes = [...new Set(results.flatMap((r) => r.authSchemes))];
    const lines = results.map((r) => {
      const auth = r.authSchemes.length > 0 ? r.authSchemes.join(", ") : "(none advertised)";
      const server = r.serverHeader ? ` server="${r.serverHeader}"` : "";
      return `${r.port}/${r.useTls ? "tls" : "plain"}: ${r.reachable ? "LISTENER" : "no listener"} auth=[${auth}]${server} — ${r.note}`;
    });
    return {
      ok: true,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(
        `winrm probe ${args.host}: ${reachable.length}/${results.length} ports answered` +
          (schemes.length > 0 ? `, auth schemes: ${schemes.join(", ")}` : ""),
        pre.secrets,
      ),
      output: redactSecrets(capOutput(lines.join("\n")), pre.secrets),
      ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(`winrm probe ${args.host} failed: ${(err as Error).message}`, pre.secrets),
      output: "",
      ms: Date.now() - started,
    };
  }
}

/**
 * NFS export enumeration (battery LX-041). Unauthenticated by design —
 * the mount protocol's EXPORT procedure needs no credentials.
 * Preflight is kill-switch + scope only; no commands run so the denylist
 * does not apply (documented, not skipped silently). Never mounts
 * anything — see nfs.ts.
 */
