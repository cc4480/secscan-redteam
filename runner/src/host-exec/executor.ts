/**
 * HostExecutor — the runner's hands on hosts.
 *
 * Every invocation flows through the safety core (common.ts) IN THIS ORDER:
 *   1. kill-switch check (refuse new work when the coordinator aborted)
 *   2. scope check (exact ROE-scope match, fail closed, before any packet)
 *   3. destructive-command denylist (fail closed, before connect)
 *   4. credential resolution (env/Secure Vault only, fail fast when missing)
 *   5. execution with timeout + abort signal + output caps
 *   6. redaction of every secret from every string that leaves
 *
 * Transports are injected as factories so tests run with fakes (no network).
 * The default factories build the real transports (ssh2 / @marsaud/smb2 /
 * winrm-client).
 */

import {
  HOST_EXEC_TIMEOUT_MS,
  capOutput,
  checkDestructive,
  collectSecrets,
  redactSecrets,
  resolveSmbCredentials,
  resolveSshCredentials,
  resolveWinrmCredentials,
  summarizeCommand,
  validateHostTarget,
  type HostCredentials,
} from "./common.js";
import { createSshTransport, type SshTransport } from "./ssh.js";
import { createSmbTransport, type SmbTransport } from "./smb.js";
import { createWinrmTransport, type WinrmTransport } from "./winrm.js";

export interface HostExecDeps {
  ssh?: () => SshTransport;
  smb?: () => SmbTransport;
  winrm?: () => WinrmTransport;
  env?: NodeJS.ProcessEnv;
}

export interface HostExecResult {
  ok: boolean;
  transport: "ssh" | "smb" | "winrm";
  host: string;
  /** Redacted one-line summary for audit logs and events. */
  summary: string;
  /** Redacted, capped output. */
  output: string;
  ms: number;
  exitCode?: number;
  /** Set when the safety core refused before connecting. */
  refused?: string;
}

export class HostExecutor {
  private readonly deps: Required<Pick<HostExecDeps, "ssh" | "smb" | "winrm">> & { env: NodeJS.ProcessEnv };
  /** Kill-switch state, shared with the engagement context (phases.ts owns it). */
  killSwitch: { aborted: boolean } = { aborted: false };

  /**
   * Executor-level timeout backstop: transports enforce their own timeouts,
   * but a misbehaving transport must never hang the engagement forever.
   * On timeout we close the transport (best effort) and report the timeout.
   */
  private async bounded<T>(p: Promise<T>, ms: number, label: string, t: { close(): Promise<void> }): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        p,
        new Promise<T>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`[host-exec] ${label} timed out after ${ms}ms (executor backstop)`)), ms);
        }),
      ]);
    } catch (err) {
      await t.close().catch(() => undefined);
      throw err;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  constructor(deps: HostExecDeps = {}) {
    this.deps = {
      ssh: deps.ssh ?? createSshTransport,
      smb: deps.smb ?? createSmbTransport,
      winrm: deps.winrm ?? createWinrmTransport,
      env: deps.env ?? process.env,
    };
  }

  private preflight(
    transport: HostExecResult["transport"],
    host: string,
    scopeHosts: string[],
    command?: string,
  ): { creds: HostCredentials; secrets: string[] } | { refused: string } {
    if (this.killSwitch.aborted) {
      return { refused: "kill switch active — coordinator aborted; no new host executions" };
    }
    const v = validateHostTarget(host, scopeHosts);
    if (!v.ok) return { refused: v.reason };
    if (command) {
      const denied = checkDestructive(command);
      if (denied) return { refused: `destructive-command denylist: ${denied}` };
    }
    try {
      const creds =
        transport === "ssh"
          ? resolveSshCredentials(this.deps.env)
          : transport === "smb"
            ? resolveSmbCredentials(this.deps.env)
            : resolveWinrmCredentials(this.deps.env);
      return { creds, secrets: collectSecrets(creds) };
    } catch (err) {
      return { refused: (err as Error).message };
    }
  }

  private refusedResult(
    transport: HostExecResult["transport"],
    host: string,
    refused: string,
    secrets: string[] = [],
  ): HostExecResult {
    return {
      ok: false,
      transport,
      host,
      summary: redactSecrets(`REFUSED: ${refused}`, secrets),
      output: "",
      ms: 0,
      refused: redactSecrets(refused, secrets),
    };
  }

  async sshExec(args: {
    host: string;
    port?: number;
    command: string;
    scopeHosts: string[];
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<HostExecResult> {
    const started = Date.now();
    const pre = this.preflight("ssh", args.host, args.scopeHosts, args.command);
    if ("refused" in pre) return this.refusedResult("ssh", args.host, pre.refused);
    const t = this.deps.ssh();
    try {
      const r = await this.bounded(
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

  async smbExec(args: {
    host: string;
    operation: "list_shares" | "list_dir" | "stat";
    share?: string;
    path?: string;
    extraShares?: string[];
    scopeHosts: string[];
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<HostExecResult> {
    const started = Date.now();
    const pre = this.preflight("smb", args.host, args.scopeHosts);
    if ("refused" in pre) return this.refusedResult("smb", args.host, pre.refused);
    if ((args.operation === "list_dir" || args.operation === "stat") && !args.share) {
      return this.refusedResult("smb", args.host, `${args.operation} requires a share name`, pre.secrets);
    }
    const t = this.deps.smb();
    try {
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
      const tArgs = { host: args.host, creds: pre.creds, timeoutMs, signal: args.signal };
      let output: string;
      if (args.operation === "list_shares") {
        const res = await this.bounded(t.probeShares(tArgs, args.extraShares ?? []), timeoutMs + 5_000, "smb_exec", t);
        output = res.map((r) => `${r.share}: ${r.accessible ? "ACCESSIBLE" : "denied"} (${r.note})`).join("\n");
      } else if (args.operation === "list_dir") {
        const entries = await this.bounded(t.listDir(tArgs, args.share!, args.path ?? ""), timeoutMs + 5_000, "smb_exec", t);
        output = entries.map((e) => `${e.isDirectory ? "[dir] " : ""}${e.name}`).join("\n") || "(empty)";
      } else {
        const st = await this.bounded(t.stat(tArgs, args.share!, args.path ?? ""), timeoutMs + 5_000, "smb_exec", t);
        output = st.exists ? `exists, ${st.isDirectory ? "directory" : `file${st.size !== undefined ? `, ${st.size} bytes` : ""}`}` : "not found";
      }
      const where = args.operation === "list_shares" ? "shares" : `${args.share}${args.path ? `\\${args.path}` : ""}`;
      return {
        ok: true,
        transport: "smb",
        host: args.host,
        summary: redactSecrets(`smb ${args.host}: ${args.operation} ${where}`, pre.secrets),
        output: redactSecrets(capOutput(output), pre.secrets),
        ms: Date.now() - started,
      };
    } catch (err) {
      return {
        ok: false,
        transport: "smb",
        host: args.host,
        summary: redactSecrets(`smb ${args.host} ${args.operation} failed: ${(err as Error).message}`, pre.secrets),
        output: "",
        ms: Date.now() - started,
      };
    } finally {
      await t.close().catch(() => undefined);
    }
  }

  async winrmExec(args: {
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
    const pre = this.preflight("winrm", args.host, args.scopeHosts, args.command);
    if ("refused" in pre) return this.refusedResult("winrm", args.host, pre.refused);
    const t = this.deps.winrm();
    try {
      const r = await this.bounded(
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
}
