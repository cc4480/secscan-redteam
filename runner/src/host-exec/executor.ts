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
import {
  resolveAgentSocketPath,
  SSH_AGENT_AUDIT_ABUSE_PATH,
  SSH_AGENT_AUDIT_SOCKET_CHECK,
} from "./ssh.js";
import { createSmbTransport, type SmbTransport } from "./smb.js";
import { createWinrmTransport, type WinrmTransport } from "./winrm.js";
import { probeWinrmListener, type WinrmProbeRequestImpl, type WinrmProbeResult } from "./winrm.js";
import { createNfsTransport, type NfsTransport } from "./nfs.js";
import { createSmbPthTransport, type SmbPthTransport } from "./smb.js";
import {
  createRdpTransport,
  type RdpTransport,
  rdpValidateCredentials,
  RDP_SHADOW_PREP_PS,
  buildShadowHandoff,
} from "./rdp.js";
import { createAdTransport, type AdTransport, adEnumerate, type AdOperation } from "./ad.js";
import { createKrbTransport, type KrbTransport, spnHostname } from "./krb.js";
import {
  resolveSmbHashCredentials,
  resolveAdCredentials,
} from "./common.js";

export interface HostExecDeps {
  ssh?: () => SshTransport;
  smb?: () => SmbTransport;
  smbPth?: () => SmbPthTransport;
  winrm?: () => WinrmTransport;
  rdp?: () => RdpTransport;
  ad?: () => AdTransport;
  /** Receives the executor's env so ticket-material resolution stays hermetic in tests. */
  krb?: (env: NodeJS.ProcessEnv) => KrbTransport;
  nfs?: () => NfsTransport;
  env?: NodeJS.ProcessEnv;
}

export interface HostExecResult {
  ok: boolean;
  transport: "ssh" | "smb" | "winrm" | "nfs";
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
  private readonly deps: Required<Pick<HostExecDeps, "ssh" | "smb" | "smbPth" | "winrm" | "rdp" | "ad" | "krb" | "nfs">> & { env: NodeJS.ProcessEnv };
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
      smbPth: deps.smbPth ?? createSmbPthTransport,
      winrm: deps.winrm ?? createWinrmTransport,
      rdp: deps.rdp ?? createRdpTransport,
      ad: deps.ad ?? createAdTransport,
      krb: deps.krb ?? ((env) => createKrbTransport({ env })),
      nfs: deps.nfs ?? createNfsTransport,
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

  /**
   * Preflight for unauthenticated recon (WinRM probe, NFS enumeration):
   * kill-switch → scope check, then done. No credential resolution —
   * these tools are unauthenticated by design, so no secrets exist and
   * redaction over [] is a no-op. No denylist either — no commands run.
   */
  private preflightNoCreds(
    transport: HostExecResult["transport"],
    host: string,
    scopeHosts: string[],
  ): { secrets: string[] } | { refused: string } {
    if (this.killSwitch.aborted) {
      return { refused: "kill switch active — coordinator aborted; no new host executions" };
    }
    const v = validateHostTarget(host, scopeHosts);
    if (!v.ok) return { refused: v.reason };
    return { secrets: [] };
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

  /**
   * WinRM listener probe (battery WS-010). Unauthenticated reconnaissance:
   * one POST /wsman per port, reads the 401 challenge. Preflight is
   * kill-switch + scope only — no credentials are resolved or sent.
   * `ok` means the probe completed (per-port answers in `output`);
   * a port with no listener is a finding, not a failure.
   */
  async winrmProbe(args: {
    host: string;
    ports?: number[];
    scopeHosts: string[];
    timeoutMs?: number;
    signal?: AbortSignal;
    /** Test seam — production callers leave this unset. */
    requestImpl?: WinrmProbeRequestImpl;
  }): Promise<HostExecResult> {
    const started = Date.now();
    const pre = this.preflightNoCreds("winrm", args.host, args.scopeHosts);
    if ("refused" in pre) return this.refusedResult("winrm", args.host, pre.refused);
    const ports = args.ports ?? [5985, 5986];
    if (ports.length === 0) return this.refusedResult("winrm", args.host, "no ports to probe");
    if (ports.length > 16) return this.refusedResult("winrm", args.host, "refusing to probe more than 16 ports");
    const perPortMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
    try {
      const results: WinrmProbeResult[] = await this.bounded(
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
  async nfsEnum(args: {
    host: string;
    scopeHosts: string[];
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<HostExecResult> {
    const started = Date.now();
    const pre = this.preflightNoCreds("nfs", args.host, args.scopeHosts);
    if ("refused" in pre) return this.refusedResult("nfs", args.host, pre.refused);
    const t = this.deps.nfs();
    try {
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
      const exports = await this.bounded(
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
  async sshAgentAudit(args: {
    host: string;
    port?: number;
    mode: "socket-check" | "abuse-path";
    scopeHosts: string[];
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<HostExecResult> {
    const started = Date.now();
    const command = args.mode === "socket-check" ? SSH_AGENT_AUDIT_SOCKET_CHECK : SSH_AGENT_AUDIT_ABUSE_PATH;
    const pre = this.preflight("ssh", args.host, args.scopeHosts, command);
    if ("refused" in pre) return this.refusedResult("ssh", args.host, pre.refused);
    let agentSocket: string;
    try {
      agentSocket = resolveAgentSocketPath(this.deps.env);
    } catch (err) {
      return this.refusedResult("ssh", args.host, (err as Error).message, pre.secrets);
    }
    const t = this.deps.ssh();
    try {
      const r = await this.bounded(
        t.exec({
          host: args.host,
          port: args.port,
          creds: pre.creds,
          command,
          timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
          signal: args.signal,
          agentForward: true,
          agentSocketPath: agentSocket,
        }),
        (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 5_000,
        "ssh_agent_audit",
        t,
      );
      const parsed =
        args.mode === "socket-check" ? parseAgentSocketCheck(r.stdout) : parseAgentAbusePath(r.stdout);
      return {
        ok: r.code === 0,
        transport: "ssh",
        host: args.host,
        summary: redactSecrets(
          `ssh agent-audit ${args.host} (${args.mode}): exit=${r.code} in ${r.ms}ms :: ${parsed.summary}`,
          pre.secrets,
        ),
        output: redactSecrets(capOutput(parsed.detail), pre.secrets),
        ms: Date.now() - started,
        exitCode: r.code,
      };
    } catch (err) {
      return {
        ok: false,
        transport: "ssh",
        host: args.host,
        summary: redactSecrets(`ssh agent-audit ${args.host} failed: ${(err as Error).message}`, pre.secrets),
        output: "",
        ms: Date.now() - started,
      };
    } finally {
      await t.close().catch(() => undefined);
    }
  }
  /**
   * RDP credential validation via NLA (battery WS-019). Test-account
   * credentials from the environment; the handshake itself never sees them
   * in logs (only the NT hash derivation, in memory).
   */
  async rdpValidate(args: {
    host: string;
    port?: number;
    scopeHosts: string[];
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<HostExecResult> {
    const started = Date.now();
    // No shell command runs here, but the credential-bearing flow still goes
    // through kill-switch + scope + credential resolution, fail closed.
    if (this.killSwitch.aborted) {
      return this.refusedResult("winrm", args.host, "kill switch active — coordinator aborted; no new host executions");
    }
    const v = validateHostTarget(args.host, args.scopeHosts);
    if (!v.ok) return this.refusedResult("winrm", args.host, v.reason);
    let creds: HostCredentials;
    let secrets: string[];
    try {
      creds = resolveWinrmCredentials(this.deps.env);
      secrets = collectSecrets(creds);
    } catch (err) {
      return this.refusedResult("winrm", args.host, (err as Error).message);
    }
    const t = this.deps.rdp();
    try {
      const r = await this.bounded(
        rdpValidateCredentials(t, {
          host: args.host,
          port: args.port,
          creds,
          timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
          signal: args.signal,
        }),
        (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 5_000,
        "rdp_auth",
        t,
      );
      const verdict =
        r.credentialValid === true ? "CREDENTIAL VALID" : r.credentialValid === false ? "credential NOT valid" : "no verdict";
      return {
        ok: r.credentialValid === true,
        transport: "winrm",
        host: args.host,
        summary: redactSecrets(
          `rdp NLA validation ${args.host}: reachable=${r.reachable} nla=${r.nlaRequired} ${verdict} (${r.selectedProtocol ?? "no protocol"})`,
          secrets,
        ),
        output: redactSecrets(capOutput(r.note), secrets),
        ms: Date.now() - started,
      };
    } catch (err) {
      return {
        ok: false,
        transport: "winrm",
        host: args.host,
        summary: redactSecrets(`rdp NLA validation ${args.host} failed: ${(err as Error).message}`, secrets),
        output: "",
        ms: Date.now() - started,
      };
    } finally {
      await t.close().catch(() => undefined);
    }
  }

  /**
   * RDP shadow preparation (battery WS-065) — HUMAN-GATED. Runs the
   * read-only session/policy enumeration over WinRM and builds the complete
   * human handoff package. The runner NEVER shadows a session.
   */
  async rdpShadowPrep(args: {
    host: string;
    scopeHosts: string[];
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<HostExecResult> {
    const started = Date.now();
    const denied = checkDestructive(RDP_SHADOW_PREP_PS);
    if (denied) {
      return this.refusedResult("winrm", args.host, `shadow-prep script tripped the denylist (${denied}) — refusing`);
    }
    const pre = this.preflight("winrm", args.host, args.scopeHosts, RDP_SHADOW_PREP_PS);
    if ("refused" in pre) return this.refusedResult("winrm", args.host, pre.refused);
    const t = this.deps.winrm();
    try {
      const r = await this.bounded(
        t.exec({
          host: args.host,
          creds: pre.creds,
          command: RDP_SHADOW_PREP_PS,
          powershell: true,
          timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
          signal: args.signal,
        }),
        (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 5_000,
        "rdp_shadow_prep",
        t,
      );
      const handoff = buildShadowHandoff(r.stdout, args.host);
      return {
        ok: true,
        transport: "winrm",
        host: args.host,
        summary: redactSecrets(
          `rdp shadow prep ${args.host}: session/policy enumeration complete — HUMAN OPERATOR REQUIRED for the shadowing act`,
          pre.secrets,
        ),
        output: redactSecrets(capOutput(handoff), pre.secrets),
        ms: Date.now() - started,
      };
    } catch (err) {
      return {
        ok: false,
        transport: "winrm",
        host: args.host,
        summary: redactSecrets(`rdp shadow prep ${args.host} failed: ${(err as Error).message}`, pre.secrets),
        output: "",
        ms: Date.now() - started,
      };
    } finally {
      await t.close().catch(() => undefined);
    }
  }

  /**
   * Pass-the-hash over SMB with NTLMv2 (battery WS-023). The NT hash is the
   * test account's OWN, client-provided via REDTEAM_SMB_NTHASH — handled
   * with password-grade secrecy.
   */
  async smbPth(args: {
    host: string;
    port?: number;
    scopeHosts: string[];
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<HostExecResult> {
    const started = Date.now();
    if (this.killSwitch.aborted) {
      return this.refusedResult("smb", args.host, "kill switch active — coordinator aborted; no new host executions");
    }
    const v = validateHostTarget(args.host, args.scopeHosts);
    if (!v.ok) return this.refusedResult("smb", args.host, v.reason);
    let hashCreds: HostCredentials;
    let secrets: string[];
    try {
      hashCreds = resolveSmbHashCredentials(this.deps.env);
      secrets = collectSecrets(hashCreds);
    } catch (err) {
      return this.refusedResult("smb", args.host, (err as Error).message);
    }
    const t = this.deps.smbPth();
    try {
      const r = await this.bounded(
        t.auth({
          host: args.host,
          port: args.port,
          username: hashCreds.username,
          ntHashHex: hashCreds.ntHash!,
          domain: hashCreds.domain,
          timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
          signal: args.signal,
        }),
        (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 5_000,
        "smb_pth",
        t,
      );
      const verdict = r.hashAccepted === true ? "HASH ACCEPTED (PtH works)" : r.hashAccepted === false ? "hash rejected" : "no verdict";
      return {
        ok: r.hashAccepted === true,
        transport: "smb",
        host: args.host,
        summary: redactSecrets(
          `smb pass-the-hash ${args.host}: ${verdict} (${r.dialect ?? "no dialect"}, status ${r.ntStatus ?? "?"})`,
          secrets,
        ),
        output: redactSecrets(capOutput(r.note), secrets),
        ms: Date.now() - started,
      };
    } catch (err) {
      return {
        ok: false,
        transport: "smb",
        host: args.host,
        summary: redactSecrets(`smb pass-the-hash ${args.host} failed: ${(err as Error).message}`, secrets),
        output: "",
        ms: Date.now() - started,
      };
    } finally {
      await t.close().catch(() => undefined);
    }
  }

  /**
   * Read-only AD enumeration (batteries WS-038 attack paths, WS-043 AD CS).
   * LDAP simple bind as the test account; nothing is ever written.
   */
  async adEnum(args: {
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
      return this.refusedResult("winrm", args.host, "ad_enum requires at least one valid operation");
    }
    if (this.killSwitch.aborted) {
      return this.refusedResult("winrm", args.host, "kill switch active — coordinator aborted; no new host executions");
    }
    const v = validateHostTarget(args.host, args.scopeHosts);
    if (!v.ok) return this.refusedResult("winrm", args.host, v.reason);
    let creds: HostCredentials;
    let secrets: string[];
    try {
      creds = resolveAdCredentials(this.deps.env);
      secrets = collectSecrets(creds);
    } catch (err) {
      return this.refusedResult("winrm", args.host, (err as Error).message);
    }
    const t = this.deps.ad();
    try {
      const r = await this.bounded(
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
  async krbPtt(args: {
    host: string;
    spn?: string;
    scopeHosts: string[];
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<HostExecResult> {
    const started = Date.now();
    if (this.killSwitch.aborted) {
      return this.refusedResult("winrm", args.host, "kill switch active — coordinator aborted; no new host executions");
    }
    const v = validateHostTarget(args.host, args.scopeHosts);
    if (!v.ok) return this.refusedResult("winrm", args.host, v.reason);
    if (args.spn) {
      const spnHost = spnHostname(args.spn);
      if (!spnHost) return this.refusedResult("winrm", args.host, `malformed SPN: ${args.spn}`);
      const sv = validateHostTarget(spnHost, args.scopeHosts);
      if (!sv.ok) return this.refusedResult("winrm", args.host, `SPN host out of scope: ${sv.reason}`);
    }
    // Ticket material (ccache/kirbi/kinit) is resolved inside the transport;
    // any password it touches is redacted from all output there. The factory
    // receives the executor's env so tests stay hermetic.
    const t = this.deps.krb(this.deps.env);
    try {
      const r = await this.bounded(
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
}

// ---------------------------------------------------------------------------
// Agent-audit output parsing (pure functions — unit-testable, no network)
// ---------------------------------------------------------------------------

interface AgentAuditParsed {
  summary: string;
  detail: string;
}

/** Parse the LX-018 socket-check compound command output. */
export function parseAgentSocketCheck(stdout: string): AgentAuditParsed {
  const pathMatch = stdout.match(/^SOCK=(.*)$/m);
  const socketPath = (pathMatch?.[1] ?? "").trim();
  const present = /SOCK_PRESENT/.test(stdout);
  const lsLine = stdout.split("\n").find((l) => /^s[rwx-]{9}/.test(l.trim()))?.trim() ?? "";
  const statMatch = stdout.match(/owner=(\S+)\s+group=(\S+)\s+mode=(\S+)/);
  const perms = statMatch ? `owner=${statMatch[1]} group=${statMatch[2]} mode=${statMatch[3]}` : "";
  const summary = present
    ? `forwarded socket PRESENT at ${socketPath || "(unknown path)"}${perms ? ` (${perms})` : ""}`
    : `forwarded socket ABSENT (SSH_AUTH_SOCK=${socketPath || "(unset)"} is not a socket)`;
  const detail = [
    `mode=socket-check`,
    `socketPresent=${present}`,
    `socketPath=${socketPath || "(unknown)"}`,
    perms ? `perms: ${perms}` : `perms: (stat unavailable)`,
    lsLine ? `ls: ${lsLine}` : `ls: (no socket line)`,
    `note: LX-018 — a forwarded agent socket on the target means anyone with write access to it can speak to the operator's local agent.`,
  ].join("\n");
  return { summary, detail };
}

/** Parse the LX-019 abuse-path command output: who could reach the socket. */
export function parseAgentAbusePath(stdout: string): AgentAuditParsed {
  // id output: uid=1000(testuser) gid=1000(testuser) groups=1000(testuser),27(sudo)
  const idLine = stdout.split("\n").find((l) => l.includes("uid=")) ?? "";
  const uidMatch = idLine.match(/uid=\d+\(([^)]+)\)/);
  const gidMatch = idLine.match(/gid=\d+\(([^)]+)\)/);
  const groupsMatch = idLine.match(/groups=(.*)$/);
  const user = uidMatch?.[1] ?? "(unknown)";
  const groupNames = (groupsMatch?.[1] ?? "")
    .split(",")
    .map((g) => g.trim().match(/^\d+\(([^)]+)\)$/)?.[1] ?? g.trim())
    .filter(Boolean);
  const statLine = stdout.split("\n").find((l) => /^[^\s]+\s+[^\s]+\s+\d{3,4}$/.test(l.trim())) ?? "";
  const [sockOwner = "", sockGroup = "", sockMode = ""] = statLine.trim().split(/\s+/);
  const modeInt = /^[0-7]{3,4}$/.test(sockMode) ? parseInt(sockMode, 8) : NaN;

  let via = "(unknown)";
  let reachable: boolean | null = null;
  if (sockOwner && !Number.isNaN(modeInt)) {
    if (user === sockOwner) {
      via = `owner (${sockOwner})`;
      reachable = ((modeInt >> 6) & 7 & 2) !== 0;
    } else if (sockGroup && (groupNames.includes(sockGroup) || gidMatch?.[1] === sockGroup)) {
      via = `group (${sockGroup})`;
      reachable = ((modeInt >> 3) & 7 & 2) !== 0;
    } else {
      via = "other";
      reachable = (modeInt & 7 & 2) !== 0;
    }
  }
  // connect(2) to a unix socket needs write permission on the socket.
  const verdict =
    reachable === null
      ? "could not determine reachability (stat output unparseable)"
      : reachable
        ? `REACHABLE by this session via ${via} write bit — the forwarded agent is exposed to uid ${user}`
        : `not reachable by this session via ${via} (no write bit)`;

  const summary = `socket ${sockOwner ? `${sockOwner}:${sockGroup} mode ${sockMode}` : "(stat unparseable)"}; session user=${user} groups=[${groupNames.join(",") || "none"}]; ${verdict}`;
  const detail = [
    `mode=abuse-path`,
    `session: ${idLine || "(id output missing)"}`,
    `socket: owner=${sockOwner || "?"} group=${sockGroup || "?"} mode=${sockMode || "?"}`,
    `assessment: ${verdict}`,
    `note: LX-019 ANALYSIS ONLY — the socket is never used for onward authentication. This reports exposure; it does not exploit it.`,
  ].join("\n");
  return { summary, detail };
}
