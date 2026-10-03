/**
 * ExecutorCore: shared host-execution machinery (v0.19.0 refactor — extracted from executor.ts).
 */
import { type HostCredentials, checkDestructive, collectSecrets, redactSecrets, resolveSmbCredentials, resolveSshCredentials, resolveWinrmCredentials, validateHostTarget } from "../common.js";
import { createAdTransport } from "../ad.js";
import { createKrbTransport } from "../krb.js";
import { createNfsTransport } from "../nfs.js";
import { createRdpTransport } from "../rdp.js";
import { createSmbPthTransport, createSmbTransport } from "../smb.js";
import { createSshTransport } from "../ssh.js";
import { createWinrmTransport } from "../winrm.js";
import { type HostExecResult, type HostExecDeps } from "./types.js";

export class ExecutorCore {
  readonly deps: Required<Pick<HostExecDeps, "ssh" | "smb" | "smbPth" | "winrm" | "rdp" | "ad" | "krb" | "nfs">> & { env: NodeJS.ProcessEnv };
  /** Kill-switch state, shared with the engagement context (phases.ts owns it). */
  killSwitch: { aborted: boolean } = { aborted: false };

  async bounded<T>(p: Promise<T>, ms: number, label: string, t: { close(): Promise<void> }): Promise<T> {
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


  preflight(
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

  preflightNoCreds(
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


  refusedResult(
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

}
