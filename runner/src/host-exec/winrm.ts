/**
 * WinRM command execution (Windows targets).
 *
 * LIBRARY CHOICE: `winrm-client` (v0.0.12, published 2026 — the most
 * recently maintained Node WinRM client found) — SOAP-based WinRM with
 * automatic auth detection: Basic for local usernames, NTLM for
 * domain-prefixed (DOMAIN\\user) or UPN (user@domain) formats. Evaluated
 * alternatives: `nodejs-winrm` (1.1.3, 2020, stale), hand-rolled SOAP
 * (NTLM handshake is error-prone to reimplement; the library's js-md4
 * based NTLM is the safer path).
 *
 * HONEST LIMITATION, stated plainly: the library exposes no abort handle
 * for in-flight requests. The kill switch therefore RACES the abort signal
 * against the request: on abort the runner abandons the promise and reports
 * termination, but the underlying HTTP request may run to the server-side
 * timeout. Commands are still bounded by timeoutMs, non-interactive, and
 * denylisted — the abandon is a runner-side guarantee, not a wire guarantee.
 *
 * Non-interactive commands only. Prefer `runPowershell` for structured
 * enumeration (Get-Service, Get-ScheduledTask, registry reads); plain
 * `runCommand` for cmd.exe builtins.
 */

import { runCommand, runPowershell } from "winrm-client";
import { HOST_EXEC_TIMEOUT_MS, type HostCredentials } from "./common.js";

export interface WinrmExecArgs {
  host: string;
  port?: number;
  creds: HostCredentials;
  command: string;
  /** PowerShell (true) vs cmd.exe (false). Default true — most battery items are PowerShell. */
  powershell?: boolean;
  useTls?: boolean;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface WinrmExecResult {
  stdout: string;
  stderr: string;
  code: number;
  ms: number;
}

/** Structural interface so tests inject a fake (no network). */
export interface WinrmTransport {
  exec(args: WinrmExecArgs): Promise<WinrmExecResult>;
  close(): Promise<void>;
}

function qualname(creds: HostCredentials): string {
  // winrm-client auto-detects NTLM from DOMAIN\user or user@domain formats.
  if (creds.domain && !creds.username.includes("\\") && !creds.username.includes("@")) {
    return `${creds.domain}\\${creds.username}`;
  }
  return creds.username;
}

export function createWinrmTransport(): WinrmTransport {
  return {
    async exec(args: WinrmExecArgs): Promise<WinrmExecResult> {
      if (args.signal?.aborted) throw new Error("[winrm] aborted by kill switch before exec");
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
      const started = Date.now();
      const user = qualname(args.creds);
      const password = args.creds.password ?? "";
      const port = args.port ?? (args.useTls ? 5986 : 5985);

      // The library has no abort handle: race the kill-switch signal against
      // the request. On abort we abandon the promise (runner-side termination);
      // the request itself runs to the server-side timeout at worst.
      const run = (async () => {
        if (args.powershell === false) {
          return runCommand(args.command.slice(0, 4000), args.host, user, password, port, false, !!args.useTls);
        }
        return runPowershell(args.command.slice(0, 4000), args.host, user, password, port, !!args.useTls);
      })();

      const winner = await Promise.race([
        run.then((r) => ({ kind: "done" as const, r })),
        new Promise<{ kind: "timeout" }>((_, reject) => setTimeout(() => reject(new Error(`[winrm] command timed out after ${timeoutMs}ms`)), timeoutMs)),
        ...(args.signal
          ? [
              new Promise<{ kind: "aborted" }>((_, reject) => {
                args.signal!.addEventListener("abort", () => reject(new Error("[winrm] aborted by kill switch — request abandoned")), { once: true });
              }),
            ]
          : []),
      ]);

      if (winner.kind !== "done") throw new Error("[winrm] unreachable");
      const r = winner.r as { stdout?: string; stderr?: string; exitCode?: number; statusCode?: number };
      return {
        stdout: String(r.stdout ?? "").slice(0, 8192),
        stderr: String(r.stderr ?? "").slice(0, 8192),
        code: typeof r.exitCode === "number" ? r.exitCode : typeof r.statusCode === "number" ? r.statusCode : -1,
        ms: Date.now() - started,
      };
    },
    async close(): Promise<void> {
      // Stateless per-call library: nothing to close.
    },
  };
}
