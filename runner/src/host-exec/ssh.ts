/**
 * SSH command execution (Linux targets).
 *
 * LIBRARY CHOICE: `ssh2` (v1.17.x, actively maintained as of 2026) — the
 * de-facto Node SSH2 implementation: key + password auth, exec channels,
 * per-command timeouts, and clean teardown. Evaluated alternatives: none
 * credible — every other Node SSH client is a thin wrapper around ssh2 or
 * unmaintained.
 *
 * Non-interactive exec channels only: no shells, no PTY, no port forwarding.
 * Agent forwarding is supported ONLY for the forwarding audit
 * (battery LX-018/LX-019, `sshAgentAudit` in executor.ts): the runner
 * passes the operator's local agent socket through, and the audit commands
 * only OBSERVE the forwarded socket on the target. The socket is never used
 * for onward authentication — that is analysis-only by design, documented
 * at both the transport and executor layers.
 */

import { Client } from "ssh2";
import { readFileSync } from "node:fs";
import { HOST_EXEC_TIMEOUT_MS, HOST_OUTPUT_CAP, capOutput, type HostCredentials } from "./common.js";

export interface SshExecArgs {
  host: string;
  port?: number;
  creds: HostCredentials;
  command: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  /**
   * Forward the local SSH agent to the target. Only the forwarding audit
   * sets this — ordinary command execution never forwards the agent.
   */
  agentForward?: boolean;
  /** Local agent socket path, passed to ssh2's `agent` connect option. */
  agentSocketPath?: string;
}

export interface SshExecResult {
  stdout: string;
  stderr: string;
  code: number;
  ms: number;
}

/** Structural interface so tests inject a fake (no network). */
export interface SshTransport {
  exec(args: SshExecArgs): Promise<SshExecResult>;
  close(): Promise<void>;
}

/**
 * Resolve the local SSH agent socket for the forwarding audit.
 * Fails fast with an actionable error when no agent is available —
 * the audit cannot run without a socket to forward.
 */
export function resolveAgentSocketPath(env: NodeJS.ProcessEnv = process.env): string {
  const sock = env["REDTEAM_SSH_AGENT_SOCKET"] ?? env["SSH_AUTH_SOCK"];
  if (sock && sock.trim()) return sock.trim();
  throw new Error(
    "[ssh] agent forwarding audit needs a local SSH agent socket: set REDTEAM_SSH_AGENT_SOCKET " +
      "(or SSH_AUTH_SOCK) to the agent socket path. The audit is read-only — the socket is " +
      "observed on the target and never used for onward authentication.",
  );
}

/**
 * FIXED audit commands (battery LX-018/LX-019). Not agent-supplied — the
 * executor runs exactly these strings, and they still pass through the
 * destructive-command denylist as a mechanical backstop.
 */
export const SSH_AGENT_AUDIT_SOCKET_CHECK =
  `printf 'SOCK=%s\\n' "$SSH_AUTH_SOCK"; ` +
  `if [ -S "$SSH_AUTH_SOCK" ]; then echo SOCK_PRESENT; ls -l "$SSH_AUTH_SOCK"; ` +
  `stat -c 'owner=%U group=%G mode=%a' "$SSH_AUTH_SOCK" 2>/dev/null; else echo SOCK_ABSENT; fi`;

/**
 * ANALYSIS ONLY: reports who could reach the forwarded socket. The socket
 * itself is never used for onward auth — this command only reads `id`,
 * `ls`, and `stat` output.
 */
export const SSH_AGENT_AUDIT_ABUSE_PATH =
  `id; ls -l "$SSH_AUTH_SOCK"; stat -c '%U %G %a' "$SSH_AUTH_SOCK"`;

function resolveKey(creds: HostCredentials): string | undefined {
  if (!creds.privateKey) return undefined;
  if (creds.privateKey.startsWith("__KEY_PATH__:")) {
    return readFileSync(creds.privateKey.slice("__KEY_PATH__:".length), "utf8");
  }
  return creds.privateKey;
}

export function createSshTransport(): SshTransport {
  let client: Client | null = null;
  let lastArgs: SshExecArgs | null = null;

  const ensureConnected = (args: SshExecArgs): Promise<Client> =>
    new Promise((resolve, reject) => {
      // Reuse the session within one engagement turn when the target AND the
      // connection profile are the same. agentForward/agentSocketPath are part
      // of the key: a forwarded session must never be reused for a
      // non-forwarded exec or vice versa.
      if (
        client &&
        lastArgs &&
        lastArgs.host === args.host &&
        lastArgs.port === args.port &&
        lastArgs.creds.username === args.creds.username &&
        !!lastArgs.agentForward === !!args.agentForward &&
        (lastArgs.agentSocketPath ?? "") === (args.agentSocketPath ?? "")
      ) {
        resolve(client);
        return;
      }
      const c = new Client();
      const timer = setTimeout(() => {
        c.destroy();
        reject(new Error(`[ssh] connect timeout to ${args.host}`));
      }, args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS);
      c.on("ready", () => {
        clearTimeout(timer);
        client = c;
        lastArgs = args;
        resolve(c);
      });
      c.on("error", (err) => {
        clearTimeout(timer);
        reject(new Error(`[ssh] ${(err as Error).message}`));
      });
      const key = resolveKey(args.creds);
      c.connect({
        host: args.host,
        port: args.port ?? 22,
        username: args.creds.username,
        password: args.creds.password,
        privateKey: key,
        readyTimeout: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
        // Agent forwarding is opt-in per exec args and set only by the
        // forwarding audit. ssh2's `agent` option is the local agent socket
        // path; the forwarded socket is observed, never used for onward auth.
        ...(args.agentForward ? { agentForward: true, agent: args.agentSocketPath } : {}),
        // Strict host-key checking is the operator's SSH config domain; the
        // runner pins nothing and trusts the operator's known_hosts setup.
      });
    });

  return {
    async exec(args: SshExecArgs): Promise<SshExecResult> {
      if (args.signal?.aborted) throw new Error("[ssh] aborted by kill switch before exec");
      const c = await ensureConnected(args);
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
      const started = Date.now();
      return new Promise((resolve, reject) => {
        let stdout = "";
        let stderr = "";
        let settled = false;
        const done = (fn: () => void) => {
          if (!settled) {
            settled = true;
            fn();
          }
        };
        const timer = setTimeout(() => {
          done(() => reject(new Error(`[ssh] command timed out after ${timeoutMs}ms`)));
        }, timeoutMs);
        const onAbort = () => {
          clearTimeout(timer);
          try {
            c.destroy();
          } catch {
            /* already gone */
          }
          client = null;
          done(() => reject(new Error("[ssh] aborted by kill switch — session destroyed")));
        };
        args.signal?.addEventListener("abort", onAbort, { once: true });
        c.exec(args.command.slice(0, 4000), (err, stream) => {
          if (err) {
            clearTimeout(timer);
            args.signal?.removeEventListener("abort", onAbort);
            done(() => reject(new Error(`[ssh] exec failed: ${(err as Error).message}`)));
            return;
          }
          stream.on("close", (code: number) => {
            clearTimeout(timer);
            args.signal?.removeEventListener("abort", onAbort);
            done(() =>
              resolve({
                stdout: capOutput(stdout, HOST_OUTPUT_CAP),
                stderr: capOutput(stderr, HOST_OUTPUT_CAP),
                code: typeof code === "number" ? code : -1,
                ms: Date.now() - started,
              }),
            );
          });
          stream.on("data", (d: Buffer) => {
            stdout += d.toString("utf8");
            if (stdout.length > HOST_OUTPUT_CAP * 2) {
              // Backpressure guard: stop a runaway command flooding the channel.
              try {
                stream.close();
              } catch {
                /* best effort */
              }
            }
          });
          stream.stderr.on("data", (d: Buffer) => {
            stderr += d.toString("utf8");
          });
        });
      });
    },
    async close(): Promise<void> {
      try {
        client?.end();
      } catch {
        /* best effort */
      }
      client = null;
      lastArgs = null;
    },
  };
}
