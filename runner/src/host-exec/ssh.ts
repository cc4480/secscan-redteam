/**
 * SSH command execution (Linux targets).
 *
 * LIBRARY CHOICE: `ssh2` (v1.17.x, actively maintained as of 2026) — the
 * de-facto Node SSH2 implementation: key + password auth, exec channels,
 * per-command timeouts, and clean teardown. Evaluated alternatives: none
 * credible — every other Node SSH client is a thin wrapper around ssh2 or
 * unmaintained.
 *
 * Non-interactive exec channels only: no shells, no PTY, no port forwarding,
 * no agent forwarding. One command per invocation, bounded by timeout.
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
      // Reuse the session within one engagement turn when the target is the same.
      if (client && lastArgs && lastArgs.host === args.host && lastArgs.port === args.port && lastArgs.creds.username === args.creds.username) {
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
