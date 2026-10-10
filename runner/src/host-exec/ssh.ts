/**
 * SSH command execution (Linux targets). Library: `ssh2` (v1.17.x) — key +
 * password auth, exec channels, clean teardown; no credible alternative.
 * Non-interactive exec only: no shells, no PTY, no port forwarding. Agent
 * forwarding exists ONLY for the forwarding audit (LX-018/LX-019) and the
 * forwarded socket is observed, never used for onward authentication.
 */

import { Client } from "ssh2";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
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
  /** How the server's host key was verified this session (audit trail). */
  hostKey?: SshHostKeyInfo;
}

export interface SshHostKeyInfo {
  fingerprint: string;
  mode: "pinned" | "tofu";
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
 * destructive-command denylist as a mechanical backstop. ANALYSIS ONLY:
 * the socket is never used for onward auth; the commands only read
 * `id`, `ls`, and `stat` output.
 */
export const SSH_AGENT_AUDIT_SOCKET_CHECK =
  `printf 'SOCK=%s\\n' "$SSH_AUTH_SOCK"; ` +
  `if [ -S "$SSH_AUTH_SOCK" ]; then echo SOCK_PRESENT; ls -l "$SSH_AUTH_SOCK"; ` +
  `stat -c 'owner=%U group=%G mode=%a' "$SSH_AUTH_SOCK" 2>/dev/null; else echo SOCK_ABSENT; fi`;
export const SSH_AGENT_AUDIT_ABUSE_PATH =
  `id; ls -l "$SSH_AUTH_SOCK"; stat -c '%U %G %a' "$SSH_AUTH_SOCK"`;

function resolveKey(creds: HostCredentials): string | undefined {
  if (!creds.privateKey) return undefined;
  if (creds.privateKey.startsWith("__KEY_PATH__:")) {
    return readFileSync(creds.privateKey.slice("__KEY_PATH__:".length), "utf8");
  }
  return creds.privateKey;
}

// ---------------------------------------------------------------------------
// Host-key verification (2026-10-09 audit). Before this, the runner pinned
// nothing and sent test-account credentials to whatever answered — a spoofed
// or rebound in-scope host harvested them. Now, fail closed:
//  - Expected keys come from an OpenSSH known_hosts file:
//    REDTEAM_SSH_KNOWN_HOSTS, default ~/.ssh/known_hosts. An entry for the
//    host (or [host]:port) must match the presented key blob exactly.
//  - No entry and no opt-in → refused BEFORE connecting, remediation in the
//    error. Pinned-but-different key → handshake refused.
//  - TOFU exists only via REDTEAM_SSH_TOFU=1: the first presented key is
//    appended to the known-hosts file BEFORE it is trusted, and the
//    fingerprint + mode ride the exec result into the engagement audit
//    trail. If the record can't be written, the key is not trusted.
//  - No accept-all mode exists. Hashed (|1|) entries cannot be matched by
//    hostname and are ignored — re-pin those hosts.
// First connect, operator's one-time action: pin the host (ssh-keyscan
// <host> >> ~/.ssh/known_hosts), set REDTEAM_SSH_KNOWN_HOSTS to a
// per-engagement file, or set REDTEAM_SSH_TOFU=1 for the first run.
// ---------------------------------------------------------------------------

interface KnownHostKey { keytype: string; b64: string; }

export function sshHostKeyFingerprint(key: Buffer): string {
  return "SHA256:" + createHash("sha256").update(key).digest("base64");
}
function sshKeyType(blob: Buffer): string {
  try { return blob.subarray(4, 4 + blob.readUInt32BE(0)).toString("ascii"); } catch { return "ssh-ed25519"; }
}
export function sshKnownHostsPath(env: NodeJS.ProcessEnv = process.env): string {
  return env["REDTEAM_SSH_KNOWN_HOSTS"]?.trim() || join(homedir(), ".ssh", "known_hosts");
}
export function loadKnownHostKeys(path: string): Map<string, KnownHostKey[]> {
  const out = new Map<string, KnownHostKey[]>();
  let raw = "";
  try { raw = readFileSync(path, "utf8"); } catch { return out; }
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#") || t.startsWith("@")) continue;
    const [hosts, keytype, b64] = t.split(/\s+/);
    if (!hosts || !keytype || !b64) continue;
    for (const h of hosts.split(",")) {
      const arr = out.get(h.toLowerCase()) ?? [];
      arr.push({ keytype, b64 });
      out.set(h.toLowerCase(), arr);
    }
  }
  return out;
}

export function createSshTransport(opts: { env?: NodeJS.ProcessEnv } = {}): SshTransport {
  const env = opts.env ?? process.env;
  let client: Client | null = null;
  let lastArgs: SshExecArgs | null = null;
  let sessionHostKey: SshHostKeyInfo | undefined;

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
      // Host-key policy resolved per connect, before any credential moves.
      const khPath = sshKnownHostsPath(env);
      const known = loadKnownHostKeys(khPath);
      const hostLc = args.host.toLowerCase();
      const port = args.port ?? 22;
      const expected = [...(known.get(hostLc) ?? []), ...(known.get(`[${hostLc}]:${port}`) ?? [])];
      const tofu = env["REDTEAM_SSH_TOFU"] === "1";
      if (expected.length === 0 && !tofu) {
        reject(new Error(
          `[ssh] host key for ${args.host} is not pinned in ${khPath} — refusing to send credentials to an unverified host. ` +
          `Pin it (ssh-keyscan ${args.host} >> ${khPath}, or REDTEAM_SSH_KNOWN_HOSTS=<file>), or set REDTEAM_SSH_TOFU=1 for trust-on-first-use with the key recorded.`,
        ));
        return;
      }
      let verifyFailure: string | null = null;
      const hostVerifier = (presented: Buffer): boolean => {
        const blob = Buffer.isBuffer(presented) ? presented : Buffer.from(presented as unknown as string, "base64");
        const b64 = blob.toString("base64");
        const fp = sshHostKeyFingerprint(blob);
        if (expected.some((e) => e.b64 === b64)) { sessionHostKey = { fingerprint: fp, mode: "pinned" }; return true; }
        if (expected.length > 0) {
          const pinned = expected.map((e) => sshHostKeyFingerprint(Buffer.from(e.b64, "base64"))).join(", ");
          verifyFailure = `[ssh] host key MISMATCH for ${args.host}: presented ${fp}, pinned ${pinned} (${khPath}). Refusing — if the host was legitimately re-keyed, re-pin deliberately.`;
          return false;
        }
        try {
          mkdirSync(dirname(khPath), { recursive: true });
          const pattern = port === 22 ? hostLc : `[${hostLc}]:${port}`;
          appendFileSync(khPath, `${pattern} ${sshKeyType(blob)} ${b64}\n`, "utf8");
        } catch (err) {
          verifyFailure = `[ssh] TOFU could not record the host key for ${args.host} into ${khPath}: ${(err as Error).message} — unrecorded keys are never trusted.`;
          return false;
        }
        sessionHostKey = { fingerprint: fp, mode: "tofu" };
        return true;
      };
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
        reject(new Error(verifyFailure ?? `[ssh] ${(err as Error).message}`));
      });
      const key = resolveKey(args.creds);
      c.connect({
        host: args.host,
        port,
        username: args.creds.username,
        password: args.creds.password,
        privateKey: key,
        readyTimeout: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
        hostVerifier,
        // Agent forwarding is opt-in per exec args and set only by the
        // forwarding audit. ssh2's `agent` option is the local agent socket
        // path; the forwarded socket is observed, never used for onward auth.
        ...(args.agentForward ? { agentForward: true, agent: args.agentSocketPath } : {}),
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
        const done = (fn: () => void) => { if (!settled) { settled = true; fn(); } };
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
            done(() => resolve({
              stdout: capOutput(stdout, HOST_OUTPUT_CAP), stderr: capOutput(stderr, HOST_OUTPUT_CAP),
              code: typeof code === "number" ? code : -1, ms: Date.now() - started, hostKey: sessionHostKey,
            }));
          });
          stream.on("data", (d: Buffer) => {
            stdout += d.toString("utf8");
            if (stdout.length > HOST_OUTPUT_CAP * 2) {
              // Backpressure guard: stop a runaway command flooding the channel.
              try { stream.close(); } catch { /* best effort */ }
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
