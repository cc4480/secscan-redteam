/**
 * SSH agent audit implementation + output parsers (v0.19.0 refactor — extracted from executor.ts).
 */
import { HOST_EXEC_TIMEOUT_MS, capOutput, redactSecrets } from "../common.js";
import { SSH_AGENT_AUDIT_ABUSE_PATH, SSH_AGENT_AUDIT_SOCKET_CHECK, resolveAgentSocketPath } from "../ssh.js";
import { ExecutorCore } from "./core.js";
import { type HostExecResult } from "./types.js";

export async function sshAgentAuditImpl(core: ExecutorCore, args: {
  host: string;
  port?: number;
  mode: "socket-check" | "abuse-path";
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  const command = args.mode === "socket-check" ? SSH_AGENT_AUDIT_SOCKET_CHECK : SSH_AGENT_AUDIT_ABUSE_PATH;
  const pre = core.preflight("ssh", args.host, args.scopeHosts, command);
  if ("refused" in pre) return core.refusedResult("ssh", args.host, pre.refused);
  let agentSocket: string;
  try {
    agentSocket = resolveAgentSocketPath(core.deps.env);
  } catch (err) {
    return core.refusedResult("ssh", args.host, (err as Error).message, pre.secrets);
  }
  const t = core.deps.ssh();
  try {
    const r = await core.bounded(
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

export interface AgentAuditParsed {
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
