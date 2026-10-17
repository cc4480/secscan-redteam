/**
 * Windows PC-agent host-exec backend — interface and client (v0.34.0).
 *
 * Why this exists: the Windows battery needs an execution channel, and our own
 * field run stalled because SMB / WinRM / SSH were all unavailable on the target
 * (WinRM closed, no test SMB credentials, RDP off). AlterEgo proved that a small
 * authenticated agent on the endpoint — speaking MCP Streamable HTTP — is a
 * workable channel for exactly that situation.
 *
 * What is here: the configuration gate, the closed tool allow-list, and a client
 * that performs the Streamable-HTTP handshake correctly — `initialize`, then
 * `notifications/initialized`, then `tools/call`, carrying the `Mcp-Session-Id`
 * the server returns. The session id is not optional: a server rejects subsequent
 * requests without it ("Missing session ID"), which an on-host smoke against a real
 * agent demonstrated.
 *
 * Deliberately NOT included: the approval dialog. An engagement cannot ask the
 * *target's* user for consent; authorisation comes from the engagement's own
 * sign-off and tier, and every call is recorded in the runner's event log.
 *
 * Verified against a real agent by `scripts/smoke-pc-agent.mjs` (AlterEgo's
 * pc-agent on loopback, paired through its 6-digit flow).
 */

export const PC_AGENT_ENV_URL = "REDTEAM_PC_AGENT_URL";
export const PC_AGENT_ENV_TOKEN = "REDTEAM_PC_AGENT_TOKEN";

/** The only tools this backend may call. Closed set, by design. */
export const PC_AGENT_ALLOWED_TOOLS = [
  "system_info",
  "list_processes",
  "list_dir",
  "read_file",
  "shell_exec",
  "shell_pwsh",
] as const;

export type PcAgentTool = (typeof PC_AGENT_ALLOWED_TOOLS)[number];

export interface PcAgentConfig {
  url: string;
  token: string;
}

export interface PcAgentClient {
  /** Call one allow-listed tool and return its text result. */
  call(tool: PcAgentTool, args: Record<string, unknown>): Promise<string>;
}

/** Response surface the client needs; a real fetch satisfies it structurally. */
export interface FetchLikeResponse {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}

export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<FetchLikeResponse>;

/** Read and validate configuration. Returns undefined when unconfigured or malformed. */
export function pcAgentConfig(env: NodeJS.ProcessEnv = process.env): PcAgentConfig | undefined {
  const url = (env[PC_AGENT_ENV_URL] ?? "").trim();
  const token = (env[PC_AGENT_ENV_TOKEN] ?? "").trim();
  if (!url || !token) return undefined;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return undefined;
  } catch {
    return undefined;
  }
  // A short bearer token would be a configuration error, not a working channel.
  if (token.length < 16) return undefined;
  return { url, token };
}

export function pcAgentConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  return pcAgentConfig(env) !== undefined;
}

/** A JSON or SSE body; empty for accepted notifications. */
function parseBody(text: string): unknown {
  const trimmed = text.trim();
  if (trimmed === "") return undefined;
  const dataLines = trimmed
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trim())
    .filter((line) => line !== "");
  if (dataLines.length > 0) return JSON.parse(dataLines[dataLines.length - 1]!);
  return JSON.parse(trimmed);
}

/** Result text of a `tools/call` reply, when the server used the content array. */
function toolText(parsed: unknown): string | undefined {
  if (parsed === null || typeof parsed !== "object") return undefined;
  const result = (parsed as { result?: unknown }).result;
  if (result === null || typeof result !== "object") return undefined;
  const content = (result as { content?: unknown }).content;
  if (!Array.isArray(content)) return undefined;
  const texts = content
    .map((item) => (item !== null && typeof item === "object" ? (item as { text?: unknown }).text : undefined))
    .filter((text): text is string => typeof text === "string");
  return texts.length > 0 ? texts.join("\n") : undefined;
}

interface RpcReply {
  parsed: unknown;
  /** `Mcp-Session-Id` from the response, when the server issued or expects one. */
  sessionId?: string;
}

/**
 * One MCP Streamable-HTTP JSON-RPC exchange over the injected fetch.
 * Throws on a transport error or a non-2xx reply.
 */
async function rpc(
  fetchImpl: FetchLike,
  cfg: PcAgentConfig,
  body: unknown,
  sessionId?: string,
): Promise<RpcReply> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    authorization: `Bearer ${cfg.token}`,
  };
  if (sessionId !== undefined) headers["mcp-session-id"] = sessionId;
  const res = await fetchImpl(cfg.url, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await res.text();
  const issued = res.headers.get("mcp-session-id") ?? undefined;
  if (!res.ok) throw new Error(`pc-agent HTTP ${String(res.status)}: ${text.slice(0, 200)}`);
  return { parsed: parseBody(text), sessionId: issued ?? sessionId };
}

/**
 * Create a client bound to one configuration. Every call re-checks the allow-list
 * so a future caller cannot widen the surface by passing an arbitrary name.
 */
export function createPcAgentClient(cfg: PcAgentConfig, fetchImpl: FetchLike): PcAgentClient {
  return {
    async call(tool: PcAgentTool, args: Record<string, unknown>): Promise<string> {
      if (!(PC_AGENT_ALLOWED_TOOLS as readonly string[]).includes(tool)) {
        throw new Error(`pc-agent: tool ${JSON.stringify(tool)} is not on the allow-list`);
      }
      const initialized = await rpc(fetchImpl, cfg, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "secscan-redteam", version: "0.34.0" },
        },
      });
      const sessionId = initialized.sessionId;
      // Notifications are accepted without a body; a server may answer 202 here.
      await rpc(fetchImpl, cfg, { jsonrpc: "2.0", method: "notifications/initialized", params: {} }, sessionId);
      const reply = await rpc(
        fetchImpl,
        cfg,
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: tool, arguments: args } },
        sessionId,
      );
      return toolText(reply.parsed) ?? JSON.stringify(reply.parsed ?? null);
    },
  };
}
