/**
 * Windows PC-agent host-exec backend — INTERFACE CONTRACT (v0.34.0).
 *
 * Why this exists: the Windows battery needs an execution channel, and our own
 * field run stalled because SMB / WinRM / SSH were all unavailable on the target
 * (WinRM closed, no test SMB credentials, RDP off). AlterEgo proved that a small
 * authenticated agent on the endpoint — speaking MCP Streamable HTTP — is a
 * workable channel for exactly that situation.
 *
 * What is here is the CONTRACT, not a shipped transport:
 *   - configuration is explicit and opt-in (two env vars, nothing implicit)
 *   - the tool allow-list is a closed set, so this backend can never become a
 *     generic shell
 *   - calls are typed and return text; the caller owns auditing
 *
 * Deliberately NOT included: the approval dialog. An engagement cannot ask the
 * *target's* user for consent; authorisation comes from the engagement's own
 * sign-off and tier, and every call is recorded in the runner's event log.
 *
 * Execution against a real agent has not been verified headless — that half of
 * AlterEgo's design needs an on-host smoke test before it is trusted.
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

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

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

/** One MCP Streamable-HTTP JSON-RPC exchange over the injected fetch. */
async function rpc(fetchImpl: FetchLike, cfg: PcAgentConfig, body: unknown): Promise<string> {
  const res = await fetchImpl(cfg.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${cfg.token}`,
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`pc-agent HTTP ${res.status}: ${text.slice(0, 200)}`);
  // Accept either an SSE stream (last data: line) or a plain JSON document.
  let parsed: unknown;
  const dataLines = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("data:"))
    .map((l) => l.slice(5).trim());
  if (dataLines.length > 0) {
    const last = dataLines[dataLines.length - 1]!;
    parsed = JSON.parse(last);
  } else {
    parsed = JSON.parse(text);
  }
  return JSON.stringify(parsed);
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
      await rpc(fetchImpl, cfg, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "secscan-redteam", version: "0.34.0" } },
      });
      await rpc(fetchImpl, cfg, { jsonrpc: "2.0", method: "notifications/initialized", params: {} });
      return rpc(fetchImpl, cfg, {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: tool, arguments: args },
      });
    },
  };
}
