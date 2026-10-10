/**
 * Minimal SecScan MCP client (Streamable HTTP, stateless).
 *
 * Dependency-free — global fetch only. A normal User-Agent is set because the
 * edge WAF blocks default library user-agents (observed: Python-urllib 403s).
 */

export interface McpConfig {
  endpoint: string; // e.g. https://secscan.us/api/mcp
  token: string; // MCP-scope Bearer <redacted> an API-scope token is rejected by the server.
  timeoutMs?: number;
}

const PROTOCOL_VERSION = "2025-03-26";
const USER_AGENT = "secscan-redteam-runner/0.4.0";
/**
 * Hard ceiling on a single MCP response body. Legit tool results (scan
 * reports included) are far below this; a hostile or broken upstream
 * streaming forever must never make the runner buffer without bound
 * (audit 2026-10-09 security #16 — the old `res.text()` slurped whole).
 */
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

/**
 * Read a response body capped WHILE reading: chunks accumulate only up to
 * `cap` bytes; the moment the body grows past it the stream is cancelled
 * and the call fails loudly — truncating silently instead would feed a
 * cut-off JSON-RPC frame to the parser and could masquerade as content.
 */
async function readBodyCapped(res: Response, cap: number): Promise<string> {
  const body = res.body;
  if (!body) {
    // No readable stream (exotic runtime): fall back to text() but still
    // refuse an over-cap body rather than keeping it.
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > cap) {
      throw new Error(`[mcp] response body exceeded ${cap} bytes — refused (capped read)`);
    }
    return text;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel().catch(() => {});
      throw new Error(`[mcp] response body exceeded ${cap} bytes — refused (capped read)`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function headers(token: string): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    authorization: `Bearer ${token}`,
    "user-agent": USER_AGENT,
  };
}

export class McpClient {
  private readonly endpoint: string;
  private readonly token: string;
  private readonly timeoutMs: number;

  constructor(cfg: McpConfig) {
    if (!cfg.token) throw new Error("[mcp] SECSCAN_MCP_TOKEN is not set.");
    this.endpoint = cfg.endpoint.replace(/\/+$/, "");
    this.token = cfg.token;
    this.timeoutMs = cfg.timeoutMs ?? 30_000;
  }

  private async post(body: unknown): Promise<unknown> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(this.endpoint, {
        method: "POST",
        headers: headers(this.token),
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      const text = await readBodyCapped(res, MAX_RESPONSE_BYTES);
      if (res.status === 401 || res.status === 403) {
        throw new Error(`[mcp] HTTP ${res.status}: token rejected (wrong scope or revoked?).`);
      }
      if (!res.ok) throw new Error(`[mcp] HTTP ${res.status}: ${text.slice(0, 300)}`);
      // SSE or plain JSON: take the last data: line that parses.
      let json: unknown = null;
      for (const line of text.split("\n")) {
        const t = line.trim();
        if (t.startsWith("data:")) {
          try {
            json = JSON.parse(t.slice(5).trim());
          } catch {
            // keep scanning
          }
        }
      }
      if (json === null && text.trim()) {
        try {
          json = JSON.parse(text);
        } catch {
          // leave null
        }
      }
      return json;
    } finally {
      clearTimeout(timer);
    }
  }

  private unwrap(message: unknown): unknown {
    if (message && typeof message === "object" && "result" in (message as Record<string, unknown>)) {
      return (message as Record<string, unknown>)["result"];
    }
    return message;
  }

  /** Call any MCP tool by name; returns the concatenated text content. Throws on isError. */
  async callTool(name: string, args: Record<string, unknown> = {}): Promise<string> {
    await this.post({
      jsonrpc: "2.0",
      id: "init",
      method: "initialize",
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "secscan-redteam-runner", version: "0.4.0" },
      },
    });
    await this.post({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
    const raw = await this.post({
      jsonrpc: "2.0",
      id: `tool-${name}`,
      method: "tools/call",
      params: { name, arguments: args },
    });
    // A JSON-RPC error envelope has no `result` — unwrap passes it through
    // and content-extraction below used to collapse it into an EMPTY
    // success ("" reads downstream as "scan completed, nothing found").
    // Surface the error instead; silent empties are not an outcome.
    const envelope = raw as { error?: { code?: unknown; message?: unknown } } | null;
    if (envelope && typeof envelope === "object" && envelope.error) {
      throw new Error(
        `[mcp] ${name}: JSON-RPC error ${String(envelope.error.code ?? "unknown")}: ${String(envelope.error.message ?? "no message")}`,
      );
    }
    const result = this.unwrap(raw) as {
      isError?: boolean;
      content?: Array<{ type?: string; text?: string }>;
    } | null;
    if (!result || typeof result !== "object") throw new Error(`[mcp] ${name}: empty result`);
    if (result.isError) {
      const text = (result.content ?? []).map((c) => c.text ?? "").join("\n");
      throw new Error(`[mcp] ${name} isError: ${text.slice(0, 500)}`);
    }
    if (!Array.isArray(result.content)) {
      // Progress notifications and other non-result shapes land here (SSE
      // keeps the LAST parseable data: line). No content array = no tool
      // result — never masquerade it as an empty successful one.
      throw new Error(`[mcp] ${name}: malformed result (no content array) — transport/server error, not an empty finding`);
    }
    return result.content
      .filter((c) => typeof c.text === "string")
      .map((c) => c.text as string)
      .join("\n");
  }

  // Convenience wrappers (all read-only except scan_url / start_domain_verification).
  scanUrl(url: string, aggressive = false): Promise<string> {
    return this.callTool("scan_url", aggressive ? { url, aggressive: true } : { url });
  }
  getScanStatus(scanId: string, waitSeconds = 60): Promise<string> {
    return this.callTool("get_scan_status", { scan_id: scanId, wait_seconds: waitSeconds });
  }
  getReport(scanId: string): Promise<string> {
    return this.callTool("get_report", { scan_id: scanId });
  }
  listRecentScans(limit = 10): Promise<string> {
    return this.callTool("list_recent_scans", { limit });
  }
  listVerifiedDomains(): Promise<string> {
    return this.callTool("list_verified_domains", {});
  }
  startDomainVerification(domain: string): Promise<string> {
    return this.callTool("start_domain_verification", { domain });
  }
  checkDomainVerification(domain: string): Promise<string> {
    return this.callTool("check_domain_verification", { domain });
  }
  getAccount(): Promise<string> {
    return this.callTool("get_account", {});
  }
}
