/**
 * Server-side domain verification over the SecScan MCP endpoint
 * (Streamable HTTP). Dependency-free — global fetch only.
 *
 * The SecScan server is the authority on which domains are verified. The
 * gate calls the server's own `list_verified_domains` tool and treats a
 * listed domain as authorized for aggressive testing. Every failure mode —
 * network error, timeout, non-2xx, bad handshake, unparseable body —
 * throws; callers MUST treat a throw as "unverified" (fail closed).
 */

import { isDomainVerified, parseVerifiedDomains } from "./verify.js";

export interface ServerVerificationConfig {
  /** MCP endpoint, e.g. https://secscan.us/api/mcp */
  endpoint: string;
  /** MCP-scope bearer token (an API-scope token is rejected by the server). */
  token: string;
  /** Per-request timeout. Default 10_000. */
  timeoutMs?: number;
}

const PROTOCOL_VERSION = "2025-03-26";
const CLIENT_NAME = "secscan-redteam-auth-gate";
const CLIENT_VERSION = "0.2.2";

function headers(token: string): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    authorization: `Bearer ${token}`,
    "mcp-protocol-version": PROTOCOL_VERSION,
  };
}

async function postJson(
  cfg: Required<Pick<ServerVerificationConfig, "endpoint" | "token">> & { timeoutMs: number },
  body: unknown,
): Promise<{ status: number; json: unknown }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), cfg.timeoutMs);
  try {
    const res = await fetch(cfg.endpoint, {
      method: "POST",
      headers: headers(cfg.token),
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    const contentType = res.headers.get("content-type") ?? "";
    let json: unknown = null;
    if (contentType.includes("text/event-stream")) {
      // SSE: take the last data: line that parses as a JSON-RPC message.
      const text = await res.text();
      for (const line of text.split("\n")) {
        const t = line.trim();
        if (t.startsWith("data:")) {
          try {
            json = JSON.parse(t.slice(5).trim());
          } catch {
            // keep scanning lines
          }
        }
      }
    } else {
      const text = await res.text();
      if (text.trim()) {
        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }
      }
    }
    return { status: res.status, json };
  } finally {
    clearTimeout(timer);
  }
}

function unwrapResult(message: unknown): unknown {
  if (message && typeof message === "object" && "result" in (message as Record<string, unknown>)) {
    return (message as Record<string, unknown>)["result"];
  }
  return message;
}

/**
 * Fetch the server's verified-domain list. Throws on ANY failure —
 * the caller must treat that as unverified.
 */
export async function fetchVerifiedDomains(cfg: ServerVerificationConfig): Promise<string[]> {
  if (!cfg.token) throw new Error("no MCP token configured");
  const full = {
    endpoint: cfg.endpoint,
    token: cfg.token,
    timeoutMs: cfg.timeoutMs ?? 10_000,
  };

  // 1. MCP initialize handshake (the endpoint is stateless; no session id is issued).
  const init = await postJson(full, {
    jsonrpc: "2.0",
    id: "auth-gate-init",
    method: "initialize",
    params: {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: CLIENT_NAME, version: CLIENT_VERSION },
    },
  });
  if (init.status !== 200 || !unwrapResult(init.json)) {
    throw new Error(`MCP initialize failed (status ${init.status})`);
  }

  // 2. Initialized notification — 202 expected, any 2xx accepted.
  const notified = await postJson(full, { jsonrpc: "2.0", method: "notifications/initialized" });
  if (notified.status < 200 || notified.status >= 300) {
    throw new Error(`MCP initialized notification failed (status ${notified.status})`);
  }

  // 3. The authoritative list.
  const called = await postJson(full, {
    jsonrpc: "2.0",
    id: "auth-gate-list-verified",
    method: "tools/call",
    params: { name: "list_verified_domains", arguments: {} },
  });
  if (called.status !== 200) {
    throw new Error(`list_verified_domains failed (status ${called.status})`);
  }
  const result = unwrapResult(called.json);
  if (result && typeof result === "object" && "isError" in (result as Record<string, unknown>) &&
      (result as Record<string, unknown>)["isError"]) {
    throw new Error("list_verified_domains returned isError");
  }
  return parseVerifiedDomains(result);
}

/**
 * Fail-closed wrapper: true only when the server positively lists the
 * domain. Any error, timeout, or missing token → false.
 */
export async function isServerVerified(
  domain: string,
  cfg: ServerVerificationConfig,
): Promise<boolean> {
  try {
    const list = await fetchVerifiedDomains(cfg);
    return isDomainVerified(domain, list);
  } catch {
    return false;
  }
}
