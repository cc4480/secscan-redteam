/**
 * MCP server face for the RedTeam console (v0.29.0) — JSON-RPC transport.
 *
 * Why this exists: the runner was an MCP CLIENT only (see ../mcp.ts — it calls
 * SecScan's server). Nothing in the product offered an MCP SERVER, so a harness
 * like DeepSeek Harness had nothing to snap onto. This is that face: POST /mcp
 * on the console server, exposing the console's existing routes as MCP tools so
 * an external agent can drive and supervise an engagement.
 *
 * Stateless Streamable HTTP with JSON responses (no SSE) — the same shape the
 * runner's own McpClient and dsh-mcp-client both accept.
 *
 * Security: every tool delegates to the same handler the console UI calls, so
 * the safety core, launch validation, tier rules and approval logging apply
 * unchanged. This endpoint adds reach, not authority. Auth is the console
 * token, checked here because a JSON-RPC caller must receive a 401 it can
 * parse rather than the HTML login page the generic gate would serve.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { isAuthorized } from "./auth.js";
import type { UiStore } from "./store.js";
import { json, readJsonBody } from "./routes/http.js";
import { TOOLS, TOOLS_BY_NAME } from "./mcp-tools.js";

const PROTOCOL_VERSION = "2025-03-26";
const SERVER_INFO = { name: "secscan-redteam-runner", version: "0.22.0" };

interface RpcRequest {
  jsonrpc?: string;
  id?: unknown;
  method?: string;
  params?: Record<string, unknown>;
}

function rpcOk(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function rpcErr(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

/** One JSON-RPC message in, one reply out (null for notifications). */
async function dispatch(store: UiStore, r: RpcRequest): Promise<Record<string, unknown> | null> {
  switch (r.method) {
    case "initialize":
      return rpcOk(r.id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
      });
    case "notifications/initialized":
    case "notifications/cancelled":
      return null; // notifications are never answered
    case "ping":
      return rpcOk(r.id, {});
    case "tools/list":
      return rpcOk(r.id, {
        tools: TOOLS.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
      });
    case "tools/call": {
      const name = String(r.params?.["name"] ?? "");
      const args = (r.params?.["arguments"] ?? {}) as Record<string, unknown>;
      const tool = TOOLS_BY_NAME.get(name);
      if (!tool) return rpcErr(r.id, -32602, `unknown tool: ${name}`);
      try {
        const out = await tool.run(store, args);
        const text = typeof out.body === "string" ? out.body : JSON.stringify(out.body, null, 2);
        // A 4xx from a handler is a tool-level failure the model should see and
        // reason about, not a transport error — so it rides in the result.
        return rpcOk(r.id, { content: [{ type: "text", text }], isError: out.status >= 400 });
      } catch (err) {
        return rpcOk(r.id, {
          content: [{ type: "text", text: `tool failed: ${(err as Error).message}` }],
          isError: true,
        });
      }
    }
    default:
      return rpcErr(r.id, -32601, `method not found: ${String(r.method)}`);
  }
}

/** POST /mcp — one JSON-RPC message per request, stateless. */
export async function handleMcp(
  store: UiStore,
  token: string,
  reqIn: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  if ((reqIn.method ?? "GET") !== "POST") {
    json(res, 405, rpcErr(null, -32600, "use POST"));
    return;
  }
  if (!isAuthorized(reqIn, token)) {
    json(res, 401, rpcErr(null, -32001, "unauthorized: send the console token as a Bearer header"));
    return;
  }

  let parsed: unknown;
  try {
    parsed = await readJsonBody(reqIn);
  } catch (err) {
    json(res, 400, rpcErr(null, -32700, `parse error: ${(err as Error).message}`));
    return;
  }

  // Batch: an array of requests gets an array of responses.
  if (Array.isArray(parsed)) {
    const out: Record<string, unknown>[] = [];
    for (const one of parsed) {
      const reply = await dispatch(store, one as RpcRequest);
      if (reply) out.push(reply);
    }
    json(res, 200, out);
    return;
  }

  const reply = await dispatch(store, parsed as RpcRequest);
  if (reply === null) {
    // A notification still needs a transport-level acknowledgement.
    res.writeHead(202, { "Content-Type": "application/json", "Content-Length": 0 });
    res.end();
    return;
  }
  json(res, 200, reply);
}
