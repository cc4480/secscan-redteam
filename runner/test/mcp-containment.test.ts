/**
 * T10 regressions — MCP error containment (audit correctness M2 + M3).
 *
 *  - Dispatch: one flaky SecScan MCP call degrades to a per-call error
 *    RESULT the agent can route around — it never throws out of the
 *    handler (which used to halt the whole engagement) and never comes
 *    back as an empty "success" ("scan done, nothing found").
 *  - Client: JSON-RPC error envelopes, SSE progress notifications, and
 *    other content-less shapes must throw a clear error — never collapse
 *    into "" the caller mistakes for a legitimately empty result.
 *
 * Fakes only: a stubbed ctx.mcp for dispatch, a loopback HTTP server
 * speaking canned JSON-RPC for the client. No real SecScan traffic.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { McpClient } from "../src/mcp.js";
import { handleMcpTools } from "../src/dispatch/mcp.js";
import type { Ctx } from "../src/context.js";
import type { ActorRole, EngagementPhase } from "../src/types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";

const call = (name: string) => ({ name }) as unknown as ToolCallRequest;

function fakeCtx(mcp: unknown): Ctx {
  return { hosts: ["target.example"], domain: "target.example", mcp } as unknown as Ctx;
}

describe("handleMcpTools — one flaky MCP call never halts the engagement", () => {
  it("scan_url failure becomes a per-call error result (no throw, no empty success)", async () => {
    const ctx = fakeCtx({
      scanUrl: async () => {
        throw new Error("[mcp] HTTP 500: upstream exploded");
      },
    });
    const res = await handleMcpTools(ctx, "recon" as ActorRole, "recon" as EngagementPhase, call("scan_url"), {
      url: "https://target.example/x",
    });
    assert.ok(res, "handler must answer, not fall through");
    assert.equal(res!.target, "https://target.example/x");
    assert.match(res!.result, /SecScan MCP error: scan_url failed/);
    assert.match(res!.result, /HTTP 500/);
    assert.notEqual(res!.result, "", "an error must never read as an empty successful scan");
    assert.match(res!.result, /missing data/);
  });

  it("read-only tool failure becomes a per-call error result with the scan id preserved", async () => {
    const ctx = fakeCtx({
      callTool: async () => {
        throw new Error("[mcp] get_report: JSON-RPC error -32000: backend down");
      },
    });
    const res = await handleMcpTools(ctx, "recon" as ActorRole, "recon" as EngagementPhase, call("get_report"), {
      scan_id: "S-1",
    });
    assert.ok(res);
    assert.equal(res!.target, "S-1");
    assert.match(res!.result, /SecScan MCP error: get_report failed/);
    assert.match(res!.result, /JSON-RPC error -32000/);
  });

  it("the handler keeps working after a failure (engagement continues)", async () => {
    let attempts = 0;
    const ctx = fakeCtx({
      scanUrl: async () => {
        attempts++;
        if (attempts === 1) throw new Error("[mcp] HTTP 503: try again");
        return "scan: 2 findings";
      },
    });
    const first = await handleMcpTools(ctx, "recon" as ActorRole, "recon" as EngagementPhase, call("scan_url"), {
      url: "https://target.example/x",
    });
    assert.match(first!.result, /SecScan MCP error: scan_url failed/);
    const second = await handleMcpTools(ctx, "recon" as ActorRole, "recon" as EngagementPhase, call("scan_url"), {
      url: "https://target.example/x",
    });
    assert.equal(second!.result, "scan: 2 findings", "a later success is returned untouched");
  });
});

describe("McpClient — error shapes throw; they never collapse into empty success", () => {
  type Responder = (res: ServerResponse) => void;

  function rpcServer(toolsCall: Responder): Promise<{ client: McpClient; close: () => Promise<void> }> {
    const server = createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => {
        let body: { method?: string; id?: unknown } | null = null;
        try {
          body = JSON.parse(data) as { method?: string; id?: unknown };
        } catch {
          body = null;
        }
        if (body?.method === "tools/call") return toolsCall(res);
        if (typeof body?.method === "string" && body.method.startsWith("notifications/")) {
          res.end();
          return;
        }
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ jsonrpc: "2.0", id: body?.id ?? null, result: { protocolVersion: "2025-03-26", capabilities: {} } }));
      });
    });
    return new Promise((resolveListen) => {
      server.listen(0, "127.0.0.1", () => {
        const port = (server.address() as AddressInfo).port;
        resolveListen({
          client: new McpClient({ endpoint: `http://127.0.0.1:${port}/mcp`, token: "test-token" }),
          close: () =>
            new Promise<void>((r) => {
              server.closeAllConnections();
              server.close(() => r());
            }),
        });
      });
    });
  }

  it("JSON-RPC error envelope rejects with the server's code and message", async () => {
    const { client, close } = await rpcServer((res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: "tool-scan_url", error: { code: -32000, message: "scan backend exploded" } }));
    });
    try {
      await assert.rejects(client.callTool("scan_url", { url: "https://target.example" }), /JSON-RPC error -32000: scan backend exploded/);
    } finally {
      await close();
    }
  });

  it("SSE progress notification as the final frame rejects instead of returning ''", async () => {
    const { client, close } = await rpcServer((res) => {
      res.setHeader("content-type", "text/event-stream");
      res.end('event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":0.5,"total":1}}\n\n');
    });
    try {
      await assert.rejects(client.callTool("scan_url", { url: "https://target.example" }), /malformed result \(no content array\)/);
    } finally {
      await close();
    }
  });

  it("isError tool result rejects with the tool's own text", async () => {
    const { client, close } = await rpcServer((res) => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({ jsonrpc: "2.0", id: "tool-scan_url", result: { isError: true, content: [{ type: "text", text: "tool blew up" }] } }),
      );
    });
    try {
      await assert.rejects(client.callTool("scan_url", { url: "https://target.example" }), /isError: tool blew up/);
    } finally {
      await close();
    }
  });

  it("HTTP 500 rejects (pre-existing behavior, regression-guarded)", async () => {
    const { client, close } = await rpcServer((res) => {
      res.statusCode = 500;
      res.end("server boom");
    });
    try {
      await assert.rejects(client.callTool("scan_url", { url: "https://target.example" }), /HTTP 500/);
    } finally {
      await close();
    }
  });

  it("a valid text result resolves to exactly its text", async () => {
    const { client, close } = await rpcServer((res) => {
      res.setHeader("content-type", "text/event-stream");
      res.end('data: {"jsonrpc":"2.0","id":"tool-scan_url","result":{"content":[{"type":"text","text":"scan: 3 findings"}]}}\n\n');
    });
    try {
      assert.equal(await client.callTool("scan_url", { url: "https://target.example" }), "scan: 3 findings");
    } finally {
      await close();
    }
  });
});
