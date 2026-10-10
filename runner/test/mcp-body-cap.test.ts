/**
 * McpClient body cap (audit 2026-10-09, security #16).
 *
 * post() used to `await res.text()` — a hostile or broken upstream could
 * stream unboundedly and OOM the runner. The body is now capped WHILE
 * reading: past the cap the stream is cancelled and the call throws a
 * clear error (never a truncated fake "success"). Error-envelope
 * semantics from T10 are unchanged — only the read strategy moved.
 * Loopback fake servers only; no real SecScan traffic.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { McpClient } from "../src/mcp.js";

function rpcServer(
  toolsCall: (res: ServerResponse) => void,
  timeoutMs?: number,
): Promise<{ client: McpClient; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    res.on("error", () => {}); // client may abort mid-stream (cap/timeout)
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
        client: new McpClient({
          endpoint: `http://127.0.0.1:${port}/mcp`,
          token: "test-token",
          ...(timeoutMs !== undefined ? { timeoutMs } : {}),
        }),
        close: () =>
          new Promise<void>((r) => {
            server.closeAllConnections();
            server.close(() => r());
          }),
      });
    });
  });
}

const resultWithText = (text: string) =>
  JSON.stringify({ jsonrpc: "2.0", id: "tool-x", result: { content: [{ type: "text", text }] } });

describe("McpClient — response body capped while reading", () => {
  it("a normal (sub-cap) result returns intact", async () => {
    const text = "F".repeat(100 * 1024);
    const { client, close } = await rpcServer((res) => {
      res.setHeader("content-type", "application/json");
      res.end(resultWithText(text));
    });
    try {
      assert.equal(await client.callTool("get_report"), text);
    } finally {
      await close();
    }
  });

  it("an over-cap result throws the cap error — never a truncated success", async () => {
    const overCap = "x".repeat(9 * 1024 * 1024); // cap is 8 MiB
    const { client, close } = await rpcServer((res) => {
      res.setHeader("content-type", "application/json");
      res.end(resultWithText(overCap));
    });
    try {
      await assert.rejects(client.callTool("get_report"), /\[mcp\] response body exceeded 8388608 bytes/);
    } finally {
      await close();
    }
  });

  it("an endless drip is cut by the client timeout, not buffered forever", async () => {
    const { client, close } = await rpcServer(
      (res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.write('{"jsonrpc":"2.0","id":"tool-x","result":{"content":[{"type":"text","text":"');
        const drip = setInterval(() => res.write("x"), 50);
        drip.unref();
        res.on("close", () => clearInterval(drip));
      },
      300,
    );
    try {
      const started = Date.now();
      await assert.rejects(client.callTool("get_report"), /abort/i);
      assert.ok(Date.now() - started < 3_000, "client timeout must cut the drip");
    } finally {
      await close();
    }
  });

  it("a JSON-RPC error envelope still throws the server's error (cap read is transparent)", async () => {
    const { client, close } = await rpcServer((res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: "tool-x", error: { code: -32000, message: "backend down" } }));
    });
    try {
      await assert.rejects(client.callTool("get_report"), /JSON-RPC error -32000: backend down/);
    } finally {
      await close();
    }
  });
});
