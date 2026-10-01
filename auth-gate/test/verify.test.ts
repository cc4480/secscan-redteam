/**
 * Unit tests for the auth gate. The gate is server-authoritative: it never
 * issues tokens and performs no DNS of its own. Pure logic is tested
 * directly; the MCP handshake in server.ts is tested against a local mock
 * MCP server (127.0.0.1 — no external network). Every failure path must
 * resolve to "unverified"/"deny", never to approval.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import {
  decide,
  extractDomain,
  fetchVerifiedDomains,
  isServerVerified,
  parseVerifiedDomains,
  type GateContext,
} from "../src/index.js";

function ctxWith(
  serverVerdict: boolean | "throw",
  allowlisted: string[] = [],
): GateContext {
  return {
    allowlistedDomains: new Set(allowlisted),
    isServerVerified: async () => {
      if (serverVerdict === "throw") throw new Error("simulated checker failure");
      return serverVerdict;
    },
  };
}

describe("extractDomain", () => {
  it("normalizes URLs and bare domains", () => {
    assert.equal(extractDomain("https://Example.COM/path?q=1"), "example.com");
    assert.equal(extractDomain("example.com"), "example.com");
    assert.equal(extractDomain("http://sub.example.com:8080/x"), "sub.example.com");
  });
  it("throws on garbage", () => {
    assert.throws(() => extractDomain("not a url at all %%%"));
  });
});

describe("parseVerifiedDomains", () => {
  it("parses an MCP content-block JSON array", () => {
    const payload = {
      content: [{ type: "text", text: JSON.stringify(["secscan.us", "example.com"]) }],
    };
    assert.deepEqual(parseVerifiedDomains(payload), ["secscan.us", "example.com"]);
  });
  it("handles object shapes, lowercases and dedupes", () => {
    const payload = {
      jsonrpc: "2.0",
      result: { domains: ["SecScan.US", "secscan.us", "https://Example.COM/a"] },
    };
    assert.deepEqual(parseVerifiedDomains(payload), ["secscan.us", "example.com"]);
  });
  it("returns [] for garbage (fail closed)", () => {
    assert.deepEqual(parseVerifiedDomains(null), []);
    assert.deepEqual(parseVerifiedDomains({ nonsense: 42 }), []);
    assert.deepEqual(parseVerifiedDomains({ content: [{ type: "text", text: "not json {" }] }), []);
  });
});

describe("decide (pre-execute gate)", () => {
  it("allows read-only and verification-workflow tools unconditionally", async () => {
    const ctx = ctxWith(false);
    for (const toolName of [
      "list_recent_scans",
      "mcp__secscan__get_report",
      "get_scan_status",
      "get_account",
      "list_verified_domains",
      "start_domain_verification",
      "check_domain_verification",
    ]) {
      assert.deepEqual(await decide({ toolName, arguments: {} }, ctx), { kind: "allow" }, toolName);
    }
  });
  it("allows passive scans without ownership proof", async () => {
    const d = await decide(
      { toolName: "scan_url", arguments: { url: "https://example.com" } },
      ctxWith(false),
    );
    assert.deepEqual(d, { kind: "allow" });
  });
  it("denies aggressive scans when the server says unverified", async () => {
    const d = await decide(
      {
        toolName: "mcp__secscan__scan_url",
        arguments: { url: "https://example.com", aggressive: true },
      },
      ctxWith(false),
    );
    assert.equal(d.kind, "deny");
    const reason = (d as { reason: string }).reason;
    assert.match(reason, /ACTIVE TESTING DENIED/);
    assert.match(reason, /_secscan-challenge\.example\.com/);
    assert.match(reason, /start_domain_verification/);
  });
  it("denies when the server check itself throws (fail closed)", async () => {
    const d = await decide(
      { toolName: "scan_url", arguments: { url: "https://example.com", mode: "aggressive" } },
      ctxWith("throw"),
    );
    assert.equal(d.kind, "deny");
  });
  it("allows aggressive scans for server-verified domains", async () => {
    const d = await decide(
      { toolName: "scan_url", arguments: { url: "https://example.com", aggressive: true } },
      ctxWith(true),
    );
    assert.deepEqual(d, { kind: "allow" });
  });
  it("allows aggressive scans for allowlisted domains even when the server says no", async () => {
    const d = await decide(
      { toolName: "scan_url", arguments: { url: "https://example.com", aggressive: true } },
      ctxWith(false, ["example.com"]),
    );
    assert.deepEqual(d, { kind: "allow" });
  });
  it("denies aggressive scans on malformed URLs", async () => {
    const d = await decide(
      { toolName: "scan_url", arguments: { url: "%%%bad", aggressive: true } },
      ctxWith(true),
    );
    assert.equal(d.kind, "deny");
  });
  it("passes through unrelated tools", async () => {
    assert.deepEqual(await decide({ toolName: "some_other_tool", arguments: {} }, ctxWith(false)), {
      kind: "allow",
    });
  });
});

describe("server verification over MCP (local mock server)", () => {
  let server: Server;
  let baseUrl: string;
  let sawAuthHeader = false;
  let failToolsCall = false;

  before(async () => {
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        sawAuthHeader = (req.headers["authorization"] ?? "").startsWith("Bearer ");
        let msg: { method?: string; id?: unknown } = {};
        try {
          msg = JSON.parse(body);
        } catch {
          res.writeHead(400).end();
          return;
        }
        if (msg.method === "initialize") {
          res.writeHead(200, { "content-type": "application/json" }).end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: msg.id,
              result: {
                protocolVersion: "2025-03-26",
                serverInfo: { name: "secscan", version: "1.1.0" },
              },
            }),
          );
        } else if (msg.method === "notifications/initialized") {
          res.writeHead(202).end();
        } else if (msg.method === "tools/call") {
          if (failToolsCall) {
            res.writeHead(500).end("boom");
            return;
          }
          res.writeHead(200, { "content-type": "application/json" }).end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: msg.id,
              result: {
                content: [
                  { type: "text", text: JSON.stringify({ domains: ["SecScan.US"] }) },
                ],
              },
            }),
          );
        } else {
          res.writeHead(400).end();
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    baseUrl = `http://127.0.0.1:${(addr as { port: number }).port}/mcp`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((e) => (e ? reject(e) : resolve())),
    );
  });

  it("completes the handshake and returns the domain list", async () => {
    const list = await fetchVerifiedDomains({ endpoint: baseUrl, token: "test-token" });
    assert.deepEqual(list, ["secscan.us"]);
    assert.equal(sawAuthHeader, true);
  });
  it("isServerVerified matches listed domains case-insensitively", async () => {
    assert.equal(await isServerVerified("secscan.us", { endpoint: baseUrl, token: "t" }), true);
    assert.equal(await isServerVerified("SEcScAn.Us", { endpoint: baseUrl, token: "t" }), true);
    assert.equal(await isServerVerified("other.com", { endpoint: baseUrl, token: "t" }), false);
  });
  it("fails closed when the server errors", async () => {
    failToolsCall = true;
    try {
      await assert.rejects(fetchVerifiedDomains({ endpoint: baseUrl, token: "t" }));
      assert.equal(await isServerVerified("secscan.us", { endpoint: baseUrl, token: "t" }), false);
    } finally {
      failToolsCall = false;
    }
  });
  it("fails closed with no token", async () => {
    assert.equal(await isServerVerified("secscan.us", { endpoint: baseUrl, token: "" }), false);
  });
});
