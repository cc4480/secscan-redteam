/**
 * Harness-plugin hook tests (audit batch 3 — the in-harness
 * `tools/pre-execute` hook was completely untested; wiring drift would
 * defeat the ownership gate in the real runtime while the standalone
 * auth-gate package tests stay green).
 *
 * What is pinned here is the PLUGIN layer (installAuthGate + apply):
 * hook registration, env wiring (SECSCAN_MCP_TOKEN / SECSCAN_MCP_URL /
 * SECSCAN_VERIFIED_DOMAINS), allow→next() passthrough identity, and
 * deny-without-next — with the decision ladder itself (passive → allow,
 * allowlisted → allow, server-verified → allow, everything else → deny)
 * exercised end-to-end against a fake MCP server on 127.0.0.1.
 * The standalone auth-gate package's decide() unit matrix lives in
 * auth-gate/test/verify.test.ts; this suite deliberately does not
 * duplicate it.
 */
import { after, afterEach, before, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { installAuthGate } from "../src/auth-gate.js";
import { apply, inject, name, plugin } from "../src/index.js";
import type { Context, PreToolDecision, ToolExecution } from "../src/harness-types.js";

type HookHandler = (exec: ToolExecution, next: () => Promise<PreToolDecision>) => Promise<PreToolDecision>;

const ALLOW_SENTINEL = { kind: "allow" } as const;

class FakeHarness {
  handlers = new Map<string, HookHandler>();
  sections: Array<{ name: string; order: number; text: string }> = [];
  ctx: Context;

  constructor() {
    this.ctx = {
      on: (event: string, handler: HookHandler) => {
        this.handlers.set(event, handler);
      },
      systemPrompt: {
        section: (s: { name: string; order: number; text: string }) => {
          this.sections.push(s);
        },
      },
    } as unknown as Context;
  }

  /** Invoke the registered pre-execute hook the way the harness would. */
  async run(toolName: string, args?: Record<string, unknown>): Promise<{ decision: PreToolDecision; nextCalls: number }> {
    const handler = this.handlers.get("tools/pre-execute");
    assert.ok(handler, "pre-execute hook must be registered");
    let nextCalls = 0;
    const next = async (): Promise<PreToolDecision> => {
      nextCalls++;
      return ALLOW_SENTINEL;
    };
    const exec = { name: toolName, arguments: args } as unknown as ToolExecution;
    const decision = await handler(exec, next);
    return { decision, nextCalls };
  }
}

// ---------------------------------------------------------------------------
// Env plumbing: gateContext() reads env at install time, so each test
// installs fresh against its own env. Snapshot/restore around every test.
// ---------------------------------------------------------------------------

const ENV_KEYS = ["SECSCAN_MCP_TOKEN", "SECSCAN_MCP_URL", "SECSCAN_VERIFIED_DOMAINS"] as const;
let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = {};
  for (const k of ENV_KEYS) {
    savedEnv[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

function install(env: Partial<Record<(typeof ENV_KEYS)[number], string>> = {}): FakeHarness {
  for (const [k, v] of Object.entries(env)) {
    if (v !== undefined) process.env[k] = v;
  }
  const harness = new FakeHarness();
  installAuthGate(harness.ctx);
  return harness;
}

// ---------------------------------------------------------------------------
// Fake SecScan MCP server (loopback only) for the server-verified rung.
// ---------------------------------------------------------------------------

let server: Server;
let baseUrl: string;
let verifiedDomains: string[] = [];
let failToolsCall = false;
let garbageToolsCall = false;
let requestCount = 0;
let lastAuthHeader: string | undefined;
let lastCallToken: string | undefined;

before(async () => {
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      requestCount++;
      lastAuthHeader = req.headers["authorization"];
      let msg: { method?: string; id?: unknown; params?: { name?: string } } = {};
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
            result: { protocolVersion: "2025-03-26", serverInfo: { name: "secscan-fake", version: "0" } },
          }),
        );
      } else if (msg.method === "notifications/initialized") {
        res.writeHead(202).end();
      } else if (msg.method === "tools/call") {
        lastCallToken = msg.params?.name;
        if (msg.params?.name !== "list_verified_domains") {
          res.writeHead(400).end();
          return;
        }
        if (failToolsCall) {
          res.writeHead(500).end("boom");
          return;
        }
        if (garbageToolsCall) {
          res.writeHead(200, { "content-type": "text/plain" }).end("this is not json");
          return;
        }
        res.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: msg.id,
            result: { content: [{ type: "text", text: JSON.stringify({ domains: verifiedDomains }) }] },
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
  baseUrl = `http://127.0.0.1:${addr.port}/mcp`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
});

beforeEach(() => {
  verifiedDomains = [];
  failToolsCall = false;
  garbageToolsCall = false;
  requestCount = 0;
  lastAuthHeader = undefined;
  lastCallToken = undefined;
});

function serverEnv(): Record<string, string> {
  return { SECSCAN_MCP_TOKEN: "test-token-abc", SECSCAN_MCP_URL: baseUrl };
}

const ACTIVE = { url: "https://victim.example", aggressive: true };

// ---------------------------------------------------------------------------

describe("installAuthGate — wiring", () => {
  it("registers exactly one tools/pre-execute handler", () => {
    const h = install();
    assert.deepEqual([...h.handlers.keys()], ["tools/pre-execute"]);
  });

  it("apply() installs the gate AND the red-team prompt section", () => {
    const h = new FakeHarness();
    apply(h.ctx);
    assert.ok(h.handlers.has("tools/pre-execute"));
    assert.equal(h.sections.length, 1);
    assert.equal(h.sections[0]!.name, "secscan-redteam");
    assert.equal(h.sections[0]!.order, 117);
    assert.match(h.sections[0]!.text, /HARD RULE: active testing/);
    assert.match(h.sections[0]!.text, /do not attempt to bypass/);
  });

  it("plugin module exports the load contract", () => {
    assert.equal(name, "secscan-redteam");
    assert.deepEqual(inject, ["tools", "systemPrompt"]);
    assert.equal(plugin.name, "secscan-redteam");
    assert.equal(plugin.apply, apply);
  });
});

describe("installAuthGate — benign traffic passes (allow → next(), identity passthrough)", () => {
  it("non-scan tools pass through untouched, namespaced or not", async () => {
    const h = install();
    for (const toolName of ["get_report", "mcp__secscan__get_scan_status", "mcp__secscan__list_verified_domains", "totally_unrelated"]) {
      const { decision, nextCalls } = await h.run(toolName, { anything: true });
      assert.equal(nextCalls, 1, toolName);
      assert.equal(decision, ALLOW_SENTINEL, `${toolName} must return next()'s decision verbatim`);
    }
  });

  it("passive scans pass through with no token, no allowlist, no server call", async () => {
    const h = install(serverEnv());
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", { url: "https://example.com" });
    assert.equal(nextCalls, 1);
    assert.equal(decision, ALLOW_SENTINEL);
    assert.equal(requestCount, 0, "passive scans must never consult the server");
  });

  it("scan calls with arguments omitted entirely pass through (no crash)", async () => {
    const h = install();
    const { nextCalls } = await h.run("mcp__secscan__scan_url", undefined);
    assert.equal(nextCalls, 1);
  });

  it("explicitly non-active scans are passive", async () => {
    const h = install();
    for (const args of [
      { url: "https://example.com", aggressive: false },
      { url: "https://example.com", mode: "passive" },
      { url: "https://example.com", tier: "standard" },
    ]) {
      const { nextCalls } = await h.run("scan_url", args);
      assert.equal(nextCalls, 1, JSON.stringify(args));
    }
  });
});

describe("installAuthGate — active-test shapes are caught (deny, next never called)", () => {
  it("aggressive:true against an unverifiable target is denied with remediation", async () => {
    const h = install();
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", ACTIVE);
    assert.equal(nextCalls, 0, "a denied call must never reach next()");
    assert.equal(decision.kind, "deny");
    const reason = (decision as { reason: string }).reason;
    assert.match(reason, /ACTIVE TESTING DENIED for victim\.example/);
    assert.match(reason, /_secscan-challenge\.victim\.example/); // DNS-TXT remediation
    assert.match(reason, /cannot be overridden in-chat/);
  });

  it("active shapes are caught in every documented spelling (regex backstop)", async () => {
    const h = install();
    const shapes: Array<Record<string, unknown>> = [
      { url: "https://victim.example", aggressive: 1 },
      { url: "https://victim.example", mode: "aggressive" },
      { url: "https://victim.example", mode: "ACTIVE" },
      { url: "https://victim.example", mode: "aggressive-scan" },
      { url: "https://victim.example", tier: "intrusive" },
      { url: "https://victim.example", note: "active" }, // value-position backstop
      { target: "https://victim.example", intrusive: "yes" },
      { site_url: "https://victim.example", activeTesting: 1 },
    ];
    for (const args of shapes) {
      const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", args);
      assert.equal(nextCalls, 0, JSON.stringify(args));
      assert.equal(decision.kind, "deny", JSON.stringify(args));
    }
  });

  it("active + garbage or missing URL is denied (fail closed on garbage)", async () => {
    const h = install(serverEnv()); // even a healthy server can't save an unparseable target
    verifiedDomains = ["victim.example"];
    for (const args of [
      { aggressive: true, url: "%%%bad" },
      { aggressive: true },
      { aggressive: true, url: "" },
      { aggressive: true, url: 42 },
    ]) {
      const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", args);
      assert.equal(nextCalls, 0, JSON.stringify(args));
      assert.equal(decision.kind, "deny", JSON.stringify(args));
      assert.match((decision as { reason: string }).reason, /no parseable target URL/);
    }
  });
});

describe("installAuthGate — the graduated ladder (allowlist → server → deny)", () => {
  it("allowlisted domain is allowed WITHOUT any server token (secondary path), case/space tolerant", async () => {
    const h = install({ SECSCAN_VERIFIED_DOMAINS: " Victim.Example , other.example " });
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", { url: "https://VICTIM.example/path", aggressive: true });
    assert.equal(nextCalls, 1);
    assert.equal(decision, ALLOW_SENTINEL);
  });

  it("a domain NOT in the allowlist still denies when no token is configured", async () => {
    const h = install({ SECSCAN_VERIFIED_DOMAINS: "other.example" });
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", ACTIVE);
    assert.equal(nextCalls, 0);
    assert.equal(decision.kind, "deny");
  });

  it("server-verified domain is allowed via the server (primary path); the token is sent as Bearer", async () => {
    verifiedDomains = ["SecScan.US"];
    const h = install(serverEnv());
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", {
      url: "https://secscan.us/login",
      aggressive: true,
    });
    assert.equal(nextCalls, 1);
    assert.equal(decision, ALLOW_SENTINEL);
    assert.equal(lastAuthHeader, "Bearer test-token-abc");
    assert.equal(lastCallToken, "list_verified_domains");
  });

  it("server says unverified → deny", async () => {
    verifiedDomains = ["someone-else.example"];
    const h = install(serverEnv());
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", ACTIVE);
    assert.equal(nextCalls, 0);
    assert.equal(decision.kind, "deny");
  });

  it("no token → the server is never consulted (no unauthenticated check, no approval)", async () => {
    const h = install({ SECSCAN_MCP_URL: baseUrl }); // URL set, token absent
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", ACTIVE);
    assert.equal(nextCalls, 0);
    assert.equal(decision.kind, "deny");
    assert.equal(requestCount, 0);
  });
});

describe("installAuthGate — fail closed when the server misbehaves", () => {
  it("server 500 on the tools/call → deny", async () => {
    failToolsCall = true;
    verifiedDomains = ["victim.example"];
    const h = install(serverEnv());
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", ACTIVE);
    assert.equal(nextCalls, 0);
    assert.equal(decision.kind, "deny");
  });

  it("server returns a non-JSON body → deny", async () => {
    garbageToolsCall = true;
    const h = install(serverEnv());
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", ACTIVE);
    assert.equal(nextCalls, 0);
    assert.equal(decision.kind, "deny");
  });

  it("server unreachable (connection refused) → deny, promptly", async () => {
    // A guaranteed-closed loopback port: bind one, then release it.
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
    const addr = probe.address();
    assert.ok(addr && typeof addr === "object");
    const deadPort = addr.port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const h = install({
      SECSCAN_MCP_TOKEN: "test-token-abc",
      SECSCAN_MCP_URL: `http://127.0.0.1:${deadPort}/mcp`,
    });
    const { decision, nextCalls } = await h.run("mcp__secscan__scan_url", ACTIVE);
    assert.equal(nextCalls, 0);
    assert.equal(decision.kind, "deny");
  });
});
