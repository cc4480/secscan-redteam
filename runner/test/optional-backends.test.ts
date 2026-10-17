/**
 * Optional backend + pairing tests (v0.34.0).
 *
 * These cover the two "not verified headless" ports from the AlterEgo audit —
 * the Windows PC-agent channel and the browser/CDP driver — plus pairing.
 * Because their *transports* cannot be exercised without a real host and a real
 * browser, what is pinned here is the contract: configuration gating, the closed
 * tool allow-list, deterministic request shaping, and fail-closed behaviour.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { PC_AGENT_ALLOWED_TOOLS, createPcAgentClient, pcAgentConfig, pcAgentConfigured } from "../src/host-exec/pc-agent.js";
import { browserConfig, browserConfigured, createCdpDriver } from "../src/browser/cdp.js";
import { PairingManager, pairingEnabled } from "../src/ui/pairing.js";
import { readinessReport } from "../src/tools/readiness.js";

type Captured = { url: string; body: string; headers: Record<string, string> };

/** Fake fetch that records requests, issues a session id on initialize, and replies with SSE. */
function fakeFetch(reply: (body: unknown) => unknown): { fetchImpl: never; calls: Captured[] } {
  const calls: Captured[] = [];
  const fetchImpl = async (url: string, init: { method: string; headers: Record<string, string>; body: string }) => {
    calls.push({ url, body: init.body, headers: init.headers });
    const request = JSON.parse(init.body) as { method?: string };
    const parsed = reply(request);
    // Streamable HTTP: the server issues a session id on initialize and requires it after.
    const sessionId = request.method === "initialize" ? "sid-smoke" : null;
    return {
      ok: true,
      status: request.method === "notifications/initialized" ? 202 : 200,
      headers: { get: (name: string) => (name.toLowerCase() === "mcp-session-id" ? sessionId : null) },
      text: async () => (parsed === undefined ? "" : `event: message\ndata: ${JSON.stringify(parsed)}\n`),
    };
  };
  return { fetchImpl: fetchImpl as never, calls };
}

describe("PC-agent backend contract", () => {
  it("requires both url and a non-trivial token", () => {
    assert.equal(pcAgentConfigured({} as NodeJS.ProcessEnv), false);
    assert.equal(pcAgentConfig({ REDTEAM_PC_AGENT_URL: "http://127.0.0.1:8765", REDTEAM_PC_AGENT_TOKEN: "short" } as NodeJS.ProcessEnv), undefined);
    const cfg = pcAgentConfig({ REDTEAM_PC_AGENT_URL: "https://pc.example/mcp", REDTEAM_PC_AGENT_TOKEN: "0123456789abcdef0123" } as NodeJS.ProcessEnv);
    assert.equal(cfg?.url, "https://pc.example/mcp");
  });

  it("handshakes then calls the allow-listed tool with a bearer token", async () => {
    const { fetchImpl, calls } = fakeFetch((body) => {
      const b = body as { id?: number; method?: string };
      if (b.method === "initialize") return { jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-03-26" } };
      return { jsonrpc: "2.0", id: 2, result: { content: [{ type: "text", text: "ok" }] } };
    });
    const client = createPcAgentClient({ url: "http://127.0.0.1:8765/mcp", token: "0123456789abcdef0123" }, fetchImpl);
    const out = await client.call("shell_exec", { cmd: "whoami" });
    assert.equal(out, "ok", "the content text is returned, not the raw JSON-RPC envelope");
    assert.equal(calls.length, 3, "initialize + initialized + tools/call");
    assert.equal(calls[0]!.headers["authorization"], "Bearer 0123456789abcdef0123");
    assert.ok(calls[2]!.body.includes("shell_exec"));
    assert.ok(calls[2]!.body.includes("whoami"));
    // The session id issued by initialize must be echoed on every later request.
    assert.equal(calls[1]!.headers["mcp-session-id"], "sid-smoke");
    assert.equal(calls[2]!.headers["mcp-session-id"], "sid-smoke");
  });

  it("refuses any tool outside the closed allow-list", async () => {
    const { fetchImpl } = fakeFetch(() => ({ jsonrpc: "2.0", id: 2, result: {} }));
    const client = createPcAgentClient({ url: "http://127.0.0.1:8765/mcp", token: "0123456789abcdef0123" }, fetchImpl);
    await assert.rejects(() => client.call("delete_file" as never, {}), /not on the allow-list/);
    assert.ok(!(PC_AGENT_ALLOWED_TOOLS as readonly string[]).includes("delete_file"));
  });
});

describe("browser/CDP driver contract", () => {
  it("configuration gating", () => {
    assert.equal(browserConfigured({} as NodeJS.ProcessEnv), false);
    assert.equal(browserConfig({ REDTEAM_BROWSER_CDP_URL: "not-a-url" } as NodeJS.ProcessEnv), undefined);
    assert.equal(browserConfigured({ REDTEAM_BROWSER_CDP_URL: "http://127.0.0.1:9222" } as NodeJS.ProcessEnv), true);
  });

  it("snapshot parses the page state from the injected transport", async () => {
    const driver = createCdpDriver({
      send: async (method) => {
        if (method !== "Runtime.evaluate") return {};
        return { result: { value: JSON.stringify({ url: "https://t/", title: "T", text: "hello" }) } };
      },
    });
    assert.deepEqual(await driver.snapshot(), { url: "https://t/", title: "T", text: "hello" });
  });

  it("navigate refuses non-http(s) URLs", async () => {
    const driver = createCdpDriver({ send: async () => ({}) });
    await assert.rejects(() => driver.navigate("file:///etc/passwd"), /only http\(s\)/);
  });

  it("fillField throws when no field matches", async () => {
    const driver = createCdpDriver({ send: async () => ({ result: { value: "not-found" } }) });
    await assert.rejects(() => driver.fillField("email", "a@b.c"), /no field matched/);
  });
});

describe("operator pairing", () => {
  it("is opt-in only", () => {
    assert.equal(pairingEnabled({} as NodeJS.ProcessEnv), false);
    assert.equal(pairingEnabled({ REDTEAM_PAIRING: "1" } as NodeJS.ProcessEnv), true);
  });

  it("mints 6-digit codes, single-use, and locks after 5 wrong guesses", () => {
    const pm = new PairingManager({ mintToken: () => "TOKEN" });
    const code = pm.newCode();
    assert.match(code, /^\d{6}$/);
    const ok = pm.exchange(code);
    assert.equal(ok.ok, true);
    assert.equal(ok.token, "TOKEN");
    assert.equal(pm.exchange(code).ok, false, "single use");

    const pm2 = new PairingManager();
    pm2.newCode();
    for (let i = 0; i < 5; i += 1) pm2.exchange("000000");
    assert.equal(pm2.isLocked(), true);
    pm2.rearm();
    assert.equal(pm2.isLocked(), false);
  });

  it("expires and can be refreshed", () => {
    let now = 1_000_000;
    const pm = new PairingManager({ now: () => now });
    const code = pm.newCode();
    now += 31 * 60 * 1000;
    assert.equal(pm.needsRefresh(), true);
    assert.equal(pm.exchange(code).ok, false);
  });
});

describe("readiness includes the optional backends", () => {
  it("lists pc_agent and browser as optional, never required", async () => {
    const report = await readinessReport({ REDTEAM_NMAP_BIN: "/no/such/nmap" } as NodeJS.ProcessEnv);
    const ids = report.items.map((i) => i.id);
    assert.ok(ids.includes("pc_agent"));
    assert.ok(ids.includes("browser"));
    assert.equal(report.items.find((i) => i.id === "pc_agent")?.required, false);
    assert.equal(report.items.find((i) => i.id === "browser")?.required, false);
  });
});
