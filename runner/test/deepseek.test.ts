/**
 * DeepSeek provider behavior tests (audit T11).
 *
 * DeepSeek is the ONLY provider routed for every role (v0.6 policy), yet it
 * had zero behavior tests. These pin, with a stubbed fetch that captures the
 * exact request body:
 *  - registration / configured state / missing-key failure (fails before any
 *    network call),
 *  - single-turn request shape and response parsing (text, reasoning, usage),
 *  - tools serialization and tool-call response parsing,
 *  - THE multi-turn tool-call round trip: an assistant turn's tool_calls must
 *    be sent back on the next turn — the wire conversion previously dropped
 *    them, so every `tool` result referenced a call the API never saw and
 *    OpenAI-compatible endpoints 400 at turn 2,
 *  - HTTP-error surfacing (status + provider text, never the key),
 *  - the RunOptions key bridge in resolveConfig: an explicitly-passed
 *    DeepSeek key reaches the env-only provider (opts wins, env fallback,
 *    absence fails loud at config time, not mid-engagement).
 *
 * Fake fetch only — no network, keys are obviously-fake literals.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  DeepSeekProvider,
  DEEPSEEK_API_KEY_ENV,
  DEEPSEEK_BASE_URL,
  complete,
  listProviders,
  type ChatMessage,
  type ToolCallRequest,
} from "@secscan/redteam-llm-router";
import { resolveConfig } from "../src/phases/config.js";

const FAKE_KEY = "fake-deepseek-key-not-real";
const FAKE_OPTS_KEY = "fake-opts-key-not-real";
const FAKE_ENV_KEY = "fake-env-key-not-real";
const FAKE_MCP_TOKEN = "fake-mcp-token-not-real";

const realFetch = globalThis.fetch;
const REAL_KEY = process.env[DEEPSEEK_API_KEY_ENV];

function stubFetch(handler: (url: string, init: Record<string, unknown>) => Promise<Response>) {
  (globalThis as Record<string, unknown>)["fetch"] = (async (url: string, init: Record<string, unknown>) =>
    handler(url, init)) as typeof fetch;
}

function okResponse(payload: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  } as Response;
}

function errResponse(status: number, payload: unknown): Response {
  return {
    ok: false,
    status,
    json: async () => payload,
    text: async () => (typeof payload === "string" ? payload : JSON.stringify(payload)),
  } as Response;
}

interface SentCall {
  url: string;
  init: Record<string, unknown>;
  body: Record<string, unknown>;
}

function installStub(handler: (n: number) => Promise<Response>): SentCall[] {
  const sent: SentCall[] = [];
  stubFetch(async (url, init) => {
    sent.push({ url, init, body: JSON.parse(init["body"] as string) as Record<string, unknown> });
    return handler(sent.length);
  });
  return sent;
}

function restoreKeyEnv(): void {
  if (REAL_KEY === undefined) delete process.env[DEEPSEEK_API_KEY_ENV];
  else process.env[DEEPSEEK_API_KEY_ENV] = REAL_KEY;
}

afterEach(() => {
  globalThis.fetch = realFetch;
  restoreKeyEnv();
});

// ---------------------------------------------------------------------------
// Registration + key handling
// ---------------------------------------------------------------------------

describe("DeepSeek provider: registration and key handling", () => {
  it("is registered and reports configured when the key is present", () => {
    process.env[DEEPSEEK_API_KEY_ENV] = FAKE_KEY;
    const p = listProviders().find((x) => x.id === "deepseek");
    assert.ok(p, "deepseek provider must be registered");
    assert.equal(p.configured, true);
  });

  it("reports unconfigured without a key, and the router refuses before any call", async () => {
    delete process.env[DEEPSEEK_API_KEY_ENV];
    const sent = installStub(async () => okResponse({ choices: [] }));
    assert.equal(new DeepSeekProvider().isConfigured(), false);
    await assert.rejects(
      () => complete("deepseek", { model: "deepseek-flash", messages: [{ role: "user", content: "hi" }] }),
      /not configured/,
    );
    assert.equal(sent.length, 0, "no request may be sent when unconfigured");
  });

  it("complete() without a key throws naming the env var, before fetching", async () => {
    delete process.env[DEEPSEEK_API_KEY_ENV];
    const sent = installStub(async () => okResponse({ choices: [] }));
    await assert.rejects(
      () => new DeepSeekProvider().complete({ model: "deepseek-flash", messages: [{ role: "user", content: "hi" }] }),
      /DEEPSEEK_API_KEY is not set/,
    );
    assert.equal(sent.length, 0, "no request may be sent without a key");
  });
});

// ---------------------------------------------------------------------------
// Request shape / response parsing
// ---------------------------------------------------------------------------

describe("DeepSeek provider: request shape and response parsing", () => {
  beforeEach(() => {
    process.env[DEEPSEEK_API_KEY_ENV] = FAKE_KEY;
  });

  it("single-turn: POSTs the chat-completions body and maps the response", async () => {
    const sent = installStub(async () =>
      okResponse({
        choices: [
          {
            message: { content: "ack", reasoning_content: "weighing options" },
            finish_reason: "stop",
          },
        ],
        usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 },
      }),
    );
    const res = await new DeepSeekProvider().complete({
      model: "deepseek-flash",
      messages: [
        { role: "system", content: "You are the recon agent." },
        { role: "user", content: "Map the surface." },
      ],
    });

    assert.equal(sent.length, 1);
    assert.equal(sent[0]!.url, `${DEEPSEEK_BASE_URL}/chat/completions`);
    const headers = sent[0]!.init["headers"] as Record<string, string>;
    assert.equal(headers["Authorization"], `Bearer ${FAKE_KEY}`);
    assert.equal(headers["Content-Type"], "application/json");
    assert.equal(sent[0]!.body["model"], "deepseek-flash");
    assert.equal(sent[0]!.body["temperature"], 0.2, "default temperature");
    assert.ok(!("max_tokens" in sent[0]!.body), "max_tokens omitted unless requested");
    assert.ok(!("tools" in sent[0]!.body), "tools omitted unless supplied");
    assert.deepEqual(sent[0]!.body["messages"], [
      { role: "system", content: "You are the recon agent." },
      { role: "user", content: "Map the surface." },
    ]);

    assert.equal(res.text, "ack");
    assert.equal(res.reasoning, "weighing options");
    assert.deepEqual(res.toolCalls, []);
    assert.deepEqual(res.usage, { promptTokens: 11, completionTokens: 7, totalTokens: 18 });
    assert.equal(res.provider, "deepseek");
    assert.equal(res.model, "deepseek-flash");
  });

  it("passes max_tokens and temperature through when given", async () => {
    const sent = installStub(async () => okResponse({ choices: [{ message: { content: "x" } }] }));
    await new DeepSeekProvider().complete({
      model: "deepseek-v4-pro",
      messages: [{ role: "user", content: "hi" }],
      maxTokens: 512,
      temperature: 0.7,
    });
    assert.equal(sent[0]!.body["max_tokens"], 512);
    assert.equal(sent[0]!.body["temperature"], 0.7);
  });

  it("serializes tools to the OpenAI function form", async () => {
    const sent = installStub(async () => okResponse({ choices: [{ message: { content: "x" } }] }));
    await new DeepSeekProvider().complete({
      model: "deepseek-flash",
      messages: [{ role: "user", content: "probe it" }],
      tools: [
        {
          name: "http_probe",
          description: "Send one HTTP request",
          parameters: { type: "object", properties: { url: { type: "string" } } },
        },
      ],
    });
    assert.deepEqual(sent[0]!.body["tools"], [
      {
        type: "function",
        function: {
          name: "http_probe",
          description: "Send one HTTP request",
          parameters: { type: "object", properties: { url: { type: "string" } } },
        },
      },
    ]);
  });

  it("parses response tool_calls; bad JSON arguments fall back to _raw; missing id is synthesized", async () => {
    installStub(async () =>
      okResponse({
        choices: [
          {
            message: {
              content: "",
              tool_calls: [
                { id: "call_a", type: "function", function: { name: "http_probe", arguments: '{"method":"GET"}' } },
                { type: "function", function: { name: "scan_url", arguments: "not-json{" } },
              ],
            },
          },
        ],
      }),
    );
    const res = await new DeepSeekProvider().complete({
      model: "deepseek-flash",
      messages: [{ role: "user", content: "go" }],
    });
    assert.deepEqual(res.toolCalls, [
      { id: "call_a", name: "http_probe", arguments: { method: "GET" } },
      { id: "call_1", name: "scan_url", arguments: { _raw: "not-json{" } },
    ]);
  });

  it("surfaces HTTP errors with status + provider text, never the key", async () => {
    installStub(async () =>
      errResponse(400, { error: { message: "invalid messages: tool_call_id not declared", code: "invalid_request" } }),
    );
    await assert.rejects(
      () => new DeepSeekProvider().complete({ model: "deepseek-flash", messages: [{ role: "user", content: "go" }] }),
      (err: Error) => {
        assert.match(err.message, /DeepSeek HTTP 400/);
        assert.match(err.message, /tool_call_id not declared/);
        assert.ok(!err.message.includes(FAKE_KEY), "error must never contain the key");
        return true;
      },
    );
  });

  it("wraps transport failures as a request failure", async () => {
    stubFetch(async () => {
      throw new Error("socket hang up");
    });
    await assert.rejects(
      () => new DeepSeekProvider().complete({ model: "deepseek-flash", messages: [{ role: "user", content: "go" }] }),
      /DeepSeek request failed: socket hang up/,
    );
  });
});

// ---------------------------------------------------------------------------
// The multi-turn tool-call round trip (the T11 regression)
// ---------------------------------------------------------------------------

describe("DeepSeek provider: multi-turn tool-call round trip", () => {
  beforeEach(() => {
    process.env[DEEPSEEK_API_KEY_ENV] = FAKE_KEY;
  });

  it("re-sends assistant tool_calls so tool results reference declared calls", async () => {
    // Turn 1: the model calls http_probe. Turn 2: plain answer.
    const sent = installStub(async (n) =>
      n === 1
        ? okResponse({
            choices: [
              {
                message: {
                  content: "",
                  tool_calls: [
                    {
                      id: "call_42",
                      type: "function",
                      function: {
                        name: "http_probe",
                        arguments: '{"method":"GET","url":"https://target.example/"}',
                      },
                    },
                  ],
                },
              },
            ],
            usage: { prompt_tokens: 20, completion_tokens: 9, total_tokens: 29 },
          })
        : okResponse({ choices: [{ message: { content: "Surface mapped." } }] }),
    );

    const provider = new DeepSeekProvider();
    const tools = [
      {
        name: "http_probe",
        description: "Send one HTTP request",
        parameters: { type: "object", properties: { url: { type: "string" } } },
      },
    ];
    const messages: ChatMessage[] = [
      { role: "system", content: "You are the recon agent." },
      { role: "user", content: "Probe https://target.example/" },
    ];

    const turn1 = await provider.complete({ model: "deepseek-flash", messages, tools });
    assert.deepEqual(turn1.toolCalls, [
      { id: "call_42", name: "http_probe", arguments: { method: "GET", url: "https://target.example/" } },
    ] as ToolCallRequest[]);

    // Next turn's history, as the agent loop must record it: the assistant
    // turn carrying its calls, then the tool result answering one of them.
    messages.push({ role: "assistant", content: "", toolCalls: turn1.toolCalls });
    messages.push({ role: "tool", toolCallId: "call_42", content: "HTTP 200, 12 bytes" });
    const turn2 = await provider.complete({ model: "deepseek-flash", messages, tools });
    assert.equal(turn2.text, "Surface mapped.");

    const wire = sent[1]!.body["messages"] as Array<Record<string, unknown>>;
    // The assistant turn must declare the calls on the wire…
    const assistant = wire.find((m) => m["role"] === "assistant");
    assert.ok(assistant, "assistant turn present in turn-2 body");
    assert.deepEqual(assistant["tool_calls"], [
      {
        id: "call_42",
        type: "function",
        function: {
          name: "http_probe",
          arguments: '{"method":"GET","url":"https://target.example/"}',
        },
      },
    ]);
    // …with arguments as a JSON string that parses back to the same object.
    const calls = assistant["tool_calls"] as Array<{ function: { arguments: string } }>;
    assert.deepEqual(JSON.parse(calls[0]!.function.arguments), {
      method: "GET",
      url: "https://target.example/",
    });
    // Invariant the API enforces: every tool result answers a call declared
    // by an earlier assistant turn.
    const declared = new Set<string>();
    for (const m of wire) {
      if (m["role"] === "assistant" && Array.isArray(m["tool_calls"])) {
        for (const c of m["tool_calls"] as Array<{ id: string }>) declared.add(c.id);
      }
      if (m["role"] === "tool") {
        assert.ok(
          declared.has(m["tool_call_id"] as string),
          `tool result references undeclared call ${String(m["tool_call_id"])}`,
        );
      }
    }
  });

  it("omits tool_calls on plain assistant turns (an empty array would be its own 400)", async () => {
    const sent = installStub(async () => okResponse({ choices: [{ message: { content: "done" } }] }));
    await new DeepSeekProvider().complete({
      model: "deepseek-flash",
      messages: [
        { role: "system", content: "sys" },
        { role: "user", content: "one" },
        { role: "assistant", content: "interim finding" },
        { role: "user", content: "continue" },
      ],
    });
    const wire = sent[0]!.body["messages"] as Array<Record<string, unknown>>;
    assert.deepEqual(
      wire.map((m) => m["role"]),
      ["system", "user", "assistant", "user"],
      "multi-turn history order preserved",
    );
    for (const m of wire) assert.ok(!("tool_calls" in m), `no tool_calls on a ${String(m["role"])} turn`);
  });
});

// ---------------------------------------------------------------------------
// RunOptions key bridging (resolveConfig -> env-only provider)
// ---------------------------------------------------------------------------

describe("resolveConfig: DeepSeek key bridging", () => {
  it("bridges an opts-passed key into env so the provider can reach it", () => {
    const env: NodeJS.ProcessEnv = { SECSCAN_MCP_TOKEN: FAKE_MCP_TOKEN };
    const cfg = resolveConfig(env, { deepseekApiKey: FAKE_OPTS_KEY });
    assert.equal(cfg.deepseekApiKey, FAKE_OPTS_KEY);
    assert.equal(env["DEEPSEEK_API_KEY"], FAKE_OPTS_KEY, "opts key must land where the provider reads");
  });

  it("explicitly-passed key wins over a different env key", () => {
    const env: NodeJS.ProcessEnv = { SECSCAN_MCP_TOKEN: FAKE_MCP_TOKEN, DEEPSEEK_API_KEY: FAKE_ENV_KEY };
    const cfg = resolveConfig(env, { deepseekApiKey: FAKE_OPTS_KEY });
    assert.equal(cfg.deepseekApiKey, FAKE_OPTS_KEY);
    assert.equal(env["DEEPSEEK_API_KEY"], FAKE_OPTS_KEY, "provider must see the explicit key, not the stale env one");
  });

  it("env-only key works unchanged and env is left untouched", () => {
    const env: NodeJS.ProcessEnv = { SECSCAN_MCP_TOKEN: FAKE_MCP_TOKEN, DEEPSEEK_API_KEY: FAKE_ENV_KEY };
    const cfg = resolveConfig(env, {});
    assert.equal(cfg.deepseekApiKey, FAKE_ENV_KEY);
    assert.equal(env["DEEPSEEK_API_KEY"], FAKE_ENV_KEY);
  });

  it("end to end via resolveConfig(process.env, opts) — the exact call run.ts makes", async () => {
    // Before the bridge this was the L5 failure: config resolution accepted
    // the opts key, then the env-only provider threw at the first LLM call.
    const realMcpToken = process.env["SECSCAN_MCP_TOKEN"];
    delete process.env[DEEPSEEK_API_KEY_ENV];
    process.env["SECSCAN_MCP_TOKEN"] = FAKE_MCP_TOKEN;
    try {
      resolveConfig(process.env, { deepseekApiKey: FAKE_OPTS_KEY });
      assert.equal(new DeepSeekProvider().isConfigured(), true);
      const sent = installStub(async () => okResponse({ choices: [{ message: { content: "ok" } }] }));
      await new DeepSeekProvider().complete({ model: "deepseek-flash", messages: [{ role: "user", content: "hi" }] });
      const headers = sent[0]!.init["headers"] as Record<string, string>;
      assert.equal(headers["Authorization"], `Bearer ${FAKE_OPTS_KEY}`);
    } finally {
      if (realMcpToken === undefined) delete process.env["SECSCAN_MCP_TOKEN"];
      else process.env["SECSCAN_MCP_TOKEN"] = realMcpToken;
      restoreKeyEnv();
    }
  });

  it("no key anywhere fails loud at config time (not mid-engagement)", () => {
    const env: NodeJS.ProcessEnv = { SECSCAN_MCP_TOKEN: FAKE_MCP_TOKEN };
    assert.throws(() => resolveConfig(env, {}), /DEEPSEEK_API_KEY is not set/);
    assert.equal(env["DEEPSEEK_API_KEY"], undefined, "a failed resolve must not invent a key");
  });

  it("dry-run without a key still resolves (no provider will be called)", () => {
    const env: NodeJS.ProcessEnv = { SECSCAN_MCP_TOKEN: FAKE_MCP_TOKEN };
    const cfg = resolveConfig(env, { dryRunAgents: true });
    assert.equal(cfg.deepseekApiKey, "");
  });
});
