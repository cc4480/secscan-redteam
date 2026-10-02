/**
 * Qwen provider tests.
 *
 * The exploiter role runs on Qwen (qwen3.8-max reasoning). These tests pin the
 * provider contract with a stubbed fetch: wire format, thinking parameters,
 * reasoning-trace parsing, tool-call translation, and key handling. No
 * network, no key needed.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  QwenProvider,
  QWEN_API_KEY_ENV,
  QWEN_API_KEY_FALLBACK_ENV,
  QWEN_BASE_URL,
  QWEN_MODELS,
  ROLE_MODEL_POLICY,
  complete,
  listProviders,
} from "@secscan/redteam-llm-router";

const realFetch = globalThis.fetch;

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

describe("Qwen provider", () => {
  let sent: { url: string; init: Record<string, unknown> }[];
  const OLD_KEY = process.env[QWEN_API_KEY_ENV];
  const OLD_FALLBACK = process.env[QWEN_API_KEY_FALLBACK_ENV];

  beforeEach(() => {
    sent = [];
    process.env[QWEN_API_KEY_ENV] = "test-qwen-key";
    delete process.env[QWEN_API_KEY_FALLBACK_ENV];
    stubFetch(async (url, init) => {
      sent.push({ url, init });
      return okResponse({
        choices: [
          {
            message: {
              content: "hypothesis: IDOR on /api/scans/{id}",
              reasoning_content: "considering object-level authz...",
              tool_calls: [
                { id: "call_1", function: { name: "http_probe", arguments: '{"method":"GET","url":"https://x/"}' } },
              ],
            },
          },
        ],
        usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 },
      });
    });
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    if (OLD_KEY === undefined) delete process.env[QWEN_API_KEY_ENV];
    else process.env[QWEN_API_KEY_ENV] = OLD_KEY;
    if (OLD_FALLBACK === undefined) delete process.env[QWEN_API_KEY_FALLBACK_ENV];
    else process.env[QWEN_API_KEY_FALLBACK_ENV] = OLD_FALLBACK;
  });

  it("is registered and reports configured with the key present", () => {
    const p = listProviders().find((x) => x.id === "qwen");
    assert.ok(p, "qwen provider must be registered");
    assert.equal(p.configured, true);
  });

  it("uses the OpenAI-compatible endpoint and sends the key as Bearer (never in the URL)", async () => {
    const q = new QwenProvider();
    await q.complete({ model: QWEN_MODELS.reasoning, messages: [{ role: "user", content: "hi" }] });
    assert.equal(sent.length, 1);
    assert.equal(sent[0]!.url, `${QWEN_BASE_URL}/chat/completions`);
    const headers = sent[0]!.init["headers"] as Record<string, string>;
    assert.equal(headers["Authorization"], "Bearer test-qwen-key");
    assert.ok(!sent[0]!.url.includes("test-qwen-key"), "key must not leak into the URL");
  });

  it("enables thinking and maps the reasoning-effort hint", async () => {
    const q = new QwenProvider();
    await q.complete({ model: QWEN_MODELS.reasoning, messages: [], reasoningEffort: "high" });
    const body = JSON.parse(sent[0]!.init["body"] as string) as Record<string, unknown>;
    assert.equal(body["model"], "qwen3.8-max");
    assert.equal(body["enable_thinking"], true);
    assert.equal(body["reasoning_effort"], "xhigh");
  });

  it("maps medium/low effort hints", async () => {
    const q = new QwenProvider();
    await q.complete({ model: QWEN_MODELS.reasoning, messages: [], reasoningEffort: "low" });
    const body = JSON.parse(sent[0]!.init["body"] as string) as Record<string, unknown>;
    assert.equal(body["reasoning_effort"], "low");
  });

  it("parses text, thinking trace, tool calls, and usage", async () => {
    const q = new QwenProvider();
    const res = await q.complete({ model: QWEN_MODELS.reasoning, messages: [] });
    assert.equal(res.provider, "qwen");
    assert.equal(res.model, "qwen3.8-max");
    assert.match(res.text, /IDOR/);
    assert.match(res.reasoning ?? "", /object-level authz/);
    assert.equal(res.toolCalls.length, 1);
    assert.equal(res.toolCalls[0]!.name, "http_probe");
    assert.deepEqual(res.toolCalls[0]!.arguments, { method: "GET", url: "https://x/" });
    assert.equal(res.usage?.totalTokens, 30);
  });

  it("falls back to DASHSCOPE_API_KEY when QWEN_API_KEY is absent", async () => {
    delete process.env[QWEN_API_KEY_ENV];
    process.env[QWEN_API_KEY_FALLBACK_ENV] = "fallback-key";
    const q = new QwenProvider();
    assert.equal(q.isConfigured(), true);
    await q.complete({ model: QWEN_MODELS.reasoning, messages: [] });
    const headers = sent[0]!.init["headers"] as Record<string, string>;
    assert.equal(headers["Authorization"], "Bearer fallback-key");
  });

  it("throws an actionable error with no key (never echoing one)", async () => {
    delete process.env[QWEN_API_KEY_ENV];
    delete process.env[QWEN_API_KEY_FALLBACK_ENV];
    const q = new QwenProvider();
    assert.equal(q.isConfigured(), false);
    await assert.rejects(() => q.complete({ model: QWEN_MODELS.reasoning, messages: [] }), /QWEN_API_KEY/);
  });

  it("surfaces HTTP errors without the key", async () => {
    stubFetch(async () => ({ ok: false, status: 401, text: async () => "invalid key" }) as Response);
    const q = new QwenProvider();
    await assert.rejects(() => q.complete({ model: QWEN_MODELS.reasoning, messages: [] }), (err: Error) => {
      assert.match(err.message, /Qwen HTTP 401/);
      assert.ok(!err.message.includes("test-qwen-key"), "error must not echo the key");
      return true;
    });
  });

  it("complete() dispatches by provider id", async () => {
    const res = await complete("qwen", { model: QWEN_MODELS.reasoning, messages: [] });
    assert.equal(res.provider, "qwen");
    assert.match(res.text, /IDOR/);
  });
});

describe("role model policy (v0.5)", () => {
  it("routes the exploiter to Qwen reasoning; everyone else to deepseek-flash", () => {
    assert.deepEqual(ROLE_MODEL_POLICY.exploiter, {
      provider: "qwen",
      model: "qwen3.8-max",
      reasoningEffort: "high",
    });
    for (const role of ["coordinator", "recon", "reporter"] as const) {
      assert.equal(ROLE_MODEL_POLICY[role].provider, "deepseek");
      assert.equal(ROLE_MODEL_POLICY[role].model, "deepseek-flash");
    }
  });
});
