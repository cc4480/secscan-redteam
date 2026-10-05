/**
 * Regression test for the tool-call round-trip bug that halted the first live
 * engagement: an assistant message that requested tool calls was serialized
 * without a `tool_calls` field, so the following `tool` message was rejected
 * by the OpenAI-compatible API ("Messages with role 'tool' must be a response
 * to a preceding message with 'tool_calls'"). Mocked-router tests never hit
 * this because they don't exercise real wire serialization.
 *
 * We stub global fetch, capture the outgoing request body, and assert the
 * assistant turn carries tool_calls whose ids match the following tool
 * message's tool_call_id.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { DeepSeekProvider, QwenProvider, DEEPSEEK_API_KEY_ENV, QWEN_API_KEY_ENV } from "../src/index.js";
import type { ChatMessage } from "../src/index.js";

const origFetch = globalThis.fetch;
let captured: { body: Record<string, unknown> } | null;

function stubFetch(): void {
  captured = null;
  globalThis.fetch = (async (_url: string, init: { body?: string }) => {
    captured = { body: JSON.parse(String(init?.body ?? "{}")) };
    return {
      ok: true,
      status: 200,
      json: async () => ({ choices: [{ message: { content: "ok" } }] }),
      text: async () => "",
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

beforeEach(() => {
  process.env[DEEPSEEK_API_KEY_ENV] = "test-key";
  process.env[QWEN_API_KEY_ENV] = "test-key";
  stubFetch();
});
afterEach(() => {
  globalThis.fetch = origFetch;
  delete process.env[DEEPSEEK_API_KEY_ENV];
  delete process.env[QWEN_API_KEY_ENV];
});

const historyWithToolCall: ChatMessage[] = [
  { role: "system", content: "sys" },
  { role: "user", content: "go" },
  {
    role: "assistant",
    content: "",
    toolCalls: [{ id: "call_1", name: "http_probe", arguments: { url: "https://example.com" } }],
  },
  { role: "tool", toolCallId: "call_1", content: "200 OK" },
];

function assertRoundTrip(wireMessages: Array<Record<string, unknown>>): void {
  const assistant = wireMessages.find((m) => m["role"] === "assistant")!;
  const toolMsg = wireMessages.find((m) => m["role"] === "tool")!;
  const toolCalls = assistant["tool_calls"] as Array<Record<string, unknown>> | undefined;
  assert.ok(toolCalls && toolCalls.length === 1, "assistant message carries tool_calls");
  assert.equal(toolCalls![0]!["id"], "call_1");
  assert.equal((toolCalls![0]!["function"] as Record<string, unknown>)["name"], "http_probe");
  // the tool result must reference the same id — the invariant the API enforces
  assert.equal(toolMsg["tool_call_id"], toolCalls![0]!["id"]);
}

describe("tool-call wire round-trip", () => {
  it("DeepSeek serializes assistant tool_calls before the tool message", async () => {
    await new DeepSeekProvider().complete({ model: "deepseek-flash", messages: historyWithToolCall });
    assertRoundTrip(captured!.body["messages"] as Array<Record<string, unknown>>);
  });

  it("Qwen serializes assistant tool_calls before the tool message", async () => {
    await new QwenProvider().complete({ model: "qwen3.8-max", messages: historyWithToolCall });
    assertRoundTrip(captured!.body["messages"] as Array<Record<string, unknown>>);
  });
});
