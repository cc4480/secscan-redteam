/**
 * Qwen provider smoke test: hypothesis-generation dry run, NO live target.
 *
 * Exercises the Qwen provider path end to end —
 *   complete("qwen", ...) → QwenProvider → DashScope OpenAI-compatible
 *   endpoint —
 * and verifies: text comes back, the thinking trace is surfaced, and a tool
 * definition round-trips (the model may call it; the call is never executed).
 *
 * v0.6: the role policy runs DeepSeek-only (no role routes to Qwen), so the
 * Qwen key is OPTIONAL. With no QWEN_API_KEY (or DASHSCOPE_API_KEY) in the
 * environment this exits 0 with a skip message. With a key present it runs
 * the real provider smoke test — useful for validating Qwen before
 * reinstating it in llm-router/src/policy.ts.
 */
import { complete, QWEN_MODELS } from "@secscan/redteam-llm-router";

const key = process.env["QWEN_API_KEY"] ?? process.env["DASHSCOPE_API_KEY"];
if (!key) {
  console.log("SMOKE SKIP: Qwen not configured — skipping (exit 0).");
  console.log(
    "The role policy is DeepSeek-only, so no Qwen key is required. " +
      "To smoke-test the Qwen provider, set QWEN_API_KEY (or DASHSCOPE_API_KEY) " +
      "via the Secure Vault and re-run.",
  );
  process.exit(0);
}

const res = await complete("qwen", {
  model: QWEN_MODELS.reasoning,
  messages: [
    {
      role: "system",
      content:
        "You are a black-hat hacker reasoning about a web target. Think step by step, then state ONE hypothesis (1-2 sentences) about a business-logic flaw in a coupon/discount flow, and call the record_hypothesis tool with it. Do not probe anything — this is a dry run.",
    },
    { role: "user", content: "Target: a fictional SaaS checkout at https://example.test (do not touch it). Generate the hypothesis." },
  ],
  reasoningEffort: "high",
  tools: [
    {
      name: "record_hypothesis",
      description: "Record a hypothesis (dry run — never executed).",
      parameters: {
        type: "object",
        properties: { hypothesis: { type: "string" } },
        required: ["hypothesis"],
      },
    },
  ],
});

console.log(`provider: ${res.provider} | model: ${res.model}`);
console.log(`text (${res.text.length} chars): ${res.text.slice(0, 300)}`);
console.log(`reasoning trace: ${res.reasoning ? `${res.reasoning.length} chars` : "ABSENT"}`);
if (res.reasoning) console.log(`reasoning head: ${res.reasoning.slice(0, 200)}`);
console.log(`tool calls: ${res.toolCalls.map((c) => c.name).join(", ") || "(none)"}`);
console.log(`usage: ${res.usage ? `${res.usage.totalTokens} tokens total` : "(not reported)"}`);

const ok =
  res.provider === "qwen" &&
  res.model === "qwen3.8-max" &&
  res.text.length > 0 &&
  !!res.reasoning;
console.log(ok ? "SMOKE PASS: Qwen reasoning path works end to end." : "SMOKE FAIL: missing text or thinking trace.");
process.exit(ok ? 0 : 1);
