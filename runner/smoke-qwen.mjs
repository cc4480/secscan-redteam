/**
 * Qwen exploiter smoke test: hypothesis-generation dry run, NO live target.
 *
 * Exercises the full provider path end to end —
 *   completeForRole("exploiter") → policy routes to qwen/qwen3.8-max →
 *   QwenProvider → DashScope OpenAI-compatible endpoint —
 * and verifies: text comes back, the thinking trace is surfaced, and a tool
 * definition round-trips (the model may call it; the call is never executed).
 *
 * Requires QWEN_API_KEY (or DASHSCOPE_API_KEY) in the environment — via the
 * Secure Vault. Exits 2 with a clear message when the key is absent.
 */
import { completeForRole, ROLE_MODEL_POLICY } from "@secscan/redteam-llm-router";

const key = process.env["QWEN_API_KEY"] ?? process.env["DASHSCOPE_API_KEY"];
if (!key) {
  console.error(
    "SMOKE SKIP: no QWEN_API_KEY (or DASHSCOPE_API_KEY) in the environment.\n" +
      "Enter the Alibaba Model Studio API key via the Secure Vault, then re-run.",
  );
  process.exit(2);
}

const route = ROLE_MODEL_POLICY.exploiter;
console.log(`policy: exploiter → ${route.provider}/${route.model} (effort=${route.reasoningEffort})`);
if (route.provider !== "qwen" || route.model !== "qwen3.8-max") {
  console.error("SMOKE FAIL: policy does not route the exploiter to qwen/qwen3.8-max");
  process.exit(1);
}

const res = await completeForRole(
  "exploiter",
  [
    {
      role: "system",
      content:
        "You are a black-hat hacker reasoning about a web target. Think step by step, then state ONE hypothesis (1-2 sentences) about a business-logic flaw in a coupon/discount flow, and call the record_hypothesis tool with it. Do not probe anything — this is a dry run.",
    },
    { role: "user", content: "Target: a fictional SaaS checkout at https://example.test (do not touch it). Generate the hypothesis." },
  ],
  {
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
  },
);

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
