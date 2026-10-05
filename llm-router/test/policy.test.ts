/**
 * Smoke tests for the router's model policy and dispatch mechanics.
 *
 * No network and no API keys: providers report unconfigured here, which is
 * exactly what we assert for the real ones. The policy mapping is the
 * product-visible contract (which model each role runs on), so it is pinned
 * explicitly; the registry mechanics are exercised with a fake provider.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  ROLE_MODEL_POLICY,
  ROLE_ORDER,
  complete,
  completeForRole,
  listProviders,
  registerProvider,
  DEEPSEEK_MODELS,
  DEEPSEEK_API_KEY_ENV,
  QWEN_API_KEY_ENV,
  QWEN_API_KEY_FALLBACK_ENV,
  type ChatResult,
  type CompleteOptions,
  type LlmProvider,
} from "../src/index.js";

// Make configuration deterministic regardless of the operator's shell: no
// provider key is set during these tests, so real providers read unconfigured.
const KEY_ENVS = [DEEPSEEK_API_KEY_ENV, QWEN_API_KEY_ENV, QWEN_API_KEY_FALLBACK_ENV];
let savedKeys: Record<string, string | undefined>;
beforeEach(() => {
  savedKeys = {};
  for (const k of KEY_ENVS) {
    savedKeys[k] = process.env[k];
    delete process.env[k];
  }
});
afterEach(() => {
  for (const k of KEY_ENVS) {
    if (savedKeys[k] === undefined) delete process.env[k];
    else process.env[k] = savedKeys[k];
  }
});

describe("ROLE_MODEL_POLICY", () => {
  it("is DeepSeek-only: exploiter on the pro reasoner, the rest on flash", () => {
    assert.equal(ROLE_MODEL_POLICY.coordinator.provider, "deepseek");
    assert.equal(ROLE_MODEL_POLICY.coordinator.model, DEEPSEEK_MODELS.flash);
    assert.equal(ROLE_MODEL_POLICY.recon.model, DEEPSEEK_MODELS.flash);
    assert.equal(ROLE_MODEL_POLICY.reporter.model, DEEPSEEK_MODELS.flash);
    assert.equal(ROLE_MODEL_POLICY.exploiter.provider, "deepseek");
    assert.equal(ROLE_MODEL_POLICY.exploiter.model, DEEPSEEK_MODELS.pro);
    assert.equal(ROLE_MODEL_POLICY.exploiter.reasoningEffort, "high");
  });

  it("ROLE_ORDER lists every role exactly once", () => {
    const keys = Object.keys(ROLE_MODEL_POLICY).sort();
    assert.deepEqual([...ROLE_ORDER].sort(), keys);
    assert.equal(new Set(ROLE_ORDER).size, ROLE_ORDER.length);
  });
});

describe("provider registry", () => {
  it("auto-registers deepseek and qwen (both unconfigured without keys here)", () => {
    const ids = listProviders().map((p) => p.id);
    assert.ok(ids.includes("deepseek"), "deepseek registered");
    assert.ok(ids.includes("qwen"), "qwen registered");
  });

  it("rejects a duplicate registration", () => {
    assert.throws(() => registerProvider({ id: "deepseek" } as unknown as LlmProvider), /already registered/);
  });

  it("completeForRole routes to an unconfigured real provider → fail closed with an actionable error", async () => {
    // No DEEPSEEK_API_KEY in the test env → the routed provider is registered
    // but not configured, which must throw (never silently proceed).
    await assert.rejects(
      completeForRole("exploiter", [{ role: "user", content: "hi" }]),
      /not configured|API key/i,
    );
  });

  it("complete() dispatches to a registered provider and passes the model through", async () => {
    let seen: CompleteOptions | null = null;
    const fake: LlmProvider = {
      id: "fake-smoke",
      label: "Fake",
      isConfigured: () => true,
      complete: async (opts: CompleteOptions): Promise<ChatResult> => {
        seen = opts;
        return { text: "ok", toolCalls: [], provider: "fake-smoke", model: opts.model };
      },
    };
    registerProvider(fake);
    const res = await complete("fake-smoke", { model: "m-1", messages: [{ role: "user", content: "x" }] });
    assert.equal(res.model, "m-1");
    assert.equal(seen!.model, "m-1");
  });

  it("unknown provider id throws", async () => {
    await assert.rejects(
      complete("nope-not-here", { model: "m", messages: [] }),
      /unknown provider/i,
    );
  });
});
