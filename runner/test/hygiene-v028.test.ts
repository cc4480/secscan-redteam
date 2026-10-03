/**
 * Hygiene sweep tests (v0.28.0) — one test per audit item.
 *
 * 1. Env-var numerics validated at config-parse time (name the variable).
 * 2. Windows path handling (basename, not split("/")).
 * 3. Node engines field present.
 * 4. UI token: timing-safe compare + weak explicit token rejected at startup.
 * 5. Tier refusal happens before the rate limiter (no token consumed).
 * 6. Agent reasoning is PII-redacted before the audit log.
 * 7. Queue jobs validated at intake, naming the file and the reason.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { resolveConfig } from "../src/phases/config.js";
import { parseTemplateList } from "../src/nuclei/executor.js";
import { tokensEqual, assertStrongToken } from "../src/ui/auth.js";
import { dispatchTool } from "../src/dispatch/router.js";
import { agentLoop } from "../src/agents.js";
import { validateQueueInput } from "../src/index.js";
import type { Ctx } from "../src/context.js";
import type { EngagementPhase } from "../src/types.js";

const KEYS = {
  SECSCAN_MCP_TOKEN: "test-mcp-token",
  DEEPSEEK_API_KEY: "test-deepseek-key",
  QWEN_API_KEY: "test-qwen-key",
};

describe("item 1: env-var numerics fail fast naming the variable", () => {
  it("rejects REDTEAM_MAX_RPS=abc", () => {
    assert.throws(
      () => resolveConfig({ ...KEYS, REDTEAM_MAX_RPS: "abc" }, {}),
      /REDTEAM_MAX_RPS/,
    );
  });
  it("rejects REDTEAM_MAX_VARIANTS=abc", () => {
    assert.throws(
      () => resolveConfig({ ...KEYS, REDTEAM_MAX_VARIANTS: "abc" }, {}),
      /REDTEAM_MAX_VARIANTS/,
    );
  });
  it("rejects non-positive values", () => {
    assert.throws(() => resolveConfig({ ...KEYS, REDTEAM_MAX_RPS: "-2" }, {}), /REDTEAM_MAX_RPS/);
    assert.throws(() => resolveConfig({ ...KEYS, REDTEAM_MAX_RPS: "0" }, {}), /REDTEAM_MAX_RPS/);
  });
  it("accepts valid values and leaves unset as undefined", () => {
    const c = resolveConfig({ ...KEYS, REDTEAM_MAX_RPS: "3", REDTEAM_MAX_VARIANTS: "25" }, {});
    assert.equal(c.maxRpsPerHost, 3);
    assert.equal(c.maxVariantsPerItem, 25);
    const d = resolveConfig({ ...KEYS }, {});
    assert.equal(d.maxRpsPerHost, undefined);
    assert.equal(d.maxVariantsPerItem, undefined);
  });
});

describe("item 2: Windows path handling", () => {
  it("parses template ids from backslash paths (nuclei -tl on Windows)", () => {
    const list = parseTemplateList("C:\\nuclei-templates\\http\\cwe-79.yaml\n");
    assert.equal(list.length, 1);
    assert.equal(list[0]!.id, "cwe-79");
  });
  it("still parses forward-slash paths", () => {
    const list = parseTemplateList("/home/op/templates/http/cwe-89.yaml\n");
    assert.equal(list[0]!.id, "cwe-89");
  });
});

describe("item 3: Node engines field", () => {
  it("package.json declares engines.node >= 20", () => {
    const pkg = JSON.parse(
      readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
    ) as { engines?: { node?: string } };
    assert.ok(pkg.engines?.node, "engines.node missing");
    assert.match(pkg.engines.node, />=\s*20/);
  });
});

describe("item 4: UI token hygiene", () => {
  it("tokensEqual compares correctly and is not plain ===", () => {
    assert.equal(tokensEqual("abc123", "abc123"), true);
    assert.equal(tokensEqual("abc123", "abc124"), false);
    assert.equal(tokensEqual("abc123", "abc1234"), false, "length mismatch is false");
  });
  it("rejects weak explicit tokens at startup", () => {
    assert.throws(() => assertStrongToken("password"), /too weak/);
    assert.throws(() => assertStrongToken("short"), /too weak/);
    assert.throws(() => assertStrongToken("changeme"), /too weak/);
  });
  it("accepts a strong token", () => {
    assertStrongToken("this-is-a-strong-enough-token-42");
  });
});

describe("item 5: tier refusal before the rate limiter", () => {
  it("a tier-denied tool never touches limiter.acquire", async () => {
    const tmp = join(tmpdir(), `tier-order-${process.pid}-${Date.now()}`);
    mkdirSync(tmp, { recursive: true });
    try {
      let acquireCalls = 0;
      const appended: Array<{ action: string; result: string }> = [];
      const ctx = {
        hostKill: { aborted: false, controllers: new Set<AbortController>() },
        safety: {
          killSwitchAborts: 0,
          autoHalt: { isHalted: () => false, haltReason: () => undefined },
          limiter: { acquire: async () => { acquireCalls++; } },
        },
        tier: { current: 0, chainSteps: new Map<string, number>() },
        itemLedger: undefined,
        events: {
          dir: tmp,
          append: (e: { action: string; result: string }) => {
            appended.push({ action: e.action, result: e.result });
          },
        },
      } as unknown as Ctx;
      const res = await dispatchTool(
        ctx,
        "exploiter",
        "exploit" as EngagementPhase,
        { id: "t1", name: "nuclei_exec", arguments: { action: "run", host: "target.example" } },
      );
      assert.match(res.result, /DENIED by autonomy tier/);
      assert.equal(acquireCalls, 0, "tier refusal must not consume a rate token");
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("item 6: agent reasoning is redacted before the audit log", () => {
  it("a secret echoed in the thinking trace is redacted in the event", async () => {
    const appended: Array<{ action: string; result: string }> = [];
    const ctx = {
      actions: 0,
      consecutive5xx: 0,
      startedAt: Date.now(),
      config: { maxActions: 60, maxDurationMs: 45 * 60_000 },
      input: { roe: { blackoutWindows: [] } },
      deps: {
        completeForRole: async () => ({
          text: "done",
          reasoning: "noted the contact analyst@client.example in the error page",
          toolCalls: [],
        }),
      },
      events: {
        append: (e: { action: string; result: string }) => {
          appended.push({ action: e.action, result: e.result });
        },
      },
    } as unknown as Ctx;
    await agentLoop(ctx, "recon", "recon" as EngagementPhase, "sys", "user", [], 3, {
      onIdle: () => null,
    });
    const reasoning = appended.find((e) => e.action === "reasoning");
    assert.ok(reasoning, "reasoning event appended");
    assert.ok(!reasoning!.result.includes("analyst@client.example"), "PII redacted from reasoning");
    assert.ok(reasoning!.result.includes("[PII-REDACTED]"), "redaction marker present");
  });
});

const GOOD_JOB = {
  target: "target.example",
  mode: "red",
  objective: "assess",
  roe: { scope: ["target.example"] },
};

describe("item 7: queue intake validation", () => {
  it("accepts a well-formed job", () => {
    const input = validateQueueInput(GOOD_JOB);
    assert.equal(input.target, "target.example");
  });
  it("rejects missing target, bad mode, missing objective", () => {
    assert.throws(() => validateQueueInput({ ...GOOD_JOB, target: "" }), /target is required/);
    assert.throws(() => validateQueueInput({ ...GOOD_JOB, mode: "purple" }), /mode must be red\|black/);
    assert.throws(() => validateQueueInput({ ...GOOD_JOB, objective: "" }), /objective is required/);
  });
  it("rejects empty scope", () => {
    assert.throws(() => validateQueueInput({ ...GOOD_JOB, roe: { scope: [] } }), /roe\.scope is required/);
    const { roe: _dropped, ...noRoe } = GOOD_JOB as Record<string, unknown>;
    assert.throws(() => validateQueueInput(noRoe), /roe\.scope is required/);
  });
  it("rejects bad targets, tier, and environment", () => {
    assert.throws(() => validateQueueInput({ ...GOOD_JOB, targets: ["mars"] }), /bad targets/);
    assert.throws(() => validateQueueInput({ ...GOOD_JOB, tier: 9 }), /tier/i);
    assert.throws(
      () => validateQueueInput({ ...GOOD_JOB, environment: "prod-ish" }),
      /environment must be staging\|production/,
    );
  });
  it("accepts optional fields when valid", () => {
    const input = validateQueueInput({
      ...GOOD_JOB,
      targets: ["windows"],
      tier: 1,
      environment: "staging",
    });
    assert.equal(input.tier, 1);
    assert.equal(input.environment, "staging");
  });
});
