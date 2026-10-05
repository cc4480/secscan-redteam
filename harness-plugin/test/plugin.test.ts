/**
 * Smoke tests for the harness plugin: the auth-gate pre-execute hook and the
 * system-prompt section it injects. No harness host and no network — a
 * minimal fake Context captures what the plugin registers, and the gate runs
 * fail-closed because no SECSCAN_MCP_TOKEN is set.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { ROLE_MODEL_POLICY } from "@secscan/redteam-llm-router";
import { plugin, apply } from "../src/index.js";
import { REDTEAM_PROFILE } from "../src/redteam-profile.js";
import type { Context, PreToolDecision, ToolExecution } from "../src/harness-types.js";

type PreHook = (exec: ToolExecution, next: () => Promise<PreToolDecision>) => Promise<PreToolDecision>;

interface Captured {
  preHooks: PreHook[];
  sections: Array<{ name: string; order: number; text: string }>;
}

function fakeCtx(): { ctx: Context; captured: Captured } {
  const captured: Captured = { preHooks: [], sections: [] };
  const ctx = {
    on: (event: string, handler: PreHook) => {
      if (event === "tools/pre-execute") captured.preHooks.push(handler);
    },
    systemPrompt: {
      section: (s: { name: string; order: number; text: string }) => captured.sections.push(s),
    },
  } as unknown as Context;
  return { ctx, captured };
}

const allow = async (): Promise<PreToolDecision> => ({ kind: "allow" });

// The gate must have no server token so it fails closed deterministically.
let savedToken: string | undefined;
beforeEach(() => {
  savedToken = process.env["SECSCAN_MCP_TOKEN"];
  delete process.env["SECSCAN_MCP_TOKEN"];
});
afterEach(() => {
  if (savedToken === undefined) delete process.env["SECSCAN_MCP_TOKEN"];
  else process.env["SECSCAN_MCP_TOKEN"] = savedToken;
});

describe("plugin module shape", () => {
  it("exports name + inject surfaces", () => {
    assert.equal(plugin.name, "secscan-redteam");
    assert.deepEqual(plugin.inject, ["tools", "systemPrompt"]);
  });
});

describe("apply()", () => {
  it("installs a pre-execute hook and the engagement-protocol section", () => {
    const { ctx, captured } = fakeCtx();
    apply(ctx);
    assert.equal(captured.preHooks.length, 1, "one pre-execute hook");
    const section = captured.sections.find((s) => s.name === "secscan-redteam");
    assert.ok(section, "section injected");
    assert.match(section!.text, /HARD RULE/);
    // Model policy line is derived from the router, not hand-written.
    assert.ok(section!.text.includes(ROLE_MODEL_POLICY.exploiter.model), "exploiter model in prompt");
  });

  it("denies aggressive scan_url on an unverified domain (fail closed, no token)", async () => {
    const { ctx, captured } = fakeCtx();
    apply(ctx);
    const hook = captured.preHooks[0]!;
    const d = await hook(
      { name: "mcp__secscan__scan_url", arguments: { url: "https://example.com", aggressive: true } } as ToolExecution,
      allow,
    );
    assert.equal(d.kind, "deny");
  });

  it("allows passive scan_url and non-scan tools (calls next)", async () => {
    const { ctx, captured } = fakeCtx();
    apply(ctx);
    const hook = captured.preHooks[0]!;
    const passive = await hook(
      { name: "mcp__secscan__scan_url", arguments: { url: "https://example.com" } } as ToolExecution,
      allow,
    );
    assert.equal(passive.kind, "allow");
    const other = await hook(
      { name: "mcp__secscan__get_report", arguments: {} } as ToolExecution,
      allow,
    );
    assert.equal(other.kind, "allow");
  });
});

describe("REDTEAM_PROFILE", () => {
  it("derives each member's model from ROLE_MODEL_POLICY (no drift)", () => {
    const byName = Object.fromEntries(REDTEAM_PROFILE.members.map((m) => [m.name, m]));
    for (const role of ["coordinator", "recon", "exploiter", "reporter"] as const) {
      assert.equal(byName[role]!.provider, ROLE_MODEL_POLICY[role].provider, `${role} provider`);
      assert.equal(byName[role]!.model, ROLE_MODEL_POLICY[role].model, `${role} model`);
    }
  });
});
