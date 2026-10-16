/**
 * The agent-action cap must be settable, and must actually arrive.
 *
 * Default is 60 actions (config.ts). A full battery is 418 items across four
 * target families, and a coordinator that reconciles them one verdict at a time
 * spends far more than 60 before it reaches a single probe. A live run halted
 * with "action cap reached (60)" holding 307 recorded verdicts and 95 items
 * still unanswered — the coverage work was real, the budget simply could not
 * hold it.
 *
 * maxActions existed as a RunnerOption but was reachable from nowhere: not the
 * CLI, not the MCP tool schema, not the launch route. These tests pin both ends
 * — that resolveConfig honours a supplied cap, and that the tool that launches
 * engagements actually advertises it.
 *
 * Worth recording how the first attempt failed: maxActions was added to
 * EngagementInput, which is the wrong type. tsc rejected it. Had the object
 * been loosely typed, the value would have been accepted and quietly dropped —
 * the operator would set a cap and watch it do nothing.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveConfig } from "../src/phases/config.js";
import { TOOLS } from "../src/ui/mcp-tools.js";

// resolveConfig reads the process environment for the MCP token and the model
// key before it returns anything, so a test that pins too little either fails
// on a real machine or passes on it by accident. Pin everything it touches.
const ENV_PIN = {
  SECSCAN_MCP_TOKEN: "test-token",
  DEEPSEEK_API_KEY: "test-key",
  REDTEAM_OPERATOR: "test-operator",
  REDTEAM_ENV: "staging",
} as unknown as NodeJS.ProcessEnv;

describe("agent-action cap", () => {
  it("defaults to 60 when nothing is supplied", () => {
    assert.equal(resolveConfig(ENV_PIN, {}).maxActions, 60);
  });

  it("honours a supplied cap — the whole point of the change", () => {
    assert.equal(resolveConfig(ENV_PIN, { maxActions: 900 }).maxActions, 900);
  });

  it("a full battery needs far more than the default", () => {
    // Not a magic number: 418 battery items, and a verdict costs an action.
    const ledgerItems = 418;
    assert.ok(
      ledgerItems > resolveConfig(ENV_PIN, {}).maxActions,
      "the default cap cannot cover one action per battery item",
    );
  });

  it("start_engagement advertises maxActions", () => {
    const tool = TOOLS.find((t: { name: string }) => t.name === "start_engagement");
    assert.ok(tool, "start_engagement exists");
    const props = (tool!.inputSchema as { properties?: Record<string, unknown> }).properties ?? {};
    assert.ok("maxActions" in props, "the cap must be settable at launch, or it is not settable at all");
  });

  it("keeps maxActions optional so existing callers are unaffected", () => {
    const tool = TOOLS.find((t: { name: string }) => t.name === "start_engagement");
    const required = (tool!.inputSchema as { required?: string[] }).required ?? [];
    assert.ok(!required.includes("maxActions"), "it has a default; requiring it would break every caller");
  });
});
