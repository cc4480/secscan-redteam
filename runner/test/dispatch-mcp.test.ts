/**
 * Regression test for the live-engagement halt: an MCP tool returning a
 * business-level isError (e.g. "you've used this month's 3 free scans") used
 * to throw out of handleMcpTools and crash the whole engagement. It must
 * instead come back as an observation string the agent can adapt to.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { handleMcpTools } from "../src/dispatch/mcp.js";

const SCOPE = ["secscan.us"];

function ctxWithMcp(throwMsg: string): never {
  const thrower = async (): Promise<string> => {
    throw new Error(throwMsg);
  };
  return {
    hosts: SCOPE,
    domain: "secscan.us",
    mcp: { scanUrl: thrower, callTool: thrower },
  } as never;
}

const scanCall = (): ToolCallRequest => ({
  id: "c1",
  name: "scan_url",
  arguments: { url: "https://secscan.us/" },
});
const reportCall = (): ToolCallRequest => ({
  id: "c2",
  name: "get_report",
  arguments: { scan_id: "abc" },
});

describe("handleMcpTools error handling", () => {
  it("scan_url quota error becomes an observation, not a thrown halt", async () => {
    const ctx = ctxWithMcp("[mcp] scan_url isError: You've used this month's 3 free scans.");
    const r = await handleMcpTools(ctx, "recon", "recon", scanCall(), scanCall().arguments as Record<string, unknown>);
    assert.ok(r, "handler claims the call");
    assert.match(r!.result, /scan_url unavailable/i);
    assert.match(r!.result, /3 free scans/i);
  });

  it("read-only tool error also becomes an observation", async () => {
    const ctx = ctxWithMcp("[mcp] get_report isError: not found");
    const r = await handleMcpTools(ctx, "recon", "recon", reportCall(), reportCall().arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r!.result, /get_report unavailable/i);
    assert.equal(r!.target, "abc");
  });

  it("out-of-scope scan is still denied before any MCP call", async () => {
    const ctx = ctxWithMcp("should not be called");
    const call: ToolCallRequest = { id: "c3", name: "scan_url", arguments: { url: "https://evil.example/" } };
    const r = await handleMcpTools(ctx, "recon", "recon", call, call.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r!.result, /DENIED/);
  });
});
