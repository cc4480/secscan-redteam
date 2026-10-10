/**
 * SecScan MCP tool handlers: scan_url + read-only tools (v0.19.0 refactor — extracted from dispatch.ts).
 *
 * Error containment: McpClient throws (HTTP errors, isError results,
 * JSON-RPC error envelopes, malformed responses). One flaky MCP call must
 * degrade to a per-call error RESULT the agent can route around — never
 * propagate out of the handler and halt the whole engagement, and never
 * collapse into an empty "success" the agent reads as "nothing found".
 */
import { urlInScope } from "../gate.js";
import { recheckVerified } from "./prelude.js";
import { type Ctx } from "../context.js";
import { type ActorRole, type EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { type DispatchResult } from "./types.js";

const readOnly = new Set(["get_scan_status", "get_report", "list_recent_scans", "get_account"]);

/** A contained MCP failure: visible as missing data, never as a finding-shaped empty success. */
function mcpErrorResult(tool: string, err: unknown): string {
  return (
    `SecScan MCP error: ${tool} failed (${(err as Error).message}). No result was obtained — ` +
    `treat this as missing data, NOT as "scan completed, nothing found". ` +
    `Continue the engagement without it; retry the call later if this tool is still needed.`
  );
}

export async function handleMcpTools(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest, args: Record<string, unknown>): Promise<DispatchResult | null> {
  if (call.name !== "scan_url" && !readOnly.has(call.name)) return null;
if (call.name === "scan_url") {
  const url = String(args["url"] ?? "");
  if (!urlInScope(url, ctx.hosts)) {
    return { result: `DENIED: ${url} is outside the engagement scope.`, target: url };
  }
  const aggressive = args["aggressive"] === true;
  if (aggressive) {
    const ok = await recheckVerified(ctx);
    if (!ok) {
      return {
        result: `DENIED by auth gate: aggressive tier requires ownership-verified domain. The server does not list ${ctx.domain} as verified.`,
        target: url,
      };
    }
  }
  try {
    const text = await ctx.mcp.scanUrl(url, aggressive);
    return { result: text.slice(0, 2000), attackId: aggressive ? "T1595.002" : undefined, target: url };
  } catch (err) {
    return { result: mcpErrorResult("scan_url", err), target: url };
  }
}
if (readOnly.has(call.name)) {
  const target = call.name === "get_report" || call.name === "get_scan_status" ? String(args["scan_id"] ?? "") : undefined;
  try {
    const text = await ctx.mcp.callTool(call.name, args);
    return { result: text.slice(0, 2000), target };
  } catch (err) {
    return { result: mcpErrorResult(call.name, err), target };
  }
}

  return null;
}
