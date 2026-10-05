/**
 * SecScan MCP tool handlers: scan_url + read-only tools (v0.19.0 refactor — extracted from dispatch.ts).
 */
import { urlInScope } from "../gate.js";
import { recheckVerified } from "./prelude.js";
import { type Ctx } from "../context.js";
import { type ActorRole, type EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { type DispatchResult } from "./types.js";

const readOnly = new Set(["get_scan_status", "get_report", "list_recent_scans", "get_account"]);

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
  // A tool-level failure (MCP isError such as quota exhausted, or a transport
  // error) is an OBSERVATION the agent adapts to — e.g. fall back to existing
  // reports — not a fatal error that ends the whole engagement. Return it as a
  // result string, mirroring how http_probe/host-exec surface their failures.
  try {
    const text = await ctx.mcp.scanUrl(url, aggressive);
    return { result: text.slice(0, 2000), attackId: aggressive ? "T1595.002" : undefined, target: url };
  } catch (err) {
    return { result: `scan_url unavailable: ${(err as Error).message}`, target: url };
  }
}
if (readOnly.has(call.name)) {
  try {
    const text = await ctx.mcp.callTool(call.name, args);
    return { result: text.slice(0, 2000), target: call.name === "get_report" || call.name === "get_scan_status" ? String(args["scan_id"] ?? "") : undefined };
  } catch (err) {
    return { result: `${call.name} unavailable: ${(err as Error).message}`, target: call.name === "get_report" || call.name === "get_scan_status" ? String(args["scan_id"] ?? "") : undefined };
  }
}

  return null;
}
