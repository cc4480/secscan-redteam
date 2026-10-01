/**
 * Auth gate: a `tools/pre-execute` hook that keeps active testing scoped.
 *
 * The SecScan MCP server (https://secscan.us/api/mcp, connected via the
 * harness-native @deepseek-ai/dsh-mcp-client) exposes its tools namespaced as
 * `mcp__<serverName>__<tool>` — e.g. `mcp__secscan__scan_url`. The server
 * itself only runs active tests against verified domains; this gate is the
 * agent-layer backstop so an explicit active-testing request can never
 * dispatch without proof.
 *
 * Verification is SERVER-AUTHORITATIVE: before allowing an active-testing
 * scan, the gate asks the SecScan server for its own verified-domain list
 * (`list_verified_domains` over the MCP endpoint) and allows only listed
 * domains. The operator-managed `SECSCAN_VERIFIED_DOMAINS` allowlist remains
 * as a secondary path for operators who verified out-of-band. The gate
 * issues no tokens and does no DNS of its own. Any check error or timeout
 * fails closed (deny).
 *
 * Field names verified against @deepseek-ai/dsh-tools 0.2.0-rc.2:
 * ToolExecution has `name` (tool name) and `arguments` (unknown).
 */

import {
  decide,
  isServerVerified,
  type GateContext,
  type ServerVerificationConfig,
} from "@secscan/redteam-auth-gate";
import type { Context, PreToolDecision, ToolExecution } from "./harness-types.js";

const DEFAULT_MCP_URL = "https://secscan.us/api/mcp";

function serverConfig(): ServerVerificationConfig | null {
  const token = process.env["SECSCAN_MCP_TOKEN"];
  if (!token) return null;
  return {
    endpoint: process.env["SECSCAN_MCP_URL"] ?? DEFAULT_MCP_URL,
    token,
  };
}

function allowlistedDomains(): Set<string> {
  const raw = process.env["SECSCAN_VERIFIED_DOMAINS"] ?? "";
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

function gateContext(): GateContext {
  const cfg = serverConfig();
  return {
    allowlistedDomains: allowlistedDomains(),
    // Fail closed twice: isServerVerified already returns false on any
    // error, and the wrapper below swallows anything unexpected.
    isServerVerified: async (domain: string): Promise<boolean> => {
      if (!cfg) return false;
      try {
        return await isServerVerified(domain, cfg);
      } catch {
        return false;
      }
    },
  };
}

/**
 * Installs the gate on `ctx`. Matches the documented hook-plugin pattern
 * (docs/cookbook/extension-cookbook.md: `ctx.on('tools/pre-execute',
 * async (exec, next) => ...)` returning a PreToolDecision).
 */
export function installAuthGate(ctx: Context): void {
  const gate = gateContext();
  ctx.on("tools/pre-execute", async (exec: ToolExecution, next): Promise<PreToolDecision> => {
    const decision = await decide(
      {
        toolName: exec.name,
        arguments: (exec.arguments ?? {}) as Record<string, unknown>,
      },
      gate,
    );
    if (decision.kind === "deny") return decision;
    return next();
  });
}
