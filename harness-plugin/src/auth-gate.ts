/**
 * Auth gate: a `tools/pre-execute` hook that keeps active testing scoped.
 *
 * The SecScan MCP server (https://secscan.us/api/mcp, connected via the
 * harness-native @deepseek-ai/dsh-mcp-client) exposes its tools namespaced as
 * `mcp__<serverName>__<tool>` — e.g. `mcp__secscan__scan_url`. The server
 * itself only runs active tests against verified domains
 * (list_verified_domains / start_domain_verification /
 * check_domain_verification); this gate is the agent-layer backstop so an
 * explicit active-testing request can never dispatch without proof.
 *
 * Policy (fail-closed):
 *  - Passive scans (no active-testing flags in args) are recon, not attack:
 *    always allowed.
 *  - A call that explicitly requests active/intrusive testing is allowed ONLY
 *    if the target domain is proven:
 *      1. listed in SECSCAN_VERIFIED_DOMAINS (comma-separated, per engagement), OR
 *      2. a DNS TXT engagement-token proof via @secscan/redteam-auth-gate
 *         (supplementary; requires SECSCAN_ENGAGEMENT_TOKEN).
 *    Otherwise the call is denied with remediation instructions.
 *
 * Field names verified against @deepseek-ai/dsh-tools 0.0.1-rc.1:
 * ToolExecution has `name` (tool name) and `arguments` (unknown).
 */

import { checkTxtRecord } from "@secscan/redteam-auth-gate";
import type { Context, PreToolDecision, ToolExecution } from "./harness-types.js";

/** dsh-mcp-client namespaces server tools as mcp__<serverName>__<tool>. */
function isScanTool(toolName: string): boolean {
  return toolName === "scan_url" || toolName.endsWith("__scan_url");
}

const URL_KEYS = ["url", "target", "target_url", "site", "site_url"];

function targetDomain(args: Record<string, unknown>): string | null {
  for (const key of URL_KEYS) {
    const v = args[key];
    if (typeof v === "string" && v.length > 0) {
      try {
        return new URL(v).hostname.toLowerCase();
      } catch {
        // Not a parseable URL under this key — try the next one.
      }
    }
  }
  return null;
}

/** True when the model explicitly asks for active/intrusive testing. */
function wantsActiveTesting(args: Record<string, unknown>): boolean {
  for (const [k, v] of Object.entries(args)) {
    if (/aggress|active|intrusive/i.test(k) && !!v) return true;
    if (
      typeof v === "string" &&
      /^(aggressive|active|intrusive)([-_ ]?(test|scan|probe|mode|tier)s?)?$/i.test(v.trim())
    ) {
      return true;
    }
  }
  return false;
}

function verifiedDomains(): Set<string> {
  const raw = process.env["SECSCAN_VERIFIED_DOMAINS"] ?? "";
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
}

/**
 * Installs the gate on `ctx`. Matches the documented hook-plugin pattern
 * (docs/cookbook/extension-cookbook.md: `ctx.on('tools/pre-execute',
 * async (exec, next) => ...)` returning a PreToolDecision).
 */
export function installAuthGate(ctx: Context): void {
  ctx.on("tools/pre-execute", async (exec: ToolExecution, next): Promise<PreToolDecision> => {
    if (!isScanTool(exec.name)) return next();

    const args = (exec.arguments ?? {}) as Record<string, unknown>;

    // Passive scans are recon, not attack — always allowed.
    if (!wantsActiveTesting(args)) return next();

    const domain = targetDomain(args);

    // Proof path 1: explicit per-engagement verified-domain allowlist.
    if (domain && verifiedDomains().has(domain)) return next();

    // Proof path 2: DNS TXT engagement-token proof (fails closed: without
    // SECSCAN_ENGAGEMENT_TOKEN there is nothing to match, so this is false).
    if (domain) {
      const token = process.env["SECSCAN_ENGAGEMENT_TOKEN"];
      if (token) {
        try {
          if (await checkTxtRecord(domain, token)) return next();
        } catch {
          // DNS lookup failure fails closed — fall through to deny.
        }
      }
    }

    return {
      kind: "deny",
      reason:
        `[auth-gate] Active testing denied for ${domain ?? "unknown target"}: ` +
        `no domain-ownership proof on file. Verify ownership first with the ` +
        `mcp__secscan__start_domain_verification tool and confirm it with ` +
        `mcp__secscan__check_domain_verification (or list mcp__secscan__list_verified_domains ` +
        `to see what's already proven), then retry. Passive scans remain available.`,
    };
  });
}
