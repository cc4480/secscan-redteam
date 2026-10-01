/**
 * secscan-redteam harness plugin.
 *
 * Install: `dsh plugin --profile <name> add /path/to/secscan-redteam/harness-plugin`
 * (the cordis.patch.yml in this directory shows the bundle-patch equivalent).
 *
 * On apply, the plugin:
 *   1. Connects the MCP bridge and registers the real SecScan tools
 *      (seclayer_scan, seclayer_list_scans, seclayer_get_report).
 *   2. Installs the auth gate as a `tools/pre-execute` hook: any active-testing
 *      call against an unverified domain is denied with instructions.
 *   3. Adds a "red-team" usage section to the system prompt so the model knows
 *      the engagement protocol and the team roles.
 *
 * Config (cordis.yml — secrets via env, never in the file):
 *   secscan-redteam:
 *     seclayerApiKey: !!js process.env.SECLAYER_API_KEY
 *     mcpCommand: "npx"                 # optional override
 *     mcpArgs: ["-y", "@seclayer/mcp"]  # optional override
 */

import type { HarnessContext, PluginModule, ToolExecution } from "./harness-types.js";
import { McpBridge, registerMcpTools } from "./mcp-bridge.js";
import { REDTEAM_PROFILE } from "./redteam-profile.js";

export const name = "secscan-redteam";
export const inject = ["tools", "systemPrompt"];

interface PluginConfig {
  seclayerApiKey?: string;
  mcpCommand?: string;
  mcpArgs?: string[];
}

const USAGE_SECTION = `## Red-team engagement protocol (secscan-redteam)

You are operating a scoped, authorized penetration test as part of a red team.
Team: coordinator (lead), recon (surface mapping), exploiter (dynamic testing),
reporter (client report). Member model policy: deepseek-v4-flash for
recon/coordinator/reporter; deepseek-v4-pro for exploiter reasoning.

Loop for every specialist: REASON → ACT (one tool call) → OBSERVE. Chase
surprises, not checklists. The tools available are the bridged SecScan MCP
tools: seclayer_scan (baseline + aggressive tiers), seclayer_list_scans,
seclayer_get_report.

HARD RULE: active testing (aggressive scans, crafted payloads, any request
designed to trigger a vulnerability) is allowed ONLY against targets whose
domain ownership is proven via DNS TXT (_seclayer-challenge.<domain>) or the
well-known verification file. Unverified targets get passive recon only.
The auth gate enforces this at the tool layer; do not attempt to bypass it.`;

async function installAuthGate(
  ctx: HarnessContext,
  verifyOwnership: (domain: string) => Promise<boolean>,
): Promise<void> {
  // Mirrors the documented hook-plugin pattern (extension-cookbook.md).
  ctx.on("tools/pre-execute", async (exec: ToolExecution, next) => {
    if (exec.toolName !== "seclayer_scan") return next();

    const args = exec.arguments as { url?: string; aggressive?: boolean };
    const url = args.url ?? "";
    let domain = "";
    try {
      domain = new URL(url).hostname.toLowerCase();
    } catch {
      return {
        kind: "deny",
        reason: `[auth-gate] seclayer_scan denied: '${url}' is not a valid URL.`,
      };
    }

    // Passive (standard-tier) scans are always allowed — they are recon, not attack.
    if (!args.aggressive) return next();

    // Aggressive tier = active probing → ownership proof required.
    const ok = await verifyOwnership(domain);
    if (!ok) {
      return {
        kind: "deny",
        reason:
          `[auth-gate] seclayer_scan (aggressive=true) denied for ${domain}: ` +
          `no domain-ownership proof found. Add a DNS TXT record at ` +
          `_seclayer-challenge.${domain} containing the engagement token, or serve the ` +
          `token at https://${domain}/.well-known/seclayer-verification.txt, then retry. ` +
          `Standard (passive) scans remain available.`,
      };
    }
    return next();
  });
}

export function apply(ctx: HarnessContext, rawConfig: Record<string, unknown>): Promise<void> {
  const config = rawConfig as PluginConfig;

  // Allow cordis.yml to inject the key; fall back to the environment.
  if (config.seclayerApiKey && !process.env["SECLAYER_API_KEY"]) {
    process.env["SECLAYER_API_KEY"] = config.seclayerApiKey;
  }

  const bridge = new McpBridge({
    command: config.mcpCommand,
    args: config.mcpArgs,
  });

  return (async () => {
    const names = await registerMcpTools(ctx, bridge);
    // eslint-disable-next-line no-console
    console.log(`[secscan-redteam] bridged MCP tools: ${names.join(", ")}`);

    // Lazy import keeps this package dependency-free at install time.
    const { checkTxtRecord } = await import("@secscan/redteam-auth-gate");
    await installAuthGate(ctx, async (domain: string) => {
      // The engagement token is supplied per-engagement via env; without one
      // there is nothing to match, so verification fails closed.
      const token = process.env["SECSCAN_ENGAGEMENT_TOKEN"];
      if (!token) return false;
      return checkTxtRecord(domain, token);
    });

    ctx.systemPrompt.addSection("secscan-redteam", 117, USAGE_SECTION);
    void REDTEAM_PROFILE; // consumed by the team plugin / runner; kept as the source of truth
  })();
}

export const plugin: PluginModule = { name, inject, apply };
