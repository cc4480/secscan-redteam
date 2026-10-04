/**
 * secscan-redteam harness plugin.
 *
 * v0.2: the SecScan connection moved to the harness-NATIVE MCP client.
 * The old design spawned the legacy `@seclayer/mcp` stdio server, which spoke
 * to the retired seclayer.io X-API-Key backend — that backend no longer serves
 * the API. The live product exposes a remote MCP endpoint,
 * https://secscan.us/api/mcp (Streamable HTTP, `Authorization: Bearer <token>`
 * with an MCP-scope token), whose tools the harness connects to natively via
 * @deepseek-ai/dsh-mcp-client (declared in this directory's cordis.patch.yml).
 * This plugin no longer bridges anything itself.
 *
 * On apply, the plugin:
 *   1. Installs the auth gate as a `tools/pre-execute` hook: any scan call
 *      that explicitly requests active/intrusive testing against a domain
 *      without ownership proof is denied with remediation instructions.
 *      Passive scans are always allowed. (See auth-gate.ts.)
 *   2. Adds the red-team engagement protocol as a system-prompt section via
 *      `ctx.systemPrompt.section({ name, order, text })`.
 *
 * Config: none. The SecScan MCP token lives in the dsh-mcp-client entry's
 * headers (env SECSCAN_MCP_TOKEN), and the per-engagement verified-domain
 * allowlist in env SECSCAN_VERIFIED_DOMAINS. Secrets via env, never in files.
 */

import type { Context, PluginModule } from "./harness-types.js";
import { installAuthGate } from "./auth-gate.js";
import { REDTEAM_PROFILE } from "./redteam-profile.js";

export const name = "secscan-redteam";
// 'tools' for the pre-execute hook surface, 'systemPrompt' for the section registry.
export const inject = ["tools", "systemPrompt"];

const USAGE_SECTION = `## Red-team engagement protocol (secscan-redteam)

You are operating a scoped, authorized penetration test as part of a red team.
Team: coordinator (lead), recon (surface mapping), exploiter (dynamic testing),
reporter (client report). Member model policy: deepseek-v4.1-flash for
recon/coordinator/reporter; deepseek-v4.1-pro for exploiter reasoning.

SecScan tools (via the native MCP connection, namespaced mcp__secscan__*):
scan_url (start a scan; passive unless the target domain is verified),
get_scan_status (progress; wait_seconds up to 60 returns the finished report),
get_report (findings with evidence, fixes, and fix prompts, paginated),
list_recent_scans, list_verified_domains, start_domain_verification,
check_domain_verification, get_account.

Loop for every specialist: REASON → ACT (one tool call) → OBSERVE. Chase
surprises, not checklists.

HARD RULE: active testing (aggressive scans, crafted payloads, any request
designed to trigger a vulnerability) is allowed ONLY against domains with
proven ownership — see mcp__secscan__list_verified_domains, and verify new
ones with start_domain_verification / check_domain_verification. Unverified
targets get passive recon only. The auth gate enforces this at the tool layer;
do not attempt to bypass it.`;

export function apply(ctx: Context): void {
  installAuthGate(ctx);

  ctx.systemPrompt.section({
    name: "secscan-redteam",
    order: 117,
    text: USAGE_SECTION,
  });

  void REDTEAM_PROFILE; // consumed by the team plugin / runner; kept as the source of truth
}

export const plugin: PluginModule = { name, inject, apply };
