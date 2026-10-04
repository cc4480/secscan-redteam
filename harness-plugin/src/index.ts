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
 * headers (env SECSCAN_MCP_TOKEN); verified domains come from the SecScan
 * server alone (no allowlist env var). Secrets via env, never in files.
 */

import { ROLE_MODEL_POLICY } from "@secscan/redteam-llm-router";
import type { Context, PluginModule } from "./harness-types.js";
import { installAuthGate } from "./auth-gate.js";
import { REDTEAM_PROFILE } from "./redteam-profile.js";

export const name = "secscan-redteam";
// 'tools' for the pre-execute hook surface, 'systemPrompt' for the section registry.
export const inject = ["tools", "systemPrompt"];

const MODEL_POLICY_LINE = `Member model policy: ${ROLE_MODEL_POLICY.coordinator.model} for ` +
  `coordinator/recon/reporter; ${ROLE_MODEL_POLICY.exploiter.model} for exploiter reasoning.`;

const USAGE_SECTION = `## Red-team engagement protocol (secscan-redteam)

You are operating a scoped, authorized penetration test as part of a red team.
Team: coordinator (lead), recon (surface mapping), exploiter (dynamic testing),
reporter (client report). ${MODEL_POLICY_LINE}

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
    // TODO: 117 has no documented meaning in this repo — it was picked to
    // sort after other known sections in testing, not derived from a
    // published ordering scheme. Verify against the host harness's actual
    // systemPrompt.section() ordering docs before relying on it.
    order: 117,
    text: USAGE_SECTION,
  });

  // REDTEAM_PROFILE is NOT consumed by anything yet — no team-spawning plugin
  // exists in this repo (the live multi-agent implementation is the
  // standalone runner, which is independent of this file). This is forward
  // scaffolding for a future harness team plugin; kept as a shape reference
  // so it type-checks and stays current (see redteam-profile.ts header).
  void REDTEAM_PROFILE;
}

export const plugin: PluginModule = { name, inject, apply };
