/**
 * secscan-redteam harness plugin.
 *
 * v0.3: the engagement is a TEAM, not one agent.
 *
 * v0.2 moved the SecScan connection to the harness-native MCP client (the old
 * design spawned a legacy `@seclayer/mcp` stdio server against the retired
 * seclayer.io X-API-Key backend). That is unchanged.
 *
 * What v0.3 adds: the plugin now drives the harness Agent Teams layer so one
 * session becomes an engagement team. On apply it:
 *
 *   1. Installs the auth gate as a `tools/pre-execute` hook: any scan call that
 *      explicitly requests active/intrusive testing against a domain without
 *      ownership proof is denied with remediation instructions. Passive scans
 *      are always allowed. (See auth-gate.ts.) This is enforced in CODE and is
 *      the only guarantee here that does not depend on the model obeying.
 *
 *   2. Adds the red-team engagement protocol as a system-prompt section that
 *      appoints the session agent ENGAGEMENT LEAD and hands it the roster, the
 *      role briefs and the task DAG it must instantiate.
 *
 *   3. Consumes REDTEAM_PROFILE to build that section. The briefs and the task
 *      list are generated from the profile, so the prompt cannot drift from the
 *      role definition — previously REDTEAM_PROFILE was `void`-referenced
 *      scaffolding that nothing read.
 *
 * The roster itself is spawned by the MODEL through the Agent Teams tools
 * (`spawn_teammate`, `team_task_*`), not by this plugin: they are model-facing
 * tools, and only the Team Lead may call them. This plugin's job is to make the
 * Lead know exactly what team to build. Mounting the Agent Teams layer itself is
 * the bundle's job — see ../desktop-bundle/cordis.patch.yml, which mounts
 * @deepseek-ai/dsh-experimental-agent-team, its tool package and its UI, and
 * disables plain subagent delegation so nothing escapes the roster.
 *
 * Note the two agent systems and keep them straight. This harness-side team is
 * NOT the engagement team: the engagement team is the runner's own multi-agent
 * implementation (runner/src/agents.ts + src/prompts/), with the safety core
 * wrapped around every action. Harness teammates have none of that — no safety
 * core, no tier rules, no authorization gate — so engagements are driven through
 * the runner over MCP (mcp__redteam__*) and harness teammates are convenience
 * only.
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

/** The specialists the Lead must spawn, generated from the profile. */
function rosterLines(): string {
  return REDTEAM_PROFILE.members.map((member) =>
    `- \`${member.name}\` — ${member.role}\n  Brief: ${member.executionPrompt ?? "(none)"}`
  ).join("\n");
}

/** The task DAG the Lead must put on the shared board, generated from the profile. */
function taskLines(): string {
  return REDTEAM_PROFILE.tasks.map((task) => {
    const deps = task.dependencies === undefined || task.dependencies.length === 0
      ? "no dependencies"
      : `after ${task.dependencies.join(", ")}`;
    return `- \`${task.id}\` — ${task.subject} (owner: ${task.assignee}; ${deps})`;
  }).join("\n");
}

function usageSection(): string {
  return `## SecScan red team — agent team (secscan-redteam)

You are the ENGAGEMENT LEAD of a red team, running a scoped, authorized
penetration test. You command specialists; you do not do their work yourself.
The session's agent is the Lead — there is no separate "coordinator" teammate
to spawn.

${REDTEAM_PROFILE.description}

### Your first action: build the team

You have Agent Teams tools (spawn_teammate, send_message, list_agents,
wait_agent, interrupt_agent, team_task_create, team_task_list, team_task_get,
team_task_update). Plain subagent delegation is deliberately DISABLED so that
every piece of work is on the roster and on the board where it can be audited.

Spawn each specialist with \`spawn_teammate\`, passing its brief VERBATIM as the
\`prompt\` argument — these briefs are the role definitions and must not be
paraphrased or shortened:

${rosterLines()}

Then put the engagement on the shared task board with \`team_task_create\`,
preserving these dependencies so a task is claimable only when its predecessor
is complete:

${taskLines()}

Assign ownership with \`team_task_update\`. Once a task's dependencies are
complete, message its owner with \`send_message\` to start it — a teammate does
not need to be re-spawned, and an inactive teammate wakes when messaged.

### Engagement engine over MCP (mcp__redteam__*)

Beyond the scan tools, the runner's engagement engine is reachable directly:
start_engagement (launch a scoped run — the same validation and tier rules the
CLI enforces), get_engagement, get_feed (events by sequence), get_findings,
get_proof, get_coverage, get_compliance, escalate (operator + reason required),
reverify, abort_engagement (kill switch), watch_profiles, watch_trigger,
list_engagements.

The engine owns the safety core: per-host rate limits, PII redaction,
staging→production confirmation, auto-halt, the authorization gate and the
approval log. Nothing here bypasses it — driving an engagement through MCP adds
reach, not authority.

### Protocol

${REDTEAM_PROFILE.protocol}

### SecScan tools (native MCP, namespaced mcp__secscan__*)

scan_url (start a scan; passive unless the target domain is verified),
get_scan_status (progress; wait_seconds up to 60 returns the finished report),
get_report (findings with evidence, fixes, and fix prompts, paginated),
list_recent_scans, list_verified_domains, start_domain_verification,
check_domain_verification, get_account.

Every specialist loops: REASON → ACT (one tool call) → OBSERVE. Chase
surprises, not checklists.

### HARD RULES

1. Active testing (aggressive scans, crafted payloads, any request designed to
   trigger a vulnerability) is allowed ONLY against domains with proven
   ownership — check mcp__secscan__list_verified_domains, and verify new ones
   with start_domain_verification / check_domain_verification. Unverified
   targets get passive recon only.
2. The auth gate enforces rule 1 at the tool layer. Do not attempt to bypass
   it, and never ask a teammate to. Attempting to bypass the gate ends the
   engagement immediately and is reported as such.
3. A finding is not real until it has TWO independent observations. Report
   nothing on one.
4. Stay inside the authorized scope. Scope creep ends the engagement.
5. Non-destructive only: no data writes, no deletes, no resource exhaustion,
   no credential stuffing, no pivoting outside the scoped hosts.
6. ${MODEL_POLICY_LINE}`;
}

export function apply(ctx: Context): void {
  installAuthGate(ctx);

  ctx.systemPrompt.section({
    name: "secscan-redteam",
    // TODO: 117 has no documented meaning in this repo — it was picked to
    // sort after other known sections in testing, not derived from a
    // published ordering scheme. Verify against the host harness's actual
    // systemPrompt.section() ordering docs before relying on it.
    order: 117,
    text: usageSection(),
  });
}

export const plugin: PluginModule = { name, inject, apply };
