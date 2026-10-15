/**
 * MCP surface for the runner's EXECUTOR tools (v0.30.0).
 *
 * The 13 tools in mcp-tools.ts drive ENGAGEMENTS. These 26 drive the tools
 * INSIDE a running engagement: nuclei_exec, msf_exec, http_probe, ssh_exec,
 * ad_enum, query_registry, and the rest. Without them an operator could start
 * an engagement and read its results but never reach the tooling itself, which
 * is the whole point of a harness-connected red team.
 *
 * Every tool requires an engagementId, and every call goes through
 * dispatchLiveTool -> dispatchTool, so the kill switch, the tier ladder,
 * auto-halt, the per-host rate limiter and the per-item variant cap all run
 * first. A Tier-1 call to `msf_exec run` is refused with the reason, exactly as
 * it would be for the engagement's own agents. This file adds reach, not
 * authority.
 *
 * The schemas are NOT duplicated: they are the same JsonSchemaTool objects the
 * agents are given, with `engagementId` added. A tool that changes its
 * parameters changes here automatically — the alternative, a hand-copied
 * schema, drifts the moment someone edits tools/*.ts.
 */

import { MCP_TOOLS, READ_TOOLS, PROBE_TOOL, BURST_PROBE_TOOL } from "../tools/web.js";
import { HOST_TOOLS } from "../tools/host.js";
import { MSF_EXEC_TOOL } from "../tools/msf.js";
import { NUCLEI_EXEC_TOOL } from "../tools/nuclei.js";
import { NMAP_EXEC_TOOL } from "../tools/nmap.js";
import {
  ABORT_TOOL,
  QUERY_REGISTRY_TOOL,
  RECORD_FINDING_TOOL,
  RECORD_ITEM_VERDICT_TOOL,
  RECORD_KILLED_TOOL,
  UPDATE_TARGET_MAP_TOOL,
} from "../tools/bookkeeping.js";
import { VARIANT_LIST_TOOL } from "../variants/tool.js";
import { TOOLS } from "./mcp-tools.js";
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";
import { dispatchLiveTool, getLive } from "../live.js";

export interface ExecToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  run: (args: Record<string, unknown>) => Promise<string>;
}

/**
 * Add the required engagementId to a tool's schema.
 *
 * Required rather than optional on purpose: defaulting to "the only running
 * engagement" would make a tool call succeed against an engagement the caller
 * never named, which is exactly the kind of implicit targeting a red-team run
 * must not do.
 */
function bindToEngagement(t: JsonSchemaTool): ExecToolDef {
  const params = (t.parameters ?? {}) as {
    properties?: Record<string, unknown>;
    required?: string[];
  };
  return {
    name: t.name,
    description:
      t.description +
      " Requires engagementId: the RUNNING engagement whose context this executes in. " +
      "Call list_live_engagements to see what is running — an engagement that has finished is no longer executable.",
    inputSchema: {
      type: "object",
      properties: {
        engagementId: {
          type: "string",
          description: "The running engagement id (e.g. eng-2026-10-15-y8fo).",
        },
        ...(params.properties ?? {}),
      },
      required: ["engagementId", ...(params.required ?? [])],
    },
    run: async (args: Record<string, unknown>): Promise<string> => {
      const id = typeof args["engagementId"] === "string" ? args["engagementId"] : "";
      if (!id) throw new Error("engagementId is required");
      const rest = { ...args };
      delete rest["engagementId"];
      const d = await dispatchLiveTool(id, t.name, rest);
      // The caller gets the tool's own result verbatim: it is already written
      // for an agent to read, and rewrapping it would only lose the detail that
      // says WHY a call was refused (tier, halt, cap, scope).
      return d.result;
    },
  };
}

/**
 * All executor tools, reachable only against a live engagement.
 *
 * The composed sets in tools/compose.ts overlap — MCP_TOOLS and READ_TOOLS both
 * carry get_scan_status / get_report / list_recent_scans / get_account — so they
 * are concatenated here and de-duplicated by name, first definition winning.
 * Exposing a name twice makes tools/call ambiguous (whichever Map entry was
 * written last silently wins) and reports a tool count that is not real.
 *
 * Names already served by the COCKPIT surface are also dropped. abort_engagement
 * exists in both: the cockpit one takes any engagement id and works cross-process
 * via abort.json, while the executor one would need a live Ctx. The cockpit
 * version is strictly more capable, and shadowing it would quietly downgrade an
 * operator's kill switch — the one tool that must never behave surprisingly.
 */
const COCKPIT_OWNED = new Set(TOOLS.map((t) => t.name));

function collect(): JsonSchemaTool[] {
  const out: JsonSchemaTool[] = [];
  const seen = new Set<string>();
  for (const t of [
    ...MCP_TOOLS,
    ...READ_TOOLS,
    PROBE_TOOL,
    BURST_PROBE_TOOL,
    ...HOST_TOOLS,
    MSF_EXEC_TOOL,
    NUCLEI_EXEC_TOOL,
    NMAP_EXEC_TOOL,
    QUERY_REGISTRY_TOOL,
    UPDATE_TARGET_MAP_TOOL,
    RECORD_FINDING_TOOL,
    RECORD_KILLED_TOOL,
    RECORD_ITEM_VERDICT_TOOL,
    VARIANT_LIST_TOOL,
    ABORT_TOOL,
  ]) {
    if (seen.has(t.name) || COCKPIT_OWNED.has(t.name)) continue;
    seen.add(t.name);
    out.push(t);
  }
  return out;
}

export const EXEC_TOOLS: ExecToolDef[] = collect().map(bindToEngagement);

export const EXEC_TOOLS_BY_NAME = new Map(EXEC_TOOLS.map((t) => [t.name, t]));

/** Just the names — used by the tests that pin the surface size. */
export const EXEC_TOOL_NAMES: string[] = EXEC_TOOLS.map((t) => t.name);

/**
 * The discovery tool. An agent that cannot tell what is live cannot use any of
 * the 26, and "which engagement?" is the first question every one of them
 * requires answering.
 */
export const LIST_LIVE_TOOL: ExecToolDef = {
  name: "list_live_engagements",
  description:
    "Engagements running IN THIS PROCESS, with the phase, tier, environment, in-scope hosts and the role an operator call would run as. " +
    "Only these accept the executor tools (nuclei_exec, msf_exec, http_probe, ssh_exec, …). " +
    "An engagement that has finished — or that was launched from a different process, such as the CLI — is not listed and cannot be driven this way; " +
    "use get_engagement and get_feed to read a finished one.",
  inputSchema: { type: "object", properties: {} },
  run: async (): Promise<string> => {
    const { listLive } = await import("../live.js");
    const rows = listLive();
    if (rows.length === 0) {
      return "No engagements are running in this process. Start one with start_engagement; the executor tools become available while it runs.";
    }
    return JSON.stringify(rows, null, 2);
  },
};

/** Guard used by the endpoint: does this tool drive a live engagement? */
export function isExecTool(name: string): boolean {
  return EXEC_TOOLS_BY_NAME.has(name) || name === LIST_LIVE_TOOL.name;
}

/** Is the named engagement live here? Exposed so the endpoint can pre-refuse. */
export function engagementIsLive(id: string): boolean {
  return getLive(id) !== undefined;
}
