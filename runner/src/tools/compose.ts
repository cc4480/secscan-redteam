/**
 * Composed tool sets per phase (withBatteryItem tagging).
 */
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";
import { BURST_PROBE_TOOL, MCP_TOOLS, PROBE_TOOL, READ_TOOLS } from "./web.js";
import { HOST_TOOLS } from "./host.js";
import { MSF_EXEC_TOOL } from "./msf.js";
import { ABORT_TOOL, QUERY_REGISTRY_TOOL, RECORD_FINDING_TOOL, RECORD_ITEM_VERDICT_TOOL, RECORD_KILLED_TOOL, UPDATE_TARGET_MAP_TOOL } from "./bookkeeping.js";

const BATTERY_ITEM_HINT =
  ' Always include batteryItem: the battery item ID under test (e.g. "SS-042"). ' +
  "The runner tracks one verdict per battery item and the battery cannot report complete while any item is pending.";

function withBatteryItem(t: JsonSchemaTool): JsonSchemaTool {
  const params = (t.parameters ?? {}) as { properties?: Record<string, unknown> };
  return {
    ...t,
    description: t.description + BATTERY_ITEM_HINT,
    parameters: {
      ...params,
      properties: {
        ...(params.properties ?? {}),
        batteryItem: {
          type: "string",
          description:
            'Battery item ID this action tests (e.g. "SS-042", "WS-023"). Untagged actions cannot be reconciled to an item.',
        },
      },
    },
  };
}

export const RECON_TOOLS = [...MCP_TOOLS, ...HOST_TOOLS.map(withBatteryItem), withBatteryItem(MSF_EXEC_TOOL), QUERY_REGISTRY_TOOL, UPDATE_TARGET_MAP_TOOL, withBatteryItem(RECORD_ITEM_VERDICT_TOOL)];
export const EXPLOIT_TOOLS = [...READ_TOOLS, withBatteryItem(PROBE_TOOL), withBatteryItem(BURST_PROBE_TOOL), ...HOST_TOOLS.map(withBatteryItem), withBatteryItem(MSF_EXEC_TOOL), QUERY_REGISTRY_TOOL, withBatteryItem(RECORD_FINDING_TOOL), withBatteryItem(RECORD_KILLED_TOOL), withBatteryItem(RECORD_ITEM_VERDICT_TOOL)];
/** The coordinator's command tools: no probes, only command authority. */
export const COMMAND_TOOLS = [ABORT_TOOL];
