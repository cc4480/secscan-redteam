/**
 * SecLayer target profile — the MCP/API layer (https://secscan.us/api/mcp).
 *
 * EXHAUSTIVE battery (v0.7.0): surface × technique. Surfaces: MCP
 * initialize/handshake, capability negotiation, tools/list, tools/call for
 * EACH tool (seclayer_scan, seclayer_list_scans, seclayer_get_report) with
 * every parameter attacked individually, notifications, ping,
 * cancellation, progress, batching, the JSON-RPC layer itself, the auth
 * layer per method, and WAF behavior.
 *
 * Non-destructive always: benign canary targets only, no real bypass
 * campaigns, no emails to real users. Items needing setup say so in
 * `needs` — honestly.
 */

import type { TargetBatteryItem, TargetProfile } from "./types.js";
import { SECLAYER_PART_1 } from "./seclayer-part-1.js";
import { SECLAYER_PART_2 } from "./seclayer-part-2.js";
import { SECLAYER_PART_3 } from "./seclayer-part-3.js";

const SECLAYER_BATTERY: TargetBatteryItem[] = [
  ...SECLAYER_PART_1,
  ...SECLAYER_PART_2,
  ...SECLAYER_PART_3,
];

export const SECLAYER_PROFILE: TargetProfile = {
  id: "seclayer",
  name: "SecLayer — MCP/API layer",
  baseUrl: "https://secscan.us/api/mcp",
  kind: "mcp-api",
  authModel: "API-key auth per account; Streamable HTTP, MCP 2025-03-26, server secscan v1.1.0. Tools: seclayer_scan, seclayer_list_scans, seclayer_get_report.",
  scopeNotes: "In-scope: /api/mcp JSON-RPC surface. Same host as the webapp — path-scoped, not host-scoped. WAF quirk: Python urllib gets 403; curl with a normal UA works.",
  battery: SECLAYER_BATTERY,
};
