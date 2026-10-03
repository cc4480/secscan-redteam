/**
 * SecScan MCP + web prober tool definitions.
 */
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";

export const MCP_TOOLS: JsonSchemaTool[] = [
  {
    name: "scan_url",
    description:
      "Run a SecScan assessment of a URL. Costs one scan credit. aggressive=true runs the active test tier (injection, XSS, SSRF…) — allowed only on ownership-verified domains; the runner denies it otherwise.",
    parameters: {
      type: "object",
      properties: { url: { type: "string" }, aggressive: { type: "boolean" } },
      required: ["url"],
    },
  },
  {
    name: "get_scan_status",
    description: "Poll a scan until it completes. wait_seconds up to 60; returns the report when done.",
    parameters: {
      type: "object",
      properties: { scan_id: { type: "string" }, wait_seconds: { type: "number" } },
      required: ["scan_id"],
    },
  },
  {
    name: "get_report",
    description: "Fetch a full past report (read-only, free).",
    parameters: { type: "object", properties: { scan_id: { type: "string" } }, required: ["scan_id"] },
  },
  {
    name: "list_recent_scans",
    description: "Recall previous scans (read-only, free). Prefer this over re-scanning.",
    parameters: { type: "object", properties: { limit: { type: "number" } } },
  },
  {
    name: "get_account",
    description: "Check scan credits remaining (read-only, free).",
    parameters: { type: "object", properties: {} },
  },
];

export const PROBE_TOOL: JsonSchemaTool = {
  name: "http_probe",
  description:
    "Send ONE HTTP request to an in-scope host to test a specific hypothesis. In-scope hosts only (runner-enforced), non-destructive. Include attackId (ATT&CK, e.g. T1190), category (logic|functionality|validation), and a one-sentence hypothesis. Full-battery engagements: also include targetProfile (secscan|seclayer|windows|linux) — host targets are never inferred from the URL, tag them explicitly.",
  parameters: {
    type: "object",
    properties: {
      method: { type: "string" },
      url: { type: "string" },
      headers: { type: "object" },
      body: { type: "string" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["secscan", "seclayer", "windows", "linux"] },
      hypothesis: { type: "string" },
    },
    required: ["method", "url", "category"],
  },
};

export const BURST_PROBE_TOOL: JsonSchemaTool = {
  name: "burst_probe",
  description:
    "Resilience/rate-limit check — NOT a flood or DoS tool. Fires one FIXED-size batch of concurrent GET/HEAD requests (size is not adjustable) to observe whether the target rate-limits at all. One-shot per endpoint per engagement; calling it again on the same path is refused. DoS/resource exhaustion stays off regardless of mode or target.",
  parameters: {
    type: "object",
    properties: {
      url: { type: "string" },
      method: { type: "string", enum: ["GET", "HEAD"] },
      attackId: { type: "string" },
      hypothesis: { type: "string" },
    },
    required: ["url"],
  },
};

export const READ_TOOLS = MCP_TOOLS.filter((t) => t.name !== "scan_url");
