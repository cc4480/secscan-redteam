/**
 * MCP tool surface for the RedTeam console (v0.29.0).
 *
 * Each tool delegates to the SAME route handler the console UI calls, so the
 * safety core, launch validation, tier rules and approval logging all apply
 * unchanged. This file adds reach, not authority.
 *
 * The handlers write to a ServerResponse, so `capture()` stands in for one and
 * collects what they wrote — that is the entire adapter, and it is why no
 * existing handler had to change.
 */

import type { ServerResponse } from "node:http";
import { handleList, handleDetail, handleLaunch } from "./routes/engagements.js";
import { handleFindings, handleProof } from "./routes/findings.js";
import { handleCoverage, handleCompliance } from "./routes/coverage.js";
import { handleAbort, handleEscalate, handleReverify, handleWatchProfiles, handleWatchTrigger } from "./routes/actions.js";
import { engagementDir, type UiStore } from "./store.js";
import { readEvents } from "../events.js";

/** What a handler produced, instead of writing it to a socket. */
export interface Captured {
  status: number;
  body: unknown;
}

/** Stand in for ServerResponse. Handlers only ever call writeHead and end. */
export function capture(): { res: ServerResponse; result: () => Captured } {
  let status = 200;
  let raw = "";
  const fake = {
    writeHead(s: number): unknown {
      status = s;
      return fake;
    },
    end(b?: unknown): unknown {
      if (typeof b === "string") raw += b;
      else if (Buffer.isBuffer(b)) raw += b.toString("utf8");
      return fake;
    },
    setHeader(): unknown {
      return fake;
    },
    write(): boolean {
      return true;
    },
  };
  return {
    res: fake as unknown as ServerResponse,
    result: (): Captured => {
      if (raw === "") return { status, body: { ok: true } };
      try {
        return { status, body: JSON.parse(raw) as unknown };
      } catch {
        return { status, body: raw };
      }
    },
  };
}

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  run: (store: UiStore, args: Record<string, unknown>) => Promise<Captured>;
}

const str = (d: string): Record<string, unknown> => ({ type: "string", description: d });
const req = (d: string): Record<string, unknown> => ({ type: "string", description: d });
const ID_ONLY = (): Record<string, unknown> => ({
  type: "object",
  properties: { id: req("Engagement id") },
  required: ["id"],
  additionalProperties: false,
});

/** Wrap a handler that takes (store, res, id). */
function byId(fn: (store: UiStore, res: ServerResponse, id: string) => void): ToolDef["run"] {
  return async (store, a) => {
    const c = capture();
    fn(store, c.res, String(a["id"]));
    return c.result();
  };
}

export const TOOLS: ToolDef[] = [
  {
    name: "list_engagements",
    description: "List every engagement this console knows: live runs first, then history.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    run: async (store) => {
      const c = capture();
      handleList(store, c.res);
      return c.result();
    },
  },
  {
    name: "get_engagement",
    description: "State snapshot for one engagement plus which artifacts exist (report, compliance pack, attestation, safety manifest, verdicts, PoC bundles).",
    inputSchema: ID_ONLY(),
    run: byId(handleDetail),
  },
  {
    name: "start_engagement",
    description:
      "Launch an engagement. Same validation as the CLI: target, mode, objective and a non-empty scope are required. "
      + "Active testing still requires proven domain ownership and production still requires confirmation — this tool adds reach, not authority.",
    inputSchema: {
      type: "object",
      properties: {
        target: req("Target name"),
        mode: { type: "string", enum: ["red", "black"], description: "red = full knowledge, black = no prior knowledge" },
        objective: req("Engagement objective"),
        scope: { type: "array", items: { type: "string" }, description: "Exact in-scope hosts. Required, non-empty." },
        client: str("Client name for the report"),
        operatorName: str("Named operator accountable for this run"),
        tier: { type: "integer", enum: [0, 1, 2], description: "Autonomy tier; production defaults to 1" },
        environment: { type: "string", enum: ["staging", "production"] },
        confirmProduction: { type: "boolean", description: "Required to run against production" },
        confirmTier2Production: { type: "boolean", description: "Required for Tier 2 on production" },
        fullBattery: { type: "boolean", description: "Run the full battery (default true)" },
        targets: {
          type: "array",
          items: { type: "string", enum: ["secscan", "seclayer", "webapp", "windows", "linux"] },
          description: "Optional battery subset. Omit for the default vendor targets. Use [\"webapp\"] to run the WA-* battery against a client web application.",
        },
        maxActions: {
          type: "integer",
          description:
            "Cap on agent actions for the whole engagement (default 60). A full battery is 418 items across four "
            + "target families, and a coordinator that reconciles them one verdict at a time spends far more than the "
            + "default before it reaches a single probe — the run then halts on the cap with the battery half-answered "
            + "and no way to continue it. Raise this for full-battery work; the cap exists to stop a runaway loop, not "
            + "to bound honest coverage.",
        },
        excludedTechniques: { type: "array", items: { type: "string" } },
        dryRun: { type: "boolean", description: "Plan only; touch nothing" },
      },
      required: ["target", "mode", "objective", "scope"],
      additionalProperties: false,
    },
    run: async (store, a) => {
      const c = capture();
      await handleLaunch(store, {} as never, c.res, a);
      return c.result();
    },
  },
  {
    name: "get_feed",
    description:
      "Recent operation events by sequence. Poll with after_seq for new events. "
      + "The console's own feed is SSE; this is the snapshot form an agent can consume.",
    inputSchema: {
      type: "object",
      properties: {
        id: req("Engagement id"),
        after_seq: { type: "integer", description: "Return events after this sequence number" },
        limit: { type: "integer", description: "Max events (default 200)" },
      },
      required: ["id"],
      additionalProperties: false,
    },
    run: async (store, a) => {
      const dir = engagementDir(store.engagementsDir, String(a["id"]));
      if (!dir) return { status: 404, body: { error: "unknown engagement" } };
      const after = Number(a["after_seq"] ?? 0);
      const limit = Number(a["limit"] ?? 200);
      return {
        status: 200,
        body: { events: readEvents(dir, Number.isFinite(after) ? after : 0, Number.isFinite(limit) ? limit : 200) },
      };
    },
  },
  {
    name: "get_findings",
    description: "Validated findings for an engagement.",
    inputSchema: ID_ONLY(),
    run: byId(handleFindings),
  },
  {
    name: "get_proof",
    description: "Proof-of-exploitation bundle for one finding: canary marker sent/echoed, audit-log derivation, negative proof for killed hypotheses.",
    inputSchema: {
      type: "object",
      properties: { id: req("Engagement id"), finding: req("Finding id") },
      required: ["id", "finding"],
      additionalProperties: false,
    },
    run: async (store, a) => {
      const c = capture();
      handleProof(store, c.res, String(a["id"]), String(a["finding"]));
      return c.result();
    },
  },
  {
    name: "get_coverage",
    description: "Battery coverage, reconciled per category x target cell and per item, with the verdict ledger.",
    inputSchema: ID_ONLY(),
    run: byId(handleCoverage),
  },
  {
    name: "get_compliance",
    description: "Compliance pack mapping (PCI DSS v4.0.1 Req 11.4 / SOC 2 CC6.1, CC6.6, CC7.1 / ISO 27001:2022 A.8.8).",
    inputSchema: ID_ONLY(),
    run: byId(handleCompliance),
  },
  {
    name: "abort_engagement",
    description: "Kill switch. Stops a live run; works on CLI-launched runs too.",
    inputSchema: {
      type: "object",
      properties: { id: req("Engagement id"), reason: str("Why the run is being stopped") },
      required: ["id"],
      additionalProperties: false,
    },
    run: async (store, a) => {
      const c = capture();
      handleAbort(store, c.res, String(a["id"]), a);
      return c.result();
    },
  },
  {
    name: "escalate",
    description:
      "Change an engagement's autonomy tier mid-run. Raising it requires an operator name and a reason; lowering is free but logged. "
      + "Tier 2 on production additionally needs explicit confirmation.",
    inputSchema: {
      type: "object",
      properties: {
        id: req("Engagement id"),
        tier: { type: "integer", enum: [0, 1, 2] },
        operator: str("Named operator approving a raise"),
        reason: str("Justification, recorded in the approval log"),
        confirmTier2Production: { type: "boolean", description: "Required to raise to Tier 2 on production" },
      },
      required: ["id", "tier"],
      additionalProperties: false,
    },
    run: async (store, a) => {
      const c = capture();
      handleEscalate(store, c.res, String(a["id"]), a);
      return c.result();
    },
  },
  {
    name: "reverify",
    description: "Replay a proof-of-exploitation bundle with a fresh canary. The bundle is resolved from the engagement's own poc/ directory.",
    inputSchema: {
      type: "object",
      properties: { id: req("Engagement id"), finding: req("Finding id (the poc/<finding>.json bundle to replay)") },
      required: ["id", "finding"],
      additionalProperties: false,
    },
    run: async (store, a) => {
      const c = capture();
      await handleReverify(store, c.res, a);
      return c.result();
    },
  },
  {
    name: "watch_profiles",
    description: "List the continuous-testing watch profiles available to trigger.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    run: async () => {
      const c = capture();
      handleWatchProfiles(c.res, new URLSearchParams());
      return c.result();
    },
  },
  {
    name: "watch_trigger",
    description: "Fire a watch profile: a continuous-testing run with rolling baselines and drift classification.",
    inputSchema: {
      type: "object",
      properties: { profile: req("Watch profile name"), trigger: str("Optional drift trigger") },
      required: ["profile"],
      additionalProperties: false,
    },
    run: async (store, a) => {
      const c = capture();
      handleWatchTrigger(store, c.res, a);
      return c.result();
    },
  },
];

export const TOOLS_BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));
