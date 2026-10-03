/**
 * Live engagement orchestration: authorize → plan → recon → exploit → report.
 *
 * LAYERING (deliberate):
 *  - FOUNDATION (DeepSeek via @secscan/redteam-llm-router — untouched): model
 *    calls, role→model routing, provider pluggability. `agentLoop` below is a
 *    thin REASON → ACT → OBSERVE driver over `completeForRole` — the harness
 *    feeds tasks to the foundation; the foundation executes.
 *  - CYBER LAYER (this package — all the value): role prompts + discipline,
 *    ATT&CK-mapped planning, the 3-category battery, technique fusion, the
 *    registry, ROE definition + enforcement, red/black mode behavior, the
 *    coordinator's decompose → delegate → observe → re-plan command loop,
 *    and reporter output.
 *
 * The runner — not the model — enforces the hard boundaries: ownership
 * verification, scope, technique exclusions, blackout windows, rate limits,
 * and stop conditions. Every tool call and every decision becomes a streamed
 * event.
 */

import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { completeForRole as routerCompleteForRole } from "@secscan/redteam-llm-router";
import type { AgentRole, ChatMessage, ChatResult, JsonSchemaTool, ToolCallRequest } from "@secscan/redteam-llm-router";
import { lookupTechnique } from "./attack.js";
import { EventLog } from "./events.js";
import {
  checkAuthorization,
  inBlackout,
  inTestWindow,
  scopeHosts,
  techniqueAllowed,
  urlInScope,
  type GateVerdict,
} from "./gate.js";
import { McpClient } from "./mcp.js";
import { WebProber, isPrivateOrLoopbackHost, type ProberLike } from "./prober.js";
import { coordinatorPrompt, exploiterPrompt, reconPrompt, reporterPrompt, taskPrompt } from "./prompts.js";
import {
  loadRegistryFile,
  queryRegistry,
  recordConfirmed,
  recordKilled,
  saveRegistryFile,
  seedRegistry,
} from "./registry.js";
import type {
  RegistryEntry,
  TargetFingerprint,
  VulnerabilityRegistry,
} from "./registry.js";
import type {
  ActorRole,
  EngagementEvent,
  EngagementInput,
  EngagementMode,
  EngagementPhase,
  EngagementResult,
  Finding,
  OperationPlan,
  PlanStep,
  ResolvedRunnerConfig,
  RulesOfEngagement,
} from "./types.js";
import { BATTERY_CATEGORIES, CATEGORY_LABELS } from "./battery.js";
import type { BatteryCategory } from "./battery.js";
import { activeTargets, inferTargetProfile, isTargetId, targetCellStatus, TARGET_PROFILES } from "./targets.js";
import type { TargetId } from "./targets.js";

export interface RunnerDeps {
  verify?: (domain: string, cfg: { endpoint: string; token: string }) => Promise<boolean>;
  completeForRole?: typeof routerCompleteForRole;
  /** Injectable for tests (defaults: real McpClient / WebProber). */
  mcp?: McpClient;
  prober?: ProberLike;
}

/** One entry in the shared target map (recon-written, whole-team-read). */
export interface TargetMapEntry {
  area: string;
  method: string;
  params?: string;
  authState?: string;
  attackId?: string;
  notes?: string;
}

/** A confirmed finding recorded live during exploitation (shared state). */
export interface LiveFinding {
  severity: string;
  title: string;
  vulnClass?: string;
  attackId: string;
  evidence: string;
  payload?: string;
}

/** A killed hypothesis recorded live during exploitation (shared state). */
export interface KilledLive {
  hypothesis: string;
  killingObservation: string;
  vulnClass?: string;
  attackId?: string;
  payload?: string;
}

interface Ctx {
  input: EngagementInput;
  config: ResolvedRunnerConfig;
  deps: RunnerDeps;
  events: EventLog;
  mcp: McpClient;
  prober: ProberLike;
  hosts: string[];
  domain: string;
  excludedNote: string;
  startedAt: number;
  actions: number;
  verifiedAt?: string;
  verificationProof?: string;
  plan: OperationPlan | null;
  opsecCooldown: Set<string>; // method+path keys abandoned after a detection signal
  consecutive5xx: number;
  /** Battery categories probed so far this engagement. */
  coverage: Set<BatteryCategory>;
  /**
   * Per-target battery coverage for full-battery engagements: target id →
   * categories probed on that target. Empty when fullBattery is off.
   */
  targetCoverage: Map<TargetId, Set<BatteryCategory>>;
  probesUsed: number;
  // -- Shared operation state (the Megazord): one context every agent reads and
  // -- writes. No agent works from a stale or private picture.
  /** Target fingerprint (stack guesses, app type) — parsed from the recon brief. */
  fingerprint: TargetFingerprint;
  /** The persistent vulnerability registry (loaded at start, saved at end). */
  registry: VulnerabilityRegistry;
  registryPath: string;
  /** Registry entries surfaced to this engagement (deduped). */
  registryHits: RegistryEntry[];
  /** Shared target map — recon writes it, the whole team reads it. */
  targetMap: TargetMapEntry[];
  /** Verdicts as they land — exploiter writes, reporter + registry consume. */
  liveFindings: LiveFinding[];
  killedLive: KilledLive[];
  /** Coordinator re-recon redirections used this engagement (max 2). */
  redirects: number;
  /** Consecutive denied/cooled-down/OPSEC-signaled probes — wall detection. */
  deniedStreak: number;
  /** The reporter's 2–3 sentence unified operation narrative (console header). */
  operationNarrative?: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Tool definitions exposed to the agents
// ---------------------------------------------------------------------------

const MCP_TOOLS: JsonSchemaTool[] = [
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

const PROBE_TOOL: JsonSchemaTool = {
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

const BURST_PROBE_TOOL: JsonSchemaTool = {
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

const READ_TOOLS = MCP_TOOLS.filter((t) => t.name !== "scan_url");
const QUERY_REGISTRY_TOOL: JsonSchemaTool = {
  name: "query_registry",
  description:
    "Query the persistent vulnerability registry: what was CONFIRMED against similar targets (payload patterns to fuse further) and what was KILLED (negative intelligence — the exact attempt died; re-attack the class only with a different angle, never the identical probe). Call BEFORE forming hypotheses. Args: vulnClass, stack (comma-separated hints), appType, attackId, limit.",
  parameters: {
    type: "object",
    properties: {
      vulnClass: { type: "string" },
      stack: { type: "string" },
      appType: { type: "string" },
      attackId: { type: "string" },
      limit: { type: "number" },
    },
  },
};
const UPDATE_TARGET_MAP_TOOL: JsonSchemaTool = {
  name: "update_target_map",
  description:
    "Write entries to the SHARED target map the whole team reads (recon's handoff to the exploiter, kept live). Call as you discover attack surface — method + params + auth state + ATT&CK ID per entry.",
  parameters: {
    type: "object",
    properties: {
      entries: {
        type: "array",
        items: {
          type: "object",
          properties: {
            area: { type: "string" },
            method: { type: "string" },
            params: { type: "string" },
            authState: { type: "string" },
            attackId: { type: "string" },
            notes: { type: "string" },
          },
          required: ["area", "method"],
        },
      },
    },
    required: ["entries"],
  },
};
const RECORD_FINDING_TOOL: JsonSchemaTool = {
  name: "record_finding",
  description:
    "Record a CONFIRMED finding the moment it lands (two independent observations required). Writes to shared state AND the persistent registry immediately. Args: severity (critical|high|medium|low|info), title, attackId, evidence, vulnClass?, payload? (the proving payload pattern).",
  parameters: {
    type: "object",
    properties: {
      severity: { type: "string" },
      title: { type: "string" },
      attackId: { type: "string" },
      evidence: { type: "string" },
      vulnClass: { type: "string" },
      payload: { type: "string" },
    },
    required: ["severity", "title", "attackId", "evidence"],
  },
};
const RECORD_KILLED_TOOL: JsonSchemaTool = {
  name: "record_killed",
  description:
    "Record a KILLED hypothesis the moment it dies (what was tried + the killing observation). Negative knowledge — recorded so future engagements attack smarter, not narrower: the exact attempt is dead, the class stays in play. Args: hypothesis, killingObservation, attackId?, vulnClass?, payload? (what was tried).",
  parameters: {
    type: "object",
    properties: {
      hypothesis: { type: "string" },
      killingObservation: { type: "string" },
      attackId: { type: "string" },
      vulnClass: { type: "string" },
      payload: { type: "string" },
    },
    required: ["hypothesis", "killingObservation"],
  },
};
const ABORT_TOOL: JsonSchemaTool = {
  name: "abort_engagement",
  description:
    "COORDINATOR ONLY. Abort the engagement immediately. Call on any stop condition, ROE violation, detection of an auth-gate bypass attempt, or production-impact signal. Arg: reason.",
  parameters: {
    type: "object",
    properties: { reason: { type: "string" } },
    required: ["reason"],
  },
};
const RECON_TOOLS = [...MCP_TOOLS, QUERY_REGISTRY_TOOL, UPDATE_TARGET_MAP_TOOL];
const EXPLOIT_TOOLS = [...READ_TOOLS, PROBE_TOOL, BURST_PROBE_TOOL, QUERY_REGISTRY_TOOL, RECORD_FINDING_TOOL, RECORD_KILLED_TOOL];
/** The coordinator's command tools: no probes, only command authority. */
const COMMAND_TOOLS = [ABORT_TOOL];

// ---------------------------------------------------------------------------
// Tool dispatcher — the runner's hands. Every denial is an event, never silent.
// ---------------------------------------------------------------------------

interface DispatchResult {
  result: string;
  attackId?: string;
  target?: string;
  opsec?: string;
}

async function recheckVerified(ctx: Ctx): Promise<boolean> {
  // Cache the authorize-phase proof for 5 minutes; re-check after that.
  if (ctx.verifiedAt && Date.now() - Date.parse(ctx.verifiedAt) < 5 * 60_000) return true;
  const v = await checkAuthorization(
    ctx.domain,
    { mcpEndpoint: ctx.config.mcpEndpoint, mcpToken: ctx.config.mcpToken },
    ctx.deps.verify,
    { allowLocalSandbox: ctx.config.localSandbox },
  );
  if (v.allowed) ctx.verifiedAt = new Date().toISOString();
  return v.allowed;
}

async function dispatchTool(ctx: Ctx, role: ActorRole, phase: EngagementPhase, call: ToolCallRequest): Promise<DispatchResult> {
  const args = call.arguments ?? {};
  ctx.actions++;

  if (call.name === "http_probe") {
    const attackId = typeof args["attackId"] === "string" ? (args["attackId"] as string).toUpperCase() : undefined;
    const rawCat = typeof args["category"] === "string" ? (args["category"] as string).toLowerCase() : "";
    const category = (BATTERY_CATEGORIES as string[]).includes(rawCat) ? (rawCat as BatteryCategory) : undefined;
    if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
      return { result: `DENIED by ROE: technique ${attackId} is excluded for this engagement.`, attackId, target: String(args["url"] ?? "") };
    }
    const url = String(args["url"] ?? "");
    const method = String(args["method"] ?? "GET").toUpperCase();
    let path = "";
    try {
      path = new URL(url).pathname;
    } catch {
      return { result: `DENIED: unparseable URL ${url}`, attackId, target: url };
    }
    const cooldownKey = `${method} ${path}`;
    if (ctx.opsecCooldown.has(cooldownKey)) {
      return {
        result: `DENIED by OPSEC cooldown: ${cooldownKey} was abandoned after a detection signal. Pivot to a quieter vector.`,
        attackId,
        target: url,
        opsec: "cooldown",
      };
    }
    // The probe is really going out: count it toward the battery.
    ctx.probesUsed++;
    if (category) {
      ctx.coverage.add(category);
      if (ctx.input.fullBattery) {
        // Per-target cell: explicit tag wins, otherwise infer from the URL
        // path (/api/mcp → seclayer, everything else → secscan). Host targets
        // (windows/linux) are never inferred — they need an explicit tag.
        const rawTp = typeof args["targetProfile"] === "string" ? (args["targetProfile"] as string).toLowerCase() : "";
        const tp: TargetId = isTargetId(rawTp) ? rawTp : inferTargetProfile(url);
        let set = ctx.targetCoverage.get(tp);
        if (!set) {
          set = new Set();
          ctx.targetCoverage.set(tp, set);
        }
        set.add(category);
      }
      ctx.events.updateState({
        batteryCoverage: {
          logic: ctx.coverage.has("logic") ? 1 : 0,
          functionality: ctx.coverage.has("functionality") ? 1 : 0,
          validation: ctx.coverage.has("validation") ? 1 : 0,
        },
      });
    }
    try {
      if (ctx.input.mode === "black") await sleep(Math.random() * 2500); // jitter
      const res = await ctx.prober.probe({
        method,
        url,
        headers: (args["headers"] as Record<string, string>) ?? {},
        body: typeof args["body"] === "string" ? (args["body"] as string) : undefined,
      });
      if (res.status >= 500) {
        ctx.consecutive5xx++;
      } else {
        ctx.consecutive5xx = 0;
      }
      if (res.opsecSignal) {
        ctx.opsecCooldown.add(cooldownKey);
        return {
          result: `HTTP ${res.status} in ${res.ms}ms — OPSEC SIGNAL: ${res.opsecSignal}. Vector abandoned; pivot quieter. Snippet: ${res.bodySnippet.slice(0, 400)}`,
          attackId,
          target: url,
          opsec: res.opsecSignal,
        };
      }
      return {
        result: `HTTP ${res.status} in ${res.ms}ms. Snippet: ${res.bodySnippet.slice(0, 600)}`,
        attackId,
        target: url,
      };
    } catch (err) {
      return { result: `probe failed: ${(err as Error).message}`, attackId, target: url };
    }
  }

  if (call.name === "burst_probe") {
    const attackId = typeof args["attackId"] === "string" ? (args["attackId"] as string).toUpperCase() : undefined;
    if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
      return { result: `DENIED by ROE: technique ${attackId} is excluded for this engagement.`, attackId, target: String(args["url"] ?? "") };
    }
    const url = String(args["url"] ?? "");
    let path = "";
    try {
      path = new URL(url).pathname;
    } catch {
      return { result: `DENIED: unparseable URL ${url}`, attackId, target: url };
    }
    const burstKey = `BURST ${path}`;
    if (ctx.opsecCooldown.has(burstKey)) {
      return {
        result: `DENIED: burst_probe already ran against ${path} this engagement — one-shot per endpoint, not a repeatable flood primitive.`,
        attackId,
        target: url,
      };
    }
    ctx.opsecCooldown.add(burstKey); // one-shot regardless of outcome, including failure
    ctx.probesUsed++;
    if (!ctx.prober.probeBurst) {
      return { result: `burst_probe unavailable: this harness's prober does not implement it.`, attackId, target: url };
    }
    try {
      const res = await ctx.prober.probeBurst({ method: String(args["method"] ?? "GET"), url });
      return {
        result: `Burst probe (${res.count} concurrent requests, fixed size): ${res.note} Latency range ${res.minMs}-${res.maxMs}ms.`,
        attackId,
        target: url,
      };
    } catch (err) {
      return { result: `burst probe failed/refused: ${(err as Error).message}`, attackId, target: url };
    }
  }

  // MCP tools.
  const readOnly = new Set(["get_scan_status", "get_report", "list_recent_scans", "get_account"]);
  if (call.name === "scan_url") {
    const url = String(args["url"] ?? "");
    if (!urlInScope(url, ctx.hosts)) {
      return { result: `DENIED: ${url} is outside the engagement scope.`, target: url };
    }
    const aggressive = args["aggressive"] === true;
    if (aggressive) {
      const ok = await recheckVerified(ctx);
      if (!ok) {
        return {
          result: `DENIED by auth gate: aggressive tier requires ownership-verified domain. The server does not list ${ctx.domain} as verified.`,
          target: url,
        };
      }
    }
    const text = await ctx.mcp.scanUrl(url, aggressive);
    return { result: text.slice(0, 2000), attackId: aggressive ? "T1595.002" : undefined, target: url };
  }
  if (readOnly.has(call.name)) {
    const text = await ctx.mcp.callTool(call.name, args);
    return { result: text.slice(0, 2000), target: call.name === "get_report" || call.name === "get_scan_status" ? String(args["scan_id"] ?? "") : undefined };
  }

  // -- Shared-state tools: the Megazord's common picture ---------------------
  if (call.name === "query_registry") {
    const limit = Math.min(Math.max(Number(args["limit"] ?? 5) || 5, 1), 10);
    const hits = queryRegistry(ctx.registry, {
      vulnClass: optStr(args["vulnClass"]),
      stack: optStr(args["stack"]) ?? ctx.fingerprint.stack.join(","),
      appType: optStr(args["appType"]) ?? ctx.fingerprint.appType,
      attackId: optStr(args["attackId"]),
      limit,
    });
    for (const h of hits) {
      if (!ctx.registryHits.some((e) => e.id === h.id)) ctx.registryHits.push(h);
    }
    if (hits.length === 0) {
      return {
        result: "Registry: no relevant entries for this target profile — uncharted territory. Proceed from first principles and write back everything you learn.",
        target: "registry",
      };
    }
    const lines = hits.map((h) =>
      h.kind === "confirmed"
        ? `[CONFIRMED] ${h.vulnClass} (${h.attackId ?? "?"} ${h.technique}) — payload: ${h.payloadPattern} — ${h.engagementId} ${h.date}`
        : `[KILLED — exact attempt dead; class still in play with a different angle] ${h.hypothesis} — killing observation: ${h.killingObservation} — ${h.engagementId} ${h.date}`,
    );
    return { result: `Registry hits (${hits.length}):\n${lines.join("\n")}`, target: "registry" };
  }

  if (call.name === "update_target_map") {
    const entries = Array.isArray(args["entries"]) ? (args["entries"] as Record<string, unknown>[]) : [];
    let added = 0;
    for (const e of entries) {
      const area = String(e["area"] ?? "").slice(0, 200);
      const method = (optStr(e["method"]) ?? "GET").toUpperCase().slice(0, 12);
      if (!area) continue;
      if (ctx.targetMap.some((t) => t.method === method && t.area === area)) continue;
      ctx.targetMap.push({
        area,
        method,
        params: optStr(e["params"])?.slice(0, 200),
        authState: optStr(e["authState"])?.slice(0, 60),
        attackId: optStr(e["attackId"])?.toUpperCase(),
        notes: optStr(e["notes"])?.slice(0, 200),
      });
      added++;
    }
    return {
      result: `Target map updated: ${added} new entries (${ctx.targetMap.length} total) — the whole team sees this shared state.`,
      target: "target-map",
    };
  }

  if (call.name === "record_finding") {
    const attackId = (optStr(args["attackId"]) ?? "T1190").toUpperCase();
    const lf: LiveFinding = {
      severity: optStr(args["severity"]) ?? "low",
      title: String(args["title"] ?? "untitled").slice(0, 200),
      vulnClass: optStr(args["vulnClass"]),
      attackId,
      evidence: String(args["evidence"] ?? "").slice(0, 800),
      payload: optStr(args["payload"])?.slice(0, 300),
    };
    ctx.liveFindings.push(lf);
    syncLiveFindingsToState(ctx);
    writeFindingToRegistry(ctx, lf);
    return {
      result: `Finding recorded to shared state + registry: [${lf.severity}] ${lf.title} (${attackId}). The reporter and all future engagements see it.`,
      attackId,
      target: ctx.domain,
    };
  }

  if (call.name === "record_killed") {
    const kl: KilledLive = {
      hypothesis: String(args["hypothesis"] ?? "").slice(0, 300),
      killingObservation: String(args["killingObservation"] ?? "").slice(0, 500),
      attackId: optStr(args["attackId"])?.toUpperCase(),
      vulnClass: optStr(args["vulnClass"]),
      payload: optStr(args["payload"])?.slice(0, 300),
    };
    ctx.killedLive.push(kl);
    writeKilledToRegistry(ctx, kl);
    return {
      result: "Killed hypothesis recorded to shared state + registry as negative intelligence — future engagements keep the full spectrum; the exact attempt is dead, the class stays in play.",
      attackId: kl.attackId,
      target: ctx.domain,
    };
  }

  if (call.name === "abort_engagement") {
    const reason = String(args["reason"] ?? "coordinator abort").slice(0, 500);
    ctx.events.append({ phase, actor: "coordinator", action: "abort_engagement", result: `ABORTED by coordinator: ${reason}` });
    throw new HaltError(`aborted by coordinator: ${reason}`);
  }

  return { result: `DENIED: unknown tool ${call.name}` };
}

// ---------------------------------------------------------------------------
// Shared operation state (Megazord) helpers
// ---------------------------------------------------------------------------

function optStr(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

function coerceSeverity(s: string): Finding["severity"] {
  const l = s.toLowerCase();
  return (VALID_SEVERITIES.has(l) ? l : "low") as Finding["severity"];
}

/** Mirror live findings into state.json so the console shows them as they land. */
function syncLiveFindingsToState(ctx: Ctx): void {
  ctx.events.updateState({
    findings: ctx.liveFindings.map((f, i) => ({
      id: `F-${i + 1}`,
      severity: coerceSeverity(f.severity),
      title: f.title,
      attackIds: [f.attackId],
      evidence: f.evidence,
      fix: "(pending — the reporter writes the fix)",
      retest: "(pending)",
      status: "confirmed" as const,
    })),
  });
}

/** Write a confirmed finding to the registry (deduped per engagement) and persist. */
function writeFindingToRegistry(ctx: Ctx, lf: LiveFinding): void {
  const vulnClass = lf.vulnClass ?? "unclassified";
  const payloadPattern = lf.payload ?? "(see evidence)";
  const dupe = ctx.registry.confirmed.some(
    (e) => e.engagementId === ctx.events.engagementId && e.vulnClass === vulnClass && e.payloadPattern === payloadPattern,
  );
  if (dupe) return;
  recordConfirmed(ctx.registry, {
    vulnClass,
    technique: lookupTechnique(lf.attackId)?.name ?? lf.attackId,
    attackId: lf.attackId,
    target: ctx.fingerprint,
    payloadPattern,
    evidenceRef: `${ctx.events.engagementId}/events.jsonl`,
    engagementId: ctx.events.engagementId,
    severity: coerceSeverity(lf.severity),
  });
  saveRegistryFile(ctx.registryPath, ctx.registry);
}

/** Write a killed hypothesis to the registry (deduped per engagement) and persist. */
function writeKilledToRegistry(ctx: Ctx, kl: KilledLive): void {
  const dupe = ctx.registry.killed.some(
    (e) => e.engagementId === ctx.events.engagementId && e.hypothesis === kl.hypothesis,
  );
  if (dupe) return;
  recordKilled(ctx.registry, {
    hypothesis: kl.hypothesis,
    killingObservation: kl.killingObservation,
    attackId: kl.attackId,
    vulnClass: kl.vulnClass,
    target: ctx.fingerprint,
    engagementId: ctx.events.engagementId,
  });
  saveRegistryFile(ctx.registryPath, ctx.registry);
}

/** Merge the exploiter's final VERDICTS JSON block into shared state + registry (backstop for verdicts never recorded live). */
function mergeVerdictBlock(ctx: Ctx, text: string): void {
  const parsed = extractJsonBlock(text) as { verdicts?: Array<Record<string, unknown>> } | null;
  const verdicts = parsed && Array.isArray(parsed.verdicts) ? parsed.verdicts : [];
  let merged = 0;
  for (const v of verdicts) {
    if (v["kind"] === "confirmed") {
      const lf: LiveFinding = {
        severity: String(v["severity"] ?? "low"),
        title: String(v["vulnClass"] ?? v["title"] ?? "finding").slice(0, 200),
        vulnClass: optStr(v["vulnClass"]),
        attackId: (optStr(v["attackId"]) ?? "T1190").toUpperCase(),
        evidence: String(v["evidence"] ?? "").slice(0, 800),
        payload: optStr(v["payloadPattern"]),
      };
      if (ctx.liveFindings.some((f) => f.title === lf.title && f.attackId === lf.attackId)) continue;
      ctx.liveFindings.push(lf);
      writeFindingToRegistry(ctx, lf);
      merged++;
    } else if (v["kind"] === "killed") {
      const kl: KilledLive = {
        hypothesis: String(v["hypothesis"] ?? "").slice(0, 300),
        killingObservation: String(v["killingObservation"] ?? "").slice(0, 500),
        attackId: optStr(v["attackId"])?.toUpperCase(),
        vulnClass: optStr(v["vulnClass"]),
      };
      if (!kl.hypothesis || ctx.killedLive.some((k) => k.hypothesis === kl.hypothesis)) continue;
      ctx.killedLive.push(kl);
      writeKilledToRegistry(ctx, kl);
      merged++;
    }
  }
  if (merged > 0) {
    syncLiveFindingsToState(ctx);
    ctx.events.append({
      phase: "exploit",
      actor: "runner",
      action: "verdicts_merged",
      result: `Merged ${merged} verdict(s) from the final VERDICTS block into shared state + registry.`,
    });
  }
}

/** Compact shared-state digest appended to every tool result — the team's common picture, never stale. */
/**
 * Runner-computed battery coverage line. Generic engagements: 3 global
 * categories. Full-battery engagements: 3 categories × selected targets
 * (12 cells by default). ✓ probed · ⊘ blocked (host-exec tooling) · … missing.
 */
export function batteryStatusLine(ctx: Ctx): string {
  if (ctx.input.fullBattery) {
    return activeTargets(ctx.input)
      .map(
        (t) =>
          `${t}: ${BATTERY_CATEGORIES.map((c) => {
            const s = targetCellStatus(TARGET_PROFILES[t], c, ctx.targetCoverage.get(t));
            return `${c}${s === "done" ? "✓" : s === "blocked" ? "⊘" : "…"}`;
          }).join(" ")}`,
      )
      .join(" | ");
  }
  return BATTERY_CATEGORIES.map((c) => `${c}${ctx.coverage.has(c) ? "✓" : "…"}`).join(" ");
}

export function sharedStateDigest(ctx: Ctx, phase: EngagementPhase): string {
  const parts: string[] = [`[SHARED STATE · phase=${phase}]`];
  if (ctx.plan) parts.push(`plan: ${ctx.plan.steps.length} steps (${ctx.plan.adversaryProfile})`);
  if (ctx.targetMap.length) {
    const entries = ctx.targetMap
      .slice(0, 10)
      .map((t) => `${t.method} ${t.area}${t.authState ? ` [${t.authState}]` : ""}${t.attackId ? ` ${t.attackId}` : ""}`);
    parts.push(
      `target-map(${ctx.targetMap.length}): ${entries.join(" | ")}${ctx.targetMap.length > 10 ? ` +${ctx.targetMap.length - 10} more` : ""}`,
    );
  }
  if (ctx.liveFindings.length) {
    parts.push(
      `findings(${ctx.liveFindings.length}): ${ctx.liveFindings.slice(0, 5).map((f) => `[${f.severity}] ${f.title}`).join(" | ")}`,
    );
  }
  if (ctx.killedLive.length) {
    parts.push(`killed(${ctx.killedLive.length}): ${ctx.killedLive.slice(0, 5).map((k) => k.hypothesis).join(" | ")}`);
  }
  if (ctx.registryHits.length) parts.push(`registry: ${ctx.registryHits.length} relevant hits surfaced this engagement`);
  parts.push(`battery: ${batteryStatusLine(ctx)}`);
  if (ctx.opsecCooldown.size) parts.push(`OPSEC cooldowns: ${ctx.opsecCooldown.size}`);
  if (ctx.redirects) parts.push(`redirects used: ${ctx.redirects}/2`);
  const s = parts.join("\n");
  return s.length > 1600 ? s.slice(0, 1600) + "…" : s;
}

// ---------------------------------------------------------------------------
// Stop-condition plumbing
// ---------------------------------------------------------------------------

async function respectBlackout(ctx: Ctx, phase: EngagementPhase): Promise<void> {
  const w = inBlackout(new Date(), ctx.input.roe.blackoutWindows);
  if (!w) return;
  ctx.events.append({
    phase,
    actor: "runner",
    action: "blackout_pause",
    result: `Entering blackout window ${w.start}–${w.end}${w.tz ? ` ${w.tz}` : ""}. No traffic until it ends.`,
  });
  for (;;) {
    await sleep(30_000);
    if (!inBlackout(new Date(), ctx.input.roe.blackoutWindows)) break;
  }
  ctx.events.append({ phase, actor: "runner", action: "blackout_resume", result: "Blackout window ended. Resuming." });
}

function haltedByCaps(ctx: Ctx): string | null {
  if (ctx.actions >= ctx.config.maxActions) return `action cap reached (${ctx.config.maxActions})`;
  if (Date.now() - ctx.startedAt >= ctx.config.maxDurationMs) return `duration cap reached`;
  if (ctx.consecutive5xx >= 3) return `three consecutive 5xx responses — possible production impact, halting`;
  return null;
}

// ---------------------------------------------------------------------------
// The agent loop: REASON → ACT → OBSERVE, bounded
// ---------------------------------------------------------------------------

async function agentLoop(
  ctx: Ctx,
  role: AgentRole,
  phase: EngagementPhase,
  system: string,
  user: string,
  tools: JsonSchemaTool[],
  maxTurns: number,
  opts: {
    /** Called when the model stops calling tools. Return a follow-up prompt to
     *  keep the phase going, or null to finish the phase. */
    onIdle?: () => string | null;
  } = {},
): Promise<string> {
  const complete = ctx.deps.completeForRole ?? routerCompleteForRole;
  const messages: ChatMessage[] = [
    { role: "system", content: system },
    { role: "user", content: user },
  ];
  const notes: string[] = [];
  for (let turn = 0; turn < maxTurns; turn++) {
    await respectBlackout(ctx, phase);
    const cap = haltedByCaps(ctx);
    if (cap) {
      ctx.events.append({ phase, actor: "runner", action: "halt", result: `Halted: ${cap}.` });
      throw new HaltError(cap);
    }
    let res: ChatResult;
    try {
      res = await complete(role, messages, { tools });
    } catch (err) {
      ctx.events.append({ phase, actor: "runner", action: "llm_error", result: `LLM call failed: ${(err as Error).message}` });
      throw err;
    }
    if (res.text || res.reasoning) {
      if (res.text) notes.push(res.text);
      // The thinking trace is first-class observability: it lands in the
      // event feed (and the console) alongside the visible reply.
      const thought = res.reasoning ? `\n[thinking] ${res.reasoning.slice(0, 600)}` : "";
      ctx.events.append({ phase, actor: role, action: "reasoning", result: `${res.text.slice(0, 500)}${thought}`.slice(0, 1200) });
    }
    if (!res.toolCalls || res.toolCalls.length === 0) {
      const followUp = opts.onIdle?.();
      if (!followUp) {
        messages.push({ role: "assistant", content: res.text });
        break;
      }
      messages.push({ role: "assistant", content: res.text || "(pausing)" });
      messages.push({ role: "user", content: followUp });
      ctx.events.append({ phase, actor: "runner", action: "phase_nudge", result: followUp.slice(0, 300) });
      continue;
    }
    messages.push({ role: "assistant", content: res.text || "(tool calls)" });
    for (const call of res.toolCalls) {
      const d = await dispatchTool(ctx, role, phase, call);
      ctx.events.append({
        phase,
        actor: role,
        action: call.name,
        attackId: d.attackId,
        target: d.target,
        result: d.result.slice(0, 800),
        opsec: d.opsec,
      });
      messages.push({
        role: "tool",
        toolCallId: call.id,
        // Every observation carries the current shared state — no agent ever
        // works from a stale or private picture (Megazord protocol).
        content: d.result.slice(0, 4000) + "\n" + sharedStateDigest(ctx, phase),
      });
      // Wall detection: consecutive blocked/cooled-down/OPSEC-signaled probes
      // with no successful observation. The coordinator redirects to re-recon.
      const blocked = /^(DENIED|probe failed)/i.test(d.result) || /OPSEC SIGNAL|cooling down/i.test(d.result);
      ctx.deniedStreak = blocked ? ctx.deniedStreak + 1 : 0;
      const capAfter = haltedByCaps(ctx);
      if (capAfter) {
        ctx.events.append({ phase, actor: "runner", action: "halt", result: `Halted: ${capAfter}.` });
        throw new HaltError(capAfter);
      }
    }
    if (phase === "exploit" && ctx.deniedStreak >= 4 && ctx.redirects < 2) {
      ctx.deniedStreak = 0;
      ctx.redirects++;
      const intel = await commanderRedirect(
        ctx,
        "The exploiter hit a wall: 4+ consecutive probes denied, cooled-down, or OPSEC-signaled with no successful observation.",
      );
      messages.push({ role: "user", content: intel });
    }
  }
  return notes.join("\n\n");
}

export class HaltError extends Error {}

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

function promptCtx(ctx: Ctx): {
  mode: EngagementMode;
  objective: string;
  target: string;
  scopeHosts: string[];
  roe: RulesOfEngagement;
  fullBattery?: boolean;
  targets?: TargetId[];
  localSandbox?: boolean;
} {
  return {
    mode: ctx.input.mode,
    objective: ctx.input.objective,
    target: ctx.input.target,
    scopeHosts: ctx.hosts,
    roe: ctx.input.roe,
    fullBattery: ctx.input.fullBattery,
    targets: ctx.input.targets,
    // Only actually relax discipline when the target is genuinely
    // loopback/private — matches the gate's invariant exactly. Leaving
    // --local-sandbox on does nothing against a real domain.
    localSandbox: ctx.config.localSandbox && ctx.hosts.every((h) => isPrivateOrLoopbackHost(h)),
  };
}

async function authorizePhase(ctx: Ctx): Promise<GateVerdict> {
  const verdict = await checkAuthorization(
    ctx.domain,
    { mcpEndpoint: ctx.config.mcpEndpoint, mcpToken: ctx.config.mcpToken },
    ctx.deps.verify,
    { allowLocalSandbox: ctx.config.localSandbox },
  );
  if (!verdict.allowed) {
    ctx.events.append({ phase: "authorize", actor: "coordinator", action: "authorization_denied", target: ctx.domain, result: verdict.reason ?? "denied" });
    ctx.events.updateState({ status: "blocked", phase: "blocked", blockedReason: verdict.reason });
    return verdict;
  }
  ctx.verifiedAt = new Date().toISOString();
  ctx.verificationProof = verdict.reason
    ? `${verdict.reason} (${ctx.verifiedAt})`
    : `SecScan server lists ${ctx.domain} as ownership-verified (${ctx.verifiedAt}).`;
  ctx.events.append({
    phase: "authorize",
    actor: "coordinator",
    action: "authorization_basis",
    target: ctx.domain,
    result: `${ctx.verificationProof} Mode: ${ctx.input.mode.toUpperCase()}. Objective: ${ctx.input.objective}. Scope: ${ctx.hosts.join(", ")}.`,
  });
  ctx.events.updateState({
    status: "running",
    verified: true,
    verificationTs: ctx.verifiedAt,
    verificationProof: ctx.verificationProof,
  });
  return verdict;
}

function extractJsonBlock(text: string): unknown | null {
  const fenced = text.match(/```json\s*([\s\S]*?)```/i) ?? text.match(/```\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : text;
  try {
    return JSON.parse(candidate);
  } catch {
    const obj = candidate.match(/\{[\s\S]*\}/);
    if (obj) {
      try {
        return JSON.parse(obj[0]);
      } catch {
        return null;
      }
    }
    return null;
  }
}

async function planPhase(ctx: Ctx, critique?: string): Promise<void> {
  if (ctx.config.dryRunAgents) {
    ctx.plan = { mode: ctx.input.mode, objective: ctx.input.objective, adversaryProfile: "dry-run", steps: [] };
    ctx.events.updateState({ plan: ctx.plan });
    ctx.events.append({ phase: "plan", actor: "coordinator", action: "plan", result: "dry-run: planning skipped." });
    return;
  }
  const text = await agentLoop(
    ctx,
    "coordinator",
    "plan",
    coordinatorPrompt(promptCtx(ctx)),
    `Authorization is proven for ${ctx.domain} (${ctx.verificationProof}). Produce the operation plan as JSON now: { "adversaryProfile": "...", "steps": [{ "phase": "recon|exploit", "attackId": "Txxxx", "description": "...", "stealthNote": "..." }] }.` +
      (critique ? `\n\nCOMMANDER REDIRECT on the previous plan: ${critique}. Revise the plan accordingly.` : ""),
    [...READ_TOOLS, ABORT_TOOL],
    4,
  );
  const parsed = extractJsonBlock(text) as { adversaryProfile?: string; steps?: PlanStep[] } | null;
  const steps: PlanStep[] = [];
  if (parsed && Array.isArray(parsed.steps)) {
    for (const s of parsed.steps) {
      const attackId = typeof s.attackId === "string" ? s.attackId.toUpperCase() : undefined;
      if (attackId && !lookupTechnique(attackId)) {
        ctx.events.append({ phase: "plan", actor: "runner", action: "plan_step_rejected", attackId, result: `Unknown ATT&CK ID ${attackId} — step rejected.` });
        continue;
      }
      if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
        ctx.events.append({ phase: "plan", actor: "runner", action: "plan_step_rejected", attackId, result: `Technique ${attackId} excluded by ROE/mode — step rejected.` });
        continue;
      }
      const step: PlanStep = {
        phase: s.phase === "exploit" ? "exploit" : "recon",
        attackId,
        description: String(s.description ?? "").slice(0, 500),
        stealthNote: typeof s.stealthNote === "string" ? s.stealthNote.slice(0, 300) : undefined,
      };
      steps.push(step);
      ctx.events.append({ phase: "plan", actor: "coordinator", action: "plan_step", attackId, result: step.description });
    }
  }
  ctx.plan = {
    mode: ctx.input.mode,
    objective: ctx.input.objective,
    adversaryProfile: typeof parsed?.adversaryProfile === "string" ? parsed.adversaryProfile : "unspecified",
    steps,
  };
  ctx.events.updateState({ plan: ctx.plan });
}

// ---------------------------------------------------------------------------
// Coordinator command authority: sign-offs, redirects, abort (Megazord protocol)
// ---------------------------------------------------------------------------

/**
 * Commander-ordered focused re-recon. Used when the exploiter hits a wall
 * (mechanical wall detection) or when the coordinator redirects the
 * recon→exploit handoff. Writes to the shared target map as it goes.
 */
async function commanderRedirect(ctx: Ctx, reason: string): Promise<string> {
  ctx.events.append({
    phase: "exploit",
    actor: "coordinator",
    action: "redirect_rerecon",
    result: `Commander redirect (${ctx.redirects}/2): ${reason}`,
  });
  const mapLines = ctx.targetMap.map((t) => `${t.method} ${t.area}${t.authState ? ` [${t.authState}]` : ""}`).join("; ");
  const intel = await agentLoop(
    ctx,
    "recon",
    "recon",
    reconPrompt(promptCtx(ctx)),
    `COMMANDER REDIRECT — focused re-recon, not a full re-scan. ${reason}\n` +
      `Current shared target map (${ctx.targetMap.length} entries): ${mapLines || "(empty)"}.\n` +
      `Find NEW angles the exploiter has not tried: untested endpoints, parameters, methods, auth flows. ` +
      `Write every discovery to the shared target map with update_target_map as you go. ` +
      `End with a 5-line brief of the new angles.`,
    RECON_TOOLS,
    6,
  );
  ctx.events.append({ phase: "recon", actor: "recon", action: "rerecon_brief", result: intel.slice(0, 800) });
  return (
    `COMMANDER REDIRECT — re-recon complete (redirect ${ctx.redirects}/2 used). New angles:\n${intel.slice(0, 1200)}\n` +
    `The shared target map now has ${ctx.targetMap.length} entries (see [SHARED STATE]). Form fresh hypotheses from the new angles — do not re-probe cooled-down vectors.`
  );
}

/** Commander-ordered focused exploitation (redirect on the exploit→report handoff). */
async function focusedExploit(ctx: Ctx, focus: string): Promise<void> {
  ctx.events.append({ phase: "exploit", actor: "coordinator", action: "redirect_exploit", result: `Commander redirect: ${focus}` });
  await agentLoop(
    ctx,
    "exploiter",
    "exploit",
    exploiterPrompt(promptCtx(ctx)),
    `COMMANDER REDIRECT — focused exploitation, not a full battery re-run. Focus: ${focus}\n` +
      `Current shared state: ${ctx.liveFindings.length} confirmed, ${ctx.killedLive.length} killed. ` +
      `Record every new verdict immediately with record_finding / record_killed.`,
    EXPLOIT_TOOLS,
    8,
  );
}

type SignOffTransition = "plan→recon" | "recon→exploit" | "exploit→report";

/**
 * Handoff protocol: nothing advances a phase without the coordinator's
 * sign-off. REDIRECT runs a bounded correction chapter (max 2 per engagement)
 * and re-reviews; a withheld sign-off after that halts the engagement.
 */
export async function coordinatorSignOff(ctx: Ctx, transition: SignOffTransition, payload: string): Promise<void> {
  if (ctx.config.dryRunAgents) {
    ctx.events.append({ phase: "plan", actor: "coordinator", action: "signoff", result: `${transition} auto-approved (dry-run).` });
    return;
  }
  const text = await agentLoop(
    ctx,
    "coordinator",
    "plan",
    coordinatorPrompt(promptCtx(ctx)) +
      `\n\n## SIGN-OFF DUTY — current task\nYou are signing off the phase transition: ${transition}.\n` +
      `Review the material below. Your reply must start with EXACTLY one of:\n` +
      `- \`SIGN-OFF: <one-line summary of what is approved>\` — the operation proceeds.\n` +
      `- \`REDIRECT: <what must change and which specialist does it>\` — at most 2 redirects per engagement (used: ${ctx.redirects}).\n` +
      `You may also call abort_engagement on any stop condition, ROE violation, or gate-bypass attempt.\n` +
      `Confirm role discipline in one line per specialist, or correct them.`,
    `Transition awaiting sign-off: ${transition}\n\n${payload}`,
    COMMAND_TOOLS,
    3,
  );
  ctx.events.append({ phase: "plan", actor: "coordinator", action: "signoff_review", result: `${transition}: ${text.slice(0, 400)}` });
  if (/^\s*REDIRECT\s*:/im.test(text)) {
    if (ctx.redirects >= 2) {
      throw new HaltError(`coordinator withheld sign-off for ${transition} after 2 redirects — engagement halted`);
    }
    const reason = (text.match(/^\s*REDIRECT\s*:\s*([\s\S]*)/im)?.[1] ?? "commander ordered redirect").trim().slice(0, 500);
    ctx.redirects++;
    ctx.events.append({ phase: "plan", actor: "coordinator", action: "signoff_redirect", result: `${transition}: ${reason}` });
    if (transition === "recon→exploit") {
      await commanderRedirect(ctx, `Sign-off redirect for ${transition}: ${reason}`);
    } else if (transition === "exploit→report") {
      await focusedExploit(ctx, reason);
    } else {
      await planPhase(ctx, reason);
    }
    return coordinatorSignOff(ctx, transition, payload);
  }
  if (!/^\s*SIGN-OFF\s*:/im.test(text)) {
    throw new HaltError(`coordinator did not issue a clear sign-off for ${transition} — engagement halted (fail closed)`);
  }
  ctx.events.append({ phase: "plan", actor: "coordinator", action: "signoff", result: `${transition} approved.` });
}

async function reconPhase(ctx: Ctx): Promise<string> {
  if (ctx.config.dryRunAgents) {
    ctx.events.append({ phase: "recon", actor: "recon", action: "recon_brief", result: "dry-run: recon skipped." });
    return "dry-run brief";
  }
  const brief = await agentLoop(
    ctx,
    "recon",
    "recon",
    reconPrompt(promptCtx(ctx)),
    `Begin reconnaissance of ${ctx.input.target}. In-scope hosts: ${ctx.hosts.join(", ")}. ` +
      (ctx.input.mode === "red"
        ? "Use scan_url with aggressive=true for the active tier."
        : "Start with the passive tier (scan_url without aggressive). Escalate only if the plan calls for it.") +
      ` Deliver the attack-surface brief when done.`,
    RECON_TOOLS,
    ctx.config.maxReconTurns,
  );
  ctx.events.append({ phase: "recon", actor: "recon", action: "recon_brief", result: brief.slice(0, 1200) });
  // Target fingerprint: the runner parses the FINGERPRINT: line from the brief
  // (format: FINGERPRINT: stack=<csv>; appType=<...>; notes=<one line>).
  const fp = brief.match(/FINGERPRINT:\s*stack=([^;]*);\s*appType=([^;]*);\s*notes=([^\n]*)/i);
  if (fp) {
    const stack = fp[1]!.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
    const appType = fp[2]!.trim() || "unknown";
    ctx.fingerprint = { host: ctx.domain, stack, appType, notes: fp[3]!.trim().slice(0, 200) || undefined };
    ctx.events.append({ phase: "recon", actor: "runner", action: "fingerprint", result: JSON.stringify(ctx.fingerprint) });
  }
  return brief;
}

// ---------------------------------------------------------------------------
// Dynamic orchestration: decompose → delegate → observe → re-plan.
//
// The coordinator never runs a long static plan. It breaks the operation into
// small discrete tasks; the runner validates each task against the cyber
// constraints (ROE, ATT&CK catalog, battery) and executes it by feeding it to
// the foundation (a bounded completeForRole loop = one specialist subagent).
// After every observation round the coordinator re-evaluates: pivot,
// escalate, go stealthy, back off, or spawn more help.
// ---------------------------------------------------------------------------

/** A discrete unit of work: one task, one specialist, one objective. */
export interface TaskDef {
  id: string;
  kind: "probe" | "recon";
  brief: string;
  attackId?: string;
  category?: BatteryCategory;
  maxTurns: number;
}

export interface TaskResult {
  task: TaskDef;
  summary: string;
  probesBefore: number;
  probesAfter: number;
  findingsBefore: number;
  findingsAfter: number;
  killedBefore: number;
  killedAfter: number;
}

/**
 * "Spawn a subagent": execute one discrete task as a bounded foundation loop
 * with a task-scoped specialist prompt. Fresh context, cyber task definition.
 */
async function runTask(ctx: Ctx, task: TaskDef): Promise<TaskResult> {
  const role = task.kind === "recon" ? "recon" : "exploiter";
  const tools = task.kind === "recon" ? RECON_TOOLS : EXPLOIT_TOOLS;
  const probesBefore = ctx.probesUsed;
  const findingsBefore = ctx.liveFindings.length;
  const killedBefore = ctx.killedLive.length;
  ctx.events.append({
    phase: "exploit",
    actor: "coordinator",
    action: "task_spawn",
    target: task.id,
    attackId: task.attackId,
    result: `[${task.kind}] ${task.brief.slice(0, 200)}${task.category ? ` (${task.category})` : ""}`,
  });
  const summary = await agentLoop(
    ctx,
    role,
    "exploit",
    taskPrompt(promptCtx(ctx), task),
    "Execute the task now.",
    tools,
    task.maxTurns,
  );
  mergeVerdictBlock(ctx, summary);
  const verdictNote =
    `probes +${ctx.probesUsed - probesBefore}, ` +
    `confirmed +${ctx.liveFindings.length - findingsBefore}, killed +${ctx.killedLive.length - killedBefore}`;
  ctx.events.append({
    phase: "exploit",
    actor: role,
    action: "task_complete",
    target: task.id,
    attackId: task.attackId,
    result: `${verdictNote}. ${summary.slice(0, 600)}`,
  });
  return {
    task,
    summary,
    probesBefore,
    probesAfter: ctx.probesUsed,
    findingsBefore,
    findingsAfter: ctx.liveFindings.length,
    killedBefore,
    killedAfter: ctx.killedLive.length,
  };
}

/**
 * Fan-out with a concurrency cap: red fans out independent tasks in parallel,
 * black runs strictly one at a time (stealth). HaltError always propagates.
 */
async function runBatch(ctx: Ctx, tasks: TaskDef[], cap: number): Promise<TaskResult[]> {
  const results: TaskResult[] = [];
  for (let i = 0; i < tasks.length; i += cap) {
    const chunk = tasks.slice(i, i + cap);
    const settled = await Promise.allSettled(chunk.map((t) => runTask(ctx, t)));
    for (let j = 0; j < settled.length; j++) {
      const s = settled[j]!;
      if (s.status === "fulfilled") {
        results.push(s.value);
      } else {
        if (s.reason instanceof HaltError) throw s.reason;
        ctx.events.append({
          phase: "exploit",
          actor: "runner",
          action: "task_failed",
          target: chunk[j]!.id,
          result: `Task failed: ${String(s.reason).slice(0, 300)}`,
        });
      }
    }
  }
  return results;
}

let taskCounter = 0;

/**
 * Cyber-layer task validation: the coordinator proposes, the runner disposes.
 * Unknown/excluded ATT&CK IDs and invalid categories are rejected (with an
 * event) — the coordinator re-plans without them.
 */
function validateTasks(ctx: Ctx, raw: Array<Record<string, unknown>>, cap: number): TaskDef[] {
  const tasks: TaskDef[] = [];
  const overCap = raw.slice(cap);
  for (const r of overCap) {
    ctx.events.append({
      phase: "exploit",
      actor: "runner",
      action: "task_rejected",
      result: `Task over concurrency cap (${cap}/round): re-plan it next round. Brief was: ${String(r["brief"] ?? "").slice(0, 120)}`,
    });
  }
  for (const r of raw.slice(0, cap)) {
    const kind = r["kind"] === "recon" ? "recon" : "probe";
    const brief = String(r["brief"] ?? "").trim().slice(0, 800);
    if (!brief) continue;
    let attackId = typeof r["attackId"] === "string" ? r["attackId"].toUpperCase() : undefined;
    if (attackId && (!lookupTechnique(attackId) || !techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe))) {
      ctx.events.append({
        phase: "exploit",
        actor: "runner",
        action: "task_rejected",
        attackId,
        result: `Task rejected: attackId ${attackId} unknown or ROE-excluded. Brief was: ${brief.slice(0, 120)}`,
      });
      continue;
    }
    let category: BatteryCategory | undefined;
    if (kind === "probe") {
      const c = String(r["category"] ?? "").toLowerCase();
      if (!(BATTERY_CATEGORIES as string[]).includes(c)) {
        ctx.events.append({
          phase: "exploit",
          actor: "runner",
          action: "task_rejected",
          result: `Task rejected: probe task needs a battery category (logic|functionality|validation). Brief was: ${brief.slice(0, 120)}`,
        });
        continue;
      }
      category = c as BatteryCategory;
    }
    const maxTurns = Math.min(Math.max(Number(r["maxTurns"]) || 6, 2), 8);
    tasks.push({ id: `task-${++taskCounter}`, kind, brief, attackId, category, maxTurns });
  }
  return tasks;
}

interface CoordinatorDirective {
  tasks: TaskDef[];
  finish: boolean;
  note: string;
}

/**
 * One coordinator command turn: DECOMPOSE (initial) or RE-PLAN (after every
 * observation round). Returns validated tasks or a finish decision.
 */
async function coordinatorDirective(
  ctx: Ctx,
  kind: "decompose" | "replan",
  context: string,
): Promise<CoordinatorDirective> {
  const cap = ctx.input.mode === "black" ? 1 : 3;
  const head =
    kind === "decompose"
      ? `DECOMPOSE — break the operation into small discrete tasks (one task, one specialist, one objective). ` +
        `Fan out independent hypotheses${ctx.input.mode === "black" ? " ONE AT A TIME (black mode: stealth, strictly sequential)" : " in parallel (red mode: up to 3 per round)"}. ` +
        `Put promising leads in their own dedicated tasks. Include registry-informed tasks (fuse what worked before). ` +
        `Tasks must span all three battery categories (logic | functionality | validation) before finish.`
      : `RE-PLAN — the last batch completed. Re-evaluate from the fresh observations: PIVOT to new angles, ESCALATE a promising lead with a dedicated deeper task, ` +
        `GO STEALTHY on detection signals, BACK OFF cooled-down vectors, SPAWN MORE HELP across independent surface. Never coast on the earlier plan.`;
  const text = await agentLoop(
    ctx,
    "coordinator",
    "exploit",
    coordinatorPrompt(promptCtx(ctx)),
    `${head}\n\nReturn ONLY a JSON block: {"tasks": [<at most ${cap} task(s) this round>, {"kind": "probe|recon", "brief": "<1-2 sentences>", "attackId": "<ATT&CK, optional>", "category": "<logic|functionality|validation — probe tasks only>", "maxTurns": 6}], "finish": <true only when the objective is met AND (battery complete OR probe budget exhausted OR no applicable surface declared with reasons)>, "note": "<what changed and why, one line>"}\n\n${context}`,
    COMMAND_TOOLS,
    3,
  );
  const parsed = extractJsonBlock(text) as {
    tasks?: Array<Record<string, unknown>>;
    finish?: boolean;
    note?: string;
  } | null;
  const tasks = validateTasks(ctx, Array.isArray(parsed?.tasks) ? parsed!.tasks! : [], cap);
  const finish = parsed?.finish === true;
  const note = typeof parsed?.note === "string" ? parsed.note.slice(0, 300) : text.slice(0, 300);
  ctx.events.append({
    phase: "exploit",
    actor: "coordinator",
    action: kind === "decompose" ? "decompose" : "replan",
    result: `${note} → ${tasks.length} task(s)${finish ? ", FINISH requested" : ""}`,
  });
  return { tasks, finish, note };
}

async function exploitPhase(ctx: Ctx, reconBrief: string): Promise<string> {
  if (ctx.config.dryRunAgents) {
    ctx.events.append({ phase: "exploit", actor: "exploiter", action: "exploit_summary", result: "dry-run: exploitation skipped." });
    return "dry-run summary";
  }
  const cap = ctx.input.mode === "black" ? 1 : 3;
  /** Cell status for one target × category: done | blocked (host-exec tooling) | missing. */
  const cellStatus = (t: TargetId, c: BatteryCategory) =>
    targetCellStatus(TARGET_PROFILES[t], c, ctx.targetCoverage.get(t));
  /** Full battery: 3 categories × selected targets (12 cells by default). Blocked cells never force more rounds — they are honestly reported, not chased. */
  const missing = () =>
    ctx.input.fullBattery
      ? activeTargets(ctx.input).flatMap((t) =>
          BATTERY_CATEGORIES.filter((c) => cellStatus(t, c) === "missing").map((c) => `${t}:${c}`),
        )
      : BATTERY_CATEGORIES.filter((c) => !ctx.coverage.has(c));
  const summaries: string[] = [];
  const MAX_ROUNDS = 10;
  let forceAsked = false;

  const baseContext = () =>
    `Recon brief:\n${reconBrief.slice(0, 4000)}\n\n${sharedStateDigest(ctx, "exploit")}\n\n` +
    `Registry hits surfaced: ${ctx.registryHits.length}. Probe budget: ${ctx.config.maxExploitProbes} total, ${ctx.probesUsed} used. ` +
    `Battery: ${ctx.input.fullBattery ? activeTargets(ctx.input).map((t) => `${t}:{${BATTERY_CATEGORIES.map((c) => `${c}:${cellStatus(t, c) === "done" ? "done" : cellStatus(t, c) === "blocked" ? "BLOCKED" : "MISSING"}`).join(",")}}`).join(" ") : (["logic", "functionality", "validation"] as const).map((c) => `${c}:${ctx.coverage.has(c) ? "done" : "MISSING"}`).join(", ")}. ` +
    `OPSEC cooldowns: ${ctx.opsecCooldown.size}. Redirects used: ${ctx.redirects}/2.`;

  let directive = await coordinatorDirective(ctx, "decompose", baseContext());
  let rounds = 0;
  while (rounds < MAX_ROUNDS) {
    rounds++;
    if (ctx.probesUsed >= ctx.config.maxExploitProbes) {
      const absent = missing();
      ctx.events.append({
        phase: "exploit",
        actor: "runner",
        action: "battery_incomplete",
        result: absent.length
          ? `Probe budget exhausted with categories unprobed: ${absent.join(", ")}. Recorded as not-covered.`
          : "Probe budget exhausted. Battery complete.",
      });
      break;
    }
    if (directive.tasks.length === 0 || directive.finish) {
      const absent = missing();
      if (absent.length === 0 || forceAsked) {
        if (absent.length > 0) {
          ctx.events.append({
            phase: "exploit",
            actor: "runner",
            action: "battery_incomplete",
            result: `Coordinator finished with categories unprobed: ${absent.join(", ")}. Recorded as not-covered.`,
          });
        }
        break;
      }
      // Battery incomplete but the coordinator wants out early: force one more round.
      forceAsked = true;
      directive = await coordinatorDirective(
        ctx,
        "replan",
        `OVERRIDE — battery incomplete (missing: ${absent.join(", ")}) and probe budget remains (${ctx.config.maxExploitProbes - ctx.probesUsed}). ` +
          `Task the missing categories NOW (one task per category), or explicitly declare which battery items have no applicable surface and why.\n\n${baseContext()}`,
      );
      continue;
    }
    const results = await runBatch(ctx, directive.tasks, cap);
    for (const r of results) {
      summaries.push(`[${r.task.id} ${r.task.kind}${r.task.category ? `/${r.task.category}` : ""}] ${r.summary.slice(0, 400)}`);
    }
    const batchReport =
      results
        .map(
          (r) =>
            `- ${r.task.id} [${r.task.kind}]: ${r.summary.slice(0, 300)} (probes +${r.probesAfter - r.probesBefore}, confirmed +${r.findingsAfter - r.findingsBefore}, killed +${r.killedAfter - r.killedBefore})`,
        )
        .join("\n") || "(no tasks completed)";
    directive = await coordinatorDirective(ctx, "replan", `Last batch results:\n${batchReport}\n\n${baseContext()}`);
  }
  if (rounds >= MAX_ROUNDS) {
    ctx.events.append({
      phase: "exploit",
      actor: "runner",
      action: "round_cap",
      result: `Max orchestration rounds (${MAX_ROUNDS}) reached — closing the phase.`,
    });
  }
  const covered = ctx.input.fullBattery
    ? activeTargets(ctx.input).flatMap((t) => BATTERY_CATEGORIES.filter((c) => cellStatus(t, c) === "done").map((c) => `${t}:${c}`))
    : BATTERY_CATEGORIES.filter((c) => ctx.coverage.has(c));
  const summary = summaries.join("\n\n") || "no tasks executed";
  ctx.events.append({
    phase: "exploit",
    actor: "exploiter",
    action: "exploit_summary",
    result: `Dynamic operation: ${rounds} rounds. Battery coverage: ${covered.join(", ") || "none"} (${ctx.probesUsed} probes). Confirmed: ${ctx.liveFindings.length}, killed: ${ctx.killedLive.length}.`,
  });
  return summary;
}

async function reportPhase(ctx: Ctx, reconBrief: string, exploitSummary: string): Promise<Finding[]> {
  const selected = ctx.input.fullBattery ? activeTargets(ctx.input) : [];
  const fbCells = selected.flatMap((t) => BATTERY_CATEGORIES.map((c) => ({ t, c })));
  const fbStatus = fbCells.map(({ t, c }) => ({ t, c, s: targetCellStatus(TARGET_PROFILES[t], c, ctx.targetCoverage.get(t)) }));
  const fbDone = fbStatus.filter((x) => x.s === "done");
  const fbBlocked = fbStatus.filter((x) => x.s === "blocked");
  const fbMissing = fbStatus.filter((x) => x.s === "missing");
  const covered = BATTERY_CATEGORIES.filter((c) => ctx.coverage.has(c));
  const batteryLine = ctx.input.fullBattery
    ? `Battery coverage (FULL BATTERY — 3 categories × ${selected.length} targets): ${fbDone.length}/${fbCells.length} cells probed ` +
      `(${batteryStatusLine(ctx)}, ${ctx.probesUsed} probes total). ` +
      (fbBlocked.length > 0
        ? `BLOCKED (host-exec tooling not yet available — planned, not probed; see Honest limits): ${fbBlocked.map(({ t, c }) => `${t}:${c}`).join(", ")}. `
        : "") +
      (fbMissing.length > 0
        ? `NOT COVERED: ${fbMissing.map(({ t, c }) => `${t}:${c}`).join(", ")} — list these under Honest limits.`
        : `Full battery complete: all ${fbCells.length} cells probed or honestly blocked.`)
    : `Battery coverage: ${covered.length}/3 categories probed ` +
      `(${covered.map((c) => `${c}:${ctx.coverage.has(c) ? "yes" : "no"}`).join(", ")}, ${ctx.probesUsed} probes total). ` +
      (covered.length < 3 ? `NOT COVERED: ${BATTERY_CATEGORIES.filter((c) => !ctx.coverage.has(c)).join(", ")} — list these under Honest limits.` : "Full battery complete.");
  let reportMd: string;
  if (ctx.config.dryRunAgents) {
    reportMd = `# Engagement report (dry-run)\n\nTarget: ${ctx.input.target}\nMode: ${ctx.input.mode}\n`;
  } else {
    reportMd = await agentLoop(
      ctx,
      "reporter",
      "report",
      reporterPrompt(promptCtx(ctx)),
      `Write the client report now.\n\nAuthorization: ${ctx.verificationProof}\n\nOperation plan: ${JSON.stringify(ctx.plan)}\n\nShared verdicts this engagement — confirmed (${ctx.liveFindings.length}):\n${ctx.liveFindings.map((f) => `- [${f.severity}] ${f.title} (${f.attackId}${f.vulnClass ? `, ${f.vulnClass}` : ""}): ${f.evidence}`).join("\n") || "(none)"}\nKilled hypotheses (${ctx.killedLive.length}):\n${ctx.killedLive.map((k) => `- ${k.hypothesis} → ${k.killingObservation}`).join("\n") || "(none)"}\nRegistry hits consulted: ${ctx.registryHits.length}. Target fingerprint: ${JSON.stringify(ctx.fingerprint)}.\n\n${batteryLine}\n\nRecon brief:\n${reconBrief.slice(0, 4000)}\n\nExploitation summary:\n${exploitSummary.slice(0, 4000)}\n\nEnd the report with a JSON block: \`\`\`json {"findings": [{"id":"F-1","severity":"low","title":"...","attackIds":["T1190"],"evidence":"...","fix":"...","retest":"...","status":"confirmed"}]} \`\`\``,
      READ_TOOLS,
      4,
    );
  }
  const parsed = extractJsonBlock(reportMd) as { findings?: Finding[] } | null;
  const findings: Finding[] = Array.isArray(parsed?.findings) ? parsed.findings : [];
  // The unified operation narrative ("Megazord"): the reporter writes it first
  // as plain paragraphs; the runner extracts it for the console header.
  const narrative = extractNarrative(reportMd);
  if (narrative) {
    ctx.operationNarrative = narrative;
    ctx.events.updateState({ operationNarrative: narrative });
  }
  // Runner-computed facts are appended deterministically — never trusted to the model.
  reportMd += `\n\n---\n\n## Battery coverage (runner-computed)\n\n${batteryLine}\n`;
  writeFileSync(join(ctx.events.dir, "report.md"), reportMd);
  ctx.events.append({ phase: "report", actor: "reporter", action: "report_written", result: `Report written (${findings.length} findings parsed).` });
  ctx.events.updateState({ findings });
  return findings;
}

/** Extract the reporter's opening OPERATION NARRATIVE paragraphs (before the first section). */
function extractNarrative(md: string): string {
  const cut = md.search(/\n#{1,3}\s|\n\d+\.\s+\*\*/);
  const head = (cut > 0 ? md.slice(0, cut) : md).replace(/^.*OPERATION NARRATIVE.*$/gim, "").trim();
  return head.slice(0, 600);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function resolveConfig(env: NodeJS.ProcessEnv, opts: {
  mcpToken?: string;
  deepseekApiKey?: string;
  qwenApiKey?: string;
  mcpEndpoint?: string;
  maxReconTurns?: number;
  maxExploitProbes?: number;
  maxActions?: number;
  maxDurationMs?: number;
  probeDelayMs?: number;
  engagementsDir?: string;
  registryPath?: string;
  dryRunAgents?: boolean;
  localSandbox?: boolean;
} = {}): ResolvedRunnerConfig {
  const mcpToken = opts.mcpToken ?? env["SECSCAN_MCP_TOKEN"];
  if (!mcpToken) {
    throw new Error(
      "[runner] SECSCAN_MCP_TOKEN is not set. Enter the SecScan MCP token via the Secure Vault (it lands in the environment).",
    );
  }
  const deepseekApiKey = opts.deepseekApiKey ?? env["DEEPSEEK_API_KEY"];
  if (!deepseekApiKey && !opts.dryRunAgents) {
    throw new Error(
      "[runner] DEEPSEEK_API_KEY is not set. Enter the DeepSeek API key via the Secure Vault.",
    );
  }
  // The exploiter runs on Qwen (qwen3.8-max reasoning) — fail fast if its key
  // is missing rather than dying mid-engagement.
  const qwenApiKey = opts.qwenApiKey ?? env["QWEN_API_KEY"] ?? env["DASHSCOPE_API_KEY"];
  if (!qwenApiKey && !opts.dryRunAgents) {
    throw new Error(
      "[runner] QWEN_API_KEY is not set. Enter the Alibaba Model Studio API key via the Secure Vault.",
    );
  }
  if (opts.qwenApiKey && !env["QWEN_API_KEY"] && !env["DASHSCOPE_API_KEY"]) {
    // Key passed programmatically: make it visible to the provider, which
    // reads env only. Never logged, never persisted.
    env["QWEN_API_KEY"] = opts.qwenApiKey;
  }
  return {
    mcpEndpoint: opts.mcpEndpoint ?? env["SECSCAN_MCP_URL"] ?? "https://secscan.us/api/mcp",
    mcpToken,
    deepseekApiKey: deepseekApiKey ?? "",
    qwenApiKey: qwenApiKey ?? "",
    maxReconTurns: opts.maxReconTurns ?? 10,
    maxExploitProbes: opts.maxExploitProbes ?? 12,
    maxActions: opts.maxActions ?? 60,
    maxDurationMs: opts.maxDurationMs ?? 45 * 60_000,
    probeDelayMs: opts.probeDelayMs ?? 800,
    engagementsDir:
      opts.engagementsDir ??
      (env["REDTEAM_HOME"] ? join(env["REDTEAM_HOME"], "engagements", "live") : join(process.cwd(), "engagements", "live")),
    registryPath:
      opts.registryPath ??
      (env["REDTEAM_HOME"] ? join(env["REDTEAM_HOME"], "engagements", "registry.json") : join(process.cwd(), "engagements", "registry.json")),
    dryRunAgents: opts.dryRunAgents ?? false,
    localSandbox: opts.localSandbox ?? env["REDTEAM_LOCAL_SANDBOX"] === "1",
  };
}

export interface RunOptions {
  mcpToken?: string;
  deepseekApiKey?: string;
  /** Alibaba Model Studio key for the exploiter (Qwen). Env QWEN_API_KEY preferred. */
  qwenApiKey?: string;
  mcpEndpoint?: string;
  /** Override the generated engagement ID (the console passes its request ID for correlation). */
  engagementId?: string;
  maxReconTurns?: number;
  maxExploitProbes?: number;
  maxActions?: number;
  maxDurationMs?: number;
  probeDelayMs?: number;
  engagementsDir?: string;
  /** Registry path override (tests). Defaults to <REDTEAM_HOME>/engagements/registry.json. */
  registryPath?: string;
  dryRunAgents?: boolean;
  /** LOCAL SANDBOX MODE ONLY. See ResolvedRunnerConfig.localSandbox. Default false. */
  localSandbox?: boolean;
  deps?: RunnerDeps;
}

export async function runEngagement(input: EngagementInput, opts: RunOptions = {}): Promise<EngagementResult> {
  const config = resolveConfig(process.env, opts);
  const deps = opts.deps ?? {};

  if (!input.target) throw new Error("[runner] target is required");
  if (!["red", "black"].includes(input.mode)) throw new Error(`[runner] mode must be red|black, got ${input.mode}`);
  if (!input.roe?.scope?.length) throw new Error("[runner] ROE scope is required (exact hosts).");
  if (!inTestWindow(new Date(), input.roe)) {
    throw new Error("[runner] current time is outside the ROE test window — refusing to run.");
  }

  const hosts = scopeHosts(input.roe);
  if (hosts.length === 0) throw new Error("[runner] ROE scope produced no parseable hosts — refusing to run.");

  const engagementId = opts.engagementId ?? `eng-${new Date().toISOString().slice(0, 10)}-${Math.random().toString(36).slice(2, 6)}`;
  const dir = join(config.engagementsDir, engagementId);
  const events = new EventLog(dir, engagementId, { target: input.target, mode: input.mode, objective: input.objective });

  // The registry: load, or seed with the v0.3.x secscan.us engagement data on first run.
  const registryPath = config.registryPath;
  const registry: VulnerabilityRegistry = loadRegistryFile(registryPath) ?? seedRegistry();
  saveRegistryFile(registryPath, registry);

  const ctx: Ctx = {
    input,
    config,
    deps,
    events,
    mcp: deps.mcp ?? new McpClient({ endpoint: config.mcpEndpoint, token: config.mcpToken }),
    prober: deps.prober ?? new WebProber({ scopeHosts: hosts, minDelayMs: config.probeDelayMs, allowPrivateHosts: config.localSandbox }),
    hosts,
    domain: hosts[0]!,
    excludedNote: "",
    startedAt: Date.now(),
    actions: 0,
    plan: null,
    opsecCooldown: new Set(),
    consecutive5xx: 0,
    coverage: new Set(),
    targetCoverage: new Map(),
    probesUsed: 0,
    fingerprint: { host: hosts[0]!, stack: [], appType: "unknown" },
    registry,
    registryPath,
    registryHits: [],
    targetMap: [],
    liveFindings: [],
    killedLive: [],
    redirects: 0,
    deniedStreak: 0,
  };

  events.append({ phase: "authorize", actor: "runner", action: "engagement_start", target: input.target, result: `Mode=${input.mode.toUpperCase()} objective="${input.objective}" scope=[${hosts.join(", ")}] registry=${registry.confirmed.length} confirmed / ${registry.killed.length} killed entries loaded` });

  try {
    const verdict = await authorizePhase(ctx);
    if (!verdict.allowed) {
      return { engagementId, status: "blocked", blockedReason: verdict.reason, findings: [] };
    }
    await planPhase(ctx);
    await coordinatorSignOff(ctx, "plan→recon", `Operation plan:\n${JSON.stringify(ctx.plan, null, 1)}`);
    const brief = await reconPhase(ctx);
    await coordinatorSignOff(
      ctx,
      "recon→exploit",
      `Recon brief:\n${brief.slice(0, 3000)}\n\nShared target map (${ctx.targetMap.length} entries):\n${ctx.targetMap.map((t) => `- ${t.method} ${t.area}${t.authState ? ` [${t.authState}]` : ""}${t.attackId ? ` ${t.attackId}` : ""}`).join("\n") || "(empty)"}\nRegistry hits consulted: ${ctx.registryHits.length}. Fingerprint: ${JSON.stringify(ctx.fingerprint)}`,
    );
    const summary = await exploitPhase(ctx, brief);
    await coordinatorSignOff(
      ctx,
      "exploit→report",
      `Exploitation summary:\n${summary.slice(0, 3000)}\n\nVerdicts — confirmed: ${ctx.liveFindings.length}, killed: ${ctx.killedLive.length}.\nBattery: ${["logic", "functionality", "validation"].map((c) => `${c}:${ctx.coverage.has(c as BatteryCategory) ? "yes" : "no"}`).join(", ")}.`,
    );
    const findings = await reportPhase(ctx, brief, summary);
    events.updateState({ status: "complete", phase: "done" });
    events.append({ phase: "done", actor: "runner", action: "engagement_complete", result: `Complete. ${findings.length} findings.` });
    return { engagementId, status: "complete", reportPath: join(dir, "report.md"), findings };
  } catch (err) {
    const reason = err instanceof HaltError ? err.message : `unexpected error: ${(err as Error).message}`;
    events.updateState({ status: "halted", phase: "halted", blockedReason: reason });
    events.append({ phase: "halted", actor: "runner", action: "engagement_halted", result: reason });
    return { engagementId, status: "halted", blockedReason: reason, findings: events.snapshot.findings };
  } finally {
    // The registry always persists — every verdict recorded live is already in it.
    saveRegistryFile(registryPath, registry);
  }
}
