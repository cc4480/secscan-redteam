/**
 * Live engagement orchestration: authorize → plan → recon → exploit → report.
 *
 * Each phase runs its role's LLM in a REASON → ACT → OBSERVE loop. The runner —
 * not the model — enforces the hard boundaries: ownership verification,
 * scope, technique exclusions, blackout windows, rate limits, and stop
 * conditions. Every tool call and every decision becomes a streamed event.
 */

import { writeFileSync } from "node:fs";
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
import { WebProber, type ProberLike } from "./prober.js";
import { coordinatorPrompt, exploiterPrompt, reconPrompt, reporterPrompt } from "./prompts.js";
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

export interface RunnerDeps {
  verify?: (domain: string, cfg: { endpoint: string; token: string }) => Promise<boolean>;
  completeForRole?: typeof routerCompleteForRole;
  /** Injectable for tests (defaults: real McpClient / WebProber). */
  mcp?: McpClient;
  prober?: ProberLike;
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
  probesUsed: number;
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
    "Send ONE HTTP request to an in-scope host to test a specific hypothesis. In-scope hosts only (runner-enforced), non-destructive. Include attackId (ATT&CK, e.g. T1190), category (logic|functionality|validation), and a one-sentence hypothesis.",
  parameters: {
    type: "object",
    properties: {
      method: { type: "string" },
      url: { type: "string" },
      headers: { type: "object" },
      body: { type: "string" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      hypothesis: { type: "string" },
    },
    required: ["method", "url", "category"],
  },
};

const READ_TOOLS = MCP_TOOLS.filter((t) => t.name !== "scan_url");
const RECON_TOOLS = MCP_TOOLS;
const EXPLOIT_TOOLS = [...READ_TOOLS, PROBE_TOOL];

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
  return { result: `DENIED: unknown tool ${call.name}` };
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
    if (res.text) {
      notes.push(res.text);
      ctx.events.append({ phase, actor: role, action: "reasoning", result: res.text.slice(0, 500) });
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
        content: d.result.slice(0, 4000),
      });
      const capAfter = haltedByCaps(ctx);
      if (capAfter) {
        ctx.events.append({ phase, actor: "runner", action: "halt", result: `Halted: ${capAfter}.` });
        throw new HaltError(capAfter);
      }
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
} {
  return {
    mode: ctx.input.mode,
    objective: ctx.input.objective,
    target: ctx.input.target,
    scopeHosts: ctx.hosts,
    roe: ctx.input.roe,
  };
}

async function authorizePhase(ctx: Ctx): Promise<GateVerdict> {
  const verdict = await checkAuthorization(
    ctx.domain,
    { mcpEndpoint: ctx.config.mcpEndpoint, mcpToken: ctx.config.mcpToken },
    ctx.deps.verify,
  );
  if (!verdict.allowed) {
    ctx.events.append({ phase: "authorize", actor: "coordinator", action: "authorization_denied", target: ctx.domain, result: verdict.reason ?? "denied" });
    ctx.events.updateState({ status: "blocked", phase: "blocked", blockedReason: verdict.reason });
    return verdict;
  }
  ctx.verifiedAt = new Date().toISOString();
  ctx.verificationProof = `SecScan server lists ${ctx.domain} as ownership-verified (${ctx.verifiedAt}).`;
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

async function planPhase(ctx: Ctx): Promise<void> {
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
    `Authorization is proven for ${ctx.domain} (${ctx.verificationProof}). Produce the operation plan as JSON now: { "adversaryProfile": "...", "steps": [{ "phase": "recon|exploit", "attackId": "Txxxx", "description": "...", "stealthNote": "..." }] }.`,
    READ_TOOLS,
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
  return brief;
}

async function exploitPhase(ctx: Ctx, reconBrief: string): Promise<string> {
  if (ctx.config.dryRunAgents) {
    ctx.events.append({ phase: "exploit", actor: "exploiter", action: "exploit_summary", result: "dry-run: exploitation skipped." });
    return "dry-run summary";
  }
  let nudges = 0;
  const missing = () => BATTERY_CATEGORIES.filter((c) => !ctx.coverage.has(c));
  const summary = await agentLoop(
    ctx,
    "exploiter",
    "exploit",
    exploiterPrompt(promptCtx(ctx)),
    `Recon brief:\n${reconBrief.slice(0, 6000)}\n\nBegin the hypothesis → probe → observe loop. ` +
      `Tag every http_probe with its ATT&CK attackId AND battery category (logic|functionality|validation). ` +
      (ctx.input.mode === "black"
        ? "BLACK mode: low and slow. Abandon any vector that triggers an OPSEC signal."
        : "RED mode: be aggressive and broad, but stay non-destructive and in scope.") +
      ` When hypotheses stop producing surprises, summarize confirmed vs killed findings and stop calling tools.`,
    EXPLOIT_TOOLS,
    ctx.config.maxExploitProbes + 8,
    {
      // The battery is complete only when all three categories have been
      // probed. If the model goes idle early, send it back for the missing
      // categories instead of letting the phase end thin.
      onIdle: () => {
        const absent = missing();
        if (absent.length === 0) return null;
        if (ctx.probesUsed >= ctx.config.maxExploitProbes) {
          ctx.events.append({
            phase: "exploit",
            actor: "runner",
            action: "battery_incomplete",
            result: `Probe budget exhausted with categories unprobed: ${absent.join(", ")}. Recorded as not-covered.`,
          });
          return null;
        }
        if (++nudges > 3) return null;
        return (
          `Battery incomplete — no probes yet in: ${absent.map((c) => CATEGORY_LABELS[c]).join("; ")}. ` +
          `Form a hypothesis in "${absent[0]}" from the battery checklist and probe it now. ` +
          `If the target exposes no surface for that category, say so explicitly and name the skipped battery items.`
        );
      },
    },
  );
  const covered = BATTERY_CATEGORIES.filter((c) => ctx.coverage.has(c));
  ctx.events.append({
    phase: "exploit",
    actor: "exploiter",
    action: "exploit_summary",
    result: `Battery coverage: ${covered.join(", ") || "none"} (${ctx.probesUsed} probes). ${summary.slice(0, 1200)}`,
  });
  return summary;
}

async function reportPhase(ctx: Ctx, reconBrief: string, exploitSummary: string): Promise<Finding[]> {
  const covered = BATTERY_CATEGORIES.filter((c) => ctx.coverage.has(c));
  const batteryLine =
    `Battery coverage: ${covered.length}/3 categories probed ` +
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
      `Write the client report now.\n\nAuthorization: ${ctx.verificationProof}\n\nOperation plan: ${JSON.stringify(ctx.plan)}\n\n${batteryLine}\n\nRecon brief:\n${reconBrief.slice(0, 4000)}\n\nExploitation summary:\n${exploitSummary.slice(0, 4000)}\n\nEnd the report with a JSON block: \`\`\`json {"findings": [{"id":"F-1","severity":"low","title":"...","attackIds":["T1190"],"evidence":"...","fix":"...","retest":"...","status":"confirmed"}]} \`\`\``,
      READ_TOOLS,
      4,
    );
  }
  const parsed = extractJsonBlock(reportMd) as { findings?: Finding[] } | null;
  const findings: Finding[] = Array.isArray(parsed?.findings) ? parsed.findings : [];
  // Runner-computed facts are appended deterministically — never trusted to the model.
  reportMd += `\n\n---\n\n## Battery coverage (runner-computed)\n\n${batteryLine}\n`;
  writeFileSync(join(ctx.events.dir, "report.md"), reportMd);
  ctx.events.append({ phase: "report", actor: "reporter", action: "report_written", result: `Report written (${findings.length} findings parsed).` });
  ctx.events.updateState({ findings });
  return findings;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function resolveConfig(env: NodeJS.ProcessEnv, opts: {
  mcpToken?: string;
  deepseekApiKey?: string;
  mcpEndpoint?: string;
  maxReconTurns?: number;
  maxExploitProbes?: number;
  maxActions?: number;
  maxDurationMs?: number;
  probeDelayMs?: number;
  engagementsDir?: string;
  dryRunAgents?: boolean;
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
  return {
    mcpEndpoint: opts.mcpEndpoint ?? env["SECSCAN_MCP_URL"] ?? "https://secscan.us/api/mcp",
    mcpToken,
    deepseekApiKey: deepseekApiKey ?? "",
    maxReconTurns: opts.maxReconTurns ?? 10,
    maxExploitProbes: opts.maxExploitProbes ?? 12,
    maxActions: opts.maxActions ?? 60,
    maxDurationMs: opts.maxDurationMs ?? 45 * 60_000,
    probeDelayMs: opts.probeDelayMs ?? 800,
    engagementsDir:
      opts.engagementsDir ??
      (env["REDTEAM_HOME"] ? join(env["REDTEAM_HOME"], "engagements", "live") : join(process.cwd(), "engagements", "live")),
    dryRunAgents: opts.dryRunAgents ?? false,
  };
}

export interface RunOptions {
  mcpToken?: string;
  deepseekApiKey?: string;
  mcpEndpoint?: string;
  /** Override the generated engagement ID (the console passes its request ID for correlation). */
  engagementId?: string;
  maxReconTurns?: number;
  maxExploitProbes?: number;
  maxActions?: number;
  maxDurationMs?: number;
  probeDelayMs?: number;
  engagementsDir?: string;
  dryRunAgents?: boolean;
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

  const ctx: Ctx = {
    input,
    config,
    deps,
    events,
    mcp: deps.mcp ?? new McpClient({ endpoint: config.mcpEndpoint, token: config.mcpToken }),
    prober: deps.prober ?? new WebProber({ scopeHosts: hosts, minDelayMs: config.probeDelayMs }),
    hosts,
    domain: hosts[0]!,
    excludedNote: "",
    startedAt: Date.now(),
    actions: 0,
    plan: null,
    opsecCooldown: new Set(),
    consecutive5xx: 0,
    coverage: new Set(),
    probesUsed: 0,
  };

  events.append({ phase: "authorize", actor: "runner", action: "engagement_start", target: input.target, result: `Mode=${input.mode.toUpperCase()} objective="${input.objective}" scope=[${hosts.join(", ")}]` });

  try {
    const verdict = await authorizePhase(ctx);
    if (!verdict.allowed) {
      return { engagementId, status: "blocked", blockedReason: verdict.reason, findings: [] };
    }
    await planPhase(ctx);
    const brief = await reconPhase(ctx);
    const summary = await exploitPhase(ctx, brief);
    const findings = await reportPhase(ctx, brief, summary);
    events.updateState({ status: "complete", phase: "done" });
    events.append({ phase: "done", actor: "runner", action: "engagement_complete", result: `Complete. ${findings.length} findings.` });
    return { engagementId, status: "complete", reportPath: join(dir, "report.md"), findings };
  } catch (err) {
    const reason = err instanceof HaltError ? err.message : `unexpected error: ${(err as Error).message}`;
    events.updateState({ status: "halted", phase: "halted", blockedReason: reason });
    events.append({ phase: "halted", actor: "runner", action: "engagement_halted", result: reason });
    return { engagementId, status: "halted", blockedReason: reason, findings: events.snapshot.findings };
  }
}
