/**
 * runEngagement entry point + RunOptions (v0.19.0 refactor — extracted from phases.ts).
 */
import { ApprovalLog, TIER_ENV, defaultTier, describeTier, parseTier, requireNamedOperator, requireTier2ProductionApproval, resolveOperatorName, tier2ProductionConfirmed, writeTierFile } from "../accountability/index.js";
import { type BatteryCategory } from "../battery.js";
import { type Ctx, HaltError, type RunnerDeps } from "../context.js";
import { type EngagementInput, type EngagementResult, type ResolvedRunnerConfig } from "../types.js";
import { EventLog } from "../events.js";
import { HostExecutor } from "../host-exec/index.js";
import { McpClient } from "../mcp.js";
import { MsfExecutor } from "../msf/index.js";
import { NucleiExecutor } from "../nuclei/index.js";
import { TargetAutoHalt, TargetRateLimiter, describeEnvironment, parseEnvironment, productionConfirmed, requireGraduation, resolveEffectiveRps, resolveLogRotationConfig } from "../safety/index.js";
import { type VulnerabilityRegistry, loadRegistryFile, saveRegistryFile, seedRegistry } from "../registry.js";
import { WebProber } from "../prober.js";
import { activeTargets } from "../targets.js";
import { buildItemLedger } from "../coverage/items.js";
import { fireSlack, reportPhase } from "../report.js";
import { inTestWindow, scopeHosts } from "../gate.js";
import { join } from "node:path";
import { authorizePhase } from "./authorize.js";
import { planPhase } from "./plan.js";
import { reconPhase } from "./recon.js";
import { exploitPhase } from "./exploit.js";
import { resolveConfig } from "./config.js";
import { coordinatorSignOff } from "./signoff.js";
import { resolveVariantCap } from "../variants/index.js";

export interface RunOptions {
  mcpToken?: string;
  deepseekApiKey?: string;
  /** Alibaba Model Studio key. Optional since v0.6 (DeepSeek-only policy — no role routes to Qwen); threaded through so reinstating Qwen needs no config change. Env QWEN_API_KEY preferred. */
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
  /** Per-host rate limit override (requests/sec). Env REDTEAM_MAX_RPS. Production caps at 2 mechanically. */
  maxRpsPerHost?: number;
  /** v0.20.0: per-item variant cap override. Env REDTEAM_MAX_VARIANTS. Undefined = env default (25 staging, 10 production). */
  maxVariantsPerItem?: number;
  /**
   * v0.26.0: log-rotation overrides. CLI --log-max-bytes / --log-max-archives,
   * env REDTEAM_LOG_MAX_BYTES / REDTEAM_LOG_MAX_ARCHIVES. Undefined = env,
   * then defaults (50 MiB, 5 archives). events.jsonl and engagement.md
   * rotate together when the cap is hit; the fresh file leads with a
   * `log_rotated` audit event so the audit trail stays resolvable.
   */
  maxLogBytes?: number;
  maxLogArchives?: number;
  dryRunAgents?: boolean;
  /** LOCAL SANDBOX MODE ONLY. See ResolvedRunnerConfig.localSandbox. Default false. */
  localSandbox?: boolean;
  deps?: RunnerDeps;
  /**
   * v0.22.0 UI kill switch: called with the operator abort handle once the
   * engagement context exists (synchronously, before authorizePhase). The
   * handle triggers the kill switch exactly as the coordinator's
   * abort_engagement does — in-flight executions terminate, new work is
   * refused, and the next tool dispatch throws HaltError so the engagement
   * unwinds to "halted".
   */
  onCtxReady?: (handle: OperatorAbortHandle) => void;
}

/** Operator abort handle handed to the UI server (v0.22.0). */
export interface OperatorAbortHandle {
  abort: (reason: string) => void;
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

  // v0.13.0 safety case: staging→production graduation is MECHANICAL.
  // Production without explicit operator confirmation refuses to start —
  // fail fast, before the engagement directory is even created.
  const environment = input.environment ?? parseEnvironment(process.env["REDTEAM_ENV"]);
  const prodConfirmed = input.confirmProduction ?? productionConfirmed(process.env);
  requireGraduation(environment, prodConfirmed);
  const { rps, productionCapApplied } = resolveEffectiveRps(environment, config.maxRpsPerHost);

  // v0.17.0 accountability: autonomy tiers + named human operator.
  // Tier resolves: explicit input → REDTEAM_TIER → environment default
  // (staging: Tier 2 chain, production: Tier 1 validate). Tier 2 on
  // production needs its own explicit operator approval. Production always
  // needs a NAMED human operator — someone must own the findings.
  // All fail fast, before the engagement directory is even created.
  const tier = input.tier ?? parseTier(process.env[TIER_ENV]) ?? defaultTier(environment);
  const tier2ProdConfirmed = input.confirmTier2Production ?? tier2ProductionConfirmed(process.env);
  requireTier2ProductionApproval(tier, environment, tier2ProdConfirmed);
  const operator = resolveOperatorName(input.operatorName, process.env);
  requireNamedOperator(environment, operator);

  const hosts = scopeHosts(input.roe);
  if (hosts.length === 0) throw new Error("[runner] ROE scope produced no parseable hosts — refusing to run.");

  const engagementId = opts.engagementId ?? `eng-${new Date().toISOString().slice(0, 10)}-${Math.random().toString(36).slice(2, 6)}`;
  const dir = join(config.engagementsDir, engagementId);
  // v0.26.0: log rotation — CLI/env overrides, then env defaults. events.jsonl
  // and engagement.md rotate together when the cap is hit (see EventLog).
  const rotation = resolveLogRotationConfig(process.env, {
    maxLogBytes: opts.maxLogBytes,
    maxLogArchives: opts.maxLogArchives,
  });
  const events = new EventLog(dir, engagementId, { target: input.target, mode: input.mode, objective: input.objective }, rotation);

  // v0.17.0 accountability: the append-only approval log. Tier declared and
  // production confirmation are recorded here FIRST — before any agent acts.
  const approvals = new ApprovalLog(dir, engagementId);
  const operatorLabel = operator ?? "(operator name not supplied — set REDTEAM_OPERATOR)";
  approvals.append("tier-declared", operatorLabel, `Autonomy ${describeTier(tier)} declared for ${environment} engagement`, undefined, tier);
  if (environment === "production") {
    approvals.append("production-confirm", operatorLabel, "Production engagement explicitly confirmed by operator");
    if (tier === 2) {
      approvals.append("tier-escalation", operatorLabel, "Tier 2 (chain) on production explicitly approved by operator", 1, 2);
    }
  }

  // v0.24.0: tier.json — the mid-run tier signal. The dispatcher re-reads it
  // before every tier check; `redteam-runner escalate` and the UI rewrite it
  // (atomically) when the operator changes the tier. No new network surface.
  writeTierFile(dir, { tier, declared: tier, environment, updatedAt: new Date().toISOString() });

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
    hostExecutor: deps.hostExecutor ?? new HostExecutor(),
    msfExecutor: deps.msfExecutor ?? new MsfExecutor(),
    nucleiExecutor: deps.nucleiExecutor ?? new NucleiExecutor(),
    nuclei: { templateExecutions: 0, templatesRun: 0, findings: 0 },
    hostKill: { aborted: false, controllers: new Set() },
    // v0.13.0 safety case: mechanical protections, armed from engagement start.
    safety: {
      limiter: new TargetRateLimiter({ rpsPerHost: rps }),
      autoHalt: new TargetAutoHalt(),
      environment,
      productionConfirmed: prodConfirmed,
      rpsPerHost: rps,
      productionCapApplied,
      killSwitchAborts: 0,
    },
    // v0.17.0 accountability: graduated autonomy, mechanically enforced.
    tier: { current: tier, declared: tier, chainSteps: new Map() },
    approvals,
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
    // v0.18.0 per-item verdicts: every selected battery item opens pending
    // (or blocked when its prerequisite is unmet); the report gate refuses
    // "complete" while any item is still pending.
    itemLedger: input.fullBattery ? buildItemLedger(activeTargets(input)) : new Map(),
    probesUsed: 0,
    // v0.20.0 payload-variant expansion: per-item cap resolved mechanically
    // (env default 25 staging / 10 production; --max-variants / REDTEAM_MAX_VARIANTS).
    variantCap: resolveVariantCap(environment, config.maxVariantsPerItem),
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

  events.append({ phase: "authorize", actor: "runner", action: "engagement_start", target: input.target, result: `Mode=${input.mode.toUpperCase()} env=${describeEnvironment(environment, prodConfirmed)} tier=${describeTier(tier)} rate_limit=${rps}rps/host objective="${input.objective}" scope=[${hosts.join(", ")}] registry=${registry.confirmed.length} confirmed / ${registry.killed.length} killed entries loaded` });
  // v0.22.0 UI kill switch: hand the operator abort handle to whoever is
  // driving this engagement (the UI server registers it for the kill-switch
  // button). Fires synchronously here — before any agent acts — so the
  // handle is always available while the engagement is live.
  if (opts.onCtxReady) {
    opts.onCtxReady({
      abort: (reason: string) => {
        ctx.hostKill.aborted = true;
        for (const c of ctx.hostKill.controllers) {
          try {
            c.abort();
          } catch {
            /* best effort */
          }
        }
        ctx.hostKill.controllers.clear();
        ctx.safety.killSwitchAborts++;
        ctx.events.append({
          phase: ctx.events.snapshot.phase,
          // Actor "coordinator": the kill-switch abort carries coordinator-level
          // authority; the result records that it came from the operator console.
          actor: "coordinator",
          action: "abort_engagement",
          result: `ABORTED by operator: ${reason.slice(0, 500)}`,
        });
      },
    });
  }
  // v0.15.0: Slack lifecycle — engagement started (best-effort, never blocking).
  void fireSlack(ctx, { kind: "started" });

  try {
    const verdict = await authorizePhase(ctx);
    if (!verdict.allowed) {
      return { engagementId, status: "blocked", blockedReason: verdict.reason, findings: [] };
    }
    await planPhase(ctx);
    await coordinatorSignOff(ctx, "plan→recon", `Operation plan:\n${JSON.stringify(ctx.plan, null, 1)}`);
    void fireSlack(ctx, { kind: "phase", phase: "recon" });
    const brief = await reconPhase(ctx);
    await coordinatorSignOff(
      ctx,
      "recon→exploit",
      `Recon brief:\n${brief.slice(0, 3000)}\n\nShared target map (${ctx.targetMap.length} entries):\n${ctx.targetMap.map((t) => `- ${t.method} ${t.area}${t.authState ? ` [${t.authState}]` : ""}${t.attackId ? ` ${t.attackId}` : ""}`).join("\n") || "(empty)"}\nRegistry hits consulted: ${ctx.registryHits.length}. Fingerprint: ${JSON.stringify(ctx.fingerprint)}`,
    );
    const summary = await exploitPhase(ctx, brief);
    void fireSlack(ctx, { kind: "phase", phase: "exploit" });
    await coordinatorSignOff(
      ctx,
      "exploit→report",
      `Exploitation summary:\n${summary.slice(0, 3000)}\n\nVerdicts — confirmed: ${ctx.liveFindings.length}, killed: ${ctx.killedLive.length}.\nBattery: ${["logic", "functionality", "validation"].map((c) => `${c}:${ctx.coverage.has(c as BatteryCategory) ? "yes" : "no"}`).join(", ")}.`,
    );
    const findings = await reportPhase(ctx, brief, summary);
    void fireSlack(ctx, { kind: "phase", phase: "report" });
    events.updateState({ status: "complete", phase: "done" });
    events.append({ phase: "done", actor: "runner", action: "engagement_complete", result: `Complete. ${findings.length} findings.` });
    return { engagementId, status: "complete", reportPath: join(dir, "report.md"), findings };
  } catch (err) {
    const reason = err instanceof HaltError ? err.message : `unexpected error: ${(err as Error).message}`;
    events.updateState({ status: "halted", phase: "halted", blockedReason: reason });
    events.append({ phase: "halted", actor: "runner", action: "engagement_halted", result: reason });
    void fireSlack(ctx, { kind: "halted", reason });
    return { engagementId, status: "halted", blockedReason: reason, findings: events.snapshot.findings };
  } finally {
    // v0.23.0: no blind save here. Every verdict persists atomically via
    // transactRegistryFile at write time; a whole-file save of this
    // engagement's in-memory copy would silently clobber verdicts transacted
    // by a concurrent engagement. The in-memory registry mirrors the file.
  }
}
