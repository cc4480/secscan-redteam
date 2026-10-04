/**
 * Public API of the live engagement runner.
 *
 * ```ts
 * import { runEngagement } from "@secscan/redteam-runner";
 * const result = await runEngagement({
 *   target: "secscan.us",
 *   mode: "red",
 *   objective: "assess the external attack surface",
 *   roe: { scope: ["secscan.us"] },
 * });
 * ```
 *
 * Credentials come from the environment (Secure Vault), never from code:
 *   SECSCAN_MCP_TOKEN, DEEPSEEK_API_KEY, QWEN_API_KEY (optional since v0.6 —
 *   DeepSeek-only policy), SECSCAN_MCP_URL (optional).
 *
 * Console bridge: the console's "start engagement" action writes an
 * EngagementInput JSON file into the queue dir; `watchQueue()` picks it up
 * and runs it. Engagement state streams to
 * <engagementsDir>/<id>/{events.jsonl,state.json,engagement.md,report.md}.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, basename } from "node:path";
import { readEvents, readState, type LiveState } from "./events.js";
import { runEngagement, type RunOptions } from "./phases.js";
import { isTargetId, type TargetId } from "./targets.js";
import { parseTier } from "./accountability/index.js";
import type { EngagementEvent, EngagementInput, EngagementResult } from "./types.js";

export { runEngagement, resolveConfig } from "./phases.js";
export type { RunOptions } from "./phases.js";
export type { RunnerDeps } from "./context.js";
export type {
  EngagementEvent,
  EngagementInput,
  EngagementMode,
  EngagementPhase,
  EngagementResult,
  EngagementStatus,
  Finding,
  OperationPlan,
  PlanStep,
  BlackoutWindow,
  RulesOfEngagement,
  RunnerOptions,
} from "./types.js";
export type { LiveState };
export { readEvents, readState };
export { TECHNIQUES, lookupTechnique, defaultExcludedForMode, resolveExcludedTechniques, ALWAYS_EXCLUDED } from "./attack.js";
export {
  BATTERY,
  BATTERY_CATEGORIES,
  CATEGORY_LABELS,
  batteryChecklistText,
  batteryItemsFor,
  lookupBatteryItem,
} from "./battery.js";
export type { BatteryCategory, BatteryItem } from "./battery.js";
export { scopeHosts, urlInScope, inBlackout, inTestWindow, techniqueAllowed, checkAuthorization } from "./gate.js";
export type { CheckAuthorizationOptions } from "./gate.js";
export { isPrivateOrLoopbackHost, validateProbeTarget } from "./prober.js";
export type { ValidateProbeTargetOptions } from "./prober.js";
export {
  COMPLIANCE_CONTROLS,
  METHODOLOGY_EXCLUSIONS,
  METHODOLOGY_TOOLS,
  TECHNIQUE_CONTROL_MAP,
  allBatteryAttackIds,
  buildCompliancePack,
  buildRetestEvidence,
  controlsForTechnique,
  invalidMappedControlIds,
  lookupControl,
  renderAttestationLetter,
  renderCompliancePackMarkdown,
  unmappedBatteryTechniques,
} from "./compliance/index.js";
export type {
  AttestationInput,
  ComplianceControl,
  ComplianceFramework,
  CompliancePack,
  CompliancePackInput,
  PackFinding,
  RetestEntry,
  RetestObservation,
  TechniqueControlMapping,
} from "./compliance/index.js";
export {
  TargetRateLimiter,
  TargetAutoHalt,
  buildSafetyManifest,
  renderSafetyManifestMarkdown,
  buildZeroDisruptionRecord,
  disruptionVerdict,
  redactPii,
  piiPatternLabels,
  parseEnvironment,
  productionConfirmed,
  requireGraduation,
  resolveEffectiveRps,
  isTargetDistress,
  PROTECTIONS_IN_FORCE,
  RESIDUAL_RISKS,
  SAFETY_MANIFEST_VERSION,
} from "./safety/index.js";
export type {
  SafetyManifest,
  ManifestInputs,
  ZeroDisruptionRecord,
  RateLimitConfig,
  AutoHaltConfig,
  TestEnvironment,
} from "./safety/index.js";
export {
  loadWatchProfile,
  checkScopeFresh,
  profileHome,
  alertSeverities,
  emptyBaseline,
  loadBaseline,
  saveBaseline,
  findingKey,
  bundlePathFor,
  classifyDrift,
  resolveMissingDrift,
  buildDriftReport,
  applyDriftToBaseline,
  touchBaselineEntries,
  remediateBaselineEntries,
  flagBaselineNeedsReview,
  renderDriftMarkdown,
  runWatchCycle,
  watchLoop,
  WATCH_PROFILE_VERSION,
  BASELINE_VERSION,
} from "./continuous/index.js";
export type {
  WatchProfile,
  WatchCadence,
  AlertSeverity,
  BaselineEntry,
  BaselineEntryStatus,
  WatchBaseline,
  DriftDisposition,
  DriftMissing,
  DriftClassification,
  DriftReport,
  ReverifyFn,
  WatchCycleOptions,
  WatchCycleStatus,
  WatchCycleResult,
} from "./continuous/index.js";

export interface QueueJob {
  /** Path of the job file (for completion bookkeeping). */
  jobFile: string;
  input: EngagementInput;
}

/** Where the console drops engagement requests. REDTEAM_HOME-aware. */
function defaultQueueDir(): string {
  const home = process.env["REDTEAM_HOME"];
  return home ? join(home, "engagements", "queue") : join(process.cwd(), "engagements", "queue");
}

/** Write a queue job (what the console's start-engagement action does). */
export function enqueueEngagement(input: EngagementInput, queueDir = defaultQueueDir()): string {
  mkdirSync(queueDir, { recursive: true });
  const name = `job-${new Date().toISOString().replace(/[:.]/g, "-")}-${Math.random().toString(36).slice(2, 6)}.json`;
  const path = join(queueDir, name);
  writeFileSync(path, JSON.stringify(input, null, 2));
  return path;
}

function listJobs(queueDir: string): string[] {
  if (!existsSync(queueDir)) return [];
  return readdirSync(queueDir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => join(queueDir, f))
    .sort();
}

/**
 * Validate a queue-dropped job file at intake (v0.28.0). Mirrors the checks
 * cli/args.ts buildInput() and the UI launch route enforce, so a malformed
 * job fails fast at the queue — naming the file and the reason — instead
 * of dying deep inside runEngagement. Throws on the first problem found.
 */
export function validateQueueInput(raw: unknown): EngagementInput {
  const b = raw as Record<string, unknown>;
  if (!b || typeof b !== "object") throw new Error("job is not an object");
  if (typeof b.target !== "string" || !b.target.trim()) throw new Error("target is required");
  if (b.mode !== "red" && b.mode !== "black") throw new Error("mode must be red|black");
  if (typeof b.objective !== "string" || !b.objective.trim()) throw new Error("objective is required");
  const roe = b.roe as Record<string, unknown> | undefined;
  const scope = roe?.scope;
  if (!Array.isArray(scope) || scope.length === 0 || !scope.every((s) => typeof s === "string" && s.trim())) {
    throw new Error("roe.scope is required (non-empty array of exact hosts)");
  }
  let targets: TargetId[] | undefined;
  if (b.targets !== undefined) {
    if (!Array.isArray(b.targets)) throw new Error("targets must be an array");
    const bad = (b.targets as unknown[]).filter((t) => typeof t !== "string" || !isTargetId(t));
    if (bad.length > 0) throw new Error(`bad targets ${JSON.stringify(bad)}; want subset of secscan,seclayer,windows,linux`);
    targets = b.targets as TargetId[];
  }
  let tier: 0 | 1 | 2 | undefined;
  if (b.tier !== undefined) tier = parseTier(String(b.tier)) as 0 | 1 | 2;
  let environment: "staging" | "production" | undefined;
  if (b.environment !== undefined) {
    if (b.environment !== "staging" && b.environment !== "production") {
      throw new Error("environment must be staging|production");
    }
    environment = b.environment;
  }
  return b as unknown as EngagementInput;
}

/**
 * Watch the queue dir and run engagements as they arrive. Long-running;
 * resolve only on abort. Each job file is moved to <queue>/done/ afterwards.
 */
export async function watchQueue(
  queueDir = defaultQueueDir(),
  opts: RunOptions = {},
  pollMs = 10_000,
  signal?: AbortSignal,
): Promise<void> {
  mkdirSync(join(queueDir, "done"), { recursive: true });
  for (;;) {
    if (signal?.aborted) return;
    for (const jobFile of listJobs(queueDir)) {
      if (signal?.aborted) return;
      let raw: unknown;
      try {
        raw = JSON.parse(readFileSync(jobFile, "utf8"));
      } catch {
        console.error(`[runner] queue: ${basename(jobFile)} is not valid JSON — moved to done/`);
        renameSync(jobFile, join(queueDir, "done", `bad-${Date.now()}.json`));
        continue;
      }
      let input: EngagementInput;
      try {
        input = validateQueueInput(raw);
      } catch (err) {
        console.error(`[runner] queue: ${basename(jobFile)} rejected: ${(err as Error).message} — moved to done/`);
        renameSync(jobFile, join(queueDir, "done", `bad-${Date.now()}.json`));
        continue;
      }
      try {
        await runEngagement(input, opts);
      } catch {
        // runEngagement records halt/block internally; never let one job kill the watcher.
      }
      renameSync(jobFile, join(queueDir, "done", basename(jobFile)));
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}
