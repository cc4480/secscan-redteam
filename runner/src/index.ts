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
 *   SECSCAN_MCP_TOKEN, DEEPSEEK_API_KEY, QWEN_API_KEY (Alibaba Model Studio,
 *   exploiter engine), SECSCAN_MCP_URL (optional).
 *
 * Console bridge: the console's "start engagement" action writes an
 * EngagementInput JSON file into the queue dir; `watchQueue()` picks it up
 * and runs it. Engagement state streams to
 * <engagementsDir>/<id>/{events.jsonl,state.json,engagement.md,report.md}.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readEvents, readState, type LiveState } from "./events.js";
import { runEngagement, type RunOptions } from "./phases.js";
import type { EngagementEvent, EngagementInput, EngagementResult } from "./types.js";

export { runEngagement, resolveConfig } from "./phases.js";
export type { RunOptions, RunnerDeps } from "./phases.js";
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

export interface QueueJob {
  /** Path of the job file (for completion bookkeeping). */
  jobFile: string;
  input: EngagementInput;
}

/** Where the console drops engagement requests. REDTEAM_HOME-aware. */
export function defaultQueueDir(): string {
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
      let input: EngagementInput;
      try {
        input = JSON.parse(readFileSync(jobFile, "utf8")) as EngagementInput;
      } catch (err) {
        renameSync(jobFile, join(queueDir, "done", `bad-${Date.now()}.json`));
        continue;
      }
      try {
        await runEngagement(input, opts);
      } catch {
        // runEngagement records halt/block internally; never let one job kill the watcher.
      }
      renameSync(jobFile, join(queueDir, "done", jobFile.split("/").pop()!));
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}
