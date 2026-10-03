/**
 * Engagement orchestration — barrel (v0.19.0 refactor).
 *
 * The orchestration lives in ./phases/ by phase (authorize, plan, recon,
 * exploit, tasks, directive, signoff, config, run). This barrel keeps the
 * `./phases.js` import path working unchanged — `runEngagement` and
 * `RunOptions` (the surface the CLI and tests use) still come from here.
 */
export type { RunnerDeps } from "./context.js";
export { authorizePhase } from "./phases/authorize.js";
export { planPhase } from "./phases/plan.js";
export { focusedExploit } from "./phases/exploit-one.js";
export { coordinatorSignOff } from "./phases/signoff.js";
export { reconPhase } from "./phases/recon.js";
export { runTask, runBatch, validateTasks, type TaskDef, type TaskResult } from "./phases/tasks.js";
export { coordinatorDirective } from "./phases/directive.js";
export { exploitPhase } from "./phases/exploit.js";
export { resolveConfig } from "./phases/config.js";
export { runEngagement, type RunOptions } from "./phases/run.js";
