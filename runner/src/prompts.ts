/**
 * Role prompts for live engagements. They extend agents/*.md with the
 * engagement's mode, objective, ROE, and ATT&CK context.
 *
 * Red vs black, plainly:
 *  - RED (overt): aggressive breadth. Time-boxed, full technique catalog,
 *    active scanner tier, direct hypothesis testing. The blue team may know.
 *  - BLACK (covert-ops tier): black-box — assume zero prior knowledge of the
 *    target. Stealth-prioritized: low-noise techniques first, jittered pacing,
 *    payload encoding to reduce signature footprint, immediate backoff on any
 *    detection signal (WAF block, 429, challenge page). Every detection signal
 *    is logged as an OPSEC event. Undeclared to the target's blue team.
 *  - BOTH: client-authorized only. Ownership proof via the SecScan server is
 *    mandatory before any active testing. Non-destructive always. Web targets
 *    only — no phishing, no social engineering, no physical.
 */

export type { PromptContext } from "./prompts/shared.js";
export { coordinatorPrompt } from "./prompts/coordinator.js";
export { reconPrompt } from "./prompts/recon.js";
export { exploiterPrompt } from "./prompts/exploiter.js";
export type { TaskBrief } from "./prompts/task.js";
export { taskPrompt } from "./prompts/task.js";
export { reporterPrompt } from "./prompts/reporter.js";
