/**
 * Tool lifecycle hooks (v0.34.0) — PreToolUse / PostToolUse.
 *
 * The dispatcher already enforces mechanical controls (ROE, tier, variant cap,
 * rate limit). Hooks are the extension point for everything engagement-specific:
 * a client rule, a redaction step, a "never run this on that host" guard — added
 * without touching the safety core.
 *
 * Contracts, ported from AlterEgo's verified implementation:
 *   - PreToolUse returns allow | deny(reason) | modify(args). Any deny stops the
 *     call; a modify feeds the new args to later hooks and to the handler.
 *   - PostToolUse may replace the result (e.g. scrub it) or leave it.
 *   - Every hook has a timeout. A pre-hook timeout DENIES (fail closed); a
 *     post-hook timeout keeps the original result and is logged.
 *   - Each evaluation is returned to the caller so the dispatcher can append one
 *     audit event per hook — never a silent decision.
 *
 * Pure aside from the injected callables and timers; unit-tested directly.
 */

export type HookPhase = "pre" | "post";

export interface HookContext {
  tool: string;
  args: Record<string, unknown>;
  target?: string;
}

export type PreDecision =
  | { decision: "allow"; reason?: string }
  | { decision: "deny"; reason: string }
  | { decision: "modify"; args: Record<string, unknown>; reason?: string };

export type PreHookFn = (ctx: HookContext) => PreDecision | void | Promise<PreDecision | void>;

export type PostOutcome = { result: string } | void;
export type PostHookFn = (ctx: HookContext, result: string) => PostOutcome | Promise<PostOutcome>;

export interface HookEvaluation {
  name: string;
  phase: HookPhase;
  decision: "allow" | "deny" | "modify" | "keep" | "replace";
  latencyMs: number;
  timedOut: boolean;
  reason?: string;
}

interface Registered<F> {
  name: string;
  pattern: string;
  fn: F;
  timeoutMs: number;
}

export interface PreRunOutcome {
  allowed: boolean;
  args: Record<string, unknown>;
  reason?: string;
  evaluations: HookEvaluation[];
}

export interface PostRunOutcome {
  result: string;
  evaluations: HookEvaluation[];
}

const DEFAULT_TIMEOUT_MS = 5000;

function matches(pattern: string, tool: string): boolean {
  const p = pattern.trim();
  if (p === "" || p === "*") return true;
  const escaped = p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i").test(tool);
}

/** Await a hook with a timeout. Resolves to `{timedOut:true}` rather than rejecting. */
async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<{ value?: T; timedOut: boolean }> {
  if (!Number.isFinite(ms) || ms <= 0) return { value: await promise, timedOut: false };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<{ value?: T; timedOut: boolean }>((resolve) => {
    timer = setTimeout(() => resolve({ timedOut: true }), ms);
  });
  try {
    const raced = await Promise.race([promise.then((value) => ({ value, timedOut: false })), timeout]);
    return raced;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class HookRegistry {
  private pre: Registered<PreHookFn>[] = [];
  private post: Registered<PostHookFn>[] = [];

  registerPre(name: string, pattern: string, fn: PreHookFn, timeoutMs = DEFAULT_TIMEOUT_MS): void {
    this.pre.push({ name, pattern, fn, timeoutMs });
  }

  registerPost(name: string, pattern: string, fn: PostHookFn, timeoutMs = DEFAULT_TIMEOUT_MS): void {
    this.post.push({ name, pattern, fn, timeoutMs });
  }

  /** Number of registered hooks — used by readiness/doctor output. */
  get size(): number {
    return this.pre.length + this.post.length;
  }

  /** Run pre-hooks in registration order. Deny wins; modify updates args for later hooks. */
  async runPre(tool: string, args: Record<string, unknown>, target?: string): Promise<PreRunOutcome> {
    const evaluations: HookEvaluation[] = [];
    let current = args;
    for (const hook of this.pre) {
      if (!matches(hook.pattern, tool)) continue;
      const started = Date.now();
      const outcome = await withTimeout(
        (async () => hook.fn({ tool, args: current, target }))(),
        hook.timeoutMs,
      );
      const latencyMs = Date.now() - started;
      if (outcome.timedOut) {
        evaluations.push({ name: hook.name, phase: "pre", decision: "deny", latencyMs, timedOut: true, reason: "hook timed out" });
        return { allowed: false, args: current, reason: `hook ${JSON.stringify(hook.name)} timed out after ${hook.timeoutMs}ms`, evaluations };
      }
      const decision = outcome.value;
      if (!decision) {
        evaluations.push({ name: hook.name, phase: "pre", decision: "allow", latencyMs, timedOut: false });
        continue;
      }
      if (decision.decision === "deny") {
        evaluations.push({ name: hook.name, phase: "pre", decision: "deny", latencyMs, timedOut: false, reason: decision.reason });
        return { allowed: false, args: current, reason: decision.reason, evaluations };
      }
      if (decision.decision === "modify") {
        current = decision.args;
        evaluations.push({ name: hook.name, phase: "pre", decision: "modify", latencyMs, timedOut: false, reason: decision.reason });
        continue;
      }
      evaluations.push({ name: hook.name, phase: "pre", decision: "allow", latencyMs, timedOut: false, reason: decision.reason });
    }
    return { allowed: true, args: current, evaluations };
  }

  /** Run post-hooks; the last replacement wins. Timeouts keep the current result. */
  async runPost(tool: string, args: Record<string, unknown>, result: string, target?: string): Promise<PostRunOutcome> {
    const evaluations: HookEvaluation[] = [];
    let current = result;
    for (const hook of this.post) {
      if (!matches(hook.pattern, tool)) continue;
      const started = Date.now();
      const outcome = await withTimeout(
        (async () => hook.fn({ tool, args, target }, current))(),
        hook.timeoutMs,
      );
      const latencyMs = Date.now() - started;
      if (outcome.timedOut) {
        evaluations.push({ name: hook.name, phase: "post", decision: "keep", latencyMs, timedOut: true, reason: "hook timed out" });
        continue;
      }
      if (outcome.value && typeof outcome.value.result === "string") {
        current = outcome.value.result;
        evaluations.push({ name: hook.name, phase: "post", decision: "replace", latencyMs, timedOut: false });
      } else {
        evaluations.push({ name: hook.name, phase: "post", decision: "keep", latencyMs, timedOut: false });
      }
    }
    return { result: current, evaluations };
  }
}
