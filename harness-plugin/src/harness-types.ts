/**
 * Harness contracts — imported from the REAL packages, not a structural mirror.
 *
 * Verified 2026-10-01 against the installed deepseek-harness release
 * (@deepseek-ai/dsh 0.2.0-rc.2) and its published type packages:
 *   - Context            from '@deepseek-ai/cordis'
 *   - PreToolDecision    from '@deepseek-ai/dsh-tools'  ({kind:'allow'} | {kind:'deny',reason} | {kind:'ask',reason?})
 *   - ToolExecution      from '@deepseek-ai/dsh-tools'  (fields: name, arguments, callId, signal, agent, token, ...)
 *
 * These are peerDependencies of this plugin: the harness host provides them
 * at load time. devDependencies pin the same versions for standalone
 * typecheck/build.
 */

import type { Context } from "@deepseek-ai/cordis";
import type { PreToolDecision, ToolExecution } from "@deepseek-ai/dsh-tools";

export type { Context, PreToolDecision, ToolExecution };

/**
 * The plugin module contract the harness plugin manager loads:
 * a name, the services it needs injected, and apply().
 * (Matches the extension-cookbook examples: `export const name`,
 * `export const inject`, `export function apply(ctx)`.)
 */
export interface PluginModule {
  name: string;
  inject?: string[];
  apply(ctx: Context, config?: Record<string, unknown>): void | Promise<void>;
}
