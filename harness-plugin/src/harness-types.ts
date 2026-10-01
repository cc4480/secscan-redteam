/**
 * Minimal STRUCTURAL mirror of the DeepSeek Harness host contracts this plugin
 * relies on. These shapes are transcribed from the official cookbook docs
 * (docs/cookbook/adding-a-tool.md, extension-cookbook.md) of
 * deepseek-ai/deepseek-harness — they exist so this package typechecks
 * standalone. When building inside the real harness workspace, delete this
 * file and import the real types:
 *   import type { Context } from '@deepseek-ai/cordis'
 *   import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
 */

/** Raw JSON-Schema tool definition — "how MCP-sourced tools arrive" per the cookbook. */
export interface RawToolDefinition {
  name: string;
  description: string;
  /** JSON Schema for the tool's input. */
  inputSchema: Record<string, unknown>;
  annotations?: {
    readOnlyHint?: boolean;
    openWorldHint?: boolean;
    destructiveHint?: boolean;
  };
}

export interface ToolExecutionContext {
  signal: AbortSignal;
  agent?: unknown;
  token: string;
  callId: string;
  toolName: string;
}

export type ToolHandler = (
  args: Record<string, unknown>,
  exec: ToolExecutionContext,
) => Promise<unknown>;

export interface ToolRegistry {
  /** Registers a raw JSON-Schema tool definition plus its handler. */
  register(def: RawToolDefinition, handler: ToolHandler): void;
}

export type PreToolDecision =
  | { kind: "allow" }
  | { kind: "deny"; reason: string };

export interface ToolExecution {
  toolName: string;
  arguments: Record<string, unknown>;
}

export interface SystemPromptRegistry {
  /** Adds a named section to the assembled system prompt. */
  addSection(id: string, order: number, text: string): void;
}

/**
 * Structural subset of the Cordis Context surface this plugin touches.
 * The real Context is vastly larger; we only declare what we use.
 */
export interface HarnessContext {
  tools: ToolRegistry;
  systemPrompt: SystemPromptRegistry;
  /** Event bus: ctx.on('tools/pre-execute', handler) for the auth gate. */
  on(
    event: "tools/pre-execute",
    handler: (
      exec: ToolExecution,
      next: () => Promise<PreToolDecision>,
    ) => Promise<PreToolDecision>,
  ): void;
}

export interface PluginModule {
  name: string;
  inject: string[];
  apply(ctx: HarnessContext, config: Record<string, unknown>): void | Promise<void>;
}
