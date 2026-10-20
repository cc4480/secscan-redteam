/**
 * Core types for the provider-pluggable LLM router.
 *
 * A provider implements `LlmProvider.complete()`. The router dispatches by
 * provider id; adding Claude / ChatGPT / Gemini / GLM / Qwen later means
 * writing one new class against this interface and calling
 * `registerProvider()` — no changes to agents or the harness plugin.
 */

export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  /** For tool messages: the id of the call being answered. */
  toolCallId?: string;
  /**
   * For assistant messages that requested tool calls: the calls themselves.
   * OpenAI-compatible APIs (DeepSeek, Qwen) REQUIRE that any `tool` message be
   * preceded by an assistant message carrying these — otherwise the request is
   * rejected ("Messages with role 'tool' must be a response to a preceding
   * message with 'tool_calls'"). Must round-trip into the wire `tool_calls`
   * field, with ids matching the following tool messages' toolCallId.
   */
  toolCalls?: ToolCallRequest[];
}

export interface ToolCallRequest {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface ChatResult {
  /** Assistant text (may be empty when the turn is pure tool calls). */
  text: string;
  /**
   * The model's thinking trace, when the provider exposes one (Qwen
   * `reasoning_content`, DeepSeek reasoner). Surfaced separately so the
   * harness can log it without polluting the visible reply.
   */
  reasoning?: string;
  /** Tool calls the model requested this turn. */
  toolCalls: ToolCallRequest[];
  usage?: { promptTokens: number; completionTokens: number; totalTokens: number };
  provider: string;
  model: string;
  /**
   * The exact request body the provider serialized onto the wire (never
   * contains credentials — auth travels in headers). Providers that can report
   * it enable byte-exact trajectory logging in the adapter layer; providers that
   * cannot leave it undefined and the adapter falls back to the given options.
   */
  requestBody?: Record<string, unknown>;
  /** The provider's response payload as received, before normalization. */
  rawResponse?: unknown;
}

export interface JsonSchemaTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>; // JSON Schema
}

/**
 * Structured-output constraint for one call. Selection order when several
 * constraints coexist mirrors the recipe discipline: tool calls >
 * json_schema > regex > json_object.
 */
export type ResponseFormat =
  | { type: "json_schema"; name: string; schema: Record<string, unknown>; strict?: boolean }
  | { type: "regex"; pattern: string }
  | { type: "json_object" };

export interface CompleteOptions {
  model: string;
  messages: ChatMessage[];
  tools?: JsonSchemaTool[];
  /** Hint only; providers may ignore it. */
  reasoningEffort?: "low" | "medium" | "high";
  signal?: AbortSignal;
  maxTokens?: number;
  temperature?: number;
  topP?: number;
  /** Structured-output constraint; validated client-side by the adapter before send. */
  responseFormat?: ResponseFormat;
  /** Calling role, for trajectory attribution. Set by completeForRole. */
  role?: AgentRole;
  /** Run this call belongs to, for trajectory grouping. */
  runId?: string;
}

export interface LlmProvider {
  /** Stable id, e.g. "deepseek". Used as the routing key. */
  readonly id: string;
  /** Human label, e.g. "DeepSeek". */
  readonly label: string;
  /** True when the provider can be used (e.g. its API key env var is set). */
  isConfigured(): boolean;
  complete(options: CompleteOptions): Promise<ChatResult>;
}

/** Agent roles the red-team uses. */
export type AgentRole = "coordinator" | "recon" | "exploiter" | "reporter";

export interface RoleRoute {
  provider: string;
  model: string;
  reasoningEffort?: "low" | "medium" | "high";
}
