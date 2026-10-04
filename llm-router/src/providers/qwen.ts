/**
 * Qwen provider — Alibaba Cloud Model Studio (DashScope), OpenAI-compatible
 * wire format (POST {baseUrl}/chat/completions). Tool calls are translated
 * between the router's JSON-Schema form and the OpenAI `tools`/`tool_calls`
 * form, exactly like the DeepSeek provider.
 *
 * Model (ID verified against Alibaba's official Model Studio docs, 2026-10):
 *   - qwen3.8-max — hosted MoE flagship, strongest reasoning in the Qwen
 *     lineup. Thinking is ON by default; depth via `reasoning_effort`
 *     ("xhigh" | "medium" | "low"). Function calling is supported.
 *   Not a coder-only or tiny variant: this is the reasoning brain the
 *   exploiter role needs.
 *
 * Auth: QWEN_API_KEY env var ONLY (falls back to DASHSCOPE_API_KEY, the
 * ecosystem-standard name, if set). Override the endpoint with QWEN_BASE_URL.
 * The key is sent as a Bearer <redacted> and is never logged, never included
 * in errors, and never written anywhere.
 */

import type {
  ChatMessage,
  ChatResult,
  CompleteOptions,
  JsonSchemaTool,
  LlmProvider,
  ToolCallRequest,
} from "../types.js";

export const QWEN_API_KEY_ENV = "QWEN_API_KEY";
/** Ecosystem-standard fallback (Qwen Code, OpenTryOn, MCP tooling all use this). */
export const QWEN_API_KEY_FALLBACK_ENV = "DASHSCOPE_API_KEY";
export const QWEN_BASE_URL_ENV = "QWEN_BASE_URL";
/** International endpoint; China-region users set QWEN_BASE_URL instead. */
export const QWEN_BASE_URL = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1";

export const QWEN_MODELS = {
  /** Flagship reasoning (thinking on by default). The exploiter's engine. */
  reasoning: "qwen3.8-max",
} as const;

/** Router hint → Qwen reasoning_effort. */
function toReasoningEffort(hint: CompleteOptions["reasoningEffort"]): string | undefined {
  if (hint === "high") return "xhigh";
  if (hint === "medium") return "medium";
  if (hint === "low") return "low";
  return undefined; // API default (xhigh) applies
}

function toWireMessages(messages: ChatMessage[]): Array<Record<string, unknown>> {
  return messages.map((m) => {
    if (m.role === "tool") {
      return { role: "tool", tool_call_id: m.toolCallId ?? "", content: m.content };
    }
    return { role: m.role, content: m.content };
  });
}

function toWireTools(tools?: JsonSchemaTool[]): Array<Record<string, unknown>> | undefined {
  if (!tools || tools.length === 0) return undefined;
  return tools.map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description,
      parameters: t.parameters,
    },
  }));
}

function fromWireToolCalls(choice: Record<string, unknown>): ToolCallRequest[] {
  const calls = (choice["tool_calls"] as Array<Record<string, unknown>> | undefined) ?? [];
  return calls.map((c, i) => {
    const fn = (c["function"] as Record<string, unknown>) ?? {};
    let args: Record<string, unknown> = {};
    try {
      args = JSON.parse((fn["arguments"] as string) ?? "{}") as Record<string, unknown>;
    } catch {
      args = { _raw: fn["arguments"] };
    }
    return {
      id: (c["id"] as string) ?? `call_${i}`,
      name: (fn["name"] as string) ?? "unknown",
      arguments: args,
    };
  });
}

export class QwenProvider implements LlmProvider {
  readonly id = "qwen";
  readonly label = "Qwen (Alibaba Model Studio)";
  private readonly baseUrl: string;

  constructor(baseUrl?: string) {
    // Same blank-but-present-env-var guard as runner/src/phases/config.ts's
    // mcpEndpoint: "" ?? x is "", not x, so a blank QWEN_BASE_URL= in .env
    // (the documented "unset, use default" convention) must use || / trim,
    // not ??, or this silently resolves to an empty base URL.
    const fromEnv = process.env[QWEN_BASE_URL_ENV]?.trim();
    this.baseUrl = (baseUrl?.trim() || fromEnv || QWEN_BASE_URL).replace(/\/+$/, "");
  }

  isConfigured(): boolean {
    return !!this.apiKeyOrNull();
  }

  private apiKeyOrNull(): string | null {
    return process.env[QWEN_API_KEY_ENV] ?? process.env[QWEN_API_KEY_FALLBACK_ENV] ?? null;
  }

  private apiKey(): string {
    const key = this.apiKeyOrNull();
    if (!key) {
      throw new Error(
        `[llm-router] neither ${QWEN_API_KEY_ENV} nor ${QWEN_API_KEY_FALLBACK_ENV} is set. ` +
          `Enter your Alibaba Model Studio API key via the Secure Vault (it lands in the environment), ` +
          `or export ${QWEN_API_KEY_ENV} before starting. The key is never stored in code or docs.`,
      );
    }
    return key;
  }

  async complete(options: CompleteOptions): Promise<ChatResult> {
    const body: Record<string, unknown> = {
      model: options.model,
      messages: toWireMessages(options.messages),
      temperature: options.temperature ?? 0.2,
      // Thinking is the point of this provider — always on for reasoning work.
      enable_thinking: true,
    };
    const effort = toReasoningEffort(options.reasoningEffort);
    if (effort) body["reasoning_effort"] = effort;
    if (options.maxTokens) body["max_tokens"] = options.maxTokens;
    const wireTools = toWireTools(options.tools);
    if (wireTools) body["tools"] = wireTools;

    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // The raw key lives only in this header — never in logs or errors.
          Authorization: `Bearer ${this.apiKey()}`,
        },
        body: JSON.stringify(body),
        signal: options.signal,
      });
    } catch (err) {
      throw new Error(`[llm-router] Qwen request failed: ${(err as Error).message}`);
    }

    if (!res.ok) {
      // Never echo the key; surface status + provider message only.
      const text = await res.text().catch(() => "");
      throw new Error(`[llm-router] Qwen HTTP ${res.status}: ${text.slice(0, 500)}`);
    }

    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: string | null; reasoning_content?: string | null } & Record<string, unknown> }>;
      usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
    };
    const choice = data.choices?.[0] ?? {};
    const message = choice.message ?? {};

    return {
      text: (message.content as string) ?? "",
      // The thinking trace: surfaced separately so the harness can log it
      // without polluting the model's visible reply.
      reasoning: (message.reasoning_content as string) ?? undefined,
      toolCalls: fromWireToolCalls(message as Record<string, unknown>),
      usage: data.usage
        ? {
            promptTokens: data.usage.prompt_tokens,
            completionTokens: data.usage.completion_tokens,
            totalTokens: data.usage.total_tokens,
          }
        : undefined,
      provider: this.id,
      model: options.model,
    };
  }
}
