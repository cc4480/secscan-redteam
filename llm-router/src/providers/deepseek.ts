/**
 * DeepSeek provider — the ONLY active provider in v0.1.
 *
 * Wire format: OpenAI-compatible Chat Completions over HTTPS
 * (POST {baseUrl}/chat/completions). Tool calls are translated between the
 * router's JSON-Schema form and the OpenAI `tools`/`tool_calls` form.
 *
 * Models:
 *   - deepseek-v4.1-flash — DeepSeek-V4.1-Flash: fast, cheap, strong tool use.
 *   - deepseek-v4.1-pro   — DeepSeek-V4.1-Pro: premium reasoning, for
 *     thinking/difficult tasks (exploiter role).
 *
 * Auth: DEEPSEEK_API_KEY env var ONLY. The key is sent as a Bearer token and
 * is never logged, never included in errors, and never written anywhere.
 */

import type {
  ChatMessage,
  ChatResult,
  CompleteOptions,
  JsonSchemaTool,
  LlmProvider,
  ToolCallRequest,
} from "../types.js";

export const DEEPSEEK_API_KEY_ENV = "DEEPSEEK_API_KEY";
export const DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1";

export const DEEPSEEK_MODELS = {
  flash: "deepseek-v4.1-flash",
  pro: "deepseek-v4.1-pro",
} as const;

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

export class DeepSeekProvider implements LlmProvider {
  readonly id = "deepseek";
  readonly label = "DeepSeek";
  private readonly baseUrl: string;

  constructor(baseUrl: string = DEEPSEEK_BASE_URL) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  isConfigured(): boolean {
    return !!process.env[DEEPSEEK_API_KEY_ENV];
  }

  private apiKey(): string {
    const key = process.env[DEEPSEEK_API_KEY_ENV];
    if (!key) {
      throw new Error(
        `[llm-router] ${DEEPSEEK_API_KEY_ENV} is not set. ` +
          `Enter your DeepSeek API key via the Secure Vault (it lands in the environment), ` +
          `or export ${DEEPSEEK_API_KEY_ENV} before starting. The key is never stored in code or docs.`,
      );
    }
    return key;
  }

  async complete(options: CompleteOptions): Promise<ChatResult> {
    const body: Record<string, unknown> = {
      model: options.model,
      messages: toWireMessages(options.messages),
      temperature: options.temperature ?? 0.2,
    };
    if (options.maxTokens) body["max_tokens"] = options.maxTokens;
    const wireTools = toWireTools(options.tools);
    if (wireTools) body["tools"] = wireTools;

    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey()}`,
        },
        body: JSON.stringify(body),
        signal: options.signal,
      });
    } catch (err) {
      throw new Error(`[llm-router] DeepSeek request failed: ${(err as Error).message}`);
    }

    if (!res.ok) {
      // Never echo the key; surface status + provider message only.
      const text = await res.text().catch(() => "");
      throw new Error(`[llm-router] DeepSeek HTTP ${res.status}: ${text.slice(0, 500)}`);
    }

    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: string | null; reasoning_content?: string | null } & Record<string, unknown> }>;
      usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
    };
    const choice = data.choices?.[0] ?? {};
    const message = choice.message ?? {};

    return {
      text: (message.content as string) ?? "",
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
