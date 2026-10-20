/**
 * DeepSeek provider — the ONLY active provider in v0.1.
 *
 * Wire format: OpenAI-compatible Chat Completions over HTTPS
 * (POST {baseUrl}/chat/completions). Tool calls are translated between the
 * router's JSON-Schema form and the OpenAI `tools`/`tool_calls` form.
 *
 * Models (wire-format IDs — confirmed against the live API 2026-10-04; a
 * "deepseek-v4.1-flash" request was rejected with "The supported API model
 * names are deepseek-flash, deepseek-v4-pro" — so despite the v4.1 product/
 * version naming, these two are what the API actually accepts):
 *   - deepseek-flash   — DeepSeek-V4.1-Flash: fast, cheap, strong tool use.
 *   - deepseek-v4-pro  — DeepSeek-V4.1-Pro: premium reasoning, for
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
  ResponseFormat,
  ToolCallRequest,
} from "../types.js";

export const DEEPSEEK_API_KEY_ENV = "DEEPSEEK_API_KEY";
export const DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1";

export const DEEPSEEK_MODELS = {
  flash: "deepseek-flash",
  pro: "deepseek-v4-pro",
} as const;

function toWireMessages(messages: ChatMessage[]): Array<Record<string, unknown>> {
  return messages.map((m) => {
    if (m.role === "tool") {
      return { role: "tool", tool_call_id: m.toolCallId ?? "", content: m.content };
    }
    if (m.role === "assistant" && m.toolCalls && m.toolCalls.length > 0) {
      // Send the calls this turn issued back verbatim: the API rejects
      // `tool` results whose tool_call_id was never declared in a
      // preceding assistant `tool_calls`. (This mapping previously dropped
      // them, which 400'd every multi-turn tool conversation at turn 2.)
      // Arguments go back as the JSON string the wire format expects.
      return {
        role: "assistant",
        content: m.content,
        tool_calls: m.toolCalls.map((c) => ({
          id: c.id,
          type: "function",
          function: { name: c.name, arguments: JSON.stringify(c.arguments ?? {}) },
        })),
      };
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

function fromWireToolCalls(choice: Record<string, unknown>): ToolCallRequest[] {  const calls = (choice["tool_calls"] as Array<Record<string, unknown>> | undefined) ?? [];
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

/**
 * Map the router's ResponseFormat to the DeepSeek wire form. Field shapes
 * follow DeepSeek's own protocol library (deepseek-recipe): Chat Completions
 * `response_format` accepts `json_schema` and `regex` in addition to the
 * OpenAI-standard `json_object`.
 */
function toWireResponseFormat(
  format?: ResponseFormat,
): Record<string, unknown> | undefined {
  if (!format) return undefined;
  switch (format.type) {
    case "json_schema":
      return {
        type: "json_schema",
        json_schema: {
          name: format.name,
          schema: format.schema,
          strict: format.strict ?? true,
        },
      };
    case "regex":
      return { type: "regex", regex: format.pattern };
    case "json_object":
      return { type: "json_object" };
  }
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
    if (options.topP !== undefined) body["top_p"] = options.topP;
    if (options.maxTokens) body["max_tokens"] = options.maxTokens;
    // Policy declares reasoning effort per role; it MUST reach the wire.
    // (Pre-adapter, this was silently dropped and every role ran on the
    // server default regardless of policy.)
    if (options.reasoningEffort) body["reasoning_effort"] = options.reasoningEffort;
    const wireFormat = toWireResponseFormat(options.responseFormat);
    if (wireFormat) body["response_format"] = wireFormat;
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
      // Byte-exact trajectory material for the adapter layer: the body as
      // serialized above (auth is a header, never in the body) and the
      // response payload as received.
      requestBody: body,
      rawResponse: data,
    };
  }
}
