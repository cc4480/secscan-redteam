/**
 * The router: provider registry + dispatch.
 *
 * Usage:
 *   import { completeForRole } from "@secscan/redteam-llm-router";
 *   const res = await completeForRole("exploiter", [
 *     { role: "system", content: EXPLOITER_PROMPT },
 *     { role: "user", content: "Begin phase 2." },
 *   ], { tools: harnessTools });
 *
 * completeForRole() applies ROLE_MODEL_POLICY automatically. complete() lets
 * callers pick provider+model explicitly. Unknown provider ids and
 * unconfigured providers (missing API key) throw with actionable messages.
 */

import type {
  AgentRole,
  ChatMessage,
  ChatResult,
  CompleteOptions,
  JsonSchemaTool,
  LlmProvider,
} from "./types.js";
import { ROLE_MODEL_POLICY } from "./policy.js";
import { DeepSeekProvider } from "./providers/deepseek.js";

const providers = new Map<string, LlmProvider>();

export function registerProvider(provider: LlmProvider): void {
  if (providers.has(provider.id)) {
    throw new Error(`[llm-router] provider '${provider.id}' is already registered.`);
  }
  providers.set(provider.id, provider);
}

export function listProviders(): Array<{ id: string; label: string; configured: boolean }> {
  return [...providers.values()].map((p) => ({
    id: p.id,
    label: p.label,
    configured: safeIsConfigured(p),
  }));
}

function safeIsConfigured(p: LlmProvider): boolean {
  try {
    return p.isConfigured();
  } catch {
    return false;
  }
}

function getProvider(id: string): LlmProvider {
  const p = providers.get(id);
  if (!p) {
    const known = [...providers.keys()].join(", ") || "(none)";
    throw new Error(
      `[llm-router] unknown provider '${id}'. Registered: ${known}. ` +
        `To add one, implement LlmProvider (see src/providers/README.md).`,
    );
  }
  if (!safeIsConfigured(p)) {
    throw new Error(
      `[llm-router] provider '${id}' is registered but not configured ` +
        `(its API key env var is missing). Enter the key via the Secure Vault.`,
    );
  }
  return p;
}

export async function complete(
  providerId: string,
  options: CompleteOptions,
): Promise<ChatResult> {
  return getProvider(providerId).complete(options);
}

export async function completeForRole(
  role: AgentRole,
  messages: ChatMessage[],
  opts: {
    tools?: JsonSchemaTool[];
    signal?: AbortSignal;
    maxTokens?: number;
    temperature?: number;
  } = {},
): Promise<ChatResult> {
  const route = ROLE_MODEL_POLICY[role];
  return complete(route.provider, {
    model: route.model,
    messages,
    tools: opts.tools,
    reasoningEffort: route.reasoningEffort,
    signal: opts.signal,
    maxTokens: opts.maxTokens,
    temperature: opts.temperature,
  });
}

// v0.1: DeepSeek is the only registered provider.
registerProvider(new DeepSeekProvider());
