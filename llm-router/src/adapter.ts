/**
 * AdapterProvider — the DeepInfer/recipe discipline as one choke point.
 *
 * Every model call in the red-team flows through this wrapper (router.ts
 * registers providers pre-wrapped). It enforces, for every call:
 *
 *   1. Structured outputs validated at home — a malformed JSON Schema or
 *      regex fails here, never as a paid API round-trip (recipe: conversion
 *      validates the schema before rendering).
 *   2. Pinned sampling — temperature / top_p / max_tokens are resolved from
 *      explicit per-call values or the pinned defaults below, and recorded.
 *      max_tokens defaults follow deepseek-recipe's resolution: 8192 outside
 *      thinking mode, 65536 with reasoning effort set.
 *   3. Byte-exact trajectory logging — one JSONL record per call with the
 *      exact request body the provider put on the wire, the raw response,
 *      usage, latency, retries, and a manifest (params + sha256 of prompt
 *      and schema). This log is the fuel line for the Harness2 improvement
 *      loop; any record replays verbatim.
 *   4. Replay-safe retries — transient failures (network, HTTP 5xx) retry
 *      with the identical options, so the wire body is byte-identical.
 *      4xx and aborts are never retried.
 *
 * The API key never reaches this layer: providers hold it and send it as a
 * header; request bodies and logs never contain it.
 */

import { appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
import type {
  ChatResult,
  CompleteOptions,
  LlmProvider,
  ResponseFormat,
} from "./types.js";

/** Pinned defaults — change here, nowhere else. */
export const ADAPTER_PINNED = {
  temperature: 0.2,
  topP: 1.0,
  maxTokensPlain: 8192,
  maxTokensThinking: 65536,
  maxRetries: 2,
  retryBackoffMs: [400, 1200],
} as const;

export interface AdapterConfig {
  /** JSONL trajectory path. Default: $REDTEAM_TRAJECTORY_LOG or ./trajectories.jsonl. Pass null to disable logging. */
  logPath?: string | null;
  maxRetries?: number;
}

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Stable stringify (sorted keys) so hashes don't depend on key order. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

const SCHEMA_TYPES = new Set(["object", "array", "string", "number", "integer", "boolean", "null"]);

/**
 * Structural sanity check of a JSON Schema — the recipe discipline of
 * validating the schema at conversion time. Not a full draft-2020-12
 * validator: it catches the malformed shapes that would otherwise fail
 * (or worse, silently misbehave) at the provider.
 */
export function validateJsonSchema(schema: unknown, path = "$"): void {
  if (typeof schema !== "object" || schema === null || Array.isArray(schema)) {
    throw new Error(`[adapter] response_format schema at ${path} must be an object`);
  }
  const s = schema as Record<string, unknown>;
  if (s["type"] !== undefined) {
    const types = Array.isArray(s["type"]) ? s["type"] : [s["type"]];
    for (const t of types) {
      if (typeof t !== "string" || !SCHEMA_TYPES.has(t)) {
        throw new Error(`[adapter] schema at ${path}.type: invalid JSON Schema type ${JSON.stringify(t)}`);
      }
    }
  }
  if (s["properties"] !== undefined) {
    if (typeof s["properties"] !== "object" || s["properties"] === null || Array.isArray(s["properties"])) {
      throw new Error(`[adapter] schema at ${path}.properties must be an object`);
    }
    for (const [key, sub] of Object.entries(s["properties"] as Record<string, unknown>)) {
      validateJsonSchema(sub, `${path}.properties.${key}`);
    }
  }
  if (s["items"] !== undefined) validateJsonSchema(s["items"], `${path}.items`);
  if (s["required"] !== undefined) {
    if (!Array.isArray(s["required"]) || s["required"].some((r) => typeof r !== "string")) {
      throw new Error(`[adapter] schema at ${path}.required must be an array of strings`);
    }
  }
  for (const kw of ["anyOf", "oneOf", "allOf"] as const) {
    if (s[kw] !== undefined) {
      if (!Array.isArray(s[kw])) throw new Error(`[adapter] schema at ${path}.${kw} must be an array`);
      (s[kw] as unknown[]).forEach((sub, i) => validateJsonSchema(sub, `${path}.${kw}[${i}]`));
    }
  }
  if (s["additionalProperties"] !== undefined && typeof s["additionalProperties"] === "object") {
    validateJsonSchema(s["additionalProperties"], `${path}.additionalProperties`);
  }
}

export function validateResponseFormat(format: ResponseFormat): void {
  if (format.type === "json_schema") {
    if (!format.name || typeof format.name !== "string") {
      throw new Error("[adapter] response_format json_schema requires a name");
    }
    validateJsonSchema(format.schema);
  } else if (format.type === "regex") {
    try {
      new RegExp(format.pattern);
    } catch (err) {
      throw new Error(`[adapter] response_format regex does not compile: ${(err as Error).message}`);
    }
  }
}

/** Recipe's constraint selection: tools > json_schema > regex > json_object. */
export function selectConstraint(options: CompleteOptions): string {
  if (options.tools && options.tools.length > 0) return "tool_calls";
  if (options.responseFormat) return options.responseFormat.type;
  return "none";
}

function isTransientError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  if (/HTTP 4\d\d/.test(msg)) return false;
  if (/HTTP 5\d\d/.test(msg)) return true;
  if (/request failed/i.test(msg)) return true; // provider network-failure wrapper
  if (/ECONNRESET|ETIMEDOUT|EAI_AGAIN|fetch failed/i.test(msg)) return true;
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class AdapterProvider implements LlmProvider {
  readonly id: string;
  readonly label: string;
  private readonly inner: LlmProvider;
  private readonly logPath: string | null;
  private readonly maxRetries: number;

  constructor(inner: LlmProvider, config: AdapterConfig = {}) {
    this.inner = inner;
    this.id = inner.id;
    this.label = inner.label;
    this.logPath =
      config.logPath !== undefined
        ? config.logPath
        : (process.env["REDTEAM_TRAJECTORY_LOG"] ?? "./trajectories.jsonl");
    this.maxRetries = config.maxRetries ?? ADAPTER_PINNED.maxRetries;
  }

  isConfigured(): boolean {
    return this.inner.isConfigured();
  }

  /** Resolve pinned params; returns the options actually sent + the manifest. */
  private resolve(options: CompleteOptions): { resolved: CompleteOptions; manifest: Record<string, unknown> } {
    if (options.responseFormat) validateResponseFormat(options.responseFormat);
    const thinking = options.reasoningEffort !== undefined;
    const resolved: CompleteOptions = {
      ...options,
      temperature: options.temperature ?? ADAPTER_PINNED.temperature,
      topP: options.topP ?? ADAPTER_PINNED.topP,
      maxTokens:
        options.maxTokens ??
        (thinking ? ADAPTER_PINNED.maxTokensThinking : ADAPTER_PINNED.maxTokensPlain),
    };
    const manifest: Record<string, unknown> = {
      provider: this.inner.id,
      model: resolved.model,
      temperature: resolved.temperature,
      top_p: resolved.topP,
      max_tokens: resolved.maxTokens,
      reasoning_effort: resolved.reasoningEffort ?? null,
      constraint: selectConstraint(resolved),
      prompt_sha256: sha256(canonicalJson(resolved.messages)),
      schema_sha256: resolved.responseFormat
        ? sha256(canonicalJson(resolved.responseFormat))
        : null,
      tools: resolved.tools?.map((t) => t.name) ?? [],
    };
    return { resolved, manifest };
  }

  private log(record: Record<string, unknown>): void {
    if (this.logPath === null) return;
    try {
      appendFileSync(this.logPath, `${JSON.stringify(record)}\n`, "utf8");
    } catch {
      // Trajectory logging must never take down an engagement. A failed
      // append surfaces via the missing record, not a crashed call.
    }
  }

  async complete(options: CompleteOptions): Promise<ChatResult> {
    const { resolved, manifest } = this.resolve(options);
    const started = Date.now();
    let retries = 0;
    for (;;) {
      try {
        const result = await this.inner.complete(resolved);
        const record: Record<string, unknown> = {
          v: 1,
          ts: new Date().toISOString(),
          run_id: resolved.runId ?? null,
          role: resolved.role ?? null,
          manifest,
          request: result.requestBody ?? null,
          response: result.rawResponse ?? null,
          usage: result.usage ?? null,
          latency_ms: Date.now() - started,
          retries,
        };
        this.log(record);
        return result;
      } catch (err) {
        if (retries < this.maxRetries && !resolved.signal?.aborted && isTransientError(err)) {
          const backoff =
            ADAPTER_PINNED.retryBackoffMs[retries] ??
            ADAPTER_PINNED.retryBackoffMs[ADAPTER_PINNED.retryBackoffMs.length - 1];
          retries += 1;
          await sleep(backoff);
          continue;
        }
        this.log({
          v: 1,
          ts: new Date().toISOString(),
          run_id: resolved.runId ?? null,
          role: resolved.role ?? null,
          manifest,
          request: null,
          response: null,
          error: err instanceof Error ? err.message : String(err),
          latency_ms: Date.now() - started,
          retries,
        });
        throw err;
      }
    }
  }
}
