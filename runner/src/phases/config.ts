/**
 * Runner config resolution (v0.19.0 refactor — extracted from phases.ts).
 */
import { type ResolvedRunnerConfig } from "../types.js";
import { join } from "node:path";

/**
 * Parse an env-provided positive number at config-parse time (v0.28.0).
 * Mirrors the rotation config precedent: fail fast with a message naming
 * the exact variable instead of dying later on NaN deep inside a
 * constructor or limiter.
 */
function parseEnvPositiveNumber(raw: string | undefined, name: string): number | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`[runner] bad ${name}=${JSON.stringify(raw)}; want a positive number`);
  }
  return n;
}

export function resolveConfig(env: NodeJS.ProcessEnv, opts: {
  mcpToken?: string;
  deepseekApiKey?: string;
  qwenApiKey?: string;
  mcpEndpoint?: string;
  maxReconTurns?: number;
  maxExploitProbes?: number;
  maxActions?: number;
  maxDurationMs?: number;
  probeDelayMs?: number;
  engagementsDir?: string;
  registryPath?: string;
  dryRunAgents?: boolean;
  localSandbox?: boolean;
  /** Per-host rate limit override (requests/sec). Env REDTEAM_MAX_RPS. Production caps at 2 mechanically. */
  maxRpsPerHost?: number;
  /** v0.20.0: per-item variant cap override. Env REDTEAM_MAX_VARIANTS. Undefined = env default (25 staging, 10 production). */
  maxVariantsPerItem?: number;
} = {}): ResolvedRunnerConfig {
  const mcpToken = opts.mcpToken ?? env["SECSCAN_MCP_TOKEN"];
  if (!mcpToken) {
    throw new Error(
      "[runner] SECSCAN_MCP_TOKEN is not set. Enter the SecScan MCP token via the Secure Vault (it lands in the environment).",
    );
  }
  const deepseekApiKey = opts.deepseekApiKey ?? env["DEEPSEEK_API_KEY"];
  if (!deepseekApiKey && !opts.dryRunAgents) {
    throw new Error(
      "[runner] DEEPSEEK_API_KEY is not set. Enter the DeepSeek API key via the Secure Vault.",
    );
  }
  // v0.6: no role currently routes to Qwen (see llm-router/src/policy.ts —
  // operator is running DeepSeek-only for now, Qwen to come back later), so
  // its key is optional here. It's still read/threaded through so flipping
  // policy.ts back to Qwen for the exploiter needs no config-layer change.
  const qwenApiKey = opts.qwenApiKey ?? env["QWEN_API_KEY"] ?? env["DASHSCOPE_API_KEY"];
  if (opts.qwenApiKey && !env["QWEN_API_KEY"] && !env["DASHSCOPE_API_KEY"]) {
    // Key passed programmatically: make it visible to the provider, which
    // reads env only. Never logged, never persisted.
    env["QWEN_API_KEY"] = opts.qwenApiKey;
  }
  return {
    // Blank-but-present SECSCAN_MCP_URL (the .env.example convention for
    // "unset, use the default") must fall through too — "" ?? x is "",
    // not x, so a stray fetch("") blew up here before the .trim()/|| guard.
    mcpEndpoint: opts.mcpEndpoint || env["SECSCAN_MCP_URL"]?.trim() || "https://secscan.us/api/mcp",
    mcpToken,
    deepseekApiKey: deepseekApiKey ?? "",
    qwenApiKey: qwenApiKey ?? "",
    maxReconTurns: opts.maxReconTurns ?? 10,
    maxExploitProbes: opts.maxExploitProbes ?? 12,
    maxActions: opts.maxActions ?? 60,
    maxDurationMs: opts.maxDurationMs ?? 45 * 60_000,
    probeDelayMs: opts.probeDelayMs ?? 800,
    engagementsDir:
      opts.engagementsDir ??
      (env["REDTEAM_HOME"] ? join(env["REDTEAM_HOME"], "engagements", "live") : join(process.cwd(), "engagements", "live")),
    registryPath:
      opts.registryPath ??
      (env["REDTEAM_HOME"] ? join(env["REDTEAM_HOME"], "engagements", "registry.json") : join(process.cwd(), "engagements", "registry.json")),
    dryRunAgents: opts.dryRunAgents ?? false,
    localSandbox: opts.localSandbox ?? env["REDTEAM_LOCAL_SANDBOX"] === "1",
    maxRpsPerHost: opts.maxRpsPerHost ?? parseEnvPositiveNumber(env["REDTEAM_MAX_RPS"], "REDTEAM_MAX_RPS"),
    maxVariantsPerItem: opts.maxVariantsPerItem ?? parseEnvPositiveNumber(env["REDTEAM_MAX_VARIANTS"], "REDTEAM_MAX_VARIANTS"),
  };
}

