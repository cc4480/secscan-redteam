/**
 * Runner config resolution (v0.19.0 refactor — extracted from phases.ts).
 */
import { type ResolvedRunnerConfig } from "../types.js";
import { join } from "node:path";

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
  // The exploiter runs on Qwen (qwen3.8-max reasoning) — fail fast if its key
  // is missing rather than dying mid-engagement.
  const qwenApiKey = opts.qwenApiKey ?? env["QWEN_API_KEY"] ?? env["DASHSCOPE_API_KEY"];
  if (!qwenApiKey && !opts.dryRunAgents) {
    throw new Error(
      "[runner] QWEN_API_KEY is not set. Enter the Alibaba Model Studio API key via the Secure Vault.",
    );
  }
  if (opts.qwenApiKey && !env["QWEN_API_KEY"] && !env["DASHSCOPE_API_KEY"]) {
    // Key passed programmatically: make it visible to the provider, which
    // reads env only. Never logged, never persisted.
    env["QWEN_API_KEY"] = opts.qwenApiKey;
  }
  return {
    mcpEndpoint: opts.mcpEndpoint ?? env["SECSCAN_MCP_URL"] ?? "https://secscan.us/api/mcp",
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
    maxRpsPerHost: opts.maxRpsPerHost ?? (env["REDTEAM_MAX_RPS"] ? Number(env["REDTEAM_MAX_RPS"]) : undefined),
    maxVariantsPerItem: opts.maxVariantsPerItem ?? (env["REDTEAM_MAX_VARIANTS"] ? Number(env["REDTEAM_MAX_VARIANTS"]) : undefined),
  };
}

