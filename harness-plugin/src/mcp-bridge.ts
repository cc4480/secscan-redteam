/**
 * MCP bridge: exposes the REAL SecScan MCP tools as DeepSeek Harness tools.
 *
 * It spawns the official `@seclayer/mcp` stdio server (the same server shipped
 * in cc4480/OPEN_SECLAYER/mcp-server/) as a child process, speaks MCP over
 * stdio with it, and registers each discovered tool as a raw JSON-Schema
 * harness tool — which is exactly "how MCP-sourced tools arrive", per the
 * harness cookbook (docs/cookbook/extension-cookbook.md).
 *
 * Real tools bridged (verified against OPEN_SECLAYER/mcp-server/src/server.ts):
 *   - seclayer_scan        (url*, authHeader?, aggressive?)
 *   - seclayer_list_scans  (limit?)
 *   - seclayer_get_report  (scanId*)
 *
 * Secrets: the bridge reads SECLAYER_API_KEY from the environment and forwards
 * it into the child process env. It NEVER logs, prints, or includes the key in
 * any tool description, error message, or returned value.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type {
  HarnessContext,
  RawToolDefinition,
  ToolExecutionContext,
} from "./harness-types.js";

export interface McpBridgeConfig {
  /** Command that launches the MCP server. Default: npx -y @seclayer/mcp */
  command?: string;
  /** Args for the command. Default: ["-y", "@seclayer/mcp"] */
  args?: string[];
  /** Env var holding the SecScan API key. Default: SECLAYER_API_KEY */
  apiKeyEnvVar?: string;
  /** Optional override for the SecScan API base URL (forwarded if the server supports it). */
  baseUrl?: string;
}

interface McpTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  annotations?: RawToolDefinition["annotations"];
}

export class McpBridge {
  private client: Client | null = null;
  private readonly config: Required<Omit<McpBridgeConfig, "baseUrl">> & { baseUrl?: string };

  constructor(config: McpBridgeConfig = {}) {
    this.config = {
      command: config.command ?? "npx",
      args: config.args ?? ["-y", "@seclayer/mcp"],
      apiKeyEnvVar: config.apiKeyEnvVar ?? "SECLAYER_API_KEY",
      baseUrl: config.baseUrl,
    };
  }

  /** Connects to the MCP server and returns its tool list. Throws if the API key is missing. */
  async connect(): Promise<McpTool[]> {
    const apiKey = process.env[this.config.apiKeyEnvVar];
    if (!apiKey) {
      throw new Error(
        `[mcp-bridge] ${this.config.apiKeyEnvVar} is not set. ` +
          `Generate a SecScan API key from the SecScan dashboard (Developer API Keys) ` +
          `and export it — or enter it via the Secure Vault — before starting the harness. ` +
          `The key is never written to disk or logs by this bridge.`,
      );
    }

    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined) env[k] = v;
    }
    // Forward the key under its canonical name even if a custom env var was configured.
    env["SECLAYER_API_KEY"] = apiKey;

    const transport = new StdioClientTransport({
      command: this.config.command,
      args: this.config.args,
      env,
      stderr: "pipe", // keep child stderr out of our stdout (MCP speaks over stdout)
    });

    const client = new Client({ name: "secscan-redteam-bridge", version: "0.1.0" });
    await client.connect(transport);
    this.client = client;

    const { tools } = await client.listTools();
    return tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: (t.inputSchema ?? { type: "object", properties: {} }) as Record<string, unknown>,
      annotations: t.annotations as RawToolDefinition["annotations"],
    }));
  }

  /** Calls a bridged MCP tool. */
  async callTool(name: string, args: Record<string, unknown>, signal: AbortSignal): Promise<unknown> {
    if (!this.client) throw new Error("[mcp-bridge] not connected — call connect() first.");
    if (signal.aborted) throw new Error(`[mcp-bridge] tool call '${name}' aborted before dispatch.`);

    const result = await this.client.callTool(
      { name, arguments: args },
      undefined,
      { signal } as never,
    );

    // Flatten MCP content blocks to plain text for the harness model surface.
    const content = (result as { content?: Array<{ type: string; text?: string }> }).content ?? [];
    const text = content
      .map((b) => (b.type === "text" ? (b.text ?? "") : `[${b.type} block omitted]`))
      .join("\n");
    if ((result as { isError?: boolean }).isError) {
      throw new Error(`[mcp-bridge] ${name} returned an error: ${text}`);
    }
    return text;
  }

  async close(): Promise<void> {
    if (this.client) {
      await this.client.close().catch(() => undefined);
      this.client = null;
    }
  }
}

/**
 * Connects the bridge and registers every discovered MCP tool in the harness
 * tool registry. Returns the registered tool names.
 */
export async function registerMcpTools(
  ctx: HarnessContext,
  bridge: McpBridge,
): Promise<string[]> {
  const tools = await bridge.connect();
  const names: string[] = [];
  for (const tool of tools) {
    const def: RawToolDefinition = {
      name: tool.name,
      description: tool.description ?? `SecScan MCP tool: ${tool.name}`,
      inputSchema: tool.inputSchema,
      annotations: tool.annotations,
    };
    ctx.tools.register(def, async (args, exec: ToolExecutionContext) => {
      return bridge.callTool(tool.name, args, exec.signal);
    });
    names.push(tool.name);
  }
  return names;
}
