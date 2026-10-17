/**
 * On-host smoke: Windows PC-agent channel contract (v0.34.0).
 *
 * `src/host-exec/pc-agent.ts` is a contract until it has talked to a real agent.
 * This script talks to one — AlterEgo's pc-agent, or any MCP Streamable-HTTP agent
 * exposing the same allow-listed tools — and prints what came back.
 *
 * Configuration (both required; the script skips with exit 0 when unset, so it is
 * safe to wire into CI on machines without an agent):
 *   REDTEAM_PC_AGENT_URL    e.g. http://127.0.0.1:8765/mcp
 *   REDTEAM_PC_AGENT_TOKEN  the agent's bearer token (obtained through its pairing flow)
 *
 * What it proves:
 *   1. configuration is accepted by the same gate the runner uses
 *   2. the MCP handshake completes over Streamable HTTP (initialize,
 *      notifications/initialized, tools/call)
 *   3. `system_info` returns a result from the host
 *   4. a tool outside the allow-list is refused locally, before any request
 *
 * Usage: node scripts/smoke-pc-agent.mjs
 */

import { createPcAgentClient, pcAgentConfig } from "../dist/host-exec/pc-agent.js";

/** Fetch adapter matching the client's declared FetchLike surface. */
async function fetchImpl(url, init) {
  const response = await fetch(url, init);
  return { ok: response.ok, status: response.status, headers: response.headers, text: () => response.text() };
}

async function main() {
  const config = pcAgentConfig(process.env);
  if (!config) {
    process.stdout.write(
      "smoke-pc-agent: SKIP — set REDTEAM_PC_AGENT_URL and REDTEAM_PC_AGENT_TOKEN (>=16 chars) to run this against a real agent\n",
    );
    return;
  }
  process.stdout.write(`smoke-pc-agent: agent ${config.url}\n`);

  const client = createPcAgentClient(config, fetchImpl);

  const systemInfo = await client.call("system_info", {});
  process.stdout.write(`smoke-pc-agent: PASS system_info (${String(systemInfo.length)} chars of MCP reply)\n`);

  const listing = await client.call("list_dir", { path: process.env.USERPROFILE ?? "." });
  process.stdout.write(`smoke-pc-agent: PASS list_dir (${String(listing.length)} chars)\n`);

  let refused = false;
  try {
    await client.call("delete_file", { path: "nope" });
  } catch (error) {
    refused = /allow-list/.test(error instanceof Error ? error.message : String(error));
  }
  if (!refused) throw new Error("the client did not refuse an off-allow-list tool");
  process.stdout.write("smoke-pc-agent: PASS off-allow-list tool refused locally\n");

  process.stdout.write("smoke-pc-agent: PASS all checks\n");
}

main().catch((error) => {
  process.stderr.write(`smoke-pc-agent: FAIL — ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
