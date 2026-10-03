#!/usr/bin/env node
/**
 * redteam-runner CLI.
 *
 *   redteam-runner start --target secscan.us --mode red \
 *     --objective "assess the external attack surface" \
 *     --scope secscan.us --exclude T1110
 *
 *   redteam-runner watch [--queue <dir>]   # run queued console jobs
 *
 * Credentials via environment only: SECSCAN_MCP_TOKEN, DEEPSEEK_API_KEY,
 * QWEN_API_KEY (Alibaba Model Studio, for the exploiter), SECSCAN_MCP_URL (optional).
 */

import { main } from "./cli/commands.js";

main().catch((err) => {
  console.error(`[runner] fatal: ${(err as Error).message}`);
  process.exit(1);
});
