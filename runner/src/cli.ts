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

import { enqueueEngagement, runEngagement, watchQueue } from "./index.js";
import type { EngagementInput, EngagementMode, RulesOfEngagement } from "./types.js";
import { isTargetId } from "./targets.js";
import type { TargetId } from "./targets.js";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function argAll(flag: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < process.argv.length; i++) {
    if (process.argv[i] === flag && process.argv[i + 1]) out.push(process.argv[i + 1]!);
  }
  return out;
}

function flag(name: string): boolean {
  return process.argv.includes(name);
}

function usage(): never {
  console.error(`Usage:
  redteam-runner start --target <domain|url> --mode <red|black> --objective "<text>" --scope <host> [--scope <host>...] [--exclude <Txxxx>...] [--blackout "02:00-04:00 America/Chicago"...] [--client "<name>"] [--full-battery] [--targets secscan,seclayer,windows,linux] [--local-sandbox] [--dry-run]
  redteam-runner start --target secscan+seclayer --mode red --objective "<text>" --scope secscan.us   # full-battery unified engagement (web targets only)
  redteam-runner queue  --target ... (same flags)   # enqueue for the watcher / console
  redteam-runner watch [--queue <dir>]              # run queued jobs until aborted

--full-battery (or --target secscan+seclayer): ONE unified engagement running the
target-specific batteries (3 categories × selected targets). The coordinator
prompt carries the selected batteries as the plan skeleton; coverage counts
complete only when every cell is probed or honestly BLOCKED.
--targets <csv>: subset of secscan,seclayer,windows,linux for a full-battery run
(default: all four). Only applies with --full-battery. Three battery items
carry honest prerequisites (WS-064: kerberos ticket material, WS-065: human
operator for the shadowing act, LX-041: privileged test client for the mount
proof) — see docs/ROADMAP.md; --scope must cover secscan.us for the web targets.

--local-sandbox: LOCAL SANDBOX MODE ONLY. Skips ownership verification and the
private-host rejection, but only for a target that already resolves to a
private/loopback address (e.g. localhost, 127.0.0.1). No effect on a real
domain. Use only against infrastructure you own, e.g. a local Juice
Shop/DVWA container — never against a live/internet target.

--dry-run: skip the live agent loops (no DEEPSEEK_API_KEY/QWEN_API_KEY
needed) — runs gating/authorize/scope/report plumbing only, useful for
smoke-testing the runner itself.

Env: SECSCAN_MCP_TOKEN, DEEPSEEK_API_KEY, QWEN_API_KEY, SECSCAN_MCP_URL (optional), REDTEAM_LOCAL_SANDBOX=1.
Host-exec (v0.9.0, Windows/Linux batteries): REDTEAM_SSH_USER + one of
REDTEAM_SSH_PASSWORD / REDTEAM_SSH_KEY / REDTEAM_SSH_KEY_PATH;
REDTEAM_SMB_USER + REDTEAM_SMB_PASSWORD (+ optional REDTEAM_SMB_DOMAIN);
REDTEAM_WINRM_USER + REDTEAM_WINRM_PASSWORD. Test accounts only, via
environment or Secure Vault — never in code, never logged.
Metasploit bridge (v0.11.0, CVE exploit validation): REDTEAM_MSFRPC_USER +
REDTEAM_MSFRPC_PASS (+ optional REDTEAM_MSFRPC_HOST / REDTEAM_MSFRPC_PORT /
REDTEAM_MSFRPC_TLS=0). Requires the operator's msfrpcd running
(msfrpcd -P <pass> -U <user> -a 127.0.0.1 -p 55553 -S) — fail closed otherwise.`);
  process.exit(2);
}

function parseBlackout(s: string): { start: string; end: string; tz?: string } {
  const m = s.match(/^(\d{2}:\d{2})-(\d{2}:\d{2})(?:\s+(.+))?$/);
  if (!m) {
    console.error(`[runner] bad --blackout ${JSON.stringify(s)}; want "HH:MM-HH:MM [Timezone]"`);
    process.exit(2);
  }
  return { start: m[1]!, end: m[2]!, tz: m[3] };
}

function buildInput(): EngagementInput {
  const target = arg("--target");
  const mode = arg("--mode") as EngagementMode | undefined;
  const objective = arg("--objective");
  const scopes = argAll("--scope");
  if (!target || !mode || !objective || scopes.length === 0) usage();
  const fullBattery = process.argv.includes("--full-battery") || target === "secscan+seclayer";
  const excludeArgs = argAll("--exclude");
  // --targets narrows the full-battery subset; the secscan+seclayer shortcut pins web targets.
  let targets: TargetId[] | undefined;
  if (target === "secscan+seclayer") {
    targets = ["secscan", "seclayer"];
  } else if (arg("--targets")) {
    const parsed = arg("--targets")!.split(",").map((s) => s.trim().toLowerCase()).filter((s) => s.length > 0);
    const bad = parsed.filter((s) => !isTargetId(s));
    if (bad.length > 0) {
      console.error(`[runner] bad --targets ${JSON.stringify(bad)}; want comma-separated subset of secscan,seclayer,windows,linux`);
      process.exit(2);
    }
    targets = parsed as TargetId[];
  }
  const roe: RulesOfEngagement = {
    scope: scopes,
    excludedTechniques: excludeArgs.length > 0 ? excludeArgs : null,
    blackoutWindows: argAll("--blackout").map(parseBlackout),
    stopConditions: argAll("--stop"),
    deconflictionContact: arg("--contact"),
    notes: arg("--notes"),
  };
  return { target: target!, mode: mode!, objective: objective!, roe, client: arg("--client"), fullBattery, targets };
}

async function main(): Promise<void> {
  const cmd = process.argv[2];
  if (cmd === "start") {
    const input = buildInput();
    const result = await runEngagement(input, { localSandbox: flag("--local-sandbox"), dryRunAgents: flag("--dry-run") });
    console.log(JSON.stringify({ status: result.status, engagementId: result.engagementId, blockedReason: result.blockedReason, findings: result.findings.length }, null, 2));
    process.exit(result.status === "complete" ? 0 : 1);
  }
  if (cmd === "queue") {
    const input = buildInput();
    const path = enqueueEngagement(input, arg("--queue"));
    console.log(`queued: ${path}`);
    return;
  }
  if (cmd === "watch") {
    const queueDir = arg("--queue");
    console.log(`[runner] watching ${queueDir ?? "(default queue dir)"} — Ctrl+C to stop`);
    const ctrl = new AbortController();
    process.on("SIGINT", () => ctrl.abort());
    await watchQueue(queueDir, {}, 10_000, ctrl.signal);
    return;
  }
  usage();
}

main().catch((err) => {
  console.error(`[runner] fatal: ${(err as Error).message}`);
  process.exit(1);
});
