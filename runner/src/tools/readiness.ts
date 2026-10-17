/**
 * Readiness report — "is this installation actually able to run an engagement?"
 *
 * The product's promise is that an installed app is ready to use. Today that
 * promise is only true if a list of external things happens to be in place:
 * the bridge binaries (nmap, ffuf, …), a wordlist, the Metasploit RPC daemon,
 * and the three credentials the engine reads from the environment. When any of
 * them is missing the failure surfaced *late and one tool at a time* — mid
 * engagement, as `spawn nmap ENOENT` or `missing REDTEAM_SMB_USER` — which is
 * exactly the class of problem a first-run check should eliminate.
 *
 * This module is the mechanical answer: one pure-ish probe that names every
 * requirement, whether it is satisfied, and the fix when it is not. The CLI
 * exposes it as `redteam-runner doctor`; the desktop app can render the same
 * report on first run and offer to install the bundled tool payloads.
 *
 * Design rules: never throw, never touch a target, and keep every probe cheap
 * (one version spawn per binary, one 1s TCP connect for the RPC daemon).
 */

import { execFileSync } from "node:child_process";
import { connect as netConnect } from "node:net";
import { existsSync } from "node:fs";

import { XTOOLS, type XToolId } from "../xtool/registry.js";
import { nmapBinaryPresent } from "../nmap/prereq.js";
import { resolveWordlist } from "../xtool/wordlist.js";
import { pcAgentConfigured } from "../host-exec/pc-agent.js";
import { browserConfigured, BROWSER_SETUP_GUIDANCE } from "../browser/cdp.js";

export type ReadinessState = "ready" | "missing" | "unreachable" | "not-configured";

export interface ReadinessItem {
  /** Stable identifier used by the UI / tests. */
  id: string;
  /** Human label. */
  label: string;
  state: ReadinessState;
  /** What was found, when relevant (path, version, endpoint). */
  detail?: string;
  /** What to do when the state is not `ready`. */
  fix?: string;
  /** Required items block an engagement; optional ones only degrade it. */
  required: boolean;
}

export interface ReadinessReport {
  /** True when every required item is ready. */
  ok: boolean;
  items: ReadinessItem[];
  /** Short human summary, e.g. "3 of 9 ready — 2 required missing". */
  summary: string;
}

/** One version probe. Returns the first output line, or undefined when not runnable. */
export function probeBinary(bin: string, args: readonly string[]): string | undefined {
  try {
    const out = execFileSync(bin, [...args], { stdio: "pipe", timeout: 8000, encoding: "utf8" });
    return String(out).split("\n")[0]?.trim() || "present";
  } catch {
    return undefined;
  }
}

/** TCP reachability for the Metasploit RPC daemon (1s, no target traffic). */
export function probeTcp(host: string, port: number, timeoutMs = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = netConnect({ host, port });
    const done = (reachable: boolean): void => {
      socket.destroy();
      resolve(reachable);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
  });
}

/**
 * Build the full readiness report.
 *
 * `env` is injectable for tests; the RPC probe is async because it opens a
 * socket, so the whole report is async.
 */
export async function readinessReport(env: NodeJS.ProcessEnv = process.env): Promise<ReadinessReport> {
  const items: ReadinessItem[] = [];

  // --- bridge binaries -----------------------------------------------------
  // nmap uses its own honest probe (it runs --version, so a present-but-broken
  // binary — missing Npcap or VC++ runtime — is reported as missing).
  const nmapReady = nmapBinaryPresent(env);
  const nmapBin = (env["REDTEAM_NMAP_BIN"] ?? "").trim() || "nmap";
  items.push({
    id: "nmap",
    label: "nmap (port/service discovery)",
    state: nmapReady ? "ready" : "missing",
    detail: nmapReady ? nmapBin : undefined,
    fix: nmapReady
      ? undefined
      : "Install nmap and put it on PATH (or set REDTEAM_NMAP_BIN). Windows: the official build needs the VC++ 2015-2022 x86 runtime; SYN scans additionally need Npcap + elevation (the runner falls back to connect scans without them).",
    required: true,
  });

  for (const spec of XTOOLS) {
    const bin = (env[spec.envBin] ?? "").trim() || spec.id;
    const present = existsSync(bin) || probeBinary(bin, ["-V"]) !== undefined || probeBinary(bin, ["--version"]) !== undefined;
    // The content-discovery tools are optional: the web battery degrades but the
    // host battery still runs. john is offline-only and never required.
    const required = false;
    items.push({
      id: spec.id,
      label: `${spec.id} (${spec.purpose})`,
      state: present ? "ready" : "missing",
      detail: present ? bin : undefined,
      fix: present ? undefined : spec.setup.join(" "),
      required,
    });
  }

  // --- wordlist ------------------------------------------------------------
  const wordlist = resolveWordlist(undefined, env);
  items.push({
    id: "wordlist",
    label: "content-discovery wordlist",
    state: wordlist ? "ready" : "missing",
    detail: wordlist,
    fix: wordlist
      ? undefined
      : "The runner ships assets/wordlists/common.txt; if that file is absent set REDTEAM_WORDLIST to a wordlist path, or pass `wordlist` on the tool call.",
    required: true,
  });

  // --- Metasploit RPC daemon ----------------------------------------------
  const rpcHost = (env["REDTEAM_MSFRPC_HOST"] ?? "127.0.0.1").trim() || "127.0.0.1";
  const rpcPort = Number((env["REDTEAM_MSFRPC_PORT"] ?? "55553").trim() || 55553);
  const rpcConfigured = Boolean((env["REDTEAM_MSFRPC_USER"] ?? "").trim() && (env["REDTEAM_MSFRPC_PASS"] ?? "").trim());
  if (!rpcConfigured) {
    items.push({
      id: "msfrpcd",
      label: "Metasploit RPC bridge (msfrpcd)",
      state: "not-configured",
      fix: "Start msfrpcd on loopback and set REDTEAM_MSFRPC_USER / REDTEAM_MSFRPC_PASS (plus HOST/PORT/TLS as needed). The MSF exploit arm is then available; without it the battery still runs.",
      required: false,
    });
  } else {
    const reachable = await probeTcp(rpcHost, rpcPort);
    items.push({
      id: "msfrpcd",
      label: "Metasploit RPC bridge (msfrpcd)",
      state: reachable ? "ready" : "unreachable",
      detail: `${rpcHost}:${rpcPort}`,
      fix: reachable
        ? undefined
        : `Credentials are set but nothing is listening on ${rpcHost}:${rpcPort} — start msfrpcd (msfrpcd -P <pass> -U <user> -a ${rpcHost} -p ${rpcPort} -S).`,
      required: false,
    });
  }

  // --- credentials the engine reads from the environment -------------------
  const secrets: ReadinessItem[] = [
    {
      id: "secscan_token",
      label: "SecScan MCP token (scan_url / get_report)",
      state: (env["SECSCAN_MCP_TOKEN"] ?? "").trim() ? "ready" : "missing",
      fix: "Set SECSCAN_MCP_TOKEN (Secure Vault → lands in the environment). Create one at https://secscan.us/settings.",
      required: true,
    },
    {
      id: "deepseek_key",
      label: "DeepSeek API key (agent loops)",
      state: (env["DEEPSEEK_API_KEY"] ?? "").trim() ? "ready" : "missing",
      fix: "Set DEEPSEEK_API_KEY (Secure Vault). No live engagement can run without it.",
      required: true,
    },
    {
      id: "seclayer_key",
      label: "Seclayer API key (Seclayer MCP / scans)",
      state: (env["SECLAYER_API_KEY"] ?? "").trim() ? "ready" : "missing",
      fix: "Optional: set SECLAYER_API_KEY to use the Seclayer MCP server and its scan tools.",
      required: false,
    },
  ];
  items.push(...secrets);

  // Optional channels: their absence degrades coverage but never blocks a run.
  items.push(
    {
      id: "pc_agent",
      label: "Windows PC-agent channel (optional)",
      state: pcAgentConfigured(env) ? "ready" : "not-configured",
      fix: "Optional: set REDTEAM_PC_AGENT_URL / REDTEAM_PC_AGENT_TOKEN to enable the PC-agent host-exec backend (a Windows target with no SMB/WinRM/SSH available).",
      required: false,
    },
    {
      id: "browser",
      label: "Browser / CDP driver (optional)",
      state: browserConfigured(env) ? "ready" : "not-configured",
      fix: BROWSER_SETUP_GUIDANCE,
      required: false,
    },
  );

  const requiredItems = items.filter((i) => i.required);
  const requiredMissing = requiredItems.filter((i) => i.state !== "ready");
  const ok = requiredMissing.length === 0;
  return {
    ok,
    items,
    summary:
      `${items.filter((i) => i.state === "ready").length} of ${items.length} ready — ` +
      (ok ? "required items satisfied" : `${requiredMissing.length} required missing: ${requiredMissing.map((i) => i.id).join(", ")}`),
  };
}

/** Render a report as a plain-text table for the CLI. */
export function formatReadiness(report: ReadinessReport): string {
  const lines: string[] = [`readiness: ${report.summary}`, ""];
  for (const item of report.items) {
    const mark = item.state === "ready" ? "OK  " : item.state === "missing" ? "MISS" : item.state === "unreachable" ? "DOWN" : "CFG ";
    lines.push(`${mark} ${item.label.padEnd(48)} ${item.detail ?? ""}`.trimEnd());
    if (item.fix && item.state !== "ready") lines.push(`     → ${item.fix}`);
  }
  return lines.join("\n");
}

export type { XToolId };
