/**
 * Nmap prerequisite probe (v0.31.0).
 *
 * Whether the operator's nmap binary is available — the honest, mechanical
 * reading behind any NEEDS_NMAP battery marker. Explicit REDTEAM_NMAP_BIN wins;
 * otherwise a cached PATH probe. Cloned from the nuclei probe: called at ledger
 * build, never on a hot path, and cached because a probe per item would spawn a
 * process per item.
 *
 * The PATH probe uses a Node-native lookup rather than `sh -c command -v`,
 * which the nuclei probe inherited from its Unix origins and which cannot work
 * on Windows — where nmap ships inside the Metasploit installer and is often
 * not on PATH at all.
 */
import { execFileSync } from "node:child_process";
import { NMAP_ENV_BIN } from "./policy.js";

let probeCache: boolean | undefined;

/** Test-only: reset the cached probe so env changes take effect. */
export function _resetNmapProbeCache(): void {
  probeCache = undefined;
}

export function nmapBinaryPresent(env: NodeJS.ProcessEnv = process.env): boolean {
  if (probeCache !== undefined) return probeCache;
  // Run `--version`, not just resolve a path: a present-but-unrunnable nmap
  // (missing Npcap driver or the VC++ runtime, which surface as a DLL load
  // failure) used to report "present" and then fail mid-engagement. Executing it
  // is the only honest probe.
  const candidate = (env[NMAP_ENV_BIN] ?? "").trim() || "nmap";
  try {
    execFileSync(candidate, ["--version"], { stdio: "ignore", timeout: 8000 });
    probeCache = true;
  } catch {
    probeCache = false;
  }
  return probeCache;
}
