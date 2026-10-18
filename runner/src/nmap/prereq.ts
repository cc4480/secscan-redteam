/**
 * Nmap prerequisite probe (v0.31.0, toolchain-aware in v0.37.0).
 *
 * Whether nmap is available -- the honest, mechanical reading behind any
 * NEEDS_NMAP battery marker. The binary path is chosen through the shared
 * toolchain resolver (explicit env -> bundled REDTEAM_TOOLS_DIR payload -> PATH),
 * then the resolved binary is RUN with --version: a present-but-unrunnable nmap
 * (missing Npcap driver or the VC++ runtime, which surface as a DLL load failure)
 * used to report "present" and then fail mid-engagement. Resolving a path is not
 * evidence; executing it is. The run happens even when the path came from the
 * bundled tools directory.
 *
 * Called at ledger build, never on a hot path, and cached because a probe per
 * item would spawn a process per item.
 */
import { execFileSync } from "node:child_process";
import { resolveExternalBinary, type ResolvedBinary } from "../toolchain.js";

let probeCache: boolean | undefined;

/** Test-only: reset the cached probe so env changes take effect. */
export function _resetNmapProbeCache(): void {
  probeCache = undefined;
}

/** Where nmap would come from and why -- no probe, no spawn. */
export function resolveNmapCommand(env: NodeJS.ProcessEnv = process.env): ResolvedBinary {
  return resolveExternalBinary("nmap", { env });
}

export function nmapBinaryPresent(env: NodeJS.ProcessEnv = process.env): boolean {
  if (probeCache !== undefined) return probeCache;
  const candidate = resolveNmapCommand(env).path;
  // Execute it, not just resolve it (see header): a DLL-broken binary is missing.
  try {
    execFileSync(candidate, ["--version"], { stdio: "ignore", timeout: 8000 });
    probeCache = true;
  } catch {
    probeCache = false;
  }
  return probeCache;
}
