/**
 * Nuclei prerequisite probe (v0.21.0).
 *
 * Whether the operator's nuclei binary is available — the honest,
 * mechanical reading behind the NEEDS_NUCLEI battery marker. Checked from
 * the environment (explicit REDTEAM_NUCLEI_BIN wins) with a cached PATH
 * probe fallback. Called at ledger build, never on a hot path.
 */
import { execFileSync } from "node:child_process";
import { NUCLEI_ENV_BIN } from "./policy.js";

let probeCache: boolean | undefined;

/** Test-only: reset the cached probe so env changes take effect. */
export function _resetNucleiProbeCache(): void {
  probeCache = undefined;
}

export function nucleiBinaryPresent(env: NodeJS.ProcessEnv = process.env): boolean {
  if (probeCache !== undefined) return probeCache;
  const explicit = (env[NUCLEI_ENV_BIN] ?? "").trim();
  if (explicit) {
    probeCache = true;
    return true;
  }
  try {
    execFileSync("sh", ["-c", "command -v nuclei"], { stdio: "ignore", timeout: 5000 });
    probeCache = true;
  } catch {
    probeCache = false;
  }
  return probeCache;
}
