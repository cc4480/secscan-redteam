/**
 * Nuclei prerequisite probe (v0.21.0, toolchain-aware in v0.37.0).
 *
 * Whether the operator's nuclei binary is available -- the honest, mechanical
 * reading behind the NEEDS_NUCLEI battery marker. The path is chosen through the
 * shared toolchain resolver (explicit env -> bundled REDTEAM_TOOLS_DIR payload ->
 * PATH). A resolved path is only evidence when it exists there; a bare command
 * name still needs the OS lookup. Called at ledger build, never on a hot path,
 * and cached because a probe per item would spawn a process per item.
 */
import { execFileSync } from "node:child_process";
import { resolveExternalBinary, type ResolvedBinary } from "../toolchain.js";

let probeCache: boolean | undefined;

/** Test-only: reset the cached probe so env changes take effect. */
export function _resetNucleiProbeCache(): void {
  probeCache = undefined;
}

/** Where nuclei would come from and why -- no probe, no spawn. */
export function resolveNucleiCommand(env: NodeJS.ProcessEnv = process.env): ResolvedBinary {
  return resolveExternalBinary("nuclei", { env });
}

export function nucleiBinaryPresent(env: NodeJS.ProcessEnv = process.env): boolean {
  if (probeCache !== undefined) return probeCache;
  const resolved = resolveNucleiCommand(env);
  // An explicit value or a bundled payload is present only when the file exists
  // (a set-but-nonexistent env path must not report "present" and then fail with
  // a confusing ENOENT at spawn time).
  if (resolved.source !== "path") {
    probeCache = resolved.exists;
    return probeCache;
  }
  if (resolved.exists) {
    probeCache = true;
    return probeCache;
  }
  // Bare command name: drop the shell (`sh -c "command -v nuclei"` never worked
  // on Windows, where there is no sh) and ask the OS directly.
  try {
    const cmd = process.platform === "win32" ? "where" : "which";
    execFileSync(cmd, ["nuclei"], { stdio: "ignore", timeout: 5000 });
    probeCache = true;
  } catch {
    probeCache = false;
  }
  return probeCache;
}
