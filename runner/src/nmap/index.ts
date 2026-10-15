/**
 * Nmap bridge (v0.31.0) — the runner's port and service discovery arm.
 *
 * Added because the harness integration kept hitting the same wall: an operator
 * could call nuclei, Metasploit and the web prober, but the single most basic
 * recon act — "what is listening on this host" — had no tool. nmap was present
 * on the machine the whole time, bundled inside the Metasploit installer, and
 * nothing in the product could call it.
 *
 * Shaped as a deliberate clone of the nuclei bridge: a named-profile surface
 * (no raw flags reach the agent), a policy module that is pure and testable
 * without a subprocess, an injected spawn so the parser is testable without
 * nmap, and one scope-checked host per call.
 */
export {
  NMAP_ENV_BIN,
  NMAP_ENV_TIMEOUT,
  NMAP_SETUP_INSTRUCTIONS,
  NMAP_PROFILES,
  NMAP_PROFILE_IDS,
  NMAP_ALLOWED_SCRIPT_CATEGORIES,
  NMAP_DENIED_SCRIPT_CATEGORIES,
  findProfile,
  resolveNmapBinary,
  resolveNmapTimeoutS,
  buildNmapRunArgv,
  buildNmapProfileListArgv,
  checkNmapFlags,
  checkNmapScriptCategories,
  nmapSecrets,
} from "./policy.js";
export type { NmapProfile, NmapRunOptions } from "./policy.js";
export { NmapExecutor } from "./executor.js";
export type { NmapDeps, NmapExecResult, NmapProfileInfo } from "./executor.js";
export { realNmapSpawn, parseNmapXml } from "./runner.js";
export type { SpawnFn, NmapSpawnOpts, NmapSpawnResult, NmapRunResult, NmapHostResult, NmapPort } from "./runner.js";
export { nmapBinaryPresent, _resetNmapProbeCache } from "./prereq.js";
