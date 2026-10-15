/**
 * External-tool bridges (v0.32.0): john, sqlmap, ffuf, gobuster, nikto.
 *
 * Five capabilities the product did not have, behind ONE policy module and ONE
 * executor. They share a shape — a binary, named profiles, refusals that happen
 * before the process starts — so the differences live as data in registry.ts
 * rather than as five near-identical module trees.
 */
export {
  XTOOLS,
  XTOOLS_BY_ID,
  XTOOL_DENIED_FLAGS,
  findXTool,
  findProfile,
  defaultProfile,
  checkXToolFlags,
  buildXToolArgv,
} from "./registry.js";
export type { XToolId, XToolSpec, XProfile, XRunOptions } from "./registry.js";

export {
  runXTool,
  realXSpawn,
  resolveBinPath,
  binPresent,
  parseFfufJsonl,
  parseGobusterText,
} from "./executor.js";
export type { XSpawnFn, XSpawnOpts, XSpawnResult, XExecResult, XFinding } from "./executor.js";
