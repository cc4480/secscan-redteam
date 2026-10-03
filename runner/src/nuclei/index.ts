/**
 * Nuclei template bridge barrel (v0.21.0).
 *
 * Competitors reach "tens of thousands of attacks" largely via template
 * libraries. The bridge gives the runner the same reach — ProjectDiscovery
 * Nuclei's ~10,000+ community templates, resolved at runtime, never
 * hardcoded — with the runner's safety discipline: scope checks, dos
 * exclusion, kill switch, audit, honest counting (template executions are
 * reported separately from the 418 intents, never merged).
 */
export {
  NUCLEI_ENV_BIN,
  NUCLEI_ENV_TEMPLATES,
  NUCLEI_ENV_TIMEOUT,
  NUCLEI_SETUP_INSTRUCTIONS,
  NUCLEI_DENIED_TAGS,
  resolveNucleiBinary,
  resolveNucleiTimeoutS,
  resolveNucleiTemplateDir,
  buildNucleiRunArgv,
  buildNucleiListArgv,
  checkNucleiTags,
  checkNucleiExtraFlags,
  nucleiSecrets,
} from "./policy.js";
export type { NucleiTemplateFilter, NucleiRunOptions } from "./policy.js";
export {
  NucleiExecutor,
  NUCLEI_LIST_CAP,
  parseTemplateList,
  filterTemplates,
  truncateIds,
} from "./executor.js";
export type { NucleiDeps, NucleiTemplateInfo, NucleiExecResult } from "./executor.js";
export { realNucleiSpawn, parseNucleiJsonl, extractCveFromTemplate } from "./runner.js";
export type { SpawnFn, NucleiSpawnOpts, NucleiFinding, NucleiRunResult } from "./runner.js";
export { mapTemplateToBattery, overlapHint, NUCLEI_METHODOLOGY_ITEMS } from "./mapping.js";
export type { TemplateOverlap } from "./mapping.js";
export { nucleiCountLine } from "./reporting.js";
export type { NucleiCounts } from "./reporting.js";
export { nucleiBinaryPresent, _resetNucleiProbeCache } from "./prereq.js";
