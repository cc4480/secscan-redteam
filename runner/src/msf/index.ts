/**
 * Metasploit bridge (v0.11.0) — the runner's CVE-specific exploit arm.
 *
 * The battery covers technique CLASSES (ATT&CK-mapped). Metasploit
 * brings the ~2,000 CVE-SPECIFIC exploits the battery can't hardcode. The
 * bridge closes that gap WITHOUT hardcoding CVEs: recon detects a
 * service/version → suggestModules maps it to candidate modules →
 * the coordinator approves → run() fires ONE module with a benign canary
 * marker as the only payload action.
 *
 * Every call goes through the same discipline as host-exec: kill switch,
 * exact-hostname ROE scope, module/payload denylists, vault credentials,
 * timeouts, session hygiene, secret redaction.
 */

export { MsfExecutor, MSF_TIMEOUT_MS } from "./executor.js";
export type { MsfDeps, MsfResult } from "./executor.js";
export { MsfClient, MsfAuthError } from "./client.js";
export type { MsfModule, ConsoleRunResult } from "./client.js";
export {
  resolveMsfCredentials,
  checkMsfPayload,
  checkMsfModule,
  msfModuleDenyList,
  buildMarkerCommand,
  msfRankWeight,
  msfSecrets,
  MSFRPC_SETUP_INSTRUCTIONS,
  MSF_ENV_HOST,
  MSF_ENV_PORT,
  MSF_ENV_USER,
  MSF_ENV_PASS,
  MSF_ENV_TLS,
} from "./policy.js";
export { extractCves, buildModuleQueries, filterAndRank, suggestModules, CVE_RE } from "./suggest.js";
export type { SuggestInput, RankedModule } from "./suggest.js";
export { msfCall, createHttpMsfRequest, MsfTransportError, MSFRPC_DEFAULT_HOST, MSFRPC_DEFAULT_PORT, MSFRPC_DEFAULT_TLS } from "./protocol.js";
export type { MsfRequestFn } from "./protocol.js";
