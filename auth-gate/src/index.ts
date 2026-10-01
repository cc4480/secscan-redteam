export {
  SERVER_CHALLENGE_PREFIX,
  SERVER_TOKEN_PREFIX,
  extractDomain,
  isDomainVerified,
  parseVerifiedDomains,
  verificationInstructions,
} from "./verify.js";
export { fetchVerifiedDomains, isServerVerified } from "./server.js";
export type { ServerVerificationConfig } from "./server.js";
export { decide, isScanTool, targetDomain, wantsActiveTesting } from "./hook.js";
export type { GateContext, GateDecision, PreExecuteEvent } from "./hook.js";
