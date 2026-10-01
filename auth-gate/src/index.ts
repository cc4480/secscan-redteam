export {
  TXT_RECORD_PREFIX,
  WELL_KNOWN_PATH,
  checkTxtRecord,
  extractDomain,
  generateEngagementToken,
  txtRecordName,
  verifyOwnership,
} from "./verify.js";
export type { OwnershipProof } from "./verify.js";
export { decide, installAuthGate } from "./hook.js";
export type { GateDecision, PreExecuteEvent } from "./hook.js";
