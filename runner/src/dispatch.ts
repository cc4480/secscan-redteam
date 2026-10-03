/**
 * Tool dispatcher — barrel (v0.19.0 refactor).
 *
 * The dispatcher lives in ./dispatch/ by tool group (web, host, msf, mcp,
 * bookkeeping) plus router (dispatchToolInner + safety wrapper) and
 * verdicts (finding/verdict helpers). This barrel keeps the `./dispatch.js`
 * import path working unchanged.
 */
export { type DispatchResult } from "./dispatch/types.js";
export { recheckVerified, optStr, numArg } from "./dispatch/prelude.js";
export { handleWebTools } from "./dispatch/web.js";
export { handleHostTools } from "./dispatch/host.js";
export { handleMsfTools } from "./dispatch/msf.js";
export { handleMcpTools } from "./dispatch/mcp.js";
export { handleBookkeepingTools } from "./dispatch/bookkeeping.js";
export { recordItemAttempt, mergeVerdictBlock } from "./dispatch/verdicts.js";
export { dispatchTool } from "./dispatch/router.js";
