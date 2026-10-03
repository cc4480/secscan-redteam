/**
 * Web UI wired directly to the CLI's code paths (v0.22.0).
 *
 * `redteam-runner ui` starts a loopback-only, token-authenticated dashboard:
 * launch engagements, stream the operation feed, browse findings with proof
 * bundles, inspect coverage and compliance packs, trigger watch cycles, and
 * hit the kill switch — all calling the same functions the CLI calls.
 */
export { startUiServer, type UiServerHandle } from "./server.js";
export { UiStore, defaultEngagementsDir, isSafeEngagementId, engagementDir, generateEngagementId } from "./store.js";
export { generateToken, isAuthorized, authCookie, UI_COOKIE } from "./auth.js";
export { renderMarkdown } from "./markdown.js";
export type { UiLaunchRequest, StoredEngagement, UiJob, UiServerOptions } from "./types.js";
