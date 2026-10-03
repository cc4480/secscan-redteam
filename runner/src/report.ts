/**
 * Report phase — barrel (v0.19.0 refactor).
 *
 * The report phase lives in ./report/ (phase orchestrator, proof bundles,
 * integrations, safety manifest, compliance pack, Slack notify, narrative).
 * This barrel keeps the `./report.js` import path working unchanged.
 */
export * from "./report/phase.js";
export * from "./report/proof.js";
export * from "./report/integrations.js";
export * from "./report/safety.js";
export * from "./report/compliance.js";
export * from "./report/notify.js";
export * from "./report/narrative.js";
