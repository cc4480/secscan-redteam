/**
 * Compliance evidence pack (v0.12.0) — the per-engagement artifact a
 * client's auditors actually use.
 *
 * One engagement → one pack, written next to report.md:
 *  - engagement metadata (scope, authorization proof, ROE, dates, tester identity)
 *  - documented methodology (what QSAs demand under PCI DSS 11.4.1):
 *    agent-driven approach described truthfully, phases, tools, validation
 *    standard, explicit exclusions
 *  - findings table: finding → severity → mapped controls → evidence →
 *    remediation → retest status (registry wired in)
 *  - retest evidence: before/after observations per vulnerability class
 *
 * Everything here is runner-computed from engagement state — the pack is
 * evidence, not marketing. Wording never claims the client is "compliant"
 * or "certified"; it says "evidence supporting requirement X".
 */

export { METHODOLOGY_EXCLUSIONS, METHODOLOGY_TOOLS, buildCompliancePack } from "./pack/meta.js";
export type { CompliancePack, CompliancePackInput } from "./pack/meta.js";
export { buildRetestEvidence } from "./pack/findings.js";
export type { PackFinding, RetestEntry, RetestObservation } from "./pack/findings.js";
export { renderCompliancePackMarkdown } from "./pack/render.js";
