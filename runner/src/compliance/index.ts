/**
 * Compliance-mapped reporting (v0.12.0) — the enterprise buyer gate.
 *
 * The reporter produces the client narrative; this module produces the
 * EVIDENCE a client's auditors use: a control catalog (PCI DSS v4.0.1
 * Req 11.4, SOC 2 CC6.1/CC6.6/CC7.1, ISO 27001:2022 A.8.8), a defensible
 * ATT&CK→control mapping, a per-engagement evidence pack, and an honest
 * attestation letter template.
 *
 * Nothing here declares anyone compliant or certified — the pack is
 * evidence supporting requirements, and the attestation says so explicitly.
 */

export { COMPLIANCE_CONTROLS, lookupControl } from "./controls.js";
export type { ComplianceControl, ComplianceFramework } from "./controls.js";
export {
  TECHNIQUE_CONTROL_MAP,
  controlsForTechnique,
  unmappedBatteryTechniques,
  invalidMappedControlIds,
} from "./mapping.js";
export type { TechniqueControlMapping } from "./mapping.js";
export {
  METHODOLOGY_EXCLUSIONS,
  METHODOLOGY_TOOLS,
  buildCompliancePack,
  buildRetestEvidence,
  renderCompliancePackMarkdown,
} from "./pack.js";
export type {
  CompliancePack,
  CompliancePackInput,
  PackFinding,
  RetestEntry,
  RetestObservation,
} from "./pack.js";
export { renderAttestationLetter } from "./attestation.js";
export type { AttestationInput } from "./attestation.js";
export { allBatteryAttackIds } from "../targets/index.js";
