/**
 * PROOF OF EXPLOITATION — PoC bundles (v0.14.0).
 *
 * Reproducible proof is the 2026 credibility standard: it is what separates
 * a serious pentest product from "AI-washing". The runner already validates
 * findings with canary markers; this module turns each validation into a
 * structured, re-verifiable proof bundle.
 *
 * The cardinal rule: bundles are DERIVED from the audit log (events.jsonl),
 * mechanically — never reconstructed from memory, never fabricated. A
 * bundle exists only when the audit trail shows a genuine validation signal:
 *   - "execution" tier: a canary marker echo was observed (the marker sent
 *     came back in tool output — command execution proved), or
 *   - "observation" tier: a read-only enumeration tool's output directly
 *     demonstrates the finding (e.g. ad_enum listing an ESC1-vulnerable
 *     certificate template — the output IS the evidence).
 * Killed hypotheses and unvalidated probes get NO bundle. The absence is
 * honest: not every probe becomes a finding.
 *
 * Anti-overclaim: the bundle proves the specific executed action, never
 * full impact ("command executed as SYSTEM", not "domain compromised").
 */

export { PROOF_TOOL_ACTIONS } from "./bundle/steps.js";
export type { PocReplay, PocStep, StepValidation } from "./bundle/steps.js";
export { buildPocBundle } from "./bundle/bundle.js";
export type { BundleBuildInput, BundleBuildResult, PocBundle, ValidationTier } from "./bundle/bundle.js";
export { buildNegativeProof, bundleSummary } from "./bundle/negative.js";
export type { NegativeProof } from "./bundle/negative.js";
