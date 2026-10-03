/**
 * Runner bookkeeping tools: registry, target map, findings, verdicts, abort.
 */
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";

export const QUERY_REGISTRY_TOOL: JsonSchemaTool = {
  name: "query_registry",
  description:
    "Query the persistent vulnerability registry: what was CONFIRMED against similar targets (payload patterns to fuse further) and what was KILLED (negative intelligence — the exact attempt died; re-attack the class only with a different angle, never the identical probe). Call BEFORE forming hypotheses. Args: vulnClass, stack (comma-separated hints), appType, attackId, limit.",
  parameters: {
    type: "object",
    properties: {
      vulnClass: { type: "string" },
      stack: { type: "string" },
      appType: { type: "string" },
      attackId: { type: "string" },
      limit: { type: "number" },
    },
  },
};
export const UPDATE_TARGET_MAP_TOOL: JsonSchemaTool = {
  name: "update_target_map",
  description:
    "Write entries to the SHARED target map the whole team reads (recon's handoff to the exploiter, kept live). Call as you discover attack surface — method + params + auth state + ATT&CK ID per entry.",
  parameters: {
    type: "object",
    properties: {
      entries: {
        type: "array",
        items: {
          type: "object",
          properties: {
            area: { type: "string" },
            method: { type: "string" },
            params: { type: "string" },
            authState: { type: "string" },
            attackId: { type: "string" },
            notes: { type: "string" },
          },
          required: ["area", "method"],
        },
      },
    },
    required: ["entries"],
  },
};
export const RECORD_FINDING_TOOL: JsonSchemaTool = {
  name: "record_finding",
  description:
    "Record a CONFIRMED finding the moment it lands (two independent observations required). Writes to shared state AND the persistent registry immediately. Args: severity (critical|high|medium|low|info), title, attackId, evidence, vulnClass?, payload? (the proving payload pattern).",
  parameters: {
    type: "object",
    properties: {
      severity: { type: "string" },
      title: { type: "string" },
      attackId: { type: "string" },
      evidence: { type: "string" },
      vulnClass: { type: "string" },
      payload: { type: "string" },
    },
    required: ["severity", "title", "attackId", "evidence"],
  },
};
export const RECORD_KILLED_TOOL: JsonSchemaTool = {
  name: "record_killed",
  description:
    "Record a KILLED hypothesis the moment it dies (what was tried + the killing observation). Negative knowledge — recorded so future engagements attack smarter, not narrower: the exact attempt is dead, the class stays in play. Args: hypothesis, killingObservation, attackId?, vulnClass?, payload? (what was tried).",
  parameters: {
    type: "object",
    properties: {
      hypothesis: { type: "string" },
      killingObservation: { type: "string" },
      attackId: { type: "string" },
      vulnClass: { type: "string" },
      payload: { type: "string" },
    },
    required: ["hypothesis", "killingObservation"],
  },
};
export const RECORD_ITEM_VERDICT_TOOL: JsonSchemaTool = {
  name: "record_item_verdict",
  description:
    'Record an explicit per-item verdict for a battery item that is NOT APPLICABLE to this target (e.g. "target exposes no SMB service"). The battery cannot report complete while any item is pending, so items with no applicable surface must be declared here — with evidence, never a bare flag. Args: batteryItem (e.g. "SS-042"), verdict ("na" — the only verdict this tool records), evidence (REQUIRED: the observation proving non-applicability).',
  parameters: {
    type: "object",
    properties: {
      batteryItem: { type: "string" },
      verdict: { type: "string", enum: ["na"] },
      evidence: { type: "string" },
    },
    required: ["batteryItem", "verdict", "evidence"],
  },
};
export const ABORT_TOOL: JsonSchemaTool = {
  name: "abort_engagement",
  description:
    "COORDINATOR ONLY. Abort the engagement immediately. Call on any stop condition, ROE violation, detection of an auth-gate bypass attempt, or production-impact signal. Arg: reason.",
  parameters: {
    type: "object",
    properties: { reason: { type: "string" } },
    required: ["reason"],
  },
};
