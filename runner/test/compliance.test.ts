/**
 * Compliance-mapped reporting tests (v0.12.0). No network, no API keys.
 *
 * Mechanical honesty gates:
 *  - every ATT&CK technique used by the battery maps to ≥1 real control
 *    (zero unmapped IDs — a forced or missing mapping fails loudly);
 *  - no mapped control id is invented (all exist in the catalog);
 *  - the attestation letter never claims compliance or certification.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  COMPLIANCE_CONTROLS,
  TECHNIQUE_CONTROL_MAP,
  allBatteryAttackIds,
  buildCompliancePack,
  buildRetestEvidence,
  controlsForTechnique,
  invalidMappedControlIds,
  renderAttestationLetter,
  renderCompliancePackMarkdown,
  unmappedBatteryTechniques,
} from "../src/compliance.js";
import type { CompliancePackInput } from "../src/compliance.js";
import { emptyRegistry, recordConfirmed } from "../src/registry.js";
import type { Finding } from "../src/types.js";

describe("compliance control catalog", () => {
  it("covers PCI DSS 11.4 (+1..7), SOC 2 CC6.1/CC6.6/CC7.1, ISO A.8.8", () => {
    const ids = COMPLIANCE_CONTROLS.map((c) => c.id);
    for (const want of [
      "PCI-11.4",
      "PCI-11.4.1",
      "PCI-11.4.2",
      "PCI-11.4.3",
      "PCI-11.4.4",
      "PCI-11.4.5",
      "PCI-11.4.6",
      "PCI-11.4.7",
      "SOC-CC6.1",
      "SOC-CC6.6",
      "SOC-CC7.1",
      "ISO-A.8.8",
    ]) {
      assert.ok(ids.includes(want), `catalog missing ${want}`);
    }
  });

  it("control ids are unique", () => {
    const ids = COMPLIANCE_CONTROLS.map((c) => c.id);
    assert.equal(new Set(ids).size, ids.length);
  });
});

describe("ATT&CK → control mapping", () => {
  it("zero unmapped battery technique IDs", () => {
    const ids = allBatteryAttackIds();
    assert.ok(ids.length > 0, "expected battery technique IDs");
    const unmapped = unmappedBatteryTechniques();
    assert.deepEqual(unmapped, [], `unmapped techniques: ${unmapped.join(", ")}`);
  });

  it("no invented control ids in the mapping", () => {
    assert.deepEqual(invalidMappedControlIds(), []);
  });

  it("every mapping entry has a defensible rationale", () => {
    for (const m of TECHNIQUE_CONTROL_MAP) {
      assert.ok(m.rationale.length >= 40, `${m.attackId} rationale too thin`);
      assert.ok(m.controls.length >= 1, `${m.attackId} has no controls`);
    }
  });

  it("spot checks: T1190 → external testing, T1110 → logical access", () => {
    assert.ok(controlsForTechnique("T1190").includes("PCI-11.4.3"));
    assert.ok(controlsForTechnique("T1110").includes("SOC-CC6.1"));
    assert.ok(controlsForTechnique("T1595.002").includes("PCI-11.4.1"));
  });
});

function mockInput(): CompliancePackInput {
  const registry = emptyRegistry();
  recordConfirmed(registry, {
    engagementId: "eng-old",
    target: { host: "example.com", stack: [], appType: "webapp" },
    vulnClass: "SQL injection",
    technique: "Exploit Public-Facing Application",
    attackId: "T1190",
    payloadPattern: "' OR 1=1--",
    evidenceRef: "eng-old/events.jsonl",
    severity: "high",
    date: "2026-09-01T00:00:00.000Z",
  });
  recordConfirmed(registry, {
    engagementId: "eng-new",
    target: { host: "example.com", stack: [], appType: "webapp" },
    vulnClass: "SQL injection",
    technique: "Exploit Public-Facing Application",
    attackId: "T1190",
    payloadPattern: "parameter still injectable",
    evidenceRef: "eng-new/events.jsonl",
    severity: "medium",
    date: "2026-10-01T00:00:00.000Z",
  });
  const findings: Finding[] = [
    {
      id: "F-1",
      severity: "medium",
      title: "SQL injection in search parameter",
      attackIds: ["T1190"],
      evidence: "canary REDTEAM-MARKER-7 echoed in response",
      fix: "Use parameterized queries.",
      retest: "Re-ran probe after fix — marker no longer reflected.",
      status: "confirmed",
    },
    {
      id: "F-2",
      severity: "info",
      title: "Banner discloses version",
      attackIds: [],
      evidence: "Server: nginx/1.18.0",
      fix: "Suppress version banner.",
      retest: "(pending)",
      status: "confirmed",
    },
  ];
  return {
    engagementId: "eng-new",
    client: "Acme Corp",
    operator: "J. Operator",
    target: "example.com",
    mode: "red",
    objective: "assess external attack surface",
    scope: ["example.com"],
    verificationProof: "DNS TXT verified 2026-10-01",
    roe: { scope: ["example.com"] },
    testStart: "2026-10-01T09:00:00.000Z",
    testEnd: "2026-10-01T10:00:00.000Z",
    findings,
    registry,
  };
}

describe("compliance evidence pack", () => {
  it("builds all sections from a mocked engagement", () => {
    const pack = buildCompliancePack(mockInput());
    assert.equal(pack.engagementId, "eng-new");
    assert.equal(pack.operator, "J. Operator");
    assert.equal(pack.metadata.scope[0], "example.com");
    assert.ok(pack.metadata.authorizationProof.includes("DNS TXT"));
    // methodology
    assert.ok(pack.methodology.approach.includes("autonomous AI agent team"));
    assert.ok(pack.methodology.phases.length >= 5);
    assert.ok(pack.methodology.toolsUsed.length > 10);
    assert.ok(pack.methodology.validationStandard.includes("canary"));
    assert.ok(pack.methodology.exclusions.some((e) => e.includes("Denial of service")));
    // findings → controls
    const f1 = pack.findings.find((f) => f.id === "F-1")!;
    assert.ok(f1.controls.includes("PCI-11.4.3"), `F-1 controls: ${f1.controls}`);
    assert.ok(f1.controls.includes("SOC-CC6.6"));
    const f2 = pack.findings.find((f) => f.id === "F-2")!;
    assert.deepEqual(f2.controls, [], "finding without ATT&CK IDs must not be force-mapped");
    // coverage
    assert.ok(pack.coverage.controlsExercised > 0);
    assert.equal(pack.coverage.controlsTotal, COMPLIANCE_CONTROLS.length);
    assert.ok(pack.coverage.controlFindings["PCI-11.4.3"].includes("F-1"));
    // retest evidence: before/after across engagements
    const re = pack.retestEvidence.find((r) => r.vulnClass === "SQL injection")!;
    assert.equal(re.observationCount, 2);
    assert.equal(re.firstSeen.engagementId, "eng-old");
    assert.equal(re.latest.engagementId, "eng-new");
    // honest limits present
    assert.ok(pack.honestLimits.some((h) => h.includes("does not declare the client compliant")));
  });

  it("flags a missing operator name honestly instead of inventing one", () => {
    const input = mockInput();
    delete input.operator;
    const pack = buildCompliancePack(input);
    assert.ok(pack.operator.includes("not supplied"));
  });

  it("markdown rendering contains every section", () => {
    const md = renderCompliancePackMarkdown(buildCompliancePack(mockInput()));
    for (const section of [
      "# Compliance evidence pack",
      "## 1. Engagement metadata",
      "## 2. Documented methodology",
      "## 3. Findings → controls",
      "## 4. Retest evidence",
      "## 5. Honest limits",
      "does not declare the client compliant or certified",
    ]) {
      assert.ok(md.includes(section), `missing: ${section}`);
    }
  });
});

describe("attestation letter", () => {
  function letter() {
    return renderAttestationLetter({
      engagementId: "eng-new",
      client: "Acme Corp",
      operator: "J. Operator",
      issuedBy: "SecScan RedTeam",
      target: "example.com",
      mode: "red",
      objective: "assess external attack surface",
      scope: ["example.com"],
      testStart: "2026-10-01T09:00:00.000Z",
      testEnd: "2026-10-01T10:00:00.000Z",
      findingCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 1 },
      exclusions: ["Denial of service"],
    });
  }

  it("contains scope, dates, methodology, exclusions, validation standard", () => {
    const l = letter();
    assert.ok(l.includes("example.com"));
    assert.ok(l.includes("2026-10-01T09:00:00.000Z"));
    assert.ok(l.includes("autonomous AI agent team"));
    assert.ok(l.includes("Denial of service"));
    assert.ok(l.includes("canary"));
    assert.ok(l.includes("J. Operator"));
    assert.ok(l.includes("Signature:"));
  });

  it("never claims compliance or certification — for the client or for us", () => {
    const l = letter();
    const forbidden = [
      /is PCI DSS compliant/i,
      /PCI DSS (certified|certification)/i,
      /SOC 2 (certified|compliant|certification)/i,
      /ISO 27001 (certified|compliant|certification)/i,
      /hereby certifies that .* is compliant/i,
      /attests that .* (is|are) compliant/i,
    ];
    for (const re of forbidden) {
      assert.ok(!re.test(l), `forbidden claim matched: ${re}`);
    }
    // The disclaimer must be present and explicit.
    assert.ok(l.includes("does not declare the client compliant"));
    assert.ok(l.includes("Nothing in this letter claims that the testing organization holds"));
  });
});

describe("retest evidence builder", () => {
  it("returns empty for a fresh registry", () => {
    assert.deepEqual(buildRetestEvidence(emptyRegistry()), []);
  });
});
