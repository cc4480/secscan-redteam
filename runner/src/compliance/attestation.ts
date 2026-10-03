/**
 * Attestation letter template (v0.12.0) — the one-page letter a client
 * hands to their auditors alongside the evidence pack.
 *
 * HONESTY IS MECHANICAL HERE, not just a prompt instruction:
 *  - The letter states WHAT was tested, WHEN, the SCOPE, the METHODOLOGY,
 *    the EXCLUSIONS, and the VALIDATION STANDARD.
 *  - It NEVER claims the client is "compliant", "certified", or "passing".
 *  - It NEVER claims WE (the testing organization / tool vendor) hold
 *    SOC 2, ISO 27001, or any other certification.
 *  - The test suite asserts the absence of certification/compliance claims.
 *
 * Rendered to attestation.md next to report.md in the engagement directory.
 * The operator's name and the issuing organization are fill-ins — the
 * letter is a template until a human signs it.
 */

export interface AttestationInput {
  engagementId: string;
  client?: string;
  /** Named human operator accountable for the engagement. */
  operator?: string;
  /** Issuing organization (the pentest provider). Defaults to a fill-in. */
  issuedBy?: string;
  target: string;
  mode: "red" | "black";
  objective: string;
  scope: string[];
  testStart: string; // ISO
  testEnd: string; // ISO
  findingCounts: { critical: number; high: number; medium: number; low: number; info: number };
  exclusions: string[];
  issuedAt?: string;
}

const FILL = "[to be completed before delivery]";

export function renderAttestationLetter(input: AttestationInput): string {
  const issuedAt = input.issuedAt ?? new Date().toISOString().slice(0, 10);
  const c = input.findingCounts;
  const total = c.critical + c.high + c.medium + c.low + c.info;
  const L: string[] = [];
  L.push(`# Penetration test attestation`);
  L.push(``);
  L.push(`**Engagement:** ${input.engagementId}`);
  L.push(`**Issued:** ${issuedAt} · **Issued by:** ${input.issuedBy?.trim() || FILL}`);
  L.push(``);
  L.push(`This letter documents that an authorized penetration test was performed as described below. `);
  L.push(`It is provided as EVIDENCE for the client's auditors and assessors. It does not declare the client compliant with, `);
  L.push(`or certified under, any standard or framework — that determination belongs solely to the client's qualified assessor. `);
  L.push(`Nothing in this letter claims that the testing organization holds SOC 2, ISO 27001, PCI DSS, or any other certification.`);
  L.push(``);
  L.push(`## What was tested`);
  L.push(``);
  L.push(`- Client: ${input.client?.trim() || FILL}`);
  L.push(`- Target: ${input.target} (mode: ${input.mode.toUpperCase()})`);
  L.push(`- Objective: ${input.objective}`);
  L.push(`- Scope (exact): ${input.scope.join(", ") || FILL}`);
  L.push(`- Test window: ${input.testStart} → ${input.testEnd}`);
  L.push(``);
  L.push(`## Methodology (summary)`);
  L.push(``);
  L.push(`Testing was performed by an autonomous AI agent team (coordinator, recon, exploiter, reporter roles) `);
  L.push(`under mechanical safety rails: exact-hostname scope enforcement, destructive-command denylists, `);
  L.push(`Secure Vault credential handling with redaction, per-probe timeouts, a coordinator kill switch, and full audit logging. `);
  L.push(`Phase order: authorize (server-authoritative ownership proof) → plan → recon → exploit → report, `);
  L.push(`with coordinator sign-off required at every phase transition. Every action carries a MITRE ATT&CK technique ID.`);
  L.push(``);
  L.push(`## Validation standard`);
  L.push(``);
  L.push(`Findings were validated by benign canary markers (runner-built proof-of-execution markers whose echo back constitutes `);
  L.push(`the validation) — no destructive payloads, no real data exfiltration, no persistent target changes.`);
  L.push(``);
  L.push(`## Findings summary`);
  L.push(``);
  L.push(`- Critical: ${c.critical} · High: ${c.high} · Medium: ${c.medium} · Low: ${c.low} · Informational: ${c.info} · Total: ${total}`);
  L.push(`- Full findings, evidence references, remediation guidance, and control mappings: see the compliance evidence pack (compliance-pack.md).`);
  L.push(``);
  L.push(`## Explicit exclusions`);
  L.push(``);
  for (const e of input.exclusions) L.push(`- ${e}`);
  L.push(``);
  L.push(`## Accountability`);
  L.push(``);
  L.push(`Named human operator accountable for this engagement: ${input.operator?.trim() || FILL}`);
  L.push(``);
  L.push(`---`);
  L.push(``);
  L.push(`Signature: ___________________________    Date: ______________`);
  L.push(``);
  L.push(`(A signed copy of this letter, with the fill-ins above completed, is the attested record.)`);
  L.push(``);
  return L.join("\n");
}
