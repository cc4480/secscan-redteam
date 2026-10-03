/**
 * Compliance control catalog (v0.12.0) — the compliance evidence pack's
 * authority list.
 *
 * These are the real controls, as written in the standards:
 *  - PCI DSS v4.0.1 Requirement 11.4 (penetration testing) + 11.4.1–11.4.7
 *  - SOC 2 Trust Services Criteria CC6.1, CC6.6, CC7.1
 *  - ISO/IEC 27001:2022 Annex A control A.8.8
 *
 * Every control id used anywhere in the compliance module must exist here —
 * the test suite enforces that (no invented control IDs).
 *
 * Honesty note: this catalog describes what EVIDENCE each control needs. The
 * runner produces evidence supporting a requirement; it never declares a
 * client "compliant" or "certified" — that judgment belongs to the client's
 * QSA/auditor, and the attestation letter says so explicitly.
 */

export type ComplianceFramework = "PCI DSS v4.0.1" | "SOC 2" | "ISO 27001:2022";

export interface ComplianceControl {
  /** Stable id used in mappings and reports, e.g. "PCI-11.4.1". */
  id: string;
  framework: ComplianceFramework;
  /** The control's requirement, as written in the standard (paraphrased tightly). */
  title: string;
  /** What an auditor/QSA looks for as evidence. */
  evidenceNeeds: string;
}

export const COMPLIANCE_CONTROLS: ComplianceControl[] = [
  {
    id: "PCI-11.4",
    framework: "PCI DSS v4.0.1",
    title: "Penetration testing is performed internally and externally.",
    evidenceNeeds:
      "Proof that both internal and external penetration tests were performed within the required cadence and after significant changes.",
  },
  {
    id: "PCI-11.4.1",
    framework: "PCI DSS v4.0.1",
    title:
      "A penetration testing methodology is defined, documented, and implemented, based on an industry-accepted approach (e.g. NIST SP 800-115, OWASP Testing Guide, PTES).",
    evidenceNeeds:
      "The documented methodology itself: scope, phases, techniques, tools, validation standard, and explicit exclusions — plus proof it was followed.",
  },
  {
    id: "PCI-11.4.2",
    framework: "PCI DSS v4.0.1",
    title:
      "Internal penetration tests are performed at least once every 12 months and after any significant infrastructure or application upgrade or modification.",
    evidenceNeeds:
      "Dated test record showing internal-vantage testing (authenticated/insider perspective: lateral movement, privesc, AD attack paths) within the window.",
  },
  {
    id: "PCI-11.4.3",
    framework: "PCI DSS v4.0.1",
    title:
      "External penetration tests are performed at least once every 12 months and after any significant infrastructure or application upgrade or modification.",
    evidenceNeeds:
      "Dated test record showing external-vantage testing (unauthenticated attacker perspective: public apps, APIs, network services) within the window.",
  },
  {
    id: "PCI-11.4.4",
    framework: "PCI DSS v4.0.1",
    title:
      "Exploitable vulnerabilities and security weaknesses found during penetration testing are corrected, and testing is repeated to verify the corrections.",
    evidenceNeeds:
      "Findings with remediation guidance PLUS retest evidence: the same test repeated after the fix, showing the weakness is gone (before/after).",
  },
  {
    id: "PCI-11.4.5",
    framework: "PCI DSS v4.0.1",
    title:
      "If segmentation is used to isolate the CDE, penetration tests verify that segmentation controls are operational and effective, at least once every 12 months and after any change to segmentation controls/methods.",
    evidenceNeeds:
      "Segmentation-bypass attempts and their outcomes (blocked = control effective).",
  },
  {
    id: "PCI-11.4.6",
    framework: "PCI DSS v4.0.1",
    title:
      "Additional requirement for service providers: segmentation-control penetration testing is performed at least once every 6 months.",
    evidenceNeeds:
      "Dated segmentation test records on the 6-month cadence. Applies to service providers only.",
  },
  {
    id: "PCI-11.4.7",
    framework: "PCI DSS v4.0.1",
    title:
      "Additional requirement for multi-tenant service providers: the provider supports customers' external penetration testing and vulnerability scans.",
    evidenceNeeds:
      "Provider cooperation records. Applies to multi-tenant service providers only.",
  },
  {
    id: "SOC-CC6.1",
    framework: "SOC 2",
    title:
      "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives.",
    evidenceNeeds:
      "Tests of authentication, authorization, and access-control enforcement: credential attacks, privilege escalation, broken access control, exposed secrets.",
  },
  {
    id: "SOC-CC6.6",
    framework: "SOC 2",
    title:
      "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
    evidenceNeeds:
      "External-attack-surface testing: public apps/APIs exploited, abuse protections (rate limiting) validated, external threat techniques exercised.",
  },
  {
    id: "SOC-CC7.1",
    framework: "SOC 2",
    title:
      "To meet its objectives, the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities.",
    evidenceNeeds:
      "Vulnerability discovery evidence (scanning, CVE validation), persistence-mechanism checks, and configuration-drift findings.",
  },
  {
    id: "ISO-A.8.8",
    framework: "ISO 27001:2022",
    title:
      "Management of technical vulnerabilities: information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated, and appropriate measures shall be taken.",
    evidenceNeeds:
      "Technical vulnerability inventory with exposure evaluation: discovered vulns, affected systems, severity, remediation guidance.",
  },
];

export function lookupControl(id: string): ComplianceControl | undefined {
  return COMPLIANCE_CONTROLS.find((c) => c.id === id);
}
