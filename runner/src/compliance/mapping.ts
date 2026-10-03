/**
 * ATT&CK technique → compliance control mapping (v0.12.0).
 *
 * Every ATT&CK technique ID used across the 418-item battery maps to ≥1
 * control. The mapping goes through ATT&CK deliberately: the runner already
 * tags every finding with ATT&CK IDs, so the compliance evidence pack gets
 * its control coverage mechanically instead of by hand-waving.
 *
 * Honesty rules (enforced by tests + review):
 *  - Every `controls` id must exist in the control catalog (no invented IDs).
 *  - Every mapping carries a `rationale` a QSA could read without laughing.
 *  - If a technique genuinely maps nowhere, OMIT it and let the
 *    completeness test fail loudly — never force a mapping.
 *
 * Note on T1499: the battery uses T1499 for rate-limiter SHAPE MAPPING
 * (a handful of probes to observe limiter keying) — never for actual
 * denial of service, which the runner refuses mechanically. The mapping
 * below reflects that: validating abuse protections, not causing outages.
 */

import { lookupControl } from "./controls.js";
import { allBatteryAttackIds } from "../targets/index.js";

export interface TechniqueControlMapping {
  attackId: string;
  /** Control ids — all must exist in COMPLIANCE_CONTROLS. */
  controls: string[];
  /** Why this technique is evidence for these controls. */
  rationale: string;
}

export const TECHNIQUE_CONTROL_MAP: TechniqueControlMapping[] = [
  {
    attackId: "T1190",
    controls: ["PCI-11.4.3", "PCI-11.4.4", "SOC-CC6.6", "ISO-A.8.8"],
    rationale:
      "Exploiting public-facing applications is the core of external penetration testing; validated findings feed remediation/retest and the technical-vulnerability inventory.",
  },
  {
    attackId: "T1110",
    controls: ["PCI-11.4.2", "PCI-11.4.3", "SOC-CC6.1", "ISO-A.8.8"],
    rationale:
      "Credential-guessing tests the strength of authentication controls (internal and external vantage) and surfaces weak-credential vulnerabilities.",
  },
  {
    attackId: "T1078",
    controls: ["PCI-11.4.2", "SOC-CC6.1"],
    rationale:
      "Use of valid (test) accounts validates that account lifecycle, least privilege, and credential hygiene hold — logical access security evidence.",
  },
  {
    attackId: "T1003",
    controls: ["PCI-11.4.2", "SOC-CC6.1", "ISO-A.8.8"],
    rationale:
      "Credential-access techniques test whether credential material is protected at rest and in memory; findings become technical vulnerabilities.",
  },
  {
    attackId: "T1552.001",
    controls: ["PCI-11.4.2", "SOC-CC6.1", "ISO-A.8.8"],
    rationale:
      "Credentials in files test secret-management hygiene — a logical-access failure and a technical vulnerability at once.",
  },
  {
    attackId: "T1556",
    controls: ["PCI-11.4.2", "SOC-CC6.1"],
    rationale:
      "Attacks on the authentication process itself (e.g. MFA/adversary-in-the-middle paths) directly test logical access security.",
  },
  {
    attackId: "T1021",
    controls: ["PCI-11.4.2", "SOC-CC6.1"],
    rationale:
      "Abuse of remote services (RDP/SMB/WinRM) from an internal vantage tests network-level access controls and segmentation of management planes.",
  },
  {
    attackId: "T1021.004",
    controls: ["PCI-11.4.2", "SOC-CC6.1"],
    rationale:
      "SSH as the remote-service vector: tests SSH hardening, key management, and authorized-access enforcement on Linux estates.",
  },
  {
    attackId: "T1047",
    controls: ["PCI-11.4.2", "SOC-CC6.1"],
    rationale:
      "WMI-based execution/lateral movement tests whether Windows management interfaces are restricted to authorized administrators.",
  },
  {
    attackId: "T1210",
    controls: ["PCI-11.4.2", "PCI-11.4.4", "SOC-CC6.6", "ISO-A.8.8"],
    rationale:
      "Exploiting remote services validates patching and exposure of network services; exploited findings require remediation and retest.",
  },
  {
    attackId: "T1068",
    controls: ["PCI-11.4.2", "PCI-11.4.4", "SOC-CC6.1", "ISO-A.8.8"],
    rationale:
      "Privilege-escalation exploits test the effectiveness of privilege boundaries; successful escalation is a high-severity technical vulnerability.",
  },
  {
    attackId: "T1548",
    controls: ["PCI-11.4.2", "PCI-11.4.4", "SOC-CC6.1"],
    rationale:
      "Abuse of elevation-control mechanisms (sudo/SUID/UAC bypass paths) tests that elevation is restricted to authorized paths.",
  },
  {
    attackId: "T1574",
    controls: ["PCI-11.4.2", "PCI-11.4.4", "SOC-CC6.1"],
    rationale:
      "Hijacking execution flow (DLL/service-binary planting paths) tests integrity of trusted execution paths and least-privilege file permissions.",
  },
  {
    attackId: "T1053",
    controls: ["PCI-11.4.2", "SOC-CC7.1", "ISO-A.8.8"],
    rationale:
      "Scheduled-task/cron persistence findings test whether unauthorized persistence is detectable — configuration-drift and monitoring evidence.",
  },
  {
    attackId: "T1547",
    controls: ["PCI-11.4.2", "SOC-CC7.1", "ISO-A.8.8"],
    rationale:
      "Boot/logon autostart persistence findings test endpoint configuration integrity and the ability to detect unauthorized persistence.",
  },
  {
    attackId: "T1505.003",
    controls: ["PCI-11.4.4", "SOC-CC6.6", "ISO-A.8.8"],
    rationale:
      "Web-shell deployment paths on public servers test external-attack-surface integrity; any viable path is a critical finding requiring remediation + retest.",
  },
  {
    attackId: "T1027",
    controls: ["PCI-11.4.4", "SOC-CC7.1", "ISO-A.8.8"],
    rationale:
      "Obfuscated/encoded payload handling tests whether defenses detect concealed malicious content — a detection-procedure input.",
  },
  {
    attackId: "T1499",
    controls: ["PCI-11.4.3", "SOC-CC6.6"],
    rationale:
      "Rate-limiter shape mapping validates the target's abuse protections against resource-exhaustion from external sources. The runner never performs actual denial of service; the protection's existence is the evidence.",
  },
  {
    attackId: "T1595.002",
    controls: ["PCI-11.4.1", "SOC-CC7.1", "ISO-A.8.8"],
    rationale:
      "Active vulnerability scanning is the methodology's discovery engine and the primary input to technical-vulnerability management.",
  },
  {
    attackId: "T1595.003",
    controls: ["PCI-11.4.1", "PCI-11.4.3"],
    rationale:
      "Hidden-path enumeration is a documented external-testing technique per the methodology — discovering unlisted attack surface.",
  },
  {
    attackId: "T1592.002",
    controls: ["PCI-11.4.1"],
    rationale:
      "Software fingerprinting is the reconnaissance the documented methodology prescribes before targeted testing.",
  },
  {
    attackId: "T1593.002",
    controls: ["PCI-11.4.1"],
    rationale:
      "DNS-based target discovery is documented-methodology reconnaissance defining the external test surface.",
  },
  {
    attackId: "T1590.002",
    controls: ["PCI-11.4.1"],
    rationale:
      "DNS posture review is documented-methodology reconnaissance (external attack-surface definition).",
  },
  {
    attackId: "T1518",
    controls: ["PCI-11.4.1"],
    rationale:
      "Software discovery on hosts is documented-methodology reconnaissance for the internal test vantage.",
  },
  {
    attackId: "T1018",
    controls: ["PCI-11.4.1", "PCI-11.4.2"],
    rationale:
      "Remote system discovery maps the internal network — the reconnaissance phase of internal penetration testing.",
  },
  {
    attackId: "T1033",
    controls: ["PCI-11.4.1", "PCI-11.4.2"],
    rationale:
      "System owner/user discovery is internal-test reconnaissance identifying high-value targets for privilege-path analysis.",
  },
  {
    attackId: "T1082",
    controls: ["PCI-11.4.1"],
    rationale:
      "System information discovery is documented-methodology reconnaissance characterizing each tested host.",
  },
  {
    attackId: "T1083",
    controls: ["PCI-11.4.1"],
    rationale:
      "File and directory discovery is documented-methodology reconnaissance for data-exposure assessment.",
  },
  {
    attackId: "T1087",
    controls: ["PCI-11.4.1", "PCI-11.4.2", "SOC-CC6.1"],
    rationale:
      "Account discovery enumerates the identity surface — input to access-control testing and logical-access evidence.",
  },
  {
    attackId: "T1135",
    controls: ["PCI-11.4.2", "SOC-CC6.1"],
    rationale:
      "Network share discovery tests whether file shares are exposed beyond authorized users — access-control evidence.",
  },
];

/** Control ids for one technique. Empty array = honestly unmapped (let the test fail loudly). */
export function controlsForTechnique(attackId: string): string[] {
  return TECHNIQUE_CONTROL_MAP.find((m) => m.attackId === attackId)?.controls ?? [];
}

/** Technique ids from the battery with no control mapping — must always be []. */
export function unmappedBatteryTechniques(): string[] {
  const ids = allBatteryAttackIds();
  return ids.filter((id) => controlsForTechnique(id).length === 0);
}

/** Every mapped control id must exist in the catalog — returns the offenders. */
export function invalidMappedControlIds(): string[] {
  const bad: string[] = [];
  for (const m of TECHNIQUE_CONTROL_MAP) {
    for (const c of m.controls) {
      if (!lookupControl(c) && !bad.includes(c)) bad.push(c);
    }
  }
  return bad;
}
