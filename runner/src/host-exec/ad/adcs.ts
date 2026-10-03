// AD CS template misconfiguration detection (MS-CSRA) — detection only.

import type { AdEntry } from "./transport.js";
import { findDangerousAces, isLowPrivSid } from "./security.js";

// AD CS constants (MS-CSRA)
const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
const EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
const EKU_ANY_PURPOSE = "2.5.29.37.0";

export interface AdcsTemplateFinding {
  template: string;
  esc: "ESC1" | "ESC2" | "ESC4";
  detail: string;
}

/** Flag ESC1/ESC2/ESC4-style misconfigurations on one template entry. Pure function. */
export function analyzeTemplate(e: AdEntry, domainSid: string): AdcsTemplateFinding[] {
  const out: AdcsTemplateFinding[] = [];
  const cn = e.attrs["cn"]?.[0] ?? e.dn;
  const nameFlag = parseInt(e.attrs["msPKI-Certificate-Name-Flag"]?.[0] ?? "0", 10) || 0;
  const ekus = e.attrs["pKIExtendedKeyUsage"] ?? [];
  const hasClientAuth = ekus.includes(EKU_CLIENT_AUTH);
  const hasAnyPurpose = ekus.includes(EKU_ANY_PURPOSE);
  const sdB64 = e.attrs["nTSecurityDescriptor"]?.[0] ?? "";
  const aces = sdB64 ? findDangerousAces(e.dn, sdB64) : [];
  const lowPrivEnroll = aces.some(
    (a) => isLowPrivSid(a.granteeSid, domainSid) && (a.rights.includes("Enroll") || a.rights.includes("GenericAll")),
  );
  const lowPrivWrite = aces.some(
    (a) => isLowPrivSid(a.granteeSid, domainSid) && (a.rights.includes("WriteDacl") || a.rights.includes("WriteOwner") || a.rights.includes("GenericAll")),
  );
  if (nameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT && hasClientAuth && lowPrivEnroll) {
    out.push({
      template: cn,
      esc: "ESC1",
      detail: "ENROLLEE_SUPPLIES_SUBJECT + Client Authentication EKU + low-privilege enrollment — arbitrary SAN impersonation path.",
    });
  }
  if (hasAnyPurpose && lowPrivEnroll) {
    out.push({
      template: cn,
      esc: "ESC2",
      detail: "Any Purpose EKU + low-privilege enrollment — certificate usable as any EKU including client auth.",
    });
  }
  if (lowPrivWrite) {
    out.push({
      template: cn,
      esc: "ESC4",
      detail: "Low-privilege principal holds WriteDacl/WriteOwner/GenericAll on the template — template reconfiguration path.",
    });
  }
  return out;
}
