/**
 * LDAP-based Active Directory enumeration — batteries WS-038 (BloodHound-style
 * attack-path analysis) and WS-043 (AD CS misconfiguration) — v0.10.0.
 *
 * LIBRARY CHOICE: `ldapts` (v9, actively maintained, TypeScript-native) —
 * the professional successor to the unmaintained ldapjs. Simple bind as the
 * authorized test account; every query is a READ. Nothing is written to the
 * directory, ever.
 *
 * SharpHound-equivalent dataset collected read-only:
 *   users (SPNs, account flags), groups (+ ranged member retrieval for large
 *   groups), computers (delegation flags), trusts, OUs (+ gPLink), GPOs,
 *   and nTSecurityDescriptors parsed from BINARY form (see parseSecurityDescriptor
 *   — no Windows API needed) to find dangerous grants (GenericAll, WriteDacl,
 *   WriteOwner) held by non-Tier-0 principals.
 *
 * Attack paths (WS-038) are COMPUTED OFFLINE on the collected graph —
 * shortest paths to Tier-0 via group nesting, dangerous ACL grants, and
 * delegation edges. No path is executed, no session hijacked, no edge
 * traversed against live systems.
 *
 * AD CS (WS-043) is DETECTION ONLY via LDAP: certificate template objects
 * carry every flag needed to identify ESC1/ESC2/ESC4-style misconfigurations.
 * No certificate is ever requested or enrolled.
 */


/**
 * LDAP-based Active Directory enumeration (see above) — split into submodules
 * (public export surface unchanged):
 *  - ad/transport.ts    — injectable ldapts transport
 *  - ad/security.ts     — binary security-descriptor + SID helpers
 *  - ad/attack-paths.ts — offline Tier-0 privilege-path computation (WS-038)
 *  - ad/adcs.ts         — AD CS template misconfiguration detection (WS-043)
 *  - ad/enumerate.ts    — the read-only LDAP enumeration driver
 */
export { createAdTransport, type AdTransport, type AdEntry } from "./ad/transport.js";
export {
  findDangerousAces,
  isLowPrivSid,
  isTier0Sid,
  type DangerousAce,
} from "./ad/security.js";
export { computeAttackPaths } from "./ad/attack-paths.js";
export { analyzeTemplate, type AdcsTemplateFinding } from "./ad/adcs.js";
export {
  adEnumerate,
  type AdOperation,
  type AdEnumArgs,
  type AdEnumResult,
} from "./ad/enumerate.js";
