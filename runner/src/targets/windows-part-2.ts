/**
 * WINDOWS battery — part 2 of 5 (v0.19.0 refactor split).
 * Starts at section: AUTH ATTACKS — AUTHORIZED TEST ACCOUNTS ONLY
 *
 * Pure data split of windows.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by windows.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_HUMAN_OPERATOR, NEEDS_KERBEROS_TICKET, NEEDS_MSFRPCD } from "./types.js";

export const WINDOWS_PART_2: TargetBatteryItem[] = [
  // ============================================ AUTH ATTACKS — AUTHORIZED TEST ACCOUNTS ONLY
  {
    id: "WS-019",
    category: "functionality", name: "RDP credential validation with test account",
    brief: "Authorized test account over RDP — authentication succeeds, sessions logged?",
    owasp: "WSTG-ATHN-02", attackId: "T1078",
    what: "Authenticate over RDP with the client-PROVIDED authorized test account only and verify session establishment, group membership applied, and that the attempt is fully logged by the host. Executes TODAY via the runner's rdp_auth tool: X.224 negotiation requesting NLA, TLS upgrade, CredSSP/NTLMv2 handshake — the server's affirmative handshake completion IS the credential validation, after which the connection is closed immediately. No desktop session is established or driven (headless runner). If the server does not offer NLA, no validation is attempted — the absent NLA is the finding. Never guessed credentials, never a second account — one authorized credential, one handshake, then disconnect.",
    blackNote: "In black mode: single attempt, no reconnection storms; avoid tripping account-lockout-adjacent alerts.",
  },
  {
    id: "WS-020", category: "functionality", name: "SMB credential validation with test account",
    brief: "Authorized test account over SMB — session setup works, audited?",
    owasp: "WSTG-ATHN-02", attackId: "T1078",
    what: "Perform SMB session setup with the client-PROVIDED authorized test account only and verify the granted share access matches the account's intended rights. Single session; no credential material beyond the provided test account is used.",
  },
  {
    id: "WS-021", category: "functionality", name: "WinRM credential validation with test account",
    brief: "Authorized test account over WinRM — which auth schemes actually accept it?",
    owasp: "WSTG-ATHN-02", attackId: "T1078",
    what: "Open a WinRM shell/session with the client-PROVIDED authorized test account only, noting which advertised auth schemes (Negotiate/Kerberos/NTLM) accept it and whether the session is logged. Session closed immediately; read-only commands only.",
  },
  {
    id: "WS-022", category: "logic", name: "NTLM relay EXPOSURE audit",
    brief: "Can in-scope hosts be coerced to authenticate elsewhere — relayable or not?",
    owasp: "CIS-v8-4.4",
    what: "Audit exposure to NTLM relay: SMB signing status, LDAP signing and channel binding, WebDAV exposure, and PetitPotam-style coercion surfaces — reporting whether relay is theoretically possible against in-scope hosts. ANALYSIS AND CONFIGURATION AUDIT ONLY: no relay execution, no coerced authentication, no credential capture.",
    blackNote: "In black mode this stays a passive config audit — relay execution is out of scope regardless of mode.",
  },
  {
    id: "WS-023",
    category: "logic", name: "Pass-the-hash exposure with test-account material",
    brief: "NTLM hash reuse of the test account — does the environment accept it?",
    owasp: "WSTG-ATHN-02", attackId: "T1078",
    what: "Using ONLY the client-PROVIDED authorized test account's own NTLM material (its own NT hash, REDTEAM_SMB_NTHASH), test whether the hash authenticates to in-scope SMB services. Executes TODAY via the runner's smb_pth tool: raw-socket SMB2 NEGOTIATE + SESSION_SETUP carrying an NTLMv2 AUTHENTICATE keyed by the hash (no password anywhere in the flow); STATUS_SUCCESS = PtH works, LOGON_FAILURE = rejected. Session logged off immediately on success; no share touched. This audits PtH exposure of the test credential itself — never another principal's material, never dumped hashes.",
  },
  {
    id: "WS-024", category: "logic", name: "Kerberoasting exposure audit",
    brief: "Service accounts with SPNs and crackable crypto — kerberoastable?",
    owasp: "CIS-v8-4.4",
    what: "Enumerate domain accounts with servicePrincipalNames, their supported encryption types, and whether pre-auth is required, then assess which service accounts are roastable in principle. Enumeration and crypto-policy audit ONLY — no TGS requests issued, no offline cracking; the exposure assessment is the finding. No catalog ATT&CK ID exists for Kerberoasting, so none is assigned.",
  },
  {
    id: "WS-025", category: "logic", name: "AS-REP roasting exposure audit",
    brief: "Accounts with pre-auth disabled — AS-REP roastable in principle?",
    owasp: "CIS-v8-4.4",
    what: "Enumerate domain accounts with Kerberos pre-authentication disabled and assess AS-REP roastability from that flag alone. Enumeration ONLY — no AS-REQ issued, no cracking; the misconfiguration finding is the deliverable. No catalog ATT&CK ID exists for AS-REP roasting, so none is assigned.",
  },
  {
    id: "WS-026", category: "functionality", name: "Lockout and brute-force protection audit",
    brief: "Deliberate failures against the test account — lockout policy working?",
    owasp: "WSTG-ATHN-03", attackId: "T1110",
    what: "Using ONLY the authorized test account against its own logon endpoints, issue a small, bounded number of deliberate bad-password attempts and record the lockout threshold, observation window, and whether the failures are logged with source. Stops at the first lockout signal; never continued past it. Never brute-forced in the general sense.",
    blackNote: "In black mode this item is EXCLUDED by default — any deliberate failed-auth activity risks detection and lockout side effects.",
  },
  {
    id: "WS-027", category: "validation", name: "NTLMv1 and LM compatibility audit",
    brief: "Legacy NTLM/LM still accepted — downgrade exposure on the wire?",
    owasp: "CIS-v8-4.4",
    what: "Read the LMCompatibilityLevel and related NTLM hardening settings on in-scope hosts and the domain policy to determine whether NTLMv1 or LM responses are still accepted. Configuration audit only; no downgrade attempts, no hash capture.",
  },
  {
    id: "WS-028", category: "validation", name: "SMB signing requirement audit",
    brief: "SMB signing required or merely negotiated — unsigned sessions allowed?",
    owasp: "CIS-v8-4.4",
    what: "Check whether SMB signing is required (not just negotiated) on in-scope hosts and the domain policy, since unsigned SMB is the enabler for relay. Registry/policy read only; no unsigned session is established.",
  },
  {
    id: "WS-029", category: "validation", name: "LDAP signing and channel binding audit",
    brief: "LDAP signing/channel binding enforced — or merely negotiated?",
    owasp: "CIS-v8-4.4",
    what: "Audit the domain controllers' LDAP signing and channel-binding requirements and whether they are enforced or merely negotiated. Configuration read only; no unsigned binds attempted.",
  },
  {
    id: "WS-030", category: "validation", name: "LAPS deployment and rotation audit",
    brief: "Local admin passwords randomized and rotated — or shared and static?",
    owasp: "CIS-v8-4.4",
    what: "Verify whether LAPS (or Windows LAPS) is deployed on in-scope hosts: randomized per-host local administrator passwords, who can read them in AD, and the rotation cadence. Attribute reads via the authorized test account; no password retrieval beyond verifying the attributes exist.",
  },
  // ============================================ ACTIVE DIRECTORY
  {
    id: "WS-031", category: "validation", name: "Domain and forest enumeration",
    brief: "Domains, trusts, naming contexts — full AD topology picture from inside.",
    owasp: "CIS-v8-4.4", attackId: "T1018",
    what: "Enumerate the forest, domains, domain controllers, and naming contexts via LDAP reads as the authorized test account, building the topology picture an attacker would start from. Read-only LDAP queries; no writes, no replication traffic.",
  },
  {
    id: "WS-032", category: "validation", name: "Trust mapping",
    brief: "All domain trusts mapped — direction, transitivity, SID filtering state.",
    owasp: "CIS-v8-4.4", attackId: "T1018",
    what: "Enumerate every trust (intra-forest, external, forest) with direction, transitivity, and SID-filtering/quarantine state, and flag trusts that widen the in-scope attack surface (e.g. trusting external domains). Read-only trust enumeration; no trust authentication attempted.",
  },
  {
    id: "WS-033", category: "validation", name: "Unconstrained delegation misconfig",
    brief: "Computers/users with unconstrained delegation — TGT-harvest targets?",
    owasp: "CIS-v8-4.4",
    what: "Enumerate accounts with TRUSTED_FOR_DELEGATION set and assess exposure: any compromised such host would cache forwardable TGTs. Finding-level audit only — no delegation abuse, no ticket harvesting, no impersonation.",
  },
  {
    id: "WS-034", category: "validation", name: "Constrained and resource-based constrained delegation",
    brief: "Allowed-to-delegate-to lists and RBCD grants — privilege paths present?",
    owasp: "CIS-v8-4.4",
    what: "Enumerate constrained delegation (msDS-AllowedToDelegateTo) and resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) grants and assess which grant a privilege path an attacker could walk. Enumeration only; no ticket forging, no S4U abuse.",
  },
  {
    id: "WS-035", category: "logic", name: "Writable GPO abuse paths",
    brief: "GPOs the test account can edit — each is a domain-wide foothold path.",
    owasp: "CIS-v8-4.4",
    what: "Determine which Group Policy Objects the authorized test account (or any low-privilege principal in scope) can write to via SYSVOL/AD ACL reads, and describe the abuse path each writable GPO represents (logon scripts, preferences, software install). ACL audit ONLY — no GPO is modified, nothing is deployed.",
  },
  {
    id: "WS-036", category: "logic", name: "GPP cpassword exposure",
    brief: "Legacy Group Policy Preferences passwords still sitting in SYSVOL?",
    owasp: "CIS-v8-4.4", attackId: "T1552.001",
    what: "Search SYSVOL policy XML files for cpassword attributes left from legacy Group Policy Preferences and verify whether the AES key is still publicly known (it is) — but do NOT decrypt anything. Presence of cpassword blobs is the finding; no decryption, no credential use.",
  },
  {
    id: "WS-037", category: "logic", name: "DACL misconfig audit — WriteDacl, GenericAll, WriteOwner",
    brief: "Dangerous ACL grants on users, groups, computers — takeover primitives.",
    owasp: "CIS-v8-4.4",
    what: "Audit security descriptors on in-scope AD objects for dangerous grants held by low-privilege principals: GenericAll, WriteDacl, WriteOwner, ForceChangePassword, AddSelf/AddMembers on groups, DCSync-extended-right equivalents on the domain. Read-only ACL analysis; no ACL is modified and no grant is exercised.",
  },
  {
    id: "WS-038",
    category: "validation", name: "BloodHound-style attack-path analysis",
    brief: "Shortest privilege paths to Domain Admins — computed, never walked.",
    owasp: "CIS-v8-4.4",
    what: "Collect the AD object graph (users, groups, computers, sessions, ACLs) via read-only LDAP as the authorized test account and compute shortest privilege-escalation paths to Tier-0, BloodHound-style, using offline graph analysis. Executes TODAY via the runner's ad_enum tool (ldapts): users/groups/computers/trusts/OUs/GPOs plus binary security-descriptor parsing for dangerous grants, BFS shortest paths computed offline. COMPUTED ONLY — no path is executed, no session hijacked, no edge traversed against live systems.",
  },
  {
    id: "WS-039", category: "functionality", name: "Unquoted service paths",
    brief: "Services with unquoted binpaths in writable directories — hijackable?",
    owasp: "CIS-v8-4.4", attackId: "T1574",
    what: "Find installed services whose ImagePath contains spaces and is not quoted, and check whether any path segment is writable by a low-privilege principal. PROOF uses a benign canary file name only (e.g. a canary placed conceptually, never an executable payload); nothing is planted, nothing is executed — the writable-segment finding is the deliverable.",
  },
  {
    id: "WS-040", category: "functionality", name: "Writable service binaries",
    brief: "Service executables writable by low-priv — replacement path exists?",
    owasp: "CIS-v8-4.4", attackId: "T1574",
    what: "Check the ACLs on service binary files and their parent directories for writability by low-privilege principals. Finding-level only: report the writable binary and the owning service, but never write, replace, or touch the binary — proof is the ACL, not a planted file.",
  },
  {
    id: "WS-041", category: "validation", name: "AD user enumeration and hygiene flags",
    brief: "Password-never-expires, stale, and privileged users — hygiene picture.",
    owasp: "CIS-v8-4.4", attackId: "T1087",
    what: "Enumerate domain users with hygiene flags: password never expires, stale logons, unconstrained adminCount, disabled-but-present accounts. Read-only LDAP attribute reads; no password changes, no account touches.",
  },
  {
    id: "WS-042", category: "validation", name: "Sensitive group membership audit",
    brief: "Who sits in Domain Admins, Enterprise Admins, Backup Operators — justified?",
    owasp: "CIS-v8-4.4", attackId: "T1087",
    what: "Enumerate membership of Tier-0 and sensitive groups (Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, Account Operators, DnsAdmins) and flag unexpected members. Read-only membership reads; no membership changes.",
  },
  {
    id: "WS-043",
    category: "logic", name: "AD CS misconfiguration exposure",
    brief: "Certificate templates with ESC1–ESC8-style flaws — cert-based takeover?",
    owasp: "CIS-v8-4.4", attackId: "T1190",
    what: "Audit AD Certificate Services templates and CA configuration for known misconfiguration classes (client-auth EKU with no manager approval, SAN-supplied templates, overly permissive enrollment rights). Executes TODAY via the runner's ad_enum tool (adcs operation): read-only LDAP reads of certificate template objects, flagging ESC1/ESC2/ESC4-style conditions from template flags, EKUs, and enrollment ACLs. Template/policy audit ONLY — no certificate is requested or enrolled; the misconfig finding is the deliverable.",
  },
  {
    id: "WS-044", category: "logic", name: "Print Spooler exposure audit",
    brief: "Spooler running on DCs/servers — coercion and PrintNightmare surface?",
    owasp: "CIS-v8-4.4",
    what: "Check whether the Print Spooler service is running on domain controllers and in-scope servers and whether the hardened driver-install policies are set. Service-state and policy audit ONLY — no driver installation, no spooler RPC abuse, no coercion execution.",
  },
  {
    id: "WS-045", category: "logic", name: "Machine account quota audit",
    brief: "MAQ > 0 — any domain user can join machines (RBCD prerequisite)?",
    owasp: "CIS-v8-4.4",
    what: "Read the ms-DS-MachineAccountQuota attribute and assess whether ordinary domain users can create machine accounts — the standard prerequisite for resource-based constrained delegation attacks. Attribute read only; no machine account is created.",
  },
  {
    id: "WS-046", category: "validation", name: "Kerberos policy audit",
    brief: "Ticket lifetimes, clock skew, AES enforcement — Kerberos hardening state.",
    owasp: "CIS-v8-4.4",
    what: "Read the domain Kerberos policy: maximum ticket lifetime, renewal lifetime, clock skew tolerance, and whether AES is enforced over RC4. Policy reads only; no ticket requests, no forging.",
  },
];
