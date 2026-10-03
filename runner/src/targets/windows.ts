/**
 * Windows target profile — host + Active Directory.
 *
 * EXHAUSTIVE battery (v0.8.0): surface × technique. Surfaces: network
 * recon (SMB/NetBIOS/RDP/WinRM/SQL/SNMP/DNS/host web), auth attacks
 * (authorized test accounts ONLY — T1078), Active Directory (trusts,
 * delegation, GPOs, DACLs, AD CS, attack paths), privilege escalation,
 * lateral movement (authorized scope, fully logged), credential-access
 * exposure (audited — nothing exfiltrated beyond evidence), persistence
 * FINDINGS (reported, NEVER planted), EDR/AV awareness, and host
 * hardening posture.
 *
 * Non-destructive always: read-only enumeration preferred; no service
 * crashing; no ransomware-style behavior; persistence mechanisms REPORTED
 * as findings, never planted; hijack proofs use benign canary files only.
 *
 * Execution model (v0.10.0): the runner's host-exec tools execute this
 * battery — `smb_exec` (share reachability + listing), `winrm_exec`
 * (PowerShell/cmd commands), `winrm_probe` (WS-010 listener/auth-scheme
 * probe), `rdp_auth` (WS-019 NLA credential validation), `smb_pth` (WS-023
 * pass-the-hash with NTLMv2), `ad_enum` (WS-038 attack-path computation +
 * WS-043 AD CS template audit, both read-only LDAP), `krb_ptt` (WS-064
 * ticket replay via MIT krb5 tools), and `rdp_shadow_prep` (WS-065 prepares
 * the human handoff — session IDs, exact command, consent checklist).
 * Two items keep honest prerequisites in `needs` (NOT plan-only — they
 * execute when the prerequisite is met): WS-064 needs kerberos ticket
 * material (ccache/kirbi via env, or kinit credentials); WS-065 needs a
 * human operator for the shadowing act itself (preparation is automated).
 * SMB share enumeration note: the library has no NetShareEnum, so
 * list_shares is reachability probing of well-known + recon-supplied names.
 */

import type { TargetBatteryItem, TargetProfile } from "./types.js";
import { NEEDS_HUMAN_OPERATOR, NEEDS_KERBEROS_TICKET, NEEDS_MSFRPCD } from "./types.js";

const WINDOWS_BATTERY: TargetBatteryItem[] = [
  // ============================================ RECON — SMB / SHARES
  {
    id: "WS-001", category: "validation", name: "SMB banner and dialect fingerprint",
    brief: "SMB dialect negotiation and banner capture — OS and server version exposure.",
    owasp: "CIS-v8-4.4", attackId: "T1018",
    what: "Negotiate SMB dialects against TCP 445 and record the returned dialect, server OS, and build string without touching shares or attempting authentication. Read-only, no service interaction beyond the banner handshake.",
  },
  {
    id: "WS-002", category: "validation", name: "Null-session and anonymous SMB enumeration",
    brief: "Null session setup — is anonymous enumeration possible on this host?",
    owasp: "CIS-v8-4.4",
    what: "Attempt anonymous (null) SMB session setup and, if accepted, enumerate what the session reveals: share lists, users, sessions, policies. Read-only; an accepted null session itself is the finding — no writes, no share access.",
  },
  {
    id: "WS-003", category: "validation", name: "Share enumeration and permission mapping",
    brief: "Visible shares mapped with their effective access — over-sharing exposed?",
    owasp: "CIS-v8-4.4", attackId: "T1135",
    what: "List all SMB shares exposed on the host and map the effective permissions per share from an unauthenticated and then an authorized-test-account viewpoint: world-writable shares, everyone-read on sensitive data, hidden C$/ADMIN$ exposure. Read-only enumeration; no file writes.",
  },
  {
    id: "WS-004", category: "validation", name: "NetBIOS and NBNS name disclosure",
    brief: "NBNS name table queries — hostname, domain, and logged-on users leaked?",
    owasp: "CIS-v8-4.4", attackId: "T1018",
    what: "Query the host's NetBIOS name service (UDP 137) and record the name table: computer name, domain/workgroup, currently logged-on usernames, and master-browser role. Purely passive query; no registration or spoofing.",
  },
  {
    id: "WS-005", category: "validation", name: "User, group, and session enumeration",
    brief: "Domain/local users, groups, and live sessions enumerable via RPC?",
    owasp: "CIS-v8-4.4", attackId: "T1033",
    what: "Enumerate users, local groups, and active logon sessions via SAMR/LSARPC as an anonymous or authorized-test-account session. Correlate group membership against sensitive groups (Administrators, RDP Users, Backup Operators). Read-only; no account changes.",
  },
  {
    id: "WS-006", category: "validation", name: "OS version and patch level fingerprint",
    brief: "Exact build and patch level — feeding the kernel CVE correlation.",
    owasp: "CIS-v8-4.4", attackId: "T1082",
    what: "Determine the exact OS version and patch/build level via SMB negotiation, RDP handshake data, and any exposed version banners, then check the build against the known missing-critical-patch window. Fingerprint only; no exploitation.",
  },
  {
    id: "WS-007", category: "validation", name: "Installed software inventory for CVE correlation",
    brief: "Software inventory — installed apps with known CVEs present?",
    owasp: "CIS-v8-4.4", attackId: "T1518",
    what: "Inventory installed software and versions (registry uninstall keys, installed program listings) via the authorized test account and correlate against known CVEs for privilege escalation or RCE. Read-only inventory; correlation is local analysis only.",
  },
  {
    id: "WS-008", category: "validation", name: "Windows service enumeration",
    brief: "Full service list with binpaths and states — misconfig hunting ground.",
    owasp: "CIS-v8-4.4",
    what: "Enumerate all Windows services with their display names, binpaths, start types, states, and service account identities via the Service Control Manager using the authorized test account. Read-only; feeds the unquoted-path and writable-binary checks downstream.",
  },
  // ============================================ RECON — RDP / WINRM / OTHER
  {
    id: "WS-009", category: "validation", name: "RDP banner and listener fingerprint",
    brief: "RDP handshake capture — NLA required, TLS version, protocol support.",
    owasp: "CIS-v8-4.4", attackId: "T1595.002",
    what: "Perform an RDP connection negotiation on TCP 3389 and record the listener fingerprint: whether Network Level Authentication is required, the TLS version offered, RDP security-layer choice, and protocol flags — without attempting any authentication. Handshake only.",
  },
  {
    id: "WS-010",
    category: "validation", name: "WinRM availability and auth-scheme exposure",
    brief: "WinRM on 5985/5986 reachable — which auth schemes does it advertise?",
    owasp: "CIS-v8-4.4", attackId: "T1021",
    what: "Probe TCP 5985/5986 for WinRM listeners and record the advertised authentication schemes (Negotiate, Kerberos, NTLM, CredSSP, Basic) and TLS posture on 5986. Executes TODAY via the runner's winrm_probe tool: unauthenticated POST to /wsman, parsing the 401 WWW-Authenticate headers. Presence and scheme disclosure only; no session creation.",
  },
  {
    id: "WS-011", category: "validation", name: "HTTP banner grab on host web ports",
    brief: "Banner grabs on 80/443/8000/8080/etc — server, IIS version, tech stack.",
    owasp: "CIS-v8-4.4", attackId: "T1595.002",
    what: "Fetch the root document on each host web port and record Server headers, IIS/ASP.NET version tokens, X-Powered-By disclosures, and any framework banners. Executes TODAY via the runner's existing http_probe — plain GETs, no auth attempts, no crawling.",
  },
  {
    id: "WS-012", category: "validation", name: "TLS certificate inspection on host web ports",
    brief: "TLS cert on host web ports — weak cipher, expired, self-signed, SAN leaks?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Complete TLS handshakes against each host HTTPS port and record the certificate chain, expiry, signature algorithm, negotiated cipher suites, and subjectAltNames for internal-hostname leakage. Executes TODAY via http_probe TLS inspection — handshake only, no exploitation.",
  },
  {
    id: "WS-013", category: "validation", name: "Security headers audit on host web ports",
    brief: "Missing HSTS, CSP, X-Frame-Options on host web services — audit only.",
    owasp: "CIS-v8-4.4",
    what: "Record the response security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) on each host web port and flag missing or misconfigured ones. Executes TODAY via http_probe — read-only header inspection on in-scope host web ports only.",
  },
  {
    id: "WS-014", category: "validation", name: "Host web admin interface presence",
    brief: "IIS defaults, ECP, WSUS, printer panels — exposed admin pages on host ports?",
    owasp: "WSTG-INFO-02", attackId: "T1595.002",
    what: "Fetch well-known host admin paths (IIS default page, Exchange ECP, WSUS selfupdate, print-server panels) via plain HTTP GETs and record which exist and which are authentication-gated. Executes TODAY via http_probe — presence detection only, no login attempts.",
  },
  {
    id: "WS-015", category: "validation", name: "SQL Server and Browser service exposure",
    brief: "MSSQL on 1433, SQL Browser on UDP 1434 — instances and versions exposed?",
    owasp: "CIS-v8-4.4", attackId: "T1595.002",
    what: "Probe for SQL Server listeners and query the SQL Browser service for instance names, versions, and cluster state. Report unauthenticated exposure; no authentication attempts against SQL, no queries.",
  },
  {
    id: "WS-016", category: "validation", name: "SNMP community exposure",
    brief: "SNMP responders with default or guessable communities — info leak?",
    owasp: "CIS-v8-4.4", attackId: "T1595.002",
    what: "Query SNMP agents with default community strings only (public/private as misconfiguration checks, not a spray campaign) and record what system information leaks: hostname, uptime, interfaces, software. Read-only GETs; no SET operations ever.",
  },
  {
    id: "WS-017", category: "validation", name: "AD SRV record and DNS locator enumeration",
    brief: "Domain locator records — DCs, GCs, Kerberos servers enumerable from DNS?",
    owasp: "CIS-v8-4.4", attackId: "T1590.002",
    what: "Query _ldap, _kerberos, _gc, and _kpasswd SRV records for the in-scope domain to enumerate domain controllers and their roles. Passive DNS queries only; no zone writes, no DC contact.",
  },
  {
    id: "WS-018", category: "validation", name: "DNS zone transfer exposure",
    brief: "AXFR on in-scope zones — full zone contents granted to unauthenticated askers?",
    owasp: "CIS-v8-4.4", attackId: "T1593.002",
    what: "Request AXFR zone transfers for the in-scope domain zones and record which name servers honor them. Read-only request; a granted transfer is the finding. No enumeration beyond the authorized scope.",
  },
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
  // ============================================ PRIVILEGE ESCALATION
  {
    id: "WS-047", category: "functionality", name: "Misconfigured service audit",
    brief: "Service registry/binpath writable by low-priv — config-level privesc path?",
    owasp: "CIS-v8-4.4", attackId: "T1548",
    what: "Audit service configurations for low-privilege writability: service registry keys, binpath values, and service-change rights held by non-admins. ACL/config audit ONLY — no service is reconfigured, no binpath changed; the writable-config finding is the deliverable.",
  },
  {
    id: "WS-048", category: "logic", name: "AlwaysInstallElevated check",
    brief: "MSI installs run as SYSTEM for everyone — installer-based privesc open?",
    owasp: "CIS-v8-4.4", attackId: "T1548",
    what: "Check both AlwaysInstallElevated registry values (HKLM and HKCU policy keys) to determine whether any user can install MSI packages with SYSTEM privileges. Registry reads only; no MSI is crafted or installed — the policy finding is the deliverable.",
  },
  {
    id: "WS-049", category: "logic", name: "Token privilege exposure audit",
    brief: "SeImpersonate/SeAssignPrimaryToken held by service accounts — potato-class?",
    owasp: "CIS-v8-4.4",
    what: "Enumerate which principals hold dangerous token privileges (SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, SeTcbPrivilege) and assess potato-class impersonation exposure in principle. Privilege enumeration ONLY — no token theft, no impersonation executed.",
  },
  {
    id: "WS-050", category: "functionality", name: "Scheduled-task abuse — test-account-owned tasks",
    brief: "Tasks owned/runnable by the test account — action or binpath writable?",
    owasp: "CIS-v8-4.4", attackId: "T1053",
    what: "Enumerate scheduled tasks visible to the authorized test account, and for tasks the test account owns or can modify, audit the task action, binary, and arguments for writability. Audit ONLY on test-account-owned tasks — no task is created, modified, or triggered; the writable-action finding is the deliverable.",
  },
  {
    id: "WS-051", category: "functionality", name: "DLL hijacking with benign canary",
    brief: "Missing DLLs in app search order — canary proves the hijack path?",
    owasp: "CIS-v8-4.4", attackId: "T1574",
    what: "Identify applications loading DLLs by relative name where an earlier search-order directory is writable by a low-privilege principal. Proof uses a BENIGN CANARY FILE (empty/renamed marker, never executable code) placed only in test-account-writable temp locations during the assessment window, then removed — demonstrating the path, never weaponizing it.",
    blackNote: "In black mode: skip the canary placement entirely — report the search-order finding from path analysis alone.",
  },
  {
    id: "WS-052", category: "validation", name: "Kernel privesc CVE correlation",
    brief: "Build number vs known kernel privesc CVEs — patch gap quantified?",
    owasp: "CIS-v8-4.4", attackId: "T1068",
    what: "Correlate the exact OS build from WS-006 against publicly known Windows kernel privilege-escalation CVEs and their fixed builds to quantify the patch gap. Local correlation ONLY — no exploit code is run, no kernel touched; the CVE-gap list is the deliverable.",
  },
  {
    id: "WS-053", category: "logic", name: "Autologon credential exposure",
    brief: "Winlogon autologon with plaintext password in the registry — readable?",
    owasp: "CIS-v8-4.4", attackId: "T1552.001",
    what: "Check the Winlogon registry keys for AutoAdminLogon/DefaultPassword artifacts and whether their ACLs expose the plaintext password to low-privilege readers. Registry reads only; no password is used, replayed, or written down beyond the finding evidence.",
  },
  {
    id: "WS-054", category: "validation", name: "PATH hijacking exposure",
    brief: "Writable directories in SYSTEM PATH — binary planting order exploitable?",
    owasp: "CIS-v8-4.4", attackId: "T1574",
    what: "Decompose the SYSTEM and service PATH environment variables and check each directory's ACL for low-privilege writability, which would let a planted binary shadow a legitimate one. ACL audit ONLY — nothing is planted; the writable-directory finding is the deliverable.",
  },
  {
    id: "WS-055", category: "validation", name: "UAC configuration audit",
    brief: "UAC level, consent behavior, secure desktop — bypass posture assessed?",
    owasp: "CIS-v8-4.4", attackId: "T1548",
    what: "Read the UAC policy settings (EnableLUA, ConsentPromptBehaviorAdmin, secure desktop, installer detection) and assess the bypass posture they imply. Registry/policy reads only; no UAC bypass is attempted.",
  },
  {
    id: "WS-056", category: "logic", name: "Stored credential exposure",
    brief: "Credential Manager, RDP files, unattended install files — creds at rest?",
    owasp: "CIS-v8-4.4", attackId: "T1552.001",
    what: "Audit locations where credentials rest: Credential Manager vaults accessible to the test account, .rdp files with embedded passwords, unattended/sysprep answer files, and Group Policy drive mappings. PRESENCE AUDIT ONLY — no credential is extracted, decrypted, or used; file existence and permissions are the findings.",
  },
  {
    id: "WS-057", category: "functionality", name: "Potato-class DCOM surface audit",
    brief: "Coercible DCOM endpoints reachable — potato attack surface mapped?",
    owasp: "CIS-v8-4.4",
    what: "Map the DCOM activation surface reachable by the authorized test account and assess which endpoints historically enable local NTLM coercion (potato class). Surface enumeration ONLY — no coercion executed, no authentication captured; the reachable-endpoint list is the deliverable.",
  },
  {
    id: "WS-058", category: "logic", name: "WSUS insecure update path",
    brief: "Updates over HTTP or untrusted WSUS — update-hijack path exists?",
    owasp: "CIS-v8-4.4",
    what: "Audit the Windows Update configuration: WSUS server URL, whether updates are fetched over plain HTTP, and whether the update client trusts the configured source. Configuration audit ONLY — no update is intercepted, forged, or installed.",
  },
  // ============================================ LATERAL MOVEMENT — AUTHORIZED SCOPE, FULLY LOGGED
  {
    id: "WS-059", category: "functionality", name: "WMI execution exposure",
    brief: "WMI process creation reachable with test account — logged and scoped?",
    owasp: "CIS-v8-4.4", attackId: "T1047",
    what: "Verify whether the authorized test account can reach WMI (DCOM/RPC) on in-scope hosts and what the audit trail looks like for a benign WMI query (process listing only — a read). No process creation, no command execution; the reachability-plus-logging finding is the deliverable.",
    blackNote: "In black mode: read-only WMI queries only, spaced out; no process-creation class touched at all.",
  },
  {
    id: "WS-060", category: "functionality", name: "PsExec-style service execution exposure",
    brief: "Remote service creation permitted — can test account create services?",
    owasp: "CIS-v8-4.4", attackId: "T1021",
    what: "Audit whether the authorized test account holds rights to create services remotely (SCM access) on in-scope hosts — the PsExec primitive. PERMISSION AUDIT ONLY — no service is created, no binary staged, no execution; the granted-right finding is the deliverable.",
    blackNote: "In black mode: permission check only, and never from a host outside the explicit scope list.",
  },
  {
    id: "WS-061", category: "functionality", name: "WinRM session lateral reach",
    brief: "WinRM sessions to sibling hosts with test account — hop allowed?",
    owasp: "CIS-v8-4.4", attackId: "T1021",
    what: "Open a WinRM session from one in-scope host to another using ONLY the authorized test account, run a single read-only command (hostname/whoami), and close the session. Fully logged, single hop, authorized scope only — the session log itself is part of the evidence.",
  },
  {
    id: "WS-062", category: "validation", name: "Admin share reachability",
    brief: "C$, ADMIN$, IPC$ reachable with test account — lateral footholds mapped?",
    owasp: "CIS-v8-4.4", attackId: "T1135",
    what: "Check which administrative shares (C$, ADMIN$, IPC$) are reachable and accessible with the authorized test account on each in-scope host. Connection-attempt audit only; no files read, no writes.",
  },
  {
    id: "WS-063", category: "functionality", name: "Session and token reuse with test accounts",
    brief: "Existing test-account sessions on other hosts — reusable for lateral proof?",
    owasp: "CIS-v8-4.4", attackId: "T1078",
    what: "Enumerate where the authorized test account already holds live sessions/tokens on in-scope hosts and assess whether those sessions permit lateral movement within scope. Enumeration of the test account's OWN sessions only — no other principal's session or token is touched; single logged hop maximum.",
    blackNote: "In black mode: enumerate only, execute no hop — the session map is the deliverable.",
  },
  {
    id: "WS-064",
    category: "logic", name: "Pass-the-ticket exposure",
    brief: "Kerberos ticket reuse of the test account's own tickets — accepted?",
    owasp: "WSTG-ATHN-02", attackId: "T1078",
    what: "Assess whether the authorized test account's OWN legitimately obtained Kerberos tickets can be replayed to in-scope services (pass-the-ticket exposure of the test credential itself). Executes TODAY via the runner's krb_ptt tool: the operator supplies ticket material (REDTEAM_KRB_CCACHE_B64 / REDTEAM_KRB_CCACHE_PATH / REDTEAM_KRB_KIRBI_B64) or the runner obtains a TGT via kinit as the test account itself; the ticket is replayed ccache-only (KRB5CCNAME) and kvno against an in-scope SPN proves KDC acceptance. The test account's own tickets only — no other principal's tickets, no forging, no silver/golden ticket construction.",
    needs: NEEDS_KERBEROS_TICKET,
  },
  {
    id: "WS-065",
    category: "logic", name: "RDP session shadowing exposure",
    brief: "Can the test account shadow others' RDP sessions — session privacy gap?",
    owasp: "CIS-v8-4.4", attackId: "T1021",
    what: "Audit whether the authorized test account holds the remote-control/shadow permission on in-scope RDS hosts and whether session shadowing would prompt the target user. Executes TODAY via the runner's rdp_shadow_prep tool: read-only WinRM enumeration of live session IDs and shadow policy, producing a complete human handoff package (exact shadow command, consent/ROE checklist, what to observe and record). THE SHADOWING ACT ITSELF IS HUMAN-ONLY — a headless agent cannot sit in a GUI session viewing another person's live desktop, and must not pretend to. PERMISSION AUDIT + PREPARATION ONLY — no session is shadowed by the runner, no other user's session is viewed or touched.",
    blackNote: "In black mode this is a pure permission read — shadowing a live user session is never acceptable.",
    needs: NEEDS_HUMAN_OPERATOR,
  },
  {
    id: "WS-066", category: "functionality", name: "DCOM lateral execution exposure",
    brief: "DCOM activation for lateral use reachable — MMC20-style surface mapped?",
    owasp: "CIS-v8-4.4", attackId: "T1021",
    what: "Audit which DCOM application IDs are activatable remotely by the authorized test account on in-scope hosts — the classic DCOM lateral-movement surface. ACTIVATION-PERMISSION AUDIT ONLY — no object is instantiated for execution, no method invoked; the activatable-AppID list is the deliverable.",
  },
  // ============================================ CREDENTIAL-ACCESS EXPOSURE — AUDITED, REPORTED
  {
    id: "WS-067", category: "validation", name: "LSASS protection audit",
    brief: "LSASS running as PPL, Credential Guard on — memory-read hardened?",
    owasp: "CIS-v8-4.4", attackId: "T1003",
    what: "Audit LSASS hardening on in-scope hosts: Protected Process Light level, Credential Guard / VBS status, and RunAsPPL configuration. Configuration audit ONLY — LSASS memory is never read, dumped, or touched; the hardening-state finding is the deliverable.",
  },
  {
    id: "WS-068", category: "validation", name: "SAM and registry hive permission audit",
    brief: "SAM/SECURITY hives readable by low-priv — offline hash extraction path?",
    owasp: "CIS-v8-4.4", attackId: "T1003",
    what: "Check the ACLs on the SAM, SECURITY, and SYSTEM hive files and registry keys for low-privilege read access that would enable offline credential extraction. ACL audit ONLY — no hive is copied, saved, or read for content; permissions are the finding.",
  },
  {
    id: "WS-069", category: "functionality", name: "Credentials in files and shares",
    brief: "Passwords in scripts, configs, shares — plaintext credential sprawl?",
    owasp: "CIS-v8-4.4", attackId: "T1552.001",
    what: "Search in-scope shares and host file systems (as the authorized test account, read-only) for plaintext credential patterns in scripts, configs, spreadsheets, and notes: passwords in connection strings, hardcoded service passwords, PII-adjacent secrets. PATTERN-MATCH AUDIT ONLY — matched values are redacted to pattern+location in the finding; no credential is used or replayed.",
  },
  {
    id: "WS-070", category: "validation", name: "WDigest credential caching audit",
    brief: "WDigest UseLogonCredential enabled — reversible creds in LSASS?",
    owasp: "CIS-v8-4.4", attackId: "T1003",
    what: "Check whether WDigest's UseLogonCredential is enabled (storing reversible credentials in LSASS memory) on in-scope hosts. Registry read only; no memory access, no credential extraction.",
  },
  {
    id: "WS-071", category: "logic", name: "Shadow copy and backup credential exposure",
    brief: "VSS snapshots/backups exposing SAM/SYSTEM — backup-side extraction path?",
    owasp: "CIS-v8-4.4", attackId: "T1003",
    what: "Audit whether volume shadow copies, system-state backups, or disk images accessible to low-privilege principals contain readable SAM/SYSTEM hives — the backup-side credential-extraction path. EXISTENCE AND PERMISSION AUDIT ONLY — no snapshot is mounted, no hive extracted; the exposure finding is the deliverable.",
  },
  {
    id: "WS-072", category: "logic", name: "LLMNR and NBT-NS spoofing exposure",
    brief: "Name-resolution poisoning possible — responder-class exposure assessed?",
    owasp: "CIS-v8-4.4",
    what: "Audit whether LLMNR and NetBIOS name resolution are enabled on in-scope hosts and whether SMB signing would blunt a spoofing attack — assessing responder-class exposure in principle. CONFIGURATION AUDIT ONLY — no spoofing, no poisoning, no hash capture of any kind.",
    blackNote: "In black mode this never becomes active spoofing — it stays a registry/GPO read.",
  },
  {
    id: "WS-073", category: "functionality", name: "SYSVOL credential sprawl",
    brief: "Scripts and policy files in SYSVOL with embedded secrets — domain-readable?",
    owasp: "CIS-v8-4.4", attackId: "T1552.001",
    what: "Search SYSVOL scripts, preference items, and deployed files (domain-readable by design) for embedded credentials and secrets. READ-ONLY SEARCH — matches are reported as location+pattern with values redacted; no credential is decrypted or used.",
  },
  {
    id: "WS-074", category: "validation", name: "Kerberos ticket lifetime audit",
    brief: "Overlong ticket lifetimes — wider replay window than necessary?",
    owasp: "CIS-v8-4.4",
    what: "Read the domain Kerberos policy ticket lifetimes and assess whether the replay window is wider than operational need justifies. Policy read only; no tickets requested or replayed.",
  },
  {
    id: "WS-075", category: "logic", name: "DPAPI master key exposure",
    brief: "DPAPI backup keys and master-key ACLs — decryptable-by-whom assessed?",
    owasp: "CIS-v8-4.4",
    what: "Audit who can read DPAPI domain backup keys and user master-key files on in-scope hosts — the prerequisite for offline DPAPI decryption. ACL/PERMISSION AUDIT ONLY — no master key is read, no blob decrypted; the access finding is the deliverable.",
  },
  // ============================================ PERSISTENCE FINDINGS — REPORTED, NEVER PLANTED
  {
    id: "WS-076", category: "validation", name: "Run and RunOnce key audit",
    brief: "Autorun registry keys — unknown or suspicious entries present?",
    owasp: "CIS-v8-4.4", attackId: "T1547",
    what: "Enumerate Run/RunOnce keys (HKLM and HKCU) on in-scope hosts and flag entries pointing at missing, unsigned, or unexpected binaries. READ-ONLY ENUMERATION — nothing is added, removed, or executed; unknown entries are reported as findings for the client to triage.",
  },
  {
    id: "WS-077", category: "validation", name: "Service persistence audit",
    brief: "Services as persistence — unexpected services or binpath drift?",
    owasp: "CIS-v8-4.4", attackId: "T1547",
    what: "Compare the installed service list against a known-good baseline (or first-seen inventory) and flag new, unexpected, or binpath-drifted services. Read-only comparison; no service is created, stopped, or altered — drift is the finding.",
  },
  {
    id: "WS-078", category: "validation", name: "Scheduled-task persistence audit",
    brief: "Tasks as persistence — hidden, tampered, or unexpected tasks present?",
    owasp: "CIS-v8-4.4", attackId: "T1053",
    what: "Enumerate all scheduled tasks including hidden ones and flag tasks with unexpected authors, missing binaries, or recent tampering. Read-only enumeration; no task is created, modified, or run — suspicious tasks are findings.",
  },
  {
    id: "WS-079", category: "validation", name: "WMI event subscription audit",
    brief: "WMI event consumers — fileless persistence hiding in the repository?",
    owasp: "CIS-v8-4.4", attackId: "T1547",
    what: "Enumerate WMI event filters, consumers, and bindings (__EventFilter/__EventConsumer/__FilterToConsumerBinding) on in-scope hosts and flag anything not attributable to known management tooling. Read-only WMI queries; nothing is created or removed.",
  },
  {
    id: "WS-080", category: "validation", name: "Winlogon helper DLL audit",
    brief: "Winlogon notify/GINA-adjacent hooks — persistence via logon chain?",
    owasp: "CIS-v8-4.4", attackId: "T1547",
    what: "Audit Winlogon registry values for helper DLLs, shell overrides, and logon-chain hooks, verifying each referenced binary is signed and expected. Registry reads only; nothing is registered or executed.",
  },
  {
    id: "WS-081", category: "validation", name: "Startup folder persistence audit",
    brief: "Startup folders — unexpected LNKs, scripts, or binaries present?",
    owasp: "CIS-v8-4.4", attackId: "T1547",
    what: "Enumerate per-user and all-users Startup folders and flag unexpected shortcuts, scripts, or binaries. Read-only listing; nothing is added, removed, or launched.",
  },
  {
    id: "WS-082", category: "validation", name: "Hidden and anomalous account audit",
    brief: "Accounts ending in $, disabled-but-active, RID anomalies — hidden users?",
    owasp: "CIS-v8-4.4",
    what: "Enumerate local and domain accounts for hiding techniques: trailing-$ names, RID-sequence anomalies, disabled accounts with recent logons, and accounts invisible in normal listings. Read-only enumeration; no account is created, disabled, or modified.",
  },
  {
    id: "WS-083", category: "validation", name: "Defender exclusion persistence audit",
    brief: "AV exclusions as persistence cover — overly broad exclusion paths?",
    owasp: "CIS-v8-4.4",
    what: "Audit Windows Defender exclusion lists (paths, processes, extensions) for overly broad entries that could shelter persistence — e.g. entire drives or user-writable directories excluded. Configuration read only; no exclusion is added or removed.",
  },
  {
    id: "WS-084", category: "validation", name: "COM hijacking audit",
    brief: "Hijacked COM CLSIDs — registry persistence via COM redirection?",
    owasp: "CIS-v8-4.4",
    what: "Audit HKCU/HKLM COM class registrations for hijack indicators: TreatAs redirections, InprocServer32 paths pointing at unexpected binaries, and per-user overrides of system CLSIDs. Registry reads only; nothing is registered or invoked.",
  },
  // ============================================ EDR / AV AWARENESS
  {
    id: "WS-085", category: "validation", name: "Defender state and tamper protection audit",
    brief: "Real-time protection, tamper protection, cloud protection — on or off?",
    owasp: "CIS-v8-4.4",
    what: "Read the Windows Defender operational state on in-scope hosts: real-time protection, tamper protection, cloud-delivered protection, and behavior monitoring. Status reads ONLY — nothing is disabled, no setting changed; a disabled control is the finding.",
  },
  {
    id: "WS-086", category: "validation", name: "AMSI provider configuration audit",
    brief: "AMSI providers registered and functional — script-content inspection intact?",
    owasp: "CIS-v8-4.4",
    what: "Verify AMSI provider registration and that script hosts (PowerShell, JScript, VBA) still route content through AMSI — no provider unregistered, no bypass shim present. Configuration reads only; no AMSI bypass is attempted or tested.",
  },
  {
    id: "WS-087", category: "validation", name: "Attack Surface Reduction rules audit",
    brief: "ASR rules deployed and enforced — or audit-only / absent?",
    owasp: "CIS-v8-4.4",
    what: "Read the deployed Attack Surface Reduction rule set and their modes (block vs audit vs off) on in-scope hosts, flagging high-value rules left in audit or off. Policy reads only; no rule is changed.",
  },
  {
    id: "WS-088", category: "validation", name: "Cloud-delivered protection and PUA blocking audit",
    brief: "Cloud protection + PUA blocking enabled — or silently disabled?",
    owasp: "CIS-v8-4.4",
    what: "Check cloud-delivered protection level, automatic sample submission, and PUA blocking state. Status reads only; nothing toggled.",
  },
  {
    id: "WS-089", category: "logic", name: "ETW provider tampering exposure",
    brief: "ETW providers blindable by the test account — telemetry gaps assessable?",
    owasp: "CIS-v8-4.4",
    what: "Assess whether the authorized test account could tamper with ETW providers or their ACLs in principle (provider permissions, patch-guard-adjacent protections). PERMISSION ASSESSMENT ONLY — no provider is touched, blinded, or patched; the tamperability finding is the deliverable.",
    blackNote: "In black mode: read the provider ACLs and stop — never demonstrate tampering, even benign.",
  },
  {
    id: "WS-090", category: "validation", name: "Defender exclusion path audit",
    brief: "Excluded paths enumerated — attacker-usable blind spots present?",
    owasp: "CIS-v8-4.4",
    what: "Enumerate Defender exclusion paths/processes visible to the authorized test account and assess which exclusions create attacker-usable blind spots. Read-only enumeration; exclusions are findings, never modified.",
  },
  {
    id: "WS-091", category: "validation", name: "EDR driver and service presence audit",
    brief: "Third-party EDR drivers/services present, running, uninstall-protected?",
    owasp: "CIS-v8-4.4",
    what: "Inventory third-party EDR/AV drivers and services on in-scope hosts: present, running, and protected against uninstall/stop by low-privilege principals. Inventory only; no driver touched, nothing stopped.",
  },
  {
    id: "WS-092", category: "validation", name: "Security Center tampering audit",
    brief: "WSC health reporting intact — or spoofed/disabled?",
    owasp: "CIS-v8-4.4",
    what: "Check Windows Security Center health reporting state and whether AV/firewall status reporting has been disabled or spoofed via policy or registry. Status reads only; no spoofing performed.",
  },
  // ============================================ HOST HARDENING POSTURE
  {
    id: "WS-093", category: "validation", name: "Host firewall profile audit",
    brief: "Firewall profiles on, rules sane — domain/private/public posture?",
    owasp: "CIS-v8-4.4",
    what: "Read the Windows Firewall state per profile (domain, private, public) and flag disabled profiles or overly permissive inbound rules on in-scope hosts. Configuration reads only; no rule added or removed.",
  },
  {
    id: "WS-094", category: "validation", name: "RDP listener hardening audit",
    brief: "RDP restricted to NLA+TLS, admin-only — or open to all?",
    owasp: "CIS-v8-4.4",
    what: "Audit the RDP listener configuration: NLA enforcement, encryption level, which principals are in Remote Desktop Users, and whether RDP is exposed beyond the intended scope. Configuration reads only; no session opened.",
  },
  {
    id: "WS-095", category: "validation", name: "BitLocker and encryption-at-rest audit",
    brief: "System volumes encrypted — or plaintext theft viable?",
    owasp: "CIS-v8-4.4",
    what: "Check BitLocker/device-encryption status on system volumes of in-scope hosts and whether protectors are escrowed per policy. Status reads only; no recovery key retrieved.",
  },
  {
    id: "WS-096", category: "validation", name: "PowerShell logging posture audit",
    brief: "Script-block, module, transcription logging — or blind to scripts?",
    owasp: "CIS-v8-4.4",
    what: "Read the PowerShell logging policy: script block logging, module logging, transcription, and protected event logging state. Policy reads only; no logging disabled or evaded.",
  },
  {
    id: "WS-097", category: "validation", name: "Sysmon deployment audit",
    brief: "Sysmon installed with a sane config — or no deep process telemetry?",
    owasp: "CIS-v8-4.4",
    what: "Check whether Sysmon is installed on in-scope hosts, whether its config covers process creation/network/image loads, and whether the config is protected from tampering. Status reads only; no config changed.",
  },
  {
    id: "WS-098", category: "validation", name: "WinRM transport encryption audit",
    brief: "WinRM over HTTPS with cert auth — or plaintext HTTP listeners?",
    owasp: "CIS-v8-4.4",
    what: "Audit WinRM listener configuration: HTTP vs HTTPS listeners, certificate validity on HTTPS listeners, and whether unencrypted traffic is allowed. Configuration reads only; no session created.",
  },
  {
    id: "WS-099", category: "validation", name: "SMBv1 and legacy protocol audit",
    brief: "SMBv1 still enabled — WannaCry-class exposure lingering?",
    owasp: "CIS-v8-4.4",
    what: "Check whether the SMBv1 server/client features are enabled on in-scope hosts and the domain. Feature-state reads only; nothing enabled or disabled.",
  },
  {
    id: "WS-100", category: "logic", name: "RDP Restricted Admin exposure",
    brief: "Restricted Admin mode supported — credential-theft surface assessed?",
    owasp: "CIS-v8-4.4",
    what: "Assess whether RDP Restricted Admin mode is enabled or supportable in the environment and what credential-exposure implications follow. POLICY ASSESSMENT ONLY — no Restricted Admin session is initiated; the configuration finding is the deliverable.",
  },
  {
    id: "WS-101", category: "validation", name: "Remote Registry exposure audit",
    brief: "Remote Registry service running — remote hive reads permitted?",
    owasp: "CIS-v8-4.4", attackId: "T1018",
    what: "Check whether the Remote Registry service is running on in-scope hosts and which principals can connect to it — the remote-hive-read primitive. Service-state and ACL reads only; no remote registry connection made.",
  },
  {
    id: "WS-102", category: "validation", name: "IPv6 and transition-protocol exposure",
    brief: "IPv6/6to4/Teredo active — unmanaged network surface present?",
    owasp: "CIS-v8-4.4",
    what: "Audit IPv6 and transition-protocol (6to4, Teredo, ISATAP) state on in-scope hosts to identify network surface outside the managed IPv4 controls. Configuration reads only; no tunnel established.",
  },
  {
    id: "WS-103", category: "logic", name: "WinRM CredSSP and double-hop exposure",
    brief: "CredSSP allowed — credential delegation beyond the first hop?",
    owasp: "CIS-v8-4.4", attackId: "T1021",
    what: "Audit whether CredSSP is enabled for WinRM and whether credential delegation would permit a second hop with the test account's credentials. CONFIGURATION AUDIT ONLY — no delegation performed, no second hop executed; the delegation-policy finding is the deliverable.",
  },
  {
    id: "WS-104", category: "validation", name: "Domain controller backup and ntds exposure",
    brief: "DC backups accessible — ntds.dit extraction path via backup media?",
    owasp: "CIS-v8-4.4",
    what: "Audit where domain controller system-state backups are stored and which principals can read them — the backup-side ntds.dit extraction path. STORAGE AND PERMISSION AUDIT ONLY — no backup mounted, no database touched; the access finding is the deliverable.",
  },
  // ------------------------------------------------- CVE EXPLOIT VALIDATION
  // (v0.11.0, Metasploit bridge). The battery above covers technique
  // CLASSES; these items cover CVE-SPECIFIC exploits WITHOUT hardcoding
  // CVEs: recon detects a service/version → msf_exec suggest maps it to
  // candidate modules → the coordinator approves → msf_exec run fires ONE
  // module with a benign canary marker as the only payload action. Each
  // CVE validated at runtime becomes a per-CVE instance (attackId
  // "MSF-CVE-…") that reconciles against coverage via its category.
  {
    id: "WS-105", category: "logic", name: "CVE → Metasploit module mapping",
    brief: "Detected service/version mapped to candidate CVE exploit modules for coordinator approval.",
    owasp: "CIS-v8-4.4", attackId: "T1190", needs: NEEDS_MSFRPCD,
    what: "For every versioned service detected during recon (SMB, RDP, WinRM, HTTP, LDAP…), run msf_exec suggest with the service and version string and present the ranked candidate exploit modules to the coordinator for approval. Mapping only — nothing fires. Methodology item: each CVE approved downstream becomes its own runtime instance.",
  },
  {
    id: "WS-106", category: "functionality", name: "CVE exploit validation via Metasploit",
    brief: "Coordinator-approved CVE modules fired with benign canary marker payloads.",
    owasp: "CIS-v8-4.4", attackId: "T1190", needs: NEEDS_MSFRPCD,
    what: "For each coordinator-approved candidate from WS-105, run msf_exec run in the exploit phase: ONE module, generic cmd payload executing ONLY the runner-built canary marker (echo REDTEAM-MARKER-*). The marker echoing back IS the validation — command execution achieved. dos/destructive modules are refused by policy; stray sessions are stopped by hygiene. Tag attackId T1190 and put the CVE in the cve field — each validated CVE is recorded as its own report instance.",
    blackNote: "One module per CVE; lowest-rank-sufficient module first; stop on first defender signal.",
  },
  {
    id: "WS-107", category: "validation", name: "Metasploit auxiliary validation rigor",
    brief: "Auxiliary scanner findings cross-validated; module ranks sanity-checked.",
    owasp: "CIS-v8-4.4", attackId: "T1595.002", needs: NEEDS_MSFRPCD,
    what: "Cross-validate auxiliary-module findings (smb_enumshares, rdp scanners, etc.) against direct host-exec evidence (smb_exec, winrm_probe, rdp_auth) — two independent observations before a finding. Sanity-check module ranks against observed behavior; a high-rank module that fails silently is reported as a coverage note, not a finding.",
  },
];

export const WINDOWS_PROFILE: TargetProfile = {
  id: "windows",
  name: "Windows host + Active Directory",
  baseUrl: "in-scope hosts (ROE scope)",
  kind: "host-windows",
  authModel: "Domain + local accounts via NTLM/Kerberos; RDP/SMB/WinRM/WMI. Credential testing against client-PROVIDED authorized test accounts ONLY (T1078) — never guessed, never stuffed.",
  scopeNotes: "Non-destructive always: read-only enumeration preferred; no service crashing; no ransomware-style behavior; persistence mechanisms REPORTED as findings, never planted; hijack proofs use benign canary files only.",
  battery: WINDOWS_BATTERY,
};
