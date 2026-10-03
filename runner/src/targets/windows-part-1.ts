/**
 * WINDOWS battery — part 1 of 5 (v0.19.0 refactor split).
 * Starts at section: RECON — SMB / SHARES
 *
 * Pure data split of windows.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by windows.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_HUMAN_OPERATOR, NEEDS_KERBEROS_TICKET, NEEDS_MSFRPCD } from "./types.js";

export const WINDOWS_PART_1: TargetBatteryItem[] = [
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
];
