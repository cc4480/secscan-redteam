/**
 * LINUX battery — part 1 of 5 (v0.19.0 refactor split).
 * Starts at section: RECON — HOST ENUMERATION
 *
 * Pure data split of linux.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by linux.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_MSFRPCD, NEEDS_PRIVILEGED_CLIENT } from "./types.js";

export const LINUX_PART_1: TargetBatteryItem[] = [
  // ============================================ RECON — HOST ENUMERATION
  {
    id: "LX-001", category: "validation", name: "Host web port sweep via HTTP prober",
    brief: "Which common web ports answer HTTP on in-scope hosts — the prober-reachable surface map.",
    owasp: "WSTG-INFO-02", attackId: "T1018",
    what: "Probe common host web ports (80, 443, 8080, 8443, 3000, 5000, 8000, 9000) with the runner's HTTP prober. Record which ports answer, status codes, and redirects. Read-only; this is the host's HTTP-reachable surface inventory for every later item.",
  },
  {
    id: "LX-002", category: "validation", name: "HTTP banner grab on host web ports",
    brief: "Server and X-Powered-By banners on host web ports — what version truth leaks pre-auth?",
    owasp: "WSTG-INFO-02", attackId: "T1018",
    what: "Grab Server, X-Powered-By, and similar version-disclosure headers from every host web port found in LX-001 using the HTTP prober. Record exact product/version strings for the version-to-CVE mapping in LX-008. Read-only, no service crashing.",
  },
  {
    id: "LX-003", category: "validation", name: "TLS certificate inspection on host web ports",
    brief: "Cert validity, expiry, SAN-vs-hostname, issuer chain on host HTTPS ports.",
    owasp: "CIS-v8-3.10",
    what: "Inspect the TLS certificate presented on each host HTTPS port via the HTTP prober: not-before/not-after, SAN coverage of the hostname, issuer chain completeness, self-signed or expired certs. Report mis-issuance as a finding. Read-only handshake inspection.",
  },
  {
    id: "LX-004", category: "validation", name: "Security headers on host web services",
    brief: "HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP presence on host web ports.",
    owasp: "WSTG-CONF",
    what: "Check response headers on host web services via the HTTP prober for HSTS (with sane max-age), X-Content-Type-Options: nosniff, X-Frame-Options or frame-ancestors, Referrer-Policy, and Content-Security-Policy. Missing headers are hardening findings, not exploits. Read-only.",
  },
  {
    id: "LX-005", category: "validation", name: "Full port/service/banner enumeration from host",
    brief: "ss/netstat plus per-port banner reads from inside the host — the complete listener inventory.",
    owasp: "WSTG-INFO-02", attackId: "T1018",
    what: "From host execution, list all listening sockets (ss -tlnp), map each to its owning process, and read one banner per open port. Diff against the LX-001 prober view to find listeners bound to localhost or firewalled interfaces. Read-only; no port-scanning floods.",
    blackNote: "Single pass, localhost-only reads; no external sweep — the host tells on itself.",
  },
  {
    id: "LX-006", category: "validation", name: "OS fingerprinting from host",
    brief: "Exact distro, kernel, and patch level from /etc/os-release and uname — the privesc baseline.",
    owasp: "CIS-v8-2.2", attackId: "T1082",
    what: "Read /etc/os-release, uname -a, and the running kernel build string via host execution. Record exact distro version and kernel release — this is the version baseline every kernel-privesc item (LX-038…) is checked against. Read-only file and syscall reads.",
  },
  {
    id: "LX-007", category: "validation", name: "Installed software inventory vs known CVEs",
    brief: "dpkg/rpm package list mapped to CVE data — version-only, no exploit code.",
    owasp: "CIS-v8-2.2", attackId: "T1518",
    what: "Enumerate installed packages (dpkg -l / rpm -qa) via host execution and map versions against known-CVE data for privilege-escalation-relevant packages (kernel, sudo, polkit, container runtimes). Version comparison only — no exploit payloads are run.",
    blackNote: "One inventory pull; the CVE mapping happens offline, not on the host.",
  },
  {
    id: "LX-008", category: "logic", name: "Service version to exploit mapping (safe checks)",
    brief: "Banner versions from LX-002/LX-005 mapped to public exploits — proof is version match only.",
    owasp: "WSTG-INFO-02", attackId: "T1595.002",
    what: "Take every version string gathered in recon and map it to public exploit/CVE entries to grade exploitability. Proof is a version-string match against the CVE's affected range — exploit code is never downloaded or executed. Read-only reasoning over gathered data.",
    blackNote: "Pure desk analysis on already-gathered banners; zero additional host contact.",
  },
  {
    id: "LX-009", category: "validation", name: "Network share discovery from host",
    brief: "NFS exports and SMB shares visible to the host — the lateral file-access surface.",
    owasp: "WSTG-INFO", attackId: "T1135",
    what: "Enumerate NFS exports (showmount, /etc/fstab, /proc/mounts) and SMB shares (smbclient -L against in-scope servers) visible from the host via host execution. Record export options and share permissions. Read-only listing — mounts are not performed here.",
  },
  {
    id: "LX-010", category: "validation", name: "Listening-socket baseline audit",
    brief: "Every listener justified against the expected baseline — unexpected daemons are findings.",
    owasp: "CIS-v8-4.1", attackId: "T1018",
    what: "Compare the full listener inventory from LX-005 against the client's expected-service baseline via host execution. Any listener with no business justification (stray debug ports, forgotten services) is reported as an exposure finding. Read-only comparison.",
  },
  {
    id: "LX-011", category: "logic", name: "TLS configuration on non-web host ports",
    brief: "openssl s_client against SMTP/LDAP/FTPS ports — weak protocols and ciphers on host services.",
    owasp: "CIS-v8-3.10", attackId: "T1595.002",
    what: "Use openssl s_client via host execution to negotiate TLS on non-web ports (587/636/990/993) and record accepted protocol versions and cipher suites. SSLv3/TLS1.0/1.1 acceptance or NULL/RC4/DES ciphers are findings. Handshake-only, read-only.",
  },
  {
    id: "LX-012", category: "functionality", name: "Hostname and DNS consistency check",
    brief: "Reverse DNS matches forward DNS matches cert SAN — spoofing surface check.",
    owasp: "WSTG-CONF",
    what: "Via host execution, verify the host's hostname resolves forward and reverse consistently (getent hosts, hostname -f) and matches the TLS SANs from LX-003. Mismatches indicate DNS spoofing or stale-record exposure surface. Read-only lookups.",
  },
  // ============================================ SSH HARDENING & ACCESS
  {
    id: "LX-013", category: "validation", name: "sshd_config hardening audit",
    brief: "PermitRootLogin, PasswordAuthentication, MaxAuthTries, AllowUsers — every knob checked.",
    owasp: "CIS-v8-4.1", attackId: "T1021.004",
    what: "Read /etc/ssh/sshd_config (and sshd_config.d) via host execution and audit PermitRootLogin, PasswordAuthentication, PubkeyAuthentication, PermitEmptyPasswords, MaxAuthTries, LoginGraceTime, MaxSessions, X11Forwarding, AllowUsers/AllowGroups, and ClientAlive settings against hardening baselines. Read-only config review; sshd is never restarted.",
  },
  {
    id: "LX-014", category: "validation", name: ".ssh directory and authorized_keys permission audit",
    brief: "~/.ssh must be 700, authorized_keys 600, owned by the user — every account checked.",
    owasp: "CIS-v8-4.1", attackId: "T1552.001",
    what: "Walk every user's ~/.ssh directory via host execution: directory must be 700 and user-owned, authorized_keys 600 and user-owned, no group/other write anywhere on the path. Violations let other local users plant keys. Read-only stat checks.",
  },
  {
    id: "LX-015", category: "validation", name: "Private key file permission audit",
    brief: "id_rsa/id_ed25519 must be 600 — keys readable by others are credential findings.",
    owasp: "CIS-v8-4.1", attackId: "T1552.001",
    what: "Find all private key files (id_rsa, id_ed25519, *.pem) via host execution and verify 600 permissions and correct ownership. Any private key readable by group/other is a credential-exposure finding. Read-only metadata checks; key material is never exfiltrated.",
  },
  {
    id: "LX-016", category: "validation", name: "Exposed private keys sweep",
    brief: "Private keys in backups, /tmp, archives, web roots — the stray-key hunt.",
    owasp: "CIS-v8-5.4", attackId: "T1552.001",
    what: "Search for private key material (-----BEGIN.*PRIVATE KEY-----) outside ~/.ssh — in backups, /tmp, /var, archives, and web roots — via host execution. Filenames and locations are reported; key contents are never copied off-host. Read-only, targeted paths only.",
    blackNote: "Narrow the path list to backups and web roots; skip the full-filesystem find.",
  },
  {
    id: "LX-017", category: "functionality", name: "SSH authentication with authorized test accounts",
    brief: "Log in with client-PROVIDED test accounts only — verify auth paths behave, never guess.",
    owasp: "WSTG-ATHN-04", attackId: "T1078",
    what: "Authenticate over SSH using ONLY client-provided authorized test accounts (one login attempt per account): verify key-based vs password paths, confirm account restrictions (AllowUsers, expiry, locked status) are enforced, then disconnect. No guessing, no stuffing, no brute force — test accounts only.",
  },
  {
    id: "LX-018",
    category: "functionality", name: "SSH agent-forwarding restriction check",
    brief: "Confirm ForwardAgent does not expose the operator's keys to the host.",
    owasp: "WSTG-ATHN", attackId: "T1021.004",
    what: "Connect with agent forwarding explicitly configured per policy via the runner's ssh_agent_audit tool and verify whether the agent socket is exposed (SSH_AUTH_SOCK presence, socket permissions). If policy forbids forwarding, confirm it is refused. Benign connection only; no key material is used for onward auth.",
  },
  {
    id: "LX-019",
    category: "logic", name: "Agent-forwarding abuse path analysis",
    brief: "If forwarding is allowed, map the exact socket-hijack path a host attacker would use.",
    owasp: "WSTG-ATHN", attackId: "T1021.004",
    what: "Where agent forwarding is permitted, document the abuse path via the runner's ssh_agent_audit tool: agent socket location and permissions, which local users could reach it, and how a host-compromise would pivot through it. Analysis only — the socket is never actually hijacked.",
    blackNote: "Read the sshd_config value and socket perms; skip the live connection entirely.",
  },
  {
    id: "LX-020", category: "validation", name: "Brute-force protections audit",
    brief: "MaxAuthTries, fail2ban/sshguard, auth-log monitoring — config audit only, no guessing.",
    owasp: "CIS-v8-4.1", attackId: "T1110",
    what: "Audit brute-force mitigations via host execution: sshd MaxAuthTries/MaxStartups, fail2ban or sshguard jails covering sshd, and whether auth failures are monitored. This is a configuration audit — no password guessing is ever performed.",
    blackNote: "Black mode excludes any active authentication probing whatsoever — config files only.",
  },
  {
    id: "LX-021", category: "validation", name: "authorized_keys hygiene audit",
    brief: "Unknown, stale, or unrestricted keys in authorized_keys — the quiet backdoor check.",
    owasp: "CIS-v8-5.4", attackId: "T1078",
    what: "Review every authorized_keys file via host execution against the client's key roster: unknown keys, keys without from=/command= restrictions where policy requires them, and stale keys of departed staff are findings. Read-only review; keys are never modified or removed.",
  },
  {
    id: "LX-022", category: "logic", name: "SSH key trust chain to privilege path",
    brief: "Does any authorized key reach an account with NOPASSWD sudo or root login? Map it.",
    owasp: "WSTG-ATHZ", attackId: "T1078",
    what: "Correlate authorized_keys entries with account privileges via host execution: for each key, determine the account's sudo rights and group memberships. A key reaching a NOPASSWD or root-equivalent account is a privilege-path finding. Read-only correlation; no login is performed with found keys.",
  },
  {
    id: "LX-023", category: "validation", name: "SSH pre-auth surface enumeration",
    brief: "Banner, key-exchange and auth-method disclosure via ssh -v — no login attempted.",
    owasp: "WSTG-INFO-02", attackId: "T1595.002",
    what: "Run ssh -v against the host's SSH port via host execution to record the pre-auth banner, offered key-exchange/cipher/MAC algorithms, and advertised auth methods. Weak algorithms (3des, md5-based MACs) or version disclosure are findings. No credentials are ever offered.",
  },
  {
    id: "LX-024", category: "functionality", name: "SSH host-key verification against baseline",
    brief: "Host keys match the client-known baseline — detect substitution or MITM.",
    owasp: "WSTG-CONF", attackId: "T1021.004",
    what: "Compare the host's presented SSH host-key fingerprints against the client's known baseline via host execution. A mismatch indicates key substitution or MITM. Fingerprint comparison only; no trust-on-first-use acceptance.",
  },
];
