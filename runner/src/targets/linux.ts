/**
 * Linux target profile — host.
 *
 * EXHAUSTIVE battery (v0.8.0): surface × technique. Every distinct attacker
 * intent against a Linux host's real surface is one item. Surfaces: recon
 * (host enumeration plus prober-reachable web ports), SSH hardening & access,
 * privilege escalation (SUID/SGID, sudo, capabilities, cron/at, PATH and
 * linker hijacking, systemd, kernel, NFS, containers/LXD), exposed services
 * (audited as FINDINGS via read-only checks), file-permission & secret
 * auditing, persistence FINDINGS (reported, never planted), accounts &
 * authentication, logging & detection, network posture, kernel & system
 * hardening, cross-cutting chains.
 *
 * Execution model (v0.9.0): the runner's `ssh_exec` host tool executes this
 * battery — non-interactive SSH command execution with the safety core
 * (scope, denylist, timeouts). Only 3 items still need MORE than command
 * execution and stay marked `needs: "host-exec tooling"` — PLAN-ONLY,
 * reported BLOCKED under Honest limits: LX-018/LX-019 (SSH agent-forwarding
 * channel the tool doesn't establish), LX-041 (NFS mount needs a test
 * client with mount privileges, not just target-side commands).
 *
 * Non-destructive always: read-only enumeration preferred; no service
 * crashing; no destructive payloads; persistence mechanisms REPORTED as
 * findings, never planted; privesc proofs are safe non-destructive checks
 * (version output, permission bits, --help, dry reads) — never a real root
 * shell. Credential testing against client-PROVIDED authorized test accounts
 * ONLY (T1078) — never guessed, never stuffed.
 */

import type { TargetBatteryItem, TargetProfile } from "./types.js";

const LINUX_BATTERY: TargetBatteryItem[] = [
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
    what: "Connect with agent forwarding explicitly configured per policy via host execution and verify whether the agent socket is exposed (SSH_AUTH_SOCK presence, socket permissions). If policy forbids forwarding, confirm it is refused. Benign connection only; no key material is used for onward auth.",
    needs: "host-exec tooling",
  },
  {
    id: "LX-019",
    category: "logic", name: "Agent-forwarding abuse path analysis",
    brief: "If forwarding is allowed, map the exact socket-hijack path a host attacker would use.",
    owasp: "WSTG-ATHN", attackId: "T1021.004",
    what: "Where agent forwarding is permitted, document the abuse path via host execution: agent socket location and permissions, which local users could reach it, and how a host-compromise would pivot through it. Analysis only — the socket is never actually hijacked.",
    blackNote: "Read the sshd_config value and socket perms; skip the live connection entirely.",
    needs: "host-exec tooling",
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
  // ============================================ PRIVILEGE ESCALATION
  {
    id: "LX-025", category: "logic", name: "SUID binary enumeration",
    brief: "Every SUID binary on the system, diffed against the distro baseline — unusual ones flagged.",
    owasp: "CIS-v8-4.1", attackId: "T1548",
    what: "Find all SUID binaries (find / -perm -4000) via host execution and diff against the distro's expected set. Unusual SUID binaries — interpreters, editors, scripting runtimes, custom binaries — are privesc-candidate findings. Read-only enumeration.",
  },
  {
    id: "LX-026", category: "logic", name: "SGID enumeration and group-writable abuse",
    brief: "SGID binaries plus group-writable targets — the overlooked elevation path.",
    owasp: "CIS-v8-4.1", attackId: "T1548",
    what: "Enumerate SGID binaries (find / -perm -2000) via host execution and check whether the owning groups are overly broad or the binaries' data files are group-writable by the test user. Group-writable SGID targets are privesc findings. Read-only checks.",
  },
  {
    id: "LX-027", category: "logic", name: "SUID abuse path with safe non-destructive proof",
    brief: "GTFOBins-mapped SUID binaries — proof is --help/version or a benign read, never a root shell.",
    owasp: "WSTG-ATHZ", attackId: "T1548",
    what: "For each GTFOBins-mapped SUID binary found in LX-025, determine the documented abuse primitive via host execution but prove it with SAFE non-destructive evidence only (version output, --help, reading a benign root-owned file). A real root shell is never spawned; the finding is the proven primitive.",
    blackNote: "Prove one representative binary; list the rest as version-matched candidates.",
  },
  {
    id: "LX-028", category: "validation", name: "SUID permission drift vs baseline",
    brief: "New or changed SUID binaries since the last baseline — drift means incident or misconfig.",
    owasp: "CIS-v8-4.1", attackId: "T1548",
    what: "Compare current SUID/SGID bits against the client's file-integrity baseline via host execution. Any SUID bit not in the baseline is flagged for review as potential persistence or misconfiguration. Read-only comparison; nothing is chmodded.",
  },
  {
    id: "LX-029", category: "logic", name: "sudo misconfiguration enumeration",
    brief: "sudo -l as the test user: NOPASSWD, wildcards, relative paths, sudoedit escapes.",
    owasp: "CIS-v8-5.4", attackId: "T1548",
    what: "Run sudo -l as the authorized test user via host execution and analyze every rule: NOPASSWD entries, wildcards in commands, relative-path commands, sudoedit on sensitive files, and SETENV tags. Each bypassable rule is a privesc finding with the exact abuse documented. Read-only listing.",
  },
  {
    id: "LX-030", category: "functionality", name: "sudo credential caching behavior",
    brief: "timestamp_timeout and tty_tickets — verify re-auth is actually required after timeout.",
    owasp: "WSTG-ATHN-04", attackId: "T1548",
    what: "Inspect sudo timestamp_timeout and tty_tickets settings via host execution, then verify with the authorized test account that a second sudo after the timeout genuinely re-prompts. Excessive timeouts or disabled tty_tickets are findings. Benign sudo -l/-v only.",
  },
  {
    id: "LX-031", category: "logic", name: "sudo environment preservation audit",
    brief: "env_keep with LD_PRELOAD or SETENV tag — the sudo environment escape.",
    owasp: "WSTG-ATHZ", attackId: "T1574",
    what: "Check sudoers env_keep, env_check, and SETENV tags via host execution for dangerous preserved variables (LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH). A preserved linker variable plus sudo execution is a privesc primitive — documented, never executed into a shell.",
  },
  {
    id: "LX-032", category: "logic", name: "Linux capabilities abuse audit",
    brief: "cap_setuid/cap_dac_read_search/cap_sys_admin binaries — file caps are the new SUID.",
    owasp: "CIS-v8-4.1", attackId: "T1548",
    what: "Enumerate file capabilities (getcap -r /) via host execution and map each dangerous capability (cap_setuid, cap_dac_read_search, cap_dac_override, cap_sys_admin, cap_sys_ptrace) on interpreters and tools to its abuse primitive. Proof is capability-bit evidence; no exploit is run.",
  },
  {
    id: "LX-033", category: "logic", name: "Writable PATH interception",
    brief: "World-writable dirs or relative entries in root/cron PATH — the classic hijack.",
    owasp: "CIS-v8-4.1", attackId: "T1574",
    what: "Inspect PATH for root, cron jobs, and systemd units via host execution: world-writable directories, group-writable entries, empty or relative (.) entries. Any writable-before-system-dir ordering is a hijack finding. Read-only path analysis; nothing is written.",
  },
  {
    id: "LX-034", category: "logic", name: "Dynamic linker hijack vectors",
    brief: "/etc/ld.so.preload writability and rpath/runpath abuse — T1574 on the loader.",
    owasp: "CIS-v8-4.1", attackId: "T1574",
    what: "Check writability of /etc/ld.so.preload and ld.so.conf.d entries via host execution, plus binaries with attacker-influenced rpath/runpath. A writable preload config is a host-wide code-execution finding. Read-only permission checks; no library is ever planted.",
  },
  {
    id: "LX-035", category: "logic", name: "Cron and at writable-job abuse",
    brief: "Writable cron files, dirs, and scripts executed as root — the scheduled privesc.",
    owasp: "CIS-v8-4.1", attackId: "T1053",
    what: "Audit /etc/crontab, /etc/cron.d, /etc/cron.*/, user crontabs, and /var/spool/cron via host execution for world/group-writable job files, writable parent directories, and scripts called by root jobs that the test user can modify. Each writable link in the chain is a privesc finding. Nothing is modified.",
  },
  {
    id: "LX-036", category: "validation", name: "cron.allow / at.allow access control audit",
    brief: "Who may schedule jobs — allow/deny files present and restrictive?",
    owasp: "CIS-v8-4.1", attackId: "T1053",
    what: "Verify /etc/cron.allow, /etc/cron.deny, /etc/at.allow, /etc/at.deny exist with restrictive permissions via host execution, and that the spool directories are not world-writable. Missing access control on the scheduler is a finding. Read-only checks.",
  },
  {
    id: "LX-037", category: "logic", name: "Writable systemd service escalation path",
    brief: "Writable unit files or drop-ins — the daemon-reload path to root, reported not executed.",
    owasp: "CIS-v8-4.1", attackId: "T1547",
    what: "Find systemd unit files, drop-ins, and the binaries they ExecStart that are writable by the test user via host execution. A writable unit is a root-escalation path (daemon-reload) — the finding is the writability evidence; the service is never modified or reloaded.",
  },
  {
    id: "LX-038", category: "validation", name: "Kernel version vs known privesc CVEs",
    brief: "Running kernel mapped to dirty-pipe/dirty-cow/overlayfs-class CVEs — version-only.",
    owasp: "CIS-v8-2.2", attackId: "T1068",
    what: "Map the running kernel version from LX-006 against known local-privesc CVEs via host execution context (version comparison only). Vulnerable-and-unpatched kernels are graded by exploit maturity. No exploit code is compiled or run — the version match is the finding.",
  },
  {
    id: "LX-039", category: "logic", name: "polkit pkexec CVE-2021-4034 safe version check",
    brief: "PwnKit-vulnerable polkit versions — check the version, never run the exploit.",
    owasp: "CIS-v8-2.2", attackId: "T1068",
    what: "Check the installed polkit version via host execution against the CVE-2021-4034 affected range. A vulnerable version is a critical privesc finding on version evidence alone — the exploit is never executed. Read-only package query.",
  },
  {
    id: "LX-040", category: "logic", name: "OverlayFS CVE-2023-0386 safe version check",
    brief: "Ubuntu-flavored kernels in the GameOver(lay) range — version evidence only.",
    owasp: "CIS-v8-2.2", attackId: "T1068",
    what: "Check the kernel build string via host execution against the CVE-2023-0386 affected range (unpatched Ubuntu-style kernels with overlayfs). Version match is the finding; the user-namespace mount exploit is never attempted. Read-only.",
  },
  {
    id: "LX-041",
    category: "logic", name: "NFS no_root_squash abuse path",
    brief: "Export with no_root_squash — prove uid-0 mapping with a benign test file, removed after.",
    owasp: "CIS-v8-4.1", attackId: "T1210",
    what: "Where an export carries no_root_squash (LX-042), mount it from an in-scope test client via host execution and prove root squashing is disabled by creating a benign test file as uid 0, then delete the file. No setuid binaries are written; the mount and file are cleaned up. Writable-export evidence only.",
    needs: "host-exec tooling",
  },
  {
    id: "LX-042", category: "validation", name: "/etc/exports misconfiguration audit",
    brief: "no_root_squash, insecure, no_subtree_check, world exports — the export-file review.",
    owasp: "CIS-v8-4.1", attackId: "T1135",
    what: "Read /etc/exports via host execution and flag no_root_squash, insecure (unprivileged source ports), no_subtree_check on sensitive trees, and exports to * or broad subnets. Each flag is a finding with the exact line. Read-only file review.",
  },
  {
    id: "LX-043", category: "logic", name: "Docker socket exposure check",
    brief: "/var/run/docker.sock writable by non-root — proof is read-only docker ps, never a container.",
    owasp: "CIS-v8-4.1", attackId: "T1210",
    what: "Check permissions and group ownership of /var/run/docker.sock via host execution. If the test user can reach it, prove access with a read-only `docker ps` — equivalent to root — and report. No container is created, no image pulled, no host file mounted.",
  },
  {
    id: "LX-044", category: "logic", name: "Container escape path analysis",
    brief: "Privileged container? hostPID, device mounts, missing seccomp/AppArmor — map the breakout.",
    owasp: "WSTG-ATHZ", attackId: "T1210",
    what: "Determine whether the host is itself containerized and audit escape-relevant configuration via host execution: privileged mode, hostPath/device mounts, hostPID/hostNetwork, and absent seccomp/AppArmor profiles. Findings are configuration evidence; no breakout is attempted.",
    blackNote: "Read /proc/self/cgroup and mountinfo only; skip any runtime interrogation.",
  },
  {
    id: "LX-045", category: "logic", name: "LXD group abuse path",
    brief: "Membership in lxd = root via privileged container — document, don't launch.",
    owasp: "CIS-v8-5.4", attackId: "T1548",
    what: "Check whether the test user or any non-admin is in the lxd group via host execution. Membership is a documented root-equivalent path (privileged container with host disk attach) — the finding is the membership evidence; no container is ever launched.",
  },
  {
    id: "LX-046", category: "validation", name: "sudoers file permission audit",
    brief: "/etc/sudoers and sudoers.d must be root-owned and non-writable — the keys to the kingdom.",
    owasp: "CIS-v8-4.1", attackId: "T1548",
    what: "Verify /etc/sudoers and every file in /etc/sudoers.d are root-owned, mode 440 or tighter, and that the directories are not writable via host execution. Writable sudoers fragments are critical findings. Read-only stat checks; sudoers content is reviewed, never edited.",
  },
  {
    id: "LX-047", category: "logic", name: "Writable /etc/passwd or /etc/shadow check",
    brief: "test -w evidence of writability — reported as critical, no account is ever added.",
    owasp: "CIS-v8-4.1", attackId: "T1548",
    what: "Test writability (test -w) of /etc/passwd, /etc/shadow, and /etc/group as the unprivileged test user via host execution. Writability is a critical privesc finding on permission evidence alone — no user is added, nothing is written.",
  },
  {
    id: "LX-048", category: "functionality", name: "Privesc mitigation verification",
    brief: "ASLR, kptr_restrict, dmesg_restrict, userns limits, core pattern — do mitigations hold?",
    owasp: "CIS-v8-4.1", attackId: "T1068",
    what: "Verify active exploit mitigations via host execution: /proc/sys/kernel/randomize_va_space, kptr_restrict, dmesg_restrict, perf_event_paranoid, unprivileged_userns_clone, and fs.suid_dumpable. Disabled mitigations widen every privesc item and are reported as such. Read-only sysctl reads.",
  },
  // ============================================ EXPOSED SERVICES (audited as FINDINGS)
  {
    id: "LX-049", category: "functionality", name: "Unauthenticated Redis access check",
    brief: "INFO command only against exposed Redis — no writes, no CONFIG, no FLUSHDB ever.",
    owasp: "WSTG-ATHN-04", attackId: "T1210",
    what: "Attempt an unauthenticated Redis connection via host execution and run INFO only. If it answers without auth, that is the finding — version, role, and exposed-data summary are recorded. No keys are read, no writes, no CONFIG/FLUSHDB/SHUTDOWN; disconnect immediately.",
  },
  {
    id: "LX-050", category: "functionality", name: "Unauthenticated MongoDB access check",
    brief: "hello/listDatabases read-only against exposed MongoDB — data is never read.",
    owasp: "WSTG-ATHN-04", attackId: "T1210",
    what: "Attempt an unauthenticated MongoDB connection via host execution and run hello and listDatabases only. Unauthenticated access is the finding; collection contents are never read and nothing is written. Read-only handshake evidence.",
  },
  {
    id: "LX-051", category: "functionality", name: "Unauthenticated Elasticsearch access check",
    brief: "GET / and cluster health read-only — exposed cluster metadata is the finding.",
    owasp: "WSTG-ATHN-04", attackId: "T1190",
    what: "Request GET / and /_cluster/health from an exposed Elasticsearch via host execution. If no authentication is required, record version and cluster name as the finding. Indices are never listed or searched; read-only HTTP.",
  },
  {
    id: "LX-052", category: "functionality", name: "Docker TCP API exposure check",
    brief: "GET /version on 2375/2376 only — exposed Docker API is root-equivalent.",
    owasp: "WSTG-ATHN-04", attackId: "T1210",
    what: "Request GET /version from Docker's TCP API ports (2375/2376) via host execution. Any 200 response is a critical finding — the Docker API is root-equivalent. No containers are listed beyond version, nothing is created. Single read-only request.",
  },
  {
    id: "LX-053", category: "functionality", name: "Unauthenticated observability dashboards",
    brief: "Kibana/Grafana/Prometheus anonymous access — dashboards reachable without login?",
    owasp: "WSTG-ATHN-04", attackId: "T1190",
    what: "Check whether Kibana, Grafana, or Prometheus endpoints on the host allow anonymous access via host execution (login page vs direct dashboard/API response). Anonymous reachability of metrics or logs is the finding. Read-only page fetches; no queries are run.",
  },
  {
    id: "LX-054", category: "functionality", name: "LDAP anonymous bind check",
    brief: "Anonymous bind + rootDSE read only — directory exposed without credentials?",
    owasp: "WSTG-ATHN-04", attackId: "T1210",
    what: "Attempt an anonymous LDAP bind via host execution and read rootDSE only. A successful bind is the finding — directory structure and entries are never enumerated. Read-only bind evidence, then disconnect.",
  },
  {
    id: "LX-055", category: "functionality", name: "SNMP community string exposure",
    brief: "public/private community strings, system MIB read-only — SET is never attempted.",
    owasp: "WSTG-ATHN-04", attackId: "T1210",
    what: "Try well-known SNMP community strings (public, private) read-only via host execution against the system MIB. A responding community string is the finding. SNMP SET is never attempted; single targeted walk, not a community dictionary sweep.",
    blackNote: "One community string, one OID subtree; the response-or-timeout is the whole test.",
  },
  {
    id: "LX-056", category: "validation", name: "Host firewall ruleset audit",
    brief: "iptables/nftables/ufw rules vs expected policy — default-deny confirmed on paper.",
    owasp: "CIS-v8-4.4",
    what: "Dump and review the active firewall ruleset (iptables-save, nft list ruleset, ufw status) via host execution against the expected policy: default-deny inbound, documented exceptions only. Unjustified ACCEPTs or a missing firewall are findings. Read-only review; rules are never changed.",
  },
  {
    id: "LX-057", category: "validation", name: "Vendor-default credential hygiene audit",
    brief: "Services still on vendor defaults — flagged via config, logins only if ROE allows.",
    owasp: "CIS-v8-5.2",
    what: "Review service configurations via host execution for unchanged vendor-default credentials (default admin accounts, default SNMP strings, default DB passwords). Defaults are reported from config evidence; login attempts with defaults happen ONLY where the ROE explicitly authorizes them, otherwise report-only.",
  },
  {
    id: "LX-058", category: "logic", name: "Exposed-service to host-impact chaining",
    brief: "Map each unauthenticated service to its host-impact path — Redis write, Docker root.",
    owasp: "WSTG-BUSL", attackId: "T1210",
    what: "For every unauthenticated service confirmed in LX-049…LX-055, document the concrete host-impact chain (e.g. Redis → file write → cron, Docker API → root container) via analysis. Chains are documented as narratives — the impact steps are never executed.",
  },
  // ============================================ FILE-PERMISSION & SECRET AUDITING
  {
    id: "LX-059", category: "validation", name: "World-writable sensitive files audit",
    brief: "passwd, shadow, sudoers, crontab, hosts — any world-writable bit is a finding.",
    owasp: "CIS-v8-4.1", attackId: "T1083",
    what: "Scan /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers, cron files, and /etc/hosts for world-writable bits via host execution. Any world-writable sensitive file is a finding with the exact mode. Read-only find; nothing is chmodded.",
  },
  {
    id: "LX-060", category: "validation", name: "/etc/shadow readability audit",
    brief: "Group/other read bits on shadow or its backups — hashes must never be readable.",
    owasp: "CIS-v8-4.1", attackId: "T1003",
    what: "Check /etc/shadow, /etc/gshadow, and their backups (-, .bak) for any group/other read permission via host execution. Readable hashes enable offline cracking — any read bit beyond root is a critical finding. Metadata only; hashes are never extracted.",
  },
  {
    id: "LX-061", category: "functionality", name: "Shadow access control enforcement proof",
    brief: "Unprivileged test user attempts to read /etc/shadow — denial must hold.",
    owasp: "WSTG-ATHZ", attackId: "T1003",
    what: "As the authorized unprivileged test user via host execution, attempt to read /etc/shadow and confirm the read is denied. Expected-deny confirmation proves the access control holds; if the read succeeds, it is a critical finding. Single benign read attempt.",
  },
  {
    id: "LX-062", category: "validation", name: "Credentials in shell history and backups",
    brief: "Passwords in .bash_history, history files, /var/backups, *.bak — the secret spill hunt.",
    owasp: "CIS-v8-3.3", attackId: "T1552.001",
    what: "Grep shell history files (*_history), /var/backups, and *.bak/*.old/*.swp files for password-shaped secrets (password=, -p<secret>, API keys) via host execution. Filenames and line counts are reported; secret values are redacted from the report. Targeted paths only, read-only.",
    blackNote: "Grep home directories and /var/backups only; skip the full-filesystem sweep.",
  },
  {
    id: "LX-063", category: "validation", name: "Database credential file readability",
    brief: ".my.cnf, .pgpass, .netrc readable by others — DB creds must be owner-only.",
    owasp: "CIS-v8-3.3", attackId: "T1552.001",
    what: "Find .my.cnf, .pgpass, .netrc, and similar credential files via host execution and verify owner-only permissions. Any such file readable by group/other is a credential-exposure finding. Metadata only; contents are never displayed.",
  },
  {
    id: "LX-064", category: "validation", name: "Sensitive files in web roots",
    brief: ".git, .env, .htpasswd, config.bak under docroots — web-reachable secrets.",
    owasp: "WSTG-CONF", attackId: "T1083",
    what: "Inspect web document roots via host execution for .git directories, .env files, .htpasswd, backup copies of configs (*.bak, *~), and exposed includes. Each web-reachable secret file is a finding. Read-only listing; files are not fetched over HTTP here.",
  },
  {
    id: "LX-065", category: "logic", name: "Web-root backdoor signature sweep",
    brief: "Known web-shell signatures in docroots — reported, never executed.",
    owasp: "CIS-v8-10.1", attackId: "T1505.003",
    what: "Scan web document roots for known web-shell and backdoor signatures (eval-heavy droppers, known shell filenames) via host execution. Matches are REPORTED as compromise indicators with paths and hashes — suspect files are never opened in a browser or executed.",
    blackNote: "Signature scan of docroots only; no behavior analysis, no execution.",
  },
  {
    id: "LX-066", category: "validation", name: "Home directory permission audit",
    brief: "World-readable home dirs and sensitive files — every user's home checked.",
    owasp: "CIS-v8-4.1", attackId: "T1083",
    what: "Check every home directory for world-readable/executable bits and sensitive files (keys, cloud credentials, tokens) readable by others via host execution. Overly permissive homes are findings. Read-only permission checks.",
  },
  {
    id: "LX-067", category: "validation", name: "Log file permission audit",
    brief: "auth.log, syslog, journal readable by non-root — auth trails must be protected.",
    owasp: "CIS-v8-8.2", attackId: "T1083",
    what: "Verify /var/log/auth.log, /var/log/syslog, and journal files are not readable by non-privileged users via host execution. Readable auth logs leak usernames, login patterns, and sudo usage. Read-only permission checks.",
  },
  {
    id: "LX-068", category: "validation", name: "/tmp and /var/tmp mount hygiene",
    brief: "noexec,nosuid,nodev on world-writable tmp — the staging-ground lockdown.",
    owasp: "CIS-v8-4.1",
    what: "Verify /tmp and /var/tmp are mounted (or bound) with noexec, nosuid, and nodev via host execution. Missing flags make tmp a reliable exploit-staging ground. Read-only mount-option review; mounts are never changed.",
  },
  {
    id: "LX-069", category: "validation", name: "LD_PRELOAD persistence vector audit",
    brief: "/etc/ld.so.preload content — any entry is host-wide code execution.",
    owasp: "CIS-v8-4.1", attackId: "T1574",
    what: "Read /etc/ld.so.preload and /etc/ld.so.conf.d via host execution. Any unexpected preload entry is a critical persistence/code-execution finding — every process on the host loads it. Read-only content review; entries are never added or removed.",
  },
  {
    id: "LX-070", category: "validation", name: "Web docroot ownership audit",
    brief: "Docroot files must not be owned or writable by the web runtime user.",
    owasp: "CIS-v8-4.1", attackId: "T1083",
    what: "Verify web document-root files are owned by root or a deploy user and NOT writable by the web server runtime user via host execution. Web-writable code means a single upload flaw becomes code execution. Read-only ownership checks.",
  },
  // ============================================ PERSISTENCE FINDINGS (reported, never planted)
  {
    id: "LX-071", category: "validation", name: "Cron persistence audit",
    brief: "crontab, cron.d, user crontabs, @reboot — unknown entries are reported findings.",
    owasp: "CIS-v8-4.1", attackId: "T1053",
    what: "Review /etc/crontab, /etc/cron.d, /etc/cron.*/, /var/spool/cron/*, and @reboot entries via host execution against the expected-job baseline. Unknown or obfuscated entries are REPORTED as persistence findings — nothing is added, nothing is removed.",
  },
  {
    id: "LX-072", category: "validation", name: "systemd units and timers audit",
    brief: "Suspicious ExecStart, user units, timers — the modern persistence surface.",
    owasp: "CIS-v8-4.1", attackId: "T1547",
    what: "List system and user systemd units and timers (systemctl list-units, list-timers, ~/.config/systemd) via host execution and flag unknown ExecStart commands, curl|bash patterns, and timers with no business owner. Reported as findings; units are never enabled, disabled, or started.",
  },
  {
    id: "LX-073", category: "validation", name: "authorized_keys additions vs baseline",
    brief: "Keys not in the roster baseline — the quiet SSH backdoor check.",
    owasp: "CIS-v8-5.4", attackId: "T1078",
    what: "Diff every authorized_keys file against the client's key baseline via host execution. Added, unknown, or recently-modified keys are REPORTED as persistence findings. Keys are never removed or altered — report only.",
  },
  {
    id: "LX-074", category: "validation", name: "rc.local and profile.d persistence audit",
    brief: "Writable rc.local, profile.d scripts, bashrc entries — logon persistence review.",
    owasp: "CIS-v8-4.1", attackId: "T1547",
    what: "Review /etc/rc.local, /etc/profile.d/*, and global/user bashrc and profile files via host execution for unknown entries and writable scripts. Each unexplained entry is REPORTED as a persistence finding; files are never modified.",
  },
  {
    id: "LX-075", category: "logic", name: "Obfuscated payloads in persistence locations",
    brief: "Base64/packed content in cron, profile.d, systemd — decoded in analysis, never run.",
    owasp: "CIS-v8-10.1", attackId: "T1027",
    what: "Scan cron files, profile.d scripts, and systemd units for obfuscated content (base64 blobs, packed one-liners, hex-encoded commands) via host execution. Matches are REPORTED with the decoded-in-analysis text as compromise indicators — payloads are never executed.",
    blackNote: "Target cron and profile.d only; skip the systemd unit corpus on this pass.",
  },
  {
    id: "LX-076", category: "validation", name: "PAM configuration audit",
    brief: "nullok, missing faillock, rogue modules — the auth-stack backdoor review.",
    owasp: "CIS-v8-4.1", attackId: "T1556",
    what: "Review /etc/pam.d/common-auth, system-auth, and sshd stacks via host execution for nullok, absent faillock/pwhistory, and unknown or unsigned modules. A rogue PAM module is a credential-interception backdoor — reported as a critical finding. Read-only review.",
  },
  {
    id: "LX-077", category: "validation", name: "sshd_config persistence vectors",
    brief: "Match blocks, ForceCommand, AuthorizedKeysCommand — SSH-layer backdoors.",
    owasp: "CIS-v8-4.1", attackId: "T1021.004",
    what: "Audit sshd_config Match blocks, ForceCommand directives, and AuthorizedKeysCommand settings via host execution for backdoor-shaped entries (commands that log, proxy, or bypass auth). Suspicious directives are REPORTED as persistence findings; sshd is never restarted or reloaded.",
  },
  {
    id: "LX-078", category: "validation", name: "Kernel module persistence audit",
    brief: "modules-load.d and modprobe.d — unexpected modules loading at boot.",
    owasp: "CIS-v8-4.1", attackId: "T1547",
    what: "Review /etc/modules-load.d, /etc/modprobe.d, and /etc/modules via host execution against the expected-module baseline. Unknown modules configured to load at boot are REPORTED as persistence findings. Read-only review; modules are never loaded or unloaded.",
  },
  {
    id: "LX-079", category: "validation", name: "XDG autostart persistence audit",
    brief: "Autostart desktop entries for service accounts — the graphical persistence corner.",
    owasp: "CIS-v8-4.1", attackId: "T1547",
    what: "Review /etc/xdg/autostart and per-user ~/.config/autostart entries via host execution for unknown or suspicious desktop entries, especially on server hosts where none are expected. Reported as findings; entries are never executed or removed.",
  },
  {
    id: "LX-080", category: "functionality", name: "Integrity monitoring on persistence paths",
    brief: "Are cron, systemd, and SSH paths covered by FIM — verify via config, no triggers.",
    owasp: "CIS-v8-4.1",
    what: "Verify via host execution that file-integrity monitoring (aide, osquery, Wazuh agent) actually covers persistence paths: /etc/cron*, systemd unit dirs, sshd_config, authorized_keys locations. Coverage is confirmed from FIM configuration — no test modifications are made to trigger alerts.",
  },
  // ============================================ ACCOUNTS & AUTHENTICATION
  {
    id: "LX-081", category: "validation", name: "Local account enumeration",
    brief: "UID 0 dupes, dormant, locked, and nologin-shell accounts — the full roster.",
    owasp: "CIS-v8-5.3", attackId: "T1087",
    what: "Enumerate local accounts via host execution (/etc/passwd, shadow expiry, lastlog): duplicate UID 0 accounts, dormant accounts, unlocked-but-unused accounts, and service users with interactive shells. Each anomaly is a finding. Read-only enumeration.",
  },
  {
    id: "LX-082", category: "validation", name: "Privileged group membership audit",
    brief: "sudo, docker, lxd, adm membership vs the authorized roster — every member justified.",
    owasp: "CIS-v8-5.4", attackId: "T1087",
    what: "List members of sudo, wheel, docker, lxd, and adm groups via host execution and compare against the client's authorized roster. Unjustified members — especially in docker or lxd, which are root-equivalent — are findings. Read-only group listing.",
  },
  {
    id: "LX-083", category: "validation", name: "Password policy audit",
    brief: "login.defs and pwquality — max age, min length, complexity, history enforced?",
    owasp: "CIS-v8-5.2",
    what: "Review /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE) and pwquality.conf (minlen, complexity, remember) via host execution against policy. Weak or unenforced settings are findings. Read-only config review.",
  },
  {
    id: "LX-084", category: "functionality", name: "Password policy enforcement proof",
    brief: "Weak-password set attempt on the authorized test account — rejection must hold.",
    owasp: "WSTG-ATHN-07",
    what: "Using ONLY the client-provided authorized test account via host execution, attempt to set a deliberately weak password and confirm it is rejected. Rejection proves enforcement; acceptance is a finding. The account's password is restored to a strong value immediately after.",
  },
  {
    id: "LX-085", category: "validation", name: "Service account shell audit",
    brief: "Service users with /bin/bash — interactive shells where nologin belongs.",
    owasp: "CIS-v8-5.5", attackId: "T1078",
    what: "List service accounts (www-data, mysql, postgres, nobody variants) with interactive shells via host execution. An interactive shell on a service account widens every compromise into an interactive foothold — reported as a finding. Read-only passwd review.",
  },
  {
    id: "LX-086", category: "validation", name: "Dormant account review",
    brief: "Accounts unused 90+ days — disable candidates and stale-access findings.",
    owasp: "CIS-v8-5.3", attackId: "T1078",
    what: "Correlate lastlog and shadow expiry data via host execution to find accounts dormant beyond the policy window. Dormant-but-enabled accounts are stale-access findings reported for disablement. Read-only; accounts are never locked by the test.",
  },
  {
    id: "LX-087", category: "validation", name: "SSH certificate authority trust audit",
    brief: "TrustedUserCAKeys and principals — who can mint SSH access to this host?",
    owasp: "CIS-v8-4.1", attackId: "T1021.004",
    what: "Review TrustedUserCAKeys, trusted CA configuration, and authorized_principals files via host execution. An overly trusted CA or wildcard principals means anyone with a CA-signed key gets in — reported as a finding. Read-only review.",
  },
  {
    id: "LX-088", category: "logic", name: "Duplicate UID 0 account detection",
    brief: "A second root-equivalent account is a backdoor until proven otherwise.",
    owasp: "CIS-v8-5.4", attackId: "T1078",
    what: "Detect any account with UID 0 beyond root itself via host execution. A duplicate UID-0 account is REPORTED as a likely backdoor or grave misconfiguration with its creation metadata. No login is attempted on the account.",
  },
  // ============================================ LOGGING & DETECTION
  {
    id: "LX-089", category: "validation", name: "Audit logging coverage audit",
    brief: "auditd/syslog capture auth events, rotate safely, and forward off-host?",
    owasp: "CIS-v8-8.2",
    what: "Verify auditd rules (or syslog auth/authpriv facility) capture authentication, sudo, and account events via host execution; check log rotation preserves evidence and that logs forward to a collector. Blind spots or local-only logs are findings. Read-only config and rule review.",
  },
  {
    id: "LX-090", category: "functionality", name: "Failed-login event fidelity check",
    brief: "One failed auth with the test account — does the event actually land in the logs?",
    owasp: "CIS-v8-8.2", attackId: "T1110",
    what: "Perform a SINGLE failed SSH login with the authorized test account via host execution, then confirm the failure event appears in auth.log/journal with correct timestamp and source. A missing event is a detection-blindness finding. One attempt only — never a guessing campaign.",
  },
  {
    id: "LX-091", category: "validation", name: "Log tampering indicator review",
    brief: "Gaps, truncation, utmp/wtmp anomalies — signs someone cleaned up.",
    owasp: "CIS-v8-8.3",
    what: "Review auth and system logs via host execution for tampering indicators: time gaps, truncated files, missing rotation archives, and utmp/wtmp/btmp anomalies. Indicators are REPORTED as compromise evidence for incident review. Read-only analysis.",
  },
  {
    id: "LX-092", category: "validation", name: "journald persistence configuration audit",
    brief: "Storage=persistent and sane rate limits — auth events must survive reboot.",
    owasp: "CIS-v8-8.3",
    what: "Verify journald Storage=persistent (or equivalent syslog persistence) and that rate limits are not silently dropping auth events via host execution. Volatile-only logging or aggressive rate-limiting is an evidence-loss finding. Read-only config review.",
  },
  // ============================================ NETWORK POSTURE
  {
    id: "LX-093", category: "validation", name: "Egress filtering posture review",
    brief: "Outbound to benign endpoints on expected ports only — document unexpected egress.",
    owasp: "CIS-v8-4.4",
    what: "Test outbound connectivity from the host via host execution to benign endpoints on expected ports (DNS, HTTPS) and document any unexpected egress (unfiltered high ports, direct outbound SMTP). Unexpected egress is a data-exfiltration and C2 finding. Benign endpoints only; no external attack traffic.",
  },
  {
    id: "LX-094", category: "validation", name: "Resolver and hosts-file integrity audit",
    brief: "/etc/hosts hijack entries and resolv.conf — the name-resolution trust check.",
    owasp: "CIS-v8-4.1", attackId: "T1556",
    what: "Review /etc/hosts, /etc/resolv.conf, and /etc/nsswitch.conf via host execution for hijack entries (security domains pinned to attacker IPs), rogue nameservers, and unexpected resolution order. Findings are REPORTED; resolver config is never changed.",
  },
  {
    id: "LX-095", category: "validation", name: "Default route and gateway sanity check",
    brief: "Unexpected gateways or rogue routes — the traffic-interception surface.",
    owasp: "CIS-v8-4.1",
    what: "Review the routing table (ip route) via host execution against the expected gateway and routes. Rogue default routes or unexpected static routes indicate traffic interception capability and are reported as findings. Read-only route review.",
  },
  {
    id: "LX-096", category: "validation", name: "Promiscuous interfaces and sniffing tools audit",
    brief: "tcpdump/Wireshark present, interfaces in promiscuous mode — sniffing capability check.",
    owasp: "CIS-v8-4.1",
    what: "Check for packet-capture tools (tcpdump, tshark) and interfaces in promiscuous mode via host execution. On a server host these indicate either legitimate troubleshooting residue or sniffing capability — reported for justification. Read-only checks; no capture is started.",
  },
  {
    id: "LX-097", category: "functionality", name: "Firewall default-deny verification",
    brief: "Unsolicited inbound is actually dropped — minimal single probes per port class.",
    owasp: "CIS-v8-4.4", attackId: "T1018",
    what: "Verify the inbound default-deny posture from outside via host execution context with a minimal set of single benign connection attempts (one per port class, closed immediately) against non-listening ports. Dropped/refused confirms the posture; an answer where LX-010 expects none is a finding. Never a sweep.",
    blackNote: "One probe per port class from a single source; the drop-or-answer verdict is the finding.",
  },
  // ============================================ KERNEL & SYSTEM HARDENING
  {
    id: "LX-098", category: "validation", name: "Kernel hardening knobs audit",
    brief: "kptr_restrict, dmesg_restrict, userns limits, kexec — the privesc-mitigating sysctls.",
    owasp: "CIS-v8-4.1", attackId: "T1068",
    what: "Verify kernel hardening sysctls via host execution: kernel.kptr_restrict, kernel.dmesg_restrict, kernel.perf_event_paranoid, kernel.unprivileged_userns_clone (where applicable), and kernel.kexec_load_disabled. Disabled knobs widen every privesc path and are reported as such. Read-only sysctl reads.",
  },
  {
    id: "LX-099", category: "validation", name: "Loaded kernel modules audit",
    brief: "Unsigned, out-of-tree, or suspicious modules — the ring-0 persistence check.",
    owasp: "CIS-v8-4.1", attackId: "T1547",
    what: "List loaded kernel modules (lsmod, modinfo) via host execution and flag unsigned, out-of-tree, or otherwise suspicious modules against the expected set. An unexpected module is a REPORTED persistence/compromise indicator. Read-only listing; modules are never loaded or unloaded.",
  },
  {
    id: "LX-100", category: "validation", name: "Secure boot and module signing status",
    brief: "mokutil and lockdown mode — is the boot chain actually enforcing signatures?",
    owasp: "CIS-v8-4.1", attackId: "T1547",
    what: "Check Secure Boot state (mokutil --sb-state) and kernel lockdown mode via host execution. Disabled Secure Boot or permissive lockdown undermines module-signing enforcement — reported as a finding. Read-only status checks.",
  },
  {
    id: "LX-101", category: "validation", name: "Core dump policy audit",
    brief: "Setuid core dumps disabled — memory of privileged processes must not hit disk.",
    owasp: "CIS-v8-4.1",
    what: "Verify fs.suid_dumpable=0 (or 2 with a safe pattern) and a restrictive kernel.core_pattern via host execution. Enabled setuid core dumps can spill privileged memory — including secrets — to disk. Read-only sysctl review.",
  },
  {
    id: "LX-102", category: "validation", name: "/etc/fstab mount hygiene audit",
    brief: "noexec/nosuid on tmp and removable media — mount options as a control.",
    owasp: "CIS-v8-4.1",
    what: "Review /etc/fstab and active mounts via host execution for missing noexec/nosuid/nodev on /tmp, /var/tmp, /dev/shm, and removable media, plus any user-writable system mounts. Weak mount options are hardening findings. Read-only review; nothing is remounted.",
  },
  {
    id: "LX-103", category: "validation", name: "Kernel patch-cadence exposure window",
    brief: "Days since last kernel update vs CVE publication — the exposure window grade.",
    owasp: "CIS-v8-2.2", attackId: "T1068",
    what: "Compare the running kernel's build/install date against the publication dates of known local-privesc CVEs via host execution. A wide exposure window (known privesc CVE public for months while the kernel predates the fix) is graded as a finding. Version and date arithmetic only.",
  },
  // ============================================ CROSS-CUTTING CHAINS
  {
    id: "LX-104", category: "logic", name: "Privilege-escalation chain synthesis",
    brief: "Combine all privesc findings into the single highest-privilege path narrative.",
    owasp: "WSTG-BUSL", attackId: "T1548",
    what: "Synthesize every privesc-relevant finding (LX-025…LX-048) into the concrete highest-privilege chain from the test user's starting position: which finding composes with which, in what order. Pure analysis over gathered evidence — no new execution, no chain is ever walked end to end.",
  },
  {
    id: "LX-105", category: "logic", name: "Found-credential exposure mapping",
    brief: "Every location a found credential would be valid — verified only per ROE test accounts.",
    owasp: "WSTG-ATHN", attackId: "T1078",
    what: "For every credential found during the engagement (keys, passwords in files), document every service and account where it would be valid via analysis. Verification logins use ONLY client-provided authorized test accounts per the ROE — found credentials are never replayed against real accounts.",
  },
  {
    id: "LX-106", category: "logic", name: "Host lateral-movement surface map",
    brief: "known_hosts trust, shared keys, SSH CA — in-scope lateral paths documented, never walked.",
    owasp: "WSTG-CONF", attackId: "T1018",
    what: "Map the host's lateral-movement surface via host execution: known_hosts entries, shared private keys, SSH CA trust, and NFS/SMB mounts pointing at other in-scope hosts. Paths are DOCUMENTED as a map — lateral movement is never executed beyond authorized test-account logins.",
    blackNote: "Build the map from config files only; no connection attempts to neighboring hosts.",
  },
];

export const LINUX_PROFILE: TargetProfile = {
  id: "linux",
  name: "Linux host",
  baseUrl: "in-scope hosts (ROE scope)",
  kind: "host-linux",
  authModel: "SSH keys/passwords; sudo for elevation. Credential testing against client-PROVIDED authorized test accounts ONLY (T1078) — never guessed, never stuffed.",
  scopeNotes: "Non-destructive always: read-only enumeration preferred; no service crashing; no destructive payloads; persistence mechanisms REPORTED as findings, never planted; privesc proofs are safe non-destructive checks.",
  battery: LINUX_BATTERY,
};
