/**
 * LINUX battery — part 3 of 5 (v0.19.0 refactor split).
 * Starts at section: EXPOSED SERVICES (audited as FINDINGS)
 *
 * Pure data split of linux.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by linux.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_MSFRPCD, NEEDS_PRIVILEGED_CLIENT } from "./types.js";

export const LINUX_PART_3: TargetBatteryItem[] = [
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
];
