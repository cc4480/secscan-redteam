/**
 * LINUX battery — part 4 of 5 (v0.19.0 refactor split).
 * Starts at section: PERSISTENCE FINDINGS (reported, never planted)
 *
 * Pure data split of linux.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by linux.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_MSFRPCD, NEEDS_PRIVILEGED_CLIENT } from "./types.js";

export const LINUX_PART_4: TargetBatteryItem[] = [
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
];
