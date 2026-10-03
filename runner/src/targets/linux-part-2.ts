/**
 * LINUX battery — part 2 of 5 (v0.19.0 refactor split).
 * Starts at section: PRIVILEGE ESCALATION
 *
 * Pure data split of linux.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by linux.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_MSFRPCD, NEEDS_PRIVILEGED_CLIENT } from "./types.js";

export const LINUX_PART_2: TargetBatteryItem[] = [
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
    what: "Where an export carries no_root_squash (LX-042), mount it from an in-scope test client via host execution and prove root squashing is disabled by creating a benign test file as uid 0, then delete the file. Executes TODAY in two stages: (1) the runner's nfs_enum tool lists exports userland (RPC portmapper + MOUNT protocol, no privileges needed); (2) the mount+file proof runs via ssh_exec on the operator-designated privileged test client (REDTEAM_NFS_TEST_CLIENT, must be in scope). No setuid binaries are written; the mount and file are cleaned up. Writable-export evidence only.",
    needs: NEEDS_PRIVILEGED_CLIENT,
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
];
