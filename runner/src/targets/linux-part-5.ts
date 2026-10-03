/**
 * LINUX battery — part 5 of 5 (v0.19.0 refactor split).
 * Starts at section: LOGGING & DETECTION
 *
 * Pure data split of linux.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by linux.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_MSFRPCD, NEEDS_NUCLEI, NEEDS_PRIVILEGED_CLIENT } from "./types.js";

export const LINUX_PART_5: TargetBatteryItem[] = [
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
  // ------------------------------------------------- CVE EXPLOIT VALIDATION
  // (v0.11.0, Metasploit bridge). Same dynamic methodology as WS-105…107:
  // recon detects a service/version → msf_exec suggest → coordinator
  // approves → msf_exec run fires ONE module with the benign canary marker.
  // Each CVE validated at runtime becomes a per-CVE instance (attackId
  // "MSF-CVE-…") reconciling against coverage via its category.
  {
    id: "LX-107", category: "logic", name: "CVE → Metasploit module mapping",
    brief: "Detected service/version mapped to candidate CVE exploit modules for coordinator approval.",
    owasp: "CIS-v8-4.4", attackId: "T1190", needs: NEEDS_MSFRPCD,
    what: "For every versioned service detected during recon (SSH, HTTP, FTP, NFS, SMB…), run msf_exec suggest with the service and version string and present the ranked candidate exploit modules to the coordinator for approval. Mapping only — nothing fires. Methodology item: each CVE approved downstream becomes its own runtime instance.",
  },
  {
    id: "LX-108", category: "functionality", name: "CVE exploit validation via Metasploit",
    brief: "Coordinator-approved CVE modules fired with benign canary marker payloads.",
    owasp: "CIS-v8-4.4", attackId: "T1190", needs: NEEDS_MSFRPCD,
    what: "For each coordinator-approved candidate from LX-107, run msf_exec run in the exploit phase: ONE module, generic cmd payload executing ONLY the runner-built canary marker (echo REDTEAM-MARKER-*). The marker echoing back IS the validation — command execution achieved. dos/destructive modules are refused by policy; stray sessions are stopped by hygiene. Tag attackId T1190 and put the CVE in the cve field — each validated CVE is recorded as its own report instance.",
    blackNote: "One module per CVE; lowest-rank-sufficient module first; stop on first defender signal.",
  },
  {
    id: "LX-109", category: "validation", name: "Metasploit auxiliary validation rigor",
    brief: "Auxiliary scanner findings cross-validated; module ranks sanity-checked.",
    owasp: "CIS-v8-4.4", attackId: "T1595.002", needs: NEEDS_MSFRPCD,
    what: "Cross-validate auxiliary-module findings (ssh_enumusers, http scanners, etc.) against direct host-exec evidence (ssh_exec version checks, banner reads) — two independent observations before a finding. Sanity-check module ranks against observed behavior; a high-rank module that fails silently is reported as a coverage note, not a finding.",
  },
  // ------------------------------------------------- TEMPLATE-BASED CHECKS
  // (v0.21.0, Nuclei bridge). Same dynamic methodology as the Metasploit
  // bridge: the operator's local Nuclei template checkout (~10k community
  // templates) is resolved at runtime, never hardcoded. nuclei_exec
  // templates selects (recon-safe); nuclei_exec run executes against ONE
  // scope-checked host in the exploit phase. Findings overlapping a battery
  // item are ONE finding with two evidence sources; template-only findings
  // become runtime instances under LX-110.
  {
    id: "LX-110", category: "functionality", name: "Template-based checks via Nuclei",
    brief: "Nuclei templates selected and executed against in-scope hosts; overlaps deduped.",
    owasp: "CIS-v8-4.4", attackId: "T1595.002", needs: NEEDS_NUCLEI,
    what: "Use nuclei_exec templates (recon-safe, no target touched) to select templates by id/tag/severity/CVE from the operator's local checkout, then nuclei_exec run in the exploit phase against ONE scope-checked host per run. dos-tagged templates are refused by policy on every run; the target URL is runner-built from the scope-checked host. Tag attackId T1595.002. A finding overlapping an existing battery item is recorded ONCE with both evidence sources; template-only findings become runtime instances under this item.",
    blackNote: "Narrow template selection (id/CVE-specific first); stop on first defender signal.",
  },
];
