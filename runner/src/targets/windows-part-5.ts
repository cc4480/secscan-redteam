/**
 * WINDOWS battery — part 5 of 5 (v0.19.0 refactor split).
 * Starts at section: EDR / AV AWARENESS
 *
 * Pure data split of windows.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by windows.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_HUMAN_OPERATOR, NEEDS_KERBEROS_TICKET, NEEDS_MSFRPCD, NEEDS_NUCLEI } from "./types.js";

export const WINDOWS_PART_5: TargetBatteryItem[] = [
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
  // ------------------------------------------------- TEMPLATE-BASED CHECKS
  // (v0.21.0, Nuclei bridge). Same dynamic methodology as the Metasploit
  // bridge: the operator's local Nuclei template checkout (~10k community
  // templates) is resolved at runtime, never hardcoded. nuclei_exec
  // templates selects (recon-safe); nuclei_exec run executes against ONE
  // scope-checked host in the exploit phase. Findings overlapping a battery
  // item are ONE finding with two evidence sources; template-only findings
  // become runtime instances under WS-108.
  {
    id: "WS-108", category: "functionality", name: "Template-based checks via Nuclei",
    brief: "Nuclei templates selected and executed against in-scope hosts; overlaps deduped.",
    owasp: "CIS-v8-4.4", attackId: "T1595.002", needs: NEEDS_NUCLEI,
    what: "Use nuclei_exec templates (recon-safe, no target touched) to select templates by id/tag/severity/CVE from the operator's local checkout, then nuclei_exec run in the exploit phase against ONE scope-checked host per run. dos-tagged templates are refused by policy on every run; the target URL is runner-built from the scope-checked host. Tag attackId T1595.002. A finding overlapping an existing battery item is recorded ONCE with both evidence sources; template-only findings become runtime instances under this item.",
    blackNote: "Narrow template selection (id/CVE-specific first); stop on first defender signal.",
  },
];
