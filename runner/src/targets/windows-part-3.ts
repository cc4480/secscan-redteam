/**
 * WINDOWS battery — part 3 of 5 (v0.19.0 refactor split).
 * Starts at section: PRIVILEGE ESCALATION
 *
 * Pure data split of windows.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by windows.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_HUMAN_OPERATOR, NEEDS_KERBEROS_TICKET, NEEDS_MSFRPCD } from "./types.js";

export const WINDOWS_PART_3: TargetBatteryItem[] = [
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
];
