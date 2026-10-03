/**
 * WINDOWS battery — part 4 of 5 (v0.19.0 refactor split).
 * Starts at section: CREDENTIAL-ACCESS EXPOSURE — AUDITED, REPORTED
 *
 * Pure data split of windows.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by windows.ts.
 */

import type { TargetBatteryItem } from "./types.js";
import { NEEDS_HUMAN_OPERATOR, NEEDS_KERBEROS_TICKET, NEEDS_MSFRPCD } from "./types.js";

export const WINDOWS_PART_4: TargetBatteryItem[] = [
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
];
