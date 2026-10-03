/**
 * Host ATT&CK techniques (v0.8.0: Windows / Linux) for the host batteries.
 */

import type { AttackTechnique } from "./techniques-web.js";

const HOST_TECHNIQUES: AttackTechnique[] = [
  {
    id: "T1018",
    name: "Remote System Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "Host and service discovery against in-scope hosts — port scans, banner " +
      "grabs, fingerprinting. Read-only; no exploitation.",
  },
  {
    id: "T1083",
    name: "File and Directory Discovery",
    tactic: "Discovery",
    phases: ["recon", "exploit"],
    noise: "low",
    description:
      "Enumerating files and directories on reachable hosts and shares " +
      "(SMB/NFS listings, readable paths). Read-only enumeration.",
  },
  {
    id: "T1135",
    name: "Network Share Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "SMB/NFS share enumeration on in-scope hosts — share names and " +
      "permissions mapping. No data exfiltration.",
  },
  {
    id: "T1033",
    name: "System Owner/User Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "Enumerating users, groups, and sessions on in-scope hosts via " +
      "authorized channels. Read-only.",
  },
  {
    id: "T1082",
    name: "System Information Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "OS version, hostname, domain membership, and patch-level discovery " +
      "on in-scope hosts. Read-only.",
  },
  {
    id: "T1518",
    name: "Software Discovery",
    tactic: "Discovery",
    phases: ["recon"],
    noise: "low",
    description:
      "Installed-software and service-version discovery on in-scope hosts " +
      "for CVE correlation. Read-only.",
  },
  {
    id: "T1021",
    name: "Remote Services",
    tactic: "Lateral Movement",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Using RDP/SMB/WinRM/SSH sessions with client-PROVIDED test-account " +
      "credentials only (never guessed). Authorized scope, fully logged.",
  },
  {
    id: "T1021.004",
    name: "Remote Services: SSH",
    tactic: "Lateral Movement",
    phases: ["exploit"],
    noise: "medium",
    description:
      "SSH sessions with authorized test-account credentials or provided " +
      "keys only. Agent-forwarding and config abuse tested, never pivoted " +
      "beyond scope.",
  },
  {
    id: "T1047",
    name: "Windows Management Instrumentation",
    tactic: "Execution",
    phases: ["exploit"],
    noise: "medium",
    description:
      "WMI for authorized enumeration and execution on Windows hosts in " +
      "scope. Non-destructive queries and test-account execution only.",
  },
  {
    id: "T1053",
    name: "Scheduled Task/Job",
    tactic: "Execution",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Scheduled-task abuse paths (schtasks, cron, at, systemd timers): " +
      "audited read-only; execution only against tasks owned by authorized " +
      "test accounts. Findings reported, never planted.",
  },
  {
    id: "T1547",
    name: "Boot or Logon Autostart Execution",
    tactic: "Persistence",
    phases: ["exploit"],
    noise: "low",
    description:
      "Persistence MECHANISMS audited as findings (run keys, systemd units, " +
      "services, authorized_keys) — reported, never planted by the runner.",
  },
  {
    id: "T1003",
    name: "OS Credential Dumping",
    tactic: "Credential Access",
    phases: ["exploit"],
    noise: "high",
    description:
      "Credential-dumping EXPOSURE audited (LSASS protections, hive " +
      "permissions, credential files) — authorized scope only. Findings " +
      "reported; nothing exfiltrated beyond evidence needs.",
  },
  {
    id: "T1210",
    name: "Exploitation of Remote Services",
    tactic: "Lateral Movement",
    phases: ["exploit"],
    noise: "high",
    description:
      "Testing remotely exploitable services (EternalBlue-class, RCE in " +
      "exposed services) against authorized test hosts only. Non-destructive " +
      "proof — never weaponized beyond a safe check.",
  },
  {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    tactic: "Privilege Escalation",
    phases: ["exploit"],
    noise: "medium",
    description:
      "Kernel and local privilege-escalation CVEs tested against authorized " +
      "test hosts only, with safe non-destructive checks.",
  },
  {
    id: "T1548",
    name: "Abuse Elevation Control Mechanism",
    tactic: "Privilege Escalation",
    phases: ["exploit"],
    noise: "medium",
    description:
      "sudo/sudo-caching, setuid/setgid binaries, and Windows " +
      "AlwaysInstallElevated tested with authorized test accounts. " +
      "Non-destructive proof only.",
  },
  {
    id: "T1574",
    name: "Hijack Execution Flow",
    tactic: "Privilege Escalation",
    phases: ["exploit"],
    noise: "medium",
    description:
      "DLL hijacking, PATH interception, and unquoted service paths — " +
      "writable-location proof with benign canary files, never real payloads.",
  },
  {
    id: "T1499",
    name: "Endpoint Denial of Service",
    tactic: "Impact",
    phases: [],
    noise: "high",
    description:
      "ALWAYS excluded. The runner never performs DoS or resource exhaustion. " +
      "Listed so plans that mention it are rejected loudly.",
  },
];

export { HOST_TECHNIQUES };
