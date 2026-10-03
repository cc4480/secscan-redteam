/**
 * Host-execution tool definitions (ssh/smb/winrm/rdp/ad/krb/nfs).
 */
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";

const SSH_EXEC_TOOL: JsonSchemaTool = {
  name: "ssh_exec",
  description:
    "Execute ONE non-interactive command on an in-scope Linux host over SSH (test-account credentials resolved from the environment — NEVER put credentials in the command). In-scope hosts only (runner-enforced), destructive commands refused by denylist, 30s timeout, output capped. Include attackId, category (logic|functionality|validation), targetProfile (must be 'linux' — host targets are never inferred), and a one-sentence hypothesis. Prefer read-only enumeration (ss, uname, dpkg, find, sudo -l, systemctl) before anything state-changing.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      port: { type: "number" },
      command: { type: "string" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["linux"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "command", "category"],
  },
};

const SMB_EXEC_TOOL: JsonSchemaTool = {
  name: "smb_exec",
  description:
    "SMB operations against an in-scope Windows host (test-account credentials resolved from the environment — NEVER put credentials in args). Operations: list_shares (reachability probe of well-known + recon-supplied share names — the library has no NetShareEnum, so this is reachability not full enumeration), list_dir (list a directory on a share), stat (check one path). In-scope hosts only (runner-enforced), read-only — the tool offers no writes. Include attackId, category, targetProfile ('windows' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      operation: { type: "string", enum: ["list_shares", "list_dir", "stat"] },
      share: { type: "string" },
      path: { type: "string" },
      extraShares: { type: "array", items: { type: "string" } },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "operation", "category"],
  },
};

const WINRM_EXEC_TOOL: JsonSchemaTool = {
  name: "winrm_exec",
  description:
    "Execute ONE non-interactive command on an in-scope Windows host over WinRM (test-account credentials resolved from the environment — NEVER put credentials in the command). powershell=true (default) runs PowerShell — prefer it for structured enumeration (Get-Service, Get-ScheduledTask, Get-ItemProperty); powershell=false runs cmd.exe. In-scope hosts only (runner-enforced), destructive commands refused by denylist, 30s timeout, output capped. Include attackId, category, targetProfile ('windows' — never inferred), hypothesis. Prefer read-only enumeration before anything state-changing.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      port: { type: "number" },
      command: { type: "string" },
      powershell: { type: "boolean" },
      useTls: { type: "boolean" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "command", "category"],
  },
};

/** Host tools: available to recon and exploiter during host phases. */
const WINRM_PROBE_TOOL: JsonSchemaTool = {
  name: "winrm_probe",
  description:
    "Probe TCP 5985/5986 for WinRM listeners WITHOUT creating a session: unauthenticated POST to /wsman, recording the advertised auth schemes from the 401 WWW-Authenticate headers (Negotiate/Kerberos/NTLM/CredSSP/Basic) and TLS posture on 5986. Presence and scheme disclosure only — no credentials used. Include attackId, category, targetProfile ('windows' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      ports: { type: "array", items: { type: "number" } },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "category"],
  },
};

const RDP_AUTH_TOOL: JsonSchemaTool = {
  name: "rdp_auth",
  description:
    "Validate the authorized test account's RDP credential via NLA (CredSSP/NTLMv2) — headless, no desktop session. Flow: X.224 negotiation requesting NLA, TLS upgrade, CredSSP handshake; the server's affirmative handshake completion IS the validation, then the connection closes immediately. If the server does not offer NLA, no validation is attempted (the absent NLA is the finding). Test-account credentials resolved from the environment — NEVER in args. In-scope hosts only (runner-enforced). Include attackId, category, targetProfile ('windows' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      port: { type: "number" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "category"],
  },
};

const RDP_SHADOW_PREP_TOOL: JsonSchemaTool = {
  name: "rdp_shadow_prep",
  description:
    "Prepare RDP session shadowing for a HUMAN operator — the runner never shadows. Read-only WinRM enumeration of live RDP session IDs and shadow policy/permission state, producing a complete handoff package: exact shadow command, consent/ROE checklist, what to observe and record. The shadowing act itself needs a human operator in a GUI session (needs: human operator). Test-account credentials from the environment. In-scope hosts only. Include attackId, category, targetProfile ('windows'), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "category"],
  },
};

const SMB_PTH_TOOL: JsonSchemaTool = {
  name: "smb_pth",
  description:
    "Pass-the-hash: test whether the test account's OWN NT hash (REDTEAM_SMB_NTHASH, client-provided — never dumped, never another principal's) authenticates to in-scope SMB. Raw-socket SMB2 NEGOTIATE + SESSION_SETUP with NTLMv2 keyed by the hash; STATUS_SUCCESS = PtH works. Session logged off immediately; no share touched. The hash is handled with password-grade secrecy (never in args, never logged). In-scope hosts only (runner-enforced). Include attackId, category, targetProfile ('windows' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      port: { type: "number" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "category"],
  },
};

const AD_ENUM_TOOL: JsonSchemaTool = {
  name: "ad_enum",
  description:
    "Read-only LDAP Active Directory enumeration as the authorized test account (ldapts simple bind; test-account credentials from the environment — NEVER in args). Operations (pick what the item needs): users, groups, computers, trusts, ous, gpos, acls (binary security-descriptor parsing for dangerous grants to non-Tier-0 principals), attack_paths (BloodHound-style shortest paths to Tier-0, COMPUTED OFFLINE — never executed), adcs (certificate template audit for ESC1/ESC2/ESC4 conditions — DETECTION ONLY, no cert requested). Nothing is ever written to the directory. In-scope hosts only (runner-enforced). Include attackId, category, targetProfile ('windows' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      port: { type: "number" },
      useTls: { type: "boolean" },
      baseDn: { type: "string" },
      operations: { type: "array", items: { type: "string", enum: ["users", "groups", "computers", "trusts", "ous", "gpos", "acls", "attack_paths", "adcs"] } },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "operations", "category"],
  },
};

const KRB_PTT_TOOL: JsonSchemaTool = {
  name: "krb_ptt",
  description:
    "Pass-the-ticket: replay the test account's OWN Kerberos tickets (needs: kerberos ticket material). Sources: REDTEAM_KRB_CCACHE_B64 / REDTEAM_KRB_CCACHE_PATH / REDTEAM_KRB_KIRBI_B64, or kinit as the test account itself (legitimately obtained). The ticket is replayed ccache-only (KRB5CCNAME); klist confirms presence/validity and kvno against an in-scope SPN proves KDC acceptance. Only the test account's own tickets — no forging, no silver/golden tickets. Requires MIT krb5 user tools on the runner host. In-scope hosts/SPNs only (runner-enforced). Include attackId, category, targetProfile ('windows' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      spn: { type: "string" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "category"],
  },
};

const SSH_AGENT_AUDIT_TOOL: JsonSchemaTool = {
  name: "ssh_agent_audit",
  description:
    "SSH agent-forwarding audit (modes: socket-check | abuse-path). Connects WITH agent forwarding (needs a local agent socket: REDTEAM_SSH_AGENT_SOCKET or SSH_AUTH_SOCK) and verifies whether the agent socket is exposed on the remote host (presence, permissions) or — in abuse-path mode — documents which local users could reach it and how a host compromise would pivot through it. ANALYSIS ONLY: the socket is never used for onward authentication. Test-account credentials from the environment. In-scope hosts only. Include attackId, category, targetProfile ('linux' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      port: { type: "number" },
      mode: { type: "string", enum: ["socket-check", "abuse-path"] },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["linux"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "mode", "category"],
  },
};

const NFS_ENUM_TOOL: JsonSchemaTool = {
  name: "nfs_enum",
  description:
    "Userland NFS export enumeration: RPC portmapper + MOUNT protocol EXPORT listing (no kernel mount, no privileges needed, no credentials). Reports exported paths and client grants — the evidence for no_root_squash/world-export findings. For LX-041's mount+file proof, use ssh_exec on the operator-designated privileged test client (REDTEAM_NFS_TEST_CLIENT, must be in scope): mount there, create+delete a benign uid-0 test file, unmount. In-scope hosts only (runner-enforced). Include attackId, category, targetProfile ('linux' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      host: { type: "string" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["linux"] },
      hypothesis: { type: "string" },
    },
    required: ["host", "category"],
  },
};

export const HOST_TOOLS = [SSH_EXEC_TOOL, SMB_EXEC_TOOL, WINRM_EXEC_TOOL, WINRM_PROBE_TOOL, RDP_AUTH_TOOL, RDP_SHADOW_PREP_TOOL, SMB_PTH_TOOL, AD_ENUM_TOOL, KRB_PTT_TOOL, SSH_AGENT_AUDIT_TOOL, NFS_ENUM_TOOL];
