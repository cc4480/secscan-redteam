# Runner Roadmap

## Host-exec tooling — DELIVERED (v0.9.0)

**Status:** the host-exec track is built, tested, and live in
`runner/src/host-exec/`. The Windows (WS-*) and Linux (LX-*) batteries are
no longer plan-only: 400 of 410 items are executable.

**What landed:**

1. **ssh-exec** (`ssh_exec` agent tool) — non-interactive SSH command
   execution against in-scope Linux hosts, via `ssh2` (actively maintained).
   Test-account credentials from environment/Secure Vault only.
2. **smb-exec** (`smb_exec` agent tool) — SMB session + share reachability
   probing + directory listing against in-scope Windows hosts, via
   `@marsaud/smb2` (most complete Node SMB2 implementation; no NetShareEnum
   support — `list_shares` is reachability probing of well-known +
   recon-supplied names, documented in code).
3. **winrm-exec** (`winrm_exec` agent tool) — non-interactive PowerShell/cmd
   execution against in-scope Windows hosts, via `winrm-client` (recently
   maintained; no abort handle — the kill switch races abandonment,
   documented in code).

**Non-negotiable properties — all mechanical, all tested:**

- **Scope enforcement** — the target host must exactly match the ROE-declared
  scope; anything else is rejected before any packet is sent (fail closed).
- **Destructive-command denylist** — `rm -rf /`, `mkfs`, `dd of=/dev/*`,
  disk wipes, shutdown/reboot, shadow-copy deletion, ransomware patterns,
  and more are refused mechanically (fail closed). Documented in
  `host-exec/common.ts`.
- **Credential discipline** — `REDTEAM_SSH_USER`/`REDTEAM_SSH_PASSWORD` (or
  `REDTEAM_SSH_KEY`/`REDTEAM_SSH_KEY_PATH`), `REDTEAM_SMB_USER`/
  `REDTEAM_SMB_PASSWORD` (+ optional `REDTEAM_SMB_DOMAIN`),
  `REDTEAM_WINRM_USER`/`REDTEAM_WINRM_PASSWORD`. Never in code, never in
  args, never in logs/errors/events (redaction tested). Fail fast with an
  actionable message when missing. T1078 is mechanical: provided test
  accounts only.
- **Audit logging** — every invocation lands in the JSONL operation log
  (time, phase, actor, tool, target host, redacted command summary, result
  summary) like any other probe; the console feed shows host actions.
- **Kill switch** — coordinator abort sets the shared abort flag and aborts
  every registered in-flight execution across all parallel tasks; new host
  work is refused once aborted.
- **Timeouts + output caps** — 30s default timeout, 8KB output cap (no bulk
  exfiltration through the tool).

**Remaining plan-only items (10):** interactive RDP logon (WS-019), WinRM
listener probe without session (WS-010), pass-the-hash (WS-023),
BloodHound collector tooling (WS-038), AD CS tooling (WS-043),
pass-the-ticket (WS-064), RDP session shadowing (WS-065), SSH
agent-forwarding channels (LX-018/LX-019), NFS test-client mounts (LX-041).
These keep `needs: "host-exec tooling"` honestly and are named as plan-only
items in the report under Honest limits — planned, not probed, never faked.

## Beyond

- Console: surface the 12-cell coverage (✓/⊘/…) and the unified Megazord
  narrative per target in the Live header.
- Registry: host findings (privesc paths, AD attack paths) compound into
  the registry like web findings do today.
- Retest mode: re-run a previous engagement's battery against a new
  deployment and diff the results — the resident-adversary loop.
