# The Full Battery — Four Targets, One Unified Engagement (v0.11.0)

This is the culmination of the red-team line: a single operation that tests
**four** targets end to end — SecScan (the scanner webapp), SecLayer (the
MCP/API layer), Windows (host + Active Directory), and Linux (host) — as one
adversary would actually see them. Not a sample. Not a representative subset.
**Everything.**

> Renamed in v0.8.0 from `full-battery-secscan-seclayer.md` — the battery
> outgrew two targets.

## The numbers

- **SecScan: 120 attack items** (SS-001…SS-120) — validation 34, logic 58, functionality 28
- **SecLayer: 80 attack items** (SL-001…SL-080) — logic 25, validation 28, functionality 27
- **Windows: 107 attack items** (WS-001…WS-107) — validation 65, logic 24, functionality 18
- **Linux: 109 attack items** (LX-001…LX-109) — validation 61, logic 29, functionality 19
- **416 total static items**, each one a distinct attacker intent with a concrete target:
  the actual endpoint, flow, mechanism, or parameter, and the exact abuse —
  **plus dynamic per-CVE runtime instances** from the Metasploit bridge
  (see below): each CVE validated becomes its own report instance.

## Methodology: surface × technique

The battery wasn't written as a list of clever tricks. It was built as a
matrix:

1. **Enumerate every attack surface per target.** For SecScan: the intake URL
   field, the SSRF guard, the DNS TXT ownership gate, the scan lifecycle,
   scan listing, report view/export, share links, AI opt-out, rate limits,
   auth/session, the API surface, TLS/headers/CORS, error handlers. For
   SecLayer: the MCP handshake, capability negotiation, tools/list, every
   tool with every parameter attacked individually, notifications, ping,
   cancellation, progress, batching, the JSON-RPC layer itself, the auth
   layer per method, the HTTP layer, WAF behavior. For Windows: SMB/shares,
   RDP/WinRM, auth attacks, Active Directory (trusts, delegation, GPOs,
   ACLs), privilege escalation, lateral movement, credential-exposure audit,
   persistence findings, EDR/AV posture. For Linux: SSH, privilege
   escalation (SUID, sudo, capabilities, cron, kernel, containers), exposed
   services, file-permission and secret auditing, persistence findings.
2. **Apply every relevant technique to each surface.** Each distinct attacker
   intent — one item. IDOR on a scan report is a different item from IDOR on
   a share link, because the trust boundary, the failure mode, and the
   evidence are all different. A SUID binary on Linux is a different item
   from AlwaysInstallElevated on Windows, for the same reason.

Generic batteries test "a webapp." This battery tests **these** targets.

## Scanner efficacy: the red team validates the scanner

The red team doesn't just attack SecScan, it adversarially validates what
SecScan *claims to do*. Canary targets with known planted flaws (reflected
XSS, SQLi errors, missing headers, exposed .git, weak TLS, open redirects,
verbose errors, vulnerable JS libraries) verify the scanner actually detects
what it promises. A clean hardened canary checks precision (no false
positives); severity-graded plants check calibration. A scanner that misses
or misgrades is a finding against the product itself.

Non-destructive, canary targets only — detection-validation, not abuse.

## Host batteries: executed, not just planned (v0.9.0)

The Windows and Linux batteries are exhaustive *and* executable. The
runner's host-exec layer (`runner/src/host-exec/`) gives the agents real
hands on hosts:

- **Executable now**: `ssh_exec` (non-interactive SSH command execution on
  Linux hosts), `smb_exec` (share reachability probing + directory listing
  on Windows hosts), `winrm_exec` (PowerShell/cmd command execution on
  Windows hosts) — plus the existing `http_probe` for HTTP(S) banner/TLS/
  headers on host web ports — plus the v0.10.0 wave: `winrm_probe` (WS-010),
  `rdp_auth` (WS-019 NLA validation), `smb_pth` (WS-023 NTLMv2
  pass-the-hash), `ad_enum` (WS-038 offline attack paths + WS-043 AD CS
  template audit), `krb_ptt` (WS-064 ticket replay via MIT krb5 tools),
  `ssh_agent_audit` (LX-018/LX-019), `nfs_enum` (LX-041 export listing),
  `rdp_shadow_prep` (WS-065 handoff preparation). These count toward their
  coverage cells normally.
- **Honest prerequisites** (`[needs: ...]`): 9 items execute when the
  operator meets the prerequisite — WS-064 needs kerberos ticket material,
  LX-041's mount proof needs a privileged test client, WS-065 needs a human
  operator for the shadowing act itself (the runner prepares everything up
  to that step), and the 6 CVE exploit-validation items (WS-105…107,
  LX-107…109) need the operator's msfrpcd. Nothing is plan-only anymore;
  the report names each item with its prerequisite under Honest limits.

Every host invocation flows through the safety core: ROE-scope check (fail
closed, before any packet), destructive-command denylist (fail closed),
test-account credentials from environment/Secure Vault only (never in args,
never logged), 30s timeouts, capped output, and a coordinator kill switch
that terminates in-flight executions. Every invocation lands in the JSONL
operation log like any other probe. See [ROADMAP.md](ROADMAP.md) for the
delivered track.

## CVE exploit validation: the Metasploit bridge (v0.11.0)

The 416-item battery covers technique *classes* — what Metasploit's
auxiliary and post modules do, mapped to ATT&CK. What it cannot hardcode is
Metasploit's ~2,000 **CVE-specific exploits**. The bridge (`runner/src/msf/`,
agent tool `msf_exec`) closes that gap dynamically — no CVE list is baked
in:

1. **Enumerate** — recon detects versioned services (banners, `http_probe`,
   `ssh_exec`/`winrm_exec` version reads).
2. **Map** — `msf_exec suggest` takes the service + version string and
   returns *ranked* candidate modules (CVE-exact queries first, service
   fuzzy second; policy-denied modules are named as refused, never hidden).
3. **Approve** — candidates go to the **coordinator**; nothing fires until
   the recon→exploit sign-off. `msf_exec run` is refused in any other phase —
   mechanically, not by prompt.
4. **Execute** — ONE exploit/auxiliary module with a generic single-command
   payload running ONLY the runner-built canary (`echo REDTEAM-MARKER-*`).
   The marker echoing back IS the validation: command execution achieved.
   dos and destructive modules are refused by policy; stray sessions are
   stopped by hygiene; the kill switch destroys the running console.
5. **Report** — each validated CVE becomes its own runtime instance
   (attackId T1190 + `cve` field, e.g. CVE-2017-0144), reconciling against
   coverage via its category and listed in the report like any other item.

Six battery items anchor the methodology — WS-105 (mapping/logic), WS-106
(validation/functionality), WS-107 (auxiliary rigor/validation),
LX-107/LX-108/LX-109 — each carrying `[needs: msfrpcd]`. Operator
prerequisite: Metasploit Framework installed and
`msfrpcd -P <pass> -U <user> -a 127.0.0.1 -p 55553 -S` running, with
`REDTEAM_MSFRPC_USER`/`REDTEAM_MSFRPC_PASS` in the environment or Secure
Vault. Without msfrpcd the tool fails closed with setup instructions and
the 6 items report under Honest limits — never silently dropped.

## How it runs

One flag: `--full-battery`. One operation:

1. **Recon** all surfaces — webapp, MCP API, and host/AD footprints.
2. **Exploit** the SecScan battery.
3. **Exploit** the SecLayer battery.
4. **Exploit** the Windows battery (all host tools incl. the Metasploit bridge; WS-064/WS-065/WS-105…107 execute when their prerequisites are met).
5. **Exploit** the Linux battery (all host tools; LX-041's mount proof needs the privileged test client; LX-107…109 need msfrpcd).
6. **Cross-cutting chains** — paths spanning targets: does a primitive on
   one surface become impact on another?
7. **Unified report** — one Megazord narrative, all batteries.

`--targets secscan,seclayer,windows,linux` narrows the subset (default: all
four); `--target secscan+seclayer` is the web-only shortcut. The coordinator
sees the full spectrum for the selected targets as a compact checklist
(every ID + name + one-line brief); the full execution detail lives in the
runner modules. The runner enforces coverage mechanically: the battery
counts complete only when **3 categories × selected targets = 12 cells**
are probed or honestly BLOCKED. Anything else is named under Honest
limits — never silently dropped.

## Unbreakable rules

- Authorized scope only. Non-destructive always: no emails to real users,
  no deleting scans/reports, benign canary content only, races are single
  paired requests, credential testing against authorized test accounts only,
  read-only host enumeration preferred, persistence mechanisms reported as
  findings — never planted.
- Killed hypotheses are negative intelligence — the exact attempt is dead,
  the class stays in play with a different angle. Nothing is ever retired
  from the battery.
- Items needing setup (second test account, canary/OAST infrastructure,
  or more than the host-exec tools provide) are marked honestly in `needs`
  — never pretended.

## Honest limits

- Some items need a second test account or canary infrastructure the
  operator must provision; without them, those items are reported as
  not-covered, not as passed.
- Windows/Linux items marked `[needs: host-exec tooling]` need more than
  the host-exec tools provide (interactive RDP, Kerberos operations,
  collector binaries) — they are planned, not executed, and reported as
  BLOCKED, never as covered or failed.
- ATT&CK mappings are advisory: web flaw classes map imperfectly onto an
  endpoint/intrusion framework. Where no technique honestly fits, the OWASP
  reference stands alone.
