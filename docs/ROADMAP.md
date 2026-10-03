# Runner Roadmap

## Host-exec tooling — DELIVERED (v0.9.0), completed (v0.10.0)

**Status:** the host-exec track is built, tested, and live in
`runner/src/host-exec/`. The Windows (WS-*) and Linux (LX-*) batteries are
fully executable: **all 418 items execute** (3 carry honest operator
prerequisites — see below; nothing is plan-only anymore).

**What landed in v0.9.0:**

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

**What landed in v0.10.0 (the last 10 items):**

4. **winrm-probe** (`winrm_probe`) — unauthenticated WinRM listener +
   auth-scheme probe (WS-010): POST to /wsman, parse 401
   `WWW-Authenticate` headers. No session, no credentials. Pure Node
   http/https.
5. **rdp-auth** (`rdp_auth`) — RDP credential validation via NLA (WS-019):
   hand-rolled X.224 + TLS + CredSSP/SPNEGO + NTLMv2 (see
   `host-exec/rdp.ts`). The only pure-JS Node RDP+NLA library found is
   AGPL-3.0 licensed — a legal risk for a commercial product — so the
   minimum viable handshake was implemented from the public specs instead.
   Validates the credential, closes immediately; no desktop session is ever
   driven. Servers without NLA are reported (not validated — the absent NLA
   is the finding).
6. **smb-pth** (`smb_pth`) — pass-the-hash with NTLMv2 keyed by the NT hash
   (WS-023): raw-socket SMB2 NEGOTIATE + SESSION_SETUP, STATUS_SUCCESS =
   the hash authenticates. The library path only does NTLMv1-from-password
   (rejected by modern Windows), so the NTLMv2-from-hash handshake is
   hand-rolled (`host-exec/ntlmv2.ts` shared primitives). Hash from
   `REDTEAM_SMB_NTHASH` (test account's own, client-provided), password-grade
   secrecy.
7. **ad-enum** (`ad_enum`) — read-only LDAP AD enumeration via `ldapts`
   (actively maintained): users/groups/computers/trusts/OUs/GPOs,
   binary security-descriptor parsing for dangerous grants, **offline
   BloodHound-style attack-path computation** (WS-038), and **AD CS
   certificate-template audit** for ESC1/ESC2/ESC4 conditions (WS-043,
   detection only — no cert ever requested). Nothing is written to the
   directory, ever.
8. **krb-ptt** (`krb_ptt`) — pass-the-ticket (WS-064) via the OS MIT krb5
   user tools: ticket material from `REDTEAM_KRB_CCACHE_B64` /
   `REDTEAM_KRB_CCACHE_PATH` / `REDTEAM_KRB_KIRBI_B64` (kirbi converted via
   impacket's ticketConverter.py when available — the runner does not
   implement KRB-CRED decryption itself), or `kinit` as the test account
   itself; replayed ccache-only (`KRB5CCNAME`), `klist` confirms
   presence/validity, `kvno` against an in-scope SPN proves KDC acceptance.
   Only the test account's own tickets — no forging.
9. **ssh-agent-audit** (`ssh_agent_audit`) — agent-forwarding socket
   exposure (LX-018) + abuse-path analysis (LX-019) via ssh2 agent
   forwarding. Analysis only — the socket is never used for onward auth.
10. **nfs-enum** (`nfs_enum`) — userland NFS export enumeration (LX-041):
    hand-rolled ONC RPC portmapper + MOUNT protocol, no kernel mount, no
    privileges needed.
11. **rdp-shadow-prep** (`rdp_shadow_prep`) — WS-065 preparation: read-only
    WinRM enumeration of live session IDs + shadow policy, producing the
    complete human handoff package (exact command, consent/ROE checklist,
    what to observe). The shadowing act itself stays human-only (see below).

**Honest prerequisites (v0.10.0) — NOT plan-only, they execute when met:**

- `WS-064 [needs: kerberos ticket material]` — supply
  `REDTEAM_KRB_CCACHE_B64` / `REDTEAM_KRB_CCACHE_PATH` /
  `REDTEAM_KRB_KIRBI_B64`, or test-account credentials for the kinit
  fallback; MIT krb5 user tools (`klist`, `kvno`, `kinit`) on the runner host.
- `WS-065 [needs: human operator]` — **the single permanent exception.**
  Shadowing a live user's session requires an operator sitting in a GUI
  session viewing another person's desktop — a headless agent cannot
  meaningfully automate that, and must not pretend to. The runner prepares
  everything up to the human step (session IDs, exact command,
  consent/ROE checklist, observation guide). Documented in `host-exec/rdp.ts`.
- `LX-041 [needs: privileged test client]` — export enumeration runs
  unprivileged; the mount+uid-0-file proof runs via `ssh_exec` on the
  operator-designated privileged test client (`REDTEAM_NFS_TEST_CLIENT`,
  must be in scope).

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

## Metasploit bridge — DELIVERED (v0.11.0)

**Status:** the Metasploit bridge is built, tested, and live in
`runner/src/msf/`. The 418-item battery covers technique *classes*
(ATT&CK-mapped); the bridge closes the CVE-*specific* gap — Metasploit's
~2,000 weaponized exploits — **without hardcoding 2,000 CVEs**. The
methodology is dynamic: recon detects a service/version → `msf_exec
suggest` maps it to ranked candidate modules → the coordinator approves →
`msf_exec run` fires ONE module with a benign canary marker as the only
payload action. Six new battery items anchor the methodology (WS-105…107,
LX-107…109, `[needs: msfrpcd]`); each CVE validated at runtime becomes a
per-CVE instance (attackId T1190 + `cve` field, e.g. CVE-2017-0144) that
reconciles against coverage via its category and is named in the report
like any other battery item.

**What landed:**

1. **msfrpc client** (`msf/protocol.ts`, `msf/client.ts`) — MessagePack
   over HTTP(S) to the operator's msfrpcd (`@msgpack/msgpack`); auth.login,
   module.search, console-based module execution WITH output capture (the
   evidence for "command execution achieved"), session hygiene. Fail closed
   with setup instructions when msfrpcd is unreachable.
2. **`msf_exec` agent tool** (wired in `phases.ts` alongside the host-exec
   tools) — three actions: `search` (module database query, recon-safe),
   `suggest` (service+version → ranked candidates for coordinator approval —
   never fires), `run` (ONE exploit/auxiliary module, benign canary marker
   only). **Run is exploit-phase-only, enforced mechanically** — the
   recon→exploit coordinator sign-off IS the approval gate.
3. **Payload/module policy** (`msf/policy.ts`) — mechanical backstop:
   - only generic single-command payloads (`cmd/<platform>/generic`) — no
     Meterpreter, no shells, no sessions; the command is ALWAYS the
     runner-built `echo REDTEAM-MARKER-*` (never agent-supplied) and
     additionally passes the destructive-command denylist;
   - dos modules refused (T1499 stays excluded per standing ROE, no
     exceptions), destructive modules refused (disk wipers, ransomware
     patterns, firmware/boot destruction);
   - attackIds on msf calls must be real ATT&CK IDs (the coordinator
     rejects anything else) — CVEs travel in the `cve` field.
4. **Recon integration** (`msf/suggest.ts`) — CVE extraction from banner
   text, service-alias normalization, most-specific-first query building
   (`cve:` exact → service fuzzy), policy filtering BEFORE the agent ever
   sees candidates (denied modules are named as refused, never hidden).
5. **Safety core** (`msf/executor.ts`) — kill switch → exact-hostname ROE
   scope → module/payload policy → vault credentials → execution with
   timeout; abort destroys the console (that IS the kill switch for a
   running module); stray sessions are stopped by hygiene; every secret
   redacted from every string that leaves.

**Operator prerequisite:** Metasploit Framework installed +
`msfrpcd -P <pass> -U <user> -a 127.0.0.1 -p 55553 -S` running;
`REDTEAM_MSFRPC_USER` / `REDTEAM_MSFRPC_PASS` (+ optional
`REDTEAM_MSFRPC_HOST` / `REDTEAM_MSFRPC_PORT` / `REDTEAM_MSFRPC_TLS`) in
the environment or Secure Vault. Fail closed with setup instructions
otherwise — the 6 methodology items report under Honest limits.

**Tests:** 21 new tests in `runner/test/msf.test.ts` against a fake msfrpcd
speaking the real MessagePack wire protocol (auth failure fail-closed,
scope denial before any request, secret redaction, kill-switch abort
destroys the console mid-run, dos/meterpreter denylist refusals, suggest
ranking, marker-echo validation, phases wiring incl. exploit-phase gating).
Full suite: 201/201 runner, 17/17 auth-gate, typecheck clean.

## Beyond

- Console: surface the 12-cell coverage (✓/⊘/…) and the unified Megazord
  narrative per target in the Live header.
- Registry: host findings (privesc paths, AD attack paths) compound into
  the registry like web findings do today.
- Retest mode: re-run a previous engagement's battery against a new
  deployment and diff the results — the resident-adversary loop.
- Credential-less AD CS: explore LDAPS channel binding / signing enforcement
  reporting as part of the ad_enum surface.

## Buyer gates — DELIVERED (v0.12.0 → v0.17.0)

One task at a time, each fully completed before the next — the enterprise
buying gates from the competitive brief, built into the runner:

- **v0.12.0 compliance-mapped reporting** — every finding mapped to PCI DSS
  4.0.1 / SOC 2 / ISO 27001 controls; documented methodology QSAs demand;
  retest evidence; an attestation letter mechanically prevented from
  overclaiming. `docs/compliance.md`.
- **v0.13.0 production safety case** — per-target rate limits, PII
  redaction, staging→production graduation, per-target auto-halt, and a
  machine-readable safety manifest with a zero-disruption record and
  honestly stated residual risks. `docs/safety.md`.
- **v0.14.0 proof-of-exploitation evidence** — structured PoC bundles
  derived mechanically from the audit log, a re-verify mode, and recorded
  negative proof. `docs/proof.md`.
- **v0.15.0 buyer integrations** — Jira/ServiceNow ticketing, Slack
  lifecycle, SIEM export, and the retest loop.
- **v0.16.0 continuous testing** — watch profiles, rolling baselines, drift
  detection.
- **v0.17.0 accountability + autonomy tiers** — graduated autonomy (Tier 0
  observe / Tier 1 validate / Tier 2 chain) enforced mechanically in the
  tool dispatcher; Tier 1 limited to one validated exploit step per target;
  Tier 2 on production needs explicit operator approval; production
  engagements refuse to start without a named human operator; every finding
  stamped with its accountable operator; append-only approval log embedded
  in the safety manifest and the compliance pack (§7). `docs/accountability.md`.

## Nuclei bridge — DELIVERED (v0.21.0)

**Status:** the Nuclei bridge is built, tested, and live in
`runner/src/nuclei/`. Competitors reach "tens of thousands of attacks"
largely via template libraries; the bridge gives the runner the same
reach — ProjectDiscovery Nuclei's ~10,000+ community templates, resolved
at runtime from the operator's local checkout, **never hardcoded** — with
the runner's safety discipline and honest counting.

**What landed:**

1. **`nuclei_exec` agent tool** — two actions: `templates` (list/select by
   id, tag, severity, CVE — recon-safe, touches no target, never fires),
   `run` (execute selected templates against ONE scope-checked host).
   **Run is exploit-phase-only and Tier 2, enforced mechanically** —
   `templates` is Tier 1.
2. **Subprocess runner** (`nuclei/runner.ts`) — argv built from structured
   options (no shell, ever); JSONL output parsed leniently (bad lines
   counted, not fatal); child killed on abort (kill switch) and on
   timeout; injectable spawn for tests.
3. **Policy** (`nuclei/policy.ts`) — dos-tagged templates refused when
   requested AND `-exclude-tags dos` appended to every run argv (T1499
   stays excluded); template updates never flaggable mid-engagement;
   explicit id lists truncated runner-side.
4. **Dedupe** (`nuclei/mapping.ts`) — a finding confirmed by both a
   battery item and a template is ONE finding with two evidence sources;
   template-only findings become runtime instances under the new
   methodology items WS-108 / LX-110 (`[needs: nuclei binary]`).
5. **Honest counting** (`nuclei/reporting.ts`) — the report prints three
   separate numbers (418 intents, N variant executions, M nuclei template
   executions), never merged into one inflated figure.

**Operator prerequisite:** nuclei binary installed +
`nuclei -update-templates` run by the operator before the engagement
(optional `REDTEAM_NUCLEI_BIN` / `REDTEAM_NUCLEI_TEMPLATES` /
`REDTEAM_NUCLEI_TIMEOUT_S`). Fail closed with setup instructions.
`docs/nuclei.md`.
