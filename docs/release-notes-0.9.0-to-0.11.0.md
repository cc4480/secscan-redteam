# Release notes: v0.9.0 → v0.11.0 — the runner grows hands, then a CVE arsenal

Three releases in one day (2026-10-03), one arc: the Windows/Linux
batteries go from *planned* to *executed* (v0.9.0, v0.10.0), then the
runner gains Metasploit's CVE-specific exploit arsenal without hardcoding
2,000 CVEs (v0.11.0). No live engagement ran during any of these builds —
all transports mocked or loopback-only; no targets touched.

**Heads-up that did not change across all three:** the first live run is
still gated on `QWEN_API_KEY` in secure storage (fail-fast is intact), and
live host/MSF work additionally needs ROE-declared scope hosts plus
operator-provided test-account credentials.

---

## v0.9.0 — host-exec tooling: the runner's hands on hosts
**Commit** `00eb3e1` (2026-10-03) · **Tests:** 112/112 runner, 17/17
auth-gate, typecheck clean · 19 files, +2,047/−320

### New agent tools (wired in `phases.ts` for recon/exploiter, host phases)
| Tool | Transport | What it does |
|---|---|---|
| `ssh_exec` | SSH via `ssh2@1.17.0` | ONE non-interactive command on in-scope Linux hosts (session reuse, per-exec timeout, output cap, backpressure guard) |
| `smb_exec` | SMB via `@marsaud/smb2@0.18.0` | `list_shares` (reachability probe of well-known + recon-supplied names — the lib has no NetShareEnum, documented), `list_dir`, `stat`. Read-only — no writes offered |
| `winrm_exec` | WinRM via `winrm-client@0.0.12` | ONE non-interactive PowerShell/cmd command on in-scope Windows hosts (auto-detects Basic vs NTLM from username format; no abort handle in the lib — kill switch races abandonment, documented) |

### New modules
- `runner/src/host-exec/common.ts` — the **safety core** every host tool
  flows through, in order: kill-switch check → exact-hostname ROE scope
  check (fail closed, before any packet; deliberately no private-IP ban —
  internal pentests legitimately target RFC1918) → destructive-command
  denylist (fail closed: `rm -rf /`, `mkfs`, `dd of=/dev/*`, disk wipes,
  shutdown/reboot, `vssadmin` shadow deletion, `cipher /w`, ransomware
  patterns…) → credential resolution → execution with timeout + output cap
  → secret redaction on everything that leaves. Pure functions
  (`validateHostTarget`, `checkDestructive`, `redactSecrets`,
  `destructiveDenyList`) — tested directly, no network.
- `runner/src/host-exec/executor.ts` — `HostExecutor`: preflight pipeline,
  injectable transport factories (tests run fakes), executor-level timeout
  backstop (a misbehaving transport can't hang the engagement; closes the
  transport on timeout).
- `runner/src/host-exec/{ssh,smb,winrm}.ts` — the three transports.
- `runner/src/host-exec/index.ts` — barrel.

### Safety properties (mechanical, all tested)
- **Scope:** out-of-scope host rejected before any connect (test asserts
  zero connection attempts).
- **Credentials:** `REDTEAM_SSH_USER` + `REDTEAM_SSH_PASSWORD`/`KEY`/`KEY_PATH`;
  `REDTEAM_SMB_USER` + `REDTEAM_SMB_PASSWORD` (+ optional `DOMAIN`);
  `REDTEAM_WINRM_USER` + `REDTEAM_WINRM_PASSWORD` — env/Secure Vault only,
  never in args, never in logs/errors/events (redaction tested); fail fast
  with actionable message when missing.
- **Denylist:** 16-pattern destructive-command table refused mechanically.
- **Bounds:** 30s timeout, 8KB output cap (no bulk exfiltration).
- **Kill switch:** coordinator abort terminates in-flight executions across
  all parallel tasks; new host work refused once aborted.
- **Audit:** every invocation lands in the JSONL operation log (time,
  phase, actor, tool, target, redacted command summary, result).

### Battery impact
400 of 410 items executable. The 10 items needing more than
non-interactive exec kept `needs: "host-exec tooling"` and reported
**BLOCKED** under Honest limits (never covered, never failed):
WS-010 (WinRM probe w/o session), WS-019 (interactive RDP logon), WS-023
(pass-the-hash), WS-038 (BloodHound collectors), WS-043 (AD CS tooling),
WS-064 (pass-the-ticket), WS-065 (RDP shadowing), LX-018/LX-019 (SSH
agent-forwarding channels), LX-041 (NFS test-client mounts).

### Docs
`docs/ROADMAP.md` — host-exec track marked delivered (what landed, the six
non-negotiable properties, the 10-item honest remainder);
`docs/full-battery.md` — "plan today, execute tomorrow" replaced with the
execution reality. CLI usage documents the new env vars.

---

## v0.10.0 — the last 10 items: full execution across all 410 battery items
**Commits** `e261a15` + `8b5ae63` (2026-10-03; the second is a 2-file
follow-up: `targets/index.ts`, `targets/test` fix) · **Tests:** 180/180
runner (incl. 947-line wave-2 + 777-line integration suites), 17/17
auth-gate, typecheck clean · 27 files, +5,550/−106

### 8 new agent tools (wave 2 — all through the same safety core)
| Tool | Battery item(s) | What it does |
|---|---|---|
| `winrm_probe` | WS-010 | Unauthenticated WinRM listener probe: POST to `/wsman` on 5985/5986, parse 401 `WWW-Authenticate` auth schemes + TLS posture. No session, no credentials (pure Node http/https) |
| `rdp_auth` | WS-019 | RDP credential validation via NLA — **hand-rolled** X.224 + TLS + CredSSP/SPNEGO + NTLMv2 (`host-exec/rdp.ts`). The only pure-JS Node RDP+NLA library found is AGPL-3.0 (legal risk for a commercial product), so the minimum viable handshake was implemented from the public specs. Validates, closes immediately; no desktop session ever driven; servers without NLA are reported, not validated |
| `smb_pth` | WS-023 | Pass-the-hash: raw-socket SMB2 NEGOTIATE + SESSION_SETUP with NTLMv2 **keyed by the NT hash** (`host-exec/ntlmv2.ts` shared primitives — NT hash, NTLMv2, SPNEGO/CredSSP DER; the library path only does NTLMv1-from-password, rejected by modern Windows). Hash = test account's OWN, client-provided via `REDTEAM_SMB_NTHASH` (strict 32-hex), password-grade secrecy, session logged off immediately |
| `ad_enum` | WS-038, WS-043 | Read-only LDAP AD enumeration via `ldapts`: users/groups/computers/trusts/OUs/GPOs, binary security-descriptor parsing for dangerous grants, **offline BloodHound-style attack-path computation** (paths computed, never executed), **AD CS certificate-template audit for ESC1/ESC2/ESC4** (detection only — no cert ever requested). Nothing written to the directory, ever |
| `krb_ptt` | WS-064 | Pass-the-ticket via OS MIT krb5 user tools: ticket material from `REDTEAM_KRB_CCACHE_B64` / `REDTEAM_KRB_CCACHE_PATH` / `REDTEAM_KRB_KIRBI_B64` (kirbi converted via impacket's ticketConverter.py when available — the runner does not implement KRB-CRED decryption itself), or `kinit` as the test account itself. Replayed ccache-only (`KRB5CCNAME`); `klist` confirms presence/validity, `kvno` against an in-scope SPN proves KDC acceptance. Only the test account's own tickets — no forging |
| `ssh_agent_audit` | LX-018, LX-019 | Agent-forwarding audit via ssh2 with `agentForward: true`: socket-check (is the forwarded socket exposed? permissions?) and abuse-path (which local users could reach it). **ANALYSIS ONLY** — the socket is never used for onward authentication |
| `nfs_enum` | LX-041 | Userland NFS export enumeration: hand-rolled ONC RPC portmapper + MOUNT protocol EXPORT listing — no kernel mount, no privileges, no credentials |
| `rdp_shadow_prep` | WS-065 | Read-only WinRM enumeration of live RDP session IDs + shadow policy, producing the complete **human handoff package** (exact shadow command, consent/ROE checklist, observation guide). The shadowing act itself stays human-only — **the single permanent exception** (shadowing needs an operator in a GUI session viewing another live desktop; a headless agent cannot meaningfully automate it and must not pretend to) |

### Battery impact
**Nothing is plan-only anymore.** Honest prerequisites replaced the
`needs: "host-exec tooling"` marker:
- `WS-064 [needs: kerberos ticket material]` — executes when ticket
  material is supplied (or kinit credentials).
- `WS-065 [needs: human operator]` — the single permanent exception above.
- `LX-041 [needs: privileged test client]` — export enumeration runs
  unprivileged; the mount+uid-0-file proof runs via `ssh_exec` on the
  operator-designated privileged test client (`REDTEAM_NFS_TEST_CLIENT`,
  must be in scope).

Coverage consequence: no cell is fully tooling-blocked anymore. Reports
gained a "Plan-only items" line naming the remainder; the cell-level
BLOCKED mechanic is preserved (tested on a synthetic fully-blocked
profile) but no longer triggers on real cells.

### New modules/files
`host-exec/{ad,krb,nfs,ntlmv2,rdp}.ts`, `winrm.ts` extended (probe),
`smb.ts` extended (PtH transport), `ssh.ts` extended (agent forwarding),
`common.ts` extended (`resolveSmbHashCredentials`, `resolveAdCredentials`,
`NEEDS_KERBEROS_TICKET`/`NEEDS_HUMAN_OPERATOR`/`NEEDS_PRIVILEGED_CLIENT`
constants in `targets/types.ts`). `phases.ts`: 8 tools wired with
targetProfile pinning (never inferred), ROE technique check, coverage
counting, black-mode jitter, kill-switch controller registration,
DENIED/ABORTED mapping. `prompts.ts`: host-tool guidance for agents.

---

## v0.11.0 — the Metasploit bridge: CVE-specific exploit validation
**Commit** pending (built 2026-10-03 on top of `8b5ae63`) · **Tests:**
201/201 runner (21 new), 17/17 auth-gate, typecheck clean

### The gap it closes
The 410-item battery covers technique *classes* (what Metasploit's
auxiliary/post modules do, ATT&CK-mapped). It cannot hardcode Metasploit's
~2,000 **CVE-specific exploits**. The bridge closes that gap
**dynamically** — no CVE list is baked in:

1. **Enumerate** — recon detects versioned services (banners,
   `http_probe`, `ssh_exec`/`winrm_exec` version reads).
2. **Map** — `msf_exec suggest` takes service + version → ranked candidate
   modules (CVE-exact queries first, service-fuzzy second; policy-denied
   modules named as refused, never hidden).
3. **Approve** — candidates go to the **coordinator**; `msf_exec run` is
   refused outside the exploit phase — mechanically, not by prompt. The
   recon→exploit sign-off IS the approval gate.
4. **Execute** — ONE module, generic single-command payload running ONLY
   the runner-built canary (`echo REDTEAM-MARKER-*`). The marker echoing
   back IS the validation: command execution achieved.
5. **Report** — each validated CVE becomes its own runtime instance
   (attackId T1190 + `cve` field, e.g. CVE-2017-0144), reconciling against
   coverage via its category, named in the report like any other item.

### New agent tool
`msf_exec` (wired in `phases.ts` alongside host tools; available in recon
+ exploit, run gated to exploit):
- `search` — module database query in msf search syntax
  (`cve:CVE-2021-44228`, `type:exploit platform:windows smb`). Recon-safe,
  never fires.
- `suggest` — service/version → ranked candidates **for coordinator
  approval**. Never fires.
- `run` — ONE exploit/auxiliary module, benign canary marker only.
  **Exploit phase only** (DENIED elsewhere with the reason stated).

### New modules (`runner/src/msf/`)
- `protocol.ts` — msfrpc wire protocol (MessagePack over HTTP(S),
  `@msgpack/msgpack`): `msfCall`, injectable `MsfRequestFn` transport,
  `createHttpMsfRequest` (timeout, abort). Tests speak the real wire
  protocol against a fake daemon.
- `policy.ts` — the mechanical backstop (pure functions, tested):
  `checkMsfPayload` (only `cmd/<platform>/generic` — no Meterpreter, no
  shells, no sessions), `checkMsfModule` (dos refused — T1499 stays
  excluded per standing ROE, no exceptions; destructive modules refused:
  disk wipers, ransomware patterns, firmware/boot destruction; only
  exploit/auxiliary types), `buildMarkerCommand` (runner-built canary,
  sanitized, additionally passes the destructive denylist),
  `resolveMsfCredentials` (fail fast with setup instructions),
  `msfRankWeight` (module rank → sort weight).
- `client.ts` — `MsfClient`: `login` (throws `MsfAuthError` with setup
  instructions on failure), `searchModules`, `runModuleConsole`
  (throwaway console: `use` → `set` → `run` foreground → poll until idle;
  **abort destroys the console — that IS the kill switch for a running
  module**), `sessionList`/`sessionStop` (hygiene).
- `suggest.ts` — recon→module mapping: `extractCves` (CVE regex over
  banner text), `buildModuleQueries` (most-specific-first:
  `type:exploit cve:…` → `type:exploit platform:… <service>` →
  `type:auxiliary …`), `filterAndRank` (policy filter BEFORE the agent
  sees candidates; denied modules returned with the refusal reason —
  never silently hidden), `suggestModules` (dedup, cap 25 for triage).
- `executor.ts` — `MsfExecutor`: preflight (kill switch → exact-hostname
  ROE scope → module/payload policy → vault credentials) → execution with
  timeout → **session hygiene** (any session that wasn't there before the
  run is stopped immediately — a validation run must not leave sessions
  behind) → secret redaction on everything that leaves. RHOSTS is always
  the scope-checked host, never agent-supplied.
- `index.ts` — barrel.

### Battery
Six methodology items (all `[needs: msfrpcd]`):
- **Windows** — WS-105 (logic: CVE→module mapping for coordinator
  approval), WS-106 (functionality: coordinator-approved modules fired
  with canary markers; each CVE its own report instance), WS-107
  (validation: auxiliary findings cross-validated against direct host-exec
  evidence; module ranks sanity-checked).
- **Linux** — LX-107, LX-108, LX-109 (same methodology).
- Battery now **416 static items** (120 + 80 + 107 + 109) **plus dynamic
  per-CVE runtime instances**.
- Honest prerequisites: 9 items (WS-064 ticket material, WS-065 human
  operator, LX-041 privileged test client, + the 6 msfrpcd items). No cell
  is fully blocked.

### Operator prerequisite (fail closed otherwise)
Metasploit Framework installed and the RPC daemon running:
`msfrpcd -P <pass> -U <user> -a 127.0.0.1 -p 55553 -S`
(`-S` = SSL; keep it on loopback). Then set `REDTEAM_MSFRPC_USER` /
`REDTEAM_MSFRPC_PASS` (+ optional `REDTEAM_MSFRPC_HOST` /
`REDTEAM_MSFRPC_PORT` / `REDTEAM_MSFRPC_TLS=0`) in the environment or
Secure Vault. Unreachable daemon or missing credentials → fail closed
with these exact setup instructions; the 6 methodology items report under
Honest limits.

### What was verified (21 new tests, `runner/test/msf.test.ts`)
Against a fake msfrpcd speaking the real MessagePack wire protocol:
policy unit tests (payload allowlist, module denylist incl. dos/wiper/
ransomware, marker sanitization, CVE extraction, query building,
filter-and-rank with named refusals, credential fail-fast); executor
tests (search/suggest return ranked candidates; **out-of-scope refused
before any msfrpcd request — zero packets**; bad credentials fail closed;
dos module and meterpreter payload refused pre-request; kill switch
refuses new runs; **mid-run abort destroys the console**; marker echo =
validation; msfrpc password in options redacted from summaries/outputs);
phases wiring (search executes with audit in the event feed, out-of-scope
run DENIED with zero msfrpcd requests, in-scope run validates the marker
and tags `[CVE-2017-0144]` in the result, `msf_exec` in the agent tool
list, run refused outside the exploit phase).

### Untouched throughout
`QWEN_API_KEY` fail-fast, the registry's negative-intelligence rule
(killed hypotheses stay in play with a different angle), and coordinator
sign-off/abort authority.

---

## Standing context (unchanged)
- Coverage contract: 3 categories × selected targets = 12 cells; a cell is
  done only when probed or honestly BLOCKED — never silently dropped.
- Non-destructive always: benign canaries, read-only preferred, no DoS
  (T1499 excluded in every mode), no destructive payloads, persistence
  reported — never planted.
- Credentials: env/Secure Vault only, never in code, never logged.
- Registry seed committed at `engagements/registry.json`.
