# SecScan RedTeam — v0.27.0

> Working name: **secscan-redteam** (renameable — see "Naming" below).

AI red-team pentesting, sold as scoped, authorized, paid B2B engagements.
Hypothesis-driven agents **reason** about the target instead of marching
down a static checklist: the exploiter's reasoning runs on Qwen
(`qwen3.8-max`), while DeepSeek flash drives the coordinator, recon, and
reporter loops.

**Honest status:** the full system is test-verified against simulated
targets (508/508 runner tests, 17/17 auth-gate tests) but has not yet
completed a live full engagement. Anything this README calls "real" means
*built, tested against mocks/fakes/loopback, and wired into the safety
core* — not *proven on a live target*. Proof exists only after a real
authorized system returns direct observation or a canary marker echo.

## The battery — 418 attack intents

- **SecScan web:** 120 items (`SS-001`–`SS-120`)
- **SecLayer MCP:** 80 items (`SL-001`–`SL-080`)
- **Windows hosts:** 108 items (`WS-001`–`WS-108`)
- **Linux hosts:** 110 items (`LX-001`–`LX-110`)

Every selected item carries a verdict ledger entry — `pending`,
`confirmed`, `executed-clean`, `killed`, `blocked`, or `na` (with evidence
required) — and the runner cannot honestly report complete while any
selected item remains `pending`. ATT&CK-mapped throughout; coverage is
reconciled per category × target cell **and** per item.

### Variant expansion (honest depth, not inflated counts)

Competitors reach "tens of thousands of attacks" by executing payload
variants. We do the same depth but count it honestly:

- **139 curated, non-destructive payloads** across 10 libraries
  (SQLi, XSS, command injection, SSTI, XXE, path traversal, SSRF, open
  redirects, auth/session, headers/CORS) — mechanical data, never
  LLM-invented at runtime.
- Caps enforced in dispatch: 25 per item (staging) / 10 (production);
  override with `--max-variants` / `REDTEAM_MAX_VARIANTS`.
- Reports print **two** numbers — "418 attack intents" and "N variant
  executions" — never merged into one inflated figure.

## Execution bridges

- **Host tooling** (`ssh_exec`, `smb_exec`, `winrm_exec`, `winrm_probe`,
  `rdp_auth`, `smb_pth`, `ad_enum`, `krb_ptt`, `ssh_agent_audit`,
  `nfs_enum`, `rdp_shadow_prep`) — real SSH/SMB/WinRM/RDP/AD/Kerberos/NFS
  execution against in-scope hosts, all through the same safety core.
- **Metasploit** (`msf_exec`) — search/suggest/run one
  coordinator-approved module with a benign canary action. DoS and
  destructive modules refused; no Meterpreter. Requires `msfrpcd` on the
  operator machine (`REDTEAM_MSFRPC_*`).
- **Nuclei** (`nuclei_exec`) — list templates locally (recon-safe) or run
  them exploit-phase-gated with `-exclude-tags dos`. Requires an
  operator-installed Nuclei binary.

## The six buyer gates

1. **Compliance packs** — PCI DSS v4.0.1 (Req 11.4), SOC 2 (CC6.1, CC6.6,
   CC7.1), ISO 27001:2022 (A.8.8): methodology, control mapping, findings
   evidence, retest evidence, honest attestation. (`docs/compliance.md`)
2. **Production safety** — per-host rate limits, PII redaction, staging →
   production confirmation, auto-halt on distress, safety manifest, log
   rotation on long watch runs. (`docs/safety.md`)
3. **Proof of exploitation** — PoC bundles derived from the audit log,
   canary marker sent/echo observed, `reverify` mode, negative proof for
   killed hypotheses.
4. **Integrations** — Jira, ServiceNow, Slack, SIEM JSONL, retest-ticket
   updates. (`docs/integrations.md`)
5. **Continuous testing** — watch profiles, rolling baselines, drift
   classification (new/unchanged/remediated/reopened), CI/CD triggers,
   expiring authorization. (`docs/continuous.md`)
6. **Accountability** — autonomy tiers (Tier 0 observe / Tier 1 validate /
   Tier 2 chain), production defaults to Tier 1 with a named operator,
   mid-run escalation (`redteam-runner escalate`) with recorded approval,
   approval log on every finding. (`docs/accountability.md`)

## Web UI — directly connected to the CLI

```bash
cd runner && npm run build && npx redteam-runner ui   # http://127.0.0.1:8787
```

`redteam-runner ui [--port 8787] [--listen <addr>] [--engagements-dir <dir>]`.
Binds `127.0.0.1` by default; a random 64-hex token is printed at startup
(bearer or HttpOnly `SameSite=Strict` cookie; stable token via
`REDTEAM_UI_TOKEN`). Same code paths as the CLI — never a separate runner.
Launcher, live event feed, kill switch (works on CLI-launched runs too),
findings, coverage, compliance packs, watch triggers, reverify.

## CLI

`redteam-runner start | queue | watch | reverify | ui | escalate`

- `start` — one engagement: target, scope, ROE, tier, mode (red/black),
  battery subset.
- `watch` — continuous mode: watch profiles, drift detection, baselines.
- `queue` — dropped engagement job files run by the watcher.
- `reverify` — replay a PoC bundle with a fresh canary.
- `escalate --engagement <id> --tier <0|1|2> --operator "<name>"
  --reason "<text>"` — mid-run tier change; up requires operator + reason,
  down is free but logged, Tier 2 on production needs explicit confirmation.

## Keys — environment only, never in code

`QWEN_API_KEY` (or `DASHSCOPE_API_KEY`) · `DEEPSEEK_API_KEY` ·
`SECSCAN_MCP_TOKEN` · `REDTEAM_MSFRPC_*` · `REDTEAM_UI_TOKEN` ·
`REDTEAM_SSH_*` / `REDTEAM_SMB_*` / `REDTEAM_WINRM_*` /
`REDTEAM_AD_*` / `REDTEAM_KRB_*` · `REDTEAM_JIRA_*` · `REDTEAM_SNOW_*` ·
`REDTEAM_MAX_VARIANTS` · `REDTEAM_MAX_RPS` · `REDTEAM_LOG_MAX_BYTES` /
`REDTEAM_LOG_MAX_ARCHIVES`. `.gitignore` blocks `.env` files.

## Authorization gate (non-negotiable)

Active testing requires proven domain ownership: the SecScan server flow
(`start_domain_verification` → DNS TXT at
`_secscan-challenge.<domain>` → `check_domain_verification`), re-checked by
the gate before every aggressive action. Fails closed for everyone,
including the operator. Unauthorized pentesting is illegal; the gate cannot
be overridden in-chat. Out-of-scope targets are refused before packets are
sent. No DoS, no ransomware behavior, no destructive payloads, no
phishing/social engineering/physical access in the automated runner.
Credential testing only against authorized test accounts.

## Quickstart

```bash
# 1. Build + test
cd runner && npm install && npm run build
npm test          # 508/508 runner tests
npm run typecheck # both tsconfigs clean
cd ../auth-gate && npm test  # 17/17

# 2. Dry run (no live target touched)
npx redteam-runner start --target example.invalid --mode red --dry-run

# 3. Smoke-test the Qwen key (no target)
node smoke-qwen.mjs
```

## Architecture

- `runner/` — the engagement runner (`@secscan/redteam-runner`): phases,
  dispatch, 26 agent tools, safety core (rate limiter, denylists,
  auto-halt, kill switch), proof bundles, registry, compliance packs,
  integrations, watch mode, web UI. No `runner/src` file exceeds 300
  lines (mechanically enforced by `file-budget.test.ts`).
- `auth-gate/` — server-authoritative DNS-TXT ownership verification,
  fails closed, 17 unit tests.
- `llm-router/` — provider-pluggable LLM interface; Qwen (`qwen3.8-max`)
  drives the exploiter's reasoning, DeepSeek flash drives
  coordinator/recon/reporter. Adding a provider = one class +
  registration.
- `agents/` — role system prompts with ReAct loops.
- `harness-plugin/` — DeepSeek Harness integration (auth gate as a
  `tools/pre-execute` hook, SecScan MCP via `dsh-mcp-client`).
- `engagements/` — runbook template; live runs stream to
  `engagements/live/<id>/`; `queue/` for dropped job files.

Docs live in `docs/` (`architecture.md`, `safety.md`, `compliance.md`,
`proof.md`, `integrations.md`, `continuous.md`, `accountability.md`,
`attack-batteries.md`, `variants.md`, `nuclei.md`, `ui.md`,
`release-notes-0.9.0-to-0.11.0.md`).

## Naming

`secscan-redteam` is a working name. Rename freely — the moving parts are
the package names (`@secscan/redteam-*`) and the plugin id in
`harness-plugin/cordis.patch.yml`.

## Security & legal

- This repo is PRIVATE. It is the paid product's secret sauce: prompts,
  policy, and engagement machinery.
- Keys via environment / Secure Vault ONLY. Nothing logs, prints, or
  persists keys. Pasted keys are treated as compromised and rotated.
- All the safety rails above are mechanical — they apply to the operator
  too. No verbal exceptions.
