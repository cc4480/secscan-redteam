# SecScan RedTeam — v0.4.0: live engagement runner + Red/Black teams

> Working name: **secscan-redteam** (renameable — see "Naming" below).

AI red-team pentesting, sold as scoped, authorized, paid B2B engagements.
The system ties the **SecScan scanning engine** (via its live MCP endpoint)
to a **live engagement runner** that executes the full loop as code —
authorize → plan → recon → exploit → report — with a four-role DeepSeek agent
team whose exploiter **reasons** and now runs a **systematic three-category
battery** (logic flaws, functionality abuse, validation rigor) instead of
marching down a static checklist.

## Red vs Black — the two engagement modes

- **RED (overt red team):** aggressive breadth. Full technique catalog, active
  scanner tier, direct hypothesis testing. Speed and coverage beat stealth.
  The blue team may know the engagement is happening.
- **BLACK (covert-ops tier):** black-box — zero prior knowledge assumed.
  Stealth-prioritized: low-noise techniques first, jittered pacing, payload
  encoding to reduce signature footprint, immediate backoff on any detection
  signal (WAF block, 429, challenge page). Every detection signal is logged as
  an OPSEC event and becomes a detection-gap finding. Undeclared to the
  target's blue team.

**Both modes require server-authoritative domain-ownership proof before any
active testing.** Covert means covert *vs the blue team* — never vs the
authorization gate. The gate cannot be bypassed, talked around, or
"black-teamed"; it fails closed for everyone, including the operator.

## Rules of Engagement (ROE)

Every engagement carries an ROE contract that the runner enforces
mechanically, not by policy memo:

- **Scope** — exact in-scope hosts. Nothing else is ever touched (exact
  hostname match; the prober additionally refuses private/loopback IPs and
  non-HTTP schemes).
- **Excluded techniques** — ATT&CK IDs that are off-limits. `T1499` (DoS) is
  always excluded; black mode also excludes `T1110` (brute force) by default.
- **Blackout windows** — daily `HH:MM–HH:MM` windows (with timezone) during
  which the runner pauses all traffic, then resumes.
- **Stop conditions** — e.g. production outage, WAF hard-block. Three
  consecutive 5xx responses halt the engagement automatically.
- **Test window** — the runner refuses to run outside the agreed window.
- **Deconfliction contact** — who to call on the client side if something
  goes wrong.

Non-destructive always. Web targets only — no phishing, social engineering,
or physical testing in the automated runner; those stay manual.

## Vision

Static scanners answer "which known checks failed." A red team answers "how
would an attacker actually get in." This product closes that gap: the SecScan
engine provides the baseline (140+ checks, oracle-proven probes), and the
agent team provides the brain — observing results, asking "that's odd, why?",
and pivoting. The client gets an attacker's-eye report: business impact,
evidence, and copy-paste fixes.

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │        DeepSeek Harness host        │
                    │  (deepseek-ai/deepseek-harness)     │
                    │                                     │
  ┌──────────────┐  │  ┌───────────────────────────────┐  │
  │  LLM router  │◄─┤  │  secscan-redteam plugin       │  │
  │              │  │  │                               │  │
  │ deepseek     │  │  │  ┌─────────────────────────┐  │  │
  │  ├ v4-flash  │  │  │  │ SecScan MCP (native)    │  │  │
  │  qwen        │  │  │  │  mcp__secscan__*        │──┼──┼──► secscan.us/api/mcp
  │  └ 3.8-max   │  │  │  │  (dsh-mcp-client,       │  │  │    (Streamable HTTP,
  │ (anthropic / │  │  │  │   live tools)           │  │  │     live engine)
  │  openai /    │  │  │  └─────────────────────────┘  │  │
  │  google /    │  │  │  ┌─────────────────────────┐  │  │
  │  zhipu/kimi  │  │  │  │ auth gate (pre-execute) │  │  │
  │  PLANNED)    │  │  │  │  DNS TXT ownership      │  │  │
  └──────────────┘  │  └─────────────────────────┘  │  │
                    │  ┌─────────────────────────┐  │  │
                    │  │ team: coordinator       │  │  │
                    │  │  ├ recon    (flash)     │  │  │
                    │  │  ├ exploiter (qwen)     │  │  │
                    │  │  └ reporter  (flash)     │  │  │
                    │  └─────────────────────────┘  │  │
                    └─────────────────────────────────────┘
```

- **harness-plugin/** — installs the auth gate as a `tools/pre-execute` hook
  (verified against the real `PreToolDecision`/`ToolExecution` contracts) and
  adds the red-team usage section to the system prompt via
  `ctx.systemPrompt.section()`. The SecScan tools themselves come from the
  harness-NATIVE `@deepseek-ai/dsh-mcp-client` (Streamable HTTP →
  `https://secscan.us/api/mcp`, declared in `harness-plugin/cordis.patch.yml`);
  the old stdio `@seclayer/mcp` bridge was removed in v0.2 because its
  seclayer.io X-API-Key backend no longer serves the API. Includes the team
  profile (roles, model assignments, seed tasks).
- **llm-router/** — provider-pluggable unified LLM interface. v0.5: DeepSeek
  + Qwen. `deepseek-flash` (fast, tool use) drives recon loops, the
  coordinator, and the reporter; `qwen3.8-max` (Alibaba Model Studio,
  flagship reasoning, thinking on by default) drives the exploiter's
  hypothesis work. Adding providers later = one new class implementing
  `LlmProvider` + `registerProvider()`.
- **agents/** — role system prompts with ReAct loops. The exploiter prompt
  carries a worked dynamic-testing example (reflected input → CSP-aware
  payload pivot → canary-token proof).
- **auth-gate/** — server-authoritative domain verification. The gate
  re-checks the SecScan server's own verified-domain list
  (`list_verified_domains` over the MCP endpoint) before any aggressive
  test; ownership is proven via the server's flow
  (`start_domain_verification` → DNS TXT at
  `_secscan-challenge.<domain>` → `check_domain_verification`). Fails
  closed; aggressive testing without proof is denied with remediation
  instructions. Legally non-negotiable.
- **engagements/** — per-client runbook template (scope, authorization,
  rules, log, close-out). Live engagements stream here:
  `engagements/live/<id>/{events.jsonl, state.json, engagement.md, report.md}`;
  the console tails these for its live view. `engagements/queue/` receives
  engagement requests from the console.
- **runner/** — the live engagement runner (`@secscan/redteam-runner`, v0.4.0).
  Executes authorize → plan → recon → exploit → report as code: the
  coordinator produces an ATT&CK-mapped operation plan, recon runs the SecScan
  engine, the exploiter runs the hypothesis → probe → observe loop against
  the systematic three-category battery (logic flaws, functionality abuse,
  validation rigor — 24 OWASP-referenced items; the runner refuses to end the
  exploit phase until all three categories are probed), and the reporter
  writes the client report. Every action streams to a JSONL event log with
  timestamp, phase, actor, ATT&CK ID, target, and result. 32 unit tests,
  no network needed.

## Running a live engagement

Keys via environment ONLY (`SECSCAN_MCP_TOKEN`, `DEEPSEEK_API_KEY`,
`QWEN_API_KEY`; `SECSCAN_MCP_URL` and `REDTEAM_HOME` optional):

```bash
# 1. Authorize the domain first (server flow — do this once per domain):
#    start_domain_verification → publish TXT at _secscan-challenge.<domain>
#    → check_domain_verification. The runner verifies before starting and
#    re-checks before every aggressive action.

# 2a. Run one engagement directly:
npx redteam-runner start --target secscan.us --mode red \
  --objective "assess the external attack surface" \
  --scope secscan.us --exclude T1110 \
  --blackout "02:00-04:00 America/Chicago"

# 2b. Or serve the console queue (the Red Team Console's Live tab drops
#     engagement requests here; the watcher runs them as they arrive):
npx redteam-runner watch
```

Black-team run: `--mode black`. Same battery, stealth-weighted: low-noise
variants first, jittered pacing, OPSEC backoff on detection signals.
Blocked engagements (no ownership proof) exit non-zero with the reason —
nothing aggressive ever runs unverified.

## Setup

Prerequisites: Node 20+, a DeepSeek Harness install (`dsh`), a SecScan MCP-scope
token, a DeepSeek API key, and an Alibaba Model Studio API key (Qwen — the
exploiter's reasoning engine).

```bash
# 1. Install the plugin into a harness profile
dsh plugin --profile redteam add ./harness-plugin
# then merge harness-plugin/cordis.patch.yml into the profile's cordis.patch.yml
# (adds the dsh-mcp-client entry -> https://secscan.us/api/mcp)

# 2. Keys — environment ONLY, never in code or docs.
#    Enter all three via the Secure Vault; they land in the environment.
export SECSCAN_MCP_TOKEN="..."  # secscan.us/settings -> AI editors (MCP scope)
export DEEPSEEK_API_KEY="..."
export QWEN_API_KEY=<redacted>   # Alibaba Model Studio; DASHSCOPE_API_KEY also accepted
# NOTE: an API-scope (ssk_) token does NOT work for the MCP endpoint; scopes are separate.

# 3. Build & typecheck
npm install && npm run typecheck

# 4. Run the auth-gate tests (no network needed)
npm test --workspace @secscan/redteam-auth-gate
```

Start an engagement: copy `engagements/engagement-template.md`, then prove
domain ownership through the SecScan server — call `start_domain_verification`
for the target domain (the server issues a `secscan-verify-…` challenge),
publish it as a DNS TXT record at `_secscan-challenge.<domain>`, and confirm
with `check_domain_verification`. Until the server lists the domain as
verified, the engagement runs passive-only; the auth gate enforces this
mechanically by re-checking `list_verified_domains` itself.

## Engagement model

Paid B2B, per engagement: scoping call → ROE contract → client proves domain
ownership (server flow) → coordinator plans (ATT&CK-mapped, adversary
profile) → recon (SecScan engine) → dynamic exploitation (three-category
battery, ruthless but non-destructive) → client-ready report (executive
summary, authorization statement, ATT&CK timeline, evidence-backed findings
with fixes, detection gaps, honest limits, retest checklist) → one retest
pass after remediation. The Red Team Console's Live tab runs the whole thing:
engagement form → ownership-verification panel → live event feed →
phase/ATT&CK timeline → findings as they land → downloadable report.

## What's real in v0.5.0

**Real (works today):** everything in v0.4.0, plus —
- **Qwen reasoning engine** — the exploiter (the heavy-reasoning black-hat
  brain) runs on `qwen3.8-max` via Alibaba Model Studio (strongest Qwen
  reasoning, thinking on by default); coordinator/recon/reporter stay on
  `deepseek-flash` for cost discipline. The llm-router was built
  provider-pluggable for exactly this: adding Qwen meant one new provider
  class + registration + a policy line — no harness changes. Thinking traces
  surface in the event feed as `[thinking]` blocks. Key via `QWEN_API_KEY`
  (or `DASHSCOPE_API_KEY`) in the environment / Secure Vault, never in code.
- **The registry** — the product's compounding attack intelligence:
  `engagements/registry.json` persists confirmed findings (vuln class,
  technique, ATT&CK ID, target fingerprint, payload pattern, evidence ref)
  and killed hypotheses (what was tried + the killing observation, so dead
  ends are never repeated). The exploiter queries it when forming hypotheses
  and writes back every verdict live. Seeded with the v0.3.x secscan.us
  engagement (10 killed, 4 confirmed).
- **Role fidelity** — each agent embodies its role in its prompt (exploiter
  thinks black-hat, recon is a patient scout, coordinator is an operation
  commander, reporter is a merciless auditor); the coordinator enforces
  role discipline at every handoff.
- **Technique fusion** — the exploiter's loop has an explicit FUSE step:
  old primitive + new development = novel probe, not replayed payloads.
- **Megazord cohesion** — one shared operation state (plan, target map,
  findings, killed hypotheses, registry hits, battery) appended to every
  tool observation; coordinator sign-off gates every phase transition
  (plan→recon→exploit→report); the coordinator can redirect (bounded
  re-recon when the exploiter hits a wall) or abort on stop conditions.
- **Dynamic orchestration** — the coordinator decomposes the operation into
  small discrete tasks, delegates each to a specialist subagent (fresh
  foundation loop), and re-plans after every observation round: pivot,
  escalate, go stealthy, back off, or fan out. Red fans out up to 3 parallel
  tasks; black runs strictly one at a time (stealth).
- 43 unit tests (runner), 17 (auth-gate). CLI: `start`, `queue`, `watch`.

## What's real in v0.4.0

**Real (works today):**
- `auth-gate` — server-authoritative verification + pre-execute decision
  logic, unit-tested, fails closed.
- `runner` — live engagement loop as code (authorize → plan → recon →
  exploit → report), red/black modes, ROE enforcement (scope, technique
  exclusions, blackout windows, test window, stop conditions), systematic
  24-item attack battery with per-category coverage enforcement, ATT&CK +
  OWASP mapping, JSONL event streaming, 32 unit tests. CLI: `start`, `queue`,
  `watch`.
- `agents/` — role prompts with ReAct loops; the exploiter prompt now carries
  the full three-category battery (logic flaws, functionality abuse,
  validation rigor) with black-mode stealth variants.
- `llm-router` — provider registry, per-role model policy (flash for
  coordinator/recon/reporter, qwen3.8-max for the exploiter), DeepSeek + Qwen
  wire clients.
- `harness-plugin` — verified against the real harness contracts; installs
  the auth gate as a `tools/pre-execute` hook.
- Red Team Console — Live tab wired to the runner (engagement form, red/black
  mode, ROE fields, verification panel, live event feed, ATT&CK timeline,
  battery coverage, findings, OPSEC notes, report download); the 2026-10-01
  replay remains a permanent read-only archive.
- Proven in combat: full passive + aggressive + D-4 engagements against
  secscan.us (v0.3.x) — Grade A, 8 hypotheses killed, reports in
  `engagements/`.

**Stubbed / planned:**
- More providers (Claude, ChatGPT, Gemini, GLM, Kimi — the runner-up) —
  interface ready, implementations not started.
- Streaming in the router (`complete()` is request/response).
- OAST infrastructure for SSRF canary callbacks (D-1); second test account
  for cross-account IDOR (D-2).

## Naming

`secscan-redteam` is a working name. Rename freely — the moving parts are the
package names (`@secscan/redteam-*`) and the plugin id in
`harness-plugin/cordis.patch.yml`.

## Security & legal

- API keys via environment / Secure Vault ONLY. The bridge, router, and docs
  never log, print, or persist keys. `.gitignore` blocks `.env` files.
- Active testing requires proven domain ownership (SecScan server
  verification: `start_domain_verification` → TXT at
  `_secscan-challenge.<domain>` → `check_domain_verification`), enforced at
  the tool layer. Unauthorized pentesting is illegal;
  the gate cannot be overridden in-chat.
- This repo is PRIVATE. It is the paid product's secret sauce: prompts,
  policy, and engagement machinery.

## Roadmap

1. ~~Install into a live `dsh` profile; run a first passive engagement.~~ Done (v0.2.1).
2. ~~Complete a verified-ownership aggressive engagement end-to-end.~~ Done (v0.3.x — Grade A).
3. ~~Runner CLI + engagement state persistence.~~ Done (v0.4.0).
4. ~~Console live-run launcher.~~ Done (v0.4.0).
5. Wrap the router as harness `LlmAdapter` streaming subclasses.
6. Add the second provider (per business priority).
7. OAST infrastructure + second test account (clears D-1, D-2).
