# SecScan RedTeam — v0.1 scaffold

> Working name: **secscan-redteam** (renameable — see "Naming" below).

AI red-team pentesting, sold as scoped, authorized, paid B2B engagements.
The system ties the **SecScan scanning engine** (via its real MCP server) to
the **DeepSeek Harness** ("everything is a plugin"), adds a **multi-LLM
router**, and runs a four-role agent team whose exploiter **reasons** —
forming hypotheses from tool output and inventing new tests on the fly,
instead of marching down a static checklist.

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
  │  ├ v4-flash  │  │  │  │ MCP bridge (stdio)      │  │  │
  │  └ v4-pro    │  │  │  │  seclayer_scan          │──┼──┼──► @seclayer/mcp
  │              │  │  │  │  seclayer_list_scans    │  │  │    (real tools,
  │ (anthropic / │  │  │  │  seclayer_get_report    │  │  │     real engine)
  │  openai /    │  │  │  └─────────────────────────┘  │  │
  │  google /    │  │  │  ┌─────────────────────────┐  │  │
  │  zhipu/qwen  │  │  │  │ auth gate (pre-execute) │  │  │
  │  PLANNED)    │  │  │  │  DNS TXT ownership      │  │  │
  └──────────────┘  │  └─────────────────────────┘  │  │
                    │  ┌─────────────────────────┐  │  │
                    │  │ team: coordinator       │  │  │
                    │  │  ├ recon    (flash)     │  │  │
                    │  │  ├ exploiter (pro)      │  │  │
                    │  │  └ reporter  (flash)     │  │  │
                    │  └─────────────────────────┘  │  │
                    └─────────────────────────────────────┘
```

- **harness-plugin/** — bridges the three real SecScan MCP tools into the
  harness tool registry (raw JSON-Schema registration — the documented
  "how MCP-sourced tools arrive"), installs the auth gate as a
  `tools/pre-execute` hook, and adds the red-team usage section to the
  system prompt. Includes the team profile (roles, model assignments, seed
  tasks) in the dsh-agent-teams shape.
- **llm-router/** — provider-pluggable unified LLM interface. v0.1: DeepSeek
  only. `deepseek-flash` (fast, tool use) drives recon loops, the
  coordinator, and the reporter; `deepseek-v4-pro` (premium reasoning)
  drives the exploiter's hypothesis work. Adding providers later = one new
  class implementing `LlmProvider` + `registerProvider()`.
- **agents/** — role system prompts with ReAct loops. The exploiter prompt
  carries a worked dynamic-testing example (reflected input → CSP-aware
  payload pivot → canary-token proof).
- **auth-gate/** — DNS TXT ownership verification
  (`_seclayer-challenge.<domain>`), mirroring SecScan's own gate. Fails
  closed; aggressive testing without proof is denied with remediation
  instructions. Legally non-negotiable.
- **engagements/** — per-client runbook template (scope, authorization,
  rules, log, close-out).

## Setup

Prerequisites: Node 20+, a DeepSeek Harness install (`dsh`), a SecScan API
key, a DeepSeek API key.

```bash
# 1. Install the plugin into a harness profile
dsh plugin --profile redteam add ./harness-plugin
# (or apply harness-plugin/cordis.patch.yml to the profile's bundle layer)

# 2. Keys — environment ONLY, never in code or docs.
#    Enter both via the Secure Vault; they land in the environment.
export SECLAYER_API_KEY="..."   # SecScan dashboard → Developer API Keys
export DEEPSEEK_API_KEY="..."   # DeepSeek platform → API keys

# 3. Build & typecheck
npm install && npm run typecheck

# 4. Run the auth-gate tests (no network needed)
npm test --workspace @secscan/redteam-auth-gate
```

Start an engagement: copy `engagements/engagement-template.md`, issue a
token (`node -e "import('@secscan/redteam-auth-gate').then(m =>
console.log(m.generateEngagementToken()))"`), have the client publish it as a
DNS TXT record, set `SECSCAN_ENGAGEMENT_TOKEN`, and let the coordinator run.

## Engagement model

Paid B2B, per engagement: scoping call → client proves domain ownership →
coordinator runs recon → dynamic exploitation → client-ready report
(executive summary, evidence-backed findings, fixes, retest checklist) →
one retest pass after remediation. Passive-only mode is available for
prospects who haven't completed verification — the gate enforces the
boundary mechanically, not by policy memo.

## What's real vs. stubbed in v0.1

**Real (works today, no keys needed):**
- `auth-gate` — full DNS TXT verification + pre-execute decision logic,
  unit-tested (`npm test`), fails closed. The pure decision function is
  production-grade.
- `agents/` — complete role prompts with ReAct loops and the exploiter's
  worked dynamic-testing example.
- `llm-router` architecture — provider registry, per-role model policy,
  DeepSeek wire client (OpenAI-compatible chat completions + tool-call
  translation). Needs `DEEPSEEK_API_KEY` to run live.

**Wired against documented contracts, not yet executed inside the harness:**
- `harness-plugin` — written exactly against the official cookbook
  contracts (`ctx.tools.register` raw JSON-Schema, `ctx.llm.registerAdapter`
  shape, `tools/pre-execute` hook, `cordis.patch.yml` install). Typechecks
  standalone against a structural mirror of those contracts. Not yet
  installed into a live `dsh` profile — that's the first integration step.
- `mcp-bridge` — spawns the real `@seclayer/mcp` server over stdio and
  registers its real tools; needs `SECLAYER_API_KEY` + network at runtime.

**Stubbed / planned:**
- Non-DeepSeek providers (Claude, ChatGPT, Gemini, GLM, Qwen) — interface
  ready, implementations not started.
- Streaming in the router (`complete()` is request/response; harness
  `LlmAdapter` streaming subclasses are the documented next step).
- A runner CLI that boots the whole engagement end-to-end (`dsh` profile
  session currently plays this role).

## Naming

`secscan-redteam` is a working name. Rename freely — the moving parts are the
package names (`@secscan/redteam-*`) and the plugin id in
`harness-plugin/cordis.patch.yml`.

## Security & legal

- API keys via environment / Secure Vault ONLY. The bridge, router, and docs
  never log, print, or persist keys. `.gitignore` blocks `.env` files.
- Active testing requires proven domain ownership (DNS TXT or well-known
  file), enforced at the tool layer. Unauthorized pentesting is illegal;
  the gate cannot be overridden in-chat.
- This repo is PRIVATE. It is the paid product's secret sauce: prompts,
  policy, and engagement machinery.

## Roadmap

1. Install into a live `dsh` profile; run a first passive engagement.
2. Complete a verified-ownership aggressive engagement end-to-end.
3. Wrap the router as harness `LlmAdapter` streaming subclasses.
4. Add the second provider (per business priority).
5. Runner CLI + engagement state persistence.
