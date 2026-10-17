# AlterEgo → secscan-redteam: reuse audit (2026-10-17)

**Source:** `cc4480/alterego` @ `main` (public), cloned to the workspace and read in full.
**Question asked:** is there anything worth bringing into `secscan-redteam`?
**Answer:** yes — but as **designs and schemas to port to TypeScript**, not as code to copy.
Three items are genuinely high-value; the rest is polish.

AlterEgo is Python (≈11.2k LOC: 9,003 pc-agent + 2,211 bridge, plus 10 test files /
1,306 lines) and secscan-redteam's runner is TypeScript, so nothing drops in directly.
The value is in four patterns AlterEgo already solved operationally and in the field.

---

## 1. What AlterEgo is (measured, not assumed)

A Windows **PC agent** that gives an AI operator a second self at the keyboard:

- `pc-agent/server.py` — FastAPI + **MCP Streamable HTTP** server on loopback (`127.0.0.1:8765`),
  reached remotely only through a Cloudflare named tunnel the owner starts.
- **63 MCP tools** (`bridge/tools.json`): screenshot, window/UI Automation control, keyboard/mouse,
  file read/write/edit/delete, `shell_exec` / `shell_pwsh`, background jobs, process control,
  Edge **CDP browser** tools, passive recon (`http_headers`, `dns_query`, `tls_info`, `tcp_check`,
  `web_fetch`, `web_search`), `notify`/`speak`, `power`, task bookkeeping, `arbitrate_tool`,
  `doctor`, `query_events`, `replay_session`.
- **Approval gate** (`approval.py`): every write tool pops a native Windows Yes/No dialog;
  timeout/dialog-error/non-interactive all **fail closed**. Tiers: `silent | routine/ask | always_ask`.
  Permission postures: `default | plan | acceptEdits | dontAsk`, with a startup confirmation for
  `dontAsk`.
- **Event-sourced operation log** (`events.py`, `event_types.py`, `projections.py`,
  `event_query.py`): append-only daily JSONL, ULID ids, `caused_by` causality chain, secret redaction,
  projections for session transcript / tool stats / approvals / causal chain, plus
  `verify_session` integrity check and `replay_session`.
- **Hook lifecycle** (`hooks.py`, `HOOKS.md`): PreToolUse → allow / **deny(reason)** / **modify(args)**;
  PostToolUse → keep/replace result; per-hook timeout (fail-closed), and **one event per hook**
  evaluation.
- **Pairing + bearer sessions** (`pairing.py`, `server.py`): 6-digit single-use code, 30-min expiry,
  5-guess lockout, IP allowlist on `/pair`, persistent session token file, revoke-one/revoke-all.
- **Risk profiles + arbitration** (`tool_profiles.py`, `arbitrate.py`): every tool declares
  `blast_radius`, `recoverability` (0-10), `side_effects`, `compensating_action`, `sensitivity_tags`;
  a weighted-linear scorer maps a candidate tool trajectory to `auto | confirm | explicit_intent`
  with a one-line rationale.
- Command policy (`command_rules.py`): JSON allow/deny rules, deny-wins, fnmatch, enforced by a
  PreToolUse hook.
- Tests: 10 files under `pc-agent/tests/` (mock pipeline, staleness guard, safer-edit rules, search,
  background screenshot, web fetch) + two root-level test modules.

---

## 2. Overlap and delta vs secscan-redteam

| Concern | AlterEgo (Python) | secscan-redteam (TS) | Delta worth taking |
|---|---|---|---|
| MCP server face | Streamable HTTP, 63 tools | runner `ui/mcp-endpoint.ts`, 13 tools | **No** — both solved; don't run two servers |
| Human approval | native dialog on the PC | tier + coordinator sign-off + `approvals.jsonl` | **Partial** — tier/risk model, not the dialog |
| Audit/event log | event-sourced, causal, projections, replay | `events.jsonl` + feed + proof bundles | **Yes — schema/causality/projections** |
| Tool gating hooks | Pre/PostToolUse, deny/modify, per-hook events | one `tools/pre-execute` gate | **Yes — hook lifecycle + per-hook audit** |
| Windows execution channel | full PC agent | ssh2 / smb2 / winrm only | **Yes — biggest gap, see R1** |
| Browser automation | Edge CDP: navigate/click/fill/eval/snapshot | none (only `authHeader` on scan_url) | **Yes — authenticated web testing** |
| Operator auth | pairing code → bearer, revoke-all | token printed at console start | **Yes, UX/security upgrade** |
| Risk metadata | per-tool blast radius/recoverability | implicit in tier 0/1/2 | **Yes — machine-readable profiles** |
| Policy rules | operator-editable allow/deny JSON | code-level destructive denylist | **Yes — per-client policy file** |
| Deployment exposure | Cloudflare named tunnel | loopback only | **Adapt — documented option** |

---

## 3. Reuse candidates (ranked)

### R1 — Windows PC-agent channel as a host-exec backend  ★ highest value
**Why it matters here:** our live Windows engagement halted because the only execution channels
(SMB / WinRM / SSH) were unavailable — WinRM closed, no test SMB credentials, RDP off. AlterEgo is
a working, approval-gated, authenticated agent channel for exactly that situation.
**Take:** the *protocol shape* — MCP Streamable HTTP + bearer session + typed tool surface
(`shell_exec`, `shell_pwsh`, `read_file`, `list_dir`, `list_processes`, `screenshot`,
`exec_background`/`exec_status`/`exec_cancel`, `kill_process`).
**Adapt:** replace the on-target Yes/No dialog with the engagement's own authorisation (coordinator
sign-off + tier), because an engagement cannot ask a *target* user for consent; record every call in
the runner's event log instead.
**Integration point:** `runner/src/host-exec/` as a fourth backend next to ssh/smb/winrm; new battery
prerequisite marker `NEEDS_PC_AGENT`; readiness item in the new `tools/readiness.ts`.
**Effort:** medium (MCP client in Node already exists in `runner/src/mcp.ts`; new tool wrappers + tests).
**Risk:** only usable where the operator can run the agent on the target (lab/VM/self-owned), which is
precisely the authorised-engagement case.

### R2 — Event model, causality and projections  ★ high value, low risk
**Take:** `event_types.py` schema conventions (typed events, ULID ids, `caused_by`), redaction keys,
and the four projections: session transcript, tool stats, approval timeline, causal chain;
`verify_session`-style integrity verification.
**Why:** the runner already streams `events.jsonl` and derives proof bundles, but causality is
implicit. Explicit `caused_by` makes proof bundles mechanically explainable ("this observation is
caused by that probe") and makes the compliance pack stronger.
**Integration:** new `runner/src/events/schema.ts` + `projections.ts`; feed them into
`report/phase.ts` and `compliance/`. Add a `verify` projection to the report.
**Effort:** medium; no safety-regression risk.

### R3 — Hook lifecycle for tool gating  ★ high value
**Take:** PreToolUse semantics (`allow | deny(reason) | modify(args)`), PostToolUse
(keep/replace result), per-hook timeout with fail-closed deny, and **one audited event per hook**
(with `caused_by`). This composes with the existing harness `tools/pre-execute` gate.
**Why:** per-client policy (blocked techniques, forbidden hosts, redaction) becomes data, not code,
and every policy decision is visible in the audit log.
**Integration:** `runner/src/dispatch/router.ts` pre/post hook points; `harness-plugin` auth gate can
stay as the outermost hook. Effort: small-medium.

### R4 — Risk profiles + arbitration scorer  ★ medium-high
**Take:** the per-tool metadata table (`blast_radius`, `recoverability` 0-10, `side_effects`,
`compensating_action`, `sensitivity_tags`) and the weighted-linear scorer
(`auto | confirm | explicit_intent` + rationale).
**Why:** the runner's tier model is coarse (0/1/2). Tool-level risk metadata would let it auto-approve
read-only work, force explicit intent on destructive steps, and print *why* in the report — directly
useful for the 418-item battery ledger and for client-facing risk narrative.
**Integration:** `runner/src/safety/` — new `profiles.ts`; map `confirm`/`explicit_intent` onto the
existing sign-off flow. Effort: medium.

### R5 — Browser automation for authenticated web tests  ★ high value for the web battery
**Take:** the CDP approach (`browser_cdp.py`): `snapshot`, `navigate`, `click_text`, `fill_field`,
`eval_js` over an Edge/Chrome CDP endpoint.
**Why:** SS battery items that need a **signed-in session** (IDOR, cross-account access, business
logic, JWT flows) are currently impossible — `scan_url` only accepts an `authHeader`. A browser tool
lets the runner log in and fuzz authenticated surfaces.
**Integration:** new `runner/src/browser/` tool bridge + battery prerequisites; run headless against
the target with the operator-supplied test account.
**Effort:** medium; big coverage unlock.

### R6 — Pairing-based operator auth for the console  ★ medium
**Take:** single-use 6-digit pairing code (expiry, guesses limit, IP allowlist) exchanging for a
persistent bearer token with revoke-one/revoke-all, delivered over TLS.
**Why:** today `REDTEAM_UI_TOKEN` is printed and pasted; pairing is a better UX for remote operators
and revocations are instant. **Caveat:** keep the current token path too — local runs should not
require pairing.
**Effort:** small-medium (`runner/src/ui/auth.ts` + a `/pair` route).

### R7 — Operator-editable command/action policy file  ★ medium
**Take:** `command_rules.py` pattern: JSON `{allow:[], deny:[]}`, deny-wins, fnmatch, enforced by a
hook; missing file = permissive default.
**Why:** per-client engagement policy ("never touch this range", "only these commands") without
patching code; pairs naturally with R3.
**Integration:** `runner/src/host-exec/` + policy loader; ship a default rules file.

### R8 — Permission postures incl. `plan` mode  ★ small
`default | plan | acceptEdits | dontAsk` maps almost 1:1 onto the runner's
`--dry-run` / tier / production-confirm model. Worth aligning names and documenting the mapping so
operators don't have to learn two vocabularies.

### R9 — Deployment + first-run patterns  ⭐ small
`doctor` tool, `startup_confirm.py` for dangerous modes, Cloudflare named-tunnel walkthrough. The
runner now has `redteam-runner doctor` (added 2026-10-17); the *startup confirmation for dangerous
permission modes* and the tunnel deployment doc are still worth borrowing.

### R10 — Test ideas (not code)
`test_staleness_guard.py` and `test_safer_edits_rules.py` are good models for regression tests around
mutable-state hazards; the mock-pipeline tests show how to test the full toolcall path without a PC.

---

## 4. What NOT to take

1. **The on-target approval dialog.** An engagement runs against a target the operator does not
   control; consent must come from the authorisation + coordinator sign-off, not a popup on the target.
   Adopt the *tier/risk* part, drop the *dialog* part.
2. **Python files as-is.** Both codebases are modern but the port is a rewrite, not a copy.
3. **Tunnel-as-auth.** The tunnel URL is explicitly "not a secret"; keep the bearer/token model and
   treat the tunnel as transport only.
4. **A second MCP server.** The runner already speaks Streamable HTTP; adding AlterEgo's server
   alongside would duplicate the face rather than extend it.
5. **Token-on-disk plaintext** (`%APPDATA%\pc-mcp-bridge\token`) — in secscan-redteam credentials
   belong in the Secure Vault / environment, not a readable file.
6. **No license file** in the repo. You own it, so this is fine for internal reuse, but add a license
   before any third-party distribution.

---

## 5. Recommended sequence

1. **Schemas first (no behaviour change).** Port the event schema + `caused_by` + projections (R2) and
   the per-tool risk profiles (R4 as data) into TypeScript with tests. This unlocks everything else
   and improves reporting immediately.
2. **Hooks + policy file (R3, R7).** Add pre/post hook points around dispatch; wire the existing
   auth gate as the first hook; load a per-engagement rules file.
3. **PC-agent backend (R1).** New host-exec backend + battery prerequisite + readiness item. This
   closes the exact field gap: a Windows target with no SMB/WinRM/SSH.
4. **Browser backend (R5).** CDP tool bridge for authenticated web coverage.
5. **Pairing (R6), permission-posture naming (R8), startup confirmation and tunnel docs (R9).**

Expected outcome: the two gaps that actually stopped our engagements — *no Windows channel* and *no
authenticated web testing* — are both covered by AlterEgo patterns, while the audit/report side gets
materially stronger.

---

## 6. Evidence index (files read)

`pc-agent/server.py` (429 LOC) · `toolcall.py` (226) · `events.py` (195) · `event_query.py` (227) ·
`projections.py` · `hooks.py` (206) · `HOOKS.md` · `approval.py` · `auth.py` · `pairing.py` ·
`tool_profiles.py` · `arbitrate.py` · `command_rules.py` · `browser_cdp.py` (236) ·
`startup_confirm.py` · `tests/` · `bridge/tools.json` (63 tools) · `bridge/op_call.py` ·
`docs/setup.md`, `docs/operator.md`, `docs/tools.md` · `README.md`.


---

## 7. Verification (actually run, 2026-10-17) — trust, but verified

Rather than port on faith, both codebases were executed.

### 7.1 AlterEgo's own test suite
`python -m pytest -q` (Python 3.12, venv): **225 passed, 4 failed** in 7.94 s.

The four failures are drift, not crashes:
1. `test_wrappers_register_all` asserts **50** tools; the catalog now has **63** (stale test).
2. `test_edit_replaces_first` expects replace-first; `edit_file` now defaults to
   `require_unique=True` (stale test vs newer, safer behaviour).
3. `test_support_tools` expects `memory_recall` to hit inside a batch — written for the Linux
   provider, fails under the Windows/mock provider used here.
4. `test_search_filenames_sort_mtime_newest_first` — three files written in the same millisecond;
   the `mtime` tie is not deterministically resolved (possible flake, possibly a real
   secondary-sort bug; worth a one-line fix in the port).

### 7.2 Independent cross-check of the reusable subsystems
A standalone harness exercised the seven components we want to borrow. **17/19 checks pass**:

| Subsystem | Verified |
|---|---|
| Risk profiles cover every tool | ❌ **7 of 63 tools have no profile** (`search_files`, `search_filenames`, `read_file_range`, `exec_background`, `exec_status`, `exec_cancel`, `arbitrate_tool`) |
| Approval tier taxonomy | ✅ `silent / routine / ask / always_ask`, 20 read-only tools silent |
| Command rules deny-wins | ✅ `git push` denied even with `allow: git *` |
| Event id (ULID) + `caused_by` | ✅ |
| Secret redaction in the event log | ❌ **nested secrets leak** — `args.token` / `args.nested.password` written in cleartext (redaction is top-level keys only) |
| Projections (transcript / stats / causal chain) | ✅ |
| Hooks allow / deny / modify | ✅ |
| Arbitration ordering | ✅ destructive → `explicit_intent`; benign 1.0 vs destructive 0.091 |
| Pairing: 6-digit, single-use, lockout | ✅ |

### 7.3 Consequences for the port

- **G1 — profile coverage.** `approval_tier` falls back to `always_ask` (fail-closed — safe), but
  `arbitrate.score_trajectory` **raises `ValueError`** for the 7 unprofiled tools. Port rule:
  *every* tool gets a profile, and the scorer uses the fail-closed default instead of raising.
  (Also fixes the "45 tools" docstring / "50 tools" test drift.)
- **G2 — deep redaction.** Port a *recursive* redactor (walk dicts/lists, redact any key matching
  `token|secret|password|passwd|pwd|key`), not the shallow top-level one.
- **Not verifiable headless.** Screenshot/UIA/mouse/browser-CDP need an interactive Windows
  desktop; treat those as *design + interface contract* only, and verify on a real host before
  release. The browser-CDP and PC-agent surfaces are therefore marked "adapt with a separate
  on-host smoke test", not "verified".

**Net:** the audit's reuse ranking holds, with two fixes folded in (G1, G2) and two candidates
downgraded from "verified" to "design-only" (R1 desktop half, R5 CDP execution half).

---

## 8. Implementation status (landed in this repo, v0.34.0)

| Item | Status | Module |
|---|---|---|
| R2 event schema + `causedBy` + projections | **done** — redaction wired into `writeEvent`; report gets a derived activity/causality section | `events/redact.ts`, `events/projections.ts`, `report/activity.ts` |
| G2 deep redaction | **fixed in the port** — recursive by key *and* by known literal secret values | `events/redact.ts` |
| R3 hook lifecycle (allow/deny/modify, timeouts, per-hook audit) | **done** — enforced by the dispatch gate | `hooks/index.ts`, `dispatch/policy-gate.ts` |
| R7 operator policy file (allow/deny, deny-wins) | **done** — parse + glob matcher + dispatch enforcement | `policy/rules.ts` |
| R4 risk profiles + arbitration | **done with G1 fixed** — unknown tools resolve to a fail-closed profile and never throw; scorer, rollback plan, ranking | `safety/risk.ts` |
| R6 operator pairing | **done** — 6-digit, single-use, TTL, lockout, re-arm; opt-in via `REDTEAM_PAIRING=1` | `ui/pairing.ts` |
| R1 Windows PC-agent channel | **verified on-host** — paired with a real AlterEgo agent over MCP Streamable HTTP and executed `system_info` + `list_dir`; the session-id echo was a real defect the smoke caught, and off-allow-list tools are refused locally | `host-exec/pc-agent.ts`, `scripts/smoke-pc-agent.mjs` |
| R5 browser/CDP driver | **verified on-host** — real headless Chrome: endpoint discovery, CDP handshake, navigate, snapshot, fillField, evalJs, and non-http(s) refusal all pass | `browser/cdp.ts`, `browser/cdp-transport.ts`, `scripts/smoke-cdp.mjs` |
| Readiness | `doctor` now also reports the two optional backends | `tools/readiness.ts` |

Verification at landing: `typecheck` clean, build clean, **752 tests pass** (runner 720, including the hooks/policy/risk, optional-backend and CDP
transport suites). R1 and R5 are no longer contracts: both are exercised against real software by
the on-host smoke scripts (`smoke:pc-agent`, `smoke:cdp`), and the browser smoke already caught one
real defect (MCP Streamable HTTP requires echoing `Mcp-Session-Id`).

### 8.1 Also fixed during implementation
- A PowerShell-5.1 patching pass had mangled non-ASCII characters in twelve touched files
  (UTF-8 read as ANSI). All were restored from pristine sources and re-patched with explicit
  UTF-8 I/O; three files with pre-existing double-encoding (`variants/injection.ts`,
  `variants/traversal.ts`, `test/readiness.test.ts`) were repaired to valid UTF-8. This was
  caught by the test suite, which is exactly what it is for.

