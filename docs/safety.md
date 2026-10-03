# Safety case — secscan-redteam v0.13.0

Production safety is the #1 buying gate for autonomous penetration testing.
This document states what the runner **mechanically enforces** (not what the
agents were prompted to do), what it does **not** promise, and what the
**operator** is responsible for. It is written for a buyer's security team.

The machine-readable version of this case ships with every engagement as
`safety-manifest.json` (+ human-readable `safety-manifest.md`), and is
embedded in the compliance pack's safety section.

## Protections in force (runner-enforced, not prompt-based)

The agents are instructed to be careful. The runner doesn't trust them:

| Protection | What it mechanically does |
|---|---|
| **Exact-hostname scope enforcement** | Every tool call's target must exactly match a host in the declared ROE scope — before any packet is sent. Out-of-scope = refused, logged. |
| **Destructive-command denylist** | 20+ patterns (recursive deletes, formats, raw disk writes, shutdown/reboot, shadow-copy deletion, ransomware patterns…) refused fail-closed. Refusals are DENIED events the coordinator re-plans around. |
| **DoS exclusion (always)** | ATT&CK T1499 excluded in every mode; DoS modules and destructive payloads refused by the Metasploit policy layer. No exceptions. |
| **Canary-only payload policy** | Validated exploits execute a runner-built benign marker (`echo REDTEAM-MARKER-*`) — nothing else. The marker echoing back IS the validation. |
| **Per-target rate limiting** | Token bucket per host: 5 req/s staging, 2 req/s production (production cap applied mechanically even if configured higher). Every probe/exec tool acquires a slot. |
| **Per-target auto-halt** | 5 consecutive target-distress outcomes (errors, refusals, timeouts, 5xx) — or ≥50% distress over the last 20 — halts that target. No further traffic to it this engagement; other targets continue. |
| **Kill switch** | Coordinator/operator abort terminates every in-flight execution across all parallel tasks; new work is refused. |
| **Credential hygiene** | Credentials come from environment/Secure Vault only, never in code, never in args, redacted from logs, errors, events, and reports. Missing credentials = fail fast. |
| **PII redaction** | Tool outputs are scrubbed (email, phone, SSN-like, card-like with Luhn check) before the audit log, agent context, finding evidence, and reports. |
| **Full audit log** | Every action → `events.jsonl` with ATT&CK ID. The zero-disruption record is *derived from this log* — counted refusals, not assertions. |
| **Phase sign-off gates** | Coordinator approves plan→recon→exploit→report. `msf_exec run` is refused outside the exploit phase — mechanically. |
| **Staging→production graduation** | `staging` (default) runs the full battery. `production` requires explicit operator confirmation (`--confirm-production` / `REDTEAM_PROD_CONFIRM=1`) — without it the runner refuses to start, before any packet. |

## The zero-disruption record

After each engagement the runner derives, from the audit log:

- destructive-denylist refusals, DoS refusals, out-of-scope refusals, policy refusals
- per-target auto-halts, kill-switch aborts
- **destructive actions fired** — counted, never assumed; the record is only clean at 0

`CLEAN: 0 destructive actions fired` is the line your security team looks for
in `safety-manifest.md`.

## Residual risks (stated honestly)

A safety case with no residual risks is marketing. Ours:

1. A validated exploit still executes a benign command on the target — the canary is harmless by construction, but it *is* code execution on your infrastructure.
2. Rate limits bound volume, not cleverness — one well-formed request can still hit an expensive code path.
3. Auto-halt reacts to distress signals; silent degradation may not trip it before the engagement's own caps do.
4. PII redaction is pattern-based — novel shapes or PII inside encoded blobs may pass through.
5. The destructive denylist matches command *text*; novel formulations are caught only if agent prompts hold.
6. Credential material lives in *your* environment/vault — we redact it everywhere we can see, but can't protect your handling of it.

## Operator responsibilities

The runner enforces the mechanics; the human owns the judgment:

- **Be reachable for the engagement's duration.** The 24/7 override is you: `abort_engagement` (coordinator tool) → kill switch. For scheduled multi-day runs, name the on-call human in the ROE.
- **Confirm production explicitly.** Staging is the default for a reason. `--confirm-production` is a deliberate act, not a default.
- **Supply test-account credentials** via environment or Secure Vault — never shared accounts, never production credentials.
- **Declare scope exactly.** The allowlist is exact-hostname; `app.example.com` does not cover `api.example.com`.
- **Review the safety manifest** (`safety-manifest.md`) with each report — it's written for exactly this review.
- **Graduate staging→production.** Run staging first; production is the same battery with confirmation and tighter limits, not a first run.

## What we never claim

- Not "zero risk". We claim specific protections and what they mechanically enforce (above), plus the residual risks (above).
- Not compliance or certification. The compliance pack is *evidence* for your QSA/auditor — the judgment is theirs.
- The tester is an AI agent team under mechanical rails, not a human pentester. Assessor guidance on tester qualification is in the compliance pack's methodology section.
