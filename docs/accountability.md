# Accountability — autonomy tiers + named human accountability (v0.17.0)

The last enterprise buying gate. Buyers reject AI-only testing without a
named human accountable per finding, and they demand graduated autonomy:
agents own frequency/retest, humans own critical assets and accountability.

## Autonomy tiers (mechanically enforced)

| Tier | Name | What the agents may do |
|------|------|------------------------|
| 0 | observe | Read-only recon/enumeration only. No exploitation tool fires — the dispatcher refuses them before any packet. |
| 1 | validate | Tier 0 + single-step validated exploitation with canary markers only. **One validated exploit step per target per engagement** — a second step is refused as chaining. |
| 2 | chain | Tier 1 + multi-step attack chains toward critical assets (`msf_exec run`). Still non-destructive, still no-DoS. |

Enforcement lives in the tool dispatcher (`dispatchTool` in
`runner/src/phases.ts`), not in prompts:

- Every tool has a minimum tier (`toolMinTier` in
  `runner/src/accountability/tiers.ts`). `scan_url` is Tier 0 passive /
  Tier 1 aggressive; `msf_exec` search/suggest is Tier 1, run is Tier 2;
  unknown tools fail closed to Tier 2.
- A tool above the current tier is refused **before any packet, before the
  rate limiter, before the executor**. The denial is an audit event, never
  silent.
- At Tier 1, successful validated exploit steps consume a per-target budget
  of one. Further steps name the re-approval path (Tier 2,
  operator-approved).
- There is **no agent tool that raises the tier**. Escalation happens only
  through `escalateTier()` with a named operator + reason, and the approval
  is recorded *before* the tier moves.

Defaults: **staging → Tier 2** (full battery), **production → Tier 1**
(careful validation). Override with `--tier 0|1|2` (or `REDTEAM_TIER`).

## Tier 2 on production

Multi-step chains against production need their own explicit operator
approval: `--confirm-tier2-production` (or
`REDTEAM_TIER2_PROD_CONFIRM=1`). Without it the runner refuses to start —
fail fast, before the engagement directory is even created. This is
separate from `--confirm-production` (which approves testing production at
all); Tier 2 approves *chaining* on production.

## Named human operator

Production engagements **refuse to start without a named human operator**
(`--operator "<name>"` or `REDTEAM_OPERATOR`). Someone must own the
findings, the tier, and the scope. The operator is:

- stamped onto every finding (`accountableOperator`, set mechanically by
  the runner at report time — the reporter agent cannot change it),
- carried into the compliance pack's per-finding records,
- named in the attestation letter with explicit responsibilities:
  reviewed the findings, approved the autonomy tier, authorized the scope.

## Approval log

Every approval is appended to `approvals.jsonl` (append-only, one file per
engagement): tier declared, tier escalations, production confirmations.
Each entry carries sequence, timestamp, engagement id, operator, kind, and
detail. The log is embedded in the safety manifest and rendered as §7 of
the compliance evidence pack — auditors see who approved what, when.

## Honest limits

- Tiers are a **control boundary**, not a safety guarantee. They state what
  the agents were allowed to do, never that the human did the work — the
  methodology doc describes the agent-driven approach truthfully.
- The approval log records operator *decisions*; it does not verify the
  operator's identity beyond the name they provided.
- A tier never loosens any other rail: scope enforcement, destructive
  denylists, the no-DoS policy, and credential hygiene apply at every tier.
