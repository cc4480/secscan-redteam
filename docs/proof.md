# The proof standard — v0.14.0

Reproducible proof-of-exploitation is the 2026 credibility standard for
pentest buyers. It is what separates a serious product from "AI-washing":
anyone can claim a finding; a serious product shows the exact steps, the
observed proof, and a way to re-run them.

## What a PoC bundle is

`runner/src/proof/bundle.ts` builds one structured bundle per CONFIRMED
finding, derived **mechanically from the audit log** (`events.jsonl`) —
never reconstructed from memory, never fabricated. Each bundle
(`poc/<finding-id>.json` next to `report.md`) contains:

- finding ID, battery item ID (resolved via ATT&CK → battery lookup),
  ATT&CK IDs, CVE (when tagged), severity, title
- the exact reproduction steps **in order**: tool used, target, the
  redacted command/request as executed, the redacted outcome, timestamp,
  audit-log sequence number — detailed enough that another operator could
  re-run them and expect the same result
- the canary marker sent and the marker echo observed (for execution
  proofs — the echo IS the proof of execution)
- timestamps, target, operator, engagement ID
- `proves` / `doesNotProve`: exactly what the bundle establishes, and
  explicitly what it does not (no impact overclaim)
- the re-verify command for that bundle

Secrets and PII are redacted via the existing redaction before anything
lands in a bundle. Credentials are never stored in bundles.

## The validation bar

A bundle is generated **only** when the audit trail shows a genuine
validation signal, in one of two tiers:

1. **Execution tier** — a canary marker echo was observed: the
   runner-built `REDTEAM-MARKER-*` sent by the tool came back in tool
   output. This proves the specific executed action (e.g. "command
   executed as SYSTEM via MS17-010"). Command-execution tools
   (`ssh_exec`, `winrm_exec`, `msf_exec`, `smb_pth`, `krb_ptt`,
   `rdp_auth`) validate **only** through a marker echo. Operators and
   agents should echo a canary marker in validation commands to reach
   this tier.
2. **Observation tier** — a read-only enumeration tool's output directly
   demonstrates the finding (e.g. `ad_enum` listing an ESC1-vulnerable
   certificate template, `smb_exec` listing an open share). The output
   IS the evidence; no marker is applicable.

No signal → no bundle. Killed hypotheses and unvalidated probes get no
bundle — the report lists the honest absence instead. Steps that ran but
did not validate (e.g. an `msf_exec` run that completed without marker
echo) are still recorded in the sequence for completeness, marked
`validation: "none"` — they are part of the story, not part of the proof.

## Re-verification (the mechanical retest loop)

`runner/src/proof/reverify.ts` + `redteam-runner reverify`:

```
redteam-runner reverify --bundle poc/F-1.json --scope target.example --execute
```

- Without `--execute`: prints the replay plan only. No traffic.
- With `--execute`: requires `--scope` (exact hosts, enforced
  mechanically by the executors — reverify never leaves declared scope).
  Replays `ssh_exec` / `winrm_exec` / `msf_exec` steps with a **fresh**
  canary marker per run (the stale marker is never replayed — its echo
  would prove nothing about the present). Credentials resolve fresh from
  the environment, exactly like the original run. SIGINT sets the kill
  switch.
- Read-only observation steps are reported as skipped: re-reading fresh
  enumeration output is a human retest, and the report says so plainly.

Verdicts:

- **reproduced** — every replayable step re-ran and its validation
  signal re-observed. The finding still holds.
- **not-reproduced** — steps ran but the validation signal did not come
  back. Treat as fixed-or-changed; confirm with a fresh engagement
  before closing the finding. (Also used when a bundle has no
  mechanically replayable steps — the summary says so explicitly.)
- **target-changed** — a step failed on connectivity (unreachable,
  refused, DNS, timeout). The environment moved, not the vulnerability:
  retest when reachable; do **not** mark the finding fixed.

The reverify report JSON is written next to the bundle
(`poc/<finding>.reverify-<ts>.json`) and carries a `registryNote`
telling the operator how the result extends the registry's before/after
chain (re-record a reproduced finding via `record_finding` to log the
fresh observation; never close a finding on a target-changed verdict).

## Negative proof

Where a high-value attack path was tested and killed, the report's
"Negative proof" section records the hypothesis, the decisive
observation that killed it, and the decisive audit events (what was
tried, what was seen). Buyers value knowing what was ruled out — and
the registry already keeps these as negative intelligence; the report
grounds them in the probe sequence.

## Honest limits

- A bundle proves the specific executed/observed action, not full
  impact. "Command executed as SYSTEM" is not "domain compromised"
  unless the chain was actually walked — the `doesNotProve` field says
  this on every bundle.
- Reproduction steps are only as complete as the audit log: tool
  results are redacted summaries (≤800 chars in events). The bundle is
  a faithful extraction of that log, not a superset of it.
- Reverify replays the action, not the moment: target state may have
  legitimately changed (patches, config). `not-reproduced` after a fix
  is the system working.
- The reporter agent is instructed not to invent PoC details; the
  "Proof of exploitation" section is runner-computed and appended
  deterministically, like battery coverage.
