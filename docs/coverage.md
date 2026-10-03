# Per-item verdict tracking (v0.18.0)

The coverage contract used to be cell-level: 3 categories × selected targets
(12 cells). A cell could report "done" while individual battery items inside
it had never been attempted. This document describes the mechanical
per-item contract that closes that gap.

## The ledger

Every full-battery engagement opens an **item ledger**: one entry per
selected battery item (416 static items across the four target profiles,
plus dynamic per-CVE runtime instances created by `msf_exec`). Each entry
carries exactly one disposition:

| Disposition      | Meaning |
|------------------|---------|
| `pending`        | Not yet attempted (initial state) |
| `confirmed`      | Executed; finding validated (proof bundle exists) |
| `executed-clean` | Executed; no finding (an honest clean result) |
| `killed`         | Hypothesis tested and ruled out — negative intelligence; the exact attempt is dead, the class stays in play |
| `blocked`        | Prerequisite unmet (names which one); reported honestly, never forces extra rounds |
| `na`             | Not applicable **with evidence** (e.g. "target exposes no SMB service", citing the observation) |

The ledger persists per engagement as `item-verdicts.json` next to the
report. It is derived from the audit log and the verdict tools — never
hand-waved.

## How dispositions land

- **Attempted**: any clean tool execution tagged with `batteryItem`
  (e.g. `"SS-042"`) moves the item pending/blocked → `executed-clean`.
  Denials, halts, aborts, refusals, and failed probes never mark anything.
- **Confirmed / killed**: `record_finding` / `record_killed` accept an
  optional `batteryItem` and set the terminal disposition with the
  evidence.
- **Not-applicable**: `record_item_verdict` with `verdict: "na"` — the
  evidence argument is **required**; a bare flag is refused mechanically.
- **Dynamic CVEs**: `msf_exec` runs carrying a `cve` argument create a
  `cve:CVE-…` ledger entry (attackId T1190 + the CVE as the key).

Transition rules are enforced in code, not by prompt: final dispositions
(`confirmed`/`killed`/`na`) cannot be overwritten, except via the reverify
reopen path (which may only move back to `pending`). Unresolvable
`batteryItem` tags are surfaced as audit events, never silently dropped.

## The completion gate

`reportPhase` refuses "battery complete" while **any** selected item is
still `pending`. The report gains an **Item reconciliation** section:
counts per disposition plus the full list of non-clean items with reasons.
The coordinator sees pending items per target × category in its context,
so re-planning aims at real gaps instead of re-probing cells; requesting
finish with items pending forces one more round (once), then the report
records NOT COMPLETE honestly.

## Honest limits

- `blocked` and `na` items never force extra rounds — exactly like blocked
  cells before them.
- `na` requires evidence text naming the observation.
- Killed hypotheses remain negative intelligence per the registry rule —
  they do not blacklist the vulnerability class.
- The ledger is append-only during a run; dispositions move toward
  terminal, never backwards, except reverify.
