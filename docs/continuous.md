# Continuous testing (v0.16.0)

One-shot engagements prove a point in time. Buyers require "annually **and
after any significant change**" — the second clause is what continuous
testing satisfies, and it's the fastest-growing slice of the pentest
market. The watcher turns the runner into a continuous operation: a
standing profile, a rolling baseline, and drift detection with teeth.

## The moving parts

| Piece | Where | What it does |
|---|---|---|
| Watch profile | `<profile>.json` (your repo, next to the authorization paperwork) | What to test, how often, until when the authorization is fresh |
| Rolling baseline | `<profile-home>/baseline.json` | Every confirmed finding ever seen, keyed stably across runs |
| Drift detection | per cycle | new / unchanged / reopened / remediated / needs-review |
| Alerts | Slack + ticketing | Immediate alert on new critical/high; tickets for every new finding |
| Runs | `<profile-home>/runs/<engagement-id>/` | Each cycle is a full engagement dir, linked to the profile |

## Profile reference

```json
{
  "version": 1,
  "name": "acme-external-weekly",
  "engagement": {
    "target": "acme.com",
    "mode": "red",
    "objective": "continuous external attack-surface validation",
    "roe": { "scope": ["acme.com", "app.acme.com"] },
    "client": "Acme Corp",
    "operatorName": "J. Operator",
    "fullBattery": true,
    "environment": "production",
    "confirmProduction": true
  },
  "cadence": { "intervalHours": 168 },
  "scopeValidUntil": "2026-12-31T23:59:59Z",
  "alertSeverities": ["critical", "high"]
}
```

- `engagement` is the standard `EngagementInput` — scope, ROE, mode,
  battery selection, everything. Targeted subsets ride the existing
  knobs (`targets`, `roe.excludedTechniques`).
- `cadence.intervalHours` — hours between scheduled runs. Must be > 0.
- `scopeValidUntil` — **the authorization freshness contract.** Every
  cycle (scheduled or triggered) refuses to run past this timestamp,
  fail closed, before any packet. Renewal is a human act: fresh client
  authorization → edit the profile. The runner never extends it itself.
- `alertSeverities` — which new-finding severities fire the immediate
  Slack drift alert. Default `["critical", "high"]`.
- `logRetention` (v0.26.0, optional) — `{ "maxBytes": 52428800,
  "maxArchives": 5 }` overrides for this profile's `history.jsonl` and
  its cycle engagement logs. CLI `--log-max-bytes` /
  `--log-max-archives` and `REDTEAM_LOG_*` env vars override these;
  all unset → 50 MiB / 5 archives. See "Log retention" below.

## Running it

```bash
# Loop on the profile's cadence until Ctrl+C (re-reads the profile each
# cycle, so authorization renewals take effect without a restart)
redteam-runner watch --profile ./acme-weekly.json

# Single cycle — for cron/systemd/external schedulers
redteam-runner watch --profile ./acme-weekly.json --once

# Change-aware trigger — run once now, tagged with the change reference
redteam-runner watch --profile ./acme-weekly.json --trigger "deploy abc123"
```

Exit codes: `0` cycle complete · `2` refused (scope authorization
expired) · `1` error.

## CI/CD wiring (the change-aware hook)

The runner ships no HTTP listener on purpose — your pipeline calls the
CLI. Example (GitHub Actions, deploy job, runner host reachable over SSH):

```yaml
- name: Trigger continuous re-test
  run: |
    ssh redteam@runner-host \
      "redteam-runner watch --profile /opt/redteam/acme-weekly.json --trigger 'deploy ${{ github.sha }}'"
```

The triggered run is tagged with the change ref in `drift.json`, the
report's drift section, and the Slack alert — so the finding-to-deploy
correlation is mechanical, not tribal knowledge.

## Drift semantics (the honest part)

Findings are matched across runs by **target + sorted ATT&CK IDs**, not
by finding ID (F-1… is per-run) and not by title (LLM-written, drifts).

| Verdict | Meaning | How it's reached |
|---|---|---|
| new | Confirmed finding with no baseline match | key matching |
| unchanged | Still present | key matching |
| reopened | Absent this run, but reverify reproduced it | PoC bundle re-executed |
| remediated | Absent this run, reverify confirms the fix | **reverify only — never assumed** |
| needs-review | Absent, but couldn't be mechanically resolved | no bundle / target-changed / reverify error |

A finding that didn't reproduce because the *target moved* (connectivity
failure) is `needs-review`, never "fixed." Entries are never deleted —
remediated ones stay as history spanning the finding's lifetime.

## What each cycle writes

- `<runs>/<engagement-id>/` — the full engagement (report, evidence
  pack, PoC bundles, safety manifest, SIEM export) exactly as a
  one-shot run would.
- `<runs>/<engagement-id>/drift.json` — machine-readable drift report.
- Report + compliance pack gain a **Continuous drift** section
  (retest-relevant; `drift.json` is the source of truth).
- `<profile-home>/baseline.json` — the updated rolling baseline.
- `<profile-home>/history.jsonl` — one line per cycle (status, counts,
  change ref).

## Log retention (v0.26.0)

The append-only logs — each engagement's `events.jsonl` and
`engagement.md`, and the watch home's `history.jsonl` — rotate under one
policy so an indefinite watch loop can't exhaust the runner host's disk:

| Setting | Default | Override (highest wins) |
|---|---|---|
| Bytes per log file before rotation | 50 MiB | CLI `--log-max-bytes` → `REDTEAM_LOG_MAX_BYTES` |
| Archives kept per log file | 5 | CLI `--log-max-archives` → `REDTEAM_LOG_MAX_ARCHIVES` |

A watch profile may also set `logRetention: { maxBytes, maxArchives }`
(validated as positive integers at profile load); CLI flags and env vars
override it.

Rotation mechanics:

- The file is **renamed** to `<name>.<UTC-timestamp>` — the archive is
  complete before the fresh file starts, so no data is ever lost mid-rotate.
- The archive is `chmod 444`: immutable, append-never.
- Archives beyond the cap are pruned oldest-first.
- The fresh `events.jsonl` leads with a `log_rotated` audit event naming
  the archive and the seq range it covers; `engagement.md` rotates
  alongside with a rotation row. Seq numbers stay continuous — the audit
  trail is unbroken, and PoC bundles' `auditSeq` references stay
  resolvable to the named archive.
- Rotation I/O failures throw with a clear message (fail closed, never
  silent loss).

Honest contract: the audit trail always records *that* a rotation
happened and *what* was archived. The retention settings determine how
long archives survive — a PoC bundle referencing a seq in a pruned
archive is resolvable only while that archive is retained. Size the caps
to your compliance retention window.

## Safety in continuous mode

Nothing is weakened because the run is scheduled: every cycle runs the
full pipeline — authorization gate, DNS ownership verification, ROE,
rate limits, auto-halt, kill switch, production graduation (set
`confirmProduction: true` in the profile for production targets; the
mechanical check still runs every cycle), destructive denylists, and
the no-DoS policy. The only thing the profile adds is *when* to run
and *until when* the authorization is fresh.

## Authorization freshness

`scopeValidUntil` is the backstop against running forever on stale
paperwork. When it passes:

1. The cycle refuses before any packet (exit 2).
2. A Slack `halted` alert fires (best-effort) naming the expired profile.
3. The refusal is recorded in `history.jsonl`.
4. The loop keeps polling on cadence — editing `scopeValidUntil` with
   fresh authorization resumes cycles without a restart.

The baseline is per-profile and explicit: a `baseline.json` belonging
to a different profile name is never merged — the cycle refuses with
instructions instead.
