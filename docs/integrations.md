# Buyer integrations (v0.15.0)

Findings that sit in a folder don't get remediated. Every engagement now
pushes confirmed findings into the buyer's existing workflows: ticketing
(Jira / ServiceNow) with a retest loop, Slack lifecycle notifications,
and a SIEM-ready event stream.

## Setup

Each integration is configured via env / Secure Vault and **fail-closed**:
unconfigured → the runner logs the skip, the report lists it, and the
engagement continues. Nothing about integrations can break a report.

| Integration | Env vars |
|---|---|
| Jira | `REDTEAM_JIRA_BASE_URL` (https URL), `REDTEAM_JIRA_USER` (email), `REDTEAM_JIRA_API_TOKEN`, `REDTEAM_JIRA_PROJECT` (key). Optional: `REDTEAM_JIRA_ISSUE_TYPE` (default `Task`), `REDTEAM_JIRA_PRIORITY_MAP` (JSON overriding severity→priority-id; defaults are stock Jira ids 1=Highest … 5=Lowest) |
| ServiceNow | `REDTEAM_SNOW_INSTANCE` (https URL), `REDTEAM_SNOW_USER`, `REDTEAM_SNOW_PASSWORD`. Optional: `REDTEAM_SNOW_TABLE` (default `incident`; point at `sn_vul_vulnerability` or a custom table if the customer routes vulns there) |
| Slack | `REDTEAM_SLACK_WEBHOOK_URL` (https incoming-webhook URL) |
| SIEM | always on — `siem-events.jsonl` is written next to the report, no config needed |

**Permissions needed.** Jira: a service account with *Create Issues*,
*Add Comments*, and *Transition Issues* in the target project.
ServiceNow: a user with `incident` (or the chosen table) write access.
Slack: an incoming webhook for the target channel.

## Data flow (plainly)

No finding data leaves the runner except to the operator-configured
endpoints above. Ticket content is: the finding title/evidence, the
proof-bundle reference, ATT&CK IDs + CVE as labels, severity-mapped
priority/urgency, and remediation guidance. Secrets and PII are redacted
before anything leaves (the same redaction the audit log uses). The
runner never writes SLA language and never promises remediation — a
ticket asserts the finding and its evidence, nothing more.

Per engagement, the runner writes into the engagement directory:

- `integrations.json` — `findingId → { jiraKey, snowSysId }` linkage,
  consumed later by the `reverify` retest loop.
- `siem-events.jsonl` — one flat JSON event per finding, per proof
  bundle, plus a safety-manifest summary and an engagement-completed
  event (schema v1 — see below).
- `report.md` gains an **Integrations** section listing what was
  attempted, skipped (with the reason), or failed.

## Retest loop

`redteam-runner reverify --bundle poc/F-1.json --execute --scope <host>`
re-executes a PoC bundle's steps. When `integrations.json` sits next to
the bundle and the sinks are configured, the verdict is pushed to the
linked tickets automatically:

- **reproduced** → comment: *STILL PRESENT*
- **not-reproduced** → comment: *VERIFIED FIXED* + best-effort resolve
  transition (Jira Done/Resolve/Close if available; ServiceNow incident
  state 6 with close notes)
- **target-changed** → comment: *TARGET CHANGED — needs human review*
  (never auto-resolved)

## SIEM schema (v1)

Every event carries: `schema_version`, `timestamp`, `vendor`
(`secscan-redteam`), `product` (`redteam-runner`), `engagement_id`,
`event_type` (`finding` | `proof_bundle` | `safety_summary` |
`engagement_completed`), `severity`, `title`, `target`, `operator`,
`attack_ids`, `cve` (or null), `bundle_id` (or null), `detail`.

**Splunk**: index the JSONL as-is; `event_type=finding severity=critical`
is the triage search. **Microsoft Sentinel** idea: ingest via the Log
Analytics HTTP Data Collector API, then an analytic rule like
`RedTeam_CL | where event_type_s == "finding" and severity_s in
("critical","high")` to open incidents per finding, joining on
`bundle_id_s` for the proof evidence.

## Slack lifecycle

`started` → per-phase (`recon`, `exploit`, `report`) → `completed`
(with severity counts) → one `:rotating_light:` alert per critical
finding → `halted` (with reason) on abnormal termination. Best-effort:
a failed webhook is swallowed; the audit log remains the source of truth.

## Honest limits

- Ticket sync covers **confirmed** findings only; killed hypotheses are
  not ticketed (they're negative intelligence, recorded in the report).
- Findings without a PoC bundle are still ticketed — the ticket says so
  explicitly rather than implying proof.
- If Jira/ServiceNow is unreachable mid-engagement, the failure is
  recorded per-finding in the report; nothing is retried silently and
  nothing is dropped silently.
