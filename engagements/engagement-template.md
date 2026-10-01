# Engagement runbook — paid B2B red-team engagement

Copy this file per engagement: `engagements/<client>-<date>.md`. It is the
paper trail that the test was scoped and authorized.

## 1. Client & scope

- Client:
- Contact (name, email):
- Scope (exact hosts/paths — nothing else is touched):
- Test window (start → end, timezone):
- Provided credentials (if any — reference the vault entry, never paste):
- Out-of-scope notes:

## 2. Authorization

- Engagement token issued: `sl-verify-…` (store in `SECSCAN_ENGAGEMENT_TOKEN`)
- Proof method: DNS TXT at `_seclayer-challenge.<domain>` / well-known file
- Verified at (timestamp):
- Verified by:

> Until this section is filled, the engagement runs **passive only**.
> The auth gate enforces this mechanically.

## 3. Rules of engagement (read to the client)

1. Non-destructive testing only: no data writes/deletes, no DoS, no resource
   exhaustion, no credential stuffing, no pivoting outside scoped hosts.
2. Findings are reported with evidence; nothing is exploited beyond proof.
3. Client may halt the test at any time — coordinator stops immediately.
4. Report delivery within _ business days of test completion, plus one
   retest pass after remediation.

## 4. Execution log

| Time | Phase | Actor | Action | Result |
|------|-------|-------|--------|--------|
| | scope | coordinator | | |
| | recon | recon | | |
| | exploit | exploiter | | |
| | report | reporter | | |

## 5. Close-out

- Report delivered:
- Retest scheduled:
- Token revoked / engagement closed:
