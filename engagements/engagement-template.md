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

Ownership is proven through the SecScan server (it is authoritative):

1. `start_domain_verification` for each in-scope domain — the server issues
   a `secscan-verify-…` challenge token.
2. Publish the token as a DNS TXT record at `_secscan-challenge.<domain>`.
3. `check_domain_verification` (or `list_verified_domains`) to confirm.

- Verified at (timestamp):
- Verified by (server check output):

> Until the server lists the domain as verified, the engagement runs
> **passive only**. The auth gate enforces this mechanically by re-checking
> the server's verified-domain list before any aggressive test.

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
