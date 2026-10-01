# Engagement: secscan.us — first live passive assessment

## 1. Client & scope

- Client: the site owner (owner-authorized test, operator-confirmed in chat 2026-10-01)
- Contact: via operator (Cho-zen1 session)
- Scope (exact hosts — nothing else touched): `https://secscan.us` apex + `www.secscan.us`
- Test window: 2026-10-01 ~05:05 → 05:40 CDT (America/Chicago)
- Provided credentials: DeepSeek API key + SecScan MCP token, transient env-only for this run (never persisted)
- Out-of-scope notes: `secscan.info` (referenced by security.txt/robots, untouched), `seclayer.app` (prior scans exist on the account, untouched), all subdomains beyond passive apex DNS

## 2. Authorization

- Passive phase (05:05–05:40 CDT): UNVERIFIED — ran passive-only; auth gate armed,
  server independently enforced passive-only checks.
- Aggressive phase (~07:20 CDT): **VERIFIED** — SecScan server `check_domain_verification`
  passed for `secscan.us` (DNS TXT at `_secscan-challenge.secscan.us`, server-issued
  challenge `secscan-verify-…`). Initial record was published without the leading
  underscore (`secscan-challenge.secscan.us`); verification failed until corrected.
  Per v0.2.2 the server is the sole authorization authority.
- Verified by: SecScan server (`check_domain_verification`), confirmed by coordinator

## 3. Rules of engagement

1. Non-destructive testing only: no data writes/deletes, no DoS, no resource exhaustion, no credential stuffing, no pivoting outside scoped hosts.
2. Findings reported with evidence; nothing exploited beyond proof (no exploitation performed — unverified).
3. Client may halt at any time.
4. One scan credit spent (1 of 3 free monthly scans); all other calls read-only and free.

## 4. Execution log

| Time (CDT) | Phase | Actor | Action | Result |
|---|---|---|---|---|
| 05:05 | scope | coordinator (deepseek-flash) | Stated authorization basis; called `list_verified_domains()` | "No verified domains yet — scans get passive checks only." → PASSIVE ONLY confirmed |
| 05:06 | scope | coordinator | Issued bounded recon brief (apex+www, passive only, one pass) | Brief queued; recon dispatched |
| 05:08 | recon | recon (deepseek-flash) | `scan_url("https://secscan.us")` | Scan started: `b2de7005-d728-4a48-a54d-966141cda82d`, paid with free scan |
| 05:08 | recon | recon | REASON: one in-flight scan is the right first artifact; ACT: `get_scan_status(scan_id, wait_seconds=60)` | — |
| 05:11 | recon | operator (harness runtime) | Executed recon's tool call | Scan COMPLETE 10:11:11Z. Grade A, risk 1/100. 0 crit / 0 high / 0 med / 1 low / 2 info. 22 of 44 tests ran; 21 skipped (unverified); 1 failed (SSL Labs) |
| 05:12 | recon | operator | Passive HTTP GETs: apex headers, /robots.txt, /sitemap.xml, /.well-known/security.txt | Server: cloudflare; HSTS preload; XFO DENY; nosniff; CSP captured. robots.txt 200 (5984 B, route map). security.txt 200 (contact security@secscan.us) |
| 05:15 | recon | recon (deepseek-flash) | Produced attack-surface brief | 8 ranked entry points, confidence-tagged fingerprint, auth flows, 5 anomalies, no-go notes. Evidence: `evidence/recon-brief.md` |
| 05:20 | exploit | exploiter (deepseek-v4-pro) | Read-only reasoning over passive findings (no tool calls — unverified) | 9 ranked hypotheses, ALL marked UNTESTED, each with confirm/kill observation + deferred test plan. Boundary respected. Evidence: `evidence/exploiter-reasoning.md` |
| 05:30 | report | reporter (deepseek-flash) | Drafted client report | Exec summary, authorization statement, 3 severity-ordered findings w/ evidence+fix+retest, methodology, retest checklist, deferred-testing section. Evidence: `evidence/client-report.md` |
| 05:35 | close | operator | Engagement file written; v0.2.1 committed | — |

### Aggressive phase (~07:20–07:45 CDT) — authorization VERIFIED, gate open

| Time (CDT) | Phase | Actor | Action | Result |
|---|---|---|---|---|
| ~07:20 | scope | coordinator (deepseek-flash) | Re-ran `check_domain_verification({"domain":"secscan.us"})` after DNS correction | VERIFIED — aggressive tier authorized |
| ~07:20 | scope | coordinator | `get_account` quota check | 0 of 3 free scans left (renew 2026-11-01), 0 credits → aggressive `scan_url` SKIPPED; exploiter battery authorized as substitute |
| ~07:22 | exploit | exploiter (deepseek-v4-pro) | H1: API unauth surface — GET/OPTIONS over `/api/*`, `/api/v1/*`; unauth probes incl. fabricated scan IDs | All 404/uniform-401; public openapi.json by design → KILLED |
| ~07:25 | exploit | exploiter | Web-app `/api/*` namespace from JS bundle (auth/user, account/tokens, domain-verifications, scans, monitor, billing) | Uniform 401s; `/api/auth/user` → 200 `{"user":null}` → KILLED |
| ~07:27 | exploit | exploiter | H4: `GET /report/1`, `GET /share/test` (fake IDs) | Generic SPA shell only, zero data → not confirmed; cross-account DEFERRED (needs 2nd account) |
| ~07:29 | exploit | exploiter | H3: X-Forwarded-Host reflection test; Host override test | 0 reflections; edge rejects mismatched Host → host vector KILLED; token entropy DEFERRED (needs test account) |
| ~07:31 | exploit | exploiter | H5: WebSocket — full 1.27MB bundle search | Zero WS/EventSource refs → KILLED (no channel exists) |
| ~07:33 | exploit | exploiter | H6: full robots.txt body, sitemap.xml, llms.txt review | 5,984B fully explained (AI-bot groups); no new routes → KILLED |
| ~07:35 | exploit | exploiter | H7: CSS injection — 4 query-param probes (`<style>`, style-attr breakouts) on `/` and `/scan` | 0 reflections → KILLED as live vector |
| ~07:36 | exploit | exploiter | H8: `GET https://www.secscan.us/` | Clean 301 to apex, no reflection → KILLED |
| ~07:37 | exploit | exploiter | H9: DNSSEC via DNS-over-HTTPS (DS + DNSKEY) | NOERROR, no records → CONFIRMED off |
| ~07:38 | exploit | exploiter | H10: TLS handshake analysis | TLSv1.3 / AES-256-GCM / ECDSA P-256, chain OK → KILLED as concern (early direct-connect reading discarded as resolver artifact) |
| ~07:38 | exploit | exploiter | Scope-confusion positive control (prior round): `POST /api/mcp/%2e%2e/v1/scans` vs control | 404 vs 401 → KILLED, gate holds |
| ~07:40 | exploit | exploiter (deepseek-v4-pro) | Verdict synthesis over all probe evidence | 8 KILLED, 1 CONFIRMED (DNSSEC), 4 DEFERRED — evidence: `evidence/aggressive-battery-2026-10-01.md` |
| ~07:42 | report | reporter (deepseek-flash) | Full client report | Exec summary, authorization statement, 3 findings (1 LOW, 2 INFO), 6 positive controls, methodology, retest checklist, 4 deferred items. Evidence: `evidence/client-report-aggressive.md` |
| ~07:45 | close | operator | Engagement log + evidence committed | v0.3.0 |

## 5. Findings summary

### Passive phase (reporter, 05:30)
- **F-1 [LOW]** CSP `style-src 'unsafe-inline'` — drop `'unsafe-inline'`, keep `style-src 'self'` (nonce/hash if inline styles remain). Evidence: response header, observed twice.
- **F-2 [INFO]** DNSSEC not enabled — enable at registrar/DNS host. Evidence: no DNSKEY records.
- **F-3 [INFO]** 21 of 44 tests unassessed (injection, XSS, path traversal, access control, SSRF, exposed backend data) — Grade A reflects a passive test set, not a clean bill.

### Aggressive phase (reporter, ~07:42) — full report: `evidence/client-report-aggressive.md`
- **F-1 [LOW]** CSP `style-src 'unsafe-inline'` — re-confirmed; active CSS-injection probes (4 payloads) returned zero reflections, so the directive is latent, not live. Fix: remove `'unsafe-inline'` (nonce/hash for needed inline styles).
- **F-2 [INFO]** DNSSEC not enabled — re-confirmed via DNS-over-HTTPS (no DS/DNSKEY records).
- **F-3 [INFO]** `robots.txt` advertises the sensitive route namespace (by design; routes themselves properly gated).
- **Positive controls (tested, holding):** uniform 401s across both API namespaces (no IDOR oracle); scope-confusion traversal killed (404 vs 401); www 301s cleanly to apex; X-Forwarded-Host not reflected; mismatched Host rejected at edge; no WebSocket channel in bundle; TLS 1.3 + valid ECDSA chain; no input reflection on tested pages.
- **Deferred:** D-1 SSRF canary (needs OAST infra); D-2 cross-account IDOR (needs 2nd test account); D-3 reset-token entropy (needs test account + approved triggers); D-4 scanner's 21 skipped active tests (needs credits, renew 2026-11-01).

No Critical / High / Medium findings in either phase. Nothing destructive was attempted or performed.

## 6. Close-out

- Passive report: `evidence/client-report.md` (in-repo; deliver to client out-of-band)
- Aggressive report: `evidence/client-report-aggressive.md` (in-repo; deliver to client out-of-band)
- Retest scheduled: after F-1/F-2 fixes + D-1…D-4 deferred items (credits renew 2026-11-01)
- Token revoked / engagement closed: transient tokens used env-only, never persisted; nothing to revoke server-side

## Evidence index

- `evidence/scan-b2de7005-report.json` — raw SecScan report JSON (passive)
- `evidence/recon-brief.md` — recon attack-surface brief
- `evidence/exploiter-reasoning.md` — exploiter ranked hypotheses (passive phase)
- `evidence/client-report.md` — passive-phase client deliverable
- `evidence/aggressive-battery-2026-10-01.md` — aggressive probe-by-probe record
- `evidence/client-report-aggressive.md` — aggressive-phase client deliverable


## Aggressive-phase authorization check (2026-10-01 ~07:13 CDT) — was BLOCKED, then CLEARED
- First `check_domain_verification({"domain":"secscan.us"})` → NOT VERIFIED: the TXT record
  was published at `secscan-challenge.secscan.us` (missing leading underscore).
- `get_account` → 0 of 3 free scans left (renew 2026-11-01), 0 credits, plan none.
  Aggressive `scan_url` skipped for lack of quota; exploiter battery ran as substitute.
- User corrected the record to `_secscan-challenge.secscan.us`; re-check ~07:20 CDT → VERIFIED.
  Aggressive battery executed 07:20–07:45 (see log above).

## D-4 deferred leg attempt (2026-10-01 ~07:40 CDT) — BLOCKED: verification is token-scoped
- User supplied a fresh MCP token; `get_account` → 3 of 3 free scans (renew 2026-11-01) — quota available.
- `check_domain_verification({"domain":"secscan.us"})` → "No verification started for that domain";
  `list_verified_domains` → none. Verification state is per-token: the new token is a different
  account/session than the one verified this morning, so the morning's proof does not carry over.
- `start_domain_verification({"domain":"secscan.us"})` issued a NEW challenge for this token:
  publish TXT `secscan-verify-dcef4086eb84b2958be413c676f5b880` at `_secscan-challenge.secscan.us`
  (or serve it at `https://secscan.us/.well-known/secscan-verification.txt`), then re-check.
- Aggressive `scan_url` NOT run — awaiting the user's DNS update. Re-dispatch this leg once verified.

## D-4 deferred leg — COMPLETED (2026-10-01 07:46 CDT)

| Time (CDT) | Phase | Actor | Action | Result |
|---|---|---|---|---|
| 07:45 | Auth | Coordinator | `check_domain_verification({"domain":"secscan.us"})` under fresh token | VERIFIED (DNS record). "Its scans now include active tests." |
| 07:45 | Recon | Recon agent | `scan_url("https://secscan.us", aggressive=true)` | Scan started: `e78f4581-d393-4ed5-822d-dbf2a587c1d3`, paid with free credit |
| 07:46 | Recon | Recon agent | `get_scan_status` (wait 60s) → complete | Grade A, risk 1/100 — 0 critical, 0 high, 0 medium, 1 low, 2 info. 33 of 44 tests ran, 11 skipped (all not-applicable), 0 failed. Report: `0f0102d9-2011-45b4-b795-b61d915ce26e` |
| 07:46 | Recon | Recon agent | `get_report` full results | Findings: (LOW) CSP `style-src 'unsafe-inline'` (CWE-79, re-confirmed); (INFO) DNSSEC off (CWE-345); (INFO, NEW) TLS 1.0/1.1 still accepted, SSL Labs grade B (CWE-326, BEAST) |
| 07:47 | Reporter | Reporter agent | Updated `evidence/client-report-aggressive.md` | Folded aggressive scan in: new finding F-4 (TLS 1.0/1.1 INFO), F-1 evidence extended, §2 authorization rewritten (scan e78f4581 executed), D-4 marked completed, retest checklist updated |

**D-4 verdict:** the 21 skipped active tests from the passive phase are now resolved — every *applicable* active test ran (33/44; the 11 skips are not-applicable-to-target, not blocked). No new critical/high/medium findings. The one genuinely new item is the TLS 1.0/1.1 INFO (F-4). Overall engagement conclusion stands: **no exploitable vulnerabilities found**; 1 LOW hardening item, 3 INFO items, 8 hypotheses killed, 3 deferred (D-1…D-3 need canary infra / second test account).

## Evidence index (updated)

- `evidence/scan-b2de7005-report.json` — raw SecScan report JSON (passive)
- `evidence/recon-brief.md` — recon attack-surface brief
- `evidence/exploiter-reasoning.md` — exploiter ranked hypotheses (passive phase)
- `evidence/client-report.md` — passive-phase client deliverable
- `evidence/aggressive-battery-2026-10-01.md` — aggressive probe-by-probe record
- `evidence/client-report-aggressive.md` — aggressive-phase client deliverable (updated with D-4 scan)
- `evidence/scan-e78f4581-report.txt` — raw aggressive scanner report text (scan e78f4581, report 0f0102d9)
