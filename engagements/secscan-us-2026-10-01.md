# Engagement: secscan.us — first live passive assessment

## 1. Client & scope

- Client: the site owner (owner-authorized test, operator-confirmed in chat 2026-10-01)
- Contact: via operator (Cho-zen1 session)
- Scope (exact hosts — nothing else touched): `https://secscan.us` apex + `www.secscan.us`
- Test window: 2026-10-01 ~05:05 → 05:40 CDT (America/Chicago)
- Provided credentials: DeepSeek API key + SecScan MCP token, transient env-only for this run (never persisted)
- Out-of-scope notes: `secscan.info` (referenced by security.txt/robots, untouched), `seclayer.app` (prior scans exist on the account, untouched), all subdomains beyond passive apex DNS

## 2. Authorization

- Engagement token issued: none (not requested)
- Proof method: DNS TXT at `_seclayer-challenge.secscan.us` — NOT published
- Verified at: n/a
- Verified by: n/a

> **UNVERIFIED — this engagement ran PASSIVE ONLY.** The auth gate stayed armed;
> no active test was attempted or requested. The SecScan server independently
> enforces passive-only checks on unverified domains.

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

## 5. Findings summary (from reporter)

- **F-1 [LOW]** CSP `style-src 'unsafe-inline'` — drop `'unsafe-inline'`, keep `style-src 'self'` (nonce/hash if inline styles remain). Evidence: response header (observed twice).
- **F-2 [INFO]** DNSSEC not enabled — enable at registrar/DNS host. Evidence: no DNSKEY records.
- **F-3 [INFO]** 21 of 44 tests unassessed (injection, XSS, path traversal, access control, SSRF, exposed backend data) — Grade A reflects a passive test set, not a clean bill. Next step: publish DNS TXT proof, re-run with active tier.

No Critical / High / Medium findings. No exploitation performed (unverified target).

## 6. Close-out

- Report delivered: `evidence/client-report.md` (in-repo; deliver to client out-of-band)
- Retest scheduled: after DNS TXT verification at `_seclayer-challenge.secscan.us` + F-1 fix
- Token revoked / engagement closed: transient tokens used env-only, never persisted; nothing to revoke server-side

## Evidence index

- `evidence/scan-b2de7005-report.json` — raw SecScan report JSON
- `evidence/recon-brief.md` — recon attack-surface brief
- `evidence/exploiter-reasoning.md` — exploiter ranked hypotheses (all UNTESTED)
- `evidence/client-report.md` — client deliverable

