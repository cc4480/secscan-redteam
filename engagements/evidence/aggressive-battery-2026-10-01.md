# Aggressive battery — probe record (2026-10-01 ~07:20–07:45 CDT)

Authorization: SecScan server `check_domain_verification` PASSED for secscan.us
(DNS TXT at `_seclayer-challenge.secscan.us`… corrected to `_secscan-challenge.secscan.us`;
server authoritative). Scope: secscan.us apex + www only. Non-destructive, read-only probes.
No scan credits remained (0 of 3, renews 2026-11-01) — the scanner's aggressive tier did
not run; the exploiter battery below substituted where feasible.

Runtime: harness operator executing the exploiter's ReAct loop; verdicts cross-checked
against deepseek-v4-pro reasoning over the evidence.

## P1 — REST API unauth surface (H1)
- `GET /api/` → 404 `{"error":"Not found"}`
- `GET /api/docs`, `/api/openapi.json`, `/api/swagger.json` → 404 (same body)
- `GET /api/v1` → 404 `{"error":{"code":"not_found","message":"No such endpoint. See /api/v1/openapi.json."}}`
  → disclosed the public spec path (by design; spec documents bearer-auth API)
- `OPTIONS /api/` → 204, `access-control-allow-methods: GET,HEAD,PUT,PATCH,POST,DELETE` (CORS preflight, standard)
- `GET /api/v1/openapi.json` → 200, 6 paths: /me, /openapi.json, /scans (POST+GET),
  /scans/{id}, /scans/{id}/report, /scans/{id}/sarif; security: bearer
- Unauth `GET /api/v1/scans`, `/api/v1/scans/nonexistent-id`, `…/nonexistent-id/report`, `/api/v1/me`
  → ALL uniform 401, byte-identical body (no IDOR oracle via status)
- **VERDICT: KILLED** — no sensitive unauthenticated endpoint; only the public spec is unauth (by design)

## P2 — Web-app API namespace (H1, from JS bundle)
Bundle `/assets/index-Do4ffn3r.js` (1.27MB) references `/api/*` routes (distinct from `/api/v1/*`).
- `GET /api/auth/user` → 200 `{"user":null}` (correct anonymous behavior, no leak)
- `GET /api/account/tokens`, `/api/domain-verifications`, `/api/scans`,
  `/api/monitor/subscriptions`, `/api/billing/status` → uniform 401 `{"error":"Unauthorized"}`
- `GET /api/oauth/authorize/decision` → 404
- **VERDICT: KILLED** — web API namespace properly gated, no differential

## P3 — /report/ + /share/ direct-object probes (H4)
- `GET /report/1` → 200, ~9.1KB generic SPA shell (marketing copy only)
- `GET /share/test` → 200, ~9.2KB generic SPA shell
- Zero scan IDs, grades, tokens, or report data in either body; data loads via authenticated API
- **VERDICT: not confirmed via direct URL** — cross-account object test DEFERRED (needs 2nd test account)

## P4 — Auth token handling (H3)
- `GET /forgot-password` with `X-Forwarded-Host: evil-attacker.example` → 200, 0 reflections
- `Host: evil.example` override → connection rejected by edge (HTTP 000)
- Reset flow is client-rendered; token format not observable without triggering emails
- **VERDICT: host-influence vector KILLED; token entropy/reuse DEFERRED**
  (needs test account + coordinator-approved reset triggers; no reset emails sent)

## P5 — WebSocket (H5)
- Zero WebSocket / EventSource / socket.io references in the full 1.27MB bundle
- **VERDICT: KILLED** — CSP `ws:`/`wss:` is permissive config; no live channel exists to attack

## P6 — robots.txt / sitemap.xml / llms.txt (H6)
- Full 5,984B robots.txt reviewed: entirely explained by 16 AI-bot user-agent groups
  repeating the Disallow list + comments. One comment admits a PAST misconfiguration
  (AI crawlers could reach dashboards and other users' reports — since fixed).
- sitemap.xml: only public pages (/learn, /about, /bot, /privacy, /terms). No new routes.
- **VERDICT: KILLED** — byte count fully accounted for; no hidden route strings

## P7 — CSS injection via style-src 'unsafe-inline' (H7)
- `GET /?q=<style>oast7x</style>`, `/?search="><style>oast7x`,
  `/?name=';background:url(oast7x)`, `/scan?url=oast7x` → all 200, **0 canary reflections**
- **VERDICT: KILLED as a live vector** — directive stays LOW hardening item (latent)

## P8 — www.secscan.us host confusion (H8)
- `GET https://www.secscan.us/` → 301 `Location: https://secscan.us/`, no hostname reflection
- **VERDICT: KILLED** — clean canonical redirect

## P9 — DNSSEC (H9)
- DoH (Cloudflare + Google): DS query → NOERROR, no records; DNSKEY query → NOERROR, no records; AD=false
- **VERDICT: CONFIRMED off** — matches scanner INFO

## P10 — TLS posture (H10)
- Real handshake (via egress proxy to the live edge): TLSv1.3 / TLS_AES_256_GCM_SHA384 /
  X25519, ECDSA P-256 cert, chain verifies OK
- NOTE: an early direct-connect reading suggested TLS 1.3 failure — DISCARDED as artifact
  (this VM's resolver sinkholes direct DNS to a benchmark IP; only the proxied live-edge
  handshake is valid evidence)
- **VERDICT: KILLED as a concern** — modern, valid TLS

## P11 — Scope-confusion / path traversal (prior round, recorded here)
- `POST /api/mcp/%2e%2e/v1/scans` (--path-as-is) → 404 `{"error":"Not found"}`
- Control `POST /api/v1/scans` → 401
- **VERDICT: KILLED** — traversal normalized; scope gate holds (positive control)

## Deferred (not tested)
- D-1 SSRF via /scan — needs OAST canary infrastructure
- D-2 Cross-account IDOR — needs a second test account
- D-3 Reset-token entropy/reuse — needs test account + approved triggers
- D-4 Scanner's 21 skipped active tests — needs scan credits (renew 2026-11-01)
