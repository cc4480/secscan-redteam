# ATTACK-SURFACE BRIEF — secscan.us (apex + www)

**Mode:** PASSIVE ONLY (confirmed — no verified domains, so scans run passive checks only; OBS 1).
**Scan:** `b2de7005-d728-4a48-a54d-966141cda82d`, COMPLETE 2026-10-01T10:11:11Z. Grade A · risk 1/100 · 1 low, 2 info. 22/44 tests ran; 21 skipped (active, need domain verification); 1 failed (SSL Labs).
**Evidence rule applied:** each item tagged `[2×]` = two independent observations (matches coordinator's rule), `[1×]` = single source, `[gap]` = not observed at all. Sections 1, 3, and 5 contain **hypotheses**, not facts — flagged as such.

---

## 1. Entry points (ranked)

No parameters, exact methods, or auth states were directly observed — only route *strings* leaked via `robots.txt` (OBS 4). Everything below the ranking column is a hypothesis for the exploiter to confirm under verification.

| # | Path | Inferred method | Inferred auth | Why it ranks | Conf |
|---|------|-----------------|---------------|--------------|------|
| 1 | `/api/` | unknown | unknown | Robots advertises the API namespace outright. Scanner confirms injection / authz / SSRF / backend-data all **unassessed** (OBS 3). Highest-value blind spot. No endpoints enumerated — no passive discovery attempted. | [1×] |
| 2 | `/sign-in`, `/register`, `/forgot-password`, `/reset-password`, `/verify-email` | GET (pages) | unauth | Full auth lifecycle exposed. Reset + email-verify are classic token-handling targets (predictability, reuse, host-header). | [1×] |
| 3 | `/scan` | GET (likely) | likely authenticated | A "scan a URL" feature implies **server-side fetching → SSRF hypothesis**. DO NOT test — report only. | [1×] |
| 4 | `/report/`, `/share/` | GET + path param | likely auth or token | Trailing slash = dynamic segment. Object references → **IDOR / share-token enumeration hypothesis**. | [1×] |
| 5 | `/dashboard`, `/monitor`, `/settings`, `/domains` | GET | authenticated | Post-auth surface; access-control unassessed (OBS 3). | [1×] |
| 6 | `/sitemap.xml`, `/robots.txt`, `/.well-known/security.txt`, `/llms.txt` | GET | unauth | Recon artifacts. robots + sitemap + security.txt fetched (OBS 4); `/llms.txt` **mentioned but not fetched** `[gap]`. | [1×] |
| 7 | WebSocket (`ws:`/`wss:` in CSP connect-src) | WS | unknown | CSP explicitly permits `wss:`/`ws:` — implies a live scan/monitor channel. Path unknown. | [1×] |

**Unknowns the exploiter must not assume:** no parameter names, no verb confirmation, no auth-state confirmation. These are route strings, nothing more.

---

## 2. Tech fingerprint

| Component | Verdict | Confidence | Basis |
|-----------|---------|-----------|-------|
| **Next.js App Router** | Likely | **MEDIUM** | Scanner stack signal "Next.js App Router (no `__NEXT_DATA__` block)" (OBS 3). Corroborated only structurally (absence of `__NEXT_DATA__`), not by bundle inspection. Single vendor claim + one consistent artifact. |
| **Cloudflare edge** (CDN/proxy/WAF) | Confirmed | **HIGH** | `Server: cloudflare` (OBS 4), plus Cloudflare-typical HSTS-preload and zero origin-server leakage. Effectively one observation stream. |
| **Node.js runtime** | Inferred | **LOW** | Follows from Next.js only. Not directly observed. |
| **Session mechanism** | Unknown | — | Scanner: "No JWT in page/headers" (OBS 3) — but that's the unauthenticated page only. Does **not** rule out cookie sessions post-login. |

---

## 3. Header + TLS/cert posture

- **HSTS:** `max-age=31536000; includeSubDomains; preload` (OBS 4) `[1×]`.
- **X-Frame-Options:** `DENY`; **X-Content-Type-Options:** `nosniff` (OBS 4).
- **CSP** — `[2×]` (scanner LOW matches operator GET): `default-src 'self'; script-src 'self'` (**no `unsafe-inline`** — strong); `object-src 'none'`; `frame-ancestors 'none'`; `base-uri 'self'`. Deviations: `style-src 'self' 'unsafe-inline'`; permissive `connect-src 'self' https: wss: ws:`; `img-src ... https: blob:`.
- **TLS certificate specifics (issuer, expiry, SANs, protocol/cipher):** `[gap]` — SSL Labs test **failed** (OBS 3), so no independent TLS grade exists. Only HSTS was observed. Do not claim TLS posture beyond what's shown.

---

## 4. Third-party integrations

- **Cloudflare** — edge proxy/CDN/WAF (OBS 4) `[1×]`.
- **secscan.info** — referenced as docs host (`/llms.txt`, docs) in `robots.txt`, and as Policy host in `security.txt` (OBS 4). **OFF-DOMAIN / OUT OF SCOPE — not touched.**
- **First-party WebSocket** implied by CSP (OBS 4) — likely the scan/monitor channel.
- **No analytics, tag manager, or third-party JS bundles observed** — but page HTML/JS were never provided, so **absence cannot be asserted** `[gap]`.

---

## 5. Candidate findings (passive, with confidence + exact observation)

**F1 — CSP `style-src 'unsafe-inline'` · LOW · `[2×]`**
Scanner LOW (CWE-79) + header match (OBS 3, 4). Mitigated hard by strict `script-src 'self'`. Style-injection only; low exploitability.

**F2 — `robots.txt` advertises the sensitive route namespace · INFO · `[1×]` (OBS 4)**
It hands an attacker the full app map: `/api/`, `/dashboard`, `/report/`, `/share/`, all five auth routes. Disclosure-by-design. **HIGH confidence the strings exist; LOW confidence every route is live.**

**F3 — `robots.txt` is 5984 bytes · ANOMALY · `[1×]` (OBS 4)**
Unusually large for a robots file — the disallow list shown is short, so ~5.5 KB is unaccounted for. Strongly suggests extra content (comments, allow rules, more routes) not surfaced in this pass. **Recommend full-body fetch** — passive, cheap, potentially high-yield.

**F4 — DNSSEC not enabled · INFO · `[1×]` (OBS 3).**

**F5 — TLS assessment unavailable · EVIDENCE GAP (not a finding) · `[1×]` (OBS 3).**

**HYPOTHESES — unverified, listed as hypotheses only, NOT tested (per rules):**
- **H1** `/scan` server-side fetch → SSRF. (from OBS 4)
- **H2** `/report/`, `/share/` object references → IDOR / token guessing. (from OBS 4)
- **H3** auth token handling in `/forgot-password`, `/reset-password`, `/verify-email` → predictability/reuse. (from OBS 4)

---

## 6. No-go notes

- **secscan.info** — off-domain; referenced only; **not touched** (OBS 4).
- **No subdomain enumeration** performed beyond passive DNS for the apex; results contain none.
- **www.secscan.us** — **IN SCOPE but NOT observed.** No scan, no GET, and **no apex↔www redirect check was done**. This is the single biggest coverage gap in the pass. `[gap]`
- `/llms.txt` — mentioned by robots, never fetched. `[gap]`
- Active tests (injection, XSS, traversal, access control, SSRF, exposed backend data) were **all skipped** — exploiter cannot run them until the domain is verified (OBS 3).

---

## 7. Process notes for the coordinator

- Free scan consumed; 1 test (SSL Labs) **failed** — may be transient, retry is passive-cheap.
- **Cheapest next passive moves:** full `/robots.txt` body (F3), fetch `/sitemap.xml` + `/llms.txt`, and one passive GET of **www.secscan.us** with a redirect check vs apex (closes the scope gap).
- Nothing in this pass should be escalated to active testing without domain verification — by the coordinator's own rule (OBS 1, 3).

**Bottom line:** a well-hardened Cloudflare-fronted Next.js app (Grade A). The exploiter's best passive leads are the **route map leaked via robots.txt** (F2/F3) and the **unreachable-but-advertised `/api/` namespace**; the real attack value sits behind the *unassessed* hypotheses (H1–H3), none of which may be tested in passive mode.
