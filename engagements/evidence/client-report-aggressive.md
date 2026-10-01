# Security Assessment Report — secscan.us

**Target:** `https://secscan.us` (apex + `www.secscan.us`)
**Assessment window:** 2026-10-01, 07:20–07:45 CDT (America/Chicago)
**Prepared by:** SecScan Red Team (Reporter)
**Distribution:** Client CTO

---

## 1. Executive Summary

An owner-authorized, aggressive-tier red-team battery was run against secscan.us on 2026-10-01; the pass was non-destructive and read-only apart from normal GET requests. No critical or high-severity issues were found, and every authorization, host-handling, TLS, and input-reflection control that was tested held. One low-severity configuration weakness was confirmed: the Content-Security-Policy permits inline styles (`style-src 'unsafe-inline'`), which is latent today because no input reflection into style contexts was observed, but would enable CSS-based data exfiltration if a future feature ever reflects user input there. Two informational items were logged — DNSSEC is not enabled, and `robots.txt` advertises the application's sensitive route namespace (a map, not a vulnerability; those routes are properly gated). Four test areas could not be completed this pass because they require out-of-band canaries, a second test account, or scan credits that renew 2026-11-01; they are listed plainly in §4 and §5 so they can be scheduled. Net posture remains strong and consistent with the earlier passive grade of **A (risk 1/100)**.

---

## 2. Authorization Statement

This assessment was performed with explicit owner authorization. SecScan's server-side `check_domain_verification` passed for `secscan.us` via a DNS TXT record at `_secscan-challenge.secscan.us`, verified by the SecScan server. The **aggressive tier** was authorized for this engagement. Testing was constrained to non-destructive, read-only probes (normal GETs plus a small number of parameter and path manipulations that did not mutate state). No authentication bypass, data destruction, or denial-of-service activity was attempted. Note for the record: the scanner's own aggressive-tier scan did **not** execute during this window because the account had 0 of 3 free scan credits remaining (quota renews 2026-11-01); the validated results below come from the hypothesis-driven exploiter pass and the earlier passive scan.

---

## 3. Findings (severity-ordered)

Severity rubric: **severity = business impact × exploitability.** Web-application findings use CVSS-style reasoning. Each finding below is backed only by observed evidence.

### F-1 — Content-Security-Policy allows `style-src 'unsafe-inline'` — **LOW**

**Business impact (plain language).**
Your site tells browsers which styles they are allowed to load, and right now it also permits styles written directly into the page. Nothing is exploiting this today — we fired four injection probes and none of your pages reflected them. But if any future feature (a search box, a profile field, a URL parameter that renders into a style) ever echoes user input into a style context, this permission would let an attacker use CSS to silently leak data — for example, exfiltrating a form field or a session token character-by-character via background-image requests. It is a latent weakness, not an active breach, and it is cheap to close.

**Evidence.**
- Response header observed on apex `200` responses: `style-src 'self' 'unsafe-inline';`
- SecScan passive scanner flagged the same directive (mapped to CWE-79).
- Active exploitation attempt: four query-parameter probes including `<style>` injection and style-attribute breakout payloads, against `/` and `/scan` — **zero reflections** returned. No live injection; the directive is simply more permissive than it needs to be.

**Fix (copy-paste-ready).**
Remove `'unsafe-inline'` from `style-src`, keeping `'self'`. Example directive:

```
Content-Security-Policy: default-src 'self'; style-src 'self'; ...
```

Then migrate the inline styles that required the exception:
- Move inline `style="..."` attributes into your stylesheet, or
- If inline styles are unavoidable, allow them by nonce or hash instead of blanket permission. For a nonce-based policy your server emits a fresh nonce per response and the header becomes:

```
style-src 'self' 'nonce-<random-per-response>';
```

and each permitted `<style nonce="<random-per-response>">` carries the same value. Hash-based (`'sha256-...'`) works the same way without per-request state if your inline styles are static.

**Retest note.**
Re-fetch apex and `www` response headers and confirm `style-src` no longer contains `'unsafe-inline'`; then re-run the four reflection probes against `/` and `/scan` to confirm the new policy does not block legitimate styling (check for console CSP violations on a page that previously relied on inline styles).

---

### F-2 — DNSSEC is not enabled for secscan.us — **INFO**

**Business impact (plain language).**
DNSSEC cryptographically signs your DNS records so that a network attacker cannot quietly redirect your visitors to an impostor site. It is off today. In practice the risk is low because your DNS sits behind Cloudflare and modern resolvers largely use encrypted DNS — but on hostile networks (a café Wi-Fi, a compromised router) a spoofed answer is theoretically possible, and an impostor login page is a phishing hazard for your users. It costs almost nothing to close.

**Evidence.**
- SecScan passive scanner reported DNSSEC **INFO** (not enabled).
- Independent DNS-over-HTTPS queries for both `DS` and `DNSKEY` records returned `NOERROR` with **no records**, confirming no signing chain is published.

**Fix (copy-paste-ready, Cloudflare).**
1. Cloudflare dashboard → your `secscan.us` zone → **DNS → Settings → DNSSEC → Enable**.
2. Cloudflare generates the `DS` record details. Copy them.
3. At your registrar (where `secscan.us` is registered), add the `DS` record exactly as Cloudflare provides it (key tag, algorithm, digest type, digest).
4. Wait for propagation, then verify the chain.

**Retest note.**
Query for a `DS` record at the parent zone (e.g., via Cloudflare’s 1.1.1.1 DoH endpoint or `dig +dnssec DS secscan.us`) — a `DS` record should be returned, and a `DNSKEY` query for `secscan.us` should return records with the **AD** (Authenticated Data) flag set on validating resolvers.

---

### F-3 — `robots.txt` advertises the sensitive route namespace — **INFO**

**Business impact (plain language).**
Your `robots.txt` publicly lists the paths to everything interesting: `/api/`, `/dashboard`, `/scan`, `/monitor`, `/settings`, `/domains`, `/report/`, `/share/`, and all five authentication routes. That is a free application map for anyone who reads it. Crucially, these routes are **properly access-controlled** — we confirmed unauthorized requests are rejected (see the scope gate and API authorization controls below) — so this is disclosure by design, not a vulnerability. It is noted for completeness and because the file's own comments record that AI-crawler groups previously reached dashboards and other users' scan reports (since fixed). The lesson is to keep that fix permanent and never treat `robots.txt` as a security boundary.

**Evidence.**
- Full 5,984-byte `robots.txt` body fetched and reviewed; it lists `/api/`, `/dashboard`, `/scan`, `/monitor`, `/settings`, `/domains`, `/report/`, `/share/`, and all five auth routes.
- The file's own comments state that AI-crawler groups previously could reach dashboards and other users' scan reports, and that this has since been fixed.

**Fix.**
None required. Recommended hygiene only: keep the `Disallow` list current, and continue to rely on server-side authorization (which you already do) rather than on `robots.txt` for access control. If you prefer to reduce the map's usefulness, consider removing route names that are not needed for crawler control, but this is optional and carries no security urgency.

**Retest note.**
Not applicable — informational. Re-review only if the route namespace changes or if crawler behavior needs re-verification.

---

### 3a. Positive Controls — Assurance, Not Findings

These were actively tested during the pass and held. They are included so the client can rely on them in security reviews and procurement questionnaires.

- **API authorization.** REST `/api/v1/*` and web `/api/*` endpoints return uniform `401` responses to unauthenticated requests, including for fabricated scan IDs — there is **no status-code oracle** that would leak existence of another tenant's resources (no IDOR signal). `/api/auth/user` correctly returns `200 {"user":null}` for anonymous callers.
- **Scope gate / path traversal.** `POST /api/mcp/%2e%2e/v1/scans` returned `404`, while the control request `POST /api/v1/scans` returned `401` — the traversal was normalized and did **not** bypass the authorization scope gate.
- **Host handling.** `www.secscan.us` issues a clean `301` redirect to the apex with **no hostname reflection**; `X-Forwarded-Host` is not reflected; a mismatched `Host` header is rejected at the edge.
- **WebSocket attack surface.** Zero WebSocket or EventSource references were found in the 1.27 MB application bundle, despite a permissive CSP allowing `ws:`/`wss:` — there is no WebSocket channel to attack.
- **TLS.** A real handshake negotiated **TLSv1.3** with cipher suite `TLS_AES_256_GCM_SHA384`, an **ECDSA P-256** certificate, and a chain that verifies OK.
- **Input reflection.** No query-parameter reflection into HTML or style contexts was observed on the tested pages (`/`, `/scan`).

---

## 4. Methodology Note

**Approach.** Testing was hypothesis-driven: the exploiter reasoned about likely weaknesses from the application's structure and headers, then issued targeted, non-destructive probes to confirm or disprove each hypothesis. All requests were read-only except for standard GETs; no state was modified, no data was deleted, and no denial-of-service activity was attempted. Results were validated against a second, independent source (the passive scanner or DNS-over-HTTPS) wherever possible.

**Baseline.** An earlier passive scan graded the site **A**, risk **1/100**. This pass did not change that posture; the single LOW finding is a configuration hardening item, not an active flaw.

**Tooling limitation — scanner credits.** The scanner's aggressive-tier scan did **not** run in this window: the account had **0 of 3** free scan credits remaining (renewing **2026-11-01**). The exploiter pass substituted for it where feasible, but it cannot replace the scanner's broader active test set.

**Deferred tests (not performed — stated plainly with what is needed):**

| ID | Test | Blocker / what's needed |
|----|------|--------------------------|
| **D-1** | SSRF via `/scan` server-side fetch | Out-of-band canary infrastructure (a listener the target can call back to). |
| **D-2** | Cross-account IDOR on `/report/` and `/share/` | A second test account. Direct-URL probes returned only the generic app shell with no data leak. |
| **D-3** | Password-reset / email-verify token entropy and reuse | A test account plus coordinator-approved reset triggers. No reset emails were sent this pass. |
| **D-4** | The scanner's 21 skipped active tests (injection, XSS, traversal, access control, backend data) | Scan credits; quota renews **2026-11-01**. |

**Severity assignment.** Consistent with the rubric in §3: business impact multiplied by exploitability. F-1 is LOW because impact is latent (no live reflection) even though the misconfiguration is trivially present. F-2 and F-3 are INFO because exploitability is low and/or the item is disclosure-by-design rather than a defect.

---

## 5. Retest Checklist

Use this to verify remediation and to schedule the deferred work.

**Remediation retests**
- [ ] **F-1** — Re-fetch apex and `www` response headers; confirm `style-src` contains no `'unsafe-inline'`. Re-run the four CSS-injection / style-breakout probes against `/` and `/scan`; confirm zero reflections and no CSP console violations on pages that previously used inline styles.
- [ ] **F-2** — DoH query for `DS secscan.us` returns records; `DNSKEY` query returns records with the **AD** flag set on a validating resolver. Confirm the `DS` record is present at the registrar.
- [ ] **F-3** — No action required; re-review only if the route namespace changes.

**Deferred work to schedule**
- [ ] **D-1** — Provision out-of-band canary infrastructure; run SSRF probes against `/scan` server-side fetch.
- [ ] **D-2** — Provision a second test account; test cross-account IDOR on `/report/` and `/share/`.
- [ ] **D-3** — Provision a test account and coordinator-approved reset triggers; test password-reset and email-verify token entropy and reuse.
- [ ] **D-4** — After **2026-11-01**, spend renewed scan credits to run the scanner's 21 skipped active tests (injection, XSS, traversal, access control, backend data).

**Standing checks (positive controls — re-verify after any auth or routing change)**
- [ ] Unauthenticated `/api/v1/*` and `/api/*` requests still return uniform `401`s for fabricated IDs.
- [ ] `POST /api/mcp/%2e%2e/v1/scans` still returns `404`; scope gate intact.
- [ ] `www` still `301`s to apex with no hostname reflection; mismatched `Host` rejected at the edge.
- [ ] TLS still negotiates 1.3 with a valid chain.

---

*End of report. Questions on any finding or on scheduling the deferred tests can be directed to the engagement lead.*