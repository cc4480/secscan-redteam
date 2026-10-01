# Security Assessment Report — secscan.us

**Prepared for:** CTO, secscan.us
**Engagement:** External attack-surface assessment (passive phase)
**Scan reference:** `b2de7005-d728-4a48-a54d-966141cda82d`
**Report date:** 2026-10-01
**Classification:** Confidential — client deliverable

---

## 1. Executive summary

Between 05:05 and 05:35 CDT on 2026-10-01 we assessed the externally visible security posture of `secscan.us`, the apex domain you authorized. Because domain ownership could not be verified during the window, the entire assessment ran **passive-only**: we read response headers, DNS and certificate metadata, and publicly served files, and we did not send a single active attack. The posture is genuinely strong — the site sits behind Cloudflare with HSTS preload, a strict `script-src 'self'` content policy, `frame-ancestors 'none'`, `base-uri 'self'`, and no inline script execution, and we found **no Critical, High, or Medium severity issues**. One Low-severity hardening item and two informational items are detailed below. The most important action is not a code fix: **21 of 44 planned tests were skipped** because active testing requires a verified domain, so today's "A" grade describes a well-hardened perimeter — not a fully tested application. Injection, cross-site scripting, path traversal, access control, SSRF, and exposed-backend-data risks remain **unassessed**, not absent, and closing that gap is the single highest-value next step.

---

## 2. Authorization statement

**Scope tested**
- `https://secscan.us` (apex) — in scope, observed.
- `https://www.secscan.us` — in scope, **not observed**. No request was made and no apex↔www redirect check was performed. This is the largest coverage gap in the pass and is carried into the retest checklist.

**Test window**
2026-10-01, 05:05–05:35 CDT (America/Chicago).

**Authorization basis — UNVERIFIED**
The engagement was owner-authorized and operator-confirmed, but ownership was **not technically proven**. No DNS TXT record was published at `_seclayer-challenge.secscan.us`, and no verified domains were present on the scanning account. The scanning server therefore enforced passive checks for the whole window, and our own authorization gate was armed the entire time: **no active test was attempted, requested, or executed.** This is stated plainly because it bounds what the findings mean — see §4.

**Explicitly excluded (untouched)**
- `secscan.info` — referenced only as a documentation/Policy host; not contacted.
- `seclayer.app` — not contacted.
- No subdomain enumeration beyond passive DNS for the apex (which returned none).

**Consequence for the reader**
Everything in §3 is a *passive observation*, backed by at minimum two independent captures where a finding is stated. Everything in §6 is an *untested hypothesis*. The two are never mixed, and the former must not be read as evidence for the latter.

---

## 3. Findings

No Critical, High, or Medium severity findings were identified in the tested surface. Three items follow, severity-ordered.

### F-1 — Content Security Policy still permits inline styles · **LOW**

**Business impact.** An attacker who can get markup into a page — via a stored field, a comment, a support ticket, a shared scan report, or any reflected input discovered later — can inject CSS even though they cannot run JavaScript. In practice this means UI redressing (making a user click the wrong control), content spoofing (hiding or rewriting what a page says), and in narrow cases data exfiltration through CSS `url()` / `@import` requests to an attacker-controlled host. The real-world ceiling here is low: because `script-src 'self'` carries no `unsafe-inline`, an attacker cannot escalate style injection into script execution. This is a hardening item, not a live compromise path.

**Evidence (two independent observations).**
1. Scanner response-header capture for `scan_id b2de7005-d728-4a48-a54d-966141cda82d` recorded `style-src 'self' 'unsafe-inline'` (CWE-79).
2. An independent operator `GET` to the apex returned the **same** CSP header, matching observation 1.

Both captures show the same policy: `default-src 'self'`; **`script-src 'self'` with no `unsafe-inline`**; `object-src 'none'`; `frame-ancestors 'none'`; `base-uri 'self'`. The only deviation is `style-src`.

**Fix (copy-paste ready).** Replace the static `unsafe-inline` style allowance with a per-request nonce. On Next.js this is done in middleware, generating the nonce at request time and attaching it to the header and to any inline `<style>` tag:

```js
// middleware.ts
const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
const csp = [
  "default-src 'self'",
  "script-src 'self' 'nonce-" + nonce + "'",
  "style-src 'self' 'nonce-" + nonce + "'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "connect-src 'self' wss://secscan.us",
  "img-src 'self' https: blob: data:",
  "form-action 'self'",
].join('; ');
```

Practical steps:
1. Move inline `style="..."` attributes into CSS classes. Inline attributes cannot be nonced and are the main blocker to removing `unsafe-inline`.
2. If a third-party component requires inline style attributes you cannot remove, use `style-src-attr` / `style-src-elem` to scope the exception to just that element type rather than allowing `unsafe-inline` globally.
3. **Also worth tightening while you are in the header:** `connect-src 'self' https: wss: ws:` currently allows outbound connections to *any* HTTPS host and to unencrypted `ws:`. Narrow it to the origins you actually use (as shown above). This is a recommendation attached to the same two header observations — no exploitability was demonstrated, so it is not scored as a separate finding.

**Retest note.** Re-fetch the apex response headers and assert `unsafe-inline` no longer appears in `style-src`. Then load the site and confirm no visual regression — the CSS that previously relied on inline styles must still apply.

---

### F-2 — DNSSEC is not enabled · **INFO**

**Business impact.** Without DNSSEC, DNS answers for `secscan.us` are not cryptographically authenticated. On networks where an attacker can spoof or race DNS responses — hostile Wi-Fi, compromised routers, some ISP-level positions — they can redirect your users to a look-alike host without any browser warning. This matters more than usual for a security-branded product: your users are being trained to trust a domain that a network attacker can hijack. It is not an application flaw and it does not make the app itself easier to breach.

**Evidence.** DNS queries for the zone returned **no DNSKEY records** (`scan_id b2de7005…`), indicating DNSSEC is not signed. Note honestly: this is a **single-source observation** and the lowest-confidence item in the report — it should be confirmed against a second independent validating resolver before you act on it (see retest checklist item 2).

**Fix.**
1. Enable DNSSEC signing at your authoritative DNS provider (Cloudflare supports one-click DNSSEC — you are already behind their edge, so this is minutes of work).
2. Publish the resulting **DS record** at your domain registrar. Enabling signing without publishing the DS chain-of-trust changes nothing.
3. Verify propagation before announcing.

**Retest note.** Query `DS` and `DNSKEY` for `secscan.us` from two independent public validating resolvers (e.g. 1.1.1.1 and 8.8.8.8) and confirm signed responses validate (AD flag set), with no validation failures.

---

### F-3 — Unassessed attack surface (coverage limitation) · **INFO**

**This is a limitation of the assessment, not a vulnerability.** It is listed here because, for planning purposes, it is the most consequential item in the report.

**Business impact.** The "A" grade and risk score of 1/100 reflect a **passive test set only**. Any of the unassessed categories — SQL/command injection, cross-site scripting, path traversal, broken access control, server-side request forgery, exposed backend data — could conceal a Critical issue, and none of them were tested. You currently have *no evidence* about them in either direction. A clean passive grade should not be used as assurance to a customer, an auditor, or a board until the active tests run.

**Evidence.** Scan record `b2de7005-d728-4a48-a54d-966141cda82d`: **22 of 44 tests executed; 21 skipped** (all requiring domain verification); 1 test failed (SSL Labs). The skipped set is exactly the active set: injection, XSS, path traversal, access control, SSRF, and exposed backend data.

**Additional evidence gaps to record.**
- **TLS posture is unassessed.** The SSL Labs test failed, so no independent certificate, protocol, or cipher grade exists. HSTS was observed; nothing beyond it should be claimed.
- **`www.secscan.us` was never fetched.** It is in scope and unexamined.
- **`/llms.txt` was referenced by `robots.txt` but never retrieved.**

**Fix.** There is no code fix. The fix is procedural: complete domain ownership verification (publish the DNS TXT proof at `_seclayer-challenge.secscan.us`), then authorize the active phase. The deferred tests in §6 are written and ready to run the moment verification lands.

**Retest note.** Re-run the scan with the domain verified so the 21 skipped tests execute, and confirm the grade is recalculated against the full 44-test set rather than the passive subset.

---

## 4. Methodology note

Testing was **dynamic and hypothesis-driven**, layered on top of the SecScan engine's automated baseline rather than replacing it. Candidate issues were formed from observed behavior, then each was required to survive an evidence bar before it could become a finding: **two independent observations** — typically the scanner's capture plus an independent operator request — or it stays out of the report.

An **aggressive tier** exists for this engagement and was not used. It is gated on verified domain ownership, and ownership was never proven during this window (no DNS TXT proof, no verified domains on the scanning account). The scanning server enforced passive checks and our authorization gate was armed throughout. Consequently **no active test was attempted or requested** — there was no partial active run to caveat.

Two honesty constraints were applied to this report deliberately:
- **Hypotheses are not findings.** The exploiter's ranked leads are reproduced in §6, explicitly labeled UNTESTED, and are excluded from §3. They are read-only reasoning about where risk *would* live; none was probed.
- **Absence of evidence is not evidence of absence.** Where a test was skipped or failed, the report says "unassessed" — never "clean."

Scan economics, for planning: 1 of 3 free scans consumed; the SSL Labs failure may be transient and re-running it is passive and cheap.

---

## 5. Retest checklist

Run after the fixes in §3 and, where noted, after domain verification.

1. **CSP (`F-1`).** Re-fetch `https://secscan.us/` response headers. Assert `style-src` no longer contains `unsafe-inline`; assert `script-src` still contains no `unsafe-inline`. Then load the site in a browser and confirm no styling regression.
2. **DNSSEC (`F-2`).** From two independent validating resolvers, query `DS secscan.us` and `DNSKEY secscan.us`. Confirm the chain validates (AD flag set) and that no resolver reports a validation failure. *(This item exists partly to upgrade the single-source observation in `F-2` to a two-source one.)*
3. **Coverage gap — www.** `GET https://www.secscan.us/`. Record status, `Location`, full response headers, and any `Set-Cookie` (including `Domain` scope). Compare against the apex. Confirm the redirect to apex is clean and does not reflect attacker-influenced hostnames.
4. **Coverage gap — recon artifacts.** Fetch full bodies of `/robots.txt`, `/sitemap.xml`, and `/llms.txt`. Diff the route strings against those already known and feed anything new into §6. (`robots.txt` was 5,984 bytes against a short visible disallow list — the extra bytes are worth reading.)
5. **Coverage gap — TLS.** Retry SSL Labs, or perform a read-only handshake inspection. Record protocol, cipher, certificate issuer, expiry, and SANs. This closes the failed-test gap.
6. **Verification gate.** Confirm the DNS TXT proof is published at `_seclayer-challenge.secscan.us` and that the domain shows as verified on the scanning account **before** any item below is scheduled.
7. **Deferred active tests (§6).** Execute in the order listed once verified, honoring the stated read-only constraint until a specific endpoint is understood and separately authorized.

---

## 6. Deferred testing — verified phase only

**These are untested hypotheses, not findings.** Nothing here has been probed. They are listed because they define the active phase's plan, and because a CTO should see where the residual risk sits. Each is ranked by expected value, not by likelihood.

| # | Hypothesis | What would confirm it | What would kill it | Constraint |
|---|---|---|---|---|
| 1 | `/api/` exposes unauthenticated or weakly authorized endpoints | An unauthenticated `GET /api/` returns schema, route/method enumeration, OpenAPI/JSON, or any non-401 data | Uniform 401/403/404 with no route or `Allow` leakage | Read-only verbs only until an endpoint is understood |
| 2 | `/scan` performs server-side fetches and is an SSRF vector | A unique canary URL submitted via `/scan` produces an out-of-band DNS/HTTP callback from the target's egress IP | No callback after a benign control and a canary attempt | Canary to attacker-controlled host only; no metadata/internal targets until the callback confirms fetching **and** the coordinator authorizes the pivot |
| 3 | Reset / email-verification tokens are predictable, reusable, or host-header influenced | A second token is predictable from the first; a used token still validates; the reset link reflects a non-canonical `Host` | High-entropy, single-use, time-limited tokens with no host reflection | Dedicated test account and inbox only — never production users. No brute-forcing |
| 4 | `/report/` and `/share/` have IDOR or guessable share-token references | A cross-account object ID or token returns another account's content | Identical 403/404 for every cross-account reference and high-entropy identifiers | Two authorized test accounts only; stop immediately if real user data appears |
| 5 | The WebSocket channel (implied by `connect-src`) lacks auth or `Origin` validation | A cookieless connection with `Origin: https://secscan.us` returns `101` plus application data frames | Clean 401/403 or an origin-mismatch rejection | Read-only connection; observe the upgrade and first frames, then close |
| 6 | Full `robots.txt` / `sitemap.xml` / `llms.txt` disclose more routes | Bodies contain path strings not already known | Bodies match what is already listed, or the extra bytes are only comments | Passive fetch — this one can be done **now**, without verification |
| 7 | `style-src 'unsafe-inline'` enables CSS injection/exfiltration | Attacker-controlled input lands in a style context and fires an out-of-band CSS canary request | No input reaches a style context | Non-destructive, read-only |
| 8 | `www.secscan.us` is a separate or host-confused origin | It serves a distinct app/config, or reflects/redirects with hostname-controlled content | Clean 301/308 to apex with no reflected hostname | Passive fetch — can be done now (checklist item 3) |

Items 6 and 8 require **no active testing** and can be closed immediately as passive follow-ups. Items 1–5 and 7 require domain verification and explicit coordinator authorization; item 2 additionally requires sign-off before any internal-target pivot.

---

## 7. Closing statement

The perimeter is well built. Cloudflare edge protection, HSTS with preload, a script policy that blocks inline execution, and `frame-ancestors 'none'` are the right controls, correctly applied. Nothing found in this pass warrants urgency.

What the report should leave you with is a calibration, not a scare: **a Grade A from a passive scan is a statement about your perimeter, not about your application.** The single action that most improves your actual security position is completing domain verification so the 21 unassessed tests can run. Everything else on the list is hardening you can schedule at your convenience.
