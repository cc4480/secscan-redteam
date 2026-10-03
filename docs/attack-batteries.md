# Attack Batteries — what the red team performs, per target type

Each target type gets its own full-spectrum battery. Nothing is shared
between them except the rules: authorized scope only, non-destructive,
ROE-bound, fail closed. Killed hypotheses are negative intelligence —
the exact attempt is dead, the class stays in play with a different angle.

---

## 1. Web Applications (dynamic: auth, APIs, workflows, payments)

The deepest battery — the app that takes input, holds state, and moves money.

**Logic flaws**
- Workflow / step skipping (checkout, onboarding, approval chains)
- Price, quantity, currency manipulation
- Coupon / discount stacking and reuse
- Race conditions (double-spend, double-redeem, TOCTOU)
- State-machine abuse (replay steps, out-of-order transitions)
- Password reset / change-flow abuse (token leakage, host-header poisoning, user enumeration)
- Multi-role privilege boundaries (horizontal + vertical escalation across roles)
- Negative / zero monetary and count values

**Functionality abuse**
- IDOR / BOLA on every object reference
- Mass assignment (hidden model fields via request body)
- Hidden / undocumented parameters
- HTTP method tampering (GET vs POST vs PUT vs PATCH vs DELETE)
- Content-type confusion (JSON ↔ form ↔ XML)
- File-upload abuse (type, extension, polyglot, path)
- Pagination / filter / sort abuse (data exfiltration via list endpoints)
- Enumeration (users, IDs, valid vs invalid oracles)

**Accuracy and validation rigor**
- Type juggling, boundary values, truncation
- Encoding / Unicode bypasses, regex bypasses
- Client-side-only validation, inconsistent validation between endpoints
- Error-message oracles (what the error reveals)

**Injection**
- SQLi, NoSQLi, XSS (stored / reflected / DOM), SSTI
- OS command injection, LDAP / XPath injection, XXE, header injection

**Auth and session**
- Session fixation, JWT flaws (alg confusion, weak secrets, missing expiry)
- OAuth / OIDC misconfiguration, MFA bypass paths
- Rate-limit and lockout testing on login (ROE-permitted only)

**API-specific**
- Excessive data exposure, BOLA at scale
- GraphQL abuse (introspection, nested queries, batching)
- API versioning gaps (old versions with old flaws)

**Chaining**
- Multi-step exploit chains: recon finding → low finding → privilege escalation path, mapped to ATT&CK.

---

## 2. Websites (static, brochure, CMS-driven)

The site that presents content — WordPress, static generators, marketing sites.

- CMS fingerprinting: vulnerable plugins / themes / core versions
- Admin surface: wp-admin / login exposure, xmlrpc.php abuse
- TLS configuration and security headers (CSP, HSTS, X-Frame-Options, cookie flags)
- Directory enumeration: backup files, .git / .env exposure, robots.txt / sitemap.xml
- Information disclosure: server banners, verbose error pages, exposed debug endpoints
- Stored XSS via comments, forms, and user-content fields
- DNS posture: DNSSEC, dangling records, subdomain takeover
- Third-party script supply chain (skimming risk on payment-adjacent pages)
- Defacement and content-injection vectors

---

## 3. Windows (host and Active Directory)

**Superseded by the exhaustive battery (v0.8.0):** `runner/src/targets/windows.ts` —
**104 items** (WS-001…WS-104), surface × technique: SMB/share recon, RDP/WinRM
recon, auth attacks (authorized test accounts only), Active Directory (trusts,
delegation, GPOs, ACLs, attack paths), privilege escalation, lateral movement,
credential-exposure audit, persistence findings (reported, never planted),
EDR/AV awareness. Items needing not-yet-built host execution tooling are
marked `[needs: host-exec tooling]` and plan-only — see
[full-battery.md](full-battery.md) and [ROADMAP.md](ROADMAP.md).

---

## 4. Linux (host)

**Superseded by the exhaustive battery (v0.8.0):** `runner/src/targets/linux.ts` —
**106 items** (LX-001…LX-106), surface × technique: recon, SSH hardening and
access, privilege escalation (SUID, sudo, capabilities, cron, kernel CVEs,
containers), exposed services as findings, file-permission and secret
auditing, persistence findings (reported, never planted). Same honest
execution scoping as Windows — see [full-battery.md](full-battery.md) and
[ROADMAP.md](ROADMAP.md).

---

## Scope note

The automated runner performs batteries 1 and 2 fully today. Batteries 3 and 4
(Windows / Linux) run as exhaustive plan batteries: HTTP(S) items execute via
`http_probe`; items marked `[needs: host-exec tooling]` are planned, not
probed, until the host-exec tooling track lands (see
[ROADMAP.md](ROADMAP.md)). Same authorization gate, ROE enforcement, and
non-destructive rules throughout.
