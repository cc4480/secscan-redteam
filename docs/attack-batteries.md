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

**Recon and enumeration**
- SMB / NetBIOS enumeration, null sessions, share and permission mapping
- User, group, and service enumeration

**Authentication attacks (ROE-permitted only)**
- RDP / SMB credential testing within authorized accounts
- NTLM relay, pass-the-hash, Kerberoasting, AS-REP roasting

**Active Directory**
- Domain mapping (BloodHound-style path analysis)
- Delegation misconfiguration, GPO abuse, misconfigured ACLs
- Unquoted service paths, writable service binaries

**Privilege escalation**
- Misconfigured services, AlwaysInstallElevated
- Token impersonation, scheduled-task abuse

**Lateral movement (authorized scope)**
- PSExec / WMI / WinRM execution paths
- Credential harvesting from authorized access (LSASS-style findings reported, not weaponized beyond scope)

**Stealth (black mode)**
- Low-noise variants of all of the above; back off on detection signals.

---

## 4. Linux (host)

**Access**
- SSH posture: weak / reused credentials (ROE-permitted), exposed keys, agent-forwarding abuse
- Exposed services: Redis, MongoDB, Elasticsearch, Docker socket

**Privilege escalation**
- SUID binaries (GTFOBins-style abuse paths)
- Sudo misconfiguration, Linux capabilities
- Cron jobs and writable PATH / service files
- Kernel version vs known local-privesc CVEs

**Configuration and data**
- World-writable sensitive files, readable /etc/shadow, NFS misconfiguration
- Container escapes where Docker/K8s is in scope

**Persistence findings (reported, authorized)**
- Cron entries, systemd units, rogue authorized_keys

**Stealth (black mode)**
- Low-noise variants; back off on detection signals.

---

## Scope note

The automated runner performs batteries 1 and 2 today. Batteries 3 and 4
(Windows / Linux host and AD testing) are the expansion track: they define
what the red team performs, and the runner grows into them under the same
authorization gate, ROE enforcement, and non-destructive rules.
