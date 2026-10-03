# The Full Battery — SecScan + SecLayer, One Unified Engagement (v0.7.0)

This is the culmination of the red-team line: a single operation that tests
**both** of our products end to end — SecScan (the scanner webapp) and
SecLayer (the MCP/API layer) — as one adversary would actually see them.
Not a sample. Not a representative subset. **Everything.**

## The numbers

- **SecScan: 120 attack items** (SS-001…SS-120) — validation 34, logic 58, functionality 28
- **SecLayer: 80 attack items** (SL-001…SL-080) — logic 25, validation 28, functionality 27
- **200 total**, each one a distinct attacker intent with a concrete target:
  the actual endpoint, flow, or parameter, and the exact abuse.

## Methodology: surface × technique

The battery wasn't written as a list of clever tricks. It was built as a
matrix:

1. **Enumerate every attack surface per target.** For SecScan: the intake URL
   field, the SSRF guard, the DNS TXT ownership gate, the scan lifecycle,
   scan listing, report view/export, share links, AI opt-out, rate limits,
   auth/session, the API surface, TLS/headers/CORS, error handlers. For
   SecLayer: the MCP handshake, capability negotiation, tools/list, every
   tool with every parameter attacked individually, notifications, ping,
   cancellation, progress, batching, the JSON-RPC layer itself, the auth
   layer per method, the HTTP layer, WAF behavior.
2. **Apply every relevant technique to each surface.** Each distinct attacker
   intent — one item. IDOR on a scan report is a different item from IDOR on
   a share link, because the trust boundary, the failure mode, and the
   evidence are all different.

Generic batteries test "a webapp." This battery tests **these** targets.

## Scanner efficacy: the red team validates the scanner

New in v0.7.0 — the red team doesn't just attack SecScan, it adversarially
validates what SecScan *claims to do*. Canary targets with known planted
flaws (reflected XSS, SQLi errors, missing headers, exposed .git, weak TLS,
open redirects, verbose errors, vulnerable JS libraries) verify the scanner
actually detects what it promises. A clean hardened canary checks precision
(no false positives); severity-graded plants check calibration. A scanner
that misses or misgrades is a finding against the product itself.

Non-destructive, canary targets only — detection-validation, not abuse.

## How it runs

One flag: `--full-battery` (or `--target secscan+seclayer`). One operation:

1. **Recon** both surfaces — webapp and MCP API.
2. **Exploit** the SecScan battery.
3. **Exploit** the SecLayer battery.
4. **Cross-cutting chains** — MCP → webapp paths: does an API-layer
   primitive become a webapp impact, or vice versa?
5. **Unified report** — one Megazord narrative, both batteries.

The coordinator sees the full 200-item spectrum as a compact checklist
(every ID + name + one-line brief); the full execution detail lives in the
runner modules. The runner enforces coverage mechanically: the battery
counts complete only at **3 categories × 2 targets = 6 cells**. Anything
uncovered is named under Honest limits — never silently dropped.

## Unbreakable rules

- Authorized scope only. Non-destructive always: no emails to real users,
  no deleting scans/reports, benign canary content only, races are single
  paired requests.
- Killed hypotheses are negative intelligence — the exact attempt is dead,
  the class stays in play with a different angle. Nothing is ever retired
  from the battery.
- Items needing setup (second test account, canary/OAST infrastructure)
  are marked honestly in `needs` — never pretended.

## Honest limits

- Some items need a second test account or canary infrastructure the
  operator must provision; without them, those items are reported as
  not-covered, not as passed.
- The battery covers the webapp and MCP/API surfaces. Host/OS testing
  (Windows/Linux) is a separate battery track.
- ATT&CK mappings are advisory: web flaw classes map imperfectly onto an
  endpoint/intrusion framework. Where no technique honestly fits, the OWASP
  reference stands alone.
