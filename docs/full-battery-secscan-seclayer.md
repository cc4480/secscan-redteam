# The Full Battery — SecScan + SecLayer, One Unified Engagement

This is the culmination of the red-team line: a single operation that tests
**both** of our products end to end — SecScan (the scanner webapp) and
SecLayer (the MCP/API layer) — as one adversary would actually see them.

## Why target-specific beats generic

A generic scanner tests "a web app." Our battery tests **these** targets —
their real surfaces, learned across our own engagements:

- The DNS TXT ownership gate (`_secscan-challenge.<domain>`, server-authoritative)
- The scan lifecycle: intake → queued → running → complete → report
- Share links with 30-day expiry, AI opt-out with evidence redaction
- The SSRF guard with per-hop redirect revalidation
- Namespaced intake/share rate limits
- The MCP layer: Streamable HTTP, JSON-RPC 2.0, API-key auth, three tools
  (`seclayer_scan`, `seclayer_list_scans`, `seclayer_get_report`)

The same flaw class lands differently on each surface. IDOR on a scan
report is not IDOR on a shopping cart. So every battery item names the
actual endpoint, flow, or parameter it attacks.

## What gets tested

**SecScan webapp — 24 items** across the three categories:

- *Logic flaws (8):* DNS-gate bypass attempts, report/share IDOR across accounts, share-link expiry enforcement, AI opt-out redaction verification, rate-limit bypass mapping, SSRF-guard probing through intake (canary targets only), mass assignment on scan options, scan-lifecycle state abuse.
- *Functionality abuse (8):* hidden intake parameters, method tampering, content-type confusion, negative/zero scan params, enumeration oracles, share-token handling, pagination abuse on scan lists, report export/format abuse.
- *Validation rigor (8):* intake URL type juggling, boundary values on IDs, encoding tricks on target URLs, client-side-only validation, error-message oracles, inconsistent validation between intake paths, truncation, regex bypasses.

**SecLayer MCP/API — 18 items** across the three categories:

- *Logic flaws (6):* unauthenticated/bad-key tool calls, cross-account IDOR, JSON-RPC session handling, SSRF via the scan-target parameter, rate-limit mapping, scan-credit accounting.
- *Functionality abuse (6):* JSON-RPC method tampering, GET-vs-POST on the MCP endpoint, content-type confusion, message ordering/notification abuse, batch-request abuse, tool parameter abuse.
- *Validation rigor (6):* API-key validation, scan_id validation, target-URL validation parity between MCP and web paths, error-message oracles, encoding tricks, WAF-behavior mapping.

**Cross-cutting chains:** the engagement explicitly hunts MCP → webapp paths —
does an API-layer primitive become a webapp impact, or vice versa?

## How the operation runs

1. **Recon** both surfaces — webapp and MCP API, fingerprints and auth models.
2. **Exploit** the SecScan battery (SS-L / SS-F / SS-V).
3. **Exploit** the SecLayer battery (SL-L / SL-F / SL-V).
4. **Chain** across surfaces.
5. **Report** — one unified Megazord narrative, both batteries, honest limits.

Coverage is mechanical, not vibes: the battery counts complete only when all
three categories are probed on **both** targets (3 × 2 = 6 cells). Anything
unprobed lands in the report's Honest Limits section by name.

## Honest limits

Some items need prerequisites we state up front rather than pretending:

- **Cross-account IDOR** (SS-L-2, SL-L-2) needs a second operator-owned test account.
- **SSRF probing** (SS-L-6, SL-L-4) needs canary infrastructure under operator control — benign targets that log hits. We never touch internal or metadata addresses.
- **UUID guessing** is not attempted anywhere — it's infeasible, and claiming otherwise would be theater.
- A killed hypothesis is negative intelligence, not a blacklist: the exact dead attempt stays dead, but the attack class stays in play for a genuinely different angle. The battery never narrows.

## Rules that never bend

Authorized scope only. Non-destructive always — no emails to real users, no
scan/report deletion, single paired requests instead of floods, benign canary
content only. Both modes fail closed on missing ownership proof. Every action
is logged with time, phase, actor, action, ATT&CK ID, target, and result.
