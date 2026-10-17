# Changelog

Notable changes to the secscan-redteam runner. This file starts at 0.35.0; no
prior release history is reconstructed here.

## [0.36.0] - 2026-10-17

- **WA-*: gap closure, 24 new items.** `WA-121`...`WA-144` add the check types
  the SecScan / Seclayer corpora had but the 120-item battery did not: HTTP
  methods, NoSQL injection, host header injection, prototype pollution,
  plaintext HTTP and redirect enforcement, rate limiting, API field
  over-sharing, Supabase Storage and email confirmation, runtime edge-function
  bypass, repo policy and Secrets/`write-all` review, structured data,
  inner-route consistency, Next.js `__NEXT_DATA__`, GraphQL field suggestions,
  JWT claims, health endpoints, WordPress XML-RPC / user enumeration, verbose
  banners, `X-XSS-Protection`, and `Cache-Control` / HSTS preload.
- **The WA family is now 144 items** (`WA-001`...`WA-144`, 21 blocks):
  validation 89, logic 46, functionality 9. `BATTERY_ITEM_COUNTS.webapp`
  becomes 144 and a webapp-only ledger has exactly 144 entries;
  `TOTAL_BATTERY_ITEMS` stays 418 because `webapp` remains opt-in.
- **Source: the SecScan / Seclayer gap analysis.** The additions close the 24
  missing check types identified in `GAP_ANALYSIS.md`; the docs and the opt-in
  contract are updated to match.

## [0.35.0] - 2026-10-17

- **WA-*: the 120-item web application battery.** A fifth, opt-in target
  (`WA-001`...`WA-120`, 19 blocks) for attacking a client's own web
  application; the four vendor batteries and the 418-item contract are
  unchanged.
- **`ALL_TARGETS` and the `webapp` target.** `webapp` is registered in the
  target registry (prefix `WA`, `BATTERY_ITEM_COUNTS.webapp = 120`, profile
  `kind: "webapp"`) and exposed through `ALL_TARGETS`, while
  `FULL_BATTERY_TARGETS` stays at the four vendor targets.
- **Launch surface.** `start_engagement` gains a `targets` argument, so the
  harness can launch a webapp engagement, and `http_probe`'s `targetProfile`
  accepts `"webapp"`.
- **`docs/webapp-battery.md` added.** Documents the 19 blocks, the tool that
  executes each, every `needs` prerequisite, the evidence discipline and the
  provenance from the SecScan and Seclayer scan corpora; `docs/full-battery.md`
  links to it.
