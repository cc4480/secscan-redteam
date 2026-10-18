# Changelog

Notable changes to the secscan-redteam runner. This file starts at 0.35.0; no
prior release history is reconstructed here.

## [0.37.1] - 2026-10-17

- **Security: every scope host is now ownership-verified, and local sandbox mode is
  operator-only.** The authorization phase verified only the engagement target, while
  every probe checked nothing but membership in the operator-supplied scope list - so a
  verified target could be paired with unrelated public hosts, and local sandbox mode
  (which skips verification for a loopback target) could be combined with a public host.
  New `checkScopeAuthorization`: each DNS scope host must be server-verified, IP-literal
  entries remain ROE-authorized host targets, private entries require local sandbox, and
  a sandbox engagement must have an entirely private scope.
- **The console launch request and the MCP `start_engagement` schema no longer accept
  `localSandbox`.** It remains a CLI flag and `REDTEAM_LOCAL_SANDBOX=1`, matching the
  gate's documented contract that it is never implied by a request.
- **Private-host probing requires an all-private scope** in the web prober, mirroring
  the rule the agent coordinator already applied.
- Tests: 8 new scope-authorization cases (gate-scope.test.ts).

## [0.37.0] - 2026-10-17


- **Zero-install toolchain: one resolver, bundled payload first.** New
  `src/toolchain.ts` resolves nmap, nuclei and every xtool in a single order -
  explicit environment value (authoritative, reported not-found when missing),
  then `REDTEAM_TOOLS_DIR/<tool>/<executable>`, then PATH - and nmap/nuclei/xtool
  executors plus their presence probes all delegate to it, so a binary shipped
  with the application actually runs instead of only being reported.
- **`doctor` reports the source.** Every bridge line now carries the resolved
  path and whether it came from an explicit override, the bundled tools
  directory or PATH; a new optional `bundled tools directory` row and an
  optional `nuclei` row were added. Required items and exit semantics are
  unchanged, and a set-but-missing explicit override still reports not-found.
- **Docs**: `docs/toolchain.md` describes the order, the bundled layout, the
  tiers/licenses and the one-line zero-install verification.
- **Tests**: 743 pass (was 726), including a new `test/toolchain.test.ts` for
  precedence, john variant selection, sqlmap/nikto directory shapes and the
  Windows/POSIX suffix rule.

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
