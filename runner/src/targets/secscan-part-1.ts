/**
 * SECSCAN battery — part 1 of 4 (v0.19.0 refactor split).
 * Starts at section: INTAKE URL FIELD (validation)
 *
 * Pure data split of secscan.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by secscan.ts.
 */

import type { TargetBatteryItem } from "./types.js";

export const SECSCAN_PART_1: TargetBatteryItem[] = [
  // ============================================ INTAKE URL FIELD (validation)
  {
    id: "SS-001", category: "validation", name: "Intake URL type juggling",
    brief: "Non-string types in the url field — does anything but a string ever reach the SSRF guard?",
    owasp: "WSTG-INPV-01", attackId: "T1190",
    what: "Submit the intake url field as an array, object, boolean, and number instead of a string. Observe coercion: does the validator reject, stringify, or pass a non-string downstream where the SSRF guard might mishandle it?",
  },
  {
    id: "SS-002", category: "validation", name: "Intake URL scheme allowlist",
    brief: "Dangerous schemes (javascript:, data:, file:, gopher:, dict:, ftp:) — allowlist or blocklist?",
    owasp: "WSTG-INPV-01", attackId: "T1190",
    what: "Submit intake URLs with schemes javascript:, data:, file:, gopher:, dict:, ftp:, and jar:. Record exactly which are rejected vs accepted — a blocklist that misses one scheme is the finding. Never submit a scheme that would execute locally.",
  },
  {
    id: "SS-003", category: "validation", name: "Intake URL userinfo trick",
    brief: "https://secscan.us@evil-canary — does the validator see the real host?",
    owasp: "WSTG-INPV-01", attackId: "T1190",
    what: "Submit https://secscan.us@<canary-host> and https://user:pass@<canary-host> as the intake URL. If the validator or the SSRF guard parses the host as secscan.us while the fetch goes to the canary host, that divergence is the finding. Canary hosts only.",
  },
  {
    id: "SS-004", category: "validation", name: "Double-encoded intake URL",
    brief: "Double-encoded hosts and paths — is validation pre- or post-decode?",
    owasp: "WSTG-INPV-01", attackId: "T1027",
    what: "Submit double-encoded URLs (%252e, %25 encoding of the host). Determine whether the intake validator normalizes before or after checking, and whether the SSRF guard sees the same normalized form.",
  },
  {
    id: "SS-005", category: "validation", name: "Unicode / IDN homograph domain",
    brief: "Lookalike unicode domains — does the validator normalize to punycode before checking?",
    owasp: "WSTG-INPV-01", attackId: "T1027",
    what: "Submit IDN homographs of secscan.us (cyrillic/greek lookalikes) as the intake target. Observe whether validation punycode-normalizes before the ownership/allow checks. Benign canary domains only.",
  },
  {
    id: "SS-006", category: "validation", name: "Overlong intake URL",
    brief: "Max-length URLs — truncation, rejection, or silent acceptance?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit URLs at and beyond plausible length limits (2k, 8k, 64k chars). Observe: clean rejection, silent truncation (dangerous — what got truncated?), or acceptance. Never a flood — a handful of single requests.",
  },
  {
    id: "SS-007", category: "validation", name: "Null byte and control chars in URL",
    brief: "Embedded nulls and control characters — stripped, rejected, or passed to the fetcher?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit intake URLs containing %00, %0d, %0a, and raw control characters. Observe whether the validator strips, rejects, or passes them to the SSRF guard / fetcher, where a null byte could truncate a host check.",
  },
  {
    id: "SS-008", category: "validation", name: "Port smuggling in intake URL",
    brief: "Explicit :443, :0, :65536, :80 on https — does the port survive validation intact?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit the intake URL with explicit ports: :443, :80 on an https URL, :0, :65536 (invalid), and :22. Observe whether validation preserves, strips, or rejects the port — and whether the guard checks the same host:port the fetcher uses.",
  },
  {
    id: "SS-009", category: "validation", name: "Scheme/host case tricks",
    brief: "HtTpS://SEcScAn.Us — is normalization case-consistent end to end?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit mixed-case scheme and host. The question is consistency: if the validator lowercases but the guard compares raw (or vice versa), case becomes a bypass primitive.",
  },
  {
    id: "SS-010", category: "validation", name: "CRLF injection in URL field",
    brief: "Embedded CRLF — header injection or clean rejection?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit intake URLs containing %0d%0a followed by benign header-shaped text. Observe whether the validator rejects or the value flows into any header-building path. Benign content only; the injection attempt itself is the test.",
  },
  {
    id: "SS-011", category: "validation", name: "Regex bypass on domain validator",
    brief: "Unanchored patterns, newline tricks — can the domain regex be walked around?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Probe the intake domain/URL regex with classic bypasses: secscan.us.evil-canary, evilsecscan.us, newline-embedded domains, and subdomain-boundary tricks. Single probes — never ReDoS-shaped input.",
  },
  {
    id: "SS-012", category: "validation", name: "DNS-rebinding-shaped hostname",
    brief: "Rebinding-shaped hostnames at the validator — flagged or accepted?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit hostnames shaped for DNS rebinding (short-TTL, dual-record canary hostnames) to the intake validator and observe the verdict. This tests the validator only — no actual rebinding attack is performed.",
    needs: "Canary DNS infrastructure under operator control.",
  },
  {
    id: "SS-013", category: "validation", name: "Loopback spellings at the validator",
    brief: "127.1, 2130706433, [::], 0.0.0.0 — does the validator catch every loopback spelling?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit decimal (2130706433), octal, short-form (127.1), IPv6 ([::1], [::]), and 0.0.0.0 loopback spellings. Validator-level verdicts only — these are never fetched. Any spelling the validator accepts is the finding.",
  },
  {
    id: "SS-014", category: "validation", name: "Private-range literals at the validator",
    brief: "10/8, 172.16/12, 192.168/16 in decimal/octal/hex — full private-range coverage?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit private-range IPs in dotted, decimal, octal, and hex spellings. Validator verdicts only, never fetched. Map exactly which spellings are caught — one missed spelling is the finding.",
  },
  {
    id: "SS-015", category: "validation", name: "Metadata-shaped addresses at the validator",
    brief: "169.254.169.254 and metadata spellings — rejected on sight?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit cloud-metadata-shaped addresses (169.254.169.254 and decimal/octal spellings) to the intake validator. Verdicts only — nothing is ever requested. A validator that accepts these is a critical finding.",
  },
  // ================================================= SSRF GUARD (logic)
  {
    id: "SS-016", category: "logic", name: "SSRF guard: redirect chain http→https→http",
    brief: "Multi-hop redirect chain through a canary redirector — every hop revalidated?",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Submit an intake URL pointing at an operator-controlled redirector that chains http→https→http across 3 hops. Observe whether the per-hop revalidation fires on every hop or only the first. Benign canary targets only.",
    needs: "Canary redirector infrastructure under operator control.",
    blackNote: "One chain; the guard's behavior is the observation, not a bypass campaign.",
  },
  {
    id: "SS-017", category: "logic", name: "SSRF guard: redirect to private range via open-redirector hop",
    brief: "Canary open redirector pointing at a private-range-shaped host — does the guard catch the landing?",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Chain: public canary URL → open redirector → private-range-shaped hostname (a canary name that RESOLVES to nothing routable, testing the guard's verdict, not an actual internal fetch). The guard must refuse the landing. Never a real internal address.",
    needs: "Canary redirector infrastructure under operator control.",
  },
  {
    id: "SS-018", category: "logic", name: "SSRF guard: per-hop revalidation depth",
    brief: "5-hop chain — is hop 5 checked as strictly as hop 1?",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Submit a 5-hop canary redirect chain and determine the revalidation depth: does the guard check every hop, or does scrutiny decay after N hops? Benign canary targets only.",
    needs: "Canary redirector infrastructure under operator control.",
  },
  {
    id: "SS-019", category: "logic", name: "SSRF guard: redirect loop and max-redirect behavior",
    brief: "Redirect loops and 20-hop chains — sane termination or resource burn?",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Submit a canary URL that redirects in a loop and one with a 20-hop chain. Observe max-redirect handling and whether loop detection terminates cleanly. Canary targets only; never a loop designed to burn scanner resources.",
  },
  {
    id: "SS-020", category: "logic", name: "SSRF guard: scheme downgrade mid-chain",
    brief: "https→http downgrade on hop 2 — does the guard re-evaluate the scheme?",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Chain a canary https URL to an http URL mid-redirect. Observe whether the guard re-evaluates scheme policy per hop or inherits the first hop's approval. Canary targets only.",
    needs: "Canary redirector infrastructure under operator control.",
  },
  {
    id: "SS-021", category: "logic", name: "SSRF guard: host swap mid-chain",
    brief: "Hop 1 benign, hop 2 a canary evil host — is the new host fully re-vetted?",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Redirect from a benign canary host to a different canary host mid-chain. The guard must treat the new host as a fresh target: full validation, not inherited trust. Canary targets only.",
    needs: "Canary redirector infrastructure under operator control.",
  },
  {
    id: "SS-022", category: "logic", name: "SSRF guard: DNS TTL games",
    brief: "Short-TTL canary DNS flipping between benign and blocked — validate-then-fetch race?",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Point intake at a canary hostname whose DNS flips between a benign and a blocked answer on short TTL. This tests for a time-of-check/time-of-use gap between guard validation and fetch. Benign canary DNS only; single attempts, never a hammering loop.",
    needs: "Canary DNS infrastructure under operator control.",
    blackNote: "Single attempt; a TOCTOU gap is reported, not exploited repeatedly.",
  },
  {
    id: "SS-023", category: "logic", name: "Validator vs guard divergence",
    brief: "Same hostile URL through validator and guard separately — divergent verdicts?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit the same hostile-shaped canary URL and compare the intake validator's verdict against the SSRF guard's verdict independently. Any input one accepts and the other rejects is a seam worth naming in the report.",
  },
  // ============================================ INTAKE OPTIONS (mixed)
  {
    id: "SS-024", category: "functionality", name: "Mass assignment on scan options",
    brief: "role/isAdmin/userId/credits/tier flags smuggled into the intake JSON — do they bind?",
    owasp: "OWASP API3:2023", attackId: "T1190",
    what: "Add unexpected fields to the scan-intake JSON body: role, isAdmin, userId, credits, tier, aggressive. Observe whether they bind, validate, or are ignored — especially anything that could escalate the scan tier without authorization. Own test account only.",
  },
  {
    id: "SS-025", category: "functionality", name: "Hidden intake parameters",
    brief: "debug/preview/aggressive/callback/_method — undocumented params honored?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Probe the intake endpoint for undocumented parameters: debug, preview, aggressive, callback, _method, admin. Prefer parameters hinted at in client bundles over blind guessing — one probe per family.",
    blackNote: "Prefer parameters already hinted at in client code over blind guessing.",
  },
  {
    id: "SS-026", category: "logic", name: "Aggressive-tier escalation without authorization",
    brief: "Free-tier account requesting aggressive scans — enforced server-side?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "From a free-tier test account, request aggressive-tier scans via the intake API (tier flags, hidden params, direct endpoint). The server must refuse — a granted aggressive scan is the finding. Never consume someone else's quota.",
  },
  {
    id: "SS-027", category: "logic", name: "Negative/zero numeric scan options",
    brief: "wait_seconds=-1, limit=0 — validated, clamped, or computed on?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Submit negative, zero, and absurd values for numeric intake options (wait_seconds, limit, depth). Observe whether the app validates, clamps, or computes on them — a negative wait becoming a huge one is the finding.",
  },
  {
    id: "SS-028", category: "functionality", name: "Content-type confusion on intake",
    brief: "Same payload as JSON, form, and text — identical parsing, validation, guard?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit the identical scan-intake payload as application/json, application/x-www-form-urlencoded, and text/plain. Observe whether parsing, validation, and the SSRF guard behave identically across content types.",
  },
  {
    id: "SS-029", category: "functionality", name: "HTTP method tampering on intake",
    brief: "Scan intake via GET/PUT/DELETE/X-HTTP-Method-Override — honored or rejected?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Replay the intake request as GET (params in query), PUT, DELETE, and POST with X-HTTP-Method-Override. A state-changing intake honored on GET is the finding. Own test account only.",
  },
  {
    id: "SS-030", category: "validation", name: "Parameter pollution on intake url",
    brief: "Duplicate url params — first wins, last wins, or array?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit duplicate url parameters (benign + hostile-shaped canary) in query and body. Observe which value wins and whether validator and guard agree on the winner.",
  },
];
