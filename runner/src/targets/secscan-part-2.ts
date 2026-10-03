/**
 * SECSCAN battery — part 2 of 4 (v0.19.0 refactor split).
 * Starts at section: DNS OWNERSHIP GATE (mixed)
 *
 * Pure data split of secscan.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by secscan.ts.
 */

import type { TargetBatteryItem } from "./types.js";

export const SECSCAN_PART_2: TargetBatteryItem[] = [
  // ============================================ DNS OWNERSHIP GATE (mixed)
  {
    id: "SS-031", category: "logic", name: "DNS gate: wrong TXT value fails closed",
    brief: "Incorrect challenge TXT — clean failure, no partial verification?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Place a wrong value in the _secscan-challenge TXT record of an operator-controlled domain and trigger verification. The gate must fail closed with no partial-verified state. Operator-controlled domains only.",
    needs: "Operator-controlled test domain with DNS access.",
  },
  {
    id: "SS-032", category: "logic", name: "DNS gate: TXT on parent vs exact host",
    brief: "Challenge TXT on the parent domain — accepted for a subdomain claim?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Place the challenge TXT on the parent domain while claiming a subdomain (and vice versa). The gate must require the exact _secscan-challenge.<claimed-host> name — parental acceptance is the finding.",
    needs: "Operator-controlled test domain with DNS access.",
  },
  {
    id: "SS-033", category: "logic", name: "DNS gate: challenge hostname case/encoding tricks",
    brief: "Case and encoding variants of _secscan-challenge — exact-match enforced?",
    owasp: "WSTG-ATHZ-04", attackId: "T1027",
    what: "Probe whether the gate's challenge-hostname comparison is exact: case variants, punycode variants, and trailing-dot forms of _secscan-challenge.<domain>. Any accepted variant is the finding.",
    needs: "Operator-controlled test domain with DNS access.",
  },
  {
    id: "SS-034", category: "logic", name: "DNS gate: cross-domain challenge replay",
    brief: "Challenge issued for domain A replayed against domain B — bound to the domain?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Take a challenge token issued for one operator-controlled domain and present it during another domain's verification. Challenges must be domain-bound — cross-acceptance is the finding.",
    needs: "Two operator-controlled test domains with DNS access.",
  },
  {
    id: "SS-035", category: "logic", name: "DNS gate: verification polling without TXT",
    brief: "Poll the verification status with no TXT ever placed — any path to verified?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Trigger verification for an operator-controlled domain with no TXT record placed, then poll the status endpoint aggressively-but-politely for transitions. Any unverified→verified transition without the TXT is a critical finding.",
    needs: "Operator-controlled test domain with DNS access.",
    blackNote: "Single verification attempt; a gate that holds is a strong-defense finding.",
  },
  {
    id: "SS-036", category: "logic", name: "DNS gate: re-verification after TXT removal",
    brief: "TXT removed post-verification — does the verified status expire or persist forever?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Verify an operator-controlled domain, remove the TXT record, then observe whether the verified status persists indefinitely or lapses. Permanent verification after de-provisioning is the finding.",
    needs: "Operator-controlled test domain with DNS access.",
  },
  {
    id: "SS-037", category: "logic", name: "DNS gate: verification race vs TXT propagation",
    brief: "Single paired verify-now/verify-later around TXT placement — TOCTOU in the checker?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Fire a single pair of verification requests around TXT placement/removal timing and compare outcomes. One pair, one observation — testing for a time-of-check gap, never a hammering loop.",
    needs: "Operator-controlled test domain with DNS access.",
  },
  {
    id: "SS-038", category: "validation", name: "DNS gate: domain field validation",
    brief: "Trailing dots, encoding, overlong domains in the claimed domain — normalized exactly?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit claimed domains with trailing dots, mixed case, punycode, and overlong labels to the verification flow. Observe whether the claimed domain is normalized identically at challenge issuance and at TXT lookup.",
  },
  {
    id: "SS-039", category: "functionality", name: "DNS gate: verification-status enumeration oracle",
    brief: "verified vs unverified vs unknown domains — response differentials?",
    owasp: "WSTG-ATHN", attackId: "T1087",
    what: "Compare verification-status responses for verified, unverified, and nonexistent domains (own test domains). A differential that reveals another party's verification state is the finding — stop at the differential, never harvest.",
    needs: "Operator-controlled test domain with DNS access.",
    blackNote: "Minimal probes; stop at the first differential.",
  },
  {
    id: "SS-040", category: "logic", name: "DNS gate: stale challenge reuse",
    brief: "Old challenge token reused in a fresh verification — single-use enforced?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Complete one verification, then attempt a second verification reusing the first challenge token. Challenges must be single-use — replay acceptance is the finding.",
    needs: "Operator-controlled test domain with DNS access.",
  },
  // ============================================ SCAN LIFECYCLE (mixed)
  {
    id: "SS-041", category: "logic", name: "Report fetch for queued scan",
    brief: "Request the report before the scan runs — invalid lifecycle transition?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Immediately after intake, request the report/export endpoints for the still-queued scan. Observe whether the app enforces queued→running→complete ordering or leaks partial state.",
  },
  {
    id: "SS-042", category: "logic", name: "Duplicate intake mid-run",
    brief: "Same URL resubmitted while its scan runs — deduped, double-charged, or double-run?",
    owasp: "WSTG-BUSL-04", attackId: "T1190",
    what: "Resubmit the identical intake while the first scan is still running. Observe: deduplicated, run twice, or charged twice. Own test account only; the observation is the finding.",
  },
  {
    id: "SS-043", category: "logic", name: "Credit deduction exactly once",
    brief: "Single paired intake — is the credit deducted exactly once?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Fire a single pair of near-simultaneous intake requests and compare credit deduction: exactly one deduction expected. One pair, one observation — never engineered into a real double-spend.",
    blackNote: "Only against own test account with operator-owned credits.",
  },
  {
    id: "SS-044", category: "logic", name: "Cancel another account's scan",
    brief: "Cancel/abort endpoint aimed at another account's scan_id — authorized?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "If a cancel/abort affordance exists, aim it at another owned test account's scan. Cross-account cancellation is the finding — stop and report instantly. Never cancel anything not owned by the operator.",
    needs: "Second test account owned by the operator.",
  },
  {
    id: "SS-045", category: "validation", name: "Malformed scan_id shapes",
    brief: "Truncated/extended/non-hex scan_ids — strict UUID validation?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Request status/report with truncated, extended, non-hex, and brace-wrapped UUID shapes. Observe strictness — and whether any malformed shape produces a verbose error (see SS-057).",
  },
  {
    id: "SS-046", category: "functionality", name: "Status polling method tampering",
    brief: "Scan status via POST/PUT/DELETE — read endpoints that execute on write methods?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Replay the scan-status endpoint as POST, PUT, and DELETE. A read endpoint that changes state or behaves differently on write methods is the finding.",
  },
  {
    id: "SS-047", category: "validation", name: "Injection-shaped scan_id",
    brief: "SQLi/XSS-shaped scan_ids — parameterized, or verbose errors?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit benign injection-shaped strings as scan_id (quote marks, comment sequences, script tags). Observation only: parameterized handling vs verbose errors vs reflection. Never destructive payloads.",
  },
  {
    id: "SS-048", category: "logic", name: "Scan retry / re-run logic",
    brief: "Re-running a completed scan — charged again? state clean?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Re-run a completed own-account scan via any retry affordance. Observe credit charging, whether the old report is replaced or versioned, and whether retry of a failed scan bypasses any gate.",
  },
  // ============================================ SCAN LISTING (mixed)
  {
    id: "SS-049", category: "functionality", name: "Listing pagination abuse",
    brief: "Negative/zero offsets, huge limits on the scan list — clamped or honored?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Request the scan-listing endpoint with negative/zero offsets, huge limits, and non-numeric page values. Observe clamping — and watch for any other-account data in oversized responses (critical: stop and report instantly).",
  },
  {
    id: "SS-050", category: "functionality", name: "Listing sort/filter field abuse",
    brief: "Sort on non-indexed fields, filter injection — strict allowlist?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Sort and filter the scan list on non-indexed and nonexistent fields; try filter-operator injection (gt/lt/regex shapes). Observe whether field names are allowlisted and whether errors leak schema.",
  },
  {
    id: "SS-051", category: "logic", name: "Cross-account listing IDOR",
    brief: "Another account's scans in my list — the critical boundary test.",
    owasp: "OWASP API1:2023", attackId: "T1190",
    what: "With account A's session, manipulate listing parameters looking for account B's scans. Any cross-account data is a critical finding — stop and report instantly, never enumerate further.",
    needs: "Second test account owned by the operator.",
  },
  {
    id: "SS-052", category: "validation", name: "Listing limit clamping and type juggling",
    brief: "limit=array, limit=-1, limit=999999 — validated or computed on?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Type-juggle the listing limit/page parameters (arrays, strings, negatives, absurd values). Observe validation vs clamping — a negative limit that returns everything is the finding.",
  },
  // ============================================ REPORT VIEW (mixed)
  {
    id: "SS-053", category: "logic", name: "Cross-account report IDOR",
    brief: "Account B's report URL with account A's session — the authorization boundary.",
    owasp: "OWASP API1:2023", attackId: "T1190",
    what: "With account A's session, request account B's report URL directly. This is authorization-boundary testing between two owned test accounts — not UUID guessing (infeasible, never attempted). Two observations before a verdict: the anomalous response AND a control.",
    needs: "Second test account owned by the operator.",
  },
  {
    id: "SS-054", category: "functionality", name: "Method tampering on report fetch",
    brief: "Report via POST/PUT/DELETE — read endpoint honoring write methods?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Fetch a report as POST, PUT, DELETE, and PATCH. Note which methods the app honors vs rejects — a GET-only report that renders on POST is the finding.",
  },
  {
    id: "SS-055", category: "validation", name: "Malformed report_id shapes",
    brief: "Truncated/extended report_ids — strict validation or verbose errors?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Request reports with malformed ID shapes. Observe strictness and feed any verbose errors into the oracle analysis (SS-058).",
  },
  {
    id: "SS-056", category: "functionality", name: "Hidden report format parameters",
    brief: "format=json|pdf|html, download, print — undocumented render paths?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Probe the report endpoint for format/render parameters: format, download, print, raw, embed. Each undocumented path is new attack surface — test it for the same flaws as the main path.",
  },
  {
    id: "SS-057", category: "logic", name: "Report for failed scan",
    brief: "Failed scan's report page — error disclosure or clean state?",
    owasp: "WSTG-ERRH-01", attackId: "T1190",
    what: "Drive a scan to failure (invalid canary target) and inspect the report path: verbose failure reasons, internal hostnames, or stack traces leaking through the failure state.",
  },
  {
    id: "SS-058", category: "validation", name: "'No such scan' vs 'not your scan' differential",
    brief: "Error-message oracle on report access — existence vs authorization distinguished?",
    owasp: "WSTG-ERRH-01", attackId: "T1592.002",
    what: "Compare responses for: nonexistent scan ID, another account's scan ID (with two owned accounts), and malformed ID. Any differential between 'does not exist' and 'not yours' is an existence oracle — the finding, not a harvest.",
    needs: "Second test account owned by the operator.",
    blackNote: "Minimal probes; stop at the first differential.",
  },
  {
    id: "SS-059", category: "functionality", name: "Self-XSS via own scan data in report",
    brief: "Benign marker in canary target — reflected unescaped in my own report?",
    owasp: "WSTG-INPV-02", attackId: "T1190",
    what: "Scan a canary target containing a benign inert marker string and check whether it renders unescaped in the report HTML. Own account only, inert marker, no script execution pursued beyond the reflection observation.",
    needs: "Canary target under operator control.",
  },
  {
    id: "SS-060", category: "validation", name: "Report caching and stale authorization",
    brief: "Cached report served after access revoked — authorization re-checked?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Access a report, then change the authorization state (share revoked / session ended) and re-request. A cached copy served past revocation is the finding.",
  },
];
