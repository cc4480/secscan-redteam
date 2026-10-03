/**
 * SECSCAN battery — part 4 of 4 (v0.19.0 refactor split).
 * Starts at section: API SURFACE (mixed)
 *
 * Pure data split of secscan.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by secscan.ts.
 */

import type { TargetBatteryItem } from "./types.js";

export const SECSCAN_PART_4: TargetBatteryItem[] = [
  // ============================================ API SURFACE (mixed)
  {
    id: "SS-095", category: "functionality", name: "Web→API parity replay",
    brief: "Every web flow replayed via the API — same authz, same validation?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Replay intake, status, report, share, and listing flows directly against the REST API. The API must enforce everything the web UI enforces — any API path weaker than its web twin is the finding.",
  },
  {
    id: "SS-096", category: "validation", name: "API accepts what the web form rejects",
    brief: "Client-side-only validation — does the server re-validate?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit directly what the UI forbids: disabled aggressive-tier toggle, JS URL checks, maxlength attributes. The question is always whether the server re-validates — bypass is the finding.",
  },
  {
    id: "SS-097", category: "functionality", name: "API versioning gaps",
    brief: "Old API versions / legacy paths — still live with old flaws?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Probe for versioned API paths (/v1, /api/v1, legacy routes) and replay attacks against them. An old version with weaker checks than current is the finding.",
  },
  {
    id: "SS-098", category: "validation", name: "API error verbosity vs web",
    brief: "JSON errors with stack traces the HTML view hides?",
    owasp: "WSTG-ERRH-01", attackId: "T1592.002",
    what: "Compare error verbosity between the web UI and the API for identical bad input. Stack traces, SQL fragments, or internal paths in JSON errors are the finding.",
  },
  {
    id: "SS-099", category: "functionality", name: "API authentication edge cases",
    brief: "Every API endpoint without a token — uniformly 401?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Hit every discovered API endpoint with no credentials, malformed tokens, and expired-shaped tokens. Any endpoint that behaves differently unauthenticated is the finding.",
  },
  // ============================================ TLS / HEADERS / CORS (mixed)
  {
    id: "SS-100", category: "validation", name: "Security headers observation",
    brief: "HSTS, CSP, X-Frame-Options, Referrer-Policy — present and strict?",
    owasp: "WSTG-CONF", attackId: "T1592.002",
    what: "Passively record security headers on the app, report, and share pages: HSTS (includeSubDomains, preload), CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy. Missing/weak headers are hardening findings — observation only.",
  },
  {
    id: "SS-101", category: "functionality", name: "CORS reflected Origin with credentials",
    brief: "Attacker Origin reflected with Access-Control-Allow-Credentials?",
    owasp: "WSTG-CONF", attackId: "T1190",
    what: "Send canary Origin values (evil-canary, null, subdomain tricks) and check reflection plus credentials flag. Reflected origin with credentials=true is the finding. Benign canary origins only.",
  },
  {
    id: "SS-102", category: "functionality", name: "Open redirect via next/return params",
    brief: "next=/\\evil-canary — redirect parameters validated?",
    owasp: "WSTG-CLNT-04", attackId: "T1190",
    what: "Probe redirect parameters (next, return, redirect, continue) with canary-external targets, protocol-relative URLs, and backslash tricks. Open redirect to a canary host is the finding — canary only, never a real external site.",
  },
  {
    id: "SS-103", category: "validation", name: "Host header injection effects",
    brief: "Poisoned Host — cache poisoning, reset-link poisoning, or clean ignore?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send requests with poisoned Host / X-Forwarded-Host values (canary hostnames) and observe: password-reset links, cached responses, and absolute URLs generated. Any reflection of the poisoned host is the finding.",
  },
  // ============================================ ERROR HANDLERS (mixed)
  {
    id: "SS-104", category: "validation", name: "404/500 verbosity",
    brief: "Error pages with stack traces or framework fingerprints?",
    owasp: "WSTG-ERRH-01", attackId: "T1592.002",
    what: "Trigger 404s and 500s across the app (bad paths, bad IDs) and harvest verbosity: stack traces, framework versions, SQL fragments. Verbose errors are the finding.",
  },
  {
    id: "SS-105", category: "functionality", name: "Error-based enumeration",
    brief: "Valid vs invalid UUID timing/message differentials — oracle?",
    owasp: "WSTG-ATHN", attackId: "T1087",
    what: "Compare timing and messages for valid-format vs invalid-format vs nonexistent scan IDs on own-account endpoints. A differential is an enumeration oracle — the finding, not a harvest.",
    blackNote: "Minimal probes; stop at the first differential.",
  },
  // ============================================ SCANNER EFFICACY (logic)
  // The red team adversarially validates the scanner itself: canary targets
  // with KNOWN planted flaws verify SecScan detects what it claims.
  // Non-destructive, canary targets only — detection-validation, not abuse.
  {
    id: "SS-106", category: "logic", name: "Efficacy: planted reflected XSS detected",
    brief: "Canary with known reflected XSS — does the scan report it?",
    owasp: "WSTG-INPV-02", attackId: "T1190",
    what: "Scan a canary target with a deliberately planted reflected XSS and verify the scan reports it with the right classification. A miss is a detection-gap finding — the scanner's core promise under test.",
    needs: "Canary target with planted flaws, under operator control.",
  },
  {
    id: "SS-107", category: "logic", name: "Efficacy: planted SQLi error detected",
    brief: "Canary with known SQLi error surface — reported?",
    owasp: "WSTG-INPV-05", attackId: "T1190",
    what: "Scan a canary target with a planted SQL error surface and verify detection. A miss is a detection-gap finding.",
    needs: "Canary target with planted flaws, under operator control.",
  },
  {
    id: "SS-108", category: "logic", name: "Efficacy: missing security headers reported",
    brief: "Canary stripped of security headers — flagged?",
    owasp: "WSTG-CONF", attackId: "T1190",
    what: "Scan a canary target with deliberately missing security headers and verify the report flags each one. Missing flags are detection gaps.",
    needs: "Canary target with planted flaws, under operator control.",
  },
  {
    id: "SS-109", category: "logic", name: "Efficacy: exposed .git reported",
    brief: "Canary with exposed .git — information-disclosure finding raised?",
    owasp: "WSTG-INFO", attackId: "T1592.002",
    what: "Scan a canary target exposing a fake .git directory and verify the scanner reports it. A miss is a detection-gap finding.",
    needs: "Canary target with planted flaws, under operator control.",
  },
  {
    id: "SS-110", category: "logic", name: "Efficacy: weak TLS reported",
    brief: "Canary with TLS 1.0/1.1 — flagged in the report?",
    owasp: "WSTG-CRYP", attackId: "T1190",
    what: "Scan a canary target serving weak TLS and verify the report flags it. A miss is a detection-gap finding.",
    needs: "Canary target with planted flaws, under operator control.",
  },
  {
    id: "SS-111", category: "logic", name: "Efficacy: open redirect reported",
    brief: "Canary with a deliberate open redirect — caught?",
    owasp: "WSTG-CLNT-04", attackId: "T1190",
    what: "Scan a canary target with a planted open redirect and verify detection. A miss is a detection-gap finding.",
    needs: "Canary target with planted flaws, under operator control.",
  },
  {
    id: "SS-112", category: "logic", name: "Efficacy: verbose errors reported",
    brief: "Canary with stack-trace errors — information-disclosure finding?",
    owasp: "WSTG-ERRH-01", attackId: "T1190",
    what: "Scan a canary target emitting verbose errors and verify the scanner flags information disclosure. A miss is a detection-gap finding.",
    needs: "Canary target with planted flaws, under operator control.",
  },
  {
    id: "SS-113", category: "logic", name: "Efficacy: known-vulnerable JS library reported",
    brief: "Canary loading a known-vuln library version — flagged?",
    owasp: "WSTG-INFO / SCA", attackId: "T1190",
    what: "Scan a canary target loading a deliberately outdated JS library and verify the report flags it. A miss is a detection-gap finding.",
    needs: "Canary target with planted flaws, under operator control.",
  },
  {
    id: "SS-114", category: "logic", name: "Efficacy: clean target precision",
    brief: "Hardened canary with no flaws — any false positives?",
    owasp: "Detection precision", attackId: "T1190",
    what: "Scan a hardened canary target with no planted flaws. Every finding on a clean target is a false positive — precision is half the scanner's promise, and false positives erode trust exactly like misses do.",
    needs: "Hardened canary target under operator control.",
  },
  {
    id: "SS-115", category: "logic", name: "Efficacy: severity calibration",
    brief: "Planted critical flaw — graded critical, not low?",
    owasp: "Detection calibration", attackId: "T1190",
    what: "Plant flaws of known severity (one critical, one low) on a canary target and verify the grades match. Misgraded severity is a calibration finding — a critical graded 'low' is as dangerous as a miss.",
    needs: "Canary target with planted flaws, under operator control.",
  },
  // ============================================ CROSS-CUTTING (mixed)
  {
    id: "SS-116", category: "functionality", name: "Cache poisoning via forwarded host",
    brief: "X-Forwarded-Host on report pages — poisoned cache served to others?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send report-page requests with canary X-Forwarded-Host values and check whether the poisoned response gets cached and served to a clean request. Cache poisoning is the finding — canary hostnames only.",
  },
  {
    id: "SS-117", category: "logic", name: "Host-header password-reset poisoning",
    brief: "Poisoned Host in reset flow — reset link points at attacker host?",
    owasp: "WSTG-ATHN-04", attackId: "T1190",
    what: "Trigger a reset for an operator-owned test account with a poisoned Host header and inspect where the reset link points. A link pointing at the canary host is the finding. Never target real users.",
    needs: "Test account with operator-controlled email.",
  },
  {
    id: "SS-118", category: "logic", name: "Free-tier quota enforcement",
    brief: "Free scans exhausted — is the (N+1)th scan refused?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Exhaust the free-tier scan quota on a test account and attempt one more scan. The refusal must be clean — a granted over-quota scan is the finding. Operator-owned credits only.",
  },
  {
    id: "SS-119", category: "logic", name: "Credit parity across intake paths",
    brief: "Web, API, and MCP intake — identical credit accounting?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Create one scan through each intake path (web, API, MCP) and compare credit deduction. Any path that deducts differently — especially one that deducts nothing — is the finding.",
  },
  {
    id: "SS-120", category: "validation", name: "CSRF on state-changing endpoints",
    brief: "Share-create and intake without CSRF tokens — cross-site forgery?",
    owasp: "WSTG-SESS-05", attackId: "T1190",
    what: "Replay share-creation and scan-intake as cross-origin form posts without CSRF tokens (test account). Missing or non-validated tokens on state-changing endpoints is the finding.",
  },
];
