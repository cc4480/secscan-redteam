/**
 * SECSCAN battery — part 3 of 4 (v0.19.0 refactor split).
 * Starts at section: REPORT EXPORT (mixed)
 *
 * Pure data split of secscan.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by secscan.ts.
 */

import type { TargetBatteryItem } from "./types.js";

export const SECSCAN_PART_3: TargetBatteryItem[] = [
  // ============================================ REPORT EXPORT (mixed)
  {
    id: "SS-061", category: "functionality", name: "Path traversal in export filename",
    brief: "filename=../../x on report export — traversal or sanitized?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Tamper with any filename parameter on report export (filename=../../canary, encoded variants). Observe sanitization — the finding is whether user input reaches a filesystem path unsanitized. Benign canary names only.",
  },
  {
    id: "SS-062", category: "functionality", name: "Export content-type mismatch",
    brief: "JSON labeled as PDF and vice versa — content sniffing risk?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Request each export format and compare the Content-Type header against the actual bytes, plus X-Content-Type-Options presence. A mismatch that enables sniffing is the finding.",
  },
  {
    id: "SS-063", category: "validation", name: "Export format parameter injection",
    brief: "format=../../etc/passwd-shaped — validated against an allowlist?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit traversal-shaped and template-shaped format values. Observation only: allowlist validation vs verbose errors vs reflection. Never a real filesystem target.",
  },
  {
    id: "SS-064", category: "logic", name: "Export another account's report via direct URL",
    brief: "Direct export URL with another account's session — same boundary as view?",
    owasp: "OWASP API1:2023", attackId: "T1190",
    what: "Replay the export endpoints against another owned test account's report. Export paths sometimes skip the checks the view path enforces — that asymmetry is the finding.",
    needs: "Second test account owned by the operator.",
  },
  {
    id: "SS-065", category: "functionality", name: "Export of partial/running scan",
    brief: "Export mid-scan — partial data, errors, or clean refusal?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Request exports while the scan is still running. Observe whether partial findings leak, the export errors cleanly, or a corrupt document is produced.",
  },
  // ============================================ SHARE LINKS (mixed)
  {
    id: "SS-066", category: "logic", name: "Share creation authorization",
    brief: "Share link for a scan I don't own — creation-side authz?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Attempt share-link creation for another owned test account's scan ID. Creation must require ownership — a share minted for someone else's scan is the finding.",
    needs: "Second test account owned by the operator.",
  },
  {
    id: "SS-067", category: "logic", name: "Expired share link access",
    brief: "Link past its 30-day expiry — dead, or still serving?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Create a share with the shortest allowed expiry, let it lapse (or manipulate the clock-facing parameter if the API exposes one), then request it. Any serving past expiry is the finding.",
  },
  {
    id: "SS-068", category: "functionality", name: "Share token tampering",
    brief: "Truncated/extended/re-encoded tokens — strict validation or prefix-tolerant?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Tamper with own share tokens: truncation, extension, base64 re-encoding, character swaps. Observe whether validation is strict or prefix-tolerant — tolerance is the finding.",
  },
  {
    id: "SS-069", category: "functionality", name: "Cross-share token swap",
    brief: "Token from share A on share B's URL — bound to the share?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Swap tokens between two own-account shares. Tokens must be bound to their share — cross-acceptance is the finding. Own account only.",
  },
  {
    id: "SS-070", category: "logic", name: "Token replay after revoke/expiry change",
    brief: "Revoked share's token replayed — single-use lifecycle enforced?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Revoke a share (or shorten its expiry to the past), then replay the old token. Revocation must actually kill the token — a replay that still serves is the finding.",
  },
  {
    id: "SS-071", category: "validation", name: "Share token entropy and format analysis",
    brief: "Token structure analyzed — entropy, predictability, information leakage?",
    owasp: "WSTG-ATHZ", attackId: "T1592.002",
    what: "Analyze own share tokens passively: length, alphabet, visible structure (embedded IDs? timestamps?). The analysis is observational — no brute-forcing, which is infeasible by design.",
  },
  {
    id: "SS-072", category: "logic", name: "Share of failed/partial scan",
    brief: "Sharing a failed scan — error internals exposed to anonymous viewers?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Create a share for a failed scan and inspect what an unauthenticated viewer sees: failure reasons and internal details must not leak wider than the authenticated report view.",
  },
  {
    id: "SS-073", category: "functionality", name: "Share-create method tampering and mass assignment",
    brief: "Share via GET/PUT, expiry smuggled in JSON — honored?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Create shares via GET/PUT/DELETE and smuggle expiry days, scope flags, and permission fields into the creation JSON. Observe method enforcement and field binding. Own account only.",
  },
  {
    id: "SS-074", category: "logic", name: "Absurd share expiry values",
    brief: "expiry=99999, 0, -1 — validated, clamped, or honored?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Submit absurd expiry values (0, -1, 999999, non-numeric). Observe validation vs clamping — a negative expiry that means 'never expires' is the finding.",
  },
  {
    id: "SS-075", category: "validation", name: "Share token case/encoding in URL",
    brief: "Case-flipped and URL-encoded tokens — canonicalized before lookup?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Request own share URLs with case-flipped, URL-encoded, and double-encoded tokens. Observe canonicalization — inconsistent handling between creation-time and lookup-time is the finding.",
  },
  {
    id: "SS-076", category: "functionality", name: "Share viewer surface enumeration",
    brief: "What can an anonymous share viewer reach beyond the report?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "As an unauthenticated viewer of an own-account share, probe adjacent paths: API endpoints, other formats, directory traversal out of the share scope. The share must be a sealed room — any exit is the finding.",
  },
  // ============================================ AI OPT-OUT (mixed)
  {
    id: "SS-077", category: "logic", name: "Opt-out toggle persistence",
    brief: "AI opt-out — persisted per scan and per account, or cosmetic?",
    owasp: "WSTG-ATHZ / privacy", attackId: "T1190",
    what: "Toggle AI opt-out on a test scan, then verify persistence: reload the report, re-fetch via API, and check a second session. A toggle that doesn't stick is the finding.",
  },
  {
    id: "SS-078", category: "logic", name: "Opt-out redaction verification",
    brief: "Opted-out scan — evidence snippets, URLs, headers truly absent from AI-visible fields?",
    owasp: "WSTG-ATHZ / privacy", attackId: "T1190",
    what: "Enable AI opt-out, then forensically verify the report output: no evidence snippets, target URLs, response headers, or identifiers in any AI-visible field. Opt-out that doesn't redact is the finding.",
  },
  {
    id: "SS-079", category: "functionality", name: "Opt-out bypass via alternate path",
    brief: "Export/share/MCP paths — do they honor the opt-out redaction?",
    owasp: "WSTG-ATHZ / privacy", attackId: "T1190",
    what: "With opt-out enabled, pull the same scan through every alternate path: exports, share links, MCP get_report. Any path serving unredacted content the main view redacts is the finding.",
  },
  {
    id: "SS-080", category: "logic", name: "Opt-out toggle on another account's scan",
    brief: "Flipping someone else's opt-out — authorization on the privacy control?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Attempt to toggle AI opt-out on another owned test account's scan. Privacy controls need the same authorization boundary as the data — cross-account toggling is the finding.",
    needs: "Second test account owned by the operator.",
  },
  // ============================================ RATE LIMITS (mixed)
  {
    id: "SS-081", category: "logic", name: "Intake limiter shape mapping",
    brief: "429 mapping — is the intake limit per-account, per-IP, or per-namespace?",
    owasp: "OWASP API4:2023", attackId: "T1499",
    what: "Probe the namespaced intake rate limit with a handful of requests: observe 429 shape, Retry-After, and whether the bucket is per-account, per-IP, or per-namespace. Mapping the limiter's shape — never stressing it.",
    blackNote: "Handful of probes only — this maps the limiter, it does not stress it.",
  },
  {
    id: "SS-082", category: "logic", name: "X-Forwarded-For rotation vs intake limiter",
    brief: "Rotating XFF — does the limiter key on a spoofable header?",
    owasp: "OWASP API4:2023", attackId: "T1499",
    what: "Replay intake requests with rotated X-Forwarded-For / X-Real-IP values (a few probes). If the limit resets per header value, the limiter keys on spoofable input — the finding. Never a real bypass campaign.",
  },
  {
    id: "SS-083", category: "logic", name: "Share limiter bypass mapping",
    brief: "Same limiter analysis on the share namespace — consistent enforcement?",
    owasp: "OWASP API4:2023", attackId: "T1499",
    what: "Map the share-namespace limiter the same way: shape, keying, and whether its strictness matches the intake limiter. Inconsistent enforcement between namespaces is the finding.",
    blackNote: "Handful of probes only.",
  },
  {
    id: "SS-084", category: "validation", name: "429 response differential",
    brief: "Does the 429 body leak limiter configuration?",
    owasp: "WSTG-ERRH-01", attackId: "T1592.002",
    what: "Inspect 429 responses for leaked configuration: limit values, window sizes, bucket keys, internal identifiers. Informative rate-limit responses are the finding.",
  },
  {
    id: "SS-085", category: "logic", name: "Limiter reset behavior",
    brief: "Window reset — fixed or sliding? predictable reset abused?",
    owasp: "OWASP API4:2023", attackId: "T1499",
    what: "Observe limiter reset timing across a few windows: fixed vs sliding, and whether the reset moment is predictable enough to schedule around. Observation only — never engineered into sustained over-limit traffic.",
  },
  // ============================================ AUTH / SESSION (mixed)
  {
    id: "SS-086", category: "logic", name: "Session fixation",
    brief: "Attacker-set session ID surviving login — fixation possible?",
    owasp: "WSTG-SESS-03", attackId: "T1190",
    what: "If cookie auth exists: set a session cookie pre-login, complete login with a test account, and check whether the pre-login ID survived. Survival is the finding. Test accounts only.",
  },
  {
    id: "SS-087", category: "logic", name: "Password-reset token reuse and expiry",
    brief: "Reset token replayed, expired, tampered — single-use and time-bound?",
    owasp: "WSTG-ATHN-04", attackId: "T1556",
    what: "Trigger reset for an operator-owned test account, then: reuse the token twice, use it after expiry, and tamper with its structure. Tokens must be single-use and time-bound. Never trigger emails to real users.",
    needs: "Test account with operator-controlled email.",
  },
  {
    id: "SS-088", category: "logic", name: "Reset for another identifier → enumeration",
    brief: "Reset requested for other emails — existence oracle in the response?",
    owasp: "WSTG-ATHN-04", attackId: "T1087",
    what: "Request resets for existent vs nonexistent operator-controlled identifiers and compare responses/timing. A differential is an account-enumeration oracle — the finding, not a harvest. Never target real users.",
    needs: "Operator-controlled test identifiers.",
    blackNote: "Minimal probes; stop at the first differential.",
  },
  {
    id: "SS-089", category: "functionality", name: "Login enumeration differential",
    brief: "Valid vs invalid username — timing or message differential?",
    owasp: "WSTG-ATHN-02", attackId: "T1087",
    what: "Compare login responses for valid vs invalid test usernames: messages, timing, and status codes. Any differential is the finding. Test accounts only, handful of probes.",
    blackNote: "Minimal probes; stop at the first differential.",
  },
  {
    id: "SS-090", category: "logic", name: "Change-email without re-authentication",
    brief: "Account email changed on session alone — re-auth required?",
    owasp: "WSTG-ATHN", attackId: "T1556",
    what: "Change the account email of a test account using only the session (no password re-entry). Sensitive account changes must demand re-authentication — its absence is the finding.",
  },
  {
    id: "SS-091", category: "logic", name: "Logout invalidates the session",
    brief: "Post-logout session replay — truly dead server-side?",
    owasp: "WSTG-SESS-06", attackId: "T1190",
    what: "Log out a test account, then replay the old session cookie/token against authenticated endpoints. The session must die server-side — any post-logout acceptance is the finding.",
  },
  {
    id: "SS-092", category: "validation", name: "Cookie flags observation",
    brief: "HttpOnly/Secure/SameSite on session cookies — set correctly?",
    owasp: "WSTG-SESS-02", attackId: "T1592.002",
    what: "Inspect session cookies passively: HttpOnly, Secure, SameSite, Path, and Domain scope. Missing flags are reported as hardening findings — observation only, no exploitation.",
  },
  {
    id: "SS-093", category: "functionality", name: "Concurrent session handling",
    brief: "Second login kills the first? password change kills all sessions?",
    owasp: "WSTG-SESS", attackId: "T1190",
    what: "Log in twice with a test account and check whether the first session survives; then change the password and check whether all sessions die. Stale sessions surviving credential change is the finding.",
  },
  {
    id: "SS-094", category: "logic", name: "Password-change logic flaws",
    brief: "Change without old password, weak new password accepted?",
    owasp: "WSTG-ATHN", attackId: "T1556",
    what: "Attempt password change without the current password, with a weak new password, and with the username as the password. Each missing check is the finding. Test account only.",
  },
];
