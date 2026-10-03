/**
 * SECLAYER battery — part 3 of 3 (v0.19.0 refactor split).
 * Starts at section: HTTP LAYER
 *
 * Pure data split of seclayer.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by seclayer.ts.
 */

import type { TargetBatteryItem } from "./types.js";

export const SECLAYER_PART_3: TargetBatteryItem[] = [
  // ============================================ HTTP LAYER
  {
    id: "SL-052", category: "functionality", name: "GET vs POST on /api/mcp",
    brief: "Tool call via GET with query-encoded JSON-RPC — executed?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Streamable HTTP expects POST: try GET with query-encoded JSON-RPC, and GET on the bare path. A GET that executes a tool call is the finding (CSRF-able state changes).",
  },
  {
    id: "SL-053", category: "functionality", name: "PUT/DELETE/PATCH on /api/mcp",
    brief: "Write methods on the MCP endpoint — honored or 405?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send the MCP payload via PUT, DELETE, and PATCH. Expect 405 — any method that executes is the finding.",
  },
  {
    id: "SL-054", category: "functionality", name: "Content-type confusion on MCP",
    brief: "Same JSON-RPC as form/text — identical auth and parsing?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send the identical JSON-RPC payload as application/json, form-encoded, and text/plain. Parsing, validation, and auth must behave identically — the known WAF quirk (urllib 403 vs curl UA) makes this especially worth mapping.",
  },
  {
    id: "SL-055", category: "validation", name: "X-HTTP-Method-Override on MCP",
    brief: "POST with method-override header — tunneled method honored?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send POST with X-HTTP-Method-Override: GET/PUT/DELETE. Observe whether the override is honored — tunneled methods bypassing method checks are the finding.",
  },
  {
    id: "SL-056", category: "functionality", name: "CORS on the API endpoint",
    brief: "Attacker Origin on /api/mcp — reflected with credentials?",
    owasp: "WSTG-CONF", attackId: "T1190",
    what: "Send canary Origin values to /api/mcp and check reflection plus credentials flag. Browser-based tool calls make this high-value — reflected origin with credentials is the finding. Canary origins only.",
  },
  {
    id: "SL-057", category: "validation", name: "WAF behavior mapping (passive)",
    brief: "Which shapes and user agents trip the 403 — defense mapping, not evasion.",
    owasp: "WSTG-INPV", attackId: "T1592.002",
    what: "Map the WAF footprint deliberately and passively: which payload shapes and user agents trigger the 403 (the known urllib-vs-curl UA differential is the starting point), and what the block page reveals. Defense mapping for the report's detection-gaps section — never iterated into evasion.",
    blackNote: "Passive mapping only. Never iterate to evade; a WAF that fires is data.",
  },
  {
    id: "SL-058", category: "functionality", name: "HEAD/OPTIONS/TRACE on /api/mcp",
    brief: "Exotic methods — information disclosure or execution?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send HEAD, OPTIONS, and TRACE. OPTIONS should not enumerate internal methods; TRACE must not echo. Any disclosure or execution is the finding.",
  },
  // ============================================ AUTH LAYER
  {
    id: "SL-059", category: "validation", name: "Authorization scheme case tricks",
    brief: "bearer vs Bearer vs BEARER — exactly one accepted?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Send the key with scheme case variants (bearer, BEARER, Token). Exactly one accepted shape expected — alternates are the finding.",
  },
  {
    id: "SL-060", category: "validation", name: "Whitespace-padded API keys",
    brief: "Padded keys accepted — sloppy comparison?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Send valid-shaped keys with leading/trailing whitespace and internal spaces. Acceptance indicates trimming/normalization that could interact with other checks — the finding.",
  },
  {
    id: "SL-061", category: "validation", name: "Key truncation/extension tolerance",
    brief: "Half a key, key plus garbage — exact match enforced?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Send truncated and extended variants of a valid key shape. Auth must be exact-match — any tolerance is the finding. (Uses malformed shapes, never a real valid key.)",
  },
  {
    id: "SL-062", category: "logic", name: "Revoked-shaped key behavior",
    brief: "Revoked-format keys — clean rejection, identical to bad keys?",
    owasp: "OWASP API2:2023", attackId: "T1592.002",
    what: "Probe with revoked-shaped keys and compare against bad-key responses. Any differential between 'revoked' and 'invalid' is an oracle — the finding.",
  },
  {
    id: "SL-063", category: "logic", name: "API key binding: IP/UA/session",
    brief: "One key from many contexts — bound or floating?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Use one test key from different user agents and observe whether any binding (IP, UA, session) is enforced. Purely floating keys are the observation — reported as a hardening note, not exploited.",
  },
  {
    id: "SL-064", category: "functionality", name: "Auth on notifications and ping",
    brief: "Unauthenticated ping/notifications — anything leaked?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Send ping and notifications with no key. Even 'harmless' endpoints must not leak version, session, or timing oracles — any leak is the finding.",
  },
  {
    id: "SL-065", category: "logic", name: "Auth differential across tools",
    brief: "Every tool, same bad key — identical auth failure everywhere?",
    owasp: "OWASP API2:2023", attackId: "T1592.002",
    what: "Send the identical bad key to every tool and compare failures. One tool failing differently (slower, different code, different message) is an oracle — the finding.",
  },
  // ============================================ NOTIFICATIONS / PROGRESS / CANCELLATION
  {
    id: "SL-066", category: "functionality", name: "Notification method abuse",
    brief: "tools/call as a notification — executed without id?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Send tools/call shaped as a notification (no id). Notifications must never execute — execution is the finding.",
  },
  {
    id: "SL-067", category: "functionality", name: "Ping without session",
    brief: "Sessionless ping — session created or info leaked?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send ping with no session context. Observe whether a session is implicitly created or any server info leaks. Implicit session creation is the finding.",
  },
  {
    id: "SL-068", category: "logic", name: "Cancellation of another's call",
    brief: "Cancel request aimed at another session's call — scoped?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Attempt to cancel an in-flight call belonging to another owned test session. Cancellation must be session-scoped — cross-session cancellation is the finding. Owned sessions only.",
    needs: "Second test session owned by the operator.",
  },
  {
    id: "SL-069", category: "functionality", name: "Progress token tampering",
    brief: "Forged progress tokens — accepted, confused, or rejected?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send progress notifications with forged, reused, and malformed progress tokens. Observe handling — accepted forgeries that influence server state are the finding.",
  },
  {
    id: "SL-070", category: "functionality", name: "Roots/list_changed abuse",
    brief: "Unexpected notification types — ignored or processed?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send roots/list_changed and other client-side notification types to the server. The server must ignore what isn't its protocol — processing them is the finding.",
  },
  // ============================================ RATE LIMITS / QUOTAS
  {
    id: "SL-071", category: "logic", name: "MCP limiter shape mapping",
    brief: "429 mapping on /api/mcp — per-key, per-IP, or global?",
    owasp: "OWASP API4:2023", attackId: "T1499",
    what: "Map the endpoint's rate limiting with a handful of probes: 429 shape, Retry-After, and bucket keying (per-key vs per-IP vs global). Mapping the limiter — never stressing it.",
    blackNote: "Minimal probes; the limiter's existence and shape are the observation.",
  },
  {
    id: "SL-072", category: "logic", name: "XFF rotation vs MCP limiter",
    brief: "Rotating XFF on the API — limiter keyed on spoofable input?",
    owasp: "OWASP API4:2023", attackId: "T1499",
    what: "Replay tool calls with rotated X-Forwarded-For values (a few probes). Limit reset per header value means spoofable keying — the finding. Never a real bypass campaign.",
  },
  {
    id: "SL-073", category: "logic", name: "Quota exhaustion behavior",
    brief: "Zero credits — clean error or partial execution?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Drain a test account's credits and call seclayer_scan. Expect a clean quota error — partial execution or a scan that runs without deduction is the finding. Operator-owned credits only.",
  },
  {
    id: "SL-074", category: "logic", name: "Credit parity: API vs web",
    brief: "Same scan via tool and web — identical deduction?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Create one scan via the MCP tool and one via web intake; compare credit deduction. Any path deducting differently — especially one deducting nothing — is the finding.",
  },
  // ============================================ ERROR ORACLES
  {
    id: "SL-075", category: "validation", name: "'Bad key' vs 'bad method' vs 'no such scan' differential",
    brief: "Error-code oracle across failure classes?",
    owasp: "WSTG-ERRH-01", attackId: "T1592.002",
    what: "Compare JSON-RPC error responses for bad key, bad method, and nonexistent scan. Differentials that let an attacker distinguish failure classes are oracles — the finding, not a harvest.",
    blackNote: "Minimal probes; stop at the first differential.",
  },
  {
    id: "SL-076", category: "validation", name: "Verbose JSON-RPC errors",
    brief: "-32602 shapes, stack traces, internal method names leaked?",
    owasp: "WSTG-ERRH-01", attackId: "T1592.002",
    what: "Harvest error responses across malformed calls: -32602 shapes, stack traces, internal method names, file paths. Verbose errors are the finding.",
  },
  {
    id: "SL-077", category: "validation", name: "Timing oracle: valid vs invalid key",
    brief: "Measurable timing gap between key verdicts?",
    owasp: "WSTG-ATHN", attackId: "T1087",
    what: "Compare response timing for valid-shaped vs invalid keys over a handful of samples. A consistent gap is a timing oracle — the finding. Handful of probes, never a measurement campaign.",
    blackNote: "Minimal probes; stop at the first consistent differential.",
  },
  // ============================================ CROSS-CUTTING
  {
    id: "SL-078", category: "logic", name: "Scan created via MCP usable via web",
    brief: "MCP-created scan's report/share via web session — cross-surface flow sound?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Create a scan via the MCP tool, then access its report and share flows through the web session. Cross-surface object handling must enforce the same authz — any gap between surfaces is the finding.",
  },
  {
    id: "SL-079", category: "functionality", name: "Session reuse across different API keys",
    brief: "Session from key A used with key B — session/key binding?",
    owasp: "WSTG-SESS", attackId: "T1190",
    what: "Establish a session with one test key, then call tools with a different test key on the same session. Sessions must be key-bound — cross-key session reuse is the finding.",
    needs: "Second test API key owned by the operator.",
  },
  {
    id: "SL-080", category: "validation", name: "Stale session with new key",
    brief: "Expired session + fresh key — clean re-handshake or confusion?",
    owasp: "WSTG-SESS", attackId: "T1190",
    what: "Let a session go stale, then present a fresh key on it. Observe whether the server demands a clean re-handshake or merges state confusingly.",
  },
];
