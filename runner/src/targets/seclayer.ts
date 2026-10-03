/**
 * SecLayer target profile — the MCP/API layer (https://secscan.us/api/mcp).
 *
 * EXHAUSTIVE battery (v0.7.0): surface × technique. Surfaces: MCP
 * initialize/handshake, capability negotiation, tools/list, tools/call for
 * EACH tool (seclayer_scan, seclayer_list_scans, seclayer_get_report) with
 * every parameter attacked individually, notifications, ping,
 * cancellation, progress, batching, the JSON-RPC layer itself, the auth
 * layer per method, and WAF behavior.
 *
 * Non-destructive always: benign canary targets only, no real bypass
 * campaigns, no emails to real users. Items needing setup say so in
 * `needs` — honestly.
 */

import type { TargetBatteryItem, TargetProfile } from "./types.js";

const SECLAYER_BATTERY: TargetBatteryItem[] = [
  // ============================================ INITIALIZE / HANDSHAKE
  {
    id: "SL-001", category: "logic", name: "tools/call before initialize",
    brief: "Tool call with no handshake — lifecycle enforced or accepted?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Send tools/call for seclayer_scan with valid auth but no prior initialize. The server must enforce the MCP message lifecycle — a call honored pre-handshake is the finding.",
  },
  {
    id: "SL-002", category: "validation", name: "protocolVersion tampering",
    brief: "Wrong, ancient, or future protocol versions — negotiated or rejected?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send initialize with wrong, ancient, and future protocolVersion values. Observe negotiation strictness — a server that silently accepts a mismatched version is the finding.",
  },
  {
    id: "SL-003", category: "validation", name: "clientInfo spoofing",
    brief: "Absurd or hostile clientInfo — validated, logged, or trusted?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send initialize with missing, absurd, and hostile-shaped clientInfo (overlong strings, injection-shaped names). Observe validation — and whether clientInfo is ever reflected or trusted downstream. Observation only.",
  },
  {
    id: "SL-004", category: "functionality", name: "Capability negotiation abuse",
    brief: "Claiming unsupported capabilities — granted or ignored?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Advertise capabilities the client doesn't have (roots, sampling, experimental flags) during initialize. Observe whether the server grants, ignores, or errors — granted-but-unenforced capabilities are the finding.",
  },
  {
    id: "SL-005", category: "logic", name: "Session fixation on initialize",
    brief: "Caller-supplied session ID surviving initialize — fixation?",
    owasp: "WSTG-SESS-03", attackId: "T1190",
    what: "Attempt to force a session identifier during initialize (header or param) and check whether the server adopts it. Server-adopted client-chosen session IDs are the finding.",
  },
  {
    id: "SL-006", category: "validation", name: "Duplicate initialize on one session",
    brief: "Second initialize on a live session — clean handling or state confusion?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Send initialize twice on the same session with different parameters. Observe whether the second is rejected, replaces state cleanly, or creates confusion the attacker can leverage.",
  },
  {
    id: "SL-007", category: "logic", name: "Initialized-notification skipped",
    brief: "Never send notifications/initialized — does the session still work?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Complete initialize but skip the notifications/initialized handshake step, then call tools. If the session works without the mandatory notification, lifecycle enforcement is the finding.",
  },
  // ============================================ TOOLS/LIST
  {
    id: "SL-008", category: "functionality", name: "tools/list without auth",
    brief: "Tool enumeration unauthenticated — capabilities leaked?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Call tools/list with no API key. The tool catalog (names, schemas) is intelligence — an unauthenticated server that enumerates its full attack surface is the finding.",
  },
  {
    id: "SL-009", category: "functionality", name: "tools/list with bad key",
    brief: "Malformed key on tools/list — identical failure to no key?",
    owasp: "OWASP API2:2023", attackId: "T1592.002",
    what: "Call tools/list with malformed, truncated, and wrong keys and compare against the no-key response. Any differential between 'no key' and 'bad key' is an oracle — the finding.",
  },
  {
    id: "SL-010", category: "validation", name: "tools/list cursor tampering",
    brief: "Pagination cursor on tools/list — validated or trusted?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Tamper with the tools/list pagination cursor: garbage, oversized, and cursor values from other contexts. Observe validation — a trusted cursor is a primitive.",
  },
  {
    id: "SL-011", category: "functionality", name: "tools/list method case tricks",
    brief: "Tools/List, TOOLS/LIST — strict method dispatch?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Call tools/list with wrong-case method names. Strict dispatch rejects — case-insensitive dispatch that still executes is the finding.",
  },
  {
    id: "SL-012", category: "functionality", name: "tools/list schema harvesting",
    brief: "Tool input schemas — do they leak internal parameter names?",
    owasp: "WSTG-INFO", attackId: "T1592.002",
    what: "Passively record the full tools/list response: parameter names, descriptions, and any internal-sounding fields. Overly revealing schemas are intelligence findings — observation only.",
  },
  // ============================================ SECLAYER_SCAN params
  {
    id: "SL-013", category: "logic", name: "seclayer_scan with no key",
    brief: "Scan tool unauthenticated — fail closed?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Call seclayer_scan with no API key. The scan tool is the highest-value target — anything but a clean auth failure is a critical finding.",
  },
  {
    id: "SL-014", category: "logic", name: "seclayer_scan with malformed/truncated key",
    brief: "Truncated or malformed key — prefix-tolerant auth?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Call seclayer_scan with truncated, extended, and character-swapped keys. Prefix-tolerant or fuzzy key matching is the finding — auth must be exact.",
  },
  {
    id: "SL-015", category: "logic", name: "seclayer_scan key in wrong place",
    brief: "Key in query/body instead of header — exactly one accepted shape?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Send the API key in the query string, request body, and cookies instead of the Authorization header. There must be exactly one accepted shape — alternates are the finding (query-string keys end up in logs).",
  },
  {
    id: "SL-016", category: "validation", name: "scan target: type juggling",
    brief: "target as array/object/number — coerced or rejected?",
    owasp: "WSTG-INPV-01", attackId: "T1190",
    what: "Pass the scan target as an array, object, boolean, and number. Observe coercion — a non-string target that reaches the SSRF guard is the finding.",
  },
  {
    id: "SL-017", category: "validation", name: "scan target: scheme tricks",
    brief: "gopher/file/dict/javascript schemes via the tool — same allowlist as web?",
    owasp: "WSTG-INPV-01", attackId: "T1190",
    what: "Pass dangerous schemes through the seclayer_scan target parameter. The tool path must enforce the same scheme allowlist as web intake — divergence is the finding.",
  },
  {
    id: "SL-018", category: "validation", name: "scan target: userinfo/encoding/unicode",
    brief: "Every URL trick from the web battery, replayed through the MCP tool.",
    owasp: "WSTG-INPV-01", attackId: "T1027",
    what: "Replay the web-battery URL tricks (userinfo, double encoding, unicode, case, CRLF) through the seclayer_scan target parameter. The tool path is a second validator — any trick it accepts that web rejects (or vice versa) is the finding. Canary hosts only.",
  },
  {
    id: "SL-019", category: "logic", name: "SSRF via scan-target redirect chains",
    brief: "Canary redirect chains through the tool — per-hop guard on the API path?",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Pass canary redirect-chain URLs as the scan target and verify the per-hop SSRF revalidation fires on the MCP path exactly as on web. A weaker guard on the API path is the finding. Canary targets only.",
    needs: "Canary redirector infrastructure under operator control.",
  },
  {
    id: "SL-020", category: "logic", name: "MCP vs web target-validation parity",
    brief: "Same hostile URL through tool and web intake — identical verdicts?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit the same hostile-shaped canary URL through seclayer_scan and through web intake. Divergent handling — the API path accepting what the web guard rejects — is the cross-surface consistency finding.",
  },
  {
    id: "SL-021", category: "functionality", name: "seclayer_scan extra parameters",
    brief: "Unknown params in the tool call — bound server-side or ignored?",
    owasp: "OWASP API3:2023", attackId: "T1190",
    what: "Call seclayer_scan with extra unknown parameters (tier, credits, role, debug, admin). Observe whether extras bind server-side — mass assignment through the tool interface is the finding.",
  },
  {
    id: "SL-022", category: "validation", name: "seclayer_scan missing required params",
    brief: "Omitted target/options — clean -32602 or verbose error?",
    owasp: "WSTG-INPV", attackId: "T1592.002",
    what: "Omit required parameters one at a time. Expect clean JSON-RPC -32602 invalid-params — verbose errors or partial execution are the finding.",
  },
  {
    id: "SL-023", category: "validation", name: "seclayer_scan overlong target",
    brief: "64k target URL — truncation, rejection, or acceptance?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Pass overlong target URLs. Observe rejection vs silent truncation — a truncated target that collides with another value is the finding. Single requests only.",
  },
  {
    id: "SL-024", category: "logic", name: "seclayer_scan credit deduction exactly once",
    brief: "Single paired tool call — exactly one credit deducted?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Fire a single pair of near-simultaneous seclayer_scan calls and compare credit deduction. One pair, one observation — never engineered into a real double-spend. Operator-owned credits only.",
    blackNote: "Only against own test account with operator-owned credits.",
  },
  {
    id: "SL-025", category: "functionality", name: "seclayer_scan aggressive option via tool",
    brief: "Aggressive-tier flag through the tool — server-side tier enforcement?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Pass aggressive-tier options through the seclayer_scan tool call from a non-aggressive account. Tier must be enforced server-side — a granted aggressive scan is the finding.",
  },
  {
    id: "SL-026", category: "validation", name: "seclayer_scan options object abuse",
    brief: "Deeply nested / wrong-typed options — validated or trusted?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Pass deeply nested, wrong-typed, and oversized options objects. Observe validation — moderately nested only, never a billion-laughs shape. Trust of the options object is the finding.",
  },
  {
    id: "SL-027", category: "logic", name: "seclayer_scan duplicate submission mid-run",
    brief: "Same target scanned twice concurrently via tool — deduped or double-charged?",
    owasp: "WSTG-BUSL-04", attackId: "T1190",
    what: "Submit the same canary target twice concurrently through the tool. Observe dedup vs double-run vs double-charge. Own test account only.",
  },
  // ============================================ SECLAYER_LIST_SCANS
  {
    id: "SL-028", category: "logic", name: "seclayer_list_scans with no/bad key",
    brief: "Listing unauthenticated or bad-key — clean failure?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Call seclayer_list_scans with no key and with malformed keys. Clean auth failure expected — any data or differential is the finding.",
  },
  {
    id: "SL-029", category: "logic", name: "list_scans cross-account IDOR",
    brief: "Account B's scans via account A's key — the critical boundary.",
    owasp: "OWASP API1:2023", attackId: "T1190",
    what: "Call seclayer_list_scans with account A's key looking for account B's scans. Any cross-account data is a critical finding — stop and report instantly, never enumerate further.",
    needs: "Second test account with its own API key, owned by the operator.",
  },
  {
    id: "SL-030", category: "functionality", name: "list_scans pagination abuse",
    brief: "limit/offset/cursor tampering — clamped, validated, or trusted?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Abuse list_scans pagination: negative/zero offsets, huge limits, garbage cursors. Observe clamping — and watch for cross-account data in oversized responses (critical: stop instantly).",
  },
  {
    id: "SL-031", category: "validation", name: "list_scans filter/sort injection",
    brief: "Filter operators and sort fields — allowlisted?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Inject filter operators (gt/lt/regex shapes) and sort on nonexistent fields. Observe allowlisting — and whether errors leak query internals.",
  },
  {
    id: "SL-032", category: "functionality", name: "list_scans extra params binding",
    brief: "account_id/user_id smuggled into list_scans — honored?",
    owasp: "OWASP API3:2023", attackId: "T1190",
    what: "Add account_id, user_id, and scope-widening fields to list_scans. Any honored field that changes whose scans are listed is the finding.",
  },
  // ============================================ SECLAYER_GET_REPORT
  {
    id: "SL-033", category: "logic", name: "seclayer_get_report with no/bad key",
    brief: "Report tool unauthenticated — fail closed?",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Call seclayer_get_report with no key and malformed keys. Clean auth failure expected — anything else is the finding.",
  },
  {
    id: "SL-034", category: "logic", name: "get_report cross-account IDOR",
    brief: "Account B's report via account A's key — authorization boundary.",
    owasp: "OWASP API1:2023", attackId: "T1190",
    what: "Call seclayer_get_report with account A's key for account B's scan ID. Authorization-boundary testing between owned accounts — not ID guessing. Cross-account report access is critical: stop and report instantly.",
    needs: "Second test account with its own API key, owned by the operator.",
  },
  {
    id: "SL-035", category: "validation", name: "get_report scan_id validation",
    brief: "Malformed/injection-shaped scan_ids — parameterized?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Pass malformed UUIDs, overlong strings, and benign injection-shaped strings as scan_id. Observation only: parameterized handling vs verbose errors vs reflection.",
  },
  {
    id: "SL-036", category: "validation", name: "get_report scan_id truncation",
    brief: "Overlong scan_id — truncated into collision with another record?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Pass overlong scan_id values and observe whether storage/lookup truncates. A truncated ID that resolves to a different record is the finding. Benign values only.",
  },
  {
    id: "SL-037", category: "functionality", name: "get_report extra params",
    brief: "format/download flags smuggled into get_report — honored?",
    owasp: "OWASP API3:2023", attackId: "T1190",
    what: "Add format, download, raw, and embed parameters to get_report. Undocumented render paths through the tool are new attack surface — test each for the same flaws as the main path.",
  },
  {
    id: "SL-038", category: "logic", name: "get_report for running/failed scan",
    brief: "Report for a non-complete scan via tool — state enforced?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Call get_report for running and failed scans. Observe whether lifecycle state is enforced on the tool path or partial/error internals leak.",
  },
  {
    id: "SL-039", category: "logic", name: "get_report honors AI opt-out redaction",
    brief: "Opted-out scan via the tool — redacted or full content?",
    owasp: "WSTG-ATHZ / privacy", attackId: "T1190",
    what: "Enable AI opt-out on a test scan, then pull it through seclayer_get_report. The tool path must redact exactly what the web view redacts — any gap is the finding.",
  },
  // ============================================ JSON-RPC LAYER
  {
    id: "SL-040", category: "validation", name: "JSON-RPC id tampering",
    brief: "Duplicate, null, huge, and type-juggled ids — matched correctly?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send duplicate ids across calls, null ids, huge numeric ids, and type-juggled ids (string vs number). Observe response matching — mismatched or confused responses are the finding.",
  },
  {
    id: "SL-041", category: "validation", name: "jsonrpc version field tampering",
    brief: "\"1.0\", missing, or wrong version value — strict 2.0?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send jsonrpc: 1.0, a missing version field, and wrong values. Strict 2.0 enforcement expected — lenient parsing is the finding.",
  },
  {
    id: "SL-042", category: "functionality", name: "Unknown JSON-RPC methods",
    brief: "tools/destroy, admin/* — strict dispatch or default handler?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send unknown methods (tools/destroy, admin/purge, system/describe). Observe whether the server dispatches strictly or falls through to a default handler — fall-through is the finding.",
  },
  {
    id: "SL-043", category: "functionality", name: "Notifications expecting responses",
    brief: "Notification shaped like a request — answered or ignored?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Send notifications (no id) that look like requests and requests missing ids. The server must treat notifications as fire-and-forget — answering one is the finding.",
  },
  {
    id: "SL-044", category: "functionality", name: "Responses before requests",
    brief: "Client sends a JSON-RPC response unprompted — accepted?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Send a JSON-RPC response object without any outstanding request. The server must ignore it — processing it is the finding.",
  },
  {
    id: "SL-045", category: "functionality", name: "Out-of-order message sequences",
    brief: "tools/call before initialize completes — lifecycle enforced?",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Interleave messages out of order: call during initialize, second initialize mid-session, notifications after close. Any accepted out-of-order message is the finding.",
  },
  {
    id: "SL-046", category: "functionality", name: "Batch: mixed valid/invalid calls",
    brief: "One bad call in a batch — partial failure handled cleanly?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send JSON-RPC batches mixing valid and invalid calls. Observe partial-failure handling: per-call errors expected — one bad call poisoning the batch, or a bad call executing, is the finding.",
  },
  {
    id: "SL-047", category: "functionality", name: "Batch: oversized and nested batches",
    brief: "100-call batches, batches-in-batches — limits enforced?",
    owasp: "WSTG-INPV", attackId: "T1499",
    what: "Send oversized batches and nested batch arrays. Observe size/depth limits — unbounded batch processing is the finding. Modest sizes only, never a resource-burn attempt.",
    blackNote: "Modest batch sizes; the limit's existence is the observation.",
  },
  {
    id: "SL-048", category: "validation", name: "Malformed JSON bodies",
    brief: "Trailing commas, comments, single quotes — strict parser?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send malformed JSON: trailing commas, comments, single quotes, unquoted keys. Strict parsing expected — a lenient parser that executes is the finding.",
  },
  {
    id: "SL-049", category: "validation", name: "Charset and encoding tricks",
    brief: "UTF-16, BOM, charset mismatches — decoded safely?",
    owasp: "WSTG-INPV", attackId: "T1027",
    what: "Send JSON-RPC bodies as UTF-16, with BOMs, and with mismatched charset declarations. Observe decoding — mojibake that bypasses validation is the finding.",
  },
  {
    id: "SL-050", category: "validation", name: "Duplicate keys in JSON objects",
    brief: "{\"method\":\"a\",\"method\":\"b\"} — first wins, last wins, or rejected?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send objects with duplicate keys (method, params, id). Observe which value wins and whether parser and dispatcher agree — disagreement is the finding.",
  },
  {
    id: "SL-051", category: "validation", name: "Params shape mismatches",
    brief: "Array params vs object params vs positional confusion?",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send params as arrays (positional), objects (named), and mismatched shapes per tool. Observe strictness — positional confusion that binds wrong values is the finding.",
  },
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

export const SECLAYER_PROFILE: TargetProfile = {
  id: "seclayer",
  name: "SecLayer — MCP/API layer",
  baseUrl: "https://secscan.us/api/mcp",
  kind: "mcp-api",
  authModel: "API-key auth per account; Streamable HTTP, MCP 2025-03-26, server secscan v1.1.0. Tools: seclayer_scan, seclayer_list_scans, seclayer_get_report.",
  scopeNotes: "In-scope: /api/mcp JSON-RPC surface. Same host as the webapp — path-scoped, not host-scoped. WAF quirk: Python urllib gets 403; curl with a normal UA works.",
  battery: SECLAYER_BATTERY,
};
