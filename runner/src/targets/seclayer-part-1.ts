/**
 * SECLAYER battery — part 1 of 3 (v0.19.0 refactor split).
 * Starts at section: INITIALIZE / HANDSHAKE
 *
 * Pure data split of seclayer.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by seclayer.ts.
 */

import type { TargetBatteryItem } from "./types.js";

export const SECLAYER_PART_1: TargetBatteryItem[] = [
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
];
