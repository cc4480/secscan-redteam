/**
 * SECLAYER battery — part 2 of 3 (v0.19.0 refactor split).
 * Starts at section: SECLAYER_LIST_SCANS
 *
 * Pure data split of seclayer.ts: every item is byte-identical to the original,
 * same order, same fields. Assembled by seclayer.ts.
 */

import type { TargetBatteryItem } from "./types.js";

export const SECLAYER_PART_2: TargetBatteryItem[] = [
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
];
