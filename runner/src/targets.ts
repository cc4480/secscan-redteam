/**
 * Target profiles + target-specific attack batteries — the culmination.
 *
 * Generic batteries test "a webapp". These batteries test THESE targets:
 * SecScan (the scanner webapp) and SecLayer (the MCP/API layer), against
 * their REAL surfaces — the DNS ownership gate, the scan lifecycle, the
 * share-link flow, the JSON-RPC message flow — as observed across our own
 * engagements (v0.3.x secscan.us runs: 8 killed hypotheses, 1 low finding).
 *
 * Target-specific beats generic because the same flaw class lands
 * differently on each surface: IDOR on a scan report is not IDOR on a
 * shopping cart. Every item names the actual endpoint, flow, or parameter.
 *
 * FULL_BATTERY unified engagement: one operation, both targets, one report —
 *   1. recon BOTH surfaces (webapp + MCP API)
 *   2. exploit SecScan battery (SS-*)
 *   3. exploit SecLayer battery (SL-*)
 *   4. cross-cutting chains (MCP → webapp paths)
 *   5. unified report
 * Coverage counts complete only at 3 categories × 2 targets (6 cells).
 *
 * Non-destructive always: never trigger emails to real users, never delete
 * scans/reports, benign canary content only, races are single paired
 * requests. Items that need prerequisites say so in `needs` — honestly,
 * never pretending a test ran when its setup was missing.
 */

import type { BatteryCategory } from "./battery.js";
import { BATTERY_CATEGORIES, CATEGORY_LABELS } from "./battery.js";

export type TargetId = "secscan" | "seclayer";
export const FULL_BATTERY_TARGETS: TargetId[] = ["secscan", "seclayer"];

export interface TargetBatteryItem {
  /** SS-L-1… / SL-F-3… — unique per target. */
  id: string;
  category: BatteryCategory;
  name: string;
  owasp: string;
  /** ATT&CK technique ID where one honestly fits; otherwise undefined. */
  attackId?: string;
  /** What to test — concrete, target-specific: the actual endpoint/flow/param. */
  what: string;
  /** Stealth-weighted variant for black-team mode. */
  blackNote?: string;
  /** Prerequisites, stated honestly (e.g. "second test account", "OAST/canary infra"). */
  needs?: string;
  /** Why this item is deferred rather than tested (set instead of pretending). */
  deferredReason?: string;
}

export type TargetKind = "webapp" | "mcp-api";

export interface TargetProfile {
  id: TargetId;
  name: string;
  baseUrl: string;
  kind: TargetKind;
  /** How the target authenticates callers — the trust boundary under test. */
  authModel: string;
  scopeNotes: string;
  battery: TargetBatteryItem[];
}

const SECSCAN_BATTERY: TargetBatteryItem[] = [
  // ------------------------------------------------------------------ LOGIC
  {
    id: "SS-L-1", category: "logic", name: "DNS ownership-gate bypass attempts",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Attack the `_secscan-challenge.<domain>` TXT gate: wrong TXT value, TXT placed on the parent domain instead of the host, `_secscan-challenge` hostname case/encoding tricks, and subdomain confusion (a challenge proven for sub.secscan.us replayed against secscan.us). The gate is server-authoritative — every attempt must fail closed.",
    blackNote: "Single probe per trick; a gate that holds is a finding for the report, not a wall to hammer.",
  },
  {
    id: "SS-L-2", category: "logic", name: "Report / share IDOR across accounts",
    owasp: "OWASP API1:2023", attackId: "T1190",
    what: "With account A's session, request account B's report and share-link URLs directly. This is authorization-boundary testing between two owned test accounts — NOT UUID guessing (infeasible, and not attempted). Two observations before a verdict: the anomalous response AND a control showing the boundary holds elsewhere.",
    needs: "Second test account owned by the operator.",
  },
  {
    id: "SS-L-3", category: "logic", name: "Share-link expiry enforcement",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Create a share link (30-day default), then test the boundary: expired-link access, tampered token, token replay after expiry change, and whether the report stays reachable through any alternate route once the link is dead.",
  },
  {
    id: "SS-L-4", category: "logic", name: "AI opt-out redaction verification",
    owasp: "WSTG-ATHZ / privacy control", attackId: "T1190",
    what: "Enable AI opt-out on a test scan, then verify the report output is actually redacted: no evidence snippets, URLs, or headers leaking into AI-visible fields. Opt-out that doesn't redact is the finding.",
  },
  {
    id: "SS-L-5", category: "logic", name: "Intake / share rate-limit bypass",
    owasp: "OWASP API4:2023", attackId: "T1499",
    what: "Probe the namespaced intake and share rate limits for bypasses: X-Forwarded-For / X-Real-IP rotation, case tricks on limit keys, parameter pollution on the intake URL. Observe 429 behavior and whether the limit is per-account, per-IP, or per-namespace.",
    blackNote: "Handful of probes only — this maps the limiter's shape, it does not stress it.",
  },
  {
    id: "SS-L-6", category: "logic", name: "SSRF-guard probing through scan intake",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Submit intake URLs designed to test the per-hop redirect revalidation: redirect chains (http→https→http), redirect to private ranges via open-redirector hops, DNS-rebinding-shaped hostnames. Benign canary targets ONLY — domains under operator control that log hits and serve inert content. Never internal/metadata addresses.",
    needs: "Canary/OAST-style infrastructure under operator control.",
    blackNote: "One chain per shape; a guard that revalidates every hop is a strong-defense finding.",
  },
  {
    id: "SS-L-7", category: "logic", name: "Mass assignment on scan options",
    owasp: "OWASP API3:2023", attackId: "T1190",
    what: "Add unexpected fields to the scan-intake JSON: role, isAdmin, userId, price/credits, aggressive-tier flags. Observe whether they bind, validate, or are ignored — especially anything that could escalate the scan tier without authorization.",
  },
  {
    id: "SS-L-8", category: "logic", name: "Scan-lifecycle state abuse",
    owasp: "WSTG-BUSL-06 / WSTG-BUSL-04", attackId: "T1190",
    what: "Drive the queued→running→complete lifecycle through invalid transitions: request the report for a still-queued scan, re-submit an identical intake mid-run, fire a SINGLE paired request on scan creation and compare credit deduction (one pair, one observation — never a double-spend flood).",
  },
  // ----------------------------------------------------------- FUNCTIONALITY
  {
    id: "SS-F-1", category: "functionality", name: "Hidden / undocumented intake parameters",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Probe the intake and report endpoints for debug/test/legacy parameters (debug, preview, admin, aggressive, callback, _method). Prefer parameters hinted at in client bundles over blind guessing — one probe per family.",
    blackNote: "Prefer parameters already hinted at in client code over blind guessing.",
  },
  {
    id: "SS-F-2", category: "functionality", name: "HTTP method tampering on API endpoints",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Replay read endpoints (scan status, report fetch, scan list) as POST/PUT/DELETE/PATCH; try X-HTTP-Method-Override. Note which methods the app honors vs rejects — a GET-only endpoint that executes on POST is the finding.",
  },
  {
    id: "SS-F-3", category: "functionality", name: "Content-type confusion on intake",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit the same scan-intake payload as JSON, form-encoded, and plain text. Observe whether parsing, validation, and the SSRF guard behave identically across content types.",
  },
  {
    id: "SS-F-4", category: "functionality", name: "Negative / zero scan parameters",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Submit negative/zero/absurd values where the API takes numbers: wait_seconds, limit, page/offset, share-expiry days. Observe whether the app validates, clamps, or computes on them.",
  },
  {
    id: "SS-F-5", category: "functionality", name: "Enumeration oracles",
    owasp: "WSTG-ATHN", attackId: "T1087",
    what: "Look for existence oracles via response differentials on own-account objects only: scan-ID polling (valid vs invalid UUID → timing/message differential), error-message differences between 'no such scan' and 'not your scan'. Low rate, handful of probes — the oracle's existence is the finding, not a harvest.",
    blackNote: "Minimal probes; stop at the first differential.",
  },
  {
    id: "SS-F-6", category: "functionality", name: "Share-link token handling",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Tamper with share tokens: truncated, extended, re-encoded, and cross-link token swaps between two own-account shares. Observe whether validation is strict or prefix-tolerant.",
  },
  {
    id: "SS-F-7", category: "functionality", name: "Pagination / filter / sort abuse on scan lists",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Negative/zero offsets, huge limits, sort on non-indexed fields against the scan-listing endpoint. Observe data leaks (other users' scans would be critical — stop and report instantly) and error differentials.",
  },
  {
    id: "SS-F-8", category: "functionality", name: "Report export / format abuse",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Probe report-format parameters (format=json|pdf|html, download flags) for path traversal in export names, content-type mismatches, and reflected content in generated exports. Benign canary content only.",
  },
  // ------------------------------------------------------------- VALIDATION
  {
    id: "SS-V-1", category: "validation", name: "Intake URL field validation",
    owasp: "WSTG-INPV-01", attackId: "T1190",
    what: "Type-juggle the intake `url` field: arrays where a string is expected, objects, booleans, numbers. Observe coercion, errors, and whether a non-string ever reaches the SSRF guard.",
  },
  {
    id: "SS-V-2", category: "validation", name: "Boundary values on IDs and inputs",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Max-length URLs, malformed UUID shapes for scan_id/report_id, empty-string vs missing-field vs null on required intake fields. One boundary family per field class.",
  },
  {
    id: "SS-V-3", category: "validation", name: "Encoding tricks on the target URL",
    owasp: "WSTG-INPV", attackId: "T1027",
    what: "Double encoding, userinfo tricks (https://legit@evil), case tricks on scheme/host, unicode domains against the intake validator AND the SSRF guard separately — divergent handling between the two is the finding. Canary hosts only.",
  },
  {
    id: "SS-V-4", category: "validation", name: "Client-side-only validation",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit directly what the UI forbids on the scan form (disabled aggressive-tier toggle, JS URL checks, maxlength attributes). The question is always: does the server re-validate?",
  },
  {
    id: "SS-V-5", category: "validation", name: "Error-message oracles",
    owasp: "WSTG-ERRH-01", attackId: "T1592.002",
    what: "Harvest verbose errors from intake and report endpoints: stack traces, SSRF-guard messages that reveal internal resolution, schema hints, and 'bad input' vs 'no such object' differentials.",
  },
  {
    id: "SS-V-6", category: "validation", name: "Inconsistent validation between intake paths",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit the same hostile URL through every intake path that accepts one (web form, API, MCP tool). Divergent handling — one path's guard catching what another's misses — is the finding.",
  },
  {
    id: "SS-V-7", category: "validation", name: "Truncation on URL / identifier fields",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Overlong URLs and identifiers where storage may truncate: test whether a truncated value collides with another record or bypasses a uniqueness/ownership check. Benign canary values only.",
  },
  {
    id: "SS-V-8", category: "validation", name: "Regex bypasses on domain / URL validators",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Newline injection, unanchored-pattern abuse, and case tricks against the intake domain/URL validators. Single probes — never ReDoS floods.",
  },
];

const SECLAYER_BATTERY: TargetBatteryItem[] = [
  // ------------------------------------------------------------------ LOGIC
  {
    id: "SL-L-1", category: "logic", name: "Unauthenticated / bad-key tool calls",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Call seclayer_scan, seclayer_list_scans, and seclayer_get_report with no key, a malformed key, a truncated key, and a revoked-shape key. Every tool must fail closed identically — any tool that behaves differently unauthenticated is the finding.",
  },
  {
    id: "SL-L-2", category: "logic", name: "Cross-account list_scans / get_report IDOR",
    owasp: "OWASP API1:2023", attackId: "T1190",
    what: "With account A's API key, call list_scans and get_report for account B's scan IDs. Authorization-boundary testing between two owned test accounts — not ID guessing. A scan from B visible to A is a critical finding; stop and report instantly.",
    needs: "Second test account with its own API key, owned by the operator.",
  },
  {
    id: "SL-L-3", category: "logic", name: "JSON-RPC session handling",
    owasp: "WSTG-SESS", attackId: "T1190",
    what: "Test the Streamable-HTTP session lifecycle: session reuse across tool calls, session fixation (can a caller force a session id?), stale-session behavior, and whether notifications vs requests are handled distinctly per MCP 2025-03-26.",
  },
  {
    id: "SL-L-4", category: "logic", name: "SSRF via the scan-target parameter",
    owasp: "WSTG-BUSL / SSRF", attackId: "T1190",
    what: "Pass SSRF-shaped targets through the seclayer_scan target parameter: redirect chains, private-range-shaped hosts via redirector hops. Benign canary targets ONLY — operator-controlled domains that log hits. Never internal/metadata addresses.",
    needs: "Canary/OAST-style infrastructure under operator control.",
  },
  {
    id: "SL-L-5", category: "logic", name: "Rate limits on the MCP endpoint",
    owasp: "OWASP API4:2023", attackId: "T1499",
    what: "Map the endpoint's rate limiting: burst of tool calls, observe 429 shape, key-rotation bypass attempts (X-Forwarded-For tricks). Handful of probes — this maps the limiter, it does not stress it.",
    blackNote: "Minimal probes; the limiter's existence and shape are the observation.",
  },
  {
    id: "SL-L-6", category: "logic", name: "Scan-credit / quota logic",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Verify credit accounting: does one seclayer_scan deduct exactly one credit? Fire a SINGLE paired request and compare deduction (one pair, one observation). Never engineer a real double-spend.",
  },
  // ----------------------------------------------------------- FUNCTIONALITY
  {
    id: "SL-F-1", category: "functionality", name: "JSON-RPC method tampering",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send unknown methods, wrong-case method names (Tools/List vs tools/list), and method/params shape mismatches to the MCP endpoint. Observe whether the server dispatches strictly or falls through to a default handler.",
  },
  {
    id: "SL-F-2", category: "functionality", name: "GET vs POST on the MCP endpoint",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Streamable HTTP expects POST; try GET (with and without query-encoded JSON-RPC), PUT, and DELETE on /api/mcp. A GET that executes a tool call is the finding.",
  },
  {
    id: "SL-F-3", category: "functionality", name: "Content-type confusion",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send the same JSON-RPC payload as application/json, form-encoded, and text/plain. Observe whether parsing, validation, and auth behave identically — the known WAF quirk (urllib 403 vs curl UA) makes this especially worth mapping.",
  },
  {
    id: "SL-F-4", category: "functionality", name: "Message ordering / notification abuse",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Send responses before requests, duplicate JSON-RPC ids, notifications that expect responses, and out-of-order initialize→tools/call sequences. Observe whether the server enforces the MCP message lifecycle.",
  },
  {
    id: "SL-F-5", category: "functionality", name: "Batch request abuse",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send JSON-RPC batches mixing valid and invalid calls, oversized batches, and nested batches. Observe partial-failure handling and whether one bad call poisons the batch.",
  },
  {
    id: "SL-F-6", category: "functionality", name: "Tool parameter abuse",
    owasp: "OWASP API3:2023", attackId: "T1190",
    what: "Call tools with extra unknown parameters, missing required parameters, and wrong-typed parameters (array for scan target URL, object for scan_id). Observe strictness — and whether extra params ever bind server-side.",
  },
  // ------------------------------------------------------------- VALIDATION
  {
    id: "SL-V-1", category: "validation", name: "API-key validation rigor",
    owasp: "OWASP API2:2023", attackId: "T1190",
    what: "Malformed keys, key in the wrong place (query param vs Authorization header vs body), case tricks on the scheme (bearer vs Bearer), and whitespace-padded keys. The question: is there exactly one accepted shape?",
  },
  {
    id: "SL-V-2", category: "validation", name: "scan_id parameter validation",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Pass malformed UUIDs, overlong strings, and benign injection-shaped strings as scan_id to seclayer_get_report / get_scan_status. Observe validation vs verbose errors — injection-shaped input is observation-only, never destructive.",
  },
  {
    id: "SL-V-3", category: "validation", name: "Target-URL validation parity (MCP vs web)",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit the same hostile target URL through the MCP tool and the web intake. Divergent handling — the API path accepting what the web guard rejects, or vice versa — is the finding. This is the cross-surface consistency check.",
  },
  {
    id: "SL-V-4", category: "validation", name: "Error-message oracles",
    owasp: "WSTG-ERRH-01", attackId: "T1592.002",
    what: "Harvest verbose JSON-RPC error responses: -32602 shapes, stack traces, internal method names, and 'bad key' vs 'bad method' vs 'no such scan' differentials.",
  },
  {
    id: "SL-V-5", category: "validation", name: "Encoding tricks in tool parameters",
    owasp: "WSTG-INPV", attackId: "T1027",
    what: "Double encoding, unicode normalization, and overlong UTF-8 in tool params (target URLs, scan IDs). Observe whether validation happens pre- or post-normalization.",
  },
  {
    id: "SL-V-6", category: "validation", name: "WAF-behavior mapping",
    owasp: "WSTG-INPV", attackId: "T1592.002",
    what: "Map the WAF's footprint deliberately and passively: which payload shapes and user agents trigger the 403 (the known urllib-vs-curl UA differential is the starting point), and what the block page reveals. This is defense mapping, not evasion — findings about the WAF go in the report's detection-gaps section.",
    blackNote: "Passive mapping only. Never iterate to evade; a WAF that fires is data.",
  },
];

export const TARGET_PROFILES: Record<TargetId, TargetProfile> = {
  secscan: {
    id: "secscan",
    name: "SecScan — scanner web app",
    baseUrl: "https://secscan.us",
    kind: "webapp",
    authModel: "DNS TXT ownership gate (_secscan-challenge.<domain>, server-authoritative) + session auth for reports/shares; scan intake rate-limited per namespace.",
    scopeNotes: "In-scope: secscan.us webapp surface (intake, scan lifecycle, reports, share links). Out-of-scope: anything not on the scoped host; no emails to real users; no scan/report deletion.",
    battery: SECSCAN_BATTERY,
  },
  seclayer: {
    id: "seclayer",
    name: "SecLayer — MCP/API layer",
    baseUrl: "https://secscan.us/api/mcp",
    kind: "mcp-api",
    authModel: "API-key auth per account; Streamable HTTP, MCP 2025-03-26, server secscan v1.1.0. Tools: seclayer_scan, seclayer_list_scans, seclayer_get_report.",
    scopeNotes: "In-scope: /api/mcp JSON-RPC surface. Same host as the webapp — path-scoped, not host-scoped. WAF quirk: Python urllib gets 403; curl with a normal UA works.",
    battery: SECLAYER_BATTERY,
  },
};

export function lookupTargetProfile(id: string): TargetProfile | undefined {
  const key = id.toLowerCase() as TargetId;
  return key === "secscan" || key === "seclayer" ? TARGET_PROFILES[key] : undefined;
}

export function targetItemsFor(profile: TargetProfile, category: BatteryCategory): TargetBatteryItem[] {
  return profile.battery.filter((b) => b.category === category);
}

/** Infer which target a probe URL belongs to: the MCP path is SecLayer, everything else is the webapp. */
export function inferTargetProfile(url: string): TargetId {
  try {
    const path = new URL(url).pathname.toLowerCase();
    if (path.startsWith("/api/mcp")) return "seclayer";
  } catch {
    /* unparseable — default to the webapp */
  }
  return "secscan";
}

/** Compact checklist text for one target's battery, for prompt injection. */
export function targetBatteryChecklistText(profile: TargetProfile, mode: "red" | "black"): string {
  const lines: string[] = [`## ${profile.name} (${profile.baseUrl}) — ${profile.battery.length} items`, `Auth model: ${profile.authModel}`];
  for (const cat of BATTERY_CATEGORIES) {
    lines.push(`### ${CATEGORY_LABELS[cat]}`);
    for (const item of targetItemsFor(profile, cat)) {
      const stealth = mode === "black" && item.blackNote ? ` [black: ${item.blackNote}]` : "";
      const needs = item.needs ? ` [needs: ${item.needs}]` : "";
      const deferred = item.deferredReason ? ` [DEFERRED: ${item.deferredReason}]` : "";
      lines.push(`- ${item.id} ${item.name} (${item.owasp}${item.attackId ? `, ${item.attackId}` : ""}): ${item.what}${stealth}${needs}${deferred}`);
    }
  }
  return lines.join("\n");
}

/** Both batteries, for the full-battery plan skeleton. */
export function fullBatteryChecklistText(mode: "red" | "black"): string {
  return FULL_BATTERY_TARGETS.map((t) => targetBatteryChecklistText(TARGET_PROFILES[t], mode)).join("\n\n");
}

/**
 * The unified engagement plan skeleton — one operation, both targets, one report.
 * The coordinator expands this into the operation plan; the runner enforces
 * the coverage rule (3 categories × 2 targets) mechanically.
 */
export function fullBatteryPlanSkeleton(): string {
  return `## FULL-BATTERY unified engagement — SecScan + SecLayer, ONE operation
Phase order (do not reorder):
1. RECON both surfaces — webapp (https://secscan.us) AND MCP API (https://secscan.us/api/mcp): entry points, auth models, fingerprints, WAF signals.
2. EXPLOIT SecScan battery (SS-L / SS-F / SS-V) — the scanner webapp.
3. EXPLOIT SecLayer battery (SL-L / SL-F / SL-V) — the MCP/API layer.
4. CROSS-CUTTING CHAINS — MCP → webapp paths: does an API-layer primitive become a webapp impact (or vice versa)? State each chain as one line.
5. UNIFIED REPORT — one Megazord narrative, both batteries, honest limits per target.
Coverage rule (runner-enforced): the battery counts complete only when ALL THREE categories are probed on BOTH targets (3 × 2 = 6 cells). Tag every http_probe with targetProfile ("secscan" | "seclayer") — the runner also infers it from the URL path (/api/mcp → seclayer).`;
}
