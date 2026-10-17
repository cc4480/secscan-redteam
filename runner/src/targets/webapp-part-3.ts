/**
 * WEBAPP battery - part 3 of 7 (blocks 8-10: injection, SSRF, access control).
 * WA-053..WA-073.
 *
 * Generic client web application battery (opt-in --targets webapp). This is the
 * executable form of the SecScan (VibeScan-Enterprise-Build) and Seclayer
 * (seclayer.io2026) scan corpora: one item per attacker intent against the
 * engagement's own in-scope application.
 *
 * Evidence discipline: a hit is a finding only when the item's confirmation
 * rule is met with a receipt (a literal substring in the matched response, or
 * an OAST callback) - PROVEN. Claims that can only be observational are NEEDS
 * VERIFICATION, never CONFIRMED (SECLAYER_INVENTORY.md section 5).
 *
 * Non-destructive always: no request whose success changes customer data;
 * writes only as dry runs; DELETE only against an identifier that cannot
 * exist; no PUT; no data exfiltration.
 */

import type { TargetBatteryItem } from "./types.js";

export const WEBAPP_PART_3: TargetBatteryItem[] = [
  // Block 8 - injection. Sources: SecScan SECSCAN_INVENTORY.md Module 11 (path traversal) and
  // Module 12 (active injection probing: canary reflected XSS, baseline-diff error-based SQLi);
  // Seclayer SECLAYER_INVENTORY.md 4.9 (probeReflectedXss, probeSqlInjection, probeCommandInjection),
  // 4.10 (paramFuzzer 11 classes: SQLi error/time/boolean, XSS, SSTI, LFI, LDAP, XPath, CRLF),
  // 4.14 (domXss) and 4.15 (stored XSS, SSTI, LFI, CRLF, LDAP/XPath).
  {
    id: "WA-053", category: "validation", name: "Reflected XSS on a discovered parameter",
    brief: "Crawler-discovered parameter echoes our canary unencoded?",
    owasp: "WSTG-INPV-01", attackId: "T1190",
    what: "Baseline request for the discovered query or body parameter, then the same parameter with a unique "
        + "canary using angle-bracket, quote and ampersand metacharacters to find the reflection context, then "
        + "a context-matched non-executing payload (an img onerror that only sets a fixed marker). Confirm ONLY "
        + "when the exact payload appears UNENCODED in the response body and was absent from the baseline body "
        + "for that parameter; a JSON echo, a 404 page, a header echo or an encoded context is NOT proof. "
        + "Non-destructive: marker-only script, no fetch, no cookie access, no write.",
  },
  {
    id: "WA-054", category: "logic", name: "Stored XSS through a discovered form",
    brief: "One form field stores our canary and executes on a reader page?",
    owasp: "WSTG-INPV-02", attackId: "T1190",
    what: "Record the baseline render of a page that displays a crawler-discovered write form (comment, "
        + "review, ticket, profile bio, filename), then submit one uniquely tagged, non-executing stored canary "
        + "into one field. Read it back with the second test account and diff against the baseline: confirm "
        + "ONLY when the reader page returns the tag UNENCODED inside a live HTML execution context (element, "
        + "attribute or script), the tag is absent from all baseline pages, and a benign twin without markup "
        + "does not reproduce it. One canary, one field, a record real users never render - and remove or "
        + "overwrite the test record afterwards.",
    needs: "second test account to view the stored value",
  },
  {
    id: "WA-055", category: "logic", name: "DOM-based XSS through a client-side sink",
    brief: "Hash or query value reaches a DOM sink and executes?",
    owasp: "WSTG-CLNT-01", attackId: "T1190",
    what: "With the browser/CDP render, drive attacker-controlled client sources (location.hash, escaped "
        + "query string, window.name, a postMessage target) into the sinks found in shipped JS (innerHTML, "
        + "outerHTML, document.write, insertAdjacentHTML, eval, new Function, jQuery html). Confirm ONLY with a "
        + "headless execution receipt: the marker exists as a live element or script node in the rendered DOM "
        + "and a marker set only by executing script fires; a string shown as text, in a comment or in an "
        + "unrendered template is NOT proof, and a bundle grep is lead-only. Alert-only payloads: no cookie "
        + "theft, no network callback.",
    needs: "browser/CDP render",
  },
  {
    id: "WA-056", category: "validation", name: "SQL injection: error-based",
    brief: "Trailing quote yields a DB error signature absent from baseline?",
    owasp: "WSTG-INPV-05", attackId: "T1190",
    what: "Baseline request for a discovered parameter, then the same parameter with a single trailing quote, "
        + "a double quote, a closing parenthesis and a numeric-repeat variant such as 1'2, sent in turn. "
        + "Confirm ONLY when the mutated response renders a DB error signature ABSENT from the baseline (SQL "
        + "syntax, ORA-, SQLSTATE, PostgreSQL at or near, unclosed quotation mark, ODBC/SQLite/JPA exception) "
        + "and the signature disappears when the same quote is fully URL-encoded; generic 500s, WAF pages and "
        + "reflected input are NOT proof. Non-destructive: no UNION extraction, no stacked queries, no sleep "
        + "here - error evidence is the whole proof.",
  },
  {
    id: "WA-057", category: "logic", name: "SQL injection: time-based blind",
    brief: "Response time tracks the injected sleep on a second pair?",
    owasp: "WSTG-INPV-05", attackId: "T1190",
    what: "Measure the response-time baseline over 3-5 clean requests, then inject a dialect-matched delay "
        + "(MySQL SLEEP(4), PostgreSQL pg_sleep(4), MSSQL WAITFOR DELAY 0:0:4, Oracle dbms_lock.sleep(4)) plus "
        + "a harmless non-sleeping twin. Confirm ONLY when the delayed request is at least 3 s slower than "
        + "baseline, a second independent delay (different function or value such as 6 s) tracks the requested "
        + "delay, and the non-sleeping twin returns at baseline speed; one slow response is inconclusive "
        + "(cache, load, throttling). Cap each pair at two runs; never chain sleeps, never stack queries.",
  },
  {
    id: "WA-058", category: "logic", name: "SQL injection: boolean-based blind",
    brief: "Two independent TRUE/FALSE pairs move the page consistently?",
    owasp: "WSTG-INPV-05", attackId: "T1190",
    what: "On a parameter with an observable content differential (record count, field text, page length) send "
        + "two independent TRUE/FALSE pairs: AND 1=1 versus AND 1=2, then OR 1=1 versus OR 1=2 (or the string "
        + "pair a'='a versus a'='b). Confirm ONLY when both TRUE responses match the pre-recorded baseline, "
        + "both FALSE responses differ in the same direction, and a semantically neutral twin (AND 2=2 versus "
        + "AND 3=3) leaves the page unchanged; a single differential explained by caching, throttling or "
        + "pagination is NOT proof. Read-only predicates only; no writing subselects.",
  },
  {
    id: "WA-059", category: "logic", name: "OS command injection",
    brief: "Random arithmetic echo lands in the response from a shell sink?",
    owasp: "WSTG-INPV-12", attackId: "T1190",
    what: "On a parameter or discovered endpoint that plausibly shells out (ping, host, resolve, file, "
        + "convert, cmd, exec) send a randomized arithmetic oracle: semicolon then expr R1 + R2, with pipe, "
        + "AND, dollar-paren and backtick separators plus the Windows ampersand and percent variants. Confirm "
        + "ONLY when the computed sum appears in the response body, was absent from the baseline, and a second "
        + "fresh random pair reproduces its own sum; the oracle is a read-only echo of constants, so never "
        + "touch files, never open a reverse connection, never exfiltrate identity or config output - the "
        + "arithmetic echo is the entire proof.",
  },
  {
    id: "WA-060", category: "logic", name: "Server-side template injection",
    brief: "Randomized product appears instead of the literal expression?",
    owasp: "WSTG-INPV-18", attackId: "T1190",
    what: "Inject a randomized arithmetic template oracle into every text parameter and discovered "
        + "template-rendering field: dollar-brace R1*R2, double-brace R1*R2, percent-equals R1*R2, hash-brace "
        + "R1*R2 and one unclosed variant, fresh random integers per request. Confirm ONLY when the computed "
        + "product - not the literal expression - appears in the response, was absent from the baseline, and a "
        + "second independent pair yields its own product; a payload reflected literally is not vulnerable. "
        + "Non-destructive: arithmetic only, no template object traversal, no file reads, no command calls, no "
        + "sandbox escapes.",
  },
  {
    id: "WA-061", category: "validation", name: "Path traversal and local file inclusion",
    brief: "Traversal payload returns an OS file marker absent from baseline?",
    owasp: "WSTG-ATHZ-01", attackId: "T1190",
    what: "Probe file-bearing parameters (file, path, page, template, download, lang, doc) with encoded "
        + "traversal families: ../, ..%2f, %2e%2e%2f, ..%5c, a double-encoded twin and a null-byte-shaped "
        + "variant. Confirm ONLY when the response contains a known OS file marker absent from the baseline - "
        + "a root:x:0:0 line from /etc/passwd or a [fonts] or [extensions] section from win.ini; a longer body, "
        + "a directory listing or a different error alone is NOT proof. One benign read-only path per request; "
        + "stop at the first marker; never read application config, credentials or customer data.",
  },
  {
    id: "WA-062", category: "logic", name: "LDAP or XPath injection",
    brief: "Unbalanced filter yields a parser signature absent from baseline?",
    owasp: "WSTG-INPV-06", attackId: "T1190",
    what: "Locate parameters feeding directory or XML lookups (user, uid, filter, search, login, group) and "
        + "send unbalanced filter syntax (star-paren uid=star, a lone star, paren splices) plus the XPath "
        + "equivalents of an always-true predicate. Confirm ONLY when a mutated request produces a parser "
        + "signature absent from the baseline (LDAP: invalid filter, LDAPException, protocol error; XPath: "
        + "XPathException, unclosed token, invalid expression) or a wildcard query returns strictly more "
        + "records than a literal matching fewer; a generic 500 without a parser signature is NOT proof. "
        + "Read-only queries; no filter that writes or authenticates.",
  },
  {
    id: "WA-063", category: "logic", name: "CRLF and response-header injection",
    brief: "Injected CRLF surfaces our canary as a real response header?",
    owasp: "WSTG-INPV-15", attackId: "T1190",
    what: "On a parameter that lands in a redirect target, Set-Cookie, Content-Disposition or a custom "
        + "response header, inject an encoded CRLF pair (%0d%0a, %0a and the double-encoded twin) followed by "
        + "a unique canary header X-Canary: token. Confirm ONLY when the canary appears as an actual response "
        + "header (not in the body) from exactly one injected CRLF, the identical baseline request without the "
        + "payload does not carry it, and the response is not a generic error page. Never inject a real "
        + "Set-Cookie value, never smuggle a second response, never alter routing: header injection proof "
        + "only.",
  },
  // Block 9 - XXE and SSRF. Sources: Seclayer SECLAYER_INVENTORY.md 4.9 (probeSsrf, probeBlindSsrf) and
  // 4.15 (XXE out-of-band); SecScan SECSCAN_INVENTORY.md Module 18 (out-of-band SSRF collector: unique
  // token planted in url, uri, callback, webhook, redirect, image, feed and proxy parameters).
  {
    id: "WA-064", category: "logic", name: "XML external entity injection",
    brief: "External entity in an XML body triggers our OAST callback?",
    owasp: "WSTG-INPV-07", attackId: "T1190",
    what: "Where XML is accepted (a discovered SOAP or REST XML endpoint, an XML upload, or a JSON endpoint "
        + "that also parses XML on the matching Content-Type), send a well-formed document whose DOCTYPE "
        + "declares an external entity pointing at a unique OAST token URL and references it from a text node. "
        + "Confirm ONLY by the collaborator callback for that exact token (matching path and timestamp); a "
        + "parser error, 400/415/500 or an entity-disabled message is a NEGATIVE result to record as "
        + "tested-negative. Optionally try the local-file entity once against a harmless marker path; OAST host "
        + "only, no internal addresses, no file writes, no credential reads.",
    needs: "OAST collaborator for out-of-band callback confirmation",
  },
  {
    id: "WA-065", category: "validation", name: "SSRF with a response differential",
    brief: "Server fetches our canary, or response tracks a live vs dead URL?",
    owasp: "WSTG-INPV-19", attackId: "T1190",
    what: "Find URL-bearing parameters (url, fetch, image, avatar, webhook, callback, proxy, next) and answer "
        + "one with an operator canary URL whose host logs requests, plus controls: the same canary on another "
        + "port, an unresolvable twin, the plain baseline value. Confirm ONLY when the canary log records the "
        + "exact request (path and timestamp), or the body or status differs systematically between live canary "
        + "and dead twin while two different dead twins behave identically and a client-side fetch does not "
        + "explain it; a generic timeout or a redirect Location is NOT proof. Canary host only - never "
        + "internal, link-local or cloud metadata addresses.",
  },
  {
    id: "WA-066", category: "logic", name: "Blind SSRF confirmed by out-of-band callback",
    brief: "URL parameter fetches our unique token URL from the server side?",
    owasp: "WSTG-INPV-19", attackId: "T1190",
    what: "Where no response differential is observable, plant a unique OAST token URL into every URL-shaped "
        + "parameter and into parameters whose error paths suggest a fetch (import, screenshot, preview, feed, "
        + "subscribe, proxy). Confirm ONLY by an actual HTTP or DNS callback for that token (path and "
        + "timestamp) from the collaborator; no callback within the agreed wait window is tested-negative, not "
        + "a finding. One token per parameter keeps the firing sink identifiable. Never point the parameter at "
        + "RFC1918, link-local, localhost or cloud metadata addresses - the callback from our own canary is "
        + "the whole proof.",
    needs: "OAST collaborator for out-of-band callback confirmation",
  },
  {
    id: "WA-067", category: "logic", name: "SSRF through URL-bearing parameter families",
    brief: "Which URL parameter family actually fires a server-side fetch?",
    owasp: "WSTG-INPV-19", attackId: "T1190",
    what: "Enumerate URL-bearing families from the crawl and parameter mining (url, uri, link, src, dest, "
        + "redirect, return, next, image, avatar, feed, webhook, callback, import, proxy, host, origin) and "
        + "send each the same canary URL tagged with the parameter name in its path. Confirm ONLY when a "
        + "callback arrives carrying that parameter's tag (identifying the sink that fired), or fetched canary "
        + "content appears where a server-side fetch result would render; record per-parameter results so an "
        + "unreachable canary is stated as inconclusive, never a pass. One request per parameter; operator "
        + "canary only; no internal ranges or metadata addresses.",
  },
  // Block 10 - access control. Sources: SecScan SECSCAN_INVENTORY.md Module 16 (API surface: data with
  // no session, write verb returning 404 not 401, mass-assignment privilege fields) and Module 17 (broken
  // access control with two accounts, identifier mutation, record served with no session); Seclayer
  // SECLAYER_INVENTORY.md 4.12 (bola.ts) and 4.16 (language route auth bypass).
  {
    id: "WA-068", category: "validation", name: "IDOR by identifier mutation",
    brief: "Mutating a loaded object id returns another object intact?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Take an identifier the current session legitimately loads (order, invoice, report, user, file) and "
        + "send a bounded mutation set: numeric plus and minus one, the adjacent value from a returned list, a "
        + "UUID swap from another operator-owned object, and the same id moved into a sibling parameter. "
        + "Confirm ONLY when the mutated request returns a complete object whose unique field belongs to the "
        + "other owned object (200 with the foreign marker); a 401/403/404, an empty body or a generic error is "
        + "object-level authorization working. Bounded mutations only, never enumeration; read-only GETs.",
  },
  {
    id: "WA-069", category: "logic", name: "Cross-account object access with two identities",
    brief: "Account B's session reads account A's object with a unique marker?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "With two operator-owned accounts (A and B) collect object ids while authenticated as A, then "
        + "replay A's reads with B's session cookie or bearer token, and the reverse direction. Confirm ONLY "
        + "when B's session receives A's object with an A-unique marker field, the same request as B against "
        + "B's own object behaves normally, and an anonymous repeat does not explain it; both directions are "
        + "attempted, and ambiguous branches stay NEEDS VERIFICATION, never CONFIRMED. Read-only GETs: never "
        + "mutate or delete the other account's object, never touch real customer data.",
    needs: "second test account",
  },
  {
    id: "WA-070", category: "validation", name: "Unauthenticated access to protected objects",
    brief: "No session at all still returns the signed-in account's record?",
    owasp: "WSTG-ATHZ-02", attackId: "T1190",
    what: "From a context with no session at all (a fresh http_probe with no cookies and no Authorization "
        + "header) replay a sample of object and list endpoints discovered by the crawl and API-surface "
        + "recovery, one request each. Confirm ONLY when the anonymous response returns the same protected "
        + "payload an authenticated baseline received (a record field unique to the signed-in account) with 200 "
        + "and a complete body; a login page, an empty array or a placeholder is authentication working. "
        + "Read-only: no anonymous writes, no DELETE, no PUT; light pacing, one attempt per endpoint.",
  },
  {
    id: "WA-071", category: "logic", name: "Write verb reachable without authentication",
    brief: "Anonymous write-shaped request reaches the handler past auth?",
    owasp: "WSTG-ATHZ-02", attackId: "T1190",
    what: "Identify write-shaped routes from the crawl and recovered API surface (form actions, REST "
        + "collections, admin JSON handlers) and with no session send DRY-RUN writes that cannot alter data: a "
        + "POST with required fields missing, a POST with a validation-rejecting type, a PATCH with an unknown "
        + "field, HEAD/OPTIONS on the same route. Confirm ONLY when the anonymous request enters the write "
        + "handler - a created or updated body, a 200/201/204, or a field-level validation error proving the "
        + "handler ran past authentication. Never send a valid write payload, never PUT; a DELETE probe uses "
        + "only an identifier that cannot exist (all-zero or random UUID) and is reported only if accepted.",
  },
  {
    id: "WA-072", category: "logic", name: "Mass assignment of privilege-bearing fields",
    brief: "Extra role or plan fields in our own update payload take effect?",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Take a legitimate self-update or registration payload from the session and add privilege-bearing "
        + "fields alongside the valid body (role admin, is_admin true, permissions wildcard, plan enterprise, "
        + "owner true, verified true, credits a huge value, tenant id), then send it as a dry run against a "
        + "throwaway operator-owned record. Confirm ONLY when a re-read shows the injected field took effect or "
        + "the response echoes the accepted privilege value; a validation error or a silently ignored field is "
        + "NOT the finding. Restore the test record afterwards; never target another user's record, never "
        + "elevate a shared account.",
  },
  {
    id: "WA-073", category: "logic", name: "Locale-route authentication bypass",
    brief: "Locale-prefixed route serves protected content that the canonical route refuses?",
    owasp: "WSTG-ATHZ-02", attackId: "T1190",
    what: "Map the localization routing, then request the same protected page or API under locale-prefixed and "
        + "unprefixed shapes (/en/, /fr/, /xx/, a bare prefix, the canonical path, any locale query parameter), "
        + "anonymously and then with the current session. Confirm ONLY when a locale-shaped route serves "
        + "protected content (an account-specific field) that the canonical route refused to the identical "
        + "anonymous request - a guard attached to one route shape and missing on another. A different "
        + "404/500, a translated login page or a cache hit is not a bypass; read-only GETs only, no "
        + "admin-intent writes through the bypass.",
  },
];
