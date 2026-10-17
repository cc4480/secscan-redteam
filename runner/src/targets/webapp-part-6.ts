/**
 * WEBAPP battery - part 6 of 7 (block 20, WA-121..WA-132).
 * Request-surface and transport gaps: HTTP method surface, NoSQL and host-header
 * injection, server-side prototype pollution, plaintext HTTP and redirect-chain
 * enforcement, rate limiting, API over-sharing, Supabase Storage and signup
 * confirmation, runtime edge-function auth, and GitHub Actions secrets/permissions.
 * Sources: SecScan probesHttp.ts, baasDepth.ts, repoCheckCi.ts, M16 apiProbeFindings;
 * Seclayer aggressive/nosql.ts, hostHeaderInjection.ts, prototypePollutionProbe.ts,
 * edgeFunctionProbe.ts. Assembled by the webapp profile; pure data, no side effects.
 */

import type { TargetBatteryItem } from "./types.js";

export const WEBAPP_PART_6: TargetBatteryItem[] = [
  // Block 20a - HTTP method surface. Sources: SecScan M4b probesHttp.ts (TRACE,
  // CONNECT, advertised write verbs); no Seclayer counterpart.
  {
    id: "WA-121", category: "validation",
    name: "HTTP TRACE or CONNECT method enabled",
    brief: "Does the origin answer TRACE or advertise CONNECT on the root document?",
    owasp: "WSTG-CONF-06", attackId: "T1595.002",
    what: "Send one OPTIONS / and one benign TRACE / with http_probe, then read the status line, the Allow header "
        + "and the body. Finding: TRACE returns 200 with the request line echoed in the body (Cross-Site Tracing), "
        + "or Allow lists TRACE or CONNECT. Record CONNECT from the header only - never open a tunnel or proxy a "
        + "request through the target. Evidence: the quoted Allow header and the TRACE request/response echo. A 405 "
        + "or 501 for both verbs is clean.",
  },
  {
    id: "WA-122", category: "validation",
    name: "Write HTTP methods advertised (PUT, DELETE, PATCH)",
    brief: "Does the Allow header name PUT, DELETE or PATCH on a surface with no write UI?",
    owasp: "WSTG-CONF-06", attackId: "T1595.002",
    what: "Send one OPTIONS / and OPTIONS on a discovered collection or object endpoint, and read the Allow header "
        + "only. Finding: Allow names PUT, DELETE or PATCH on a surface that exposes no authenticated write flow, so "
        + "a write verb is reachable beyond the app's intent. Evidence: the quoted Allow header per endpoint and the "
        + "unauthorised OPTIONS status. Never send an actual PUT, DELETE or PATCH - advertising the method is the "
        + "whole proof and no state is changed.",
  },

  // Block 20b - injection extras. Sources: Seclayer aggressive/nosql.ts,
  // hostHeaderInjection.ts, prototypePollutionProbe.ts.
  {
    id: "WA-123", category: "logic",
    name: "NoSQL operator injection in an authentication or query parameter",
    brief: "Does an operator object bypass a string check on a login or search field?",
    owasp: "WSTG-INPV-05", attackId: "T1190",
    what: "Record a baseline login or search response with a normal string value, then replay the same request with "
        + "the value replaced by an operator object where a string is expected ({\"$ne\":null}, {\"$gt\":\"\"}). "
        + "Finding: the operator body authenticates where the baseline failed, or returns a result set that differs "
        + "from the string baseline. Evidence: both request bodies and the differing response bodies, quoting at "
        + "most ONE returned record as proof of the differential. Never dump a collection, never write, and stop at "
        + "the first confirming response.",
  },
  {
    id: "WA-124", category: "logic",
    name: "Host header injection via X-Forwarded-Host",
    brief: "Does an injected X-Forwarded-Host reach a generated link or Location?",
    owasp: "WSTG-INPV-17", attackId: "T1190",
    what: "Send one request to a password-reset, login or account page with the header X-Forwarded-Host: "
        + "evil.example added, plus one baseline request without it. Finding: evil.example appears in a generated "
        + "absolute link, a canonical URL or a Location header in the response. Evidence: the quoted link carrying "
        + "the injected host next to the baseline link. Do NOT trigger a password-reset email to a real user, do not "
        + "send the request for another account, and never cache-poison a shared edge path.",
  },
  {
    id: "WA-125", category: "logic",
    name: "Server-side prototype pollution through a JSON body",
    brief: "Does a __proto__ JSON field produce a gadget effect on the server?",
    owasp: "WSTG-INPV-19", attackId: "T1190",
    what: "Send one JSON body carrying __proto__ or constructor.prototype alongside a normal field, for example "
        + "{\"__proto__\":{\"status\":510}} or {\"__proto__\":{\"json spaces\":10}}, to an endpoint that merges the body "
        + "into a config or option object. Finding: the documented gadget fires on a follow-up request - the "
        + "response status or a response header changes to the injected value, or JSON formatting changes as "
        + "documented by the probe. Evidence: the injected body and the quoted clean-baseline versus injected "
        + "differential. One benign gadget only: no crash and no denial of service.",
  },

  // Block 20c - transport, throttling and API data. Sources: SecScan M1/M4c
  // (plaintext HTTP, redirect chain, rate limiting), M16 #108 apiProbeFindings;
  // Seclayer coverage group for rate limiting.
  {
    id: "WA-126", category: "validation",
    name: "Plaintext HTTP served or the redirect chain never reaches HTTPS",
    brief: "Does http:// reach https:// within the hop budget, or serve content in cleartext?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Request http://<host>/ without following redirects, then follow up to 5 hops and record every Location "
        + "header. Finding: the first hop serves application content over cleartext HTTP, or none of the up-to-5 "
        + "hops lands on an https:// URL. Evidence: the hop chain of status codes and raw Location headers, stating "
        + "the final scheme. One 301 or 308 to the same host over https is clean; HSTS strength belongs to WA-003.",
  },
  {
    id: "WA-127", category: "functionality",
    name: "Missing rate limiting on the root or a sensitive endpoint",
    brief: "Does one bounded burst of GETs get throttled at all?",
    owasp: "WSTG-ATHN-04", attackId: "T1595.002",
    what: "Run burst_probe exactly once per endpoint - the root and one sensitive login or authenticated endpoint - "
        + "and count how many responses of the fixed-size batch carry 429, 503 or Retry-After. Finding: no response "
        + "throttles, so no rate limit is observable at this volume; report that absence as NEEDS VERIFICATION, not "
        + "as a confirmed missing control. Evidence: the status distribution and quoted throttle headers from the "
        + "one batch. Never repeat or enlarge the batch and never treat it as a flood test.",
  },
  {
    id: "WA-128", category: "validation",
    name: "API response over-shares sensitive fields",
    brief: "Does an authorised response carry password hashes, tokens, keys or card-shaped data?",
    owasp: "WSTG-APIT-01", attackId: "T1595.002", needs: "authorized test session",
    what: "With the authorised test session GET the already-discovered profile, user, order and settings endpoints "
        + "and scan each JSON body for field names and value shapes that should never leave the server: password "
        + "hashes, bearer or API tokens, private keys, card PAN-shaped values and other users' identifiers. "
        + "Finding: such a field is present in the response. Evidence: the FIELD NAMES plus a masked value only "
        + "(first and last two characters), never stored or reused, and never another user's object is requested.",
  },

  // Block 20d - BaaS depth: Supabase Storage, signup confirmation, runtime edge
  // function auth. Sources: SecScan baasDepth.ts; Seclayer supabaseStorageProbe.ts,
  // edgeFunctionProbe.ts.
  {
    id: "WA-129", category: "validation",
    name: "Supabase Storage bucket listable with the anon key",
    brief: "Can the browser-shipped Supabase anon key list Storage buckets or objects?",
    owasp: "WSTG-CONF-04", attackId: "T1083", needs: "client-side Supabase key discovered",
    what: "Using the project URL and anon key already discovered (the same credential as WA-085), GET "
        + "/storage/v1/bucket and then one /storage/v1/object/list/<bucket> call for a bucket name returned there. "
        + "Finding: bucket metadata (name, public flag) or an object listing comes back, so Storage is browsable "
        + "with the key the browser already carries. Evidence: the truncated JSON bodies and the bucket names. "
        + "Never download object contents beyond one metadata listing, and never write or delete an object.",
  },
  {
    id: "WA-130", category: "validation",
    name: "Supabase email confirmation disabled",
    brief: "Does a signup without confirmation still issue a session?",
    owasp: "WSTG-IDNT-02", attackId: "T1078", needs: "client-side Supabase key discovered",
    what: "Using the discovered project URL and anon key, POST /auth/v1/signup once with a disposable engagement "
        + "address and read the response body. Finding: the response carries an access_token and a user object, or "
        + "shows email_confirmed_at already set, proving signup issues a confirmed session without email "
        + "confirmation. Evidence: the response field names and the quoted email_confirmed_at or session shape with "
        + "the token redacted. One disposable address only, never a real user's address, and never sign in as an "
        + "existing user.",
  },
  {
    id: "WA-131", category: "logic",
    name: "Runtime edge function skips token verification",
    brief: "Does the deployed edge function reject a missing or forged bearer token?",
    owasp: "WSTG-ATHZ-02", attackId: "T1190", needs: "deployed edge function endpoint discovered",
    what: "Call the discovered deployed edge-function endpoint read-only three times: with no Authorization header, "
        + "with a syntactically valid but forged or expired bearer token, and with the genuine test token. Finding: "
        + "the untokened or forged call returns success data that should have been a 401, so verification is not "
        + "enforced at the deployed function. Evidence: the three status/body pairs, quoting the success body field "
        + "names only. No writes and no admin action: only the function's documented read method is invoked.",
  },

  // Block 20e - CI policy. Sources: SecScan Module 22 repoCheckCi.ts (secret
  // printing step, write-all permissions).
  {
    id: "WA-132", category: "logic",
    name: "GitHub Actions step prints a secret or requests write-all",
    brief: "Does a workflow echo a secret or hold write-all permissions?",
    owasp: "WSTG-CONF-04", attackId: "T1552.001", needs: "GitHub repository supplied",
    what: "Read the supplied repository's .github/workflows only. Finding: a run step that echoes a secret context "
        + "(echo ${{ secrets.X }}, printenv or an env dump) where the workflow log would expose it, or a workflow "
        + "that sets permissions: write-all or contents: write on a job triggered by pull_request or issue events. "
        + "Evidence: workflow path, line number and the quoted step or permissions block, naming the secret without "
        + "showing its value. Report only - never push a branch, open a pull request or trigger a workflow run.",
  },
];
