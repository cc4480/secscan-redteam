/**
 * WEBAPP battery - part 4 of 7 (blocks 11-14, WA-074..WA-096).
 *
 * Blocks: 11 JWT and session tokens, 12 API surface, 13 BaaS and storage,
 * 14 cloud and perimeter. Assembled by webapp.ts.
 *
 * Content is authored from the WA_ITEMS_SPEC.md manifest: every id, name,
 * category and ATT&CK id is fixed there and must not be edited here.
 */

import type { TargetBatteryItem } from "./types.js";

export const WEBAPP_PART_4: TargetBatteryItem[] = [
  // Block 11 - JWT & session tokens. Sources: SecScan SCAN_COVERAGE.md M6
  // (jwtAnalysis.ts: alg none, empty signature, missing exp, lifetime > 365d)
  // and M21; Seclayer jwtProbe.ts (5 forgery variants incl. leaked-secret
  // resign + escalated role), weakTokenScan.ts, redTeam/weakSessionToken.ts.
  {
    id: "WA-074", category: "validation", name: "JWT with alg:none accepted",
    brief: "Forged unsigned JWT - does any read endpoint accept it as the original principal?",
    owasp: "WSTG-SESS-10", attackId: "T1078",
    what: "Base64url-decode the observed bearer JWT header, re-encode it as {\"alg\":\"none\",\"typ\":\"JWT\"} "
        + "with an empty signature segment (two-dot and three-dot forms, plus None/NONE case variants) and "
        + "replay against a read-only authenticated endpoint (GET /api/me, /api/v1/profile, /v1/userinfo). "
        + "Capture the anonymous baseline first. Proof: the forged call returns the original principal's "
        + "profile body while a random-token control is 401. Quote the decoded header and the status pair.",
    needs: "a bearer JWT observed or supplied",
  },
  {
    id: "WA-075", category: "validation", name: "JWT with a tampered signature accepted",
    brief: "Payload rewritten but signature kept - is the signature verified at all?",
    owasp: "WSTG-SESS-10", attackId: "T1078",
    what: "Keep the observed JWT's signature segment and rewrite the caller-identifying claims (sub, user_id, "
        + "role, tenant) to values absent from the original, one variant per claim, and replay each against one "
        + "read endpoint. Controls: signature segment truncated, and one signature byte flipped. Proof: a 200 "
        + "whose returned record or echoed claim matches the tampered value on two independent mutations, with "
        + "both controls rejected. That separates 'signature never checked' from 'signature checked'.",
    needs: "a bearer JWT observed or supplied",
  },
  {
    id: "WA-076", category: "logic", name: "JWT re-signed with a leaked secret and escalated role",
    brief: "Leaked HMAC secret plus role admin - does a self-signed admin token work?",
    owasp: "WSTG-SESS-10", attackId: "T1078",
    what: "Take a secret already recovered from client code or the repo (WA-045, WA-116, WA-091), recompute "
        + "HMAC-SHA256 over the forged header.payload with that candidate, set role to admin/superuser, and "
        + "replay against an admin-only read path plus the normal user path. Proof: 200 with an admin-only "
        + "field, or 200 on a path that returned 403 for the genuine token, while the same forged token signed "
        + "with a wrong secret is rejected as the control. No candidate secret means report the prerequisite.",
    needs: "a bearer JWT observed or supplied",
  },
  {
    id: "WA-077", category: "validation", name: "JWT missing expiry or with excessive lifetime",
    brief: "Decoded exp/iat claims - no expiry, or a multi-year session?",
    owasp: "WSTG-SESS-10", attackId: "T1078",
    what: "Decode the observed JWT payload and record exp, iat, nbf and any custom lifetime claim. Finding "
        + "without re-signing: no exp at all, exp minus iat beyond 365 days, or nbf far in the future. Live "
        + "check only where signature verification is already known broken (WA-075): present an exp in the past "
        + "and confirm the API still accepts it. Evidence: quote the decoded claim block and the accepted or "
        + "rejected status. Never quote the signature segment.",
    needs: "a bearer JWT observed or supplied",
  },
  {
    id: "WA-078", category: "logic", name: "Predictable session token recipe",
    brief: "Two logins compared - is the session token a decodable recipe of a known field?",
    owasp: "WSTG-SESS-01", attackId: "T1078",
    what: "With the authorized test login, sign in twice from the same account a few seconds apart and collect "
        + "every Set-Cookie session value and access token. Test whether a segment is sequential, a base64 of "
        + "the username/email/login timestamp, or a bare hash of a known field. Confirm by recomputing "
        + "md5/sha1/sha256 of the lowercased email and of the observed login second, and by checking the two "
        + "tokens differ only in that component. Proof: quote the recipe and the matched recomputation.",
    needs: "authorized test login credentials",
  },

  // Block 12 - API surface. Sources: SecScan SCAN_COVERAGE.md M16
  // (apiDocsProbe.ts, apiProbes.ts: no-session data, SQLi in query/path/body,
  // BFLA 404-not-401) and M17 (bola.ts body-similarity); Seclayer apiProbes.ts
  // (GraphQL introspection, query-cost alias amplification), graphqlProbe.ts.
  {
    id: "WA-079", category: "logic", name: "OpenAPI or Swagger schema exposed and used for surface discovery",
    brief: "Schema file live - and does it hand over the real endpoint list?",
    owasp: "WSTG-APIT-01", attackId: "T1190",
    what: "GET /openapi.json, /swagger.json, /v3/api-docs, /api-docs, /docs/openapi.json, "
        + "/swagger-ui/index.html and /.well-known/openapi.json. Accept only a body that parses as JSON with an "
        + "openapi or swagger version key and a non-empty paths object - this rejects SPA catch-all shells. "
        + "Proof: quote the version and three recovered method+path pairs, then show one of them answered a "
        + "real request. Record the path count so the discovered surface is measurable.",
  },
  {
    id: "WA-080", category: "validation", name: "API endpoint returns data without a session",
    brief: "Documented endpoint, no cookie and no bearer - does it still return records?",
    owasp: "WSTG-APIT-01", attackId: "T1190",
    what: "Take the method+path pairs recovered in WA-079 (or path literals from the JS bundles) and request "
        + "each record endpoint three ways: primary-account token, second-account token if supplied, and "
        + "anonymous, plus a random-path catch-all control. Compare bodies by field-name set and value-token "
        + "overlap (similarity, never byte equality). Proof: anonymous gets 200 with the same record shape the "
        + "primary token sees, or the second account gets a body similar to the primary's (BOLA). Report field "
        + "names and row counts only; values masked - read-shaped, never an export of customer data.",
  },
  {
    id: "WA-081", category: "validation", name: "SQL injection in an API query, path or body parameter",
    brief: "One trailing quote in a read endpoint - does the database speak?",
    owasp: "WSTG-INPV-05", attackId: "T1190",
    what: "On read-shaped API endpoints only (GET item/list/filter), inject a single trailing quote into one "
        + "query parameter (?search=term'), one path segment (/api/v1/items/1'), and one JSON body filter "
        + "({\"filter\":{\"q\":\"term'\"}}), after a clean baseline of each same request. Proof: a database error "
        + "signature ('syntax error at or near', 'You have an error in your SQL syntax', 'unrecognized token', "
        + "'Incorrect syntax near') present in the injected response and absent from baseline. No UNION, no "
        + "extraction, no write verbs.",
  },
  {
    id: "WA-082", category: "validation", name: "GraphQL schema introspection enabled",
    brief: "Introspection query - does the endpoint return the full type system?",
    owasp: "WSTG-APIT-02", attackId: "T1190",
    what: "POST {\"query\":\"{__schema{queryType{name} types{name kind}}}\"} with content-type application/json "
        + "to /graphql, /api/graphql, /api/v1/graphql and /v1/graphql. Accept only a JSON response carrying "
        + "data.__schema.types as an array. Proof: quote the query type name, three type names and the type "
        + "count, plus a malformed-query POST returning a GraphQL errors[] envelope (confirms a real resolver). "
        + "The negative is a specific 'introspection is not allowed' error, which must be quoted as the deny.",
  },
  {
    id: "WA-083", category: "logic", name: "GraphQL query-cost controls missing",
    brief: "Fifty aliases of one cheap field - is there any cost or depth limit?",
    owasp: "WSTG-APIT-02", attackId: "T1190",
    what: "Using the schema from WA-082, POST one query with 50 aliases of the cheapest field "
        + "(a0:__typename ... a49:__typename), then repeat at 200 aliases. A server with cost or depth controls "
        + "answers 400/429 with a validation error; one without returns every alias in a single 200. Proof: "
        + "quote the response carrying the last alias plus the exact rejection that never appeared, and record "
        + "the highest alias count accepted. __typename only, no nested expensive resolvers, no flood.",
  },
  {
    id: "WA-084", category: "logic", name: "API error verbosity and versioning gaps",
    brief: "Bad input and old versions - does the error body leak the stack, or an older weaker API?",
    owasp: "WSTG-APIT-01", attackId: "T1190",
    what: "Send malformed JSON, an unsupported content-type, a missing required field and an invalid enum to "
        + "one documented endpoint, then request an unsupported version (/api/v2, /api/v3, and the unversioned "
        + "path). Proof: the 4xx/5xx body quotes internals ('node_modules', 'Traceback', 'SQLSTATE', 'at com.'), "
        + "or the legacy unversioned path serves the same record with weaker validation than the documented "
        + "version (status and body differential between both, quoted). Report which version leaked.",
  },

  // Block 13 - BaaS & storage. Sources: SecScan SCAN_COVERAGE.md M8
  // (baasProbes.ts: service_role key, CVE-2025-48757 anon read, dry-run
  // Prefer: tx=rollback INSERT, storage bucket list; Firebase Firestore/RTDB
  // unauth reads) + M15 (storageProbe.ts); Seclayer supabase-storage, firebase,
  // bucket and credentialChain probes.
  {
    id: "WA-085", category: "validation", name: "Supabase anon-key read exposure",
    brief: "Anon key against /rest/v1 tables - do rows come back without RLS?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "With the anon key and project URL recovered from client code, GET "
        + "<project>/rest/v1/<table>?select=*&limit=1 with apikey and Authorization: Bearer <anon>, table names "
        + "taken from the /rest/v1/ OpenAPI root. Proof: 200 JSON array whose first row shows field names, "
        + "contrasted with a bogus-key replay at 401 (the read is key-gated, not public), plus a non-existent "
        + "table as negative control. Report table names, presence and row counts only. Read-shaped, values "
        + "masked, no dump.",
    needs: "client-side Supabase key discovered",
  },
  {
    id: "WA-086", category: "logic", name: "Supabase unauthenticated write via dry-run rollback",
    brief: "INSERT that must not persist - does PostgREST reach the schema cache with only the anon key?",
    owasp: "WSTG-ATHZ-02", attackId: "T1190",
    what: "POST <project>/rest/v1/<table> with apikey + Bearer <anon>, content-type application/json, header "
        + "Prefer: tx=rollback, body {\"__probe_nonexistent_field__\":\"1\"} - a column no real schema has. A "
        + "400/422 naming that probe column (PGRST204 'could not find the ... column') proves PostgREST reached "
        + "the INSERT, so auth and RLS did not block the write path, while tx=rollback means no row persists. "
        + "Proof: quote the code and column, and show the table's prior count unchanged under a read-only count "
        + "query. A 401/403 (code 42501) is the negative.",
    needs: "client-side Supabase key discovered",
  },
  {
    id: "WA-087", category: "logic", name: "Supabase anon key reaches the admin API (CVE-2025-48757)",
    brief: "Anon key on admin surfaces - /auth/v1/admin/users or an RPC it should never reach?",
    owasp: "WSTG-ATHZ-02", attackId: "T1190",
    what: "With the same anon key, GET <project>/rest/v1/ (the PostgREST OpenAPI root) and note the tables and "
        + "verbs advertised for the anon role, then try the admin surfaces that must never accept it: "
        + "<project>/auth/v1/admin/users, any defined <project>/rest/v1/rpc/* function, and "
        + "<project>/storage/v1/bucket. Proof: 200 JSON with a users or bucket array under the anon key, against "
        + "the same call with a bogus key at 401. Report endpoint, status and object count only; every value "
        + "masked.",
    needs: "client-side Supabase key discovered",
  },
  {
    id: "WA-088", category: "validation", name: "Firebase database open to unauthenticated reads",
    brief: "Firestore or RTDB read with no token - do documents come back?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "From the discovered Firebase config (databaseURL, projectId, apiKey), read with no auth token: "
        + "GET <databaseURL>/.json?shallow=true (Realtime Database) and GET "
        + "https://firestore.googleapis.com/v1/projects/<projectId>/databases/(default)/documents/<collection>"
        + "?pageSize=1 (Firestore). Proof: 200 JSON whose shallow read returns top-level key names, or a "
        + "documents array with a name and fields map; a non-existent database or collection returning "
        + "404/permission-denied is the negative. Report key names and counts, never document values.",
    needs: "client-side Firebase config discovered",
  },
  {
    id: "WA-089", category: "validation", name: "PocketBase or Appwrite collection readable without authentication",
    brief: "PocketBase /api/collections or Appwrite documents - readable with no Authorization header?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190",
    what: "Fingerprint the backend from headers and /api/health (PocketBase) versus /v1/health (Appwrite), then "
        + "GET without any Authorization header: /api/collections and "
        + "/api/collections/<name>/records?perPage=1 for PocketBase, and "
        + "/v1/databases/<db>/collections/<col>/documents for Appwrite. Proof: 200 JSON carrying total plus "
        + "documents (or an items array) with no auth, and a bogus collection id at 404 while the real one is "
        + "200. Quote collection names, totals and field names only; do not harvest documents.",
  },

  // Block 14 - Cloud & perimeter. Sources: SecScan SCAN_COVERAGE.md M7
  // (subdomainTakeover.ts, 19 service fingerprints), M15 (storageProbe.ts
  // S3/GCS/Azure), recon.ts (TCP port scan); Seclayer perimeter.ts (34-subdomain
  // enum with wildcard filtering, 12 sensitive paths) and nmap/*.
  {
    id: "WA-090", category: "validation", name: "Public cloud bucket listing (S3, GCS, Azure)",
    brief: "Named buckets from JS and hostname - does the listing XML come back?",
    owasp: "WSTG-CONF-04", attackId: "T1083",
    what: "Derive bucket names from the hostname and JS bundle strings (<brand>-assets, <brand>-prod, "
        + "<brand>-backup), then request read-only listings: S3 GET "
        + "https://<bucket>.s3.amazonaws.com/?list-type=2, GCS GET "
        + "https://storage.googleapis.com/storage/v1/b/<bucket>/o?maxResults=1, Azure GET "
        + "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list. Proof: a "
        + "ListBucketResult with a Key element, a GCS objects JSON with items[0].name, or an EnumerationResults "
        + "with a Blob entry, quoted masked; a random bucket name returning NoSuchBucket/404 is the control. "
        + "First key only.",
  },
  {
    id: "WA-091", category: "logic", name: "Client-side key chained to backend access",
    brief: "The secret found in JS - how far does it actually reach into the backend?",
    owasp: "WSTG-ATHZ-02", attackId: "T1552.001",
    what: "Take the credential recovered from client code (WA-043, WA-045, WA-085) and test the backend it "
        + "should not unlock: replay it as Authorization or apikey against the origin's own API and against the "
        + "vendor endpoint the key names. Proof: a response carrying data the anonymous request cannot get - the "
        + "same call without the credential returns 401/403 while the credentialed call returns 200 with record "
        + "field names, both quoted. Report key type, first 6 and last 4 characters, and endpoint unlocked.",
    needs: "client-side credential discovered",
  },
  {
    id: "WA-092", category: "logic", name: "Subdomain takeover through a dangling CNAME",
    brief: "Dangling CNAME to an unclaimed service - is the service's own 404 marker served?",
    owasp: "WSTG-CONF-03", attackId: "T1590.002",
    what: "For every live subdomain from WA-096, follow the CNAME chain (max 5 hops) and match the terminal "
        + "target against known unclaimed-service fingerprints (herokuapp.com, github.io, netlify.app, "
        + "vercel.app, s3.amazonaws.com, azurewebsites.net, fastly.net, ghost.io, readme.io, fly.dev, "
        + "onrender.com, up.railway.app). Proof needs both the CNAME target and the service's unclaimed marker "
        + "in the HTTP body ('No such app', 'There isn't a GitHub Pages site here', 'NoSuchBucket', 'Project "
        + "not found'); quote both. A CNAME alone is not a finding. Never claim the resource.",
  },
  {
    id: "WA-093", category: "validation", name: "High-risk service ports exposed",
    brief: "Open database, cache or container-daemon ports on the resolved hosts?",
    owasp: "WSTG-CONF-01", attackId: "T1595.002",
    what: "Run the nmap quick and service profiles against each resolved host and triage the high-risk set: 22, "
        + "23, 2375/2376, 3306, 5432, 6379, 9200, 10250, 11211, 11434, 27017, 5672, 9092, 2181, 5984, 8500, "
        + "9090. Proof: nmap reports state open with a service/version string, then one read-only reachability "
        + "probe on the worst port (Redis PING expecting +PONG, Elasticsearch GET / expecting a version.number) "
        + "confirms it is not a filtered SYN. Never issue a state-changing command (no CONFIG SET, FLUSHALL, "
        + "DEL, or database write).",
    needs: "nmap binary",
  },
  {
    id: "WA-094", category: "functionality", name: "robots.txt discloses sensitive paths",
    brief: "Disallowed admin and staging paths - do they actually resolve?",
    owasp: "WSTG-INFO-01", attackId: "T1083",
    what: "GET /robots.txt and read the Disallow and Sitemap lines. For every sensitive-looking Disallow "
        + "(/admin, /internal, /staging, /api/v1/private, /.git, /backup), request it once and compare with a "
        + "random path control. Proof: the robots.txt line quoted verbatim plus that path answering something "
        + "other than the catch-all (200 with an admin login form, or 401 rather than the SPA shell). A Disallow "
        + "for a path that is already 404 is hygiene only - report the weaker claim.",
  },
  {
    id: "WA-095", category: "functionality", name: "security.txt absent or malformed",
    brief: "RFC 9116 file - missing entirely, or missing Contact/Expires?",
    owasp: "WSTG-INFO-01", attackId: "T1595.002",
    what: "Fetch /.well-known/security.txt then /security.txt (the RFC 9116 fallback), rejecting any HTML "
        + "catch-all shell by requiring a text/plain body of key: value lines. Proof: absent is 404 or the same "
        + "catch-all shell on both paths, quoted; malformed is a present file missing Contact or Expires, or an "
        + "Expires timestamp already in the past - quote the offending field. Record the expiry date so the "
        + "weakness is measurable.",
  },
  {
    id: "WA-096", category: "functionality", name: "Subdomain enumeration with wildcard handling",
    brief: "Wildcard DNS detected first - which hosts are genuinely distinct?",
    owasp: "WSTG-INFO-04", attackId: "T1590.002",
    what: "Detect wildcard DNS first: resolve three random labels under the domain and record any wildcard "
        + "address. Then enumerate from the crt.sh JSON feed plus the common list (www, api, dev, staging, "
        + "admin, vpn, dashboard, status, mail, portal, app, cdn, qa, test, docs, auth, sso, git, jenkins, "
        + "grafana, kibana, minio, s3, storage, upload) and suppress every candidate resolving only to the "
        + "wildcard address. Proof: per live host quote a distinct A/AAAA record and an HTTP title or Server "
        + "header differing from the wildcard response; report the suppression count so a wildcard cannot "
        + "inflate the host list.",
  },
];
