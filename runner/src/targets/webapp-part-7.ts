/**
 * WEBAPP battery - part 7 of 7 (block 21, WA-133..WA-144).
 * Repo/policy and TLS review, structured data and metadata, inner-route header
 * consistency, client hydration secrets, GraphQL field suggestions, JWT claims,
 * health endpoints, WordPress routes, and informational banner/header gaps.
 * Sources: SecScan repoCheckSupabase.ts, repoCheckCode.ts, structuredData.ts,
 * crawlerHeaders.ts/crawlerCookies.ts, nextjsProbe.ts, graphqlExtra.ts,
 * jwtAnalysis.ts, healthEndpointProbe.ts; Seclayer findings.ts, templates.ts.
 * Assembled by the webapp profile; pure data, no side effects.
 */

import type { TargetBatteryItem } from "./types.js";

export const WEBAPP_PART_7: TargetBatteryItem[] = [
  // Block 21a - supplied-repository policy and TLS review (static read only).
  // Sources: SecScan repoCheckSupabase.ts (RLS/policy/storage/view findings),
  // repoCheckCode.ts (certificate verification disabled).
  {
    id: "WA-133", category: "validation",
    name: "Repository Supabase policies missing RLS or granting blanket access",
    brief: "Do any table, view or storage policy bypass row-level security?",
    owasp: "WSTG-ATHZ-04", attackId: "T1190", needs: "GitHub repository supplied",
    what: "Read the supplied repository's supabase/migrations and every policy SQL file. Finding: a table created "
        + "without ENABLE ROW LEVEL SECURITY, a policy whose USING or WITH CHECK predicate is true or whose role is "
        + "anon/authenticated with no predicate, a storage.objects policy granting blanket select or insert, or a "
        + "view without security_invoker. Also flag a SECURITY DEFINER function with no pinned search_path. "
        + "Evidence: migration file, line number and the quoted CREATE TABLE / POLICY / VIEW statement. Static "
        + "review only - never call the live PostgREST or Storage API.",
  },
  {
    id: "WA-134", category: "validation",
    name: "TLS certificate verification disabled in source",
    brief: "Does the code switch off certificate checks on outbound HTTPS calls?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002", needs: "GitHub repository supplied",
    what: "Search the supplied repository for rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0, verify: "
        + "false, verify=False, InsecureSkipVerify: true, ssl._create_unverified_context and "
        + "CURLOPT_SSL_VERIFYPEER 0. Finding: a reachable outbound HTTPS client built with verification disabled, "
        + "especially where the target URL or webhook destination comes from config or a request. Evidence: file, "
        + "line, the quoted option and the quoted client construction. Static read only - never send traffic to the "
        + "unverified endpoint.",
  },

  // Block 21b - page metadata and inner-route consistency. Sources: SecScan
  // structuredData.ts (9 findings), crawlerHeaders.ts / crawlerCookies.ts.
  {
    id: "WA-135", category: "validation",
    name: "Structured data or social metadata leaks internal details",
    brief: "Does JSON-LD, canonical or the OG block expose internal hosts or a mis-owned domain?",
    owasp: "WSTG-CLNT-13", attackId: "T1590.002",
    what: "Fetch the root and crawled pages with http_probe and parse every application/ld+json block, the "
        + "link rel=canonical tag and the og:* / twitter:* meta tags. Finding, all INFO or LOW: a canonical or og:url "
        + "whose host is outside the engagement domain, an internal hostname, container name or private IP in "
        + "JSON-LD, malformed JSON-LD with no @context or @type, or a robots noindex tag on a page meant to be "
        + "indexed. Evidence: the quoted tag or JSON fragment plus the engagement domain it should have named.",
  },
  {
    id: "WA-136", category: "functionality",
    name: "Security headers or cookie flags inconsistent across inner routes",
    brief: "Do inner pages serve weaker headers or cookie flags than the root document?",
    owasp: "WSTG-CONF-07", attackId: "T1595.002",
    what: "Crawl at least two inner routes (a login or account page and a static content page) plus the root with "
        + "http_probe and record the exact response headers and every Set-Cookie line for each. Finding: a control "
        + "present on one route and absent on another - CSP, X-Content-Type-Options, X-Frame-Options or "
        + "Referrer-Policy missing on an inner route, or a cookie set there without Secure, HttpOnly or SameSite. "
        + "Evidence: the two header blocks quoted side by side and the exact route pair compared.",
  },

  // Block 21c - client surfaces. Sources: SecScan nextjsProbe.ts (__NEXT_DATA__ secrets),
  // graphqlExtra.ts (field suggestions), jwtAnalysis.ts (sensitive payload claims).
  {
    id: "WA-137", category: "validation",
    name: "Secrets embedded in the Next.js __NEXT_DATA__ payload",
    brief: "Does the hydration payload carry credentials the browser should never receive?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    what: "Fetch the root and crawled Next.js pages, extract the script tag with id __NEXT_DATA__ and parse the "
        + "JSON, then repeat for /_next/data/<buildId>/<route>.json when the build id is visible. Finding: a value "
        + "shaped like a service_role key, database URL, provider secret or private token anywhere under props, "
        + "runtimeConfig or query. Evidence: the JSON path to the value with the value redacted to its prefix and "
        + "last four characters. Do not use the value and do not test it against its provider.",
  },
  {
    id: "WA-138", category: "validation",
    name: "GraphQL field suggestions enabled (schema leak without introspection)",
    brief: "Does a bad field come back with Did you mean suggestions naming real fields?",
    owasp: "WSTG-APIT-02", attackId: "T1190",
    what: "POST {\"query\":\"{ __typename }\"} to the GraphQL endpoint, then POST a deliberately invalid field such "
        + "as {\"query\":\"{ userr { id } }\"} and read the errors array. Finding: introspection may be disabled yet "
        + "the error carries a Did you mean message naming real fields, plus locations and a path - each cycle "
        + "reveals more schema. Evidence: quote the error message and the field it suggested. Clean only when the "
        + "invalid field returns a generic error with no suggestion.",
  },
  {
    id: "WA-139", category: "validation",
    name: "JWT payload carries sensitive claims",
    brief: "Does a decoded token payload hold secrets or personal data?",
    owasp: "WSTG-SESS-10", attackId: "T1552.001", needs: "a bearer JWT observed or supplied",
    what: "Base64url-decode the payload segment of the observed or supplied JWT (no signature check) and list its "
        + "claim names. Finding: claims named password, pwd, secret, api_key, apikey, ssn, credit_card, card, token "
        + "or refresh_token, or a claim value that is a password hash or another bearer credential. Evidence: the "
        + "claim NAMES only, never the values, plus where the token was observed. Do not replay a modified token.",
  },

  // Block 21d - informational surface disclosure. Sources: SecScan
  // healthEndpointProbe.ts, M1 header findings (#15-17), probes-data xmlrpc/wp-json;
  // Seclayer findings.ts Verbose Server Framework Signature Leaked, templates.ts.
  {
    id: "WA-140", category: "validation",
    name: "Health or readiness endpoint discloses runtime details",
    brief: "Do /health, /healthz or /actuator/health expose component or build detail?",
    owasp: "WSTG-CONF-04", attackId: "T1595.002",
    what: "GET /health, /healthz, /ready, /readiness, /status and /actuator/health with http_probe and read each "
        + "body. Finding: a per-component breakdown (database, redis, s3, payment provider) with status or error "
        + "detail, or a version, build hash, hostname or config value beyond a bare status. Absence of these paths "
        + "is clean. Evidence: the quoted JSON or plain-text body fragment naming the component or version, not the "
        + "status line alone.",
  },
  {
    id: "WA-141", category: "validation",
    name: "WordPress XML-RPC enabled or REST user enumeration exposed",
    brief: "Do /xmlrpc.php and the WP REST users route answer without authentication?",
    owasp: "WSTG-INFO-02", attackId: "T1087",
    what: "POST a benign system.listMethods call to /xmlrpc.php and GET /wp-json/wp/v2/users and "
        + "/?rest_route=/wp/v2/users. Finding: the XML-RPC methods list is returned (opening pingback and credential "
        + "brute force), or the users route returns a JSON array exposing slugs and display names. Evidence: the "
        + "quoted methodName line or the quoted user array entries, plus the route. Clean when both routes 404 or "
        + "refuse methods; never attempt a login or brute force against wp-login.",
  },
  {
    id: "WA-142", category: "validation",
    name: "Verbose server banner discloses product and version",
    brief: "Do the Server or X-Powered-By headers name a product version?",
    owasp: "WSTG-INFO-02", attackId: "T1592.002",
    what: "Record the exact Server, X-Powered-By and Via headers on the root and an inner route with http_probe. "
        + "Finding: a header carries a product version such as nginx/1.18.0, Apache/2.4.49, PHP/7.4.3 or "
        + "ASP.NET/4.0.30319. INFO only - report it as reconnaissance context and pair it with the version-to-CVE "
        + "item rather than claiming exploitability. Evidence: quote the header line verbatim; a bare product name "
        + "with no version is a weaker finding.",
  },
  {
    id: "WA-143", category: "validation",
    name: "X-XSS-Protection explicitly disabled",
    brief: "Does the response set X-XSS-Protection to 0?",
    owasp: "WSTG-CONF-07", attackId: "T1595.002",
    what: "GET the root and an inner route with http_probe and record the exact X-XSS-Protection header. Finding: "
        + "the header is present with the value 0, which disables the legacy browser XSS auditor for every visitor; "
        + "quote the header line verbatim. A header that is entirely absent is not this finding (modern browsers "
        + "ignore the header anyway), and a value of 1; mode=block is not a finding.",
  },
  {
    id: "WA-144", category: "validation",
    name: "Cache-Control missing or HSTS preload status available",
    brief: "Is an account-bearing response cacheable, and is the domain on the HSTS preload list?",
    owasp: "WSTG-CONF-07", attackId: "T1595.002",
    what: "Record Cache-Control, Pragma and Expires on the root document, a JSON/API response and, when the run "
        + "holds a session, the authenticated account page. Finding: no Cache-Control (and no no-store) on a "
        + "response carrying account data or a token, so a shared cache may store it. Separately query "
        + "hstspreload.org for the domain and report the preload status as INFO only - not preloaded is not a "
        + "vulnerability by itself. Evidence: the quoted header block and the preload API answer.",
  },
];
