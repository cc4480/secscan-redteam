/**
 * WEBAPP battery - part 2 of 5 (blocks 5-7: exposed files and templates,
 * client-side secrets, SCA/CVE). Items WA-029..WA-052 in manifest order.
 *
 * Pure data split: the webapp profile assembles the parts. Content provenance
 * is the per-block comment below; every item names the concrete path/parameter
 * or artifact plus the confirming evidence that proves it. Non-destructive:
 * GET/HEAD probes and rendered-bundle reads only.
 */

import type { TargetBatteryItem } from "./types.js";

export const WEBAPP_PART_2: TargetBatteryItem[] = [
  // Block 5 - exposed files and templates. Sources: SecScan probes.ts sensitive-file
  // probes (~75 paths, each with a body validator) and SCAN_COVERAGE.md module 4a;
  // Seclayer perimeter.ts (12 sensitive paths incl. .env/.git/lockfiles) and
  // templates.ts (60 tech-gated exposure templates, SPA negative matcher).
  {
    id: "WA-029", category: "validation",
    name: "VCS metadata exposed (.git, .svn, .hg)",
    brief: "Are /.git/config, /.svn/entries or /.hg/ reachable with a real VCS body?",
    owasp: "WSTG-CONF-04", attackId: "T1552.001",
    what: "GET /.git/HEAD, /.git/config, /.svn/entries, /.svn/wc.db and /.hg/requires. A hit is a finding only when the"
        + "body is a real VCS artifact: /.git/HEAD containing 'ref: refs/heads/' or a 40-hex object id, or /.git/config"
        + "containing the section header '[core]'. Suppress any body matching the catch-all/SPA shell (compare against a"
        + "random path at the same status). Evidence: the matching body line quoted verbatim.",
  },
  {
    id: "WA-030", category: "validation",
    name: "Environment files exposed (.env family)",
    brief: "Does .env, .env.local, .env.production or a .env backup return KEY= lines?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    what: "GET /.env, /.env.local, /.env.production, /.env.staging, /.env.backup and /.env.old. A hit requires a body"
        + "matching an uppercase KEY= value line ('^[A-Z][A-Z0-9_]+=') or a connection string with credentials; a 200"
        + "returning the SPA shell or a marketing page is not the file. Never quote values: quote the key name and mask"
        + "the secret. Evidence: the matched KEY= line, value masked.",
  },
  {
    id: "WA-031", category: "validation",
    name: "Database dump or backup archive exposed",
    brief: "Do dump.sql, backup.zip or db.tar.gz actually return a dump or archive?",
    owasp: "WSTG-CONF-04", attackId: "T1552.001",
    what: "GET backup.sql, dump.sql, db.sql, database.sql, backup.zip, backup.tar.gz, site.zip and www.zip. A hit"
        + "requires a dump/archive signature: '-- MySQL dump' or '-- PostgreSQL database dump' in the leading lines, ZIP"
        + "bytes 50 4B 03 04, or gzip bytes 1F 8B. A 200 text/html shell is the catch-all, not the backup. Evidence: the"
        + "path plus the signature bytes or dump comment.",
  },
  {
    id: "WA-032", category: "validation",
    name: "Framework configuration files serving secrets",
    brief: "wp-config.php, settings.php, database.yml or config.php: real secrets or shell?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    what: "GET /wp-config.php, /wp-config.php.bak, /configuration.php, /settings.php, /config.php, /config/database.yml,"
        + " /config/secrets.yml, /app/config/parameters.yml and /local_settings.py. Confirming evidence: a"
        + "credential-defining line in the body (DB_PASSWORD, AUTH_KEY, 'password:' with a literal, SECRET_KEY=). A login"
        + "form or the SPA shell is not exposure. Quote the key name only, mask the value.",
  },
  {
    id: "WA-033", category: "validation",
    name: "Spring Boot Actuator and management endpoints exposed",
    brief: "Do /actuator/env, /configprops, /heapdump or /health?details leak internals?",
    owasp: "WSTG-CONF-05", attackId: "T1083",
    what: "GET /actuator, /actuator/env, /actuator/configprops, /actuator/beans, /actuator/heapdump, /actuator/mappings,"
        + " /actuator/loggers and the legacy /env, /health. Confirming evidence: JSON carrying actuator keys"
        + "('activeProfiles' and 'propertySources' for env, 'contexts' for configprops) or a heapdump body starting"
        + "'JAVA PROFILE'. /health returning plain 'UP' is informational only. Evidence: the exact JSON key path.",
  },
  {
    id: "WA-034", category: "validation",
    name: "Administrative and database tooling exposed",
    brief: "phpMyAdmin, Adminer, server-status, Jolokia or Tomcat manager reachable?",
    owasp: "WSTG-CONF-05", attackId: "T1083",
    what: "GET /phpmyadmin/, /pma/, /adminer.php, /server-status, /server-info, /nginx_status, /jolokia/ and"
        + " /manager/html. Confirming evidence is the tool's own fingerprint: the phpMyAdmin login form with 'pma_' asset"
        + "paths, the Adminer login form, Apache mod_status 'Server Status' plus 'Total Accesses', or the Tomcat manager"
        + "login realm. Reachable only behind a login is a weaker informational finding. Evidence: the body markers.",
  },
  {
    id: "WA-035", category: "validation",
    name: "Infrastructure files exposed (Dockerfile, compose, kubeconfig, terraform state, .npmrc)",
    brief: "Are Dockerfile, docker-compose.yml, kubeconfig, terraform.tfstate or .npmrc served?",
    owasp: "WSTG-CONF-04", attackId: "T1552.001",
    what: "GET /Dockerfile, /docker-compose.yml, /kubeconfig, /terraform.tfstate, /terraform.tfstate.backup, /.npmrc,"
        + " /.netrc and /.git-credentials. Confirming evidence: the body parses as the artifact - 'FROM ' in the leading"
        + "Dockerfile lines, 'services:' in compose, 'apiVersion: v1' with 'kind: Config' in kubeconfig, a state file with"
        + "a version field, or '_authToken=' in .npmrc. Quote the marker line, mask every token.",
  },
  {
    id: "WA-036", category: "validation",
    name: "API documentation or GraphQL IDE exposed",
    brief: "Is /swagger-ui, /openapi.json, /graphiql or a GraphQL playground served?",
    owasp: "WSTG-APIT-01", attackId: "T1083",
    what: "GET /swagger-ui.html, /swagger-ui/, /openapi.json, /v3/api-docs, /api-docs, /graphiql, /playground and"
        + " /altair. Confirming evidence: JSON with an 'openapi' or 'swagger' version field plus a 'paths' object, or the"
        + "GraphiQL/Playground HTML with its query-editor bundle. This is the discovery handoff: record every declared"
        + "path and security scheme, then feed them to WA-079..WA-084. Evidence: spec version plus a sample path.",
  },
  {
    id: "WA-037", category: "validation",
    name: "Error and debug output discloses internals",
    brief: "Do stack traces, SQL errors or a framework debugger page reach the client?",
    owasp: "WSTG-ERRH-01", attackId: "T1595.002",
    what: "Trigger benign errors (a malformed query value, an unknown path, a body the endpoint parses) and read the"
        + "body: a stack trace with file paths and line numbers, a SQL error string ('SQLSTATE', 'ORA-', 'syntax error at"
        + "or near'), or a Flask/Werkzeug debugger page with 'Traceback (most recent call last)'. Evidence: the quoted"
        + "error line plus the request that produced it; a generic 500 page with no detail is a negative result.",
  },
  {
    id: "WA-038", category: "validation",
    name: "Directory listing or metadata files exposed",
    brief: "Directory indexes, .DS_Store, .htaccess or .gitignore served verbatim?",
    owasp: "WSTG-CONF-04", attackId: "T1083",
    what: "GET /images/, /uploads/, /assets/, /.DS_Store, /.htaccess, /.htpasswd, /.gitignore and /backup/. Confirming"
        + "evidence: an Apache index body 'Index of /' with a 'Parent Directory' link, an autoindex JSON listing, a"
        + ".DS_Store body with the Bud1 magic (42 75 64 31), or .htaccess carrying 'RewriteEngine'/'AuthType'. Probe"
        + "three short dirs, never recursive. Evidence: the index title or the magic bytes.",
  },
  // Block 6 - client-side secrets. Sources: SecScan jsScanner.ts (32 patterns over
  // inline plus up to 8 external JS at 512 KB each, entropy-filtered) and
  // nextjsProbe.ts __NEXT_DATA__ scans; Seclayer staticAnalysis.ts (6 secret
  // signatures, masked display) and credentialChainProbe.ts. Needs a rendered page.
  {
    id: "WA-039", category: "validation",
    name: "Cloud provider credentials in client code",
    brief: "Does served JS carry an AWS AKIA/ASIA key or a GCP service-account block?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    needs: "browser/CDP render for inline script capture",
    what: "Render the page with the browser/CDP harness and capture inline scripts plus up to 8 external scripts (512 KB"
        + "each). Match the jsScanner.ts patterns: AWS access key id 'AKIA'/'ASIA'/'AGPA' plus 16 base32 chars, an AWS"
        + "secret assignment on a nearby line, or a Google service-account JSON with 'type': 'service_account'. Evidence:"
        + "the masked token (first 4 and last 4), the script URL and the surrounding assignment.",
  },
  {
    id: "WA-040", category: "validation",
    name: "Payment provider credentials in client code",
    brief: "Are Stripe sk_live, Paystack or Flutterwave secrets served to the browser?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    needs: "browser/CDP render for inline script capture",
    what: "From the rendered bundle set, match payment-server prefixes: Stripe 'sk_live_'/'rk_live_' (a 'pk_live_'"
        + "publishable key is expected and NOT a finding), Square 'sq0csp-', Paystack 'sk_live_', Flutterwave 'FLWSECK-',"
        + "Razorpay 'rzp_live_'. Evidence: the masked token, the script URL and the fetch call site; a key that only"
        + "appears in a server webhook route never reaches this check.",
  },
  {
    id: "WA-041", category: "validation",
    name: "Source-control or CI token in client code",
    brief: "GitHub PAT, GitLab glpat or npm _authToken shipped in client JS?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    needs: "browser/CDP render for inline script capture",
    what: "Match source-control and CI token prefixes in rendered JS: GitHub 'ghp_'/'gho_'/'ghs_'/'github_pat_', GitLab"
        + "'glpat-', npm '_authToken=', CircleCI/Vercel/Netlify token shapes. Evidence: the masked token prefix and the"
        + "exact script URL. Verify against the provider prefix table only - never call the provider API with the token.",
  },
  {
    id: "WA-042", category: "validation",
    name: "AI provider key shipped to the browser",
    brief: "Is an OpenAI sk-proj, Anthropic sk-ant or Gemini AIza key in client JS?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    needs: "browser/CDP render for inline script capture",
    what: "Match AI provider prefixes in the rendered bundles: OpenAI 'sk-proj-'/'sk-', Anthropic 'sk-ant-', Google"
        + "Gemini 'AIza', Hugging Face 'hf_', Replicate 'r8_', Groq 'gsk_'. Evidence: masked token plus the script URL and"
        + "the endpoint URL fetched from the same bundle, proving browser use. A key passed through a server-side proxy is"
        + "not this finding.",
  },
  {
    id: "WA-043", category: "validation",
    name: "Database or BaaS admin key in client code",
    brief: "Is a Supabase service_role JWT or Firebase admin key in the bundle?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    needs: "browser/CDP render for inline script capture",
    what: "Decode every JWT-shaped string in the rendered bundles and flag a payload whose 'role' claim is 'service_role'"
        + "or 'supabase_admin' (the 'anon' role is public by design and is NOT a finding). Also match a Firebase admin"
        + "service-account JSON ('type': 'service_account') and password-bearing MongoDB/Postgres connection strings."
        + "Evidence: the decoded role claim, the masked JWT and the script URL.",
  },
  {
    id: "WA-044", category: "validation",
    name: "Messaging provider credentials in client code",
    brief: "SendGrid SG., Twilio, Slack xoxb or Mailgun secrets in client JS?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    needs: "browser/CDP render for inline script capture",
    what: "Match messaging prefixes in the rendered bundles: SendGrid 'SG.' plus a URL-safe body, Twilio 'SK' plus 32 hex"
        + "with a nearby auth token, Slack 'xoxb-'/'xoxp-'/'xapp-' and 'hooks.slack.com/services/', Mailgun 'key-', a"
        + "Telegram bot token shaped as digits, colon, 35 chars. Evidence: masked token plus script URL; a send-only key is"
        + "still a secret-exposure finding.",
  },
  {
    id: "WA-045", category: "validation",
    name: "Private key block or hardcoded JWT served to clients",
    brief: "Does served JS embed a PEM private key or a hardcoded bearer JWT?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    needs: "browser/CDP render for inline script capture",
    what: "Search the rendered bundles for a PEM header ('-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN EC PRIVATE"
        + "KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----') followed by a base64 key body, and for JWT triples whose"
        + "payload decodes to a real identity ('sub', 'iss', 'role'). A long-lived hardcoded bearer JWT is the finding."
        + "Evidence: the PEM header line or the decoded claims, signature masked.",
  },
  {
    id: "WA-046", category: "validation",
    name: "Hardcoded password or generic high-entropy secret",
    brief: "apiKey=, password= or secret= assigned a literal in client code?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    needs: "browser/CDP render for inline script capture",
    what: "Scan the rendered bundles for assignment patterns: apiKey/apikey/secret/token/password/api_secret assigned a"
        + "quoted literal of 16+ chars, plus high-entropy strings (Shannon above 4.0, 32+ chars) not already matched by a"
        + "provider prefix. Apply the 512 KB cap and entropy filter from jsScanner.ts. Evidence: the masked value, the"
        + "enclosing assignment and the script URL.",
  },
  {
    id: "WA-047", category: "validation",
    name: "Internal addresses or environment dump in client code",
    brief: "Internal hostnames, 10/8 or 192.168 addresses, or a full env dump in JS?",
    owasp: "WSTG-CONF-02", attackId: "T1552.001",
    needs: "browser/CDP render for inline script capture",
    what: "Match infrastructure hints in rendered JS: 10.x, 172.16-31.x and 192.168.x addresses, 'localhost:' with a"
        + "port, '.internal'/'.local'/'.corp' hostnames, and a stringified environment object holding several KEY:'value'"
        + "pairs (a process.env dump). Evidence: the address or hostname plus the script URL. A public API host is not"
        + "this finding.",
  },
  // Block 7 - SCA / CVE. Sources: SecScan cveCheck.ts (OSV.dev CVE plus PHP/Apache/
  // Nginx EOL lookup) per SCAN_COVERAGE.md module 5; Seclayer staticAnalysis.ts SCA
  // (jQuery <3.5.0, Bootstrap 3.x, AngularJS 1.x, Lodash <4.17.21 signatures).
  {
    id: "WA-048", category: "validation",
    name: "Vulnerable jQuery version loaded",
    brief: "Is a jQuery below 3.5.0 loaded from a script tag?",
    owasp: "WSTG-INFO-02", attackId: "T1518",
    what: "Parse every script src and match a jQuery version from the URL or a bundle banner ('jQuery v1.12.4'):"
        + "versions below 3.5.0 are affected by CVE-2020-11022 and CVE-2020-11023 (XSS via .html()). Evidence: the exact"
        + "version string and the script URL; a stylesheet or an unversioned filename is not this finding. Hand the version"
        + "to WA-052.",
  },
  {
    id: "WA-049", category: "validation",
    name: "Vulnerable Bootstrap 3.x loaded",
    brief: "Does the page load Bootstrap 3.x (EOL, CVE-2019-8331)?",
    owasp: "WSTG-INFO-02", attackId: "T1518",
    what: "Match the JavaScript bundle (bootstrap.js/bootstrap.min.js) or a banner 'Bootstrap v3.x.x'. Bootstrap 3.x is"
        + "end-of-life and affected by CVE-2019-8331 (tooltip/popover XSS). A CSS-only link is not enough - the script"
        + "must load. Evidence: the version string plus the script URL; hand the pair to WA-052 for the CVE sweep.",
  },
  {
    id: "WA-050", category: "validation",
    name: "End-of-life AngularJS loaded",
    brief: "Is an AngularJS 1.x build loaded and therefore end-of-life?",
    owasp: "WSTG-INFO-02", attackId: "T1518",
    what: "Match 'angular.js'/'angular.min.js' script tags carrying a 1.x version, or an 'ng-app' body marker with"
        + "'angular.version.full' visible in the served bundle. AngularJS 1.x reached end-of-life in January 2022 - no"
        + "security support at any 1.x version. Evidence: the version string and script URL.",
  },
  {
    id: "WA-051", category: "validation",
    name: "Vulnerable Lodash version loaded",
    brief: "Is a Lodash below 4.17.21 loaded?",
    owasp: "WSTG-INFO-02", attackId: "T1518",
    what: "Match 'lodash.js'/'lodash.min.js' script tags with a version, or a banner 'lodash 4.x.x'. Versions below"
        + "4.17.21 are affected by CVE-2019-10744 (prototype pollution), CVE-2020-8203 and CVE-2021-23337 (command"
        + "injection in template). Evidence: the version string and script URL; record whether the bundle exposes '_' on"
        + "window.",
  },
  {
    id: "WA-052", category: "logic",
    name: "Library version matched to known CVEs and end-of-life dates",
    brief: "Do the harvested library versions map to real CVE and EOL records?",
    owasp: "WSTG-INFO-02", attackId: "T1518",
    needs: "nuclei binary for template-driven CVE sweep",
    what: "Resolve the library/version pairs from WA-048..WA-051 against OSV.dev and end-of-life dates, then run the"
        + "nuclei template sweep for the matched CVEs. Evidence: an advisory id printed beside the observed version with a"
        + "matching affected range; a version outside every affected range is a recorded negative, not a finding.",
  },
];
