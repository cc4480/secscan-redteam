/**
 * WEBAPP battery - part 1 of 7 (v0.36.0 split).
 * Blocks 1-4: headers & cookies (WA-001..WA-011), TLS / transport (WA-012..WA-018),
 * DNS & email authentication (WA-019..WA-025), mail transport (WA-026..WA-028).
 *
 * Provenance: the corpus derives from the SecScan and Seclayer catalogues
 * (SECSCAN_INVENTORY.md modules M1/M3/M14/M19; SECLAYER_INVENTORY.md 4.1-4.4).
 * Assembled by webapp.ts.
 */

import type { TargetBatteryItem } from "./types.js";

export const WEBAPP_PART_1: TargetBatteryItem[] = [
  // Block 1 - headers & cookies. Sources: SecScan SCAN_COVERAGE.md M1 (scannerHeaderChecks,
  // scannerCspChecks, scannerCookies); Seclayer findings.ts buildHeaderFindings/buildCookieFindings.
  {
    id: "WA-001", category: "validation", name: "Content-Security-Policy absent or report-only",
    brief: "No enforcing CSP on the root document - header absent, or report-only only?",
    owasp: "WSTG-CONF-12", attackId: "T1595.002",
    what: "GET the target root with http_probe and record the exact response header block. Absent CSP plus absent "
        + "CSP-Report-Only is the finding; a report-only policy is the separate weaker case (the browser reports the "
        + "violation and executes the script anyway). Suppress absent-CSP only when a <meta http-equiv="
        + "Content-Security-Policy> directive is present in the body. Evidence: quote the header block verbatim; for "
        + "report-only quote the Content-Security-Policy-Report-Only line.",
  },
  {
    id: "WA-002", category: "validation", name: "CSP allows unsafe-inline or unsafe-eval",
    brief: "CSP present but weakened by an unsafe-inline or unsafe-eval token?",
    owasp: "WSTG-CONF-12", attackId: "T1595.002",
    what: "GET the root and every cached HTML response with http_probe; parse the enforcing CSP value only "
        + "(ignore report-only). The finding is the literal token 'unsafe-inline' or 'unsafe-eval' in script-src, "
        + "default-src, or an inherited source list: unsafe-eval removes the eval barrier, unsafe-inline permits a "
        + "reflected payload. Evidence: quote the exact CSP value and the matching directive; note a nonce or hash "
        + "that is also present, because in CSP2+ the token makes the policy browser-dependent and the weaker "
        + "reading is the honest one.",
  },
  {
    id: "WA-003", category: "validation", name: "HSTS absent, short max-age, or missing includeSubDomains",
    brief: "Strict-Transport-Security missing, max-age too short, or no includeSubDomains?",
    owasp: "WSTG-CONF-07", attackId: "T1595.002",
    what: "GET the root over HTTPS with http_probe and quote the Strict-Transport-Security line. Findings in "
        + "order: header absent on an HTTPS host (and no http:// -> https:// 301 on a plaintext request); "
        + "max-age below 15552000 (180 days); includeSubDomains absent on an apex domain that also serves "
        + "subdomains. Evidence: the verbatim header value, plus one http:// GET showing whether the redirect to "
        + "https is enforced at all.",
  },
  {
    id: "WA-004", category: "validation", name: "Clickjacking exposure: no X-Frame-Options and no frame-ancestors",
    brief: "Neither X-Frame-Options nor CSP frame-ancestors protects the page from framing?",
    owasp: "WSTG-CLNT-09", attackId: "T1595.002",
    what: "GET the root and one authenticated page if a session exists, with http_probe; quote the "
        + "X-Frame-Options line and the CSP frame-ancestors directive. Finding when XFO is absent, invalid, or "
        + "ALLOW-FROM (a dead directive modern browsers ignore) AND frame-ancestors is absent or allows * or an "
        + "attacker origin. Evidence: both header lines verbatim; a page protected only by SAMEORIGIN is reported "
        + "separately, since same-site framing remains possible.",
  },
  {
    id: "WA-005", category: "validation", name: "X-Content-Type-Options missing",
    brief: "No nosniff token, so MIME sniffing can turn an upload into script?",
    owasp: "WSTG-CONF-12", attackId: "T1595.002",
    what: "GET the root and one static asset the page references (image, JS, or CSS) with http_probe. Finding "
        + "when x-content-type-options is absent or is any value other than the exact token nosniff. Evidence: "
        + "quote the header line verbatim, and for the absent case quote the whole header block so the missing "
        + "line is itself the evidence - never a status code.",
  },
  {
    id: "WA-006", category: "validation", name: "Referrer-Policy header missing",
    brief: "No Referrer-Policy, or an unsafe one such as unsafe-url?",
    owasp: "WSTG-CONF-12", attackId: "T1595.002",
    what: "GET the root and a login or error page with http_probe. Finding when Referrer-Policy is absent or set "
        + "to unsafe-url / no-referrer-when-downgrade, which leak the full URL (including path and query tokens) "
        + "to every third party the page loads. Evidence: quote the header line; when absent quote the full header "
        + "block, and record any <meta name=referrer> fallback found in the body.",
  },
  {
    id: "WA-007", category: "validation", name: "Permissions-Policy header missing",
    brief: "No Permissions-Policy, so camera, mic, geolocation stay at their default allowlists?",
    owasp: "WSTG-CONF-12", attackId: "T1595.002",
    what: "GET the root with http_probe. Finding when Permissions-Policy (and legacy Feature-Policy) is absent, "
        + "leaving camera, microphone, geolocation, USB and payment at their default allowlists so any embedded "
        + "or hijacked frame on the same origin retains access. Evidence: quote the header block for the absent "
        + "case; when present quote the directive list and name every sensitive feature left unset.",
  },
  {
    id: "WA-008", category: "validation", name: "Cross-origin isolation headers missing (COOP, COEP, CORP)",
    brief: "No COOP, COEP or CORP - cross-origin windows and resources stay reachable?",
    owasp: "WSTG-CONF-12", attackId: "T1595.002",
    what: "GET the root plus one cross-origin script or stylesheet URL that the page references, with http_probe. "
        + "Findings: no Cross-Origin-Opener-Policy: same-origin (window.opener and XS-Leak style reads stay "
        + "reachable); no Cross-Origin-Embedder-Policy: require-corp; and a resource served with neither "
        + "Cross-Origin-Resource-Policy nor a CORS grant, so any origin may embed it. Evidence: quote each of the "
        + "three header lines, or the header block proving each one absent.",
  },
  {
    id: "WA-009", category: "logic", name: "CORS wildcard or reflected origin with credentials",
    brief: "Does a foreign Origin come back reflected, or ACAO * sit beside ACAC true?",
    owasp: "WSTG-CLNT-11", attackId: "T1190",
    what: "Send GET on the root and one API path with http_probe twice: once with "
        + "Origin: https://<unrelated-canary-host>, once with Origin: null. Findings: Access-Control-Allow-Origin "
        + "echoing the supplied origin, or ACAO * together with Access-Control-Allow-Credentials: true. Probe a "
        + "suffix trick too (https://target.example.<canary-host>) against naive startsWith/endsWith checks. "
        + "Evidence: quote the ACAO, ACAC and Vary: Origin lines from both responses as a differential. Never "
        + "follow up with a credentialed request from a real user.",
  },
  {
    id: "WA-010", category: "validation", name: "Session cookie missing the Secure flag",
    brief: "Does any session cookie cross a plaintext request because Secure is absent?",
    owasp: "WSTG-SESS-02", attackId: "T1595.002",
    what: "GET the root, the login page, and any 302 in the flow with http_probe; evaluate every Set-Cookie line "
        + "separately (a correctly flagged cookie must not mask another). Finding: a session or auth cookie "
        + "without the Secure attribute on an HTTPS host, so the token can travel over a plaintext request. "
        + "Evidence: quote the full Set-Cookie line verbatim including Path, Domain and Max-Age.",
  },
  {
    id: "WA-011", category: "validation", name: "Cookie missing HttpOnly or SameSite",
    brief: "Per Set-Cookie line: JS-readable session cookie, or no SameSite attribute?",
    owasp: "WSTG-SESS-02", attackId: "T1595.002",
    what: "Read each Set-Cookie line from the root and login responses separately with http_probe. Findings per "
        + "line: a session/auth cookie without HttpOnly (document.cookie readable, so any XSS steals it), and "
        + "without SameSite (attribute absent, or SameSite=None with no Secure). Evidence: quote the Set-Cookie "
        + "line and state the cookie's classification (session/auth vs analytics/preference), because "
        + "non-session cookies are deliberately not reported.",
  },
  // Block 2 - TLS / transport. Sources: SecScan SCAN_COVERAGE.md M14 (TLS configuration,
  // thresholds 14 days / RSA 2048 / EC 224 / SHA-1); Seclayer tlsProbe.ts (expiry, deprecation).
  {
    id: "WA-012", category: "validation", name: "TLS 1.0 or 1.1 still accepted",
    brief: "Do deprecated protocol versions complete a handshake on 443?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Handshake against host:443 pinning each protocol version separately (openssl s_client -tls1 and "
        + "-tls1_1), then run TLS1.2 and TLS1.3 as the control so a dead host is not mistaken for a hardened one. "
        + "Acceptance is a completed handshake printing 'Protocol : TLSv1' or 'TLSv1.1'; a protocol_version alert "
        + "means refused. Evidence: quote the Protocol and Cipher lines from each attempt.",
  },
  {
    id: "WA-013", category: "validation", name: "TLS certificate expired or not yet valid",
    brief: "Are the leaf certificate's notBefore/notAfter outside the current window?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Perform the TLS handshake to host:443 and read the leaf certificate's dates (openssl s_client | openssl "
        + "x509 -noout -dates). Expired when notAfter is in the past; not yet valid when notBefore is in the "
        + "future. Evidence: quote the notBefore and notAfter lines plus the subject and issuer lines, and state "
        + "the comparison date used, so the finding is reproducible.",
  },
  {
    id: "WA-014", category: "validation", name: "TLS certificate expiring soon",
    brief: "Under 14 days of certificate lifetime left?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Compare the leaf certificate's notAfter from the handshake against the scan date. Finding at fewer "
        + "than 14 days remaining (the SecScan M14 and Seclayer tlsProbe threshold). Evidence: quote notAfter and "
        + "state the exact days remaining, so the report shows a countdown rather than the word 'soon'.",
  },
  {
    id: "WA-015", category: "validation", name: "TLS certificate does not cover the host",
    brief: "Is the engagement hostname outside the certificate's SAN set?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Complete the handshake, then read the leaf certificate's Subject Alternative Name extension and CN "
        + "(openssl x509 -noout -ext subjectAltName). Finding when the engagement hostname matches no dNSName SAN "
        + "- CN alone no longer counts in modern clients - and when a wildcard covers only one label, so "
        + "*.example.com does not match a.b.example.com. Evidence: quote the SAN extension verbatim and name the "
        + "mismatch.",
  },
  {
    id: "WA-016", category: "validation", name: "Self-signed or untrusted certificate chain",
    brief: "Self-signed leaf, unknown root, or an incomplete intermediate chain?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Run the handshake with chain verification against the runner trust store (openssl s_client "
        + "-verify_return_error) and record the 'verify error' output. Findings: self-signed leaf (issuer equals "
        + "subject), unknown CA root, or an incomplete chain ('unable to get local issuer certificate' with the "
        + "intermediate missing from the served chain). Evidence: the verify error text and each subject/issuer "
        + "pair in the chain. An incomplete chain is a separate Medium finding from a bad root.",
  },
  {
    id: "WA-017", category: "validation", name: "Weak key size or weak signature algorithm",
    brief: "RSA under 2048, EC under 224, or a SHA-1/MD5 signature?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "From the leaf certificate read the public key algorithm and size plus the signature algorithm "
        + "(openssl x509 -noout -text). Findings: RSA below 2048 bits, EC below 224 bits, or a SHA-1 or MD5 "
        + "signature. Evidence: quote the 'Public-Key: (N bit)' line, the 'Signature Algorithm' line, and the "
        + "exact bit count and hash name, not a paraphrase.",
  },
  {
    id: "WA-018", category: "validation", name: "Weak cipher suite or no forward secrecy",
    brief: "Are RC4/DES/NULL/EXPORT/anon suites accepted, or no ECDHE/DHE negotiated?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Enumerate accepted suites by handshaking with each class pinned (openssl s_client -cipher for RC4, "
        + "DES/3DES, NULL, EXPORT, aNULL and MD5-MAC; -ciphersuites for TLS1.3). Findings: any of those classes "
        + "accepted, or no ECDHE/DHE suite negotiated on TLS1.2 and below (no forward secrecy). Evidence: quote "
        + "each Protocol : Cipher pair from every handshake that completed, including the control modern suite.",
  },
  // Block 3 - DNS & email authentication. Sources: SecScan SCAN_COVERAGE.md M3 (Cloudflare DoH,
  // SPF/DMARC/DKIM/DNSSEC thresholds); Seclayer perimeter.ts (A/NS resolution).
  {
    id: "WA-019", category: "validation", name: "SPF record absent",
    brief: "No v=spf1 TXT record at the apex, so receivers have no sender authorization?",
    owasp: "WSTG-CONF-02", attackId: "T1590.002",
    what: "Query the apex TXT records through DNS-over-HTTPS (Cloudflare DoH JSON API, type=TXT) with the runner "
        + "resolver as a control. Finding: no TXT record beginning 'v=spf1'. Evidence: quote the complete TXT "
        + "answer set returned; for the absent case quote the full answer section showing only unrelated records, "
        + "and note whether an MX exists (no MX lowers the severity under SecScan M3).",
  },
  {
    id: "WA-020", category: "logic", name: "SPF record authorizes any sender (+all)",
    brief: "Does the SPF policy end in +all, authorizing every host on the internet?",
    owasp: "WSTG-CONF-02", attackId: "T1590.002",
    what: "Read the 'v=spf1' record and inspect its final term. Finding: a '+all' mechanism (every host "
        + "authorized) at any position, including a '+all' made unreachable only by an earlier all - which "
        + "receiver implementations resolve differently. Evidence: quote the full TXT record verbatim and isolate "
        + "the terminal mechanism token; judge an include:-ed '+all' in the included record's own lookup, not in "
        + "the parent record.",
  },
  {
    id: "WA-021", category: "logic", name: "SPF neutral policy or DNS lookup limit exceeded",
    brief: "?all (asserts nothing) or more than 10 DNS-querying mechanisms (permerror)?",
    owasp: "WSTG-CONF-02", attackId: "T1590.002",
    what: "Read the SPF record and walk its include:, redirect=, a, mx, ptr and exists mechanisms with DoH "
        + "queries, counting DNS lookups. Findings: a '?all' terminal (explicitly neutral, so SPF asserts "
        + "nothing about the sender) or more than 10 DNS-querying mechanisms, which makes receivers return "
        + "permerror and discard the whole policy. Evidence: quote the record plus the enumerated include chain "
        + "with the counted lookup total.",
  },
  {
    id: "WA-022", category: "validation", name: "DMARC record absent",
    brief: "Is there no v=DMARC1 record at _dmarc.<domain>?",
    owasp: "WSTG-CONF-02", attackId: "T1590.002",
    what: "Query _dmarc.<domain> TXT via DNS-over-HTTPS. Finding: no record beginning 'v=DMARC1' at that exact "
        + "name - a record on a parent or organisational domain does not cover this host unless sp= applies, and "
        + "a record at the wrong name is a distinct subdomain-policy finding. Evidence: quote the full DoH answer "
        + "block including an NXDOMAIN or empty-answer response, with the organisational-domain record as the "
        + "control.",
  },
  {
    id: "WA-023", category: "logic", name: "DMARC policy is monitoring-only (p=none)",
    brief: "p=none, or pct below 100, so a failing message still lands in the inbox?",
    owasp: "WSTG-CONF-02", attackId: "T1590.002",
    what: "Read the v=DMARC1 record from _dmarc.<domain>. Finding: p=none (receivers report but take no action "
        + "on a message that fails alignment, so spoofed mail is delivered). Also quote pct= when below 100 (only "
        + "that share of failing mail is actioned) and note an absent rua= (no reporting backlog exists). "
        + "Evidence: quote the full record verbatim and name the exact policy tag values.",
  },
  {
    id: "WA-024", category: "validation", name: "DKIM selectors return no key",
    brief: "Do the common selectors return no v=DKIM1 key, or a revoked empty p=?",
    owasp: "WSTG-CONF-02", attackId: "T1590.002",
    what: "Query the common selectors' TXT records at <selector>._domainkey.<domain> (default, google, "
        + "selector1, selector2, s1, s2, mail, k1, dkim) via DoH. Finding: no selector returns a record carrying "
        + "v=DKIM1 and a non-empty p= base64 key; an empty p= is a revoked key and is also a finding. Evidence: "
        + "quote each queried FQDN with its answer. Suppress when DMARC already enforces, since the key may live "
        + "on a selector not in this probe set.",
  },
  {
    id: "WA-025", category: "validation", name: "DNSSEC not enabled",
    brief: "No DS at the parent, so spoofed DNS answers cannot be detected?",
    owasp: "WSTG-CONF-02", attackId: "T1590.002",
    what: "Query the DS record at the parent zone and the DNSKEY at the apex via DoH, and record the AD flag on "
        + "a validating query. Finding: no DS at the parent, so the zone is unsigned and no record above can be "
        + "integrity-checked. Evidence: quote the DS answer, the DNSKEY answer, and the AD flag value; a DS with "
        + "a missing DNSKEY is a broken chain, a separate finding.",
  },
  // Block 4 - mail transport. Sources: SecScan SCAN_COVERAGE.md M19 (port 25 SMTP conversation:
  // no STARTTLS, MX cert expired, MX cert expiring under 21 days).
  {
    id: "WA-026", category: "validation", name: "Mail exchanger does not advertise STARTTLS",
    brief: "Does the MX EHLO capability list omit 250-STARTTLS, exposing mail in cleartext?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Resolve the domain's MX hosts, then open a port 25 SMTP conversation to each: read the 220 banner, "
        + "send 'EHLO <runner-fqdn>', and quote the multiline capability response. Finding: no 250-STARTTLS line "
        + "in the EHLO capabilities, so mail to that host crosses the internet in cleartext. Evidence: the banner "
        + "line and the full EHLO response verbatim. Requires port 25 egress from the runner host; "
        + "non-destructive - EHLO only, no MAIL FROM and no message body.",
    needs: "port 25 egress from the runner host",
  },
  {
    id: "WA-027", category: "validation", name: "Mail exchanger TLS certificate expired",
    brief: "Is the MX certificate's notAfter already in the past?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "After EHLO and a STARTTLS upgrade on port 25, complete the TLS handshake and read the MX "
        + "certificate's notBefore and notAfter. Finding: notAfter in the past on any MX host, which leaves mail "
        + "to that host in cleartext or bounced by senders that enforce TLS. Evidence: quote the dates, the MX "
        + "hostname, and the issuing CA. Requires port 25 egress from the runner host; handshake-only, no message "
        + "is ever sent.",
    needs: "port 25 egress from the runner host",
  },
  {
    id: "WA-028", category: "validation", name: "Mail exchanger TLS certificate expiring soon",
    brief: "Under 21 days left on any MX certificate?",
    owasp: "WSTG-CRYP-01", attackId: "T1595.002",
    what: "Same STARTTLS handshake on port 25; compare each MX certificate's notAfter against the scan date. "
        + "Finding at fewer than 21 days remaining (the SecScan M19 threshold for MX certificates). Evidence: "
        + "quote notBefore and notAfter, the MX hostname, and the computed days remaining per MX, because MXs "
        + "sometimes share a certificate and sometimes do not. Requires port 25 egress from the runner host.",
    needs: "port 25 egress from the runner host",
  },
];
