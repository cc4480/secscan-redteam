# The Web Application Battery (WA-*) - the opt-in fifth target (v0.35.0)

The red team's battery family for a **client's own web application**: 120
attack items, `WA-001`...`WA-120`, each one a distinct attacker intent with a
concrete request, flow or parameter and the exact evidence that proves it.
Not a sample and not a representative subset - every check the two scanner
products perform against a customer site, encoded as an executable intent.

It is a **fifth target, and it is opt-in**. The four vendor batteries
(SS-*, SL-*, WS-*, LX-*) and the 418-item full-battery contract are unchanged.
`webapp` is registered in `ALL_TARGETS` but deliberately left out of
`FULL_BATTERY_TARGETS`, so a full-battery engagement against secscan.us /
seclayer.app never carries it by accident. It runs only when selected:

- CLI: `--targets webapp` (optionally `--targets webapp,windows` for a client
  app plus its Windows host).
- Harness / MCP: `start_engagement` with `targets: ["webapp"]` - the tool now
  accepts a `targets` array for exactly this purpose.
- `http_probe` also accepts `targetProfile: "webapp"`, and an unknown host
  infers to the `webapp` profile (`/api/mcp` still infers to seclayer).

## How it differs from SS-* and SL-*

The two product batteries answer a different question:

- **SS-001...SS-120** test `secscan.us` itself: URL-intake type juggling, the
  SSRF guard, the DNS TXT ownership gate, the scan lifecycle, report/share
  IDOR, MCP framing, API-key handling, rate limits, and the planted-canary
  efficacy cluster.
- **SL-001...SL-080** test `seclayer.app` itself: the MCP handshake and every
  tool with every parameter attacked individually, JSON-RPC framing, auth per
  method, and the scanner's own API surface.

They answer "is our product secure and accurate?". **WA-* answers "what does
an agent do when it attacks a customer's application?"** - headers, TLS, DNS
and mail posture, exposed files, client-side secrets, injection, access
control, APIs, BaaS, AI features, business logic, and coverage honesty on a
target the operator is authorized to test. Mixing the two questions in one
family would blur the report, so WA is a separate target with a separate
profile (`kind: "webapp"`), not a relabelled SS/SL item.

## The numbers

- **120 attack items** (`WA-001`...`WA-120`): validation 72, logic 41,
  functionality 7. All three categories are non-empty, so a webapp-only run
  produces the usual **3 categories x 1 target = 3 coverage cells**.
- **19 blocks** (table below), authored in five part files
  (`runner/src/targets/webapp-part-1.ts` ... `webapp-part-5.ts`, assembled by
  `runner/src/targets/webapp.ts`).
- **41 items carry an honest prerequisite** - 17 distinct `needs` values,
  listed below. The rest need nothing beyond scope and network reachability.
- `TOTAL_BATTERY_ITEMS` stays **418**; the contract count for the new target
  is `BATTERY_ITEM_COUNTS.webapp = 120`, and a webapp-only item ledger has
  exactly 120 entries.

## The 19 blocks

| # | Block | Items | Ids | Executed by |
|---:|---|---:|---|---|
| 1 | Headers and cookie flags | 11 | WA-001..WA-011 | `http_probe` |
| 2 | TLS / transport | 7 | WA-012..WA-018 | `http_probe`, `nmap_exec` (ssl-cert / ssl-enum-ciphers) |
| 3 | DNS and email authentication | 7 | WA-019..WA-025 | `http_probe` (DNS-over-HTTPS JSON queries) |
| 4 | Mail transport | 3 | WA-026..WA-028 | `nmap_exec` SMTP scripts; needs port 25 egress |
| 5 | Exposed files and templates | 10 | WA-029..WA-038 | `ffuf_exec`, `gobuster_exec`, `nikto_exec`, `nuclei_exec` templates |
| 6 | Client-side secrets | 9 | WA-039..WA-047 | CDP browser (rendered/inline script capture), `http_probe` for markup |
| 7 | SCA / CVE / end-of-life | 5 | WA-048..WA-052 | `nuclei_exec` (CVE templates), `msf_exec` for CVE validation |
| 8 | Injection | 11 | WA-053..WA-063 | `http_probe`, `sqlmap_exec` (deep SQLi confirmation) |
| 9 | XXE and SSRF | 4 | WA-064..WA-067 | `http_probe`; OAST collaborator for blind confirmation |
| 10 | Access control | 6 | WA-068..WA-073 | `http_probe` |
| 11 | JWT and session tokens | 5 | WA-074..WA-078 | `http_probe` |
| 12 | API surface | 6 | WA-079..WA-084 | `http_probe`, `sqlmap_exec` (API SQLi) |
| 13 | BaaS and storage | 5 | WA-085..WA-089 | `http_probe` |
| 14 | Cloud and perimeter | 7 | WA-090..WA-096 | `http_probe`, `nmap_exec`, `gobuster_exec` (dns) |
| 15 | Client-side trust | 6 | WA-097..WA-102 | CDP browser for DOM execution, `http_probe` for markup |
| 16 | AI feature abuse | 5 | WA-103..WA-107 | `http_probe` |
| 17 | Business logic | 4 | WA-108..WA-111 | `http_probe`, `burst_probe` (rate-limit shape) |
| 18 | Supplied-repository SAST | 5 | WA-112..WA-116 | none - operator-supplied repository review; `needs: GitHub repository supplied` |
| 19 | Coverage honesty | 4 | WA-117..WA-120 | none - report and coverage content, no new traffic |

The 19 blocks sum to **120 items**, in id order, with no gaps and no
duplicates (the file-budget test and the item ledger both enforce this).

Execution follows the same rule as the rest of the battery: the block name is
the *intent*, the right-hand column is the *channel* that can actually carry
it. Every WA item is an intent plus an evidence requirement - never a shell
command. The runner still owns the command line: profiles, argv, scope and
policy are built runner-side, so nothing from the model reaches a shell, and
DNS-over-HTTPS / TLS / SMTP posture checks are subject to the same in-scope
host rule as any other probe.

## Prerequisites (`needs`)

Items whose prerequisite is absent are reported under Honest limits with the
exact text below - never as passed, and never silently dropped.

| `needs` value | What it unlocks | Items |
|---|---|---|
| `port 25 egress from the runner host` | outbound SMTP conversation (banner, EHLO/STARTTLS, MX certificate) | WA-026, WA-027, WA-028 |
| `browser/CDP render for inline script capture` | headless page render, so inline and runtime-generated scripts can be scanned for secrets | WA-039..WA-047 |
| `browser/CDP render` | headless execution of a client-side sink for DOM-based XSS | WA-055 |
| `second test account to view the stored value` | a second identity that can observe a stored payload | WA-054 |
| `second test account` | a second identity for cross-account object access (BOLA) | WA-069 |
| `OAST collaborator for out-of-band callback confirmation` | external callback collector proving blind XXE and blind SSRF | WA-064, WA-066 |
| `nuclei binary for template-driven CVE sweep` | nuclei binary plus templates for library CVE matching | WA-052 |
| `nmap binary` | port/service sweep for high-risk exposed services | WA-093 |
| `a bearer JWT observed or supplied` | a current session token to decode, mutate and replay | WA-074..WA-077 |
| `authorized test login credentials` | an authenticated session for session-token, CSRF and price checks | WA-078, WA-097, WA-108 |
| `client-side Supabase key discovered` | a Supabase anon/service key found in client code | WA-085, WA-086, WA-087 |
| `client-side Firebase config discovered` | a Firebase project config found in client code | WA-088 |
| `client-side credential discovered` | any client-side credential to chain into backend access | WA-091 |
| `AI endpoint or key observed in client code` | a discovered AI endpoint or provider key | WA-103, WA-104 |
| `AI endpoint discovered` | a confirmed AI-backed endpoint to probe | WA-105, WA-107 |
| `AI endpoint discovered; OAST collaborator` | both of the above, for tool-use SSRF | WA-106 |
| `GitHub repository supplied` | the customer repository handed to the engagement for SAST | WA-112..WA-116 |

That is 41 items across 17 distinct prerequisites. The prerequisite text is
rendered verbatim in the report, so an operator can see exactly what to
provision to turn a blocked item into an executable one.

## Evidence discipline

WA inherits the runner's proof model and adds the two-tier evidence rule the
corpus was written to (the Seclayer `confirmed-evidence-spec.md` discipline):

- **A confirmation is receipt-backed.** `record_finding` requires two
  independent observations, and `get_proof` bundles the receipt: the canary
  token that was sent and echoed back, the quoted response substring, or the
  audit-log derivation already in the step ledger. "The response was 200" is
  never proof on its own.
- **An absence claim is negative evidence, not a confirmation.** "No rate
  limiting observed in N attempts", "no X-Frame-Options in the header block",
  "the cookie is not flagged Secure" are recorded through the negative ledger
  (`record_killed`-style evidence) and reported as **NEEDS VERIFICATION** in
  the item verdict. They are never marked CONFIRMED.
- **The item text names the evidence.** Every `what` states the concrete
  request or flow and the literal proof required (a quoted header block, a
  status/body differential against a control, a callback token, a decoded JWT
  claim block) so a reviewer can reproduce the finding.
- **Non-destructive by construction.** No request whose success changes
  customer data. BaaS write probes are dry runs (`Prefer: tx=rollback`-style),
  DELETE is only ever aimed at identifiers that cannot exist, and PUT is never
  used. Races are single paired requests, not load tests.

## Provenance

The corpus is derived from the two scanner engines, not invented:

- **SecScan** - `cc4480/VibeScan-Enterprise-Build` (the engine behind
  secscan.us). Local inventories: `SECSCAN_INVENTORY.md` (352 findings, 129
  check types) and `SECSCAN_FINDING_INDEX.md` (all findings by module,
  severity, CWE and WSTG).
- **Seclayer** - `cc4480/seclayer.io2026`. Local inventory:
  `SECLAYER_INVENTORY.md` (77 findings, ~60 check types, 60-template exposure
  pack, receipt-backed evidence discipline).

The overlap analysis that produced the block list lives in
`REDTEAM_BATTERY_ALIGNMENT.md`: the 13 check areas both products implement
(headers, exposure, TLS, XSS/SQLi, SSTI/LFI/redirect/CRLF/CORS/XXE/NoSQL,
JWT, source maps and client secrets, GraphQL, BOLA, bucket listing, vulnerable
libraries, deserialization/CSRF, rate limiting) are imported once, and the
areas only one product has are imported from that product. Each block in
`webapp-part-N.ts` carries a comment naming the source modules it came from
(for example "SecScan SCAN_COVERAGE.md M14; Seclayer tlsProbe.ts"), so every
WA item is answerable to an inventory entry. No item was added that the
inventories cannot source.

## Honest limits

- **Items without a tool report blocked.** When a prerequisite is absent - a
  CDP browser session, port 25 egress, a second test account, an OAST
  collaborator, the supplied repository - the item carries its `needs` text
  and is reported as BLOCKED under Honest limits. It is never faked as tested
  and never quietly marked executed-clean. This is the same contract the
  existing 418 items live under.
- **No new binaries in v1.** WA reuses `http_probe` / `burst_probe`,
  `nmap_exec`, `nuclei_exec`, `sqlmap_exec`, `ffuf_exec`, `gobuster_exec`,
  `nikto_exec`, `msf_exec` and the CDP browser. A first-party OOB
  collaborator, a JWT forger, a BaaS prober and a headless DOM-XSS runner are
  a later track; until then their items say so in `needs`.
- **No scan-credit dependency.** WA does not require the SecScan MCP scan
  service. A `scan_url` cross-check is optional and only used when the
  operator has a scan credit and wants a second opinion on a block - the
  battery itself is runner-executed.
- **ATT&CK mappings are advisory.** Web flaw classes map imperfectly onto an
  endpoint/intrusion framework; where no technique honestly fits, the WSTG
  reference in the item stands alone. The corpus is constrained to attack ids
  that already map to compliance controls, so no WA item weakens the
  compliance pack.

See [full-battery.md](full-battery.md) for how WA fits the four-target
engagement, [attack-batteries.md](attack-batteries.md) for the per-surface
attack menu, [coverage.md](coverage.md) for the per-item verdict contract, and
[proof.md](proof.md) for the evidence model.
