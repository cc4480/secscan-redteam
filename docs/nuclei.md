# Nuclei bridge (v0.21.0) — template-based checks

Competitors reach "tens of thousands of attacks" largely via template
libraries. The Nuclei bridge gives the runner the same reach —
ProjectDiscovery Nuclei's ~10,000+ community templates, resolved at
runtime from the operator's local checkout, never hardcoded — with the
runner's safety discipline and honest counting.

## Operator setup (fail closed otherwise)

1. Install nuclei: https://github.com/projectdiscovery/nuclei/releases
   (or `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`).
2. **As the operator, before any engagement:** `nuclei -update-templates`
   Template updates NEVER run mid-engagement.
3. Optionally set in the environment / Secure Vault:
   - `REDTEAM_NUCLEI_BIN` — explicit binary path (else `nuclei` on PATH)
   - `REDTEAM_NUCLEI_TEMPLATES` — template directory override
   - `REDTEAM_NUCLEI_TIMEOUT_S` — per-run timeout, 10–1800s (default 120)

Without a working binary, `nuclei_exec` fails closed with these exact
instructions; the WS-108 / LX-110 methodology items report under Honest
limits.

## The tool: `nuclei_exec`

| Action | Phase | Tier | What it does |
|---|---|---|---|
| `templates` | recon or exploit | 1 | List/select templates by id, tag, severity, CVE from the local checkout. **Recon-safe: touches no target, never fires.** |
| `run` | exploit only | 2 | Execute selected templates against ONE scope-checked host. Refused in recon (the recon→exploit sign-off is the approval gate). |

Arguments: `host` (scope-checked; the target URL is runner-built, never
agent-supplied), `scheme` (http|https, default https), `ids` / `tags` /
`severities` / `cve` filters, plus the standard `attackId` (T1595.002),
`category`, `targetProfile` ("windows"|"linux" — never inferred),
`hypothesis`, `batteryItem`.

## Safety (mechanical)

- **Exact-hostname ROE scope check** before any subprocess spawns — zero
  packets/subprocesses for out-of-scope hosts.
- **DoS templates excluded always**: `dos` tags are refused if requested
  AND `-exclude-tags dos` is appended to every run argv (T1499 stays
  excluded per standing ROE, no exceptions).
- **No shell**: the argv is built from structured options only; unknown
  flags are dropped, never forwarded.
- **Kill switch**: abort kills the subprocess (SIGKILL). Timeout kills it
  too. Rate limit inherited from the engagement safety config.
- **Audit**: every invocation lands in the JSONL operation log.

## Dedupe

A finding confirmed by BOTH a battery item and a template is ONE finding
with two evidence sources — never two findings. The `run` result includes
an overlap hint per finding (CVE match → the owning battery item;
template-only → runtime instance under WS-108 / LX-110, the methodology
items, same pattern as the Metasploit bridge's WS-105…107).

## Honest counting

Template executions are variant-level checks. The report prints three
separate numbers — 418 intents, N variant executions, M nuclei template
executions — never merged into one inflated "attacks" figure. A
competitor-style single number is exactly what we refuse to print.

## Honest limits

- Template quality depends on the operator's checkout freshness
  (`-update-templates` is their job, before the engagement).
- `templates` metadata comes from template paths/ids; tag inference is
  conservative — when in doubt the runner reports template-only.
- Nuclei templates are overwhelmingly HTTP-oriented; non-HTTP host
  services are better covered by the host-exec tools and the Metasploit
  bridge.
