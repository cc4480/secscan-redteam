# Payload-variant expansion (v0.20.0)

## The honest answer to "tens of thousands of attacks"

Our battery has 418 attack **intents** — one item per distinct attacker
intent. Competitors reach "tens of thousands" by executing **variants**:
payload mutations, parameter combinations, encoding bypasses. This module
gives us that depth honestly:

- **Curated libraries** (`runner/src/variants/`): reviewed payload lists
  per attack class — SQLi, XSS, command injection, SSTI, XXE, path
  traversal, SSRF, open redirect, auth/session parameters, header/CORS
  matrices. Mechanical data, never LLM-invented at runtime.
- **Same rails**: variants dispatch through the same tools, rate limiter,
  denylists, safety rails, and proof bundles as parent items.
- **Honest counting**: reports print TWO numbers — "418 attack intents"
  and "N variant executions" — never merged into one inflated figure.

## How it works

1. Agent calls `variant_list(batteryItem: "SS-042")` (Tier 0, never fires).
   The runner classifies the item's attack shape, opens **variant
   expansion** on its ledger entry, and returns the capped payload list
   (each with `variantIndex`).
2. Agent executes variants via the normal tools with `batteryItem` +
   `variantIndex` tagged.
3. The per-item **cap** (default 25 staging / 10 production; override with
   `--max-variants` / `REDTEAM_MAX_VARIANTS`) is enforced mechanically in
   dispatch — past the cap, variant-tagged calls are DENIED before any
   packet. One item can't spray.
4. When variants are exhausted (or the cap cuts the library short), the
   item settles to `executed-clean` with the honest counts. A variant that
   confirms → `confirmed` + proof bundle, as usual.
5. Agent may close early: `variant_list(batteryItem, closeExpansion: true)`.
   The report shows exactly what ran — closing early is transparent.

Opening expansion reopens an `executed-clean` item to `pending` for
deeper testing (`executed-clean` is not a final disposition). While
expansion is open, the variant tracker owns the item's disposition —
plain attempts don't close it early.

## Variant libraries

| Class | Size | Notes |
|---|---|---|
| SQLi | 20 | Tautologies, unions, time-based (SLEEP/WAITFOR/pg_sleep), stacked, encodings. No DROP/DELETE/UPDATE. |
| XSS | 20 | Contexts, event handlers, encoding/case/nesting bypasses. |
| Command injection | 15 | Benign commands only (`id`/`echo`/sleep). Agent substitutes its canary for `VARIANT`. |
| SSTI | 12 | Detection markers (Jinja2, Freemarker, Twig, ERB…). No sandbox escapes. |
| XXE | 8 | Detection shapes; `{{CANARY}}` placeholder. No billion-laughs (DoS). |
| Path traversal | 15 | Separators, encodings, bypass shapes. Read-only targets. |
| SSRF | 15 | Guard-verdict shapes (does the guard refuse?) — never live internal fetches, same rule as the battery's SSRF items. |
| Open redirect | 10 | Landing-control shapes. |
| Auth/session | 12 | Parameter + header combos. Detection only; safe method-override values. |
| Headers/CORS | 12 | Client-IP trust headers, CORS reflection, downgrade signals. |

Classification is mechanical text matching over each item's own fields
(`classifyItem` in `runner/src/variants/classify.ts`) — deterministic,
no LLM judgment. Items with no matching attack shape get no library and
reconcile normally.

## Configuration

- `resolveVariantCap(environment, configured)`: 25 staging / 10 production
  by default.
- CLI: `--max-variants <n>` · Env: `REDTEAM_MAX_VARIANTS`.

## Counting honesty (the anti-AI-washing posture)

The report's reconciliation section prints, e.g.:

> Variant executions: 137 across 12 items (3 confirmed via variants).
> Intents (418) and executions are counted separately — never merged.

We refuse to print a single merged "553 attacks" figure. That is the
entire point.
