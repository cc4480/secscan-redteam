# Harness integration — driving the runner from DeepSeek Harness

How the desktop app and the engagement engine fit together, and how to run it.

---

## Two different things, and the distinction is the whole story

`secscan-redteam` is **two** systems. Confusing them is what made the first
integration attempt aim at the wrong layer.

| | What it is | MCP role |
|---|---|---|
| **SecScan scan service** | `https://secscan.us/api/mcp` — scan_url, get_report, domain verification | an MCP **server** the harness calls |
| **The runner** (`@secscan/redteam-runner`) | the engagement engine: 418-intent battery, safety core, proof bundles, compliance packs, watch mode | was an MCP **client** only |

The runner had no MCP server face, so there was nothing for a harness to connect
to. `runner/src/ui/mcp-endpoint.ts` is that face.

```
DSH desktop app  =  the cockpit
      |
      |  MCP (dsh-mcp-client, two rows)
      |
      +--> secscan.us/api/mcp ......... scan service   -> mcp__secscan__*
      |
      +--> 127.0.0.1:8787/mcp ......... THE RUNNER      -> mcp__redteam__*
                    |
                    v
            @secscan/redteam-runner
```

---

## Running it

### 1. Start the console

The runner exposes MCP on its existing console server, so the console must be up:

```bash
npx redteam-runner ui                       # 127.0.0.1:8787
```

Set a **stable** token so the harness config does not go stale on every restart:

```bash
REDTEAM_UI_TOKEN=<at-least-strong-token> npx redteam-runner ui
```

Unset, it generates a strong random token and prints it — copy that if you prefer.
`REDTEAM_UI_TOKEN` must clear the strength floor (`assertStrongToken`); the
console drives live pentest tooling and fails fast rather than run with
`password`.

### 2. Point the harness at it

Both variables are read by the bundle's patch layer:

```powershell
[Environment]::SetEnvironmentVariable('REDTEAM_UI_TOKEN', '<the same token>', 'User')
# optional, if you moved the console off the default port:
[Environment]::SetEnvironmentVariable('REDTEAM_MCP_URL', 'http://127.0.0.1:8787/mcp', 'User')
```

Restart the desktop app. Env vars are read at process start.

### 3. Check it connected

The model gains `mcp__redteam__*` tools. Quick check from any shell:

```bash
curl -s -X POST http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $REDTEAM_UI_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Thirteen tools should come back. If the console is **not** running, the harness
still starts and the `mcp__redteam__*` tools are simply absent — the same
failure mode as an unset `SECSCAN_MCP_TOKEN`.

---

## The tools

| Tool | Does |
|---|---|
| `list_engagements` | live runs first, then history |
| `get_engagement` | state snapshot + which artifacts exist |
| `start_engagement` | launch (same validation as the CLI) |
| `get_feed` | operation events by sequence; poll with `after_seq` |
| `get_findings` | validated findings |
| `get_proof` | PoC bundle: canary sent/echoed, audit-log derivation |
| `get_coverage` | battery coverage per category × target cell |
| `get_compliance` | PCI DSS / SOC 2 / ISO 27001 mapping |
| `abort_engagement` | kill switch; works on CLI-launched runs too |
| `escalate` | mid-run tier change; needs operator + reason |
| `reverify` | replay a PoC bundle with a fresh canary |
| `watch_profiles` | list continuous-testing profiles |
| `watch_trigger` | fire a watch run with baselines + drift |

---

## Why this is safe to expose

**It adds reach, not authority.** Every tool delegates to the same route handler
the console UI already called, so nothing is reimplemented and no rule is
bypassed:

- `start_engagement` goes through the shared `toEngagementInput` validation —
  the console cannot launch something the CLI would refuse.
- `escalate` still demands an operator name and a reason, recorded in the
  approval log. Tier 2 on production still needs explicit confirmation.
- The safety core — per-host rate limits, PII redaction, staging → production
  confirmation, auto-halt, kill switch — is untouched and applies to every run
  however it was started.
- Active testing still requires proven domain ownership. The auth gate fails
  closed, for the operator too.

**Auth.** `/mcp` requires the console token as a `Bearer` header. The route is
deliberately placed *before* the generic gate, because that gate answers a
non-`/api` path with the HTML login page — an MCP client needs a 401 it can
parse. Verified: unauthenticated `POST /mcp` returns HTTP 401 with a JSON-RPC
error body, while `GET /` still serves the human login page.

**Loopback only.** The console binds `127.0.0.1` unless explicitly overridden.
Keep it there — it drives live pentest tooling.

---

## Implementation notes

- **Stateless Streamable HTTP, JSON responses.** No SSE: it fits request/response
  tools and is what both `dsh-mcp-client` and the runner's own `McpClient` accept.
- **`get_feed` reads events directly** rather than reusing `handleFeed`, because
  that handler is an SSE stream and cannot answer a request/response tool.
- **The capture adapter** (`capture()` in `mcp-tools.ts`) stands in for a
  `ServerResponse` and collects what a handler writes. That is the entire
  adapter — no existing handler needed to change.
- **Split for the file budget.** `mcp-endpoint.ts` (transport, 118 lines) +
  `mcp-tools.ts` (tool surface, 265 lines), both under the 300-line cap that
  `runner/test/file-budget.test.ts` enforces.
- **Batch and notifications** are handled: an array of requests gets an array of
  responses; a notification gets HTTP 202 with no body.

---

## The Agent Teams layer

The bundle also mounts DeepSeek Harness's own Agent Teams layer
(`agent-team`, `tool-agent-team`, `ui-agent-team`) and disables plain subagent
delegation so nothing escapes the roster.

**This is not the engagement team.** The engagement team is the runner's own
multi-agent implementation (`runner/src/agents.ts` + `runner/src/prompts/`) —
coordinator, recon, exploiter, reporter, with the safety core wrapped around
every action. The harness-side Agent Teams layer is a separate, generic
capability: useful if you want the cockpit agent to run parallel *non-engagement*
work, such as drafting a client report while triaging findings.

Two agent systems in one app is a real risk of confusion about which one is
enforcing the safety rails. **The answer is the runner.** Nothing the harness
spawns has the safety core, the tier rules, or the authorization gate wired into
it. Drive engagements through `mcp__redteam__*`; treat harness teammates as
convenience only.
