# Web Console (v0.22.0)

`redteam-runner ui` starts a dashboard wired **directly to the same code paths
the CLI uses** — it imports `runEngagement`, `runWatchCycle`, `reverifyBundle`,
and the event/findings readers as modules. It never shells out to its own
binary. Every endpoint maps 1:1 to a CLI command:

| UI action | API endpoint | CLI equivalent |
|---|---|---|
| Launch | `POST /api/engagements` | `start` |
| List | `GET /api/engagements` | (engagements dir listing) |
| Live feed | `GET /api/engagements/:id/events` (SSE) | `events.jsonl` tail |
| Kill switch | `POST /api/engagements/:id/abort` | coordinator `abort_engagement` |
| Findings + proof | `GET …/findings`, `GET …/proof/:fid` | `state.json`, `poc/*.json` |
| Coverage | `GET …/coverage` | `item-verdicts.json` |
| Compliance pack | `GET …/compliance` | `compliance-pack.md` et al. |
| Watch profiles / trigger | `GET /api/watch/profiles`, `POST /api/watch/trigger` | `watch --profile … --once` |
| Reverify | `POST /api/reverify` (+ `GET /api/jobs/:id`) | `reverify --bundle …` |

## Start

```bash
redteam-runner ui [--port 8787] [--listen <addr>] [--engagements-dir <dir>]
```

The server prints a random 64-hex **UI token** to the terminal on startup. Enter
it once on the login page (it is stored in an `HttpOnly` `SameSite=Strict`
cookie); API clients can use `Authorization: Bearer <token>` instead.
`REDTEAM_UI_TOKEN` sets your own token. The token is never written to disk.

## Security

This console drives live pentest tooling — treat it as a **privileged console**,
not a public page:

- **Loopback only by default.** The server binds `127.0.0.1`. `--listen`
  overrides this and prints a loud warning; only do it if you know exactly
  what you are doing.
- **Token auth on everything.** No token → 401 on every `/api/*` route; the
  dashboard itself serves a login page instead.
- **No credential storage.** Host-exec / MSRPC credentials still come from
  the environment or Secure Vault, exactly as with the CLI.
- **Confirm before destruction.** Launch, abort, watch-trigger, and
  reverify-execute all sit behind a confirm dialog in the UI.

## Page tour

- **Engagements** — every engagement in the engagements dir, live ones first.
- **Launch** — target, scope, ROE, tier, mode, battery subset. Validation is
  the same as the CLI's: anything the CLI would refuse, the UI refuses too
  (400 with the reason).
- **Engagement detail** — four tabs:
  - *Live feed*: the operation feed streaming as Server-Sent Events, with
    phase badges and agent activity. The **kill-switch bar** at the bottom
    aborts in-flight work immediately: in-flight executions are terminated,
    new work is refused, and the next tool dispatch throws `HaltError` so the
    engagement unwinds to `halted` — the exact same path as the coordinator's
    own `abort_engagement`.
  - *Findings*: severity filter, click a row for the PoC bundle (steps,
    canary marker, reverify command).
  - *Coverage*: per-item verdict counts plus the 12-cell battery summary.
  - *Compliance*: evidence pack, attestation letter, safety manifest, and the
    report — markdown rendered to sanitized HTML (raw HTML is escaped,
    non-`http(s)` links are stripped to text).
- **Watch** — list watch profiles in a directory and trigger a single cycle
  (background job; poll `/api/jobs/:id` for the result).
- **Reverify** — paste a bundle path; plan mode shows the replay steps with
  zero traffic, execute mode replays with a fresh canary and pushes verdicts
  to linked tickets, exactly like the CLI.

## Notes

- Engagements launched from the UI run **in the UI process** and return 202
  immediately; progress arrives over SSE. CLI-launched engagements are listed
  read-only (their abort handle lives in the CLI process, so the kill switch
  shows only for UI-launched runs).
- `redteam-runner ui` keeps running until Ctrl+C; closing the browser tab does
  not stop a running engagement.
