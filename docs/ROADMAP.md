# Runner Roadmap

## Next capability: host-exec tooling (unblocks the Windows/Linux batteries)

**Status (v0.8.0):** the Windows (WS-*) and Linux (LX-*) batteries exist as
exhaustive plan batteries — 100+ items each, every distinct attacker intent
against host and Active Directory surfaces. The runner can *plan* them today
but can only *execute* the HTTP(S) subset (banner grabs, TLS inspection,
security headers via `http_probe`). Every other host item is marked
`[needs: host-exec tooling]` and its coverage cell reports **BLOCKED** under
Honest limits — planned, never probed, never faked.

**What host-exec tooling must provide:**

1. **ssh-exec** — authenticated SSH command execution against in-scope
   Linux hosts, using operator-provided test-account credentials/keys only.
2. **smb-exec** — authenticated SMB session execution and share
   enumeration against in-scope Windows hosts (test accounts only).
3. **winrm-exec** — authenticated WinRM command execution against
   in-scope Windows hosts (test accounts only).

**Non-negotiable properties (same bar as the rest of the runner):**

- **Audit logging** — every command, its target, its arguments, and its
  result lands in the JSONL operation log with time, phase, actor,
  ATT&CK ID, and effect. No silent execution, ever.
- **Kill switch** — the coordinator's abort authority extends to host
  execution: one abort stops in-flight host commands and no new ones start.
- **Scope enforcement** — host allowlist from the ROE, checked on every
  invocation, same as `http_probe`. Out-of-scope host → denied loudly.
- **Credential discipline** — test-account credentials referenced in ROE
  notes, injected via Secure Vault / environment, never logged, never in
  error strings. The T1078 contract (provided credentials only, never
  guessed or stuffed) is mechanical, not advisory.
- **Non-destructive defaults** — read-only enumeration commands are the
  default set; any state-changing command requires explicit ROE allowance
  and is still bounded (benign canary files, single paired requests,
  no service disruption).

**When it lands:** the `[needs: host-exec tooling]` markers come off item
by item as each execution path is proven, and BLOCKED cells start counting
as probed. The battery content doesn't change — only the execution layer
grows into it.

## Beyond

- Console: surface the 12-cell coverage (✓/⊘/…) and the unified Megazord
  narrative per target in the Live header.
- Registry: host findings (privesc paths, AD attack paths) compound into
  the registry like web findings do today.
- Retest mode: re-run a previous engagement's battery against a new
  deployment and diff the results — the resident-adversary loop.
