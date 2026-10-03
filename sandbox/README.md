# Local sandbox targets

Intentionally-vulnerable apps for developing/testing the runner against,
without touching a real domain or needing ownership verification.

## Prerequisites

Docker Desktop (needs WSL2 on Windows — see repo root README/setup notes).
Verify with:

```powershell
docker --version
docker compose version
```

## Start the targets

```powershell
cd sandbox
docker compose up -d
```

- Juice Shop: http://localhost:3000
- DVWA: http://localhost:3001 (first visit: click "Create / Reset Database")

Both are bound to `127.0.0.1` only — not reachable from your LAN or the
internet.

## Running an engagement against the sandbox

The runner's authorization gate normally requires server-authoritative
domain-ownership proof (DNS TXT), which can't exist for a loopback target.
Use `--local-sandbox` (or `REDTEAM_LOCAL_SANDBOX=1`) to skip it — this flag
has **no effect on a real domain**; it only ever bypasses verification and
the private-host rejection for a target that already resolves to
`localhost`/`127.0.0.1`/an RFC1918 address. See `runner/src/gate.ts` and
`runner/src/prober.ts` for the enforced invariant, and
`runner/test/runner.test.ts` ("local sandbox mode") for the tests that pin
it down.

Everything else is unchanged: `T1499` (DoS) is still always excluded,
payloads are still non-destructive, scope is still an exact hostname match,
findings still need two independent observations.

```powershell
cd ..\runner
npm run build
node dist/cli.js start `
  --target localhost `
  --mode red `
  --objective "shake out the runner's exploit battery against a known-vulnerable app" `
  --scope localhost `
  --local-sandbox `
  --dry-run   # drop this once DEEPSEEK_API_KEY / QWEN_API_KEY / SECSCAN_MCP_TOKEN are set, to run the real agent loop
```

With `--dry-run`, no live LLM/MCP keys are needed — it exercises gating,
authorize, scope enforcement, and the report pipeline with fake agents. Drop
`--dry-run` once you've set `SECSCAN_MCP_TOKEN`, `DEEPSEEK_API_KEY`, and
`QWEN_API_KEY` to run the real coordinator/recon/exploiter/reporter loop
against Juice Shop/DVWA.

## Stopping / cleaning up

```powershell
docker compose down -v
```
