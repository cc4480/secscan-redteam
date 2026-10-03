# Architecture — secscan-redteam runner (v0.19.0)

The runner (`runner/src/`) is organized as small, single-purpose modules.
**Hard rule: no file exceeds 300 lines.** If a module approaches the limit,
split it at a clean seam — never grow it.

## Module map

```
runner/src/
├── phases.ts            # BARREL — re-exports ./phases/
├── phases/              # Engagement orchestration: authorize → plan → recon → exploit → report
│   ├── authorize.ts     # authorizePhase (DNS ownership gate)
│   ├── plan.ts          # planPhase (ATT&CK-mapped planning)
│   ├── recon.ts         # reconPhase
│   ├── exploit.ts       # exploitPhase (coordinator command loop)
│   ├── exploit-one.ts   # focusedExploit (single-focus helper)
│   ├── tasks.ts         # TaskDef/TaskResult, runTask, runBatch, validateTasks
│   ├── directive.ts     # coordinatorDirective (decompose/replan synthesis)
│   ├── signoff.ts       # coordinatorSignOff (phase-transition gate)
│   ├── config.ts        # resolveConfig
│   └── run.ts           # runEngagement + RunOptions (public entry)
├── dispatch.ts          # BARREL — re-exports ./dispatch/
├── dispatch/            # Tool-call router (the 25 agent tools)
│   ├── router.ts        # dispatchToolInner (ordered handlers) + dispatchTool (safety wrapper)
│   ├── web.ts           # http_probe, burst_probe
│   ├── host.ts          # ssh/smb/winrm_exec (wave 1) + winrm_probe, rdp_*, smb_pth, ad_enum, krb_ptt, ssh_agent_audit, nfs_enum (wave 2)
│   ├── msf.ts           # msf_exec
│   ├── mcp.ts           # scan_url + read-only SecScan MCP tools
│   ├── bookkeeping.ts   # query_registry, update_target_map, record_finding, record_killed, record_item_verdict, abort_engagement
│   ├── verdicts.ts      # finding/verdict helpers, mergeVerdictBlock
│   ├── prelude.ts       # recheckVerified, optStr, numArg
│   └── types.ts         # DispatchResult
├── tools.ts             # BARREL — re-exports ./tools/
├── tools/               # Agent tool DEFINITIONS (schemas)
│   ├── web.ts           # MCP tools + prober tools
│   ├── host.ts          # 11 host-execution tool schemas
│   ├── msf.ts           # msf_exec schema
│   ├── bookkeeping.ts   # registry/verdict/abort schemas
│   └── compose.ts       # RECON_TOOLS / EXPLOIT_TOOLS / COMMAND_TOOLS (per-phase sets)
├── report.ts            # BARREL — re-exports ./report/
├── report/              # Report phase: reporter agent + runner-computed artifacts
│   ├── phase.ts         # reportPhase orchestrator
│   ├── proof.ts         # PoC bundle section (mechanical, from audit log)
│   ├── integrations.ts  # ticket sync + SIEM export + Slack section
│   ├── safety.ts        # safety-manifest.json/.md writer
│   ├── compliance.ts    # compliance-pack + attestation letter writer
│   ├── notify.ts        # fireSlack (best-effort)
│   └── narrative.ts     # operation-narrative extractor
├── agents.ts            # agentLoop driver, promptCtx, commanderRedirect
├── context.ts           # Ctx, RunnerDeps, HaltError
├── coverage/
│   ├── cells.ts         # batteryStatusLine, sharedStateDigest
│   └── items.ts         # per-item ledger (418 battery items)
├── targets/             # 4 target batteries (secscan, seclayer, windows, linux) — split by category
├── host-exec/
│   ├── executor.ts      # HostExecutor FACADE (thin wrappers; public surface unchanged)
│   └── executor/        # core (shared machinery) + per-transport impls (ssh, smb, winrm, nfs, rdp, ad, krb, agent-audit)
├── msf/executor/        # MsfExecutor (same facade pattern)
├── proof/               # PoC bundle builders + reverify
├── integrations/        # Jira, ServiceNow, SIEM, Slack
├── compliance/          # compliance pack builders
├── continuous/          # watch mode (queue, drift, cycle)
├── prompts/             # role prompts (coordinator, recon, exploiter, reporter, task)
├── cli/                 # CLI commands (start, queue, watch, reverify)
└── ...                  # gate, mcp, prober, registry, safety, accountability, battery, events, types, util
```

## Conventions

- **Barrels keep import paths stable.** `phases.ts`, `dispatch.ts`, `tools.ts`,
  `report.ts` (and the `host-exec/executor.ts` facade) re-export so existing
  `./x.js` imports keep working. New code imports from the submodule directly.
- **Handlers return null when not theirs.** Dispatch handlers
  (`handleWebTools`, `handleHostTools`, …) take
  `(ctx, role, phase, call, args)` and return `DispatchResult | null`;
  the router tries them in the original order.
- **Report sections are pure-ish.** `buildProofSection` /
  `buildIntegrationsSection` return markdown strings; `writeSafetyArtifacts` /
  `writeComplianceArtifacts` write files. `reportPhase` concatenates in order.
- **The runner enforces; the model proposes.** Ownership verification, scope,
  denylists, rate limits, kill switch, and tier gates are mechanical in the
  runner — never trusted to prompts.
- **Public surface (do not break):** 4 CLI commands, 25 flags, 26 agent tool
  names (variant_list added in v0.20.0), 418 battery item IDs, 8 report
  artifacts, env-var names. The behavior inventory
  (`/tmp/refactor-inventory.mjs` pattern) must diff empty.

## Payload variants (v0.20.0)

`runner/src/variants/` — curated, mechanical payload libraries per attack
class (sqli, xss, cmdi, ssti, xxe, traversal, ssrf, redirect, auth, headers).
`variant_list` (Tier 0 bookkeeping tool) classifies a battery item, opens
**variant expansion** on its ledger entry, and returns the capped payload
list. Per-item cap: 25 staging / 10 production (override via
`--max-variants` / `REDTEAM_MAX_VARIANTS`), enforced mechanically in
dispatch before any packet. The ledger tracks `variants?: VariantProgress`
(run/planned/confirmed/closed); an item isn't `executed-clean` until its
variants are exhausted or the cap is reached. Reports print "418 attack
intents" and "N variant executions" as two numbers — never merged. See
`docs/variants.md`.

## Concurrency (v0.23.0)

The UI can launch multiple engagements in one process (`POST
/api/engagements` runs detached). Two guarantees hold for concurrent runs:

- **Audit-log sequencing is per-engagement.** `EventLog` owns a private
  sequence counter seeded from its own `state.json` on open; the old
  module-global counter corrupted `seq` numbering when two runs interleaved.
  On-disk format is unchanged (append-only JSONL with `seq`).
- **Registry verdicts are atomic.** Every verdict persists via
  `transactRegistryFile` — a synchronous read-modify-write, which Node can
  never preempt mid-transaction. The old load-at-start / blind-save-at-verdict
  pattern silently lost the first writer's entries; the end-of-run blind save
  was removed for the same reason.

Known limitation: this covers one process. Two separate OS processes writing
the same `registry.json` can still race — the SQLite migration trigger stands.
Other module-global counters were audited: `phases/tasks.ts` taskCounter
(globally unique IDs, cosmetic only), `host-exec/nfs/rpc.ts` xidCounter
(RPC transaction IDs, random init), `nuclei/prereq.ts` probeCache
(idempotent binary probe) — none leak engagement state.
