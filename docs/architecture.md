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
│   └── items.ts         # per-item ledger (416 battery items)
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
- **Public surface (do not break):** 4 CLI commands, 25 flags, 25 agent tool
  names, 416 battery item IDs, 8 report artifacts, env-var names. The
  behavior inventory (`/tmp/refactor-inventory.mjs` pattern) must diff empty.
