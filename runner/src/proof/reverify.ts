/**
 * RE-VERIFY — the mechanical retest loop (v0.14.0).
 *
 * Takes a PoC bundle and re-executes its steps against the target to confirm
 * the finding still reproduces. Verdicts:
 *   - "reproduced"     — every replayable step re-ran and its validation
 *                         signal re-observed (fresh marker echoed / evidence
 *                         output returned).
 *   - "not-reproduced" — steps ran but the validation signal did not come
 *                         back (fixed, or the finding never reproduced this way).
 *   - "target-changed"  — a step failed on connectivity (unreachable,
 *                         refused, DNS, timeout): the environment moved, not
 *                         the vulnerability. Retest, don't celebrate.
 *
 * Only steps with structured replay parameters are re-executed
 * (ssh_exec / winrm_exec / msf_exec — the execution tools). Read-only
 * observation steps are reported as skipped: re-reading fresh enumeration
 * output is a human retest, and the report says so plainly.
 *
 * Credentials are NEVER in the bundle. Reverify resolves them fresh from
 * the environment at re-execution time — exactly like the original run.
 * A FRESH canary marker is generated per reverify run; the old marker is
 * never replayed (its echo would prove nothing about the present).
 */

import type { PocBundle, PocStep } from "./bundle.js";
import { HostExecutor } from "../host-exec/executor.js";
import { MsfExecutor } from "../msf/executor.js";
import { validateHostTarget } from "../host-exec/common.js";

export interface StepRunResult {
  ok: boolean;
  output: string;
  note?: string;
}

/**
 * Executes one bundle step. Injected — the CLI wires the real replayer,
 * tests wire fakes. Receives a FRESH marker to use for this reverify run.
 */
export type StepRunner = (step: PocStep, freshMarker: string) => Promise<StepRunResult>;

export type ReverifyVerdict = "reproduced" | "not-reproduced" | "target-changed";

export interface ReverifyStepReport {
  seq: number;
  tool: string;
  replayed: boolean;
  ok: boolean;
  validationObserved: boolean;
  note: string;
}

export interface ReverifyReport {
  bundleId: string;
  findingId: string;
  engagementId: string;
  reverifiedAt: string;
  verdict: ReverifyVerdict;
  steps: ReverifyStepReport[];
  summary: string;
  /** What the operator should do with this result (registry before/after). */
  registryNote: string;
}

const TARGET_CHANGED_RE =
  /unreachable|econnrefused|connection refused|enotfound|etimedout|timed out|no route to host|nxdomain|getaddrinfo|network is unreachable|dial tcp/i;

const MARKER_RE = /REDTEAM-MARKER-[A-Za-z0-9_-]{1,64}/;

function freshMarker(): string {
  return `REVERIFY-${Date.now().toString(36)}${Math.floor(Math.random() * 0xffffff).toString(16)}`;
}

async function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      p,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Re-execute a bundle's steps. Pure orchestration over an injected
 * StepRunner — the verdict logic is fully testable without a network.
 */
export async function reverifyBundle(
  bundle: PocBundle,
  runner: StepRunner,
  opts: { perStepTimeoutMs?: number } = {},
): Promise<ReverifyReport> {
  const marker = freshMarker();
  const perStep = opts.perStepTimeoutMs ?? 60_000;
  const steps: ReverifyStepReport[] = [];

  for (const step of bundle.steps) {
    if (!step.replay) {
      steps.push({
        seq: step.seq,
        tool: step.tool,
        replayed: false,
        ok: false,
        validationObserved: false,
        note: "not mechanically replayable — manual retest required",
      });
      continue;
    }
    let res: StepRunResult;
    try {
      res = await withTimeout(runner(step, marker), perStep, `reverify seq ${step.seq}`);
    } catch (err) {
      res = { ok: false, output: "", note: (err as Error).message };
    }
    const changed = !res.ok && TARGET_CHANGED_RE.test(`${res.output} ${res.note ?? ""}`);
    // Validation: the FRESH marker must echo (execution steps), or the tool
    // must succeed with evidence output (observation steps).
    const validationObserved = changed
      ? false
      : step.validation === "marker-echo"
        ? res.ok && res.output.includes(marker)
        : res.ok && res.output.trim().length > 0;
    steps.push({
      seq: step.seq,
      tool: step.tool,
      replayed: true,
      ok: res.ok,
      validationObserved,
      note: changed ? `target-changed: ${res.note ?? res.output.slice(0, 200)}` : (res.note ?? (res.ok ? "ok" : "failed")),
    });
  }

  const replayed = steps.filter((s) => s.replayed);
  let verdict: ReverifyVerdict;
  let summary: string;
  if (steps.some((s) => s.replayed && !s.ok && /target-changed:/.test(s.note))) {
    verdict = "target-changed";
    summary =
      `target-changed: a reverify step failed on connectivity — the environment moved, not the vulnerability. ` +
      `Retest when the target is reachable; do not mark the finding fixed.`;
  } else if (replayed.length === 0) {
    verdict = "not-reproduced";
    summary =
      `not-reproduced (inconclusive): this bundle has no mechanically replayable steps — ` +
      `manual retest required. Nothing was re-executed.`;
  } else if (replayed.every((s) => s.ok && s.validationObserved)) {
    verdict = "reproduced";
    summary =
      `reproduced: ${replayed.length}/${bundle.steps.length} replayable step(s) re-ran and every validation ` +
      `signal re-observed (fresh marker ${marker} echoed where applicable). The finding still holds.`;
  } else {
    verdict = "not-reproduced";
    const bad = replayed.filter((s) => !s.ok || !s.validationObserved).length;
    summary =
      `not-reproduced: ${bad}/${replayed.length} replayable step(s) failed or lost their validation signal. ` +
      `Treat as fixed-or-changed: confirm with a fresh engagement before closing the finding.`;
  }

  return {
    bundleId: bundle.bundleId,
    findingId: bundle.findingId,
    engagementId: bundle.engagementId,
    reverifiedAt: new Date().toISOString(),
    verdict,
    steps,
    summary,
    registryNote:
      verdict === "reproduced"
        ? `${bundle.findingId} re-verified ${new Date().toISOString().slice(0, 10)}: REPRODUCED — extends the before/after chain; re-record via record_finding to log the fresh observation.`
        : verdict === "target-changed"
          ? `${bundle.findingId} re-verify inconclusive (target-changed): do NOT close the finding; retest when reachable.`
          : `${bundle.findingId} re-verify ${new Date().toISOString().slice(0, 10)}: NOT REPRODUCED — candidate for closure after one fresh-engagement confirmation.`,
  };
}

export interface ReplayerOptions {
  /** Exact in-scope hosts. The executors enforce this mechanically. */
  scope: string[];
  env?: NodeJS.ProcessEnv;
  killSwitch?: { aborted: boolean };
  perStepTimeoutMs?: number;
}

/**
 * Production StepRunner: replays bundle steps through the real executors.
 * Scope is enforced by the executors themselves (fail closed); credentials
 * resolve fresh from env; the kill switch aborts via SIGINT wiring in the CLI.
 */
export function createReplayer(opts: ReplayerOptions): StepRunner {
  const env = opts.env ?? process.env;
  const hostExec = new HostExecutor({ env });
  const msfExec = new MsfExecutor({ env });
  if (opts.killSwitch) {
    hostExec.killSwitch = opts.killSwitch;
    msfExec.killSwitch = opts.killSwitch;
  }
  const scope = opts.scope;

  return async (step: PocStep, marker: string): Promise<StepRunResult> => {
    const replay = step.replay;
    if (!replay) return { ok: false, output: "", note: "not replayable" };
    const host = replay.host ?? step.target ?? "";
    const scopeCheck = validateHostTarget(host, scope);
    if (!scopeCheck.ok) {
      return { ok: false, output: "", note: `REFUSED: ${scopeCheck.reason} — reverify never leaves declared scope` };
    }
    try {
      if (replay.tool === "ssh_exec" || replay.tool === "winrm_exec") {
        let command = String(replay.args["command"] ?? "");
        // Fresh marker in, old marker out: replaying the stale marker would prove nothing.
        command = command.replace(/REDTEAM-MARKER-[A-Za-z0-9_-]{1,64}/g, marker);
        const res =
          replay.tool === "ssh_exec"
            ? await hostExec.sshExec({ host, command, scopeHosts: scope, timeoutMs: opts.perStepTimeoutMs })
            : await hostExec.winrmExec({ host, command, scopeHosts: scope, timeoutMs: opts.perStepTimeoutMs });
        if (res.refused) return { ok: false, output: res.output, note: res.refused };
        return { ok: res.ok, output: `${res.summary}\n${res.output}`.slice(0, 4000) };
      }
      if (replay.tool === "msf_exec") {
        const res = await msfExec.run({
          host,
          moduleType: replay.args["moduleType"] === "auxiliary" ? "auxiliary" : "exploit",
          module: String(replay.args["module"] ?? ""),
          marker,
          scopeHosts: scope,
          timeoutMs: opts.perStepTimeoutMs,
        });
        if (res.refused) return { ok: false, output: res.output, note: res.refused };
        return { ok: res.ok, output: `${res.summary}\n${res.output}`.slice(0, 4000) };
      }
      return { ok: false, output: "", note: `no replayer for tool ${replay.tool} — manual retest` };
    } catch (err) {
      return { ok: false, output: "", note: (err as Error).message.slice(0, 300) };
    }
  };
}
