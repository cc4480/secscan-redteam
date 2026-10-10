/**
 * RE-VERIFY — the mechanical retest loop (v0.14.0).
 *
 * Takes a PoC bundle and re-executes its steps against the target:
 *   - "reproduced"     — every replayable step re-ran, validation signal re-observed.
 *   - "not-reproduced" — steps ran but the signal did not come back.
 *   - "target-changed"  — a step failed on connectivity: the environment
 *                         moved, not the vulnerability. Retest, don't celebrate.
 * Only steps with structured replay parameters are re-executed
 * (ssh_exec / winrm_exec / msf_exec); observation steps are reported as
 * skipped (re-reading enumeration output is a human retest).
 *
 * Credentials are NEVER in the bundle; they resolve fresh from env at
 * re-execution, exactly like the original run. Recorded steps are replayed
 * VERBATIM and validation checks the ORIGINALLY recorded marker against
 * the fresh run's raw tool output — never the result summary, which embeds
 * the sent command (marker and all) and would "verify" a command that
 * never echoed anything. A marker-echo step that records no marker means
 * incomplete verification material: the replay ABORTS before firing.
 * Before ALL of that, the bundle's runner-recorded integrity digest must
 * verify (bundle/integrity.ts): a bundle of unproven origin never runs.
 */

import { verifyBundleIntegrity, type PocBundle, type PocStep } from "./bundle.js";
import { HostExecutor } from "../host-exec/executor.js";
import { MsfExecutor } from "../msf/executor.js";
import { validateHostTarget } from "../host-exec/common.js";

export interface StepRunResult {
  ok: boolean;
  /** RAW tool output only — never the result summary (it embeds the sent
   *  command, marker and all). Summaries belong in `note`. */
  output: string;
  note?: string;
}

/** Executes one bundle step (CLI wires the real replayer, tests wire
 *  fakes). Receives the step's ORIGINALLY recorded marker (full
 *  `REDTEAM-MARKER-…` form, "" when none) + a timeout abort signal. */
export type StepRunner = (step: PocStep, recordedMarker: string, signal?: AbortSignal) => Promise<StepRunResult>;

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

const MARKER_SUFFIX_RE = /^[A-Za-z0-9_-]{1,64}$/;
const FULL_MARKER_RE = /^REDTEAM-MARKER-[A-Za-z0-9_-]{1,64}$/;

/**
 * The step's originally recorded marker, full form. Steps record the
 * marker suffix; the bundle-level observed marker is the fallback when a
 * bundle carries exactly one marker-echo step. "" = not recorded.
 */
function recordedMarkerFor(step: PocStep, bundle: PocBundle): string {
  if (step.marker && MARKER_SUFFIX_RE.test(step.marker)) return `REDTEAM-MARKER-${step.marker}`;
  const markerSteps = bundle.steps.filter((s) => s.validation === "marker-echo");
  if (markerSteps.length === 1 && bundle.markerObserved && FULL_MARKER_RE.test(bundle.markerObserved)) {
    return bundle.markerObserved;
  }
  return "";
}

/**
 * Run one step under a REAL deadline: on timeout the abort signal fires
 * (transports/executors cancel the underlying work — the step does not
 * keep acting on the target in the background) and the race rejects.
 */
async function runStepWithTimeout(
  runner: StepRunner,
  step: PocStep,
  marker: string,
  ms: number,
): Promise<StepRunResult> {
  const ctrl = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      runner(step, marker, ctrl.signal),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          ctrl.abort();
          reject(new Error(`reverify seq ${step.seq} timed out after ${ms}ms`));
        }, ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Preflight refusal/abort report: every step listed, nothing fired. */
function abortedReport(b: PocBundle, note: string, summary: string, registryNote: string): ReverifyReport {
  return { bundleId: b.bundleId, findingId: b.findingId, engagementId: b.engagementId, reverifiedAt: new Date().toISOString(), verdict: "not-reproduced",
    steps: b.steps.map((s) => ({ seq: s.seq, tool: s.tool, replayed: false, ok: false, validationObserved: false, note })), summary, registryNote };
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
  const perStep = opts.perStepTimeoutMs ?? 60_000;
  const steps: ReverifyStepReport[] = [];

  // Preflight: verification material must be complete BEFORE anything
  // fires. A marker-echo step that records no marker can never be
  // verified output-side — abort the whole replay without firing a
  // single step rather than marching on unverifiable material.
  // Provenance FIRST: stored commands replay with fresh env credentials, so
  // the bundle must be bit-for-bit what the runner recorded — else refuse.
  const badProvenance = verifyBundleIntegrity(bundle);
  if (badProvenance) return abortedReport(bundle, "not fired — reverify refused (bundle provenance check failed)",
    `refused before firing: ${badProvenance}. Nothing was executed. Re-derive the bundle from the audit log (report phase) and re-verify that instead.`,
    `${bundle.findingId} re-verify REFUSED (bundle provenance check failed): do NOT close the finding; re-derive the bundle from the audit log and re-verify.`);

  const unverifiable = bundle.steps.filter(
    (s) => s.validation === "marker-echo" && recordedMarkerFor(s, bundle) === "",
  );
  if (unverifiable.length > 0) {
    const seqs = unverifiable.map((s) => s.seq).join(", ");
    return abortedReport(bundle, "not fired — reverify aborted (verification material missing)",
      `aborted before firing: step(s) ${seqs} claim marker-echo validation but the bundle records no marker for them — there is nothing trustworthy to verify against. Nothing was executed. Re-derive the bundle from the audit log (its marker must be captured from tool output) and re-verify.`,
      `${bundle.findingId} re-verify ABORTED (verification material missing): do NOT close the finding; re-derive the bundle from the audit log and re-verify.`);
  }

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
    const marker = recordedMarkerFor(step, bundle);
    let res: StepRunResult;
    try {
      res = await runStepWithTimeout(runner, step, marker, perStep);
    } catch (err) {
      res = { ok: false, output: "", note: (err as Error).message };
    }
    const changed = !res.ok && TARGET_CHANGED_RE.test(`${res.output} ${res.note ?? ""}`);
    // Validation: the RECORDED marker must reappear in the fresh run's raw
    // tool output (execution steps), or the tool must succeed with
    // evidence output (observation steps). The summary never counts.
    const validationObserved = changed
      ? false
      : step.validation === "marker-echo"
        ? res.ok && marker !== "" && res.output.includes(marker)
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
      `signal re-observed (the recorded marker reappeared in fresh tool output where applicable). The finding still holds.`;
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
  /** Test seam: pre-built executors (fake transports) instead of real ones. */
  executors?: { hostExec?: HostExecutor; msfExec?: MsfExecutor };
}

/**
 * Production StepRunner: replays bundle steps through the real executors.
 * Scope is enforced by the executors (fail closed); credentials resolve
 * fresh from env. Recorded commands replay VERBATIM, every replay carries
 * an explicit timeout + the caller's abort signal, and results carry raw
 * tool output only (the summary rides in the note, unread by validation).
 */
export function createReplayer(opts: ReplayerOptions): StepRunner {
  const env = opts.env ?? process.env;
  const hostExec = opts.executors?.hostExec ?? new HostExecutor({ env });
  const msfExec = opts.executors?.msfExec ?? new MsfExecutor({ env });
  if (opts.killSwitch) {
    hostExec.killSwitch = opts.killSwitch;
    msfExec.killSwitch = opts.killSwitch;
  }
  const scope = opts.scope;
  const stepTimeoutMs = opts.perStepTimeoutMs ?? 60_000;

  return async (step: PocStep, recordedMarker: string, signal?: AbortSignal): Promise<StepRunResult> => {
    const replay = step.replay;
    if (!replay) return { ok: false, output: "", note: "not replayable" };
    const host = replay.host ?? step.target ?? "";
    const scopeCheck = validateHostTarget(host, scope);
    if (!scopeCheck.ok) {
      return { ok: false, output: "", note: `REFUSED: ${scopeCheck.reason} — reverify never leaves declared scope` };
    }
    try {
      if (replay.tool === "ssh_exec" || replay.tool === "winrm_exec") {
        const command = String(replay.args["command"] ?? "");
        const res =
          replay.tool === "ssh_exec"
            ? await hostExec.sshExec({ host, command, scopeHosts: scope, timeoutMs: stepTimeoutMs, signal })
            : await hostExec.winrmExec({ host, command, scopeHosts: scope, timeoutMs: stepTimeoutMs, signal });
        if (res.refused) return { ok: false, output: res.output, note: res.refused };
        return { ok: res.ok, output: res.output.slice(0, 4000), note: res.summary.slice(0, 300) };
      }
      if (replay.tool === "msf_exec") {
        const res = await msfExec.run({
          host,
          moduleType: replay.args["moduleType"] === "auxiliary" ? "auxiliary" : "exploit",
          module: String(replay.args["module"] ?? ""),
          // The executor builds `echo REDTEAM-MARKER-<id>` — hand it the
          // recorded marker's id so the fresh echo IS the recorded marker.
          marker: recordedMarker.replace(/^REDTEAM-MARKER-/, ""),
          scopeHosts: scope,
          timeoutMs: stepTimeoutMs,
          signal,
        });
        if (res.refused) return { ok: false, output: res.output, note: res.refused };
        return { ok: res.ok, output: res.output.slice(0, 4000), note: res.summary.slice(0, 300) };
      }
      return { ok: false, output: "", note: `no replayer for tool ${replay.tool} — manual retest` };
    } catch (err) {
      return { ok: false, output: "", note: (err as Error).message.slice(0, 300) };
    }
  };
}
