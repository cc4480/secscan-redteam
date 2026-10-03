/**
 * Operator actions (v0.22.0): kill switch, reverify, watch triggers.
 *
 * POST /api/engagements/:id/abort — the kill switch. Uses the abort handle
 * registered at launch: terminates in-flight executions, refuses new work,
 * and the next tool dispatch throws HaltError so the engagement unwinds to
 * "halted". 409 when the engagement isn't live in this process.
 * POST /api/engagements/:id/escalate — v0.24.0 mid-run tier change. Same
 * rules as the CLI (`redteam-runner escalate`): raising the tier requires a
 * named operator + reason; lowering is logged freely; Tier 2 on production
 * needs explicit confirmation. The running dispatcher picks the new tier up
 * on its next tool call — no restart.
 * POST /api/reverify — plan or execute a PoC bundle replay (mirrors the
 * CLI's reverify command; execution runs as a background job).
 * GET/POST /api/watch — list watch profiles in a dir; trigger one cycle.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { UiStore } from "../store.js";
import { createReplayer, reverifyBundle, type PocBundle } from "../../proof/index.js";
import { loadTicketMapping, updateTicketsForReverify } from "../../integrations/index.js";
import { loadWatchProfile, runWatchCycle } from "../../continuous/index.js";
import { describeEscalation, escalateEngagement } from "../../accountability/index.js";
import { json, badRequest } from "./http.js";

/** POST /api/engagements/:id/abort { reason? } */
export function handleAbort(store: UiStore, res: ServerResponse, id: string, body: unknown): void {
  const entry = store.get(id);
  if (!entry?.abort) {
    json(res, 409, { error: "engagement is not live in this UI process (already finished or started by CLI)" });
    return;
  }
  const reason = typeof (body as { reason?: unknown })?.reason === "string" ? String((body as { reason?: string }).reason) : "operator abort from UI";
  try {
    entry.abort(reason);
  } catch (err) {
    json(res, 500, { error: `abort failed: ${(err as Error).message}` });
    return;
  }
  json(res, 200, { ok: true, id });
}

interface EscalateBody {
  tier?: unknown;
  operator?: unknown;
  reason?: unknown;
  confirmTier2Production?: unknown;
}

/**
 * POST /api/engagements/:id/escalate { tier, operator, reason?, confirmTier2Production? }
 * v0.24.0: mid-run tier change with the CLI's exact rules. Raising the tier
 * requires a named operator + reason; lowering is logged freely; Tier 2 on
 * production needs explicit confirmation. The running dispatcher picks the
 * new tier up on its next tool call — no restart. Works for CLI-started
 * engagements too (the signal is tier.json on disk, not the UI's live map).
 */
export function handleEscalate(store: UiStore, res: ServerResponse, id: string, body: unknown): void {
  const b = (body ?? {}) as EscalateBody;
  try {
    const result = escalateEngagement({
      engagementsDir: store.engagementsDir,
      engagementId: id,
      toTier: typeof b.tier === "string" || typeof b.tier === "number" ? String(b.tier) : "",
      operator: typeof b.operator === "string" ? b.operator : undefined,
      reason: typeof b.reason === "string" ? b.reason : undefined,
      tier2ProdConfirmed: b.confirmTier2Production === true,
    });
    json(res, 200, {
      ok: true,
      engagementId: result.engagementId,
      fromTier: result.fromTier,
      toTier: result.toTier,
      operator: result.operator,
      engagementStatus: result.engagementStatus,
      approvalSeq: result.approvalSeq,
      message: describeEscalation(result),
    });
  } catch (err) {
    badRequest(res, (err as Error).message);
  }
}

interface ReverifyBody {
  bundlePath?: string;
  scope?: string[];
  execute?: boolean;
}

/** POST /api/reverify — plan (sync) or execute (background job). */
export async function handleReverify(store: UiStore, res: ServerResponse, body: unknown): Promise<void> {
  const b = (body ?? {}) as ReverifyBody;
  if (!b.bundlePath || typeof b.bundlePath !== "string" || !existsSync(b.bundlePath)) {
    badRequest(res, "bundlePath is required and must exist");
    return;
  }
  let bundle: PocBundle;
  try {
    bundle = JSON.parse(readFileSync(b.bundlePath, "utf8")) as PocBundle;
  } catch (err) {
    badRequest(res, `bad bundle JSON: ${(err as Error).message}`);
    return;
  }
  if (bundle.version !== 1 || !Array.isArray(bundle.steps)) {
    badRequest(res, "not a v1 PoC bundle");
    return;
  }
  if (!b.execute) {
    // Plan only — no traffic, same as the CLI without --execute.
    json(res, 200, {
      plan: true,
      bundleId: bundle.bundleId,
      findingId: bundle.findingId,
      title: bundle.title,
      validationTier: bundle.validationTier,
      proves: bundle.proves,
      doesNotProve: bundle.doesNotProve,
      steps: bundle.steps.map((s) => ({
        seq: s.seq,
        tool: s.tool,
        target: s.target,
        command: s.command.slice(0, 200),
        validation: s.validation,
        replayable: !!s.replay,
      })),
    });
    return;
  }
  if (!Array.isArray(b.scope) || b.scope.length === 0) {
    badRequest(res, "execute requires scope: string[] (exact hosts, enforced mechanically)");
    return;
  }
  const job = store.createJob("reverify");
  json(res, 202, { jobId: job.id });
  // Background: replay with a fresh canary, then push the verdict to
  // linked tickets exactly like the CLI does.
  void (async () => {
    try {
      const killSwitch = { aborted: false };
      const report = await reverifyBundle(bundle, createReplayer({ scope: b.scope as string[], killSwitch }));
      let tickets: unknown = null;
      try {
        const mapping = loadTicketMapping(join(b.bundlePath as string, ".."));
        if (mapping) {
          const { attempts } = await updateTicketsForReverify(mapping, bundle, report);
          tickets = attempts;
        }
      } catch {
        // ticket updates never fail the reverify itself
      }
      store.finishJob(job.id, { verdict: report.verdict, summary: report.summary, tickets });
    } catch (err) {
      store.failJob(job.id, err);
    }
  })();
}

/** GET /api/jobs/:jobId — background job status. */
export function handleJob(store: UiStore, res: ServerResponse, jobId: string): void {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(jobId)) {
    badRequest(res, "bad job id");
    return;
  }
  const job = store.getJob(jobId);
  if (!job) {
    json(res, 404, { error: "unknown job" });
    return;
  }
  json(res, 200, job);
}

/** GET /api/watch/profiles?dir= — list parseable watch profiles. */
export function handleWatchProfiles(res: ServerResponse, query: URLSearchParams): void {
  const dir = query.get("dir") || process.cwd();
  let files: string[] = [];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  } catch {
    json(res, 200, []);
    return;
  }
  const out: { path: string; target?: string; intervalHours?: number }[] = [];
  for (const f of files) {
    const p = join(dir, f);
    try {
      const profile = loadWatchProfile(p);
      out.push({ path: p, target: (profile.engagement as { target?: string } | undefined)?.target, intervalHours: profile.cadence?.intervalHours });
    } catch {
      // not a watch profile — skip
    }
  }
  json(res, 200, out);
}

/** POST /api/watch/trigger { profilePath, trigger? } — one cycle, background job. */
export function handleWatchTrigger(store: UiStore, res: ServerResponse, body: unknown): void {
  const b = (body ?? {}) as { profilePath?: string; trigger?: string };
  if (!b.profilePath || typeof b.profilePath !== "string") {
    badRequest(res, "profilePath is required");
    return;
  }
  const job = store.createJob("watch-trigger");
  json(res, 202, { jobId: job.id });
  void (async () => {
    try {
      const result = await runWatchCycle({ profilePath: b.profilePath as string, once: true, trigger: b.trigger });
      store.finishJob(job.id, {
        status: result.status,
        engagementId: result.engagementId,
        engagementStatus: result.engagementStatus,
        reason: result.reason,
      });
    } catch (err) {
      store.failJob(job.id, err);
    }
  })();
}
