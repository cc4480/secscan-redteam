/**
 * CONTINUOUS TESTING — watch cycles (v0.16.0).
 *
 * One watch cycle = one engagement run + drift detection against the
 * rolling baseline + alerts. The safety contract:
 *
 *   - Every cycle re-checks scopeValidUntil (fail closed past expiry).
 *   - Every cycle runs the full engagement pipeline — authorization,
 *     ownership verification, ROE, rate limits, kill switch, production
 *     graduation — nothing is weakened because the run is scheduled.
 *   - "Remediated" requires a confirming reverify; anything else that
 *     can't be mechanically resolved stays open as needs-review.
 *   - Drift alerts and ticket sync are best-effort and never break the
 *     cycle; the baseline update is the source of truth and always lands.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  alertSeverities,
  checkScopeFresh,
  loadWatchProfile,
  profileHome,
  type WatchProfile,
} from "./profile.js";
import {
  emptyBaseline,
  loadBaseline,
  saveBaseline,
  type WatchBaseline,
} from "./baseline.js";
import {
  applyDriftToBaseline,
  buildDriftReport,
  classifyDrift,
  flagBaselineNeedsReview,
  remediateBaselineEntries,
  renderDriftMarkdown,
  resolveMissingDrift,
  touchBaselineEntries,
  type DriftReport,
  type ReverifyFn,
} from "./drift.js";
import type { EngagementInput, EngagementResult, EngagementStatus, Finding } from "../types.js";
import { runEngagement, type RunOptions } from "../phases.js";
import { createReplayer, reverifyBundle, type PocBundle } from "../proof/index.js";
import {
  defaultHttp,
  loadTicketMapping,
  notifySlack,
  resolveSlackConfig,
  syncFindingsToTickets,
  type HttpFn,
} from "../integrations/index.js";

export interface WatchCycleOptions {
  profilePath: string;
  /** Single cycle (also implied by --trigger). The loop calls this per cycle. */
  once?: boolean;
  /** CI/CD change reference, e.g. "deploy abc123" — tags the drift report. */
  trigger?: string;
  env?: NodeJS.ProcessEnv;
  /** Injected HTTP for integrations (tests). */
  http?: HttpFn;
  /** Injected clock (tests). */
  now?: () => Date;
  /** Injected engagement runner (tests). Defaults to runEngagement. */
  runFn?: (input: EngagementInput, opts: RunOptions) => Promise<EngagementResult>;
  /** Injected reverify (tests). Defaults to the real replayer. */
  reverifyFn?: ReverifyFn;
  /** Per-host rate limit override, passed through to runEngagement. */
  maxRpsPerHost?: number;
}

export type WatchCycleStatus = "complete" | "refused" | "error";

export interface WatchCycleResult {
  status: WatchCycleStatus;
  engagementId?: string;
  engagementStatus?: EngagementStatus;
  drift?: DriftReport;
  /** Machine-readable reason for refused/error. */
  reason?: string;
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "watch";
}

function cycleEngagementId(profile: WatchProfile, trigger: string | undefined, now: Date): string {
  const d = now.toISOString().slice(0, 10).replace(/-/g, "");
  const rand = Math.random().toString(36).slice(2, 6);
  return `watch-${slug(profile.name)}-${trigger ? "trigger-" : ""}${d}-${rand}`;
}

/** Real reverify: bundle → reverifyBundle with the production replayer. */
function realReverifyFn(scope: string[], env: NodeJS.ProcessEnv): ReverifyFn {
  const killSwitch = { aborted: false };
  const replayer = createReplayer({ scope, env, killSwitch });
  return async (bundlePath: string) => {
    const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
    const report = await reverifyBundle(bundle, replayer);
    return { verdict: report.verdict, note: report.summary };
  };
}

/** Best-effort Slack send. Never throws. */
async function bestEffortSlack(
  env: NodeJS.ProcessEnv,
  http: HttpFn,
  ev: Parameters<typeof notifySlack>[1],
): Promise<void> {
  try {
    const cfg = resolveSlackConfig(env);
    if (!cfg.configured) return;
    await notifySlack(cfg, ev, http);
  } catch {
    // best-effort only — alerts never break a cycle
  }
}

/**
 * Ensure every NEW finding has a ticket. The engagement's own reportPhase
 * already synced all confirmed findings (including new ones) via the
 * existing integrations — this only fills gaps (e.g. sinks were
 * unconfigured during reportPhase). Never duplicates: findings already
 * present in integrations.json are skipped, and the mapping is merged,
 * not overwritten.
 */
async function ensureDriftTickets(
  runDir: string,
  drift: DriftReport,
  input: EngagementInput,
  env: NodeJS.ProcessEnv,
  http: HttpFn,
): Promise<void> {
  try {
    if (drift.newFindings.length === 0) return;
    const existing = loadTicketMapping(runDir);
    const have = new Set(Object.keys(existing?.tickets ?? {}));
    const unticketed = drift.newFindings.filter((f) => !have.has(f.id));
    if (unticketed.length === 0) return;
    const bundles = new Map<string, PocBundle>();
    for (const f of unticketed) {
      const p = join(runDir, "poc", `${f.id}.json`);
      if (!existsSync(p)) continue;
      try {
        bundles.set(f.id, JSON.parse(readFileSync(p, "utf8")) as PocBundle);
      } catch {
        // skip unparseable bundle — ticket still created without it
      }
    }
    const { mapping } = await syncFindingsToTickets(
      {
        engagementId: drift.engagementId,
        target: input.target,
        findings: unticketed,
        bundles,
        env,
        http,
      },
      runDir,
    );
    // syncFindingsToTickets rewrote integrations.json with only the new
    // mapping — merge the pre-existing refs back in.
    const merged = {
      engagementId: drift.engagementId,
      writtenAt: new Date().toISOString(),
      tickets: { ...(existing?.tickets ?? {}), ...(mapping?.tickets ?? {}) },
    };
    writeFileSync(join(runDir, "integrations.json"), JSON.stringify(merged, null, 2));
  } catch {
    // best-effort only
  }
}

function appendSection(filePath: string, body: string): void {
  try {
    if (!existsSync(filePath)) return;
    appendFileSync(filePath, `\n\n---\n\n${body}`);
  } catch {
    // best-effort only
  }
}

function appendHistory(home: string, line: Record<string, unknown>): void {
  try {
    appendFileSync(join(home, "history.jsonl"), JSON.stringify(line) + "\n");
  } catch {
    // best-effort only
  }
}

/**
 * Run one watch cycle: freshness gate → engagement → drift → baseline →
 * alerts. Never throws for operational failures — they become a result
 * with status refused/error and a reason.
 */
export async function runWatchCycle(opts: WatchCycleOptions): Promise<WatchCycleResult> {
  const env = opts.env ?? process.env;
  const http = opts.http ?? defaultHttp();
  const now = opts.now ? opts.now() : new Date();
  const trigger = opts.trigger?.trim() || undefined;

  let profile: WatchProfile;
  try {
    profile = loadWatchProfile(opts.profilePath);
  } catch (err) {
    return { status: "error", reason: (err as Error).message };
  }
  const home = profileHome(opts.profilePath);
  const runsDir = join(home, "runs");
  const baselinePath = join(home, "baseline.json");

  // Fail closed on stale authorization — before any packet, every cycle.
  const fresh = checkScopeFresh(profile, now);
  if (!fresh.ok) {
    await bestEffortSlack(env, http, {
      kind: "halted",
      engagementId: `watch-${slug(profile.name)}`,
      target: profile.engagement.target,
      mode: profile.engagement.mode,
      reason: `watch refused: ${fresh.reason}`,
    });
    appendHistory(home, { ts: now.toISOString(), status: "refused", reason: fresh.reason, trigger });
    return { status: "refused", reason: fresh.reason };
  }

  const engagementId = cycleEngagementId(profile, trigger, now);
  const input: EngagementInput = { ...profile.engagement };
  const runFn = opts.runFn ?? runEngagement;
  let result: EngagementResult;
  try {
    result = await runFn(input, {
      engagementsDir: runsDir,
      engagementId,
      maxRpsPerHost: opts.maxRpsPerHost,
    });
  } catch (err) {
    const reason = `engagement threw: ${(err as Error).message}`;
    appendHistory(home, { ts: now.toISOString(), status: "error", engagementId, reason, trigger });
    return { status: "error", engagementId, reason };
  }
  const runDir = join(runsDir, engagementId);

  if (result.status !== "complete") {
    const reason = `engagement ${result.status}: ${result.blockedReason ?? "no reason recorded"}`;
    appendHistory(home, { ts: now.toISOString(), status: "error", engagementId, reason, trigger });
    return { status: "error", engagementId, engagementStatus: result.status, reason };
  }

  // Drift: phase 1 (pure) then phase 2 (reverify) then fold into baseline.
  const confirmed = result.findings.filter((f) => f.status === "confirmed");
  let baseline: WatchBaseline = loadBaseline(baselinePath) ?? emptyBaseline(profile.name);
  if (baseline.profileName !== profile.name) {
    // Never silently merge baselines across profiles/scopes.
    return {
      status: "error",
      engagementId,
      engagementStatus: result.status,
      reason: `baseline.json at ${baselinePath} belongs to profile "${baseline.profileName}", not "${profile.name}" — refusing to merge across profiles. Move it aside to start a fresh baseline.`,
    };
  }
  const classification = classifyDrift(baseline, confirmed, input.target);
  const reverify = opts.reverifyFn ?? realReverifyFn(input.roe.scope, env);
  const resolved = await resolveMissingDrift(classification.missing, runsDir, reverify);
  const drift = buildDriftReport({
    profileName: profile.name,
    engagementId,
    changeRef: trigger,
    classification,
    resolved,
  });

  const nowIso = now.toISOString();
  baseline = applyDriftToBaseline(baseline, drift, input.target, engagementId, nowIso);
  const matchedKeys = classification.unchanged.map(({ entry }) => entry.key);
  const reopenedKeys = drift.reopened.map((m) => m.entry.key);
  const remediatedKeys = drift.remediated.map((m) => m.entry.key);
  baseline = touchBaselineEntries(baseline, [...matchedKeys, ...reopenedKeys], engagementId, nowIso);
  baseline = remediateBaselineEntries(baseline, remediatedKeys, nowIso);
  for (const m of drift.needsReview) {
    baseline = flagBaselineNeedsReview(baseline, [m.entry.key], m.note);
  }
  saveBaseline(baselinePath, baseline);

  // Drift record next to the engagement + appended to the human-readable reports.
  try {
    mkdirSync(runDir, { recursive: true });
    writeFileSync(join(runDir, "drift.json"), JSON.stringify(drift, null, 2));
  } catch {
    // best-effort only — baseline already persisted above
  }
  const driftMd = renderDriftMarkdown(drift);
  appendSection(join(runDir, "report.md"), driftMd);
  appendSection(
    join(runDir, "compliance-pack.md"),
    driftMd.replace(
      `## Continuous drift — watch profile "${profile.name}"`,
      `## Continuous drift (retest update) — watch profile "${profile.name}"`,
    ) + `\n> Machine-readable: \`drift.json\` in this engagement directory.`,
  );

  // Alerts: immediate Slack drift alert for new findings at/above the
  // profile's alert severities; tickets ensured for every new finding.
  const severities = alertSeverities(profile);
  const alertable = drift.newFindings.filter((f) => severities.includes(f.severity as (typeof severities)[number]));
  if (alertable.length > 0 || drift.newFindings.length > 0) {
    await bestEffortSlack(env, http, {
      kind: "drift",
      engagementId,
      target: input.target,
      mode: input.mode,
      drift: {
        newCount: drift.newFindings.length,
        remediatedCount: drift.remediated.length,
        reopenedCount: drift.reopened.length,
        needsReviewCount: drift.needsReview.length,
        ...(trigger ? { changeRef: trigger } : {}),
        topNew: alertable.slice(0, 5).map((f) => ({ id: f.id, severity: f.severity, title: f.title })),
      },
    });
  }
  await ensureDriftTickets(runDir, drift, input, env, http);

  appendHistory(home, {
    ts: nowIso,
    status: "complete",
    engagementId,
    trigger,
    new: drift.newFindings.length,
    unchanged: drift.unchangedCount,
    reopened: drift.reopened.length,
    remediated: drift.remediated.length,
    needsReview: drift.needsReview.length,
  });

  return { status: "complete", engagementId, engagementStatus: result.status, drift };
}

/**
 * Loop watch cycles on the profile's cadence until aborted. The profile is
 * re-read every cycle so authorization renewals (scopeValidUntil edits)
 * take effect without restarting the watcher. One bad cycle never kills
 * the loop.
 */
export async function watchLoop(
  opts: WatchCycleOptions,
  signal?: AbortSignal,
): Promise<void> {
  for (;;) {
    if (signal?.aborted) return;
    let intervalHours = 24;
    try {
      const profile = loadWatchProfile(opts.profilePath);
      intervalHours = profile.cadence.intervalHours;
      const result = await runWatchCycle({ ...opts, once: true });
      console.log(
        `[watch] cycle ${result.status}${result.engagementId ? ` ${result.engagementId}` : ""}` +
          (result.drift
            ? ` — new:${result.drift.newFindings.length} reopened:${result.drift.reopened.length} remediated:${result.drift.remediated.length} needs-review:${result.drift.needsReview.length}`
            : "") +
          (result.reason ? ` — ${result.reason}` : ""),
      );
    } catch (err) {
      console.log(`[watch] cycle error (loop continues): ${(err as Error).message}`);
    }
    const waitMs = Math.max(60_000, intervalHours * 3600_000);
    await new Promise<void>((resolve) => {
      const t = setTimeout(resolve, waitMs);
      signal?.addEventListener("abort", () => {
        clearTimeout(t);
        resolve();
      }, { once: true });
    });
  }
}
