/**
 * One watch cycle: freshness gate -> engagement -> drift -> baseline ->
 * alerts. Never throws for operational failures — they become a result
 * with status refused/error and a reason.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { WatchProfile } from "../profile.js";
import { resolveLogRotationConfig } from "../../safety/rotation.js";
import {
  alertSeverities,
  checkScopeFresh,
  loadWatchProfile,
  profileHome,
} from "../profile.js";
import {
  emptyBaseline,
  loadBaseline,
  saveBaseline,
} from "../baseline.js";
import type { WatchBaseline } from "../baseline.js";
import {
  applyDriftToBaseline,
  buildDriftReport,
  classifyDrift,
  flagBaselineNeedsReview,
  remediateBaselineEntries,
  renderDriftMarkdown,
  resolveMissingDrift,
  touchBaselineEntries,
} from "../drift.js";
import type { DriftReport, ReverifyFn } from "../drift.js";
import type { EngagementInput, EngagementResult, EngagementStatus, Finding } from "../../types.js";
import { runEngagement } from "../../phases.js";
import type { RunOptions } from "../../phases.js";
import { defaultHttp } from "../../integrations/index.js";
import type { HttpFn } from "../../integrations/index.js";
import {
  appendHistory,
  appendSection,
  bestEffortSlack,
  cycleEngagementId,
  ensureDriftTickets,
  realReverifyFn,
  slug,
} from "./helpers.js";


import type { WatchCycleOptions, WatchCycleResult, WatchCycleStatus } from "./types.js";

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

  // v0.26.0: log rotation — CLI flags > env > profile logRetention > defaults.
  // Covers the watch home's history.jsonl and this cycle's engagement logs.
  const rotation = resolveLogRotationConfig(env, {
    maxLogBytes: opts.maxLogBytes ?? profile.logRetention?.maxBytes,
    maxLogArchives: opts.maxLogArchives ?? profile.logRetention?.maxArchives,
  });

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
    appendHistory(home, { ts: now.toISOString(), status: "refused", reason: fresh.reason, trigger }, rotation);
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
      maxLogBytes: rotation.maxBytes,
      maxLogArchives: rotation.maxArchives,
    });
  } catch (err) {
    const reason = `engagement threw: ${(err as Error).message}`;
    appendHistory(home, { ts: now.toISOString(), status: "error", engagementId, reason, trigger }, rotation);
    return { status: "error", engagementId, reason };
  }
  const runDir = join(runsDir, engagementId);

  if (result.status !== "complete") {
    const reason = `engagement ${result.status}: ${result.blockedReason ?? "no reason recorded"}`;
    appendHistory(home, { ts: now.toISOString(), status: "error", engagementId, reason, trigger }, rotation);
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
  }, rotation);

  return { status: "complete", engagementId, engagementStatus: result.status, drift };
}

/**
 * Loop watch cycles on the profile's cadence until aborted. The profile is
 * re-read every cycle so authorization renewals (scopeValidUntil edits)
 * take effect without restarting the watcher. One bad cycle never kills
 * the loop.
 */
