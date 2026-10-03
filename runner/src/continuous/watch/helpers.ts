/**
 * Watch-cycle helpers: ids, the real reverify fn, best-effort Slack,
 * drift-ticket backfill, and run-dir/history appends. The cycle itself
 * lives in cycle.ts; the loop in loop.ts.
 */

import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { WatchProfile } from "../profile.js";
import { createReplayer, reverifyBundle } from "../../proof/index.js";
import type { PocBundle } from "../../proof/index.js";
import {
  loadTicketMapping,
  notifySlack,
  resolveSlackConfig,
  syncFindingsToTickets,
} from "../../integrations/index.js";
import type { HttpFn } from "../../integrations/index.js";
import type { EngagementInput } from "../../types.js";
import type { DriftReport, ReverifyFn } from "../drift.js";

export function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "watch";
}

export function cycleEngagementId(profile: WatchProfile, trigger: string | undefined, now: Date): string {
  const d = now.toISOString().slice(0, 10).replace(/-/g, "");
  const rand = Math.random().toString(36).slice(2, 6);
  return `watch-${slug(profile.name)}-${trigger ? "trigger-" : ""}${d}-${rand}`;
}

/** Real reverify: bundle → reverifyBundle with the production replayer. */
export function realReverifyFn(scope: string[], env: NodeJS.ProcessEnv): ReverifyFn {
  const killSwitch = { aborted: false };
  const replayer = createReplayer({ scope, env, killSwitch });
  return async (bundlePath: string) => {
    const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
    const report = await reverifyBundle(bundle, replayer);
    return { verdict: report.verdict, note: report.summary };
  };
}

/** Best-effort Slack send. Never throws. */
export async function bestEffortSlack(
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
export async function ensureDriftTickets(
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

export function appendSection(filePath: string, body: string): void {
  try {
    if (!existsSync(filePath)) return;
    appendFileSync(filePath, `\n\n---\n\n${body}`);
  } catch {
    // best-effort only
  }
}

export function appendHistory(home: string, line: Record<string, unknown>): void {
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
