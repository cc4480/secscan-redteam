/**
 * INTEGRATIONS — ticket orchestration + retest loop (v0.15.0).
 *
 * After the report phase, every confirmed finding is synced to the
 * configured ticketing sinks (Jira and/or ServiceNow). The linkage is
 * persisted in `integrations.json` (findingId → ticket references) so the
 * standalone `reverify` command can update the same tickets later:
 *   - verdict "reproduced"     → ticket comment: still present
 *   - verdict "not-reproduced" → ticket comment + resolve attempt: verified fixed
 *   - verdict "target-changed" → ticket comment: target changed, needs review
 *
 * Every sink call is individually try/caught: one failing integration
 * never blocks the others, and a total integration failure never breaks
 * the report. The engagement report lists what was attempted/skipped.
 */

import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../types.js";
import type { PocBundle } from "../proof/bundle.js";
import type { ReverifyReport } from "../proof/reverify.js";
import {
  resolveJiraConfig,
  resolveSnowConfig,
  type JiraConfig,
  type SnowConfig,
} from "./config.js";
import { createJiraIssue, commentJiraIssue, transitionJiraIssueDone } from "./jira.js";
import { createSnowRecord, updateSnowRecord } from "./snow.js";
import { defaultHttp, type HttpFn } from "./http.js";

/** Persisted linkage: which ticket(s) each finding got. */
export interface TicketMapping {
  engagementId: string;
  writtenAt: string;
  tickets: Record<string, { jiraKey?: string; snowSysId?: string }>;
}

export interface IntegrationAttempt {
  sink: "jira" | "servicenow" | "slack" | "siem";
  status: "ok" | "skipped" | "failed";
  detail: string;
}

export interface TicketSyncInput {
  engagementId: string;
  target: string;
  findings: Finding[];
  /** findingId → bundle for confirmed findings that earned one. */
  bundles: Map<string, PocBundle>;
  env?: NodeJS.ProcessEnv;
  http?: HttpFn;
}

export interface TicketSyncResult {
  mapping: TicketMapping;
  attempts: IntegrationAttempt[];
}

function isConfigured<T extends { configured: boolean }>(r: T | { configured: false; reason: string }): r is T {
  return r.configured === true;
}

async function syncOneFinding(
  cfg: { jira?: JiraConfig; snow?: SnowConfig },
  finding: Finding,
  bundle: PocBundle | null,
  engagementId: string,
  target: string,
  http: HttpFn,
  attempts: IntegrationAttempt[],
): Promise<{ jiraKey?: string; snowSysId?: string }> {
  const out: { jiraKey?: string; snowSysId?: string } = {};
  if (cfg.jira) {
    try {
      out.jiraKey = await createJiraIssue(cfg.jira, { finding, bundle, engagementId, target }, http);
      attempts.push({ sink: "jira", status: "ok", detail: `${finding.id} → ${out.jiraKey}` });
    } catch (err) {
      attempts.push({ sink: "jira", status: "failed", detail: `${finding.id}: ${(err as Error).message}` });
    }
  }
  if (cfg.snow) {
    try {
      out.snowSysId = await createSnowRecord(cfg.snow, { finding, bundle, engagementId, target }, http);
      attempts.push({ sink: "servicenow", status: "ok", detail: `${finding.id} → sys_id ${out.snowSysId.slice(0, 8)}…` });
    } catch (err) {
      attempts.push({ sink: "servicenow", status: "failed", detail: `${finding.id}: ${(err as Error).message}` });
    }
  }
  return out;
}

/**
 * Sync confirmed findings to configured ticketing sinks. Writes
 * integrations.json into dir. Never throws — failures are recorded in
 * attempts.
 */
export async function syncFindingsToTickets(input: TicketSyncInput, dir: string): Promise<TicketSyncResult> {
  const env = input.env ?? process.env;
  const http = input.http ?? defaultHttp();
  const attempts: IntegrationAttempt[] = [];
  const mapping: TicketMapping = { engagementId: input.engagementId, writtenAt: new Date().toISOString(), tickets: {} };

  const jiraRes = resolveJiraConfig(env);
  const snowRes = resolveSnowConfig(env);
  if (!isConfigured(jiraRes)) attempts.push({ sink: "jira", status: "skipped", detail: jiraRes.reason });
  if (!isConfigured(snowRes)) attempts.push({ sink: "servicenow", status: "skipped", detail: snowRes.reason });
  const jiraCfg = isConfigured(jiraRes) ? jiraRes : undefined;
  const snowCfg = isConfigured(snowRes) ? snowRes : undefined;

  if (!jiraCfg && !snowCfg) {
    writeFileSync(join(dir, "integrations.json"), JSON.stringify(mapping, null, 2));
    return { mapping, attempts };
  }

  for (const f of input.findings) {
    if (f.status !== "confirmed") continue;
    const refs = await syncOneFinding(
      { jira: jiraCfg, snow: snowCfg },
      f,
      input.bundles.get(f.id) ?? null,
      input.engagementId,
      input.target,
      http,
      attempts,
    );
    if (refs.jiraKey || refs.snowSysId) mapping.tickets[f.id] = refs;
  }
  writeFileSync(join(dir, "integrations.json"), JSON.stringify(mapping, null, 2));
  return { mapping, attempts };
}

/** Load a previously written mapping (reverify side). Null when absent. */
export function loadTicketMapping(dir: string): TicketMapping | null {
  const path = join(dir, "integrations.json");
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as TicketMapping;
  } catch {
    return null;
  }
}

export interface RetestUpdateResult {
  attempts: IntegrationAttempt[];
}

/**
 * Retest loop: after `reverify` produces a verdict, update the linked
 * tickets. reproduced → "still present"; not-reproduced → "verified fixed"
 * (resolve attempted); target-changed → "needs review". Never throws.
 */
export async function updateTicketsForReverify(
  mapping: TicketMapping,
  bundle: PocBundle,
  report: ReverifyReport,
  opts: { env?: NodeJS.ProcessEnv; http?: HttpFn } = {},
): Promise<RetestUpdateResult> {
  const env = opts.env ?? process.env;
  const http = opts.http ?? defaultHttp();
  const attempts: IntegrationAttempt[] = [];
  const refs = mapping.tickets[bundle.findingId];
  if (!refs || (!refs.jiraKey && !refs.snowSysId)) {
    attempts.push({ sink: "jira", status: "skipped", detail: `no linked ticket for ${bundle.findingId} — nothing to update` });
    return { attempts };
  }

  const verdictLine =
    report.verdict === "reproduced"
      ? `Re-test ${new Date().toISOString()}: STILL PRESENT — the PoC steps reproduced the finding.`
      : report.verdict === "not-reproduced"
        ? `Re-test ${new Date().toISOString()}: VERIFIED FIXED — the PoC steps no longer reproduce the finding.`
        : `Re-test ${new Date().toISOString()}: TARGET CHANGED — steps could not run cleanly; needs human review.`;
  const note = [`${verdictLine}`, ``, report.summary.slice(0, 800)].join("\n");

  const jiraRes = resolveJiraConfig(env);
  if (refs.jiraKey && isConfigured(jiraRes)) {
    try {
      await commentJiraIssue(jiraRes, refs.jiraKey, [verdictLine, report.summary.slice(0, 800)], http);
      let transitioned = false;
      if (report.verdict === "not-reproduced") {
        transitioned = await transitionJiraIssueDone(jiraRes, refs.jiraKey, http);
      }
      attempts.push({
        sink: "jira",
        status: "ok",
        detail: `${refs.jiraKey}: commented (${report.verdict})${transitioned ? ", transitioned to done" : ""}`,
      });
    } catch (err) {
      attempts.push({ sink: "jira", status: "failed", detail: `${refs.jiraKey}: ${(err as Error).message}` });
    }
  } else if (refs.jiraKey) {
    attempts.push({ sink: "jira", status: "skipped", detail: `Jira not configured — cannot update ${refs.jiraKey}` });
  }

  const snowRes = resolveSnowConfig(env);
  if (refs.snowSysId && isConfigured(snowRes)) {
    try {
      const done = await updateSnowRecord(snowRes, refs.snowSysId, note, report.verdict === "not-reproduced", http);
      attempts.push({ sink: "servicenow", status: "ok", detail: `sys_id ${refs.snowSysId.slice(0, 8)}…: ${done}` });
    } catch (err) {
      attempts.push({ sink: "servicenow", status: "failed", detail: `sys_id ${refs.snowSysId.slice(0, 8)}…: ${(err as Error).message}` });
    }
  } else if (refs.snowSysId) {
    attempts.push({ sink: "servicenow", status: "skipped", detail: `ServiceNow not configured — cannot update record` });
  }

  return { attempts };
}
