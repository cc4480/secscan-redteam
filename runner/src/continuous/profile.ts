/**
 * CONTINUOUS TESTING — watch profiles (v0.16.0).
 *
 * A watch profile is the standing configuration for continuous testing:
 * what to test (the full EngagementInput), how often (cadence), and until
 * when the authorization is fresh (scopeValidUntil — fail closed past it).
 *
 * Profiles are plain JSON files so they can live in version control next
 * to the engagement's authorization paperwork:
 *
 * ```json
 * {
 *   "version": 1,
 *   "name": "secscan-us-weekly",
 *   "engagement": {
 *     "target": "secscan.us", "mode": "red",
 *     "objective": "continuous external attack-surface validation",
 *     "roe": { "scope": ["secscan.us"] },
 *     "fullBattery": true
 *   },
 *   "cadence": { "intervalHours": 168 },
 *   "scopeValidUntil": "2026-12-31T23:59:59Z",
 *   "alertSeverities": ["critical", "high"]
 * }
 * ```
 *
 * Cadence is interval-based on purpose: for cron-style scheduling, point
 * an external scheduler (cron/systemd/CI) at
 * `redteam-runner watch --profile <file> --once`. Targeted subsets are
 * expressed through the engagement itself (--targets / excludedTechniques
 * in the ROE) — the watcher runs the engagement as declared, honestly.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { EngagementInput, EngagementMode } from "../types.js";

export const WATCH_PROFILE_VERSION = 1;

export interface WatchCadence {
  /** Hours between scheduled runs. Must be > 0. */
  intervalHours: number;
}

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";

/**
 * v0.26.0: per-profile log-retention overrides for the watch home's
 * history.jsonl (and the cycle engagements' logs). CLI --log-max-bytes /
 * --log-max-archives and the REDTEAM_LOG_* env vars override these.
 */
export interface WatchLogRetention {
  /** Rotate once a log exceeds this many bytes. Positive integer. */
  maxBytes?: number;
  /** Archives to keep per log file. Positive integer. */
  maxArchives?: number;
}

export interface WatchProfile {
  version: 1;
  /** Short slug, used in engagement IDs and the baseline file. */
  name: string;
  /** The engagement to run every cycle — targets, scope, ROE, mode. */
  engagement: EngagementInput;
  cadence: WatchCadence;
  /**
   * ISO timestamp bounding the authorization. The watcher REFUSES to run
   * past it — fail closed. Renew by editing the profile (with the client's
   * fresh authorization), never by the runner.
   */
  scopeValidUntil: string;
  /**
   * New-finding severities that trigger immediate Slack drift alerts.
   * Default ["critical", "high"]. Ticket creation for new findings goes
   * through the engagement's normal integration step.
   */
  alertSeverities?: AlertSeverity[];
  /**
   * v0.26.0: log-retention overrides for this profile's history.jsonl and
   * its cycle engagements. Optional; CLI flags and REDTEAM_LOG_* env vars
   * override these, and everything falls back to the 50 MiB / 5-archive
   * defaults. Without a cap, a daily-cadence profile grows disk forever.
   */
  logRetention?: WatchLogRetention;
}

const ALERT_SEVERITIES: AlertSeverity[] = ["critical", "high", "medium", "low", "info"];

function fail(path: string, why: string): never {
  throw new Error(`[watch] bad profile ${path}: ${why}`);
}

/** Load and strictly validate a watch profile file. Throws with a clear reason. */
export function loadWatchProfile(profilePath: string): WatchProfile {
  const path = resolve(profilePath);
  if (!existsSync(path)) fail(path, "file not found");
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    fail(path, `not valid JSON: ${(err as Error).message}`);
  }
  const p = raw as Record<string, unknown>;
  if (p["version"] !== WATCH_PROFILE_VERSION) fail(path, `version must be ${WATCH_PROFILE_VERSION}`);
  if (typeof p["name"] !== "string" || p["name"].trim().length === 0) fail(path, `"name" must be a non-empty string`);
  const name = (p["name"] as string).trim();
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(name)) {
    fail(path, `"name" must be a short slug (letters, digits, -, _) for use in engagement IDs`);
  }
  const e = p["engagement"] as Record<string, unknown> | undefined;
  if (!e || typeof e !== "object") fail(path, `"engagement" must be an EngagementInput object`);
  if (typeof e["target"] !== "string" || !e["target"].trim()) fail(path, `"engagement.target" is required`);
  if (e["mode"] !== "red" && e["mode"] !== "black") fail(path, `"engagement.mode" must be "red" or "black"`);
  if (typeof e["objective"] !== "string" || !e["objective"].trim()) fail(path, `"engagement.objective" is required`);
  const roe = e["roe"] as Record<string, unknown> | undefined;
  if (!roe || !Array.isArray(roe["scope"]) || (roe["scope"] as unknown[]).length === 0) {
    fail(path, `"engagement.roe.scope" must be a non-empty array of exact hosts`);
  }
  const cad = p["cadence"] as Record<string, unknown> | undefined;
  if (!cad || typeof cad["intervalHours"] !== "number" || !Number.isFinite(cad["intervalHours"]) || cad["intervalHours"] <= 0) {
    fail(path, `"cadence.intervalHours" must be a positive number`);
  }
  if (typeof p["scopeValidUntil"] !== "string" || Number.isNaN(Date.parse(p["scopeValidUntil"] as string))) {
    fail(path, `"scopeValidUntil" must be a valid ISO timestamp`);
  }
  if (p["alertSeverities"] !== undefined) {
    if (!Array.isArray(p["alertSeverities"]) || (p["alertSeverities"] as unknown[]).some((s) => !ALERT_SEVERITIES.includes(s as AlertSeverity))) {
      fail(path, `"alertSeverities" must be a subset of ${ALERT_SEVERITIES.join(", ")}`);
    }
  }
  const lr = p["logRetention"] as Record<string, unknown> | undefined;
  if (lr !== undefined) {
    if (typeof lr !== "object" || Array.isArray(lr)) fail(path, `"logRetention" must be an object`);
    for (const key of ["maxBytes", "maxArchives"] as const) {
      const v = lr[key];
      if (v !== undefined && (!Number.isInteger(v) || (v as number) <= 0)) {
        fail(path, `"logRetention.${key}" must be a positive integer`);
      }
    }
  }
  return {
    version: 1,
    name,
    engagement: {
      target: (e["target"] as string).trim(),
      mode: e["mode"] as EngagementMode,
      objective: (e["objective"] as string).trim(),
      roe: e["roe"] as WatchProfile["engagement"]["roe"],
      client: typeof e["client"] === "string" ? e["client"] : undefined,
      operatorName: typeof e["operatorName"] === "string" ? e["operatorName"] : undefined,
      fullBattery: e["fullBattery"] === true,
      targets: Array.isArray(e["targets"]) ? (e["targets"] as WatchProfile["engagement"]["targets"]) : undefined,
      environment: e["environment"] === "production" ? "production" : e["environment"] === "staging" ? "staging" : undefined,
      confirmProduction: e["confirmProduction"] === true,
    },
    cadence: { intervalHours: cad["intervalHours"] as number },
    scopeValidUntil: p["scopeValidUntil"] as string,
    alertSeverities: p["alertSeverities"] as AlertSeverity[] | undefined,
    logRetention:
      lr === undefined
        ? undefined
        : {
            maxBytes: lr["maxBytes"] as number | undefined,
            maxArchives: lr["maxArchives"] as number | undefined,
          },
  };
}

/**
 * Authorization freshness — the continuous-mode safety contract. Every
 * cycle (scheduled or triggered) re-checks this; past expiry the watcher
 * refuses to run, fail closed. Renewal is a human act (fresh client
 * authorization → edit the profile), never automatic.
 */
export function checkScopeFresh(
  profile: WatchProfile,
  now: Date = new Date(),
): { ok: true } | { ok: false; reason: string } {
  const until = new Date(profile.scopeValidUntil);
  if (Number.isNaN(until.getTime())) {
    return { ok: false, reason: `scopeValidUntil is not a valid timestamp: ${profile.scopeValidUntil}` };
  }
  if (now.getTime() > until.getTime()) {
    return {
      ok: false,
      reason:
        `scope authorization expired at ${profile.scopeValidUntil} — refusing to run. ` +
        `Renew the client's authorization and update scopeValidUntil in the profile; the runner never extends it itself.`,
    };
  }
  return { ok: true };
}

/** Profile home directory: runs/, baseline.json and drift records live here. */
export function profileHome(profilePath: string): string {
  return dirname(resolve(profilePath));
}

/** Default alert severities when the profile doesn't declare them. */
export function alertSeverities(profile: WatchProfile): AlertSeverity[] {
  return profile.alertSeverities ?? ["critical", "high"];
}
