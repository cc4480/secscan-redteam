/**
 * INTEGRATIONS — configuration resolution (v0.15.0).
 *
 * Enterprise buyers need findings to flow into their workflows: Jira /
 * ServiceNow ticketing, Slack notifications, SIEM ingestion. Every
 * integration is operator-configured via env / Secure Vault and
 * fail-closed: when unconfigured, the resolver says so with a clear
 * reason, the engagement logs the skip, and the report lists it —
 * the engagement itself is never halted by a missing integration.
 *
 * No finding data leaves the runner except to the operator-configured
 * endpoints. See docs/integrations.md for the full data-flow.
 */

export interface JiraConfig {
  configured: true;
  baseUrl: string;
  /** Jira account email for Basic auth. */
  user: string;
  /** API token — password-grade secrecy, never logged. */
  apiToken: string;
  /** Project key, e.g. "SEC". */
  project: string;
  /** Issue type name. Default "Task". */
  issueType: string;
  /** Severity → Jira priority id. Defaults are the stock Jira ids. */
  priorityMap: Record<string, string>;
}

export interface SnowConfig {
  configured: true;
  /** Full instance URL, e.g. https://acme.service-now.com */
  instance: string;
  user: string;
  /** Password — password-grade secrecy, never logged. */
  password: string;
  /** Table to write. Default "incident". */
  table: string;
}

export interface SlackConfig {
  configured: true;
  /** Incoming webhook URL — secret, never logged. */
  webhookUrl: string;
}

export type Unconfigured = { configured: false; reason: string };

export type JiraResolution = JiraConfig | Unconfigured;
export type SnowResolution = SnowConfig | Unconfigured;
export type SlackResolution = SlackConfig | Unconfigured;

const DEFAULT_PRIORITY_MAP: Record<string, string> = {
  critical: "1", // Highest
  high: "2", // High
  medium: "3", // Medium
  low: "4", // Low
  info: "5", // Lowest
};

function required(
  env: NodeJS.ProcessEnv,
  names: string[],
): { ok: true; values: Record<string, string> } | { ok: false; missing: string[] } {
  const missing = names.filter((n) => !(env[n] ?? "").trim());
  if (missing.length > 0) return { ok: false, missing };
  const values: Record<string, string> = {};
  for (const n of names) values[n] = env[n]!.trim();
  return { ok: true, values };
}

const SETUP_HINT = "Set the REDTEAM_* env vars (or Secure Vault equivalents) — see docs/integrations.md.";

export function resolveJiraConfig(env: NodeJS.ProcessEnv = process.env): JiraResolution {
  const r = required(env, ["REDTEAM_JIRA_BASE_URL", "REDTEAM_JIRA_USER", "REDTEAM_JIRA_API_TOKEN", "REDTEAM_JIRA_PROJECT"]);
  if (!r.ok) {
    return { configured: false, reason: `Jira not configured (missing ${r.missing.join(", ")}). ${SETUP_HINT}` };
  }
  let priorityMap = { ...DEFAULT_PRIORITY_MAP };
  const raw = (env["REDTEAM_JIRA_PRIORITY_MAP"] ?? "").trim();
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as Record<string, string>;
      priorityMap = { ...priorityMap, ...parsed };
    } catch {
      return { configured: false, reason: `REDTEAM_JIRA_PRIORITY_MAP is not valid JSON — fix or unset it. ${SETUP_HINT}` };
    }
  }
  const baseUrl = r.values["REDTEAM_JIRA_BASE_URL"]!.replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(baseUrl)) {
    return { configured: false, reason: `REDTEAM_JIRA_BASE_URL must be an http(s) URL. ${SETUP_HINT}` };
  }
  return {
    configured: true,
    baseUrl,
    user: r.values["REDTEAM_JIRA_USER"]!,
    apiToken: r.values["REDTEAM_JIRA_API_TOKEN"]!,
    project: r.values["REDTEAM_JIRA_PROJECT"]!,
    issueType: (env["REDTEAM_JIRA_ISSUE_TYPE"] ?? "").trim() || "Task",
    priorityMap,
  };
}

export function resolveSnowConfig(env: NodeJS.ProcessEnv = process.env): SnowResolution {
  const r = required(env, ["REDTEAM_SNOW_INSTANCE", "REDTEAM_SNOW_USER", "REDTEAM_SNOW_PASSWORD"]);
  if (!r.ok) {
    return { configured: false, reason: `ServiceNow not configured (missing ${r.missing.join(", ")}). ${SETUP_HINT}` };
  }
  const instance = r.values["REDTEAM_SNOW_INSTANCE"]!.replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(instance)) {
    return { configured: false, reason: `REDTEAM_SNOW_INSTANCE must be an http(s) URL. ${SETUP_HINT}` };
  }
  return {
    configured: true,
    instance,
    user: r.values["REDTEAM_SNOW_USER"]!,
    password: r.values["REDTEAM_SNOW_PASSWORD"]!,
    table: (env["REDTEAM_SNOW_TABLE"] ?? "").trim() || "incident",
  };
}

export function resolveSlackConfig(env: NodeJS.ProcessEnv = process.env): SlackResolution {
  const url = (env["REDTEAM_SLACK_WEBHOOK_URL"] ?? "").trim();
  if (!url) {
    return { configured: false, reason: `Slack not configured (missing REDTEAM_SLACK_WEBHOOK_URL). ${SETUP_HINT}` };
  }
  if (!/^https:\/\//i.test(url)) {
    return { configured: false, reason: `REDTEAM_SLACK_WEBHOOK_URL must be an https URL. ${SETUP_HINT}` };
  }
  return { configured: true, webhookUrl: url };
}

/** Names of env vars that carry secrets — redacted from any log/error text. */
export const INTEGRATION_SECRET_ENVS = [
  "REDTEAM_JIRA_API_TOKEN",
  "REDTEAM_SNOW_PASSWORD",
  "REDTEAM_SLACK_WEBHOOK_URL",
];
