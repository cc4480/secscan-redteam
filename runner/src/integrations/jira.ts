/**
 * INTEGRATIONS — Jira sink (v0.15.0).
 *
 * One issue per confirmed finding: summary, severity→priority mapping,
 * description with proof-bundle reference and remediation guidance,
 * labels carrying the ATT&CK IDs + CVE. Retest loop: comment with the
 * verdict; when a finding is verified fixed, attempt the Done/Resolve
 * transition (best-effort — a comment is always left regardless).
 *
 * Ticket content is the finding + proof reference + fix guidance. No SLA
 * language is ever written; no remediation is ever promised.
 */

import type { Finding } from "../types.js";
import type { PocBundle } from "../proof/bundle.js";
import type { JiraConfig } from "./config.js";
import { basicAuth, defaultHttp, requestJson, type HttpFn } from "./http.js";

/** Minimal Atlassian Document Format paragraph builder (Jira Cloud v3 needs ADF). */
function adfDoc(paragraphs: string[]): unknown {
  return {
    type: "doc",
    version: 1,
    content: paragraphs.map((p) => ({
      type: "paragraph",
      content: [{ type: "text", text: p }],
    })),
  };
}

export interface JiraIssueInput {
  finding: Finding;
  bundle: PocBundle | null;
  engagementId: string;
  target: string;
}

export function buildJiraSummary(input: JiraIssueInput): string {
  const f = input.finding;
  return `[${f.severity.toUpperCase()}] ${f.title} (${f.id}, ${input.target})`.slice(0, 255);
}

export function buildJiraDescription(input: JiraIssueInput): string[] {
  const { finding: f, bundle, engagementId, target } = input;
  const lines: string[] = [
    `SecScan RedTeam finding ${f.id} — confirmed during engagement ${engagementId} against ${target}.`,
    `Severity: ${f.severity}. ATT&CK: ${f.attackIds.join(", ") || "n/a"}.`,
    ``,
    `Evidence:`,
    f.evidence.slice(0, 1500),
  ];
  if (bundle) {
    lines.push(
      ``,
      `Proof of exploitation (bundle ${bundle.bundleId}, ${bundle.validationTier} tier):`,
      bundle.proves.slice(0, 1500),
      `Full bundle: poc/${f.id}.json. Re-verify: \`${bundle.reverifyCommand}\``,
    );
  } else {
    lines.push(``, `No PoC bundle was generated for this finding (honest absence — see report).`);
  }
  lines.push(``, `Remediation guidance:`, f.fix.slice(0, 1500));
  lines.push(``, `This ticket was created by the red-team runner. It asserts the finding and its evidence — nothing more.`);
  return lines;
}

export function buildJiraLabels(input: JiraIssueInput): string[] {
  const labels = ["redteam", `finding-${input.finding.id.toLowerCase()}`];
  for (const a of input.finding.attackIds) labels.push(a.toLowerCase().replace(/[^a-z0-9-]/g, ""));
  if (input.bundle?.cve) labels.push(input.bundle.cve.toLowerCase().replace(/[^a-z0-9-]/g, ""));
  return [...new Set(labels)].filter(Boolean).slice(0, 20);
}

function authHeaders(cfg: JiraConfig): Record<string, string> {
  return { Authorization: basicAuth(cfg.user, cfg.apiToken) };
}

/**
 * Create one issue per finding. Returns the issue key (e.g. "SEC-123").
 * Throws IntegrationHttpError on failure — callers catch and record.
 */
export async function createJiraIssue(
  cfg: JiraConfig,
  input: JiraIssueInput,
  http: HttpFn = defaultHttp(),
): Promise<string> {
  const priorityId = cfg.priorityMap[input.finding.severity] ?? cfg.priorityMap["medium"] ?? "3";
  const body = {
    fields: {
      project: { key: cfg.project },
      summary: buildJiraSummary(input),
      description: adfDoc(buildJiraDescription(input)),
      issuetype: { name: cfg.issueType },
      priority: { id: priorityId },
      labels: buildJiraLabels(input),
    },
  };
  const res = (await requestJson(http, "POST", `${cfg.baseUrl}/rest/api/3/issue`, authHeaders(cfg), body)) as {
    key?: string;
  };
  if (!res.key) throw new Error("Jira create returned no issue key");
  return res.key;
}

export async function commentJiraIssue(
  cfg: JiraConfig,
  issueKey: string,
  paragraphs: string[],
  http: HttpFn = defaultHttp(),
): Promise<void> {
  await requestJson(
    http,
    "POST",
    `${cfg.baseUrl}/rest/api/3/issue/${encodeURIComponent(issueKey)}/comment`,
    authHeaders(cfg),
    { body: adfDoc(paragraphs) },
  );
}

/**
 * Best-effort resolve transition: look up available transitions and pick
 * one named like Done/Resolve(d)/Close(d). Returns false when none matches
 * (the caller still leaves a comment — the ticket is never left silent).
 */
export async function transitionJiraIssueDone(cfg: JiraConfig, issueKey: string, http: HttpFn = defaultHttp()): Promise<boolean> {
  const res = (await requestJson(
    http,
    "GET",
    `${cfg.baseUrl}/rest/api/3/issue/${encodeURIComponent(issueKey)}/transitions`,
    authHeaders(cfg),
  )) as { transitions?: Array<{ id: string; name?: string; to?: { name?: string } }> };
  const match = (res.transitions ?? []).find((t) =>
    /^(done|resolve|resolved|close|closed)$/i.test((t.name ?? "").trim()) ||
    /^(done|resolve|resolved|close|closed)$/i.test((t.to?.name ?? "").trim()),
  );
  if (!match) return false;
  await requestJson(
    http,
    "POST",
    `${cfg.baseUrl}/rest/api/3/issue/${encodeURIComponent(issueKey)}/transitions`,
    authHeaders(cfg),
    { transition: { id: match.id } },
  );
  return true;
}
