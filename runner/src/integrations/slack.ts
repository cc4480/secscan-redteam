/**
 * INTEGRATIONS — Slack sink (v0.15.0).
 *
 * Engagement lifecycle notifications via incoming webhook: started, phase
 * transitions, completed (with severity counts), and critical-finding
 * alerts. Best-effort by design — a failed notification is logged and
 * never breaks the engagement.
 */

import type { SlackConfig } from "./config.js";
import { defaultHttp, type HttpFn } from "./http.js";
import { IntegrationHttpError } from "./http.js";

export type SlackEventKind = "started" | "phase" | "completed" | "critical_finding" | "halted";

export interface SlackEvent {
  kind: SlackEventKind;
  engagementId: string;
  target: string;
  mode: string;
  /** Phase name for "phase" events. */
  phase?: string;
  /** Severity counts for "completed" events. */
  severityCounts?: Record<string, number>;
  /** Finding title for "critical_finding" events. */
  findingTitle?: string;
  findingId?: string;
  /** Reason for "halted" events. */
  reason?: string;
}

export function buildSlackPayload(ev: SlackEvent): { text: string; blocks: unknown[] } {
  const header = `*RedTeam* \`${ev.engagementId}\` — ${ev.target} (${ev.mode})`;
  let line: string;
  switch (ev.kind) {
    case "started":
      line = `:crossed_swords: Engagement started.`;
      break;
    case "phase":
      line = `:arrow_forward: Phase: *${ev.phase}*.`;
      break;
    case "completed": {
      const counts = Object.entries(ev.severityCounts ?? {})
        .filter(([, n]) => n > 0)
        .map(([s, n]) => `${s}:${n}`)
        .join(" ");
      line = `:white_check_mark: Engagement completed. Findings — ${counts || "none"}.`;
      break;
    }
    case "critical_finding":
      line = `:rotating_light: *CRITICAL finding* ${ev.findingId}: ${ev.findingTitle}`;
      break;
    case "halted":
      line = `:octagonal_sign: Engagement halted: ${ev.reason}`;
      break;
  }
  return {
    text: `RedTeam ${ev.engagementId}: ${ev.kind}`,
    blocks: [{ type: "section", text: { type: "mrkdwn", text: `${header}\n${line}` } }],
  };
}

/** Fire-and-forget shape: throws on failure so callers can log it. */
export async function notifySlack(
  cfg: SlackConfig,
  ev: SlackEvent,
  http: HttpFn = defaultHttp(),
): Promise<void> {
  const payload = buildSlackPayload(ev);
  const res = await http(cfg.webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const text = await res.text().catch(() => "");
  if (!res.ok) {
    throw new IntegrationHttpError(`Slack webhook failed → HTTP ${res.status}`, res.status, text);
  }
}
