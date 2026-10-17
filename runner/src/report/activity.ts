/**
 * Derived activity section for the engagement report (v0.33.0).
 *
 * Everything here is *projected* from the event stream — it is runner-computed
 * record, never model narrative. It gives the report three things it could not
 * state before:
 *   - what was actually executed, per action, with ATT&CK mapping and seq range
 *   - the operator-decision timeline (sign-off / escalation / abort)
 *   - a mechanical causality-integrity check over `causedBy` links
 */

import type { EngagementEvent } from "../types.js";
import { projectApprovals, projectDanglingCauses, projectToolStats } from "../events/projections.js";

/** Render the tool-activity / decisions / causality section, or "" for an empty log. */
export function buildActivitySection(events: EngagementEvent[]): string {
  if (events.length === 0) return "";
  const stats = projectToolStats(events);
  const decisions = projectApprovals(events);
  const dangling = projectDanglingCauses(events);

  const lines: string[] = [];
  lines.push("---", "", "## Tool activity (runner-computed, derived from events.jsonl)", "");
  lines.push(`**${events.length} events** across **${stats.length} distinct actions**.`, "");
  lines.push("| Action | Count | ATT&CK | First seq | Last seq |");
  lines.push("|---|---|---|---|---|");
  for (const s of stats.slice(0, 40)) {
    lines.push(`| ${s.action} | ${s.count} | ${s.attackIds.join(", ") || "—"} | ${s.firstSeq} | ${s.lastSeq} |`);
  }
  if (stats.length > 40) lines.push(`| … ${stats.length - 40} more actions (see events.jsonl) | | | | |`);
  lines.push("");
  lines.push(
    `**Operator decisions recorded:** ${decisions.length}` +
      (decisions.length > 0 ? ` — ${decisions.map((d) => `${d.action} (seq ${d.seq})`).join(", ")}` : " (none)"),
  );
  lines.push("");
  lines.push(
    dangling.length === 0
      ? "**Causality integrity:** every `causedBy` link resolves."
      : `**Causality integrity:** ${dangling.length} dangling cause reference(s): seq ${dangling.join(", ")}.`,
  );
  return `${lines.join("\n")}\n`;
}
