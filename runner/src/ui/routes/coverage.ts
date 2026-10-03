/**
 * Coverage + compliance views (v0.22.0).
 *
 * GET /api/engagements/:id/coverage — per-item verdict counts from
 * item-verdicts.json plus the cell summary from state.json.
 * GET /api/engagements/:id/compliance — compliance pack, attestation, and
 * safety manifest rendered to sanitized HTML.
 */

import type { ServerResponse } from "node:http";
import type { UiStore } from "../store.js";
import { engagementDir } from "../store.js";
import { readState } from "../../events.js";
import { renderMarkdown } from "../markdown.js";
import { json } from "./http.js";

interface ItemVerdictJson {
  key: string;
  disposition: string;
}

/** GET /api/engagements/:id/coverage */
export function handleCoverage(store: UiStore, res: ServerResponse, id: string): void {
  const dir = engagementDir(store.engagementsDir, id);
  if (!dir) {
    json(res, 404, { error: "unknown engagement" });
    return;
  }
  const state = readState(dir);
  const raw = store.readJsonArtifact(id, "item-verdicts.json");
  const verdicts = Array.isArray(raw) ? (raw as ItemVerdictJson[]) : [];
  const byDisposition: Record<string, number> = {};
  for (const v of verdicts) {
    byDisposition[v.disposition] = (byDisposition[v.disposition] ?? 0) + 1;
  }
  json(res, 200, {
    cells: state?.batteryCoverage ?? null,
    total: verdicts.length,
    byDisposition,
    pending: verdicts.filter((v) => v.disposition === "pending").map((v) => v.key).slice(0, 200),
    pendingTotal: byDisposition["pending"] ?? 0,
  });
}

/** GET /api/engagements/:id/compliance */
export function handleCompliance(store: UiStore, res: ServerResponse, id: string): void {
  const dir = engagementDir(store.engagementsDir, id);
  if (!dir) {
    json(res, 404, { error: "unknown engagement" });
    return;
  }
  const pack = store.readTextArtifact(id, "compliance-pack.md");
  const attestation = store.readTextArtifact(id, "attestation.md");
  const safety = store.readTextArtifact(id, "safety-manifest.md");
  const report = store.readTextArtifact(id, "report.md");
  json(res, 200, {
    packHtml: pack ? renderMarkdown(pack) : null,
    attestationHtml: attestation ? renderMarkdown(attestation) : null,
    safetyHtml: safety ? renderMarkdown(safety) : null,
    reportHtml: report ? renderMarkdown(report) : null,
  });
}
