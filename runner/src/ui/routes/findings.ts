/**
 * Findings + proof bundles (v0.22.0).
 *
 * GET /api/engagements/:id/findings — confirmed findings from state.json,
 * each flagged with whether a PoC bundle exists.
 * GET /api/engagements/:id/proof/:fid — the PoC bundle JSON (already
 * redacted at build time; secrets never stored in bundles).
 */

import type { ServerResponse } from "node:http";
import type { UiStore } from "../store.js";
import { engagementDir } from "../store.js";
import { readState } from "../../events.js";
import { json } from "./http.js";

/** GET /api/engagements/:id/findings */
export function handleFindings(store: UiStore, res: ServerResponse, id: string): void {
  const dir = engagementDir(store.engagementsDir, id);
  if (!dir) {
    json(res, 404, { error: "unknown engagement" });
    return;
  }
  const state = readState(dir);
  if (!state) {
    json(res, 404, { error: "no state for engagement" });
    return;
  }
  const bundles = new Set(store.listSubdir(id, "poc").map((f) => f.replace(/\.json$/, "")));
  json(
    res,
    200,
    state.findings.map((f) => ({
      ...f,
      hasProof: bundles.has(f.id),
    })),
  );
}

/** GET /api/engagements/:id/proof/:fid */
export function handleProof(store: UiStore, res: ServerResponse, id: string, fid: string): void {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(fid)) {
    json(res, 400, { error: "bad finding id" });
    return;
  }
  const bundle = store.readJsonArtifact(id, `poc/${fid}.json`);
  if (!bundle) {
    json(res, 404, { error: "no proof bundle for finding" });
    return;
  }
  json(res, 200, bundle);
}
