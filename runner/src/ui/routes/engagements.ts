/**
 * Engagement routes (v0.22.0): launch, list, detail.
 *
 * Launch calls runEngagement() directly — the same function the CLI calls —
 * with the run detached (no await) so the HTTP request returns immediately.
 * Validation mirrors cli/args.ts buildInput() so the UI can never launch
 * something the CLI would refuse.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { join } from "node:path";
import { runEngagement } from "../../phases.js";
import { isTargetId, type TargetId } from "../../targets.js";
import { parseTier } from "../../accountability/index.js";
import type { EngagementInput } from "../../types.js";
import { readState } from "../../events.js";
import type { UiStore } from "../store.js";
import { engagementDir, generateEngagementId } from "../store.js";
import type { UiLaunchRequest } from "../types.js";
import { json, badRequest } from "./http.js";

function toEngagementInput(b: UiLaunchRequest): EngagementInput {
  if (!b.target || typeof b.target !== "string") throw new Error("target is required");
  if (b.mode !== "red" && b.mode !== "black") throw new Error("mode must be red|black");
  if (!b.objective || typeof b.objective !== "string") throw new Error("objective is required");
  if (!Array.isArray(b.scope) || b.scope.length === 0 || !b.scope.every((s) => typeof s === "string" && s.trim())) {
    throw new Error("scope is required (non-empty array of exact hosts)");
  }
  let targets: TargetId[] | undefined;
  if (b.targets && b.targets.length > 0) {
    const bad = b.targets.filter((t) => !isTargetId(t));
    if (bad.length > 0) throw new Error(`bad targets ${JSON.stringify(bad)}; want subset of secscan,seclayer,windows,linux`);
    targets = b.targets as TargetId[];
  }
  let tier: 0 | 1 | 2 | undefined;
  if (b.tier !== undefined) {
    tier = parseTier(String(b.tier)) as 0 | 1 | 2;
  }
  let environment: "staging" | "production" | undefined;
  if (b.environment !== undefined) {
    if (b.environment !== "staging" && b.environment !== "production") throw new Error("environment must be staging|production");
    environment = b.environment;
  }
  return {
    target: b.target,
    mode: b.mode,
    objective: b.objective,
    roe: {
      scope: b.scope,
      excludedTechniques: b.excludedTechniques?.length ? b.excludedTechniques : null,
      blackoutWindows: [],
      stopConditions: [],
    },
    client: b.client,
    operatorName: b.operatorName,
    fullBattery: b.fullBattery ?? true,
    targets,
    environment,
    confirmProduction: b.confirmProduction ?? false,
    tier,
    confirmTier2Production: b.confirmTier2Production ?? false,
  };
}

/** POST /api/engagements — launch. Returns 202 { id }. */
export async function handleLaunch(store: UiStore, req: IncomingMessage, res: ServerResponse, body: unknown): Promise<void> {
  let input: EngagementInput;
  try {
    input = toEngagementInput(body as UiLaunchRequest);
  } catch (err) {
    badRequest(res, (err as Error).message);
    return;
  }
  const dryRun = (body as UiLaunchRequest).dryRun === true;
  const localSandbox = (body as UiLaunchRequest).localSandbox === true;
  const id = generateEngagementId();
  const dir = join(store.engagementsDir, id);
  store.register({ id, dir, status: "starting", startedAt: new Date().toISOString() });
  // Detached run — the request returns now; progress streams via SSE.
  // onCtxReady fires synchronously inside runEngagement before any agent
  // acts, so the kill-switch handle is registered while the run is live.
  try {
    const p = runEngagement(input, {
      engagementId: id,
      dryRunAgents: dryRun,
      localSandbox,
      onCtxReady: (handle) => store.setAbort(id, handle.abort),
    });
    void p.then(
      () => store.complete(id),
      (err: unknown) => store.fail(id, err),
    );
  } catch (err) {
    store.fail(id, err);
    badRequest(res, `launch failed: ${(err as Error).message}`);
    return;
  }
  res.writeHead(202, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ id }));
}

/** GET /api/engagements — list all (live first, then history). */
export function handleList(store: UiStore, res: ServerResponse): void {
  json(res, 200, store.list());
}

/** GET /api/engagements/:id — state snapshot + artifact availability. */
export function handleDetail(store: UiStore, res: ServerResponse, id: string): void {
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
  const live = store.get(id);
  json(res, 200, {
    state,
    live: !!live?.abort,
    artifacts: {
      report: store.readTextArtifact(id, "report.md") !== null,
      compliancePack: store.readTextArtifact(id, "compliance-pack.md") !== null,
      attestation: store.readTextArtifact(id, "attestation.md") !== null,
      safetyManifest: store.readTextArtifact(id, "safety-manifest.md") !== null,
      itemVerdicts: store.readJsonArtifact(id, "item-verdicts.json") !== null,
      proofBundles: store.listSubdir(id, "poc").length,
    },
  });
}
