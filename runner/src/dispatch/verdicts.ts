/**
 * Finding/verdict helpers: live-finding sync, registry writes, verdict-block merge (v0.19.0 refactor — extracted from dispatch.ts).
 */
import { type Ctx, type KilledLive, type LiveFinding } from "../context.js";
import { type EngagementPhase, type Finding } from "../types.js";
import { ensureCveEntry, markAttempted, resolveItemKey } from "../coverage/items.js";
import { hasActiveVariantExpansion } from "../variants/index.js";
import { extractJsonBlock } from "../util.js";
import { lookupTechnique } from "../attack.js";
import { recordConfirmed, recordKilled, transactRegistryFile } from "../registry.js";
import { redactPii } from "../safety/index.js";
import { resolve } from "node:path";
import { optStr } from "./prelude.js";

export function recordItemAttempt(
  ctx: Ctx,
  args: Record<string, unknown>,
  phase: EngagementPhase,
): void {
  if (!ctx.input.fullBattery || ctx.itemLedger.size === 0) return;
  const rawTp = typeof args["targetProfile"] === "string" ? args["targetProfile"] : undefined;
  // Dynamic per-CVE instances from msf_exec (v0.11.0): each CVE gets its
  // own ledger entry, attempted here, confirmed via record_finding.
  const rawCve = typeof args["cve"] === "string" ? args["cve"].trim() : "";
  if (/^CVE-\d{4}-\d{4,7}$/i.test(rawCve)) {
    try {
      markAttempted(ctx.itemLedger, ensureCveEntry(ctx.itemLedger, rawCve));
    } catch {
      /* not a CVE id — ignore */
    }
  }
  const rawItem = typeof args["batteryItem"] === "string" ? args["batteryItem"].trim() : "";
  if (!rawItem) return;
  const key = resolveItemKey(rawItem, rawTp);
  if (!key || !ctx.itemLedger.has(key)) {
    ctx.events.append({
      phase,
      actor: "runner",
      action: "item_tag_unresolved",
      result: `batteryItem "${rawItem}" did not resolve to a selected battery item — action executed but not reconciled to the ledger. Tag a valid item ID (e.g. SS-042).`,
    });
    return;
  }
  // v0.20.0 variants: while expansion is open for this item, the variant
  // tracker owns its disposition — a tagged attempt doesn't close it
  // early. Exhaustion, cap, or close flips it to executed-clean.
  if (hasActiveVariantExpansion(ctx.itemLedger, key)) return;
  markAttempted(ctx.itemLedger, key);
}

// ---------------------------------------------------------------------------
// Shared operation state (Megazord) helpers
// ---------------------------------------------------------------------------


const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

function coerceSeverity(s: string): Finding["severity"] {
  const l = s.toLowerCase();
  return (VALID_SEVERITIES.has(l) ? l : "low") as Finding["severity"];
}

/** Mirror live findings into state.json so the console shows them as they land. */
export function syncLiveFindingsToState(ctx: Ctx): void {
  ctx.events.updateState({
    findings: ctx.liveFindings.map((f, i) => ({
      id: `F-${i + 1}`,
      severity: coerceSeverity(f.severity),
      title: f.title,
      attackIds: [f.attackId],
      evidence: f.evidence,
      fix: "(pending — the reporter writes the fix)",
      retest: "(pending)",
      status: "confirmed" as const,
    })),
  });
}

/** Write a confirmed finding to the registry (deduped per engagement) and persist. */
export function writeFindingToRegistry(ctx: Ctx, lf: LiveFinding): void {
  const vulnClass = lf.vulnClass ?? "unclassified";
  const payloadPattern = lf.payload ?? "(see evidence)";
  // v0.23.0: atomic transaction — dedupe and ID assignment run against the
  // freshly-loaded file, so two concurrent engagements never lose each
  // other's verdicts. The created entry is mirrored into the in-memory
  // registry so in-engagement queries keep working.
  const created = transactRegistryFile(ctx.registryPath, (reg) => {
    const dupe = reg.confirmed.some(
      (e) => e.engagementId === ctx.events.engagementId && e.vulnClass === vulnClass && e.payloadPattern === payloadPattern,
    );
    if (dupe) return null;
    return recordConfirmed(reg, {
      vulnClass,
      technique: lookupTechnique(lf.attackId)?.name ?? lf.attackId,
      attackId: lf.attackId,
      target: ctx.fingerprint,
      payloadPattern,
      evidenceRef: `${ctx.events.engagementId}/events.jsonl`,
      engagementId: ctx.events.engagementId,
      severity: coerceSeverity(lf.severity),
    });
  });
  if (created) ctx.registry.confirmed.push(created);
}

/** Write a killed hypothesis to the registry (deduped per engagement) and persist. */
export function writeKilledToRegistry(ctx: Ctx, kl: KilledLive): void {
  const created = transactRegistryFile(ctx.registryPath, (reg) => {
    const dupe = reg.killed.some(
      (e) => e.engagementId === ctx.events.engagementId && e.hypothesis === kl.hypothesis,
    );
    if (dupe) return null;
    return recordKilled(reg, {
      hypothesis: kl.hypothesis,
      killingObservation: kl.killingObservation,
      attackId: kl.attackId,
      vulnClass: kl.vulnClass,
      target: ctx.fingerprint,
      engagementId: ctx.events.engagementId,
    });
  });
  if (created) ctx.registry.killed.push(created);
}

/** Merge the exploiter's final VERDICTS JSON block into shared state + registry (backstop for verdicts never recorded live). */
export function mergeVerdictBlock(ctx: Ctx, text: string): void {
  const parsed = extractJsonBlock(text) as { verdicts?: Array<Record<string, unknown>> } | null;
  const verdicts = parsed && Array.isArray(parsed.verdicts) ? parsed.verdicts : [];
  let merged = 0;
  for (const v of verdicts) {
    if (v["kind"] === "confirmed") {
      const lf: LiveFinding = {
        severity: String(v["severity"] ?? "low"),
        title: redactPii(String(v["vulnClass"] ?? v["title"] ?? "finding").slice(0, 200)),
        vulnClass: optStr(v["vulnClass"]),
        attackId: (optStr(v["attackId"]) ?? "T1190").toUpperCase(),
        evidence: redactPii(String(v["evidence"] ?? "").slice(0, 800)),
        payload: optStr(v["payloadPattern"]),
      };
      if (ctx.liveFindings.some((f) => f.title === lf.title && f.attackId === lf.attackId)) continue;
      ctx.liveFindings.push(lf);
      writeFindingToRegistry(ctx, lf);
      merged++;
    } else if (v["kind"] === "killed") {
      const kl: KilledLive = {
        hypothesis: String(v["hypothesis"] ?? "").slice(0, 300),
        killingObservation: String(v["killingObservation"] ?? "").slice(0, 500),
        attackId: optStr(v["attackId"])?.toUpperCase(),
        vulnClass: optStr(v["vulnClass"]),
      };
      if (!kl.hypothesis || ctx.killedLive.some((k) => k.hypothesis === kl.hypothesis)) continue;
      ctx.killedLive.push(kl);
      writeKilledToRegistry(ctx, kl);
      merged++;
    }
  }
  if (merged > 0) {
    syncLiveFindingsToState(ctx);
    ctx.events.append({
      phase: "exploit",
      actor: "runner",
      action: "verdicts_merged",
      result: `Merged ${merged} verdict(s) from the final VERDICTS block into shared state + registry.`,
    });
  }
}
