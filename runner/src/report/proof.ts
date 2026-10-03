/**
 * PoC bundle section (v0.19.0 refactor — extracted from reportPhase).
 *
 * Builds proof-of-exploitation bundles MECHANICALLY from the audit log —
 * one per CONFIRMED finding with a genuine validation signal, plus negative
 * proof for killed hypotheses. Returns the markdown section to append.
 * Its own try/catch: proof generation must never break the report.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { readEvents } from "../events.js";
import { PocBundle, buildNegativeProof, buildPocBundle, bundleSummary } from "../proof/index.js";
import { type Finding } from "../types.js";
import { TARGET_PROFILES } from "../targets.js";
import { type Ctx } from "../context.js";

export function buildProofSection(ctx: Ctx, findings: Finding[], pocBundleMap: Map<string, PocBundle>): string {
  let section = "";
  // v0.14.0 proof of exploitation: PoC bundles derived MECHANICALLY from the
  // audit log (events.jsonl) — one per CONFIRMED finding with a genuine
  // validation signal (marker echo = execution tier; read-only evidence
  // output = observation tier). Killed hypotheses get negative proof (what
  // was tried, the decisive observation that killed it). No bundle is ever
  // fabricated: unconfirmed findings are listed as such. Its own try/catch:
  // proof generation must never break the report.
  // pocBundleMap is declared outside the try so the v0.15.0 integrations
  // block (ticket sync + SIEM export) can reuse the bundles it built.
  try {
    const proofEvents = readEvents(ctx.events.dir);
    const secretEnvNames = [
      "REDTEAM_SSH_PASSWORD", "REDTEAM_SSH_KEY",
      "REDTEAM_SMB_PASSWORD", "REDTEAM_SMB_NTHASH",
      "REDTEAM_WINRM_PASSWORD", "REDTEAM_MSFRPC_PASS",
      "REDTEAM_KRB_CCACHE_B64", "REDTEAM_KRB_KIRBI_B64",
      "SECSCAN_MCP_TOKEN", "DEEPSEEK_API_KEY", "QWEN_API_KEY",
    ];
    const proofSecrets = secretEnvNames
      .map((n) => process.env[n])
      .filter((v): v is string => typeof v === "string" && v.length >= 4);
    const proofMeta = {
      engagementId: ctx.events.engagementId,
      target: ctx.input.target,
      operator: ctx.input.operatorName ?? process.env["REDTEAM_OPERATOR"] ?? "(operator name not supplied — set REDTEAM_OPERATOR)",
    };
    const attackToItem = new Map<string, string>();
    for (const [tid, profile] of Object.entries(TARGET_PROFILES)) {
      for (const item of profile.battery) {
        if (item.attackId && !attackToItem.has(item.attackId.toUpperCase())) {
          attackToItem.set(item.attackId.toUpperCase(), `${tid}:${item.id}`);
        }
      }
    }
    const pocDir = join(ctx.events.dir, "poc");
    mkdirSync(pocDir, { recursive: true });
    const bundleLines: string[] = [];
    const noBundleLines: string[] = [];
    for (const f of findings) {
      if (f.status !== "confirmed") continue;
      const batteryItemId = f.attackIds.map((a) => attackToItem.get(a.toUpperCase())).find(Boolean);
      const { bundle, reason } = buildPocBundle({
        finding: f,
        batteryItemId,
        events: proofEvents,
        engagement: proofMeta,
        secrets: proofSecrets,
      });
      if (bundle) {
        writeFileSync(join(pocDir, `${f.id}.json`), JSON.stringify(bundle, null, 2));
        pocBundleMap.set(f.id, bundle);
        bundleLines.push(`- ${bundleSummary(bundle)}`);
      } else {
        noBundleLines.push(`- **${f.id}** — ${f.title}: no PoC bundle — ${reason}`);
      }
    }
    const negative = buildNegativeProof(ctx.killedLive, proofEvents, proofSecrets);
    section += `\n\n---\n\n## Proof of exploitation (runner-computed)\n\n`;
    section += `Each bundle below was derived mechanically from the audit log (events.jsonl) — the exact ` +
      `redacted steps, in order, that validated the finding. Full bundles: \`poc/<finding-id>.json\`.\n\n`;
    if (bundleLines.length > 0) {
      section += bundleLines.join("\n") + "\n";
    } else {
      section += `(no confirmed findings with a validation signal this engagement — no bundles generated)\n`;
    }
    if (noBundleLines.length > 0) {
      section += `\nConfirmed findings without a bundle (honest absence — not every probe becomes provable proof):\n\n` +
        noBundleLines.join("\n") + "\n";
    }
    section += `\n### Negative proof — tested and ruled out\n\n`;
    if (negative.length > 0) {
      for (const n of negative) {
        section += `\n- **Ruled out:** ${n.hypothesis}${n.attackId ? ` (${n.attackId})` : ""}\n` +
          `  **Decisive observation:** ${n.killingObservation}\n`;
        if (n.decisiveEvents.length > 0) {
          section += `  **Decisive audit events:** ${n.decisiveEvents.map((e) => `seq ${e.seq} ${e.tool}: ${e.result.slice(0, 160)}`).join(" | ")}\n`;
        }
      }
    } else {
      section += `(no killed hypotheses this engagement)\n`;
    }
    ctx.events.append({
      phase: "report",
      actor: "runner",
      action: "proof_bundles",
      result: `PoC bundles: ${bundleLines.length} built, ${noBundleLines.length} confirmed without bundle, ${negative.length} negative proofs.`,
    });
  } catch (err) {
    ctx.events.append({
      phase: "report",
      actor: "runner",
      action: "proof_bundles_failed",
      result: `PoC bundle generation failed (report.md unaffected): ${(err as Error).message}`,
    });
  }
  return section;
}
