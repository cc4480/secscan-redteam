/**
 * redteam-runner CLI commands: start, queue, watch, reverify.
 */

import { enqueueEngagement, runEngagement, watchQueue } from "../index.js";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createReplayer, reverifyBundle, type PocBundle } from "../proof/index.js";
import { loadTicketMapping, updateTicketsForReverify } from "../integrations/index.js";
import { runWatchCycle, watchLoop } from "../continuous/index.js";
import { startUiServer } from "../ui/index.js";
import { arg, argAll, buildInput, flag, usage } from "./args.js";

async function runReverify(): Promise<void> {
  const bundlePath = arg("--bundle");
  if (!bundlePath || !existsSync(bundlePath)) {
    console.error(`[runner] reverify needs --bundle <poc/F-1.json> (file not found: ${bundlePath ?? "(missing)"})`);
    process.exit(3);
  }
  let bundle: PocBundle;
  try {
    bundle = JSON.parse(readFileSync(bundlePath, "utf8")) as PocBundle;
  } catch (err) {
    console.error(`[runner] bad bundle JSON: ${(err as Error).message}`);
    process.exit(3);
  }
  if (bundle.version !== 1 || !Array.isArray(bundle.steps)) {
    console.error(`[runner] not a v1 PoC bundle: ${bundlePath}`);
    process.exit(3);
  }
  const execute = flag("--execute");
  console.log(`[runner] PoC ${bundle.bundleId} — ${bundle.findingId}: ${bundle.title}`);
  console.log(`[runner] validation tier: ${bundle.validationTier}; proves: ${bundle.proves}`);
  console.log(`[runner] steps:`);
  for (const s of bundle.steps) {
    console.log(
      `  seq ${s.seq} ${s.tool}${s.target ? ` @ ${s.target}` : ""} :: ${s.command.slice(0, 120)} ` +
        `[${s.validation}${s.replay ? "" : ", not replayable"}]`,
    );
  }
  if (!execute) {
    console.log(`[runner] plan only (no --execute): no traffic sent. Re-run with --execute --scope <host> to re-verify.`);
    return;
  }
  const scopes = argAll("--scope");
  if (scopes.length === 0) {
    console.error(`[runner] --execute requires --scope <host> (exact hosts; enforced mechanically)`);
    process.exit(3);
  }
  const killSwitch = { aborted: false };
  process.on("SIGINT", () => {
    killSwitch.aborted = true;
    console.error(`\n[runner] SIGINT — kill switch set; in-flight step will abort`);
  });
  const report = await reverifyBundle(bundle, createReplayer({ scope: scopes, killSwitch }));
  const outDir = arg("--out") ?? dirname(resolve(bundlePath));
  mkdirSync(outDir, { recursive: true });
  const outPath = join(outDir, `${bundle.findingId}.reverify-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
  writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`[runner] verdict: ${report.verdict}`);
  console.log(`[runner] ${report.summary}`);
  for (const s of report.steps) {
    console.log(`  seq ${s.seq} ${s.tool}: ${s.replayed ? (s.ok ? "ok" : "FAILED") : "skipped"} — ${s.note.slice(0, 160)}`);
  }
  console.log(`[runner] ${report.registryNote}`);
  console.log(`[runner] report written: ${outPath}`);
  // v0.15.0 retest loop: update the tickets linked in integrations.json
  // (written by reportPhase next to the bundle) with the reverify verdict.
  // Never throws — a missing mapping or unconfigured sink just logs.
  try {
    const mapping = loadTicketMapping(dirname(resolve(bundlePath)));
    if (mapping) {
      const { attempts } = await updateTicketsForReverify(mapping, bundle, report);
      for (const a of attempts) {
        console.log(`[runner] ticket ${a.sink}: ${a.status} — ${a.detail}`);
      }
    } else {
      console.log(`[runner] no integrations.json next to the bundle — ticket update skipped (no linked tickets)`);
    }
  } catch (err) {
    console.log(`[runner] ticket update failed (reverify report unaffected): ${(err as Error).message}`);
  }
  process.exit(report.verdict === "reproduced" ? 0 : report.verdict === "target-changed" ? 2 : 1);
}

async function runWatchCli(profilePath: string): Promise<void> {
  const once = flag("--once");
  const trigger = arg("--trigger");
  const rpsIdx = process.argv.indexOf("--max-rps");
  const rpsRaw = rpsIdx >= 0 ? process.argv[rpsIdx + 1] : undefined;
  const maxRpsPerHost = rpsRaw === undefined ? undefined : Number(rpsRaw);
  if (maxRpsPerHost !== undefined && (!Number.isFinite(maxRpsPerHost) || maxRpsPerHost <= 0)) {
    console.error(`[runner] bad --max-rps ${JSON.stringify(rpsRaw)}; want a positive number (requests/sec per host)`);
    process.exit(2);
  }
  // A triggered run is always a single cycle, tagged with the change ref —
  // this is the CI/CD hook: wire the pipeline webhook to this command.
  if (once || trigger) {
    const result = await runWatchCycle({ profilePath, once: true, trigger, maxRpsPerHost });
    const drift = result.drift;
    console.log(
      JSON.stringify(
        {
          status: result.status,
          engagementId: result.engagementId,
          engagementStatus: result.engagementStatus,
          reason: result.reason,
          drift: drift
            ? {
                new: drift.newFindings.map((f) => `${f.id}[${f.severity}]`),
                unchanged: drift.unchangedCount,
                reopened: drift.reopened.map((m) => m.entry.key),
                remediated: drift.remediated.map((m) => m.entry.key),
                needsReview: drift.needsReview.map((m) => m.entry.key),
              }
            : undefined,
        },
        null,
        2,
      ),
    );
    process.exit(result.status === "complete" ? 0 : result.status === "refused" ? 2 : 1);
  }
  console.log(`[runner] continuous watch: ${profilePath} — Ctrl+C to stop`);
  const ctrl = new AbortController();
  process.on("SIGINT", () => ctrl.abort());
  await watchLoop({ profilePath, maxRpsPerHost }, ctrl.signal);
}

export async function main(): Promise<void> {
  const cmd = process.argv[2];
  if (cmd === "start") {
    const input = buildInput();
    const rpsIdx = process.argv.indexOf("--max-rps");
    const rpsRaw = rpsIdx >= 0 ? process.argv[rpsIdx + 1] : undefined;
    const maxRps = rpsRaw === undefined ? undefined : Number(rpsRaw);
    if (maxRps !== undefined && (!Number.isFinite(maxRps) || maxRps <= 0)) {
      console.error(`[runner] bad --max-rps ${JSON.stringify(rpsRaw)}; want a positive number (requests/sec per host)`);
      process.exit(2);
    }
    // v0.20.0 payload-variant expansion: per-item cap, enforced mechanically.
    const varIdx = process.argv.indexOf("--max-variants");
    const varRaw = varIdx >= 0 ? process.argv[varIdx + 1] : undefined;
    const maxVariants = varRaw === undefined ? undefined : Number(varRaw);
    if (maxVariants !== undefined && (!Number.isFinite(maxVariants) || maxVariants <= 0)) {
      console.error(`[runner] bad --max-variants ${JSON.stringify(varRaw)}; want a positive number (variants per battery item)`);
      process.exit(2);
    }
    const result = await runEngagement(input, {
      localSandbox: flag("--local-sandbox"),
      dryRunAgents: flag("--dry-run"),
      maxRpsPerHost: maxRps,
      maxVariantsPerItem: maxVariants,
    });
    console.log(JSON.stringify({ status: result.status, engagementId: result.engagementId, blockedReason: result.blockedReason, findings: result.findings.length }, null, 2));
    process.exit(result.status === "complete" ? 0 : 1);
  }
  if (cmd === "queue") {
    const input = buildInput();
    const path = enqueueEngagement(input, arg("--queue"));
    console.log(`queued: ${path}`);
    return;
  }
  if (cmd === "watch") {
    const profilePath = arg("--profile");
    if (profilePath) {
      await runWatchCli(profilePath);
      return;
    }
    const queueDir = arg("--queue");
    console.log(`[runner] watching ${queueDir ?? "(default queue dir)"} — Ctrl+C to stop`);
    const ctrl = new AbortController();
    process.on("SIGINT", () => ctrl.abort());
    await watchQueue(queueDir, {}, 10_000, ctrl.signal);
    return;
  }
  if (cmd === "reverify") {
    await runReverify();
    return;
  }
  if (cmd === "ui") {
    const portRaw = arg("--port");
    const port = portRaw === undefined ? 8787 : Number(portRaw);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.error(`[runner] bad --port ${JSON.stringify(portRaw)}; want 1-65535`);
      process.exit(2);
    }
    const listen = arg("--listen");
    const engagementsDir = arg("--engagements-dir");
    // startUiServer keeps the event loop alive; it prints the token itself.
    await startUiServer({ port, listen, engagementsDir });
    return;
  }
  usage();
}

