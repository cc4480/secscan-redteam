/**
 * T10 regressions — PoC bundle provenance + finding-id filename safety.
 *
 *  - Finding ids are reporter-influenced: bundleFileName() must never
 *    turn one into a path that escapes the poc/ directory.
 *  - buildProofSection writes bundles INSIDE poc/ even for hostile ids.
 *  - Reverify replays stored commands with fresh credentials, so the
 *    bundle must carry the runner-recorded integrity digest: a tampered
 *    or digest-less bundle is refused BEFORE a single step fires, while
 *    a pristine runner-built bundle replays normally.
 *
 * Fakes only — no network, no live engagements.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import {
  buildPocBundle,
  bundleFileName,
  verifyBundleIntegrity,
  type PocBundle,
} from "../src/proof/bundle.js";
import { reverifyBundle, type StepRunner } from "../src/proof/reverify.js";
import { buildProofSection } from "../src/report/proof.js";
import type { Ctx } from "../src/context.js";
import type { EngagementEvent, Finding } from "../src/types.js";

const META = { engagementId: "eng-1", target: "target.example", operator: "op" };

function ev(partial: Partial<EngagementEvent> & { action: string; result: string }): EngagementEvent {
  return {
    ts: "2026-10-03T06:00:00.000Z",
    seq: 1,
    engagementId: "eng-1",
    phase: "exploit",
    actor: "exploiter",
    target: "target.example",
    ...partial,
  } as EngagementEvent;
}

function confirmedFinding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-1",
    severity: "critical",
    title: "EternalBlue RCE",
    attackIds: ["T1190"],
    evidence: "marker echoed",
    fix: "patch",
    retest: "re-run",
    status: "confirmed",
    ...over,
  };
}

const MSF_EVENT = ev({
  seq: 10,
  action: "msf_exec",
  attackId: "T1190",
  result:
    "msf exploit/windows/smb/ms17_010_eternalblue vs target.example: MARKER ECHOED — command execution validated. " +
    "[CVE-2017-0144] Output: REDTEAM-MARKER-abc123",
});

function builtBundle(over: Partial<Finding> = {}): PocBundle {
  const { bundle, reason } = buildPocBundle({ finding: confirmedFinding(over), events: [MSF_EVENT], engagement: META, secrets: [] });
  assert.ok(bundle, `expected bundle, got reason: ${reason}`);
  return bundle!;
}

describe("bundleFileName — finding ids cannot escape poc/", () => {
  const EVIL_IDS = [
    "../../registry",
    "../../../etc/passwd",
    "/etc/passwd",
    "..\\..\\evil",
    "a/b/c",
    "..",
    ".",
    "",
    ".../x",
    "F-1/../../registry",
  ];

  it("maps every id to a separator-free name contained in the target dir", () => {
    const pocDir = resolve("/engagements/eng-1/poc");
    for (const id of EVIL_IDS) {
      const name = bundleFileName(id);
      assert.ok(!name.includes("/") && !name.includes("\\"), `id ${JSON.stringify(id)} -> ${name} must contain no separators`);
      assert.ok(!name.startsWith("."), `id ${JSON.stringify(id)} -> ${name} must not be a dot-segment/hidden name`);
      assert.ok(name.endsWith(".json"), `id ${JSON.stringify(id)} -> ${name} must keep the .json suffix`);
      const dest = resolve(pocDir, name);
      assert.ok(dest.startsWith(pocDir + sep), `id ${JSON.stringify(id)} -> ${dest} escapes ${pocDir}`);
      assert.notEqual(dest, pocDir);
    }
  });

  it("keeps well-formed ids unchanged (existing bundles stay addressable)", () => {
    assert.equal(bundleFileName("F-1"), "F-1.json");
    assert.equal(bundleFileName("F-12"), "F-12.json");
  });
});

describe("buildProofSection — hostile finding ids stay inside poc/", () => {
  it("writes the bundle under a sanitized name and never at the traversed path", () => {
    const dir = mkdtempSync(join(tmpdir(), "t10-poc-"));
    // The full event log T8 made buildProofSection read: one marker-echo event.
    writeFileSync(join(dir, "events.jsonl"), JSON.stringify(MSF_EVENT) + "\n");
    const appended: unknown[] = [];
    const ctx = {
      events: { dir, engagementId: "eng-1", append: (e: unknown) => appended.push(e) },
      input: { target: "target.example", operatorName: "op" },
      killedLive: [],
    } as unknown as Ctx;
    const evil = confirmedFinding({ id: "../../registry" });
    const normal = confirmedFinding({ id: "F-1" });
    const section = buildProofSection(ctx, [evil, normal], new Map());
    assert.ok(section.includes("Proof of exploitation"), "proof section still renders");

    const pocDir = join(dir, "poc");
    const names = readdirSync(pocDir).sort();
    // Both bundles landed inside poc/ under contained names…
    assert.deepEqual(names, ["F-1.json", bundleFileName("../../registry")].sort());
    // …and nothing exists where the traversal wanted to write.
    assert.ok(!existsSync(resolve(pocDir, "../../registry.json")), "traversed write target must not exist");
    assert.ok(!existsSync(join(dir, "registry.json")), "no bundle may land at the engagement root");
  });
});

describe("bundle provenance — reverify refuses unproven bundles", () => {
  it("runner-built bundles carry a digest that verifies, even after a JSON round trip", () => {
    const bundle = builtBundle();
    assert.equal(bundle.integrity?.algorithm, "sha256");
    assert.match(bundle.integrity!.digest, /^[0-9a-f]{64}$/);
    assert.equal(verifyBundleIntegrity(bundle), null);
    const revived = JSON.parse(JSON.stringify(bundle)) as PocBundle;
    assert.equal(verifyBundleIntegrity(revived), null, "digest must survive write/read exactly as reverify sees it");
  });

  it("tampered bundle (payload edited after the runner wrote it) is refused with zero steps fired", async () => {
    const tampered = JSON.parse(JSON.stringify(builtBundle())) as PocBundle;
    // One-byte-class edit: append to a replayed step's recorded command.
    tampered.steps[0] = { ...tampered.steps[0]!, command: `${tampered.steps[0]!.command} ` };
    tampered.title = `${tampered.title}!`;
    assert.match(verifyBundleIntegrity(tampered) ?? "", /integrity digest mismatch/);

    let calls = 0;
    const runner: StepRunner = async () => {
      calls++;
      return { ok: true, output: "REDTEAM-MARKER-abc123" };
    };
    const report = await reverifyBundle(tampered, runner);
    assert.equal(calls, 0, "no step may fire against a tampered bundle");
    assert.equal(report.verdict, "not-reproduced");
    assert.match(report.summary, /refused before firing/);
    assert.match(report.summary, /provenance check failed/);
    assert.match(report.summary, /digest mismatch/);
    assert.ok(report.steps.every((s) => !s.replayed && !s.validationObserved));
    assert.match(report.registryNote, /do NOT close the finding/);
  });

  it("digest-less bundle (crafted/hand-written) is refused with zero steps fired", async () => {
    const crafted = JSON.parse(JSON.stringify(builtBundle())) as PocBundle;
    delete crafted.integrity;
    assert.match(verifyBundleIntegrity(crafted) ?? "", /no runner-recorded integrity digest/);

    let calls = 0;
    const runner: StepRunner = async () => {
      calls++;
      return { ok: true, output: "REDTEAM-MARKER-abc123" };
    };
    const report = await reverifyBundle(crafted, runner);
    assert.equal(calls, 0, "no step may fire against a bundle of unproven origin");
    assert.equal(report.verdict, "not-reproduced");
    assert.match(report.summary, /refused before firing: bundle provenance check failed/);
    assert.ok(report.steps.every((s) => !s.replayed));
    assert.match(report.registryNote, /REFUSED \(bundle provenance check failed\)/);
  });

  it("pristine runner-built bundle replays normally", async () => {
    const bundle = builtBundle();
    const seen: string[] = [];
    const runner: StepRunner = async (_step, marker) => {
      seen.push(marker);
      return { ok: true, output: `fresh output with ${marker} echoed` };
    };
    const report = await reverifyBundle(bundle, runner);
    assert.equal(report.verdict, "reproduced");
    assert.deepEqual(seen, ["REDTEAM-MARKER-abc123"], "the recorded marker is what gets verified");
  });
});
