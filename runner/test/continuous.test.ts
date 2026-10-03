/**
 * Continuous testing tests (v0.16.0) — watch profiles, baselines, drift.
 *
 * No network, no API keys. What we prove here:
 *  - profile loading is strict (bad version/scope/cadence/expiry rejected)
 *  - scope freshness fails closed past scopeValidUntil
 *  - finding keys are stable across runs (ATT&CK-based, not title-based)
 *  - drift classifies new/unchanged/missing purely
 *  - "remediated" is unreachable without a confirming reverify;
 *    target-changed / missing bundle / reverify error → needs-review
 *  - a full watch cycle: baseline creation, drift, reverify resolution,
 *    drift.json, report appends, Slack drift alert, history.jsonl
 *  - expired authorization refuses before any engagement runs
 *  - baselines never merge across profiles
 *  - --trigger tags the drift report with the change ref
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  loadWatchProfile,
  checkScopeFresh,
  profileHome,
  alertSeverities,
  emptyBaseline,
  loadBaseline,
  saveBaseline,
  findingKey,
  classifyDrift,
  resolveMissingDrift,
  buildDriftReport,
  applyDriftToBaseline,
  touchBaselineEntries,
  remediateBaselineEntries,
  flagBaselineNeedsReview,
  renderDriftMarkdown,
  runWatchCycle,
  type WatchProfile,
  type WatchBaseline,
  type BaselineEntry,
} from "../src/continuous/index.js";
import type { EngagementInput, EngagementResult, Finding } from "../src/types.js";
import type { RunOptions } from "../src/phases.js";

const NOW = new Date("2026-10-03T06:00:00Z");
const FUTURE = "2026-12-31T23:59:59Z";
const PAST = "2026-01-01T00:00:00Z";

function mkProfile(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    name: "acme-weekly",
    engagement: {
      target: "acme.com",
      mode: "red",
      objective: "continuous validation",
      roe: { scope: ["acme.com"] },
      fullBattery: true,
    },
    cadence: { intervalHours: 168 },
    scopeValidUntil: FUTURE,
    ...over,
  };
}

function writeProfile(dir: string, over: Record<string, unknown> = {}): string {
  const p = join(dir, "profile.json");
  writeFileSync(p, JSON.stringify(mkProfile(over)));
  return p;
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-1",
    severity: "high",
    title: "SQL injection in login",
    attackIds: ["T1190"],
    evidence: "marker echoed",
    fix: "parameterize",
    retest: "re-run",
    status: "confirmed",
    ...over,
  };
}

describe("watch profiles", () => {
  it("loads a valid profile", () => {
    const dir = mkdtempSync(join(tmpdir(), "watch-prof-"));
    try {
      const p = loadWatchProfile(writeProfile(dir));
      assert.equal(p.name, "acme-weekly");
      assert.equal(p.cadence.intervalHours, 168);
      assert.deepEqual(alertSeverities(p), ["critical", "high"]);
      assert.equal(profileHome(join(dir, "profile.json")), dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects bad profiles with clear reasons", () => {
    const dir = mkdtempSync(join(tmpdir(), "watch-prof-"));
    try {
      const bad = (over: Record<string, unknown>, re: RegExp) => {
        const p = join(dir, `p-${Math.random().toString(36).slice(2)}.json`);
        writeFileSync(p, JSON.stringify(mkProfile(over)));
        assert.throws(() => loadWatchProfile(p), re);
      };
      bad({ version: 2 }, /version must be 1/);
      bad({ engagement: { target: "x", mode: "red", objective: "o", roe: { scope: [] } } }, /non-empty array/);
      bad({ engagement: { target: "x", mode: "blue", objective: "o", roe: { scope: ["x"] } } }, /red.*black/);
      bad({ cadence: { intervalHours: 0 } }, /positive number/);
      bad({ cadence: { intervalHours: -5 } }, /positive number/);
      bad({ scopeValidUntil: "not-a-date" }, /valid ISO timestamp/);
      bad({ alertSeverities: ["critical", "bogus"] }, /subset of/);
      bad({ name: "has spaces!" }, /short slug/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("scope freshness fails closed past expiry", () => {
    const okProfile = mkProfile({ scopeValidUntil: FUTURE }) as unknown as WatchProfile;
    const oldProfile = mkProfile({ scopeValidUntil: PAST }) as unknown as WatchProfile;
    assert.deepEqual(checkScopeFresh(okProfile, NOW), { ok: true });
    const r = checkScopeFresh(oldProfile, NOW);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /expired.*never extends it itself/s);
  });
});

describe("finding keys", () => {
  it("is stable across title drift when technique IDs match", () => {
    const a = findingKey("acme.com", finding({ title: "SQLi in login form", attackIds: ["T1190"] }));
    const b = findingKey("ACME.COM", finding({ title: "Totally different wording here", attackIds: ["t1190"] }));
    assert.equal(a, b);
  });

  it("splits on different techniques and different targets", () => {
    const a = findingKey("acme.com", finding({ attackIds: ["T1190"] }));
    const b = findingKey("acme.com", finding({ attackIds: ["T1046"] }));
    const c = findingKey("other.com", finding({ attackIds: ["T1190"] }));
    assert.notEqual(a, b);
    assert.notEqual(a, c);
  });

  it("falls back to a title slug when no technique IDs exist", () => {
    const a = findingKey("acme.com", finding({ title: "Weird Thing", attackIds: [] }));
    const b = findingKey("acme.com", finding({ title: "Weird Thing", attackIds: [] }));
    assert.equal(a, b);
    assert.match(a, /title-weird-thing/);
  });
});

describe("drift classification (phase 1, pure)", () => {
  function baselineWith(entries: Partial<BaselineEntry>[]): WatchBaseline {
    return {
      version: 1,
      profileName: "acme-weekly",
      updatedAt: NOW.toISOString(),
      entries: entries.map((e, i) => ({
        key: `k${i}`,
        target: "acme.com",
        severity: "high",
        title: `t${i}`,
        attackIds: ["T1190"],
        firstSeen: NOW.toISOString(),
        lastSeen: NOW.toISOString(),
        firstSeenEngagement: "watch-acme-weekly-20260101-aaaa",
        lastSeenEngagement: "watch-acme-weekly-20260101-aaaa",
        status: "open" as const,
        engagementId: "watch-acme-weekly-20260101-aaaa",
        findingId: `F-${i + 1}`,
        ...e,
      })),
    };
  }

  it("classifies new / unchanged / missing; ignores killed findings", () => {
    const base = baselineWith([{ key: "acme.com::T1190" }]);
    const current = [
      finding({ id: "F-1", attackIds: ["T1190"], title: "sqli, reworded" }), // unchanged
      finding({ id: "F-2", attackIds: ["T1110"], title: "password spray" }), // new
      finding({ id: "F-9", attackIds: ["T1046"], title: "port scan", status: "killed" }), // ignored
    ];
    const c = classifyDrift(base, current, "acme.com");
    assert.equal(c.newFindings.length, 1);
    assert.equal(c.newFindings[0]!.id, "F-2");
    assert.equal(c.unchanged.length, 1);
    assert.equal(c.unchanged[0]!.finding.id, "F-1");
    assert.equal(c.missing.length, 0);
  });

  it("marks baseline entries absent from the run as missing", () => {
    const base = baselineWith([{ key: "acme.com::T1190" }, { key: "acme.com::T1046" }]);
    const c = classifyDrift(base, [finding({ id: "F-1", attackIds: ["T1190"] })], "acme.com");
    assert.equal(c.missing.length, 1);
    assert.equal(c.missing[0]!.key, "acme.com::T1046");
  });

  it("suffixes duplicate keys within one run instead of merging", () => {
    const base = baselineWith([]);
    const c = classifyDrift(
      base,
      [finding({ id: "F-1", attackIds: ["T1190"] }), finding({ id: "F-2", attackIds: ["T1190"] })],
      "acme.com",
    );
    assert.equal(c.newFindings.length, 2);
  });

  it("excludes remediated entries from matching", () => {
    const base = baselineWith([{ key: "acme.com::T1190", status: "remediated" }]);
    const c = classifyDrift(base, [finding({ id: "F-1", attackIds: ["T1190"] })], "acme.com");
    assert.equal(c.newFindings.length, 1); // remediated entry doesn't swallow it
    assert.equal(c.missing.length, 0);
  });
});

describe("drift resolution (phase 2, reverify-gated)", () => {
  function entry(over: Partial<BaselineEntry> = {}): BaselineEntry {
    return {
      key: "acme.com::T1046",
      target: "acme.com",
      severity: "high",
      title: "open port",
      attackIds: ["T1046"],
      firstSeen: NOW.toISOString(),
      lastSeen: NOW.toISOString(),
      firstSeenEngagement: "eng-old",
      lastSeenEngagement: "eng-old",
      status: "open",
      engagementId: "eng-old",
      findingId: "F-2",
      ...over,
    };
  }

  it("reproduced → reopened; not-reproduced → remediated", async () => {
    const dir = mkdtempSync(join(tmpdir(), "watch-runs-"));
    try {
      mkdirSync(join(dir, "eng-old", "poc"), { recursive: true });
      writeFileSync(join(dir, "eng-old", "poc", "F-2.json"), JSON.stringify({ bundleId: "b" }));
      const [reopened] = await resolveMissingDrift([entry()], dir, async () => ({
        verdict: "reproduced",
        note: "marker echoed",
      }));
      assert.equal(reopened!.disposition, "reopened");
      const [remediated] = await resolveMissingDrift([entry()], dir, async () => ({
        verdict: "not-reproduced",
        note: "no echo",
      }));
      assert.equal(remediated!.disposition, "remediated");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("target-changed, missing bundle, and reverify errors → needs-review (never remediated)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "watch-runs-"));
    try {
      mkdirSync(join(dir, "eng-old", "poc"), { recursive: true });
      writeFileSync(join(dir, "eng-old", "poc", "F-2.json"), JSON.stringify({ bundleId: "b" }));
      const [changed] = await resolveMissingDrift([entry()], dir, async () => ({
        verdict: "target-changed",
        note: "connection refused",
      }));
      assert.equal(changed!.disposition, "needs-review");
      assert.match(changed!.note, /Not marked remediated/);
      const [noBundle] = await resolveMissingDrift([entry({ findingId: "F-99" })], dir, async () => ({
        verdict: "not-reproduced",
        note: "should never run",
      }));
      assert.equal(noBundle!.disposition, "needs-review");
      const [threw] = await resolveMissingDrift([entry()], dir, async () => {
        throw new Error("boom");
      });
      assert.equal(threw!.disposition, "needs-review");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("baseline folding", () => {
  it("adds new findings, touches unchanged, remediates only via explicit call", () => {
    let base = emptyBaseline("acme-weekly");
    const f1 = finding({ id: "F-1", attackIds: ["T1190"] });
    const report = buildDriftReport({
      profileName: "acme-weekly",
      engagementId: "eng-1",
      classification: { newFindings: [f1], unchanged: [], missing: [] },
      resolved: [],
    });
    base = applyDriftToBaseline(base, report, "acme.com", "eng-1", NOW.toISOString());
    assert.equal(base.entries.length, 1);
    assert.equal(base.entries[0]!.status, "open");
    base = touchBaselineEntries(base, [base.entries[0]!.key], "eng-2", NOW.toISOString());
    assert.equal(base.entries[0]!.lastSeenEngagement, "eng-2");
    base = remediateBaselineEntries(base, [base.entries[0]!.key], NOW.toISOString());
    assert.equal(base.entries[0]!.status, "remediated");
    base = flagBaselineNeedsReview(base, [base.entries[0]!.key], "manual check");
    assert.equal(base.entries[0]!.needsReview, true);
  });

  it("round-trips through disk", () => {
    const dir = mkdtempSync(join(tmpdir(), "watch-base-"));
    try {
      const p = join(dir, "baseline.json");
      assert.equal(loadBaseline(p), null);
      const b = emptyBaseline("acme-weekly");
      saveBaseline(p, b);
      const loaded = loadBaseline(p)!;
      assert.equal(loaded.profileName, "acme-weekly");
      assert.deepEqual(loaded.entries, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("renders drift markdown with all sections", () => {
    const report = buildDriftReport({
      profileName: "acme-weekly",
      engagementId: "eng-2",
      changeRef: "deploy abc123",
      classification: {
        newFindings: [finding({ id: "F-3", severity: "critical", attackIds: ["T1110"] })],
        unchanged: [],
        missing: [],
      },
      resolved: [],
    });
    const md = renderDriftMarkdown(report);
    assert.match(md, /Continuous drift/);
    assert.match(md, /deploy abc123/);
    assert.match(md, /F-3/);
    assert.match(md, /never.*remediated|Remediated verdicts require/i);
  });
});

describe("watch cycles (integration, injected runner)", () => {
  interface Ctx {
    dir: string;
    profilePath: string;
    runCount: number;
    slackCalls: Array<{ url: string; body: string }>;
    findingsPlan: Finding[][];
    reverifyVerdicts: Record<string, "reproduced" | "not-reproduced" | "target-changed">;
  }

  function setup(over: Record<string, unknown> = {}): Ctx {
    const dir = mkdtempSync(join(tmpdir(), "watch-cycle-"));
    const profilePath = writeProfile(dir, over);
    const ctx: Ctx = { dir, profilePath, runCount: 0, slackCalls: [], findingsPlan: [], reverifyVerdicts: {} };
    return ctx;
  }

  function runFnFor(ctx: Ctx) {
    return async (input: EngagementInput, opts: RunOptions): Promise<EngagementResult> => {
      ctx.runCount++;
      const runDir = join(opts.engagementsDir!, opts.engagementId!);
      mkdirSync(join(runDir, "poc"), { recursive: true });
      writeFileSync(join(runDir, "report.md"), "# Engagement report\n");
      writeFileSync(join(runDir, "compliance-pack.md"), "# Compliance pack\n");
      const findings = ctx.findingsPlan[ctx.runCount - 1] ?? [];
      for (const f of findings) {
        writeFileSync(join(runDir, "poc", `${f.id}.json`), JSON.stringify({ bundleId: `b-${f.id}`, findingId: f.id }));
      }
      return { engagementId: opts.engagementId!, status: "complete", findings };
    };
  }

  function cycleOpts(ctx: Ctx, extra: Record<string, unknown> = {}) {
    return {
      profilePath: ctx.profilePath,
      once: true,
      env: { REDTEAM_SLACK_WEBHOOK_URL: "https://hooks.slack.test/hook" } as NodeJS.ProcessEnv,
      http: (async (url: string, init: { body?: string }) => {
        ctx.slackCalls.push({ url, body: String(init?.body ?? "") });
        return { ok: true, text: async () => "" };
      }) as never,
      now: () => NOW,
      runFn: runFnFor(ctx),
      reverifyFn: async (bundlePath: string) => {
        const base = bundlePath.split("/").pop() ?? "";
        const verdict = ctx.reverifyVerdicts[base] ?? "not-reproduced";
        return { verdict, note: `fake ${verdict}` };
      },
      ...extra,
    };
  }

  function teardown(ctx: Ctx) {
    rmSync(ctx.dir, { recursive: true, force: true });
  }

  it("first cycle creates the baseline; second cycle detects drift", async () => {
    const ctx = setup();
    try {
      ctx.findingsPlan = [
        [finding({ id: "F-1", severity: "critical", attackIds: ["T1190"] }), finding({ id: "F-2", severity: "high", attackIds: ["T1046"] })],
        [finding({ id: "F-1", severity: "critical", attackIds: ["T1190"], title: "sqli, reworded" }), finding({ id: "F-3", severity: "medium", attackIds: ["T1110"] })],
      ];
      ctx.reverifyVerdicts = { "F-2.json": "not-reproduced" }; // T1046 fixed between runs

      const r1 = await runWatchCycle(cycleOpts(ctx));
      assert.equal(r1.status, "complete");
      assert.equal(r1.drift!.newFindings.length, 2);
      assert.equal(r1.drift!.unchangedCount, 0);
      const base1 = JSON.parse(readFileSync(join(ctx.dir, "baseline.json"), "utf8"));
      assert.equal(base1.entries.length, 2);

      const r2 = await runWatchCycle(cycleOpts(ctx));
      assert.equal(r2.status, "complete");
      const d2 = r2.drift!;
      assert.equal(d2.newFindings.length, 1);
      assert.equal(d2.newFindings[0]!.id, "F-3");
      assert.equal(d2.unchangedCount, 1);
      assert.equal(d2.remediated.length, 1); // T1046 verified fixed
      assert.equal(d2.remediated[0]!.entry.attackIds[0], "T1046");
      assert.equal(d2.needsReview.length, 0);

      // drift.json + report appends + history
      assert.ok(existsSync(join(ctx.dir, "runs", r2.engagementId!, "drift.json")));
      const reportMd = readFileSync(join(ctx.dir, "runs", r2.engagementId!, "report.md"), "utf8");
      assert.match(reportMd, /Continuous drift/);
      const packMd = readFileSync(join(ctx.dir, "runs", r2.engagementId!, "compliance-pack.md"), "utf8");
      assert.match(packMd, /Continuous drift \(retest update\)/);
      const history = readFileSync(join(ctx.dir, "history.jsonl"), "utf8").trim().split("\n");
      assert.equal(history.length, 2);
      assert.match(history[1]!, /"remediated":1/);

      // baseline: T1046 remediated (kept as history), T1110 added open
      const base2 = JSON.parse(readFileSync(join(ctx.dir, "baseline.json"), "utf8"));
      const t1046 = base2.entries.find((e: { key: string }) => e.key === "acme.com::T1046");
      assert.equal(t1046.status, "remediated");
      const t1110 = base2.entries.find((e: { key: string }) => e.key === "acme.com::T1110");
      assert.equal(t1110.status, "open");
    } finally {
      teardown(ctx);
    }
  });

  it("sends a Slack drift alert for new critical/high findings", async () => {
    const ctx = setup();
    try {
      ctx.findingsPlan = [[finding({ id: "F-1", severity: "critical", attackIds: ["T1190"], title: "RCE" })]];
      const r = await runWatchCycle(cycleOpts(ctx));
      assert.equal(r.status, "complete");
      assert.ok(ctx.slackCalls.length >= 1);
      const driftCall = ctx.slackCalls.find((c) => c.body.includes("Drift alert"));
      assert.ok(driftCall, "expected a Slack drift alert");
      assert.match(driftCall!.body, /RCE/);
    } finally {
      teardown(ctx);
    }
  });

  it("refuses before any engagement when scope authorization expired", async () => {
    const ctx = setup({ scopeValidUntil: PAST });
    try {
      ctx.findingsPlan = [[finding({ id: "F-1", attackIds: ["T1190"] })]];
      const r = await runWatchCycle(cycleOpts(ctx));
      assert.equal(r.status, "refused");
      assert.equal(ctx.runCount, 0); // no engagement ran — fail closed
      assert.match(r.reason!, /expired/);
      assert.ok(!existsSync(join(ctx.dir, "baseline.json")));
    } finally {
      teardown(ctx);
    }
  });

  it("refuses to merge a baseline belonging to another profile", async () => {
    const ctx = setup();
    try {
      writeFileSync(join(ctx.dir, "baseline.json"), JSON.stringify({ version: 1, profileName: "other-profile", updatedAt: NOW.toISOString(), entries: [] }));
      ctx.findingsPlan = [[finding({ id: "F-1", attackIds: ["T1190"] })]];
      const r = await runWatchCycle(cycleOpts(ctx));
      assert.equal(r.status, "error");
      assert.match(r.reason!, /never.*merge|refusing to merge/i);
    } finally {
      teardown(ctx);
    }
  });

  it("tags triggered runs with the change ref", async () => {
    const ctx = setup();
    try {
      ctx.findingsPlan = [[finding({ id: "F-1", attackIds: ["T1190"] })]];
      const r = await runWatchCycle(cycleOpts(ctx, { trigger: "deploy abc123" }));
      assert.equal(r.status, "complete");
      assert.equal(r.drift!.changeRef, "deploy abc123");
      const driftJson = JSON.parse(readFileSync(join(ctx.dir, "runs", r.engagementId!, "drift.json"), "utf8"));
      assert.equal(driftJson.changeRef, "deploy abc123");
      assert.match(r.engagementId!, /trigger/);
    } finally {
      teardown(ctx);
    }
  });

  it("missing reverify target → needs-review, baseline flagged, never remediated", async () => {
    const ctx = setup();
    try {
      ctx.findingsPlan = [
        [finding({ id: "F-1", severity: "high", attackIds: ["T1046"] })],
        [], // second run: nothing found
      ];
      ctx.reverifyVerdicts = { "F-1.json": "target-changed" };
      await runWatchCycle(cycleOpts(ctx));
      const r2 = await runWatchCycle(cycleOpts(ctx));
      assert.equal(r2.drift!.needsReview.length, 1);
      assert.equal(r2.drift!.remediated.length, 0);
      const base = JSON.parse(readFileSync(join(ctx.dir, "baseline.json"), "utf8"));
      const e = base.entries.find((x: { key: string }) => x.key === "acme.com::T1046");
      assert.equal(e.status, "open"); // still open
      assert.equal(e.needsReview, true);
    } finally {
      teardown(ctx);
    }
  });

  it("bad profile file → error result, nothing runs", async () => {
    const ctx = setup();
    try {
      const r = await runWatchCycle(cycleOpts(ctx, { profilePath: join(ctx.dir, "nope.json") }));
      assert.equal(r.status, "error");
      assert.equal(ctx.runCount, 0);
    } finally {
      teardown(ctx);
    }
  });
});
