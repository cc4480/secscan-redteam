/**
 * Runner tests — no network, no API keys. The LLM and the server gate are
 * injected fakes; dryRunAgents skips the agent loops. Every fail-closed path
 * must resolve to blocked/denied, never to approval.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  checkAuthorization,
  inBlackout,
  scopeHosts,
  techniqueAllowed,
  urlInScope,
} from "../src/gate.js";
import { readEvents, readState } from "../src/events.js";
import { validateProbeTarget } from "../src/prober.js";
import { resolveExcludedTechniques, defaultExcludedForMode, ALWAYS_EXCLUDED } from "../src/attack.js";
import { runEngagement } from "../src/phases.js";
import type { EngagementInput } from "../src/types.js";

const noVerify = async () => false;
const yesVerify = async () => true;
const throwingVerify = async () => {
  throw new Error("simulated gate failure");
};

function input(mode: "red" | "black" = "red"): EngagementInput {
  return {
    target: "secscan.us",
    mode,
    objective: "test objective",
    roe: { scope: ["secscan.us"] },
  };
}

describe("checkAuthorization (both modes)", () => {
  for (const mode of ["red", "black"] as const) {
    it(`${mode}: blocked when the server does not verify`, async () => {
      const v = await checkAuthorization("secscan.us", { mcpEndpoint: "https://x", mcpToken: "t" }, noVerify);
      assert.equal(v.allowed, false);
      assert.match(v.reason ?? "", /never vs/i); // covert ≠ vs the gate
    });
    it(`${mode}: blocked when the checker throws (fail closed)`, async () => {
      const v = await checkAuthorization("secscan.us", { mcpEndpoint: "https://x", mcpToken: "t" }, throwingVerify);
      assert.equal(v.allowed, false);
    });
    it(`${mode}: allowed on positive server proof`, async () => {
      const v = await checkAuthorization("secscan.us", { mcpEndpoint: "https://x", mcpToken: "t" }, yesVerify);
      assert.equal(v.allowed, true);
    });
  }
  it("rejects unparseable targets", async () => {
    const v = await checkAuthorization("not a url %%%", { mcpEndpoint: "https://x", mcpToken: "t" }, yesVerify);
    assert.equal(v.allowed, false);
  });
});

describe("scope enforcement", () => {
  it("normalizes scope entries to hostnames", () => {
    assert.deepEqual(scopeHosts({ scope: ["https://SecScan.US/path", "www.example.com"] }), ["secscan.us", "www.example.com"]);
  });
  it("requires exact hostname match", () => {
    const hosts = ["secscan.us"];
    assert.equal(urlInScope("https://secscan.us/scan", hosts), true);
    assert.equal(urlInScope("https://www.secscan.us/", hosts), false); // not exact
    assert.equal(urlInScope("https://evil.com/", hosts), false);
    assert.equal(urlInScope("not a url", hosts), false);
  });
});

describe("blackout windows", () => {
  // 2026-10-02T07:30:00Z == 02:30 America/Chicago (CDT, UTC-5)
  const d = (iso: string) => new Date(iso);
  it("detects inside/outside a window", () => {
    const w = [{ start: "02:00", end: "04:00", tz: "America/Chicago" }];
    assert.ok(inBlackout(d("2026-10-02T07:30:00Z"), w));
    assert.equal(inBlackout(d("2026-10-02T09:30:00Z"), w), null);
  });
  it("handles windows crossing midnight", () => {
    const w = [{ start: "22:00", end: "02:00", tz: "America/Chicago" }];
    assert.ok(inBlackout(d("2026-10-02T04:30:00Z"), w)); // 23:30 CDT
    assert.ok(inBlackout(d("2026-10-02T06:30:00Z"), w)); // 01:30 CDT
    assert.equal(inBlackout(d("2026-10-02T09:30:00Z"), w), null); // 04:30 CDT
  });
  it("ignores malformed windows instead of blocking on garbage", () => {
    assert.equal(inBlackout(d("2026-10-02T07:30:00Z"), [{ start: "xx", end: "yy" }]), null);
  });
  it("no windows → never in blackout", () => {
    assert.equal(inBlackout(new Date(), undefined), null);
  });
});

describe("technique exclusions", () => {
  it("T1499 is always excluded", () => {
    assert.ok(ALWAYS_EXCLUDED.includes("T1499"));
    assert.equal(techniqueAllowed("T1499", "red", { scope: ["x"] }), false);
    assert.equal(techniqueAllowed("T1499", "black", { scope: ["x"] }), false);
  });
  it("black mode excludes brute force by default; red does not", () => {
    assert.deepEqual(defaultExcludedForMode("black"), ["T1499", "T1110"]);
    assert.deepEqual(defaultExcludedForMode("red"), ["T1499"]);
    assert.equal(techniqueAllowed("T1110", "black", { scope: ["x"] }), false);
    assert.equal(techniqueAllowed("T1110", "red", { scope: ["x"] }), true);
  });
  it("ROE exclusions are honored and normalized", () => {
    assert.deepEqual(resolveExcludedTechniques("red", ["t1190", "T1190"]), ["T1499", "T1190"]);
    assert.equal(techniqueAllowed("T1190", "red", { scope: ["x"], excludedTechniques: ["T1190"] }), false);
  });
  it("unmapped actions are allowed (mapping is advisory)", () => {
    assert.equal(techniqueAllowed(undefined, "black", { scope: ["x"] }), true);
  });
});

describe("prober guardrails", () => {
  const scope = ["secscan.us"];
  it("allows in-scope http/https", () => {
    assert.deepEqual(validateProbeTarget("https://secscan.us/scan", scope), { ok: true });
  });
  it("rejects out-of-scope hosts", () => {
    const r = validateProbeTarget("https://evil.com/", scope);
    assert.equal(r.ok, false);
  });
  it("rejects private/loopback hosts", () => {
    for (const u of ["http://127.0.0.1/", "http://10.0.0.5/x", "http://192.168.1.1/", "http://localhost:3000/"]) {
      const r = validateProbeTarget(u, scope);
      assert.equal(r.ok, false, u);
    }
  });
  it("rejects non-http schemes", () => {
    assert.equal(validateProbeTarget("file:///etc/passwd", scope).ok, false);
    assert.equal(validateProbeTarget("gopher://secscan.us/", scope).ok, false);
  });
});

describe("runEngagement gating (dry-run agents, fake gate)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rt-eng-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const opts = (verify: typeof noVerify) => ({
    mcpToken: "test",
    deepseekApiKey: "test",
    engagementsDir: dir,
    dryRunAgents: true,
    deps: { verify },
  });

  for (const mode of ["red", "black"] as const) {
    it(`${mode}: blocked end-to-end without verification, no tools touched`, async () => {
      const res = await runEngagement(input(mode), opts(noVerify));
      assert.equal(res.status, "blocked");
      assert.match(res.blockedReason ?? "", /not ownership-verified/);
      const state = readState(join(dir, res.engagementId));
      assert.equal(state?.status, "blocked");
      assert.equal(state?.verified, false);
    });
  }

  it("completes the loop on positive proof and streams events", async () => {
    const res = await runEngagement(input("red"), opts(yesVerify));
    assert.equal(res.status, "complete");
    assert.ok(res.reportPath && existsSync(res.reportPath));
    const engDir = join(dir, res.engagementId);
    assert.ok(existsSync(join(engDir, "events.jsonl")));
    assert.ok(existsSync(join(engDir, "engagement.md")));
    const state = readState(engDir);
    assert.equal(state?.status, "complete");
    assert.equal(state?.verified, true);
    assert.ok(state?.verificationProof);
    const events = readEvents(engDir);
    assert.ok(events.length >= 5);
    // seq ordering is strict
    for (let i = 1; i < events.length; i++) {
      assert.ok(events[i]!.seq > events[i - 1]!.seq);
    }
    assert.equal(events[0]!.action, "engagement_start");
    assert.ok(events.some((e) => e.action === "authorization_basis"));
    assert.ok(events.some((e) => e.phase === "done"));
    // tail-after-seq works (console polling)
    const tail = readEvents(engDir, events[0]!.seq);
    assert.equal(tail.length, events.length - 1);
  });

  it("refuses to run outside the ROE test window", async () => {
    const inp = input("red");
    inp.roe.testWindow = { start: "2020-01-01T00:00:00Z", end: "2020-01-02T00:00:00Z" };
    await assert.rejects(() => runEngagement(inp, opts(yesVerify)), /test window/);
  });

  it("refuses empty/unparseable scope", async () => {
    const inp = input("red");
    inp.roe.scope = ["%%%"];
    await assert.rejects(() => runEngagement(inp, opts(yesVerify)), /scope/);
  });
});
