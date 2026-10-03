/**
 * Safety case tests (v0.13.0) — the production safety case.
 *
 * No network, no API keys. What we prove here:
 *  - per-target rate limiting is mechanical (token bucket, per-host, stated limits)
 *  - PII redaction scrubs the documented shapes and leaves operational text alone
 *  - staging→production graduation fails closed without explicit confirmation
 *  - per-target auto-halt fires on distress and refuses further traffic
 *  - the safety manifest + zero-disruption record are derived mechanically
 *  - a full dry-run engagement writes safety-manifest.json/.md
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  TargetRateLimiter,
  resolveEffectiveRps,
  TargetAutoHalt,
  isTargetDistress,
  buildZeroDisruptionRecord,
  disruptionVerdict,
  buildSafetyManifest,
  renderSafetyManifestMarkdown,
  redactPii,
  piiPatternLabels,
  likelyContainsPii,
  parseEnvironment,
  productionConfirmed,
  requireGraduation,
  PROTECTIONS_IN_FORCE,
  RESIDUAL_RISKS,
} from "../src/safety/index.js";
import type { EngagementEvent } from "../src/types.js";
import { runEngagement } from "../src/phases.js";
import { readEvents } from "../src/events.js";
import type { EngagementInput } from "../src/types.js";

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

describe("TargetRateLimiter", () => {
  it("grants burst tokens then denies until refill (injectable clock)", () => {
    let now = 0;
    const lim = new TargetRateLimiter({ rpsPerHost: 2, burst: 2 }, () => now);
    assert.equal(lim.tryAcquire("h"), true);
    assert.equal(lim.tryAcquire("h"), true);
    assert.equal(lim.tryAcquire("h"), false); // burst exhausted
    now += 500; // 1 token refilled at 2 rps
    assert.equal(lim.tryAcquire("h"), true);
    assert.equal(lim.tryAcquire("h"), false);
  });

  it("isolates buckets per host", () => {
    let now = 0;
    const lim = new TargetRateLimiter({ rpsPerHost: 1, burst: 1 }, () => now);
    assert.equal(lim.tryAcquire("a"), true);
    assert.equal(lim.tryAcquire("a"), false);
    assert.equal(lim.tryAcquire("b"), true); // other host unaffected
  });

  it("refuses non-positive rps at construction", () => {
    assert.throws(() => new TargetRateLimiter({ rpsPerHost: 0 }), /positive/);
    assert.throws(() => new TargetRateLimiter({ rpsPerHost: -3 }), /positive/);
  });

  it("acquire waits for a token and counts throttled time", async () => {
    const lim = new TargetRateLimiter({ rpsPerHost: 1000, burst: 1 });
    assert.equal(lim.tryAcquire("h"), true);
    const waited = await lim.acquire("h"); // ~1ms at 1000 rps
    assert.ok(waited >= 0);
    assert.equal(lim.acquires, 2);
    assert.ok(lim.throttledMs >= 0);
  });
});

describe("resolveEffectiveRps", () => {
  it("staging defaults to 5, honors higher operator config", () => {
    assert.deepEqual(resolveEffectiveRps("staging", undefined), { rps: 5, productionCapApplied: false });
    assert.deepEqual(resolveEffectiveRps("staging", 20), { rps: 20, productionCapApplied: false });
  });

  it("production defaults to 2 and caps higher config mechanically", () => {
    assert.deepEqual(resolveEffectiveRps("production", undefined), { rps: 2, productionCapApplied: false });
    const capped = resolveEffectiveRps("production", 50);
    assert.equal(capped.rps, 2);
    assert.equal(capped.productionCapApplied, true);
  });
});

// ---------------------------------------------------------------------------
// PII redaction
// ---------------------------------------------------------------------------

describe("redactPii", () => {
  it("redacts email addresses", () => {
    const out = redactPii("contact admin@example.com for access");
    assert.ok(!out.includes("admin@example.com"));
    assert.ok(out.includes("[PII-REDACTED]"));
  });

  it("redacts phone-like strings", () => {
    assert.ok(!redactPii("call +1-555-123-4567 now").includes("555-123-4567"));
    assert.ok(!redactPii("tel: (555) 123 4567").includes("(555)"));
  });

  it("redacts SSN-like numbers", () => {
    assert.ok(!redactPii("ssn 123-45-6789 on file").includes("123-45-6789"));
  });

  it("redacts card-like numbers only with a valid Luhn check", () => {
    // 4111111111111111 is the standard Luhn-valid test number.
    assert.ok(!redactPii("card 4111111111111111 charged").includes("4111111111111111"));
    // Same shape, bad checksum → left alone.
    assert.ok(redactPii("card 4111111111111112 charged").includes("4111111111111112"));
  });

  it("leaves operational text alone (IPs, hostnames, versions, ports)", () => {
    const text = "host 10.0.0.5:443 secscan.us responded HTTP 200 in 120ms (nginx/1.25.3)";
    assert.equal(redactPii(text), text);
  });

  it("leaves CVE identifiers alone (regression: 2017-0144 is not a phone)", () => {
    assert.equal(redactPii("validated [CVE-2017-0144] via ms17_010"), "validated [CVE-2017-0144] via ms17_010");
    assert.equal(redactPii("CVE-2021-44228 log4shell"), "CVE-2021-44228 log4shell");
  });

  it("is idempotent and lists its patterns", () => {
    const once = redactPii("mail bob@example.com");
    assert.equal(redactPii(once), once);
    assert.deepEqual(piiPatternLabels(), ["email address", "phone number", "US-SSN-like number", "payment-card-like number"]);
  });

  it("likelyContainsPii agrees with redaction", () => {
    assert.equal(likelyContainsPii("mail bob@example.com"), true);
    assert.equal(likelyContainsPii(redactPii("mail bob@example.com")), false);
    assert.equal(likelyContainsPii("HTTP 200 from 10.0.0.5"), false);
  });
});

// ---------------------------------------------------------------------------
// Graduation
// ---------------------------------------------------------------------------

describe("staging→production graduation", () => {
  it("parses environments, fails loud on unknown", () => {
    assert.equal(parseEnvironment(undefined), "staging");
    assert.equal(parseEnvironment("staging"), "staging");
    assert.equal(parseEnvironment("production"), "production");
    assert.equal(parseEnvironment("prod"), "production");
    assert.throws(() => parseEnvironment("prodution"), /unknown test environment/);
  });

  it("reads confirmation from the environment", () => {
    assert.equal(productionConfirmed({ REDTEAM_PROD_CONFIRM: "1" } as NodeJS.ProcessEnv), true);
    assert.equal(productionConfirmed({} as NodeJS.ProcessEnv), false);
  });

  it("fails closed: production without confirmation refuses to start", () => {
    assert.throws(() => requireGraduation("production", false), /not confirmed/);
    requireGraduation("production", true); // no throw
    requireGraduation("staging", false); // no throw
  });
});

// ---------------------------------------------------------------------------
// Auto-halt
// ---------------------------------------------------------------------------

describe("TargetAutoHalt", () => {
  it("halts after N consecutive distress outcomes", () => {
    const ah = new TargetAutoHalt({ consecutiveThreshold: 3, windowSize: 20, windowFailureRate: 0.5 });
    assert.equal(ah.recordOutcome("h", true), null);
    assert.equal(ah.recordOutcome("h", true), null);
    const reason = ah.recordOutcome("h", true);
    assert.ok(reason && reason.includes("consecutive"));
    assert.equal(ah.isHalted("h"), true);
    assert.deepEqual(ah.haltedHosts(), ["h"]);
  });

  it("clean outcomes reset the consecutive counter", () => {
    const ah = new TargetAutoHalt({ consecutiveThreshold: 3, windowSize: 20, windowFailureRate: 0.5 });
    ah.recordOutcome("h", true);
    ah.recordOutcome("h", true);
    ah.recordOutcome("h", false);
    assert.equal(ah.recordOutcome("h", true), null);
    assert.equal(ah.isHalted("h"), false);
  });

  it("halts on window failure rate", () => {
    const ah = new TargetAutoHalt({ consecutiveThreshold: 100, windowSize: 4, windowFailureRate: 0.5 });
    ah.recordOutcome("h", true);
    ah.recordOutcome("h", false);
    ah.recordOutcome("h", true);
    const reason = ah.recordOutcome("h", false); // 2/4 = 50%
    assert.ok(reason && reason.includes("50%"));
    assert.equal(ah.isHalted("h"), true);
  });

  it("other hosts are unaffected; reset clears a halt", () => {
    const ah = new TargetAutoHalt({ consecutiveThreshold: 2, windowSize: 20, windowFailureRate: 0.5 });
    ah.recordOutcome("a", true);
    ah.recordOutcome("a", true);
    assert.equal(ah.isHalted("a"), true);
    assert.equal(ah.isHalted("b"), false);
    ah.reset("a");
    assert.equal(ah.isHalted("a"), false);
  });
});

describe("isTargetDistress", () => {
  it("classifies transport/target errors as distress", () => {
    assert.equal(isTargetDistress("probe failed: connection refused"), true);
    assert.equal(isTargetDistress("HTTP 500 in 120ms. Snippet: error"), true);
    assert.equal(isTargetDistress("ssh_exec timed out after 30s"), true);
  });

  it("classifies clean negatives as not distress", () => {
    assert.equal(isTargetDistress("DENIED by ROE: technique T1110 is excluded"), false);
    assert.equal(isTargetDistress("HTTP 404 in 40ms. Snippet: not found"), false);
    assert.equal(isTargetDistress("DENIED: unparseable URL"), false);
    assert.equal(isTargetDistress("HALTED: target h was auto-halted"), false);
  });
});

// ---------------------------------------------------------------------------
// Zero-disruption record + manifest
// ---------------------------------------------------------------------------

function ev(action: string, result: string): EngagementEvent {
  return {
    ts: new Date().toISOString(),
    seq: 1,
    engagementId: "eng-test",
    phase: "exploit",
    actor: "exploiter",
    action,
    result,
  };
}

describe("buildZeroDisruptionRecord", () => {
  it("counts interventions from the audit log and proves the negative", () => {
    const events = [
      ev("ssh_exec", "DENIED by destructive-command denylist: recursive delete of filesystem root"),
      ev("msf_exec", "DENIED by module policy: dos modules refused (T1499 excluded)"),
      ev("http_probe", "DENIED: https://evil.example is outside the engagement scope."),
      ev("http_probe", "DENIED by ROE: technique T1499 is excluded for this engagement."),
      ev("target_auto_halt", "AUTO-HALT: db.internal — 5 consecutive target-distress outcomes."),
      ev("abort_engagement", "ABORTED by coordinator: operator stop"),
      ev("http_probe", "HTTP 200 in 40ms. Snippet: ok"),
    ];
    const rec = buildZeroDisruptionRecord(events);
    assert.equal(rec.denylistRefusals, 1);
    assert.equal(rec.dosRefusals, 1);
    assert.equal(rec.scopeRefusals, 1);
    assert.equal(rec.policyRefusals, 1);
    assert.equal(rec.autoHalts, 1);
    assert.equal(rec.killSwitchAborts, 1);
    assert.equal(rec.destructiveActionsFired, 0);
    assert.equal(rec.totalInterventions, 6);
    assert.match(disruptionVerdict(rec), /^CLEAN/);
  });

  it("flags a recorded destructive execution as FAIL", () => {
    const rec = buildZeroDisruptionRecord([ev("ssh_exec", "destructive action executed: disk wiped")]);
    assert.equal(rec.destructiveActionsFired, 1);
    assert.match(disruptionVerdict(rec), /^FAIL/);
  });
});

describe("buildSafetyManifest", () => {
  const zero = buildZeroDisruptionRecord([]);

  it("states every protection, the config, and residual risks honestly", () => {
    const m = buildSafetyManifest({
      engagementId: "eng-1",
      environment: "staging",
      productionConfirmed: false,
      scopeAllowlist: ["secscan.us"],
      rpsPerHost: 5,
      burst: 5,
      productionCapApplied: false,
      throttledMs: 120,
      acquires: 40,
      killSwitchAborts: 0,
      operator: "Test Operator",
      autoHalt: { consecutiveThreshold: 5, windowSize: 20, windowFailureRate: 0.5, haltedTargets: [], haltCount: 0 },
      zeroDisruption: zero,
      disruptionVerdict: disruptionVerdict(zero),
    });
    assert.equal(m.environment, "staging");
    assert.deepEqual(m.scopeAllowlist, ["secscan.us"]);
    assert.equal(m.rateLimit.rpsPerHost, 5);
    assert.equal(m.killSwitch.armed, true);
    assert.equal(m.payloadPolicy, "canary-only");
    assert.equal(m.dosPolicy, "excluded-always");
    assert.ok(m.destructiveDenylist.patternCount > 0);
    assert.ok(m.protectionsInForce.length >= 10);
    assert.ok(m.residualRisks.length > 0, "a safety case with no residual risks is marketing");
    assert.match(m.disruptionVerdict, /^CLEAN/);
    assert.equal(m.piiRedaction.enabled, true);
  });

  it("records production confirmation state", () => {
    const m = buildSafetyManifest({
      engagementId: "eng-2",
      environment: "production",
      productionConfirmed: true,
      scopeAllowlist: ["app.example"],
      rpsPerHost: 2,
      burst: 2,
      productionCapApplied: true,
      throttledMs: 0,
      acquires: 0,
      killSwitchAborts: 0,
      operator: "Op",
      autoHalt: { consecutiveThreshold: 5, windowSize: 20, windowFailureRate: 0.5, haltedTargets: ["db.example"], haltCount: 1 },
      zeroDisruption: zero,
      disruptionVerdict: disruptionVerdict(zero),
    });
    assert.equal(m.environment, "production");
    assert.equal(m.productionConfirmed, true);
    assert.equal(m.rateLimit.productionCapApplied, true);
    assert.deepEqual(m.autoHalt.haltedTargets, ["db.example"]);
    const md = renderSafetyManifestMarkdown(m);
    assert.ok(md.includes("# Safety manifest"));
    assert.ok(md.includes("Residual risks"));
    assert.ok(md.includes("**0**"));
  });

  it("protections and risks are non-empty constants", () => {
    assert.ok(PROTECTIONS_IN_FORCE.length > 0);
    assert.ok(RESIDUAL_RISKS.length > 0);
  });
});

// ---------------------------------------------------------------------------
// Integration: dry-run engagement writes the safety manifest
// ---------------------------------------------------------------------------

describe("safety case end-to-end (dry-run engagement)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rt-safety-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const yesVerify = async () => true;
  const opts = () => ({
    mcpToken: "test",
    deepseekApiKey: "test",
    qwenApiKey: "test",
    engagementsDir: dir,
    dryRunAgents: true,
    deps: { verify: yesVerify },
  });
  const input = (extra: Partial<EngagementInput> = {}): EngagementInput => ({
    target: "secscan.us",
    mode: "red",
    objective: "safety case test",
    roe: { scope: ["secscan.us"] },
    ...extra,
  });

  it("staging engagement writes safety-manifest.json/.md with the zero-disruption record", async () => {
    const res = await runEngagement(input(), opts());
    assert.equal(res.status, "complete");
    const engDir = join(dir, res.engagementId);
    const jsonPath = join(engDir, "safety-manifest.json");
    const mdPath = join(engDir, "safety-manifest.md");
    assert.ok(existsSync(jsonPath), "safety-manifest.json written");
    assert.ok(existsSync(mdPath), "safety-manifest.md written");
    const m = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.equal(m.environment, "staging");
    assert.equal(m.rateLimit.rpsPerHost, 5);
    assert.deepEqual(m.scopeAllowlist, ["secscan.us"]);
    assert.equal(m.zeroDisruption.destructiveActionsFired, 0);
    assert.match(m.disruptionVerdict, /^CLEAN/);
    assert.ok(m.residualRisks.length > 0);
    // The manifest event is in the audit log.
    const events = readEvents(engDir);
    assert.ok(events.some((e) => e.action === "safety_manifest"));
  });

  it("production without confirmation refuses before any engagement state", async () => {
    await assert.rejects(() => runEngagement(input({ environment: "production" }), opts()), /not confirmed/);
  });

  it("production with confirmation runs and records it in the manifest", async () => {
    const res = await runEngagement(input({ environment: "production", confirmProduction: true }), opts());
    assert.equal(res.status, "complete");
    const m = JSON.parse(readFileSync(join(dir, res.engagementId, "safety-manifest.json"), "utf8"));
    assert.equal(m.environment, "production");
    assert.equal(m.productionConfirmed, true);
    assert.equal(m.rateLimit.rpsPerHost, 2);
  });
});
