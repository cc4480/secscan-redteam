/**
 * Event redaction + projection tests (v0.33.0).
 *
 * Two contracts, both of which regressed in the field on the AlterEgo side and
 * must not regress here:
 *   - no live credential ever reaches events.jsonl (recursive redaction)
 *   - the derived views of the stream (tool stats, approvals, causal chain) are
 *     computed correctly and stay pure
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { collectSecrets, redact } from "../src/events/redact.js";
import {
  projectToolStats,
  projectActorTimeline,
  projectApprovals,
  projectFindings,
  projectCausalChain,
  projectDanglingCauses,
} from "../src/events/projections.js";
import type { EngagementEvent } from "../src/types.js";

let n = 0;
/** Build a well-formed event with defaults for the fields projections ignore. */
function ev(p: Partial<EngagementEvent> & { seq: number; action: string }): EngagementEvent {
  n += 1;
  return {
    ts: `2026-01-01T00:00:${String(n % 60).padStart(2, "0")}Z`,
    engagementId: "eng-test",
    phase: "recon",
    actor: "runner",
    result: "",
    ...p,
  } as EngagementEvent;
}

describe("redact", () => {
  it("collects only non-trivial secret values from the environment", () => {
    const secrets = collectSecrets({
      DEEPSEEK_API_KEY: "sk-abcdef123456",
      SECSCAN_MCP_TOKEN: "ssk_1234567890abcdef",
      REDTEAM_MSFRPC_PASS: "ab", // too short — must be dropped
    } as NodeJS.ProcessEnv);
    assert.ok(secrets.includes("sk-abcdef123456"));
    assert.ok(secrets.includes("ssk_1234567890abcdef"));
    assert.ok(!secrets.some((s) => s === "ab"));
  });

  it("redacts secret-named keys recursively, whatever the depth", () => {
    const out = redact({
      tool: "shell_exec",
      args: { cmd: "x", token: "TOP", nested: { password: "PW", ok: "keep" } },
      list: [{ apiKey: "K1" }],
    }, []);
    const j = JSON.stringify(out);
    assert.ok(!j.includes("TOP") && !j.includes("PW") && !j.includes("K1"), j);
    assert.ok(j.includes("<redacted>"));
    assert.ok(j.includes("keep"), "non-secret values must survive");
  });

  it("masks a known secret literal anywhere inside a string (incl. free-form result)", () => {
    const out = redact({ result: "ran whoami; token=ssk_SECRET123 ok" }, ["ssk_SECRET123"]);
    assert.ok(!out.result.includes("ssk_SECRET123"));
    assert.ok(out.result.includes("<redacted>"));
  });

  it("passes primitives through unchanged", () => {
    assert.equal(redact(42, []), 42);
    assert.equal(redact("nothing here", []), "nothing here");
    assert.equal(redact(null, []), null);
  });
});

describe("projections", () => {
  const e1 = ev({ seq: 1, action: "http_probe", attackId: "T1595", result: "200" });
  const e2 = ev({ seq: 2, action: "http_probe", attackId: "T1595", result: "404", causedBy: 1 });
  const e3 = ev({ seq: 3, action: "record_finding", result: "F-1" });
  const e4 = ev({ seq: 4, action: "signoff", phase: "plan", actor: "coordinator", result: "approved" });
  const e5 = ev({ seq: 5, action: "abort_engagement", phase: "exploit", actor: "coordinator", result: "kill switch" });

  const events = [e1, e2, e3, e4, e5];

  it("tool stats count per action and dedupe attack ids", () => {
    const stats = projectToolStats(events);
    const probe = stats.find((s) => s.action === "http_probe");
    assert.equal(probe?.count, 2);
    assert.deepEqual(probe?.attackIds, ["T1595"]);
    assert.equal(stats.length, 4, "distinct actions only");
  });

  it("actor timeline counts per phase", () => {
    const timeline = projectActorTimeline(events);
    const plan = timeline.find((t) => t.phase === "plan");
    assert.equal(plan?.actors["coordinator"], 1);
    assert.equal(plan?.total, 1);
  });

  it("approvals isolate operator decisions; findings isolate record_finding", () => {
    assert.deepEqual(projectApprovals(events).map((e) => e.seq), [4, 5]);
    assert.deepEqual(projectFindings(events).map((e) => e.seq), [3]);
  });

  it("causal chain resolves causedBy links oldest-first and stops on dangling links", () => {
    const chain = projectCausalChain(events, 2);
    assert.deepEqual(chain.chain.map((e) => e.seq), [1, 2]);
    // a dangling cause is reported, not looped
    const dangling = ev({ seq: 6, action: "x", causedBy: 999 });
    assert.deepEqual(projectDanglingCauses([...events, dangling]), [6]);
    const chainDangling = projectCausalChain([...events, dangling], 6);
    assert.equal(chainDangling.chain.length, 1);
  });
});
