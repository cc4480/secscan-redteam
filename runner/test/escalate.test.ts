/**
 * Mid-run tier escalation tests (v0.24.0).
 *
 * No live engagement, no network: engagement directories are fixtures under a
 * tmp dir; the dispatcher pickup is exercised through refreshTierFromDisk
 * with a real EventLog (so the audit event is real, not stubbed); the UI
 * endpoint is called directly with a mocked response. Auth for the endpoint
 * is the server's per-startup token gate, shared with every other route
 * (covered in ui.test.ts).
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  escalateEngagement,
  describeEscalation,
  isSafeEngagementId,
} from "../src/accountability/escalate.js";
import { readTierFile, writeTierFile } from "../src/accountability/tierfile.js";
import { checkTierAllows, type AutonomyTier, type TierState } from "../src/accountability/tiers.js";
import { refreshTierFromDisk } from "../src/dispatch/router.js";
import { EventLog, readEvents } from "../src/events.js";
import { UiStore } from "../src/ui/store.js";
import { handleEscalate } from "../src/ui/routes/actions.js";

let tmp = "";
beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "escalate-test-"));
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** Canned engagement dir with a real event log: state.json + tier.json. */
function cannedEngagement(id: string, tier: AutonomyTier, environment: "staging" | "production"): string {
  const dir = join(tmp, id);
  mkdirSync(dir, { recursive: true });
  const log = new EventLog(dir, id, { target: "example.com", mode: "red", objective: "test" });
  log.updateState({ status: "running" });
  writeTierFile(dir, { tier, declared: tier, environment, updatedAt: "2026-10-03T15:00:00Z" });
  return dir;
}

function approvalEntries(dir: string): Array<Record<string, unknown>> {
  const raw = readFileSync(join(dir, "approvals.jsonl"), "utf8").trim();
  return raw.split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
}

describe("escalateEngagement (CLI core)", () => {
  it("records the approval and rewrites tier.json on up-escalation", () => {
    const dir = cannedEngagement("eng-up-1", 0, "staging");
    const r = escalateEngagement({
      engagementsDir: tmp,
      engagementId: "eng-up-1",
      toTier: "1",
      operator: "op",
      reason: "intrusive checks needed",
    });
    assert.equal(r.fromTier, 0);
    assert.equal(r.toTier, 1);
    assert.equal(r.operator, "op");
    assert.equal(r.engagementStatus, "running");
    const tf = readTierFile(dir)!;
    assert.equal(tf.tier, 1);
    assert.equal(tf.by, "op");
    assert.equal(tf.reason, "intrusive checks needed");
    assert.equal(tf.declared, 0, "declared tier is preserved — the trail stays honest");
    const entries = approvalEntries(dir);
    const esc = entries[entries.length - 1]!;
    assert.equal(esc["kind"], "tier-escalation");
    assert.equal(esc["operator"], "op");
    assert.equal(esc["fromTier"], 0);
    assert.equal(esc["toTier"], 1);
    assert.match(String(esc["detail"]), /intrusive checks needed/);
  });

  it("refuses up-escalation without a named operator or a reason", () => {
    cannedEngagement("eng-noop-1", 0, "staging");
    assert.throws(
      () => escalateEngagement({ engagementsDir: tmp, engagementId: "eng-noop-1", toTier: "1", reason: "x" }),
      /named operator/,
    );
    assert.throws(
      () => escalateEngagement({ engagementsDir: tmp, engagementId: "eng-noop-1", toTier: "1", operator: "op" }),
      /--reason/,
    );
    assert.equal(readTierFile(join(tmp, "eng-noop-1"))!.tier, 0, "tier unchanged after refusals");
  });

  it("allows de-escalation freely and logs it with the operator's name", () => {
    const dir = cannedEngagement("eng-down-1", 2, "staging");
    const r = escalateEngagement({ engagementsDir: tmp, engagementId: "eng-down-1", toTier: "0", operator: "op" });
    assert.equal(r.fromTier, 2);
    assert.equal(r.toTier, 0);
    assert.equal(readTierFile(dir)!.tier, 0);
    const entries = approvalEntries(dir);
    const last = entries[entries.length - 1]!;
    assert.equal(last["kind"], "tier-de-escalation");
    assert.equal(last["operator"], "op");
    assert.equal(last["fromTier"], 2);
    assert.equal(last["toTier"], 0);
  });

  it("refuses traversal ids, unknown engagements, and bad tiers", () => {
    assert.ok(!isSafeEngagementId("../evil"));
    assert.ok(isSafeEngagementId("eng-2026-10-03_abc"));
    assert.throws(
      () => escalateEngagement({ engagementsDir: tmp, engagementId: "../evil", toTier: "1", operator: "op", reason: "x" }),
      /bad engagement id/,
    );
    assert.throws(
      () => escalateEngagement({ engagementsDir: tmp, engagementId: "nope", toTier: "1", operator: "op", reason: "x" }),
      /unknown engagement/,
    );
    cannedEngagement("eng-badtier-1", 0, "staging");
    assert.throws(
      () => escalateEngagement({ engagementsDir: tmp, engagementId: "eng-badtier-1", toTier: "9", operator: "op", reason: "x" }),
      /bad autonomy tier/,
    );
  });

  it("Tier 2 on production needs explicit confirmation, staging does not", () => {
    cannedEngagement("eng-prod-1", 1, "production");
    assert.throws(
      () =>
        escalateEngagement({ engagementsDir: tmp, engagementId: "eng-prod-1", toTier: "2", operator: "op", reason: "chain needed" }),
      /requires explicit operator approval/,
      "Tier 2 on production without confirmation is refused",
    );
    const r = escalateEngagement({
      engagementsDir: tmp,
      engagementId: "eng-prod-1",
      toTier: "2",
      operator: "op",
      reason: "chain needed",
      tier2ProdConfirmed: true,
    });
    assert.equal(r.toTier, 2);
    cannedEngagement("eng-stg-1", 1, "staging");
    const r2 = escalateEngagement({
      engagementsDir: tmp,
      engagementId: "eng-stg-1",
      toTier: "2",
      operator: "op",
      reason: "chain needed",
    });
    assert.equal(r2.toTier, 2, "staging needs no extra confirmation");
  });

  it("describeEscalation names the live pickup", () => {
    cannedEngagement("eng-desc-1", 0, "staging");
    const r = escalateEngagement({
      engagementsDir: tmp,
      engagementId: "eng-desc-1",
      toTier: "1",
      operator: "op",
      reason: "x",
    });
    assert.match(describeEscalation(r), /next tool call/);
    assert.match(describeEscalation(r), /Tier 0.*→ Tier 1/);
  });
});

describe("dispatcher pickup (refreshTierFromDisk)", () => {
  it("a running engagement picks up the new tier without restarting", () => {
    const dir = cannedEngagement("eng-pickup-1", 0, "staging");
    const log = EventLog.open(dir);
    const tier: TierState = { current: 0, declared: 0, chainSteps: new Map() };
    // ssh_exec is Tier 1: denied at Tier 0.
    assert.ok(checkTierAllows(tier, "ssh_exec", {}, undefined), "tier-denied before escalation");
    // Operator escalates out-of-band; the dispatcher notices on its next call.
    escalateEngagement({
      engagementsDir: tmp,
      engagementId: "eng-pickup-1",
      toTier: "1",
      operator: "op",
      reason: "host access approved",
    });
    refreshTierFromDisk({ events: log, tier } as never, "recon");
    assert.equal(tier.current, 1, "tier adopted from tier.json");
    assert.equal(checkTierAllows(tier, "ssh_exec", {}, undefined), undefined, "no longer denied");
    const events = readEvents(dir);
    const changed = events.filter((e) => e.action === "tier_changed");
    assert.equal(changed.length, 1, "one audit event for the change");
    assert.match(changed[0]!.result, /Tier 0.*→ Tier 1/);
    assert.match(changed[0]!.result, /by op/);
    assert.match(changed[0]!.result, /approvals\.jsonl/, "points at the recorded approval");
  });

  it("is a no-op when tier.json is unchanged, missing, or corrupt", () => {
    const dir = cannedEngagement("eng-quiet-1", 1, "staging");
    const log = EventLog.open(dir);
    const tier: TierState = { current: 1, declared: 1, chainSteps: new Map() };
    refreshTierFromDisk({ events: log, tier } as never, "recon");
    assert.equal(tier.current, 1);
    assert.equal(readEvents(dir).filter((e) => e.action === "tier_changed").length, 0, "no audit noise");
    writeFileSync(join(dir, "tier.json"), "{not json");
    refreshTierFromDisk({ events: log, tier } as never, "recon");
    assert.equal(tier.current, 1, "corrupt tier.json means no change, not a crash");
  });
});

describe("UI endpoint (handleEscalate)", () => {
  /** Minimal mock response capturing status + body (same shape as ui.test.ts). */
  function mockRes() {
    const chunks: string[] = [];
    const res = {
      status: 0,
      body: "",
      writeHead(s: number) {
        res.status = s;
      },
      write(c: string) {
        chunks.push(c);
        return true;
      },
      end(c?: string) {
        if (c) chunks.push(c);
        res.body = chunks.join("");
      },
    };
    return res;
  }

  it("records the escalation and returns 200 with the pickup detail", () => {
    const store = new UiStore(tmp);
    cannedEngagement("eng-ui-1", 0, "staging");
    const res = mockRes();
    handleEscalate(store, res as never, "eng-ui-1", { tier: "1", operator: "op", reason: "ui test" });
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body) as { ok: boolean; toTier: number; approvalSeq: number; message: string };
    assert.equal(body.ok, true);
    assert.equal(body.toTier, 1);
    assert.match(body.message, /next tool call/);
    const entries = approvalEntries(join(tmp, "eng-ui-1"));
    assert.equal(entries[entries.length - 1]!["kind"], "tier-escalation");
  });

  it("validates input and refuses unsafe ids with 400", () => {
    const store = new UiStore(tmp);
    cannedEngagement("eng-ui-2", 0, "staging");
    const missingOperator = mockRes();
    handleEscalate(store, missingOperator as never, "eng-ui-2", { tier: "1", reason: "x" });
    assert.equal(missingOperator.status, 400);
    const missingReason = mockRes();
    handleEscalate(store, missingReason as never, "eng-ui-2", { tier: "1", operator: "op" });
    assert.equal(missingReason.status, 400, "up-escalation without reason is refused");
    const traversal = mockRes();
    handleEscalate(store, traversal as never, "../../etc", { tier: "1", operator: "op", reason: "x" });
    assert.equal(traversal.status, 400);
    const unknown = mockRes();
    handleEscalate(store, unknown as never, "no-such-eng", { tier: "1", operator: "op", reason: "x" });
    assert.equal(unknown.status, 400);
    assert.equal(readTierFile(join(tmp, "eng-ui-2"))!.tier, 0, "refused requests change nothing");
  });
});
