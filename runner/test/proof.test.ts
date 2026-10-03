/**
 * Proof-of-exploitation tests (v0.14.0). No network, no API keys.
 *
 * Mechanical honesty gates:
 *  - a bundle is built ONLY for confirmed findings with a genuine
 *    validation signal (marker echo, or read-only evidence output);
 *  - killed hypotheses and unvalidated probes get NO bundle, with an
 *    honest reason — never fabricated;
 *  - bundles are derived from actual audit events (events.jsonl round-trip);
 *  - secrets never leak into bundles;
 *  - reverify verdicts: reproduced / not-reproduced / target-changed.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildNegativeProof,
  buildPocBundle,
  bundleSummary,
  type PocBundle,
} from "../src/proof/bundle.js";
import { reverifyBundle, type StepRunner } from "../src/proof/reverify.js";
import { EventLog, readEvents } from "../src/events.js";
import type { EngagementEvent, Finding } from "../src/types.js";

const SECRET = "s3cr3t-p@ssw0rd-value";

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

const META = { engagementId: "eng-1", target: "target.example", operator: "op" };

describe("buildPocBundle — execution tier (marker echo)", () => {
  it("builds a complete bundle from a marker-echo validation", () => {
    const events = [
      ev({ seq: 10, action: "msf_exec", attackId: "T1190", result: "msf exploit/windows/smb/ms17_010_eternalblue vs target.example: MARKER ECHOED — command execution validated. [CVE-2017-0144] Output: REDTEAM-MARKER-abc123" }),
      ev({ seq: 11, action: "reasoning", result: "looks confirmed" }),
    ];
    const { bundle, reason } = buildPocBundle({ finding: confirmedFinding(), events, engagement: META, secrets: [] });
    assert.ok(bundle, `expected bundle, got reason: ${reason}`);
    assert.equal(bundle!.version, 1);
    assert.equal(bundle!.bundleId, "POC-eng-1-F-1");
    assert.equal(bundle!.validationTier, "execution");
    assert.equal(bundle!.markerObserved, "REDTEAM-MARKER-abc123");
    assert.equal(bundle!.cve, "CVE-2017-0144");
    // Only the tool-call event becomes a step — reasoning is excluded.
    assert.equal(bundle!.steps.length, 1);
    assert.equal(bundle!.steps[0]!.tool, "msf_exec");
    assert.equal(bundle!.steps[0]!.validation, "marker-echo");
    assert.ok(bundle!.steps[0]!.replay, "msf_exec step should be replayable");
    assert.equal(bundle!.steps[0]!.replay!.args["module"], "exploit/windows/smb/ms17_010_eternalblue");
    assert.match(bundle!.proves, /marker REDTEAM-MARKER-abc123 echoed back/);
    assert.match(bundle!.doesNotProve, /not attempted/i);
    assert.match(bundle!.reverifyCommand, /reverify --bundle poc\/F-1\.json/);
    const summary = bundleSummary(bundle!);
    assert.match(summary, /F-1/);
    assert.match(summary, /execution proof/);
  });

  it("extracts the ssh command and builds replay args", () => {
    const events = [
      ev({ seq: 5, action: "ssh_exec", attackId: "T1068", result: "ssh target.example: exit=0 in 42ms :: echo REDTEAM-MARKER-zzz999 && id" }),
    ];
    const { bundle } = buildPocBundle({
      finding: confirmedFinding({ id: "F-2", attackIds: ["T1068"], title: "privesc" }),
      events, engagement: META, secrets: [],
    });
    assert.ok(bundle);
    assert.equal(bundle!.validationTier, "execution");
    assert.equal(bundle!.steps[0]!.command, "echo REDTEAM-MARKER-zzz999 && id");
    assert.deepEqual(bundle!.steps[0]!.replay, {
      tool: "ssh_exec",
      host: "target.example",
      args: { command: "echo REDTEAM-MARKER-zzz999 && id" },
    });
  });

  it("redacts secrets from every bundle string", () => {
    const events = [
      ev({ seq: 7, action: "ssh_exec", attackId: "T1078", result: `ssh target.example: exit=0 in 9ms :: echo ${SECRET} && echo REDTEAM-MARKER-q1` }),
    ];
    const { bundle } = buildPocBundle({
      finding: confirmedFinding({ id: "F-3", attackIds: ["T1078"], title: `valid creds ${SECRET} reused` }),
      events, engagement: META, secrets: [SECRET],
    });
    assert.ok(bundle);
    const json = JSON.stringify(bundle);
    assert.ok(!json.includes(SECRET), "secret leaked into bundle");
  });
});

describe("buildPocBundle — observation tier (read-only evidence)", () => {
  it("builds an observation bundle for ad_enum output", () => {
    const events = [
      ev({ seq: 3, action: "ad_enum", attackId: "T1553", result: "ad target.example: 1 certificate template(s) with ESC1 flags (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)" }),
    ];
    const { bundle, reason } = buildPocBundle({
      finding: confirmedFinding({ id: "F-4", attackIds: ["T1553"], title: "ESC1-vulnerable template" }),
      events, engagement: META, secrets: [],
    });
    assert.ok(bundle, `expected bundle, got: ${reason}`);
    assert.equal(bundle!.validationTier, "observation");
    assert.equal(bundle!.markerObserved, undefined);
    assert.match(bundle!.proves, /directly demonstrates/);
  });
});

describe("buildPocBundle — honest absence (no fabrication)", () => {
  it("no bundle for killed hypotheses", () => {
    const events = [ev({ seq: 2, action: "msf_exec", attackId: "T1190", result: "msf exploit/windows/smb/ms17_010_eternalblue vs target.example: MARKER ECHOED — command execution validated" })];
    const { bundle, reason } = buildPocBundle({
      finding: confirmedFinding({ status: "killed" }),
      events, engagement: META, secrets: [],
    });
    assert.equal(bundle, null);
    assert.match(reason!, /not confirmed/);
  });

  it("no bundle when the finding is confirmed but nothing validated", () => {
    const events = [
      ev({ seq: 4, action: "msf_exec", attackId: "T1190", result: "msf exploit/windows/smb/ms17_010_eternalblue vs target.example: completed without marker echo" }),
    ];
    const { bundle, reason } = buildPocBundle({ finding: confirmedFinding(), events, engagement: META, secrets: [] });
    assert.equal(bundle, null);
    assert.match(reason!, /no validation signal/);
  });

  it("no bundle when only refusals/failures correlate", () => {
    const events = [
      ev({ seq: 6, action: "ssh_exec", attackId: "T1078", result: "DENIED by ROE: technique T1078 is excluded for this engagement." }),
    ];
    const { bundle } = buildPocBundle({ finding: confirmedFinding({ attackIds: ["T1078"] }), events, engagement: META, secrets: [] });
    assert.equal(bundle, null);
  });

  it("no bundle when no correlated execution exists in the log", () => {
    const events = [ev({ seq: 8, action: "http_probe", attackId: "T1595", target: "other.example", result: "GET / ok 200" })];
    const { bundle, reason } = buildPocBundle({ finding: confirmedFinding(), events, engagement: META, secrets: [] });
    assert.equal(bundle, null);
    assert.match(reason!, /no correlated tool execution/);
  });
});

describe("buildPocBundle — derived from the actual audit log", () => {
  it("round-trips through events.jsonl via EventLog", () => {
    const dir = mkdtempSync(join(tmpdir(), "proof-eng-"));
    const log = new EventLog(dir, "eng-rt", { target: "target.example", mode: "red", objective: "test" });
    log.append({
      phase: "exploit", actor: "exploiter", action: "msf_exec", attackId: "T1190", target: "target.example",
      result: "msf exploit/windows/smb/ms17_010_eternalblue vs target.example: MARKER ECHOED — command execution validated. Output: REDTEAM-MARKER-live1",
    });
    const events = readEvents(dir);
    assert.ok(events.length >= 1);
    const { bundle, reason } = buildPocBundle({
      finding: confirmedFinding(),
      events,
      engagement: { engagementId: "eng-rt", target: "target.example", operator: "op" },
      secrets: [],
    });
    assert.ok(bundle, `expected bundle from real audit log, got: ${reason}`);
    assert.equal(bundle!.steps[0]!.seq, 1);
    assert.equal(bundle!.validationTier, "execution");
  });
});

describe("buildNegativeProof", () => {
  it("attaches decisive audit events to killed hypotheses", () => {
    const events = [
      ev({ seq: 20, action: "smb_exec", attackId: "T1135", result: "smb target.example: list_shares IPC$ only — no readable shares" }),
      ev({ seq: 21, action: "http_probe", attackId: "T1595", result: "GET / ok 200" }),
    ];
    const out = buildNegativeProof(
      [{ hypothesis: "open SMB shares", killingObservation: "only IPC$ reachable", attackId: "T1135" }],
      events,
      [],
    );
    assert.equal(out.length, 1);
    assert.equal(out[0]!.hypothesis, "open SMB shares");
    assert.equal(out[0]!.killingObservation, "only IPC$ reachable");
    assert.equal(out[0]!.decisiveEvents.length, 1);
    assert.equal(out[0]!.decisiveEvents[0]!.tool, "smb_exec");
  });

  it("redacts secrets in negative proof", () => {
    const events = [ev({ seq: 22, action: "ssh_exec", attackId: "T1078", result: `tried password ${SECRET}: auth failed` })];
    const out = buildNegativeProof(
      [{ hypothesis: "weak creds", killingObservation: `account locked after ${SECRET} attempts`, attackId: "T1078" }],
      events,
      [SECRET],
    );
    assert.ok(!JSON.stringify(out).includes(SECRET));
  });
});

describe("reverifyBundle", () => {
  function bundleWithSteps(): PocBundle {
    return {
      version: 1,
      bundleId: "POC-eng-1-F-1",
      engagementId: "eng-1",
      findingId: "F-1",
      attackIds: ["T1190"],
      severity: "critical",
      title: "RCE",
      target: "target.example",
      operator: "op",
      generatedAt: "2026-10-03T06:00:00.000Z",
      steps: [
        {
          seq: 10, ts: "2026-10-03T06:00:00.000Z", tool: "msf_exec", target: "target.example",
          attackId: "T1190", command: "msf_exec run exploit/windows/smb/ms17_010_eternalblue",
          result: "MARKER ECHOED", validation: "marker-echo", marker: "abc123",
          replay: { tool: "msf_exec", host: "target.example", args: { moduleType: "exploit", module: "exploit/windows/smb/ms17_010_eternalblue" } },
        },
        {
          seq: 11, ts: "2026-10-03T06:01:00.000Z", tool: "ad_enum", target: "target.example",
          attackId: "T1553", command: "ad_enum enumeration", result: "1 template",
          validation: "observation", replay: null,
        },
      ],
      validationTier: "execution",
      proves: "marker echoed",
      doesNotProve: "no impact overclaim",
      reverifyCommand: "redteam-runner reverify --bundle poc/F-1.json",
    };
  }

  it("reproduced: fresh marker echoes on every replayable step", async () => {
    const seen: string[] = [];
    const runner: StepRunner = async (step, marker) => {
      seen.push(marker);
      return { ok: true, output: `output with ${marker} echoed` };
    };
    const report = await reverifyBundle(bundleWithSteps(), runner);
    assert.equal(report.verdict, "reproduced");
    assert.ok(seen[0]!.startsWith("REVERIFY-"), "fresh marker per run");
    assert.ok(!seen[0]!.includes("abc123"), "stale marker never replayed");
    assert.equal(report.steps.find((s) => s.seq === 11)!.replayed, false);
    assert.match(report.registryNote, /REPRODUCED/);
  });

  it("not-reproduced: steps run but the marker does not echo", async () => {
    const runner: StepRunner = async () => ({ ok: true, output: "completed without marker echo" });
    const report = await reverifyBundle(bundleWithSteps(), runner);
    assert.equal(report.verdict, "not-reproduced");
    assert.match(report.summary, /validation signal/);
  });

  it("target-changed: connectivity failure is not a fix", async () => {
    const runner: StepRunner = async () => ({ ok: false, output: "", note: "dial tcp: connection refused" });
    const report = await reverifyBundle(bundleWithSteps(), runner);
    assert.equal(report.verdict, "target-changed");
    assert.match(report.registryNote, /do NOT close the finding/);
  });

  it("inconclusive when no steps are replayable", async () => {
    const b = bundleWithSteps();
    b.steps = b.steps.map((s) => ({ ...s, replay: null }));
    const runner: StepRunner = async () => ({ ok: true, output: "x" });
    const report = await reverifyBundle(b, runner);
    assert.equal(report.verdict, "not-reproduced");
    assert.match(report.summary, /manual retest required/);
  });
});
