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
  stampBundleIntegrity,
  type PocBundle,
} from "../src/proof/bundle.js";
import { createReplayer, reverifyBundle, type StepRunner } from "../src/proof/reverify.js";
import { extractToolOutput, stepValidation } from "../src/proof/bundle/steps.js";
import { HostExecutor } from "../src/host-exec/index.js";
import type { SshTransport, WinrmTransport } from "../src/host-exec/index.js";
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
      ev({ seq: 5, action: "ssh_exec", attackId: "T1068", result: "ssh target.example: exit=0 in 42ms :: echo REDTEAM-MARKER-zzz999 && id. Output: REDTEAM-MARKER-zzz999\nuid=0(root) gid=0(root)" }),
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
      ev({ seq: 7, action: "ssh_exec", attackId: "T1078", result: `ssh target.example: exit=0 in 9ms :: echo ${SECRET} && echo REDTEAM-MARKER-q1. Output: REDTEAM-MARKER-q1` }),
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
    return stampBundleIntegrity({
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
    });
  }

  it("reproduced: the recorded marker reappears in fresh tool output", async () => {
    const seen: string[] = [];
    const runner: StepRunner = async (step, marker) => {
      seen.push(marker);
      return { ok: true, output: `output with ${marker} echoed` };
    };
    const report = await reverifyBundle(bundleWithSteps(), runner);
    assert.equal(report.verdict, "reproduced");
    assert.deepEqual(seen, ["REDTEAM-MARKER-abc123"], "the runner receives the ORIGINALLY recorded marker, never a fresh one");
    assert.equal(report.steps.find((s) => s.seq === 11)!.replayed, false);
    assert.match(report.registryNote, /REPRODUCED/);
  });

  it("not-reproduced: a marker in the summary/note alone never validates (output-only)", async () => {
    // The old replayer returned summary+output as "output", and the summary
    // embeds the sent command (marker and all) — even a silent target
    // "validated". The runner contract now keeps them separate.
    const runner: StepRunner = async () => ({
      ok: true,
      output: "",
      note: "ssh target.example: exit=0 in 5ms :: echo REDTEAM-MARKER-abc123",
    });
    const report = await reverifyBundle(bundleWithSteps(), runner);
    assert.equal(report.verdict, "not-reproduced");
    assert.equal(report.steps.find((s) => s.seq === 10)!.validationObserved, false);
  });

  it("not-reproduced: a failed step does not validate even with marker-shaped output", async () => {
    const runner: StepRunner = async () => ({ ok: false, output: "REDTEAM-MARKER-abc123" });
    const report = await reverifyBundle(bundleWithSteps(), runner);
    assert.equal(report.verdict, "not-reproduced");
    assert.equal(report.steps.find((s) => s.seq === 10)!.validationObserved, false);
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
    stampBundleIntegrity(b);
    const runner: StepRunner = async () => ({ ok: true, output: "x" });
    const report = await reverifyBundle(b, runner);
    assert.equal(report.verdict, "not-reproduced");
    assert.match(report.summary, /manual retest required/);
  });
});


describe("stepValidation — output-only marker verification (audit H3)", () => {
  it("extractToolOutput strips the summary (and its embedded sent command)", () => {
    const composed = "ssh h: exit=0 in 5ms :: echo REDTEAM-MARKER-x && id. Output: REDTEAM-MARKER-x\nuid=0";
    assert.equal(extractToolOutput("ssh_exec", composed), "REDTEAM-MARKER-x\nuid=0");
    // Summary-only record: no output was ever captured — no evidence.
    assert.equal(extractToolOutput("ssh_exec", "ssh h: exit=0 in 5ms :: echo REDTEAM-MARKER-x"), "");
    assert.equal(extractToolOutput("msf_exec", "msf exploit/x vs h: MARKER ECHOED — validated"), "");
    // Prober-style results are output by construction.
    assert.equal(extractToolOutput("http_probe", "GET / ok 200"), "GET / ok 200");
  });

  it("marker in tool output validates; marker only in the sent command does not", () => {
    const echoed = stepValidation("ssh_exec", "ssh h: exit=0 in 5ms :: echo REDTEAM-MARKER-x. Output: REDTEAM-MARKER-x");
    assert.equal(echoed.validation, "marker-echo");
    assert.equal(echoed.marker, "x");
    const summaryOnly = stepValidation("ssh_exec", "ssh h: exit=0 in 5ms :: echo REDTEAM-MARKER-x. Output: uid=0(root)");
    assert.equal(summaryOnly.validation, "none", "the sent command in the summary must never satisfy the check");
    const noOutput = stepValidation("ssh_exec", "ssh h: exit=0 in 5ms :: echo REDTEAM-MARKER-x");
    assert.equal(noOutput.validation, "none", "no recorded output → honest downgrade, not a pass");
  });

  it("a failed command (exit != 0) never validates, even with the marker in its output", () => {
    const failed = stepValidation("ssh_exec", "ssh h: exit=1 in 5ms :: echo REDTEAM-MARKER-x. Output: REDTEAM-MARKER-x");
    assert.equal(failed.validation, "none");
    assert.equal(failed.marker, undefined);
    const failedWinrm = stepValidation("winrm_exec", "winrm h [tls]: exit=2 in 5ms :: echo REDTEAM-MARKER-y. Output: REDTEAM-MARKER-y");
    assert.equal(failedWinrm.validation, "none");
  });

  it("buildPocBundle refuses summary-echo and failed-command 'proof'", () => {
    const summaryOnly = buildPocBundle({
      finding: confirmedFinding({ attackIds: ["T1068"] }),
      events: [ev({ seq: 5, action: "ssh_exec", attackId: "T1068", result: "ssh target.example: exit=0 in 42ms :: echo REDTEAM-MARKER-zzz999 && id. Output: uid=0(root)" })],
      engagement: META, secrets: [],
    });
    assert.equal(summaryOnly.bundle, null, "marker only in the sent command (summary) is not proof");
    assert.match(summaryOnly.reason!, /no validation signal/);
    const failed = buildPocBundle({
      finding: confirmedFinding({ attackIds: ["T1068"] }),
      events: [ev({ seq: 6, action: "ssh_exec", attackId: "T1068", result: "ssh target.example: exit=1 in 42ms :: echo REDTEAM-MARKER-zzz999. Output: REDTEAM-MARKER-zzz999" })],
      engagement: META, secrets: [],
    });
    assert.equal(failed.bundle, null, "a failed command validates nothing, even if its text carries the marker");
  });
});

describe("reverifyBundle — verification material + timeout discipline", () => {
  function bundleWithSteps(): PocBundle {
    return stampBundleIntegrity({
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
      ],
      validationTier: "execution",
      proves: "marker echoed",
      doesNotProve: "no impact overclaim",
      reverifyCommand: "redteam-runner reverify --bundle poc/F-1.json",
    });
  }

  it("aborts WITHOUT firing when a marker-echo step records no marker", async () => {
    const b = bundleWithSteps();
    delete b.steps[0]!.marker;
    stampBundleIntegrity(b);
    let calls = 0;
    const runner: StepRunner = async () => {
      calls++;
      return { ok: true, output: "REDTEAM-MARKER-abc123" };
    };
    const report = await reverifyBundle(b, runner);
    assert.equal(calls, 0, "nothing may fire when verification material is missing");
    assert.equal(report.verdict, "not-reproduced");
    assert.match(report.summary, /aborted before firing/);
    assert.match(report.summary, /records no marker/);
    assert.ok(report.steps.every((s) => !s.replayed && !s.validationObserved));
    assert.match(report.registryNote, /do NOT close the finding/);
  });

  it("timeout enforced: a hung step is aborted via the signal, not left running", async () => {
    let seenSignal: AbortSignal | undefined;
    const runner: StepRunner = async (_step, _marker, signal) => {
      seenSignal = signal;
      await new Promise<void>(() => {}); // hangs forever; only the abort ends the wait
      return { ok: true, output: "" };
    };
    const started = Date.now();
    const report = await reverifyBundle(bundleWithSteps(), runner, { perStepTimeoutMs: 50 });
    assert.ok(Date.now() - started < 5_000, "reverify must not hang on a stuck step");
    assert.equal(seenSignal?.aborted, true, "the timeout must fire the abort signal");
    const step = report.steps.find((s) => s.seq === 10)!;
    assert.equal(step.ok, false);
    assert.equal(step.validationObserved, false);
    assert.match(step.note, /timed out/);
    assert.notEqual(report.verdict, "reproduced");
  });
});

describe("createReplayer — production replay is output-only, verbatim, timed", () => {
  const SSH_ENV: NodeJS.ProcessEnv = { REDTEAM_SSH_USER: "testuser", REDTEAM_SSH_PASSWORD: "testpass" };
  const WINRM_ENV: NodeJS.ProcessEnv = { REDTEAM_WINRM_USER: "testuser", REDTEAM_WINRM_PASSWORD: "testpass" };

  function sshBundle(): PocBundle {
    return stampBundleIntegrity({
      version: 1,
      bundleId: "POC-eng-1-F-9",
      engagementId: "eng-1",
      findingId: "F-9",
      attackIds: ["T1068"],
      severity: "high",
      title: "SSH command execution",
      target: "target.example",
      operator: "op",
      generatedAt: "2026-10-03T06:00:00.000Z",
      steps: [
        {
          seq: 3, ts: "2026-10-03T06:00:00.000Z", tool: "ssh_exec", target: "target.example",
          attackId: "T1068", command: "echo REDTEAM-MARKER-mk42 && id",
          result: "ssh target.example: exit=0 in 5ms :: echo REDTEAM-MARKER-mk42 && id. Output: REDTEAM-MARKER-mk42",
          validation: "marker-echo", marker: "mk42",
          replay: { tool: "ssh_exec", host: "target.example", args: { command: "echo REDTEAM-MARKER-mk42 && id" } },
        },
      ],
      validationTier: "execution",
      proves: "marker echoed",
      doesNotProve: "no impact overclaim",
      reverifyCommand: "redteam-runner reverify --bundle poc/F-9.json",
    });
  }

  function fakeSsh(behavior: { code?: number; stdout?: string }) {
    const seen: Array<{ command: string; timeoutMs?: number }> = [];
    const t: SshTransport = {
      async exec(args) {
        seen.push({ command: args.command, timeoutMs: args.timeoutMs });
        return { stdout: behavior.stdout ?? "", stderr: "", code: behavior.code ?? 0, ms: 3 };
      },
      async close() {},
    };
    return { t, seen };
  }

  it("does NOT validate when only the summary echoes the marker (silent target)", async () => {
    // Transport succeeds but the target never echoes: the executor summary
    // still contains the sent command (marker included). The old replayer
    // returned summary+output as "output" and this validated — regression.
    const { t, seen } = fakeSsh({ code: 0, stdout: "uid=0(root)" });
    const replayer = createReplayer({
      scope: ["target.example"],
      executors: { hostExec: new HostExecutor({ ssh: () => t, env: SSH_ENV }) },
    });
    const report = await reverifyBundle(sshBundle(), replayer);
    assert.equal(report.verdict, "not-reproduced");
    assert.equal(report.steps[0]!.validationObserved, false);
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.command, "echo REDTEAM-MARKER-mk42 && id", "recorded command replayed verbatim — no marker substitution");
    assert.equal(seen[0]!.timeoutMs, 60_000, "an explicit per-step timeout reaches the transport");
  });

  it("validates when the fresh raw output carries the recorded marker", async () => {
    const { t } = fakeSsh({ code: 0, stdout: "REDTEAM-MARKER-mk42\nuid=0(root)" });
    const replayer = createReplayer({
      scope: ["target.example"],
      executors: { hostExec: new HostExecutor({ ssh: () => t, env: SSH_ENV }) },
    });
    const report = await reverifyBundle(sshBundle(), replayer);
    assert.equal(report.verdict, "reproduced");
    assert.equal(report.steps[0]!.validationObserved, true);
  });

  it("does NOT validate a failed command even when its output carries the marker", async () => {
    const { t } = fakeSsh({ code: 1, stdout: "REDTEAM-MARKER-mk42" });
    const replayer = createReplayer({
      scope: ["target.example"],
      executors: { hostExec: new HostExecutor({ ssh: () => t, env: SSH_ENV }) },
    });
    const report = await reverifyBundle(sshBundle(), replayer);
    assert.equal(report.verdict, "not-reproduced");
    assert.equal(report.steps[0]!.ok, false);
    assert.equal(report.steps[0]!.validationObserved, false);
  });

  it("winrm replay: verbatim command, explicit timeout, marker from raw output", async () => {
    const seen: Array<{ command: string; timeoutMs?: number }> = [];
    const t: WinrmTransport = {
      async exec(args) {
        seen.push({ command: args.command, timeoutMs: args.timeoutMs });
        return { stdout: "REDTEAM-MARKER-w7\r\nNT AUTHORITY\\SYSTEM", stderr: "", code: 0, ms: 3 };
      },
      async close() {},
    };
    const b = sshBundle();
    b.findingId = "F-10";
    b.bundleId = "POC-eng-1-F-10";
    b.steps = [
      {
        seq: 4, ts: "2026-10-03T06:00:00.000Z", tool: "winrm_exec", target: "target.example",
        attackId: "T1021", command: "echo REDTEAM-MARKER-w7",
        result: "winrm target.example [tls]: exit=0 in 5ms :: echo REDTEAM-MARKER-w7. Output: REDTEAM-MARKER-w7",
        validation: "marker-echo", marker: "w7",
        replay: { tool: "winrm_exec", host: "target.example", args: { command: "echo REDTEAM-MARKER-w7" } },
      },
    ];
    stampBundleIntegrity(b);
    const replayer = createReplayer({
      scope: ["target.example"],
      perStepTimeoutMs: 5_000,
      executors: { hostExec: new HostExecutor({ winrm: () => t, env: WINRM_ENV }) },
    });
    const report = await reverifyBundle(b, replayer, { perStepTimeoutMs: 5_000 });
    assert.equal(report.verdict, "reproduced");
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.command, "echo REDTEAM-MARKER-w7");
    assert.equal(seen[0]!.timeoutMs, 5_000, "the configured per-step timeout reaches winrm, never undefined");
  });
});
