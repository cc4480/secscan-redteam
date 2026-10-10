/**
 * Report-phase verdict integrity (audit correctness H1).
 *
 * The engagement's findings must be derived from the verdicts recorded
 * mechanically during the run (record_finding → ctx.liveFindings), never
 * from the reporter LLM's closing JSON. That JSON may only lend fix/retest
 * text to a recorded verdict. These tests run full engagements against a
 * scripted fake LLM whose exploiter records two findings live, while the
 * reporter is scripted to (a) omit/mangle its JSON block, (b) invent and
 * rewrite findings, and (c) behave — proving the record stands in the
 * first two cases and the cooperative path is unchanged in the third.
 *
 * Fakes only: fake prober, fake gate, scripted LLM. No network.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AgentRole, ChatMessage, ChatResult, ToolCallRequest } from "@secscan/redteam-llm-router";
import { readEvents, readState } from "../src/events.js";
import { runEngagement } from "../src/phases.js";
import type { EngagementInput, Finding } from "../src/types.js";

const RECORDED = [
  {
    severity: "high",
    title: "SQL injection in login form",
    vulnClass: "sqli",
    attackId: "T1190",
    evidence: "boolean-based blind confirmed: conditional payload altered the returned row set",
  },
  {
    severity: "critical",
    title: "Auth token reusable after logout",
    vulnClass: "auth",
    attackId: "T1078",
    evidence: "session token replayed after logout returned 200 with account data",
  },
] as const;

const textOnly = (text: string): ChatResult => ({ text, toolCalls: [], provider: "fake", model: "fake" });

/**
 * Scripted engagement: coordinator decomposes logic → functionality →
 * validation (mirrors battery.test.ts), the logic-task exploiter fires one
 * probe and records BOTH findings live via record_finding, other tasks
 * just probe. The reporter returns the supplied text verbatim.
 */
function scriptedLlm(reporterText: string) {
  const counts: Record<string, number> = {};
  const taskCalls: Record<string, number> = {};
  let replans = 0;
  const probe = (category: string, id: number): ToolCallRequest => ({
    id: `call-${id}`,
    name: "http_probe",
    arguments: {
      method: "GET",
      url: "https://secscan.us/probe",
      category,
      attackId: "T1190",
      hypothesis: `report-phase test ${category}`,
    },
  });
  const recordFinding = (f: (typeof RECORDED)[number], id: number): ToolCallRequest => ({
    id: `call-${id}`,
    name: "record_finding",
    arguments: {
      severity: f.severity,
      title: f.title,
      vulnClass: f.vulnClass,
      attackId: f.attackId,
      evidence: f.evidence,
    },
  });
  const taskJson = (tasks: object[], finish: boolean, note: string): ChatResult =>
    textOnly("```json " + JSON.stringify({ tasks, finish, note }) + " ```");
  return async (role: AgentRole, messages: ChatMessage[], _opts: object): Promise<ChatResult> => {
    counts[role] = (counts[role] ?? 0) + 1;
    const has = (s: string) => messages.some((m) => m.content.includes(s));
    if (role === "coordinator") {
      if (has("Transition awaiting sign-off")) {
        return textOnly("SIGN-OFF: test approval — brief is sufficient.");
      }
      if (has("DECOMPOSE")) {
        return taskJson(
          [{ kind: "probe", brief: "test logic flaws", attackId: "T1190", category: "logic", maxTurns: 4 }],
          false,
          "opening with logic",
        );
      }
      if (has("RE-PLAN")) {
        replans++;
        if (has("OVERRIDE")) {
          return taskJson(
            [
              { kind: "probe", brief: "test functionality abuse", attackId: "T1190", category: "functionality", maxTurns: 4 },
              { kind: "probe", brief: "test validation rigor", attackId: "T1190", category: "validation", maxTurns: 4 },
            ],
            false,
            "covering missing categories",
          );
        }
        if (replans === 1) return taskJson([], true, "wrapping up early");
        if (messages.some((m) => m.content.includes("validation:MISSING"))) {
          return taskJson(
            [{ kind: "probe", brief: "test validation rigor", attackId: "T1190", category: "validation", maxTurns: 4 }],
            false,
            "retrying validation task dropped over cap",
          );
        }
        return taskJson([], true, "battery complete");
      }
      return textOnly('```json {"adversaryProfile":"test","steps":[]} ```');
    }
    if (role === "recon") return textOnly("recon brief: surface mapped");
    if (role === "reporter") return textOnly(reporterText);
    // exploiter (task subagent): keyed by task brief so parallel tasks
    // don't confuse the script. The logic task records the findings live.
    const n = counts[role]!;
    const sys = messages.find((m) => m.role === "system")?.content ?? "";
    const brief = sys.match(/- Task: ([^\n]+)/)?.[1] ?? `task-${n}`;
    taskCalls[brief] = (taskCalls[brief] ?? 0) + 1;
    if (taskCalls[brief] === 1) {
      const cat = sys.match(/Battery category: (\w+)/)?.[1] ?? "logic";
      if (brief.includes("logic")) {
        return {
          text: "logic hypothesis confirmed twice",
          toolCalls: [probe(cat, n), recordFinding(RECORDED[0], n + 100), recordFinding(RECORDED[1], n + 200)],
          provider: "fake",
          model: "fake",
        };
      }
      return { text: `${cat} hypothesis`, toolCalls: [probe(cat, n)], provider: "fake", model: "fake" };
    }
    return textOnly("TRIED: probe / OBSERVED: 200 ok / VERDICT: killed - no flaw");
  };
}

const fakeProber = {
  probe: async () => ({ status: 200, headers: {}, bodySnippet: "ok", ms: 5 }),
};

describe("report phase: findings come from recorded verdicts (H1)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rt-report-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function run(reporterText: string) {
    const input: EngagementInput = {
      target: "secscan.us",
      mode: "red",
      objective: "report verdict integrity test",
      roe: { scope: ["secscan.us"] },
      operatorName: "Casey Operator",
    };
    const res = await runEngagement(input, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: {
        verify: async () => true,
        completeForRole: scriptedLlm(reporterText) as never,
        prober: fakeProber,
      },
    });
    assert.equal(res.status, "complete");
    return res;
  }

  function assertRecordedStand(findings: Finding[]) {
    assert.equal(findings.length, 2, "both recorded findings must stand");
    const [a, b] = findings as [Finding, Finding];
    assert.equal(a!.id, "F-1");
    assert.equal(a!.severity, "high");
    assert.equal(a!.title, RECORDED[0].title);
    assert.deepEqual(a!.attackIds, ["T1190"]);
    assert.equal(a!.evidence, RECORDED[0].evidence);
    assert.equal(a!.status, "confirmed");
    assert.equal(b!.id, "F-2");
    assert.equal(b!.severity, "critical");
    assert.equal(b!.title, RECORDED[1].title);
    assert.deepEqual(b!.attackIds, ["T1078"]);
    assert.equal(b!.evidence, RECORDED[1].evidence);
    assert.equal(b!.status, "confirmed");
  }

  it("reporter omits the JSON block entirely — recorded findings still stand", async () => {
    const res = await run("# Engagement report\n\nEverything checked out. (The model never emitted its JSON block.)");
    assertRecordedStand(res.findings);
    // No remediation text was supplied, so the pending placeholders stand.
    assert.equal(res.findings[0]!.fix, "(pending — the reporter writes the fix)");
    assert.equal(res.findings[0]!.retest, "(pending)");
    assert.equal(res.findings[0]!.accountableOperator, "Casey Operator");
    // state.json (the drift watcher's input) carries the recorded findings,
    // not the empty set a missing JSON block used to produce.
    const engDir = join(dir, res.engagementId);
    const state = readState(engDir);
    assert.deepEqual(
      (state?.findings ?? []).map((f) => f.title),
      [RECORDED[0].title, RECORDED[1].title],
    );
    // The override is on the audit record.
    const events = readEvents(engDir);
    assert.ok(events.some((e) => e.action === "findings_reconciled"), "reconciliation must be logged");
    assert.ok(existsSync(join(engDir, "report.md")));
  });

  it("reporter returns an empty findings array — recorded findings still stand", async () => {
    const res = await run('# Report\n\n```json {"findings": []} ```');
    assertRecordedStand(res.findings);
  });

  it("reporter truncates/mangles its JSON block — recorded findings still stand", async () => {
    const res = await run('# Report\n\n```json {"findings": [{"id": "F-1", "severity": "high", "tit');
    assertRecordedStand(res.findings);
  });

  it("reporter invents a finding and rewrites a recorded one — recorded verdicts win", async () => {
    const reporterJson = JSON.stringify({
      findings: [
        {
          id: "F-1",
          severity: "info", // downgrade attempt — recorded "high" must win
          title: RECORDED[0].title,
          attackIds: ["T1190"],
          evidence: "trust me, it is basically fine", // rewrite attempt — recorded evidence must win
          fix: "parameterize all queries",
          retest: "replay the login probe",
          status: "confirmed",
        },
        {
          id: "F-9",
          severity: "critical",
          title: "Invented unauthenticated RCE",
          attackIds: ["T1190"],
          evidence: "no tool ever observed this",
          fix: "n/a",
          retest: "n/a",
          status: "confirmed",
        },
      ],
    });
    const res = await run(`# Report\n\n\`\`\`json ${reporterJson} \`\`\``);
    assertRecordedStand(res.findings);
    assert.ok(
      !res.findings.some((f) => f.title.includes("Invented")),
      "a finding no verdict recorded must never reach the results",
    );
    // Remediation text is the reporter's legitimate contribution and is kept.
    assert.equal(res.findings[0]!.fix, "parameterize all queries");
    assert.equal(res.findings[0]!.retest, "replay the login probe");
    // The second recorded verdict, omitted from the reporter JSON, stands too.
    assert.equal(res.findings[1]!.fix, "(pending — the reporter writes the fix)");
    const events = readEvents(join(dir, res.engagementId));
    const rec = events.find((e) => e.action === "findings_reconciled");
    assert.ok(rec, "dropping the invented finding must be on the audit record");
    assert.match(rec!.result, /reporter-only/);
  });

  it("cooperative reporter (normal path) — findings unchanged, fix/retest borrowed", async () => {
    const reporterJson = JSON.stringify({
      findings: [
        {
          id: "F-1",
          severity: "high",
          title: RECORDED[0].title,
          attackIds: ["T1190"],
          evidence: RECORDED[0].evidence,
          fix: "parameterize all queries",
          retest: "replay the login probe",
          status: "confirmed",
        },
        {
          id: "F-2",
          severity: "critical",
          title: RECORDED[1].title,
          attackIds: ["T1078"],
          evidence: RECORDED[1].evidence,
          fix: "invalidate session tokens at logout",
          retest: "replay the token after logout",
          status: "confirmed",
        },
      ],
    });
    const res = await run(`# Report\n\nFindings below.\n\n\`\`\`json ${reporterJson} \`\`\``);
    assert.deepEqual(res.findings, [
      {
        id: "F-1",
        severity: "high",
        title: RECORDED[0].title,
        attackIds: ["T1190"],
        evidence: RECORDED[0].evidence,
        fix: "parameterize all queries",
        retest: "replay the login probe",
        status: "confirmed",
        accountableOperator: "Casey Operator",
      },
      {
        id: "F-2",
        severity: "critical",
        title: RECORDED[1].title,
        attackIds: ["T1078"],
        evidence: RECORDED[1].evidence,
        fix: "invalidate session tokens at logout",
        retest: "replay the token after logout",
        status: "confirmed",
        accountableOperator: "Casey Operator",
      },
    ]);
    // No disagreement → nothing to reconcile.
    const events = readEvents(join(dir, res.engagementId));
    assert.ok(!events.some((e) => e.action === "findings_reconciled"));
    const report = readFileSync(join(dir, res.engagementId, "report.md"), "utf8");
    assert.ok(report.includes("Battery coverage (runner-computed)"));
  });
});
