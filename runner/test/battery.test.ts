/**
 * Battery + coverage-enforcement tests.
 *
 * The coverage test scripts a fake LLM: it probes "logic" twice, then tries
 * to stop — the runner must nudge it back for "functionality" and
 * "validation" before the exploit phase may end. Fake prober = no network.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AgentRole, ChatMessage, ChatResult, ToolCallRequest } from "@secscan/redteam-llm-router";
import {
  BATTERY,
  BATTERY_CATEGORIES,
  batteryChecklistText,
  batteryItemsFor,
  lookupBatteryItem,
} from "../src/battery.js";
import { lookupTechnique } from "../src/attack.js";
import { readEvents, readState } from "../src/events.js";
import { runEngagement } from "../src/phases.js";
import type { EngagementInput } from "../src/types.js";

describe("battery checklist integrity", () => {
  it("has 28 items (8 logic, 12 functionality, 8 validation), unique IDs", () => {
    assert.equal(BATTERY.length, 28);
    const expected: Record<string, number> = { logic: 8, functionality: 12, validation: 8 };
    for (const cat of BATTERY_CATEGORIES) {
      assert.equal(batteryItemsFor(cat).length, expected[cat], cat);
    }
    const ids = BATTERY.map((b) => b.id);
    assert.equal(new Set(ids).size, 28);
    for (const b of BATTERY) {
      assert.match(b.id, /^[LFV]-\d+$/);
      assert.ok(b.owasp.length > 0, `${b.id} needs an OWASP reference`);
    }
  });
  it("every ATT&CK ID on a battery item resolves in the catalog", () => {
    for (const b of BATTERY) {
      if (b.attackId) assert.ok(lookupTechnique(b.attackId), `${b.id} → ${b.attackId}`);
    }
  });
  it("lookup is case-insensitive", () => {
    assert.equal(lookupBatteryItem("l-1")?.name, "Workflow / step-skipping");
    assert.equal(lookupBatteryItem("V-8")?.category, "validation");
  });
  it("black mode renders stealth variants in the checklist", () => {
    const text = batteryChecklistText("black");
    assert.ok(text.includes("[black:"));
    assert.ok(!batteryChecklistText("red").includes("[black:"));
    for (const cat of BATTERY_CATEGORIES) {
      assert.ok(text.includes(cat === "logic" ? "Logic flaws" : cat === "functionality" ? "Functionality abuse" : "Accuracy"));
    }
  });
});

describe("battery coverage enforcement", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rt-batt-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function scriptedLlm() {
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
        hypothesis: `battery test ${category}`,
      },
    });
    const textOnly = (text: string): ChatResult => ({ text, toolCalls: [], provider: "fake", model: "fake" });
    const taskJson = (tasks: object[], finish: boolean, note: string): ChatResult =>
      textOnly("```json " + JSON.stringify({ tasks, finish, note }) + " ```");
    return async (role: AgentRole, _messages: ChatMessage[], _opts: object): Promise<ChatResult> => {
      counts[role] = (counts[role] ?? 0) + 1;
      const has = (s: string) => _messages.some((m) => m.content.includes(s));
      if (role === "coordinator") {
        // Sign-off turns: play the handoff protocol.
        if (has("Transition awaiting sign-off")) {
          return textOnly("SIGN-OFF: test approval — brief is sufficient.");
        }
        // Dynamic orchestration: decompose, then try to finish early (the
        // runner must force another round), then cover the missing categories.
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
          // Black mode caps at 1 task/round: the runner rejects over-cap tasks
          // with an event — re-task validation when it's still missing.
          if (replans === 1) return taskJson([], true, "wrapping up early");
          if (_messages.some((m) => m.content.includes("validation:MISSING"))) {
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
      if (role === "reporter") return textOnly("# Report\n\n```json " + '{"findings":[]}' + " ```");
      // exploiter (task subagent): one probe per task, then the task report.
      // Keyed by task brief so parallel tasks don't confuse the script.
      const n = counts[role]!;
      const sys = _messages.find((m) => m.role === "system")?.content ?? "";
      const brief = sys.match(/- Task: ([^\n]+)/)?.[1] ?? `task-${n}`;
      taskCalls[brief] = (taskCalls[brief] ?? 0) + 1;
      if (taskCalls[brief] === 1) {
        const cat = sys.match(/Battery category: (\w+)/)?.[1] ?? "logic";
        return { text: `${cat} hypothesis`, toolCalls: [probe(cat, n)], provider: "fake", model: "fake" };
      }
      return textOnly("TRIED: probe / OBSERVED: 200 ok / VERDICT: killed - no flaw");
    };
  }

  const fakeProber = {
    probe: async () => ({ status: 200, headers: {}, bodySnippet: "ok", ms: 5 }),
  };

  it("nudges the exploiter until all three categories are probed", async () => {
    const input: EngagementInput = {
      target: "secscan.us",
      mode: "red",
      objective: "battery test",
      roe: { scope: ["secscan.us"] },
    };
    const res = await runEngagement(input, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: {
        verify: async () => true,
        completeForRole: scriptedLlm() as never,
        prober: fakeProber,
      },
    });
    assert.equal(res.status, "complete");
    const engDir = join(dir, res.engagementId);
    const state = readState(engDir);
    assert.deepEqual(state?.batteryCoverage, { logic: 1, functionality: 1, validation: 1 });
    const events = readEvents(engDir);
    const probes = events.filter((e) => e.action === "http_probe");
    assert.equal(probes.length, 3);
    // Dynamic orchestration: the coordinator decomposed into tasks, tried to
    // finish early, was forced back for the missing categories, then finished.
    const spawns = events.filter((e) => e.action === "task_spawn");
    assert.equal(spawns.length, 3);
    assert.ok(spawns.some((e) => e.result.includes("(logic)")));
    assert.ok(spawns.some((e) => e.result.includes("(functionality)")));
    assert.ok(spawns.some((e) => e.result.includes("(validation)")));
    const replans = events.filter((e) => e.action === "replan");
    assert.ok(replans.some((e) => e.result.includes("covering missing categories")), "forced battery round must happen");
    assert.ok(events.some((e) => e.action === "task_complete"));
    // Report carries the coverage line.
    const report = readFileSync(join(engDir, "report.md"), "utf8");
    assert.ok(report.includes("Battery coverage"));
  });

  it("black mode runs the same battery (stealth-weighted prompt, same coverage rule)", async () => {
    const input: EngagementInput = {
      target: "secscan.us",
      mode: "black",
      objective: "battery test",
      roe: { scope: ["secscan.us"] },
    };
    const seen: string[] = [];
    const llm = scriptedLlm();
    const res = await runEngagement(input, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: {
        verify: async () => true,
        completeForRole: (async (role: AgentRole, messages: ChatMessage[], opts: object) => {
          if (role === "exploiter" && messages[0]?.role === "system") {
            seen.push(messages[0].content);
          }
          return llm(role, messages, opts);
        }) as never,
        prober: fakeProber,
      },
    });
    assert.equal(res.status, "complete");
    const prompt = seen[0] ?? "";
    assert.ok(prompt.includes("BLACK mode"), "exploiter prompt must carry the black-mode brief");
    assert.ok(prompt.includes("Logic flaws (business-logic abuse)"), "battery checklist must be in the prompt");
    const state = readState(join(dir, res.engagementId));
    assert.deepEqual(state?.batteryCoverage, { logic: 1, functionality: 1, validation: 1 });
  });
});
