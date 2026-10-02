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
  it("has 24 items, 8 per category, unique IDs", () => {
    assert.equal(BATTERY.length, 24);
    for (const cat of BATTERY_CATEGORIES) {
      assert.equal(batteryItemsFor(cat).length, 8, cat);
    }
    const ids = BATTERY.map((b) => b.id);
    assert.equal(new Set(ids).size, 24);
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
    return async (role: AgentRole, _messages: ChatMessage[], _opts: object): Promise<ChatResult> => {
      counts[role] = (counts[role] ?? 0) + 1;
      const n = counts[role]!;
      if (role === "coordinator") {
        return textOnly('```json {"adversaryProfile":"test","steps":[]} ```');
      }
      if (role === "recon") return textOnly("recon brief: surface mapped");
      if (role === "reporter") return textOnly("# Report\n\n```json " + '{"findings":[]}' + " ```");
      // exploiter: probes logic twice, then keeps trying to stop early
      if (n === 1) return { text: "logic hypotheses", toolCalls: [probe("logic", 1), probe("logic", 2)], provider: "fake", model: "fake" };
      if (n === 2) return textOnly("logic done, stopping early");
      if (n === 3) return { text: "functionality hypothesis", toolCalls: [probe("functionality", 3)], provider: "fake", model: "fake" };
      if (n === 4) return textOnly("functionality done, stopping");
      if (n === 5) return { text: "validation hypothesis", toolCalls: [probe("validation", 4)], provider: "fake", model: "fake" };
      return textOnly("battery complete");
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
    assert.equal(probes.length, 4);
    // The runner refused to let the phase end thin: two nudges fired.
    const nudges = events.filter((e) => e.action === "phase_nudge");
    assert.ok(nudges.length >= 2, `expected ≥2 nudges, got ${nudges.length}`);
    assert.ok(nudges.some((e) => e.result.includes("functionality")));
    assert.ok(nudges.some((e) => e.result.includes("validation")));
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
