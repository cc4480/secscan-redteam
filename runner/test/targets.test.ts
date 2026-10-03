/**
 * Full-battery tests (v0.7.0) — EXHAUSTIVE target-specific SecScan (120+) +
 * SecLayer (80+) batteries run as ONE unified engagement. No network, no API
 * keys: fake LLM, fake prober, injected server gate.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AgentRole, ChatMessage, ChatResult, ToolCallRequest } from "@secscan/redteam-llm-router";
import {
  TARGET_PROFILES,
  FULL_BATTERY_TARGETS,
  fullBatteryPlanSkeleton,
  fullBatteryChecklistText,
  targetBatteryChecklistText,
  inferTargetProfile,
  lookupTargetProfile,
  targetItemsFor,
} from "../src/targets.js";
import { BATTERY_CATEGORIES } from "../src/battery.js";
import { lookupTechnique } from "../src/attack.js";
import { coordinatorPrompt, exploiterPrompt } from "../src/prompts.js";
import { runEngagement } from "../src/phases.js";
import type { EngagementInput } from "../src/types.js";

function promptCtx(fullBattery?: boolean) {
  return {
    mode: "red" as const,
    objective: "full battery test",
    target: "secscan+seclayer",
    scopeHosts: ["secscan.us"],
    roe: { scope: ["secscan.us"] },
    fullBattery,
  };
}

describe("target profile integrity", () => {
  it("both profiles present; battery floors met (secscan ≥120, seclayer ≥80)", () => {
    assert.deepEqual(FULL_BATTERY_TARGETS, ["secscan", "seclayer"]);
    assert.ok(TARGET_PROFILES.secscan.battery.length >= 120, `secscan has ${TARGET_PROFILES.secscan.battery.length}`);
    assert.ok(TARGET_PROFILES.seclayer.battery.length >= 80, `seclayer has ${TARGET_PROFILES.seclayer.battery.length}`);
    // Every category represented on both targets (the 6-cell coverage contract).
    for (const profile of Object.values(TARGET_PROFILES)) {
      for (const cat of BATTERY_CATEGORIES) {
        assert.ok(targetItemsFor(profile, cat).length > 0, `${profile.id}:${cat} non-empty`);
      }
    }
  });
  it("ids unique per target, SS-001/SL-001 shape, every item has category/name/brief/what/owasp", () => {
    for (const [id, profile] of Object.entries(TARGET_PROFILES)) {
      const prefix = id === "secscan" ? "SS" : "SL";
      const ids = profile.battery.map((b) => b.id);
      assert.equal(new Set(ids).size, ids.length, `${id} ids unique`);
      for (const b of profile.battery) {
        assert.match(b.id, new RegExp(`^${prefix}-\\d{3}$`), b.id);
        assert.ok(BATTERY_CATEGORIES.includes(b.category), `${b.id} category`);
        assert.ok(b.name.length > 0, `${b.id} name`);
        assert.ok(b.brief.length > 10, `${b.id} brief is a real one-liner`);
        assert.ok(b.what.length > 20, `${b.id} what is concrete`);
        assert.ok(b.owasp.length > 0, `${b.id} owasp`);
        if (b.attackId) assert.ok(lookupTechnique(b.attackId), `${b.id} → ${b.attackId}`);
      }
    }
  });
  it("lookupTargetProfile resolves both, rejects unknown", () => {
    assert.equal(lookupTargetProfile("secscan")?.name.includes("SecScan"), true);
    assert.equal(lookupTargetProfile("SECLAYER")?.name.includes("SecLayer"), true);
    assert.equal(lookupTargetProfile("nope"), undefined);
  });
  it("checklist text carries needs/deferred markers honestly", () => {
    const text = targetBatteryChecklistText(TARGET_PROFILES.secscan, "red");
    assert.ok(text.includes("[needs: Second test account"), "cross-account IDOR marked");
    assert.ok(text.includes("[needs: Canary"), "canary infra marked");
    const black = targetBatteryChecklistText(TARGET_PROFILES.seclayer, "black");
    assert.ok(black.includes("[black:"), "stealth variants rendered");
    assert.ok(!targetBatteryChecklistText(TARGET_PROFILES.seclayer, "red").includes("[black:"));
  });
  it("compact checklist contains EVERY item id (full spectrum visible to the coordinator)", () => {
    for (const profile of Object.values(TARGET_PROFILES)) {
      const text = targetBatteryChecklistText(profile, "red");
      for (const item of profile.battery) {
        assert.ok(text.includes(item.id), `${item.id} present in compact checklist`);
      }
    }
  });
});

describe("unified plan", () => {
  it("covers both targets in order: recon both → secscan → seclayer → chains → report", () => {
    const s = fullBatteryPlanSkeleton();
    const order = ["RECON both surfaces", "EXPLOIT SecScan battery", "EXPLOIT SecLayer battery", "CROSS-CUTTING CHAINS", "UNIFIED REPORT"];
    let prev = -1;
    for (const step of order) {
      const i = s.indexOf(step);
      assert.ok(i > prev, `${step} in order`);
      prev = i;
    }
    assert.ok(s.includes("3 × 2 = 6 cells"), "coverage rule stated");
  });
  it("inferTargetProfile routes /api/mcp to seclayer", () => {
    assert.equal(inferTargetProfile("https://secscan.us/api/mcp"), "seclayer");
    assert.equal(inferTargetProfile("https://secscan.us/api/mcp?x=1"), "seclayer");
    assert.equal(inferTargetProfile("https://secscan.us/scan"), "secscan");
    assert.equal(inferTargetProfile("not a url"), "secscan");
  });
});

describe("prompt wiring", () => {
  it("coordinator prompt includes BOTH batteries when fullBattery is set, generic otherwise", () => {
    const fb = coordinatorPrompt(promptCtx(true));
    assert.ok(fb.includes("FULL-BATTERY unified engagement"), "plan skeleton present");
    assert.ok(fb.includes("SS-001"), "SecScan battery present");
    assert.ok(fb.includes("SL-001"), "SecLayer battery present");
    assert.ok(fb.includes("120 items"), "secscan count shown");
    assert.ok(fb.includes("80 items"), "seclayer count shown");
    const generic = coordinatorPrompt(promptCtx(false));
    assert.ok(!generic.includes("SS-001"), "no target battery without the flag");
    assert.ok(!generic.includes("FULL-BATTERY unified engagement"));
  });
  it("exploiter prompt swaps in target batteries + targetProfile tagging when fullBattery", () => {
    const fb = exploiterPrompt(promptCtx(true));
    assert.ok(fb.includes("SS-060") && fb.includes("SL-040"), "both target checklists");
    assert.ok(fb.includes("targetProfile"), "tagging instruction");
    assert.ok(fb.includes("3 × 2 = 6 cells"), "coverage rule");
    const generic = exploiterPrompt(promptCtx(undefined));
    assert.ok(!generic.includes("SL-001"), "generic battery otherwise");
    assert.ok(generic.includes("L-1"), "generic checklist intact");
  });
});

describe("full-battery coverage mechanics", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rt-fb-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const textOnly = (text: string): ChatResult => ({ text, toolCalls: [], provider: "fake", model: "fake" });
  const taskJson = (tasks: object[], finish: boolean, note: string): ChatResult =>
    textOnly("```json " + JSON.stringify({ tasks, finish, note }) + " ```");
  const fakeProber = {
    probe: async () => ({ status: 200, headers: {}, bodySnippet: "ok", ms: 5 }),
  };
  const baseInput: EngagementInput = {
    target: "secscan+seclayer",
    mode: "red",
    objective: "full battery test",
    roe: { scope: ["secscan.us"] },
    fullBattery: true,
  };

  /** Scripted LLM: coordinator tasks per-target cells; exploiter probes with targetProfile (explicit for secscan, URL-inferred for seclayer). */
  function scriptedLlm(seclayerCells: boolean) {
    let n = 0;
    const probe = (target: string, category: string): ToolCallRequest => ({
      id: `call-${++n}`,
      name: "http_probe",
      arguments: {
        method: "POST",
        url: target === "seclayer" ? "https://secscan.us/api/mcp" : "https://secscan.us/scan",
        category,
        attackId: "T1190",
        // Explicit tag for secscan cells; seclayer cells rely on /api/mcp URL inference.
        ...(target === "secscan" ? { targetProfile: "secscan" } : {}),
        hypothesis: `full battery ${target} ${category}`,
      },
    });
    return async (role: AgentRole, messages: ChatMessage[], _opts: object): Promise<ChatResult> => {
      const has = (s: string) => messages.some((m) => m.content.includes(s));
      if (role === "coordinator") {
        if (has("Transition awaiting sign-off")) return textOnly("SIGN-OFF: test approval.");
        if (has("DECOMPOSE")) {
          const tasks = ["logic", "functionality", "validation"].map((category) => ({
            kind: "probe", brief: `test secscan ${category}`, attackId: "T1190", category, maxTurns: 3,
          }));
          return taskJson(tasks, false, "secscan cells");
        }
        if (has("RE-PLAN") && seclayerCells && !has("OVERRIDE")) {
          const tasks = ["logic", "functionality", "validation"].map((category) => ({
            kind: "probe", brief: `test seclayer ${category}`, attackId: "T1190", category, maxTurns: 3,
          }));
          return taskJson(tasks, false, "seclayer cells");
        }
        return taskJson([], true, "done");
      }
      if (role === "recon") return textOnly("recon brief: both surfaces mapped");
      if (role === "reporter") return textOnly("# Report\n\n```json " + '{"findings":[]}' + " ```");
      // exploiter task subagent: parse target + category from the task brief.
      const sys = messages.find((m) => m.role === "system")?.content ?? "";
      const brief = sys.match(/- Task: ([^\n]+)/)?.[1] ?? "";
      const category = sys.match(/Battery category: (\w+)/)?.[1] ?? "logic";
      const target = brief.includes("seclayer") ? "seclayer" : "secscan";
      const calls = messages.filter((m) => m.role === "assistant" && (m as { toolCalls?: unknown }).toolCalls);
      if (calls.length === 0) {
        return { text: `${target} ${category} hypothesis`, toolCalls: [probe(target, category)], provider: "fake", model: "fake" };
      }
      return textOnly("TRIED: probe / OBSERVED: 200 ok / VERDICT: killed - no flaw");
    };
  }

  async function run(input: EngagementInput, llm: (role: AgentRole, messages: ChatMessage[], opts: object) => Promise<ChatResult>) {
    return runEngagement(input, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: { verify: async () => true, completeForRole: llm as never, prober: fakeProber },
    });
  }

  it("6/6 cells → report says full battery complete on both targets", async () => {
    const res = await run(baseInput, scriptedLlm(true));
    assert.equal(res.status, "complete");
    const report = readFileSync(join(dir, res.engagementId, "report.md"), "utf8");
    assert.ok(report.includes("Full battery complete on both targets."), "6-cell completion line");
    assert.ok(report.includes("3 categories × 2 targets"), "per-target coverage header");
  });

  it("missing seclayer cells → report names them under Honest limits", async () => {
    const res = await run(baseInput, scriptedLlm(false));
    assert.equal(res.status, "complete");
    const report = readFileSync(join(dir, res.engagementId, "report.md"), "utf8");
    assert.ok(report.includes("NOT COVERED: seclayer:logic, seclayer:functionality, seclayer:validation"), "missing cells named");
    assert.ok(report.includes("list these under Honest limits"), "honest-limits directive");
  });
});
