/**
 * Full-battery tests (v0.8.0) — EXHAUSTIVE target-specific SecScan (120+) +
 * SecLayer (80+) + Windows (100+) + Linux (100+) batteries run as ONE unified
 * engagement, with honest host-exec tooling scoping. No network, no API
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
  HOST_EXEC_TOOLING,
  NEEDS_HUMAN_OPERATOR,
  NEEDS_KERBEROS_TICKET,
  NEEDS_PRIVILEGED_CLIENT,
  TARGET_PREFIXES,
  activeTargets,
  fullBatteryPlanSkeleton,
  fullBatteryChecklistText,
  inferTargetProfile,
  isTargetId,
  lookupTargetProfile,
  targetBatteryChecklistText,
  targetCellBlocked,
  targetCellStatus,
  targetItemsFor,
} from "../src/targets.js";
import type { TargetId, TargetProfile } from "../src/targets.js";
import { BATTERY_CATEGORIES } from "../src/battery.js";
import { lookupTechnique } from "../src/attack.js";
import { coordinatorPrompt, exploiterPrompt } from "../src/prompts.js";
import { runEngagement } from "../src/phases.js";
import type { EngagementInput } from "../src/types.js";

function promptCtx(fullBattery?: boolean, targets?: TargetId[]) {
  return {
    mode: "red" as const,
    objective: "full battery test",
    target: "secscan+seclayer",
    scopeHosts: ["secscan.us"],
    roe: { scope: ["secscan.us"] },
    fullBattery,
    targets,
  };
}

describe("target registry", () => {
  it("isTargetId accepts the four targets, rejects unknown", () => {
    for (const t of ["secscan", "seclayer", "windows", "linux", "SecScan", "WINDOWS"]) assert.ok(isTargetId(t), t);
    assert.ok(!isTargetId("nope") && !isTargetId(""), "rejects unknown");
  });
  it("FULL_BATTERY_TARGETS is all four; activeTargets defaults and filters", () => {
    assert.deepEqual(FULL_BATTERY_TARGETS, ["secscan", "seclayer", "windows", "linux"]);
    assert.deepEqual(activeTargets({}), ["secscan", "seclayer", "windows", "linux"]);
    assert.deepEqual(activeTargets({ targets: ["secscan", "seclayer"] }), ["secscan", "seclayer"]);
    assert.deepEqual(activeTargets({ targets: ["windows", "nope" as TargetId] }), ["windows"]);
    assert.deepEqual(activeTargets({ targets: [] }), ["secscan", "seclayer", "windows", "linux"]);
  });
});

describe("target profile integrity", () => {
  it("four profiles present; battery floors met (120/80/100/100)", () => {
    assert.deepEqual(Object.keys(TARGET_PROFILES).sort(), ["linux", "seclayer", "secscan", "windows"]);
    const floors: Record<TargetId, number> = { secscan: 120, seclayer: 80, windows: 100, linux: 100 };
    for (const [id, floor] of Object.entries(floors)) {
      const n = TARGET_PROFILES[id as TargetId].battery.length;
      assert.ok(n >= floor, `${id} has ${n}, want ≥${floor}`);
    }
    // Every category represented on every target (the 12-cell coverage contract).
    for (const profile of Object.values(TARGET_PROFILES)) {
      for (const cat of BATTERY_CATEGORIES) {
        assert.ok(targetItemsFor(profile, cat).length > 0, `${profile.id}:${cat} non-empty`);
      }
    }
  });
  it("ids unique per target, prefix shape, every item has category/name/brief/what/owasp", () => {
    for (const [id, profile] of Object.entries(TARGET_PROFILES)) {
      const prefix = TARGET_PREFIXES[id as TargetId];
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
  it("lookupTargetProfile resolves all four, rejects unknown", () => {
    assert.equal(lookupTargetProfile("secscan")?.name.includes("SecScan"), true);
    assert.equal(lookupTargetProfile("SECLAYER")?.name.includes("SecLayer"), true);
    assert.equal(lookupTargetProfile("windows")?.kind, "host-windows");
    assert.equal(lookupTargetProfile("LINUX")?.kind, "host-linux");
    assert.equal(lookupTargetProfile("nope"), undefined);
  });
  it("checklist text carries needs/deferred markers honestly", () => {
    const text = targetBatteryChecklistText(TARGET_PROFILES.secscan, "red");
    assert.ok(text.includes("[needs: Second test account"), "cross-account IDOR marked");
    assert.ok(text.includes("[needs: Canary"), "canary infra marked");
    const win = targetBatteryChecklistText(TARGET_PROFILES.windows, "red");
    assert.ok(win.includes(`[needs: ${NEEDS_KERBEROS_TICKET}]`), "kerberos ticket prerequisite marked (WS-064)");
    assert.ok(win.includes(`[needs: ${NEEDS_HUMAN_OPERATOR}]`), "human-operator prerequisite marked (WS-065)");
    const lin = targetBatteryChecklistText(TARGET_PROFILES.linux, "red");
    assert.ok(lin.includes(`[needs: ${NEEDS_PRIVILEGED_CLIENT}]`), "privileged-client prerequisite marked (LX-041)");
    assert.ok(!win.includes(`[needs: ${HOST_EXEC_TOOLING}]`), "no v0.9.0 plan-only markers remain");
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
  it("--targets subset: checklist carries only selected target ids", () => {
    const text = fullBatteryChecklistText("red", ["windows", "linux"]);
    assert.ok(text.includes("WS-001") && text.includes("LX-001"), "host batteries present");
    assert.ok(!text.includes("SS-001") && !text.includes("SL-001"), "web batteries excluded");
  });
});

describe("host-exec tooling scoping (v0.10.0)", () => {
  it("no cell is fully blocked; exactly 3 items carry honest prerequisites (nothing plan-only)", () => {
    const remaining: string[] = [];
    for (const id of ["windows", "linux"] as TargetId[]) {
      const profile = TARGET_PROFILES[id];
      for (const c of BATTERY_CATEGORIES) {
        // v0.10.0: every cell is probe-able — tools exist for all 410 items.
        assert.equal(targetCellBlocked(profile, c), false, `${id}:${c} probe-able`);
      }
      for (const b of profile.battery) {
        if (b.needs) remaining.push(`${id}:${b.id} [${b.needs}]`);
      }
    }
    assert.equal(remaining.length, 3, `3 prerequisite items remain (got ${remaining.join(", ")})`);
    assert.deepEqual(
      remaining.sort(),
      [
        `linux:LX-041 [${NEEDS_PRIVILEGED_CLIENT}]`,
        `windows:WS-064 [${NEEDS_KERBEROS_TICKET}]`,
        `windows:WS-065 [${NEEDS_HUMAN_OPERATOR}]`,
      ].sort(),
      "the honest remainder: ticket material, human operator, privileged client",
    );
    // The v0.9.0 marker is fully retired.
    for (const id of ["windows", "linux"] as TargetId[]) {
      for (const b of TARGET_PROFILES[id].battery) {
        assert.notEqual(b.needs, HOST_EXEC_TOOLING, `${b.id} no longer plan-only`);
      }
    }
  });
  it("targetCellStatus: done > blocked > missing (blocked mechanic preserved on a synthetic fully-blocked cell)", () => {
    const win = TARGET_PROFILES.windows;
    // v0.9.0: no real cell is fully blocked — cells report missing until probed.
    assert.equal(targetCellStatus(win, "logic", new Set()), "missing");
    assert.equal(targetCellStatus(win, "logic", new Set(["logic"])), "done");
    assert.equal(targetCellStatus(win, "validation", new Set(["validation"])), "done");
    const sec = TARGET_PROFILES.secscan;
    assert.equal(targetCellStatus(sec, "logic", new Set()), "missing", "web cells are never blocked");
    // The blocked mechanic itself still works: a cell where every item is marked → blocked.
    const blockedProfile: TargetProfile = {
      ...win,
      battery: win.battery.map((b) => (b.category === "logic" ? { ...b, needs: HOST_EXEC_TOOLING } : b)),
    };
    assert.equal(targetCellStatus(blockedProfile, "logic", new Set()), "blocked");
    assert.equal(targetCellStatus(blockedProfile, "logic", new Set(["logic"])), "done", "probed beats blocked");
  });
});

describe("unified plan", () => {
  it("covers all four targets in order: recon all → secscan → seclayer → windows → linux → chains → report", () => {
    const s = fullBatteryPlanSkeleton();
    const order = ["RECON all surfaces", "EXPLOIT SecScan battery", "EXPLOIT SecLayer battery", "EXPLOIT Windows battery", "EXPLOIT Linux battery", "CROSS-CUTTING CHAINS", "UNIFIED REPORT"];
    let prev = -1;
    for (const step of order) {
      const i = s.indexOf(step);
      assert.ok(i > prev, `${step} in order`);
      prev = i;
    }
    assert.ok(s.includes("3 × 4 = 12 cells"), "coverage rule stated");
    assert.ok(
      s.includes("All 410 items are executable"),
      "v0.10.0 host execution reality stated",
    );
  });
  it("subset skeleton: two targets → 6 cells, host phases omitted", () => {
    const s = fullBatteryPlanSkeleton(["secscan", "seclayer"]);
    assert.ok(s.includes("3 × 2 = 6 cells"));
    assert.ok(!s.includes("EXPLOIT Windows battery"));
    assert.ok(s.includes('"secscan" | "seclayer"'), "tag enum narrowed");
  });
  it("inferTargetProfile routes /api/mcp to seclayer; never invents host targets", () => {
    assert.equal(inferTargetProfile("https://secscan.us/api/mcp"), "seclayer");
    assert.equal(inferTargetProfile("https://secscan.us/api/mcp?x=1"), "seclayer");
    assert.equal(inferTargetProfile("https://secscan.us/scan"), "secscan");
    assert.equal(inferTargetProfile("https://10.9.0.11/"), "secscan", "host URLs default to secscan — explicit tag required");
    assert.equal(inferTargetProfile("not a url"), "secscan");
  });
});

describe("prompt wiring", () => {
  it("coordinator prompt includes selected batteries when fullBattery is set, generic otherwise", () => {
    const fb = coordinatorPrompt(promptCtx(true));
    assert.ok(fb.includes("FULL-BATTERY unified engagement"), "plan skeleton present");
    assert.ok(fb.includes("SS-001"), "SecScan battery present");
    assert.ok(fb.includes("SL-001"), "SecLayer battery present");
    assert.ok(fb.includes("WS-001"), "Windows battery present");
    assert.ok(fb.includes("LX-001"), "Linux battery present");
    const subset = coordinatorPrompt(promptCtx(true, ["secscan", "seclayer"]));
    assert.ok(subset.includes("SS-001") && !subset.includes("WS-001"), "--targets subset honored");
    const generic = coordinatorPrompt(promptCtx(false));
    assert.ok(!generic.includes("SS-001"), "no target battery without the flag");
    assert.ok(!generic.includes("FULL-BATTERY unified engagement"));
  });
  it("exploiter prompt swaps in target batteries + targetProfile tagging when fullBattery", () => {
    const fb = exploiterPrompt(promptCtx(true));
    assert.ok(fb.includes("WS-050") && fb.includes("LX-050"), "host checklists present");
    assert.ok(fb.includes("targetProfile"), "tagging instruction");
    assert.ok(fb.includes('"windows" | "linux"'), "host tags listed");
    assert.ok(fb.includes("3 × 4 = 12 cells"), "coverage rule");
    assert.ok(fb.includes("[needs: ...] EXECUTE when the prerequisite is met"), "prerequisite rule");
    assert.ok(fb.includes("never pretend the runner shadowed a session"), "human-gated shadowing rule");
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
    targets: ["secscan", "seclayer"],
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

  /** 12-cell scripted LLM: reads the runner's Battery line and tasks every MISSING cell (blocked cells are never chased). */
  function scriptedLlm12() {
    let n = 0;
    const fired = new Set<string>(); // one probe per task — the fake loop doesn't record tool calls as assistant messages
    const urls: Record<string, string> = {
      secscan: "https://secscan.us/scan",
      seclayer: "https://secscan.us/api/mcp",
      windows: "https://10.9.0.11/",
      linux: "https://10.9.0.12/",
    };
    const probe = (target: string, category: string): ToolCallRequest => ({
      id: `call-${++n}`,
      name: "http_probe",
      arguments: {
        method: "GET",
        url: urls[target],
        category,
        attackId: "T1018",
        targetProfile: target, // explicit tag for every cell — exercises the tagging path
        hypothesis: `full battery ${target} ${category}`,
      },
    });
    const taskFor = (target: string, category: string) => ({
      kind: "probe", brief: `test ${target} ${category}`, attackId: "T1018", category, maxTurns: 3,
    });
    return async (role: AgentRole, messages: ChatMessage[], _opts: object): Promise<ChatResult> => {
      const has = (s: string) => messages.some((m) => m.content.includes(s));
      if (role === "coordinator") {
        if (has("Transition awaiting sign-off")) return textOnly("SIGN-OFF: test approval.");
        // Faithful coordinator: parse the runner's Battery line and task MISSING cells.
        const battLine = messages.map((m) => m.content).join("\n").match(/Battery: ([^\n]*)/)?.[1] ?? "";
        const seen = new Set<string>();
        const tasks: object[] = [];
        for (const m of battLine.matchAll(/(\w+):\{([^}]+)\}/g)) {
          for (const part of m[2].split(",")) {
            const [c, s] = part.split(":");
            const key = `${m[1]}:${c}`;
            if (s === "MISSING" && ["logic", "functionality", "validation"].includes(c) && !seen.has(key)) {
              seen.add(key);
              if (tasks.length < 3) tasks.push(taskFor(m[1], c));
            }
          }
        }
        if (tasks.length === 0) return taskJson([], true, "done");
        return taskJson(tasks, false, `covering ${tasks.map((t) => (t as { brief: string }).brief).join(", ")}`);
      }
      if (role === "recon") return textOnly("recon brief: all surfaces mapped");
      if (role === "reporter") return textOnly("# Report\n\n```json " + '{"findings":[]}' + " ```");
      const sys = messages.find((m) => m.role === "system")?.content ?? "";
      const brief = sys.match(/- Task: ([^\n]+)/)?.[1] ?? "";
      const parts = brief.split(" ");
      const target = parts[1] ?? "secscan";
      const category = sys.match(/Battery category: (\w+)/)?.[1] ?? parts[2] ?? "logic";
      if (!fired.has(brief)) {
        fired.add(brief);
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

  it("6/6 web cells (--targets secscan,seclayer) → report says full battery complete", async () => {
    const res = await run(baseInput, scriptedLlm(true));
    assert.equal(res.status, "complete");
    const report = readFileSync(join(dir, res.engagementId, "report.md"), "utf8");
    assert.ok(report.includes("Full battery complete: all 6 cells probed or honestly blocked."), "6-cell completion line");
    assert.ok(report.includes("3 categories × 2 targets"), "per-target coverage header");
  });

  it("missing seclayer cells → report names them under Honest limits", async () => {
    const res = await run(baseInput, scriptedLlm(false));
    assert.equal(res.status, "complete");
    const report = readFileSync(join(dir, res.engagementId, "report.md"), "utf8");
    assert.ok(report.includes("NOT COVERED: seclayer:logic, seclayer:functionality, seclayer:validation"), "missing cells named");
    assert.ok(report.includes("list these under Honest limits"), "honest-limits directive");
  });

  it("12 cells (all four targets): all probed → complete; the 3 prerequisite items named under Honest limits", async () => {
    const input: EngagementInput = { ...baseInput, targets: undefined }; // default: all four
    const res = await run(input, scriptedLlm12());
    assert.equal(res.status, "complete");
    const report = readFileSync(join(dir, res.engagementId, "report.md"), "utf8");
    assert.ok(report.includes("3 categories × 4 targets"), "12-cell header");
    assert.ok(report.includes("12/12 cells probed"), "all 12 cells probed");
    assert.ok(report.includes("Full battery complete: all 12 cells probed or honestly blocked."), "completion line");
    assert.ok(!report.includes("NOT COVERED"), "no missing cells");
    assert.ok(!report.includes("BLOCKED (prerequisite"), "no fully-blocked cells in v0.10.0");
    assert.ok(
      report.includes("Items with prerequisites (execute when met — see Honest limits)"),
      "prerequisite remainder named honestly",
    );
    for (const id of ["windows:WS-064", "windows:WS-065", "linux:LX-041"]) {
      assert.ok(report.includes(id), `${id} named with its prerequisite`);
    }
  });
});
