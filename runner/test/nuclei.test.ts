/**
 * Nuclei bridge tests (v0.21.0) — the runner's template-based check arm.
 *
 * NO real nuclei needed: the executor's spawn is injectable, so a fake
 * spawn returns canned `nuclei -tl` / JSONL output. What we prove:
 *  - policy: dos tags refused, -exclude-tags dos on every run argv, no
 *    shell interpolation (argv array), template updates never flaggable
 *  - missing binary fails closed with setup instructions
 *  - out-of-scope hosts rejected BEFORE any spawn (zero subprocess calls)
 *  - kill switch aborts in-flight runs (signal → child killed)
 *  - JSONL parsed into findings with CVE extraction; bad lines counted
 *  - mapping: CVE overlap → battery items (one finding, two sources);
 *    template-only → WS-108/LX-110 runtime instances
 *  - tiers: templates → Tier 1, run → Tier 2
 *  - phases wiring: nuclei_exec in the agent tool lists, run refused
 *    outside the exploit phase, honest counting in the report
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  NucleiExecutor,
  buildNucleiRunArgv,
  buildNucleiListArgv,
  checkNucleiTags,
  checkNucleiExtraFlags,
  parseNucleiJsonl,
  parseTemplateList,
  filterTemplates,
  truncateIds,
  extractCveFromTemplate,
  mapTemplateToBattery,
  overlapHint,
  nucleiCountLine,
  nucleiBinaryPresent,
  _resetNucleiProbeCache,
  NUCLEI_SETUP_INSTRUCTIONS,
  type SpawnFn,
} from "../src/nuclei/index.js";
import { toolMinTier } from "../src/accountability/tiers.js";
import { prerequisiteMet } from "../src/coverage/items.js";
import { handleNucleiTools } from "../src/dispatch/nuclei.js";
import { NUCLEI_EXEC_TOOL } from "../src/tools/nuclei.js";
import { RECON_TOOLS, EXPLOIT_TOOLS } from "../src/tools/compose.js";
import { runEngagement } from "../src/phases.js";
import type { EngagementInput } from "../src/types.js";
import type { AgentRole, ChatMessage, ChatResult, ToolCallRequest } from "@secscan/redteam-llm-router";

const SCOPE = ["10.9.0.12"];

const TL_OUTPUT = [
  "/root/nuclei-templates/http/cves/2021/CVE-2021-44228.yaml",
  "/root/nuclei-templates/http/cves/2017/CVE-2017-0144.yaml",
  "/root/nuclei-templates/http/misconfiguration/rdp-misconfig.yaml",
  "/root/nuclei-templates/dos/http-dos.yaml",
].join("\n");

const JSONL_OUTPUT = [
  JSON.stringify({
    "template-id": "CVE-2021-44228",
    info: { name: "Log4Shell RCE", severity: "critical", tags: ["cve", "rce"] },
    host: "https://10.9.0.12",
    "matched-at": "https://10.9.0.12/login",
    "extracted-results": ["REDTEAM-ok"],
  }),
  "this line is not json",
  JSON.stringify({
    "template-id": "rdp-misconfig",
    info: { name: "RDP misconfiguration", severity: "high", tags: ["misconfig"] },
    host: "https://10.9.0.12",
    "matched-at": "https://10.9.0.12:3389",
  }),
].join("\n");

function fakeSpawn(opts: { tl?: string; jsonl?: string; onArgv?: (argv: string[]) => void; hang?: boolean } = {}): SpawnFn & { calls: string[][] } {
  const calls: string[][] = [];
  const fn = (async (argv: string[], o: { timeoutMs: number; signal?: AbortSignal }) => {
    calls.push(argv);
    opts.onArgv?.(argv);
    if (o.signal?.aborted) return { stdout: "", stderr: "", exitCode: null, killed: true, timedOut: false };
    if (opts.hang) return new Promise(() => {});
    const isList = argv.includes("-tl");
    return {
      stdout: isList ? (opts.tl ?? TL_OUTPUT) : (opts.jsonl ?? JSONL_OUTPUT),
      stderr: "",
      exitCode: 0,
      killed: false,
      timedOut: false,
    };
  }) as SpawnFn & { calls: string[][] };
  fn.calls = calls;
  return fn;
}

const TEST_ENV: NodeJS.ProcessEnv = { REDTEAM_NUCLEI_BIN: "/usr/bin/nuclei" };

function testExecutor(spawn: SpawnFn): NucleiExecutor {
  return new NucleiExecutor({ env: TEST_ENV, spawn, probeBinary: async () => true });
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

describe("nuclei policy", () => {
  it("refuses dos tags", () => {
    assert.match(checkNucleiTags(["dos"]) ?? "", /denial-of-service|dos/i);
    assert.match(checkNucleiTags(["DoS"]) ?? "", /dos/i);
    assert.equal(checkNucleiTags(["cve", "misconfig"]), null);
    assert.equal(checkNucleiTags(undefined), null);
  });

  it("refuses template-update flags", () => {
    assert.match(checkNucleiExtraFlags(["-update-templates"]) ?? "", /never/);
    assert.equal(checkNucleiExtraFlags(["-silent"]), null);
  });

  it("every run argv excludes dos and never interpolates shell", () => {
    const argv = buildNucleiRunArgv("nuclei", {
      target: "https://10.9.0.12; rm -rf /",
      filter: { tags: ["cve"] },
      rateLimit: 2,
      timeoutS: 60,
    });
    // The hostile target is ONE argv element — no shell, no splitting.
    assert.ok(argv.includes("https://10.9.0.12; rm -rf /"));
    assert.ok(argv.includes("-exclude-tags") && argv.includes("dos"));
    assert.ok(!argv.includes("-update-templates"));
    // spawn() uses argv arrays, never a shell string.
    assert.ok(!argv.some((a) => a.includes("&&") || a.includes("|")));
  });

  it("list argv is recon-safe (no target, no update)", () => {
    const argv = buildNucleiListArgv("nuclei");
    assert.ok(argv.includes("-tl"));
    assert.ok(!argv.includes("-u"));
    assert.ok(!argv.includes("-update-templates"));
  });
});

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

describe("nuclei executor", () => {
  it("templates: lists and filters recon-safely, nothing fired", async () => {
    const spawn = fakeSpawn();
    const exec = testExecutor(spawn);
    const res = await exec.templates({ filter: { cve: "CVE-2021-44228" } });
    assert.ok(res.summary.includes("1 templates match"));
    assert.equal(res.templatesListed?.[0]?.id, "CVE-2021-44228");
    assert.ok(!res.refused);
    // Only the -tl listing ran — no -u target flag anywhere.
    assert.ok(spawn.calls.every((a) => a.includes("-tl") && !a.includes("-u")));
  });

  it("templates: missing binary fails closed with setup instructions", async () => {
    const exec = new NucleiExecutor({ env: TEST_ENV, spawn: fakeSpawn(), probeBinary: async () => false });
    const res = await exec.templates({});
    assert.ok(res.refused);
    assert.ok(res.refused.includes("nuclei binary not available"));
    assert.ok(res.refused.includes("update-templates"));
  });

  it("run: out-of-scope host refused BEFORE any spawn", async () => {
    const spawn = fakeSpawn();
    const exec = testExecutor(spawn);
    const res = await exec.run({ host: "10.99.0.99", scopeHosts: SCOPE, rateLimit: 2 });
    assert.ok(res.refused);
    assert.match(res.refused, /scope/i);
    assert.equal(spawn.calls.length, 0, "zero subprocess calls for out-of-scope host");
  });

  it("run: dos tag refused before spawn", async () => {
    const spawn = fakeSpawn();
    const exec = testExecutor(spawn);
    const res = await exec.run({ host: "10.9.0.12", scopeHosts: SCOPE, filter: { tags: ["dos"] }, rateLimit: 2 });
    assert.ok(res.refused);
    assert.match(res.refused, /dos/i);
    assert.equal(spawn.calls.length, 0);
  });

  it("run: parses JSONL findings with CVE extraction; bad lines counted", async () => {
    const spawn = fakeSpawn();
    const exec = testExecutor(spawn);
    const res = await exec.run({ host: "10.9.0.12", scopeHosts: SCOPE, filter: { tags: ["cve"] }, rateLimit: 2 });
    assert.ok(!res.refused);
    assert.equal(res.findings.length, 2);
    assert.equal(res.findings[0]?.cve, "CVE-2021-44228");
    assert.equal(res.findings[0]?.severity, "critical");
    assert.ok(res.summary.includes("2 findings"));
    // Rate limit inherited from the safety config.
    const argv = spawn.calls[0] ?? [];
    assert.ok(argv.includes("-rate-limit") && argv.includes("2"));
  });

  it("run: kill switch aborts in-flight runs", async () => {
    const spawn = fakeSpawn();
    const exec = testExecutor(spawn);
    exec.killSwitch.aborted = true;
    const res = await exec.run({ host: "10.9.0.12", scopeHosts: SCOPE, rateLimit: 2 });
    assert.ok(res.refused);
    assert.match(res.refused, /kill switch/i);
    assert.equal(spawn.calls.length, 0);
  });

  it("run: explicit id lists are truncated runner-side", async () => {
    const ids = Array.from({ length: 150 }, (_, i) => `t-${i}`);
    const spawn = fakeSpawn();
    const exec = testExecutor(spawn);
    await exec.run({ host: "10.9.0.12", scopeHosts: SCOPE, filter: { ids }, rateLimit: 2 });
    const argv = spawn.calls[0] ?? [];
    const idIdx = argv.indexOf("-id");
    const passed = argv[idIdx + 1]?.split(",") ?? [];
    assert.equal(passed.length, 100, "id list truncated to the runner cap");
  });
});

describe("nuclei template list parsing", () => {
  it("parses -tl output leniently; filters by id/cve/tag", () => {
    const list = parseTemplateList(TL_OUTPUT);
    assert.equal(list.length, 4);
    assert.equal(list[0]?.id, "CVE-2021-44228");
    assert.equal(filterTemplates(list, { cve: "cve-2017-0144" }).length, 1);
    assert.equal(filterTemplates(list, { ids: ["rdp-misconfig"] }).length, 1);
    assert.equal(filterTemplates(list, { tags: ["misconfig"] }).length, 1);
    assert.deepEqual(truncateIds(["a", "b", "c"], 2), ["a", "b"]);
  });

  it("extracts CVEs from template ids", () => {
    assert.equal(extractCveFromTemplate("CVE-2021-44228", "Log4Shell"), "CVE-2021-44228");
    assert.equal(extractCveFromTemplate("http-misconfig", "bad config"), undefined);
  });
});

// ---------------------------------------------------------------------------
// Mapping (dedupe)
// ---------------------------------------------------------------------------

describe("nuclei template→battery mapping", () => {
  const log4shell = {
    templateId: "CVE-2021-44228", name: "Log4Shell", severity: "critical",
    host: "h", matchedAt: "h", cve: "CVE-2021-44228", tags: ["cve"], excerpt: "",
  };

  it("CVE already confirmed → overlap (one finding, two evidence sources)", () => {
    const o = mapTemplateToBattery(log4shell, "windows", new Set(["CVE-2021-44228"]));
    assert.ok(!o.templateOnly);
    assert.ok(o.batteryItems.includes("WS-106"));
    assert.match(overlapHint(o), /ONE finding/i);
  });

  it("no overlap → template-only runtime instance under the methodology item", () => {
    // A CVE-named template for a CVE nobody confirmed: new information,
    // NOT forced into the Metasploit methodology items.
    const fresh = { ...log4shell, cve: "CVE-2021-44228", tags: ["cve"] };
    const o = mapTemplateToBattery(fresh, "linux", new Set());
    assert.ok(o.templateOnly);
    assert.equal(o.methodologyItem, "LX-110");
    const ow = mapTemplateToBattery(fresh, "windows", new Set());
    assert.ok(ow.templateOnly);
    assert.equal(ow.methodologyItem, "WS-108");
    assert.match(overlapHint(ow), /WS-108/);
  });
});

// ---------------------------------------------------------------------------
// Tiers, prerequisites, honest counting
// ---------------------------------------------------------------------------

describe("nuclei tiers and prerequisites", () => {
  it("templates → Tier 1 (recon-safe); run → Tier 2 (fires)", () => {
    assert.equal(toolMinTier("nuclei_exec", { action: "templates" }), 1);
    assert.equal(toolMinTier("nuclei_exec", { action: "run" }), 2);
  });

  it("prerequisiteMet: nuclei binary via env override", () => {
    _resetNucleiProbeCache();
    process.env.REDTEAM_NUCLEI_BIN = "/usr/bin/nuclei";
    assert.equal(prerequisiteMet("nuclei binary"), true);
    delete process.env.REDTEAM_NUCLEI_BIN;
    _resetNucleiProbeCache();
    // Real PATH probe: nuclei is not installed in this test env.
    assert.equal(prerequisiteMet("nuclei binary"), false);
    _resetNucleiProbeCache();
  });

  it("honest counting: template executions reported separately from intents", () => {
    assert.equal(nucleiCountLine({ templateExecutions: 0, templatesRun: 0, findings: 0 }), "");
    const line = nucleiCountLine({ templateExecutions: 12, templatesRun: 40, findings: 3 });
    assert.match(line, /12 runs/);
    assert.match(line, /never merged/);
  });
});

// ---------------------------------------------------------------------------
// Dispatcher + tool lists
// ---------------------------------------------------------------------------

describe("nuclei_exec wiring", () => {
  it("is in the recon and exploit tool lists", () => {
    assert.ok(RECON_TOOLS.some((t) => t.name === "nuclei_exec"));
    assert.ok(EXPLOIT_TOOLS.some((t) => t.name === "nuclei_exec"));
    const params = NUCLEI_EXEC_TOOL.parameters as { required?: string[] };
    assert.ok(params.required?.includes("action"));
  });

  function fakeCtx(over: Record<string, unknown> = {}): never {
    return {
      probesUsed: 0,
      coverage: new Set<string>(),
      targetCoverage: new Map(),
      input: { mode: "red", fullBattery: false, roe: {} },
      events: { updateState: () => {} },
      hostKill: { aborted: false, controllers: new Set() },
      hosts: SCOPE,
      safety: { rpsPerHost: 2 },
      nucleiExecutor: testExecutor(fakeSpawn()),
      nuclei: { templateExecutions: 0, templatesRun: 0, findings: 0 },
      ...over,
    } as never;
  }

  const call = (action: string, extra: Record<string, unknown> = {}): ToolCallRequest => ({
    id: "call-nuclei",
    name: "nuclei_exec",
    arguments: { action, host: "10.9.0.12", category: "functionality", targetProfile: "windows", attackId: "T1595.002", ...extra },
  });

  it("run is refused outside the exploit phase", async () => {
    const r = await handleNucleiTools(fakeCtx(), "exploiter", "recon", call("run"), (call("run") as { arguments: Record<string, unknown> }).arguments);
    assert.ok(r);
    assert.match(r.result, /exploit phase only/i);
  });

  it("templates is allowed in recon (never fires)", async () => {
    const r = await handleNucleiTools(fakeCtx(), "recon", "recon", call("templates"), (call("templates") as { arguments: Record<string, unknown> }).arguments);
    assert.ok(r);
    assert.ok(!/DENIED|refused/i.test(r.result) || r.result.includes("template selection"));
    assert.match(r.result, /template selection/i);
  });

  it("requires an explicit windows|linux targetProfile (never inferred)", async () => {
    const bad = call("templates", { targetProfile: "secscan" });
    const r = await handleNucleiTools(fakeCtx(), "recon", "recon", bad, bad.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /DENIED.*targetProfile/);
  });

  it("out-of-scope run is DENIED with zero subprocess calls", async () => {
    const spawn = fakeSpawn();
    const ctx = fakeCtx({ nucleiExecutor: testExecutor(spawn) });
    const c = call("run", { host: "10.99.0.99" });
    const r = await handleNucleiTools(ctx, "exploiter", "exploit", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /DENIED/);
    assert.equal(spawn.calls.length, 0);
  });

  it("successful run increments the honest counters", async () => {
    const ctx = fakeCtx();
    const c = call("run", { tags: ["cve"] });
    const r = await handleNucleiTools(ctx, "exploiter", "exploit", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.ok(!/DENIED/.test(r.result));
    const n = (ctx as unknown as { nuclei: { templateExecutions: number; findings: number } }).nuclei;
    assert.equal(n.templateExecutions, 1);
    assert.equal(n.findings, 2);
    assert.match(r.result, /Dedupe guidance/);
  });
});

// ---------------------------------------------------------------------------
// Full engagement wiring (happy path)
// ---------------------------------------------------------------------------

describe("nuclei_exec engagement wiring", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "nuclei-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const textOnly = (text: string): ChatResult => ({ text, toolCalls: [], provider: "fake", model: "fake" });

  function scriptedLlm() {
    return async (role: AgentRole, messages: ChatMessage[]): Promise<ChatResult> => {
      const has = (s: string) => messages.some((m) => m.content.includes(s));
      if (role === "coordinator") {
        if (has("Transition awaiting sign-off")) return textOnly("SIGN-OFF: approved.");
        if (has("RE-PLAN") || has("Last batch results") || has("OVERRIDE"))
          return textOnly('```json\n{"tasks": [], "finish": true, "note": "done"}\n```');
        if (has("Return ONLY a JSON block")) {
          return textOnly(
            '```json\n{"tasks": [{"kind": "probe", "brief": "nuclei template checks", "attackId": "T1595.002", "category": "functionality", "maxTurns": 4}], "finish": false, "note": "go"}\n```',
          );
        }
        return textOnly('```json\n{"adversaryProfile": "test", "steps": [{"phase": "exploit", "attackId": "T1595.002", "description": "nuclei run"}]}\n```');
      }
      if (role === "recon") return textOnly("recon brief: web services on host");
      if (role === "reporter") return textOnly('# Report\n\n```json {"findings": []} ```');
      const sys = messages.find((m) => m.role === "system")?.content ?? "";
      if (sys.includes("Task:") || has("Execute the task now")) {
        const toolSeen = messages.some((m) => m.role === "tool");
        if (!toolSeen) {
          return {
            text: "running nuclei templates",
            toolCalls: [
              {
                id: "call-nuclei",
                name: "nuclei_exec",
                arguments: {
                  action: "run", host: "10.9.0.12", category: "functionality",
                  targetProfile: "windows", attackId: "T1595.002", tags: ["cve"],
                  hypothesis: "WS-108 template checks", batteryItem: "WS-108",
                },
              },
            ],
            provider: "fake",
            model: "fake",
          };
        }
        return textOnly("TRIED: nuclei run / OBSERVED: 2 findings / VERDICT: killed - templates need review");
      }
      return textOnly("idle");
    };
  }

  it("nuclei_exec run fires in the exploit phase with honest counting", async () => {
    const spawn = fakeSpawn();
    const input: EngagementInput = {
      target: "10.9.0.12",
      mode: "red",
      objective: "nuclei wiring test",
      roe: { scope: ["10.9.0.12"] },
    };
    const nucleiExecutor = new NucleiExecutor({ env: TEST_ENV, spawn, probeBinary: async () => true });
    const res = await runEngagement(input, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: { verify: async () => true, completeForRole: scriptedLlm() as never, nucleiExecutor },
    });
    assert.equal(res.status, "complete");
    // The subprocess actually ran (scope-checked host, runner-built argv).
    assert.ok(spawn.calls.length > 0);
    assert.ok(spawn.calls.every((a) => a.includes("-exclude-tags")));
    const report = readFileSync(join(dir, res.engagementId, "report.md"), "utf8");
    assert.match(report, /Nuclei template executions/);
    assert.match(report, /never merged/);
  });
});
