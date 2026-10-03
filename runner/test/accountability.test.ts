/**
 * Accountability tests (v0.17.0) — autonomy tiers + named human accountability.
 *
 * No network, no API keys. What we prove here:
 *  - tier parsing fails loud on bad input, never guesses
 *  - tool→tier classification: Tier 0 is read-only, exploit tools need
 *    Tier 1, msf_exec run needs Tier 2, unknown tools fail closed to Tier 2
 *  - the dispatcher REFUSES above-tier tools before any packet (Tier 0
 *    cannot fire ssh_exec — the transport is never touched)
 *  - Tier 1 enforces the single-step chain budget per target
 *  - tier escalation requires a named operator + reason and is recorded
 *  - production refuses to start without a named operator
 *  - Tier 2 on production refuses to start without explicit approval
 *  - the approval log, safety manifest, compliance pack, and attestation
 *    all carry the tier + accountability record
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  parseTier,
  defaultTier,
  toolMinTier,
  isExploitStepTool,
  checkTierAllows,
  recordExploitStep,
  describeTier,
  escalateTier,
  requireTier2ProductionApproval,
  requireNamedOperator,
  resolveOperatorName,
  ApprovalLog,
  TIER_NAMES,
  TIER1_CHAIN_BUDGET_PER_TARGET,
} from "../src/accountability/index.js";
import type { AutonomyTier, TierState, ApprovalEntry } from "../src/accountability/index.js";
import { renderAttestationLetter } from "../src/compliance/index.js";
import { runEngagement } from "../src/phases.js";
import type { EngagementInput } from "../src/types.js";
import type { AgentRole, ChatMessage, ChatResult, ToolCallRequest } from "@secscan/redteam-llm-router";
import { HostExecutor } from "../src/host-exec/index.js";
import type { SshTransport } from "../src/host-exec/index.js";

const FAKE_ENV: NodeJS.ProcessEnv = {
  REDTEAM_SSH_USER: "testuser",
  REDTEAM_SSH_PASSWORD: "testpass",
};

// ---------------------------------------------------------------------------
// Tier parsing
// ---------------------------------------------------------------------------

describe("parseTier", () => {
  it("parses 0/1/2 and names", () => {
    assert.equal(parseTier("0"), 0);
    assert.equal(parseTier("1"), 1);
    assert.equal(parseTier("2"), 2);
    assert.equal(parseTier("observe"), 0);
    assert.equal(parseTier("validate"), 1);
    assert.equal(parseTier("chain"), 2);
  });
  it("undefined/empty → undefined (caller applies the environment default)", () => {
    assert.equal(parseTier(undefined), undefined);
    assert.equal(parseTier(""), undefined);
    assert.equal(parseTier("  "), undefined);
  });
  it("fails LOUD on anything else — never guesses about autonomy", () => {
    for (const bad of ["3", "-1", "high", "full", "yes"]) {
      assert.throws(() => parseTier(bad), /bad autonomy tier/, `should throw for ${JSON.stringify(bad)}`);
    }
  });
  it("environment defaults: staging chains, production validates", () => {
    assert.equal(defaultTier("staging"), 2);
    assert.equal(defaultTier("production"), 1);
  });
  it("tier names and descriptions exist for every tier", () => {
    for (const t of [0, 1, 2] as AutonomyTier[]) {
      assert.ok(TIER_NAMES[t], `name for tier ${t}`);
      assert.ok(describeTier(t).includes(`Tier ${t}`));
    }
  });
});

// ---------------------------------------------------------------------------
// Tool classification
// ---------------------------------------------------------------------------

describe("toolMinTier", () => {
  const cases: [string, Record<string, unknown>, AutonomyTier][] = [
    // Tier 0 — read-only
    ["http_probe", {}, 0],
    ["burst_probe", {}, 0],
    ["get_scan_status", {}, 0],
    ["get_report", {}, 0],
    ["list_recent_scans", {}, 0],
    ["get_account", {}, 0],
    ["query_registry", {}, 0],
    ["update_target_map", {}, 0],
    ["record_finding", {}, 0],
    ["record_killed", {}, 0],
    ["abort_engagement", {}, 0],
    ["scan_url", {}, 0],
    ["scan_url", { aggressive: false }, 0],
    // Tier 1 — single validated steps
    ["scan_url", { aggressive: true }, 1],
    ["ssh_exec", {}, 1],
    ["smb_exec", {}, 1],
    ["winrm_exec", {}, 1],
    ["winrm_probe", {}, 1],
    ["rdp_auth", {}, 1],
    ["rdp_shadow_prep", {}, 1],
    ["smb_pth", {}, 1],
    ["ad_enum", {}, 1],
    ["krb_ptt", {}, 1],
    ["ssh_agent_audit", {}, 1],
    ["nfs_enum", {}, 1],
    ["msf_exec", { action: "search" }, 1],
    ["msf_exec", { action: "suggest" }, 1],
    ["msf_exec", {}, 1],
    // Tier 2 — chaining
    ["msf_exec", { action: "run" }, 2],
    // Unknown tools fail closed to the highest tier
    ["brand_new_tool", {}, 2],
  ];
  for (const [tool, args, want] of cases) {
    it(`${tool} ${JSON.stringify(args)} → Tier ${want}`, () => {
      assert.equal(toolMinTier(tool, args), want);
    });
  }

  it("exploit-step tools are the executing ones, not the enumerating ones", () => {
    for (const t of ["ssh_exec", "smb_exec", "winrm_exec", "smb_pth", "krb_ptt", "rdp_auth"]) {
      assert.ok(isExploitStepTool(t, {}), `${t} consumes the chain budget`);
    }
    assert.ok(isExploitStepTool("scan_url", { aggressive: true }));
    assert.ok(!isExploitStepTool("scan_url", {}));
    for (const t of ["winrm_probe", "ad_enum", "nfs_enum", "ssh_agent_audit", "rdp_shadow_prep", "http_probe"]) {
      assert.ok(!isExploitStepTool(t, {}), `${t} observes; it does not consume the budget`);
    }
  });
});

// ---------------------------------------------------------------------------
// Pure tier checks
// ---------------------------------------------------------------------------

function tierState(tier: AutonomyTier): TierState {
  return { current: tier, declared: tier, chainSteps: new Map() };
}

describe("checkTierAllows", () => {
  it("Tier 0 allows recon, refuses exploitation", () => {
    const s = tierState(0);
    assert.equal(checkTierAllows(s, "http_probe", {}, "h"), undefined);
    assert.equal(checkTierAllows(s, "scan_url", {}, "h"), undefined);
    const d = checkTierAllows(s, "ssh_exec", {}, "h");
    assert.ok(d?.includes("DENIED by autonomy tier"), d ?? "no denial");
    assert.ok(d?.includes("Tier 1"), d ?? "no tier named");
    const d2 = checkTierAllows(s, "msf_exec", { action: "run" }, "h");
    assert.ok(d2?.includes("Tier 2"), d2 ?? "no tier named");
  });
  it("Tier 1 allows single steps, refuses msf run", () => {
    const s = tierState(1);
    assert.equal(checkTierAllows(s, "ssh_exec", {}, "h"), undefined);
    assert.equal(checkTierAllows(s, "msf_exec", { action: "search" }, "h"), undefined);
    const d = checkTierAllows(s, "msf_exec", { action: "run" }, "h");
    assert.ok(d?.includes("DENIED by autonomy tier") && d.includes("Tier 2"), d ?? "no denial");
  });
  it("Tier 2 allows everything", () => {
    const s = tierState(2);
    assert.equal(checkTierAllows(s, "msf_exec", { action: "run" }, "h"), undefined);
    assert.equal(checkTierAllows(s, "ssh_exec", {}, "h"), undefined);
  });
  it("Tier 1 chain budget: one validated step per target, then refused", () => {
    const s = tierState(1);
    const args = {};
    assert.equal(checkTierAllows(s, "ssh_exec", args, "h1"), undefined);
    recordExploitStep(s, "ssh_exec", args, "h1");
    const d = checkTierAllows(s, "ssh_exec", args, "h1");
    assert.ok(d?.includes("single validated exploit step per target"), d ?? "no chain denial");
    assert.ok(d?.includes("Tier 2"), d ?? "no re-approval path named");
    // A different target still has its budget.
    assert.equal(checkTierAllows(s, "ssh_exec", args, "h2"), undefined);
    // Enumeration does not consume the budget.
    assert.equal(checkTierAllows(s, "ad_enum", args, "h1"), undefined);
  });
  it("denials do not consume the budget (recordExploitStep only on success paths)", () => {
    const s = tierState(1);
    // recordExploitStep is only called by the dispatcher on clean results;
    // at Tier 2 it is a no-op even when called.
    const s2 = tierState(2);
    recordExploitStep(s2, "ssh_exec", {}, "h");
    assert.equal(s2.chainSteps.size, 0);
    recordExploitStep(s, "http_probe", {}, "h");
    assert.equal(s.chainSteps.size, 0);
  });
  it("chain budget constant is 1 (single-step)", () => {
    assert.equal(TIER1_CHAIN_BUDGET_PER_TARGET, 1);
  });
});

// ---------------------------------------------------------------------------
// Escalation + approvals
// ---------------------------------------------------------------------------

describe("escalateTier", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "acct-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("records the approval BEFORE moving the tier", () => {
    const log = new ApprovalLog(dir, "eng-1");
    const state = { current: 1 as AutonomyTier };
    const e = escalateTier(state, 2, log, { operator: "op", reason: "need chaining for AD paths" });
    assert.equal(state.current, 2);
    assert.equal(e.kind, "tier-escalation");
    assert.equal(e.operator, "op");
    assert.equal(e.fromTier, 1);
    assert.equal(e.toTier, 2);
    assert.ok(e.ts, "timestamp recorded");
    const listed = log.list();
    assert.equal(listed.length, 1);
    assert.equal(listed[0]!.detail, e.detail);
  });
  it("refuses anonymous or unexplained up-escalation", () => {
    const log = new ApprovalLog(dir, "eng-1");
    const state = { current: 0 as AutonomyTier };
    assert.throws(() => escalateTier(state, 1, log, { operator: " ", reason: "x" }), /named operator/);
    assert.throws(() => escalateTier(state, 1, log, { operator: "op", reason: " " }), /recorded reason/);
    assert.equal(state.current, 0, "tier unchanged after refused escalation");
  });
  it("refuses no-op moves but allows logged de-escalation", () => {
    const log = new ApprovalLog(dir, "eng-1");
    const state = { current: 1 as AutonomyTier };
    assert.throws(() => escalateTier(state, 1, log, { operator: "op", reason: "x" }), /no-op tier change refused/);
    const entry = escalateTier(state, 0, log, { operator: "op" });
    assert.equal(state.current, 0, "tier lowered");
    assert.equal(entry.kind, "tier-de-escalation");
    assert.equal(entry.operator, "op");
    assert.equal(entry.fromTier, 1);
    assert.equal(entry.toTier, 0);
    assert.throws(() => escalateTier(state, 2, log, { operator: " ", reason: "x" }), /named operator/, "down-tier still needs a name");
  });
});

describe("ApprovalLog", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "acct-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("appends with sequence order and reads back", () => {
    const log = new ApprovalLog(dir, "eng-9");
    log.append("tier-declared", "op", "declared", undefined, 2);
    log.append("production-confirm", "op", "confirmed");
    const list = log.list();
    assert.equal(list.length, 2);
    assert.equal(list[0]!.seq, 0);
    assert.equal(list[1]!.seq, 1);
    assert.ok(list[0]!.ts <= list[1]!.ts, "timestamps ordered");
    assert.ok(existsSync(join(dir, "approvals.jsonl")), "approvals.jsonl written");
  });
});

describe("operator + tier-2-production gates", () => {
  it("production requires a named operator — fail fast", () => {
    assert.throws(() => requireNamedOperator("production", undefined), /named human operator/);
    requireNamedOperator("production", "op"); // no throw
    requireNamedOperator("staging", undefined); // staging keeps the honest fallback
  });
  it("Tier 2 on production requires explicit approval", () => {
    assert.throws(() => requireTier2ProductionApproval(2, "production", false), /Tier 2 \(chain\) on PRODUCTION/);
    requireTier2ProductionApproval(2, "production", true);
    requireTier2ProductionApproval(1, "production", false); // Tier 1 needs no extra approval
    requireTier2ProductionApproval(2, "staging", false); // staging Tier 2 is the default
  });
  it("resolveOperatorName prefers input, then env", () => {
    assert.equal(resolveOperatorName("  op  ", { REDTEAM_OPERATOR: "env-op" }), "op");
    assert.equal(resolveOperatorName(undefined, { REDTEAM_OPERATOR: "env-op" }), "env-op");
    assert.equal(resolveOperatorName(undefined, {}), undefined);
  });
});

// ---------------------------------------------------------------------------
// Attestation: tier + responsibilities, still no certification claims
// ---------------------------------------------------------------------------

describe("attestation accountability", () => {
  it("names the tier and the operator's responsibilities", () => {
    const md = renderAttestationLetter({
      engagementId: "eng-1",
      operator: "op",
      tier: 2,
      target: "t",
      mode: "red",
      objective: "o",
      scope: ["t"],
      testStart: "2026-10-03T00:00:00Z",
      testEnd: "2026-10-03T01:00:00Z",
      findingCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      exclusions: [],
    });
    assert.ok(md.includes("op"), "operator named");
    assert.ok(md.includes("Tier 2 (chain)"), "tier named");
    assert.ok(md.includes("Reviewed the findings"), "responsibilities listed");
    assert.ok(md.includes("Approved the autonomy tier"), "tier approval listed");
    assert.ok(md.includes("Authorized the scope"), "scope authorization listed");
  });
  it("never claims certification or compliance (mirrors the compliance-suite bar)", () => {
    const md = renderAttestationLetter({
      engagementId: "eng-1",
      operator: "op",
      tier: 1,
      target: "t",
      mode: "red",
      objective: "o",
      scope: ["t"],
      testStart: "2026-10-03T00:00:00Z",
      testEnd: "2026-10-03T01:00:00Z",
      findingCounts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      exclusions: [],
    });
    const forbidden = [
      /is PCI DSS compliant/i,
      /PCI DSS (certified|certification)/i,
      /SOC 2 (certified|compliant|certification)/i,
      /ISO 27001 (certified|compliant|certification)/i,
      /hereby certifies that .* is compliant/i,
      /attests that .* (is|are) compliant/i,
    ];
    for (const re of forbidden) {
      assert.ok(!re.test(md), `forbidden claim matched: ${re}`);
    }
    assert.ok(md.includes("does not declare the client compliant"));
    assert.ok(md.includes("Nothing in this letter claims that the testing organization holds"));
  });
});

// ---------------------------------------------------------------------------
// Integration: dispatcher enforcement + engagement wiring
// ---------------------------------------------------------------------------

const textOnly = (text: string): ChatResult => ({ text, toolCalls: [], provider: "fake", model: "fake" });
const toolCall = (name: string, args: Record<string, unknown>): ToolCallRequest => ({
  id: `call-${name}`,
  name,
  arguments: args,
});

function fakeSshTransport() {
  const calls: string[] = [];
  const t: SshTransport = {
    async exec(args) {
      calls.push(args.command);
      return { stdout: "Linux testhost", stderr: "", code: 0, ms: 5 };
    },
    async close() {},
  };
  return { t, calls };
}

/** Scripted LLM: the exploiter fires the given tool calls in order, then stops. */
function scriptedFiring(fires: { name: string; args: Record<string, unknown> }[]) {
  return async (role: AgentRole, messages: ChatMessage[]): Promise<ChatResult> => {
    const has = (s: string) => messages.some((m) => m.content.includes(s));
    if (role === "coordinator") {
      if (has("Transition awaiting sign-off")) return textOnly("SIGN-OFF: approved.");
      if (has("RE-PLAN") || has("Last batch results") || has("OVERRIDE")) {
        return textOnly('```json\n{"tasks": [], "finish": true, "note": "done"}\n```');
      }
      if (has("Return ONLY a JSON block")) {
        return textOnly('```json\n{"tasks": [{"kind": "probe", "brief": "tier test", "attackId": "T1021", "category": "functionality", "maxTurns": 6}], "finish": false, "note": "go"}\n```');
      }
      return textOnly('```json\n{"adversaryProfile": "test", "steps": [{"phase": "exploit", "attackId": "T1021", "description": "tier test"}]}\n```');
    }
    if (role === "recon") return textOnly("recon brief: test host");
    if (role === "reporter") return textOnly('# Report\n\n```json {"findings": []} ```');
    // exploiter task turn
    const sys = messages.find((m) => m.role === "system")?.content ?? "";
    if (sys.includes("Task:") || has("Execute the task now")) {
      const toolMsgs = messages.filter((m) => m.role === "tool").length;
      if (toolMsgs < fires.length) {
        const f = fires[toolMsgs]!;
        return { text: `firing ${f.name}`, toolCalls: [toolCall(f.name, f.args)], provider: "fake", model: "fake" };
      }
      return textOnly("TRIED: done / OBSERVED: done / VERDICT: killed - done");
    }
    return textOnly("idle");
  };
}

const SSH_ARGS = {
  host: "10.9.0.12",
  command: "echo hello",
  attackId: "T1021",
  category: "functionality",
  targetProfile: "linux",
  hypothesis: "tier test",
};

function toolEvents(dir: string, engagementId: string, tool: string) {
  return readFileSync(join(dir, engagementId, "events.jsonl"), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as { action: string; result: string })
    .filter((e) => e.action === tool);
}

describe("dispatcher tier enforcement (integration)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "acct-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const base: EngagementInput = {
    target: "10.9.0.12",
    mode: "red",
    objective: "tier enforcement test",
    roe: { scope: ["10.9.0.12"] },
  };

  it("Tier 0: ssh_exec is DENIED by autonomy tier — transport never touched", async () => {
    const { t, calls } = fakeSshTransport();
    const hostExecutor = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const res = await runEngagement({ ...base, tier: 0 }, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: { verify: async () => true, completeForRole: scriptedFiring([{ name: "ssh_exec", args: SSH_ARGS }]) as never, hostExecutor },
    });
    assert.equal(res.status, "complete");
    const events = toolEvents(dir, res.engagementId, "ssh_exec");
    assert.ok(events.length >= 1, "ssh_exec denial event logged");
    assert.ok(events[0]!.result.includes("DENIED by autonomy tier"), events[0]!.result.slice(0, 200));
    assert.ok(events[0]!.result.includes("Tier 1"), "names the required tier");
    assert.equal(calls.length, 0, "transport never touched — refused before any packet");
  });

  it("Tier 1: first validated step fires, second step on the same target is refused as chaining", async () => {
    const { t, calls } = fakeSshTransport();
    const hostExecutor = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const res = await runEngagement({ ...base, tier: 1 }, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: {
        verify: async () => true,
        completeForRole: scriptedFiring([
          { name: "ssh_exec", args: SSH_ARGS },
          { name: "ssh_exec", args: { ...SSH_ARGS, command: "echo second" } },
        ]) as never,
        hostExecutor,
      },
    });
    assert.equal(res.status, "complete");
    const events = toolEvents(dir, res.engagementId, "ssh_exec");
    assert.ok(events.length >= 2, `expected 2 ssh_exec events, got ${events.length}`);
    assert.ok(!events[0]!.result.startsWith("DENIED"), `first step should fire: ${events[0]!.result.slice(0, 160)}`);
    assert.ok(events[1]!.result.includes("single validated exploit step per target"), `second step refused as chaining: ${events[1]!.result.slice(0, 200)}`);
    assert.equal(calls.length, 1, "only the first step reached the transport");
  });

  it("Tier 2 (staging default): exploit tools fire without tier interference", async () => {
    const { t, calls } = fakeSshTransport();
    const hostExecutor = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const res = await runEngagement({ ...base }, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: {
        verify: async () => true,
        completeForRole: scriptedFiring([
          { name: "ssh_exec", args: SSH_ARGS },
          { name: "ssh_exec", args: { ...SSH_ARGS, command: "echo second" } },
        ]) as never,
        hostExecutor,
      },
    });
    assert.equal(res.status, "complete");
    assert.equal(calls.length, 2, "both steps fired at Tier 2");
  });

  it("production without a named operator refuses to start", async () => {
    await assert.rejects(
      () =>
        runEngagement({ ...base, environment: "production", confirmProduction: true }, {
          mcpToken: "test",
          deepseekApiKey: "test",
          qwenApiKey: "test",
          engagementsDir: dir,
          deps: { verify: async () => true },
        }),
      /named human operator/,
    );
  });

  it("Tier 2 on production without explicit approval refuses to start", async () => {
    await assert.rejects(
      () =>
        runEngagement({ ...base, environment: "production", confirmProduction: true, operatorName: "op", tier: 2 }, {
          mcpToken: "test",
          deepseekApiKey: "test",
          qwenApiKey: "test",
          engagementsDir: dir,
          deps: { verify: async () => true },
        }),
      /Tier 2 \(chain\) on PRODUCTION/,
    );
  });

  it("approval log, safety manifest, and compliance pack carry the tier + accountability", async () => {
    const res = await runEngagement({ ...base, tier: 1, operatorName: "op" }, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: { verify: async () => true, completeForRole: scriptedFiring([]) as never },
    });
    assert.equal(res.status, "complete");
    const eDir = join(dir, res.engagementId);
    // Approval log: tier declared, append-only.
    const approvals = readFileSync(join(eDir, "approvals.jsonl"), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as ApprovalEntry);
    assert.ok(approvals.length >= 1, "approval entries recorded");
    assert.equal(approvals[0]!.kind, "tier-declared");
    assert.equal(approvals[0]!.toTier, 1);
    assert.equal(approvals[0]!.operator, "op");
    // Safety manifest carries the autonomy section.
    const manifest = JSON.parse(readFileSync(join(eDir, "safety-manifest.json"), "utf8")) as {
      autonomy: { tier: number; tierName: string; approvals: ApprovalEntry[] };
    };
    assert.equal(manifest.autonomy.tier, 1);
    assert.equal(manifest.autonomy.tierName, "validate");
    assert.ok(manifest.autonomy.approvals.length >= 1, "approval trail embedded");
    // Compliance pack: section 7 present with the approval log.
    const packMd = readFileSync(join(eDir, "compliance-pack.md"), "utf8");
    assert.ok(packMd.includes("## 7. Autonomy tier & approval log"), "pack section 7 present");
    assert.ok(packMd.includes("Tier 1 (validate)"), "tier named in pack");
    assert.ok(packMd.includes("tier-declared"), "approval log rendered");
  });

  it("production run records production-confirm + tier approvals", async () => {
    const res = await runEngagement(
      { ...base, environment: "production", confirmProduction: true, operatorName: "op", tier: 1 },
      {
        mcpToken: "test",
        deepseekApiKey: "test",
        qwenApiKey: "test",
        engagementsDir: dir,
        deps: { verify: async () => true, completeForRole: scriptedFiring([]) as never },
      },
    );
    assert.equal(res.status, "complete");
    const approvals = readFileSync(join(dir, res.engagementId, "approvals.jsonl"), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as ApprovalEntry);
    const kinds = approvals.map((a) => a.kind);
    assert.ok(kinds.includes("tier-declared"), `tier-declared recorded: ${kinds}`);
    assert.ok(kinds.includes("production-confirm"), `production-confirm recorded: ${kinds}`);
    assert.ok(approvals.every((a) => a.operator === "op"), "every approval names the operator");
  });
});
