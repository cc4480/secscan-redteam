/**
 * Hooks + policy + risk tests (v0.34.0) â€” the three operator-facing controls
 * added by porting AlterEgo's verified designs.
 *
 * What is pinned:
 *   - policy deny wins over allow, and an allow-list defaults to deny
 *   - hooks may deny, may imply fail-closed on timeout, and may rewrite args
 *   - a post-hook can scrub a result before it is stored
 *   - every hook evaluation is reported (never a silent decision)
 *   - risk scoring covers UNKNOWN tools without throwing (the AlterEgo gap)
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { checkToolPolicy, globMatch, parsePolicy } from "../src/policy/rules.js";
import { HookRegistry } from "../src/hooks/index.js";
import { approvalTierFor, explainTrajectory, profileFor, rankTrajectories, scoreTrajectory } from "../src/safety/risk.js";

describe("policy rules", () => {
  it("glob matching is anchored and case-insensitive", () => {
    assert.equal(globMatch("smb_exec *", "smb_exec 10.0.0.5"), true);
    assert.equal(globMatch("SMB_EXEC", "smb_exec"), true);
    assert.equal(globMatch("smb_exec", "smb_exec_extra"), false);
    assert.equal(globMatch("* 10.0.0.5", "ssh_exec 10.0.0.5"), true);
  });

  it("deny wins over allow", () => {
    const rules = parsePolicy({ allow: ["*"], deny: ["smb_exec *"] })!;
    assert.equal(checkToolPolicy(rules, "http_probe", "10.0.0.9").allowed, true);
    const denied = checkToolPolicy(rules, "smb_exec", "10.0.0.5");
    assert.equal(denied.allowed, false);
    assert.match(denied.reason, /deny rule/);
  });

  it("a non-empty allow-list defaults to deny", () => {
    const rules = parsePolicy({ allow: ["http_probe", "nmap_exec"], deny: [] })!;
    assert.equal(checkToolPolicy(rules, "http_probe", "h").allowed, true);
    const denied = checkToolPolicy(rules, "msf_exec", "h");
    assert.equal(denied.allowed, false);
    assert.match(denied.reason, /no allow rule matched/);
  });

  it("no policy means allow, and malformed documents parse to undefined", () => {
    assert.equal(checkToolPolicy(undefined, "anything").allowed, true);
    assert.equal(parsePolicy([1, 2, 3]), undefined);
    assert.equal(parsePolicy("nope"), undefined);
  });
});

describe("hooks", () => {
  it("deny stops the call and reports an evaluation", async () => {
    const hooks = new HookRegistry();
    hooks.registerPre("no-smb", "smb_exec", () => ({ decision: "deny", reason: "client rule: no SMB" }));
    const out = await hooks.runPre("smb_exec", { host: "10.0.0.5" });
    assert.equal(out.allowed, false);
    assert.match(out.reason ?? "", /client rule/);
    assert.equal(out.evaluations.length, 1);
    assert.equal(out.evaluations[0]!.decision, "deny");
  });

  it("modify rewrites args for later hooks and the handler", async () => {
    const hooks = new HookRegistry();
    hooks.registerPre("clip-port", "http_probe", (c) => ({ decision: "modify", args: { ...c.args, port: 443 } }));
    hooks.registerPre("observe", "http_probe", (c) => ({ decision: "allow", reason: `port=${String(c.args["port"])}` }));
    const out = await hooks.runPre("http_probe", { port: 80 });
    assert.equal(out.allowed, true);
    assert.equal(out.args["port"], 443);
    assert.equal(out.evaluations.length, 2);
    assert.equal(out.evaluations[1]!.decision, "allow");
  });

  it("a pre-hook timeout fails closed", async () => {
    const hooks = new HookRegistry();
    hooks.registerPre("slow", "*", () => new Promise(() => {}), 5);
    const out = await hooks.runPre("http_probe", {});
    assert.equal(out.allowed, false);
    assert.equal(out.evaluations[0]!.timedOut, true);
    assert.match(out.reason ?? "", /timed out/);
  });

  it("post-hooks may replace the result and are evaluated/scoped by pattern", async () => {
    const hooks = new HookRegistry();
    hooks.registerPost("scrub", "http_probe", (_c, result) => ({ result: result.replace(/secret-\w+/g, "<redacted>") }));
    hooks.registerPost("ignore-others", "msf_exec", () => ({ result: "should not apply" }));
    const out = await hooks.runPost("http_probe", {}, "value secret-abc end");
    assert.equal(out.result, "value <redacted> end");
    assert.equal(out.evaluations.length, 1);
  });

  it("reports size for readiness output", () => {
    const hooks = new HookRegistry();
    hooks.registerPre("a", "*", () => ({ decision: "allow" }));
    hooks.registerPost("b", "*", () => ({ result: "kept" }));
    assert.equal(hooks.size, 2);
  });
});

describe("risk profiles and arbitration", () => {
  it("curated profiles classify read-only vs executing tools", () => {
    assert.equal(profileFor("http_probe").blastRadius, "external");
    assert.equal(approvalTierFor(profileFor("http_probe")), "routine");
    assert.equal(approvalTierFor(profileFor("get_engagement")), "silent");
    assert.equal(approvalTierFor(profileFor("msf_exec")), "always_ask");
  });

  it("unknown tools get a fail-closed profile and never throw", () => {
    const unknown = profileFor("totally_new_tool");
    assert.equal(unknown.blastRadius, "system");
    assert.equal(unknown.recoverability, 0);
    assert.equal(unknown.unknown, true);
    const score = scoreTrajectory(["totally_new_tool"]);
    assert.equal(score.tier, "explicit_intent");
    assert.match(score.rationale, /unclassified/);
  });

  it("benign trajectories outrank destructive ones", () => {
    const benign = scoreTrajectory(["get_engagement", "list_recent_scans", "query_registry"]);
    const destructive = scoreTrajectory(["msf_exec", "ssh_exec"]);
    assert.ok(benign.score > destructive.score, `${benign.score} vs ${destructive.score}`);
    assert.equal(benign.tier, "auto");
    assert.notEqual(destructive.tier, "auto");
  });

  it("explainTrajectory emits a rollback plan and max blast radius", () => {
    const ex = explainTrajectory(["http_probe", "ssh_exec"]);
    assert.equal(ex.maxBlastRadius, "system");
    assert.ok(ex.rollbackPlan.some((r) => r.startsWith("ssh_exec")));
    assert.equal(ex.steps.length, 2);
  });

  it("ranks candidates safest first", () => {
    const { ranked, recommended } = rankTrajectories([["ssh_exec"], ["get_engagement"]]);
    assert.equal(ranked.length, 2);
    assert.equal(recommended?.tools[0], "get_engagement");
  });
});
