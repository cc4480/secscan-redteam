/**
 * Live engagement registry + executor tool surface (v0.30.0).
 *
 * These tests pin the CONTRACT that makes the 26 executor tools safe to expose:
 *
 *   1. A tool is reachable only while its engagement is live; a finished one
 *      reports "not running" rather than serving a stale context whose
 *      executors and kill switch no longer belong to anything.
 *   2. The role is DERIVED from the phase and is not a parameter. That is what
 *      stops an operator from reaching the exploit toolset during recon by
 *      naming a role — the whole reason this surface adds reach without adding
 *      authority.
 *   3. engagementId is required and never defaulted. A tool call that silently
 *      resolved to "the one running engagement" would act against an engagement
 *      the caller never named.
 *   4. No executor tool may shadow a cockpit tool. abort_engagement exists in
 *      both sets, and the cockpit version is strictly more capable (it works
 *      cross-process via abort.json), so it must win.
 *
 * The live registry is process-global, so every test here registers and
 * unregisters its own id and never relies on another test's state.
 */
import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  registerLive,
  unregisterLive,
  getLive,
  listLive,
  roleForPhase,
  dispatchLiveTool,
} from "../src/live.js";
import { EXEC_TOOLS, EXEC_TOOLS_BY_NAME, EXEC_TOOL_NAMES } from "../src/ui/mcp-exec.js";
import { TOOLS } from "../src/ui/mcp-tools.js";
import type { Ctx } from "../src/context.js";

const ID = "eng-test-live-0001";

/** The minimum a Ctx needs for the registry paths under test. */
function fakeCtx(phase: string): Ctx {
  return {
    events: { snapshot: { phase } },
    tier: { current: 1, declared: 1, chainSteps: new Map() },
    safety: { environment: "staging" },
    hosts: ["example.test"],
    startedAt: Date.now(),
    actions: 0,
  } as unknown as Ctx;
}

afterEach(() => {
  unregisterLive(ID);
});

describe("live engagement registry", () => {
  it("getLive returns nothing for an id that was never registered", () => {
    assert.equal(getLive("eng-never-registered"), undefined);
  });

  it("registers, reports and withdraws a context", () => {
    registerLive(ID, fakeCtx("recon"));
    assert.ok(getLive(ID), "registered");
    const rows = listLive();
    const row = rows.find((r) => r.engagementId === ID);
    assert.ok(row, "listed while live");
    assert.equal(row.phase, "recon");
    assert.equal(row.environment, "staging");
    unregisterLive(ID);
    assert.equal(getLive(ID), undefined, "withdrawn");
    assert.equal(listLive().find((r) => r.engagementId === ID), undefined);
  });

  it("unregistering an id that was never registered is a no-op", () => {
    assert.doesNotThrow(() => unregisterLive("eng-not-here"));
  });
});

describe("role is derived from phase, never passed in", () => {
  it("maps each phase to the specialist that owns it", () => {
    assert.equal(roleForPhase("recon"), "recon");
    assert.equal(roleForPhase("exploit"), "exploiter");
  });

  it("gives non-specialist phases the coordinator (no escalation by naming)", () => {
    for (const p of ["authorize", "plan", "report", "done", "blocked", "halted"] as const) {
      assert.equal(roleForPhase(p), "coordinator", `phase ${p}`);
    }
  });

  it("dispatchLiveTool exposes no role argument to override", () => {
    // Three parameters: id, tool name, args. A fourth would be a role knob.
    assert.equal(dispatchLiveTool.length, 3);
  });
});

describe("executor tool surface", () => {
  it("exposes the expected tools and no duplicates", () => {
    const dupes = EXEC_TOOL_NAMES.filter((n, i) => EXEC_TOOL_NAMES.indexOf(n) !== i);
    assert.deepEqual(dupes, [], "no name exposed twice");
    assert.equal(EXEC_TOOLS.length, EXEC_TOOLS_BY_NAME.size);
  });

  it("carries the tools an operator actually needs on command", () => {
    for (const n of ["nuclei_exec", "msf_exec", "http_probe", "burst_probe", "scan_url", "ssh_exec", "ad_enum"]) {
      assert.ok(EXEC_TOOLS_BY_NAME.has(n), `missing ${n}`);
    }
  });

  it("never shadows a cockpit tool", () => {
    const cockpit = new Set(TOOLS.map((t) => t.name));
    const shadowed = EXEC_TOOL_NAMES.filter((n) => cockpit.has(n));
    assert.deepEqual(shadowed, [], "abort_engagement must resolve to the cockpit version");
  });

  it("requires engagementId on every tool, and never defaults it", async () => {
    for (const t of EXEC_TOOLS) {
      const schema = t.inputSchema as { required?: string[] };
      assert.ok(schema.required?.includes("engagementId"), `${t.name} must require engagementId`);
    }
    // Called without one it must refuse rather than pick an engagement.
    await assert.rejects(() => EXEC_TOOLS_BY_NAME.get("nuclei_exec")!.run({}), /engagementId is required/);
  });

  it("refuses a tool call against an engagement that is not live", async () => {
    await assert.rejects(
      () => EXEC_TOOLS_BY_NAME.get("http_probe")!.run({ engagementId: "eng-not-running" }),
      /is not running in this process/,
    );
  });
});
