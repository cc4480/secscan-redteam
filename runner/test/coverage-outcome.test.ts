/**
 * Coverage-on-outcome tests (audit 2026-10-09 H2).
 *
 * Battery coverage used to be marked at DISPATCH time: a probe that was
 * refused, denied, or failed in transport still marked its category (and
 * its full-battery cell) covered. These tests pin the fixed semantics at
 * the dispatcher level — coverage (ctx.coverage / ctx.targetCoverage)
 * is recorded only when the probe actually EXECUTED and produced an
 * outcome. ctx.probesUsed stays the attempt counter throughout.
 *
 * All executors/probers are fakes — no network, no subprocesses.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { handleWebTools } from "../src/dispatch/web.js";
import { handleMsfTools } from "../src/dispatch/msf.js";
import { handleHostTools } from "../src/dispatch/host.js";
import { handleNucleiTools } from "../src/dispatch/nuclei.js";
import { MSF_OPERATOR_GRANT_ENV } from "../src/accountability/tiers.js";

const SCOPE = ["10.9.0.12", "secscan.us"];

interface FakeCtxShape {
  probesUsed: number;
  coverage: Set<string>;
  targetCoverage: Map<string, Set<string>>;
}

function baseCtx(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    probesUsed: 0,
    coverage: new Set<string>(),
    targetCoverage: new Map<string, Set<string>>(),
    input: { mode: "red", fullBattery: true, roe: {}, operatorName: "coverage-test" },
    events: { updateState: () => {} },
    hostKill: { aborted: false, controllers: new Set() },
    hosts: SCOPE,
    ...over,
  };
}

function covered(ctx: Record<string, unknown>, category: string): boolean {
  return (ctx as unknown as FakeCtxShape).coverage.has(category);
}
function cellCovered(ctx: Record<string, unknown>, tp: string, category: string): boolean {
  return ((ctx as unknown as FakeCtxShape).targetCoverage.get(tp) ?? new Set()).has(category);
}

const call = (name: string, args: Record<string, unknown>): ToolCallRequest =>
  ({ id: `call-${name}`, name, arguments: args }) as ToolCallRequest;

// ---------------------------------------------------------------------------
// http_probe (dispatch/web.ts)
// ---------------------------------------------------------------------------

describe("coverage on outcome: http_probe", () => {
  const probeCall = (over: Record<string, unknown> = {}): ToolCallRequest =>
    call("http_probe", {
      url: "https://secscan.us/scan",
      category: "logic",
      targetProfile: "secscan",
      attackId: "T1190",
      ...over,
    });

  function webCtx(probe: (req: unknown) => Promise<unknown>): Record<string, unknown> {
    return baseCtx({ opsecCooldown: new Set<string>(), consecutive5xx: 0, prober: { probe } });
  }

  it("successful probe marks coverage + cell; attempt counted", async () => {
    const ctx = webCtx(async () => ({ status: 200, headers: {}, bodySnippet: "ok", ms: 5 }));
    const r = await handleWebTools(ctx as never, "exploiter", "exploit", probeCall(), probeCall().arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /HTTP 200/);
    assert.equal((ctx as unknown as FakeCtxShape).probesUsed, 1);
    assert.ok(covered(ctx, "logic"));
    assert.ok(cellCovered(ctx, "secscan", "logic"));
  });

  it("a 500 response still executed — marks coverage", async () => {
    const ctx = webCtx(async () => ({ status: 503, headers: {}, bodySnippet: "boom", ms: 5 }));
    const r = await handleWebTools(ctx as never, "exploiter", "exploit", probeCall(), probeCall().arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /HTTP 503/);
    assert.ok(covered(ctx, "logic"));
  });

  it("prober refusal (out of scope) marks nothing", async () => {
    const ctx = webCtx(async () => {
      throw new Error("[prober] refused: host evil.example is out of scope");
    });
    const r = await handleWebTools(ctx as never, "exploiter", "exploit", probeCall(), probeCall().arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /^probe failed: \[prober\] refused/);
    assert.equal((ctx as unknown as FakeCtxShape).probesUsed, 1, "attempt counted");
    assert.ok(!covered(ctx, "logic"), "coverage unmarked");
    assert.ok(!cellCovered(ctx, "secscan", "logic"), "cell unmarked");
  });

  it("transport error (DNS/connect) marks nothing", async () => {
    const ctx = webCtx(async () => {
      throw new Error("fetch failed: getaddrinfo ENOTFOUND secscan.us");
    });
    const r = await handleWebTools(ctx as never, "exploiter", "exploit", probeCall(), probeCall().arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /^probe failed:/);
    assert.ok(!covered(ctx, "logic"));
    assert.ok(!cellCovered(ctx, "secscan", "logic"));
  });

  it("ROE-denied technique never reaches the prober and marks nothing", async () => {
    let probed = 0;
    const ctx = webCtx(async () => {
      probed++;
      return { status: 200, headers: {}, bodySnippet: "ok", ms: 5 };
    });
    (ctx["input"] as Record<string, unknown>)["roe"] = { excludedTechniques: ["T1190"] };
    const c = probeCall();
    const r = await handleWebTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /DENIED by ROE/);
    assert.equal(probed, 0);
    assert.ok(!covered(ctx, "logic"));
  });
});

// ---------------------------------------------------------------------------
// msf_exec (dispatch/msf.ts) — operator gate + executor outcomes
// ---------------------------------------------------------------------------

describe("coverage on outcome: msf_exec", () => {
  interface MsfStubResult {
    ok: boolean;
    transport: "msf";
    host: string;
    summary: string;
    output: string;
    ms: number;
    refused?: string;
  }
  const msfResult = (over: Partial<MsfStubResult>): MsfStubResult => ({
    ok: true,
    transport: "msf",
    host: "10.9.0.12",
    summary: "msf stub result",
    output: "",
    ms: 10,
    ...over,
  });

  function msfCtx(result: MsfStubResult, counter: { runs: number }): Record<string, unknown> {
    const exec = {
      killSwitch: { aborted: false },
      search: async () => result,
      suggest: async () => result,
      run: async () => {
        counter.runs++;
        return result;
      },
    };
    return baseCtx({ msfExecutor: exec });
  }

  const runCall = (): ToolCallRequest =>
    call("msf_exec", {
      action: "run",
      host: "10.9.0.12",
      category: "functionality",
      targetProfile: "windows",
      moduleType: "exploit",
      module: "windows/smb/ms17_010_eternalblue",
      attackId: "T1190",
    });

  async function withGrant<T>(grant: boolean, fn: () => Promise<T>): Promise<T> {
    const prev = process.env[MSF_OPERATOR_GRANT_ENV];
    if (grant) process.env[MSF_OPERATOR_GRANT_ENV] = "1";
    else delete process.env[MSF_OPERATOR_GRANT_ENV];
    try {
      return await fn();
    } finally {
      if (prev === undefined) delete process.env[MSF_OPERATOR_GRANT_ENV];
      else process.env[MSF_OPERATOR_GRANT_ENV] = prev;
    }
  }

  it("run without operator grant is DENIED before the executor — coverage unmarked", async () => {
    const counter = { runs: 0 };
    const ctx = msfCtx(msfResult({}), counter);
    const c = runCall();
    const r = await withGrant(false, () =>
      handleMsfTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>),
    );
    assert.ok(r);
    assert.match(r.result, /DENIED by operator gate/);
    assert.equal(counter.runs, 0, "executor never invoked");
    assert.ok(!covered(ctx, "functionality"));
    assert.ok(!cellCovered(ctx, "windows", "functionality"));
  });

  it("granted run whose module executes (marker missed) marks coverage", async () => {
    const counter = { runs: 0 };
    const ctx = msfCtx(
      msfResult({ ok: false, summary: "msf exploit/windows/smb/ms17_010_eternalblue vs 10.9.0.12: completed without marker echo", output: "exploit output" }),
      counter,
    );
    const c = runCall();
    const r = await withGrant(true, () =>
      handleMsfTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>),
    );
    assert.ok(r);
    assert.equal(counter.runs, 1);
    assert.match(r.result, /completed without marker echo/);
    assert.ok(covered(ctx, "functionality"), "executed probe counts even when the exploit missed");
    assert.ok(cellCovered(ctx, "windows", "functionality"));
  });

  it("executor policy refusal marks nothing", async () => {
    const counter = { runs: 0 };
    const ctx = msfCtx(msfResult({ ok: false, refused: "module on denylist", summary: "REFUSED: module on denylist" }), counter);
    const c = runCall();
    const r = await withGrant(true, () =>
      handleMsfTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>),
    );
    assert.ok(r);
    assert.match(r.result, /DENIED by msf safety policy/);
    assert.ok(!covered(ctx, "functionality"));
    assert.ok(!cellCovered(ctx, "windows", "functionality"));
  });

  it("transport failure (msfrpcd unreachable) marks nothing", async () => {
    const counter = { runs: 0 };
    const ctx = msfCtx(
      msfResult({ ok: false, summary: "msfrpcd unreachable at 127.0.0.1:55553: connect ECONNREFUSED" }),
      counter,
    );
    const c = call("msf_exec", {
      action: "search",
      host: "10.9.0.12",
      category: "functionality",
      targetProfile: "windows",
      service: "smb",
      attackId: "T1190",
    });
    const r = await handleMsfTools(ctx as never, "exploiter", "recon", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /unreachable/);
    assert.ok(!covered(ctx, "functionality"));
    assert.ok(!cellCovered(ctx, "windows", "functionality"));
  });

  it("failed search marks nothing; successful search marks coverage", async () => {
    const failCtx = msfCtx(msfResult({ ok: false, summary: "msf search failed: msfrpcd timeout" }), { runs: 0 });
    const c1 = call("msf_exec", { action: "search", host: "10.9.0.12", category: "logic", targetProfile: "windows", service: "smb", attackId: "T1190" });
    const r1 = await handleMsfTools(failCtx as never, "exploiter", "recon", c1, c1.arguments as Record<string, unknown>);
    assert.ok(r1);
    assert.ok(!covered(failCtx, "logic"));

    const okCtx = msfCtx(msfResult({ ok: true, summary: "msf search vs 10.9.0.12: 3 runnable module(s)" }), { runs: 0 });
    const r2 = await handleMsfTools(okCtx as never, "exploiter", "recon", c1, c1.arguments as Record<string, unknown>);
    assert.ok(r2);
    assert.ok(covered(okCtx, "logic"));
    assert.ok(cellCovered(okCtx, "windows", "logic"));
  });
});

// ---------------------------------------------------------------------------
// ssh_exec (dispatch/host.ts)
// ---------------------------------------------------------------------------

describe("coverage on outcome: ssh_exec", () => {
  interface HostStubResult {
    ok: boolean;
    transport: "ssh";
    host: string;
    summary: string;
    output: string;
    ms: number;
    exitCode?: number;
    refused?: string;
  }
  const hostResult = (over: Partial<HostStubResult>): HostStubResult => ({
    ok: true,
    transport: "ssh",
    host: "10.9.0.12",
    summary: "ssh 10.9.0.12: exit=0 in 5ms :: id",
    output: "uid=0(root)",
    ms: 5,
    exitCode: 0,
    ...over,
  });

  function hostCtx(result: HostStubResult): Record<string, unknown> {
    const exec = { killSwitch: { aborted: false }, sshExec: async () => result };
    return baseCtx({ hostExecutor: exec });
  }

  const sshCall = (): ToolCallRequest =>
    call("ssh_exec", {
      host: "10.9.0.12",
      category: "validation",
      targetProfile: "linux",
      command: "id",
      attackId: "T1190",
    });

  it("command that runs (exit 0) marks coverage + cell", async () => {
    const ctx = hostCtx(hostResult({}));
    const c = sshCall();
    const r = await handleHostTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.ok(covered(ctx, "validation"));
    assert.ok(cellCovered(ctx, "linux", "validation"));
  });

  it("command that runs and fails (exit 1) still executed — marks coverage", async () => {
    const ctx = hostCtx(hostResult({ ok: false, exitCode: 1, summary: "ssh 10.9.0.12: exit=1 in 5ms :: id", output: "permission denied" }));
    const c = sshCall();
    const r = await handleHostTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.ok(covered(ctx, "validation"), "exit code proves the command ran on the target");
    assert.ok(cellCovered(ctx, "linux", "validation"));
  });

  it("safety-core refusal marks nothing", async () => {
    const ctx = hostCtx(hostResult({ ok: false, exitCode: undefined, refused: "destructive-command denylist", summary: "REFUSED: destructive-command denylist" }));
    const c = sshCall();
    const r = await handleHostTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /DENIED by host-exec safety core/);
    assert.ok(!covered(ctx, "validation"));
    assert.ok(!cellCovered(ctx, "linux", "validation"));
  });

  it("transport failure (connect refused, no exit code) marks nothing", async () => {
    const ctx = hostCtx(
      hostResult({ ok: false, exitCode: undefined, summary: "ssh 10.9.0.12 failed: connect ECONNREFUSED 10.9.0.12:22", output: "" }),
    );
    const c = sshCall();
    const r = await handleHostTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /failed: connect ECONNREFUSED/);
    assert.equal((ctx as unknown as FakeCtxShape).probesUsed, 1, "attempt counted");
    assert.ok(!covered(ctx, "validation"));
    assert.ok(!cellCovered(ctx, "linux", "validation"));
  });
});

// ---------------------------------------------------------------------------
// nuclei_exec (dispatch/nuclei.ts)
// ---------------------------------------------------------------------------

describe("coverage on outcome: nuclei_exec", () => {
  interface NucleiStubResult {
    summary: string;
    output: string;
    ms: number;
    findings: unknown[];
    refused?: string;
    templatesExecuted?: number;
    timedOut?: boolean;
  }
  const nucleiResult = (over: Partial<NucleiStubResult>): NucleiStubResult => ({
    summary: "Nuclei run against https://10.9.0.12: 0 findings (top severity: none; 4 output lines, 0 parse errors)",
    output: "",
    ms: 20,
    findings: [],
    templatesExecuted: 4,
    ...over,
  });

  function nucleiCtx(resolved: { run?: NucleiStubResult; templates?: NucleiStubResult }): Record<string, unknown> {
    const exec = {
      killSwitch: { aborted: false },
      run: async () => resolved.run ?? nucleiResult({}),
      templates: async () => resolved.templates ?? nucleiResult({ summary: "Nuclei template selection: 2 templates match. Recon-safe — nothing fired." }),
    };
    return baseCtx({
      safety: { rpsPerHost: 2 },
      nucleiExecutor: exec,
      nuclei: { templateExecutions: 0, templatesRun: 0, findings: 0 },
    });
  }

  const nucleiCall = (action: string): ToolCallRequest =>
    call("nuclei_exec", {
      action,
      host: "10.9.0.12",
      category: "functionality",
      targetProfile: "windows",
      attackId: "T1595.002",
    });

  it("successful run marks coverage + cell", async () => {
    const ctx = nucleiCtx({});
    const c = nucleiCall("run");
    const r = await handleNucleiTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.ok(!/DENIED/.test(r.result));
    assert.ok(covered(ctx, "functionality"));
    assert.ok(cellCovered(ctx, "windows", "functionality"));
  });

  it("policy-refused run (denied tag) marks nothing", async () => {
    const ctx = nucleiCtx({ run: nucleiResult({ refused: "DENIED by nuclei safety policy: tag 'dos' is denied", summary: "REFUSED: tag denied" }) });
    const c = nucleiCall("run");
    const r = await handleNucleiTools(ctx as never, "exploiter", "exploit", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /DENIED by nuclei safety policy/);
    assert.ok(!covered(ctx, "functionality"));
    assert.ok(!cellCovered(ctx, "windows", "functionality"));
  });

  it("missing-binary refusal (templates) marks nothing", async () => {
    const ctx = nucleiCtx({
      templates: nucleiResult({ refused: "nuclei binary not available", summary: "REFUSED: nuclei binary not available" }),
    });
    const c = nucleiCall("templates");
    const r = await handleNucleiTools(ctx as never, "recon", "recon", c, c.arguments as Record<string, unknown>);
    assert.ok(r);
    assert.match(r.result, /DENIED by nuclei safety policy/);
    assert.ok(!covered(ctx, "functionality"));
    assert.ok(!cellCovered(ctx, "windows", "functionality"));
  });
});
