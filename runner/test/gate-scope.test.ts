/**
 * Scope-wide ownership gate regression tests (audit 2026-10-09, Batch 1
 * items 2+3): every host in the ROE scope must be ownership-verified, and
 * the --local-sandbox skip is a per-host private/loopback exemption that
 * never covers a public scope host. No network — the server check is an
 * injected fake, engagements run with dryRunAgents into a tmp dir.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  checkAuthorization,
  checkScopeAuthorization,
  type VerifyFn,
} from "../src/gate.js";
import { recheckVerified } from "../src/dispatch/prelude.js";
import { readState } from "../src/events.js";
import { runEngagement } from "../src/phases.js";
import type { Ctx } from "../src/context.js";
import type { EngagementInput } from "../src/types.js";

const CFG = { mcpEndpoint: "https://x", mcpToken: "t" };

/** A fake server check: verifies only the listed domains; records its calls. */
function verifyOnly(verified: readonly string[]) {
  const calls: string[] = [];
  const fn: VerifyFn = async (domain) => {
    calls.push(domain);
    return verified.includes(domain);
  };
  return { fn, calls };
}

describe("checkScopeAuthorization (every scope host)", () => {
  it("blocks when hosts[1] is unverified and names it; every host is checked", async () => {
    const { fn, calls } = verifyOnly(["a.example"]);
    const v = await checkScopeAuthorization(["a.example", "b.example"], CFG, fn);
    assert.equal(v.allowed, false);
    assert.match(v.reason ?? "", /b\.example/);
    assert.deepEqual([...calls].sort(), ["a.example", "b.example"]);
    assert.equal(v.hosts.find((h) => h.host === "b.example")?.basis, "none");
  });

  it("allows when every scope host is server-verified", async () => {
    const { fn } = verifyOnly(["a.example", "b.example"]);
    const v = await checkScopeAuthorization(["a.example", "b.example"], CFG, fn);
    assert.equal(v.allowed, true);
    assert.deepEqual(v.hosts.map((h) => h.basis), ["server", "server"]);
  });

  it("a host whose check throws blocks the scope (fail closed) and is named", async () => {
    const throwing: VerifyFn = async (domain) => {
      if (domain === "b.example") throw new Error("simulated gate failure");
      return true;
    };
    const v = await checkScopeAuthorization(["a.example", "b.example"], CFG, throwing);
    assert.equal(v.allowed, false);
    assert.match(v.reason ?? "", /b\.example/);
  });

  it("single-host scope behaves exactly like checkAuthorization", async () => {
    const yes: VerifyFn = async () => true;
    const no: VerifyFn = async () => false;
    assert.equal((await checkScopeAuthorization(["secscan.us"], CFG, yes)).allowed, true);
    const denied = await checkScopeAuthorization(["secscan.us"], CFG, no);
    assert.equal(denied.allowed, false);
    assert.match(denied.reason ?? "", /secscan\.us is not ownership-verified/);
    // And the legacy entry point is unchanged.
    assert.equal((await checkAuthorization("secscan.us", CFG, yes)).allowed, true);
    assert.equal((await checkAuthorization("secscan.us", CFG, no)).allowed, false);
  });

  it("empty scope is denied", async () => {
    const { fn } = verifyOnly([]);
    const v = await checkScopeAuthorization([], CFG, fn);
    assert.equal(v.allowed, false);
  });
});

describe("local-sandbox composition (per-host exemption, never blanket)", () => {
  it("mixed scope: the public host is NOT skipped — it must verify", async () => {
    const { fn, calls } = verifyOnly([]);
    const v = await checkScopeAuthorization(["127.0.0.1", "victim.example"], CFG, fn, {
      allowLocalSandbox: true,
    });
    assert.equal(v.allowed, false);
    assert.match(v.reason ?? "", /victim\.example/);
    assert.ok(calls.includes("victim.example"), "server check must run for the public host");
    assert.ok(!calls.includes("127.0.0.1"), "loopback host needs no server call");
    assert.equal(v.hosts.find((h) => h.host === "127.0.0.1")?.basis, "local-sandbox");
  });

  it("mixed scope: verified public host + exempt loopback → allowed", async () => {
    const { fn } = verifyOnly(["api.example"]);
    const v = await checkScopeAuthorization(["127.0.0.1", "api.example"], CFG, fn, {
      allowLocalSandbox: true,
    });
    assert.equal(v.allowed, true);
    assert.equal(v.hosts.find((h) => h.host === "127.0.0.1")?.basis, "local-sandbox");
    assert.equal(v.hosts.find((h) => h.host === "api.example")?.basis, "server");
  });

  it("all-private scope: skip still works and verify is never called", async () => {
    const { fn, calls } = verifyOnly([]);
    const v = await checkScopeAuthorization(["127.0.0.1", "192.168.1.10"], CFG, fn, {
      allowLocalSandbox: true,
    });
    assert.equal(v.allowed, true);
    assert.deepEqual(calls, []);
    assert.deepEqual(v.hosts.map((h) => h.basis), ["local-sandbox", "local-sandbox"]);
  });

  it("without the flag, a loopback host gets no exemption (server check, fail closed)", async () => {
    const { fn, calls } = verifyOnly([]);
    const v = await checkScopeAuthorization(["127.0.0.1", "api.example"], CFG, fn);
    assert.equal(v.allowed, false);
    assert.ok(calls.includes("127.0.0.1"), "no flag → loopback faces the server check like any host");
  });
});

describe("runEngagement: scope-wide authorization end-to-end", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rt-gate-scope-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const run = (inp: EngagementInput, verify: VerifyFn, extra: Record<string, unknown> = {}) =>
    runEngagement(inp, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      dryRunAgents: true,
      deps: { verify },
      ...extra,
    });

  const input = (scope: string[]): EngagementInput => ({
    target: scope[0]!,
    mode: "red",
    objective: "gate scope regression",
    roe: { scope },
  });

  it("blocked when the second scope host is unverified — reason names it", async () => {
    const { fn } = verifyOnly(["secscan.us"]);
    const res = await run(input(["secscan.us", "other.example"]), fn);
    assert.equal(res.status, "blocked");
    assert.match(res.blockedReason ?? "", /other\.example/);
    const state = readState(join(dir, res.engagementId));
    assert.equal(state?.verified, false);
  });

  it("completes when every scope host is verified; proof names them all", async () => {
    const { fn } = verifyOnly(["secscan.us", "other.example"]);
    const res = await run(input(["secscan.us", "other.example"]), fn);
    assert.equal(res.status, "complete");
    const state = readState(join(dir, res.engagementId));
    assert.equal(state?.verified, true);
    assert.match(state?.verificationProof ?? "", /secscan\.us/);
    assert.match(state?.verificationProof ?? "", /other\.example/);
  });

  it("mixed sandbox scope end-to-end: unverified public host blocks despite loopback host[0]", async () => {
    const { fn } = verifyOnly([]);
    const res = await run(input(["127.0.0.1", "other.example"]), fn, { localSandbox: true });
    assert.equal(res.status, "blocked");
    assert.match(res.blockedReason ?? "", /other\.example/);
  });

  it("mixed sandbox scope end-to-end: verified public host completes", async () => {
    const { fn } = verifyOnly(["other.example"]);
    const res = await run(input(["127.0.0.1", "other.example"]), fn, { localSandbox: true });
    assert.equal(res.status, "complete");
  });
});

describe("recheckVerified (dispatch-time, same per-host model)", () => {
  const fakeCtx = (hosts: string[], verify: VerifyFn, verifiedAt?: string): Ctx =>
    ({
      hosts,
      domain: hosts[0],
      config: { mcpEndpoint: "https://x", mcpToken: "t", localSandbox: false },
      deps: { verify },
      verifiedAt,
    }) as unknown as Ctx;

  it("re-checks every scope host, not just hosts[0]", async () => {
    const { fn, calls } = verifyOnly(["a.example"]);
    const ctx = fakeCtx(["a.example", "b.example"], fn);
    assert.equal(await recheckVerified(ctx), false);
    assert.ok(calls.includes("b.example"));
  });

  it("passes when all hosts verify and stamps verifiedAt; fresh cache short-circuits", async () => {
    const { fn, calls } = verifyOnly(["a.example", "b.example"]);
    const ctx = fakeCtx(["a.example", "b.example"], fn);
    assert.equal(await recheckVerified(ctx), true);
    assert.ok(ctx.verifiedAt);
    const callsAfterFirst = calls.length;
    assert.equal(await recheckVerified(ctx), true);
    assert.equal(calls.length, callsAfterFirst, "5-minute cache must not re-hit the server");
  });
});
