/**
 * Scope enforcement in the nmap and xtool dispatch handlers.
 *
 * This pins a CRITICAL fix. The web prober, scan_url, host-exec, nuclei and msf
 * all validated the target against ctx.hosts before any packet; nmap_exec and
 * the four network xtools (sqlmap/ffuf/gobuster/nikto) did NOT — their executors
 * even documented that "the dispatch layer owns the ROE host check", a check
 * that was never written. An agent could point a port sweep or a scanner at any
 * host/IP/CIDR out of scope, contradicting the safety manifest's
 * "out-of-scope targets refused before any packet".
 *
 * The test asserts the denial path directly: an out-of-scope host must be
 * refused before the executor is touched, and an in-scope host must reach the
 * executor with the scope still intact.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { handleNmapTools } from "../src/dispatch/nmap.js";
import { handleXTool } from "../src/dispatch/xtool.js";
import { urlInScope } from "../src/gate.js";
import type { Ctx } from "../src/context.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";

function baseCtx(over: Record<string, unknown> = {}): Ctx {
  return {
    input: { mode: "red", roe: { excludedTechniques: [], scope: ["seclayer.app"] } },
    tier: { current: 1 },
    hosts: ["seclayer.app"],
    probesUsed: 0,
    hostKill: { controllers: new Set() },
    safety: { rpsPerHost: 5 },
    ...over,
  } as unknown as Ctx;
}

const call = (name: string): ToolCallRequest => ({ name } as unknown as ToolCallRequest);

describe("nmap_exec scope enforcement", () => {
  it("refuses an out-of-scope host before the executor runs", async () => {
    let scanned: string | null = null;
    const ctx = baseCtx({
      nmapExecutor: { scan: async (a: { target: string }) => { scanned = a.target; return { ok: true, message: "ok", run: { hosts: [] } }; } },
    });
    const r = await handleNmapTools(ctx, "recon", "recon", call("nmap_exec"), {
      action: "scan",
      host: "evil.example",
      targetProfile: "linux",
      profile: "quick",
    });
    assert.ok(r, "handled");
    assert.match(r.result, /DENIED by scope/, "the refusal is a scope denial");
    assert.match(r.result, /evil\.example/, "names the refused host");
    assert.equal(scanned, null, "the executor was never invoked");
  });

  it("lets an in-scope host through to the executor", async () => {
    let scanned: string | null = null;
    const ctx = baseCtx({
      nmapExecutor: { scan: async (a: { target: string }) => { scanned = a.target; return { ok: true, message: "ok", run: { hosts: [] } }; } },
    });
    const r = await handleNmapTools(ctx, "recon", "recon", call("nmap_exec"), {
      action: "scan",
      host: "seclayer.app",
      targetProfile: "linux",
      profile: "quick",
    });
    assert.ok(r);
    assert.ok(!/DENIED/.test(r.result), "in-scope is not denied");
    assert.equal(scanned, "seclayer.app", "the executor received the in-scope host");
  });

  it("does not scope-gate the read-only 'profiles' listing", async () => {
    let profiles = false;
    const ctx = baseCtx({ nmapExecutor: { profiles: async () => { profiles = true; return { message: "Profiles" }; } } });
    const r = await handleNmapTools(ctx, "recon", "recon", call("nmap_exec"), { action: "profiles", host: "anything.example", targetProfile: "linux" });
    assert.ok(r);
    assert.ok(!/DENIED/.test(r.result));
    assert.ok(profiles, "profile listing proceeds without a target");
  });
});

describe("network xtool scope enforcement", () => {
  it("refuses an out-of-scope sqlmap target before the executor runs", async () => {
    let ran = false;
    const ctx = baseCtx({ xtool: {} }); // runXTool is imported from ../xtool and not easily injected; assert the denial happens first
    // sqlmap_exec requires the real runXTool only past the scope gate, so we
    // assert the denial is returned without needing a working sqlmap install.
    const r = await handleXTool(ctx, "recon", "recon", call("sqlmap_exec"), {
      action: "run",
      host: "https://evil.example/id",
      targetProfile: "linux",
    });
    assert.ok(r, "handled");
    assert.match(r.result, /DENIED by scope/, "refused as out of scope");
    assert.match(r.result, /evil\.example/);
  });

  it("accepts an in-scope URL host", async () => {
    // The scope predicate the handler uses is `urlInScope(host, ctx.hosts) ||
    // validateHostTarget(host, ctx.hosts).ok`. Pin the URL half hermetically
    // rather than driving runXTool, which would spawn sqlmap against a live
    // target — a network side effect a unit test must never have.
    assert.equal(urlInScope("https://seclayer.app/x", ["seclayer.app"]), true);
    assert.equal(urlInScope("https://evil.example/x", ["seclayer.app"]), false);
    assert.equal(urlInScope("seclayer.app", ["seclayer.app"]), false, "bare host is not a URL — validateHostTarget covers that half");
  });

  it("never scope-gates john (offline: host is a hash-file path)", async () => {
    const ctx = baseCtx();
    const r = await handleXTool(ctx, "recon", "recon", call("john_exec"), {
      action: "run",
      host: "C:\\Users\\someone\\hashes.txt",
    });
    assert.ok(r);
    assert.ok(!/DENIED by scope/.test(r.result), "john is exempt from the network scope check");
  });
});
