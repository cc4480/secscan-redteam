/**
 * External-tool bridge tests (v0.32.0): john, sqlmap, ffuf, gobuster, nikto.
 *
 * The policy is pure, so almost none of this needs a subprocess. What is pinned
 * is the SAFETY contract, not the happy path:
 *
 *   - the agent never reaches a command line: any agent-supplied flag at all is
 *     refused, not just the ones on a denylist
 *   - the flags that hand over a shell, write to the target, extract data or
 *     conceal the tester are refused by name, with the reason
 *   - the tier is the SELECTED PROFILE's, because five tools share ten profile
 *     names between them and the tool name alone cannot classify the risk
 *   - john is treated as OFFLINE: it must not be scope-checked or rate-limited
 *     like a network tool, and its identify mode must receive no target
 *
 * The argv assertions are the load-bearing ones. Every bug found while wiring
 * this bridge was an argv bug — john got `--wordlist` with no value, then a
 * stray `--`, then `--show` with no file — and every one of them would have
 * looked like "the tool is broken" rather than "the builder is wrong".
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  XTOOLS,
  XTOOLS_BY_ID,
  XTOOL_DENIED_FLAGS,
  findProfile,
  checkXToolFlags,
  buildXToolArgv,
} from "../src/xtool/registry.js";
import { parseFfufJsonl, parseGobusterText, runXTool } from "../src/xtool/executor.js";
import { toolMinTier } from "../src/accountability/tiers.js";
import { XTOOL_DEFS, XTOOL_DEFS_BY_NAME } from "../src/tools/xtool.js";

describe("xtool registry", () => {
  it("registers all five tools with unique ids and profiles", () => {
    assert.equal(XTOOLS.length, 5);
    assert.deepEqual(XTOOLS.map((t) => t.id).sort(), ["ffuf", "gobuster", "john", "nikto", "sqlmap"]);
    for (const spec of XTOOLS) {
      assert.ok(spec.profiles.length > 0, `${spec.id} has profiles`);
      const ids = spec.profiles.map((p) => p.id);
      assert.equal(new Set(ids).size, ids.length, `${spec.id} profile ids unique`);
    }
  });

  it("gives every tool at least one profile that cracks/scans nothing at Tier 0 or 1", () => {
    for (const spec of XTOOLS) {
      assert.ok(spec.profiles.some((p) => p.minTier <= 1), `${spec.id} has a low-tier profile`);
    }
  });

  it("exposes one tool definition per spec, named <id>_exec", () => {
    assert.equal(XTOOL_DEFS.length, 5);
    for (const spec of XTOOLS) assert.ok(XTOOL_DEFS_BY_NAME.has(`${spec.id}_exec`), `${spec.id}_exec`);
  });

  it("never claims a binary is missing in its description", () => {
    // The setup text is a FALLBACK for when a binary is absent. Appending it
    // bare made all five descriptions open with "john not found." and friends
    // even on a machine where every binary was installed and working — a
    // teammate reading the schema caught it, which is exactly how it would have
    // reached a user. Availability is what `probe` reports; a schema must never
    // assert it either way.
    for (const t of XTOOL_DEFS) {
      const opening = t.description.slice(0, 120);
      assert.ok(
        !/^(john|sqlmap|ffuf|gobuster|nikto) not found/i.test(opening),
        `${t.name} must not open by asserting its binary is missing`,
      );
      assert.ok(
        /If \w+ is not installed/i.test(t.description),
        `${t.name} must frame its setup text as a fallback, not a fact`,
      );
    }
  });
});

describe("the agent never reaches the command line", () => {
  it("refuses ANY agent-supplied flag, denied or merely unknown", () => {
    assert.match(checkXToolFlags(["--anything"])!, /does not accept agent-supplied flags/);
    assert.match(checkXToolFlags(["--verbose"])!, /does not accept agent-supplied flags/);
    assert.equal(checkXToolFlags(undefined), null);
    assert.equal(checkXToolFlags([]), null);
  });

  it("refuses the flags that change the target or conceal the tester", () => {
    // -x is on the denylist (it swaps in an external SQLi engine), so it gets
    // the specific denial rather than the generic one.
    for (const f of ["--os-shell", "--file-write", "--dump", "--proxy", "--tor", "-x"]) {
      assert.ok(XTOOL_DENIED_FLAGS.includes(f), `${f} on the denylist`);
      assert.match(checkXToolFlags([f])!, /may never run through the bridge/);
    }
  });

  it("does not refuse a value that merely CONTAINS a denied flag", () => {
    // --dumpsomething is not --dump; a spurious refusal is its own bug.
    assert.match(checkXToolFlags(["--dumpsomething"])!, /does not accept agent-supplied flags/);
    assert.equal(checkXToolFlags(["dumps"])?.includes("may never run") ?? false, false);
  });
});

describe("argv construction", () => {
  const john = XTOOLS_BY_ID.get("john")!;
  const ffuf = XTOOLS_BY_ID.get("ffuf")!;
  const sqlmap = XTOOLS_BY_ID.get("sqlmap")!;

  it("john identify takes NO target (it lists formats and reads no file)", () => {
    const argv = buildXToolArgv(john, {
      bin: "john.exe", target: "/tmp/hashes.txt",
      profile: findProfile(john, "identify")!, timeoutS: 60,
    });
    assert.deepEqual(argv, ["john.exe", "--list=formats"]);
  });

  it("john wordlist passes --wordlist=<path> AND the hash file", () => {
    const argv = buildXToolArgv(john, {
      bin: "john.exe", target: "h.txt", wordlist: "w.txt",
      profile: findProfile(john, "wordlist")!, timeoutS: 60,
    });
    assert.deepEqual(argv, ["john.exe", "--wordlist=w.txt", "h.txt"]);
    assert.ok(!argv.includes("--"), "no stray end-of-options marker");
  });

  it("john show passes the hash file positionally", () => {
    const argv = buildXToolArgv(john, {
      bin: "john.exe", target: "h.txt",
      profile: findProfile(john, "show")!, timeoutS: 60,
    });
    assert.deepEqual(argv, ["john.exe", "--show", "h.txt"]);
  });

  it("ffuf gets -w <wordlist> and -u <target> as separate argv elements", () => {
    const argv = buildXToolArgv(ffuf, {
      bin: "ffuf.exe", target: "https://h/FUZZ", wordlist: "w.txt",
      profile: findProfile(ffuf, "dirs")!, timeoutS: 60,
    });
    assert.equal(argv[0], "ffuf.exe");
    assert.equal(argv[argv.indexOf("-w") + 1], "w.txt");
    assert.equal(argv[argv.indexOf("-u") + 1], "https://h/FUZZ");
  });

  it("sqlmap puts the target after -u and never a bare --", () => {
    const argv = buildXToolArgv(sqlmap, {
      bin: "sqlmap", target: "https://h/?id=1",
      profile: findProfile(sqlmap, "detect")!, timeoutS: 60,
    });
    assert.equal(argv[argv.indexOf("-u") + 1], "https://h/?id=1");
    assert.ok(!argv.includes("--"), "sqlmap rejects a bare --");
  });

  it("a target beginning with '-' cannot be read as a flag", () => {
    const argv = buildXToolArgv(ffuf, {
      bin: "ffuf.exe", target: "--os-shell", wordlist: "w.txt",
      profile: findProfile(ffuf, "dirs")!, timeoutS: 60,
    });
    assert.equal(argv[argv.indexOf("-u") + 1], "--os-shell");
    assert.equal(argv.filter((a) => a === "--os-shell").length, 1, "appears once, as the target value");
  });
});

describe("tier is the SELECTED PROFILE's, not the tool name", () => {
  it("a probe runs nothing, so it is Tier 0", () => {
    for (const id of ["john", "sqlmap", "ffuf", "gobuster", "nikto"]) {
      assert.equal(toolMinTier(`${id}_exec`, { action: "probe" }), 0, id);
    }
  });

  it("john incremental is Tier 2 while its read-only modes are Tier 0", () => {
    assert.equal(toolMinTier("john_exec", { action: "run", profile: "incremental" }), 2);
    assert.equal(toolMinTier("john_exec", { action: "run", profile: "identify" }), 0);
    assert.equal(toolMinTier("john_exec", { action: "run", profile: "show" }), 0);
  });

  it("sqlmap detection is Tier 1", () => {
    assert.equal(toolMinTier("sqlmap_exec", { action: "run", profile: "detect" }), 1);
  });
});

describe("output parsing", () => {
  it("reads ffuf JSONL into endpoint findings", () => {
    const out = '{"url":"https://h/admin","status":200,"length":1234}\nnot json\n{"url":"https://h/api","status":403,"length":99}\n';
    const f = parseFfufJsonl(out, "https://h");
    assert.equal(f.length, 2, "the non-JSON line is skipped, not thrown on");
    assert.equal(f[0]!.kind, "endpoint");
    assert.match(f[0]!.detail, /HTTP 200/);
  });

  it("reads gobuster text into path findings, skipping banners", () => {
    const f = parseGobusterText("===============================================================\n/admin                (Status: 301)\n\n/api  (Status: 200)\n", "https://h");
    assert.equal(f.length, 2);
    assert.equal(f[0]!.kind, "path");
  });

  it("returns nothing for empty output rather than throwing", () => {
    assert.deepEqual(parseFfufJsonl("", "t"), []);
    assert.deepEqual(parseGobusterText("", "t"), []);
  });
});

describe("probe runs nothing", () => {
  it("reports binary + profiles without spawning for a run", async () => {
    let spawned = false;
    const r = await runXTool(
      XTOOLS_BY_ID.get("ffuf")!,
      { action: "probe", target: "", profileId: "dirs", rateLimit: 5, timeoutS: 10 },
      async () => {
        spawned = true;
        return { stdout: "", stderr: "", code: 0, timedOut: false };
      },
    );
    assert.ok(r.ok);
    assert.match(r.message, /profiles:/);
    assert.equal(spawned, false, "probe must not spawn anything");
  });
});
