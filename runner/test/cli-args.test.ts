/**
 * CLI argument-parsing tests (audit batch 3 — the parse layer that gates
 * real engagements had zero tests).
 *
 * buildInput() turns argv into an EngagementInput and fails loud
 * (console.error + exit 2) on invalid safety-relevant values. These tests
 * pin that contract: invalid values never silently default into something
 * more permissive, and valid values parse exactly as documented in the
 * --help text (see usage()).
 *
 * process.argv / console.error / process.exit are stubbed per test and
 * restored after each — no shelling out, no network.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { arg, argAll, buildInput, flag, parseBlackout, parseLogRotationArgs } from "../src/cli/args.js";

/** process.exit stub: throws so error paths are assertable in-process. */
class ExitSignal extends Error {
  constructor(public code: number) {
    super(`process.exit(${code})`);
  }
}

const originalArgv = process.argv;
const originalExit = process.exit;
const originalError = console.error;
let stderr: string[];

beforeEach(() => {
  stderr = [];
  console.error = (...parts: unknown[]) => {
    stderr.push(parts.map(String).join(" "));
  };
  process.exit = ((code?: number) => {
    throw new ExitSignal(code ?? 0);
  }) as typeof process.exit;
});

afterEach(() => {
  process.argv = originalArgv;
  process.exit = originalExit;
  console.error = originalError;
});

function argv(...args: string[]): void {
  process.argv = ["node", "redteam-runner", "start", ...args];
}

function validBase(): string[] {
  return ["--target", "example.com", "--mode", "red", "--objective", "check it", "--scope", "example.com"];
}

/** Run fn, expecting it to die via process.exit(code); returns the code. */
function expectExit(fn: () => unknown, code: number): void {
  assert.throws(fn, (err: unknown) => err instanceof ExitSignal && (err as ExitSignal).code === code);
}

describe("arg / argAll / flag helpers", () => {
  it("arg returns the next token; absent flag → undefined", () => {
    argv("--tier", "1");
    assert.equal(arg("--tier"), "1");
    assert.equal(arg("--missing"), undefined);
  });

  it("arg at the very end of argv yields undefined (no fabricated value)", () => {
    argv("--tier");
    assert.equal(arg("--tier"), undefined);
  });

  it("argAll collects repeated flags in order and skips a trailing flag with no value", () => {
    argv("--scope", "a.com", "--mode", "red", "--scope", "b.com", "--scope");
    assert.deepEqual(argAll("--scope"), ["a.com", "b.com"]);
  });

  it("flag() is presence-only and defaults to false for the safety booleans", () => {
    argv("--confirm-production");
    assert.equal(flag("--confirm-production"), true);
    assert.equal(flag("--confirm-tier2-production"), false);
    assert.equal(flag("--local-sandbox"), false);
    assert.equal(flag("--dry-run"), false);
  });
});

describe("buildInput — required arguments", () => {
  it("missing required flags print usage and exit 2", () => {
    const cases: Array<[string, string[]]> = [
      ["target", ["--mode", "red", "--objective", "x", "--scope", "a.com"]],
      ["mode", ["--target", "a.com", "--objective", "x", "--scope", "a.com"]],
      ["objective", ["--target", "a.com", "--mode", "red", "--scope", "a.com"]],
      ["scope", ["--target", "a.com", "--mode", "red", "--objective", "x"]],
    ];
    for (const [name, args] of cases) {
      argv(...args);
      expectExit(() => buildInput(), 2);
      assert.match(stderr.join("\n"), /Usage:/, `missing ${name} should print usage`);
    }
  });
});

describe("buildInput — valid invocations parse as documented", () => {
  it("minimal invocation", () => {
    argv(...validBase());
    const input = buildInput();
    assert.equal(input.target, "example.com");
    assert.equal(input.mode, "red");
    assert.equal(input.objective, "check it");
    assert.deepEqual(input.roe.scope, ["example.com"]);
    assert.equal(input.fullBattery, false);
    assert.equal(input.targets, undefined);
    assert.equal(input.environment, undefined);
    assert.equal(input.tier, undefined);
    assert.equal(input.confirmProduction, false);
    assert.equal(input.confirmTier2Production, false);
    assert.equal(input.operatorName, undefined);
    assert.equal(input.client, undefined);
    assert.equal(input.roe.excludedTechniques, null);
  });

  it("kitchen-sink invocation: roe, blackouts, confirmations, operator, env, tier", () => {
    argv(
      "--target", "Example.COM",
      "--mode", "black",
      "--objective", "assess",
      "--scope", "example.com",
      "--scope", "api.example.com",
      "--exclude", "T1046",
      "--exclude", "t1498",
      "--blackout", "02:00-04:00 America/Chicago",
      "--blackout", "23:00-23:30",
      "--stop", "status page goes red",
      "--contact", "ops@example.com",
      "--client", "Acme",
      "--env", "production",
      "--confirm-production",
      "--tier", "1",
      "--confirm-tier2-production",
      "--operator", "carlos",
    );
    const input = buildInput();
    assert.equal(input.mode, "black");
    assert.deepEqual(input.roe.scope, ["example.com", "api.example.com"]);
    assert.deepEqual(input.roe.excludedTechniques, ["T1046", "t1498"]);
    assert.deepEqual(input.roe.blackoutWindows, [
      { start: "02:00", end: "04:00", tz: "America/Chicago" },
      { start: "23:00", end: "23:30", tz: undefined },
    ]);
    assert.deepEqual(input.roe.stopConditions, ["status page goes red"]);
    assert.equal(input.roe.deconflictionContact, "ops@example.com");
    assert.equal(input.client, "Acme");
    assert.equal(input.environment, "production");
    assert.equal(input.confirmProduction, true);
    assert.equal(input.tier, 1);
    assert.equal(input.confirmTier2Production, true);
    assert.equal(input.operatorName, "carlos");
  });

  it("--env accepts the prod alias and is case-insensitive", () => {
    argv(...validBase(), "--env", "prod");
    assert.equal(buildInput().environment, "production");
    argv(...validBase(), "--env", "STAGING");
    assert.equal(buildInput().environment, "staging");
  });

  it("--tier accepts 0|1|2 and the documented words", () => {
    const cases: Array<[string, number]> = [
      ["0", 0], ["1", 1], ["2", 2],
      ["observe", 0], ["validate", 1], ["chain", 2],
      ["Observe", 0], ["CHAIN", 2], [" 1 ", 1],
    ];
    for (const [raw, want] of cases) {
      argv(...validBase(), "--tier", raw);
      assert.equal(buildInput().tier, want, `tier ${JSON.stringify(raw)}`);
    }
  });

  it("secscan+seclayer target pins the web targets; --full-battery flag works too", () => {
    argv("--target", "secscan+seclayer", "--mode", "red", "--objective", "x", "--scope", "secscan.us");
    const pinned = buildInput();
    assert.equal(pinned.fullBattery, true);
    assert.deepEqual(pinned.targets, ["secscan", "seclayer"]);

    argv(...validBase(), "--full-battery", "--targets", "secscan, windows");
    const subset = buildInput();
    assert.equal(subset.fullBattery, true);
    assert.deepEqual(subset.targets, ["secscan", "windows"]);
  });

  it("--tier with no value (last flag) leaves tier unset — never a silent default", () => {
    argv(...validBase(), "--tier");
    assert.equal(buildInput().tier, undefined);
  });
});

describe("buildInput — invalid safety-relevant values fail loud (exit 2)", () => {
  it("bad --env", () => {
    argv(...validBase(), "--env", "prd");
    expectExit(() => buildInput(), 2);
    assert.match(stderr.join("\n"), /bad --env "prd"; want staging\|production/);
  });

  it("bad --mode (must be red|black)", () => {
    argv(...validBase().map((s) => (s === "red" ? "purple" : s)));
    expectExit(() => buildInput(), 2);
    assert.match(stderr.join("\n"), /bad --mode "purple"; want red\|black/);
  });

  it("bad --tier values", () => {
    for (const raw of ["3", "-1", "root", "2x", "t2"]) {
      argv(...validBase(), "--tier", raw);
      expectExit(() => buildInput(), 2);
      assert.match(stderr.join("\n"), /bad autonomy tier/, `tier ${raw}`);
    }
  });

  it("--tier followed by another flag treats the flag as the value and fails loud", () => {
    argv(...validBase(), "--tier", "--confirm-production");
    expectExit(() => buildInput(), 2);
    assert.match(stderr.join("\n"), /bad autonomy tier/);
  });

  it("bad --targets lists the offenders", () => {
    argv(...validBase(), "--targets", "secscan,nope,windows");
    expectExit(() => buildInput(), 2);
    assert.match(stderr.join("\n"), /bad --targets \["nope"\]/);
  });

  it("bad --blackout shapes fail loud", () => {
    for (const bad of ["2am-4am", "02:00/04:00", "0200-0400", "02:00–04:00"]) {
      argv(...validBase(), "--blackout", bad);
      expectExit(() => buildInput(), 2);
      assert.match(stderr.join("\n"), /bad --blackout/, `blackout ${bad}`);
    }
  });

  it("out-of-range --blackout hours/minutes fail loud instead of silently never matching", () => {
    for (const bad of ["25:00-26:00", "02:60-03:00", "99:99-99:99", "02:00-24:00"]) {
      argv(...validBase(), "--blackout", bad);
      expectExit(() => buildInput(), 2);
      assert.match(stderr.join("\n"), /bad --blackout/, `blackout ${bad}`);
    }
  });
});

describe("parseBlackout", () => {
  it("parses window + optional timezone", () => {
    assert.deepEqual(parseBlackout("02:00-04:00 America/Chicago"), {
      start: "02:00",
      end: "04:00",
      tz: "America/Chicago",
    });
    assert.deepEqual(parseBlackout("23:59-00:30"), { start: "23:59", end: "00:30", tz: undefined });
  });
});

describe("parseLogRotationArgs", () => {
  it("parses positive integers and leaves absent flags unset", () => {
    argv("--log-max-bytes", "1048576", "--log-max-archives", "3");
    assert.deepEqual(parseLogRotationArgs(), { maxLogBytes: 1048576, maxLogArchives: 3 });
    argv();
    assert.deepEqual(parseLogRotationArgs(), {});
  });

  it("rejects zero/negative/non-numeric/non-integer values with exit 2", () => {
    for (const flagName of ["--log-max-bytes", "--log-max-archives"]) {
      for (const bad of ["0", "-5", "abc", "1.5"]) {
        argv(flagName, bad);
        expectExit(() => parseLogRotationArgs(), 2);
        assert.match(stderr.join("\n"), new RegExp(`bad ${flagName.replace(/[-]/g, "\\-")} "${bad}"`), `${flagName} ${bad}`);
      }
    }
  });
});
