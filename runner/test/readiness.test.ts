/**
 * Readiness-layer tests (v0.33.0).
 *
 * What is pinned here is the "installed app is ready to use" contract, which is
 * exactly where the product was weakest: every failure we hit in the field
 * (ffuf wordlist, FUZZ keyword, nmap privilege, silent prereq lie) surfaced one
 * tool at a time, mid-engagement. These tests keep those four from regressing:
 *
 *   - the wordlist resolver never returns another machine's hardcoded path
 *   - the ffuf argv always carries a FUZZ placeholder
 *   - the nmap privilege fallback is decided from stderr, not guessed
 *   - the readiness report names every requirement and never throws
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { buildXToolArgv, findProfile, findXTool } from "../src/xtool/registry.js";
import { resolveWordlist, wordlistCandidates } from "../src/xtool/wordlist.js";
import { connectScanArgv, isNmapPrivilegeFailure } from "../src/nmap/privilege.js";
import { formatReadiness, readinessReport } from "../src/tools/readiness.js";
import { _resetNmapProbeCache } from "../src/nmap/prereq.js";

const ffuf = findXTool("ffuf");
const dirs = ffuf ? findProfile(ffuf, "dirs") : undefined;
const vhosts = ffuf ? findProfile(ffuf, "vhosts") : undefined;

describe("wordlist resolution", () => {
  it("never embeds an operator-specific path and prefers explicit → env → bundle", () => {
    const candidates = wordlistCandidates("/explicit/list.txt", {
      REDTEAM_WORDLIST: "/env/list.txt",
      REDTEAM_TOOLS_DIR: "/tools",
    } as NodeJS.ProcessEnv);
    assert.equal(candidates[0], "/explicit/list.txt");
    assert.equal(candidates[1], "/env/list.txt");
    assert.ok(candidates.some((c) => c.includes("assets") && c.endsWith("common.txt")));
    assert.ok(candidates.every((c) => !c.includes("Cho-zen")), "no machine-specific path may appear");
  });

  it("resolves the bundled asset that ships with the package", () => {
    const picked = resolveWordlist(undefined, {} as NodeJS.ProcessEnv);
    assert.ok(picked, "the shipped asset must resolve");
    // Both production (dist/xtool) and test (dist-test/src/xtool) layouts are
    // searched, so assert on the tail rather than on one root's absolute path.
    assert.match(picked, /assets[\\/]wordlists[\\/]common\.txt$/);
  });

  it("never returns one of the non-existent candidates it was given", () => {
    const picked = resolveWordlist("/definitely/not/here.txt", { REDTEAM_WORDLIST: "/nor/this" } as NodeJS.ProcessEnv);
    // A shipped asset may legitimately satisfy the request, but a path that does
    // not exist must never be handed to the tool.
    assert.notEqual(picked, "/definitely/not/here.txt");
    assert.notEqual(picked, "/nor/this");
    if (picked !== undefined) assert.ok(picked.endsWith("common.txt"), `unexpected wordlist ${picked}`);
  });
});

describe("ffuf argv — FUZZ keyword", () => {
  it("appends /FUZZ for a bare target and keeps the wordlist flag", () => {
    assert.ok(dirs);
    const argv = buildXToolArgv(ffuf!, { bin: "ffuf", profile: dirs, target: "http://127.0.0.1:8080", wordlist: "/w.txt", timeoutS: 300 });
    assert.ok(argv.includes("http://127.0.0.1:8080/FUZZ"), `expected FUZZ url, got ${argv.join(" ")}`);
    assert.ok(argv.includes("-w") && argv.includes("/w.txt"));
  });

  it("does not double-append when the target already has FUZZ", () => {
    assert.ok(dirs);
    const argv = buildXToolArgv(ffuf!, { bin: "ffuf", profile: dirs, target: "http://x/FUZZ", wordlist: "/w.txt", timeoutS: 300 });
    assert.ok(argv.includes("http://x/FUZZ"));
    assert.ok(!argv.includes("http://x/FUZZ/FUZZ"));
  });

  it("fuzzes the Host header for vhost discovery", () => {
    assert.ok(vhosts);
    const argv = buildXToolArgv(ffuf!, { bin: "ffuf", profile: vhosts, target: "http://x", wordlist: "/w.txt", timeoutS: 300 });
    const i = argv.indexOf("-H");
    assert.ok(i >= 0 && argv[i + 1] === "Host: FUZZ", `expected -H Host: FUZZ, got ${argv.join(" ")}`);
  });
});

describe("nmap privilege handling", () => {
  it("recognises the raw-socket failure signatures", () => {
    for (const stderr of [
      "Couldn't open a raw socket. Error: Npcap is not installed",
      "You requested a scan type which requires root privileges",
      "socket creation failed: Operation not permitted",
      "Access is denied.",
    ]) {
      assert.equal(isNmapPrivilegeFailure(stderr), true, stderr);
    }
    assert.equal(isNmapPrivilegeFailure("Host seems down"), false);
    assert.equal(isNmapPrivilegeFailure(""), false);
  });

  it("rewrites SYN to a connect scan and drops raw-only flags", () => {
    const argv = ["nmap", "-sS", "-O", "--osscan-guess", "-sV", "-T4", "10.0.0.5"];
    assert.deepEqual(connectScanArgv(argv), ["nmap", "-sT", "-sV", "-T4", "10.0.0.5"]);
  });

  it("returns undefined when the scan is already a connect/UDP scan (nothing to rewrite)", () => {
    assert.equal(connectScanArgv(["nmap", "-sT", "x"]), undefined);
    assert.equal(connectScanArgv(["nmap", "-sU", "x"]), undefined);
  });
});

describe("readiness report", () => {
  it("names every requirement and never throws on a bare environment", async () => {
    _resetNmapProbeCache();
    const report = await readinessReport({ REDTEAM_NMAP_BIN: "/no/such/nmap" } as NodeJS.ProcessEnv);
    const ids = report.items.map((i) => i.id);
    for (const id of ["nmap", "wordlist", "msfrpcd", "secscan_token", "deepseek_key"]) {
      assert.ok(ids.includes(id), `missing readiness item ${id}`);
    }
    assert.equal(report.ok, false, "an environment without tokens cannot be ready");
    const missingRequired = report.items.filter((i) => i.required && i.state !== "ready").map((i) => i.id);
    assert.ok(missingRequired.includes("nmap"));
    assert.ok(missingRequired.includes("secscan_token"));
    assert.ok(missingRequired.includes("deepseek_key"));
    assert.match(formatReadiness(report), /readiness:/);
    assert.match(report.summary, /required missing/);
  });

  it("reports the RPC daemon as not-configured when credentials are absent and unreachable when they are not", async () => {
    _resetNmapProbeCache();
    const noCreds = await readinessReport({ REDTEAM_NMAP_BIN: "/no/such/nmap" } as NodeJS.ProcessEnv);
    assert.equal(noCreds.items.find((i) => i.id === "msfrpcd")?.state, "not-configured");

    const creds = await readinessReport({
      REDTEAM_NMAP_BIN: "/no/such/nmap",
      REDTEAM_MSFRPC_USER: "msf",
      REDTEAM_MSFRPC_PASS: "x",
      REDTEAM_MSFRPC_HOST: "127.0.0.1",
      REDTEAM_MSFRPC_PORT: "1", // nothing listens on port 1
    } as NodeJS.ProcessEnv);
    const rpc = creds.items.find((i) => i.id === "msfrpcd");
    assert.equal(rpc?.state, "unreachable");
    assert.match(rpc?.fix ?? "", /msfrpcd/);
  });
});
