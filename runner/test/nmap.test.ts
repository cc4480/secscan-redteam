/**
 * Nmap bridge tests (v0.31.0).
 *
 * The policy module is pure, so most of this needs no subprocess and no
 * network — which is the point of keeping the argv builder separate from the
 * spawn. The scan tests inject a spawn that replays captured nmap XML.
 *
 * What is pinned here is the SAFETY contract, not the happy path:
 *   - the agent never reaches nmap's command line (no raw flags, target last)
 *   - intrusive NSE categories are REFUSED, not silently dropped
 *   - timing above -T4 and the attribution-defeating flags are refused
 *   - a partial or failed scan is reported as such, never as clean
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildNmapRunArgv,
  checkNmapFlags,
  checkNmapScriptCategories,
  findProfile,
  resolveNmapBinary,
  resolveNmapTimeoutS,
  NMAP_PROFILES,
  NMAP_ALLOWED_SCRIPT_CATEGORIES,
} from "../src/nmap/policy.js";
import { NmapExecutor } from "../src/nmap/executor.js";
import { parseNmapXml, type SpawnFn } from "../src/nmap/runner.js";
import { toolMinTier } from "../src/accountability/tiers.js";

// Captured from a real `nmap -sS -T4 --top-ports 100 -oX - scanme.nmap.org`.
const REAL_XML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sS -T4 --top-ports 100 -oX - scanme.nmap.org" start="1" elapsed="21.70">
<host><status state="up" reason="syn-ack"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu"/>
<script id="ssh-hostkey"><table>abc</table></script></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.4.7"/></port>
<port protocol="tcp" portid="9929"><state state="closed"/></port>
</ports>
<os><osmatch name="Linux 3.2 - 4.9" accuracy="95"/></os></host>
<host><status state="down" reason="no-response"/><address addr="10.0.0.9"/></host>
</nmaprun>`;

const replay = (xml: string): SpawnFn => async () => ({ stdout: xml, stderr: "", code: 0, timedOut: false });

describe("nmap policy — the agent never reaches the command line", () => {
  it("builds the argv entirely from the profile", () => {
    const argv = buildNmapRunArgv("nmap", {
      target: "10.0.0.5",
      profile: findProfile("service")!,
      rateLimit: 7,
      timeoutS: 60,
    });
    assert.equal(argv[0], "nmap");
    assert.ok(argv.includes("-sV"), "profile flags present");
    assert.ok(argv.includes("--max-rate"), "rate limit handed to nmap itself");
    assert.equal(argv[argv.indexOf("--max-rate") + 1], "7");
  });

  it("puts the target LAST, after --, so it cannot be read as a flag", () => {
    const argv = buildNmapRunArgv("nmap", {
      target: "-oN-/etc/passwd",
      profile: findProfile("quick")!,
      rateLimit: 5,
      timeoutS: 60,
    });
    assert.equal(argv[argv.length - 1], "-oN-/etc/passwd", "target is last");
    assert.equal(argv[argv.length - 2], "--", "preceded by the end-of-options marker");
  });

  it("emits --script only with validated categories", () => {
    const without = buildNmapRunArgv("nmap", {
      target: "h", profile: findProfile("quick")!, rateLimit: 5, timeoutS: 60,
    });
    assert.ok(!without.includes("--script"), "no --script when none requested");
    const with_ = buildNmapRunArgv("nmap", {
      target: "h", profile: findProfile("quick")!, rateLimit: 5, timeoutS: 60, scriptCategories: ["safe"],
    });
    assert.equal(with_[with_.indexOf("--script") + 1], "safe");
  });

  it("REFUSES intrusive NSE categories rather than filtering them", () => {
    for (const cat of ["exploit", "intrusive", "dos", "brute", "fuzzer", "malware", "external"]) {
      const msg = checkNmapScriptCategories([cat]);
      assert.ok(msg, `${cat} must be refused`);
      assert.match(msg!, /denied/i);
    }
  });

  it("refuses an unknown category instead of ignoring it", () => {
    assert.match(checkNmapScriptCategories(["nonsense"])!, /unknown NSE category/);
  });

  it("allows exactly the safe categories", () => {
    for (const cat of NMAP_ALLOWED_SCRIPT_CATEGORIES) assert.equal(checkNmapScriptCategories([cat]), null, cat);
  });

  it("refuses timing above -T4", () => {
    assert.match(checkNmapFlags(["-T5"])!, /above -T4/);
    assert.equal(checkNmapFlags(["-T4"]), null);
    assert.equal(checkNmapFlags(["-T2"]), null);
  });

  it("refuses decoys, spoofing and fragmentation", () => {
    for (const f of ["-D", "-S", "-f", "--mtu"]) assert.ok(checkNmapFlags([f]), `${f} must be refused`);
  });

  it("gates the loud profiles behind Tier 1", () => {
    assert.equal(findProfile("quick")!.minTier, 0);
    assert.equal(findProfile("service")!.minTier, 0);
    assert.equal(findProfile("full")!.minTier, 1);
    assert.equal(findProfile("udp")!.minTier, 1);
    assert.equal(findProfile("os")!.minTier, 1);
  });

  it("resolves binary and timeout from env with sane fallbacks", () => {
    assert.equal(resolveNmapBinary({ REDTEAM_NMAP_BIN: " /x/nmap " }), "/x/nmap");
    assert.equal(resolveNmapBinary({}), "nmap");
    assert.equal(resolveNmapTimeoutS({ REDTEAM_NMAP_TIMEOUT_S: "900" }), 900);
    assert.equal(resolveNmapTimeoutS({ REDTEAM_NMAP_TIMEOUT_S: "1" }), 300, "out of range falls back");
    assert.equal(resolveNmapTimeoutS({}), 300);
  });
});

describe("nmap tier is the SELECTED PROFILE's tier, not the tool name", () => {
  it("profile listing touches no target so it is Tier 0", () => {
    assert.equal(toolMinTier("nmap_exec", { action: "profiles" }), 0);
  });

  it("a quiet scan is Tier 0 and a full sweep is Tier 1", () => {
    assert.equal(toolMinTier("nmap_exec", { action: "scan", profile: "quick" }), 0);
    assert.equal(toolMinTier("nmap_exec", { action: "scan", profile: "service" }), 0);
    assert.equal(toolMinTier("nmap_exec", { action: "scan", profile: "full" }), 1);
    assert.equal(toolMinTier("nmap_exec", { action: "scan", profile: "os" }), 1);
  });

  it("defaults to the quiet profile when none is named", () => {
    assert.equal(toolMinTier("nmap_exec", { action: "scan" }), 0);
  });
});

describe("nmap XML parsing", () => {
  it("reads ports, services, versions and hostnames", () => {
    const r = parseNmapXml(REAL_XML);
    assert.equal(r.hosts.length, 1, "the down host is not a result");
    assert.equal(r.upHostCount, 1);
    const h = r.hosts[0]!;
    assert.equal(h.address, "45.33.32.156");
    assert.deepEqual(h.hostnames, ["scanme.nmap.org"]);
    const open = h.ports.filter((p) => p.state === "open");
    assert.deepEqual(open.map((p) => p.port), [22, 80]);
    assert.equal(open[0]!.service, "ssh");
    assert.equal(open[0]!.product, "OpenSSH");
    assert.ok(open[0]!.scripts["ssh-hostkey"], "NSE output captured");
    assert.equal(h.osMatches[0], "Linux 3.2 - 4.9");
  });

  it("keeps closed ports out of the open count but in the record", () => {
    const h = parseNmapXml(REAL_XML).hosts[0]!;
    assert.equal(h.ports.length, 3);
    assert.equal(h.ports.filter((p) => p.state === "open").length, 2);
  });

  it("returns nothing for unparseable output rather than throwing", () => {
    const r = parseNmapXml("nmap: unrecognised argument");
    assert.equal(r.hosts.length, 0);
    assert.equal(r.summary, "no hosts up");
  });

  it("summarises per host for the audit log", () => {
    assert.match(parseNmapXml(REAL_XML).summary, /45\.33\.32\.156 \(scanme\.nmap\.org\): 2 open/);
  });
});

describe("nmap executor", () => {
  it("lists profiles and confirms the binary", async () => {
    const exec = new NmapExecutor({ spawn: replay("<nmaprun/>") });
    const r = await exec.profiles();
    assert.ok(r.ok);
    assert.equal(r.profiles?.length, NMAP_PROFILES.length);
  });

  it("scans and reports parsed evidence", async () => {
    const exec = new NmapExecutor({ spawn: replay(REAL_XML), env: { REDTEAM_NMAP_BIN: "nmap" } });
    const r = await exec.scan({ target: "scanme.nmap.org", profile: "quick", rateLimit: 10 });
    assert.ok(r.ok);
    assert.match(r.message, /2 open/);
    assert.equal(r.run?.hosts.length, 1);
  });

  it("refuses an unknown profile by name", async () => {
    const exec = new NmapExecutor({ spawn: replay(REAL_XML) });
    const r = await exec.scan({ target: "h", profile: "lol", rateLimit: 10 });
    assert.equal(r.ok, false);
    assert.match(r.message, /unknown profile/);
  });

  it("never starts a scan once the kill switch is set", async () => {
    let spawned = false;
    const exec = new NmapExecutor({
      spawn: async () => {
        spawned = true;
        return { stdout: "", stderr: "", code: 0, timedOut: false };
      },
    });
    exec.killSwitch = { aborted: true };
    const r = await exec.scan({ target: "h", profile: "quick", rateLimit: 10 });
    assert.equal(r.ok, false);
    assert.match(r.message, /kill switch/i);
    assert.equal(spawned, false, "no process was started");
  });

  it("reports a timeout as PARTIAL, never as clean", async () => {
    const exec = new NmapExecutor({
      spawn: async () => ({ stdout: REAL_XML, stderr: "", code: null, timedOut: true }),
      env: { REDTEAM_NMAP_BIN: "nmap" },
    });
    const r = await exec.scan({ target: "h", profile: "full", rateLimit: 10 });
    assert.equal(r.ok, false, "a killed scan is not ok");
    assert.match(r.message, /timeout/i);
    assert.ok(r.run, "partial evidence is still returned");
  });

  it("surfaces a non-zero exit with the stderr reason", async () => {
    const exec = new NmapExecutor({
      spawn: async () => ({ stdout: "", stderr: "Failed to resolve target.", code: 1, timedOut: false }),
    });
    const r = await exec.scan({ target: "nope.invalid", profile: "quick", rateLimit: 10 });
    assert.equal(r.ok, false);
    assert.match(r.message, /Failed to resolve/);
  });
});
