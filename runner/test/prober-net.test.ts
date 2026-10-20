/**
 * Prober DNS-pinning / SSRF-guard tests (audit 2026-10-09, security #5).
 *
 * NO real DNS and NO external fetches: every WebProber here gets an injected
 * fake resolver, and the only real socket traffic goes to a throwaway HTTP
 * server bound to 127.0.0.1 (same pattern as the integration capture server).
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { WebProber, validateProbeTarget } from "../src/prober.js";
import {
  classifyIpAddress,
  makePinnedLookup,
  resolveCheckedAddresses,
  type DnsAddress,
  type DnsResolver,
} from "../src/prober-net.js";

function fakeResolver(map: Record<string, string[]>): DnsResolver {
  return async (hostname: string) => {
    const addrs = map[hostname.toLowerCase()];
    if (!addrs) throw new Error(`getaddrinfo ENOTFOUND ${hostname}`);
    return addrs.map(
      (address): DnsAddress => ({ address, family: address.includes(":") ? 6 : 4 }),
    );
  };
}

describe("classifyIpAddress", () => {
  it("classifies link-local incl. IPv4-embedded forms as link-local", () => {
    for (const ip of ["169.254.169.254", "169.254.0.1", "fe80::1", "fe80::a634:d9ff:fe07:c5a8", "::ffff:169.254.169.254"]) {
      assert.equal(classifyIpAddress(ip), "link-local", ip);
    }
  });
  it("classifies loopback and private ranges", () => {
    for (const ip of ["127.0.0.1", "::1", "0:0:0:0:0:0:0:1"]) assert.equal(classifyIpAddress(ip), "loopback", ip);
    for (const ip of ["10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.1", "0.0.0.0", "100.64.0.1", "fd00::1", "fc12:3456::1"]) {
      assert.equal(classifyIpAddress(ip), "private", ip);
    }
  });
  it("classifies routable addresses public", () => {
    for (const ip of ["8.8.8.8", "93.184.216.34", "172.32.0.1", "::ffff:8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"]) {
      assert.equal(classifyIpAddress(ip), "public", ip);
    }
  });
});

describe("resolveCheckedAddresses (fake resolver — no real DNS)", () => {
  it("refuses a hostname resolving to 169.254.169.254 — even in sandbox mode", async () => {
    const resolver = fakeResolver({ "target.test": ["169.254.169.254"] });
    const normal = await resolveCheckedAddresses("target.test", { resolver });
    assert.equal(normal.ok, false);
    assert.match(normal.ok === false ? normal.reason : "", /link-local/);
    const sandbox = await resolveCheckedAddresses("target.test", { resolver, allowPrivateHosts: true });
    assert.equal(sandbox.ok, false, "metadata must stay refused with allowPrivateHosts");
  });
  it("refuses RFC1918 resolutions unless private hosts are allowed", async () => {
    const resolver = fakeResolver({ "target.test": ["10.1.2.3"] });
    assert.equal((await resolveCheckedAddresses("target.test", { resolver })).ok, false);
    const sandbox = await resolveCheckedAddresses("target.test", { resolver, allowPrivateHosts: true });
    assert.deepEqual(sandbox, { ok: true, addresses: [{ address: "10.1.2.3", family: 4 }] });
  });
  it("refuses when ANY resolved address is bad (no round-robin smuggling)", async () => {
    const resolver = fakeResolver({ "target.test": ["93.184.216.34", "169.254.169.254"] });
    assert.equal((await resolveCheckedAddresses("target.test", { resolver, allowPrivateHosts: true })).ok, false);
  });
  it("passes a clean public resolution through for pinning", async () => {
    const resolver = fakeResolver({ "target.test": ["93.184.216.34"] });
    const r = await resolveCheckedAddresses("target.test", { resolver });
    assert.deepEqual(r, { ok: true, addresses: [{ address: "93.184.216.34", family: 4 }] });
  });
  it("fails closed on resolver errors and empty answers", async () => {
    const throwing = fakeResolver({});
    assert.equal((await resolveCheckedAddresses("nope.test", { resolver: throwing })).ok, false);
    const empty: DnsResolver = async () => [];
    assert.equal((await resolveCheckedAddresses("nope.test", { resolver: empty })).ok, false);
  });
  it("classifies IP literals directly (literal metadata never consulted via DNS)", async () => {
    let called = false;
    const resolver: DnsResolver = async () => {
      called = true;
      return [{ address: "93.184.216.34", family: 4 }];
    };
    assert.equal((await resolveCheckedAddresses("169.254.169.254", { resolver, allowPrivateHosts: true })).ok, false);
    assert.equal(called, false);
    assert.equal((await resolveCheckedAddresses("93.184.216.34", { resolver })).ok, true);
  });
});

describe("validateProbeTarget — link-local literals are never allowed", () => {
  it("refuses 169.254.169.254 even with allowPrivateHosts and the host in scope", () => {
    const r = validateProbeTarget("http://169.254.169.254/latest/meta-data/", ["169.254.169.254"], { allowPrivateHosts: true });
    assert.equal(r.ok, false);
    assert.match(r.ok === false ? r.reason : "", /link-local/);
  });
  it("refuses fe80:: literals even with allowPrivateHosts", () => {
    const r = validateProbeTarget("http://[fe80::1]/", ["[fe80::1]"], { allowPrivateHosts: true });
    assert.equal(r.ok, false);
  });
});

describe("makePinnedLookup", () => {
  it("yields only the validated addresses (single + all forms)", async () => {
    const lookup = makePinnedLookup([{ address: "93.184.216.34", family: 4 }]);
    const single = await new Promise<{ address: unknown; family?: number }>((resolve, reject) => {
      lookup("anything.test", {}, (err, address, family) => (err ? reject(err) : resolve({ address, family })));
    });
    assert.equal(single.address, "93.184.216.34");
    const all = await new Promise<unknown>((resolve, reject) => {
      lookup("anything.test", { all: true }, (err, address) => (err ? reject(err) : resolve(address)));
    });
    assert.deepEqual(all, [{ address: "93.184.216.34", family: 4 }]);
  });
});

describe("WebProber DNS pinning (loopback server + fake resolver)", () => {
  let server: Server;
  let port = 0;
  let okHits = 0;

  before(async () => {
    server = createServer((req, res) => {
      switch (req.url) {
        case "/ok":
          okHits++;
          res.writeHead(200, { "content-type": "text/plain" });
          res.end("hello-probe");
          break;
        case "/to-metadata":
          res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
          res.end();
          break;
        case "/to-metadata-host":
          res.writeHead(302, { location: "http://metadata.test/secret" });
          res.end();
          break;
        case "/to-public":
          res.writeHead(302, { location: "http://example.com/landing" });
          res.end();
          break;
        case "/to-private":
          res.writeHead(302, { location: "http://10.0.0.5/admin" });
          res.end();
          break;
        case "/to-self":
          res.writeHead(302, { location: "/ok" });
          res.end();
          break;
        default:
          res.writeHead(404);
          res.end();
      }
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });
  after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const resolver = fakeResolver({
    "sandbox.test": ["127.0.0.1"],
    "victim.test": ["127.0.0.1"],
    "meta.test": ["169.254.169.254"],
    "metadata.test": ["169.254.169.254"],
    "example.com": ["93.184.216.34"],
  });
  const sandbox = () =>
    new WebProber({ scopeHosts: ["sandbox.test", "victim.test", "meta.test"], allowPrivateHosts: true, resolver, minDelayMs: 0, timeoutMs: 5000 });

  it("sandbox: a name resolving to loopback fetches fine through the pin", async () => {
    const res = await sandbox().probe({ method: "GET", url: `http://sandbox.test:${port}/ok` });
    assert.equal(res.status, 200);
    assert.match(res.bodySnippet, /hello-probe/);
  });

  it("non-sandbox: a name resolving to loopback is refused BEFORE any packet (server sees nothing)", async () => {
    const prober = new WebProber({ scopeHosts: ["victim.test"], resolver, minDelayMs: 0, timeoutMs: 5000 });
    const hitsBefore = okHits;
    await assert.rejects(() => prober.probe({ method: "GET", url: `http://victim.test:${port}/ok` }), /\[prober\] refused:.*loopback/);
    assert.equal(okHits, hitsBefore, "the loopback server must not receive the rebound request");
  });

  it("sandbox: a name resolving to 169.254.169.254 is refused (metadata has no sandbox exception)", async () => {
    await assert.rejects(() => sandbox().probe({ method: "GET", url: `http://meta.test:${port}/ok` }), /\[prober\] refused:.*link-local/);
  });

  it("redirect to a link-local literal is refused, not handed back as a hop", async () => {
    await assert.rejects(() => sandbox().probe({ method: "GET", url: `http://sandbox.test:${port}/to-metadata` }), /\[prober\] refused:/);
  });

  it("redirect to a hostname resolving to link-local is refused", async () => {
    await assert.rejects(() => sandbox().probe({ method: "GET", url: `http://sandbox.test:${port}/to-metadata-host` }), /\[prober\] refused:/);
  });

  it("redirect to a public host is returned as a normal 302 (validated, never followed)", async () => {
    const res = await sandbox().probe({ method: "GET", url: `http://sandbox.test:${port}/to-public` });
    assert.equal(res.status, 302);
    assert.equal(res.headers["location"], "http://example.com/landing");
  });

  it("redirect to RFC1918 is fine in sandbox mode (only link-local is absolute)", async () => {
    const res = await sandbox().probe({ method: "GET", url: `http://sandbox.test:${port}/to-private` });
    assert.equal(res.status, 302);
  });

  it("relative redirects validate against the same safe host and stay manual", async () => {
    const res = await sandbox().probe({ method: "GET", url: `http://sandbox.test:${port}/to-self` });
    assert.equal(res.status, 302);
  });

  it("burst: pinned batch works in sandbox, and a metadata-bound name is refused up front", async () => {
    const burst = await sandbox().probeBurst({ method: "GET", url: `http://sandbox.test:${port}/ok` });
    assert.equal(burst.count, 8);
    assert.ok(burst.statuses.every((s) => s === 200));
    await assert.rejects(() => sandbox().probeBurst({ method: "GET", url: `http://meta.test:${port}/ok` }), /\[prober\] refused:/);
  });
});
