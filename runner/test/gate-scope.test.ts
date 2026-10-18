/**
 * Scope authorization tests (v0.37.1 security fix).
 *
 * The engagement target is ownership-verified by checkAuthorization, but every
 * OTHER host in scope used to be trusted on membership alone. That let a verified
 * target be paired with an arbitrary public host, and let local-sandbox mode (which
 * skips verification for a loopback target) be combined with a public scope host.
 * checkScopeAuthorization closes both; these tests pin the rules.
 *
 * Pure: the verify function is injected, so no network is touched.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkAuthorization, checkScopeAuthorization } from "../src/gate.js";

const cfg = { mcpEndpoint: "https://secscan.example/api/mcp", mcpToken: "test-token" };

/** A verify function answering per-host and recording every call. */
function verifier(answer: (host: string) => boolean, calls: string[] = []) {
  return async (host: string): Promise<boolean> => {
    calls.push(host);
    return answer(host);
  };
}

describe("checkScopeAuthorization", () => {
  it("allows a scope whose DNS hosts are each ownership-verified", async () => {
    const calls: string[] = [];
    const verdict = await checkScopeAuthorization(
      ["app.example.com", "api.example.com"],
      cfg,
      verifier(() => true, calls),
      { verifiedTarget: "https://app.example.com/landing" },
    );
    assert.equal(verdict.allowed, true);
    // The target is already verified by checkAuthorization; only the other host is asked.
    assert.deepEqual(calls, ["api.example.com"]);
  });

  it("denies a scope containing a DNS host that is not verified, naming it", async () => {
    const verdict = await checkScopeAuthorization(
      ["app.example.com", "someone-elses-site.test"],
      cfg,
      verifier((host) => host === "app.example.com"),
      { verifiedTarget: "app.example.com" },
    );
    assert.equal(verdict.allowed, false);
    assert.match(verdict.reason ?? "", /someone-elses-site\.test/);
    assert.match(verdict.reason ?? "", /not ownership-verified/);
  });

  it("fails closed when the verification call throws", async () => {
    const verdict = await checkScopeAuthorization(
      ["api.example.com"],
      cfg,
      async () => { throw new Error("network down") },
      { verifiedTarget: "app.example.com" },
    );
    assert.equal(verdict.allowed, false);
  });

  it("allows an IP-literal scope host (a host engagement target, not a domain)", async () => {
    const calls: string[] = [];
    const verdict = await checkScopeAuthorization(
      ["203.0.113.10", "198.51.100.7"],
      cfg,
      verifier(() => false, calls),
      { verifiedTarget: "app.example.com" },
    );
    assert.equal(verdict.allowed, true);
    assert.deepEqual(calls, [], "an address cannot be domain-verified, so no call is made");
  });

  it("denies a private/loopback scope host when local sandbox is off", async () => {
    const verdict = await checkScopeAuthorization(["127.0.0.1"], cfg, verifier(() => true), {
      verifiedTarget: "app.example.com",
    });
    assert.equal(verdict.allowed, false);
    assert.match(verdict.reason ?? "", /local sandbox/);
  });

  it("denies local sandbox combined with a public host in scope (the reported chain)", async () => {
    const verdict = await checkScopeAuthorization(
      ["127.0.0.1", "some-public-host.example"],
      cfg,
      verifier(() => true),
      { allowLocalSandbox: true, verifiedTarget: "127.0.0.1" },
    );
    assert.equal(verdict.allowed, false);
    assert.match(verdict.reason ?? "", /some-public-host\.example/);
    assert.match(verdict.reason ?? "", /LOCAL SANDBOX MODE cannot cover/);
  });

  it("allows local sandbox when every scope host is private, without verifying any", async () => {
    const calls: string[] = [];
    const verdict = await checkScopeAuthorization(
      ["127.0.0.1", "10.0.0.5", "localhost"],
      cfg,
      verifier(() => true, calls),
      { allowLocalSandbox: true, verifiedTarget: "127.0.0.1" },
    );
    assert.equal(verdict.allowed, true);
    assert.deepEqual(calls, []);
  });

  it("denies an empty scope", async () => {
    const verdict = await checkScopeAuthorization(["   "], cfg, verifier(() => true), {});
    assert.equal(verdict.allowed, false);
    assert.match(verdict.reason ?? "", /scope is empty/);
  });
});

describe("checkAuthorization still gates the target itself", () => {
  it("denies an unverified public target even when the scope is otherwise clean", async () => {
    const verdict = await checkAuthorization("app.example.com", cfg, async () => false);
    assert.equal(verdict.allowed, false);
  });

  it("local sandbox skips verification only for a private target", async () => {
    const allowed = await checkAuthorization("127.0.0.1", cfg, async () => false, { allowLocalSandbox: true });
    assert.equal(allowed.allowed, true);
    const denied = await checkAuthorization("app.example.com", cfg, async () => false, { allowLocalSandbox: true });
    assert.equal(denied.allowed, false);
  });
});
