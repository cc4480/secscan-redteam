/**
 * Unit tests for the auth gate's pure logic. DNS-touching paths are tested
 * only for their fail-closed behavior (no network required):
 * checkTxtRecord against a reserved-invalid domain must return false.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  checkTxtRecord,
  decide,
  extractDomain,
  generateEngagementToken,
  txtRecordName,
  verifyOwnership,
} from "../src/index.js";

describe("extractDomain", () => {
  it("normalizes URLs and bare domains", () => {
    assert.equal(extractDomain("https://Example.COM/path?q=1"), "example.com");
    assert.equal(extractDomain("example.com"), "example.com");
    assert.equal(extractDomain("http://sub.example.com:8080/x"), "sub.example.com");
  });
  it("throws on garbage", () => {
    assert.throws(() => extractDomain("not a url at all %%%"));
  });
});

describe("txtRecordName", () => {
  it("builds the challenge record name", () => {
    assert.equal(txtRecordName("example.com"), "_seclayer-challenge.example.com");
    assert.equal(txtRecordName("https://Sub.Example.com/"), "_seclayer-challenge.sub.example.com");
  });
});

describe("generateEngagementToken", () => {
  it("issues unique sl-verify- tokens", () => {
    const a = generateEngagementToken();
    const b = generateEngagementToken();
    assert.match(a, /^sl-verify-[0-9a-f]{32}$/);
    assert.notEqual(a, b);
  });
});

describe("checkTxtRecord", () => {
  it("fails closed on unresolvable domains", async () => {
    // .invalid is RFC-reserved to never resolve — no network needed for the answer.
    assert.equal(await checkTxtRecord("does-not-exist-12345.invalid", "sl-verify-abc"), false);
  });
  it("fails closed with an empty token", async () => {
    assert.equal(await checkTxtRecord("example.com", ""), false);
  });
});

describe("verifyOwnership", () => {
  it("returns instructions when unverified", async () => {
    const proof = await verifyOwnership("https://example.invalid", undefined);
    assert.equal(proof.ok, false);
    assert.equal(proof.method, "none");
    assert.match(proof.instructions ?? "", /_seclayer-challenge\.example\.invalid/);
  });
});

describe("decide (pre-execute gate)", () => {
  it("allows read-only tools unconditionally", async () => {
    assert.deepEqual(await decide({ toolName: "seclayer_list_scans", arguments: {} }, undefined), {
      kind: "allow",
    });
    assert.deepEqual(
      await decide({ toolName: "seclayer_get_report", arguments: { scanId: "x" } }, undefined),
      { kind: "allow" },
    );
  });
  it("allows standard-tier scans without ownership proof", async () => {
    assert.deepEqual(
      await decide(
        { toolName: "seclayer_scan", arguments: { url: "https://example.com" } },
        undefined,
      ),
      { kind: "allow" },
    );
  });
  it("denies aggressive scans without a token (fail closed)", async () => {
    const d = await decide(
      { toolName: "seclayer_scan", arguments: { url: "https://example.invalid", aggressive: true } },
      undefined,
    );
    assert.equal(d.kind, "deny");
    assert.match((d as { reason: string }).reason, /ACTIVE TESTING DENIED/);
  });
  it("denies aggressive scans on malformed URLs", async () => {
    const d = await decide(
      { toolName: "seclayer_scan", arguments: { url: "%%%bad", aggressive: true } },
      "sl-verify-token",
    );
    assert.equal(d.kind, "deny");
  });
  it("passes through unrelated tools", async () => {
    assert.deepEqual(await decide({ toolName: "some_other_tool", arguments: {} }, undefined), {
      kind: "allow",
    });
  });
});
