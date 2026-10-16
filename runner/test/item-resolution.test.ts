/**
 * Battery item resolution must not be defeated by targetProfile.
 *
 * Every tool that carries a `batteryItem` also carries a REQUIRED
 * `targetProfile` of "windows" or "linux" — that is what the host tools need,
 * and the schema enforces it. So an agent tagging a probe on a web target
 * naturally sends both:
 *
 *   batteryItem: "SS-042",  targetProfile: "linux"
 *
 * "SS-042" is a secscan (web) item and "linux" is a host profile, so a strict
 * cross-check between them rejected the item — even though SS-042 was in the
 * ledger the entire time. A live run produced eight "did not resolve to a
 * selected battery item" warnings for SS-042 through SS-048, every one of them
 * a real item, and none of the probes reconciled to the coverage ledger.
 *
 * The bare form's prefix already names the target unambiguously, so the profile
 * is a hint at most. The qualified form ("secscan:SS-042") is a claim about
 * which battery the item belongs to, and that is still checked strictly.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveItemKey, buildItemLedger } from "../src/coverage/items.js";

describe("resolveItemKey — a host targetProfile does not invalidate a web item", () => {
  it("resolves a bare item when the profile conflicts, rather than refusing", () => {
    assert.equal(resolveItemKey("SS-042", "linux"), "secscan:SS-042");
    assert.equal(resolveItemKey("SS-042", "windows"), "secscan:SS-042");
  });

  it("resolves a bare item with no profile at all", () => {
    assert.equal(resolveItemKey("SS-042"), "secscan:SS-042");
  });

  it("still resolves when the profile agrees", () => {
    assert.equal(resolveItemKey("LX-006", "linux"), "linux:LX-006");
    assert.equal(resolveItemKey("WS-001", "windows"), "windows:WS-001");
  });

  it("the resolved key is actually in the ledger — which is the whole point", () => {
    // The failure was not a bad key; it was a key that never got built.
    const ledger = buildItemLedger(["secscan"]);
    for (const raw of ["SS-042", "SS-045", "SS-046", "SS-047", "SS-048"]) {
      const key = resolveItemKey(raw, "linux");
      assert.ok(key, `${raw} resolves`);
      assert.ok(ledger.has(key!), `${raw} -> ${key} is a real ledger key`);
    }
  });

  it("still refuses a genuinely unknown item", () => {
    assert.equal(resolveItemKey("ZZ-999"), undefined, "no such prefix");
    assert.equal(resolveItemKey("not-an-item"), undefined);
    assert.equal(resolveItemKey(""), undefined);
  });

  it("still checks the qualified form strictly", () => {
    // "linux:SS-042" is a claim that SS-042 belongs to the linux battery. It
    // does not, and a qualified claim is checked rather than guessed at.
    assert.equal(resolveItemKey("linux:SS-042"), undefined);
    assert.equal(resolveItemKey("secscan:SS-042"), "secscan:SS-042");
    assert.equal(resolveItemKey("secscan:LX-006"), undefined);
  });

  it("handles CVE ids unchanged", () => {
    assert.equal(resolveItemKey("CVE-2021-44228", "linux"), "cve:CVE-2021-44228");
    assert.equal(resolveItemKey("cve:CVE-2021-44228"), "cve:CVE-2021-44228");
  });
});
