/**
 * Payload-variant expansion tests (v0.20.0).
 *
 * Curated libraries are mechanical (never LLM-invented): counts, tags,
 * and non-destructive policy are asserted. Tracking is tested against a
 * minimal fake ctx — no network, no API keys.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Ctx } from "../src/context.js";
import type { ItemVerdict } from "../src/coverage/items.js";
import { buildItemLedger } from "../src/coverage/items.js";
import { TARGET_PROFILES, FULL_BATTERY_TARGETS } from "../src/targets/index.js";
import {
  SQLI_VARIANTS,
  XSS_VARIANTS,
  CMDI_VARIANTS,
  SSTI_VARIANTS,
  XXE_VARIANTS,
  TRAVERSAL_VARIANTS,
  SSRF_VARIANTS,
  REDIRECT_VARIANTS,
  AUTH_VARIANTS,
  HEADER_VARIANTS,
  classifyItem,
  totalLibrarySize,
  resolveVariantCap,
  DEFAULT_VARIANT_CAP_STAGING,
  DEFAULT_VARIANT_CAP_PRODUCTION,
  startVariantExpansion,
  checkVariantCap,
  recordVariantExecution,
  closeVariantExpansion,
  hasActiveVariantExpansion,
  countVariants,
  variantCountLine,
  VARIANT_LIST_TOOL,
  VARIANT_CLASSES,
} from "../src/variants/index.js";
import { EXPLOIT_TOOLS, RECON_TOOLS } from "../src/tools.js";
import { toolMinTier } from "../src/accountability/index.js";

/** Minimal fake ctx — tracking touches itemLedger, variantCap, events.append only. */
function fakeCtx(cap = 25): Ctx {
  const appended: Array<{ action: string; result: string }> = [];
  return {
    itemLedger: buildItemLedger([...FULL_BATTERY_TARGETS]),
    variantCap: cap,
    events: { append: (e: { action: string; result: string }) => void appended.push(e) },
  } as unknown as Ctx;
}

describe("variant libraries", () => {
  const libs: Array<[string, typeof SQLI_VARIANTS]> = [
    ["sqli", SQLI_VARIANTS],
    ["xss", XSS_VARIANTS],
    ["cmdi", CMDI_VARIANTS],
    ["ssti", SSTI_VARIANTS],
    ["xxe", XXE_VARIANTS],
    ["traversal", TRAVERSAL_VARIANTS],
    ["ssrf", SSRF_VARIANTS],
    ["redirect", REDIRECT_VARIANTS],
    ["auth", AUTH_VARIANTS],
    ["headers", HEADER_VARIANTS],
  ];
  for (const [name, lib] of libs) {
    it(`${name}: non-empty, every payload tagged with kind + whatItTests`, () => {
      assert.ok(lib.length >= 8, `${name} should have a real library, got ${lib.length}`);
      for (const p of lib) {
        assert.equal(p.kind, name);
        assert.ok(p.payload.length > 0);
        assert.ok(p.whatItTests.length > 0, `${name} payload missing whatItTests: ${p.payload}`);
      }
    });
  }
  it("total library size is the sum of parts", () => {
    const sum = libs.reduce((n, [, lib]) => n + lib.length, 0);
    assert.equal(totalLibrarySize(), sum);
    assert.ok(sum >= 100, `expected a deep library, got ${sum}`);
  });
  it("VARIANT_CLASSES covers every library", () => {
    assert.deepEqual([...VARIANT_CLASSES].sort(), libs.map(([n]) => n).sort());
  });
  it("no destructive payloads in any library", () => {
    const banned = [/drop\s+table/i, /delete\s+from/i, /;\s*shutdown/i, /rm\s+-rf\s+\//, /mkfs/i];
    for (const [, lib] of libs) {
      for (const p of lib) {
        for (const b of banned) {
          assert.ok(!b.test(p.payload), `destructive payload in library: ${p.payload}`);
        }
      }
    }
  });
  it("no XXE billion-laughs shapes", () => {
    for (const p of XXE_VARIANTS) {
      const entities = (p.payload.match(/<!ENTITY/g) || []).length;
      assert.ok(entities <= 3, `too many entities (DoS shape): ${p.payload.slice(0, 60)}`);
    }
  });
});

describe("classifyItem", () => {
  it("classifies SSRF items as ssrf (checked before redirect)", () => {
    const item = TARGET_PROFILES.secscan.battery.find((b) => b.id === "SS-016")!;
    assert.ok(classifyItem(item).includes("ssrf"), `SS-016 classes: ${classifyItem(item)}`);
  });
  it("classifies the planted-SQLi efficacy item as sqli", () => {
    const item = TARGET_PROFILES.secscan.battery.find((b) => b.id === "SS-107")!;
    assert.ok(classifyItem(item).includes("sqli"));
  });
  it("classifies the planted-XSS efficacy item as xss", () => {
    const item = TARGET_PROFILES.secscan.battery.find((b) => b.id === "SS-106")!;
    assert.ok(classifyItem(item).includes("xss"));
  });
  it("covers a meaningful share of the battery, deterministically", () => {
    let withVariants = 0;
    for (const t of FULL_BATTERY_TARGETS) {
      for (const item of TARGET_PROFILES[t].battery) {
        const a = classifyItem(item);
        const b = classifyItem(item);
        assert.deepEqual(a, b, "classification must be deterministic");
        if (a.length > 0) withVariants++;
        assert.ok(a.length <= 4, `${item.id} has too many classes: ${a}`);
      }
    }
    assert.ok(withVariants >= 50, `expected broad coverage, got ${withVariants}`);
  });
});

describe("resolveVariantCap", () => {
  it("defaults: 25 staging, 10 production", () => {
    assert.equal(resolveVariantCap("staging"), DEFAULT_VARIANT_CAP_STAGING);
    assert.equal(resolveVariantCap("production"), DEFAULT_VARIANT_CAP_PRODUCTION);
    assert.equal(DEFAULT_VARIANT_CAP_STAGING, 25);
    assert.equal(DEFAULT_VARIANT_CAP_PRODUCTION, 10);
  });
  it("operator override wins when positive", () => {
    assert.equal(resolveVariantCap("staging", 5), 5);
    assert.equal(resolveVariantCap("production", 50), 50);
  });
  it("non-positive override falls back to default", () => {
    assert.equal(resolveVariantCap("staging", 0), 25);
    assert.equal(resolveVariantCap("staging", -3), 25);
  });
});

describe("variant expansion lifecycle", () => {
  it("startVariantExpansion offers capped, indexed variants", () => {
    const ctx = fakeCtx(5);
    const opened = startVariantExpansion(ctx, "secscan:SS-016", "exploit");
    assert.ok(opened.classes.includes("ssrf"));
    assert.ok(opened.librarySize >= 10);
    assert.equal(opened.cap, 5);
    assert.equal(opened.variants.length, 5);
    opened.variants.forEach((v, i) => {
      assert.equal(v.variantIndex, i);
      assert.equal(v.parentItemId, "SS-016");
    });
    const verdict = ctx.itemLedger.get("secscan:SS-016")!;
    assert.ok(verdict.variants);
    assert.equal(verdict.variants!.planned, 5);
  });
  it("opening twice never resets progress", () => {
    const ctx = fakeCtx(25);
    const first = startVariantExpansion(ctx, "secscan:SS-016", "exploit");
    const v = ctx.itemLedger.get("secscan:SS-016")!;
    v.variants!.executed = 7;
    const again = startVariantExpansion(ctx, "secscan:SS-016", "exploit");
    assert.equal(ctx.itemLedger.get("secscan:SS-016")!.variants!.executed, 7);
    assert.equal(again.variants.length, first.variants.length);
    assert.deepEqual(
      again.variants.map((x) => x.payload),
      first.variants.map((x) => x.payload),
    );
  });
  it("reopens an executed-clean item to pending", () => {
    const ctx = fakeCtx(25);
    const v = ctx.itemLedger.get("secscan:SS-016")!;
    v.disposition = "executed-clean";
    const opened = startVariantExpansion(ctx, "secscan:SS-016", "exploit");
    assert.equal(opened.reopened, true);
    assert.equal(ctx.itemLedger.get("secscan:SS-016")!.disposition, "pending");
  });
  it("item without a library gets no expansion", () => {
    const ctx = fakeCtx(25);
    // WS-065 (RDP shadowing prep) names no injection/traversal/SSRF shape.
    const opened = startVariantExpansion(ctx, "windows:WS-065", "exploit");
    assert.equal(opened.variants.length, 0);
    assert.equal(ctx.itemLedger.get("windows:WS-065")!.variants, undefined);
  });
  it("hasActiveVariantExpansion tracks exhaustion", () => {
    const ctx = fakeCtx(25);
    assert.equal(hasActiveVariantExpansion(ctx.itemLedger, "secscan:SS-016"), false);
    startVariantExpansion(ctx, "secscan:SS-016", "exploit");
    assert.equal(hasActiveVariantExpansion(ctx.itemLedger, "secscan:SS-016"), true);
  });
});

describe("cap enforcement + execution", () => {
  it("checkVariantCap denies past the cap, allows below it", () => {
    const ctx = fakeCtx(3);
    startVariantExpansion(ctx, "secscan:SS-016", "exploit");
    const args = { batteryItem: "SS-016", variantIndex: 0 };
    assert.equal(checkVariantCap(ctx.itemLedger, args), undefined);
    const v = ctx.itemLedger.get("secscan:SS-016")!;
    v.variants!.executed = 3;
    const denial = checkVariantCap(ctx.itemLedger, args);
    assert.ok(denial, "expected a denial past the cap");
    assert.match(denial!, /DENIED.*variant cap reached.*secscan:SS-016/);
  });
  it("checkVariantCap ignores non-variant calls", () => {
    const ctx = fakeCtx(3);
    assert.equal(checkVariantCap(ctx.itemLedger, { batteryItem: "SS-016" }), undefined);
    assert.equal(checkVariantCap(ctx.itemLedger, {}), undefined);
  });
  it("recordVariantExecution increments and settles on exhaustion", () => {
    const ctx = fakeCtx(2);
    startVariantExpansion(ctx, "secscan:SS-016", "exploit");
    // SS-016 carries an unmet canary-infrastructure prerequisite → blocked.
    // Variant executions still count; exhaustion settles it honestly.
    assert.equal(ctx.itemLedger.get("secscan:SS-016")!.disposition, "blocked");
    const args = { batteryItem: "SS-016", variantIndex: 0, targetProfile: "secscan" };
    recordVariantExecution(ctx, args, "exploit");
    let v: ItemVerdict = ctx.itemLedger.get("secscan:SS-016")!;
    assert.equal(v.variants!.executed, 1);
    assert.equal(v.disposition, "blocked");
    recordVariantExecution(ctx, { ...args, variantIndex: 1 }, "exploit");
    v = ctx.itemLedger.get("secscan:SS-016")!;
    assert.equal(v.variants!.executed, 2);
    assert.equal(v.disposition, "executed-clean");
    assert.match(v.reason ?? "", /Variant expansion complete: 2\/2/);
  });
  it("closeVariantExpansion settles early with honest counts", () => {
    const ctx = fakeCtx(25);
    startVariantExpansion(ctx, "secscan:SS-016", "exploit");
    const v0 = ctx.itemLedger.get("secscan:SS-016")!;
    v0.variants!.executed = 4;
    const msg = closeVariantExpansion(ctx, "secscan:SS-016", "exploit");
    assert.match(msg, /4\/15 variants executed/);
    assert.equal(ctx.itemLedger.get("secscan:SS-016")!.disposition, "executed-clean");
  });
  it("closeVariantExpansion with nothing open says so", () => {
    const ctx = fakeCtx(25);
    assert.match(closeVariantExpansion(ctx, "secscan:SS-016", "exploit"), /no variant expansion open/);
  });
});

describe("honest counting", () => {
  it("countVariants separates intents from executions", () => {
    const ctx = fakeCtx(25);
    startVariantExpansion(ctx, "secscan:SS-016", "exploit");
    const v = ctx.itemLedger.get("secscan:SS-016")!;
    v.variants!.executed = 9;
    v.variants!.confirmed = 2;
    const c = countVariants(ctx.itemLedger);
    assert.equal(c.intents, ctx.itemLedger.size);
    assert.ok(c.intents >= 416);
    assert.equal(c.variantExecutions, 9);
    assert.equal(c.variantConfirmed, 2);
    assert.equal(c.itemsWithVariants, 1);
  });
  it("variantCountLine never merges the two numbers", () => {
    const line = variantCountLine({ intents: 416, variantExecutions: 137, variantConfirmed: 3, itemsWithVariants: 12, itemsCapped: 1 });
    assert.match(line, /137/);
    assert.match(line, /416/);
    assert.match(line, /never merged/);
    // no single "553 attacks"-style figure
    assert.ok(!/\b553\b/.test(line));
  });
});

describe("variant_list tool wiring", () => {
  it("is a Tier 0 bookkeeping tool in recon + exploit sets", () => {
    assert.equal(VARIANT_LIST_TOOL.name, "variant_list");
    assert.equal(toolMinTier("variant_list"), 0);
    assert.ok(EXPLOIT_TOOLS.some((t) => t.name === "variant_list"), "missing from EXPLOIT_TOOLS");
    assert.ok(RECON_TOOLS.some((t) => t.name === "variant_list"), "missing from RECON_TOOLS");
  });
});
