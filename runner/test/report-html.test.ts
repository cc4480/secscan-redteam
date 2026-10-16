/**
 * The HTML report renderer.
 *
 * The runner writes markdown artifacts; the HTML is the human-facing deliverable.
 * The properties worth pinning are the ones that make it safe to hand a pentest
 * report to a client: it must be self-contained (no CDN that 404s on an
 * air-gapped review), it must escape target-derived text, it must colour
 * severity so the critical item is findable at a glance, and it must print to
 * PDF without turning into an unstyled wall.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { renderReportHtml, type ReportMeta } from "../src/report/html.js";

const meta: ReportMeta = {
  engagementId: "eng-2026-01-01-abcd",
  target: "example.com",
  mode: "red",
  environment: "staging",
  tier: 1,
  operator: "Cho-zen",
  client: "Example Corp",
  status: "complete",
  phase: "done",
  verified: true,
  objective: "Map the surface",
  startedAt: "2026-01-01T00:00:00.000Z",
  generatedAt: "2026-01-01T01:00:00.000Z",
  findings: { critical: 1, high: 2, medium: 0, low: 1, info: 3 },
  battery: { total: 418, confirmed: 1, executedClean: 3, killed: 20, blocked: 0, na: 380, pending: 12 },
};

const html = renderReportHtml({
  title: "Penetration Test Report",
  meta,
  markdown: "## Summary\n\n- **[high] SQL injection** in the `id` param.\n- [info] informational note.\n\n`<script>alert(1)</script>` stays escaped.",
});

describe("report HTML — self-contained and safe", () => {
  it("is a full document", () => {
    assert.match(html, /^<!doctype html>/i);
    assert.match(html, /<title>Penetration Test Report — example\.com<\/title>/);
    assert.match(html, /<\/html>\s*$/);
  });

  it("carries no external assets — no CDN, no remote stylesheet, no external script", () => {
    assert.ok(!/cdn\.|googleapis|fonts\.gstatic|bootstrapcdn|unpkg/.test(html), "no CDN");
    assert.ok(!/<link\s+rel=["']stylesheet["']/i.test(html), "no linked stylesheet");
    assert.ok(!/<script[^>]+src=/i.test(html), "no external script");
  });

  it("escapes target-derived HTML rather than rendering it", () => {
    assert.ok(!/<script>alert\(1\)<\/script>/.test(html), "raw script tag must not survive");
    assert.match(html, /&lt;script&gt;/, "it is escaped");
  });

  it("colour-codes severity", () => {
    assert.match(html, /<span class="sev sev-high">high<\/span>/);
    assert.match(html, /<span class="sev sev-info">info<\/span>/);
  });

  it("shows the severity and battery strip", () => {
    assert.match(html, /<div class="strip">/);
    assert.match(html, /Critical/);
    assert.match(html, /Pending/);
    assert.match(html, />12</, "pending count present");
  });

  it("is dark/light aware and print-ready", () => {
    assert.match(html, /prefers-color-scheme/);
    assert.match(html, /@media print/);
  });

  it("marks the record as unindexable", () => {
    assert.match(html, /noindex,nofollow/);
  });
});

describe("report HTML — shape without a strip", () => {
  it("omits the strip when asked (attestation, manifests)", () => {
    const h = renderReportHtml({ title: "Safety Manifest", meta, markdown: "# x", showStrip: false });
    assert.ok(!h.includes('<div class="strip">'));
  });

  it("renders an empty findings set without a NaN or crash", () => {
    const bare = renderReportHtml({
      title: "Attestation",
      meta: { ...meta, findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, battery: undefined },
      markdown: "# x",
    });
    assert.match(bare, />0</);
  });
});

describe("report HTML — hostile metadata", () => {
  it("escapes the objective and client, which an operator can supply", () => {
    const hostile = renderReportHtml({
      title: "Report",
      meta: {
        ...meta,
        client: '"><img src=x onerror=alert(1)>',
        objective: "<b>bold</b> objective",
      },
      markdown: "# x",
    });
    assert.ok(!hostile.includes('"><img src=x onerror='), "attribute injection neutralised");
    assert.ok(!hostile.includes("<b>bold</b>"), "objective HTML escaped");
  });
});
