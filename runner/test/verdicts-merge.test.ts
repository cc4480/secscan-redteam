/**
 * VERDICTS-block merge tests (audit batch 3 — LLM free text becomes
 * permanent registry entries here; only the atomic writer was tested).
 *
 * mergeVerdictBlock(ctx, text) is the backstop that merges the exploiter's
 * final VERDICTS JSON block into shared state + the registry. Since T6 made
 * recorded verdicts the findings source-of-truth, this merge's contract is:
 *   - confirmed/killed verdicts land in live state + the registry file,
 *   - duplicates collapse (confirmed by title+attackId, killed by
 *     hypothesis) and never double-count against live-recorded findings,
 *   - severities are coerced through the shared whitelist (unknown → low),
 *   - malformed blocks and malformed entries never corrupt the record
 *     and never throw — garbage in, nothing merged, engagement survives.
 *
 * Tmp dirs only; real EventLog + real registry file, no network.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EventLog, readEvents } from "../src/events.js";
import { emptyRegistry, loadRegistryFile } from "../src/registry.js";
import { mergeVerdictBlock } from "../src/dispatch/verdicts.js";
import type { Ctx } from "../src/context.js";

let tmp = "";

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "verdicts-merge-test-"));
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

let n = 0;
function makeCtx(): Ctx {
  n++;
  const dir = join(tmp, `eng-${n}`);
  return {
    events: new EventLog(dir, `eng-${n}`, { target: "t", mode: "red", objective: "o" }),
    registry: emptyRegistry(),
    registryPath: join(tmp, `registry-${n}.json`),
    fingerprint: { host: "h", stack: [], appType: "t" },
    liveFindings: [],
    killedLive: [],
  } as unknown as Ctx;
}

function fenced(verdicts: unknown): string {
  return `Exploiter summary prose.\n\n\`\`\`json\n${JSON.stringify({ verdicts })}\n\`\`\`\n`;
}

function stateFindings(ctx: Ctx): Array<Record<string, unknown>> {
  const statePath = join(ctx.events.dir, "state.json");
  assert.ok(existsSync(statePath), "state.json should exist after a merge");
  const state = JSON.parse(readFileSync(statePath, "utf8")) as { findings: Array<Record<string, unknown>> };
  return state.findings;
}

function mergedEvents(ctx: Ctx): Array<{ action: string; result: string }> {
  return readEvents(ctx.events.dir).filter((e) => e.action === "verdicts_merged");
}

describe("mergeVerdictBlock — confirmed verdicts", () => {
  it("merges confirmed verdicts into live state, state.json, the registry file, and logs the merge", () => {
    const ctx = makeCtx();
    // Documented VERDICTS shape (runner/src/prompts/exploiter.ts): the
    // confirmed entry carries vulnClass, not a title — the merged finding's
    // title IS the vulnClass. A stray title field is only a fallback.
    mergeVerdictBlock(ctx, fenced([
      { kind: "confirmed", severity: "high", vulnClass: "sqli", technique: "Exploit Public-Facing Application", attackId: "t1190", evidence: "UNION SELECT echoed rows", payloadPattern: "' OR 1=1" },
      { kind: "confirmed", severity: "medium", title: "Verbose errors", attackId: "T1595", evidence: "stack trace in 500" },
    ]));
    assert.equal(ctx.liveFindings.length, 2);
    assert.equal(ctx.liveFindings[0]!.title, "sqli");
    assert.equal(ctx.liveFindings[0]!.vulnClass, "sqli");
    assert.equal(ctx.liveFindings[0]!.attackId, "T1190");
    assert.equal(ctx.liveFindings[1]!.title, "Verbose errors", "title field is the fallback when vulnClass is absent");

    const reg = loadRegistryFile(ctx.registryPath)!;
    assert.equal(reg.confirmed.length, 2);
    assert.equal(reg.confirmed[0]!.vulnClass, "sqli");
    assert.equal(reg.confirmed[0]!.severity, "high");
    assert.equal(ctx.registry.confirmed.length, 2, "in-memory mirror tracks the file");

    const findings = stateFindings(ctx);
    assert.equal(findings.length, 2);
    assert.equal(findings[0]!.id, "F-1");
    assert.equal(findings[0]!.severity, "high");
    assert.equal(findings[0]!.status, "confirmed");

    const merged = mergedEvents(ctx);
    assert.equal(merged.length, 1);
    assert.match(merged[0]!.result, /Merged 2 verdict\(s\)/);
  });

  it("accepts a bare (unfenced) JSON block too", () => {
    const ctx = makeCtx();
    mergeVerdictBlock(ctx, JSON.stringify({
      verdicts: [{ kind: "confirmed", severity: "low", title: "Info leak", attackId: "T1595", evidence: "banner" }],
    }));
    assert.equal(ctx.liveFindings.length, 1);
    assert.equal(ctx.liveFindings[0]!.title, "Info leak");
  });

  it("defaults: missing severity → low, missing attackId → T1190, missing vulnClass → title fallback", () => {
    const ctx = makeCtx();
    mergeVerdictBlock(ctx, fenced([
      { kind: "confirmed", evidence: "e" },
      { kind: "confirmed", title: "Has title only", evidence: "e2" },
    ]));
    assert.equal(ctx.liveFindings[0]!.severity, "low");
    assert.equal(ctx.liveFindings[0]!.title, "finding");
    assert.equal(ctx.liveFindings[0]!.attackId, "T1190");
    assert.equal(ctx.liveFindings[1]!.title, "Has title only");
    const reg = loadRegistryFile(ctx.registryPath)!;
    assert.equal(reg.confirmed[0]!.vulnClass, "unclassified");
    assert.equal(stateFindings(ctx)[0]!.severity, "low");
  });

  it("coerces severity through the whitelist: case-normalized, unknown → low", () => {
    const ctx = makeCtx();
    // Distinct vulnClass+payloadPattern per verdict: the registry writer
    // dedupes per engagement on (vulnClass, payloadPattern) — see
    // concurrency.test.ts — so class-less lookalikes would collapse there
    // even though the merge keeps all three live.
    mergeVerdictBlock(ctx, fenced([
      { kind: "confirmed", severity: "CRITICAL", vulnClass: "sqli", payloadPattern: "p1", attackId: "T1190", evidence: "e" },
      { kind: "confirmed", severity: "nucular", vulnClass: "xss", payloadPattern: "p2", attackId: "T1190", evidence: "e" },
      { kind: "confirmed", vulnClass: "ssrf", payloadPattern: "p3", attackId: "T1190", evidence: "e" },
    ]));
    assert.equal(ctx.liveFindings.length, 3);
    const reg = loadRegistryFile(ctx.registryPath)!;
    assert.deepEqual(reg.confirmed.map((e) => e.severity), ["critical", "low", "low"]);
    assert.deepEqual(stateFindings(ctx).map((f) => f.severity), ["critical", "low", "low"]);
  });

  it("redacts PII from merged titles and evidence before they persist", () => {
    const ctx = makeCtx();
    mergeVerdictBlock(ctx, fenced([
      { kind: "confirmed", severity: "high", title: "PII for 123-45-6789", attackId: "T1190", evidence: "row for ssn 123-45-6789 dumped" },
    ]));
    assert.ok(!JSON.stringify(ctx.liveFindings).includes("123-45-6789"));
    const reg = loadRegistryFile(ctx.registryPath)!;
    assert.ok(!JSON.stringify(reg).includes("123-45-6789"));
  });
});

describe("mergeVerdictBlock — dedupe", () => {
  it("collapses duplicate confirmed verdicts by title+attackId (first writer wins, even on severity conflict)", () => {
    const ctx = makeCtx();
    mergeVerdictBlock(ctx, fenced([
      { kind: "confirmed", severity: "high", title: "SQLi in login", attackId: "T1190", evidence: "first" },
      { kind: "confirmed", severity: "low", title: "SQLi in login", attackId: "t1190", evidence: "second" },
    ]));
    assert.equal(ctx.liveFindings.length, 1);
    assert.equal(ctx.liveFindings[0]!.evidence, "first");
    const reg = loadRegistryFile(ctx.registryPath)!;
    assert.equal(reg.confirmed.length, 1);
    assert.equal(reg.confirmed[0]!.severity, "high");
    assert.match(mergedEvents(ctx)[0]!.result, /Merged 1 verdict\(s\)/);
  });

  it("same title with a different attackId is a distinct finding (not deduped)", () => {
    const ctx = makeCtx();
    mergeVerdictBlock(ctx, fenced([
      { kind: "confirmed", severity: "high", title: "Injection", attackId: "T1190", evidence: "e1" },
      { kind: "confirmed", severity: "high", title: "Injection", attackId: "T1059", evidence: "e2" },
    ]));
    assert.equal(ctx.liveFindings.length, 2);
  });

  it("never duplicates a finding already recorded live (record_finding path)", () => {
    const ctx = makeCtx();
    ctx.liveFindings.push({
      severity: "high", title: "SQLi in login", vulnClass: "sqli", attackId: "T1190", evidence: "live", payload: "p",
    });
    mergeVerdictBlock(ctx, fenced([
      { kind: "confirmed", severity: "high", title: "SQLi in login", attackId: "T1190", evidence: "from block" },
    ]));
    assert.equal(ctx.liveFindings.length, 1);
    assert.equal(ctx.liveFindings[0]!.evidence, "live");
    assert.equal(mergedEvents(ctx).length, 0, "nothing merged → no merge event");
  });
});

describe("mergeVerdictBlock — killed verdicts", () => {
  it("merges killed hypotheses into live state + registry, deduped by hypothesis", () => {
    const ctx = makeCtx();
    mergeVerdictBlock(ctx, fenced([
      { kind: "killed", hypothesis: "SSRF via webhook", killingObservation: "callback never fired", attackId: "t1190" },
      { kind: "killed", hypothesis: "SSRF via webhook", killingObservation: "duplicate of the above" },
      { kind: "killed", hypothesis: "Auth bypass via header", killingObservation: "401 on all variants", vulnClass: "auth" },
    ]));
    assert.equal(ctx.killedLive.length, 2);
    assert.equal(ctx.killedLive[0]!.attackId, "T1190");
    const reg = loadRegistryFile(ctx.registryPath)!;
    assert.equal(reg.killed.length, 2);
    assert.match(mergedEvents(ctx)[0]!.result, /Merged 2 verdict\(s\)/);
  });

  it("skips killed verdicts with an empty hypothesis", () => {
    const ctx = makeCtx();
    mergeVerdictBlock(ctx, fenced([
      { kind: "killed", hypothesis: "", killingObservation: "nothing" },
      { kind: "killed", killingObservation: "no hypothesis at all" },
    ]));
    assert.equal(ctx.killedLive.length, 0);
    assert.equal(mergedEvents(ctx).length, 0);
  });
});

describe("mergeVerdictBlock — malformed input never corrupts the record", () => {
  it("ignores text with no parseable JSON and non-verdicts JSON without throwing", () => {
    const ctx = makeCtx();
    const inputs = [
      "no json here at all",
      "",
      "```json\n{not valid json,,,\n```",
      JSON.stringify({ findings: [] }),
      JSON.stringify({ verdicts: "not-an-array" }),
      JSON.stringify({ verdicts: 42 }),
      JSON.stringify(["just", "an", "array"]),
    ];
    for (const text of inputs) {
      assert.doesNotThrow(() => mergeVerdictBlock(ctx, text), JSON.stringify(text));
    }
    assert.equal(ctx.liveFindings.length, 0);
    assert.equal(ctx.killedLive.length, 0);
    assert.equal(mergedEvents(ctx).length, 0);
    assert.ok(!existsSync(ctx.registryPath), "nothing merged → no registry file written");
  });

  it("skips malformed entries (nulls, primitives, unknown kinds) and still merges the valid ones", () => {
    const ctx = makeCtx();
    const text = fenced([
      null,
      42,
      "a string, not a verdict",
      { kind: "note", text: "unknown kind — ignored" },
      { noKind: true },
      { kind: "confirmed", severity: "critical", title: "Real one", attackId: "T1190", evidence: "proven" },
      null,
    ]);
    assert.doesNotThrow(() => mergeVerdictBlock(ctx, text));
    assert.equal(ctx.liveFindings.length, 1);
    assert.equal(ctx.liveFindings[0]!.title, "Real one");
    const reg = loadRegistryFile(ctx.registryPath)!;
    assert.equal(reg.confirmed.length, 1);
    assert.equal(reg.confirmed[0]!.severity, "critical");
    assert.match(mergedEvents(ctx)[0]!.result, /Merged 1 verdict\(s\)/);
  });

  it("an entirely malformed block leaves pre-recorded findings untouched", () => {
    const ctx = makeCtx();
    ctx.liveFindings.push({
      severity: "high", title: "Recorded live", vulnClass: "sqli", attackId: "T1190", evidence: "proof", payload: "p",
    });
    assert.doesNotThrow(() => mergeVerdictBlock(ctx, "garbage {{{ not json"));
    assert.doesNotThrow(() => mergeVerdictBlock(ctx, fenced([null, { kind: "confirmed" }])));
    assert.equal(ctx.liveFindings.length, 2, "the {kind:confirmed} shell merges with defaults; the live one is untouched");
    assert.equal(ctx.liveFindings[0]!.title, "Recorded live");
    assert.equal(ctx.liveFindings[0]!.evidence, "proof");
  });
});
