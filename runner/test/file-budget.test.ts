/**
 * File budget enforcement (v0.20.0) — the v0.19.0 hard rule, mechanical.
 *
 * No file under runner/src may exceed 300 lines. This test walks the
 * compiled tree's source directory and fails the suite on any violation,
 * so the rule can't silently rot.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

/** runner/src — resolved from the compiled test location (dist-test/test). */
function srcDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
}

function walkTs(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walkTs(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

describe("file budget", () => {
  it("no runner/src file exceeds 300 lines (wc -l semantics)", () => {
    const files = walkTs(srcDir());
    assert.ok(files.length > 100, `expected the full source tree, found ${files.length} files`);
    const over = files
      .map((f) => ({ file: f, lines: (readFileSync(f, "utf8").match(/\n/g) || []).length }))
      .filter(({ lines }) => lines > 300);
    assert.deepEqual(
      over.map(({ file }) => file),
      [],
      `files over the 300-line budget:\n${over.map(({ file, lines }) => `  ${lines}  ${file}`).join("\n")}`,
    );
  });
});
