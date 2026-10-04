/**
 * Dist-freshness tests: a stale compiled dist/ running against newer src/ is a
 * silent-safety bug (the llm-router policy switch changed src without
 * rebuilding dist, and the runner kept routing to the retired provider).
 *
 * Covers:
 *  - hashSrcDir is deterministic and content-sensitive
 *  - the build-time stamper (scripts/dist-hash.mjs) and the runtime checker
 *    (safety/distfresh.ts) compute BYTE-IDENTICAL hashes (parity test —
 *    if these drift, the guard is useless)
 *  - distIsFresh: missing stamp → stale; stamped → fresh; src touched → stale;
 *    installed package (no src/) → not flagged
 *  - findWorkspaceRoot climbs out of the dist-test layout to the workspace root
 *  - assertDistFresh honors REDTEAM_SKIP_DIST_CHECK=1
 * No live engagement, no network — tmp fixture dirs only.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { distIsFresh, findWorkspaceRoot, hashSrcDir, assertDistFresh } from "../src/safety/distfresh.js";

const SCRIPT = join(process.cwd(), "..", "scripts", "dist-hash.mjs");

function makeFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), "distfresh-"));
  mkdirSync(join(dir, "src", "nested"), { recursive: true });
  writeFileSync(join(dir, "src", "a.ts"), "export const a = 1;\n");
  writeFileSync(join(dir, "src", "nested", "b.ts"), "export const b = 2;\n");
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture" }));
  mkdirSync(join(dir, "dist"), { recursive: true });
  return dir;
}

describe("hashSrcDir", () => {
  let dir = "";
  beforeEach(() => { dir = makeFixture(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("is deterministic across runs", () => {
    const h1 = hashSrcDir(join(dir, "src"));
    const h2 = hashSrcDir(join(dir, "src"));
    assert.equal(h1.sha256, h2.sha256);
    assert.equal(h1.files, 2);
  });

  it("changes when any src file changes", () => {
    const before = hashSrcDir(join(dir, "src")).sha256;
    writeFileSync(join(dir, "src", "a.ts"), "export const a = 999;\n");
    assert.notEqual(hashSrcDir(join(dir, "src")).sha256, before);
  });

  it("changes when a src file is added", () => {
    const before = hashSrcDir(join(dir, "src")).sha256;
    writeFileSync(join(dir, "src", "c.ts"), "export const c = 3;\n");
    const after = hashSrcDir(join(dir, "src"));
    assert.notEqual(after.sha256, before);
    assert.equal(after.files, 3);
  });
});

describe("stamper/checker parity (scripts/dist-hash.mjs vs safety/distfresh.ts)", () => {
  let dir = "";
  beforeEach(() => { dir = makeFixture(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("script-written stamp matches the TS hash byte-for-byte", () => {
    execFileSync(process.execPath, [SCRIPT, "write", dir], { stdio: "pipe" });
    const stamp = JSON.parse(readFileSync(join(dir, "dist", ".src-hash"), "utf8"));
    const tsHash = hashSrcDir(join(dir, "src"));
    assert.equal(stamp.sha256, tsHash.sha256);
    assert.equal(stamp.files, tsHash.files);
  });

  it("script check passes on a fresh fixture", () => {
    execFileSync(process.execPath, [SCRIPT, "write", dir], { stdio: "pipe" });
    execFileSync(process.execPath, [SCRIPT, "check", dir], { stdio: "pipe" }); // throws on nonzero exit
  });

  it("script check fails loudly after src changes", () => {
    execFileSync(process.execPath, [SCRIPT, "write", dir], { stdio: "pipe" });
    writeFileSync(join(dir, "src", "a.ts"), "// the original bug: src changed, dist not rebuilt\n");
    assert.throws(
      () => execFileSync(process.execPath, [SCRIPT, "check", dir], { stdio: "pipe" }),
      /STALE BUILD/,
    );
  });
});

describe("distIsFresh", () => {
  let dir = "";
  beforeEach(() => { dir = makeFixture(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("missing stamp is stale with a clear rebuild message", () => {
    const r = distIsFresh(dir, "fixture");
    assert.equal(r.fresh, false);
    assert.match(r.reason ?? "", /STALE BUILD/);
    assert.match(r.reason ?? "", /npm run build/);
  });

  it("stamped fixture is fresh", () => {
    execFileSync(process.execPath, [SCRIPT, "write", dir], { stdio: "pipe" });
    assert.equal(distIsFresh(dir, "fixture").fresh, true);
  });

  it("touched src after stamping is stale", () => {
    execFileSync(process.execPath, [SCRIPT, "write", dir], { stdio: "pipe" });
    writeFileSync(join(dir, "src", "nested", "b.ts"), "export const b = 'changed';\n");
    const r = distIsFresh(dir, "fixture");
    assert.equal(r.fresh, false);
    assert.match(r.reason ?? "", /src\/ changed since dist\/ was built/);
  });

  it("missing src/ (installed package) is not flagged stale", () => {
    const installed = mkdtempSync(join(tmpdir(), "distfresh-installed-"));
    try {
      writeFileSync(join(installed, "package.json"), JSON.stringify({ name: "fixture" }));
      mkdirSync(join(installed, "dist"), { recursive: true });
      // No src/ shipped with an installed package: the dist IS the artifact.
      assert.equal(distIsFresh(installed, "fixture").fresh, true);
    } finally {
      rmSync(installed, { recursive: true, force: true });
    }
  });
});

describe("findWorkspaceRoot", () => {
  it("climbs from dist-test layout to the workspace root", () => {
    // This test itself runs from <workspace>/dist-test/test — one level deeper
    // than dist/, mirroring the layout assertDistFresh must handle.
    const from = join(process.cwd(), "dist-test", "src", "safety");
    assert.equal(findWorkspaceRoot(from, "@secscan/redteam-runner"), process.cwd());
  });

  it("returns null when no ancestor carries the name", () => {
    assert.equal(findWorkspaceRoot(tmpdir(), "@secscan/does-not-exist"), null);
  });
});

describe("assertDistFresh", () => {
  it("honors REDTEAM_SKIP_DIST_CHECK=1", () => {
    const prev = process.env["REDTEAM_SKIP_DIST_CHECK"];
    process.env["REDTEAM_SKIP_DIST_CHECK"] = "1";
    try {
      assert.doesNotThrow(() => assertDistFresh());
    } finally {
      if (prev === undefined) delete process.env["REDTEAM_SKIP_DIST_CHECK"];
      else process.env["REDTEAM_SKIP_DIST_CHECK"] = prev;
    }
  });
});
