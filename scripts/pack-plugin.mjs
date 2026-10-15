/**
 * pack-plugin.mjs — build a SELF-CONTAINED tarball of the harness plugin.
 *
 * Background: `npm pack harness-plugin` produces a tarball that cannot be
 * installed. The plugin imports two sibling workspace packages at runtime:
 *
 *   dist/auth-gate.js       -> @secscan/redteam-auth-gate
 *   dist/index.js           -> @secscan/redteam-llm-router
 *   dist/redteam-profile.js -> @secscan/redteam-llm-router
 *
 * Those are pnpm workspace links (junctions into this repo) and every package
 * here is `private: true`, so nothing is on the npm registry. Installing the
 * plain tarball therefore fails with:
 *
 *   npm error 404 Not Found - GET .../@secscan%2Fredteam-auth-gate
 *
 * Both siblings have ZERO runtime dependencies of their own (devDeps only),
 * so inlining them is cheap: dist/ + package.json each.
 *
 * This script stages the plugin, inlines those two packages under
 * node_modules/@secscan/, declares them bundled, and packs the result. The
 * tarball installs with no registry access and loads standalone.
 *
 * Verified 2026-10-15: `npm install <tarball>` in a clean dir ->
 * `import('@secscan/redteam-harness-plugin')` -> "LOADED OK; exports:
 * apply,inject,name,plugin".
 *
 * The peerDependencies (@deepseek-ai/cordis, @deepseek-ai/dsh-tools) are NOT
 * bundled: the DSH host provides them, which is what `peerDependencies` means.
 *
 * Usage (from the repo root or anywhere):
 *   node scripts/pack-plugin.mjs [--out <dir>]
 *
 * Exit codes: 0 packed · 1 stale dist or missing build output.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PLUGIN_DIR = join(ROOT, "harness-plugin");

/** Workspace packages inlined into the plugin tarball, in dependency order. */
const BUNDLED = [
  { dir: "auth-gate", name: "@secscan/redteam-auth-gate" },
  { dir: "llm-router", name: "@secscan/redteam-llm-router" },
];

const outIdx = process.argv.indexOf("--out");
const OUT_DIR = outIdx !== -1 && process.argv[outIdx + 1] ? process.argv[outIdx + 1] : ROOT;

function fail(msg) {
  console.error(`[pack-plugin] ${msg}`);
  process.exit(1);
}

function pkg(dir) {
  return JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
}

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

// ---------------------------------------------------------------- 1. dist fresh
// A self-contained tarball of a stale build is worse than no tarball: it ships
// old behaviour with no way for the consumer to notice. Reuse the same gate the
// repo already uses everywhere else.
try {
  execFileSync(process.execPath, [join(ROOT, "scripts", "dist-hash.mjs"), "check-all"], {
    cwd: ROOT, stdio: "pipe",
  });
} catch (err) {
  const out = `${err.stdout ?? ""}${err.stderr ?? ""}`.trim();
  fail(`dist is STALE — refusing to pack.\n${out}\nRun: npm run build`);
}

for (const d of [join("harness-plugin", "dist"), ...BUNDLED.map((b) => join(b.dir, "dist"))]) {
  if (!existsSync(join(ROOT, d))) fail(`missing build output: ${d} — run: npm run build`);
}

// ---------------------------------------------------------------- 2. stage
const stage = mkdtempSync(join(tmpdir(), "rt-plugin-pack-"));
try {
  const meta = pkg(PLUGIN_DIR);
  cpSync(join(PLUGIN_DIR, "dist"), join(stage, "dist"), { recursive: true });
  cpSync(join(PLUGIN_DIR, "cordis.patch.yml"), join(stage, "cordis.patch.yml"));
  cpSync(join(PLUGIN_DIR, "package.json"), join(stage, "package.json"));

  // ------------------------------------------------------------ 3. inline deps
  const scope = join(stage, "node_modules", "@secscan");
  mkdirSync(scope, { recursive: true });
  for (const b of BUNDLED) {
    const target = join(scope, b.name.split("/")[1]);
    mkdirSync(target, { recursive: true });
    cpSync(join(ROOT, b.dir, "dist"), join(target, "dist"), { recursive: true });
    cpSync(join(ROOT, b.dir, "package.json"), join(target, "package.json"));
    const v = pkg(join(ROOT, b.dir)).version;
    console.log(`[pack-plugin] inlined ${b.name}@${v}`);
  }

  // npm only bundles what is both declared AND physically present.
  const bundledNames = BUNDLED.map((b) => b.name);
  const declared = meta.bundledDependencies ?? [];
  const missing = bundledNames.filter((n) => !declared.includes(n));
  if (missing.length) fail(`package.json bundledDependencies is missing: ${missing.join(", ")}`);

  // ------------------------------------------------------------ 4. pack
  // npm pack --pack-destination does NOT create the directory (ENOENT if absent).
  //
  // Invoking npm needs care on Windows:
  //   * execFileSync("npm", ...)            -> ENOENT
  //   * execFileSync("npm.cmd", ...)        -> EINVAL on Node >= 20.12, which
  //                                            refuses to spawn .cmd without a shell
  //   * shell: true                         -> works, but DEP0190: args are
  //                                            concatenated unescaped, so an
  //                                            OUT_DIR containing spaces breaks
  // So run npm's CLI entry through the current node binary instead.
  mkdirSync(OUT_DIR, { recursive: true });
  const npmCli = [
    join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
    join(dirname(process.execPath), "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ].find(existsSync);
  if (!npmCli) fail("could not locate npm-cli.js next to the running node binary");

  const args = ["pack", "--pack-destination", OUT_DIR];
  const name = execFileSync(process.execPath, [npmCli, ...args], { cwd: stage, encoding: "utf8" })
    .trim().split("\n").pop().trim();
  const tgz = join(OUT_DIR, name);

  // ------------------------------------------------------------ 5. report
  const kb = (statSync(tgz).size / 1024).toFixed(1);
  console.log(`[pack-plugin] packed ${meta.name}@${meta.version}`);
  console.log(`[pack-plugin]   ${tgz}`);
  console.log(`[pack-plugin]   ${kb} KB`);
  console.log(`[pack-plugin]   sha256 ${sha256(tgz)}`);
  console.log("[pack-plugin] installs standalone: npm install <tarball>  (no registry needed)");
} finally {
  rmSync(stage, { recursive: true, force: true });
}
