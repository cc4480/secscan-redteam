/**
 * copy-dir.mjs — cross-platform recursive directory copy for build scripts.
 *
 * Background: the runner build used `rm -rf <dest> && mkdir -p <dest> &&
 * cp -r <src>/. <dest>/` to stage its web-UI assets into dist/. Those are
 * Unix shell builtins; on Windows npm runs scripts through cmd.exe, where
 * they fail ("The syntax of the command is incorrect.") — which killed the
 * build before dist-hash.mjs could stamp dist/, tripping the stale-build
 * gate and blocking every runner test and engagement on Windows.
 *
 * This replaces that shell chain with Node's own fs (built-in, no deps):
 * remove <dest>, recreate it, then recursively copy <src> into it. Same
 * net effect as the old `cp -r <src>/. <dest>/`, on every platform.
 *
 * Usage (cwd = workspace dir, or pass absolute/relative paths):
 *   node ../scripts/copy-dir.mjs <src> <dest>
 */

import { cpSync, existsSync, mkdirSync, rmSync, statSync } from "node:fs";
import { resolve } from "node:path";

const [src, dest] = process.argv.slice(2);
if (!src || !dest) {
  console.error("usage: node copy-dir.mjs <src> <dest>");
  process.exit(2);
}

const srcAbs = resolve(src);
const destAbs = resolve(dest);

if (!existsSync(srcAbs) || !statSync(srcAbs).isDirectory()) {
  console.error(`[copy-dir] source is not a directory: ${srcAbs}`);
  process.exit(1);
}

// Fresh copy: clear any previous contents (matches the old `rm -rf <dest>`),
// then recreate and copy. `cpSync` recursive needs the parent to exist.
rmSync(destAbs, { recursive: true, force: true });
mkdirSync(destAbs, { recursive: true });
cpSync(srcAbs, destAbs, { recursive: true });

console.log(`[copy-dir] ${src} -> ${dest}`);
