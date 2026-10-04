/**
 * dist-hash.mjs — stamp and verify that dist/ was built from current src/.
 *
 * Background: llm-router/src/policy.ts once changed without rebuilding the
 * git-ignored dist/, and the runner (which imports compiled dist) silently
 * ran the OLD policy. This makes that class of bug impossible to miss.
 *
 * Mechanism: every workspace build stamps dist/.src-hash with a sha256 over
 * every file under src/ (sorted relative paths + contents). `check` recomputes
 * and fails loudly on any mismatch or missing stamp.
 *
 * The runner ALSO enforces this at engagement start (see
 * runner/src/safety/distfresh.ts, which reimplements the same hash — the two
 * implementations must stay byte-identical).
 *
 * Usage (cwd = workspace dir, or pass the dir explicitly):
 *   node ../scripts/dist-hash.mjs write [dir]       # stamp dist/.src-hash
 *   node ../scripts/dist-hash.mjs check [dir]       # exit 0 fresh / 1 stale
 *   node ../scripts/dist-hash.mjs check-all [dirs]  # all workspaces (default:
 *                                                   #   workspaces[] in root package.json)
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HASH_VERSION = 1;
const STAMP_NAME = ".src-hash";
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** sha256 over sorted (relpath + NUL + content) for every regular file under srcDir. */
export function hashSrcDir(srcDir) {
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) files.push(full);
    }
  };
  walk(srcDir);
  files.sort((a, b) => rel(a, srcDir).localeCompare(rel(b, srcDir)));
  const h = createHash("sha256");
  for (const full of files) {
    h.update(rel(full, srcDir));
    h.update("\0");
    h.update(readFileSync(full));
    h.update("\0");
  }
  return { sha256: h.digest("hex"), files: files.length };
}

function rel(full, base) {
  return relative(base, full).split(sep).join("/");
}

function stampFor(workspaceDir) {
  return {
    srcDir: join(workspaceDir, "src"),
    distDir: join(workspaceDir, "dist"),
    stampPath: join(workspaceDir, "dist", STAMP_NAME),
  };
}

function workspaceName(workspaceDir) {
  try {
    return JSON.parse(readFileSync(join(workspaceDir, "package.json"), "utf8")).name ?? workspaceDir;
  } catch {
    return workspaceDir;
  }
}

/** Write the stamp. Throws on error (build scripts chain with &&, so this fails the build). */
export function writeStamp(workspaceDir) {
  const { srcDir, distDir, stampPath } = stampFor(workspaceDir);
  if (!existsSync(srcDir)) throw new Error(`[dist-hash] no src/ in ${workspaceDir} — refusing to stamp`);
  if (!existsSync(distDir)) throw new Error(`[dist-hash] no dist/ in ${workspaceDir} — build must emit dist/ before stamping`);
  const { sha256, files } = hashSrcDir(srcDir);
  mkdirSync(distDir, { recursive: true });
  writeFileSync(
    stampPath,
    JSON.stringify({ v: HASH_VERSION, sha256, files, writtenAt: new Date().toISOString() }) + "\n",
  );
  console.log(`[dist-hash] stamped ${workspaceName(workspaceDir)}: ${files} src files → ${stampPath}`);
}

/**
 * Check freshness. Returns { fresh: true } or { fresh: false, reason }.
 * Never throws for stale state — the caller decides how loud to be.
 */
export function checkFresh(workspaceDir) {
  const { srcDir, stampPath } = stampFor(workspaceDir);
  const name = workspaceName(workspaceDir);
  if (!existsSync(srcDir)) return { fresh: false, reason: `${name}: src/ missing` };
  if (!existsSync(stampPath)) {
    return {
      fresh: false,
      reason: `${name}: STALE BUILD — dist/ was never stamped (build without the hash step, or dist/ deleted). Run \`npm run build\` from the repo root.`,
    };
  }
  let stamp;
  try {
    stamp = JSON.parse(readFileSync(stampPath, "utf8"));
  } catch {
    return { fresh: false, reason: `${name}: STALE BUILD — dist/${STAMP_NAME} is corrupt. Run \`npm run build\` from the repo root.` };
  }
  if (stamp.v !== HASH_VERSION || typeof stamp.sha256 !== "string") {
    return { fresh: false, reason: `${name}: STALE BUILD — dist/${STAMP_NAME} has an unknown format. Run \`npm run build\` from the repo root.` };
  }
  const { sha256, files } = hashSrcDir(srcDir);
  if (stamp.sha256 !== sha256) {
    return {
      fresh: false,
      reason:
        `${name}: STALE BUILD — src/ changed since dist/ was built ` +
        `(${files} files now, stamp covers ${stamp.files ?? "?"}). ` +
        `Run \`npm run build\` from the repo root and retry.`,
    };
  }
  return { fresh: true };
}

function defaultWorkspaces() {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  return (pkg.workspaces ?? []).map((w) => join(ROOT, w));
}

const [, , cmd, ...args] = process.argv;

if (cmd === "write") {
  writeStamp(args[0] ?? process.cwd());
} else if (cmd === "check") {
  const dir = args[0] ?? process.cwd();
  const r = checkFresh(dir);
  if (r.fresh) {
    console.log(`[dist-hash] FRESH: ${workspaceName(dir)}`);
  } else {
    console.error(`[dist-hash] ${r.reason}`);
    process.exit(1);
  }
} else if (cmd === "check-all") {
  const dirs = args.length > 0 ? args : defaultWorkspaces();
  let failed = 0;
  for (const dir of dirs) {
    // Only workspaces that actually compile src/ → dist/ participate.
    if (!existsSync(join(dir, "src"))) continue;
    const r = checkFresh(dir);
    if (r.fresh) console.log(`[dist-hash] FRESH: ${workspaceName(dir)}`);
    else {
      console.error(`[dist-hash] ${r.reason}`);
      failed++;
    }
  }
  if (failed > 0) process.exit(1);
  console.log("[dist-hash] all workspace dists fresh");
} else {
  console.error("usage: dist-hash.mjs <write|check|check-all> [dir...]");
  process.exit(2);
}
