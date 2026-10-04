/**
 * Dist-freshness guard (safety-relevant, not hygiene).
 *
 * A stale compiled dist/ running against newer src/ is a SILENT safety bug:
 * the llm-router policy switch changed src/policy.ts without rebuilding the
 * git-ignored dist/, and the runner — which imports the compiled dist —
 * kept routing the exploiter to the retired provider until someone rebuilt
 * locally. A stale policy running silently can change WHAT the agents do;
 * that must fail fast, never run.
 *
 * Every engagement start (CLI, UI, watch — all funnel through runEngagement)
 * calls assertDistFresh(), which verifies the runner's own dist/ and the
 * dist/ of the workspace dependencies it imports (llm-router, auth-gate)
 * were built from the current src/. Bypass: REDTEAM_SKIP_DIST_CHECK=1
 * (unit tests only — never set this in operation).
 *
 * The hash MUST stay byte-identical to scripts/dist-hash.mjs (the build-time
 * stamper): sha256 over sorted relative-posix-path + NUL + file bytes + NUL
 * for every regular file under src/.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HASH_VERSION = 1;
const STAMP_NAME = ".src-hash";
const SKIP_ENV = "REDTEAM_SKIP_DIST_CHECK";

/** Workspace packages whose compiled dist the runner imports. */
const CHECKED_DEPS = ["@secscan/redteam-llm-router", "@secscan/redteam-auth-gate"];

function relPosix(full: string, base: string): string {
  return relative(base, full).split(sep).join("/");
}

/**
 * sha256 over every regular file under srcDir.
 * MUST match scripts/dist-hash.mjs hashSrcDir byte-for-byte.
 */
export function hashSrcDir(srcDir: string): { sha256: string; files: number } {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) files.push(full);
    }
  };
  walk(srcDir);
  files.sort((a, b) => relPosix(a, srcDir).localeCompare(relPosix(b, srcDir)));
  const h = createHash("sha256");
  for (const full of files) {
    h.update(relPosix(full, srcDir));
    h.update("\0");
    h.update(readFileSync(full));
    h.update("\0");
  }
  return { sha256: h.digest("hex"), files: files.length };
}

export interface FreshnessResult {
  fresh: boolean;
  /** Human-readable reason when not fresh. */
  reason?: string;
}

/** Check one workspace dir (must contain src/ and dist/.src-hash). Never throws for stale state. */
export function distIsFresh(workspaceDir: string, label: string): FreshnessResult {
  const srcDir = join(workspaceDir, "src");
  const stampPath = join(workspaceDir, "dist", STAMP_NAME);
  if (!existsSync(srcDir)) {
    // Installed package (no src/ shipped): the dist IS the artifact — nothing
    // to be stale against. The guard only applies to source checkouts.
    return { fresh: true };
  }
  if (!existsSync(stampPath)) {
    return {
      fresh: false,
      reason:
        `[runner] STALE BUILD in ${label}: dist/ was never stamped ` +
        `(built without the hash step, or dist/ deleted). ` +
        `Run \`npm run build\` from the repo root and retry.`,
    };
  }
  let stamp: { v?: number; sha256?: string; files?: number };
  try {
    stamp = JSON.parse(readFileSync(stampPath, "utf8")) as typeof stamp;
  } catch {
    return {
      fresh: false,
      reason: `[runner] STALE BUILD in ${label}: dist/${STAMP_NAME} is corrupt. Run \`npm run build\` from the repo root and retry.`,
    };
  }
  if (stamp.v !== HASH_VERSION || typeof stamp.sha256 !== "string") {
    return {
      fresh: false,
      reason: `[runner] STALE BUILD in ${label}: dist/${STAMP_NAME} has an unknown format. Run \`npm run build\` from the repo root and retry.`,
    };
  }
  const { sha256, files } = hashSrcDir(srcDir);
  if (stamp.sha256 !== sha256) {
    return {
      fresh: false,
      reason:
        `[runner] STALE BUILD in ${label}: src/ changed since dist/ was built ` +
        `(${files} files now, stamp covers ${stamp.files ?? "?"}). ` +
        `Run \`npm run build\` from the repo root and retry.`,
    };
  }
  return { fresh: true };
}

/**
 * Walk up from startDir to the workspace root: the nearest ancestor whose
 * package.json carries the given name. Works from dist/safety AND from
 * dist-test/src/safety (the test build mirrors src/ one level deeper).
 */
export function findWorkspaceRoot(startDir: string, packageName: string): string | null {
  let dir = startDir;
  for (let i = 0; i < 10; i++) {
    const pkgPath = join(dir, "package.json");
    if (existsSync(pkgPath)) {
      try {
        if ((JSON.parse(readFileSync(pkgPath, "utf8")) as { name?: string }).name === packageName) return dir;
      } catch {
        // unreadable package.json — keep walking up
      }
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

/**
 * Fail fast when the runner's own dist or a workspace dependency's dist is
 * stale. Called at the top of runEngagement — before any target is touched.
 */
export function assertDistFresh(): void {
  if (process.env[SKIP_ENV] === "1") return;
  const here = dirname(fileURLToPath(import.meta.url)); // dist/safety (or dist-test/src/safety)
  const problems: string[] = [];
  const runnerDir = findWorkspaceRoot(here, "@secscan/redteam-runner");
  if (!runnerDir) {
    problems.push("[runner] cannot locate the runner workspace root — refusing to run. Run `npm run build` from the repo root and retry.");
  } else {
    const self = distIsFresh(runnerDir, "@secscan/redteam-runner");
    if (!self.fresh && self.reason) problems.push(self.reason);
  }
  const require = createRequire(import.meta.url);
  for (const dep of CHECKED_DEPS) {
    let depDir: string;
    try {
      depDir = dirname(require.resolve(`${dep}/package.json`));
    } catch {
      problems.push(`[runner] STALE BUILD: cannot resolve ${dep} — is it installed? Run \`npm run build\` from the repo root and retry.`);
      continue;
    }
    const r = distIsFresh(depDir, dep);
    if (!r.fresh && r.reason) problems.push(r.reason);
  }
  if (problems.length > 0) throw new Error(problems.join("\n"));
}
