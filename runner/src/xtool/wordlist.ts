/**
 * Wordlist resolution for the content-discovery bridges (ffuf, gobuster).
 *
 * The bridges need a filesystem path, but the *operator's* path is not the
 * runner's path: a packaged desktop app cannot assume `C:\Users\<dev>\...`, and
 * an unattended engagement should not fail because one environment variable is
 * unset. So resolve in a fixed order and hand back the first candidate that
 * actually exists, instead of embedding one machine's absolute path in the
 * argv (which is what v0.32.0 did — every ffuf run failed on a fresh install).
 *
 * Order, most specific first:
 *   1. an explicit `wordlist` tool argument
 *   2. REDTEAM_WORDLIST
 *   3. <REDTEAM_TOOLS_DIR>/wordlists/common.txt   (bundled tools directory)
 *   4. the asset shipped inside this package: <runner>/assets/wordlists/common.txt
 *   5. <LOCALAPPDATA|HOME>/SecScanRedTeam/wordlists/common.txt (operator override)
 *
 * Pure and synchronous — testable without a subprocess and cheap enough to call
 * per tool invocation.
 */

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Package roots to look for the bundled asset under.
 *
 * Compiled production layout is `<runner>/dist/xtool/wordlist.js` (so `../..` is
 * the package root). The test build is `<runner>/dist-test/src/xtool/...`, one
 * level deeper, so both are searched. Listing roots instead of assuming one
 * keeps the same code honest in both layouts without a build-time constant.
 */
function packageRoots(): string[] {
  const here = dirname(fileURLToPath(import.meta.url));
  return [join(here, "..", ".."), join(here, "..", "..", "..")];
}

/** All candidate paths, in precedence order. The caller picks the first that exists. */
export function wordlistCandidates(explicit?: string, env: NodeJS.ProcessEnv = process.env): string[] {
  const candidates: string[] = [];

  const fromArg = (explicit ?? "").trim();
  if (fromArg) candidates.push(fromArg);

  const fromEnv = (env["REDTEAM_WORDLIST"] ?? "").trim();
  if (fromEnv) candidates.push(fromEnv);

  const toolsDir = (env["REDTEAM_TOOLS_DIR"] ?? "").trim();
  if (toolsDir) candidates.push(join(toolsDir, "wordlists", "common.txt"));

  for (const root of packageRoots()) candidates.push(join(root, "assets", "wordlists", "common.txt"));

  const local = (env["LOCALAPPDATA"] ?? env["HOME"] ?? "").trim();
  if (local) candidates.push(join(local, "SecScanRedTeam", "wordlists", "common.txt"));

  return candidates;
}

/**
 * Resolve a usable wordlist path, or `undefined` when none of the candidates
 * exists. `undefined` is the honest answer: the bridge then returns the setup
 * instructions rather than spawning a tool that is guaranteed to fail.
 */
export function resolveWordlist(explicit?: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  for (const candidate of wordlistCandidates(explicit, env)) {
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}
