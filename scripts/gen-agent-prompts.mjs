#!/usr/bin/env node
/**
 * Regenerate agents/*.md from the executing prompt code.
 *
 * The single source of truth for role behavior is runner/src/prompts/
 * (the functions the runner runs). agents/*.md are operator-facing docs
 * rendered from that code with a canonical, engagement-independent
 * context — never edit them by hand. runner/test/prompts-drift.test.ts
 * fails loudly if a committed file drifts from what the code renders.
 *
 * Usage:
 *   npm run build                              # render from fresh dist/
 *   node scripts/gen-agent-prompts.mjs         # rewrite agents/*.md
 *   node scripts/gen-agent-prompts.mjs --check # report drift, exit 1
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const agentsDir = join(repoRoot, "agents");

let agentDocs;
try {
  agentDocs = await import(join(repoRoot, "runner", "dist", "prompts", "agent-docs.js"));
} catch (err) {
  console.error("[gen-agent-prompts] cannot load runner/dist/prompts/agent-docs.js.");
  console.error("Run `npm run build` from the repo root first, then re-run this script.");
  console.error(String(err && err.message ? err.message : err));
  process.exit(2);
}

// Refuse to render from a stale dist: agents/*.md must reflect runner/src,
// not an old build. This mirrors the runner's own start-up freshness guard.
try {
  const { execFileSync } = await import("node:child_process");
  execFileSync(process.execPath, [join(repoRoot, "scripts", "dist-hash.mjs"), "check-all"], {
    stdio: "pipe",
  });
} catch {
  console.error("[gen-agent-prompts] runner dist is STALE vs src — refusing to render docs from it.");
  console.error("Run `npm run build` from the repo root first, then re-run this script.");
  process.exit(2);
}

const { AGENT_DOC_ROLES, renderAgentMarkdown } = agentDocs;
const checkOnly = process.argv.includes("--check");
const drifted = [];

for (const role of AGENT_DOC_ROLES) {
  const path = join(agentsDir, `${role}.md`);
  const rendered = renderAgentMarkdown(role);
  const current = existsSync(path) ? readFileSync(path, "utf8") : null;
  if (current === rendered) {
    console.log(`[gen-agent-prompts] agents/${role}.md up to date`);
    continue;
  }
  drifted.push(role);
  if (checkOnly) {
    console.error(`[gen-agent-prompts] agents/${role}.md is STALE (differs from runner/src/prompts render)`);
  } else {
    writeFileSync(path, rendered);
    console.log(`[gen-agent-prompts] agents/${role}.md regenerated`);
  }
}

if (checkOnly && drifted.length > 0) {
  console.error(
    `[gen-agent-prompts] ${drifted.length} file(s) drifted: ${drifted.join(", ")}. ` +
      "Regenerate with: npm run build && node scripts/gen-agent-prompts.mjs",
  );
  process.exit(1);
}
