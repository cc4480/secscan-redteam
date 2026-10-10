/**
 * Prompt single-source-of-truth guard (T14).
 *
 * The four role prompts execute from runner/src/prompts/*.ts; the committed
 * agents/*.md files are GENERATED from that code (renderAgentMarkdown, with a
 * canonical engagement-independent context). Two failure modes must be loud:
 *   1. drift — a prompt edit (or a hand-edited .md) without regeneration;
 *   2. parity loss — a safety-relevant instruction that exists in either the
 *      old agents/*.md prose or the executing prompts silently disappearing
 *      from the runtime prompts.
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  AGENT_DOC_ROLES,
  canonicalAgentDocContext,
  renderAgentMarkdown,
} from "../src/prompts/agent-docs.js";
import { coordinatorPrompt } from "../src/prompts/coordinator.js";
import { exploiterPrompt } from "../src/prompts/exploiter.js";
import { reconPrompt } from "../src/prompts/recon.js";
import { reporterPrompt } from "../src/prompts/reporter.js";

const AGENTS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "agents");
const REGEN = "npm run build && node scripts/gen-agent-prompts.mjs";

describe("agents/*.md are generated from runner/src/prompts (single source of truth)", () => {
  for (const role of AGENT_DOC_ROLES) {
    it(`agents/${role}.md matches the code render`, () => {
      const path = join(AGENTS_DIR, `${role}.md`);
      assert.ok(
        existsSync(path),
        `agents/${role}.md is missing. Generate it: ${REGEN}`,
      );
      const committed = readFileSync(path, "utf8");
      assert.strictEqual(
        committed,
        renderAgentMarkdown(role),
        `agents/${role}.md has drifted from runner/src/prompts (the single source of truth). ` +
          `Edit behavior in runner/src/prompts, then regenerate: ${REGEN}`,
      );
    });

    it(`agents/${role}.md carries the generated banner (no hand edits)`, () => {
      const committed = readFileSync(join(AGENTS_DIR, `${role}.md`), "utf8");
      assert.ok(
        committed.startsWith("<!--\n  GENERATED FILE — do not edit by hand."),
        `agents/${role}.md does not start with the generated banner. Regenerate: ${REGEN}`,
      );
    });
  }
});

describe("behavior parity — safety-relevant instructions survive in the runtime prompts", () => {
  const ctx = canonicalAgentDocContext();
  const prompts = {
    coordinator: coordinatorPrompt(ctx),
    recon: reconPrompt(ctx),
    exploiter: exploiterPrompt(ctx),
    reporter: reporterPrompt(ctx),
  };

  // Each entry: an instruction that existed in the agents/*.md prose, the
  // executing prompts, or both BEFORE the collapse — losing any of these from
  // the runtime prompt (in either mode) is a behavior regression.
  const parity: Record<keyof typeof prompts, string[]> = {
    coordinator: [
      "State the authorization basis first (server verification proof + timestamp).",
      "If unverified, the engagement is already blocked — say so and stop.",
      "A specialist attempting to bypass, disable, or work around the auth gate ends the engagement immediately",
      "One finding needs two independent observations.",
      "each scan_url consumes a scan credit",
      "In-scope hosts (EXACT — touch nothing else)", // the old .md "scope creep ends the engagement" rule, enforced mechanically via the ROE block
    ],
    recon: [
      "one tool call per turn",
      "You never craft payloads or fuzz — that's the exploiter's job",
      'Do not "confirm" a vuln by exploiting it. Observation, not proof.',
      "do not try to evade during recon.",
      "Every claim cites its observation.",
      "mark every guess as a guess",
    ],
    exploiter: [
      "Active testing ONLY on ownership-verified targets (the runner gates every probe).",
      "Never attempt to bypass the gate; attempting it ends the engagement.",
      'Two independent observations before anything is "confirmed".',
      "Two independent observations before calling anything a finding.",
      "Never repeat a failed payload verbatim",
      "Rate each step by evidence, not imagination.",
      "Non-destructive always: no data writes/deletes, no DoS",
      // merged from agents/exploiter.md in T14:
      "## Worked example — how dynamic testing beats a checklist",
      "collaborator endpoint controlled for this engagement",
      "The scanner's aggressive tier already runs oracle/signature proving",
    ],
    reporter: [
      "You work for the CLIENT",
      "every claim must cite an observation",
      "You never promise what wasn't tested.",
      // merged from agents/reporter.md in T14:
      "answers three questions — what is it, why does it matter to the business",
      "Never invent findings to pad",
      "OPERATION NARRATIVE",
      "Authorization statement",
      "Honest limits",
    ],
  };

  for (const role of AGENT_DOC_ROLES) {
    it(`${role} runtime prompt keeps every parity instruction`, () => {
      for (const needle of parity[role]) {
        assert.ok(
          prompts[role].includes(needle),
          `${role} runtime prompt lost the safety-relevant instruction: ${JSON.stringify(needle)}`,
        );
      }
    });
  }
});
