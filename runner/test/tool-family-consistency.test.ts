/**
 * Tool-family consistency.
 *
 * The same host-tool names are hand-maintained in four separate places: the
 * dispatcher's wave-2 handler set, the rate-limit set, the tier ladder's
 * exploit-step set, and the proof-action set in the PoC bundle builder. They are
 * intentionally different SUBSETS, but they overlap by requirement — and a new
 * host tool that lands in some lists and not others fails silently, in the worst
 * direction:
 *
 *   - missing from RATE_LIMITED_TOOLS → the tool fires real traffic with no
 *     rate limiter and no auto-halt tracking at all;
 *   - missing from PROOF_TOOL_ACTIONS → its executions can never become proof,
 *     so a confirmed finding silently gets no bundle step.
 *
 * This is the same class of gap as the nmap scope check: a control that existed
 * for some tools and not others. These assertions are coverage, not equality —
 * extra members are fine, missing ones are not.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { HOST_TOOLS } from "../src/tools/host.js";
import { PROOF_TOOL_ACTIONS } from "../src/proof/bundle.js";
import { RATE_LIMITED_TOOLS } from "../src/dispatch/router.js";
import { WAVE2_TOOLS } from "../src/dispatch/host.js";

describe("tool-family consistency", () => {
  it("rate-limits and auto-halt tracks every host-exec tool", () => {
    for (const t of HOST_TOOLS) {
      assert.ok(
        RATE_LIMITED_TOOLS.has(t.name),
        `${t.name} is missing from RATE_LIMITED_TOOLS — it would fire traffic with no limiter`,
      );
    }
  });

  it("rate-limits every wave-2 tool", () => {
    for (const name of WAVE2_TOOLS) {
      assert.ok(RATE_LIMITED_TOOLS.has(name), `${name} is missing from RATE_LIMITED_TOOLS`);
    }
  });

  it("lets every host-exec tool contribute a proof step", () => {
    for (const t of HOST_TOOLS) {
      assert.ok(
        PROOF_TOOL_ACTIONS.has(t.name),
        `${t.name} is missing from PROOF_TOOL_ACTIONS — its events could never become proof`,
      );
    }
  });

  it("keeps the wave-2 set inside the host-exec family", () => {
    const hostNames = new Set(HOST_TOOLS.map((t) => t.name));
    for (const name of WAVE2_TOOLS) {
      assert.ok(hostNames.has(name), `${name} is in WAVE2_TOOLS but has no HOST_TOOLS definition`);
    }
  });

  it("lists no rate-limited tool that the dispatcher cannot route", () => {
    // Every rate-limited name must be a tool the runner actually exposes, or the
    // entry is dead and a real tool may be missing its limiter in its place.
    const exposed = new Set([...HOST_TOOLS.map((t) => t.name), "http_probe", "burst_probe", "scan_url", "msf_exec", "nuclei_exec", "nmap_exec", "sqlmap_exec", "ffuf_exec", "gobuster_exec", "nikto_exec"]);
    for (const name of RATE_LIMITED_TOOLS) {
      assert.ok(exposed.has(name), `${name} is rate-limited but is not a tool this runner exposes (typo?)`);
    }
  });
});
