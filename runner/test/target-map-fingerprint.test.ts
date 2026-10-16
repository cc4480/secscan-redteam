/**
 * The target fingerprint needs a way to be set that a model can actually use.
 *
 * Until now the ONLY route was a "FINGERPRINT: stack=...; appType=...; notes=..."
 * line written into the recon agent's free-text brief, which the runner scraped
 * with a regex in phases/recon.ts. The recon prompt required that line in every
 * run, and the agent never once emitted it — fingerprint events stayed at zero
 * while the coordinator refused recon→exploit sign-off over "fingerprint is
 * {stack:[],appType:unknown}", a gap nobody could close because there was no
 * tool to close it with.
 *
 * A regex over prose is a fragile contract with a language model. A tool
 * parameter is one it can keep, so update_target_map now carries stack and
 * appType and the dispatch side merges them into ctx.fingerprint.
 *
 * The second thing pinned here is a description that prevents a real failure:
 * an agent recorded the SecScan API endpoint in the shared target map as an
 * "adjacent origin", the coordinator read its own scanning service as an
 * out-of-scope host, and it halted the run for an ROE breach. The coordinator
 * was right about the evidence — the service should never have been in the map.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { UPDATE_TARGET_MAP_TOOL } from "../src/tools/bookkeeping.js";

type Schema = {
  description?: string;
  parameters: {
    properties?: Record<string, unknown>;
    required?: string[];
  };
};

const tool = UPDATE_TARGET_MAP_TOOL as unknown as Schema;

describe("update_target_map carries the fingerprint", () => {
  it("accepts stack", () => {
    assert.ok("stack" in (tool.parameters.properties ?? {}), "stack must be settable, or the fingerprint cannot be");
  });

  it("accepts appType", () => {
    assert.ok("appType" in (tool.parameters.properties ?? {}));
  });

  it("does not require them — the fingerprint is discovered, not demanded up front", () => {
    assert.ok(!(tool.parameters.required ?? []).includes("stack"));
    assert.ok(!(tool.parameters.required ?? []).includes("appType"));
    assert.deepEqual(tool.parameters.required, ["entries"], "entries stays the only required field");
  });

  it("warns that the scanner is the instrument, not a target", () => {
    const d = tool.description ?? "";
    assert.match(d, /instrument, not a target/i);
    assert.match(d, /secscan/i, "names the service it must not be confused with");
    assert.match(d, /ROE breach/i, "and says what putting it there looks like");
  });

  it("still describes the map as the shared handoff", () => {
    assert.match(tool.description ?? "", /SHARED target map/);
  });
});
