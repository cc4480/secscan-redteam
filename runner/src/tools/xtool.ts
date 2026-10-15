/**
 * Tool definitions for the external-tool bridges (v0.32.0).
 *
 * Generated from the registry rather than hand-written five times, so a tool
 * that gains a profile gains it here automatically and the schemas cannot drift
 * from what the executor will accept.
 *
 * The agent picks a TOOL, an ACTION, a PROFILE and a TARGET. It never supplies a
 * flag: `checkXToolFlags` refuses anything beginning with "-" and every argv is
 * built runner-side from the profile table.
 */
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";
import { XTOOLS, type XToolSpec } from "../xtool/registry.js";

const BATTERY_HINT =
  ' Include batteryItem: the battery item ID under test (e.g. "SS-042"), and attackId ' +
  "(a real ATT&CK ID such as 'T1190' for exploit public-facing app, 'T1046' for network " +
  "service discovery, 'T1110' for brute force, or 'T1083' for file and directory discovery). " +
  'targetProfile must be "windows" or "linux" — host targets are never inferred.';

function profileEnum(spec: XToolSpec): Record<string, unknown> {
  return {
    type: "string",
    enum: spec.profiles.map((p) => p.id),
    description:
      `Named profile. Defaults to ${spec.profiles[0]!.id}. ` +
      spec.profiles.map((p) => `${p.id} (tier${p.minTier}+) — ${p.description}`).join("; "),
  };
}

export function xToolDef(spec: XToolSpec): JsonSchemaTool {
  const properties: Record<string, unknown> = {
    action: { type: "string", enum: ["probe", "run"], description: "'probe' reports the binary and profiles and runs nothing; 'run' executes a profile against the target." },
    host: { type: "string", description: "'run' only. The scope-checked target: a hostname, URL or path depending on the tool." },
    profile: profileEnum(spec),
    category: { type: "string", enum: ["logic", "functionality", "validation"] },
    targetProfile: { type: "string", enum: ["windows", "linux"] },
    attackId: { type: "string" },
    hypothesis: { type: "string" },
  };
  // Whether the schema offers `wordlist` is decided by the profiles: a tool
  // where ANY profile needs a wordlist gets the field. Per-profile, because
  // john's identify mode never reads one while its cracking modes require it.
  if (spec.profiles.some((p) => p.wordlist)) {
    properties["wordlist"] = {
      type: "string",
      description:
        "Absolute path to a wordlist. Defaults to the configured wordlist (REDTEAM_WORDLIST) — the agent cannot point this at an arbitrary system file.",
    };
  }
  if (spec.id === "john") {
    properties["host"] = { type: "string", description: "'run' only. Absolute path to the HASH FILE to crack. John is offline: it never touches a network target." };
  }
  return {
    name: `${spec.id}_exec`,
    description:
      `${spec.id} bridge: ${spec.purpose}. ` +
      `Actions: 'probe' (report the binary path and the available profiles, running nothing) or 'run' (execute ONE profile). ` +
      "Policy: the agent never supplies flags — the argv is built runner-side from the profile, so the command cannot be bent. " +
      "Flags that hand over a shell, write to the target, extract data or conceal the tester are refused by name, and so is any flag at all. " +
      (spec.id === "john"
        ? "John is an OFFLINE cracker: 'host' is a path to a hash file on this machine, never a network target. "
        : "The target is scope-checked before the process starts. ") +
      // The setup text is a FALLBACK, not a statement of fact. Appending it bare
      // made every description open with "john not found." / "sqlmap not found."
      // even when the binary was installed and working — found by a teammate
      // reading the schema, which is exactly how it would have reached a user.
      // Call `probe` first to learn which case applies.
      `If ${spec.id} is not installed, probe will say so and name the install steps: ` +
      spec.setup.join(" ") +
      BATTERY_HINT,
    parameters: {
      type: "object",
      properties,
      required: ["action", "category"],
    },
  };
}

export const XTOOL_DEFS: JsonSchemaTool[] = XTOOLS.map(xToolDef);
export const XTOOL_DEFS_BY_NAME = new Map(XTOOL_DEFS.map((t) => [t.name, t]));
