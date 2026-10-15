/**
 * Nmap bridge tool definition.
 *
 * The agent picks a PROFILE and a HOST. It does not supply flags: the argv is
 * runner-built from the profile table, so there is no path from agent input to
 * nmap's command line. Intrusive NSE categories, timing above -T4 and the
 * attribution-defeating flags are refused with a reason (see policy.ts).
 *
 * `profiles` touches no target and is safe in any phase; `scan` sends packets
 * and is subject to the same scope check, rate limit and tier rules as every
 * other tool that touches a host.
 */
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";
import { NMAP_PROFILES, NMAP_ALLOWED_SCRIPT_CATEGORIES } from "../nmap/policy.js";

export const NMAP_EXEC_TOOL: JsonSchemaTool = {
  name: "nmap_exec",
  description:
    "Nmap bridge: port and service discovery against ONE scope-checked host. Actions: " +
    "'profiles' (list the available scan profiles and confirm the binary runs — touches no target, safe in any phase), " +
    "'scan' (run ONE named profile against the host). " +
    `Profiles: ${NMAP_PROFILES.map((p) => `${p.id} (${p.description})`).join("; ")}. ` +
    "Policy: the agent never supplies flags — the runner builds the argv from the profile, so the target is fixed by scope and the command is fixed by policy. " +
    `NSE script categories are limited to ${NMAP_ALLOWED_SCRIPT_CATEGORIES.join("/")}; intrusive, exploit, brute, fuzzer, dos, malware and external are refused by name. ` +
    "Timing above -T4 and the decoy/spoof/fragment flags are refused. " +
    "Output is nmap XML parsed runner-side, so report ports, services and versions as EVIDENCE, not impressions. " +
    "Include attackId (a real ATT&CK ID such as 'T1046' for network service discovery), category, targetProfile ('windows'|'linux' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      action: { type: "string", enum: ["profiles", "scan"] },
      host: { type: "string", description: "Scope-checked hostname, IP or CIDR. Never a URL." },
      profile: {
        type: "string",
        enum: NMAP_PROFILES.map((p) => p.id),
        description: "Named scan profile. Defaults to 'quick' for action=scan.",
      },
      scriptCategories: {
        type: "array",
        items: { type: "string", enum: [...NMAP_ALLOWED_SCRIPT_CATEGORIES] },
        description: "Optional NSE categories to run. Refused, not filtered, if a category is not allowed.",
      },
      skipPing: {
        type: "boolean",
        description: "Pass -Pn when the host is known to be up but drops ICMP. Avoids a false 'host seems down'.",
      },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows", "linux"] },
      hypothesis: { type: "string" },
    },
    required: ["action", "host", "category"],
  },
};
