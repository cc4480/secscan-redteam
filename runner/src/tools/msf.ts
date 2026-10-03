/**
 * Metasploit bridge tool definition.
 */
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";

export const MSF_EXEC_TOOL: JsonSchemaTool = {
  name: "msf_exec",
  description:
    "Metasploit bridge: CVE-specific exploit validation (Windows/Linux host targets). Actions: 'search' (module database query, recon-safe), 'suggest' (service+version → ranked candidate modules for coordinator approval — never fires), 'run' (ONE exploit/auxiliary module with a benign canary marker as the only payload; EXPLOIT PHASE ONLY, after coordinator sign-off). Policy: dos/destructive modules refused, only generic single-command payloads, marker command is runner-built, stray sessions stopped. Requires msfrpcd (REDTEAM_MSFRPC_* env). In-scope hosts only (runner-enforced). Include attackId (a real ATT&CK ID such as 'T1190' — the coordinator rejects anything else), the CVE in 'cve', category, targetProfile ('windows'|'linux' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      action: { type: "string", enum: ["search", "suggest", "run"] },
      host: { type: "string" },
      query: { type: "string" },
      service: { type: "string" },
      version: { type: "string" },
      cve: { type: "string" },
      platform: { type: "string", enum: ["windows", "linux"] },
      moduleType: { type: "string", enum: ["exploit", "auxiliary"] },
      module: { type: "string" },
      options: { type: "object", additionalProperties: { type: "string" } },
      payload: { type: "string" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows", "linux"] },
      hypothesis: { type: "string" },
    },
    required: ["action", "host", "category"],
  },
};
