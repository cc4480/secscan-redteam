/**
 * Nuclei bridge tool definition.
 */
import type { JsonSchemaTool } from "@secscan/redteam-llm-router";

export const NUCLEI_EXEC_TOOL: JsonSchemaTool = {
  name: "nuclei_exec",
  description:
    "Nuclei bridge: template-based checks from the operator's local Nuclei template checkout (~10k community templates, resolved at runtime — never hardcoded). Actions: 'templates' (list/select templates by id, tag, severity, or CVE — recon-safe, touches no target, never fires), 'run' (execute selected templates against ONE scope-checked host; EXPLOIT PHASE ONLY, after coordinator sign-off). Policy: dos-tagged templates refused always (T1499 excluded by ROE), template updates never run mid-engagement, target URL is runner-built from the scope-checked host. Requires the nuclei binary (REDTEAM_NUCLEI_BIN or PATH). Findings that overlap a battery item are ONE finding with two evidence sources — check the overlap hint in the result. Include attackId (a real ATT&CK ID such as 'T1595.002'), category, targetProfile ('windows'|'linux' — never inferred), hypothesis.",
  parameters: {
    type: "object",
    properties: {
      action: { type: "string", enum: ["templates", "run"] },
      host: { type: "string" },
      scheme: { type: "string", enum: ["http", "https"] },
      ids: { type: "array", items: { type: "string" } },
      tags: { type: "array", items: { type: "string" } },
      severities: { type: "array", items: { type: "string" } },
      cve: { type: "string" },
      attackId: { type: "string" },
      category: { type: "string", enum: ["logic", "functionality", "validation"] },
      targetProfile: { type: "string", enum: ["windows", "linux"] },
      hypothesis: { type: "string" },
    },
    required: ["action", "host", "category"],
  },
};
