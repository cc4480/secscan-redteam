/**
 * Template→battery mapping for dedupe (v0.21.0).
 *
 * A finding confirmed by BOTH a battery item and a Nuclei template is ONE
 * finding with two evidence sources — never two findings. This module maps
 * Nuclei template metadata (CVE, tags, template id) to battery item ids so
 * the reporter agent records overlaps honestly.
 *
 * Templates with no battery overlap become runtime instances under the
 * methodology items WS-108 (Windows) / LX-110 (Linux) — the same pattern
 * the Metasploit bridge uses (WS-105…107 → per-CVE instances).
 */
import type { NucleiFinding } from "./runner.js";

/** Template-id/tag hints → battery item ids. Conservative: only map when the tag is unambiguous. */
const TAG_TO_ITEMS: Array<{ tag: string; items: string[] }> = [
  // Exposed panels / default credentials overlap host auth-surface items.
  { tag: "default-login", items: ["WS-019", "LX-018"] },
  { tag: "misconfig", items: ["WS-043", "LX-041"] },
  { tag: "exposure", items: ["WS-038", "LX-041"] },
  // NOTE: no blanket "cve" tag mapping. A CVE-named template whose CVE was
  // already validated (via msf or a battery item) overlaps via the
  // knownCves path below. A CVE template for an UNconfirmed CVE is new
  // information — it becomes a template-only runtime instance under
  // WS-108/LX-110, never forced into the Metasploit methodology items.
];

/** Methodology items that own template-only runtime instances. */
export const NUCLEI_METHODOLOGY_ITEMS = { windows: "WS-108", linux: "LX-110" } as const;

export interface TemplateOverlap {
  /** Battery item ids this template finding overlaps (dedupe: record once). */
  batteryItems: string[];
  /** True when the template has no battery overlap → runtime instance. */
  templateOnly: boolean;
  /** Suggested methodology item for template-only instances. */
  methodologyItem?: string;
}

/**
 * Map a Nuclei finding to overlapping battery items. CVE match is the
 * strongest signal; tag hints are secondary. Unknown → templateOnly.
 */
export function mapTemplateToBattery(
  finding: NucleiFinding,
  targetProfile: "windows" | "linux",
  knownCves: Set<string> = new Set(),
): TemplateOverlap {
  const items = new Set<string>();
  if (finding.cve && knownCves.has(finding.cve)) {
    // The CVE was already confirmed by a battery/msf finding — same finding,
    // second evidence source. The methodology items own the mapping entry.
    items.add(targetProfile === "windows" ? "WS-106" : "LX-108");
  }
  const hay = `${finding.templateId} ${finding.tags.join(" ")}`.toLowerCase();
  for (const { tag, items: mapped } of TAG_TO_ITEMS) {
    if (hay.includes(tag)) {
      for (const id of mapped) {
        if ((targetProfile === "windows") === id.startsWith("WS")) items.add(id);
      }
    }
  }
  const batteryItems = [...items];
  const templateOnly = batteryItems.length === 0;
  return {
    batteryItems,
    templateOnly,
    methodologyItem: templateOnly ? NUCLEI_METHODOLOGY_ITEMS[targetProfile] : undefined,
  };
}

/** One-line overlap hint for the agent result string. */
export function overlapHint(overlap: TemplateOverlap): string {
  if (overlap.templateOnly) {
    return `No battery overlap — record as a runtime instance under ${overlap.methodologyItem} (template-only finding).`;
  }
  return `Overlaps battery item(s) ${overlap.batteryItems.join(", ")} — record ONE finding with both evidence sources, never two findings.`;
}
