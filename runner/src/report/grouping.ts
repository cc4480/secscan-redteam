/**
 * Report presentation helpers.
 *
 * A scoped engagement can legitimately mark hundreds of battery items
 * not-applicable — every item in each battery family the engagement cannot
 * reach — and they all carry the same family-level reason. Listed one per line
 * that produced a 392-line report of which 338 lines were a single sentence
 * repeated with a different id: the reader scrolled past a wall of "not in
 * scope" to reach the findings, which were somewhere in the middle.
 *
 * The ids still matter, but they belong in item-verdicts.json, which is the
 * machine-readable record. The report is for a human, and a human needs the
 * shape of the result, not the enumeration.
 */

export interface VerdictRow {
  key: string;
  disposition: string;
  name: string;
  reason?: string;
}

export interface VerdictGroup {
  target: string;
  reason: string;
  ids: string[];
}

/** Group not-applicable verdicts by target and reason, largest group first. */
export function groupNotApplicable(items: VerdictRow[]): VerdictGroup[] {
  const groups = new Map<string, VerdictGroup>();
  for (const v of items) {
    if (v.disposition !== "na") continue;
    const target = v.key.split(":")[0] ?? "?";
    const reason = v.reason ?? "(no reason recorded)";
    const k = `${target}\u0000${reason}`;
    const g = groups.get(k) ?? { target, reason, ids: [] };
    g.ids.push(v.key);
    groups.set(k, g);
  }
  // Largest first: the family that dominated the ledger is the one a reader
  // most needs to see, and a stable order beats insertion order for diffing.
  return [...groups.values()].sort((a, b) => b.ids.length - a.ids.length || a.target.localeCompare(b.target));
}

/**
 * One markdown line per group.
 *
 * The id range is included so a reader can see the span at a glance without the
 * report becoming the enumeration again.
 */
export function renderNotApplicable(groups: VerdictGroup[]): string {
  if (groups.length === 0) return "";
  const total = groups.reduce((n, g) => n + g.ids.length, 0);
  const out: string[] = [`Not-applicable, grouped (\`${total}\` items — full ids in item-verdicts.json):`, ""];
  for (const g of groups) {
    const range = g.ids.length > 1 ? ` (${g.ids[0]} … ${g.ids[g.ids.length - 1]})` : ` (${g.ids[0]})`;
    out.push(`- **${g.target}:** ${g.ids.length} item${g.ids.length === 1 ? "" : "s"}${range} — ${g.reason}`);
  }
  return out.join("\n");
}
