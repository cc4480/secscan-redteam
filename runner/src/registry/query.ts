/**
 * Registry querying: relevance scoring over confirmed findings and killed
 * hypotheses. Stack overlap weighs most, then appType, then vuln class.
 */

import type { RegistryEntry, RegistryQuery, VulnerabilityRegistry } from "./store.js";

function norm(s: string): string {
  return s.toLowerCase().trim();
}

/**
 * Score an entry against a query. Stack overlap weighs most (same stack =
 * same bug classes recur), then appType, then vuln class / technique.
 */
function score(entry: RegistryEntry, q: RegistryQuery): number {
  let s = 0;
  if (q.kind && entry.kind !== q.kind) return -1;
  if (q.stack) {
    const want = q.stack.split(",").map(norm).filter(Boolean);
    const have = entry.target.stack.map(norm);
    const overlap = want.filter((w) => have.some((h) => h.includes(w) || w.includes(h))).length;
    if (want.length > 0 && overlap === 0) return -1;
    s += overlap * 3;
  }
  if (q.appType) {
    const a = norm(q.appType);
    const b = norm(entry.target.appType);
    if (!(a.includes(b) || b.includes(a))) return -1;
    s += 2;
  }
  if (q.vulnClass) {
    const vc = norm(entry.vulnClass ?? "");
    const h = norm(entry.kind === "killed" ? entry.hypothesis : "");
    if (!(vc.includes(norm(q.vulnClass)) || h.includes(norm(q.vulnClass)))) return -1;
    s += 2;
  }
  if (q.attackId) {
    if (norm(entry.attackId ?? "") !== norm(q.attackId)) return -1;
    s += 1;
  }
  return s;
}

/** Best matches first, capped at limit (default 8). Empty query → newest first. */
export function queryRegistry(reg: VulnerabilityRegistry, q: RegistryQuery = {}): RegistryEntry[] {
  const all: RegistryEntry[] = [...reg.confirmed, ...reg.killed];
  const hasFilter = q.vulnClass || q.stack || q.appType || q.attackId || q.kind;
  const scored = all
    .map((e) => ({ e, s: hasFilter ? score(e, q) : 0 }))
    .filter((x) => x.s >= 0)
    .sort((a, b) => b.s - a.s || b.e.date.localeCompare(a.e.date));
  return scored.slice(0, q.limit ?? 8).map((x) => x.e);
}

