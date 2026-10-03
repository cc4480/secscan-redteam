/**
 * Compliance pack finding/retest types + before/after evidence builder.
 */

import type { ConfirmedFinding, VulnerabilityRegistry } from "../../registry.js";

export interface PackFinding {
  id: string;
  severity: string;
  title: string;
  attackIds: string[];
  /** Compliance control ids exercised by this finding. */
  controls: string[];
  evidence: string;
  fix: string;
  retest: string;
  status: string;
  /** Named human operator accountable for this finding (v0.17.0). */
  accountableOperator: string;
}

export interface RetestObservation {
  engagementId: string;
  date: string;
  severity: string;
  evidenceRef: string;
}

export interface RetestEntry {
  vulnClass: string;
  /** Earliest observation across all engagements (the "before"). */
  firstSeen: RetestObservation;
  /** Latest observation (the "after" — possibly this engagement). */
  latest: RetestObservation;
  observationCount: number;
}

export function buildRetestEvidence(registry: VulnerabilityRegistry): RetestEntry[] {
  const byClass = new Map<string, ConfirmedFinding[]>();
  for (const c of registry.confirmed) {
    const list = byClass.get(c.vulnClass) ?? [];
    list.push(c);
    byClass.set(c.vulnClass, list);
  }
  const entries: RetestEntry[] = [];
  for (const [vulnClass, list] of byClass) {
    const sorted = [...list].sort((a, b) => a.date.localeCompare(b.date));
    const first = sorted[0]!;
    const last = sorted[sorted.length - 1]!;
    const obs = (c: ConfirmedFinding): RetestObservation => ({
      engagementId: c.engagementId,
      date: c.date,
      severity: c.severity,
      evidenceRef: c.evidenceRef,
    });
    entries.push({ vulnClass, firstSeen: obs(first), latest: obs(last), observationCount: sorted.length });
  }
  return entries.sort((a, b) => a.vulnClass.localeCompare(b.vulnClass));
}

/** Human-readable markdown rendering of the pack (written next to report.md). */
