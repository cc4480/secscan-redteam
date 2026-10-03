/**
 * THE REGISTRY — the product's compounding proprietary attack intelligence.
 *
 * Every engagement reads from and writes to this registry:
 *  - CONFIRMED findings: vuln class, technique, ATT&CK ID, target fingerprint,
 *    payload pattern, evidence ref, engagement, date.
 *  - KILLED hypotheses: what was tried + the killing observation — negative
 *    knowledge, so future engagements attack the same ground smarter —
 *    with a different angle, never the identical dead probe.
 *
 * The exploiter queries it when forming hypotheses ("what worked against
 * similar targets before?") and writes back every verdict. It compounds with
 * every engagement — that compounding is the moat.
 *
 * Storage: a single versioned JSON file (engagements/registry.json). The
 * runner is single-process per engagement and the watcher runs jobs
 * sequentially, so read-modify-write is safe. If concurrent writers ever
 * arrive, migrate this to SQLite (the schema maps 1:1 to tables).
 */
export * from "./registry/store.js";
export * from "./registry/query.js";
