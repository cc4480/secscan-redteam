"""Seed the service_detect simulated contrast (Cycle 2 initialization).

Gate rule: simulated seeds ONLY initialize the contrast structure. They are
never evidence and can never clear the adoption gate — the gate requires a
live n>=8 batch with a confusion matrix. Every row here is labeled
mode=simulated in trace_json and SIMULATED SEED in verifier_output so no
reader (human or tuner) can mistake them for results.

Scenarios (ground-truth types the live batch will use):
  open-fast        listening service, connect succeeds immediately
  closed-rst       unused port, RST/refused immediately
  filtered-timeout nothing answers; probes hang to timeout
  open-slow        listening service behind ~600ms connect latency

Layer behaviors per the Cycle 2 design lock (2026-10-19):
  v0-baseline-probe  naive probe, aggressive UNBOUNDED retries on timeout
                     (the flaw: connection-pool exhaustion on filtered ports)
  v1-robust-syn      fast probe 800ms; RST/ICMP -> closed immediately, no
                     retry; on total timeout escalate ONCE to tcp_connect
                     2500ms before declaring filtered
"""
import json
import sqlite3
import time
import uuid
from pathlib import Path

DB_PATH = Path(__file__).parent / "trajectories.db"

# (scenario, ground_truth, v0: (passed, score, tokens, latency_ms, note),
#                          v1: (passed, score, tokens, latency_ms, note))
SCENARIOS = [
    ("open-fast", "open",
     (1, 0.90, 300, 150, "connect ok"),
     (1, 0.95, 300, 120, "connect ok")),
    ("closed-rst", "closed",
     (1, 0.85, 350, 200, "refused -> closed"),
     (1, 0.95, 300, 90, "RST fail-fast -> closed, no retry")),
    ("filtered-timeout", "filtered",
     (0, 0.10, 4200, 24000, "unbounded retries exhausted budget, still undecided"),
     (1, 0.90, 700, 3300, "800ms probe timeout + one 2500ms fallback -> filtered")),
    ("open-slow", "open",
     (1, 0.80, 500, 900, "connect ok after latency"),
     (1, 0.85, 650, 1400, "probe raced latency; fallback connect confirmed open")),
]


def run_id() -> str:
    return f"run-{int(time.time())}-{uuid.uuid4().hex[:6]}"


def main() -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with sqlite3.connect(DB_PATH) as conn:
        existing = conn.execute(
            "SELECT COUNT(*) FROM trajectories WHERE target_class='service_detect'"
        ).fetchone()[0]
        if existing:
            print(f"service_detect already has {existing} rows — refusing to double-seed")
            return
        for scenario, truth, v0, v1 in SCENARIOS:
            for layer, (passed, score, tokens, latency, note) in (
                ("v0-baseline-probe", v0),
                ("v1-robust-syn", v1),
            ):
                trace = [{
                    "mode": "simulated",
                    "scenario": scenario,
                    "ground_truth": truth,
                    "note": note,
                }]
                conn.execute(
                    "INSERT INTO trajectories VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        run_id(), ts, "service_detect", layer,
                        passed, score, tokens, latency,
                        f"[simulated seed] Classify port state: {scenario}",
                        json.dumps(trace),
                        f"SIMULATED SEED — not evidence: {note}",
                    ),
                )
        conn.commit()
        n = conn.execute(
            "SELECT COUNT(*) FROM trajectories WHERE target_class='service_detect'"
        ).fetchone()[0]
    print(f"seeded service_detect rows: {n} (all labeled simulated)")


if __name__ == "__main__":
    main()
