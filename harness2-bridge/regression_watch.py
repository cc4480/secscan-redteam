#!/usr/bin/env python3
"""Regression watch for adopted Harness2 layers (Phase 3d).

The governing principle: an adopted layer that regresses in production
reverts itself, and the regression becomes training data. This watcher is
the measurement + trigger half of that rule:

  - A registry (layer_registry.json, next to trajectories.db) records each
    adopted layer: parent layer, adoption date, and its ADOPTION BASELINE
    (live accuracy over the gate batch that earned adoption).
  - The watcher scans NEW live trajectories (trace mode=live, logged after
    adoption) in windows of >= WINDOW runs. If a layer's recent live
    accuracy falls more than DROP_POINTS below its baseline (or under the
    absolute FLOOR), the trigger fires:
      1. the registry flips the layer's status to `rolled-back`,
      2. ACTIVE layer pointer for the class reverts to the parent layer,
      3. an alert file regression-alert-<class>.json is written for the
         editor/operator, and the window is preserved for the tuner.
  - With fewer than WINDOW new live runs it reports `insufficient-data`
    and changes nothing. It never touches the trajectories table.

Modes: default is report-only (--report). --enforce performs the registry
flip + pointer revert + alert when the trigger fires. The cron/loop runs
--enforce; humans run --report.

Usage:
  python regression_watch.py --db trajectories.db --registry layer_registry.json [--enforce]
Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

WINDOW = 8            # minimum new live runs before judging (the n>=8 rule)
DROP_POINTS = 0.15    # regression = accuracy < baseline - 0.15 ...
FLOOR = 0.75          # ... or accuracy < 0.75, whichever bites first


def live_rows(db_path: Path, target_class: str, layer_id: str, since_ts: str) -> list[sqlite3.Row]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT run_id, timestamp, passed, trace_json FROM trajectories "
            "WHERE target_class=? AND layer_id=? AND timestamp>=? ORDER BY timestamp",
            (target_class, layer_id, since_ts),
        ).fetchall()
    out = []
    for r in rows:
        try:
            trace = json.loads(r["trace_json"] or "[]")
        except json.JSONDecodeError:
            continue
        if trace and isinstance(trace, list) and trace[0].get("mode") == "live":
            out.append(r)
    return out


def evaluate_layer(db_path: Path, entry: dict) -> dict:
    rows = live_rows(db_path, entry["target_class"], entry["layer_id"], entry["adopted_on"])
    baseline = entry["baseline_accuracy"]
    result = {
        "layer_id": entry["layer_id"],
        "target_class": entry["target_class"],
        "status": entry["status"],
        "baseline_accuracy": baseline,
        "new_live_runs": len(rows),
    }
    if entry["status"] != "adopted":
        result["verdict"] = "not-watched"
        return result
    if len(rows) < WINDOW:
        result["verdict"] = "insufficient-data"
        return result
    window = rows[-WINDOW:]
    accuracy = sum(r["passed"] for r in window) / WINDOW
    result["window_accuracy"] = accuracy
    result["window_run_ids"] = [r["run_id"] for r in window]
    # Trigger rule: below the absolute floor OR more than DROP_POINTS under baseline.
    if accuracy < FLOOR or accuracy < baseline - DROP_POINTS:
        result["verdict"] = "REGRESSION"
        result["threshold_floor"] = FLOOR
        result["threshold_baseline_minus_drop"] = baseline - DROP_POINTS
    else:
        result["verdict"] = "healthy"
    return result


def enforce_rollback(registry_path: Path, registry: dict, entry: dict, result: dict, harness_dir: Path) -> None:
    for e in registry["layers"]:
        if e["layer_id"] == entry["layer_id"]:
            e["status"] = "rolled-back"
            e["rolled_back_on"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            e["rollback_reason"] = (
                f"live window accuracy {result.get('window_accuracy')} over "
                f"{WINDOW} runs vs baseline {entry['baseline_accuracy']}"
            )
    registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    # Active-layer pointer for the class reverts to the parent layer.
    pointer_path = harness_dir / "ACTIVE_LAYERS.json"
    pointer = {}
    if pointer_path.exists():
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    pointer[entry["target_class"]] = entry["parent_layer"]
    pointer_path.write_text(json.dumps(pointer, indent=2), encoding="utf-8")
    alert = {
        "alert": "LAYER_REGRESSION_ROLLBACK",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "layer_id": entry["layer_id"],
        "target_class": entry["target_class"],
        "reverted_to": entry["parent_layer"],
        "evidence": result,
    }
    (harness_dir / f"regression-alert-{entry['target_class']}.json").write_text(
        json.dumps(alert, indent=2), encoding="utf-8"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True, type=Path)
    ap.add_argument("--registry", required=True, type=Path)
    ap.add_argument("--enforce", action="store_true")
    args = ap.parse_args()
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    harness_dir = args.db.parent
    any_regression = False
    for entry in registry["layers"]:
        result = evaluate_layer(args.db, entry)
        line = (
            f"{entry['layer_id']} ({entry['target_class']}): {result['verdict']}"
            f" | baseline={result['baseline_accuracy']} new_live={result['new_live_runs']}"
        )
        if "window_accuracy" in result:
            line += f" window_acc={result['window_accuracy']:.2f}"
        print(line)
        if result["verdict"] == "REGRESSION":
            any_regression = True
            if args.enforce:
                enforce_rollback(args.registry, registry, entry, result, harness_dir)
                print(f"  -> ENFORCED: rolled back to {entry['parent_layer']}, alert written")
            else:
                print("  -> report-only: rerun with --enforce to roll back")
    return 0


if __name__ == "__main__":
    sys.exit(main())
