#!/usr/bin/env python3
"""Import adapter trajectory JSONL into the Harness2 database.

The adapter (llm-router Phase 1) emits one JSONL record per model call:
{ts, run_id, role, manifest, request, response, usage, latency_ms, retries}.

Harness2's `trajectories` table holds *evaluated* layer runs (pass/fail +
verifier output) — a different grain, written by harness_logger.log_trajectory.
Raw model calls are NOT evaluations, so this importer lands them in a sibling
table `call_trajectories` in the same DB. The tuner/eval tooling promotes
verified outcomes into `trajectories`; nothing unverified is ever stamped as
evaluated (the pkg-auth_check-004 lesson).

Idempotent: call_id is a content hash, re-importing the same file is a no-op.

Usage:
  python import_adapter_trajectories.py --jsonl trajectories.jsonl --db trajectories.db
Stdlib only (runs on the PC's Python 3.12).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

DDL = """
CREATE TABLE IF NOT EXISTS call_trajectories (
    call_id TEXT PRIMARY KEY,
    ts TEXT,
    run_id TEXT,
    role TEXT,
    provider TEXT,
    model TEXT,
    manifest_json TEXT,
    request_json TEXT,
    response_json TEXT,
    usage_json TEXT,
    latency_ms INTEGER,
    retries INTEGER,
    error TEXT,
    imported_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_call_traj_run ON call_trajectories(run_id);
"""


def call_id_for(rec: dict) -> str:
    manifest = rec.get("manifest") or {}
    basis = "|".join(
        [
            str(rec.get("ts", "")),
            str(manifest.get("prompt_sha256", "")),
            str(manifest.get("model", "")),
            json.dumps(rec.get("response"), sort_keys=True, default=str)[:512],
        ]
    )
    return "adapter-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def import_file(jsonl_path: Path, db_path: Path) -> tuple[int, int]:
    imported = skipped = 0
    imported_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with sqlite3.connect(db_path) as conn:
        conn.executescript(DDL)
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            manifest = rec.get("manifest") or {}
            cur = conn.execute(
                """INSERT OR IGNORE INTO call_trajectories VALUES
                   (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    call_id_for(rec),
                    rec.get("ts"),
                    rec.get("run_id"),
                    rec.get("role"),
                    manifest.get("provider"),
                    manifest.get("model"),
                    json.dumps(manifest, default=str),
                    json.dumps(rec.get("request"), default=str) if rec.get("request") is not None else None,
                    json.dumps(rec.get("response"), default=str) if rec.get("response") is not None else None,
                    json.dumps(rec.get("usage"), default=str) if rec.get("usage") is not None else None,
                    rec.get("latency_ms"),
                    rec.get("retries"),
                    rec.get("error"),
                    imported_at,
                ),
            )
            if cur.rowcount:
                imported += 1
            else:
                skipped += 1
        conn.commit()
    return imported, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jsonl", required=True, type=Path)
    ap.add_argument("--db", required=True, type=Path)
    args = ap.parse_args()
    if not args.jsonl.exists():
        print(f"jsonl not found: {args.jsonl}", file=sys.stderr)
        return 2
    imported, skipped = import_file(args.jsonl, args.db)
    print(f"imported={imported} skipped={skipped} db={args.db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
