#!/usr/bin/env python3
"""Propose-only intake for agent-authored penetration tests.

Part of the background improvement loop (Phase 3b): any agent may PROPOSE a
new test — it may never adopt one. A proposal is a structured record that
enters the gate pipeline in state `proposed`; only the editor review can move
it to `in-review`, and only promotion by the editor turns it into contrast
seed material for a Harness2 cycle. Adoption remains Carlos's call, always.

Storage: `test_proposals` table in the Harness2 trajectories.db (created on
first use). Validation is structural and fails loud: a proposal without a
rationale, without arsenal grounding, or with an empty test spec is rejected
at the door — merit is judged later by the gate, never by this intake.

Usage:
  python propose.py add --json proposal.json --db trajectories.db
  python propose.py list --db trajectories.db [--status proposed]
  python propose.py set-status --db trajectories.db --id prop-... --status in-review

Proposal JSON fields:
  author        who proposes ("exploiter", "tuner", "cho-zen1", ...)
  title         short name of the test
  target_type   one of SS | SL | WS | LX  (battery target affinity)
  target_class  harness class it extends (e.g. "auth_check", "service_detect",
                or a proposed new class name)
  rationale     why this test should exist — the gap it covers
  arsenal_refs  non-empty list of arsenal entry names/URLs that ground it
  test_spec     {setup, steps[], expected_vulnerable, expected_fixed}
Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

TARGET_TYPES = {"SS", "SL", "WS", "LX"}
STATUSES = {"proposed", "in-review", "rejected", "promoted"}
# Legal transitions — propose-only means nothing skips the editor.
TRANSITIONS = {
    "proposed": {"in-review", "rejected"},
    "in-review": {"rejected", "promoted"},
    "rejected": set(),
    "promoted": set(),
}

DDL = """
CREATE TABLE IF NOT EXISTS test_proposals (
    proposal_id TEXT PRIMARY KEY,
    ts TEXT,
    author TEXT,
    title TEXT,
    target_type TEXT,
    target_class TEXT,
    rationale TEXT,
    arsenal_refs TEXT,
    test_spec TEXT,
    status TEXT
);
"""


def validate(p: dict) -> list[str]:
    errors: list[str] = []
    for field in ("author", "title", "rationale", "target_class"):
        if not p.get(field) or not isinstance(p[field], str):
            errors.append(f"missing/empty string field: {field}")
    if p.get("target_type") not in TARGET_TYPES:
        errors.append(f"target_type must be one of {sorted(TARGET_TYPES)}")
    refs = p.get("arsenal_refs")
    if not isinstance(refs, list) or not refs or not all(isinstance(r, str) and r for r in refs):
        errors.append("arsenal_refs must be a non-empty list of entry names/URLs")
    spec = p.get("test_spec")
    if not isinstance(spec, dict):
        errors.append("test_spec must be an object")
    else:
        if not spec.get("setup"):
            errors.append("test_spec.setup is required")
        if not isinstance(spec.get("steps"), list) or not spec["steps"]:
            errors.append("test_spec.steps must be a non-empty list")
        if not spec.get("expected_vulnerable"):
            errors.append("test_spec.expected_vulnerable is required")
        if not spec.get("expected_fixed"):
            errors.append("test_spec.expected_fixed is required")
    return errors


def add_proposal(db_path: Path, p: dict) -> str:
    errors = validate(p)
    if errors:
        raise ValueError("invalid proposal: " + "; ".join(errors))
    basis = json.dumps(p, sort_keys=True, default=str)
    proposal_id = "prop-" + hashlib.sha256(basis.encode()).hexdigest()[:10]
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with sqlite3.connect(db_path) as conn:
        conn.executescript(DDL)
        conn.execute(
            "INSERT OR IGNORE INTO test_proposals VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                proposal_id, ts, p["author"], p["title"], p["target_type"],
                p["target_class"], p["rationale"],
                json.dumps(p["arsenal_refs"]),
                json.dumps(p["test_spec"]),
                "proposed",
            ),
        )
        conn.commit()
    return proposal_id


def list_proposals(db_path: Path, status: str | None) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.executescript(DDL)
        conn.row_factory = sqlite3.Row
        q = "SELECT * FROM test_proposals"
        args: list = []
        if status:
            q += " WHERE status = ?"
            args.append(status)
        q += " ORDER BY ts"
        return [dict(r) for r in conn.execute(q, args).fetchall()]


def set_status(db_path: Path, proposal_id: str, new_status: str) -> None:
    if new_status not in STATUSES:
        raise ValueError(f"status must be one of {sorted(STATUSES)}")
    with sqlite3.connect(db_path) as conn:
        conn.executescript(DDL)
        row = conn.execute(
            "SELECT status FROM test_proposals WHERE proposal_id = ?", (proposal_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown proposal: {proposal_id}")
        current = row[0]
        if new_status not in TRANSITIONS[current]:
            raise ValueError(f"illegal transition {current} -> {new_status}")
        conn.execute(
            "UPDATE test_proposals SET status = ? WHERE proposal_id = ?",
            (new_status, proposal_id),
        )
        conn.commit()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True, type=Path)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("--json", required=True, type=Path)
    l = sub.add_parser("list")
    l.add_argument("--status")
    s = sub.add_parser("set-status")
    s.add_argument("--id", required=True)
    s.add_argument("--status", required=True)
    args = ap.parse_args()
    try:
        if args.cmd == "add":
            p = json.loads(args.json.read_text(encoding="utf-8"))
            pid = add_proposal(args.db, p)
            print(f"proposed: {pid} (status=proposed)")
        elif args.cmd == "list":
            for row in list_proposals(args.db, args.status):
                print(f"{row['proposal_id']}  [{row['status']}]  {row['target_type']}/{row['target_class']}  {row['title']}  (by {row['author']})")
        elif args.cmd == "set-status":
            set_status(args.db, args.id, args.status)
            print(f"{args.id} -> {args.status}")
    except ValueError as err:
        print(str(err), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
