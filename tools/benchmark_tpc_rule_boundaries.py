#!/usr/bin/env python3
"""Measure pinned TPC-DS optimizer rule CPU without executing query results."""

from __future__ import annotations

import argparse
import inspect
import json
import statistics
import sys
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--snapshots", action="store_true")
    args = parser.parse_args()
    if args.repeats < 1:
        raise SystemExit("--repeats must be positive")
    sys.path.insert(0, str(args.tree.resolve()))

    from sqlglot import parse_one
    from sqlglot.optimizer import optimizer
    from sqlglot.schema import ensure_schema
    from tests.helpers import TPCDS_SCHEMA, load_sql_fixture_pairs
    from tpc_rule_replay import RULES, boundary_digest

    rules = optimizer.RULES
    names = tuple(f"{rule.__module__}.{rule.__name__}" for rule in rules)
    if names != RULES:
        raise SystemExit("pinned optimizer rule identity mismatch")
    fixtures = list(load_sql_fixture_pairs("optimizer/tpc-ds/tpc-ds.sql"))
    if len(fixtures) != 99 or sum(bool(meta.get("execute")) for meta, _, _ in fixtures) != 57:
        raise SystemExit("TPC-DS fixture accounting mismatch")
    schema = ensure_schema(TPCDS_SCHEMA)
    runs = []
    for _ in range(args.repeats):
        totals = {name: 0 for name in names}
        active = {name: 0 for name in names}
        snapshots = 0
        started = time.process_time_ns()
        for meta, sql, _expected in fixtures:
            expression = parse_one(sql)
            possible = {
                "db": None, "catalog": None, "schema": schema, "dialect": None,
                "sql": None, "isolate_tables": True, "quote_identifiers": False,
            }
            for name, rule in zip(names, rules):
                params = inspect.getfullargspec(rule).args
                kwargs = {key: possible[key] for key in params if key in possible}
                before = time.process_time_ns()
                expression = rule(expression, **kwargs)
                elapsed = time.process_time_ns() - before
                totals[name] += elapsed
                if meta.get("execute"):
                    active[name] += elapsed
                if args.snapshots:
                    before = time.process_time_ns()
                    boundary_digest(expression)
                    snapshots += time.process_time_ns() - before
        runs.append({
            "total_ns": time.process_time_ns() - started,
            "rules_ns": totals,
            "active_rules_ns": active,
            "snapshot_ns": snapshots,
        })
    result = {
        "format": "tpc-rule-cpu-v1",
        "tree": str(args.tree.resolve()),
        "repeats": args.repeats,
        "queries": 99,
        "active_queries": 57,
        "snapshots": args.snapshots,
        "total_median_ns": int(statistics.median(run["total_ns"] for run in runs)),
        "snapshot_median_ns": int(statistics.median(run["snapshot_ns"] for run in runs)),
        "rules": {
            name: {
                "all_median_ns": int(statistics.median(run["rules_ns"][name] for run in runs)),
                "active_median_ns": int(statistics.median(run["active_rules_ns"][name] for run in runs)),
            }
            for name in names
        },
        "runs": runs,
    }
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
