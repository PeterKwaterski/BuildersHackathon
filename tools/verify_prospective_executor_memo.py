#!/usr/bin/env python3
"""Run the patched TPC-DS logic with conservative memo validation.

Success means every executable query matched DuckDB and every cache hit was
also freshly executed uncached from identical pre-state.  Consequently this is
a correctness verifier, not evidence of runtime savings by itself.
"""

from __future__ import annotations

import argparse
import copy
import json
import resource
import signal
import sys
import time
import unittest  # noqa: F401 - keep target-test import order.
from pathlib import Path

from executor_result_memo import (
    MemoStore,
    UnsupportedValue,
    build_cache_key,
    build_provenance,
    mutable_table_state,
    read_artifact,
    record_execution,
    structural_digest,
)


def cpu_seconds() -> float:
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime


def verify(tree: Path, artifact: Path, changed_paths: set[str]) -> dict:
    tree = tree.resolve()
    sys.path.insert(0, str(tree))
    from sqlglot import find_tables, parse_one
    from sqlglot.executor.python import PythonExecutor
    from sqlglot.executor.table import ensure_tables
    from sqlglot.optimizer import optimize
    from sqlglot.planner import Plan
    from tests.test_executor import TestExecutor
    from tests.helpers import TPCDS_SCHEMA

    payload = read_artifact(artifact)
    provenance = build_provenance(tree)
    store = MemoStore(payload, enabled=True)
    hits = 0
    misses = 0
    verified_hits = 0
    started_cpu = cpu_seconds()
    started_wall = time.monotonic()

    TestExecutor.setUpClass()
    case = TestExecutor(methodName="test_execute_tpcds")
    try:
        parsed = [parse_one(sql) for _meta, sql, _expected in case.tpcds_sqls]
        options = {
            "dialect": None,
            "optimizer": {"leave_tables_isolated": True},
            "executor_env": "sqlglot.executor.env.ENV",
            "query_order": "forward",
        }
        for index, ((meta, _sql, _expected), expression) in enumerate(
            zip(case.tpcds_sqls, parsed)
        ):
            if not meta.get("execute"):
                continue
            selected = {
                table.name: case.tpcds_tables[table.name] for table in find_tables(expression)
            }
            tables = ensure_tables(selected)
            optimized = optimize(
                expression, TPCDS_SCHEMA, leave_tables_isolated=True, dialect=None
            )
            query_identity = (
                "tests/test_executor.py::TestExecutor::test_execute_tpcds"
                f"::query-{index + 1}"
            )
            key = build_cache_key(
                expression=optimized,
                tables=tables,
                schema=TPCDS_SCHEMA,
                provenance=provenance,
                query_identity=query_identity,
                options=options,
            )
            entry = payload.get("entries", {}).get(key)
            if entry and changed_paths.intersection(entry.get("executor_coverage", {})):
                entry = None

            pre_tables = copy.deepcopy(tables) if entry else None
            uncached_entry, uncached = record_execution(
                PythonExecutor(tables=tables), Plan(optimized), tables
            )
            if entry:
                cached = store.lookup(key=key, tables=pre_tables, provenance=provenance)
                if cached is None:
                    raise UnsupportedValue(f"validated lookup missed query {index + 1}")
                if structural_digest((cached.columns, cached.rows)) != structural_digest(
                    (uncached.columns, uncached.rows)
                ):
                    raise UnsupportedValue(f"cached result mismatch query {index + 1}")
                if mutable_table_state(pre_tables) != mutable_table_state(tables):
                    raise UnsupportedValue(f"cached state transition mismatch query {index + 1}")
                if entry.get("result_sha256") != uncached_entry.get("result_sha256"):
                    raise UnsupportedValue(f"cached payload mismatch query {index + 1}")
                hits += 1
                verified_hits += 1
            else:
                misses += 1
            case.subtestHelper(index, uncached, tpch=False)
    finally:
        TestExecutor.tearDownClass()

    return {
        "accepted": True,
        "hits": hits,
        "misses": misses,
        "verified_hits": verified_hits,
        "process_tree_cpu_s": round(cpu_seconds() - started_cpu, 6),
        "wall_s": round(time.monotonic() - started_wall, 6),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--changed-path", action="append", default=[])
    parser.add_argument("--deadline-s", type=float, default=0.0)
    args = parser.parse_args()
    started_cpu = cpu_seconds()
    started_wall = time.monotonic()

    def deadline(_signum, _frame):
        raise TimeoutError("prospective verifier deadline exceeded")

    if args.deadline_s:
        if args.deadline_s <= 0:
            raise SystemExit("--deadline-s must be positive")
        signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, args.deadline_s)
    try:
        result = verify(args.tree, args.artifact, set(args.changed_path))
    except Exception as error:
        result = {
            "accepted": False,
            "reason": f"{type(error).__name__}: {error}",
            "process_tree_cpu_s": round(cpu_seconds() - started_cpu, 6),
            "wall_s": round(time.monotonic() - started_wall, 6),
        }
    finally:
        if args.deadline_s:
            signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["accepted"] else 1)


if __name__ == "__main__":
    main()
