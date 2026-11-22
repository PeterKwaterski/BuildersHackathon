#!/usr/bin/env python3
"""Build one deterministic TPC-DS PythonExecutor memo artifact."""

from __future__ import annotations

import argparse
import ast
import csv
import gzip
import json
import sys
import unittest  # noqa: F401 - imported before sqlglot to match the target test.
from pathlib import Path

from executor_result_memo import (
    ExecutionCoverage,
    FORMAT,
    TEST_ID,
    StructuralEncoder,
    build_cache_key,
    build_provenance,
    canonical_json,
    record_execution,
    sha256_bytes,
    write_artifact,
)


def open_file(path: Path):
    with path.open("rb") as source:
        gzipped = source.read(2) == b"\x1f\x8b"
    if gzipped:
        return gzip.open(path, "rt", newline="")
    return path.open(encoding="utf-8", newline="")


def load_tables(tree: Path, schema):
    from sqlglot.executor.table import Table

    directory = tree / "tests" / "fixtures" / "optimizer" / "tpc-ds"
    tables = {}
    for table_name, columns in schema.items():
        reader = csv.reader(open_file(directory / f"{table_name}.csv.gz"), delimiter="|")
        next(reader)
        rows = []
        cell_types = []
        for row in reader:
            if not cell_types:
                for value in row:
                    try:
                        cell_types.append(type(ast.literal_eval(value)))
                    except (ValueError, SyntaxError):
                        cell_types.append(str)
            rows.append(
                tuple(
                    None if (kind is not str and value == "") else kind(value)
                    for kind, value in zip(cell_types, row)
                )
            )
        tables[table_name] = Table(columns=columns, rows=rows)
    return tables


def build(tree: Path, order: str) -> dict:
    tree = tree.resolve()
    sys.path.insert(0, str(tree))

    from sqlglot import find_tables, parse_one
    from sqlglot.executor.python import PythonExecutor
    from sqlglot.executor.table import ensure_tables
    from sqlglot.optimizer import optimize
    from sqlglot.planner import Plan
    from tests.helpers import TPCDS_SCHEMA, load_sql_fixture_pairs

    provenance = build_provenance(tree)
    fixture_rows = list(load_sql_fixture_pairs("optimizer/tpc-ds/tpc-ds.sql"))
    parsed = [parse_one(sql) for _, sql, _ in fixture_rows]
    all_tables = load_tables(tree, TPCDS_SCHEMA)
    indices = list(range(len(fixture_rows)))
    if order == "reverse":
        indices.reverse()

    entries = {}
    query_results = {}
    options = {
        "dialect": None,
        "optimizer": {"leave_tables_isolated": True},
        "executor_env": "sqlglot.executor.env.ENV",
        "query_order": order,
    }
    for index in indices:
        meta, _sql, _expected = fixture_rows[index]
        if not meta.get("execute"):
            continue
        expression = parsed[index]
        selected = {table.name: all_tables[table.name] for table in find_tables(expression)}
        tables = ensure_tables(selected)
        optimized = optimize(
            expression,
            TPCDS_SCHEMA,
            leave_tables_isolated=True,
            dialect=None,
        )
        query_identity = f"{TEST_ID}::query-{index + 1}"
        key = build_cache_key(
            expression=optimized,
            tables=tables,
            schema=TPCDS_SCHEMA,
            provenance=provenance,
            query_identity=query_identity,
            options=options,
        )
        coverage = ExecutionCoverage(tree)
        with coverage:
            plan = Plan(optimized)
        entry, result = record_execution(
            PythonExecutor(tables=tables), plan, tables, coverage=coverage
        )
        entry["executor_coverage"] = coverage.payload()
        entry["query_identity"] = query_identity
        entries[key] = entry
        query_results[str(index + 1)] = {
            "result_sha256": entry["result_sha256"],
            "columns_rows_sha256": sha256_bytes(
                canonical_json(StructuralEncoder().encode((result.columns, result.rows)))
            ),
        }

    return {
        "format": FORMAT,
        "provenance": provenance,
        "options": options,
        "query_count": len(fixture_rows),
        "executed_query_count": len(entries),
        "entries": entries,
        "query_results": query_results,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--order", choices=("forward", "reverse"), default="forward")
    args = parser.parse_args()
    payload = build(args.tree, args.order)
    artifact_hash, payload_hash = write_artifact(args.output, payload)
    print(
        json.dumps(
            {
                "artifact": str(args.output),
                "artifact_sha256": artifact_hash,
                "payload_sha256": payload_hash,
                "queries": payload["executed_query_count"],
                "order": args.order,
                "seed": payload["provenance"]["runtime"]["python_hash_seed"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
