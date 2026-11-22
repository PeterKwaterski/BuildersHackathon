#!/usr/bin/env python3
"""Build an answer-free profile of the pinned TPC optimizer frontends."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import sys
import unittest  # Keep the target tests' import order.
from pathlib import Path

from tpc_graph_digest import GRAPH_FORMAT, graph_digest


SOURCE_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


def collect(tree: Path) -> dict:
    sys.path.insert(0, str(tree))
    from sqlglot import parse_one
    from sqlglot.optimizer import optimize
    from tests.helpers import TPCDS_SCHEMA, TPCH_SCHEMA, load_sql_fixture_pairs

    suites = {}
    for name, fixture, schema in (
        ("tpcds", "optimizer/tpc-ds/tpc-ds.sql", TPCDS_SCHEMA),
        ("tpch", "optimizer/tpc-h/tpc-h.sql", TPCH_SCHEMA),
    ):
        rows = []
        for index, (meta, sql, expected) in enumerate(load_sql_fixture_pairs(fixture), 1):
            expression = optimize(parse_one(sql), schema, leave_tables_isolated=True, dialect=None)
            rows.append(
                {
                    "index": index,
                    "execute": bool(meta.get("execute")),
                    "sql_sha256": hashlib.sha256(sql.encode()).hexdigest(),
                    "expected_sha256": hashlib.sha256(expected.encode()).hexdigest(),
                    "pretty_sha256": hashlib.sha256(expression.sql(pretty=True).encode()).hexdigest(),
                    "graph_sha256": graph_digest(expression)
                    if bool(meta.get("execute"))
                    else None,
                }
            )
        suites[name] = rows
    return {
        "format": "kashimo-tpc-plan-profile-v2",
        "graph_format": GRAPH_FORMAT,
        "source_sha": SOURCE_SHA,
        "python": list(sys.version_info[:3]),
        "implementation": sys.implementation.name,
        "platform": platform.machine(),
        "hash_seed": os.environ.get("PYTHONHASHSEED"),
        "suites": suites,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = collect(args.tree.resolve())
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with args.output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as stream:
            stream.write(encoded)
    print(hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
