"""Isolated exact-semantics worker for tpc_fixture_verify."""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import sys
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context
from pathlib import Path


def _pairs(path: Path):
    source = path.read_text(encoding="utf-8")
    filtered = "\n".join(
        line for line in source.splitlines() if line and not line.startswith("--")
    )
    statements = filtered.split(";")
    pairs = []
    for index in range(0, len(statements), 2):
        if index + 1 >= len(statements):
            continue
        sql = statements[index].strip()
        lines = sql.split("\n")
        meta = {}
        position = 0
        while position < len(lines) and lines[position].startswith("#"):
            key, value = lines[position].split(":", maxsplit=1)
            meta[key.lstrip("#").strip()] = value.strip()
            position += 1
        pairs.append((meta, "\n".join(lines[position:]), statements[index + 1].strip()))
    return pairs


def _safe_queries(prospective, original, indices):
    from sqlglot import exp, find_tables, parse_one
    from tests.helpers import TPCDS_SCHEMA

    allowed_nodes = set()
    allowed_functions = set()
    for meta, sql, _expected in original:
        if not meta.get("execute"):
            continue
        expression = parse_one(sql)
        for node in expression.walk():
            allowed_nodes.add((type(node).__module__, type(node).__qualname__))
            if isinstance(node, exp.Anonymous):
                allowed_functions.add(node.name.upper())

    def shape(node):
        if isinstance(node, exp.Literal):
            return (type(node).__module__, type(node).__qualname__, bool(node.is_string))
        if isinstance(node, exp.Expr):
            return (
                type(node).__module__,
                type(node).__qualname__,
                tuple((key, shape(value)) for key, value in node.args.items()),
            )
        if isinstance(node, list):
            return ("list", tuple(shape(value) for value in node))
        if isinstance(node, tuple):
            return ("tuple", tuple(shape(value) for value in node))
        return (type(node).__module__, type(node).__qualname__, node)

    parsed = {}
    for index in indices:
        meta, sql, _expected = prospective[index]
        expression = parse_one(sql)
        original_expression = parse_one(original[index][1])
        if not isinstance(expression, exp.Query):
            raise ValueError("non-query fixture")
        nodes = {(type(node).__module__, type(node).__qualname__) for node in expression.walk()}
        functions = {
            node.name.upper() for node in expression.find_all(exp.Anonymous)
        }
        tables = {table.name for table in find_tables(expression)}
        if (
            nodes - allowed_nodes
            or functions - allowed_functions
            or tables - set(TPCDS_SCHEMA)
            or shape(expression) != shape(original_expression)
        ):
            raise ValueError("query outside pinned TPC-DS grammar")
        parsed[index] = (meta, expression)
    return parsed


def _table_digest(tables) -> str:
    digest = hashlib.sha256()
    for name in sorted(tables):
        table = tables[name]
        digest.update(pickle.dumps((name, table.columns, table.rows, table.column_range), protocol=5))
    return digest.hexdigest()


def _primed_execute(expression, meta, mode):
    from tests import test_executor

    tables = test_executor._tables
    before = _table_digest(tables)
    for table in tables.values():
        if mode == "first" and table.rows:
            table.reader.row = table.rows[0]
            table.range_reader.range = range(0, min(1, len(table.rows)))
        elif mode == "last" and table.rows:
            table.reader.row = table.rows[-1]
            table.range_reader.range = range(max(0, len(table.rows) - 1), len(table.rows))
        else:
            table.reader.row = ()
            table.range_reader.range = range(0)
    result = test_executor.mp_execute(expression, meta)
    after = _table_digest(tables)
    if before != after:
        raise AssertionError("executor mutated persistent table structure")
    return result


def main() -> None:
    if len(sys.argv) != 4 or os.geteuid() == 0:
        raise SystemExit(2)
    repo, payload_path, result_path = map(Path, sys.argv[1:])
    os.chdir(repo)
    sys.path.insert(0, str(repo))
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    indices = payload.get("indices")
    if (
        type(indices) is not list
        or not indices
        or len(indices) > 3
        or any(type(index) is not int or index < 0 or index >= 99 for index in indices)
        or len(indices) != len(set(indices))
        or indices != sorted(indices)
    ):
        raise ValueError("invalid changed-pair roster")

    prospective = _pairs(Path("tests/fixtures/optimizer/tpc-ds/tpc-ds.sql"))
    original = _pairs(Path("/app/sqlglot-pinned/tests/fixtures/optimizer/tpc-ds/tpc-ds.sql"))
    if len(prospective) != len(original) or len(original) != 99:
        raise ValueError("fixture roster")
    parsed = _safe_queries(prospective, original, indices)

    if not any(meta.get("execute") for meta, _expression in parsed.values()):
        Path(result_path).write_text(
            json.dumps({"ok": True, "indices": indices}, separators=(",", ":")),
            encoding="utf-8",
        )
        return

    from tests import test_executor

    TestExecutor = test_executor.TestExecutor
    initializer = test_executor.initializer
    # The two benchmark families use separate connections, tables, schemas,
    # fixture lists, and cache keys. This verifier invokes only the TPC-DS test,
    # so avoid materializing unused TPC-H CSV rows while retaining the pinned
    # setUpClass implementation for every TPC-DS input.
    tpch_schema = test_executor.TPCH_SCHEMA
    test_executor.TPCH_SCHEMA = {}
    try:
        TestExecutor.setUpClass()
    finally:
        test_executor.TPCH_SCHEMA = tpch_schema
    try:
        instance = TestExecutor("test_execute_tpcds")
        with ProcessPoolExecutor(
            max_workers=1,
            mp_context=get_context("spawn"),
            initializer=initializer,
            initargs=(__import__("tests.helpers", fromlist=["TPCDS_SCHEMA"]).TPCDS_SCHEMA, TestExecutor.tpcds_tables),
        ) as pool:
            for index in indices:
                meta, expression = parsed[index]
                if not meta.get("execute"):
                    continue
                for mode in ("empty", "last", "empty"):
                    table = pool.submit(_primed_execute, expression, meta, mode).result()
                    if table is None:
                        raise AssertionError("executed query returned no table")
                    instance.subtestHelper(index, table, tpch=False)
    finally:
        TestExecutor.tearDownClass()
    Path(result_path).write_text(
        json.dumps({"ok": True, "indices": indices}, separators=(",", ":")),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
