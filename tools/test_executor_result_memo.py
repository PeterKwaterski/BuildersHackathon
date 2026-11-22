#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from executor_result_memo import (
    ExecutionCoverage,
    MemoStore,
    UnsupportedValue,
    build_cache_key,
    build_provenance,
    read_artifact,
    record_execution,
    source_manifest,
    write_artifact,
)
from run_prospective_executor_memo import PatchRejected, apply_change, parse_patch


TREE = Path(os.environ.get("SQLGLOT_TREE", "/home/silverdisk/BuildersHackathon-branch/sqlglot"))
sys.path.insert(0, str(TREE))

from sqlglot import parse_one  # noqa: E402
from sqlglot.executor.python import PythonExecutor  # noqa: E402
from sqlglot.executor.table import Table, ensure_tables  # noqa: E402
from sqlglot.optimizer import optimize  # noqa: E402
from sqlglot.planner import Plan  # noqa: E402


SCHEMA = {"x": {"a": "int", "b": "int"}}
OPTIONS = {"dialect": None, "optimizer": {"leave_tables_isolated": True}}


def inputs(sql="SELECT a + b AS c FROM x", rows=None, schema=None):
    schema = schema or SCHEMA
    rows = rows or [(1, 2), (3, 4)]
    tables = ensure_tables({"x": Table(columns=tuple(schema["x"]), rows=list(rows))})
    expression = optimize(parse_one(sql), schema, leave_tables_isolated=True)
    return expression, tables, schema


class MemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provenance = build_provenance(TREE)

    def key(self, expression, tables, schema=SCHEMA, **kwargs):
        return build_cache_key(
            expression=expression,
            tables=tables,
            schema=schema,
            provenance=kwargs.get("provenance", self.provenance),
            query_identity=kwargs.get("query_identity", "target::query-1"),
            options=kwargs.get("options", OPTIONS),
        )

    def test_equal_inputs_have_equal_key(self):
        left = inputs()
        right = inputs()
        self.assertEqual(self.key(*left), self.key(*right))

    def test_every_input_family_changes_key(self):
        base = inputs()
        base_key = self.key(*base)
        variants = [
            inputs(rows=[(1, 2), (3, 9)]),
            inputs(schema={"x": {"b": "int", "a": "int"}}, rows=[(2, 1), (4, 3)]),
            inputs(sql="SELECT b + a AS c FROM x"),
        ]
        for variant in variants:
            self.assertNotEqual(base_key, self.key(*variant))

        expression, tables, schema = inputs()
        tables.mapping["x"].reader.row = (1, 2)
        self.assertNotEqual(base_key, self.key(expression, tables, schema))
        self.assertNotEqual(
            base_key,
            self.key(*inputs(), query_identity="target::query-2"),
        )
        self.assertNotEqual(
            base_key,
            self.key(*inputs(), options={**OPTIONS, "dialect": "duckdb"}),
        )
        changed_provenance = {**self.provenance, "files_sha256": "0" * 64}
        self.assertNotEqual(
            base_key,
            self.key(*inputs(), provenance=changed_provenance),
        )

    def test_source_and_fixture_bytes_are_bound(self):
        manifest = dict(source_manifest(TREE))
        self.assertIn("sqlglot/executor/python.py", manifest)
        self.assertIn("sqlglot/planner.py", manifest)
        self.assertIn("tests/test_executor.py", manifest)
        self.assertIn("tests/fixtures/optimizer/tpc-ds/tpc-ds.sql", manifest)
        self.assertIn("tests/fixtures/optimizer/tpc-ds/store_sales.csv.gz", manifest)

    def test_real_executor_coverage_is_query_scoped(self):
        expression, tables, _schema = inputs()
        coverage = ExecutionCoverage(TREE)
        with coverage:
            plan = Plan(expression)
        record_execution(PythonExecutor(tables=tables), plan, tables, coverage=coverage)
        payload = coverage.payload()
        self.assertIn("sqlglot/executor/python.py", payload)
        self.assertTrue(payload["sqlglot/executor/python.py"])

    def test_default_off_and_validated_hit(self):
        expression, tables, schema = inputs()
        key = self.key(expression, tables, schema)
        entry, uncached = record_execution(PythonExecutor(tables=tables), Plan(expression), tables)
        payload = {
            "format": "sqlglot-python-executor-memo-v1",
            "provenance": self.provenance,
            "entries": {key: entry},
        }
        self.assertIsNone(MemoStore(payload).lookup(key=key, tables=tables, provenance=self.provenance))

        fresh_expression, fresh_tables, fresh_schema = inputs()
        fresh_key = self.key(fresh_expression, fresh_tables, fresh_schema)
        cached = MemoStore(payload, enabled=True).lookup(
            key=fresh_key, tables=fresh_tables, provenance=self.provenance
        )
        self.assertEqual((uncached.columns, uncached.rows), (cached.columns, cached.rows))

        changed_expression, changed_tables, changed_schema = inputs(rows=[(1, 2), (3, 9)])
        changed_key = self.key(changed_expression, changed_tables, changed_schema)
        self.assertIsNone(
            MemoStore(payload, enabled=True).lookup(
                key=changed_key, tables=changed_tables, provenance=self.provenance
            )
        )

    def test_artifact_is_byte_deterministic_and_tamper_evident(self):
        payload = {"format": "sqlglot-python-executor-memo-v1", "z": 1, "a": [2, 3]}
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json.gz"
            second = Path(directory) / "second.json.gz"
            first_hashes = write_artifact(first, payload)
            second_hashes = write_artifact(second, payload)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_hashes, second_hashes)
            self.assertEqual(read_artifact(first), payload)
            damaged = bytearray(first.read_bytes())
            damaged[-8] ^= 1
            first.write_bytes(damaged)
            with self.assertRaises(UnsupportedValue):
                read_artifact(first)

    def test_malformed_hit_falls_back_without_mutating_tables(self):
        expression, tables, schema = inputs()
        key = self.key(expression, tables, schema)
        entry, _result = record_execution(PythonExecutor(tables=tables), Plan(expression), tables)
        fresh_expression, fresh_tables, fresh_schema = inputs()
        fresh_key = self.key(fresh_expression, fresh_tables, fresh_schema)
        before = fresh_tables.mapping["x"].reader.row
        entry["result_sha256"] = "0" * 64
        payload = {
            "format": "sqlglot-python-executor-memo-v1",
            "provenance": self.provenance,
            "entries": {key: entry},
        }
        self.assertEqual(key, fresh_key)
        self.assertIsNone(
            MemoStore(payload, enabled=True).lookup(
                key=fresh_key, tables=fresh_tables, provenance=self.provenance
            )
        )
        self.assertEqual(before, fresh_tables.mapping["x"].reader.row)

    def test_closed_patch_applier_constructs_isolated_edit(self):
        patch_text = """diff --git a/sqlglot/example.py b/sqlglot/example.py
index 1111111..2222222 100644
--- a/sqlglot/example.py
+++ b/sqlglot/example.py
@@ -1,2 +1,2 @@
 one
-two
+changed
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tree"
            target = root / "sqlglot" / "example.py"
            target.parent.mkdir(parents=True)
            target.write_text("one\ntwo\n", encoding="utf-8")
            patch = Path(directory) / "change.patch"
            patch.write_text(patch_text, encoding="utf-8")
            changes = parse_patch(patch)
            self.assertEqual(apply_change(root, changes[0]), "sqlglot/example.py")
            self.assertEqual(target.read_text(encoding="utf-8"), "one\nchanged\n")

    def test_closed_patch_applier_rejects_unknown_directive(self):
        with tempfile.TemporaryDirectory() as directory:
            patch = Path(directory) / "bad.patch"
            patch.write_text(
                "diff --git a/x b/y\nrename from x\nrename to y\n",
                encoding="utf-8",
            )
            with self.assertRaises(PatchRejected):
                parse_patch(patch)


if __name__ == "__main__":
    unittest.main()
