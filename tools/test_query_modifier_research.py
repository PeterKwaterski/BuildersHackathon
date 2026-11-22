#!/usr/bin/env python3
from __future__ import annotations

import copy
import gzip
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import query_modifier_research as runtime
import collect_query_modifier_reads as collector
from build_query_modifier_model import load_trace, packed_cost, source_theorem


class QueryModifierResearchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.original = 'QUERY_MODIFIERS = {\n    "where": False,\n    "limit": False,\n}\n'
        self.changed = 'QUERY_MODIFIERS = {\n    "limit": False,\n}\n'
        digest_a = "a" * 64
        digest_b = "b" * 64
        self.model = {
            "d": {
                "where": [hashlib.sha256(self.changed.encode()).hexdigest(), [0]],
                "limit": ["c" * 64, [1]],
            },
            "n": 2,
            "p": {
                "builder": digest_a,
                "collector": digest_b,
                "manifests": [digest_a, digest_b],
                "traces": [digest_a, digest_b],
            },
            "s": hashlib.sha256(self.original.encode()).hexdigest(),
            "sha": "source",
            "t": hashlib.sha256(b"test-a\0test-b").hexdigest(),
            "v": 1,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def write_model(self, model=None):
        raw = gzip.compress(
            json.dumps(model or self.model, sort_keys=True, separators=(",", ":")).encode(),
            mtime=0,
        )
        path = self.root / "model.json.gz"
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def test_hash_first_recursive_model_validation(self):
        path, digest = self.write_model()
        loaded = runtime.load_model(path, digest, "source", ["test-a", "test-b"])
        self.assertEqual(loaded, self.model)

        raw = path.read_bytes()
        for tampered in (raw + b"append", raw[:-1] + bytes([raw[-1] ^ 1])):
            path.write_bytes(tampered)
            self.assertIsNone(
                runtime.load_model(path, digest, "source", ["test-a", "test-b"])
            )

        mutations = (
            lambda value: value.update(extra=True),
            lambda value: value["p"].pop("collector"),
            lambda value: value["p"]["traces"].append("d" * 64),
            lambda value: value["p"]["traces"].__setitem__(0, []),
            lambda value: value["d"]["where"][1].append("0"),
            lambda value: value["d"]["limit"].__setitem__(0, value["d"]["where"][0]),
        )
        for mutate in mutations:
            broken = copy.deepcopy(self.model)
            mutate(broken)
            broken_path, broken_digest = self.write_model(broken)
            self.assertIsNone(
                runtime.load_model(
                    broken_path, broken_digest, "source", ["test-a", "test-b"]
                )
            )

    def test_trace_provenance_validation_rejects_malformed_types(self):
        valid = {
            "creations": {},
            "events": {"label": {"'key'": ["test-a"]}},
            "imports": [],
            "tasks": {
                "completed": ["task"],
                "submitted": ["task"],
                "workers": {"task": [123]},
            },
        }
        path = self.root / "trace.json"
        path.write_text(json.dumps(valid))
        self.assertEqual(load_trace(path), valid)
        mutations = (
            lambda value: value["events"]["label"]["'key'"].append([]),
            lambda value: value["tasks"]["workers"]["task"].append("pid"),
            lambda value: value["tasks"]["completed"].clear(),
            lambda value: value.update(extra=True),
        )
        for mutate in mutations:
            broken = copy.deepcopy(valid)
            mutate(broken)
            path.write_text(json.dumps(broken))
            with self.assertRaises(SystemExit):
                load_trace(path)

    def test_runtime_accepts_only_certified_exact_whole_file_deletion(self):
        self.assertTrue(runtime.FEATURE_ENABLED)
        with patch.object(runtime, "FEATURE_ENABLED", True):
            self.assertEqual(
                runtime.readers(runtime.TARGET_PATH, self.original, self.changed, self.model),
                {0},
            )
            for changed in (
                self.original.replace("False", "True", 1),
                self.changed.replace('    "limit": False,\n', ""),
                self.changed + "# extra\n",
            ):
                self.assertIsNone(
                    runtime.readers(runtime.TARGET_PATH, self.original, changed, self.model)
                )
            self.assertIsNone(
                runtime.readers("sqlglot/expressions/query.py", self.original, self.changed, self.model)
            )
            self.assertIsNone(
                runtime.readers(runtime.TARGET_PATH, self.original + "# drift\n", self.changed, self.model)
            )
            malformed = copy.deepcopy(self.model)
            malformed["d"] = []
            self.assertIsNone(
                runtime.readers(runtime.TARGET_PATH, self.original, self.changed, malformed)
            )

            disallowed = copy.deepcopy(self.model)
            disallowed["d"]["match"] = disallowed["d"].pop("where")
            self.assertIsNone(
                runtime.readers(
                    runtime.TARGET_PATH, self.original, self.changed, disallowed
                )
            )

    def test_committed_artifact_pin_and_where_reader_set(self):
        root = Path(__file__).parent.parent
        source = Path(
            "/home/silverdisk/BuildersHackathon-overload-trace/"
            "trace-output-overload-full/sqlglot-pinned"
        )
        if not source.exists():
            self.skipTest("pinned research checkout unavailable")
        roster = json.loads((root / "sample/tests.json").read_text())["tests"]
        model = runtime.load_model(
            root / "query_modifier_model.json.gz",
            runtime.MODEL_GZIP_SHA256,
            "eb11aec4be8cb2122afe713a4816662c3f0fb2fa",
            [test["id"] for test in roster],
        )
        self.assertIsNotNone(model)
        self.assertEqual(runtime.ALLOWED_KEYS, {"where"})
        original = (source / runtime.TARGET_PATH).read_text()
        changed = original.replace('    "where": False,\n', "")
        self.assertEqual(
            runtime.readers(runtime.TARGET_PATH, original, changed, model),
            {1133, 1136, 1332, 1355, 1361, 1369, 1371, 1434, 1440, 1441},
        )

    def test_collector_requires_every_sensitive_consumer_shape(self):
        sqlglot = self.root / "sqlglot"
        (sqlglot / "optimizer").mkdir(parents=True)
        (sqlglot / "expressions").mkdir(parents=True)
        (sqlglot / "expressions/core.py").write_text(
            "cls.required_args = {k for k, v in cls.arg_types.items() if v}\n"
        )
        (sqlglot / "expressions/query.py").write_text(
            "a = {**QUERY_MODIFIERS}\n"
            "b = {**QUERY_MODIFIERS}\n"
            "c = {**QUERY_MODIFIERS}\n"
        )
        (sqlglot / "parser.py").write_text(
            "        for key in exp.QUERY_MODIFIERS:\n"
            "            if modifier := values.args.get(key):\n"
            "                pass\n"
        )
        (sqlglot / "generator.py").write_text(
            "x = any(inner.args.get(key) for key in exp.QUERY_MODIFIERS)\n"
            "y = any(left.this.args.get(key) for key in exp.QUERY_MODIFIERS)\n"
        )
        (sqlglot / "optimizer/merge_subqueries.py").write_text(
            "UNMERGABLE_ARGS = set(exp.Select.arg_types) - {\"x\"}\n"
            "x = any(v for k, v in inner_select.args.items() if k in UNMERGABLE_ARGS)\n"
        )
        with patch.object(collector, "BASE_INSTRUMENT_SOURCE", return_value=0):
            self.assertEqual(collector.instrument_source(self.root), 0)
        self.assertIn("_br_sensitive_pair_get", (sqlglot / "parser.py").read_text())
        self.assertEqual(
            (sqlglot / "generator.py").read_text().count("_br_sensitive_bool_get"), 2
        )
        self.assertEqual(
            (sqlglot / "parser.py").read_text().count("_br_sensitive_keys"), 1
        )
        self.assertEqual(
            (sqlglot / "generator.py").read_text().count("_br_sensitive_keys"), 2
        )
        self.assertNotIn(
            "for key in exp.QUERY_MODIFIERS",
            (sqlglot / "parser.py").read_text() + (sqlglot / "generator.py").read_text(),
        )
        self.assertIn(
            "_br_sensitive_unmerge",
            (sqlglot / "optimizer/merge_subqueries.py").read_text(),
        )
        self.assertEqual(
            (sqlglot / "expressions/query.py").read_text().count(
                "_br_sensitive_unpack"
            ),
            3,
        )
        self.assertIn(
            "_br_sensitive_required_items",
            (sqlglot / "expressions/core.py").read_text(),
        )
        self.assertIn(
            "_br_sensitive_keys",
            (sqlglot / "optimizer/merge_subqueries.py").read_text(),
        )

        (sqlglot / "generator.py").write_text("x = False\n")
        with patch.object(collector, "BASE_INSTRUMENT_SOURCE", return_value=0):
            with self.assertRaises(SystemExit):
                collector.instrument_source(self.root)

    def test_pinned_source_theorem_closes_keys_unpacks_and_consumers(self):
        source = Path(
            "/home/silverdisk/BuildersHackathon-overload-trace/"
            "trace-output-overload-full/sqlglot-pinned"
        )
        if not source.exists():
            self.skipTest("pinned research checkout unavailable")
        source_label, arg_labels, deletions, core_digest = source_theorem(source)
        self.assertTrue(source_label.endswith(":QUERY_MODIFIERS"))
        self.assertEqual(len(arg_labels), 3)
        self.assertEqual(len(deletions), 23)
        self.assertEqual(len(set(deletions.values())), 23)
        self.assertEqual(len(core_digest), 64)
        roster = json.loads(
            (Path(__file__).parent.parent / "sample/tests.json").read_text()
        )["tests"]
        self.assertEqual(packed_cost(roster), 36.817)


if __name__ == "__main__":
    unittest.main()
