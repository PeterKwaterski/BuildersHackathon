#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from collect_function_default_imports import module_names, tasks
from build_function_default_model import (
    SUITE_MANIFEST_KEYS,
    SYNC_INSTRUMENTATION_DELTA,
    consumed_labels,
    reader_owners,
    valid_instrumentation_counts,
    valid_import_provenance,
    valid_suite_provenance,
    write_model,
)


class ImportTracePlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.source = Path(self.temporary.name)
        (self.source / "sqlglot/dialects").mkdir(parents=True)
        (self.source / "sqlglot/__init__.py").write_text("")
        (self.source / "sqlglot/example.py").write_text("")
        (self.source / "sqlglot/__main__.py").write_text("")
        (self.source / "sqlglot/dialects/__init__.py").write_text(
            'DIALECTS = ["Alpha", "Spark2"]\n'
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_plan_covers_each_module_and_both_dialect_orders(self):
        modules = module_names(self.source)
        plan = tasks(self.source)
        self.assertEqual(len(modules), len(set(modules)))
        self.assertEqual(
            plan[:-2], [{"kind": "module", "name": module} for module in modules]
        )
        forward, reverse = plan[-2:]
        self.assertEqual(forward["kind"], "dialects")
        self.assertEqual(reverse["kind"], "dialects")
        self.assertEqual(forward["dialects"], list(reversed(reverse["dialects"])))
        self.assertIn("spark2", forward["dialects"])

    def test_task_tokens_are_unique_and_tamper_sensitive(self):
        plan = tasks(self.source)

        def token(task):
            return hashlib.sha256(
                json.dumps(task, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        tokens = [token(task) for task in plan]
        self.assertEqual(len(tokens), len(set(tokens)))
        changed = dict(plan[0], name=plan[0]["name"] + ".tampered")
        self.assertNotEqual(token(plan[0]), token(changed))

    def test_only_consumption_events_poison_import_global_defaults(self):
        events = {
            "explicit": {"call": ["__IMPORT__"], "entered": ["__IMPORT__"]},
            "omitted": {
                "call": ["__IMPORT__"],
                "entered": ["__IMPORT__"],
                "reader": ["__IMPORT__"],
            },
            "native": {"opaque": ["__IMPORT__"], "reader": ["__IMPORT__"]},
            "reflected": {"reflect": ["__IMPORT__"], "reader": ["__IMPORT__"]},
            "test-only": {"reader": ["a-test"]},
            "suite-explicit": {
                "call": ["__NO_TEST__"],
                "entered": ["__NO_TEST__"],
            },
            "suite-omitted": {"reader": ["__NO_TEST__"]},
        }
        self.assertEqual(
            consumed_labels(events, "__IMPORT__"),
            {"omitted", "native", "reflected"},
        )
        self.assertEqual(reader_owners(events["explicit"]), set())
        self.assertEqual(reader_owners(events["omitted"]), {"__IMPORT__"})
        self.assertEqual(
            consumed_labels(events, "__NO_TEST__"), {"suite-omitted"}
        )


class ArtifactEncodingTests(unittest.TestCase):
    def test_gzip_is_path_independent_without_name_or_time(self):
        payload = {"d": {"sqlglot/example.py": [[1, "safe"]]}, "v": 1}
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first-name.json.gz"
            second = Path(directory) / "different-name.json.gz"
            write_model(first, payload)
            write_model(second, payload)
            first_bytes = first.read_bytes()
            self.assertEqual(first_bytes, second.read_bytes())
            self.assertEqual(first_bytes[:2], b"\x1f\x8b")
            self.assertEqual(first_bytes[3] & 0x08, 0)
            self.assertEqual(first_bytes[4:8], b"\0\0\0\0")
            self.assertEqual(json.loads(gzip.decompress(first_bytes)), payload)


class SuiteProvenanceTests(unittest.TestCase):
    def test_instrumentation_counts_match_static_census_and_sync_delta(self):
        normal = {"instrumented": 100}
        synchronous = {"instrumented": 100 + SYNC_INSTRUMENTATION_DELTA}
        self.assertTrue(valid_instrumentation_counts(normal, synchronous, 100))
        self.assertFalse(valid_instrumentation_counts(normal, synchronous, 99))
        synchronous["instrumented"] += 1
        self.assertFalse(valid_instrumentation_counts(normal, synchronous, 100))
        self.assertFalse(valid_instrumentation_counts({}, synchronous, 100))

    def test_implementation_and_execution_fields_are_tamper_bound(self):
        collector = "a" * 64
        dependency = "b" * 64
        pytest_args = hashlib.sha256(b"[]").hexdigest()
        manifest = {key: None for key in SUITE_MANIFEST_KEYS}
        manifest.update({
            "collector_sha256": collector,
            "dependency_sha256": dependency,
            "instrumented": 123,
            "instrumented_tree_sha256": "c" * 64,
            "pytest_args_sha256": pytest_args,
            "support_sha256": "d" * 64,
        })
        self.assertTrue(
            valid_suite_provenance(manifest, collector, dependency, pytest_args)
        )
        for field, replacement in (
            ("collector_sha256", "0" * 64),
            ("dependency_sha256", "0" * 64),
            ("instrumented", 0),
            ("instrumented_tree_sha256", "short"),
            ("pytest_args_sha256", "0" * 64),
            ("support_sha256", "short"),
        ):
            tampered = dict(manifest)
            tampered[field] = replacement
            self.assertFalse(
                valid_suite_provenance(tampered, collector, dependency, pytest_args),
                field,
            )
        extra = dict(manifest, injected=True)
        self.assertFalse(valid_suite_provenance(extra, collector, dependency, pytest_args))

    def test_import_implementation_and_tree_fields_are_tamper_bound(self):
        collector = "a" * 64
        dependency = "b" * 64
        instrumenter = "c" * 64
        record = {
            "collector_sha256": collector,
            "dependency_sha256": dependency,
            "instrumented": 123,
            "instrumenter_sha256": instrumenter,
            "instrumented_tree_sha256": "d" * 64,
            "support_sha256": "e" * 64,
        }
        self.assertTrue(
            valid_import_provenance(
                record, collector, dependency, instrumenter, 123
            )
        )
        for field, replacement in (
            ("collector_sha256", "0" * 64),
            ("dependency_sha256", "0" * 64),
            ("instrumented", 0),
            ("instrumenter_sha256", "0" * 64),
            ("instrumented_tree_sha256", "short"),
            ("support_sha256", "short"),
        ):
            tampered = dict(record)
            tampered[field] = replacement
            self.assertFalse(
                valid_import_provenance(
                    tampered, collector, dependency, instrumenter, 123
                ),
                field,
            )


if __name__ == "__main__":
    unittest.main()
