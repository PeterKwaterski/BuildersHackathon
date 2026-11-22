from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import registry_key_research
import selector
from tools import build_registry_key_research as builder
from tools import collect_dict_access as collector


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = Path("/home/silverdisk/public-matchaluvrs-readonly/validation/val10/commits")


class RegistryKeyResearchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = selector.pinned_sources()["sqlglot/parser.py"]
        cls.tree = ast.parse(cls.original, type_comments=True)
        cls.statement = registry_key_research._class_assignment(
            cls.tree, "Parser", "FUNCTION_PARSERS"
        )
        assert cls.statement is not None

    def patch(self, name: str):
        change = selector.patch_changes(PUBLIC / f"{name}.patch")[0]
        changed = selector.patched_source(change, change["old"])
        self.assertIsNotNone(changed)
        return change, changed

    def model(self, *, safe_keys=None):
        return {
            "d": {"sqlglot/parser.py": [[
                self.statement.lineno,
                self.statement.end_lineno,
                "Parser",
                "FUNCTION_PARSERS",
                ast.dump(self.statement.value, include_attributes=False),
                hashlib.sha256(self.original.encode()).hexdigest(),
                hashlib.sha256(
                    ast.dump(self.tree, include_attributes=False).encode()
                ).hexdigest(),
                {"EXTRACT": [1], "EXTRACTX": [3], "CAST": [4], "CASTX": [5]},
                [2],
                sorted(safe_keys or {"CAST", "EXTRACT"}),
                sorted({"CAST", "EXTRACT", "TRY_CAST"}),
            ]]},
            "n": 10,
        }

    def readers(self, name: str, model=None):
        change, changed = self.patch(name)
        with mock.patch.object(registry_key_research, "FEATURE_ENABLED", True):
            return registry_key_research.readers(
                change["old"], self.original, changed, change, model or self.model()
            )

    def test_exact_key_and_wildcard_readers(self):
        self.assertEqual(self.readers("k65d"), {1, 2, 3})
        self.assertEqual(self.readers("k8ea"), {2, 4, 5})

    def test_selector_integration_uses_only_authenticated_single_change_model(self):
        change, _ = self.patch("k65d")
        with gzip.open(ROOT / "selector_model.json.gz", "rt") as stream:
            selector_model = json.load(stream)
        selector_model["h"] = set(selector_model.get("h", ()))
        with mock.patch.object(registry_key_research, "FEATURE_ENABLED", True):
            selected = selector.selected_indices(
                PUBLIC / "k65d.patch",
                selector_model,
                set(range(10)),
                registry_key_model=self.model(),
                parsed_changes=[change],
            )
        self.assertEqual(selected, {1, 2, 3})

    def test_import_dependency_key_falls_back(self):
        self.assertIsNone(self.readers("kef8"))

    def test_certified_artifact_rejects_cold_collection_key(self):
        tests = json.loads((ROOT / "sample/tests.json").read_text())["tests"]
        model = registry_key_research.load_model(
            ROOT / "registry_key_research_model.json.gz",
            "eb11aec4be8cb2122afe713a4816662c3f0fb2fa",
            [test["id"] for test in tests],
        )
        self.assertIsNotNone(model)
        self.assertIsNotNone(self.readers("k65d", model))
        self.assertIsNone(self.readers("k8ea", model))

    def test_explicit_disable_falls_back(self):
        change, changed = self.patch("k65d")
        with mock.patch.object(registry_key_research, "FEATURE_ENABLED", False):
            self.assertIsNone(registry_key_research.readers(
                change["old"], self.original, changed, change, self.model()
            ))

    def test_irrelevant_path_returns_before_ast_parsing(self):
        with (
            mock.patch.object(registry_key_research, "FEATURE_ENABLED", True),
            mock.patch.object(registry_key_research.ast, "parse", side_effect=AssertionError),
        ):
            self.assertIsNone(registry_key_research.readers(
                "sqlglot/expressions.py",
                "x = 1\n",
                "x = 2\n",
                {"added": ["+x = 2"], "lines": {1}},
                self.model(),
            ))

    def test_source_digest_and_extra_byte_gate(self):
        change, changed = self.patch("k65d")
        wrong = self.model()
        wrong["d"]["sqlglot/parser.py"][0][5] = "0" * 64
        with mock.patch.object(registry_key_research, "FEATURE_ENABLED", True):
            self.assertIsNone(registry_key_research.readers(
                change["old"], self.original, changed, change, wrong
            ))
            self.assertIsNone(registry_key_research.readers(
                change["old"], self.original, changed + "\n", change, self.model()
            ))

    def test_duplicate_key_and_value_change_fall_back(self):
        change, changed = self.patch("k65d")
        duplicate = changed.replace('"EXTRACTX"', '"CAST"', 1)
        value_change = changed.replace("self._parse_extract()", "self._parse_trim()", 1)
        with mock.patch.object(registry_key_research, "FEATURE_ENABLED", True):
            self.assertIsNone(registry_key_research.readers(
                change["old"], self.original, duplicate, change, self.model()
            ))
            self.assertIsNone(registry_key_research.readers(
                change["old"], self.original, value_change, change, self.model()
            ))

    def test_directives_structural_invalid_and_ambiguous_owner_fall_back(self):
        change, changed = self.patch("k65d")
        directive = copy.deepcopy(change)
        directive["added"] = ["+# noqa"]
        structural = copy.deepcopy(change)
        structural["structural_invalid"] = True
        ambiguous = self.model()
        ambiguous["d"]["sqlglot/parser.py"].append(
            copy.deepcopy(ambiguous["d"]["sqlglot/parser.py"][0])
        )
        with mock.patch.object(registry_key_research, "FEATURE_ENABLED", True):
            for candidate_change, model in (
                (directive, self.model()),
                (structural, self.model()),
                (change, ambiguous),
            ):
                with self.subTest(entries=len(model["d"]["sqlglot/parser.py"])):
                    self.assertIsNone(registry_key_research.readers(
                        change["old"], self.original, changed, candidate_change, model
                    ))

    def test_malformed_model_fields_fail_closed_without_exception(self):
        mutations = []
        for index, value in (
            (0, "line"),
            (5, None),
            (6, None),
            (7, {"EXTRACT": [True]}),
            (8, [99]),
            (9, ["EXTRACT", "EXTRACT"]),
            (10, [1]),
        ):
            model = self.model()
            model["d"]["sqlglot/parser.py"][0][index] = value
            mutations.append(model)
        model = self.model()
        model["n"] = True
        mutations.append(model)
        for model in mutations:
            self.assertIsNone(self.readers("k65d", model))

    def test_authenticated_model_loader(self):
        ids = ["a", "b"]
        payload = {
            "d": {},
            "n": 2,
            "sha": "pinned",
            "state": "certified",
            "t": hashlib.sha256("a\0b".encode()).hexdigest(),
            "v": 4,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "model.json.gz"
            with gzip.open(path, "wt") as stream:
                json.dump(payload, stream)
            artifact_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with mock.patch.object(
                registry_key_research, "MODEL_GZIP_SHA256", artifact_digest
            ):
                self.assertEqual(
                    registry_key_research.load_model(path, "pinned", ids), payload
                )
                self.assertIsNone(registry_key_research.load_model(path, "wrong", ids))
            self.assertIsNone(registry_key_research.load_model(path, "pinned", ids))

    def test_static_key_domain_excludes_filters_and_direct_dependencies(self):
        with gzip.open(ROOT / "semantic_sources.json.gz", "rt") as stream:
            sources = json.load(stream)
        trees = {
            path: ast.parse(source, filename=path, type_comments=True)
            for path, source in sources.items()
        }
        parents = {path: builder.parent_map(tree) for path, tree in trees.items()}
        assignments, _ = builder.registry_assignments(trees, parents)
        safe, forbidden = builder.registry_key_domain(
            trees, assignments, "FUNCTION_PARSERS"
        )
        self.assertIn("CAST", safe)
        self.assertIn("EXTRACT", safe)
        self.assertNotIn("TRY_CAST", safe)
        self.assertNotIn("TRIM", safe)
        self.assertIn("CAST", forbidden)

    def test_incomplete_task_trace_is_rejected(self):
        document = {
            "creations": {},
            "events": {},
            "imports": [],
            "tasks": {
                "completed": [],
                "submitted": ["test#0"],
                "workers": {},
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "trace.json"
            path.write_text(json.dumps(document))
            with self.assertRaises(SystemExit):
                builder.trace_document(path)

    def test_collection_path_normalization_chooses_deepest_source_root(self):
        tree = ast.parse(collector.TRACKER)
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "normalized_filename"
        )
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "tracker", "exec"), namespace)
        normalize = namespace["normalized_filename"]
        self.assertEqual(
            normalize("/tmp/copy/sqlglot/tests/test_parser.py"),
            "tests/test_parser.py",
        )
        self.assertEqual(
            normalize("/tmp/copy/sqlglot/sqlglot/parser.py"),
            "sqlglot/parser.py",
        )


if __name__ == "__main__":
    unittest.main()
