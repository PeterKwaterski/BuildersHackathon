from __future__ import annotations

import difflib
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import selector


class FormattingEquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.saved_sources = selector._PINNED_SOURCES
        self.saved_trees = selector._SOURCE_TREES.copy()
        self.saved_indexes = selector._SOURCE_INDEXES.copy()
        self.saved_code = selector._SOURCE_CODE.copy()

    def tearDown(self):
        selector._PINNED_SOURCES = self.saved_sources
        selector._SOURCE_TREES.clear()
        selector._SOURCE_TREES.update(self.saved_trees)
        selector._SOURCE_INDEXES.clear()
        selector._SOURCE_INDEXES.update(self.saved_indexes)
        selector._SOURCE_CODE.clear()
        selector._SOURCE_CODE.update(self.saved_code)

    def change(self, before: str, after: str, path: str = "sqlglot/example.py"):
        patch = "diff --git a/{0} b/{0}\n".format(path)
        patch += "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile="a/" + path,
                tofile="b/" + path,
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            patch_path = Path(temporary) / "candidate.patch"
            patch_path.write_text(patch)
            changes = selector.patch_changes(patch_path)
        self.assertEqual(len(changes), 1)
        selector._PINNED_SOURCES = {path: before}
        selector._SOURCE_TREES.clear()
        selector._SOURCE_INDEXES.clear()
        selector._SOURCE_CODE.clear()
        return changes[0], path

    def proved(self, before: str, after: str, path: str = "sqlglot/example.py") -> bool:
        change, path = self.change(before, after, path)
        return selector.position_preserving_formatting_edit(change, path)

    def test_trailing_whitespace_is_accepted(self):
        self.assertTrue(self.proved("def f():\n    return 1\n", "def f():\n    return 1  \n"))

    def test_spacing_before_unchanged_comment_is_accepted(self):
        before = 'class C:\n    TABLE = {\n        "D": "%u",  # day\n    }\n'
        after = 'class C:\n    TABLE = {\n        "D": "%u",   # day\n    }\n'
        self.assertTrue(self.proved(before, after))

    def test_multiple_position_preserving_replacements_are_accepted(self):
        before = "def f():\n    x = 1\n    return x\n"
        after = "def f():\n    x = 1  \n    return x  \n"
        self.assertTrue(self.proved(before, after))

    def test_internal_spacing_that_moves_an_expression_is_rejected(self):
        before = "def f(g):\n    return g(1)\n"
        after = "def f(g):\n    return  g(1)\n"
        self.assertFalse(self.proved(before, after))

    def test_changed_comment_text_is_rejected(self):
        self.assertFalse(self.proved("X = 1  # old\n", "X = 1  # new\n"))

    def test_directive_is_rejected_even_when_only_spacing_moves(self):
        self.assertFalse(
            self.proved("X = value  # type: ignore\n", "X = value   # type: ignore\n")
        )

    def test_encoding_comment_is_rejected(self):
        self.assertFalse(
            self.proved("# coding: utf-8\nX = 1\n", "#  coding: utf-8\nX = 1\n")
        )

    def test_typing_source_is_rejected(self):
        self.assertFalse(
            self.proved(
                "def f():\n    return 1\n",
                "def f():\n    return 1  \n",
                "sqlglot/typing/example.py",
            )
        )

    def test_test_source_is_rejected(self):
        self.assertFalse(
            self.proved(
                "def test_x():\n    assert True\n",
                "def test_x():\n    assert True  \n",
                "tests/test_x.py",
            )
        )

    def test_process_serialization_source_is_rejected(self):
        self.assertFalse(
            self.proved(
                "def f():\n    return 1\n",
                "def f():\n    return 1  \n",
                "sqlglot/serde.py",
            )
        )

    def test_insertion_is_rejected(self):
        self.assertFalse(self.proved("X = 1\n", "X = 1\n\n"))

    def test_type_comment_change_is_rejected(self):
        self.assertFalse(self.proved("x = value  # type: A\n", "x = value  # type: B\n"))

    def test_docstring_change_is_rejected(self):
        self.assertFalse(self.proved('def f():\n    "a"\n', 'def f():\n    "b"\n'))

    def test_executable_change_is_rejected(self):
        self.assertFalse(self.proved("def f():\n    return 1\n", "def f():\n    return 2\n"))

    def test_resource_failure_fails_closed(self):
        change, path = self.change("X = 1\n", "X = 1  \n")
        with mock.patch.object(selector, "semantic_code_fingerprint", side_effect=MemoryError):
            self.assertFalse(selector.position_preserving_formatting_edit(change, path))

    def test_non_python_directive_comments_use_fixture_readers(self):
        path = "tests/fixtures/optimizer/pushdown_predicates.sql"
        with gzip.open(selector.MODEL, "rt", encoding="utf-8") as model_file:
            model = json.load(model_file)
        model["h"] = set(model.get("h", ()))
        all_indices = set(range(len(model["t"])))

        for directive in ("# type: ignore", "# noqa"):
            with self.subTest(directive=directive), tempfile.TemporaryDirectory() as temporary:
                patch = Path(temporary) / "fixture.patch"
                patch.write_text(
                    "diff --git a/{0} b/{0}\n--- a/{0}\n+++ b/{0}\n"
                    "@@ -1 +1,2 @@\n SELECT 1;\n+{1}\n".format(path, directive)
                )
                selected = selector.selected_indices(patch, model, all_indices)
            expected = selector.mapped_set(model, model["x"][path])
            self.assertEqual(selected, expected)
            self.assertNotEqual(selected, all_indices)

    def test_python_type_ignore_still_fails_closed_without_reflection(self):
        change, path = self.change(
            "def f():\n    return 1\n",
            "def f():\n    # type: ignore\n    return 1\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            patch = Path(temporary) / "python.patch"
            patch.write_text(
                "diff --git a/{0} b/{0}\n--- a/{0}\n+++ b/{0}\n"
                "@@ -1,2 +1,3 @@\n def f():\n+    # type: ignore\n"
                "     return 1\n".format(path)
            )
            with gzip.open(selector.MODEL, "rt", encoding="utf-8") as model_file:
                model = json.load(model_file)
            model["h"] = set(model.get("h", ()))
            all_indices = set(range(len(model["t"])))
            self.assertEqual(selector.selected_indices(patch, model, all_indices), all_indices)


if __name__ == "__main__":
    unittest.main()
