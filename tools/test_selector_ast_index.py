#!/usr/bin/env python3
"""Regression checks for the cached one-pass selector AST index."""

from __future__ import annotations

import ast
import difflib
import gc
import tempfile
import unittest
import weakref
from pathlib import Path

import selector


PATH = "sqlglot/fake_index.py"


def parsed_change(original: str, changed: str) -> dict:
    selector._PINNED_SOURCES = {PATH: original}
    selector._SOURCE_TREES.clear()
    selector._SOURCE_INDEXES.clear()
    selector._SOURCE_CODE.clear()
    selector._IMPORT_DEFINITION_RANGES.clear()
    patch = "diff --git a/sqlglot/fake_index.py b/sqlglot/fake_index.py\n" + "".join(
        difflib.unified_diff(
            original.splitlines(True),
            changed.splitlines(True),
            fromfile="a/sqlglot/fake_index.py",
            tofile="b/sqlglot/fake_index.py",
        )
    )
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary, "change.patch")
        path.write_text(patch)
        changes = selector.patch_changes(path)
    assert len(changes) == 1
    return changes[0]


def follow(root: ast.AST, path: tuple[tuple[str, int | None], ...]) -> ast.AST | None:
    node = root
    for field, index in path:
        value = getattr(node, field, None)
        if index is None:
            node = value
        elif isinstance(value, list) and index < len(value):
            node = value[index]
        else:
            return None
        if not isinstance(node, ast.AST):
            return None
    return node


class AstIndexTest(unittest.TestCase):
    def tearDown(self) -> None:
        selector._PINNED_SOURCES = None
        selector._SOURCE_TREES.clear()
        selector._SOURCE_INDEXES.clear()
        selector._SOURCE_CODE.clear()
        selector._IMPORT_DEFINITION_RANGES.clear()

    def test_order_parents_and_paths_match_ast(self) -> None:
        tree = ast.parse(
            "@decorate(x=1)\nclass C(Base):\n"
            "    def f(self, values):\n"
            "        return [item + 1 for item in values if item]\n"
        )
        index = selector._AstIndex(tree)
        self.assertEqual(index.nodes, tuple(ast.walk(tree)))
        expected_parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        self.assertEqual(index.parents, expected_parents)
        occurrences = {}
        for parent in index.nodes:
            for child in ast.iter_child_nodes(parent):
                occurrences[child] = occurrences.get(child, 0) + 1
        for child, count in occurrences.items():
            if count == 1:
                self.assertIs(follow(tree, index.path(child)), child)

    def test_source_index_rebuilds_after_tree_cache_reset(self) -> None:
        selector._PINNED_SOURCES = {PATH: "def first():\n    return 1\n"}
        first_tree = selector.source_tree(PATH)
        first_tree_ref = weakref.ref(first_tree)
        first = selector._source_index(PATH)
        self.assertIsNotNone(first)
        selector._PINNED_SOURCES = {PATH: "def second():\n    return 2\n"}
        selector._SOURCE_TREES.clear()
        second = selector._source_index(PATH)
        self.assertIsNot(first, second)
        self.assertEqual([node.name for node in second.functions], ["second"])
        self.assertEqual(len(selector._SOURCE_INDEXES), 1)
        del first, first_tree
        gc.collect()
        self.assertIsNone(first_tree_ref())

    def test_runtime_gate_restores_cached_function_body(self) -> None:
        original = "def f(value):\n    return value + 1\n"
        changed = "def f(value):\n    return value + 2\n"
        change = parsed_change(original, changed)
        tree = selector.source_tree(PATH)
        before = ast.dump(tree, include_attributes=True)
        self.assertEqual(selector.runtime_body_patch_source(change, PATH), changed)
        self.assertEqual(ast.dump(tree, include_attributes=True), before)
        self.assertEqual(selector.runtime_body_patch_source(change, PATH), changed)
        self.assertEqual(ast.dump(tree, include_attributes=True), before)

    def test_runtime_gate_restores_after_dump_failure(self) -> None:
        original = "def f(value):\n    return value + 1\n"
        changed = "def f(value):\n    return value + 2\n"
        change = parsed_change(original, changed)
        tree = selector.source_tree(PATH)
        before = ast.dump(tree, include_attributes=True)
        original_dump = selector.ast.dump

        def fail(*_args, **_kwargs):
            raise RecursionError

        selector.ast.dump = fail
        try:
            self.assertIsNone(selector.runtime_body_patch_source(change, PATH))
        finally:
            selector.ast.dump = original_dump
        self.assertEqual(ast.dump(tree, include_attributes=True), before)

    def test_annotation_gate_restores_after_dump_failure(self) -> None:
        original = "def f():\n    value: int = 1\n"
        changed = "def f():\n    value: str = 1\n"
        change = parsed_change(original, changed)
        tree = selector.source_tree(PATH)
        before = ast.dump(tree, include_attributes=True)
        original_dump = selector.ast.dump

        def fail(*_args, **_kwargs):
            raise MemoryError

        selector.ast.dump = fail
        try:
            self.assertFalse(selector.local_annotation_only_edit(change, PATH))
        finally:
            selector.ast.dump = original_dump
        self.assertEqual(ast.dump(tree, include_attributes=True), before)

    def test_annotation_gate_restores_after_success(self) -> None:
        original = "def f():\n    value: int = 1\n"
        changed = "def f():\n    value: str = 1\n"
        change = parsed_change(original, changed)
        tree = selector.source_tree(PATH)
        before = ast.dump(tree, include_attributes=True)
        self.assertTrue(selector.local_annotation_only_edit(change, PATH))
        self.assertEqual(ast.dump(tree, include_attributes=True), before)
        self.assertTrue(selector.local_annotation_only_edit(change, PATH))
        self.assertEqual(ast.dump(tree, include_attributes=True), before)

    def test_malformed_source_caches_fail_closed(self) -> None:
        selector._PINNED_SOURCES = {PATH: "def broken("}
        self.assertIsNone(selector.source_tree(PATH))
        self.assertIsNone(selector._source_index(PATH))
        self.assertIsNone(selector._source_index(PATH))


if __name__ == "__main__":
    unittest.main()
