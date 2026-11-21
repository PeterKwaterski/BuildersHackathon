#!/usr/bin/env python3
from __future__ import annotations

import gzip
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import max_nodes_exact as exact
import selector


TREE = Path(
    os.environ.get(
        "MAX_NODES_PINNED_TREE",
        "/home/silverdisk/BuildersHackathon-branch/sqlglot",
    )
)
SOURCE = (TREE / exact.PARSER_PATH).read_text()
TESTS = json.loads((ROOT / "sample/tests.json").read_text())["tests"]
ORIGINAL = """        if self.max_nodes > -1:
            self._node_count += 1
            if self._node_count > self.max_nodes:
                self.raise_error(f\"Maximum number of AST nodes ({self.max_nodes}) exceeded\")"""


def changed(block: str, outside: tuple[str, str] | None = None) -> str:
    result = SOURCE.replace(ORIGINAL, block)
    if result == SOURCE and block != ORIGINAL:
        raise AssertionError("mutation did not apply")
    if outside:
        result = result.replace(*outside)
    return result


def accepted(source: str, *, profile=exact.PROFILE_PATH, tree=TREE) -> bool:
    return exact.can_skip(SOURCE, source, TESTS, tree=tree, profile_path=profile)


class ExactMaxNodesTests(unittest.TestCase):
    def test_selector_requires_one_exact_parser_file(self):
        patch_text = """diff --git a/sqlglot/parser.py b/sqlglot/parser.py
--- a/sqlglot/parser.py
+++ b/sqlglot/parser.py
@@ -2200,3 +2200,3 @@
         if self.max_nodes > -1:
-            self._node_count += 1
+            self._node_count += 2
             if self._node_count > self.max_nodes:
"""
        with tempfile.TemporaryDirectory() as temporary:
            patch = Path(temporary) / "accepted.patch"
            patch.write_text(patch_text)
            changes = selector.patch_changes(patch)
            previous_tree = exact.PINNED_TREE
            exact.PINNED_TREE = TREE
            try:
                self.assertTrue(selector.exact_max_nodes_passes(changes, TESTS))
            finally:
                exact.PINNED_TREE = previous_tree

            second = Path(temporary) / "second.patch"
            second.write_text(
                patch_text
                + """diff --git a/sqlglot/helper.py b/sqlglot/helper.py
--- a/sqlglot/helper.py
+++ b/sqlglot/helper.py
@@ -1,1 +1,1 @@
-from __future__ import annotations
+from __future__ import annotations  # changed
"""
            )
            exact.PINNED_TREE = TREE
            try:
                self.assertFalse(
                    selector.exact_max_nodes_passes(selector.patch_changes(second), TESTS)
                )
            finally:
                exact.PINNED_TREE = previous_tree

    def test_exact_passing_envelope(self):
        cases = (
            ORIGINAL.replace(
                "if self._node_count > self.max_nodes:",
                "if self._node_count >= self.max_nodes:",
            ),
            ORIGINAL.replace("self._node_count += 1", "self._node_count += 2"),
            ORIGINAL.replace("self._node_count += 1", "self._node_count += 10"),
            ORIGINAL.replace("if self.max_nodes > -1:", "if self.max_nodes >= 0:"),
            ORIGINAL.replace("self.max_nodes:", "self.max_nodes - 1:"),
            ORIGINAL.replace(
                " exceeded\")",
                " exceeded; Maximum number of AST nodes ({self.max_nodes})\")",
            ),
        )
        for block in cases:
            with self.subTest(block=block):
                self.assertTrue(accepted(changed(block)))

    def test_exact_assertion_failures_remain_selected(self):
        cases = (
            ORIGINAL.replace("self.max_nodes:", "self.max_nodes + 100:"),
            ORIGINAL.replace("if self.max_nodes > -1:", "if self.max_nodes >= -1:"),
            ORIGINAL.replace("Maximum number of AST nodes", "Node budget"),
            ORIGINAL.replace("({self.max_nodes})", "nodes={self.max_nodes}"),
            ORIGINAL.replace("self._node_count += 1", "self._node_count += 1000000"),
        )
        for block in cases:
            with self.subTest(block=block):
                self.assertFalse(accepted(changed(block)))

    def test_size_index_global_late_iteration_and_effects_rejected(self):
        cases = (
            ORIGINAL.replace("self._node_count += 1", "self._node_count += 0"),
            ORIGINAL.replace("self._node_count += 1", "self._node_count -= 1"),
            ORIGINAL.replace(
                "if self._node_count > self.max_nodes:",
                "if len(self.sql) > 100 and self._node_count > self.max_nodes:",
            ),
            ORIGINAL.replace(
                "if self._node_count > self.max_nodes:",
                "if self._index > 200 and self._node_count > self.max_nodes:",
            ),
            ORIGINAL.replace(
                "self._node_count += 1", "global COUNTER\n            COUNTER += 1"
            ),
            ORIGINAL.replace(
                "if self._node_count > self.max_nodes:",
                "if self._node_count > 500000 and self._node_count > self.max_nodes:",
            ),
            ORIGINAL.replace(
                'self.raise_error(f"Maximum number of AST nodes ({self.max_nodes}) exceeded")',
                "self.errors.append(self._node_count)",
            ),
            ORIGINAL.replace("({self.max_nodes})", "at {self._index} ({self.max_nodes})"),
        )
        for block in cases:
            with self.subTest(block=block):
                self.assertFalse(accepted(changed(block)))

    def test_every_byte_outside_prefix_is_pinned(self):
        self.assertFalse(accepted(SOURCE))
        valid_block = ORIGINAL.replace("self._node_count += 1", "self._node_count += 2")
        self.assertFalse(
            accepted(
                changed(
                    valid_block,
                    ("    def _try_parse(", "    # changed source\n    def _try_parse("),
                )
            )
        )
        self.assertFalse(accepted(changed(valid_block.replace(" += 2", " += 2  # pragma: no cover"))))
        self.assertFalse(accepted(changed(valid_block.replace(" += 2", " += 2  # type: ignore"))))
        self.assertFalse(
            accepted(
                changed(
                    valid_block,
                    ("self._node_count: int = 0", "self._node_count: int = 1"),
                )
            )
        )
        self.assertFalse(
            accepted(
                changed(
                    valid_block,
                    (
                        "if self.error_level != ErrorLevel.IGNORE:",
                        "if self.error_level == ErrorLevel.IMMEDIATE:",
                    ),
                )
            )
        )

    def test_artifact_and_manifest_tamper_fail_closed(self):
        self.assertFalse(exact.can_skip(SOURCE, changed(ORIGINAL), TESTS, tree=TREE))
        altered = [dict(test) for test in TESTS]
        altered[1490]["seconds"] += 0.001
        valid_change = changed(ORIGINAL.replace("self._node_count += 1", "self._node_count += 2"))
        self.assertFalse(exact.can_skip(SOURCE, valid_change, altered, tree=TREE))
        with tempfile.TemporaryDirectory() as temporary:
            corrupt = Path(temporary) / "profile.json.gz"
            corrupt.write_bytes(b"not gzip")
            self.assertFalse(accepted(valid_change, profile=corrupt))
            duplicate = Path(temporary) / "duplicate.json.gz"
            with duplicate.open("wb") as raw:
                with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as stream:
                    stream.write(b'{"format":1,"format":1}')
            self.assertFalse(accepted(valid_change, profile=duplicate))

    def test_test_source_and_compile_are_bound(self):
        valid_change = changed(ORIGINAL.replace("self._node_count += 1", "self._node_count += 2"))
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            target = tree / exact.TEST_PATH
            target.parent.mkdir(parents=True)
            target.write_text((TREE / exact.TEST_PATH).read_text() + "\n# tampered\n")
            self.assertFalse(accepted(valid_change, tree=tree))
        self.assertFalse(accepted(valid_change.replace("return expression", "return (")))


if __name__ == "__main__":
    unittest.main()
