#!/usr/bin/env python3
from __future__ import annotations

import gzip
import hashlib
import json
import ast
import shutil
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).parents[1]))

import none_static_runtime
from none_comparison_envelopes import (
    _closed_tree_rows,
    domain,
    validate,
    verify_pushdown_entry_closure,
    verify_rowreader_dynamic_closure,
)
from selector import patch_changes, patched_source, selected_indices


ROOT = Path(__file__).parents[1]
PINNED = Path("/home/silverdisk/BlastRadiusTPCReplayE2/sqlglot")
TESTS = ROOT / "sample/tests.json"


def test_identity() -> tuple[str, int]:
    document = json.loads(TESTS.read_text())
    tests = [row["id"] for row in document["tests"]]
    return hashlib.sha256("\0".join(tests).encode()).hexdigest(), len(tests)


def diff(path: str, line: int, removed: str, added: str, extra: str = "") -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -{line},1 +{line},1 @@\n"
        f"-{removed}\n"
        f"+{added}\n"
        f"{extra}"
    )


class NoneStaticProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        digest, count = test_identity()
        cls.profile = none_static_runtime.load_profile(digest, count)
        if cls.profile is None:
            raise AssertionError("static profile failed its identity gate")

    def _changes(self, text: str) -> list[dict]:
        with tempfile.NamedTemporaryFile("w", suffix=".patch") as patch:
            patch.write(text)
            patch.flush()
            return patch_changes(Path(patch.name))

    def _match(self, text: str) -> set[int] | None:
        changes = self._changes(text)
        if len(changes) != 1:
            return none_static_runtime.match(changes, self.profile, None, None)
        path = changes[0]["old"]
        original = (PINNED / path).read_text()
        prospective = patched_source(changes[0], path)
        return none_static_runtime.match(changes, self.profile, original, prospective)

    def test_exact_two_site_patches_are_admitted_with_no_reflection_readers(self) -> None:
        for site in self.profile["sites"]:
            with self.subTest(site=site["path"]):
                text = diff(site["path"], site["line"], site["removed"], site["added"])
                self.assertEqual(self._match(text), set())

    def test_comments_formatting_and_second_edits_are_rejected(self) -> None:
        site = self.profile["sites"][0]
        cases = [
            diff(site["path"], site["line"], site["removed"], site["added"] + "  # x"),
            diff(site["path"], site["line"], site["removed"], site["added"] + " "),
            diff(
                site["path"], site["line"], site["removed"], site["added"],
                f"@@ -1,1 +1,1 @@\n-from __future__ import annotations\n+from __future__ import annotations # x\n",
            ),
            diff(site["path"], site["line"], site["removed"], site["added"])
            + "diff --git a/sqlglot/__init__.py b/sqlglot/__init__.py\n"
            + "--- a/sqlglot/__init__.py\n+++ b/sqlglot/__init__.py\n"
            + "@@ -1,1 +1,1 @@\n-from __future__ import annotations\n"
            + "+from __future__ import annotations # x\n",
        ]
        for candidate in cases:
            with self.subTest(candidate=candidate[-100:]):
                self.assertIsNone(self._match(candidate))

    def test_simplify_and_eliminate_are_not_certified(self) -> None:
        self.assertIsNone(domain("sqlglot/optimizer/simplify.py", 1743))
        self.assertIsNone(domain("sqlglot/optimizer/eliminate_joins.py", 84))

    def test_removed_broad_identity_shortcut_retains_hostile_public_sites(self) -> None:
        with gzip.open(ROOT / "selector_model.json.gz", "rt", encoding="utf-8") as handle:
            model = json.load(handle)
        model["h"] = set(model.get("h", ()))
        all_indices = set(range(len(model["t"])))
        cases = [
            ("sqlglot/optimizer/simplify.py", 1743, "                if node is not None:", "                if node != None:"),
            ("sqlglot/optimizer/eliminate_joins.py", 84, "    if on is not None:", "    if on != None:"),
        ]
        for path, line, removed, added in cases:
            changes = diff(path, line, removed, added)
            with tempfile.NamedTemporaryFile("w", suffix=".patch") as patch:
                patch.write(changes)
                patch.flush()
                selected = selected_indices(
                    Path(patch.name), model, all_indices,
                    none_static_profile=self.profile,
                )
            self.assertTrue(selected, path)

    def test_artifact_tampering_fails_closed(self) -> None:
        original_path = none_static_runtime.PROFILE_PATH
        original_digest = none_static_runtime.PROFILE_GZIP_SHA256
        with tempfile.TemporaryDirectory() as temporary:
            tampered = Path(temporary) / "profile.json.gz"
            document = json.loads(gzip.decompress(original_path.read_bytes()))
            document["sites"][0]["reflection_retain"] = [0]
            tampered.write_bytes(
                gzip.compress(
                    json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
                    mtime=0,
                )
            )
            try:
                none_static_runtime.PROFILE_PATH = tampered
                # Even changing the runtime digest cannot bypass the byte pin
                # embedded in the shipped module under normal operation.
                self.assertIsNone(none_static_runtime.load_profile(*test_identity()))
            finally:
                none_static_runtime.PROFILE_PATH = original_path
                none_static_runtime.PROFILE_GZIP_SHA256 = original_digest

    def test_synthetic_dynamic_and_hostile_paths_invalidate_whole_tree(self) -> None:
        attacks = {
            "hostile_rowreader.py": (
                "from sqlglot.executor.table import RowReader\n"
                "class Evil(tuple):\n"
                "    def __ne__(self, other): return False\n"
                "RowReader(Evil())\n"
            ),
            "setattr_columns.py": (
                "from sqlglot.executor.table import Table\n"
                "table = Table(())\n"
                "setattr(table, ''.join(['col', 'umns']), object())\n"
            ),
            "optimize_journal.py": (
                "from sqlglot.optimizer import optimize\n"
                "class Evil:\n"
                "    def __ne__(self, other): return False\n"
                "optimize('select 1', journal=Evil())\n"
            ),
            "aliased_kwargs.py": (
                "from sqlglot.optimizer.pushdown_projections import pushdown_projections as p\n"
                "kwargs = {'jour' + 'nal': object()}\n"
                "p(None, **kwargs)\n"
            ),
            "dict_columns.py": (
                "from sqlglot.executor.table import Table\n"
                "table = Table(())\n"
                "table.__dict__['columns'] = object()\n"
            ),
            "aliased_dict_columns.py": (
                "from sqlglot.executor.table import Table\n"
                "table = Table(())\n"
                "namespace = table.__dict__\n"
                "alias = namespace\n"
                "alias['columns'] = object()\n"
            ),
            "vars_columns.py": (
                "from sqlglot.executor.table import Table\n"
                "table = Table(())\n"
                "namespace = vars(table)\n"
                "namespace['col' + 'umns'] = object()\n"
            ),
            "update_columns.py": (
                "from sqlglot.executor.table import Table\n"
                "table = Table(())\n"
                "namespace = table.__dict__\n"
                "namespace.update({'columns': object()})\n"
            ),
            "operator_setitem_columns.py": (
                "import operator\n"
                "from sqlglot.executor.table import Table\n"
                "table = Table(())\n"
                "namespace = table.__dict__\n"
                "operator.setitem(namespace, 'columns', object())\n"
            ),
            "container_alias_columns.py": (
                "from sqlglot.executor.table import Table\n"
                "table = Table(())\n"
                "holder = (table.__dict__,)\n"
                "namespace, = holder\n"
                "namespace['columns'] = object()\n"
            ),
            "getattr_columns.py": (
                "from sqlglot.executor.table import Table\n"
                "table = Table(())\n"
                "namespace = getattr(table, '__dict__')\n"
                "namespace['columns'] = object()\n"
            ),
            "globals_rowreader.py": (
                "from sqlglot.executor.table import RowReader\n"
                "globals()['RowReader'] = object()\n"
            ),
            "aliased_rowreader.py": (
                "from sqlglot.executor.table import RowReader\n"
                "reader = RowReader\n"
                "reader(object())\n"
            ),
            "aliased_journal_key.py": (
                "from sqlglot.optimizer import optimize\n"
                "key = 'jour' + 'nal'\n"
                "kwargs = {key: object()}\n"
                "optimize('select 1', **kwargs)\n"
            ),
            "rules_mutation.py": (
                "from sqlglot import optimizer\n"
                "optimizer.RULES = ()\n"
            ),
            "rules_namespace_alias.py": (
                "import operator\n"
                "import sqlglot.optimizer.optimizer as optimizer_module\n"
                "namespace = vars(optimizer_module)\n"
                "key = 'RU' + 'LES'\n"
                "operator.setitem(namespace, key, ())\n"
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary)
            shutil.copytree(PINNED / "sqlglot", copied / "sqlglot")
            shutil.copytree(PINNED / "tests", copied / "tests")
            self.assertEqual(validate(copied), self.profile["proof_sha256"])
            _rows, base_trees = _closed_tree_rows(copied)
            for name, attack in attacks.items():
                with self.subTest(attack=name):
                    trees = dict(base_trees)
                    trees[f"tests/{name}"] = ast.parse(attack, filename=name)
                    if name in {
                        "optimize_journal.py", "aliased_kwargs.py",
                        "aliased_journal_key.py", "rules_mutation.py",
                        "rules_namespace_alias.py",
                    }:
                        with self.assertRaises(ValueError):
                            verify_pushdown_entry_closure(trees)
                    else:
                        with self.assertRaises(ValueError):
                            verify_rowreader_dynamic_closure(trees)


if __name__ == "__main__":
    unittest.main()
