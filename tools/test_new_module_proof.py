import copy
import gzip
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import selector
from tools.build_new_module_model import risky_inventory, write_deterministic_gzip


ROOT = Path(__file__).resolve().parents[1]
PINNED_SHA = "eb11aec4be8cb2122afe713a4816662c3f0fb2fa"


class NewModuleProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with gzip.open(ROOT / "new_module_model.json.gz", "rt", encoding="utf-8") as f:
            cls.profile = json.load(f)
        with gzip.open(ROOT / "selector_model.json.gz", "rt", encoding="utf-8") as f:
            cls.selector_model = json.load(f)
        cls.tests = json.loads((ROOT / "sample/tests.json").read_text())["tests"]
        cls.test_digest = hashlib.sha256(
            "\0".join(test["id"] for test in cls.tests).encode()
        ).hexdigest()

    def changes(
        self,
        path="sqlglot/fresh_kashimo_module.py",
        body="VALUE = 1\n",
        mode="100644",
        *,
        crlf=False,
        no_newline_marker=False,
        quoted_header=False,
        declared_count=None,
        index_line="index 0000000..1234567",
        extra_metadata=(),
        duplicate_markers=False,
        trailing_garbage=None,
    ):
        lines = body.splitlines()
        old_header = f'a/{path}'
        new_header = f'b/{path}'
        if quoted_header:
            old_header = f'"{old_header}"'
            new_header = f'"{new_header}"'
        patch = "\n".join(
            [
                f"diff --git {old_header} {new_header}",
                f"new file mode {mode}",
                index_line,
                *extra_metadata,
                "--- /dev/null",
                f"+++ b/{path}",
                *(
                    ["--- /dev/null", f"+++ b/{path}"]
                    if duplicate_markers
                    else []
                ),
                f"@@ -0,0 +1,{declared_count if declared_count is not None else len(lines)} @@",
                *(f"+{line}" for line in lines),
                *(["\\ No newline at end of file"] if no_newline_marker else []),
                *([trailing_garbage] if trailing_garbage is not None else []),
                "",
            ]
        )
        if crlf:
            patch = patch.replace("\n", "\r\n")
        with tempfile.NamedTemporaryFile("w", delete=False) as patch_file:
            patch_file.write(patch)
            patch_path = Path(patch_file.name)
        try:
            return selector.patch_changes(patch_path)
        finally:
            patch_path.unlink()

    def test_bundled_certificate_and_expected_channels(self):
        self.assertTrue(
            selector.valid_new_module_model(
                self.profile, PINNED_SHA, self.test_digest, len(self.tests)
            )
        )
        readers = {self.selector_model["t"][i] for i in self.profile["r"]}
        expected = {
            "tests/test_typing.py::TestTyping::test_no_redundant_expression_metadata",
            "tests/dialects/test_dialect.py::TestDialect::test_lazy_load",
            "tests/test_sqlglotc.py::TestSQLGlotC::test_build_removes_obsolete_extensions",
            "tests/test_executor.py::TestExecutor::test_execute_tpch",
            "tests/test_optimizer.py::TestOptimizer::test_canonicalize",
            "tests/test_expressions.py::TestExprs::test_ref_type_builder",
        }
        self.assertTrue(expected <= readers)

    def test_accepts_only_one_fresh_regular_module(self):
        changes = self.changes()
        self.assertEqual(
            selector.isolated_new_module_indices(changes, self.profile),
            set(self.profile["r"]),
        )
        self.assertIsNone(
            selector.isolated_new_module_indices(changes + changes, self.profile)
        )
        self.assertIsNone(
            selector.isolated_new_module_indices(self.changes(mode="120000"), self.profile)
        )

    def test_enabled_selector_path_and_disabled_or_invalid_fallback(self):
        changes = self.changes()
        all_indices = set(range(len(self.tests)))
        expected = set(self.profile["r"])
        with (
            mock.patch.object(selector, "patch_changes", return_value=changes),
            mock.patch.object(selector, "NEW_MODULE_PROOF_ENABLED", True),
        ):
            self.assertEqual(
                selector.selected_indices(
                    Path("unused.patch"),
                    self.selector_model,
                    all_indices,
                    new_module_model=self.profile,
                ),
                expected,
            )

        for enabled, model, parsed_changes in (
            (False, self.profile, changes),
            (True, None, changes),
            (True, self.profile, self.changes(mode="120000")),
        ):
            with (
                mock.patch.object(selector, "patch_changes", return_value=parsed_changes),
                mock.patch.object(selector, "NEW_MODULE_PROOF_ENABLED", enabled),
            ):
                self.assertEqual(
                    selector.selected_indices(
                        Path("unused.patch"),
                        self.selector_model,
                        all_indices,
                        new_module_model=model,
                    ),
                    all_indices,
                )

    def test_gzip_output_is_independent_of_output_basename(self):
        with tempfile.TemporaryDirectory() as temporary:
            one = Path(temporary) / "one-name.gz"
            two = Path(temporary) / "another-name.gz"
            payload = b'{"proof":"same"}'
            write_deterministic_gzip(one, payload)
            write_deterministic_gzip(two, payload)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            with gzip.open(one, "rb") as compressed:
                self.assertEqual(compressed.read(), payload)

    def test_rejects_new_ancestors_and_pytest_names(self):
        for path in (
            "sqlglot/new_package/fresh_kashimo_module.py",
            "sqlglot/test_fresh_kashimo.py",
            "sqlglot/fresh_kashimo_test.py",
            "sqlglot/conftest.py",
            "sqlglot/__special__.py",
        ):
            with self.subTest(path=path):
                self.assertIsNone(
                    selector.isolated_new_module_indices(
                        self.changes(path=path), self.profile
                    )
                )

    def test_rejects_ambiguous_patch_encodings_and_headers(self):
        for changes in (
            self.changes(crlf=True),
            self.changes(no_newline_marker=True),
            self.changes(quoted_header=True),
            self.changes(declared_count=2),
            self.changes(index_line="index 1234567..7654321"),
            self.changes(index_line=""),
            self.changes(extra_metadata=("new file mode 100644",)),
            self.changes(extra_metadata=("copy from sqlglot/old.py",)),
            self.changes(
                extra_metadata=(
                    "rename from sqlglot/old.py",
                    "rename to sqlglot/fresh_kashimo_module.py",
                )
            ),
            self.changes(extra_metadata=("old mode 100755",)),
            self.changes(duplicate_markers=True),
            self.changes(trailing_garbage="unexpected patch payload"),
        ):
            self.assertIsNone(
                selector.isolated_new_module_indices(changes, self.profile)
            )

    def test_ordinary_rename_paths_remain_bound_for_dependency_fallback(self):
        patch = (
            "diff --git a/sqlglot/old.py b/sqlglot/new.py\n"
            "similarity index 100%\n"
            "rename from sqlglot/old.py\n"
            "rename to sqlglot/new.py\n"
        )
        with tempfile.NamedTemporaryFile("w", delete=False) as patch_file:
            patch_file.write(patch)
            path = Path(patch_file.name)
        try:
            changes = selector.patch_changes(path)
        finally:
            path.unlink()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["old"], "sqlglot/old.py")
        self.assertEqual(changes[0]["new"], "sqlglot/new.py")
        self.assertTrue(changes[0]["structural_invalid"])

    def test_rejects_archive_words_and_bad_source(self):
        # Both names occur in pinned imports/data, including from-import sites.
        for path in ("sqlglot/athena.py", "sqlglot/parser.py"):
            with self.subTest(path=path):
                self.assertIsNone(
                    selector.isolated_new_module_indices(
                        self.changes(path=path), self.profile
                    )
                )
        self.assertIsNone(
            selector.isolated_new_module_indices(
                self.changes(body="def broken(:\n    pass\n"), self.profile
            )
        )

    def test_inventory_finds_computed_and_aliased_channels(self):
        source = """
import glob
import importlib
import os
import pkgutil
import runpy
from importlib import import_module as load
from pathlib import Path
from subprocess import run as launch

def probe(root, left, right):
    importlib.import_module("sqlglot." + left + right)
    load(f"sqlglot.{left}{right}")
    __import__("sqlglot." + left)
    pkgutil.iter_modules([root])
    pkgutil.walk_packages([root])
    os.listdir(root)
    os.scandir(root)
    glob.glob(root + "/*.py")
    Path(root).iterdir()
    Path(root).glob("*.py")
    Path(root).read_text()
    open(root)
    eval(left + right)
    runpy.run_path(root)
    launch(["python", "-c", left])
"""
        inventory = risky_inventory({"tests/synthetic.py": source})
        kinds = {entry[3] for entry in inventory}
        calls = {entry[4] for entry in inventory}
        self.assertTrue(
            {
                "dynamic-import",
                "directory-listing",
                "source-reader",
                "dynamic-code",
                "subprocess",
            }
            <= kinds
        )
        self.assertIn("importlib.import_module", calls)
        self.assertIn("builtins.__import__", calls)
        self.assertIn("pkgutil.iter_modules", calls)
        self.assertIn("os.listdir", calls)
        self.assertIn("glob.glob", calls)

    def test_every_profile_tamper_fails_closed(self):
        mutations = []
        for key, value in (
            ("sha", "0" * 40),
            ("d", "0" * 64),
            ("p", "0" * 64),
            ("r", self.profile["r"][:-1]),
            ("i", self.profile["i"][:-1]),
            ("a", self.profile["a"] + ["sqlglot/new_package"]),
            ("b", self.profile["b"][:-4] + "AAAA"),
        ):
            changed = copy.deepcopy(self.profile)
            changed[key] = value
            mutations.append(changed)
        for changed in mutations:
            self.assertFalse(
                selector.valid_new_module_model(
                    changed, PINNED_SHA, self.test_digest, len(self.tests)
                )
            )


if __name__ == "__main__":
    unittest.main()
